//! Daemon server — accept loop + per-client task.
//!
//! Bound to the daemon's Unix socket. Each accepted connection spawns
//! a [`handle_client`] task that owns a [`ProtoStream`] and routes
//! requests to / forwards events from the [`SessionRegistry`].
//!
//! See `the design notes` §8 for the architecture and §8c for the wire-schema
//! contract that lets this layer ship without bikeshedding transport.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use uuid::Uuid;

use crate::config::extended::{DaemonUploadLimitsConfig, ExtendedConfig, RetentionConfig};
use crate::config::providers::{ConfigDoc, ProvidersConfig};
use crate::config::trust::WorkspaceTrustPolicy;
use crate::daemon::DaemonPaths;
use crate::daemon::principal::{self, ClientPrincipal, SessionAccess};
use crate::daemon::proto::{
    self, Body, Envelope, ErrorCode, ErrorPayload, ProtoStream, RecvFrame, Request, Response,
};
use crate::daemon::registry::SessionRegistry;
use crate::daemon::session_worker::{SessionWork, SessionWorkerHandle};
use crate::daemon::shutdown::ShutdownPhase;
use crate::daemon::{
    EventEnvelope, EventReceiver, EventSender, SharedRedactionTable, current_redaction, send_event,
    set_current_redaction,
};
use crate::db::Db;
use crate::env_snapshot::{
    EnvDiffSummary, EnvDriftPolicy, EnvSnapshot, EnvSnapshotMeta, EnvSnapshotSource,
    EnvSnapshotWire, diff_summary,
};
use crate::locks::LockManager;
use crate::redact::RedactionTable;

/// Daemon-wide broadcast capacity for global (non-session) events such as
/// [`proto::Event::CaffeinateState`]. Generous — these are rare.
const GLOBAL_EVENT_CAPACITY: usize = 64;
const IN_PROCESS_REQUEST_QUEUE: usize = 64;
const IN_PROCESS_EVENT_QUEUE: usize = 1024;

static IN_PROCESS_CONTEXTS: OnceLock<StdMutex<HashMap<PathBuf, Weak<DaemonContext>>>> =
    OnceLock::new();

fn build_daemon_redaction_table() -> Arc<RedactionTable> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let cfg = crate::config::extended::load_for_cwd(&cwd).redact;
    Arc::new(RedactionTable::build(&cfg, &cwd).unwrap_or_else(|error| {
        tracing::warn!(error = %error, "building daemon redaction table failed");
        RedactionTable::empty()
    }))
}

fn refresh_global_redaction_table(shared: &SharedRedactionTable) -> Arc<RedactionTable> {
    let fresh = build_daemon_redaction_table();
    let table = match current_redaction(shared).union(&fresh) {
        Ok(table) => Arc::new(table),
        Err(error) => {
            tracing::warn!(error = %error, "unioning daemon redaction table failed");
            fresh
        }
    };
    set_current_redaction(shared, table.clone());
    table
}

fn scrub_json_strings(value: &mut serde_json::Value, redact: &RedactionTable) {
    match value {
        serde_json::Value::String(s) => {
            *s = redact.scrub(s);
        }
        serde_json::Value::Array(items) => {
            for item in items {
                scrub_json_strings(item, redact);
            }
        }
        serde_json::Value::Object(map) => {
            for value in map.values_mut() {
                scrub_json_strings(value, redact);
            }
        }
        _ => {}
    }
}

fn scrub_event_for_principal(
    principal: &ClientPrincipal,
    envelope: EventEnvelope,
) -> Option<proto::Event> {
    if principal.is_owner() {
        return Some(envelope.event);
    }
    scrub_proto_event(envelope.event, &envelope.redact)
}

fn scrub_proto_event(event: proto::Event, redact: &RedactionTable) -> Option<proto::Event> {
    let mut value = match serde_json::to_value(&event) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(error = %error, "serializing event for redaction failed; dropping event");
            return None;
        }
    };
    scrub_json_strings(&mut value, redact);
    match serde_json::from_value(value) {
        Ok(event) => Some(event),
        Err(error) => {
            tracing::warn!(error = %error, "deserializing redacted event failed; dropping event");
            None
        }
    }
}

fn scrub_history_for_principal(
    principal: &ClientPrincipal,
    history: Vec<proto::HistoryEntry>,
    redact: &RedactionTable,
) -> Vec<proto::HistoryEntry> {
    if principal.is_owner() {
        return history;
    }
    history
        .into_iter()
        .filter_map(|entry| scrub_history_entry(entry, redact))
        .collect()
}

fn scrub_history_entry(
    entry: proto::HistoryEntry,
    redact: &RedactionTable,
) -> Option<proto::HistoryEntry> {
    let mut value = match serde_json::to_value(&entry) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(error = %error, "serializing history entry for redaction failed; dropping entry");
            return None;
        }
    };
    scrub_json_strings(&mut value, redact);
    match serde_json::from_value(value) {
        Ok(entry) => Some(entry),
        Err(error) => {
            tracing::warn!(error = %error, "deserializing redacted history entry failed; dropping entry");
            None
        }
    }
}

/// Daemon-wide singletons. Held in an `Arc` so per-client tasks can
/// share without copying.
pub struct DaemonContext {
    pub db: Db,
    pub registry: SessionRegistry,
    pub paths: DaemonPaths,
    pub started_at: Instant,
    /// Caffeination authority (`/caffeinate`, GOALS §1a chrome glyph).
    /// Holds the OS sleep assertion **in the daemon process** so it
    /// survives TUI-client exit, plus the on/off + until-idle state.
    pub caffeinate: Arc<crate::daemon::caffeinate::CaffeineController>,
    /// Daemon-global event bus. Unlike the per-session broadcast on each
    /// worker, every client task subscribes to this regardless of which
    /// (if any) session it's attached to — so a daemon-global event like
    /// [`proto::Event::CaffeinateState`] reaches *all* connected clients.
    global_events: EventSender,
    global_redaction: SharedRedactionTable,
    pub terminal_host: Arc<crate::daemon::terminal_host::TerminalHost>,
    /// Live count of connected clients. Each [`handle_client`] task
    /// increments on accept and decrements on exit. The ephemeral
    /// self-reaping watchdog (Layer C) watches the receiver side for
    /// "no clients" transitions; the persistent daemon ignores it.
    client_count: tokio::sync::watch::Sender<usize>,
    /// Daemon-wide graceful-shutdown gate
    /// (`daemon-graceful-drain-shutdown.md`). Shared with the registry
    /// (installed into worker models). New `SendUserMessage` requests are
    /// refused while it reports draining.
    shutdown: crate::daemon::shutdown::ShutdownSignal,
    env_baseline: Arc<std::sync::RwLock<EnvSnapshot>>,
    upload_accounting: Arc<StdMutex<UploadAccounting>>,
    connector_wake: watch::Sender<u64>,
}

impl DaemonContext {
    fn caffeinate_state_event(&self) -> proto::Event {
        let snap = self.caffeinate.snapshot();
        proto::Event::CaffeinateState {
            active: snap.active,
            lid_close_guaranteed: false,
            message: None,
        }
    }

    fn drain_state_event(&self) -> Option<proto::Event> {
        match self.shutdown.phase() {
            ShutdownPhase::Running => None,
            ShutdownPhase::Draining | ShutdownPhase::Forced => Some(proto::Event::DaemonDraining {
                forced: self.shutdown.is_forced(),
            }),
        }
    }

    pub fn new(db: Db, locks: Arc<LockManager>, paths: DaemonPaths) -> Self {
        // The daemon-wide graceful-shutdown gate
        // (`daemon-graceful-drain-shutdown.md`) — the central drain
        // authority. Built here and shared into the registry (which installs
        // it into every worker's model) so the inference-dispatch chokepoint,
        // the new-user-work gate, and teardown all read one state.
        let shutdown = crate::daemon::shutdown::ShutdownSignal::new();
        let resource_scheduler = (!paths.ephemeral).then(|| {
            Arc::new(crate::engine::resource_scheduler::ResourceScheduler::new(
                ExtendedConfig::default().resource_scheduler,
            ))
        });
        let registry =
            SessionRegistry::new(db.clone(), locks, shutdown.clone(), resource_scheduler);
        let (client_count, _) = tokio::sync::watch::channel(0usize);
        let (connector_wake, _) = watch::channel(0u64);
        let (global_events, _) = broadcast::channel(GLOBAL_EVENT_CAPACITY);
        let global_redaction = Arc::new(std::sync::RwLock::new(build_daemon_redaction_table()));
        let terminal_host = Arc::new(crate::daemon::terminal_host::TerminalHost::new(
            global_events.clone(),
            global_redaction.clone(),
            terminal_temp_root(&paths),
        ));
        let container = Arc::new(crate::container::ContainerManager::detect());
        let _ = crate::container::container_manager().set((*container).clone());
        spawn_terminal_reaper(terminal_host.clone(), shutdown.clone());
        registry
            .lsp_manager()
            .set_notice_bus(global_events.clone(), global_redaction.clone());
        registry.set_global_bus(global_events.clone());
        Self {
            db,
            registry,
            paths,
            started_at: Instant::now(),
            caffeinate: Arc::new(crate::daemon::caffeinate::CaffeineController::new()),
            global_events,
            global_redaction,
            terminal_host,
            client_count,
            shutdown,
            env_baseline: Arc::new(std::sync::RwLock::new(EnvSnapshot::from_process(
                EnvSnapshotSource::DaemonStart,
            ))),
            upload_accounting: Arc::new(StdMutex::new(UploadAccounting::default())),
            connector_wake,
        }
    }

    /// The daemon's graceful-shutdown gate. New-user-work rejection and the
    /// single drain path both read it.
    pub fn shutdown_signal(&self) -> &crate::daemon::shutdown::ShutdownSignal {
        &self.shutdown
    }

    /// Subscribe to the daemon-global event bus. Every client task holds
    /// one of these for its lifetime.
    pub fn subscribe_global(&self) -> EventReceiver {
        self.global_events.subscribe()
    }

    /// Broadcast a daemon-global event to all connected clients.
    pub fn broadcast_global(&self, event: proto::Event) {
        let table = refresh_global_redaction_table(&self.global_redaction);
        send_event(&self.global_events, &table, event);
    }

    async fn resync_caffeinate_state<S>(&self, proto: &mut ProtoStream<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        proto
            .send(&Envelope::event(self.caffeinate_state_event()))
            .await
    }

    async fn resync_drain_state<S>(&self, proto: &mut ProtoStream<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if let Some(event) = self.drain_state_event() {
            proto.send(&Envelope::event(event)).await
        } else {
            Ok(())
        }
    }

    async fn resync_after_global_lag<S>(
        &self,
        proto: &mut ProtoStream<S>,
        attached: Option<&AttachedSession>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.resync_caffeinate_state(proto).await?;
        self.resync_drain_state(proto).await?;
        let _ = attached;
        Ok(())
    }

    /// Subscribe to connector wakeups. Credential store/clear requests use
    /// this to interrupt the connector's fallback polling sleep and any active
    /// relay socket so credential changes take effect immediately.
    pub fn connector_wake_rx(&self) -> watch::Receiver<u64> {
        self.connector_wake.subscribe()
    }

    pub fn wake_connector(&self) {
        self.connector_wake.send_modify(|version| {
            *version = version.wrapping_add(1);
        });
    }

    /// Subscribe to the live connected-client count. Used by the
    /// ephemeral idle watchdog (Layer C).
    pub fn client_presence(&self) -> tokio::sync::watch::Receiver<usize> {
        self.client_count.subscribe()
    }

    /// RAII guard: bumps the connected-client count on construction and
    /// decrements it on drop, so the count stays correct on every exit
    /// path of a client task (clean EOF, decode error, send failure).
    fn track_client(self: &Arc<Self>) -> ClientGuard {
        self.client_count.send_modify(|n| *n += 1);
        ClientGuard { ctx: self.clone() }
    }
}

/// Decrements the daemon's connected-client count when a client task
/// ends, regardless of how it ends.
struct ClientGuard {
    ctx: Arc<DaemonContext>,
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.ctx
            .client_count
            .send_modify(|n| *n = n.saturating_sub(1));
    }
}

pub(crate) fn register_in_process_context(ctx: Arc<DaemonContext>) {
    let contexts = IN_PROCESS_CONTEXTS.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut contexts = contexts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    contexts.insert(ctx.paths.socket.clone(), Arc::downgrade(&ctx));
}

pub(crate) fn in_process_context(socket: &Path) -> Option<Arc<DaemonContext>> {
    let contexts = IN_PROCESS_CONTEXTS.get()?;
    let mut contexts = contexts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let weak = contexts.get(socket)?;
    match weak.upgrade() {
        Some(ctx) => Some(ctx),
        None => {
            contexts.remove(socket);
            None
        }
    }
}

/// Bootstrap the daemon: open the DB, build the lock manager, return
/// a ready-to-use context. Called from `daemon::run_foreground`.
pub fn boot(paths: DaemonPaths) -> Result<DaemonContext> {
    let mut timer = crate::startup::PhaseTimer::start("daemon::boot");
    let db = Db::open_default().context("opening session DB")?;
    timer.phase("db_open_and_migrate");
    let locks = Arc::new(LockManager::from_db(db.clone()).context("loading lock state")?);
    timer.phase("lock_manager");
    run_boot_housekeeping(&db);
    timer.phase("prune_and_sweep");
    let ctx = DaemonContext::new(db, locks, paths);
    timer.done();
    Ok(ctx)
}

const TERMINAL_REAPER_POLL: Duration = Duration::from_secs(30);

fn spawn_terminal_reaper(
    terminal_host: Arc<crate::daemon::terminal_host::TerminalHost>,
    shutdown: crate::daemon::shutdown::ShutdownSignal,
) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        let mut interval = tokio::time::interval(TERMINAL_REAPER_POLL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if shutdown.is_draining() {
                return;
            }
            let closed = terminal_host.sweep_idle(Instant::now());
            if !closed.is_empty() {
                tracing::info!(count = closed.len(), "swept idle remote terminals");
            }
        }
    });
}

fn terminal_temp_root(paths: &DaemonPaths) -> PathBuf {
    paths
        .socket
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir)
        .join("terminal-pastes")
}

fn run_boot_housekeeping(db: &Db) {
    // Drop autocomplete-tally rows that have aged out of the 30-day
    // window. Best-effort — a prune failure shouldn't block boot.
    let before = chrono::Utc::now().timestamp() - crate::db::usage_events::USAGE_WINDOW_SECS;
    if let Err(e) = db.prune_usage_events(before) {
        tracing::warn!(error = %e, "pruning usage_events on boot failed");
    }
    // SIGKILL backstop for `/side`: a side conversation whose owning process
    // died uncatchably can orphan an ephemeral session row. Sweep them on
    // boot so ephemeral sessions never accumulate. Best-effort.
    match db.sweep_ephemeral_sessions() {
        Ok(n) if n > 0 => tracing::info!(count = n, "swept orphaned ephemeral sessions on boot"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "sweeping ephemeral sessions on boot failed"),
    }
    run_retention_pass_blocking(
        db.clone(),
        retention_config(),
        chrono::Utc::now().timestamp(),
    );
    match db.reconcile_orphaned_task_delegations() {
        Ok(n) if n > 0 => {
            tracing::info!(count = n, "marked orphaned task delegations lost on boot")
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "reconciling orphaned task delegations on boot failed")
        }
    }
}

/// Bind the Unix socket and run the accept loop until the daemon's
/// graceful-shutdown gate leaves `Running`. Each accepted connection spawns
/// a detached client task. Breaking the loop hands control back to
/// [`crate::daemon::run_foreground_inner`], which drains the workers.
#[cfg(unix)]
pub async fn run_accept_loop(ctx: Arc<DaemonContext>, listener: UnixListener) -> Result<()> {
    let mut shutdown = ctx.shutdown.subscribe();
    let retention_cfg = retention_config();
    let mut retention_interval = tokio::time::interval(std::time::Duration::from_secs(
        (retention_cfg.sweep_interval_hours.max(1) as u64) * 60 * 60,
    ));
    retention_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    retention_interval.tick().await;
    // A drain may already have begun before we subscribed (begin_drain on a
    // very fast StopDaemon); break immediately if so.
    if ctx.shutdown.is_draining() {
        return Ok(());
    }

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                // Any transition out of `Running` (drain begun) closes the
                // accept loop; `changed()` only errs if the sender dropped,
                // which also means we should stop accepting.
                if changed.is_err() || ctx.shutdown.is_draining() {
                    tracing::info!("daemon: drain begun, closing accept loop");
                    break;
                }
            }
            _ = retention_interval.tick() => {
                run_retention_tick(ctx.clone(), retention_cfg).await;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _peer)) => {
                        if let Err(e) = validate_peer_owner(&stream) {
                            tracing::warn!(error = %e, "rejected daemon socket peer");
                            continue;
                        }
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, ctx).await {
                                tracing::warn!(error = ?e, "client task ended with error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed; backing off");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    Ok(())
}

fn retention_config() -> RetentionConfig {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    crate::config::extended::load_for_cwd(&cwd).retention
}

fn log_retention_outcome(outcome: crate::db::retention::RetentionOutcome) {
    if outcome.sessions_expired > 0 || outcome.payload_rows_deleted > 0 || outcome.vacuumed {
        tracing::info!(
            sessions_expired = outcome.sessions_expired,
            payload_rows_deleted = outcome.payload_rows_deleted,
            vacuumed = outcome.vacuumed,
            "session payload retention pass completed"
        );
    }
}

fn run_retention_pass_blocking(db: Db, cfg: RetentionConfig, now_secs: i64) {
    match db.run_retention_pass(&cfg, now_secs) {
        Ok(outcome) => log_retention_outcome(outcome),
        Err(error) => tracing::warn!(error = %error, "session payload retention pass failed"),
    }
}

async fn run_retention_tick(ctx: Arc<DaemonContext>, cfg: RetentionConfig) {
    run_retention_tick_db(ctx.db.clone(), cfg).await;
}

async fn run_retention_tick_db(db: Db, cfg: RetentionConfig) {
    let now_secs = chrono::Utc::now().timestamp();
    match tokio::task::spawn_blocking(move || db.run_retention_pass(&cfg, now_secs)).await {
        Ok(Ok(outcome)) => log_retention_outcome(outcome),
        Ok(Err(error)) => {
            tracing::warn!(error = %error, "session payload retention pass failed")
        }
        Err(error) => {
            tracing::warn!(error = %error, "session payload retention worker failed")
        }
    }
}

#[cfg(unix)]
fn validate_peer_owner(stream: &UnixStream) -> Result<()> {
    let peer_uid = peer_uid(stream)?;
    let daemon_uid = current_uid();
    validate_peer_uid(peer_uid, daemon_uid)
}

#[cfg(all(unix, target_os = "linux"))]
fn peer_uid(stream: &UnixStream) -> Result<libc::uid_t> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;

    let mut cred = MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `getsockopt` writes at most `len` bytes into the valid
    // `ucred` storage. We check the return value before reading it.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("reading daemon socket peer uid");
    }

    // SAFETY: `getsockopt` succeeded and initialized the `ucred` struct.
    Ok(unsafe { cred.assume_init().uid })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn peer_uid(stream: &UnixStream) -> Result<libc::uid_t> {
    use std::os::fd::AsRawFd;

    let mut euid: libc::uid_t = 0;
    let mut egid: libc::gid_t = 0;
    // SAFETY: `getpeereid` writes to valid uid/gid pointers for this socket.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut euid, &mut egid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("reading daemon socket peer uid");
    }
    Ok(euid)
}

#[cfg(unix)]
fn current_uid() -> libc::uid_t {
    // SAFETY: `getuid` has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(unix)]
fn validate_peer_uid(peer_uid: libc::uid_t, daemon_uid: libc::uid_t) -> Result<()> {
    if peer_uid != daemon_uid {
        anyhow::bail!(
            "daemon socket peer uid `{peer_uid}` does not match daemon uid `{daemon_uid}`"
        );
    }
    Ok(())
}

// ---- per-client state -----------------------------------------------------

struct ClientState {
    principal: ClientPrincipal,
    attached: Option<AttachedSession>,
    pending_uploads: HashMap<Uuid, PendingAttachmentUpload>,
    ready_attachments: HashMap<Uuid, ReadyAttachment>,
    upload_accounting: Arc<StdMutex<UploadAccounting>>,
    upload_limits: AttachmentUploadLimits,
    terminal_views: HashSet<Uuid>,
    terminal_host: Arc<crate::daemon::terminal_host::TerminalHost>,
}

impl ClientState {
    fn detached_with_principal(
        upload_accounting: Arc<StdMutex<UploadAccounting>>,
        principal: ClientPrincipal,
        terminal_host: Arc<crate::daemon::terminal_host::TerminalHost>,
    ) -> Self {
        Self {
            principal,
            attached: None,
            pending_uploads: HashMap::new(),
            ready_attachments: HashMap::new(),
            upload_accounting,
            upload_limits: AttachmentUploadLimits::default(),
            terminal_views: HashSet::new(),
            terminal_host,
        }
    }

    #[cfg(test)]
    fn detached_for_test() -> Self {
        Self::detached_with_principal(
            Arc::new(StdMutex::new(UploadAccounting::default())),
            ClientPrincipal::owner(),
            test_terminal_host(),
        )
    }
}

#[cfg(test)]
fn test_terminal_host() -> Arc<crate::daemon::terminal_host::TerminalHost> {
    let (tx, _rx) = broadcast::channel(16);
    Arc::new(crate::daemon::terminal_host::TerminalHost::new_for_test(
        tx,
        std::env::temp_dir().join("cockpit-test-terminal-pastes"),
    ))
}

impl Drop for ClientState {
    fn drop(&mut self) {
        release_uploads(
            &self.upload_accounting,
            self.pending_uploads.keys().copied(),
        );
        for terminal_id in self.terminal_views.drain() {
            self.terminal_host.release_viewer(terminal_id);
        }
    }
}

const MIN_ATTACHMENT_UPLOAD_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy)]
struct AttachmentUploadLimits {
    per_client_uploads: usize,
    global_uploads: usize,
    per_upload_bytes: usize,
    global_bytes: usize,
}

impl Default for AttachmentUploadLimits {
    fn default() -> Self {
        DaemonUploadLimitsConfig::default().into()
    }
}

impl AttachmentUploadLimits {
    fn from_config(config: DaemonUploadLimitsConfig) -> Self {
        let (limits, warning) = Self::from_config_with_warning(config);
        if let Some(warning) = warning {
            tracing::warn!(%warning, "daemon upload limit adjusted");
        }
        limits
    }

    fn from_config_with_warning(config: DaemonUploadLimitsConfig) -> (Self, Option<String>) {
        let (per_upload_bytes, warning) = normalize_per_upload_bytes(config.per_upload_bytes);
        (
            Self {
                per_client_uploads: config.per_client_uploads,
                global_uploads: config.global_uploads,
                per_upload_bytes,
                global_bytes: config.global_bytes,
            },
            warning,
        )
    }
}

impl From<DaemonUploadLimitsConfig> for AttachmentUploadLimits {
    fn from(config: DaemonUploadLimitsConfig) -> Self {
        Self::from_config(config)
    }
}

fn normalize_per_upload_bytes(configured: usize) -> (usize, Option<String>) {
    if configured > proto::MAX_SINGLE_IMAGE_BYTES {
        return (
            proto::MAX_SINGLE_IMAGE_BYTES,
            Some(format!(
                "per_upload_bytes {} exceeds protocol cap {}; clamping",
                format_upload_bytes(configured),
                format_upload_bytes(proto::MAX_SINGLE_IMAGE_BYTES)
            )),
        );
    }
    if configured < MIN_ATTACHMENT_UPLOAD_BYTES {
        return (
            MIN_ATTACHMENT_UPLOAD_BYTES,
            Some(format!(
                "per_upload_bytes {} is below minimum {}; clamping",
                format_upload_bytes(configured),
                format_upload_bytes(MIN_ATTACHMENT_UPLOAD_BYTES)
            )),
        );
    }
    (configured, None)
}

fn format_upload_bytes(bytes: usize) -> String {
    const MIB: usize = 1024 * 1024;
    const KIB: usize = 1024;
    if bytes >= MIB && bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else if bytes >= KIB && bytes.is_multiple_of(KIB) {
        format!("{} KiB", bytes / KIB)
    } else {
        format!("{bytes} bytes")
    }
}

#[derive(Debug, Default)]
struct UploadAccounting {
    pending: HashMap<Uuid, usize>,
}

impl UploadAccounting {
    fn pending_bytes(&self) -> usize {
        self.pending.values().sum()
    }

    fn reserve(
        &mut self,
        upload_id: Uuid,
        byte_len: usize,
        limits: AttachmentUploadLimits,
    ) -> std::result::Result<(), ErrorPayload> {
        if self.pending.len() >= limits.global_uploads {
            return Err(bad_request(format!(
                "too many pending attachment uploads: daemon has {} pending, limit {}",
                self.pending.len(),
                limits.global_uploads
            )));
        }
        let pending_bytes = self.pending_bytes();
        if pending_bytes.saturating_add(byte_len) > limits.global_bytes {
            return Err(bad_request(format!(
                "pending attachment uploads exceed daemon byte limit: {} + {} bytes exceeds {}",
                pending_bytes, byte_len, limits.global_bytes
            )));
        }
        self.pending.insert(upload_id, byte_len);
        Ok(())
    }

    fn release(&mut self, upload_id: &Uuid) {
        self.pending.remove(upload_id);
    }
}

fn release_uploads<I>(accounting: &Arc<StdMutex<UploadAccounting>>, upload_ids: I)
where
    I: IntoIterator<Item = Uuid>,
{
    let mut accounting = crate::sync::lock_or_recover(accounting);
    for upload_id in upload_ids {
        accounting.release(&upload_id);
    }
}

struct PendingAttachmentUpload {
    session_id: Option<Uuid>,
    mime: String,
    byte_len: usize,
    sha256: String,
    purpose: proto::AttachmentPurpose,
    bytes: Vec<u8>,
    created_at: Instant,
}

struct ReadyAttachment {
    session_id: Uuid,
    mime: String,
    bytes: Vec<u8>,
    purpose: proto::AttachmentPurpose,
    created_at: Instant,
}

struct AttachedSession {
    handle: SessionWorkerHandle,
    event_rx: EventReceiver,
    /// Held for the lifetime of the attachment when this client is
    /// interactive (can answer interrupts). Dropping it on detach /
    /// re-attach / disconnect decrements the worker's interactive-client
    /// count so the loop guard reverts to headless behavior. `None` for a
    /// non-interactive attach (e.g. `cockpit run`'s event pump).
    _interactive_guard: Option<crate::daemon::session_worker::InteractiveClientGuard>,
}

pub(crate) struct InProcessRequest {
    pub request: Request,
    pub reply: oneshot::Sender<std::result::Result<Response, ErrorPayload>>,
}

pub(crate) fn spawn_in_process_client(
    ctx: Arc<DaemonContext>,
) -> (mpsc::Sender<InProcessRequest>, mpsc::Receiver<proto::Event>) {
    let (request_tx, request_rx) = mpsc::channel(IN_PROCESS_REQUEST_QUEUE);
    let (event_tx, event_rx) = mpsc::channel(IN_PROCESS_EVENT_QUEUE);
    tokio::spawn(run_in_process_client(ctx, request_rx, event_tx));
    (request_tx, event_rx)
}

async fn run_in_process_client(
    ctx: Arc<DaemonContext>,
    mut request_rx: mpsc::Receiver<InProcessRequest>,
    event_tx: mpsc::Sender<proto::Event>,
) {
    let _client_guard = ctx.track_client();
    let mut state = ClientState::detached_with_principal(
        ctx.upload_accounting.clone(),
        ClientPrincipal::owner(),
        ctx.terminal_host.clone(),
    );
    let mut global_rx = ctx.subscribe_global();

    if event_tx.send(ctx.caffeinate_state_event()).await.is_err() {
        return;
    }

    loop {
        let event_branch = async {
            match state.attached.as_mut() {
                Some(att) => Some(att.event_rx.recv().await),
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            biased;
            global = global_rx.recv() => {
                match global {
                    Ok(envelope) => {
                        if event_tx.send(envelope.event).await.is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(missed = n, "in-process client global event stream lagged");
                        if event_tx.send(ctx.caffeinate_state_event()).await.is_err() {
                            return;
                        }
                        if let Some(event) = ctx.drain_state_event()
                            && event_tx.send(event).await.is_err()
                        {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {}
                }
            }
            event = event_branch => {
                match event {
                    Some(Ok(envelope)) => {
                        if event_tx.send(envelope.event).await.is_err() {
                            return;
                        }
                    }
                    Some(Err(broadcast::error::RecvError::Lagged(n))) => {
                        tracing::warn!(missed = n, "in-process client event stream lagged; reattach to resync");
                    }
                    Some(Err(broadcast::error::RecvError::Closed)) => {
                        state.attached = None;
                    }
                    None => unreachable!("event_branch is pending when not attached"),
                }
            }
            cmd = request_rx.recv() => {
                let Some(InProcessRequest { request, reply }) = cmd else {
                    return;
                };
                let is_attach = matches!(&request, Request::Attach { .. });
                let result = handle_request(request, &mut state, &ctx).await;
                let attached = matches!(&result, Ok(Response::Attached { .. }));
                let _ = reply.send(result);
                if is_attach && attached
                    && let Some(event) = ctx.drain_state_event()
                    && event_tx.send(event).await.is_err()
                {
                    return;
                }
            }
        }
    }
}

#[cfg(unix)]
async fn handle_client(stream: UnixStream, ctx: Arc<DaemonContext>) -> Result<()> {
    handle_client_transport(stream, ctx).await
}

#[allow(dead_code)]
pub(crate) async fn handle_relay_channel<S>(stream: S, ctx: Arc<DaemonContext>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    handle_relay_channel_as(stream, ctx, ClientPrincipal::owner()).await
}

pub(crate) async fn handle_relay_channel_as<S>(
    stream: S,
    ctx: Arc<DaemonContext>,
    principal: ClientPrincipal,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    handle_client_transport_as(stream, ctx, principal).await
}

async fn handle_client_transport<S>(stream: S, ctx: Arc<DaemonContext>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    handle_client_transport_as(stream, ctx, ClientPrincipal::owner()).await
}

async fn handle_client_transport_as<S>(
    stream: S,
    ctx: Arc<DaemonContext>,
    principal: ClientPrincipal,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Count this client for the lifetime of the task. The guard
    // decrements on every return below (Layer C presence tracking).
    let _client_guard = ctx.track_client();
    let mut proto = ProtoStream::new(stream);

    // Emit a "hello" envelope immediately so cheap probes
    // (`probe_blocking`, third-party reachability checks) can confirm
    // the daemon is alive without doing a full proto handshake. The
    // envelope is a self-contained `DaemonStatus` response with
    // `id = Nil`, which `DaemonClient` ignores (no pending request
    // matches it).
    let hello = Envelope::response(
        Uuid::nil(),
        Response::DaemonStatus {
            pid: std::process::id(),
            uptime_secs: ctx.started_at.elapsed().as_secs(),
            active_sessions: ctx.registry.active_session_ids().len() as u32,
            socket_path: ctx.paths.socket.display().to_string(),
            daemon_version: proto::DAEMON_VERSION.to_string(),
            protocol_version: proto::PROTOCOL_VERSION,
            paused_sessions: ctx
                .db
                .paused_session_work_all()
                .map(|r| r.len())
                .unwrap_or(0) as u32,
        },
    );
    if proto.send(&hello).await.is_err() {
        return Ok(());
    }

    let mut state = ClientState::detached_with_principal(
        ctx.upload_accounting.clone(),
        principal,
        ctx.terminal_host.clone(),
    );

    // Daemon-global events (caffeinate, …) reach every client regardless
    // of attachment, so this receiver lives for the whole client task.
    let mut global_rx = ctx.subscribe_global();

    // On connect, sync the client's caffeinate glyph to the daemon's
    // current state (a TUI that attaches while caffeination is already on
    // must show ☕ immediately). Fire-and-forget; a send failure just
    // means the client went away.
    let _ = ctx.resync_caffeinate_state(&mut proto).await;

    loop {
        // The select! pulls from whichever side of the socket has work.
        // We have to expand `recv_event` inline because Future<Output=
        // …> from `broadcast::Receiver::recv` borrows the receiver.
        let inbound = async {
            match proto.recv().await {
                Ok(Some(env)) => Some(Ok(env)),
                Ok(None) => None,
                Err(e) => Some(Err(e)),
            }
        };

        // If there's an attached session, listen for its events too.
        // When there isn't, the `event_branch` future is `pending`.
        let event_branch = async {
            match state.attached.as_mut() {
                Some(att) => Some(att.event_rx.recv().await),
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            biased;
            global = global_rx.recv() => {
                match global {
                    Ok(envelope) => {
                        let Some(ev) = scrub_event_for_principal(&state.principal, envelope) else {
                            continue;
                        };
                        if let Err(e) = proto.send(&Envelope::event(ev)).await {
                            tracing::debug!(error = ?e, "client disconnected during global event send");
                            return Ok(());
                        }
                    }
                    // A lagging global bus is non-fatal: caffeinate state
                    // and other daemon-global level state are re-synced
                    // immediately so dropped edge events do not leave stale
                    // chrome behind.
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(missed = n, "client global event stream lagged");
                        if ctx
                            .resync_after_global_lag(&mut proto, state.attached.as_ref())
                            .await
                            .is_err()
                        {
                            return Ok(());
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // The daemon is tearing down; let the socket close.
                    }
                }
            }
            event = event_branch => {
                match event {
                    Some(Ok(envelope)) => {
                        let Some(ev) = scrub_event_for_principal(&state.principal, envelope) else {
                            continue;
                        };
                        // A raised/resolved interrupt moves the project's
                        // interruptions count. The worker's single forwarder
                        // recomputes and broadcasts the global plan-status
                        // state once per interrupt event; this per-client fan-
                        // out path only forwards the interrupt itself.
                        if let Err(e) = proto.send(&Envelope::event(ev)).await {
                            tracing::debug!(error = ?e, "client disconnected during event send");
                            return Ok(());
                        }
                    }
                    Some(Err(broadcast::error::RecvError::Lagged(n))) => {
                        tracing::warn!(missed = n, "client event stream lagged; reattach to resync");
                        // Per design, lagging clients re-attach. We
                        // emit a synthetic error so the TUI surfaces it.
                        let _ = proto
                            .send(&Envelope::error(
                                None,
                                ErrorPayload {
                                    code: ErrorCode::Internal,
                                    message: format!("event stream lagged by {n}; re-attach"),
                                },
                            ))
                            .await;
                    }
                    Some(Err(broadcast::error::RecvError::Closed)) => {
                        // The session worker exited. Detach so the
                        // client can attach to a different session
                        // without churning.
                        state.attached = None;
                    }
                    None => unreachable!("event_branch is pending when not attached"),
                }
            }
            recv = inbound => {
                match recv {
                    None => return Ok(()), // clean EOF
                    Some(Err(e)) => {
                        tracing::debug!(error = ?e, "envelope decode failed; closing client");
                        return Ok(());
                    }
                    Some(Ok(frame)) => {
                        match frame {
                            RecvFrame::Envelope(env) => {
                                handle_envelope(*env, &mut state, &ctx, &mut proto).await?;
                            }
                            RecvFrame::VersionMismatch { v, kind, id } => {
                                if kind == "req"
                                    && let Some(id) = id
                                {
                                    let envelope = Envelope::error(
                                        Some(id),
                                        ErrorPayload {
                                            code: ErrorCode::ProtocolVersion,
                                            message: proto::version_mismatch_message(v),
                                        },
                                    );
                                    let _ = proto.send(&envelope).await;
                                } else {
                                    tracing::debug!(
                                        version = v,
                                        kind,
                                        ?id,
                                        "closing client after protocol version mismatch"
                                    );
                                }
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn handle_envelope<S>(
    env: Envelope,
    state: &mut ClientState,
    ctx: &Arc<DaemonContext>,
    proto: &mut ProtoStream<S>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    match env.body {
        Body::Request { id, request } => {
            let is_attach = matches!(&request, Request::Attach { .. });
            let result = handle_request(request, state, ctx).await;
            let attached = matches!(&result, Ok(Response::Attached { .. }));
            let envelope = match result {
                Ok(response) => Envelope::response(id, response),
                Err(err) => Envelope::error(Some(id), err),
            };
            if let Err(error) = proto.send(&envelope).await {
                log_response_send_failed(id, envelope_kind(&envelope), &error);
            }
            if is_attach && attached {
                let _ = ctx.resync_drain_state(proto).await;
            }
        }
        Body::Response { id, .. } => {
            tracing::warn!(id = %id, "client sent a response envelope; ignoring");
        }
        Body::Event { event } => {
            tracing::warn!(?event, "client sent an event envelope; ignoring");
        }
        Body::Error { id, error } => {
            tracing::warn!(?id, ?error, "client sent an error envelope; ignoring");
        }
    }
    Ok(())
}

fn envelope_kind(envelope: &Envelope) -> &'static str {
    match envelope.body {
        Body::Response { .. } => "response",
        Body::Error { .. } => "error",
        Body::Request { .. } => "request",
        Body::Event { .. } => "event",
    }
}

fn log_response_send_failed(id: Uuid, envelope_kind: &'static str, error: &anyhow::Error) {
    tracing::warn!(
        request_id = %id,
        envelope_kind,
        error = %error,
        "daemon failed to send response envelope to client"
    );
}

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::BadRequest,
        message: message.into(),
    }
}

fn authorization_error(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Authorization,
        message: message.into(),
    }
}

fn read_only_error(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::ReadOnly,
        message: message.into(),
    }
}

fn session_access_for_row(
    principal: &ClientPrincipal,
    row: &crate::db::sessions::SessionRow,
) -> SessionAccess {
    if principal.is_owner() {
        return SessionAccess::Owner;
    }
    let project_root = row.project_root.as_str();
    let created_by_this_principal = principal
        .tag()
        .as_deref()
        .is_some_and(|tag| row.created_by_principal.as_deref() == Some(tag));
    let scoped_to_session = created_by_this_principal || row.shared_with_collaborators;
    if !scoped_to_session {
        return SessionAccess::None;
    }
    if principal.can_agent_write_project(project_root) {
        SessionAccess::Writer
    } else if principal.can_agent_read_project(project_root) {
        SessionAccess::Readonly
    } else {
        SessionAccess::None
    }
}

fn session_access_for_summary(
    principal: &ClientPrincipal,
    summary: &proto::SessionSummary,
) -> SessionAccess {
    if principal.is_owner() {
        return SessionAccess::Owner;
    }
    let created_by_this_principal = principal
        .tag()
        .as_deref()
        .is_some_and(|tag| summary.created_by_principal.as_deref() == Some(tag));
    let scoped_to_session = created_by_this_principal || summary.shared_with_collaborators;
    if !scoped_to_session {
        return SessionAccess::None;
    }
    if principal.can_agent_write_project(&summary.project_root) {
        SessionAccess::Writer
    } else if principal.can_agent_read_project(&summary.project_root) {
        SessionAccess::Readonly
    } else {
        SessionAccess::None
    }
}

fn attached_session_access(
    principal: &ClientPrincipal,
    state: &ClientState,
    ctx: &DaemonContext,
) -> std::result::Result<SessionAccess, ErrorPayload> {
    if principal.is_owner() {
        return Ok(SessionAccess::Owner);
    }
    let att = require_attached(state)?;
    match ctx.db.get_session(att.handle.session_id) {
        Ok(Some(row)) => Ok(session_access_for_row(principal, &row)),
        Ok(None) => {
            let project_root = att.handle.project_root.to_string_lossy();
            if principal.can_agent_write_project(&project_root) {
                Ok(SessionAccess::Writer)
            } else if principal.can_agent_read_project(&project_root) {
                Ok(SessionAccess::Readonly)
            } else {
                Ok(SessionAccess::None)
            }
        }
        Err(e) => Err(internal(e)),
    }
}

fn require_remote_session_writer(
    principal: &ClientPrincipal,
    state: &ClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    match attached_session_access(principal, state, ctx)? {
        SessionAccess::Owner | SessionAccess::Writer => Ok(()),
        SessionAccess::Readonly => Err(read_only_error(
            "remote principal has read-only access to this session",
        )),
        SessionAccess::None => Err(authorization_error(
            "remote principal cannot access this session",
        )),
    }
}

fn require_remote_target_session_writer(
    principal: &ClientPrincipal,
    ctx: &DaemonContext,
    session_id: Uuid,
) -> std::result::Result<(), ErrorPayload> {
    match ctx.db.get_session(session_id) {
        Ok(Some(row)) => match session_access_for_row(principal, &row) {
            SessionAccess::Owner | SessionAccess::Writer => Ok(()),
            SessionAccess::Readonly => Err(read_only_error(
                "remote principal has read-only access to this session",
            )),
            SessionAccess::None => Err(authorization_error(
                "remote principal cannot access this session",
            )),
        },
        Ok(None) => Err(ErrorPayload {
            code: ErrorCode::UnknownSession,
            message: format!("unknown session {session_id}"),
        }),
        Err(e) => Err(internal(e)),
    }
}

fn request_session_id(request: &Request, state: &ClientState) -> Option<Uuid> {
    match request {
        Request::Attach { session_id, .. } => *session_id,
        Request::ResumePausedWork { session_id }
        | Request::CancelPausedWork { session_id }
        | Request::RepairResume { session_id }
        | Request::SteerDelegation { session_id, .. }
        | Request::SubagentTranscript { session_id, .. }
        | Request::ArchiveSession { session_id, .. }
        | Request::UnarchiveSession { session_id }
        | Request::DiscardSession { session_id }
        | Request::RenameSession { session_id, .. }
        | Request::ShareSession { session_id, .. }
        | Request::RecordSessionNote { session_id, .. }
        | Request::DeleteSession { session_id, .. } => Some(*session_id),
        Request::ForkSession {
            parent_session_id, ..
        } => Some(*parent_session_id),
        Request::PromoteResource { session_id, .. } => *session_id,
        Request::SendUserMessage { .. }
        | Request::BeginAttachmentUpload { .. }
        | Request::UploadAttachmentChunk { .. }
        | Request::FinishAttachmentUpload { .. }
        | Request::CancelAttachmentUpload { .. }
        | Request::RemoveQueuedUserMessage { .. }
        | Request::RemoveNewestQueuedUserMessage { .. }
        | Request::RemoveEditableQueuedUserMessages { .. }
        | Request::CancelTurn
        | Request::LspControl { .. }
        | Request::ResolveInterrupt { .. }
        | Request::SetActiveModel { .. }
        | Request::SetAgent { .. }
        | Request::SetLlmMode { .. }
        | Request::SetSessionLlmMode { .. }
        | Request::SetApprovalMode { .. }
        | Request::SetDelegationRecursion { .. }
        | Request::CancelSchedule { .. }
        | Request::SetSandbox { .. }
        | Request::SetPreflight { .. }
        | Request::SetTrustedOnly { .. }
        | Request::SetRedaction { .. }
        | Request::SetTandemModels { .. }
        | Request::Prune
        | Request::Compact
        | Request::Pin { .. }
        | Request::RefreshEnv { .. } => state.attached.as_ref().map(|att| att.handle.session_id),
        _ => None,
    }
}

fn request_audit_path(request: &Request) -> Option<String> {
    match request {
        Request::FsWrite { path, .. }
        | Request::FsCreateDir { path, .. }
        | Request::FsDelete { path, .. }
        | Request::GitDiffFile { path, .. } => Some(path.clone()),
        Request::FsRename {
            from_path, to_path, ..
        } => Some(format!("{from_path} -> {to_path}")),
        _ => None,
    }
}

fn is_remote_mutating_request(request: &Request) -> bool {
    !matches!(
        request,
        Request::ListSessions { .. }
            | Request::SessionLiveStatus { .. }
            | Request::DaemonStatus
            | Request::ListSkills { .. }
            | Request::ListModels { .. }
            | Request::GuidanceEstimate { .. }
            | Request::FsList { .. }
            | Request::FsStat { .. }
            | Request::FsRead { .. }
            | Request::GitStatus { .. }
            | Request::GitDiffFile { .. }
            | Request::AttachTerminal { .. }
            | Request::TerminalInput { .. }
            | Request::TerminalResize { .. }
    )
}

fn audit_remote_request(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    kind: &str,
    session_id: Option<Uuid>,
    path: Option<&str>,
    verdict: &str,
) {
    let Some(tag) = principal.tag() else {
        return;
    };
    let result = match path {
        Some(path) => {
            ctx.db
                .insert_remote_audit_with_path(&tag, kind, session_id, verdict, Some(path))
        }
        None => ctx.db.insert_remote_audit(&tag, kind, session_id, verdict),
    };
    if let Err(e) = result {
        tracing::warn!(error = %e, principal = %tag, request_kind = kind, "remote request audit write failed");
    }
}

fn authorize_request(
    request: &Request,
    state: &ClientState,
    ctx: &DaemonContext,
) -> std::result::Result<(), ErrorPayload> {
    let principal = &state.principal;
    if principal.is_owner() {
        return Ok(());
    }

    match request {
        Request::Attach {
            session_id: Some(session_id),
            ..
        } => match ctx.db.get_session(*session_id) {
            Ok(Some(row)) => match session_access_for_row(principal, &row) {
                SessionAccess::Writer | SessionAccess::Readonly => Ok(()),
                SessionAccess::Owner => Ok(()),
                SessionAccess::None => Err(authorization_error(
                    "remote principal cannot access this session",
                )),
            },
            Ok(None) => Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            }),
            Err(e) => Err(internal(e)),
        },
        Request::Attach {
            session_id: None,
            project_root: Some(project_root),
            ..
        } => {
            if principal.can_agent_read_project(project_root) {
                Ok(())
            } else {
                Err(authorization_error(
                    "remote principal cannot create sessions for this project",
                ))
            }
        }
        Request::Attach {
            session_id: None,
            project_root: None,
            ..
        } => Ok(()),
        Request::SubagentTranscript { session_id, .. } => match ctx.db.get_session(*session_id) {
            Ok(Some(row)) => match session_access_for_row(principal, &row) {
                SessionAccess::Writer | SessionAccess::Readonly | SessionAccess::Owner => Ok(()),
                SessionAccess::None => Err(authorization_error(
                    "remote principal cannot access this session",
                )),
            },
            Ok(None) => Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            }),
            Err(e) => Err(internal(e)),
        },

        Request::ListSessions { .. }
        | Request::SessionLiveStatus { .. }
        | Request::DaemonStatus => Ok(()),
        Request::ListSkills { project_root } | Request::GuidanceEstimate { project_root, .. } => {
            if principal.can_agent_read_project(project_root)
                || principal.has_project_files(project_root)
            {
                Ok(())
            } else {
                Err(authorization_error(
                    "remote principal cannot read this project",
                ))
            }
        }
        Request::LspControl { project_root, .. } => {
            if principal.has_terminal() && principal.can_agent_read_project(project_root) {
                Ok(())
            } else {
                Err(authorization_error(
                    "remote principal cannot control project language servers",
                ))
            }
        }

        Request::FsList { project_root, .. }
        | Request::FsStat { project_root, .. }
        | Request::FsRead { project_root, .. }
        | Request::FsWrite { project_root, .. }
        | Request::FsCreateDir { project_root, .. }
        | Request::FsRename { project_root, .. }
        | Request::GitStatus { project_root }
        | Request::GitDiffFile { project_root, .. } => {
            if principal.has_project_files(project_root) {
                Ok(())
            } else {
                Err(authorization_error(
                    "remote principal cannot access project files for this project",
                ))
            }
        }
        Request::FsDelete { .. } => Err(authorization_error("request requires the local owner")),

        Request::OpenTerminal { .. }
        | Request::AttachTerminal { .. }
        | Request::TerminalInput { .. }
        | Request::TerminalResize { .. }
        | Request::CloseTerminal { .. } => {
            if principal.has_terminal() {
                Ok(())
            } else {
                Err(authorization_error(
                    "remote principal cannot access terminals",
                ))
            }
        }

        Request::BeginAttachmentUpload {
            purpose: proto::AttachmentPurpose::TerminalPasteImage { .. },
            ..
        } => {
            if principal.has_terminal() {
                Ok(())
            } else {
                Err(authorization_error(
                    "remote principal cannot paste into terminals",
                ))
            }
        }
        Request::UploadAttachmentChunk { upload_id, .. }
        | Request::FinishAttachmentUpload { upload_id }
        | Request::CancelAttachmentUpload { upload_id }
            if state.pending_uploads.get(upload_id).is_some_and(|upload| {
                matches!(
                    upload.purpose,
                    proto::AttachmentPurpose::TerminalPasteImage { .. }
                )
            }) =>
        {
            if principal.has_terminal() {
                Ok(())
            } else {
                Err(authorization_error(
                    "remote principal cannot paste into terminals",
                ))
            }
        }

        Request::SteerDelegation { session_id, .. } => {
            require_remote_target_session_writer(principal, ctx, *session_id)
        }

        Request::SendUserMessage { .. }
        | Request::BeginAttachmentUpload { .. }
        | Request::UploadAttachmentChunk { .. }
        | Request::FinishAttachmentUpload { .. }
        | Request::CancelAttachmentUpload { .. }
        | Request::RemoveQueuedUserMessage { .. }
        | Request::RemoveNewestQueuedUserMessage { .. }
        | Request::RemoveEditableQueuedUserMessages { .. }
        | Request::ResumePausedWork { .. }
        | Request::CancelPausedWork { .. }
        | Request::RepairResume { .. }
        | Request::CancelTurn
        | Request::ResolveInterrupt { .. }
        | Request::SetActiveModel { .. }
        | Request::SetAgent { .. }
        | Request::SetLlmMode { .. }
        | Request::SetSessionLlmMode { .. }
        | Request::SetApprovalMode { .. }
        | Request::SetDelegationRecursion { .. }
        | Request::CancelSchedule { .. }
        | Request::SetSandbox { .. }
        | Request::SetPreflight { .. }
        | Request::SetTrustedOnly { .. }
        | Request::SetRedaction { .. }
        | Request::SetTandemModels { .. }
        | Request::Prune
        | Request::Compact
        | Request::Pin { .. }
        | Request::RefreshEnv { .. } => require_remote_session_writer(principal, state, ctx),

        Request::ForkSession {
            parent_session_id, ..
        }
        | Request::ArchiveSession {
            session_id: parent_session_id,
            ..
        }
        | Request::UnarchiveSession {
            session_id: parent_session_id,
        }
        | Request::DiscardSession {
            session_id: parent_session_id,
        }
        | Request::RenameSession {
            session_id: parent_session_id,
            ..
        }
        | Request::RecordSessionNote {
            session_id: parent_session_id,
            ..
        }
        | Request::DeleteSession {
            session_id: parent_session_id,
            ..
        } => match ctx.db.get_session(*parent_session_id) {
            Ok(Some(row)) => match session_access_for_row(principal, &row) {
                SessionAccess::Writer | SessionAccess::Owner => Ok(()),
                SessionAccess::Readonly => Err(read_only_error(
                    "remote principal has read-only access to this session",
                )),
                SessionAccess::None => Err(authorization_error(
                    "remote principal cannot access this session",
                )),
            },
            Ok(None) => Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {parent_session_id}"),
            }),
            Err(e) => Err(internal(e)),
        },

        Request::ShareSession { .. }
        | Request::ResourceSnapshot
        | Request::PromoteResource { .. }
        | Request::ListAgents
        | Request::ListModels { .. }
        | Request::SetCaffeinate { .. }
        | Request::StoreFlycockpitCredential { .. }
        | Request::ClearFlycockpitCredential
        | Request::RecordUsage { .. }
        | Request::GetUsageCounts { .. }
        | Request::StopDaemon => Err(authorization_error("request requires the local owner")),
    }
}

fn prune_expired_attachments(state: &mut ClientState) {
    let ttl = Duration::from_secs(proto::PENDING_ATTACHMENT_TTL_SECS);
    let now = Instant::now();
    let expired: Vec<_> = state
        .pending_uploads
        .iter()
        .filter_map(|(upload_id, upload)| {
            (now.duration_since(upload.created_at) > ttl).then_some(*upload_id)
        })
        .collect();
    for upload_id in &expired {
        state.pending_uploads.remove(upload_id);
    }
    release_uploads(&state.upload_accounting, expired);
    state
        .ready_attachments
        .retain(|_, attachment| now.duration_since(attachment.created_at) <= ttl);
}

fn validate_sha256_hex(sha256: &str) -> bool {
    sha256.len() == 64
        && sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    crate::intel::hex_lower(&digest)
}

async fn validate_png_attachment(bytes: Vec<u8>) -> std::result::Result<Vec<u8>, ErrorPayload> {
    tokio::task::spawn_blocking(move || validate_png_attachment_blocking(bytes))
        .await
        .map_err(internal)?
}

fn validate_png_attachment_blocking(bytes: Vec<u8>) -> std::result::Result<Vec<u8>, ErrorPayload> {
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(proto::MAX_IMAGE_DIMENSION_PIXELS);
    limits.max_image_height = Some(proto::MAX_IMAGE_DIMENSION_PIXELS);
    limits.max_alloc = Some(proto::MAX_SINGLE_IMAGE_BYTES as u64);
    let mut reader = image::ImageReader::with_format(
        std::io::Cursor::new(bytes.as_slice()),
        image::ImageFormat::Png,
    );
    reader.limits(limits);
    reader.decode().map_err(|err| match err {
        image::ImageError::Limits(_) => bad_request(format!(
            "attachment PNG exceeds the {} pixel or {} byte decode limit",
            proto::MAX_IMAGE_DIMENSION_PIXELS,
            proto::MAX_SINGLE_IMAGE_BYTES
        )),
        _ => bad_request("attachment is not a valid PNG"),
    })?;
    Ok(bytes)
}

fn begin_attachment_upload(
    state: &mut ClientState,
    mime: String,
    byte_len: usize,
    sha256: String,
    purpose: proto::AttachmentPurpose,
) -> std::result::Result<Response, ErrorPayload> {
    begin_attachment_upload_with_limits(state, mime, byte_len, sha256, purpose, state.upload_limits)
}

fn begin_attachment_upload_with_limits(
    state: &mut ClientState,
    mime: String,
    byte_len: usize,
    sha256: String,
    purpose: proto::AttachmentPurpose,
    limits: AttachmentUploadLimits,
) -> std::result::Result<Response, ErrorPayload> {
    let session_id = match purpose {
        proto::AttachmentPurpose::UserMessageImage => {
            Some(require_attached(state)?.handle.session_id)
        }
        proto::AttachmentPurpose::TerminalPasteImage { terminal_id } => {
            if !state.terminal_host.contains(terminal_id) {
                return Err(bad_request(format!("unknown terminal {terminal_id}")));
            }
            None
        }
    };
    if mime != proto::IMAGE_ATTACHMENT_MIME_PNG {
        return Err(bad_request(format!("unsupported attachment MIME `{mime}`")));
    }
    if byte_len == 0 {
        return Err(bad_request("attachment is empty"));
    }
    if state.pending_uploads.len() >= limits.per_client_uploads {
        return Err(bad_request(format!(
            "too many pending attachment uploads for this client: {} pending, limit {}",
            state.pending_uploads.len(),
            limits.per_client_uploads
        )));
    }
    if byte_len > limits.per_upload_bytes {
        return Err(bad_request(format!(
            "attachment upload is too large: {} bytes exceeds {} byte pending-upload limit",
            byte_len, limits.per_upload_bytes
        )));
    }
    if byte_len > proto::MAX_SINGLE_IMAGE_BYTES {
        return Err(bad_request(format!(
            "image is too large: {} bytes exceeds {} byte limit",
            byte_len,
            proto::MAX_SINGLE_IMAGE_BYTES
        )));
    }
    if !validate_sha256_hex(&sha256) {
        return Err(bad_request(
            "attachment sha256 must be 64 lowercase hex characters",
        ));
    }
    let upload_id = Uuid::new_v4();
    {
        let mut accounting = crate::sync::lock_or_recover(&state.upload_accounting);
        accounting.reserve(upload_id, byte_len, limits)?;
    }
    state.pending_uploads.insert(
        upload_id,
        PendingAttachmentUpload {
            session_id,
            mime,
            byte_len,
            sha256,
            purpose,
            bytes: Vec::with_capacity(byte_len),
            created_at: Instant::now(),
        },
    );
    Ok(Response::AttachmentUploadStarted {
        upload_id,
        max_chunk_base64_bytes: proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES,
    })
}

fn upload_attachment_chunk(
    state: &mut ClientState,
    upload_id: Uuid,
    offset: usize,
    data_base64: String,
) -> std::result::Result<Response, ErrorPayload> {
    let Some(upload) = state.pending_uploads.get_mut(&upload_id) else {
        return Err(bad_request("unknown or expired attachment upload id"));
    };
    if data_base64.len() > proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES {
        return Err(bad_request(format!(
            "attachment chunk is too large: {} base64 bytes exceeds {} byte limit",
            data_base64.len(),
            proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES
        )));
    }
    if offset != upload.bytes.len() {
        return Err(bad_request(format!(
            "attachment chunk offset mismatch: got {offset}, expected {}",
            upload.bytes.len()
        )));
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(data_base64.as_bytes())
        .map_err(|_| bad_request("attachment chunk is not valid base64"))?;
    if upload.bytes.len() + decoded.len() > upload.byte_len {
        return Err(bad_request("attachment chunk exceeds declared byte length"));
    }
    upload.bytes.extend(decoded);
    Ok(Response::AttachmentChunkAccepted {
        upload_id,
        next_offset: upload.bytes.len(),
    })
}

async fn finish_attachment_upload(
    state: &mut ClientState,
    upload_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    let Some(upload) = state.pending_uploads.remove(&upload_id) else {
        return Err(bad_request("unknown or expired attachment upload id"));
    };
    release_uploads(&state.upload_accounting, [upload_id]);
    if upload.bytes.len() != upload.byte_len {
        return Err(bad_request(format!(
            "attachment length mismatch: got {} bytes, expected {}",
            upload.bytes.len(),
            upload.byte_len
        )));
    }
    let actual = sha256_hex(&upload.bytes);
    if actual != upload.sha256 {
        return Err(bad_request("attachment SHA-256 mismatch"));
    }
    let bytes = validate_png_attachment(upload.bytes).await?;
    match upload.purpose {
        proto::AttachmentPurpose::UserMessageImage => {
            let Some(session_id) = upload.session_id else {
                return Err(bad_request(
                    "user-message image upload is missing its session",
                ));
            };
            let image_ref = proto::ImageAttachmentRef { id: Uuid::new_v4() };
            state.ready_attachments.insert(
                image_ref.id,
                ReadyAttachment {
                    session_id,
                    mime: upload.mime,
                    bytes,
                    purpose: upload.purpose,
                    created_at: Instant::now(),
                },
            );
            Ok(Response::AttachmentUploaded { image_ref })
        }
        proto::AttachmentPurpose::TerminalPasteImage { terminal_id } => {
            state.terminal_host.paste_image(terminal_id, &bytes)
        }
    }
}

fn consume_image_refs(
    state: &mut ClientState,
    session_id: Uuid,
    refs: &[proto::ImageAttachmentRef],
) -> std::result::Result<Vec<Vec<u8>>, ErrorPayload> {
    if refs.len() > proto::MAX_IMAGES_PER_USER_MESSAGE {
        return Err(bad_request(format!(
            "too many images: {} exceeds {} image limit",
            refs.len(),
            proto::MAX_IMAGES_PER_USER_MESSAGE
        )));
    }
    let mut seen = HashSet::new();
    for image_ref in refs {
        if !seen.insert(image_ref.id) {
            return Err(bad_request("duplicate image ref in user message"));
        }
    }
    let mut total = 0usize;
    for image_ref in refs {
        let Some(attachment) = state.ready_attachments.get(&image_ref.id) else {
            return Err(bad_request(
                "unknown, expired, or already consumed image ref",
            ));
        };
        if attachment.session_id != session_id {
            return Err(bad_request("image ref belongs to a different session"));
        }
        if attachment.mime != proto::IMAGE_ATTACHMENT_MIME_PNG {
            return Err(bad_request("image ref has unsupported MIME"));
        }
        if attachment.purpose != proto::AttachmentPurpose::UserMessageImage {
            return Err(bad_request("image ref has unsupported purpose"));
        }
        total += attachment.bytes.len();
        if total > proto::MAX_TOTAL_IMAGE_BYTES {
            return Err(bad_request(format!(
                "total image data is too large: {} bytes exceeds {} byte limit",
                total,
                proto::MAX_TOTAL_IMAGE_BYTES
            )));
        }
    }
    let images = refs
        .iter()
        .map(|image_ref| {
            state
                .ready_attachments
                .remove(&image_ref.id)
                .expect("image ref was validated before removal")
                .bytes
        })
        .collect();
    Ok(images)
}

async fn handle_request(
    request: Request,
    state: &mut ClientState,
    ctx: &Arc<DaemonContext>,
) -> std::result::Result<Response, ErrorPayload> {
    prune_expired_attachments(state);
    let request_kind = principal::request_kind(&request);
    let audit_session_id = request_session_id(&request, state);
    let audit_path = request_audit_path(&request);
    let audit_remote = !state.principal.is_owner() && is_remote_mutating_request(&request);
    if let Err(error) = authorize_request(&request, state, ctx) {
        if audit_remote {
            audit_remote_request(
                ctx,
                &state.principal,
                request_kind,
                audit_session_id,
                audit_path.as_deref(),
                "denied",
            );
        }
        return Err(error);
    }
    if audit_remote {
        audit_remote_request(
            ctx,
            &state.principal,
            request_kind,
            audit_session_id,
            audit_path.as_deref(),
            "allowed",
        );
    }
    match request {
        Request::Attach {
            session_id,
            project_root,
            no_sandbox,
            interactive,
            model_override,
            client_protocol_version,
            env_snapshot,
            env_policy,
        } => {
            let principal = state.principal.clone();
            attach(
                state,
                ctx,
                session_id,
                project_root,
                no_sandbox,
                interactive,
                model_override,
                client_protocol_version,
                env_snapshot,
                env_policy,
                &principal,
            )
            .await
        }

        Request::SubagentTranscript {
            session_id,
            task_call_id,
            label,
        } => {
            let db = ctx.db.clone();
            let task_call_id_for_read = task_call_id.clone();
            let label_for_read = label.clone();
            let history = db
                .read(move |conn| {
                    crate::engine::rehydrate::subagent_history_snapshot_conn(
                        conn,
                        session_id,
                        &task_call_id_for_read,
                        &label_for_read,
                    )
                })
                .await
                .map_err(internal)?;
            Ok(Response::SubagentTranscript {
                session_id,
                task_call_id,
                label,
                history,
            })
        }

        Request::SendUserMessage {
            text,
            image_refs,
            forced_skill,
        } => {
            // New-user-work gate (`daemon-graceful-drain-shutdown.md`): once
            // a drain begins, reject new turns with a short notice rather
            // than silently dropping or queuing them. In-flight turns keep
            // running; this only stops *new* work from starting.
            if ctx.shutdown.is_draining() {
                return Err(ErrorPayload {
                    code: ErrorCode::Shutdown,
                    message: "daemon is shutting down; not accepting new messages".into(),
                });
            }
            let session_id = require_attached(state)?.handle.session_id;
            let images = consume_image_refs(state, session_id, &image_refs)?;
            let att = require_attached(state)?;
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::UserMessage {
                    submission: Box::new(crate::engine::message::UserSubmission {
                        kind: crate::engine::message::UserSubmissionKind::User,
                        text,
                        images,
                        forced_skill,
                        origin_principal: state.principal.tag(),
                        job_id: None,
                        preflight_cleaned: None,
                        queue_item_ids: Vec::new(),
                        queue_target: None,
                    }),
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let (item, queue) = response_rx.await.map_err(internal)?;
            Ok(Response::UserMessageQueued { item, queue })
        }

        Request::SteerDelegation {
            session_id,
            task_call_id,
            label,
            message,
        } => {
            let Some(handle) = ctx.registry.live_handle(session_id) else {
                return Ok(Response::DelegationSteer {
                    result: proto::DelegationSteerResult::not_steerable(
                        task_call_id,
                        Some(label),
                        "session is not live".to_string(),
                    ),
                });
            };
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            handle
                .send_work(SessionWork::SteerDelegation {
                    task_call_id,
                    label,
                    message,
                    origin_principal: state.principal.steer_origin(),
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let result = response_rx.await.map_err(internal)?;
            Ok(Response::DelegationSteer { result })
        }

        Request::BeginAttachmentUpload {
            mime,
            byte_len,
            sha256,
            purpose,
        } => begin_attachment_upload(state, mime, byte_len, sha256, purpose),

        Request::UploadAttachmentChunk {
            upload_id,
            offset,
            data_base64,
        } => upload_attachment_chunk(state, upload_id, offset, data_base64),

        Request::FinishAttachmentUpload { upload_id } => {
            finish_attachment_upload(state, upload_id).await
        }

        Request::CancelAttachmentUpload { upload_id } => {
            if state.pending_uploads.remove(&upload_id).is_some() {
                release_uploads(&state.upload_accounting, [upload_id]);
            }
            Ok(Response::Ack)
        }

        Request::RemoveQueuedUserMessage { queue_item_id } => {
            let att = require_attached(state)?;
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::RemoveQueuedUserMessage {
                    queue_item_id,
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let result = response_rx.await.map_err(internal)?;
            Ok(Response::RemoveQueuedUserMessageResult {
                applied: result.applied,
                reason: result.reason,
                removed_item: result.removed_item,
                queue: result.queue,
            })
        }
        Request::RemoveNewestQueuedUserMessage { target_id } => {
            let att = require_attached(state)?;
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::RemoveNewestQueuedUserMessage {
                    target_id,
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let result = response_rx.await.map_err(internal)?;
            Ok(Response::RemoveQueuedUserMessageResult {
                applied: result.applied,
                reason: result.reason,
                removed_item: result.removed_item,
                queue: result.queue,
            })
        }
        Request::RemoveEditableQueuedUserMessages { target_id } => {
            let att = require_attached(state)?;
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::RemoveEditableQueuedUserMessages {
                    target_id,
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let result = response_rx.await.map_err(internal)?;
            Ok(Response::RemoveQueuedUserMessagesResult {
                applied: result.applied,
                reason: result.reason,
                removed_items: result.removed_items,
                queue: result.queue,
            })
        }

        Request::ResumePausedWork { session_id } => {
            let changed = ctx
                .db
                .mark_paused_session_work_resumed(session_id)
                .map_err(internal)?;
            if changed
                && let Some(att) = state.attached.as_ref()
                && att.handle.session_id == session_id
            {
                att.handle.broadcast_notice(
                    "paused work resumed; pending approvals will use the normal prompt flow"
                        .to_string(),
                );
            }
            Ok(Response::Ack)
        }

        Request::CancelPausedWork { session_id } => {
            let changed = ctx
                .db
                .cancel_paused_session_work(session_id)
                .map_err(internal)?;
            if changed {
                if let Err(e) = ctx.registry.locks().suspend_session(session_id) {
                    tracing::warn!(error = %e, %session_id, "releasing cancelled paused work locks failed");
                }
                if let Some(att) = state.attached.as_ref()
                    && att.handle.session_id == session_id
                {
                    att.handle.broadcast_notice(
                        "paused work cancelled; the session is waiting for new input".to_string(),
                    );
                }
            }
            Ok(Response::Ack)
        }

        Request::RepairResume { session_id } => {
            let att = require_attached(state)?;
            if att.handle.session_id != session_id {
                return Err(ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: "repair_resume session_id does not match the attached session".into(),
                });
            }
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::RepairResume { respond_to })
                .await
                .map_err(internal)?;
            match response_rx.await.map_err(internal)? {
                Ok(()) => Ok(Response::Ack),
                Err(message) => Err(ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message,
                }),
            }
        }

        Request::CancelTurn => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::Cancel)
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::FsList {
            project_root,
            path,
            show_hidden,
        } => crate::daemon::fs_api::fs_list(&state.principal, &project_root, &path, show_hidden),

        Request::FsStat { project_root, path } => {
            crate::daemon::fs_api::fs_stat(&state.principal, &project_root, &path)
        }

        Request::FsRead {
            project_root,
            path,
            base64,
        } => crate::daemon::fs_api::fs_read(&state.principal, &project_root, &path, base64),

        Request::FsWrite {
            project_root,
            path,
            content,
            base_hash,
        } => crate::daemon::fs_api::fs_write(ctx, &project_root, &path, &content, base_hash),

        Request::FsCreateDir { project_root, path } => {
            crate::daemon::fs_api::fs_create_dir(&project_root, &path)
        }

        Request::FsRename {
            project_root,
            from_path,
            to_path,
        } => crate::daemon::fs_api::fs_rename(ctx, &project_root, &from_path, &to_path),

        Request::FsDelete { project_root, path } => {
            crate::daemon::fs_api::fs_delete(ctx, &project_root, &path)
        }

        Request::GitStatus { project_root } => crate::daemon::fs_api::git_status(&project_root),

        Request::GitDiffFile { project_root, path } => {
            crate::daemon::fs_api::git_diff_file(&project_root, &path)
        }

        Request::OpenTerminal { cwd, cols, rows } => {
            let response = state.terminal_host.open(cwd, cols, rows)?;
            if let Response::TerminalOpened { terminal_id, .. } = response {
                state.terminal_views.insert(terminal_id);
                Ok(Response::TerminalOpened {
                    terminal_id,
                    viewer_count: 1,
                    recording: false,
                })
            } else {
                Ok(response)
            }
        }

        Request::AttachTerminal {
            terminal_id,
            cols,
            rows,
        } => {
            let response = state.terminal_host.attach(terminal_id, cols, rows)?;
            state.terminal_views.insert(terminal_id);
            Ok(response)
        }

        Request::TerminalInput { terminal_id, bytes } => {
            state.terminal_host.input(terminal_id, bytes)
        }

        Request::TerminalResize {
            terminal_id,
            cols,
            rows,
        } => state.terminal_host.resize(terminal_id, cols, rows),

        Request::CloseTerminal { terminal_id } => {
            state.terminal_views.remove(&terminal_id);
            state.terminal_host.close(terminal_id)
        }

        Request::LspControl {
            project_root,
            server_id,
            action,
        } => {
            let att = require_attached(state)?;
            let cwd = Path::new(&project_root);
            let config = crate::config::trust::with_workspace_trust_policy(
                att.handle.trust_policy.clone(),
                || crate::config::extended::load_for_cwd(cwd),
            );
            let message = ctx
                .registry
                .lsp_manager()
                .control(cwd, &server_id, action, &config)
                .await;
            att.handle.broadcast_notice(message.clone());
            Ok(Response::LspControlResult { message })
        }

        Request::ResolveInterrupt {
            interrupt_id,
            response,
        } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::ResolveInterrupt {
                    interrupt_id,
                    response,
                })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::ListSessions {
            project_id,
            parent_session_id,
        } => list_sessions(ctx, &state.principal, project_id, parent_session_id).await,

        Request::SessionLiveStatus { session_ids } => {
            let mut visible_ids = Vec::new();
            for id in session_ids {
                if state.principal.is_owner() {
                    visible_ids.push(id);
                    continue;
                }
                match ctx.db.get_session(id) {
                    Ok(Some(row))
                        if session_access_for_row(&state.principal, &row)
                            != SessionAccess::None =>
                    {
                        visible_ids.push(id);
                    }
                    Ok(_) => {}
                    Err(e) => return Err(internal(e)),
                }
            }
            let statuses = visible_ids
                .into_iter()
                .filter_map(|id| {
                    ctx.registry
                        .live_status(id)
                        .map(|(has_active_schedules, processing)| proto::LiveStatus {
                            session_id: id,
                            has_active_schedules,
                            processing,
                        })
                })
                .collect();
            Ok(Response::SessionLiveStatus { statuses })
        }

        Request::ArchiveSession {
            session_id,
            cascade,
        } => archive_session(ctx, session_id, cascade).await,

        Request::UnarchiveSession { session_id } => unarchive_session(ctx, session_id),

        Request::ForkSession {
            parent_session_id,
            fork_point_turn_id,
            ephemeral,
        } => fork_session(
            ctx,
            &state.principal,
            parent_session_id,
            fork_point_turn_id,
            ephemeral,
        ),

        Request::DiscardSession { session_id } => discard_session(state, ctx, session_id).await,

        Request::RenameSession { session_id, title } => rename_session(ctx, session_id, &title),

        Request::ShareSession { session_id, shared } => {
            ctx.db
                .set_session_shared_with_collaborators(session_id, shared)
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::RecordSessionNote { session_id, text } => {
            record_session_note(ctx, session_id, &text)
        }

        Request::DeleteSession {
            session_id,
            cascade,
        } => delete_session(ctx, session_id, cascade).await,

        Request::ListSkills { project_root } => {
            // Resolve the configured scan dirs from the client's cwd so
            // per-project skills config applies, then run the shared
            // discovery used by the `skill` tool and auto-select path.
            let att = require_attached(state)?;
            let cwd = Path::new(&project_root);
            let extended = crate::config::trust::with_workspace_trust_policy(
                att.handle.trust_policy.clone(),
                || crate::config::extended::load_for_cwd(cwd),
            );
            let skills = crate::skills::discover(cwd, &extended.skills).map_err(internal)?;
            let skills = skills
                .into_iter()
                .map(|s| proto::SkillSummary {
                    name: s.frontmatter.name,
                    description: s.frontmatter.description,
                    source: s.source.display().to_string(),
                })
                .collect();
            Ok(Response::Skills { skills })
        }
        Request::ResourceSnapshot => Ok(Response::ResourceSnapshot {
            snapshot: resource_scheduler_snapshot(ctx),
        }),
        Request::PromoteResource {
            request_id,
            session_id,
        } => promote_resource_request(ctx, &request_id, session_id),

        Request::ListAgents => Err(not_implemented("ListAgents")),
        Request::ListModels { .. } => Err(not_implemented("ListModels")),

        Request::SetActiveModel { provider, model } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetActiveModel { provider, model })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetAgent { name } => {
            let att = require_attached(state)?;
            validate_set_agent(att, &name)?;
            att.handle
                .send_work(SessionWork::SetAgent { name })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetLlmMode { mode } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetLlmMode { mode })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetSessionLlmMode { mode } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetSessionLlmMode { mode })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetApprovalMode { mode } => {
            let att = require_attached(state)?;
            let mode = att.handle.set_approval_mode(mode);
            Ok(Response::ApprovalModeState { mode })
        }

        Request::SetDelegationRecursion {
            enabled,
            default_depth,
        } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetDelegationRecursion {
                    enabled,
                    default_depth,
                })
                .await
                .map_err(internal)?;
            Ok(Response::DelegationRecursionState {
                enabled,
                default_depth,
            })
        }

        Request::SetCaffeinate { mode } => set_caffeinate(state, ctx, mode),

        Request::CancelSchedule { job_id } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::CancelSchedule { job_id })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetSandbox {
            mode,
            container_network_enabled,
        } => {
            // Flip the session's sandbox mode directly (it's a shared
            // atomic) and reply with the resulting state. The handle also
            // broadcasts a `SandboxState` event so every attached client
            // stays in sync.
            let att = require_attached(state)?;
            let new = att
                .handle
                .set_sandbox(mode, container_network_enabled)
                .map_err(bad_request)?;
            Ok(Response::SandboxState {
                mode: new,
                enabled: new.enabled(),
                container_network_enabled: att.handle.container_network_enabled(),
                container_availability: crate::container::availability_snapshot(),
            })
        }

        Request::SetPreflight { enabled } => {
            // `/preflight`: route to the worker, which sets the session-only
            // override on the driver (precedence over config), and broadcasts
            // the resulting state (→ toast + mirror). Session-only — no
            // config-file write.
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetPreflight { enabled })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetTrustedOnly { enabled } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetTrustedOnly { enabled })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetRedaction {
            scan_environment,
            scan_dotenv,
            scan_ssh_keys,
        } => {
            // `/toggle-redaction`: route to the worker, which mutates the
            // session's effective `RedactConfig` in memory, rebuilds the
            // redaction table for subsequent outbound prompts, and
            // broadcasts the resulting state (→ toast). Session-only — no
            // config-file write. `scrub()` stays non-bypassable.
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetRedaction {
                    scan_environment,
                    scan_dotenv,
                    scan_ssh_keys,
                })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetTandemModels { models } => {
            // `/model-comparison`: route to the worker, which builds a
            // completion model for each selected `(provider, model)`, replaces
            // the driver's in-memory tandem set, and broadcasts the resulting
            // state (+ token-burn warning) via `Event::TandemState`.
            // Session-only — no config-file write.
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetTandemModels { models })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::Prune => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::Prune)
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::Compact => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::Compact)
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::Pin { text } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::Pin { text })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::StoreFlycockpitCredential { credential } => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept Flycockpit credential writes",
                ));
            }
            crate::auth::flycockpit::store_credential(&credential).map_err(internal)?;
            ctx.wake_connector();
            Ok(Response::Ack)
        }

        Request::ClearFlycockpitCredential => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept Flycockpit credential writes",
                ));
            }
            crate::auth::flycockpit::clear_credential().map_err(internal)?;
            ctx.wake_connector();
            Ok(Response::Ack)
        }

        Request::DaemonStatus => Ok(Response::DaemonStatus {
            pid: std::process::id(),
            uptime_secs: ctx.started_at.elapsed().as_secs(),
            active_sessions: ctx.registry.active_session_ids().len() as u32,
            socket_path: ctx.paths.socket.display().to_string(),
            daemon_version: proto::DAEMON_VERSION.to_string(),
            protocol_version: proto::PROTOCOL_VERSION,
            paused_sessions: ctx.db.paused_session_work_all().map_err(internal)?.len() as u32,
        }),

        Request::RefreshEnv { vars } => {
            let att = require_attached(state)?;
            att.handle.set_env_overlay(vars);
            Ok(Response::Ack)
        }

        Request::RecordUsage {
            kind,
            key,
            project_id,
        } => {
            // Global tally — no attached session required.
            ctx.db
                .record_usage(
                    kind.as_str(),
                    &key,
                    project_id.as_deref(),
                    chrono::Utc::now().timestamp(),
                )
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::GetUsageCounts { project_id } => {
            let since = chrono::Utc::now().timestamp() - crate::db::usage_events::USAGE_WINDOW_SECS;
            let models = ctx
                .db
                .usage_counts("model", None, since)
                .map_err(internal)?;
            let slash = ctx
                .db
                .usage_counts("slash", None, since)
                .map_err(internal)?;
            // Tags are per-project; with no project there's nothing to
            // scope to, so the map is empty rather than a global mash-up.
            let tags = match project_id.as_deref() {
                Some(pid) => ctx
                    .db
                    .usage_counts("tag", Some(pid), since)
                    .map_err(internal)?,
                None => std::collections::HashMap::new(),
            };
            Ok(Response::UsageCounts {
                models,
                slash,
                tags,
            })
        }

        Request::GuidanceEstimate {
            project_root,
            provider,
            model,
        } => {
            // Resolve the single guidance file the engine would load and
            // estimate, with the calibrated tokenizer for the active model
            // (cl100k fallback when uncalibrated), two figures: the
            // guidance-file body (the `… in <file>` label) and the full
            // composed system prompt (the fresh-context baseline the
            // running estimate folds in). No session exists yet at the
            // fresh-chat indicator, so the system prompt omits the
            // `Session:` line — matching what the engine then sends.
            let cwd = Path::new(&project_root);
            let (strategy, scale) = ctx.db.resolve_tokenizer(
                provider.as_deref().unwrap_or(""),
                model.as_deref().unwrap_or(""),
            );
            let system_prompt = crate::engine::builtin::default_chat_system_prompt(cwd, "");
            let system_tokens = crate::tokens::scaled_estimate(&system_prompt, strategy, scale);
            match crate::engine::builtin::load_agent_guidance(cwd) {
                Some((path, body)) => {
                    let tokens = crate::tokens::scaled_estimate(&body, strategy, scale);
                    let file = path.file_name().map(|n| n.to_string_lossy().into_owned());
                    Ok(Response::GuidanceEstimate {
                        file,
                        tokens,
                        system_tokens,
                    })
                }
                None => Ok(Response::GuidanceEstimate {
                    file: None,
                    tokens: 0,
                    system_tokens,
                }),
            }
        }

        Request::StopDaemon => {
            tracing::info!("StopDaemon requested via client");
            // Route through the single graceful-shutdown path
            // (`daemon-graceful-drain-shutdown.md`): the same begin-drain /
            // shorten-to-force transition SIGINT/SIGTERM and the ephemeral
            // teardown use. A second `StopDaemon` while already draining
            // shortens to an immediate force-exit instead of starting a
            // second drain or resetting the deadline.
            request_shutdown(ctx);
            Ok(Response::Ack)
        }
    }
}

// ---- shutdown -------------------------------------------------------------

/// The single entry point every stop trigger (SIGINT/SIGTERM, explicit
/// `StopDaemon`, the ephemeral last-client/owner-exit teardown) routes
/// through (`daemon-graceful-drain-shutdown.md`).
///
/// First call begins the drain: it broadcasts the `DaemonDraining { forced:
/// false }` notice (TUIs show "finishing in-flight work, shutting down…"
/// and start refusing new input) and flips the central gate so the
/// inference-dispatch chokepoint refuses new provider requests. A *second*
/// call while already draining **shortens** to an immediate force-exit —
/// it promotes the gate to `Forced` and broadcasts `DaemonDraining { forced:
/// true }`. Both transitions are monotonic/idempotent, so a redundant
/// trigger never starts a second drain, resets the deadline, or deadlocks.
pub fn request_shutdown(ctx: &Arc<DaemonContext>) {
    if ctx.shutdown.begin_drain() {
        tracing::info!("daemon: graceful drain begun");
        ctx.broadcast_global(proto::Event::DaemonDraining { forced: false });
    } else if !ctx.shutdown.is_forced() {
        // Already draining and a second trigger arrived: shorten to force.
        ctx.shutdown.force();
        tracing::warn!("daemon: second stop request during drain; forcing exit");
        ctx.broadcast_global(proto::Event::DaemonDraining { forced: true });
    }
}

// ---- helpers --------------------------------------------------------------

/// Apply a `/caffeinate` request: resolve the display-awake scope from
/// config, drive the daemon-held [`CaffeineController`], broadcast the
/// resulting state to **all** clients, and (for `until-idle`) arm the
/// daemon's auto-off watcher. The OS assertion lives in this process so it
/// survives the requesting client's exit.
fn set_caffeinate(
    state: &ClientState,
    ctx: &Arc<DaemonContext>,
    mode: crate::daemon::caffeinate::CaffeinateMode,
) -> std::result::Result<Response, ErrorPayload> {
    use crate::daemon::caffeinate::InhibitScope;

    // Display-awake is a config setting; resolve it from the attached
    // session's project root when available, else the daemon's cwd.
    let attached_policy = state
        .attached
        .as_ref()
        .map(|att| att.handle.trust_policy.clone());
    let cfg_root = state
        .attached
        .as_ref()
        .map(|att| att.handle.project_root.clone())
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let configs = match attached_policy {
        Some(policy) => load_configs_with_trust(&cfg_root, &policy),
        None => load_configs(&cfg_root),
    };
    let scope: InhibitScope = match configs {
        Ok((_, extended)) => extended.tui.sleep_scope().into(),
        // Config read failure must not block caffeination: fall back to
        // the safe default (system-only, display free to sleep).
        Err(_) => InhibitScope {
            keep_display_on: false,
        },
    };

    match ctx.caffeinate.apply(mode, scope) {
        Ok(applied) => {
            // Broadcast to every client so the ☕ glyph stays in sync.
            ctx.broadcast_global(proto::Event::CaffeinateState {
                active: applied.state.active,
                lid_close_guaranteed: applied.lid_close_guaranteed,
                message: None,
            });
            // Arm the daemon-owned until-idle watcher: it polls "is any
            // agent running?" and auto-offs once none are.
            if applied.state.until_idle {
                spawn_until_idle_watcher(ctx.clone());
            }
            Ok(Response::CaffeinateState {
                active: applied.state.active,
                lid_close_guaranteed: applied.lid_close_guaranteed,
                message: applied.message,
            })
        }
        // Missing-mechanism / acquire failure: report it so the TUI shows
        // an honest, actionable toast (never silent). State stays off.
        Err(message) => Ok(Response::CaffeinateState {
            active: false,
            lid_close_guaranteed: false,
            message,
        }),
    }
}

/// Poll interval for the until-idle auto-off watcher. Short enough that
/// the machine doesn't stay awake long after the last agent finishes,
/// long enough to be negligible overhead.
const UNTIL_IDLE_POLL: std::time::Duration = std::time::Duration::from_secs(5);

/// Spawn the daemon's `until-idle` auto-off watcher. The daemon owns the
/// session workers / `ScheduleAuthority`, so it is the authority for "is an
/// agent running anywhere?". The watcher polls that and, once no agent is
/// running, releases the assertion and broadcasts the off-state to all
/// clients. It exits if the mode is no longer until-idle (a later
/// `on`/`off`/`toggle` superseded it) so a fresh `until-idle` can re-arm
/// without stacking watchers racing each other.
fn spawn_until_idle_watcher(ctx: Arc<DaemonContext>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(UNTIL_IDLE_POLL).await;
            // Superseded (explicit on/off, or already auto-offed): stop.
            if !ctx.caffeinate.is_until_idle() {
                return;
            }
            let running = ctx.registry.any_agent_running();
            if let Some(applied) = ctx.caffeinate.idle_check(running) {
                ctx.broadcast_global(proto::Event::CaffeinateState {
                    active: applied.state.active,
                    lid_close_guaranteed: applied.lid_close_guaranteed,
                    message: None,
                });
                return;
            }
        }
    });
}

/// Poll interval for the idle-lock sweeper. Short relative to
/// [`crate::locks::LOCK_IDLE_TIMEOUT`] (5 min) so a reclaimable lock is
/// freed within a few seconds of crossing the threshold, but coarse enough
/// to be negligible overhead.
const LOCK_SWEEP_POLL: std::time::Duration = std::time::Duration::from_secs(10);

/// Spawn the daemon's idle-lock sweeper
/// (implementation note). On each tick it asks the
/// single lock authority to reclaim any lock whose holder has been idle
/// past [`crate::locks::LOCK_IDLE_TIMEOUT`] — releasing it, invalidating the
/// §3c read-record, persisting the release, and waking blocked `readlock`
/// waiters so they proceed. Modeled on [`spawn_until_idle_watcher`]; runs
/// for the daemon's lifetime and exits when the daemon drains.
pub(crate) fn spawn_lock_sweeper(ctx: Arc<DaemonContext>) {
    let locks = ctx.registry.locks();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(LOCK_SWEEP_POLL).await;
            if ctx.shutdown.is_draining() {
                return;
            }
            let now = chrono::Utc::now().timestamp();
            match locks.sweep_expired(now) {
                Ok(reclaimed) if !reclaimed.is_empty() => {
                    tracing::info!(count = reclaimed.len(), "swept idle-expired locks");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "idle-lock sweep failed"),
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn attach(
    state: &mut ClientState,
    ctx: &DaemonContext,
    session_id: Option<Uuid>,
    project_root: Option<String>,
    no_sandbox: bool,
    interactive: bool,
    model_override: Option<String>,
    client_protocol_version: u32,
    env_snapshot: Option<EnvSnapshotWire>,
    env_policy: EnvDriftPolicy,
    principal: &ClientPrincipal,
) -> std::result::Result<Response, ErrorPayload> {
    // The client's `--no-sandbox` only governs sessions it *creates*
    // (sandboxing part 2). On resume of an existing session id the session
    // keeps its own runtime state, so the flag is ignored there.
    let client_no_sandbox = no_sandbox && session_id.is_none();
    // The plan-level model override (`cockpit run --model`) governs only
    // sessions this attach *creates*; on resume the worker is already
    // running, so the flag is ignored (mirrors `--no-sandbox`).
    let model_override = model_override.filter(|_| session_id.is_none());
    let project_root = project_root.map(PathBuf::from);

    let cfg_root = match (session_id, &project_root) {
        (Some(id), _) => match ctx.db.get_session(id) {
            Ok(Some(row)) => Some(PathBuf::from(row.project_root)),
            Ok(None) => {
                return Err(ErrorPayload {
                    code: ErrorCode::UnknownSession,
                    message: format!("unknown session {id}"),
                });
            }
            Err(e) => return Err(internal(e)),
        },
        (None, Some(root)) => Some(root.clone()),
        (None, None) => {
            return Err(ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "attach requires session_id or project_root".into(),
            });
        }
    };

    let cfg_root = cfg_root.expect("resolved above");
    let remote_readonly_attach = !principal.is_owner()
        && !principal.can_agent_write_project(&cfg_root.to_string_lossy())
        && principal.can_agent_read_project(&cfg_root.to_string_lossy());
    let client_no_sandbox = client_no_sandbox && !remote_readonly_attach;
    let trust_policy =
        crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &cfg_root)
            .map_err(internal)?;
    let (providers_cfg, extended_cfg) =
        load_configs_with_trust(&cfg_root, &trust_policy).map_err(internal)?;
    let client_snapshot = env_snapshot.map(EnvSnapshot::from_wire);
    let (session_env, env_baseline_meta, env_session_meta, env_drift, env_policy_applied) =
        select_session_env(ctx, client_snapshot, env_policy)?;

    let handle = ctx
        .registry
        .attach(
            session_id,
            project_root,
            &providers_cfg,
            &extended_cfg,
            client_no_sandbox,
            model_override.as_deref(),
            trust_policy,
            session_env,
        )
        .await
        .map_err(internal)?;

    if session_id.is_none()
        && let Some(tag) = principal.tag()
    {
        handle
            .set_created_by_principal(Some(tag))
            .map_err(internal)?;
    }
    if remote_readonly_attach {
        let _ = handle.set_sandbox(Some(crate::tools::sandbox_mode::SandboxMode::Sandbox), None);
        handle.set_approval_mode(crate::config::extended::ApprovalMode::Manual);
    }

    // Replace any prior attachment. Register this client with the worker's
    // interactive-client counter when it can answer interrupts (the loop
    // guard reads that count for headless detection). Building the guard
    // before the old `state.attached` is replaced means a re-attach by the
    // same client transiently holds two guards, never zero — the count
    // can't briefly read headless mid-swap.
    let event_rx = handle.subscribe();
    let interactive_guard = if interactive {
        Some(handle.register_interactive_client())
    } else {
        None
    };
    let session_id = handle.session_id;

    // Read/unread marker (GOALS §17f): the session just became active for
    // this client, so everything the agent produced up to now is "seen."
    // Best-effort — a marker write failure must not block the attach.
    if let Err(e) = handle.mark_viewed() {
        tracing::warn!(error = %e, %session_id, "mark_session_viewed failed");
    }

    let foreground = handle.foreground_snapshot();
    let project_root = handle.project_root.to_string_lossy().into_owned();
    let active_agent = foreground
        .active_agent_path
        .last()
        .cloned()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| handle.active_agent_name.clone());
    // Source identity from the live session, not a DB read: a freshly
    // created session is deferred-persistence (session-id-display-and-lazy-
    // persist) and has no `sessions` row yet, so `get_session` would miss.
    let project_id = handle.project_id();
    let short_id = handle.short_id();

    state.pending_uploads.clear();
    state.ready_attachments.clear();
    state.upload_limits = extended_cfg.daemon.uploads.into();
    state.attached = Some(AttachedSession {
        handle,
        event_rx,
        _interactive_guard: interactive_guard,
    });

    // Hydrate the gitignore read-allowlist for this client
    // (implementation note): broadcast the session's
    // current session-approved globs over the per-session bus so a late-opened
    // or reconnecting TUI — and any second concurrent client — re-includes
    // approvals made before it attached, not only ones broadcast live
    // afterward. The just-subscribed `event_rx` receives it; full-list replace,
    // idempotent for already-attached clients. Only the allow-set is sent.
    if let Some(att) = state.attached.as_ref() {
        att.handle.broadcast_gitignore_allow();
    }

    // Full chronological history snapshot (user messages + assistant turns +
    // tool calls) for the attached session, so a resuming TUI repopulates the
    // whole prior transcript (implementation note). Run the
    // scan-shaped attach reads on one blocking DB worker and one mutex
    // acquisition, while preserving the single history projection source.
    let db = ctx.db.clone();
    let extended_cfg_for_attach = extended_cfg.clone();
    let active_subagent_for_attach = foreground.active_subagent.clone();
    let (history, paused_work): (Vec<proto::HistoryEntry>, Vec<proto::PausedWorkSummary>) = db
        .read(move |conn| {
            let root_agent = crate::daemon::session_worker::resolve_root_agent_conn(
                conn,
                session_id,
                &extended_cfg_for_attach,
            );
            let history = crate::engine::rehydrate::history_snapshot_with_active_subagent_conn(
                conn,
                session_id,
                &root_agent,
                active_subagent_for_attach.as_ref(),
            )
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, %session_id, "building attach history snapshot failed; sending empty history");
                Vec::new()
            });
            let paused_work = crate::db::Db::paused_session_work_conn(conn, session_id)?
                .into_iter()
                .map(paused_work_to_proto)
                .collect();
            Ok((history, paused_work))
        })
        .await
        .map_err(internal)?;
    if !paused_work.is_empty()
        && let Some(att) = state.attached.as_ref()
    {
        att.handle.broadcast_notice(
            "paused work is waiting for resume or cancel after daemon restart".to_string(),
        );
    }

    let history = if let Some(att) = state.attached.as_ref() {
        let redact = att.handle.redaction_table();
        scrub_history_for_principal(&state.principal, history, &redact)
    } else {
        history
    };

    Ok(Response::Attached {
        session_id,
        short_id,
        project_root,
        project_id,
        active_agent,
        active_agent_path: foreground.active_agent_path,
        foreground_target: Some(foreground.foreground_target),
        active_subagent: foreground.active_subagent,
        history,
        paused_work,
        repair_required: state
            .attached
            .as_ref()
            .and_then(|att| att.handle.repair_required())
            .map(Box::new),
        daemon_version: proto::DAEMON_VERSION.to_string(),
        compatible: proto::is_protocol_compatible(client_protocol_version),
        env_baseline: Some(env_baseline_meta),
        env_session: Some(env_session_meta),
        env_drift: env_drift.map(Box::new),
        env_policy_applied,
    })
}

fn select_session_env(
    ctx: &DaemonContext,
    client_snapshot: Option<EnvSnapshot>,
    policy: EnvDriftPolicy,
) -> std::result::Result<
    (
        EnvSnapshot,
        EnvSnapshotMeta,
        EnvSnapshotMeta,
        Option<EnvDiffSummary>,
        EnvDriftPolicy,
    ),
    ErrorPayload,
> {
    let Some(client_snapshot) = client_snapshot else {
        let baseline = ctx
            .env_baseline
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let meta = baseline.meta();
        return Ok((baseline, meta.clone(), meta, None, EnvDriftPolicy::Daemon));
    };

    let baseline = ctx
        .env_baseline
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let drift = diff_summary(&baseline, &client_snapshot).filter(EnvDiffSummary::meaningful);
    if matches!(policy, EnvDriftPolicy::ErrorOnDrift) && drift.is_some() {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "client environment differs from daemon baseline".to_string(),
        });
    }

    let chosen = match policy {
        EnvDriftPolicy::Daemon | EnvDriftPolicy::ErrorOnDrift => baseline.clone(),
        EnvDriftPolicy::Client => client_snapshot.clone(),
        EnvDriftPolicy::UpdateDaemon => {
            {
                let mut guard = ctx
                    .env_baseline
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                *guard = client_snapshot.clone();
            }
            client_snapshot.clone()
        }
    };
    let baseline_meta = if matches!(policy, EnvDriftPolicy::UpdateDaemon) {
        client_snapshot.meta()
    } else {
        baseline.meta()
    };
    let session_meta = chosen.meta();
    if matches!(policy, EnvDriftPolicy::Daemon)
        && let Some(diff) = drift.clone()
    {
        ctx.broadcast_global(proto::Event::EnvDriftWarning {
            baseline: baseline.meta(),
            candidate: client_snapshot.meta(),
            diff,
            policy,
        });
    }
    Ok((chosen, baseline_meta, session_meta, drift, policy))
}

fn paused_work_to_proto(row: crate::db::paused_work::PausedWorkRow) -> proto::PausedWorkSummary {
    proto::PausedWorkSummary {
        session_id: row.session_id,
        active_agent: row.active_agent,
        project_root: row.project_root,
        reason: row.reason,
        pending_tool_count: row.pending_tool_count,
        daemon_version: row.daemon_version,
        client_version: row.client_version,
        updated_at: row.updated_at,
    }
}

async fn list_sessions(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    project_id: Option<String>,
    parent_session_id: Option<Uuid>,
) -> std::result::Result<Response, ErrorPayload> {
    // The row assembly (level selection, fork counts, read/unread inputs)
    // lives in one place — `Db::list_session_summaries` — so the daemon
    // and the TUI's daemonless direct-DB fallback produce the same shape
    // (ordering / scoping / fork-grouping). Live status is layered on by
    // the client via `SessionLiveStatus`, not here.
    let db = ctx.db.clone();
    let mut sessions = db
        .read(move |conn| {
            crate::db::Db::list_session_summaries_conn(
                conn,
                project_id.as_deref(),
                parent_session_id,
                100,
            )
        })
        .await
        .map_err(internal)?;
    if !principal.is_owner() {
        sessions.retain(|summary| {
            session_access_for_summary(principal, summary) != SessionAccess::None
        });
    }
    Ok(Response::Sessions { sessions })
}

fn resource_scheduler_snapshot(
    ctx: &DaemonContext,
) -> crate::engine::resource_scheduler::ResourceSchedulerSnapshot {
    ctx.registry
        .resource_scheduler()
        .map(|scheduler| scheduler.snapshot())
        .unwrap_or_else(|| {
            crate::engine::resource_scheduler::ResourceScheduler::disabled().snapshot()
        })
}

fn promote_resource_request(
    ctx: &DaemonContext,
    request_id: &str,
    fallback_session_id: Option<Uuid>,
) -> std::result::Result<Response, ErrorPayload> {
    use crate::engine::resource_scheduler::ResourcePromoteError;

    let Some(scheduler) = ctx.registry.resource_scheduler() else {
        let snapshot = resource_scheduler_snapshot(ctx);
        return Ok(Response::PromoteResourceResult {
            status: proto::ResourcePromoteStatus::Disabled,
            message: "resource scheduler is disabled for this daemon".to_string(),
            snapshot,
        });
    };

    let token = request_id.trim();
    let before = scheduler.snapshot();
    let running_match = before
        .running
        .iter()
        .find(|entry| entry.display_id == token || entry.id.to_string() == token);
    if let Some(entry) = running_match {
        let message = format!(
            "resource request {} is already running; running work cannot be promoted",
            entry.display_id
        );
        record_resource_promotion(
            ctx,
            Some(entry.metadata.session_id).flatten(),
            token,
            false,
            &message,
        );
        return Ok(Response::PromoteResourceResult {
            status: proto::ResourcePromoteStatus::NotQueued,
            message,
            snapshot: before,
        });
    }

    let queued_match = before
        .queued
        .iter()
        .find(|entry| entry.display_id == token || entry.id.to_string() == token);
    let promote_id = queued_match
        .map(|entry| entry.id)
        .or_else(|| Uuid::parse_str(token).ok());
    let audit_session_id = queued_match
        .and_then(|entry| entry.metadata.session_id)
        .or(fallback_session_id);

    let Some(promote_id) = promote_id else {
        let message = format!("resource request `{token}` is no longer queued");
        record_resource_promotion(ctx, audit_session_id, token, false, &message);
        return Ok(Response::PromoteResourceResult {
            status: proto::ResourcePromoteStatus::NotFound,
            message,
            snapshot: before,
        });
    };

    let result = scheduler.promote(promote_id, "tui");
    let snapshot = scheduler.snapshot();
    let (status, message, applied) = match result {
        Ok(()) => {
            let display = queued_match
                .map(|entry| entry.display_id.as_str())
                .unwrap_or(token);
            (
                proto::ResourcePromoteStatus::Promoted,
                format!("promoted resource request {display}"),
                true,
            )
        }
        Err(ResourcePromoteError::NotQueued(_)) => (
            proto::ResourcePromoteStatus::NotQueued,
            format!("resource request `{token}` is already running or completed"),
            false,
        ),
        Err(ResourcePromoteError::NotFound(_)) => (
            proto::ResourcePromoteStatus::NotFound,
            format!("resource request `{token}` is no longer queued"),
            false,
        ),
    };
    record_resource_promotion(ctx, audit_session_id, token, applied, &message);
    Ok(Response::PromoteResourceResult {
        status,
        message,
        snapshot,
    })
}

fn record_resource_promotion(
    ctx: &DaemonContext,
    session_id: Option<Uuid>,
    request_id: &str,
    applied: bool,
    message: &str,
) {
    let Some(session_id) = session_id else {
        return;
    };
    let data = serde_json::json!({
        "request_id": request_id,
        "applied": applied,
        "message": message,
        "source": "tui",
    });
    let _ = ctx.db.insert_session_event(
        session_id,
        crate::db::session_log::SessionEventKind::ResourcePromotion,
        None,
        None,
        &data,
    );
}

fn fork_session(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    parent_session_id: Uuid,
    fork_point_turn_id: Option<String>,
    ephemeral: bool,
) -> std::result::Result<Response, ErrorPayload> {
    // Guard rail: refuse forks of unknown parents with the typed
    // `UnknownSession` code so the TUI can surface a friendlier error
    // than a generic internal failure.
    match ctx.db.get_session(parent_session_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown parent session {parent_session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    }
    // `/side` forks land ephemeral (excluded from lists, never auto-titled,
    // discarded on end/exit); `/fork` forks persist normally.
    let row = if ephemeral {
        ctx.db
            .create_ephemeral_fork(parent_session_id, fork_point_turn_id.clone())
    } else {
        ctx.db
            .create_fork(parent_session_id, fork_point_turn_id.clone())
    }
    .map_err(internal)?;
    if let Some(tag) = principal.tag() {
        ctx.db
            .set_session_created_by_principal(row.session_id, Some(&tag))
            .map_err(internal)?;
    }
    Ok(Response::Forked {
        session_id: row.session_id,
        short_id: row.short_id.unwrap_or_default(),
        parent_session_id,
        fork_point_turn_id,
    })
}

/// Discard an ephemeral side-conversation (`/side`): stop its live worker
/// (cancelling jobs, ending the current turn) then delete its row +
/// descendant forks. Guarded — a non-ephemeral session is left untouched,
/// so a stray discard can never drop a persisted session. Idempotent: an
/// already-gone session acks without error.
async fn discard_session(
    state: &mut ClientState,
    ctx: &DaemonContext,
    session_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    // Detach this client from the session it's discarding so the daemon
    // doesn't keep streaming a torn-down worker's events at it.
    if let Some(att) = &state.attached
        && att.handle.session_id == session_id
    {
        state.attached = None;
    }
    // Stop the live worker first. Fail closed: if the worker does not stop,
    // leave the ephemeral session row intact.
    ctx.registry
        .interrupt_and_stop(session_id)
        .await
        .map_err(internal)?;
    ctx.db
        .discard_ephemeral_session(session_id)
        .map_err(internal)?;
    Ok(Response::Ack)
}

fn rename_session(
    ctx: &DaemonContext,
    session_id: Uuid,
    title: &str,
) -> std::result::Result<Response, ErrorPayload> {
    match ctx.db.get_session(session_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    }
    ctx.db.rename_session(session_id, title).map_err(internal)?;
    Ok(Response::Ack)
}

/// Append a `/note` user-authored session-history note
/// (implementation note). Records a `user_note` session event on
/// the target session and returns its assigned `seq`. The note never enters
/// model-bound history (rehydration skips `user_note`) and triggers no
/// inference — it is purely a durable, exportable transcript annotation.
fn record_session_note(
    ctx: &DaemonContext,
    session_id: Uuid,
    text: &str,
) -> std::result::Result<Response, ErrorPayload> {
    let agent = match ctx.db.get_session(session_id) {
        Ok(Some(s)) => s.active_agent,
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    };
    let seq = ctx
        .db
        .insert_session_event(
            session_id,
            crate::db::session_log::SessionEventKind::UserNote,
            Some(agent.as_str()),
            None,
            &serde_json::json!({ "text": text }),
        )
        .map_err(internal)?;
    Ok(Response::NoteRecorded { seq })
}

async fn delete_session(
    ctx: &DaemonContext,
    session_id: Uuid,
    cascade: bool,
) -> std::result::Result<Response, ErrorPayload> {
    match ctx.db.get_session(session_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    }
    // Don't delete out from under a running worker (GOALS §17h): stop any
    // live workers in the affected subtree first — that cancels their
    // async jobs and ends the current turn cleanly.
    stop_subtree(ctx, session_id, cascade).await?;
    ctx.db
        .delete_session(session_id, cascade)
        .map_err(internal)?;
    Ok(Response::Ack)
}

async fn archive_session(
    ctx: &DaemonContext,
    session_id: Uuid,
    cascade: bool,
) -> std::result::Result<Response, ErrorPayload> {
    match ctx.db.get_session(session_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    }
    // Same interrupt-first rule as delete: don't archive a session while
    // its worker is live.
    stop_subtree(ctx, session_id, cascade).await?;
    ctx.db
        .archive_session(session_id, cascade)
        .map_err(internal)?;
    Ok(Response::Ack)
}

/// Stop any live worker for `root` (and, when `cascade`, its whole fork
/// subtree) before an archive/delete. Best-effort over the candidate ids
/// the daemon currently has active workers for — there is no DB walk
/// here because only sessions with a live worker need interrupting, and
/// the registry already knows those.
async fn stop_subtree(
    ctx: &DaemonContext,
    root: Uuid,
    cascade: bool,
) -> std::result::Result<(), ErrorPayload> {
    if !cascade {
        ctx.registry
            .interrupt_and_stop(root)
            .await
            .map_err(internal)?;
        return Ok(());
    }
    // Cascade: interrupt every active session whose row sits in the
    // subtree rooted at `root`. We intersect the daemon's live worker set
    // with the DB subtree so we only walk what's actually running.
    let active = ctx.registry.active_session_ids();
    for id in active {
        if ctx.db.is_in_subtree(root, id).unwrap_or(false) {
            ctx.registry
                .interrupt_and_stop(id)
                .await
                .map_err(internal)?;
        }
    }
    Ok(())
}

fn unarchive_session(
    ctx: &DaemonContext,
    session_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    match ctx.db.get_session(session_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    }
    ctx.db.unarchive_session(session_id).map_err(internal)?;
    Ok(Response::Ack)
}

fn require_attached(state: &ClientState) -> std::result::Result<&AttachedSession, ErrorPayload> {
    state.attached.as_ref().ok_or_else(|| ErrorPayload {
        code: ErrorCode::NotAttached,
        message: "client has not attached to a session".into(),
    })
}

fn validate_set_agent(att: &AttachedSession, name: &str) -> std::result::Result<(), ErrorPayload> {
    let (cfg, ownable) =
        crate::config::trust::with_workspace_trust_policy(att.handle.trust_policy.clone(), || {
            (
                crate::config::extended::load_for_cwd(&att.handle.project_root),
                crate::agents::chat_ownable_primaries(&att.handle.project_root),
            )
        });
    validate_set_agent_name(name, cfg.experimental_mode, &ownable)
}

fn validate_set_agent_name(
    name: &str,
    experimental_mode: bool,
    ownable: &[String],
) -> std::result::Result<(), ErrorPayload> {
    if crate::agents::is_experimental_primary(name) && !experimental_mode {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!("agent `{name}` requires experimental mode"),
        });
    }

    if !ownable.iter().any(|agent| agent == name) {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!(
                "agent `{name}` is not a chat-ownable primary; valid choices: {}",
                ownable.join(", ")
            ),
        });
    }

    Ok(())
}

fn internal<E: std::fmt::Display>(err: E) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Internal,
        // `{:#}` walks the full anyhow context chain (e.g. `resolving
        // model: provider ...: ...`) rather than printing only the
        // outermost context, so daemon-surfaced errors are legible
        // instead of an opaque `internal: resolving model`.
        message: format!("{err:#}"),
    }
}

fn not_implemented(what: &str) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Internal,
        // `{:#}` for consistency with `internal()`; `what` is a plain
        // slug here, so the alternate form is identical, but keeping the
        // same form means a future error-typed arg would print its chain.
        message: format!("{what:#} not yet implemented in v1"),
    }
}

/// Read the effective layered provider/model and former-`ExtendedConfig` keys
/// out of `config.json` (GOALS §2a). This mirrors
/// `tui::agent_runner::load_providers` / `load_extended` so the in-process and
/// daemon-mediated paths see identical config behavior.
fn load_configs(cwd: &Path) -> Result<(ProvidersConfig, ExtendedConfig)> {
    let providers = ConfigDoc::load_effective(cwd);
    let extended = crate::config::extended::load_for_cwd(cwd);
    Ok((providers, extended))
}

fn load_configs_with_trust(
    cwd: &Path,
    policy: &WorkspaceTrustPolicy,
) -> Result<(ProvidersConfig, ExtendedConfig)> {
    crate::config::trust::with_workspace_trust_policy(policy.clone(), || load_configs(cwd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::session_worker::SessionWorkerHandle;
    use crate::daemon::shutdown::ShutdownPhase;
    use crate::session::Session;
    use std::collections::{HashMap, HashSet};
    use std::io;
    use std::sync::Mutex as StdMutex;
    use tracing::Level;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct CaptureWriter(std::sync::Arc<StdMutex<Vec<u8>>>);

    struct CaptureGuard(std::sync::Arc<StdMutex<Vec<u8>>>);

    impl io::Write for CaptureGuard {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureGuard;

        fn make_writer(&'a self) -> Self::Writer {
            CaptureGuard(self.0.clone())
        }
    }

    fn capture_warn_log(f: impl FnOnce()) -> String {
        let bytes = std::sync::Arc::new(StdMutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::WARN)
            .with_ansi(false)
            .with_writer(CaptureWriter(bytes.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        String::from_utf8(bytes.lock().unwrap().clone()).unwrap()
    }

    fn remote_principal() -> ClientPrincipal {
        ClientPrincipal::Remote(principal::RemotePrincipal {
            user_id: "remote-user".to_string(),
            grants: vec![principal::PrincipalGrant {
                scope: principal::PrincipalScope::AgentReadonly,
                project_root: None,
            }],
        })
    }

    fn table_for(secret: &str) -> Arc<RedactionTable> {
        let cfg = crate::config::extended::RedactConfig {
            enabled: true,
            scan_environment: false,
            scan_dotenv: false,
            scan_ssh_keys: false,
            denylist: vec![secret.to_string()],
            placeholder: "[redacted]".to_string(),
            ..crate::config::extended::RedactConfig::default()
        };
        Arc::new(RedactionTable::build(&cfg, Path::new(".")).unwrap())
    }

    #[test]
    fn boundary_owner_gets_raw_non_owner_gets_scrubbed_from_same_envelope() {
        let table = table_for("client-boundary-secret");
        let event = proto::Event::AssistantText {
            session_id: Uuid::new_v4(),
            agent: "Build".to_string(),
            text: "visible client-boundary-secret".to_string(),
            reasoning: String::new(),
            seq: None,
        };
        let envelope = EventEnvelope {
            event: event.clone(),
            redact: table,
        };

        let owner = scrub_event_for_principal(&ClientPrincipal::owner(), envelope.clone()).unwrap();
        assert_eq!(
            serde_json::to_string(&owner).unwrap(),
            serde_json::to_string(&event).unwrap()
        );
        let scrubbed = scrub_event_for_principal(&remote_principal(), envelope).unwrap();
        let proto::Event::AssistantText { text, .. } = scrubbed else {
            panic!("expected AssistantText")
        };
        assert_eq!(text, "visible [redacted]");
    }

    #[test]
    fn boundary_scrubs_streaming_deltas_for_non_owner() {
        let table = table_for("stream-secret");
        for event in [
            proto::Event::AssistantTextDelta {
                session_id: Uuid::new_v4(),
                agent: "Build".to_string(),
                delta: "token stream-secret".to_string(),
            },
            proto::Event::ReasoningDelta {
                session_id: Uuid::new_v4(),
                agent: "Build".to_string(),
                delta: "thought stream-secret".to_string(),
            },
        ] {
            let scrubbed = scrub_event_for_principal(
                &remote_principal(),
                EventEnvelope {
                    event,
                    redact: table.clone(),
                },
            )
            .unwrap();
            let rendered = serde_json::to_string(&scrubbed).unwrap();
            assert!(!rendered.contains("stream-secret"), "{rendered}");
            assert!(rendered.contains("[redacted]"), "{rendered}");
        }
    }

    #[test]
    fn boundary_scrubs_nested_json_text_for_non_owner() {
        let table = table_for("nested-secret");
        let event = proto::Event::ToolStart {
            session_id: Uuid::new_v4(),
            agent: "Build".to_string(),
            call_id: "call-1".to_string(),
            tool: "bash".to_string(),
            args: serde_json::json!({ "sidecar": { "text": "nested-secret" } }),
        };
        let scrubbed = scrub_event_for_principal(
            &remote_principal(),
            EventEnvelope {
                event,
                redact: table,
            },
        )
        .unwrap();
        let rendered = serde_json::to_string(&scrubbed).unwrap();
        assert!(!rendered.contains("nested-secret"), "{rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
    }

    #[test]
    fn boundary_uses_emit_time_table_not_later_table() {
        let emit_table = table_for("emit-secret");
        let _later_table = table_for("later-secret");
        let event = proto::Event::AssistantTextDelta {
            session_id: Uuid::new_v4(),
            agent: "Build".to_string(),
            delta: "emit-secret later-secret".to_string(),
        };
        let scrubbed = scrub_event_for_principal(
            &remote_principal(),
            EventEnvelope {
                event,
                redact: emit_table,
            },
        )
        .unwrap();
        let proto::Event::AssistantTextDelta { delta, .. } = scrubbed else {
            panic!("expected AssistantTextDelta")
        };
        assert_eq!(delta, "[redacted] later-secret");
    }

    #[test]
    fn session_and_global_events_use_their_own_tables() {
        let session_id = Uuid::new_v4();
        let session_event = proto::Event::Notice {
            session_id,
            text: "session-secret global-secret".to_string(),
        };
        let global_event = proto::Event::LspNotice {
            text: "session-secret global-secret".to_string(),
        };

        let scrubbed_session = scrub_event_for_principal(
            &remote_principal(),
            EventEnvelope {
                event: session_event,
                redact: table_for("session-secret"),
            },
        )
        .unwrap();
        let scrubbed_global = scrub_event_for_principal(
            &remote_principal(),
            EventEnvelope {
                event: global_event,
                redact: table_for("global-secret"),
            },
        )
        .unwrap();

        let proto::Event::Notice { text, .. } = scrubbed_session else {
            panic!("expected Notice")
        };
        assert_eq!(text, "[redacted] global-secret");
        let proto::Event::LspNotice { text } = scrubbed_global else {
            panic!("expected LspNotice")
        };
        assert_eq!(text, "session-secret [redacted]");
    }

    #[test]
    fn attach_history_is_scrubbed_only_for_non_owner() {
        let table = table_for("history-secret");
        let history = vec![proto::HistoryEntry::ToolCall {
            agent: "Build".to_string(),
            call_id: "call-1".to_string(),
            tool: "bash".to_string(),
            original_input: serde_json::json!({ "cmd": "echo history-secret" }),
            wire_input: serde_json::json!({ "cmd": "echo history-secret" }),
            recovery_kind: None,
            recovery_stage: None,
            output: "history-secret".to_string(),
            hard_fail: false,
            truncated: false,
            hint: Some("history-secret".to_string()),
        }];

        let owner = scrub_history_for_principal(&ClientPrincipal::owner(), history.clone(), &table);
        assert_eq!(
            serde_json::to_string(&owner).unwrap(),
            serde_json::to_string(&history).unwrap()
        );
        let remote = scrub_history_for_principal(&remote_principal(), history, &table);
        let rendered = serde_json::to_string(&remote).unwrap();
        assert!(!rendered.contains("history-secret"), "{rendered}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
    }

    fn test_ctx() -> Arc<DaemonContext> {
        let db = Db::open_in_memory().expect("in-memory db");
        let locks = Arc::new(LockManager::from_db(db.clone()).expect("locks"));
        let paths = DaemonPaths {
            socket: std::path::PathBuf::from("/tmp/cockpit-test.sock"),
            pid_file: std::path::PathBuf::from("/tmp/cockpit-test.pid"),
            ephemeral: true,
        };
        Arc::new(DaemonContext::new(db, locks, paths))
    }

    fn persistent_test_ctx() -> Arc<DaemonContext> {
        let db = Db::open_in_memory().expect("in-memory db");
        let locks = Arc::new(LockManager::from_db(db.clone()).expect("locks"));
        let paths = DaemonPaths {
            socket: std::path::PathBuf::from("/tmp/cockpit-persistent-test.sock"),
            pid_file: std::path::PathBuf::from("/tmp/cockpit-persistent-test.pid"),
            ephemeral: false,
        };
        Arc::new(DaemonContext::new(db, locks, paths))
    }

    fn remote_state_with_grants(
        grants: Vec<crate::daemon::principal::PrincipalGrant>,
    ) -> ClientState {
        ClientState {
            principal: ClientPrincipal::Remote(crate::daemon::principal::RemotePrincipal {
                user_id: "user-1".into(),
                grants,
            }),
            attached: None,
            pending_uploads: HashMap::new(),
            ready_attachments: HashMap::new(),
            upload_accounting: Arc::new(StdMutex::new(UploadAccounting::default())),
            upload_limits: AttachmentUploadLimits::default(),
            terminal_views: HashSet::new(),
            terminal_host: test_terminal_host(),
        }
    }

    fn project_files_grant(root: &Path) -> crate::daemon::principal::PrincipalGrant {
        crate::daemon::principal::PrincipalGrant {
            scope: crate::daemon::principal::PrincipalScope::ProjectFiles,
            project_root: Some(root.to_string_lossy().into_owned()),
        }
    }

    fn terminal_grant() -> crate::daemon::principal::PrincipalGrant {
        crate::daemon::principal::PrincipalGrant {
            scope: crate::daemon::principal::PrincipalScope::Terminal,
            project_root: None,
        }
    }

    fn owner_state() -> ClientState {
        ClientState {
            principal: ClientPrincipal::owner(),
            attached: None,
            pending_uploads: HashMap::new(),
            ready_attachments: HashMap::new(),
            upload_accounting: Arc::new(StdMutex::new(UploadAccounting::default())),
            upload_limits: AttachmentUploadLimits::default(),
            terminal_views: HashSet::new(),
            terminal_host: test_terminal_host(),
        }
    }

    fn flycockpit_credential() -> crate::auth::flycockpit::StoredFlycockpitCredential {
        crate::auth::flycockpit::StoredFlycockpitCredential {
            server_url: "https://app.example.test".to_string(),
            instance_id: "inst-1".to_string(),
            instance_token: "fci_instance_secret_rpc".to_string(),
            account: crate::auth::flycockpit::AccountInfo {
                user_id: "user-1".to_string(),
                email: "user@example.test".to_string(),
            },
            display_name: Some("Devbox".to_string()),
            relay_choice: None,
        }
    }

    #[tokio::test]
    async fn persistent_daemon_stores_flycockpit_credential_and_wakes_connector() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let state_home = tmp.path().join("state");
        let runtime_dir = tmp.path().join("runtime");
        let _env = crate::daemon::test_harness::DaemonEnvGuard::set_paths(&[
            ("XDG_STATE_HOME", state_home.as_path()),
            ("XDG_RUNTIME_DIR", runtime_dir.as_path()),
        ]);
        let ctx = persistent_test_ctx();
        let credential = flycockpit_credential();
        let mut state = owner_state();
        let mut wake_rx = ctx.connector_wake_rx();

        let debug = format!(
            "{:?}",
            Request::StoreFlycockpitCredential {
                credential: credential.clone(),
            }
        );
        assert!(!debug.contains(&credential.instance_token));
        assert!(debug.contains("<redacted>"));

        let response = handle_request(
            Request::StoreFlycockpitCredential {
                credential: credential.clone(),
            },
            &mut state,
            &ctx,
        )
        .await
        .expect("credential store succeeds");
        assert!(matches!(response, Response::Ack));
        tokio::time::timeout(Duration::from_millis(100), wake_rx.changed())
            .await
            .expect("connector wake delivered")
            .expect("wake sender alive");

        let stored = crate::auth::flycockpit::load_credential().unwrap();
        assert_eq!(stored, credential);

        #[cfg(unix)]
        {
            let store = crate::credentials::CredentialStore::open_default().unwrap();
            let mode = std::fs::metadata(store.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        let table = crate::redact::RedactionTable::build(
            &crate::config::extended::RedactConfig::default(),
            tmp.path(),
        )
        .unwrap();
        let scrubbed = table.scrub("token=fci_instance_secret_rpc");
        assert!(!scrubbed.contains("fci_instance_secret_rpc"));
    }

    #[tokio::test]
    async fn persistent_daemon_clears_flycockpit_credential_and_wakes_connector() {
        let tmp = tempfile::tempdir().unwrap();
        let state_home = tmp.path().join("state");
        let runtime_dir = tmp.path().join("runtime");
        let _env = crate::daemon::test_harness::DaemonEnvGuard::set_paths(&[
            ("XDG_STATE_HOME", state_home.as_path()),
            ("XDG_RUNTIME_DIR", runtime_dir.as_path()),
        ]);
        let ctx = persistent_test_ctx();
        crate::auth::flycockpit::store_credential(&flycockpit_credential()).unwrap();
        let mut state = owner_state();
        let mut wake_rx = ctx.connector_wake_rx();

        let response = handle_request(Request::ClearFlycockpitCredential, &mut state, &ctx)
            .await
            .expect("credential clear succeeds");
        assert!(matches!(response, Response::Ack));
        tokio::time::timeout(Duration::from_millis(100), wake_rx.changed())
            .await
            .expect("connector wake delivered")
            .expect("wake sender alive");
        assert!(crate::auth::flycockpit::load_credential().is_err());
    }

    #[tokio::test]
    async fn ephemeral_daemon_rejects_flycockpit_credential_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let state_home = tmp.path().join("state");
        let runtime_dir = tmp.path().join("runtime");
        let _env = crate::daemon::test_harness::DaemonEnvGuard::set_paths(&[
            ("XDG_STATE_HOME", state_home.as_path()),
            ("XDG_RUNTIME_DIR", runtime_dir.as_path()),
        ]);
        let ctx = test_ctx();
        let mut state = owner_state();
        let err = handle_request(
            Request::StoreFlycockpitCredential {
                credential: flycockpit_credential(),
            },
            &mut state,
            &ctx,
        )
        .await
        .expect_err("ephemeral daemon must reject credential writes");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("ephemeral daemons"));

        let err = handle_request(Request::ClearFlycockpitCredential, &mut state, &ctx)
            .await
            .expect_err("ephemeral daemon must reject credential clears");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(crate::auth::flycockpit::load_credential().is_err());
    }

    #[tokio::test]
    async fn fs_requests_require_project_files_scope_for_matching_root() {
        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();
        let root_a = tmp.path().join("a");
        let root_b = tmp.path().join("b");
        std::fs::create_dir_all(&root_a).unwrap();
        std::fs::create_dir_all(&root_b).unwrap();
        std::fs::write(root_a.join("readme.md"), "ok").unwrap();
        std::fs::write(root_b.join("readme.md"), "no").unwrap();

        let mut no_scope = remote_state_with_grants(Vec::new());
        let err = handle_request(
            Request::FsRead {
                project_root: root_a.to_string_lossy().into_owned(),
                path: "readme.md".into(),
                base64: false,
            },
            &mut no_scope,
            &ctx,
        )
        .await
        .expect_err("missing project_files scope must be denied");
        assert_eq!(err.code, ErrorCode::Authorization);

        let mut root_a_scope = remote_state_with_grants(vec![project_files_grant(&root_a)]);
        let err = handle_request(
            Request::FsRead {
                project_root: root_b.to_string_lossy().into_owned(),
                path: "readme.md".into(),
                base64: false,
            },
            &mut root_a_scope,
            &ctx,
        )
        .await
        .expect_err("project_files scope must not cross roots");
        assert_eq!(err.code, ErrorCode::Authorization);

        let response = handle_request(
            Request::FsRead {
                project_root: root_a.to_string_lossy().into_owned(),
                path: "readme.md".into(),
                base64: false,
            },
            &mut root_a_scope,
            &ctx,
        )
        .await
        .expect("matching scope reads");
        match response {
            Response::FsRead { content, .. } => assert_eq!(content.as_deref(), Some("ok")),
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn terminal_requests_require_terminal_scope_and_audit_open_close() {
        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();

        let mut no_scope = remote_state_with_grants(Vec::new());
        let err = handle_request(
            Request::OpenTerminal {
                cwd: Some(tmp.path().to_string_lossy().into_owned()),
                cols: 80,
                rows: 24,
            },
            &mut no_scope,
            &ctx,
        )
        .await
        .expect_err("missing terminal scope must be denied");
        assert_eq!(err.code, ErrorCode::Authorization);

        let mut terminal_scope = remote_state_with_grants(vec![terminal_grant()]);
        let response = handle_request(
            Request::OpenTerminal {
                cwd: Some(tmp.path().to_string_lossy().into_owned()),
                cols: 80,
                rows: 24,
            },
            &mut terminal_scope,
            &ctx,
        )
        .await
        .expect("terminal scope opens a PTY");
        let terminal_id = match response {
            Response::TerminalOpened { terminal_id, .. } => terminal_id,
            other => panic!("unexpected response: {other:?}"),
        };
        assert!(terminal_scope.terminal_views.contains(&terminal_id));

        handle_request(
            Request::CloseTerminal { terminal_id },
            &mut terminal_scope,
            &ctx,
        )
        .await
        .expect("close succeeds");

        let rows = ctx.db.list_remote_audit().unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].request_kind, "open_terminal");
        assert_eq!(rows[0].verdict, "denied");
        assert_eq!(rows[1].request_kind, "open_terminal");
        assert_eq!(rows[1].verdict, "allowed");
        assert_eq!(rows[2].request_kind, "close_terminal");
        assert_eq!(rows[2].verdict, "allowed");
    }

    #[tokio::test]
    async fn remote_fs_write_hash_mismatch_and_lock_conflict_are_typed() {
        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let path = root.join("file.txt");
        std::fs::write(&path, "current").unwrap();
        let mut state = remote_state_with_grants(vec![project_files_grant(root)]);

        let err = handle_request(
            Request::FsWrite {
                project_root: root.to_string_lossy().into_owned(),
                path: "file.txt".into(),
                content: "next".into(),
                base_hash: Some("wrong".into()),
            },
            &mut state,
            &ctx,
        )
        .await
        .expect_err("stale hash must be rejected");
        assert_eq!(err.code, ErrorCode::HashMismatch);

        let session = ctx
            .db
            .create_session("proj", &root.to_string_lossy(), "Build")
            .unwrap();
        ctx.registry
            .locks()
            .acquire(&path, "builder", session.session_id)
            .unwrap();
        let err = handle_request(
            Request::FsWrite {
                project_root: root.to_string_lossy().into_owned(),
                path: "file.txt".into(),
                content: "next".into(),
                base_hash: None,
            },
            &mut state,
            &ctx,
        )
        .await
        .expect_err("active agent lock must conflict");
        assert_eq!(err.code, ErrorCode::LockConflict);
    }

    #[tokio::test]
    async fn remote_fs_mutations_are_audited_with_path() {
        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut state = remote_state_with_grants(vec![project_files_grant(root)]);

        let response = handle_request(
            Request::FsWrite {
                project_root: root.to_string_lossy().into_owned(),
                path: "src/main.rs".into(),
                content: "fn main() {}\n".into(),
                base_hash: None,
            },
            &mut state,
            &ctx,
        )
        .await
        .expect("write succeeds");
        assert!(matches!(response, Response::FsWrite { .. }));

        let rows = ctx.db.list_remote_audit().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].principal, "flycockpit:user-1");
        assert_eq!(rows[0].request_kind, "fs_write");
        assert_eq!(rows[0].verdict, "allowed");
        assert_eq!(rows[0].path.as_deref(), Some("src/main.rs"));
    }

    #[test]
    fn resource_scheduler_is_shared_only_for_persistent_daemons() {
        let persistent_db = Db::open_in_memory().expect("in-memory db");
        let persistent_locks =
            Arc::new(LockManager::from_db(persistent_db.clone()).expect("locks"));
        let persistent = DaemonContext::new(
            persistent_db,
            persistent_locks,
            DaemonPaths {
                socket: std::path::PathBuf::from("/tmp/cockpit-test.sock"),
                pid_file: std::path::PathBuf::from("/tmp/cockpit-test.pid"),
                ephemeral: false,
            },
        );
        assert!(persistent.registry.resource_scheduler().is_some());

        let ephemeral_db = Db::open_in_memory().expect("in-memory db");
        let ephemeral_locks = Arc::new(LockManager::from_db(ephemeral_db.clone()).expect("locks"));
        let ephemeral = DaemonContext::new(
            ephemeral_db,
            ephemeral_locks,
            DaemonPaths {
                socket: std::path::PathBuf::from("/tmp/cockpit-eph-test.sock"),
                pid_file: std::path::PathBuf::from("/tmp/cockpit-eph-test.pid"),
                ephemeral: true,
            },
        );
        assert!(ephemeral.registry.resource_scheduler().is_none());
    }

    #[tokio::test]
    async fn promote_resource_request_moves_queued_request_to_front() {
        let ctx = persistent_test_ctx();
        let scheduler = ctx
            .registry
            .resource_scheduler()
            .expect("persistent scheduler");
        let running = scheduler
            .submit(
                crate::engine::resource_scheduler::ResourceAcquireRequest::new(
                    crate::engine::resource_scheduler::ResourceRequirements::new([("cpu", 1)]),
                ),
            )
            .expect("running ticket");
        let _queued_a = scheduler
            .submit(
                crate::engine::resource_scheduler::ResourceAcquireRequest::new(
                    crate::engine::resource_scheduler::ResourceRequirements::new([("cpu", 1)]),
                ),
            )
            .expect("queued ticket");
        let queued_b = scheduler
            .submit(
                crate::engine::resource_scheduler::ResourceAcquireRequest::new(
                    crate::engine::resource_scheduler::ResourceRequirements::new([("cpu", 1)]),
                ),
            )
            .expect("queued ticket");
        let before = scheduler.snapshot();
        assert_eq!(before.running[0].id, running.request_id());
        assert_eq!(before.queued[1].id, queued_b.request_id());

        let mut state = ClientState::detached_for_test();
        let response = handle_request(
            Request::PromoteResource {
                request_id: queued_b.display_id().to_string(),
                session_id: None,
            },
            &mut state,
            &ctx,
        )
        .await
        .expect("promote response");

        match response {
            Response::PromoteResourceResult {
                status, snapshot, ..
            } => {
                assert_eq!(status, proto::ResourcePromoteStatus::Promoted);
                assert_eq!(snapshot.queued[0].id, queued_b.request_id());
                assert_eq!(snapshot.running[0].id, running.request_id());
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn promote_resource_request_stale_id_is_nonfatal() {
        let ctx = persistent_test_ctx();
        let mut state = ClientState::detached_for_test();

        let response = handle_request(
            Request::PromoteResource {
                request_id: "rs-9999".to_string(),
                session_id: None,
            },
            &mut state,
            &ctx,
        )
        .await
        .expect("promote response");

        match response {
            Response::PromoteResourceResult {
                status, message, ..
            } => {
                assert_eq!(status, proto::ResourcePromoteStatus::NotFound);
                assert!(message.contains("no longer queued"));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn boot_housekeeping_succeeds_with_empty_task_delegation_tables() {
        let db = Db::open_in_memory().expect("in-memory db");
        run_boot_housekeeping(&db);
        assert_eq!(db.reconcile_orphaned_task_delegations().unwrap(), 0);
    }

    #[tokio::test]
    async fn retention_tick_runs_one_pass_without_sleep() {
        let db = Db::open_in_memory().expect("in-memory db");
        let session = db.create_session("p", "/x", "Build").unwrap();
        db.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET ended_at = 10, last_active_at = 10 WHERE session_id = ?1",
                [session.session_id.to_string()],
            )?;
            conn.execute(
                "INSERT INTO session_events (session_id, ts_ms, type, data_json)
                 VALUES (?1, 10000, 'user_message', '{}')",
                [session.session_id.to_string()],
            )?;
            Ok(())
        })
        .unwrap();
        let cfg = RetentionConfig {
            payload_window_days: 1,
            vacuum_interval_days: 0,
            ..RetentionConfig::default()
        };

        run_retention_tick_db(db.clone(), cfg).await;

        let rows: i64 = db
            .read_blocking(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM session_events WHERE session_id = ?1",
                    [session.session_id.to_string()],
                    |row| row.get(0),
                )
                .context("counting session_events")
            })
            .unwrap();
        assert_eq!(rows, 0);
    }

    fn attached_state(
        ctx: &Arc<DaemonContext>,
        project_root: &std::path::Path,
    ) -> (ClientState, Uuid) {
        let session_row = ctx
            .db
            .create_session("p", project_root.to_str().unwrap(), "Build")
            .unwrap();
        let session = Arc::new(
            Session::resume(ctx.db.clone(), session_row.session_id)
                .unwrap()
                .unwrap(),
        );
        let locks = Arc::new(LockManager::from_db(ctx.db.clone()).expect("locks"));
        let handle = SessionWorkerHandle::test_handle(session, locks);
        let event_rx = handle.subscribe();
        (
            ClientState {
                principal: ClientPrincipal::owner(),
                attached: Some(AttachedSession {
                    handle,
                    event_rx,
                    _interactive_guard: None,
                }),
                pending_uploads: HashMap::new(),
                ready_attachments: HashMap::new(),
                upload_accounting: Arc::new(StdMutex::new(UploadAccounting::default())),
                upload_limits: AttachmentUploadLimits::default(),
                terminal_views: HashSet::new(),
                terminal_host: test_terminal_host(),
            },
            session_row.session_id,
        )
    }

    fn overlay_value(state: &ClientState, key: &str) -> Option<String> {
        state
            .attached
            .as_ref()
            .unwrap()
            .handle
            .env_overlay()
            .read()
            .unwrap()
            .get(key)
            .cloned()
    }

    fn sample_png() -> Vec<u8> {
        let image = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            1,
            1,
            image::Rgba([1, 2, 3, 255]),
        ));
        let mut out = Vec::new();
        image
            .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
            .unwrap();
        out
    }

    fn begin_upload_for(state: &mut ClientState, png: &[u8]) -> Uuid {
        match begin_attachment_upload(
            state,
            proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
            png.len(),
            sha256_hex(png),
            proto::AttachmentPurpose::UserMessageImage,
        )
        .unwrap()
        {
            Response::AttachmentUploadStarted { upload_id, .. } => upload_id,
            other => panic!("unexpected response: {other:?}"),
        }
    }

    fn finish_attachment_upload_for_test(
        state: &mut ClientState,
        upload_id: Uuid,
    ) -> std::result::Result<Response, ErrorPayload> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(finish_attachment_upload(state, upload_id))
    }

    fn finish_upload_for(state: &mut ClientState, png: &[u8]) -> proto::ImageAttachmentRef {
        let upload_id = begin_upload_for(state, png);
        let data_base64 = base64::engine::general_purpose::STANDARD.encode(png);
        upload_attachment_chunk(state, upload_id, 0, data_base64).unwrap();
        match finish_attachment_upload_for_test(state, upload_id).unwrap() {
            Response::AttachmentUploaded { image_ref } => image_ref,
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn attachment_upload_consumes_image_refs_exactly_once() {
        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, session_id) = attached_state(&ctx, tmp.path());
        let png = sample_png();
        let image_ref = finish_upload_for(&mut state, &png);

        let images = consume_image_refs(&mut state, session_id, std::slice::from_ref(&image_ref))
            .expect("first consume");
        assert_eq!(images, vec![png]);

        let err = consume_image_refs(&mut state, session_id, &[image_ref])
            .expect_err("second consume must fail");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("already consumed"));
    }

    #[test]
    fn duplicate_image_refs_are_rejected_without_consuming() {
        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, session_id) = attached_state(&ctx, tmp.path());
        let png = sample_png();
        let image_ref = finish_upload_for(&mut state, &png);

        let err = consume_image_refs(
            &mut state,
            session_id,
            &[image_ref.clone(), image_ref.clone()],
        )
        .expect_err("duplicate refs must fail");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("duplicate image ref"));

        let images = consume_image_refs(&mut state, session_id, &[image_ref]).unwrap();
        assert_eq!(images, vec![png]);
    }

    #[test]
    fn attachment_ref_is_scoped_to_attached_session() {
        let ctx = test_ctx();
        let tmp_a = tempfile::tempdir().unwrap();
        let tmp_b = tempfile::tempdir().unwrap();
        let (mut state, session_a) = attached_state(&ctx, tmp_a.path());
        let (_, session_b) = attached_state(&ctx, tmp_b.path());
        let image_ref = finish_upload_for(&mut state, &sample_png());

        let err = consume_image_refs(&mut state, session_b, &[image_ref.clone()])
            .expect_err("wrong session must fail");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("different session"));

        let images =
            consume_image_refs(&mut state, session_a, &[image_ref]).expect("owner consume");
        assert_eq!(images, vec![sample_png()]);
        assert_ne!(session_a, session_b);
    }

    #[test]
    fn attachment_upload_rejects_bad_chunk_shapes() {
        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, _) = attached_state(&ctx, tmp.path());
        let png = sample_png();
        let upload_id = begin_upload_for(&mut state, &png);

        let err = upload_attachment_chunk(&mut state, upload_id, 1, "AAAA".to_string())
            .expect_err("offset mismatch");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("offset mismatch"));

        let err = upload_attachment_chunk(&mut state, upload_id, 0, "not base64!".to_string())
            .expect_err("invalid base64");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("valid base64"));
    }

    #[test]
    fn attachment_finish_rejects_sha_mismatch_and_invalid_png() {
        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, _) = attached_state(&ctx, tmp.path());
        let png = sample_png();
        let upload_id = match begin_attachment_upload(
            &mut state,
            proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
            png.len(),
            "0".repeat(64),
            proto::AttachmentPurpose::UserMessageImage,
        )
        .unwrap()
        {
            Response::AttachmentUploadStarted { upload_id, .. } => upload_id,
            other => panic!("unexpected response: {other:?}"),
        };
        upload_attachment_chunk(
            &mut state,
            upload_id,
            0,
            base64::engine::general_purpose::STANDARD.encode(&png),
        )
        .unwrap();
        let err =
            finish_attachment_upload_for_test(&mut state, upload_id).expect_err("hash mismatch");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("SHA-256 mismatch"));

        let bad_png = b"not actually png".to_vec();
        let upload_id = begin_upload_for(&mut state, &bad_png);
        upload_attachment_chunk(
            &mut state,
            upload_id,
            0,
            base64::engine::general_purpose::STANDARD.encode(&bad_png),
        )
        .unwrap();
        let err =
            finish_attachment_upload_for_test(&mut state, upload_id).expect_err("invalid png");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("valid PNG"));
    }

    #[test]
    fn png_validation_uses_strict_limits() {
        let large = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            proto::MAX_IMAGE_DIMENSION_PIXELS + 1,
            1,
            image::Rgba([1, 2, 3, 255]),
        ));
        let mut png = Vec::new();
        large
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();

        let err = validate_png_attachment_blocking(png).expect_err("dimension limit");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("decode limit"));
    }

    #[test]
    fn attachment_upload_default_limits_match_config_defaults() {
        let limits = AttachmentUploadLimits::default();
        assert_eq!(limits.per_client_uploads, 4);
        assert_eq!(limits.global_uploads, 32);
        assert_eq!(limits.per_upload_bytes, proto::MAX_SINGLE_IMAGE_BYTES);
        assert_eq!(limits.global_bytes, 256 * 1024 * 1024);

        let cfg_limits: AttachmentUploadLimits = ExtendedConfig::default().daemon.uploads.into();
        assert_eq!(cfg_limits.per_client_uploads, limits.per_client_uploads);
        assert_eq!(cfg_limits.global_uploads, limits.global_uploads);
        assert_eq!(cfg_limits.per_upload_bytes, limits.per_upload_bytes);
        assert_eq!(cfg_limits.global_bytes, limits.global_bytes);
    }

    #[test]
    fn attachment_upload_config_clamps_to_protocol_cap_and_warns() {
        let (limits, warning) =
            AttachmentUploadLimits::from_config_with_warning(DaemonUploadLimitsConfig {
                per_upload_bytes: 64 * 1024 * 1024,
                ..DaemonUploadLimitsConfig::default()
            });
        assert_eq!(limits.per_upload_bytes, proto::MAX_SINGLE_IMAGE_BYTES);
        assert_eq!(
            warning.as_deref(),
            Some("per_upload_bytes 64 MiB exceeds protocol cap 4 MiB; clamping")
        );

        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, _) = attached_state(&ctx, tmp.path());
        let byte_len = proto::MAX_SINGLE_IMAGE_BYTES + 1;
        let err = begin_attachment_upload_with_limits(
            &mut state,
            proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
            byte_len,
            "0".repeat(64),
            proto::AttachmentPurpose::UserMessageImage,
            limits,
        )
        .expect_err("upload above protocol cap is rejected by clamped per-upload limit");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(
            err.message.contains("pending-upload limit"),
            "{}",
            err.message
        );
    }

    #[test]
    fn attachment_upload_config_below_protocol_cap_binds() {
        let configured = MIN_ATTACHMENT_UPLOAD_BYTES + 1;
        let (limits, warning) =
            AttachmentUploadLimits::from_config_with_warning(DaemonUploadLimitsConfig {
                per_upload_bytes: configured,
                ..DaemonUploadLimitsConfig::default()
            });
        assert_eq!(limits.per_upload_bytes, configured);
        assert!(warning.is_none());

        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, _) = attached_state(&ctx, tmp.path());
        let err = begin_attachment_upload_with_limits(
            &mut state,
            proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
            configured + 1,
            "0".repeat(64),
            proto::AttachmentPurpose::UserMessageImage,
            limits,
        )
        .expect_err("upload above configured cap is rejected even below protocol cap");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(
            err.message.contains("pending-upload limit"),
            "{}",
            err.message
        );
    }

    #[test]
    fn attachment_upload_config_degenerate_per_upload_bytes_clamps_to_floor() {
        let (limits, warning) =
            AttachmentUploadLimits::from_config_with_warning(DaemonUploadLimitsConfig {
                per_upload_bytes: 0,
                ..DaemonUploadLimitsConfig::default()
            });
        assert_eq!(limits.per_upload_bytes, MIN_ATTACHMENT_UPLOAD_BYTES);
        assert_eq!(
            warning.as_deref(),
            Some("per_upload_bytes 0 bytes is below minimum 64 KiB; clamping")
        );
    }

    #[test]
    fn attachment_upload_default_limits_enforce_per_client_count() {
        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, _) = attached_state(&ctx, tmp.path());
        let png = sample_png();

        for _ in 0..4 {
            begin_attachment_upload(
                &mut state,
                proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
                png.len(),
                sha256_hex(&png),
                proto::AttachmentPurpose::UserMessageImage,
            )
            .unwrap();
        }

        let err = begin_attachment_upload(
            &mut state,
            proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
            png.len(),
            sha256_hex(&png),
            proto::AttachmentPurpose::UserMessageImage,
        )
        .expect_err("fifth pending upload exceeds default per-client cap");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("limit 4"), "{}", err.message);
    }

    #[test]
    fn attachment_upload_default_limits_enforce_global_count() {
        let ctx = test_ctx();
        let accounting = Arc::new(StdMutex::new(UploadAccounting::default()));
        let png = sample_png();
        let mut tempdirs = Vec::new();
        let mut states = Vec::new();

        for _ in 0..32 {
            let tmp = tempfile::tempdir().unwrap();
            let (mut state, _) = attached_state(&ctx, tmp.path());
            state.upload_accounting = accounting.clone();
            begin_attachment_upload(
                &mut state,
                proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
                png.len(),
                sha256_hex(&png),
                proto::AttachmentPurpose::UserMessageImage,
            )
            .unwrap();
            tempdirs.push(tmp);
            states.push(state);
        }

        let tmp = tempfile::tempdir().unwrap();
        let (mut overflow, _) = attached_state(&ctx, tmp.path());
        overflow.upload_accounting = accounting;
        let err = begin_attachment_upload(
            &mut overflow,
            proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
            png.len(),
            sha256_hex(&png),
            proto::AttachmentPurpose::UserMessageImage,
        )
        .expect_err("thirty-third pending upload exceeds default daemon cap");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("limit 32"), "{}", err.message);
        drop((states, tempdirs, tmp));
    }

    #[test]
    fn attachment_upload_limits_enforce_per_client_count_and_per_upload_bytes() {
        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, _) = attached_state(&ctx, tmp.path());
        let png = sample_png();
        let limits = AttachmentUploadLimits {
            per_client_uploads: 2,
            global_uploads: 32,
            per_upload_bytes: png.len(),
            global_bytes: usize::MAX,
        };

        begin_attachment_upload_with_limits(
            &mut state,
            proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
            png.len(),
            sha256_hex(&png),
            proto::AttachmentPurpose::UserMessageImage,
            limits,
        )
        .unwrap();
        begin_attachment_upload_with_limits(
            &mut state,
            proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
            png.len(),
            sha256_hex(&png),
            proto::AttachmentPurpose::UserMessageImage,
            limits,
        )
        .unwrap();
        let err = begin_attachment_upload_with_limits(
            &mut state,
            proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
            png.len(),
            sha256_hex(&png),
            proto::AttachmentPurpose::UserMessageImage,
            limits,
        )
        .expect_err("third pending upload exceeds per-client cap");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("this client"), "{}", err.message);

        let (mut state, _) = attached_state(&ctx, tmp.path());
        let err = begin_attachment_upload_with_limits(
            &mut state,
            proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
            png.len(),
            sha256_hex(&png),
            proto::AttachmentPurpose::UserMessageImage,
            AttachmentUploadLimits {
                per_upload_bytes: png.len() - 1,
                ..limits
            },
        )
        .expect_err("declared upload exceeds per-upload cap");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(
            err.message.contains("pending-upload limit"),
            "{}",
            err.message
        );
    }

    #[test]
    fn attachment_upload_limits_enforce_global_count_and_bytes() {
        let ctx = test_ctx();
        let tmp_a = tempfile::tempdir().unwrap();
        let tmp_b = tempfile::tempdir().unwrap();
        let (mut a, _) = attached_state(&ctx, tmp_a.path());
        let (mut b, _) = attached_state(&ctx, tmp_b.path());
        b.upload_accounting = a.upload_accounting.clone();
        let png = sample_png();
        let limits = AttachmentUploadLimits {
            per_client_uploads: 4,
            global_uploads: 1,
            per_upload_bytes: png.len(),
            global_bytes: usize::MAX,
        };

        let upload_id = begin_upload_for(&mut a, &png);
        let err = begin_attachment_upload_with_limits(
            &mut b,
            proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
            png.len(),
            sha256_hex(&png),
            proto::AttachmentPurpose::UserMessageImage,
            limits,
        )
        .expect_err("second client exceeds daemon-global count cap");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("daemon has"), "{}", err.message);

        assert!(a.pending_uploads.remove(&upload_id).is_some());
        release_uploads(&a.upload_accounting, [upload_id]);
        let limits = AttachmentUploadLimits {
            global_uploads: 32,
            global_bytes: png.len(),
            ..limits
        };
        begin_attachment_upload_with_limits(
            &mut a,
            proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
            png.len(),
            sha256_hex(&png),
            proto::AttachmentPurpose::UserMessageImage,
            limits,
        )
        .unwrap();
        let err = begin_attachment_upload_with_limits(
            &mut b,
            proto::IMAGE_ATTACHMENT_MIME_PNG.to_string(),
            png.len(),
            sha256_hex(&png),
            proto::AttachmentPurpose::UserMessageImage,
            limits,
        )
        .expect_err("second client exceeds daemon-global byte cap");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("byte limit"), "{}", err.message);
    }

    #[test]
    fn expired_pending_upload_prune_releases_global_accounting() {
        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, _) = attached_state(&ctx, tmp.path());
        let png = sample_png();
        let upload_id = begin_upload_for(&mut state, &png);
        state
            .pending_uploads
            .get_mut(&upload_id)
            .unwrap()
            .created_at =
            Instant::now() - Duration::from_secs(proto::PENDING_ATTACHMENT_TTL_SECS + 1);

        prune_expired_attachments(&mut state);

        assert!(state.pending_uploads.is_empty());
        assert!(
            crate::sync::lock_or_recover(&state.upload_accounting)
                .pending
                .is_empty()
        );
    }

    async fn recv_body<S>(proto: &mut ProtoStream<S>) -> Body
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        match proto.recv().await.unwrap().unwrap() {
            RecvFrame::Envelope(env) => env.body,
            other => panic!("expected envelope, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn refresh_env_compat_accepts_path_snapshot() {
        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();
        let (mut state, _) = attached_state(&ctx, tmp.path());

        let mut vars = HashMap::new();
        vars.insert("OPENAI_API_KEY".to_string(), "sk-new".to_string());
        vars.insert(
            "PATH".to_string(),
            "/home/me/.nvm/versions/node/v20/bin".to_string(),
        );
        handle_request(Request::RefreshEnv { vars }, &mut state, &ctx)
            .await
            .expect("PATH is accepted for compatibility");
        assert_eq!(
            overlay_value(&state, "OPENAI_API_KEY").as_deref(),
            Some("sk-new")
        );
        assert_eq!(
            overlay_value(&state, "PATH").as_deref(),
            Some("/home/me/.nvm/versions/node/v20/bin")
        );
    }

    #[tokio::test]
    async fn refresh_env_is_scoped_to_attached_session_overlay() {
        let ctx = test_ctx();
        let tmp_a = tempfile::tempdir().unwrap();
        let tmp_b = tempfile::tempdir().unwrap();
        let (mut state_a, _) = attached_state(&ctx, tmp_a.path());
        let (mut state_b, _) = attached_state(&ctx, tmp_b.path());

        handle_request(
            Request::RefreshEnv {
                vars: HashMap::from([("OPENAI_API_KEY".to_string(), "sk-a".to_string())]),
            },
            &mut state_a,
            &ctx,
        )
        .await
        .expect("refresh a");
        handle_request(
            Request::RefreshEnv {
                vars: HashMap::from([("OPENAI_API_KEY".to_string(), "sk-b".to_string())]),
            },
            &mut state_b,
            &ctx,
        )
        .await
        .expect("refresh b");

        assert_eq!(
            overlay_value(&state_a, "OPENAI_API_KEY").as_deref(),
            Some("sk-a")
        );
        assert_eq!(
            overlay_value(&state_b, "OPENAI_API_KEY").as_deref(),
            Some("sk-b")
        );
    }

    #[test]
    fn env_policy_daemon_keeps_baseline_and_reports_safe_drift() {
        let ctx = test_ctx();
        let baseline = EnvSnapshot::new(
            EnvSnapshotSource::DaemonStart,
            HashMap::from([
                ("PATH".to_string(), "/usr/bin".to_string()),
                ("OPENAI_API_KEY".to_string(), "daemon-secret".to_string()),
            ]),
        );
        *ctx.env_baseline.write().unwrap() = baseline.clone();
        let client = EnvSnapshot::new(
            EnvSnapshotSource::TuiShell,
            HashMap::from([
                (
                    "PATH".to_string(),
                    "/usr/bin:/home/me/.nvm/versions/node/v20/bin".to_string(),
                ),
                ("OPENAI_API_KEY".to_string(), "client-secret".to_string()),
            ]),
        );

        let (chosen, baseline_meta, session_meta, drift, applied) =
            select_session_env(&ctx, Some(client), EnvDriftPolicy::Daemon).unwrap();

        assert_eq!(chosen.digest(), baseline.digest());
        assert_eq!(baseline_meta.digest, baseline.digest());
        assert_eq!(session_meta.digest, baseline.digest());
        assert_eq!(applied, EnvDriftPolicy::Daemon);
        let drift = drift.expect("drift summarized");
        assert_eq!(drift.changed_secret_keys, vec!["OPENAI_API_KEY"]);
        let serialized = serde_json::to_string(&drift).unwrap();
        assert!(!serialized.contains("client-secret"));
        assert!(!serialized.contains("daemon-secret"));
    }

    #[test]
    fn env_policy_update_daemon_replaces_future_baseline() {
        let ctx = test_ctx();
        *ctx.env_baseline.write().unwrap() = EnvSnapshot::new(
            EnvSnapshotSource::DaemonStart,
            HashMap::from([("PATH".to_string(), "/usr/bin".to_string())]),
        );
        let client = EnvSnapshot::new(
            EnvSnapshotSource::TuiShell,
            HashMap::from([("PATH".to_string(), "/opt/node/bin".to_string())]),
        );

        let (chosen, baseline_meta, session_meta, _, applied) =
            select_session_env(&ctx, Some(client.clone()), EnvDriftPolicy::UpdateDaemon).unwrap();

        assert_eq!(chosen.digest(), client.digest());
        assert_eq!(baseline_meta.digest, client.digest());
        assert_eq!(session_meta.digest, client.digest());
        assert_eq!(applied, EnvDriftPolicy::UpdateDaemon);
        assert_eq!(ctx.env_baseline.read().unwrap().digest(), client.digest());
    }

    #[test]
    fn env_policy_error_on_drift_rejects() {
        let ctx = test_ctx();
        *ctx.env_baseline.write().unwrap() = EnvSnapshot::new(
            EnvSnapshotSource::DaemonStart,
            HashMap::from([("PATH".to_string(), "/usr/bin".to_string())]),
        );
        let client = EnvSnapshot::new(
            EnvSnapshotSource::ExplicitCli,
            HashMap::from([("PATH".to_string(), "/custom/bin".to_string())]),
        );

        let err = select_session_env(&ctx, Some(client), EnvDriftPolicy::ErrorOnDrift)
            .expect_err("drift rejected");

        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("environment differs"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn peer_uid_accepts_same_uid_socket_pair() {
        let (left, _right) = UnixStream::pair().expect("socket pair");

        validate_peer_owner(&left).expect("same uid peer is accepted");
        assert_eq!(peer_uid(&left).expect("peer uid"), current_uid());
    }

    #[cfg(unix)]
    #[test]
    fn peer_uid_rejects_mismatched_uid() {
        let daemon_uid = current_uid();
        let peer_uid = daemon_uid.saturating_add(1);

        let err = validate_peer_uid(peer_uid, daemon_uid).expect_err("different uid is rejected");

        let message = format!("{err:#}");
        assert!(message.contains(&format!("peer uid `{peer_uid}`")));
        assert!(message.contains(&format!("daemon uid `{daemon_uid}`")));
    }

    fn insert_hung_worker(ctx: &Arc<DaemonContext>, session_id: Uuid) {
        let session = Arc::new(
            Session::resume(ctx.db.clone(), session_id)
                .unwrap()
                .expect("session row"),
        );
        let locks = Arc::new(LockManager::from_db(ctx.db.clone()).expect("locks"));
        let handle = SessionWorkerHandle::test_handle(session, locks);
        let join = tokio::spawn(async move {
            std::future::pending::<()>().await;
        });
        ctx.registry.insert_test_worker(handle, join);
    }

    #[tokio::test]
    async fn set_agent_rejects_experimental_primary_when_mode_off() {
        let ctx = test_ctx();
        let tmp = tempfile::TempDir::new().unwrap();
        let (mut state, session_id) = attached_state(&ctx, tmp.path());

        let err = handle_request(
            Request::SetAgent {
                name: "Swarm".into(),
            },
            &mut state,
            &ctx,
        )
        .await
        .expect_err("Swarm is gated when experimental mode is off");

        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("agent `Swarm`"));
        assert!(err.message.contains("requires experimental mode"));
        let got = ctx.db.get_session(session_id).unwrap().unwrap();
        assert_eq!(got.active_agent, "Build");
    }

    #[tokio::test]
    async fn set_approval_mode_updates_session_and_broadcasts() {
        let ctx = test_ctx();
        let tmp = tempfile::TempDir::new().unwrap();
        let (mut state, _session_id) = attached_state(&ctx, tmp.path());

        let response = handle_request(
            Request::SetApprovalMode {
                mode: crate::config::extended::ApprovalMode::Yolo,
            },
            &mut state,
            &ctx,
        )
        .await
        .expect("approval mode request succeeds");
        match response {
            Response::ApprovalModeState { mode } => {
                assert_eq!(mode, crate::config::extended::ApprovalMode::Yolo);
            }
            other => panic!("expected ApprovalModeState response, got {other:?}"),
        }

        let attached = state.attached.as_mut().expect("attached session");
        match attached
            .event_rx
            .try_recv()
            .expect("approval broadcast")
            .event
        {
            proto::Event::ApprovalModeState { mode, .. } => {
                assert_eq!(mode, crate::config::extended::ApprovalMode::Yolo);
            }
            other => panic!("expected ApprovalModeState, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn set_agent_rejects_non_ownable_subagent_name() {
        let ctx = test_ctx();
        let tmp = tempfile::TempDir::new().unwrap();
        let (mut state, session_id) = attached_state(&ctx, tmp.path());

        let err = handle_request(Request::SetAgent { name: "bee".into() }, &mut state, &ctx)
            .await
            .expect_err("subagent names are not root primaries");

        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("agent `bee`"));
        assert!(err.message.contains("not a chat-ownable primary"));
        let got = ctx.db.get_session(session_id).unwrap().unwrap();
        assert_eq!(got.active_agent, "Build");
    }

    #[test]
    fn set_agent_allows_swarm_when_experimental_mode_on() {
        let ownable = vec![
            "Auto".to_string(),
            "Plan".to_string(),
            "Build".to_string(),
            "Swarm".to_string(),
            "Build".to_string(),
        ];

        validate_set_agent_name("Swarm", true, &ownable)
            .expect("Swarm is allowed when experimental mode is enabled");
    }

    #[test]
    fn set_agent_allows_build_when_experimental_mode_off() {
        let ownable = vec!["Build".to_string()];

        validate_set_agent_name("Build", false, &ownable)
            .expect("Build remains a chat-ownable primary without experimental mode");
    }

    #[test]
    fn response_send_failure_warns_with_request_id_and_no_payload() {
        let request_id = Uuid::new_v4();
        let log = capture_warn_log(|| {
            let error = anyhow::anyhow!("broken pipe while writing envelope");
            log_response_send_failed(request_id, "error", &error);
        });

        assert!(log.contains(&request_id.to_string()));
        assert!(log.contains("envelope_kind=\"error\"") || log.contains("envelope_kind=error"));
        assert!(log.contains("broken pipe"));
        assert!(!log.contains("secret prompt body"));
        assert!(!log.contains("provider_header"));
    }

    #[tokio::test]
    async fn delete_live_session_timeout_leaves_row_intact() {
        let ctx = test_ctx();
        let mut state = ClientState::detached_for_test();
        let session = ctx.db.create_session("p", "/x", "Build").unwrap();
        insert_hung_worker(&ctx, session.session_id);

        let err = handle_request(
            Request::DeleteSession {
                session_id: session.session_id,
                cascade: false,
            },
            &mut state,
            &ctx,
        )
        .await
        .expect_err("hung worker should block delete");

        assert_eq!(err.code, ErrorCode::Internal);
        assert!(
            err.message
                .contains("refusing destructive session mutation")
        );
        assert!(ctx.db.get_session(session.session_id).unwrap().is_some());
        assert!(
            ctx.registry
                .active_session_ids()
                .contains(&session.session_id)
        );
    }

    #[tokio::test]
    async fn archive_live_session_timeout_leaves_row_unarchived() {
        let ctx = test_ctx();
        let mut state = ClientState::detached_for_test();
        let session = ctx.db.create_session("p", "/x", "Build").unwrap();
        insert_hung_worker(&ctx, session.session_id);

        let err = handle_request(
            Request::ArchiveSession {
                session_id: session.session_id,
                cascade: false,
            },
            &mut state,
            &ctx,
        )
        .await
        .expect_err("hung worker should block archive");

        assert_eq!(err.code, ErrorCode::Internal);
        assert!(
            err.message
                .contains("refusing destructive session mutation")
        );
        let row = ctx
            .db
            .get_session(session.session_id)
            .unwrap()
            .expect("row remains");
        assert!(row.archived_at.is_none());
    }

    #[tokio::test]
    async fn discard_live_ephemeral_session_timeout_leaves_row_intact() {
        let ctx = test_ctx();
        let mut state = ClientState::detached_for_test();
        let parent = ctx.db.create_session("p", "/x", "Build").unwrap();
        let side = ctx
            .db
            .create_ephemeral_fork(parent.session_id, None)
            .unwrap();
        insert_hung_worker(&ctx, side.session_id);

        let err = handle_request(
            Request::DiscardSession {
                session_id: side.session_id,
            },
            &mut state,
            &ctx,
        )
        .await
        .expect_err("hung worker should block discard");

        assert_eq!(err.code, ErrorCode::Internal);
        assert!(
            err.message
                .contains("refusing destructive session mutation")
        );
        assert!(ctx.db.get_session(side.session_id).unwrap().is_some());
    }

    #[tokio::test]
    async fn cascaded_delete_timeout_stops_before_any_db_mutation() {
        let ctx = test_ctx();
        let mut state = ClientState::detached_for_test();
        let root = ctx.db.create_session("p", "/x", "Build").unwrap();
        let child = ctx.db.create_fork(root.session_id, None).unwrap();
        insert_hung_worker(&ctx, child.session_id);

        let err = handle_request(
            Request::DeleteSession {
                session_id: root.session_id,
                cascade: true,
            },
            &mut state,
            &ctx,
        )
        .await
        .expect_err("hung child should block cascaded delete");

        assert_eq!(err.code, ErrorCode::Internal);
        assert!(
            err.message
                .contains("refusing destructive session mutation")
        );
        assert!(ctx.db.get_session(root.session_id).unwrap().is_some());
        assert!(ctx.db.get_session(child.session_id).unwrap().is_some());
    }

    /// The single graceful-shutdown path
    /// (`daemon-graceful-drain-shutdown.md`): the first `request_shutdown`
    /// begins the drain and broadcasts the (non-forced) notice; a **second**
    /// one while still draining **shortens** to force and broadcasts the
    /// forced notice — never a second drain or a reset deadline.
    #[tokio::test]
    async fn second_stop_request_shortens_to_force() {
        let ctx = test_ctx();
        let mut events = ctx.subscribe_global();
        assert_eq!(ctx.shutdown.phase(), ShutdownPhase::Running);

        // First request: begin drain + non-forced notice.
        request_shutdown(&ctx);
        assert_eq!(ctx.shutdown.phase(), ShutdownPhase::Draining);
        match events.recv().await.expect("drain notice").event {
            proto::Event::DaemonDraining { forced } => assert!(!forced),
            other => panic!("expected DaemonDraining, got {other:?}"),
        }

        // Second request mid-drain: shorten to force + forced notice.
        request_shutdown(&ctx);
        assert_eq!(ctx.shutdown.phase(), ShutdownPhase::Forced);
        match events.recv().await.expect("forced notice").event {
            proto::Event::DaemonDraining { forced } => assert!(forced),
            other => panic!("expected forced DaemonDraining, got {other:?}"),
        }

        // A third request is a no-op — already forced, no further events.
        request_shutdown(&ctx);
        assert_eq!(ctx.shutdown.phase(), ShutdownPhase::Forced);
    }

    /// `/note` (`RecordSessionNote`) records a durable `user_note` session
    /// event and returns its `seq` — without enqueueing any work on a worker
    /// (no inference). The event is queryable for export immediately.
    #[tokio::test]
    async fn record_session_note_persists_event_without_inference() {
        let ctx = test_ctx();
        let mut state = ClientState::detached_for_test();
        let s = ctx.db.create_session("p", "/x", "Build").unwrap();

        let resp = handle_request(
            Request::RecordSessionNote {
                session_id: s.session_id,
                text: "remember the retry change broke it".into(),
            },
            &mut state,
            &ctx,
        )
        .await
        .expect("note recorded");
        let seq = match resp {
            Response::NoteRecorded { seq } => seq,
            other => panic!("expected NoteRecorded, got {other:?}"),
        };
        assert!(seq > 0);

        // The event landed durably with its discriminant + verbatim text, and
        // no worker/turn was started (no AttachedSession was ever created).
        let events = ctx.db.list_session_events(s.session_id).unwrap();
        assert_eq!(
            events.len(),
            1,
            "exactly the note event — no inference turn"
        );
        assert_eq!(events[0].kind, "user_note");
        assert_eq!(
            events[0].data.get("text").and_then(|v| v.as_str()),
            Some("remember the retry change broke it")
        );
        assert!(state.attached.is_none(), "no worker attached / spawned");
    }

    /// `RecordSessionNote` for an unknown session is an `UnknownSession` error
    /// — never a phantom session created just to hold the note.
    #[tokio::test]
    async fn record_session_note_unknown_session_errors() {
        let ctx = test_ctx();
        let mut state = ClientState::detached_for_test();
        let err = handle_request(
            Request::RecordSessionNote {
                session_id: Uuid::new_v4(),
                text: "x".into(),
            },
            &mut state,
            &ctx,
        )
        .await
        .expect_err("unknown session must error");
        assert_eq!(err.code, ErrorCode::UnknownSession);
    }

    /// New-user-work gate: once draining, `SendUserMessage` is refused with
    /// the `Shutdown` error code rather than dropped or queued.
    #[tokio::test]
    async fn send_user_message_refused_while_draining() {
        let ctx = test_ctx();
        let mut state = ClientState::detached_for_test();

        ctx.shutdown.begin_drain();

        let err = handle_request(
            Request::SendUserMessage {
                text: "hi".into(),
                image_refs: vec![],
                forced_skill: None,
            },
            &mut state,
            &ctx,
        )
        .await
        .expect_err("draining daemon must refuse new user messages");
        assert_eq!(err.code, ErrorCode::Shutdown);
    }

    #[tokio::test]
    async fn resync_drain_state_sends_nothing_while_running() {
        let ctx = test_ctx();
        let (left, right) = tokio::io::duplex(proto::MAX_FRAME_BYTES);
        let mut server = ProtoStream::new(left);
        let mut client = ProtoStream::new(right);

        ctx.resync_drain_state(&mut server)
            .await
            .expect("running resync should not fail");

        let recv = tokio::time::timeout(std::time::Duration::from_millis(20), client.recv()).await;
        assert!(recv.is_err(), "running phase should not emit an envelope");
    }

    #[tokio::test]
    async fn resync_drain_state_replays_draining_and_forced() {
        let ctx = test_ctx();
        let (left, right) = tokio::io::duplex(proto::MAX_FRAME_BYTES);
        let mut server = ProtoStream::new(left);
        let mut client = ProtoStream::new(right);

        assert!(ctx.shutdown.begin_drain());
        ctx.resync_drain_state(&mut server)
            .await
            .expect("draining resync");
        match recv_body(&mut client).await {
            Body::Event {
                event: proto::Event::DaemonDraining { forced },
            } => assert!(!forced),
            other => panic!("expected non-forced DaemonDraining, got {other:?}"),
        }

        ctx.shutdown.force();
        ctx.resync_drain_state(&mut server)
            .await
            .expect("forced resync");
        match recv_body(&mut client).await {
            Body::Event {
                event: proto::Event::DaemonDraining { forced },
            } => assert!(forced),
            other => panic!("expected forced DaemonDraining, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn attach_replays_drain_state_after_attached_response() {
        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();
        ctx.db
            .set_workspace_trust(
                tmp.path(),
                crate::db::workspace_trust::WorkspaceTrustMode::Trust,
            )
            .unwrap();
        let session = ctx
            .db
            .create_session("p", tmp.path().to_str().unwrap(), "Build")
            .unwrap();
        let live_session = Arc::new(
            Session::resume(ctx.db.clone(), session.session_id)
                .unwrap()
                .expect("session row"),
        );
        let (handle, _work_rx) =
            SessionWorkerHandle::test_handle_with_receiver(live_session, ctx.registry.locks());
        let join = tokio::spawn(async move {
            std::future::pending::<()>().await;
        });
        ctx.registry.insert_test_worker(handle, join);
        assert!(ctx.shutdown.begin_drain());

        let (left, right) = tokio::io::duplex(proto::MAX_FRAME_BYTES);
        let mut server = ProtoStream::new(left);
        let mut client = ProtoStream::new(right);
        let mut state = ClientState::detached_for_test();
        let request_id = Uuid::new_v4();
        handle_envelope(
            Envelope::request(
                request_id,
                Request::Attach {
                    session_id: Some(session.session_id),
                    project_root: Some(tmp.path().to_string_lossy().into_owned()),
                    no_sandbox: false,
                    interactive: true,
                    model_override: None,
                    client_protocol_version: proto::PROTOCOL_VERSION,
                    env_snapshot: None,
                    env_policy: EnvDriftPolicy::Daemon,
                },
            ),
            &mut state,
            &ctx,
            &mut server,
        )
        .await
        .expect("attach envelope handled");

        match recv_body(&mut client).await {
            Body::Response { id, response } => {
                let Response::Attached { session_id, .. } = *response else {
                    panic!("expected Attached response, got {response:?}");
                };
                assert_eq!(id, request_id);
                assert_eq!(session_id, session.session_id);
            }
            other => panic!("expected Attached response, got {other:?}"),
        }
        match recv_body(&mut client).await {
            Body::Event {
                event: proto::Event::DaemonDraining { forced },
            } => assert!(!forced),
            other => panic!("expected DaemonDraining replay, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn attach_compatible_reflects_client_protocol_version() {
        let ctx = test_ctx();
        let tmp = tempfile::tempdir().unwrap();
        ctx.db
            .set_workspace_trust(
                tmp.path(),
                crate::db::workspace_trust::WorkspaceTrustMode::Trust,
            )
            .unwrap();

        let mut state = ClientState::detached_for_test();
        let response = handle_request(
            Request::Attach {
                session_id: None,
                project_root: Some(tmp.path().to_string_lossy().into_owned()),
                no_sandbox: false,
                interactive: true,
                model_override: None,
                client_protocol_version: 0,
                env_snapshot: None,
                env_policy: EnvDriftPolicy::Daemon,
            },
            &mut state,
            &ctx,
        )
        .await
        .expect("old client attaches");
        match response {
            Response::Attached { compatible, .. } => assert!(!compatible),
            other => panic!("expected Attached, got {other:?}"),
        }

        let mut state = ClientState::detached_for_test();
        let response = handle_request(
            Request::Attach {
                session_id: None,
                project_root: Some(tmp.path().to_string_lossy().into_owned()),
                no_sandbox: false,
                interactive: true,
                model_override: None,
                client_protocol_version: proto::PROTOCOL_VERSION,
                env_snapshot: None,
                env_policy: EnvDriftPolicy::Daemon,
            },
            &mut state,
            &ctx,
        )
        .await
        .expect("current client attaches");
        match response {
            Response::Attached { compatible, .. } => assert!(compatible),
            other => panic!("expected Attached, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn server_answers_too_new_request_with_protocol_version_error() {
        let ctx = test_ctx();
        let (server_stream, client_stream) = UnixStream::pair().expect("socket pair");
        let server = tokio::spawn(handle_client(server_stream, ctx));
        let mut client = ProtoStream::new(client_stream);

        // Initial hello + caffeinate snapshot.
        let _ = recv_body(&mut client).await;
        let _ = recv_body(&mut client).await;

        let id = Uuid::new_v4();
        client
            .send_raw_line(
                serde_json::json!({
                    "v": 999,
                    "kind": "req",
                    "id": id,
                    "request": "daemon_status"
                })
                .to_string(),
            )
            .await
            .unwrap();

        match recv_body(&mut client).await {
            Body::Error {
                id: Some(got_id),
                error,
            } => {
                assert_eq!(got_id, id);
                assert_eq!(error.code, ErrorCode::ProtocolVersion);
                assert!(error.message.contains("wire protocol version mismatch"));
            }
            other => panic!("expected protocol version error, got {other:?}"),
        }
        assert!(matches!(client.recv().await.unwrap(), None));
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn attach_requires_db_workspace_trust_row() {
        let ctx = test_ctx();
        let mut state = ClientState::detached_for_test();
        let tmp = tempfile::tempdir().unwrap();

        let err = handle_request(
            Request::Attach {
                session_id: None,
                project_root: Some(tmp.path().to_string_lossy().into_owned()),
                no_sandbox: false,
                interactive: true,
                model_override: None,
                client_protocol_version: proto::PROTOCOL_VERSION,
                env_snapshot: None,
                env_policy: EnvDriftPolicy::Daemon,
            },
            &mut state,
            &ctx,
        )
        .await
        .expect_err("daemon attach must fail closed without a trust row");

        assert_eq!(err.code, ErrorCode::Internal);
        assert!(err.message.contains("workspace trust is not set"));
        assert!(state.attached.is_none());
    }

    #[test]
    fn daemon_load_configs_uses_session_policy_over_global_policy() {
        let trusted = tempfile::tempdir().unwrap();
        let ignored = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(trusted.path().join(".cockpit")).unwrap();
        std::fs::create_dir_all(ignored.path().join(".cockpit")).unwrap();
        std::fs::write(
            ignored.path().join(".cockpit").join("config.json"),
            r#"{"max_primary_rounds": 77}"#,
        )
        .unwrap();

        crate::config::trust::clear_runtime_policy_for_tests();
        let global_root = crate::config::trust::resolve_trust_root(trusted.path()).unwrap();
        crate::config::trust::set_runtime_policy(
            global_root,
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        );
        let session_policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(ignored.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        };

        let (_, extended) = load_configs_with_trust(ignored.path(), &session_policy).unwrap();

        assert_ne!(extended.max_primary_rounds, 77);
        crate::config::trust::clear_runtime_policy_for_tests();
    }
}
