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
use crate::config::providers::ProvidersConfig;
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

fn scrub_proto_response(
    response: proto::Response,
    redact: &RedactionTable,
) -> Option<proto::Response> {
    let mut value = match serde_json::to_value(&response) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(error = %error, "serializing response for redaction failed; dropping response");
            return None;
        }
    };
    scrub_json_strings(&mut value, redact);
    match serde_json::from_value(value) {
        Ok(response) => Some(response),
        Err(error) => {
            tracing::warn!(error = %error, "deserializing redacted response failed; dropping response");
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
    shutdown_grace_override: StdMutex<Option<Duration>>,
    env_baseline: Arc<std::sync::RwLock<EnvSnapshot>>,
    upload_accounting: Arc<StdMutex<UploadAccounting>>,
    connector_wake: watch::Sender<u64>,
    credential_store_path: Option<PathBuf>,
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
            shutdown_grace_override: StdMutex::new(None),
            env_baseline: Arc::new(std::sync::RwLock::new(EnvSnapshot::from_process(
                EnvSnapshotSource::DaemonStart,
            ))),
            upload_accounting: Arc::new(StdMutex::new(UploadAccounting::default())),
            connector_wake,
            credential_store_path: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_credential_store_path(mut self, path: PathBuf) -> Self {
        self.credential_store_path = Some(path);
        self
    }

    pub(crate) fn store_flycockpit_credential(
        &self,
        credential: &crate::auth::flycockpit::StoredFlycockpitCredential,
    ) -> Result<()> {
        if let Some(path) = &self.credential_store_path {
            crate::auth::flycockpit::store_credential_at_path(path.clone(), credential)
        } else {
            crate::auth::flycockpit::store_credential(credential)
        }
    }

    pub(crate) fn clear_flycockpit_credential(&self) -> Result<()> {
        if let Some(path) = &self.credential_store_path {
            crate::auth::flycockpit::clear_credential_at_path(path.clone())
        } else {
            crate::auth::flycockpit::clear_credential()
        }
    }

    /// The daemon's graceful-shutdown gate. New-user-work rejection and the
    /// single drain path both read it.
    pub fn shutdown_signal(&self) -> &crate::daemon::shutdown::ShutdownSignal {
        &self.shutdown
    }

    pub fn set_shutdown_grace_override(&self, grace: Duration) {
        *crate::sync::lock_or_recover(&self.shutdown_grace_override) = Some(grace);
    }

    pub fn take_shutdown_grace_override(&self) -> Option<Duration> {
        crate::sync::lock_or_recover(&self.shutdown_grace_override).take()
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
    let ctx = boot_with_db(paths, db, &mut timer)?;
    timer.done();
    Ok(ctx)
}

pub(crate) fn boot_with_db(
    paths: DaemonPaths,
    db: Db,
    timer: &mut crate::startup::PhaseTimer,
) -> Result<DaemonContext> {
    timer.phase("db_open_and_migrate");
    let locks = Arc::new(LockManager::from_db(db.clone()).context("loading lock state")?);
    timer.phase("lock_manager");
    run_boot_housekeeping(&db);
    timer.phase("prune_and_sweep");
    let ctx = DaemonContext::new(db, locks, paths);
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
    pending_replay: Vec<proto::Event>,
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
            pending_replay: Vec::new(),
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
                if is_attach && attached {
                    for event in std::mem::take(&mut state.pending_replay) {
                        if event_tx.send(event).await.is_err() {
                            return;
                        }
                    }
                    if let Some(event) = ctx.drain_state_event()
                        && event_tx.send(event).await.is_err()
                    {
                        return;
                    }
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
            database_path: ctx
                .db
                .path()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<in-memory>".to_string()),
            schema_version: ctx.db.schema_version().unwrap_or(0),
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
                Ok(response) => {
                    let response = if state.principal.is_owner() {
                        Some(response)
                    } else if let Some(attached) = state.attached.as_ref() {
                        scrub_proto_response(response, &attached.handle.redaction_table())
                    } else {
                        // Session-bearing responses without an attachment must
                        // scrub inside their request arm using the target
                        // session's persisted table (for example
                        // `SubagentTranscript`). Other unattached responses do
                        // not carry session user content.
                        Some(response)
                    };
                    match response {
                        Some(response) => Envelope::response(id, response),
                        None => Envelope::error(
                            Some(id),
                            ErrorPayload {
                                code: ErrorCode::Internal,
                                message: "response redaction failed".to_string(),
                            },
                        ),
                    }
                }
                Err(err) => Envelope::error(Some(id), err),
            };
            if let Err(error) = proto.send(&envelope).await {
                log_response_send_failed(id, envelope_kind(&envelope), &error);
            }
            if is_attach && attached {
                for event in std::mem::take(&mut state.pending_replay) {
                    if let Err(error) = proto.send(&Envelope::event(event)).await {
                        tracing::debug!(error = ?error, "client disconnected during attach replay");
                        return Ok(());
                    }
                }
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

include!("authz.rs");
include!("attachments.rs");
include!("dispatch.rs");
include!("sessions.rs");
include!("tests.rs");
