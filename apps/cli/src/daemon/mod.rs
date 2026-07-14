//! Daemon process + client. cockpit's daemon owns the session DB, the
//! lock manager, the redaction table, the provider clients, and the
//! configuration resolver (GOALS §8). The TUI is a *client* of the
//! daemon, not the process that does the work.
//!
//! Process layout:
//!
//! - [`proto`] — NDJSON wire schema. Same envelope shape for in-process
//!   channels, the Unix-socket transport, and (later) the WebSocket
//!   relay (`cockpit connect`, GOALS §8d).
//! - `server` (P2) — accept loop + per-client task + per-session worker.
//! - `client` (P3) — typed client over the proto.
//!
//! Lifecycle:
//!
//! - PID file at `$XDG_STATE_HOME/cockpit/daemon.pid`.
//! - Unix socket at `$XDG_RUNTIME_DIR/cockpit/cockpit.sock`, fallback
//!   to `$XDG_STATE_HOME/cockpit/daemon.sock`. Socket file mode is
//!   0600.
//! - First `cockpit` invocation auto-promotes via setsid + double-fork
//!   (GOALS §8b); the foreground terminal becomes a TUI client attached
//!   to the freshly spawned daemon. `cockpit daemon {start, stop,
//!   status}` lets the user manage the lifecycle explicitly.

pub mod caffeinate;
pub mod client;
pub mod connector;
pub mod ephemeral_guard;
pub mod fs_api;
pub mod lsp;
pub mod org_sync;
pub mod principal;
pub mod proto;
pub mod registry;
pub mod relay_envelope;
pub mod remote_audit_upload;
pub mod server;
pub mod session_worker;
pub mod shutdown;
pub mod terminal_host;
#[cfg(test)]
pub(crate) mod test_harness;

#[cfg(unix)]
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::private_fs::ensure_private_dir;
#[cfg(unix)]
use crate::private_fs::with_private_umask;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use tokio::io::AsyncBufReadExt;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

use crate::redact::RedactionTable;

/// In-daemon event broadcast item. The wire schema remains proto::Event;
/// the envelope pins the accumulated redaction table that was live when the
/// event was emitted so each client can scrub with the correct snapshot.
#[derive(Debug, Clone)]
pub struct EventEnvelope {
    pub event: proto::Event,
    pub redact: Arc<RedactionTable>,
}

pub type EventSender = broadcast::Sender<EventEnvelope>;
pub type EventReceiver = broadcast::Receiver<EventEnvelope>;
pub type SharedRedactionTable = Arc<std::sync::RwLock<Arc<RedactionTable>>>;

pub fn current_redaction(table: &SharedRedactionTable) -> Arc<RedactionTable> {
    table
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

pub fn set_current_redaction(table: &SharedRedactionTable, redact: Arc<RedactionTable>) {
    *table
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = redact;
}

pub fn send_current_event(tx: &EventSender, redact: &SharedRedactionTable, event: proto::Event) {
    send_event(tx, &current_redaction(redact), event);
}

pub fn send_event(tx: &EventSender, redact: &Arc<RedactionTable>, event: proto::Event) {
    let _ = tx.send(EventEnvelope {
        event,
        redact: redact.clone(),
    });
}

/// Env var carrying the ephemeral daemon's socket path from the parent
/// `run` process to the daemon child it spawns. Internal wiring only —
/// never exposed on the user-facing CLI surface (Layer B). Its presence
/// is also what flips the child into ephemeral mode (enabling the
/// self-reaping watchdog, Layer C).
const EPHEMERAL_SOCKET_ENV: &str = "COCKPIT_EPHEMERAL_SOCKET";
/// Companion to [`EPHEMERAL_SOCKET_ENV`]: the ephemeral pid-file path.
const EPHEMERAL_PID_ENV: &str = "COCKPIT_EPHEMERAL_PID_FILE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonPaths {
    pub pid_file: PathBuf,
    pub socket: PathBuf,
    /// True for a per-run ephemeral daemon (unique
    /// `cockpit-eph-<pid>-<nonce>` paths); false for the canonical persistent daemon. Gates the
    /// idle-reaping watchdog (Layer C) — the persistent daemon must
    /// never self-exit on idle.
    pub ephemeral: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonEndpointRecord {
    version: u8,
    pid: u32,
    socket: PathBuf,
    kind: DaemonEndpointKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DaemonEndpointKind {
    Persistent,
}

#[derive(Debug, Clone)]
pub struct DaemonProbe {
    pub status: DaemonStatus,
    pub paths: DaemonPaths,
}

impl DaemonProbe {
    fn new(status: DaemonStatus, paths: DaemonPaths) -> Self {
        Self { status, paths }
    }
}

fn endpoint_file() -> Result<PathBuf> {
    Ok(endpoint_file_for_state(
        &state_dir().context("could not locate state dir")?,
    ))
}

fn endpoint_file_for_state(state: &Path) -> PathBuf {
    state.join("daemon-endpoint.json")
}

fn read_endpoint_record() -> Option<DaemonEndpointRecord> {
    let path = endpoint_file().ok()?;
    read_endpoint_record_from(&path)
}

fn read_endpoint_record_from(path: &Path) -> Option<DaemonEndpointRecord> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_endpoint_record(paths: &DaemonPaths) -> Result<()> {
    write_endpoint_record_with_pid(paths, std::process::id())
}

fn write_endpoint_record_with_pid(paths: &DaemonPaths, pid: u32) -> Result<()> {
    let canonical = DaemonPaths::resolve_canonical()
        .context("resolving canonical daemon paths for endpoint publication")?;
    write_endpoint_record_with_pid_and_canonical(paths, &canonical, pid)
}

fn write_endpoint_record_with_pid_and_canonical(
    paths: &DaemonPaths,
    canonical: &DaemonPaths,
    pid: u32,
) -> Result<()> {
    if paths.ephemeral {
        return Ok(());
    }
    if paths != canonical {
        anyhow::bail!(
            "refusing to publish shared daemon endpoint from noncanonical paths: pid_file={}, socket={}",
            paths.pid_file.display(),
            paths.socket.display()
        );
    }
    let record = DaemonEndpointRecord {
        version: 1,
        pid,
        socket: paths.socket.clone(),
        kind: DaemonEndpointKind::Persistent,
    };
    let Some(state) = paths.pid_file.parent() else {
        anyhow::bail!(
            "daemon pid file has no parent: {}",
            paths.pid_file.display()
        );
    };
    let path = endpoint_file_for_state(state);
    let data = serde_json::to_vec_pretty(&record).context("serializing daemon endpoint")?;
    std::fs::write(&path, data).with_context(|| format!("writing {}", path.display()))
}

fn remove_endpoint_record_if_owned(paths: &DaemonPaths) {
    if paths.ephemeral {
        return;
    }
    let Ok(canonical) = DaemonPaths::resolve_canonical() else {
        tracing::debug!("skipping shared daemon endpoint cleanup: canonical paths unavailable");
        return;
    };
    remove_endpoint_record_if_owned_with_canonical(paths, &canonical);
}

fn remove_endpoint_record_if_owned_with_canonical(paths: &DaemonPaths, canonical: &DaemonPaths) {
    if paths.ephemeral {
        return;
    }
    if paths != canonical {
        tracing::debug!(
            pid_file = %paths.pid_file.display(),
            socket = %paths.socket.display(),
            "skipping shared daemon endpoint cleanup for noncanonical paths"
        );
        return;
    }
    let Some(state) = canonical.pid_file.parent() else {
        return;
    };
    let path = endpoint_file_for_state(state);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => return,
    };
    let Ok(record) = serde_json::from_slice::<DaemonEndpointRecord>(&bytes) else {
        return;
    };
    if record.pid == std::process::id() && record.socket == paths.socket {
        let _ = std::fs::remove_file(path);
    }
}

fn remove_endpoint_record_unverified() {
    if let Ok(path) = endpoint_file() {
        let _ = std::fs::remove_file(path);
    }
}

impl DaemonPaths {
    /// Resolve the daemon paths. A daemon child spawned for an
    /// ephemeral run inherits its unique path set from
    /// [`EPHEMERAL_SOCKET_ENV`] / [`EPHEMERAL_PID_ENV`] (set by the
    /// parent via [`spawn_detached_ephemeral`]); everyone else gets the
    /// canonical persistent path set.
    pub fn resolve() -> Result<Self> {
        if let Some(paths) = Self::from_ephemeral_env()? {
            return Ok(paths);
        }
        Self::resolve_canonical()
    }

    /// The canonical persistent daemon's path set. `cockpit daemon
    /// {start,stop,status}` operate exclusively on these.
    pub fn resolve_canonical() -> Result<Self> {
        let state = state_dir().context("could not locate state dir")?;
        ensure_private_dir(&state).with_context(|| format!("securing {}", state.display()))?;
        let pid_file = state.join("daemon.pid");
        let socket = if let Some(rt) = runtime_dir() {
            ensure_private_dir(&rt).with_context(|| format!("securing {}", rt.display()))?;
            rt.join("cockpit.sock")
        } else {
            state.join("daemon.sock")
        };
        Ok(Self {
            pid_file,
            socket,
            ephemeral: false,
        })
    }

    #[cfg(test)]
    fn resolve_canonical_in(state_home: &Path, runtime_dir: Option<&Path>) -> Result<Self> {
        let state = state_home.join("cockpit");
        ensure_private_dir(&state).with_context(|| format!("securing {}", state.display()))?;
        let pid_file = state.join("daemon.pid");
        let socket = if let Some(rt) = runtime_dir {
            let rt = rt.join("cockpit");
            ensure_private_dir(&rt).with_context(|| format!("securing {}", rt.display()))?;
            rt.join("cockpit.sock")
        } else {
            state.join("daemon.sock")
        };
        Ok(Self {
            pid_file,
            socket,
            ephemeral: false,
        })
    }

    /// Allocate a unique ephemeral path set:
    /// `cockpit-eph-<pid>-<nonce>.sock` + `cockpit-eph-<pid>-<nonce>.pid`,
    /// in the same directory the canonical socket/pid would live in.
    /// The parent computes this once and hands the exact paths to the
    /// child it spawns (Layer B).
    pub fn allocate_ephemeral() -> Result<Self> {
        Self::ephemeral_with_nonce(
            std::process::id(),
            uuid::Uuid::new_v4().simple().to_string(),
        )
    }

    #[cfg(test)]
    fn allocate_ephemeral_for_test_in(
        pid: u32,
        state_home: &Path,
        runtime_dir: Option<&Path>,
    ) -> Result<Self> {
        Self::ephemeral_with_nonce_in(
            pid,
            uuid::Uuid::new_v4().simple().to_string(),
            state_home,
            runtime_dir,
        )
    }

    fn ephemeral_with_nonce(pid: u32, nonce: String) -> Result<Self> {
        let state = state_dir().context("could not locate state dir")?;
        ensure_private_dir(&state).with_context(|| format!("securing {}", state.display()))?;
        let stem = format!("cockpit-eph-{pid}-{nonce}");
        let pid_file = state.join(format!("{stem}.pid"));
        let socket = if let Some(rt) = runtime_dir() {
            ensure_private_dir(&rt).with_context(|| format!("securing {}", rt.display()))?;
            rt.join(format!("{stem}.sock"))
        } else {
            state.join(format!("{stem}.sock"))
        };
        Ok(Self {
            pid_file,
            socket,
            ephemeral: true,
        })
    }

    #[cfg(test)]
    fn ephemeral_with_nonce_in(
        pid: u32,
        nonce: String,
        state_home: &Path,
        runtime_dir: Option<&Path>,
    ) -> Result<Self> {
        let state = state_home.join("cockpit");
        ensure_private_dir(&state).with_context(|| format!("securing {}", state.display()))?;
        let stem = format!("cockpit-eph-{pid}-{nonce}");
        let pid_file = state.join(format!("{stem}.pid"));
        let socket = if let Some(rt) = runtime_dir {
            let rt = rt.join("cockpit");
            ensure_private_dir(&rt).with_context(|| format!("securing {}", rt.display()))?;
            rt.join(format!("{stem}.sock"))
        } else {
            state.join(format!("{stem}.sock"))
        };
        Ok(Self {
            pid_file,
            socket,
            ephemeral: true,
        })
    }

    /// Reconstruct the ephemeral path set the parent chose, from the
    /// internal env vars. Returns `Ok(None)` when not running as an
    /// ephemeral child (the common case).
    fn from_ephemeral_env() -> Result<Option<Self>> {
        let socket = std::env::var_os(EPHEMERAL_SOCKET_ENV);
        let pid_file = std::env::var_os(EPHEMERAL_PID_ENV);
        Self::from_ephemeral_values(socket.map(PathBuf::from), pid_file.map(PathBuf::from))
    }

    #[cfg(test)]
    fn from_ephemeral_paths(
        socket: Option<PathBuf>,
        pid_file: Option<PathBuf>,
    ) -> Result<Option<Self>> {
        Self::from_ephemeral_values(socket, pid_file)
    }

    fn from_ephemeral_values(
        socket: Option<PathBuf>,
        pid_file: Option<PathBuf>,
    ) -> Result<Option<Self>> {
        match (socket, pid_file) {
            (Some(socket), Some(pid_file)) => {
                if let Some(parent) = socket.parent() {
                    ensure_private_dir(parent)
                        .with_context(|| format!("securing {}", parent.display()))?;
                }
                Ok(Some(Self {
                    pid_file,
                    socket,
                    ephemeral: true,
                }))
            }
            _ => Ok(None),
        }
    }
}

fn state_dir() -> Option<PathBuf> {
    if let Ok(s) = std::env::var("XDG_STATE_HOME")
        && !s.trim().is_empty()
    {
        return Some(PathBuf::from(s).join("cockpit"));
    }
    let home = dirs::home_dir()?;
    Some(home.join(".local/state/cockpit"))
}

fn runtime_dir() -> Option<PathBuf> {
    if let Ok(s) = std::env::var("XDG_RUNTIME_DIR")
        && !s.trim().is_empty()
    {
        return Some(PathBuf::from(s).join("cockpit"));
    }
    None
}

#[cfg(unix)]
fn bind_private_socket(socket: &std::path::Path) -> Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = socket.parent() {
        ensure_private_dir(parent).with_context(|| format!("securing {}", parent.display()))?;
    }
    let listener = with_private_umask(0o177, || {
        UnixListener::bind(socket).with_context(|| format!("binding {}", socket.display()))
    })?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", socket.display()))?;
    let mode = std::fs::metadata(socket)
        .with_context(|| format!("stat {}", socket.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        anyhow::bail!(
            "refusing to use {}: expected private socket mode 0600, got {mode:03o}",
            socket.display()
        );
    }
    Ok(listener)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonStatus {
    /// Daemon is running and the socket accepts a connection.
    Running,
    /// PID file exists and belongs to a verified cockpit daemon, but no
    /// socket path we know about answers the daemon handshake.
    LivePidSocketUnreachable,
    /// PID file exists and names a live process whose identity could not be
    /// verified. Mutating commands must fail closed rather than assuming it is
    /// safe to ignore or signal.
    UnverifiedPid,
    /// PID file exists but the process is dead, not a daemon, or the socket is gone.
    Stale,
    /// No PID file.
    NotRunning,
}

#[cfg(unix)]
async fn socket_responds(socket: &Path) -> bool {
    if !socket.exists() {
        return false;
    }
    match tokio::time::timeout(Duration::from_millis(500), UnixStream::connect(socket)).await {
        Ok(Ok(mut stream)) => {
            let mut reader = tokio::io::BufReader::new(&mut stream);
            let mut line = String::new();
            matches!(
                tokio::time::timeout(Duration::from_millis(500), reader.read_line(&mut line)).await,
                Ok(Ok(_)) if !line.is_empty()
            )
        }
        _ => false,
    }
}

#[cfg(unix)]
fn socket_responds_blocking(socket: &Path) -> bool {
    use std::os::unix::net::UnixStream as StdUnixStream;

    if !socket.exists() {
        return false;
    }
    match StdUnixStream::connect(socket) {
        Ok(s) => {
            let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
            let mut buf = String::new();
            let mut r = BufReader::new(&s);
            r.read_line(&mut buf).is_ok() && !buf.is_empty()
        }
        Err(_) => false,
    }
}

#[cfg(unix)]
fn status_for_unreachable_pid(paths: &DaemonPaths) -> DaemonStatus {
    status_for_unreachable_pid_with_cleanup(paths, remove_endpoint_record_unverified)
}

#[cfg(unix)]
fn status_for_unreachable_pid_with_cleanup(
    paths: &DaemonPaths,
    cleanup: impl FnOnce(),
) -> DaemonStatus {
    let Some(pid) = read_pid(paths) else {
        return DaemonStatus::Stale;
    };
    status_for_pid_identity(verify_daemon_pid_identity(pid), cleanup)
}

#[cfg(unix)]
fn status_for_pid_identity(identity: PidIdentity, cleanup: impl FnOnce()) -> DaemonStatus {
    match identity {
        PidIdentity::VerifiedDaemon => DaemonStatus::LivePidSocketUnreachable,
        PidIdentity::Missing | PidIdentity::NotDaemon => {
            cleanup();
            DaemonStatus::Stale
        }
        PidIdentity::Unverified => DaemonStatus::UnverifiedPid,
    }
}

#[cfg(not(unix))]
fn status_for_unreachable_pid(_paths: &DaemonPaths) -> DaemonStatus {
    DaemonStatus::Stale
}

fn endpoint_paths(canonical: &DaemonPaths, record: &DaemonEndpointRecord) -> DaemonPaths {
    DaemonPaths {
        pid_file: canonical.pid_file.clone(),
        socket: record.socket.clone(),
        ephemeral: false,
    }
}

pub async fn discover() -> DaemonProbe {
    let canonical = match DaemonPaths::resolve_canonical() {
        Ok(paths) => paths,
        Err(_) => {
            return DaemonProbe::new(
                DaemonStatus::Stale,
                DaemonPaths {
                    pid_file: PathBuf::from("daemon.pid"),
                    socket: PathBuf::from("cockpit.sock"),
                    ephemeral: false,
                },
            );
        }
    };

    if let Some(record) = read_endpoint_record()
        && record.kind == DaemonEndpointKind::Persistent
    {
        let recorded = endpoint_paths(&canonical, &record);
        if socket_responds(&recorded.socket).await {
            return DaemonProbe::new(DaemonStatus::Running, recorded);
        }
        if !canonical.socket.exists() && canonical.pid_file.exists() {
            return DaemonProbe::new(status_for_unreachable_pid(&canonical), recorded);
        }
    }

    DaemonProbe::new(probe_direct(&canonical).await, canonical)
}

#[cfg(test)]
thread_local! {
    static BLOCKING_PROBE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_blocking_probe_call_count() {
    BLOCKING_PROBE_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
pub(crate) fn blocking_probe_call_count() -> usize {
    BLOCKING_PROBE_CALLS.with(std::cell::Cell::get)
}

fn note_blocking_probe_call() {
    #[cfg(test)]
    BLOCKING_PROBE_CALLS.with(|calls| calls.set(calls.get() + 1));
}

pub fn discover_blocking() -> DaemonProbe {
    note_blocking_probe_call();
    let canonical = match DaemonPaths::resolve_canonical() {
        Ok(paths) => paths,
        Err(_) => {
            return DaemonProbe::new(
                DaemonStatus::Stale,
                DaemonPaths {
                    pid_file: PathBuf::from("daemon.pid"),
                    socket: PathBuf::from("cockpit.sock"),
                    ephemeral: false,
                },
            );
        }
    };

    if let Some(record) = read_endpoint_record()
        && record.kind == DaemonEndpointKind::Persistent
    {
        let recorded = endpoint_paths(&canonical, &record);
        if socket_responds_blocking(&recorded.socket) {
            return DaemonProbe::new(DaemonStatus::Running, recorded);
        }
        if !canonical.socket.exists() && canonical.pid_file.exists() {
            return DaemonProbe::new(status_for_unreachable_pid(&canonical), recorded);
        }
    }

    DaemonProbe::new(probe_direct_blocking(&canonical), canonical)
}

#[cfg(test)]
fn discover_blocking_with_canonical(canonical: DaemonPaths) -> DaemonProbe {
    note_blocking_probe_call();
    if let Some(state) = canonical.pid_file.parent() {
        let endpoint = endpoint_file_for_state(state);
        if let Some(record) = read_endpoint_record_from(&endpoint)
            && record.kind == DaemonEndpointKind::Persistent
        {
            let recorded = endpoint_paths(&canonical, &record);
            if socket_responds_blocking(&recorded.socket) {
                return DaemonProbe::new(DaemonStatus::Running, recorded);
            }
            if !canonical.socket.exists() && canonical.pid_file.exists() {
                let status = status_for_unreachable_pid_with_cleanup(&canonical, || {
                    let _ = std::fs::remove_file(&endpoint);
                });
                return DaemonProbe::new(status, recorded);
            }
        }
    }

    DaemonProbe::new(probe_direct_blocking(&canonical), canonical)
}

#[cfg(unix)]
async fn probe_direct(paths: &DaemonPaths) -> DaemonStatus {
    if socket_responds(&paths.socket).await {
        return DaemonStatus::Running;
    }
    if paths.pid_file.exists() {
        status_for_unreachable_pid(paths)
    } else {
        DaemonStatus::NotRunning
    }
}

#[cfg(not(unix))]
async fn probe_direct(paths: &DaemonPaths) -> DaemonStatus {
    if paths.pid_file.exists() {
        status_for_unreachable_pid(paths)
    } else {
        DaemonStatus::NotRunning
    }
}

#[cfg(unix)]
fn probe_direct_blocking(paths: &DaemonPaths) -> DaemonStatus {
    if socket_responds_blocking(&paths.socket) {
        return DaemonStatus::Running;
    }
    if paths.pid_file.exists() {
        status_for_unreachable_pid(paths)
    } else {
        DaemonStatus::NotRunning
    }
}

#[cfg(not(unix))]
fn probe_direct_blocking(paths: &DaemonPaths) -> DaemonStatus {
    if paths.pid_file.exists() {
        status_for_unreachable_pid(paths)
    } else {
        DaemonStatus::NotRunning
    }
}

/// Cheap probe: try to connect and read the daemon's "hello"
/// envelope. The server emits one immediately on accept (see
/// [`server::handle_client`]), so any successful read of a non-empty
/// line confirms the daemon is alive — no client-side write needed.
pub async fn probe(paths: &DaemonPaths) -> DaemonStatus {
    probe_direct(paths).await
}

/// Sync version of `probe`. Useful before the tokio runtime is up.
pub fn probe_blocking(paths: &DaemonPaths) -> DaemonStatus {
    note_blocking_probe_call();
    probe_direct_blocking(paths)
}

/// Spawn a detached *canonical* daemon process. Returns the child PID.
/// The current process should *not* wait on the child — it's intended
/// to outlive us. `no_sandbox` forwards the daemon-level `--no-sandbox`
/// (sandboxing part 2): the child disables filesystem sandboxing for all
/// its sessions.
pub fn spawn_detached(no_sandbox: bool) -> Result<u32> {
    spawn_detached_inner(None, no_sandbox, false)
}

pub fn spawn_detached_with_resume(no_sandbox: bool, resume_all_sessions: bool) -> Result<u32> {
    spawn_detached_inner(None, no_sandbox, resume_all_sessions)
}

pub fn restart_no_sandbox_from_argv(args: &[String], explicit_no_sandbox: bool) -> bool {
    explicit_no_sandbox
        || (cmdline_is_cockpit_daemon(args) && args.iter().any(|arg| arg == "--no-sandbox"))
}

pub fn derive_restart_no_sandbox(paths: &DaemonPaths, explicit_no_sandbox: bool) -> bool {
    if explicit_no_sandbox {
        return true;
    }
    #[cfg(unix)]
    {
        let Some(pid) = read_pid(paths) else {
            return false;
        };
        read_process_cmdline(pid)
            .map(|args| restart_no_sandbox_from_argv(&args, false))
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = paths;
        false
    }
}

pub fn daemon_pid(paths: &DaemonPaths) -> Option<u32> {
    read_pid(paths)
}

pub fn restart_release_timeout(grace_secs: Option<u64>) -> Duration {
    let drain = grace_secs
        .map(Duration::from_secs)
        .unwrap_or(shutdown::SHUTDOWN_DRAIN_GRACE);
    drain.saturating_add(Duration::from_secs(2))
}

pub async fn wait_for_restart_release(
    paths: &DaemonPaths,
    expected_pid: Option<u32>,
    timeout: Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if restart_metadata_released(paths, expected_pid) {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            if let Some(pid) = expected_pid {
                remove_metadata_if_pid_matches(paths, pid);
            }
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn restart_metadata_released(paths: &DaemonPaths, expected_pid: Option<u32>) -> bool {
    let pid_released = expected_pid.is_none_or(|pid| read_pid(paths) != Some(pid));
    pid_released && !paths.pid_file.exists() && !paths.socket.exists()
}

/// Spawn a detached *ephemeral* daemon bound to `paths` (a unique
/// `cockpit-eph-<pid>-<nonce>` path set).
/// The child binds the exact path the parent chose by reading the
/// internal env vars (Layer B); never via the user-facing CLI surface.
/// Returns the child PID.
///
/// An auto-promoted ephemeral daemon is never launched `--no-sandbox`:
/// the client's `--no-sandbox` is a *per-session* default passed at
/// attach time, not a daemon-level one (sandboxing part 2 precedence).
pub fn spawn_detached_ephemeral(paths: &DaemonPaths) -> Result<u32> {
    spawn_detached_inner(Some(paths), false, false)
}

#[cfg(unix)]
fn spawn_detached_inner(
    ephemeral: Option<&DaemonPaths>,
    no_sandbox: bool,
    resume_all_sessions: bool,
) -> Result<u32> {
    use std::process::{Command, Stdio};
    let exe = std::env::current_exe().context("locating own binary")?;
    let mut command = Command::new(exe);
    command
        .arg("daemon")
        .arg("start")
        .arg("--foreground")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if no_sandbox {
        command.arg("--no-sandbox");
    }
    if resume_all_sessions {
        command.arg("--resume-all-sessions");
    }
    if let Some(paths) = ephemeral {
        command
            .env(EPHEMERAL_SOCKET_ENV, &paths.socket)
            .env(EPHEMERAL_PID_ENV, &paths.pid_file);
    }
    let child = command.spawn().context("spawning daemon child")?;
    Ok(child.id())
}

#[cfg(not(unix))]
fn spawn_detached_inner(
    _ephemeral: Option<&DaemonPaths>,
    _no_sandbox: bool,
    _resume_all_sessions: bool,
) -> Result<u32> {
    anyhow::bail!("daemon socket transport is not supported on this platform")
}

/// Idle grace period for the ephemeral self-reaping watchdog (Layer C).
/// When the last client of an *ephemeral* daemon disconnects, the
/// daemon waits this long before exiting on its own; a reconnect within
/// the window cancels the countdown. Bounds the lifetime of an orphan
/// left by an uncatchable foreground death (SIGKILL, power loss) to
/// roughly this value. The persistent daemon never arms this timer.
pub const EPHEMERAL_IDLE_GRACE: Duration = Duration::from_secs(30);

/// Run the daemon's accept loop in the current process. Blocks until
/// SIGINT/SIGTERM. Boots the DB + lock manager, registers a shutdown
/// watcher, and runs the [`server::run_accept_loop`]. Uses the production
/// idle ([`EPHEMERAL_IDLE_GRACE`]) and drain
/// ([`shutdown::SHUTDOWN_DRAIN_GRACE`]) graces.
pub async fn run_foreground(paths: DaemonPaths) -> Result<()> {
    run_foreground_inner(
        paths,
        EPHEMERAL_IDLE_GRACE,
        shutdown::SHUTDOWN_DRAIN_GRACE,
        false,
    )
    .await
}

pub async fn run_foreground_with_resume(
    paths: DaemonPaths,
    resume_all_sessions: bool,
) -> Result<()> {
    run_foreground_inner(
        paths,
        EPHEMERAL_IDLE_GRACE,
        shutdown::SHUTDOWN_DRAIN_GRACE,
        resume_all_sessions,
    )
    .await
}

pub(crate) fn boot_in_process(paths: DaemonPaths) -> Result<std::sync::Arc<server::DaemonContext>> {
    if let Some(ctx) = server::in_process_context(&paths.socket) {
        return Ok(ctx);
    }

    let ctx = std::sync::Arc::new(server::boot(paths)?);
    #[cfg(not(test))]
    {
        server::spawn_lock_sweeper(ctx.clone());
        let _org_sync_task = org_sync::spawn_background(ctx.clone());
        let _remote_audit_upload_task = remote_audit_upload::spawn_background(ctx.clone());
        let _connector_task = connector::spawn_background(ctx.clone());
    }
    server::register_in_process_context(ctx.clone());
    Ok(ctx)
}

#[cfg(test)]
pub(crate) fn boot_in_process_with_db(
    paths: DaemonPaths,
    db: crate::db::Db,
) -> Result<std::sync::Arc<server::DaemonContext>> {
    if let Some(ctx) = server::in_process_context(&paths.socket) {
        return Ok(ctx);
    }
    let locks = Arc::new(crate::locks::LockManager::from_db(db.clone())?);
    let ctx = std::sync::Arc::new(server::DaemonContext::new(db, locks, paths));
    server::register_in_process_context(ctx.clone());
    Ok(ctx)
}

/// Like [`run_foreground`] but with injectable idle- and drain-grace
/// durations so tests can exercise the ephemeral watchdog (Layer C) and the
/// graceful drain (`daemon-graceful-drain-shutdown.md`) without sleeping the
/// full 30s of wall-clock. `idle_grace` bounds the ephemeral idle watchdog;
/// `drain_grace` bounds how long teardown awaits in-flight work before
/// force-aborting it.
#[cfg(unix)]
pub async fn run_foreground_inner(
    paths: DaemonPaths,
    idle_grace: Duration,
    drain_grace: Duration,
    resume_all_sessions: bool,
) -> Result<()> {
    run_foreground_inner_with_boot_db(paths, idle_grace, drain_grace, resume_all_sessions, None)
        .await
}

#[cfg(unix)]
async fn run_foreground_inner_with_boot_db(
    paths: DaemonPaths,
    idle_grace: Duration,
    drain_grace: Duration,
    resume_all_sessions: bool,
    boot_db: Option<crate::db::Db>,
) -> Result<()> {
    let mut timer = crate::startup::PhaseTimer::start("daemon::run_foreground");
    if matches!(probe(&paths).await, DaemonStatus::Running) {
        anyhow::bail!(
            "another daemon is already running (socket: {})",
            paths.socket.display()
        );
    }
    if boot_db.is_none() && !paths.ephemeral && paths == DaemonPaths::resolve_canonical()? {
        let discovered = discover().await;
        if matches!(
            discovered.status,
            DaemonStatus::Running
                | DaemonStatus::LivePidSocketUnreachable
                | DaemonStatus::UnverifiedPid
        ) && discovered.paths.socket != paths.socket
        {
            anyhow::bail!(
                "another daemon is already running or owns the shared pid file (pid file: {})",
                paths.pid_file.display()
            );
        }
    }
    // Clear any stale leftover.
    let _ = std::fs::remove_file(&paths.socket);
    std::fs::write(&paths.pid_file, std::process::id().to_string())
        .with_context(|| format!("writing pid file {}", paths.pid_file.display()))?;

    let listener = bind_private_socket(&paths.socket)?;
    if boot_db.is_some() {
        write_endpoint_record_with_pid_and_canonical(&paths, &paths, std::process::id())?;
    } else {
        write_endpoint_record(&paths)?;
    }
    timer.phase("probe_pidfile_bind");

    let ctx = std::sync::Arc::new(match boot_db {
        Some(db) => server::boot_with_db(paths.clone(), db, &mut timer)?,
        None => server::boot(paths.clone())?,
    });
    if resume_all_sessions {
        resume_all_paused_sessions(&ctx.db)?;
    }
    timer.phase("boot");

    // Signal task: SIGINT/SIGTERM (or Ctrl-C / console-close on Windows)
    // route into the single graceful-shutdown path. The **first** signal
    // begins the drain; a **second** signal while still draining shortens
    // to an immediate force-exit (`request_shutdown`'s begin → force
    // promotion). The task therefore loops rather than firing once.
    let signal_task = {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};
                let mut int = signal(SignalKind::interrupt()).ok();
                let mut term = signal(SignalKind::terminate()).ok();
                loop {
                    tokio::select! {
                        _ = async { if let Some(s) = int.as_mut() { s.recv().await; } else { std::future::pending::<()>().await } } => {}
                        _ = async { if let Some(s) = term.as_mut() { s.recv().await; } else { std::future::pending::<()>().await } } => {}
                    }
                    server::request_shutdown(&ctx);
                    if ctx.shutdown_signal().is_forced() {
                        break;
                    }
                }
            }
            #[cfg(not(unix))]
            {
                // Windows has no SIGTERM; `ctrl_c` covers Ctrl-C and the
                // console-close control events, consistent with the rest of
                // the codebase's non-unix signal handling. A second Ctrl-C
                // during drain shortens to force, same as unix.
                loop {
                    if tokio::signal::ctrl_c().await.is_err() {
                        break;
                    }
                    server::request_shutdown(&ctx);
                    if ctx.shutdown_signal().is_forced() {
                        break;
                    }
                }
            }
        })
    };

    // Layer C: ephemeral-only self-reaping watchdog. The persistent daemon
    // must never self-exit on idle, so the watchdog is armed only when this
    // daemon owns an ephemeral path set (Layer B's flag). It routes through
    // the same `request_shutdown` path, so a fired timer drains in-flight
    // work before reaping (an *in-flight* ephemeral daemon drains; only an
    // *idle* one is reaped promptly).
    let watchdog_task = if paths.ephemeral {
        let ctx = ctx.clone();
        let client_presence = ctx.client_presence();
        Some(tokio::spawn(async move {
            idle_watchdog(client_presence, idle_grace, move || {
                server::request_shutdown(&ctx);
            })
            .await;
        }))
    } else {
        None
    };

    // Idle-lock sweeper (`readlock-wait-and-lock-expiry.md`): the single
    // daemon-internal periodic task that reclaims locks whose holder has
    // gone idle past the 5-minute threshold, so a hung/abandoned holder
    // can't block a waiting `readlock` forever.
    server::spawn_lock_sweeper(ctx.clone());
    let org_sync_task = org_sync::spawn_background(ctx.clone());
    let remote_audit_upload_task = remote_audit_upload::spawn_background(ctx.clone());
    let connector_task = connector::spawn_background(ctx.clone());

    timer.phase("signal_and_watchdog");
    timer.done();
    let accept = server::run_accept_loop(ctx.clone(), listener);
    let result = accept.await;

    // The accept loop has stopped (a drain began). Ensure the drain is
    // marked even on the (impossible-by-construction, but defensive) path
    // where the loop broke without `request_shutdown` having run, so the
    // new-request gate is definitely closed before we await workers.
    server::request_shutdown(&ctx);

    // Bounded grace, then force: arm a timer that escalates the central
    // gate to `Forced` once the grace elapses (also broadcasting the forced
    // notice), so a hung provider request can't block shutdown past the
    // deadline. `drain_all` awaits the workers up to the same grace and
    // aborts whatever remains.
    let drain_grace = ctx.take_shutdown_grace_override().unwrap_or(drain_grace);
    spawn_force_timer(ctx.clone(), drain_grace);
    let drained_clean = ctx.registry.drain_all(drain_grace).await;
    if !drained_clean {
        // Make sure the forced state + notice are set even if the timer
        // hadn't fired yet (e.g. all workers wedged right at the deadline).
        if !ctx.shutdown_signal().is_forced() {
            ctx.shutdown_signal().force();
            ctx.broadcast_global(proto::Event::DaemonDraining { forced: true });
        }
        tracing::warn!("daemon: forced shutdown — in-flight work aborted at grace deadline");
    }

    // Cleanup on every path, but only while the pid file still names this
    // process. A restart replacement may have taken ownership of the shared
    // canonical paths before the old daemon finishes draining.
    if remove_metadata_if_pid_matches(&paths, std::process::id()) {
        remove_endpoint_record_if_owned(&paths);
    }

    signal_task.abort();
    if let Some(watchdog) = watchdog_task {
        watchdog.abort();
    }
    org_sync_task.abort();
    remote_audit_upload_task.abort();
    connector_task.abort();
    result
}

#[cfg(not(unix))]
pub async fn run_foreground_inner(
    _paths: DaemonPaths,
    _idle_grace: Duration,
    _drain_grace: Duration,
    _resume_all_sessions: bool,
) -> Result<()> {
    anyhow::bail!("daemon socket transport is not supported on this platform")
}

/// Arm the bounded-grace force timer for a graceful drain
/// (`daemon-graceful-drain-shutdown.md`). Once `grace` elapses, it
/// escalates the central gate to `Forced` and broadcasts the forced
/// notice — so even if `drain_all`'s own timeout is somehow still pending,
/// the gate reflects "forced" for any late observer. Detached; the process
/// exits shortly after `drain_all` returns regardless.
fn spawn_force_timer(ctx: std::sync::Arc<server::DaemonContext>, grace: Duration) {
    tokio::spawn(async move {
        tokio::time::sleep(grace).await;
        if !ctx.shutdown_signal().is_forced() {
            ctx.shutdown_signal().force();
            ctx.broadcast_global(proto::Event::DaemonDraining { forced: true });
        }
    });
}

fn resume_all_paused_sessions(db: &crate::db::Db) -> Result<()> {
    for row in db.paused_session_work_all()? {
        if let Err(e) = db.mark_paused_session_work_resumed(row.session_id) {
            tracing::warn!(
                error = %e,
                session_id = %row.session_id,
                "resume-all failed to mark paused session resumed"
            );
        }
    }
    Ok(())
}

/// Ephemeral self-reaping watchdog (Layer C). Watches `presence` (a live
/// count of connected clients). Whenever the count drops to zero, it starts
/// an `idle_grace` countdown; if a client reconnects before the timer
/// fires, the countdown is cancelled and the daemon keeps running; if the
/// timer fires with still no client, it routes into the single graceful
/// drain via [`server::request_shutdown`]. Idempotent: re-entry just
/// re-reads the latest count.
///
/// Note the drain still runs to completion afterwards — an ephemeral daemon
/// whose last UI detached *mid-inference* drains the in-flight work (same
/// grace/force bound) before the process exits; only an *idle* one reaps
/// with nothing to wait on.
async fn idle_watchdog(
    mut presence: tokio::sync::watch::Receiver<usize>,
    idle_grace: Duration,
    mut on_reap: impl FnMut(),
) {
    loop {
        // Block until there are no connected clients.
        if *presence.borrow() != 0 {
            if presence.changed().await.is_err() {
                // Sender dropped — daemon is tearing down anyway.
                return;
            }
            continue;
        }

        // No clients: race the grace timer against a reconnect.
        tokio::select! {
            _ = tokio::time::sleep(idle_grace) => {
                // Re-check under the borrow: a client may have connected
                // in the same tick the timer fired.
                if *presence.borrow() == 0 {
                    tracing::info!("ephemeral daemon idle past grace; self-reaping");
                    on_reap();
                    return;
                }
            }
            changed = presence.changed() => {
                if changed.is_err() {
                    return;
                }
                // Loop re-evaluates the (possibly non-zero) count.
            }
        }
    }
}

/// Kill the running daemon (if any) and clean up its pid + socket files.
pub fn stop(paths: &DaemonPaths) -> Result<bool> {
    let Some(pid) = read_pid(paths) else {
        return Ok(false);
    };
    #[cfg(unix)]
    return stop_unix_with(paths, pid, verify_daemon_pid_identity, send_sigterm, || {
        paths.pid_file.exists()
    });
    #[cfg(not(unix))]
    {
        let _ = pid;
        let _ = std::fs::remove_file(&paths.pid_file);
        let _ = std::fs::remove_file(&paths.socket);
        Ok(true)
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PidIdentity {
    VerifiedDaemon,
    NotDaemon,
    Missing,
    Unverified,
}

#[cfg(unix)]
fn stop_unix_with(
    paths: &DaemonPaths,
    pid: u32,
    verify: impl Fn(u32) -> PidIdentity,
    signal: impl Fn(u32) -> Result<()>,
    pid_file_exists: impl Fn() -> bool,
) -> Result<bool> {
    match verify(pid) {
        PidIdentity::VerifiedDaemon => {}
        PidIdentity::Missing | PidIdentity::NotDaemon => {
            remove_metadata_if_pid_matches(paths, pid);
            return Ok(false);
        }
        PidIdentity::Unverified => {
            anyhow::bail!(
                "refusing to signal pid {pid}: daemon process identity could not be verified"
            );
        }
    }

    // SIGTERM is graceful — daemon's signal handler removes its pid/socket
    // files. Fall back to outright file cleanup if a verified daemon does not
    // clean up promptly.
    signal(pid)?;
    for _ in 0..20 {
        if !pid_file_exists() {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    remove_metadata_if_pid_matches(paths, pid);
    Ok(true)
}

fn remove_metadata_if_pid_matches(paths: &DaemonPaths, expected_pid: u32) -> bool {
    if read_pid(paths) != Some(expected_pid) {
        return false;
    }
    let _ = std::fs::remove_file(&paths.pid_file);
    let _ = std::fs::remove_file(&paths.socket);
    true
}

#[cfg(unix)]
fn send_sigterm(pid: u32) -> Result<()> {
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()).with_context(|| format!("signaling pid {pid}"))
    }
}

#[cfg(unix)]
fn verify_daemon_pid_identity(pid: u32) -> PidIdentity {
    if !process_exists(pid) {
        return PidIdentity::Missing;
    }
    match read_process_cmdline(pid) {
        Ok(args) if cmdline_is_cockpit_daemon(&args) => PidIdentity::VerifiedDaemon,
        Ok(_) => PidIdentity::NotDaemon,
        Err(_) => PidIdentity::Unverified,
    }
}

#[cfg(unix)]
fn process_exists(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(all(unix, target_os = "linux"))]
fn read_process_cmdline(pid: u32) -> std::io::Result<Vec<String>> {
    let bytes = std::fs::read(format!("/proc/{pid}/cmdline"))?;
    Ok(split_proc_cmdline(&bytes))
}

#[cfg(all(unix, target_os = "macos"))]
fn read_process_cmdline(pid: u32) -> std::io::Result<Vec<String>> {
    let mut argmax: libc::c_int = 0;
    let mut argmax_len = std::mem::size_of_val(&argmax);
    let mut argmax_mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    let rc = unsafe {
        libc::sysctl(
            argmax_mib.as_mut_ptr(),
            argmax_mib.len() as libc::c_uint,
            &mut argmax as *mut _ as *mut libc::c_void,
            &mut argmax_len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if argmax <= 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "KERN_ARGMAX returned a non-positive argv buffer size",
        ));
    }

    let mut bytes = vec![0_u8; argmax as usize];
    let mut len = bytes.len();
    let mut procargs_mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
    let rc = unsafe {
        libc::sysctl(
            procargs_mib.as_mut_ptr(),
            procargs_mib.len() as libc::c_uint,
            bytes.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    bytes.truncate(len);
    parse_macos_procargs2(&bytes)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn read_process_cmdline(_pid: u32) -> std::io::Result<Vec<String>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "pid identity verification is unsupported on this platform",
    ))
}

#[cfg(unix)]
fn split_proc_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

#[cfg(all(unix, any(test, target_os = "macos")))]
fn parse_macos_procargs2(bytes: &[u8]) -> std::io::Result<Vec<String>> {
    const ARG_COUNT_LEN: usize = std::mem::size_of::<libc::c_int>();
    if bytes.len() < ARG_COUNT_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "KERN_PROCARGS2 data is shorter than argc",
        ));
    }

    let argc =
        i32::from_ne_bytes(bytes[..ARG_COUNT_LEN].try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid argc width")
        })?);
    if argc <= 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "KERN_PROCARGS2 argc is not positive",
        ));
    }

    let mut pos = ARG_COUNT_LEN;
    let Some(exec_end) = bytes[pos..].iter().position(|b| *b == 0).map(|n| pos + n) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "KERN_PROCARGS2 data is missing executable path terminator",
        ));
    };
    pos = exec_end + 1;

    while pos < bytes.len() && bytes[pos] == 0 {
        pos += 1;
    }

    let mut args = Vec::with_capacity(argc as usize);
    while args.len() < argc as usize {
        if pos >= bytes.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "KERN_PROCARGS2 data ended before argc arguments",
            ));
        }
        let Some(arg_end) = bytes[pos..].iter().position(|b| *b == 0).map(|n| pos + n) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "KERN_PROCARGS2 argument is not NUL terminated",
            ));
        };
        if arg_end > pos {
            args.push(String::from_utf8_lossy(&bytes[pos..arg_end]).into_owned());
        }
        pos = arg_end + 1;
    }

    Ok(args)
}

fn cmdline_is_cockpit_daemon(args: &[String]) -> bool {
    let Some(program) = args.first() else {
        return false;
    };
    let program_name = std::path::Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(program);
    program_name.contains("cockpit")
        && args
            .windows(2)
            .any(|pair| pair[0] == "daemon" && pair[1] == "start")
}

fn read_pid(paths: &DaemonPaths) -> Option<u32> {
    let s = std::fs::read_to_string(&paths.pid_file).ok()?;
    s.trim().parse().ok()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::daemon::test_harness::{
        CleanupReport, DaemonTestHarness, TEST_OWNER_ENV, TestDaemonManifest,
        TestDaemonManifestEntry, cleanup_manifest, write_manifest,
    };

    #[cfg(unix)]
    fn mode(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    fn spawn_hello_socket(socket: PathBuf) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind socket");
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::Write;
                let _ = writeln!(stream, "{{}}");
            }
        })
    }

    fn canonical_in(state_home: &Path, runtime_dir: &Path) -> DaemonPaths {
        DaemonPaths::resolve_canonical_in(state_home, Some(runtime_dir)).expect("canonical paths")
    }

    #[test]
    fn stale_manifest_with_dead_pid_removes_only_manifest_files() {
        let harness = DaemonTestHarness::new();
        let socket = harness.state_home.join("dead.sock");
        let pid_file = harness.state_home.join("dead.pid");
        std::fs::create_dir_all(&harness.state_home).expect("state dir");
        std::fs::write(&socket, "socket").expect("socket marker");
        std::fs::write(&pid_file, "999999999").expect("pid marker");
        let manifest_path = harness.manifest_path("dead-pid");
        write_manifest(
            &manifest_path,
            &TestDaemonManifest {
                owner: harness.owner.clone(),
                entries: vec![TestDaemonManifestEntry {
                    pid: 999_999_999,
                    socket: socket.clone(),
                    pid_file: pid_file.clone(),
                    endpoint_file: None,
                }],
            },
        )
        .expect("write manifest");

        let report = cleanup_manifest(&manifest_path).expect("cleanup manifest");

        assert_eq!(
            report,
            CleanupReport {
                removed_files: 3,
                signaled_processes: 0,
                dead_processes: 1,
            }
        );
        assert!(!socket.exists());
        assert!(!pid_file.exists());
        assert!(!manifest_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn stale_manifest_refuses_live_pid_without_test_daemon_identity() {
        let harness = DaemonTestHarness::new();
        let socket = harness.state_home.join("live.sock");
        let pid_file = harness.state_home.join("live.pid");
        std::fs::create_dir_all(&harness.state_home).expect("state dir");
        std::fs::write(&socket, "socket").expect("socket marker");
        std::fs::write(&pid_file, std::process::id().to_string()).expect("pid marker");
        let manifest_path = harness.manifest_path("live-without-marker");
        write_manifest(
            &manifest_path,
            &TestDaemonManifest {
                owner: harness.owner.clone(),
                entries: vec![TestDaemonManifestEntry {
                    pid: std::process::id(),
                    socket: socket.clone(),
                    pid_file: pid_file.clone(),
                    endpoint_file: None,
                }],
            },
        )
        .expect("write manifest");

        let err = cleanup_manifest(&manifest_path).expect_err("must refuse current process");

        assert!(
            err.to_string().contains(TEST_OWNER_ENV) || err.to_string().contains("not a cockpit"),
            "error should name the failed identity check: {err:#}"
        );
        assert!(socket.exists());
        assert!(pid_file.exists());
        assert!(manifest_path.exists());
        let _ = std::fs::remove_file(socket);
        let _ = std::fs::remove_file(pid_file);
        let _ = std::fs::remove_file(manifest_path);
    }

    #[cfg(unix)]
    #[test]
    fn endpoint_record_recovers_running_daemon_from_different_runtime_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_home = dir.path().join("state");
        let runtime_a = dir.path().join("rt-a");
        let runtime_b = dir.path().join("rt-b");
        std::fs::create_dir_all(runtime_a.join("cockpit")).expect("runtime a");

        let socket_a = runtime_a.join("cockpit/cockpit.sock");
        let listener = spawn_hello_socket(socket_a.clone());

        // Wait until the listener thread has bound before probing; in the full
        // test suite other threads can otherwise let this test race the bind.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !socket_a.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "hello socket was not bound"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        let paths = canonical_in(&state_home, &runtime_a);
        assert_eq!(paths.socket, socket_a);
        std::fs::write(&paths.pid_file, std::process::id().to_string()).expect("pid file");
        write_endpoint_record_with_pid_and_canonical(&paths, &paths, std::process::id())
            .expect("endpoint record");

        let canonical_b = canonical_in(&state_home, &runtime_b);
        assert_ne!(canonical_b.socket, socket_a);

        let probe = discover_blocking_with_canonical(canonical_b);
        assert_eq!(probe.status, DaemonStatus::Running);
        assert_eq!(probe.paths.socket, socket_a);
        listener.join().expect("listener thread");
    }

    #[cfg(unix)]
    #[test]
    fn no_endpoint_record_uses_explicit_canonical_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_home = dir.path().join("state");
        let runtime_dir = dir.path().join("runtime");
        let paths = canonical_in(&state_home, &runtime_dir);
        let probe = discover_blocking_with_canonical(paths.clone());
        assert_eq!(probe.status, DaemonStatus::NotRunning);
        assert_eq!(probe.paths.socket, paths.socket);
    }

    #[cfg(unix)]
    #[test]
    fn stale_endpoint_with_missing_pid_is_removed_without_signaling() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_home = dir.path().join("state");
        let runtime_dir = dir.path().join("runtime");
        let paths = canonical_in(&state_home, &runtime_dir);
        std::fs::write(&paths.pid_file, "999999999").expect("pid file");
        let record = DaemonEndpointRecord {
            version: 1,
            pid: 999999999,
            socket: runtime_dir.join("other/cockpit.sock"),
            kind: DaemonEndpointKind::Persistent,
        };
        let endpoint = endpoint_file_for_state(paths.pid_file.parent().unwrap());
        std::fs::write(&endpoint, serde_json::to_vec(&record).unwrap()).expect("write endpoint");

        let probe = discover_blocking_with_canonical(paths);
        assert_eq!(probe.status, DaemonStatus::Stale);
        assert!(!endpoint.exists());
    }

    #[test]
    fn ephemeral_paths_do_not_use_shared_endpoint_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_home = dir.path().join("state");
        let runtime_dir = dir.path().join("runtime");
        let eph = DaemonPaths::allocate_ephemeral_for_test_in(111, &state_home, Some(&runtime_dir))
            .expect("ephemeral");
        let canonical = canonical_in(&state_home, &runtime_dir);
        write_endpoint_record_with_pid_and_canonical(&eph, &canonical, std::process::id())
            .expect("skip endpoint");
        assert!(!endpoint_file_for_state(canonical.pid_file.parent().unwrap()).exists());
    }

    #[test]
    fn noncanonical_persistent_paths_cannot_publish_shared_endpoint_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_home = dir.path().join("state");
        let runtime_dir = dir.path().join("runtime");
        let noncanonical = DaemonPaths {
            pid_file: state_home.join("cockpit").join("other.pid"),
            socket: runtime_dir.join("cockpit").join("other.sock"),
            ephemeral: false,
        };
        let canonical = canonical_in(&state_home, &runtime_dir);

        let err = write_endpoint_record_with_pid_and_canonical(
            &noncanonical,
            &canonical,
            std::process::id(),
        )
        .expect_err("noncanonical write rejected");
        assert!(
            err.to_string().contains("noncanonical paths"),
            "error names noncanonical paths: {err:#}"
        );
        assert!(!endpoint_file_for_state(canonical.pid_file.parent().unwrap()).exists());
    }

    #[test]
    fn noncanonical_persistent_cleanup_does_not_remove_shared_endpoint_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_home = dir.path().join("state");
        let runtime_dir = dir.path().join("runtime");
        let canonical = canonical_in(&state_home, &runtime_dir);
        write_endpoint_record_with_pid_and_canonical(&canonical, &canonical, std::process::id())
            .expect("endpoint record");
        let endpoint = endpoint_file_for_state(canonical.pid_file.parent().unwrap());
        assert!(endpoint.exists());

        let noncanonical = DaemonPaths {
            pid_file: canonical.pid_file.with_file_name("other.pid"),
            socket: canonical.socket.clone(),
            ephemeral: false,
        };
        remove_endpoint_record_if_owned_with_canonical(&noncanonical, &canonical);

        assert!(
            endpoint.exists(),
            "noncanonical cleanup must not remove the shared endpoint record"
        );
    }

    #[cfg(unix)]
    #[test]
    fn exact_path_probe_does_not_discover_shared_endpoint_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_home = dir.path().join("state");
        let runtime_a = dir.path().join("rt-a");
        let runtime_b = dir.path().join("rt-b");
        std::fs::create_dir_all(runtime_a.join("cockpit")).expect("runtime a");

        let socket_a = runtime_a.join("cockpit/cockpit.sock");
        let listener = spawn_hello_socket(socket_a.clone());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !socket_a.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "hello socket was not bound"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        let paths_a = canonical_in(&state_home, &runtime_a);
        write_endpoint_record_with_pid_and_canonical(&paths_a, &paths_a, std::process::id())
            .expect("endpoint record");

        let paths_b = canonical_in(&state_home, &runtime_b);
        assert_ne!(paths_b.socket, socket_a);
        assert_eq!(probe_blocking(&paths_b), DaemonStatus::NotRunning);

        let discovered = discover_blocking_with_canonical(paths_b);
        assert_eq!(discovered.status, DaemonStatus::Running);
        assert_eq!(discovered.paths.socket, socket_a);
        listener.join().expect("listener thread");
    }

    /// Layer B: ephemeral paths keep a human-readable pid prefix plus a
    /// per-spawn nonce, live in the same directory as the canonical paths,
    /// and are flagged ephemeral. The canonical paths are distinct and never
    /// flagged ephemeral.
    #[test]
    fn ephemeral_paths_are_unique_and_distinct_from_canonical() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_home = dir.path().join("state");
        let runtime_dir = dir.path().join("runtime");
        let eph_a =
            DaemonPaths::allocate_ephemeral_for_test_in(111, &state_home, Some(&runtime_dir))
                .expect("resolve eph a");
        let eph_b =
            DaemonPaths::allocate_ephemeral_for_test_in(111, &state_home, Some(&runtime_dir))
                .expect("resolve eph b");
        let canonical = canonical_in(&state_home, &runtime_dir);

        // Unique even for the same pid.
        assert_ne!(eph_a.socket, eph_b.socket);
        assert_ne!(eph_a.pid_file, eph_b.pid_file);

        // `cockpit-eph-<pid>-<nonce>` scheme.
        let socket_name = eph_a.socket.file_name().unwrap().to_string_lossy();
        let pid_name = eph_a.pid_file.file_name().unwrap().to_string_lossy();
        assert!(socket_name.starts_with("cockpit-eph-111-"));
        assert!(socket_name.ends_with(".sock"));
        assert!(pid_name.starts_with("cockpit-eph-111-"));
        assert!(pid_name.ends_with(".pid"));

        // Same parent directory as the canonical socket/pid.
        assert_eq!(eph_a.socket.parent(), canonical.socket.parent());
        assert_eq!(eph_a.pid_file.parent(), canonical.pid_file.parent());

        // Never collides with the canonical files.
        assert_ne!(eph_a.socket, canonical.socket);
        assert_ne!(eph_a.pid_file, canonical.pid_file);

        // Flags.
        assert!(eph_a.ephemeral);
        assert!(eph_b.ephemeral);
        assert!(!canonical.ephemeral);
    }

    #[cfg(unix)]
    #[test]
    fn daemon_socket_parent_is_repaired_to_private_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let parent = dir.path().join("runtime").join("cockpit");
        std::fs::create_dir_all(&parent).expect("create parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
            .expect("chmod parent open");

        ensure_private_dir(&parent).expect("secure parent");

        assert_eq!(mode(&parent), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_fails_closed_when_path_is_not_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("runtime-file");
        std::fs::write(&path, "not a directory").expect("write file");

        ensure_private_dir(&path).expect_err("file path should fail");

        assert!(path.is_file());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_private_socket_sets_socket_mode_immediately() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("runtime").join("cockpit.sock");

        let listener = bind_private_socket(&socket).expect("bind socket");

        assert_eq!(mode(socket.parent().unwrap()), 0o700);
        assert_eq!(mode(&socket), 0o600);
        drop(listener);
    }

    /// Layer B wiring: a daemon child started for an ephemeral run binds
    /// the exact path set the parent chose, transmitted via the internal
    /// env vars. `resolve()` honors those env vars (flagging ephemeral);
    /// absent them, it falls back to the canonical path set.
    #[test]
    fn resolve_honors_ephemeral_env() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("runtime").join("chosen.sock");
        let pid_file = dir.path().join("state").join("chosen.pid");

        let resolved =
            DaemonPaths::from_ephemeral_paths(Some(socket.clone()), Some(pid_file.clone()))
                .expect("resolve explicit ephemeral paths")
                .expect("ephemeral paths");
        assert_eq!(resolved.socket, socket);
        assert_eq!(resolved.pid_file, pid_file);
        assert!(resolved.ephemeral);
        #[cfg(unix)]
        assert_eq!(mode(resolved.socket.parent().unwrap()), 0o700);

        let canonical = DaemonPaths::from_ephemeral_paths(None, None)
            .expect("resolve absent explicit ephemeral paths");
        assert!(canonical.is_none());

        let canonical = canonical_in(&dir.path().join("state"), &dir.path().join("runtime"));
        assert!(!canonical.ephemeral);
    }

    /// Layer C: with no connected client, the watchdog signals shutdown
    /// once the (injected, short) grace elapses.
    #[tokio::test(start_paused = true)]
    async fn watchdog_reaps_after_idle_grace() {
        let (presence_tx, presence_rx) = tokio::sync::watch::channel(0usize);
        let reaped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let grace = Duration::from_secs(30);

        let reaped_c = reaped.clone();
        let task = tokio::spawn(idle_watchdog(presence_rx, grace, move || {
            reaped_c.store(true, std::sync::atomic::Ordering::SeqCst);
        }));

        // Advance past the grace window. With paused time this is
        // deterministic and instant — no wall-clock sleep.
        tokio::time::advance(grace + Duration::from_secs(1)).await;
        let _ = task.await;

        assert!(
            reaped.load(std::sync::atomic::Ordering::SeqCst),
            "watchdog should have reaped after idle grace"
        );
        drop(presence_tx);
    }

    /// Layer C: a client reconnecting inside the grace window cancels the
    /// countdown; the daemon does not self-exit while a client is present.
    #[tokio::test(start_paused = true)]
    async fn watchdog_reconnect_cancels_countdown() {
        let (presence_tx, presence_rx) = tokio::sync::watch::channel(0usize);
        let reaped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let grace = Duration::from_secs(30);

        let reaped_c = reaped.clone();
        let task = tokio::spawn(idle_watchdog(presence_rx, grace, move || {
            reaped_c.store(true, std::sync::atomic::Ordering::SeqCst);
        }));

        // A client connects partway through the grace window.
        tokio::time::advance(grace / 2).await;
        presence_tx.send(1).unwrap();

        // Even well past the original deadline, no shutdown fires while a
        // client is connected.
        tokio::time::advance(grace * 2).await;
        tokio::task::yield_now().await;
        assert!(
            !reaped.load(std::sync::atomic::Ordering::SeqCst),
            "watchdog reaped despite a client"
        );

        drop(presence_tx);
        let _ = task.await;
    }

    /// End-to-end gating (Layers B + C): a real *ephemeral* daemon with
    /// no client self-reaps within the injected grace and removes its
    /// own socket + pid files; a real *persistent* daemon with the same
    /// idle conditions stays up. Uses a short injected grace and advances
    /// paused Tokio time so the test does not depend on wall-clock sleeps.
    #[tokio::test]
    async fn ephemeral_self_reaps_persistent_does_not() {
        let harness = DaemonTestHarness::new();
        let grace = Duration::from_millis(300);

        // --- Ephemeral: must self-reap. ---
        let eph = harness.ephemeral_paths("eph");
        let eph_clone = eph.clone();
        let eph_db = harness.db.clone();
        let eph_task = tokio::spawn(async move {
            run_foreground_inner_with_boot_db(eph_clone, grace, grace, false, Some(eph_db)).await
        });

        // Wait for it to come up.
        wait_until(|| eph.socket.exists(), Duration::from_secs(2)).await;
        assert!(eph.pid_file.exists(), "ephemeral pid file written");

        tokio::time::pause();

        // No client ever connects; it should self-reap and clean up.
        tokio::time::advance(grace + Duration::from_millis(1)).await;
        let reaped = tokio::time::timeout(Duration::from_secs(3), eph_task)
            .await
            .expect("ephemeral daemon did not self-reap in time");
        reaped.expect("join").expect("run_foreground_inner ok");
        assert!(!eph.socket.exists(), "ephemeral socket removed on reap");
        assert!(!eph.pid_file.exists(), "ephemeral pid removed on reap");

        // --- Persistent: must NOT self-reap. ---
        let persistent = canonical_in(&harness.state_home, &harness._runtime_dir);
        let persistent_clone = persistent.clone();
        let persistent_db = harness.db.clone();
        let persist_task = tokio::spawn(async move {
            run_foreground_inner_with_boot_db(
                persistent_clone,
                grace,
                grace,
                false,
                Some(persistent_db),
            )
            .await
        });
        wait_until(|| persistent.socket.exists(), Duration::from_secs(2)).await;

        // Past several grace windows with no client: still alive.
        tokio::time::advance(grace * 4).await;
        assert!(
            persistent.socket.exists(),
            "persistent daemon must never self-reap on idle"
        );
        assert!(
            !persist_task.is_finished(),
            "persistent daemon exited on idle"
        );

        // Tear it down so the test leaves nothing behind.
        persist_task.abort();
        let _ = persist_task.await;
        let _ = std::fs::remove_file(&persistent.socket);
        let _ = std::fs::remove_file(&persistent.pid_file);
    }

    /// Lingering-daemon fix (`daemonless-tui-ephemeral-lifecycle.md` §2): a
    /// **persisted** session must not, by itself, keep an *owned* ephemeral
    /// daemon alive past its owner's exit. We stand up a real ephemeral
    /// daemon, write a persisted `sessions` row into the very DB the daemon
    /// opened (the exact effect the first user message has via
    /// `persist_if_needed`), then trigger the owner-exit teardown
    /// (`StopDaemon`, the same request the `EphemeralDaemonGuard` sends). The
    /// daemon must drain and reap — removing its socket + pid — within the
    /// grace, identically to the no-message case. A long idle grace is used
    /// so the *only* thing that can reap it is the `StopDaemon`, not the idle
    /// watchdog backstop.
    #[tokio::test]
    async fn owned_ephemeral_reaps_on_stop_even_with_persisted_session() {
        use crate::daemon::ephemeral_guard::stop_daemon_blocking;
        use crate::session::Session;

        let harness = DaemonTestHarness::new();
        // Idle grace far longer than the test window: the watchdog can NOT be
        // what reaps the daemon — only the `StopDaemon` teardown can.
        let idle_grace = Duration::from_secs(3600);
        let drain_grace = Duration::from_millis(300);

        let eph = harness.ephemeral_paths("eph-with-session");
        let eph_clone = eph.clone();
        let daemon_db = harness.db.clone();
        let eph_task = tokio::spawn(async move {
            run_foreground_inner_with_boot_db(
                eph_clone,
                idle_grace,
                drain_grace,
                false,
                Some(daemon_db),
            )
            .await
        });

        wait_until(|| eph.socket.exists(), Duration::from_secs(2)).await;
        assert!(eph.pid_file.exists(), "ephemeral pid file written");

        // Persist a `sessions` row into the daemon's DB — the same DB effect
        // the first user message has. This is what the (suspected) lingering
        // bug pinned on; it must NOT keep the owned daemon alive.
        {
            let session = Session::create(harness.db.clone(), std::env::temp_dir(), "Build")
                .expect("persist a session row");
            assert!(session.is_persisted(), "row is persisted");
        }

        // Owner exit: the same `StopDaemon` the guard fires synchronously.
        // Run it off the runtime thread (mirrors the real blocking `Drop`).
        let socket = eph.socket.clone();
        tokio::task::spawn_blocking(move || stop_daemon_blocking(&socket))
            .await
            .unwrap();

        // The daemon must drain and exit — despite the persisted session.
        let reaped = tokio::time::timeout(Duration::from_secs(3), eph_task)
            .await
            .expect("owned ephemeral daemon did not reap on StopDaemon with a persisted session");
        reaped.expect("join").expect("run_foreground_inner ok");
        assert!(
            !eph.socket.exists(),
            "ephemeral socket removed on owner-exit teardown"
        );
        assert!(
            !eph.pid_file.exists(),
            "ephemeral pid removed on owner-exit teardown"
        );
    }

    /// Two daemonless TUIs are fully isolated: each owns a per-spawn ephemeral
    /// daemon, so even the same pid prefix can resolve to distinct
    /// sockets/pid files and never the canonical ones. Stale files from a
    /// prior crashed run of one TUI can't belong to — or block — the other.
    /// This is the path-level isolation guarantee
    /// `LifecycleMode::AttachOwnEphemeral` relies on.
    #[test]
    fn two_daemonless_tuis_resolve_distinct_owned_ephemeral_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_home = dir.path().join("state");
        let runtime_dir = dir.path().join("runtime");

        // Two daemonless TUI instances, even if the OS later reuses a pid.
        let tui_a =
            DaemonPaths::allocate_ephemeral_for_test_in(4242, &state_home, Some(&runtime_dir))
                .expect("resolve eph a");
        let tui_b =
            DaemonPaths::allocate_ephemeral_for_test_in(4242, &state_home, Some(&runtime_dir))
                .expect("resolve eph b");
        let canonical = canonical_in(&state_home, &runtime_dir);

        // Distinct sockets + pid files → two independent ephemeral daemons.
        assert_ne!(tui_a.socket, tui_b.socket);
        assert_ne!(tui_a.pid_file, tui_b.pid_file);

        // Neither daemonless TUI binds the canonical (shared persistent)
        // socket — they coexist with it and with `daemon stop`/`status`.
        assert_ne!(tui_a.socket, canonical.socket);
        assert_ne!(tui_b.socket, canonical.socket);

        // Both are flagged ephemeral so the self-reaping idle watchdog
        // (Layer C) is armed as the SIGKILL backstop.
        assert!(tui_a.ephemeral && tui_b.ephemeral);
        assert!(!canonical.ephemeral);
    }

    #[cfg(unix)]
    fn test_paths(dir: &tempfile::TempDir) -> DaemonPaths {
        DaemonPaths {
            socket: dir.path().join("daemon.sock"),
            pid_file: dir.path().join("daemon.pid"),
            ephemeral: false,
        }
    }

    #[cfg(unix)]
    #[test]
    fn stop_verified_daemon_sends_sigterm() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(&dir);
        std::fs::write(&paths.pid_file, "123").unwrap();
        let signaled = std::cell::Cell::new(false);

        let stopped = stop_unix_with(
            &paths,
            123,
            |_| PidIdentity::VerifiedDaemon,
            |_| {
                signaled.set(true);
                Ok(())
            },
            || false,
        )
        .unwrap();

        assert!(stopped);
        assert!(signaled.get());
    }

    #[cfg(unix)]
    #[test]
    fn stop_reused_pid_cleans_metadata_without_signal() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(&dir);
        std::fs::write(&paths.pid_file, "123").unwrap();
        std::fs::write(&paths.socket, "").unwrap();

        let stopped = stop_unix_with(
            &paths,
            123,
            |_| PidIdentity::NotDaemon,
            |_| panic!("must not signal an unrelated process"),
            || true,
        )
        .unwrap();

        assert!(!stopped);
        assert!(!paths.pid_file.exists());
        assert!(!paths.socket.exists());
    }

    #[cfg(unix)]
    #[test]
    fn stop_missing_pid_cleans_metadata_without_signal() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(&dir);
        std::fs::write(&paths.pid_file, "123").unwrap();

        let stopped = stop_unix_with(
            &paths,
            123,
            |_| PidIdentity::Missing,
            |_| panic!("must not signal a missing process"),
            || true,
        )
        .unwrap();

        assert!(!stopped);
        assert!(!paths.pid_file.exists());
    }

    #[cfg(unix)]
    #[test]
    fn stop_cleanup_does_not_remove_replaced_pid_or_socket() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(&dir);
        std::fs::write(&paths.pid_file, "456").unwrap();
        std::fs::write(&paths.socket, "new socket").unwrap();

        let stopped = stop_unix_with(
            &paths,
            123,
            |_| PidIdentity::NotDaemon,
            |_| panic!("must not signal an unrelated process"),
            || true,
        )
        .unwrap();

        assert!(!stopped);
        assert_eq!(std::fs::read_to_string(&paths.pid_file).unwrap(), "456");
        assert_eq!(
            std::fs::read_to_string(&paths.socket).unwrap(),
            "new socket"
        );
    }

    #[cfg(unix)]
    #[test]
    fn stop_timeout_cleanup_does_not_remove_new_daemon_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(&dir);
        std::fs::write(&paths.pid_file, "456").unwrap();
        std::fs::write(&paths.socket, "new socket").unwrap();

        let stopped = stop_unix_with(
            &paths,
            123,
            |_| PidIdentity::VerifiedDaemon,
            |_| Ok(()),
            || true,
        )
        .unwrap();

        assert!(stopped);
        assert_eq!(std::fs::read_to_string(&paths.pid_file).unwrap(), "456");
        assert_eq!(
            std::fs::read_to_string(&paths.socket).unwrap(),
            "new socket"
        );
    }

    #[cfg(unix)]
    #[test]
    fn stop_unverified_pid_fails_closed_without_cleanup_or_signal() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(&dir);
        std::fs::write(&paths.pid_file, "123").unwrap();

        let err = stop_unix_with(
            &paths,
            123,
            |_| PidIdentity::Unverified,
            |_| panic!("must not signal an unverified process"),
            || true,
        )
        .unwrap_err();

        assert!(err.to_string().contains("could not be verified"));
        assert!(paths.pid_file.exists());
    }

    #[cfg(unix)]
    #[test]
    fn unreachable_unverified_pid_is_not_reported_stale() {
        let status = status_for_pid_identity(PidIdentity::Unverified, || {
            panic!("unverified live pid must not be cleaned up as stale")
        });

        assert_eq!(status, DaemonStatus::UnverifiedPid);
    }

    #[test]
    fn restart_no_sandbox_derives_from_old_daemon_argv_and_explicit_override() {
        let sandboxed = vec![
            "/usr/bin/cockpit".to_string(),
            "daemon".to_string(),
            "start".to_string(),
            "--foreground".to_string(),
        ];
        let unsandboxed = vec![
            "/usr/bin/cockpit".to_string(),
            "daemon".to_string(),
            "start".to_string(),
            "--foreground".to_string(),
            "--no-sandbox".to_string(),
        ];
        let unrelated = vec![
            "/usr/bin/cockpit".to_string(),
            "session".to_string(),
            "list".to_string(),
            "--no-sandbox".to_string(),
        ];

        assert!(!restart_no_sandbox_from_argv(&sandboxed, false));
        assert!(restart_no_sandbox_from_argv(&unsandboxed, false));
        assert!(!restart_no_sandbox_from_argv(&unrelated, false));
        assert!(restart_no_sandbox_from_argv(&sandboxed, true));
    }

    #[test]
    fn restart_release_timeout_uses_default_drain_plus_cleanup_window() {
        assert_eq!(
            restart_release_timeout(None),
            shutdown::SHUTDOWN_DRAIN_GRACE + Duration::from_secs(2)
        );
        assert_eq!(restart_release_timeout(Some(0)), Duration::from_secs(2));
        assert_eq!(restart_release_timeout(Some(7)), Duration::from_secs(9));
    }

    #[tokio::test]
    async fn restart_release_wait_cleans_matching_metadata_after_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(&dir);
        std::fs::write(&paths.pid_file, "123").unwrap();
        std::fs::write(&paths.socket, "").unwrap();

        wait_for_restart_release(&paths, Some(123), Duration::ZERO).await;

        assert!(!paths.pid_file.exists());
        assert!(!paths.socket.exists());
    }

    #[cfg(unix)]
    #[test]
    fn cmdline_identity_requires_cockpit_daemon_start() {
        assert!(cmdline_is_cockpit_daemon(&[
            "/usr/bin/cockpit".into(),
            "daemon".into(),
            "start".into(),
            "--foreground".into(),
        ]));
        assert!(!cmdline_is_cockpit_daemon(&[
            "/usr/bin/sleep".into(),
            "daemon".into(),
            "start".into(),
        ]));
        assert!(!cmdline_is_cockpit_daemon(&[
            "/usr/bin/cockpit".into(),
            "session".into(),
            "list".into(),
        ]));
    }

    #[cfg(unix)]
    fn kern_procargs2_fixture(exec_path: &str, args: &[&str]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(args.len() as libc::c_int).to_ne_bytes());
        bytes.extend_from_slice(exec_path.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&[0, 0, 0]);
        for arg in args {
            bytes.extend_from_slice(arg.as_bytes());
            bytes.push(0);
        }
        bytes
    }

    #[cfg(unix)]
    #[test]
    fn macos_procargs2_daemon_start_verifies_through_shared_identity_rule() {
        let bytes = kern_procargs2_fixture(
            "/usr/local/bin/cockpit",
            &[
                "/usr/local/bin/cockpit",
                "daemon",
                "start",
                "--foreground",
                "--resume-all-sessions",
            ],
        );

        let args = parse_macos_procargs2(&bytes).unwrap();

        assert_eq!(args[0], "/usr/local/bin/cockpit");
        assert!(cmdline_is_cockpit_daemon(&args));
    }

    #[cfg(unix)]
    #[test]
    fn macos_procargs2_rejects_truncated_or_malformed_data() {
        assert!(parse_macos_procargs2(&[1, 0]).is_err());

        let missing_exec_nul = {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&(1 as libc::c_int).to_ne_bytes());
            bytes.extend_from_slice(b"/usr/local/bin/cockpit");
            bytes
        };
        assert!(parse_macos_procargs2(&missing_exec_nul).is_err());

        let missing_argv = kern_procargs2_fixture("/usr/local/bin/cockpit", &["cockpit"]);
        let mut truncated = missing_argv;
        truncated.truncate(truncated.len() - 1);
        assert!(parse_macos_procargs2(&truncated).is_err());

        let non_daemon = kern_procargs2_fixture(
            "/usr/local/bin/cockpit",
            &["/usr/local/bin/cockpit", "session", "list"],
        );
        let args = parse_macos_procargs2(&non_daemon).unwrap();
        assert!(!cmdline_is_cockpit_daemon(&args));
    }

    #[cfg(unix)]
    #[test]
    fn proc_cmdline_split_drops_empty_segments() {
        assert_eq!(
            split_proc_cmdline(b"/bin/cockpit\0daemon\0start\0\0"),
            vec!["/bin/cockpit", "daemon", "start"]
        );
    }

    async fn wait_until(mut cond: impl FnMut() -> bool, timeout: Duration) {
        let deadline = std::time::Instant::now() + timeout;
        while !cond() {
            if std::time::Instant::now() >= deadline {
                panic!("condition not met within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}
