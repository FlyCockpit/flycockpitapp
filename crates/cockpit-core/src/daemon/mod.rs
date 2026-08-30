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

pub mod agent_installation;
pub mod agent_management;
pub mod agent_session_override;
pub(crate) mod authority_token;
pub mod bulk_staging;
#[cfg(test)]
pub mod bulk_upload;
pub mod caffeinate;
pub mod client;
pub mod code_roots;
pub(crate) mod config_publication_recovery;
pub(crate) mod config_refresh;
pub mod config_source;
pub(crate) mod config_watch;
#[cfg(feature = "remote")]
pub mod connector;
#[cfg(feature = "remote")]
pub mod control_replay;
pub(crate) mod diagnostics_probe;
pub mod effective_default_recovery;
#[cfg(feature = "remote")]
pub mod egress;
pub(crate) mod ephemeral_guard;
pub mod fs_api;
pub(crate) mod image_generation_adapters;
pub mod image_generation_worker;
pub mod image_runtime;
pub mod image_sidecar_authority;
pub mod leak_reveal;
pub mod leak_reveal_frame;
#[cfg(unix)]
pub mod leak_reveal_socket;
pub mod lsp;
#[cfg(feature = "remote")]
pub mod org_sync;
pub mod principal;
pub mod proto;
pub mod registry;
#[cfg(feature = "remote")]
pub mod relay_envelope;
#[cfg(feature = "remote")]
pub mod remote_attempt;
#[cfg(feature = "remote")]
pub mod remote_audit_upload;
#[cfg(feature = "remote")]
pub(crate) mod remote_outbox_worker;
#[cfg(feature = "remote")]
pub mod remote_project_resolver;
pub mod scheduler;
pub mod server;
#[cfg(feature = "remote")]
pub mod session_continuity;
pub(crate) mod session_setup_projection;
pub mod session_worker;
pub mod shutdown;
pub mod skew_restart;
pub mod terminal;
#[cfg(test)]
pub(crate) mod test_harness;
#[cfg(feature = "remote")]
pub mod transport_selection;
#[cfg(feature = "remote")]
pub mod turn_socket_provider;

#[cfg(unix)]
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
#[cfg(target_os = "macos")]
use cockpit_host::daemon_lifecycle::parse_macos_procargs2;
#[cfg(unix)]
use cockpit_host::daemon_lifecycle::reclaim_stale_and_reserve;
#[cfg(unix)]
use cockpit_host::daemon_lifecycle::remove_dead_legacy_metadata;
#[cfg(test)]
use cockpit_host::daemon_lifecycle::split_proc_cmdline;
#[cfg(test)]
use cockpit_host::daemon_lifecycle::write_pid_file;
#[cfg(any(unix, test))]
use cockpit_host::daemon_lifecycle::{
    DaemonPidReceipt, ForegroundMetadataGuard, PidIdentity, retire_metadata_if_receipt_matches,
    with_lifecycle_lock,
};
use cockpit_host::daemon_lifecycle::{DaemonPidRecord, read_daemon_pid_record, read_pid_file};
#[cfg(target_os = "linux")]
use cockpit_host::daemon_lifecycle::{VerifiedProcessOutcome, acquire_verified_daemon_process};
#[cfg(unix)]
use cockpit_host::daemon_lifecycle::{legacy_pid_identity, verify_cockpit_daemon_receipt_identity};
use cockpit_host::private_fs::ensure_private_dir;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

use crate::redact::RedactionTable;

/// Extra time after the requested drain window for a stopped daemon to be
/// scheduled, unwind its tasks, and release owned pid/socket metadata. This is
/// deliberately separate from the user-selected drain grace: even a zero-
/// grace shutdown still needs a bounded process-cleanup allowance under load.
const RESTART_RELEASE_CLEANUP_GRACE: Duration = Duration::from_secs(10);

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

/// Internal lifetime marker passed to a detached child. Both persistent and
/// ephemeral owners publish at the canonical socket; only their lifetime
/// policy differs.
const DAEMON_LIFETIME_ENV: &str = "COCKPIT_DAEMON_LIFETIME";
const EPHEMERAL_LIFETIME: &str = "ephemeral";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonPaths {
    pub pid_file: PathBuf,
    pub socket: PathBuf,
    /// True when this canonical owner is reference-counted. Persistent owners
    /// survive zero clients; ephemeral owners begin teardown when the last
    /// client detaches.
    pub ephemeral: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonEndpointRecord {
    version: u8,
    socket: PathBuf,
    receipt: DaemonPidReceipt,
    kind: DaemonEndpointKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DaemonEndpointKind {
    Persistent,
    Ephemeral,
}

#[derive(Debug, Clone)]
pub struct DaemonProbe {
    pub status: DaemonStatus,
    pub paths: DaemonPaths,
    pub hello: Option<proto::DaemonHello>,
}

impl DaemonProbe {
    fn new(status: DaemonStatus, paths: DaemonPaths) -> Self {
        Self {
            status,
            paths,
            hello: None,
        }
    }

    fn with_hello(
        status: DaemonStatus,
        paths: DaemonPaths,
        hello: Option<proto::DaemonHello>,
    ) -> Self {
        Self {
            status,
            paths,
            hello,
        }
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

fn read_endpoint_record(canonical: &DaemonPaths) -> Option<DaemonEndpointRecord> {
    let expected_path = endpoint_file_for_state(canonical.pid_file.parent()?);
    let configured_path = endpoint_file().ok()?;
    if configured_path != expected_path {
        return None;
    }
    read_published_endpoint_record_from(&configured_path, canonical)
}

fn read_endpoint_record_from(path: &Path) -> Option<DaemonEndpointRecord> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn read_bound_endpoint_record_from(
    path: &Path,
    canonical: &DaemonPaths,
) -> Option<DaemonEndpointRecord> {
    let record = read_published_endpoint_record_from(path, canonical)?;
    (record.socket == canonical.socket).then_some(record)
}

/// Shared-state endpoint publication may point at a different runtime
/// socket than the queried canonical paths. Discovery follows that
/// redirect; exact-path probe does not.
fn read_published_endpoint_record_from(
    path: &Path,
    canonical: &DaemonPaths,
) -> Option<DaemonEndpointRecord> {
    if path != endpoint_file_for_state(canonical.pid_file.parent()?) {
        return None;
    }
    let record = read_endpoint_record_from(path)?;
    if record.version != 1 {
        return None;
    }
    let DaemonPidRecord::Receipt(receipt) = read_daemon_pid_record(&canonical.pid_file)? else {
        return None;
    };
    (record.receipt == receipt).then_some(record)
}

fn write_endpoint_record(paths: &DaemonPaths) -> Result<()> {
    let Some(DaemonPidRecord::Receipt(receipt)) = read_daemon_pid_record(&paths.pid_file) else {
        anyhow::bail!("daemon PID receipt is missing before endpoint publication");
    };
    let canonical = DaemonPaths::resolve_canonical()
        .context("resolving canonical daemon paths for endpoint publication")?;
    write_endpoint_record_with_receipt_and_canonical(paths, &canonical, &receipt)
}

fn write_endpoint_record_with_receipt_and_canonical(
    paths: &DaemonPaths,
    canonical: &DaemonPaths,
    receipt: &DaemonPidReceipt,
) -> Result<()> {
    if paths.pid_file != canonical.pid_file || paths.socket != canonical.socket {
        anyhow::bail!(
            "refusing to publish shared daemon endpoint from noncanonical paths: pid_file={}, socket={}",
            paths.pid_file.display(),
            paths.socket.display()
        );
    }
    let Some(state) = paths.pid_file.parent() else {
        anyhow::bail!(
            "daemon pid file has no parent: {}",
            paths.pid_file.display()
        );
    };
    let path = endpoint_file_for_state(state);
    with_lifecycle_lock(&paths.pid_file, || {
        if read_daemon_pid_record(&paths.pid_file)
            != Some(DaemonPidRecord::Receipt(receipt.clone()))
        {
            anyhow::bail!("daemon PID receipt changed before endpoint publication");
        }
        let record = DaemonEndpointRecord {
            version: 1,
            socket: paths.socket.clone(),
            receipt: receipt.clone(),
            kind: if paths.ephemeral {
                DaemonEndpointKind::Ephemeral
            } else {
                DaemonEndpointKind::Persistent
            },
        };
        let data = serde_json::to_vec_pretty(&record).context("serializing daemon endpoint")?;
        cockpit_host::private_fs::write_private_file(&path, &data)
            .with_context(|| format!("writing {}", path.display()))
    })
}

impl DaemonPaths {
    /// Resolve the canonical daemon paths and the detached child's lifetime.
    /// Transport discovery is always canonical: an ephemeral owner is
    /// attachable by every client of this ledger.
    pub fn resolve() -> Result<Self> {
        let mut paths = Self::resolve_canonical()?;
        paths.ephemeral =
            std::env::var_os(DAEMON_LIFETIME_ENV).is_some_and(|value| value == EPHEMERAL_LIFETIME);
        Ok(paths)
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

    /// Mark the canonical endpoint as a reference-counted ephemeral owner.
    /// This changes lifetime only; it never changes the ledger's discovery
    /// paths or write authority.
    pub fn with_ephemeral_lifetime(mut self) -> Self {
        self.ephemeral = true;
        self
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

    /// The dedicated leak-reveal socket path for this daemon instance: same
    /// parent directory as the control socket, basename
    /// `{control_file_stem}-leak-reveal.sock`. Recomputed from `self.socket`
    /// via the single pure derivation ([`Self::leak_reveal_socket_path`]) so
    /// daemon bind and TUI/client connect never diverge and ephemeral
    /// uniqueness is inherited from the control stem.
    pub fn leak_reveal_socket(&self) -> PathBuf {
        Self::leak_reveal_socket_path(&self.socket)
    }

    /// The **only** leak-reveal socket path derivation: a pure function of the
    /// control socket path. Same parent directory; basename is the control
    /// file stem (filename without final extension) + `-leak-reveal.sock`.
    ///
    /// * `…/cockpit.sock` → `…/cockpit-leak-reveal.sock`
    /// * `…/daemon.sock` → `…/daemon-leak-reveal.sock`
    /// * `…/cockpit-eph-<pid>-<nonce>.sock` →
    ///   `…/cockpit-eph-<pid>-<nonce>-leak-reveal.sock`
    ///
    /// Never a fixed global basename, so concurrent ephemeral daemons never
    /// collide on the reveal-socket bind.
    pub fn leak_reveal_socket_path(control_socket: &Path) -> PathBuf {
        let stem = control_socket
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("cockpit");
        let file_name = format!("{stem}-leak-reveal.sock");
        match control_socket.parent() {
            Some(parent) => parent.join(file_name),
            None => PathBuf::from(file_name),
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

/// Restores the process umask on drop, so a scoped tightening around a single
/// syscall is undone on every path including an early `?` return.
#[cfg(unix)]
pub(crate) fn bind_private_socket(socket: &std::path::Path) -> Result<UnixListener> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    if let Some(parent) = socket.parent() {
        ensure_private_dir(parent).with_context(|| format!("securing {}", parent.display()))?;
    }

    // Bind inside the 0700 parent secured above, then set 0600 by PATH. A
    // post-bind `fchmod` on a bound Unix-socket fd does NOT change its on-disk
    // directory-entry mode on Linux, and umask is not reliably honored by the
    // async bind, so a path-based chmod is the only mechanism that sets the
    // socket node's mode. The TOCTOU this could open (a same-uid process
    // swapping the path for a symlink between bind and chmod) is closed by the
    // held-fd verification below: the listener fd points at the ORIGINAL socket,
    // so if the chmod hit a swapped victim, the socket's own mode stays wide and
    // the `fstat` check fails closed.
    let listener =
        UnixListener::bind(socket).with_context(|| format!("binding {}", socket.display()))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", socket.display()))?;

    // Fail-closed verification of the SOCKET PATH NODE via a no-follow lstat.
    // We must inspect the filesystem path node, NOT the listener fd: `fstat` on
    // an AF_UNIX listening fd reads the anonymous sockfs inode, whose permission
    // bits are always 0777 and are unaffected by `chmod`. Access to the socket
    // is gated by the filesystem path node's mode — set to 0600 above — inside
    // the 0700 owner-only parent that `ensure_private_dir` verified through its
    // own held directory fd. `symlink_metadata` (lstat, portable across Unix)
    // does not follow a final symlink, so a path swapped for a symlink after
    // bind is reported as a symlink — not a socket — and fails the type check
    // closed rather than being followed. A residual same-uid swap of the path
    // between bind and this stat is out of the cross-user threat model (only the
    // owner can create entries in the 0700-verified parent).
    let meta =
        std::fs::symlink_metadata(socket).with_context(|| format!("stat {}", socket.display()))?;
    let file_type = meta.file_type();
    let mode = meta.mode() & 0o777;
    let owner = meta.uid();
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if !file_type.is_socket() || owner != euid || mode != 0o600 {
        anyhow::bail!(
            "refusing to use {}: expected owner-only socket (uid {euid}, mode 0600), \
             got uid {owner} mode {mode:03o}",
            socket.display()
        );
    }
    Ok(listener)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonStatus {
    /// Daemon is running and completed a valid current-protocol hello.
    Running,
    /// Daemon's hello was malformed or its protocol is outside this client's
    /// supported range. Restart or upgrade before issuing requests.
    IncompatibleProtocol,
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

#[derive(Debug, Clone)]
struct SocketHelloResponse {
    hello: Option<proto::DaemonHello>,
}

fn status_for_socket_response(response: &SocketHelloResponse) -> DaemonStatus {
    if response
        .hello
        .as_ref()
        .is_none_or(|hello| !proto::is_protocol_compatible(hello.protocol_version))
    {
        DaemonStatus::IncompatibleProtocol
    } else {
        DaemonStatus::Running
    }
}

#[cfg(any(unix, test))]
fn parse_socket_hello_line(socket: &Path, line: &str) -> Option<proto::DaemonHello> {
    match proto::parse_daemon_hello_line(line) {
        Ok(hello) => hello,
        Err(error) => {
            tracing::debug!(
                socket = %socket.display(),
                error = %error,
                "daemon hello line could not be parsed"
            );
            None
        }
    }
}

#[cfg(unix)]
async fn socket_responds(socket: &Path) -> Option<SocketHelloResponse> {
    if !socket.exists() {
        return None;
    }
    match tokio::time::timeout(Duration::from_millis(500), UnixStream::connect(socket)).await {
        Ok(Ok(stream)) => {
            let mut proto_stream = proto::ProtoStream::new(stream);
            match tokio::time::timeout(Duration::from_millis(500), proto_stream.recv_raw_line())
                .await
            {
                Ok(Ok(Some(line))) if !line.is_empty() => Some(SocketHelloResponse {
                    hello: parse_socket_hello_line(socket, &line),
                }),
                _ => None,
            }
        }
        _ => None,
    }
}

/// A recorded endpoint can only name a Unix-domain socket. Keep the discovery
/// path intact on platforms without that transport, but honestly report that
/// no daemon is reachable rather than attempting to interpret the path as a
/// different kind of endpoint.
#[cfg(not(unix))]
async fn socket_responds(_socket: &Path) -> Option<SocketHelloResponse> {
    None
}

#[cfg(unix)]
fn socket_responds_blocking(socket: &Path) -> Option<SocketHelloResponse> {
    use std::os::unix::net::UnixStream as StdUnixStream;

    if !socket.exists() {
        return None;
    }
    match StdUnixStream::connect(socket) {
        Ok(s) => {
            let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
            let mut buf = String::new();
            let mut r = BufReader::new(&s);
            if r.read_line(&mut buf).is_ok() && !buf.is_empty() {
                Some(SocketHelloResponse {
                    hello: parse_socket_hello_line(socket, &buf),
                })
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

#[cfg(not(unix))]
fn socket_responds_blocking(_socket: &Path) -> Option<SocketHelloResponse> {
    None
}

#[cfg(unix)]
fn status_for_unreachable_pid(paths: &DaemonPaths) -> DaemonStatus {
    let Some(record) = read_daemon_pid_record(&paths.pid_file) else {
        return DaemonStatus::Stale;
    };
    let identity = match record {
        DaemonPidRecord::Receipt(receipt) => verify_cockpit_daemon_receipt_identity(&receipt),
        DaemonPidRecord::LegacyNumeric(pid) => legacy_pid_identity(pid),
    };
    status_for_pid_identity(identity)
}

#[cfg(unix)]
fn status_for_pid_identity(identity: PidIdentity) -> DaemonStatus {
    match identity {
        PidIdentity::VerifiedDaemon => DaemonStatus::LivePidSocketUnreachable,
        PidIdentity::Missing | PidIdentity::NotDaemon => DaemonStatus::Stale,
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
        ephemeral: record.kind == DaemonEndpointKind::Ephemeral,
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

    if crate::daemon::server::in_process_context(&canonical.socket).is_some() {
        return DaemonProbe::new(DaemonStatus::Running, canonical);
    }

    if let Some(record) = read_endpoint_record(&canonical) {
        let recorded = endpoint_paths(&canonical, &record);
        if let Some(response) = socket_responds(&recorded.socket).await {
            return DaemonProbe::with_hello(
                status_for_socket_response(&response),
                recorded,
                response.hello,
            );
        }
        if !canonical.socket.exists() && canonical.pid_file.exists() {
            return DaemonProbe::new(status_for_unreachable_pid(&canonical), recorded);
        }
    }

    probe_direct(&canonical).await
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static BLOCKING_PROBE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(any(test, feature = "test-support"))]
pub fn reset_blocking_probe_call_count() {
    BLOCKING_PROBE_CALLS.with(|calls| calls.set(0));
}

#[cfg(any(test, feature = "test-support"))]
pub fn blocking_probe_call_count() -> usize {
    BLOCKING_PROBE_CALLS.with(std::cell::Cell::get)
}

fn note_blocking_probe_call() {
    #[cfg(any(test, feature = "test-support"))]
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

    if crate::daemon::server::in_process_context(&canonical.socket).is_some() {
        return DaemonProbe::new(DaemonStatus::Running, canonical);
    }

    if let Some(record) = read_endpoint_record(&canonical) {
        let recorded = endpoint_paths(&canonical, &record);
        if let Some(response) = socket_responds_blocking(&recorded.socket) {
            return DaemonProbe::with_hello(
                status_for_socket_response(&response),
                recorded,
                response.hello,
            );
        }
        if !canonical.socket.exists() && canonical.pid_file.exists() {
            return DaemonProbe::new(status_for_unreachable_pid(&canonical), recorded);
        }
    }

    probe_direct_blocking(&canonical)
}

#[cfg(test)]
fn discover_blocking_with_canonical(canonical: DaemonPaths) -> DaemonProbe {
    note_blocking_probe_call();
    if let Some(state) = canonical.pid_file.parent() {
        let endpoint = endpoint_file_for_state(state);
        if let Some(record) = read_published_endpoint_record_from(&endpoint, &canonical) {
            let recorded = endpoint_paths(&canonical, &record);
            if let Some(response) = socket_responds_blocking(&recorded.socket) {
                return DaemonProbe::with_hello(
                    status_for_socket_response(&response),
                    recorded,
                    response.hello,
                );
            }
            if !canonical.socket.exists() && canonical.pid_file.exists() {
                let status = status_for_unreachable_pid(&canonical);
                // The recorded socket is a cross-runtime redirect hint.  When
                // it is dead, discovery must report the canonical runtime's
                // own stale state — not steal another runtime's socket path.
                return DaemonProbe::new(status, canonical.clone());
            }
        }
    }

    probe_direct_blocking(&canonical)
}

#[cfg(unix)]
async fn probe_direct(paths: &DaemonPaths) -> DaemonProbe {
    if let Some(response) = socket_responds(&paths.socket).await {
        return DaemonProbe::with_hello(
            status_for_socket_response(&response),
            paths.clone(),
            response.hello,
        );
    }
    if paths.pid_file.exists() {
        DaemonProbe::new(status_for_unreachable_pid(paths), paths.clone())
    } else {
        DaemonProbe::new(DaemonStatus::NotRunning, paths.clone())
    }
}

#[cfg(not(unix))]
async fn probe_direct(paths: &DaemonPaths) -> DaemonProbe {
    if paths.pid_file.exists() {
        DaemonProbe::new(status_for_unreachable_pid(paths), paths.clone())
    } else {
        DaemonProbe::new(DaemonStatus::NotRunning, paths.clone())
    }
}

#[cfg(unix)]
fn probe_direct_blocking(paths: &DaemonPaths) -> DaemonProbe {
    if let Some(response) = socket_responds_blocking(&paths.socket) {
        return DaemonProbe::with_hello(
            status_for_socket_response(&response),
            paths.clone(),
            response.hello,
        );
    }
    if paths.pid_file.exists() {
        DaemonProbe::new(status_for_unreachable_pid(paths), paths.clone())
    } else {
        DaemonProbe::new(DaemonStatus::NotRunning, paths.clone())
    }
}

#[cfg(not(unix))]
fn probe_direct_blocking(paths: &DaemonPaths) -> DaemonProbe {
    if paths.pid_file.exists() {
        DaemonProbe::new(status_for_unreachable_pid(paths), paths.clone())
    } else {
        DaemonProbe::new(DaemonStatus::NotRunning, paths.clone())
    }
}

/// Cheap probe: try to connect and read the daemon's "hello"
/// envelope. The server emits one immediately on accept (see
/// [`server::handle_client`]), so any successful read of a non-empty
/// line confirms the daemon is alive — no client-side write needed.
pub async fn probe(paths: &DaemonPaths) -> DaemonStatus {
    // Exact-path probe keys on this socket. A shared state-home pid file
    // belonging to another runtime must not make this path look stale.
    if !paths.socket.exists() {
        return DaemonStatus::NotRunning;
    }
    probe_direct(paths).await.status
}

/// Sync version of `probe`. Useful before the tokio runtime is up.
pub fn probe_blocking(paths: &DaemonPaths) -> DaemonStatus {
    note_blocking_probe_call();
    // Exact-path probe keys on this socket. A shared state-home pid file
    // belonging to another runtime must not make this path look stale.
    if !paths.socket.exists() {
        return DaemonStatus::NotRunning;
    }
    probe_direct_blocking(paths).status
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
        || (argv_requests_daemon_start(args) && args.iter().any(|arg| arg == "--no-sandbox"))
}

fn argv_requests_daemon_start(args: &[String]) -> bool {
    let Some(exe) = args.first() else {
        return false;
    };
    let is_cockpit = Path::new(exe)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "cockpit" || name.starts_with("cockpit-"));
    is_cockpit
        && args
            .windows(2)
            .any(|pair| pair[0] == "daemon" && pair[1] == "start")
}

pub fn derive_restart_no_sandbox(paths: &DaemonPaths, explicit_no_sandbox: bool) -> bool {
    if explicit_no_sandbox {
        return true;
    }
    #[cfg(unix)]
    {
        let Some(pid) = read_pid_file(&paths.pid_file) else {
            return false;
        };
        cockpit_host::daemon_lifecycle::read_process_cmdline(pid)
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
    read_pid_file(&paths.pid_file)
}

pub fn restart_release_timeout(grace_secs: Option<u64>) -> Duration {
    let drain = grace_secs
        .map(Duration::from_secs)
        .unwrap_or(shutdown::SHUTDOWN_DRAIN_GRACE);
    drain.saturating_add(RESTART_RELEASE_CLEANUP_GRACE)
}

pub async fn wait_for_restart_release(
    paths: &DaemonPaths,
    expected_pid: Option<u32>,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if restart_metadata_released(paths, expected_pid) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn restart_metadata_released(paths: &DaemonPaths, expected_pid: Option<u32>) -> bool {
    let pid_file_released =
        expected_pid.is_none_or(|pid| read_pid_file(&paths.pid_file) != Some(pid));
    // The exclusive SQLite boot lock is a kernel flock on the dying
    // process. Pid/socket files are unlinked during drain *before* that
    // process exits; spawning the replacement then fails with
    // `database already has a live exclusive owner`.
    let process_released = expected_pid.is_none_or(|pid| {
        #[cfg(unix)]
        {
            if !cockpit_host::daemon_lifecycle::process_exists(pid) {
                return true;
            }
            match cockpit_host::daemon_lifecycle::read_daemon_pid_record(&paths.pid_file) {
                Some(cockpit_host::daemon_lifecycle::DaemonPidRecord::Receipt(receipt))
                    if receipt.pid == pid =>
                {
                    matches!(
                        cockpit_host::daemon_lifecycle::verify_cockpit_daemon_receipt_identity(
                            &receipt
                        ),
                        cockpit_host::daemon_lifecycle::PidIdentity::Missing
                            | cockpit_host::daemon_lifecycle::PidIdentity::NotDaemon
                    )
                }
                _ => false,
            }
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            true
        }
    });
    pid_file_released && process_released && !paths.pid_file.exists() && !paths.socket.exists()
}

/// Spawn a detached ephemeral daemon at the canonical ledger endpoint.
/// The lifetime marker is internal; the socket remains discoverable so every
/// client of this ledger can share the same owner.
/// Returns the live child handle. The owning guard retains it until verified
/// shutdown, so PID reuse is impossible even before the v2 receipt publishes.
///
/// An auto-promoted ephemeral daemon is never launched `--no-sandbox`:
/// the client's `--no-sandbox` is a *per-session* default passed at
/// attach time, not a daemon-level one (sandboxing part 2 precedence).
pub struct DetachedEphemeralChild {
    child: std::process::Child,
    process_start: cockpit_host::daemon_lifecycle::ProcessStartIdentity,
    executable: PathBuf,
}

impl DetachedEphemeralChild {
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    fn into_child(self) -> std::process::Child {
        self.child
    }

    fn process_start(&self) -> cockpit_host::daemon_lifecycle::ProcessStartIdentity {
        self.process_start
    }

    fn executable(&self) -> &Path {
        &self.executable
    }
}

pub fn spawn_detached_ephemeral(paths: &DaemonPaths) -> Result<DetachedEphemeralChild> {
    ephemeral_guard::initialize_process_reaper()?;
    let provisional = ephemeral_guard::ProvisionalEphemeralChild::new(
        paths.clone(),
        spawn_detached_child(Some(paths), false, false)?,
    );
    let process_start = match cockpit_host::daemon_lifecycle::process_start_identity(
        provisional.id()?,
    ) {
        Ok(identity) => identity,
        Err(error) => {
            return match provisional.shutdown() {
                Ok(()) => Err(error).context("capturing ephemeral child start identity"),
                Err(cleanup) => Err(anyhow::anyhow!(
                    "capturing ephemeral child start identity: {error}; exact child cleanup failed: {cleanup}"
                )),
            };
        }
    };
    let executable = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .context("capturing ephemeral child executable identity")?;
    let child = provisional.into_child()?;
    Ok(DetachedEphemeralChild {
        child,
        process_start,
        executable,
    })
}

#[cfg(unix)]
fn spawn_detached_inner(
    ephemeral: Option<&DaemonPaths>,
    no_sandbox: bool,
    resume_all_sessions: bool,
) -> Result<u32> {
    Ok(spawn_detached_child(ephemeral, no_sandbox, resume_all_sessions)?.id())
}

#[cfg(unix)]
fn spawn_detached_child(
    ephemeral: Option<&DaemonPaths>,
    no_sandbox: bool,
    resume_all_sessions: bool,
) -> Result<std::process::Child> {
    #[cfg(unix)]
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    let exe = std::env::current_exe().context("locating own binary")?;
    let mut command = Command::new(exe);
    command
        .arg("daemon")
        .arg("start")
        .arg("--foreground")
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    match open_detach_child_log() {
        Some(file) => {
            command.stderr(file);
        }
        None => {
            command.stderr(Stdio::null());
        }
    }
    if no_sandbox {
        command.arg("--no-sandbox");
    }
    if resume_all_sessions {
        command.arg("--resume-all-sessions");
    }
    if ephemeral.is_some() {
        command.env(DAEMON_LIFETIME_ENV, EPHEMERAL_LIFETIME);
    }
    #[cfg(unix)]
    command.process_group(0);
    command.spawn().context("spawning daemon child")
}

#[cfg(unix)]
fn open_detach_child_log() -> Option<std::fs::File> {
    let dir = dirs::cache_dir()?.join("cockpit");
    cockpit_host::private_fs::ensure_private_dir(&dir).ok()?;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("cockpit.log"))
        .ok()
}

#[cfg(not(unix))]
fn spawn_detached_inner(
    _ephemeral: Option<&DaemonPaths>,
    _no_sandbox: bool,
    _resume_all_sessions: bool,
) -> Result<u32> {
    anyhow::bail!("daemon socket transport is not supported on this platform")
}

#[cfg(not(unix))]
fn spawn_detached_child(
    _ephemeral: Option<&DaemonPaths>,
    _no_sandbox: bool,
    _resume_all_sessions: bool,
) -> Result<std::process::Child> {
    anyhow::bail!("daemon socket transport is not supported on this platform")
}

/// Run the daemon's accept loop in the current process. Blocks until
/// SIGINT/SIGTERM. Boots the DB + lock manager, registers a shutdown
/// watcher, and runs the [`server::run_accept_loop`].
pub async fn run_foreground(
    paths: DaemonPaths,
    terminal_factory: terminal::TerminalHostFactory,
) -> Result<()> {
    run_foreground_inner(
        paths,
        shutdown::SHUTDOWN_DRAIN_GRACE,
        false,
        terminal_factory,
    )
    .await
}

pub async fn run_foreground_with_resume(
    paths: DaemonPaths,
    resume_all_sessions: bool,
    terminal_factory: terminal::TerminalHostFactory,
) -> Result<()> {
    run_foreground_inner(
        paths,
        shutdown::SHUTDOWN_DRAIN_GRACE,
        resume_all_sessions,
        terminal_factory,
    )
    .await
}

pub struct InProcessDaemonGuard {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    force: shutdown::ShutdownSignal,
    completion: Option<tokio::sync::oneshot::Receiver<Result<()>>>,
    supervisor: Option<std::thread::JoinHandle<()>>,
}

struct SupervisorReap {
    supervisor: std::thread::JoinHandle<()>,
    completed: Option<tokio::sync::oneshot::Sender<Result<()>>>,
}

static IN_PROCESS_SUPERVISOR_REAPER: std::sync::OnceLock<
    Option<std::sync::mpsc::Sender<SupervisorReap>>,
> = std::sync::OnceLock::new();

fn supervisor_reaper() -> Option<&'static std::sync::mpsc::Sender<SupervisorReap>> {
    IN_PROCESS_SUPERVISOR_REAPER
        .get_or_init(|| {
            let (send, receive) = std::sync::mpsc::channel::<SupervisorReap>();
            std::thread::Builder::new()
                .name("cockpit-daemon-supervisor-reaper".to_string())
                .spawn(move || {
                    while let Ok(reap) = receive.recv() {
                        let result = reap
                            .supervisor
                            .join()
                            .map_err(|_| anyhow::anyhow!("in-process daemon supervisor panicked"));
                        if let Some(completed) = reap.completed {
                            let _ = completed.send(result);
                        } else if let Err(error) = result {
                            tracing::error!(%error, "reaped in-process daemon supervisor failed");
                        }
                    }
                })
                .ok()
                .map(|_| send)
        })
        .as_ref()
}

fn submit_supervisor_to_reaper(
    supervisor: std::thread::JoinHandle<()>,
    completed: Option<tokio::sync::oneshot::Sender<Result<()>>>,
) {
    submit_supervisor_reap(
        supervisor_reaper(),
        SupervisorReap {
            supervisor,
            completed,
        },
    );
}

fn submit_supervisor_reap(
    reaper: Option<&std::sync::mpsc::Sender<SupervisorReap>>,
    reap: SupervisorReap,
) {
    let reap = match reaper {
        Some(reaper) => match reaper.send(reap) {
            Ok(()) => return,
            Err(error) => error.0,
        },
        None => reap,
    };
    // Emergency fallback retains the original JoinHandle. There is no second
    // fallible thread spawn whose closure could consume and detach it.
    let result = reap
        .supervisor
        .join()
        .map_err(|_| anyhow::anyhow!("in-process daemon supervisor panicked"));
    if let Some(completed) = reap.completed {
        let _ = completed.send(result);
    } else if let Err(error) = result {
        tracing::error!(%error, "emergency supervisor join failed");
    }
}

pub(crate) fn reap_daemon_owner_thread(supervisor: std::thread::JoinHandle<()>) {
    submit_supervisor_to_reaper(supervisor, None);
}

impl InProcessDaemonGuard {
    pub async fn shutdown(mut self) -> Result<()> {
        self.begin_shutdown();
        let result = self
            .completion
            .take()
            .context("in-process daemon shutdown completion missing")?
            .await
            .context("in-process daemon shutdown supervisor stopped")?;
        let supervisor = self
            .supervisor
            .take()
            .context("in-process daemon shutdown supervisor handle missing")?;
        let (joined, join) = tokio::sync::oneshot::channel();
        submit_supervisor_to_reaper(supervisor, Some(joined));
        join.await
            .context("in-process daemon supervisor reaper stopped")??;
        result
    }

    pub(crate) fn begin_shutdown(&mut self) {
        // Make drain visible on the owner thread immediately. The
        // supervisor still performs the actual teardown; it must not treat
        // this first transition as a second stop request.
        self.force.begin_drain();
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }

    pub(crate) fn shutdown_force_handle(&self) -> shutdown::ShutdownSignal {
        self.force.clone()
    }
}

impl Drop for InProcessDaemonGuard {
    fn drop(&mut self) {
        self.begin_shutdown();
        // Cancellation/panic never blocks an async executor. The process-wide
        // OS-thread reaper joins the runtime-independent supervisor even if
        // the originating Tokio runtime is already disappearing.
        if let Some(supervisor) = self.supervisor.take() {
            submit_supervisor_to_reaper(supervisor, None);
        }
    }
}

async fn drain_daemon_context(
    ctx: &std::sync::Arc<server::DaemonContext>,
    grace: Duration,
) -> Result<()> {
    let force_ctx = ctx.clone();
    let force_timer = tokio::spawn(async move {
        tokio::time::sleep(grace).await;
        if !force_ctx.shutdown_signal().is_forced() {
            force_ctx.shutdown_signal().force();
            force_ctx.broadcast_global(proto::Event::DaemonDraining { forced: true });
        }
    });
    let drain = ctx.registry.drain_all(grace).await;
    let mut failures = Vec::new();
    if !drain.park_commit.is_clean() {
        failures.push(format!("interrupt park commit: {:?}", drain.park_commit));
    }
    if !drain.is_clean() {
        failures.push("session worker drain was forced or incomplete".to_string());
    }

    if ctx.process_containment.is_some() || ctx.write_scope.is_some() {
        let containment = ctx.process_containment.clone();
        let write_scope = ctx.write_scope.clone();
        let wall_cap = grace
            .checked_add(Duration::from_millis(500))
            .unwrap_or(grace)
            .min(Duration::from_secs(2));
        let barrier = tokio::task::spawn_blocking(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("building shutdown containment runtime")?;
            runtime.block_on(async move {
                tokio::time::timeout(wall_cap, async move {
                    let mut errors = Vec::new();
                    if let Some(containment) = containment.as_ref()
                        && let Err(error) = containment.begin_shutdown().await
                    {
                        errors.push(format!("containment begin-shutdown: {error}"));
                    }
                    if let Some(write_scope) = write_scope.as_ref()
                        && let Err(error) = write_scope.begin_shutdown().await
                    {
                        errors.push(format!("write-scope begin-shutdown: {error}"));
                    }
                    if let Some(containment) = containment.as_ref()
                        && let Err(error) = containment.await_all_empty(Some(grace)).await
                    {
                        errors.push(format!("containment not empty: {error}"));
                    }
                    if let Some(write_scope) = write_scope.as_ref()
                        && let Err(error) = write_scope.assert_shutdown_clean().await
                    {
                        errors.push(format!("write-scope not clean: {error}"));
                    }
                    if errors.is_empty() {
                        Ok::<(), anyhow::Error>(())
                    } else {
                        anyhow::bail!(errors.join("; "))
                    }
                })
                .await
                .map_err(|_| anyhow::anyhow!("containment barrier exceeded {wall_cap:?}"))?
            })
        });
        match barrier.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failures.push(format!("containment barrier: {error}")),
            Err(error) => failures.push(format!("containment barrier task: {error}")),
        }
    }

    let result = if failures.is_empty() {
        Ok(())
    } else {
        if !ctx.shutdown_signal().is_forced() {
            ctx.shutdown_signal().force();
            ctx.broadcast_global(proto::Event::DaemonDraining { forced: true });
        }
        Err(anyhow::anyhow!(failures.join("; ")))
    };
    force_timer.abort();
    let _ = force_timer.await;
    result
}

async fn shutdown_in_process_context(
    ctx: std::sync::Arc<server::DaemonContext>,
    mut tasks: Vec<tokio::task::JoinHandle<()>>,
) -> Result<()> {
    // Owner Drop may already have begun drain so observers see it before
    // this runtime is scheduled. Do not go through `request_shutdown`:
    // that treats an already-draining signal as a second stop and forces.
    if ctx.shutdown_signal().begin_drain() {
        tracing::info!("daemon: graceful drain begun");
        ctx.broadcast_global(proto::Event::DaemonDraining { forced: false });
    }
    let grace = ctx
        .take_shutdown_grace_override()
        .unwrap_or(shutdown::SHUTDOWN_DRAIN_GRACE);
    let result = drain_daemon_context(&ctx, grace).await;
    for task in tasks.drain(..) {
        task.abort();
        let _ = task.await;
    }
    if let Err(error) = &result {
        tracing::warn!(%error, "in-process daemon shutdown was not clean");
    }
    drop(ctx);
    result
}

fn spawn_in_process_shutdown_supervisor(
    ctx: std::sync::Arc<server::DaemonContext>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
) -> Result<InProcessDaemonGuard> {
    let force = ctx.shutdown_signal().clone();
    let (shutdown, shutdown_request) = tokio::sync::oneshot::channel();
    let (completion, completed) = tokio::sync::oneshot::channel();
    let supervisor = std::thread::Builder::new()
        .name("cockpit-in-process-shutdown".to_string())
        .spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("building in-process daemon shutdown runtime")
                .and_then(|runtime| {
                    runtime.block_on(async move {
                        let _ = shutdown_request.await;
                        shutdown_in_process_context(ctx, tasks).await
                    })
                });
            let _ = completion.send(result);
        })
        .context("spawning in-process daemon shutdown supervisor")?;
    Ok(InProcessDaemonGuard {
        shutdown: Some(shutdown),
        force,
        completion: Some(completed),
        supervisor: Some(supervisor),
    })
}

struct InProcessBootReady {
    endpoint: cockpit_client::InProcessEndpoint,
    force: shutdown::ShutdownSignal,
}

struct PendingInProcessBoot {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    supervisor: Option<std::thread::JoinHandle<()>>,
}

impl Drop for PendingInProcessBoot {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(supervisor) = self.supervisor.take() {
            submit_supervisor_to_reaper(supervisor, None);
        }
    }
}

fn spawn_owned_in_process_daemon(
    paths: DaemonPaths,
    terminal_factory: terminal::TerminalHostFactory,
) -> Result<(
    tokio::sync::oneshot::Receiver<Result<InProcessBootReady>>,
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<Result<()>>,
    std::thread::JoinHandle<()>,
)> {
    let (booted, boot) = tokio::sync::oneshot::channel();
    let (shutdown, shutdown_request) = tokio::sync::oneshot::channel();
    let (completion, completed) = tokio::sync::oneshot::channel();
    let supervisor = std::thread::Builder::new()
        .name("cockpit-in-process-daemon".to_string())
        .spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("building in-process daemon runtime")
                .and_then(|runtime| {
                    runtime.block_on(async move {
                        let ctx = match server::boot(paths, terminal_factory).await {
                            Ok(ctx) => std::sync::Arc::new(ctx),
                            Err(error) => {
                                let _ = booted.send(Err(error));
                                return Ok(());
                            }
                        };
                        #[cfg(not(test))]
                        let tasks = {
                            let mut tasks = Vec::new();
                            tasks.push(server::spawn_lock_sweeper(ctx.clone()));
                            #[cfg(feature = "remote")]
                            tasks.push(org_sync::spawn_background(ctx.clone()));
                            #[cfg(feature = "remote")]
                            tasks.push(remote_audit_upload::spawn_background(ctx.clone()));
                            #[cfg(feature = "remote")]
                            tasks.push(connector::spawn_background(ctx.clone()));
                            #[cfg(feature = "remote")]
                            tasks.push(remote_outbox_worker::spawn_background(ctx.clone()));
                            tasks
                        };
                        #[cfg(test)]
                        let tasks = Vec::new();
                        let endpoint = server::register_in_process_context(ctx.clone());
                        let force = ctx.shutdown_signal().clone();
                        if booted
                            .send(Ok(InProcessBootReady { endpoint, force }))
                            .is_err()
                        {
                            return shutdown_in_process_context(ctx, tasks).await;
                        }
                        let _ = shutdown_request.await;
                        shutdown_in_process_context(ctx, tasks).await
                    })
                });
            let _ = completion.send(result);
        })
        .context("spawning in-process daemon owner thread")?;
    Ok((boot, shutdown, completed, supervisor))
}

pub(crate) async fn boot_in_process(
    paths: DaemonPaths,
    terminal_factory: terminal::TerminalHostFactory,
) -> Result<(
    cockpit_client::InProcessEndpoint,
    Option<InProcessDaemonGuard>,
)> {
    if let Some(endpoint) = server::registered_in_process_endpoint(&paths.socket) {
        return Ok((endpoint, None));
    }
    let (boot, shutdown, completion, supervisor) =
        spawn_owned_in_process_daemon(paths, terminal_factory)?;
    let mut pending = PendingInProcessBoot {
        shutdown: Some(shutdown),
        supervisor: Some(supervisor),
    };
    let ready = boot
        .await
        .context("in-process daemon owner stopped during boot")??;
    Ok((
        ready.endpoint,
        Some(InProcessDaemonGuard {
            shutdown: pending.shutdown.take(),
            force: ready.force,
            completion: Some(completion),
            supervisor: pending.supervisor.take(),
        }),
    ))
}

/// Isolated persistent daemon for tests. Holds the owner thread so the
/// registered in-process endpoint can hello without an OS socket. Dropping
/// this value tears that owner down.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub struct TestPersistentDaemon {
    ctx: std::sync::Arc<server::DaemonContext>,
    _owner: Option<InProcessDaemonGuard>,
}

#[cfg(any(test, feature = "test-support"))]
impl TestPersistentDaemon {
    pub fn context(&self) -> &std::sync::Arc<server::DaemonContext> {
        &self.ctx
    }
}

#[cfg(any(test, feature = "test-support"))]
struct TestPersistentBootReady {
    ctx: std::sync::Arc<server::DaemonContext>,
    force: shutdown::ShutdownSignal,
}

/// Owner-thread boot used by [`boot_test_persistent_daemon`] and in-process
/// auto-promote. Endpoint acceptors are spawned on this runtime — never on
/// the caller's `#[tokio::test(flavor = "current_thread")]` runtime and never
/// via `spawn_local`.
#[cfg(any(test, feature = "test-support"))]
fn spawn_owned_test_persistent_daemon(
    paths: DaemonPaths,
    source: config_source::ConfigSource,
) -> Result<(
    tokio::sync::oneshot::Receiver<Result<TestPersistentBootReady>>,
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<Result<()>>,
    std::thread::JoinHandle<()>,
)> {
    let (booted, boot) = tokio::sync::oneshot::channel();
    let (shutdown, shutdown_request) = tokio::sync::oneshot::channel();
    let (completion, completed) = tokio::sync::oneshot::channel();
    let supervisor = std::thread::Builder::new()
        .name("cockpit-test-persistent-daemon".to_string())
        .spawn(move || {
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("building test persistent daemon runtime")
                .and_then(|runtime| {
                    runtime.block_on(async move {
                        let db = crate::db::Db::open_in_memory()
                            .context("opening isolated test daemon DB")?;
                        let locks = Arc::new(crate::locks::LockManager::in_memory(db.clone()));
                        let ctx = std::sync::Arc::new(server::DaemonContext::new(
                            db,
                            locks,
                            paths,
                            terminal::default_host_factory(),
                            source,
                        ));
                        let _endpoint = server::register_in_process_context(ctx.clone());
                        let force = ctx.shutdown_signal().clone();
                        if booted
                            .send(Ok(TestPersistentBootReady {
                                ctx: ctx.clone(),
                                force,
                            }))
                            .is_err()
                        {
                            return shutdown_in_process_context(ctx, Vec::new()).await;
                        }
                        let _ = shutdown_request.await;
                        shutdown_in_process_context(ctx, Vec::new()).await
                    })
                });
            let _ = completion.send(result);
        })
        .context("spawning test persistent daemon owner thread")?;
    Ok((boot, shutdown, completed, supervisor))
}

#[cfg(any(test, feature = "test-support"))]
pub async fn boot_test_persistent_daemon() -> Result<TestPersistentDaemon> {
    boot_test_persistent_daemon_with_source(config_source::ConfigSource::fixed(
        Default::default(),
        Default::default(),
    ))
    .await
}

#[cfg(any(test, feature = "test-support"))]
async fn boot_test_persistent_daemon_with_source(
    source: config_source::ConfigSource,
) -> Result<TestPersistentDaemon> {
    let paths = DaemonPaths::resolve_canonical()?;
    if let Some(ctx) = server::in_process_context(&paths.socket) {
        return Ok(TestPersistentDaemon { ctx, _owner: None });
    }
    let (boot, shutdown, completion, supervisor) =
        spawn_owned_test_persistent_daemon(paths, source)?;
    let mut pending = PendingInProcessBoot {
        shutdown: Some(shutdown),
        supervisor: Some(supervisor),
    };
    let ready = boot
        .await
        .context("in-process test daemon owner stopped during boot")??;
    Ok(TestPersistentDaemon {
        ctx: ready.ctx,
        _owner: Some(InProcessDaemonGuard {
            shutdown: pending.shutdown.take(),
            force: ready.force,
            completion: Some(completion),
            supervisor: pending.supervisor.take(),
        }),
    })
}

/// Test seam for first-run persistent promotion.
/// boots an in-process canonical daemon instead of spawning a child.
#[cfg(any(test, feature = "test-support"))]
static IN_PROCESS_AUTO_PROMOTE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(any(test, feature = "test-support"))]
static IN_PROCESS_AUTO_PROMOTE_PRODUCTION_CONFIG: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(any(test, feature = "test-support"))]
static AUTO_PROMOTED_DAEMON: std::sync::Mutex<Option<TestPersistentDaemon>> =
    std::sync::Mutex::new(None);

#[cfg(any(test, feature = "test-support"))]
pub struct InProcessAutoPromoteGuard;

#[cfg(any(test, feature = "test-support"))]
impl Drop for InProcessAutoPromoteGuard {
    fn drop(&mut self) {
        IN_PROCESS_AUTO_PROMOTE.store(false, std::sync::atomic::Ordering::SeqCst);
        IN_PROCESS_AUTO_PROMOTE_PRODUCTION_CONFIG.store(false, std::sync::atomic::Ordering::SeqCst);
        *AUTO_PROMOTED_DAEMON
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn enable_in_process_auto_promote() -> InProcessAutoPromoteGuard {
    IN_PROCESS_AUTO_PROMOTE.store(true, std::sync::atomic::Ordering::SeqCst);
    InProcessAutoPromoteGuard
}

/// Test seam equivalent to [`enable_in_process_auto_promote`] whose daemon
/// uses the production layered config source. This is intentionally separate
/// from the fixed-config guard so existing core tests retain their isolated
/// config behavior.
#[cfg(any(test, feature = "test-support"))]
pub fn enable_in_process_auto_promote_with_production_config() -> InProcessAutoPromoteGuard {
    IN_PROCESS_AUTO_PROMOTE_PRODUCTION_CONFIG.store(true, std::sync::atomic::Ordering::SeqCst);
    IN_PROCESS_AUTO_PROMOTE.store(true, std::sync::atomic::Ordering::SeqCst);
    InProcessAutoPromoteGuard
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn in_process_auto_promote_enabled() -> bool {
    IN_PROCESS_AUTO_PROMOTE.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) async fn auto_promote_in_process_persistent() -> Result<u32> {
    let ctx = if IN_PROCESS_AUTO_PROMOTE_PRODUCTION_CONFIG.load(std::sync::atomic::Ordering::SeqCst)
    {
        boot_test_persistent_daemon_with_source(config_source::ConfigSource::production()).await?
    } else {
        boot_test_persistent_daemon().await?
    };
    *AUTO_PROMOTED_DAEMON
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(ctx);
    Ok(std::process::id())
}

#[cfg(test)]
pub(crate) async fn boot_in_process_with_db(
    paths: DaemonPaths,
    db: crate::db::Db,
) -> Result<std::sync::Arc<server::DaemonContext>> {
    if let Some(ctx) = server::in_process_context(&paths.socket) {
        return Ok(ctx);
    }
    let locks = Arc::new(crate::locks::LockManager::from_db(db.clone()).await?);
    let ctx = std::sync::Arc::new(server::DaemonContext::new(
        db,
        locks,
        paths,
        terminal::test_host_factory(),
        config_source::ConfigSource::fixed(Default::default(), Default::default()),
    ));
    server::register_in_process_context(ctx.clone());
    Ok(ctx)
}

/// Like [`run_foreground`] but with injectable drain grace for lifecycle
/// tests. `drain_grace` bounds how long teardown awaits in-flight work before
/// force-aborting it.
#[cfg(unix)]
pub async fn run_foreground_inner(
    paths: DaemonPaths,
    drain_grace: Duration,
    resume_all_sessions: bool,
    terminal_factory: terminal::TerminalHostFactory,
) -> Result<()> {
    run_foreground_inner_with_boot_db(
        paths,
        drain_grace,
        resume_all_sessions,
        terminal_factory,
        None,
    )
    .await
}

#[cfg(unix)]
async fn run_foreground_inner_with_boot_db(
    paths: DaemonPaths,
    drain_grace: Duration,
    resume_all_sessions: bool,
    terminal_factory: terminal::TerminalHostFactory,
    boot_db: Option<crate::db::Db>,
) -> Result<()> {
    let mut timer = crate::startup::PhaseTimer::start("daemon::run_foreground");
    if matches!(
        probe(&paths).await,
        DaemonStatus::Running | DaemonStatus::IncompatibleProtocol
    ) {
        anyhow::bail!(
            "another daemon is already running (socket: {})",
            paths.socket.display()
        );
    }
    if boot_db.is_none()
        && DaemonPaths::resolve_canonical()
            .as_ref()
            .is_ok_and(|canonical| {
                paths.pid_file == canonical.pid_file && paths.socket == canonical.socket
            })
    {
        let discovered = discover().await;
        if matches!(
            discovered.status,
            DaemonStatus::Running
                | DaemonStatus::IncompatibleProtocol
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
    let executable = std::env::current_exe().context("resolving daemon executable identity")?;
    let endpoint_record = if DaemonPaths::resolve_canonical()
        .as_ref()
        .is_ok_and(|canonical| {
            paths.pid_file == canonical.pid_file && paths.socket == canonical.socket
        }) {
        paths.pid_file.parent().map(endpoint_file_for_state)
    } else {
        None
    };
    // The exclusive PID receipt is the starting reservation. Acquire it before
    // touching the shared socket so a losing concurrent starter cannot unlink
    // the winner's newly bound endpoint.
    let pid_receipt = reclaim_stale_and_reserve(
        &paths.pid_file,
        &paths.socket,
        endpoint_record.as_deref(),
        std::process::id(),
        &executable,
    )
    .with_context(|| format!("reserving pid file {}", paths.pid_file.display()))?;
    let mut metadata_guard = ForegroundMetadataGuard::new(
        paths.pid_file.clone(),
        paths.socket.clone(),
        endpoint_record,
        pid_receipt.clone(),
    );
    match std::fs::remove_file(&paths.socket) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("removing stale daemon socket after reservation"),
    }

    let uses_supplied_boot_db = boot_db.is_some();
    let ctx = std::sync::Arc::new(match boot_db {
        Some(db) => {
            server::boot_with_db(
                paths.clone(),
                db,
                &mut timer,
                terminal_factory,
                crate::daemon::config_source::ConfigSource::production(),
            )
            .await?
        }
        None => server::boot(paths.clone(), terminal_factory).await?,
    });
    if resume_all_sessions {
        resume_all_paused_sessions(&ctx.db).await?;
    }
    // Recovery is part of the socket-publication barrier. Neither the control
    // socket nor its reveal sibling may be observable while durable authority
    // is still being reconciled.
    server::recover_before_socket_publish(&ctx).await?;
    timer.phase("boot");

    // Do not expose a connectable socket until boot has completed. A client
    // that observes a bound socket expects the hello promptly; publishing it
    // before database/config initialization creates a startup handshake race.
    let listener = bind_private_socket(&paths.socket)?;
    if uses_supplied_boot_db {
        write_endpoint_record_with_receipt_and_canonical(&paths, &paths, &pid_receipt)?;
    } else {
        write_endpoint_record(&paths)?;
    }
    timer.phase("bind_publish");

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

    // A reference-counted ephemeral owner remains available until at least
    // one client has established a transport connection, then begins the
    // normal drain immediately when the final client disconnects. This
    // deliberately has no idle timeout.
    let lifecycle_task = if paths.ephemeral {
        let ctx = ctx.clone();
        let reaper_ctx = ctx.clone();
        let client_presence = ctx.client_presence();
        Some(tokio::spawn(async move {
            ephemeral_last_client_reaper(client_presence, move || {
                reaper_ctx.reap_ephemeral_last_client()
            })
            .await;
        }))
    } else {
        None
    };

    // Idle-lock sweeper (`read-wait-and-lock-expiry.md`): the single
    // daemon-internal periodic task that reclaims locks whose holder has
    // gone idle past the 5-minute threshold, so a hung/abandoned holder
    // can't block a waiting `read` forever.
    let _lock_sweeper = server::spawn_lock_sweeper(ctx.clone());
    #[cfg(feature = "remote")]
    let org_sync_task = org_sync::spawn_background(ctx.clone());
    #[cfg(feature = "remote")]
    let remote_audit_upload_task = remote_audit_upload::spawn_background(ctx.clone());
    #[cfg(feature = "remote")]
    let connector_task = connector::spawn_background(ctx.clone());
    #[cfg(feature = "remote")]
    let remote_outbox_task = remote_outbox_worker::spawn_background(ctx.clone());

    // Dedicated Unix peer-authenticated leak-reveal socket (sibling of the
    // control socket; path a pure function of it). Carries only the closed
    // reveal frame — never ordinary proto — and accepts only after the same
    // same-uid peer check the control socket uses. A bind failure is non-fatal
    // for daemon boot: reveal-over-socket is simply unavailable then.
    #[cfg(unix)]
    let leak_reveal_task = match leak_reveal_socket::bind_reveal_socket(&ctx) {
        Ok(reveal_listener) => {
            let ctx = ctx.clone();
            Some(tokio::spawn(async move {
                if let Err(error) =
                    leak_reveal_socket::run_reveal_accept_loop(ctx, reveal_listener).await
                {
                    tracing::warn!(%error, "leak-reveal accept loop ended with error");
                }
            }))
        }
        Err(error) => {
            tracing::warn!(%error, "failed to bind leak-reveal socket; reveal-over-socket unavailable");
            None
        }
    };

    timer.phase("signal_and_lifecycle");
    timer.done();
    let accept = server::run_accept_loop(ctx.clone(), listener);
    let result = accept.await;

    // The accept loop has stopped (a drain began). Ensure the drain is
    // marked even on the (impossible-by-construction, but defensive) path
    // where the loop broke without `request_shutdown` having run, so the
    // new-request gate is definitely closed before we await workers.
    server::request_shutdown(&ctx);

    // Bounded grace, then force. `drain_daemon_context` owns the shared
    // foreground/in-process force timer and result policy, so neither path
    // can report a clean stop with unfinished workers or containment.
    let drain_grace = ctx.take_shutdown_grace_override().unwrap_or(drain_grace);
    // `drain_all` now returns BOTH the grace-bounded running-work result and the
    // decoupled interrupt-park commit terminal
    // (`daemon-lifecycle-replay-timing-robustness.md`). Crucially it does not
    // return until the park-commit has resolved (committed, known-failed write,
    // or its own product-owned deadline) — so `metadata_guard.cleanup()` below,
    // which releases the pid/socket the restart command polls, cannot fire while
    // a registered interrupt waiter's park is still un-committed. A restart then
    // never reports success (or lets the successor bind) with an interrupt row
    // left `Open`.
    let shutdown_result = drain_daemon_context(&ctx, drain_grace).await;
    if let Err(error) = &shutdown_result {
        tracing::warn!(%error, "daemon shutdown was not clean");
    }

    // Cleanup on every path, but only while the pid file still names this
    // process. A restart replacement may have taken ownership of the shared
    // canonical paths before the old daemon finishes draining.
    let metadata_result = metadata_guard.cleanup();

    signal_task.abort();
    if let Some(task) = lifecycle_task {
        task.abort();
    }
    #[cfg(feature = "remote")]
    org_sync_task.abort();
    #[cfg(feature = "remote")]
    remote_audit_upload_task.abort();
    #[cfg(feature = "remote")]
    connector_task.abort();
    #[cfg(feature = "remote")]
    remote_outbox_task.abort();
    #[cfg(unix)]
    if let Some(task) = leak_reveal_task {
        task.abort();
    }
    #[cfg(unix)]
    let _ = std::fs::remove_file(paths.leak_reveal_socket());
    let mut failures = Vec::new();
    if let Err(error) = result {
        failures.push(format!("daemon accept loop: {error}"));
    }
    if let Err(error) = shutdown_result {
        failures.push(format!("daemon shutdown: {error}"));
    }
    if let Err(error) = metadata_result {
        failures.push(format!("daemon metadata cleanup: {error}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(failures.join("; "))
    }
}

#[cfg(not(unix))]
pub async fn run_foreground_inner(
    _paths: DaemonPaths,
    _drain_grace: Duration,
    _resume_all_sessions: bool,
    _terminal_factory: terminal::TerminalHostFactory,
) -> Result<()> {
    anyhow::bail!("daemon socket transport is not supported on this platform")
}

#[cfg(any(unix, test))]
async fn resume_all_paused_sessions(db: &crate::db::Db) -> Result<()> {
    for row in db.paused_session_work_all().await? {
        if let Err(e) = db.mark_paused_session_work_resumed(row.session_id).await {
            tracing::warn!(
                error = %e,
                session_id = %row.session_id,
                "resume-all failed to mark paused session resumed"
            );
        }
    }
    Ok(())
}

/// Wait for an ephemeral owner to acquire its first lifetime client and then
/// request teardown as soon as the reference count returns to zero. The gate
/// prevents a freshly spawned daemon from racing its creator's initial
/// handshake or a hello-only reachability probe.
#[cfg(any(unix, test))]
async fn ephemeral_last_client_reaper(
    mut presence: tokio::sync::watch::Receiver<server::ClientPresence>,
    mut try_reap: impl FnMut() -> server::EphemeralReapDecision,
) {
    loop {
        let observed = *presence.borrow_and_update();
        if observed.has_lifetime_client && observed.count == 0 {
            match try_reap() {
                server::EphemeralReapDecision::Shutdown => {
                    tracing::info!("ephemeral daemon lost its final client; beginning teardown");
                    return;
                }
                server::EphemeralReapDecision::Persistent => return,
                // A detach-time snapshot may race a worker becoming live after
                // the client receives its response. Never tear that work down;
                // wait for it to settle before completing ephemeral teardown.
                server::EphemeralReapDecision::WaitingForLiveWork => {
                    tokio::select! {
                        changed = presence.changed() => {
                            if changed.is_err() {
                                return;
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                    }
                    continue;
                }
            }
        }
        if presence.changed().await.is_err() {
            return;
        }
    }
}

/// Kill the running daemon (if any) and clean up its pid + socket files.
pub fn stop(paths: &DaemonPaths) -> Result<bool> {
    let Some(record) = read_daemon_pid_record(&paths.pid_file) else {
        return Ok(false);
    };
    #[cfg(target_os = "linux")]
    return stop_linux(paths, record);
    #[cfg(all(unix, not(target_os = "linux")))]
    return stop_unix_without_stable_handle(paths, record);
    #[cfg(not(unix))]
    {
        let _ = (paths, record);
        anyhow::bail!(
            "daemon lifecycle metadata exists but this platform has no stable process handle; preserving metadata and refusing numeric signaling"
        )
    }
}

pub(crate) fn stop_exact(paths: &DaemonPaths, expected: &DaemonPidReceipt) -> Result<bool> {
    let current = read_daemon_pid_record(&paths.pid_file);
    if current != Some(DaemonPidRecord::Receipt(expected.clone())) {
        anyhow::bail!(
            "daemon PID receipt changed; refusing to signal or clean a replacement incarnation"
        );
    }
    #[cfg(target_os = "linux")]
    return stop_linux(paths, DaemonPidRecord::Receipt(expected.clone()));
    #[cfg(all(unix, not(target_os = "linux")))]
    return stop_unix_without_stable_handle(paths, DaemonPidRecord::Receipt(expected.clone()));
    #[cfg(not(unix))]
    {
        let _ = (paths, expected);
        anyhow::bail!("exact daemon process teardown is unsupported on this platform")
    }
}

#[cfg(target_os = "linux")]
fn stop_linux(paths: &DaemonPaths, record: DaemonPidRecord) -> Result<bool> {
    let receipt = match record {
        DaemonPidRecord::LegacyNumeric(pid) => return settle_legacy_stop(paths, pid),
        DaemonPidRecord::Receipt(receipt) => receipt,
    };
    let process = match acquire_verified_daemon_process(&receipt) {
        VerifiedProcessOutcome::Verified(process) => process,
        VerifiedProcessOutcome::Identity(PidIdentity::Missing | PidIdentity::NotDaemon) => {
            cleanup_receipt_metadata(paths, &receipt)?;
            return Ok(false);
        }
        VerifiedProcessOutcome::Identity(PidIdentity::Unverified) => {
            anyhow::bail!("refusing to signal daemon: PID receipt could not be verified");
        }
        VerifiedProcessOutcome::Identity(PidIdentity::VerifiedDaemon) => unreachable!(),
    };
    if read_daemon_pid_record(&paths.pid_file) != Some(DaemonPidRecord::Receipt(receipt.clone())) {
        anyhow::bail!(
            "daemon PID receipt changed after stable process acquisition; refusing signal"
        );
    }
    if let Err(error) = process.send_sigterm() {
        if error.raw_os_error() == Some(libc::ESRCH) {
            cleanup_receipt_metadata(paths, &receipt)?;
            return Ok(true);
        }
        return Err(error).with_context(|| {
            format!(
                "signaling daemon PID {} through its stable pidfd",
                receipt.pid
            )
        });
    }
    let deadline = std::time::Instant::now() + restart_release_timeout(None);
    loop {
        if read_daemon_pid_record(&paths.pid_file)
            != Some(DaemonPidRecord::Receipt(receipt.clone()))
        {
            return Ok(true);
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(
            Duration::from_millis(100)
                .min(deadline.saturating_duration_since(std::time::Instant::now())),
        );
    }
    match process.is_alive() {
        Ok(false) => {}
        Ok(true) => anyhow::bail!(
            "timed out waiting for daemon PID {} to stop; preserving its receipt and socket metadata",
            receipt.pid
        ),
        Err(error) => anyhow::bail!(
            "could not prove daemon PID {} exited ({error}); preserving its receipt and socket metadata",
            receipt.pid
        ),
    }
    cleanup_receipt_metadata(paths, &receipt)?;
    Ok(true)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn stop_unix_without_stable_handle(paths: &DaemonPaths, record: DaemonPidRecord) -> Result<bool> {
    match record {
        DaemonPidRecord::LegacyNumeric(pid) => settle_legacy_stop(paths, pid),
        DaemonPidRecord::Receipt(receipt) => {
            match verify_cockpit_daemon_receipt_identity(&receipt) {
                PidIdentity::Missing | PidIdentity::NotDaemon => {
                    cleanup_receipt_metadata(paths, &receipt)?;
                    Ok(false)
                }
                PidIdentity::VerifiedDaemon | PidIdentity::Unverified => anyhow::bail!(
                    "daemon PID {} is live but this platform has no stable process handle; refusing numeric signaling",
                    receipt.pid
                ),
            }
        }
    }
}

#[cfg(unix)]
fn settle_legacy_stop(paths: &DaemonPaths, pid: u32) -> Result<bool> {
    match legacy_pid_identity(pid) {
        PidIdentity::Missing => {
            remove_dead_legacy_metadata(&paths.pid_file, &paths.socket, pid)?;
            Ok(false)
        }
        PidIdentity::VerifiedDaemon | PidIdentity::NotDaemon | PidIdentity::Unverified => {
            anyhow::bail!(
                "legacy numeric-only daemon PID {pid} is live; refusing unbound numeric signaling"
            )
        }
    }
}

#[cfg(unix)]
fn cleanup_receipt_metadata(paths: &DaemonPaths, receipt: &DaemonPidReceipt) -> Result<bool> {
    let endpoint = Some(endpoint_file_for_state(
        paths.pid_file.parent().context("PID file has no parent")?,
    ));
    retire_metadata_if_receipt_matches(&paths.pid_file, &paths.socket, endpoint.as_deref(), receipt)
}

#[cfg(all(test, unix))]
mod tests {
    use super::client::temp_ephemeral_paths;
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
        let hello = proto::Envelope::response(
            uuid::Uuid::nil(),
            proto::Response::DaemonStatus {
                pid: 1,
                uptime_secs: 0,
                active_sessions: 0,
                socket_path: "test.sock".to_string(),
                daemon_version: "test".to_string(),
                protocol_version: proto::PROTOCOL_VERSION,
                paused_sessions: 0,
                database_path: "test.db".to_string(),
                schema_version: crate::db::EXPECTED_SCHEMA_VERSION,
            },
        );
        spawn_hello_socket_with_line(socket, serde_json::to_string(&hello).unwrap())
    }

    #[cfg(unix)]
    fn spawn_hello_socket_with_line(socket: PathBuf, line: String) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind socket");
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::Write;
                let _ = writeln!(stream, "{line}");
            }
        })
    }

    #[cfg(unix)]
    fn wait_for_socket(socket: &Path) {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !socket.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "hello socket was not bound"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
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
            err.to_string().contains(TEST_OWNER_ENV)
                || err.to_string().contains("not a cockpit")
                || err.to_string().contains("unsupported on this platform"),
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
    fn endpoint_record_cannot_redirect_discovery_to_a_different_runtime_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_home = dir.path().join("state");
        let runtime_a = dir.path().join("rt-a");
        let runtime_b = dir.path().join("rt-b");
        std::fs::create_dir_all(runtime_a.join("cockpit")).expect("runtime a");

        let socket_a = runtime_a.join("cockpit/cockpit.sock");
        let paths = canonical_in(&state_home, &runtime_a);
        assert_eq!(paths.socket, socket_a);
        let receipt = write_pid_file(
            &paths.pid_file,
            std::process::id(),
            &std::env::current_exe().unwrap(),
        )
        .expect("pid receipt");
        write_endpoint_record_with_receipt_and_canonical(&paths, &paths, &receipt)
            .expect("endpoint record");

        let canonical_b = canonical_in(&state_home, &runtime_b);
        assert_ne!(canonical_b.socket, socket_a);

        let probe = discover_blocking_with_canonical(canonical_b);
        assert_eq!(probe.status, DaemonStatus::Stale);
        assert_eq!(probe.paths.socket, runtime_b.join("cockpit/cockpit.sock"));
    }

    #[cfg(unix)]
    #[test]
    fn incompatible_protocol_probe_reports_incompatible_status() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_home = dir.path().join("state");
        let runtime_dir = dir.path().join("runtime");
        let paths = canonical_in(&state_home, &runtime_dir);
        let hello = proto::Envelope::response_at(
            0,
            uuid::Uuid::nil(),
            proto::Response::DaemonStatus {
                pid: 1,
                uptime_secs: 1,
                active_sessions: 0,
                socket_path: paths.socket.display().to_string(),
                daemon_version: "0.0.old".to_string(),
                protocol_version: 0,
                paused_sessions: 0,
                database_path: ":memory:".to_string(),
                schema_version: crate::db::EXPECTED_SCHEMA_VERSION,
            },
        );
        let listener = spawn_hello_socket_with_line(
            paths.socket.clone(),
            serde_json::to_string(&hello).unwrap(),
        );
        wait_for_socket(&paths.socket);

        let probe = discover_blocking_with_canonical(paths);

        assert_eq!(probe.status, DaemonStatus::IncompatibleProtocol);
        assert_eq!(
            probe.hello,
            Some(proto::DaemonHello {
                daemon_version: "0.0.old".to_string(),
                protocol_version: 0,
            })
        );
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
    fn stale_endpoint_without_bound_receipt_is_preserved_without_signaling() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_home = dir.path().join("state");
        let runtime_dir = dir.path().join("runtime");
        let paths = canonical_in(&state_home, &runtime_dir);
        std::fs::write(&paths.pid_file, "999999999").expect("pid file");
        let record = DaemonEndpointRecord {
            version: 1,
            socket: runtime_dir.join("other/cockpit.sock"),
            receipt: test_pid_receipt(999999999),
            kind: DaemonEndpointKind::Persistent,
        };
        let endpoint = endpoint_file_for_state(paths.pid_file.parent().unwrap());
        std::fs::write(&endpoint, serde_json::to_vec(&record).unwrap()).expect("write endpoint");

        let probe = discover_blocking_with_canonical(paths);
        assert_eq!(probe.status, DaemonStatus::Stale);
        assert!(
            endpoint.exists(),
            "unbound endpoint cleanup must fail closed"
        );
    }

    #[test]
    fn endpoint_reader_rejects_executable_receipt_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_home = dir.path().join("state");
        let runtime_dir = dir.path().join("runtime");
        let paths = canonical_in(&state_home, &runtime_dir);
        let receipt = write_pid_file(
            &paths.pid_file,
            std::process::id(),
            &std::env::current_exe().unwrap(),
        )
        .expect("pid receipt");
        let endpoint = endpoint_file_for_state(paths.pid_file.parent().unwrap());
        let record = DaemonEndpointRecord {
            version: 1,
            socket: paths.socket.clone(),
            receipt: DaemonPidReceipt {
                executable: paths.pid_file.clone(),
                ..receipt
            },
            kind: DaemonEndpointKind::Persistent,
        };
        std::fs::write(&endpoint, serde_json::to_vec(&record).unwrap()).expect("endpoint");

        assert!(read_bound_endpoint_record_from(&endpoint, &paths).is_none());
    }

    #[test]
    fn ephemeral_paths_do_not_use_shared_endpoint_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_home = dir.path().join("state");
        let runtime_dir = dir.path().join("runtime");
        let eph = DaemonPaths::allocate_ephemeral_for_test_in(111, &state_home, Some(&runtime_dir))
            .expect("ephemeral");
        let canonical = canonical_in(&state_home, &runtime_dir);
        write_endpoint_record_with_receipt_and_canonical(
            &eph,
            &canonical,
            &test_pid_receipt(std::process::id()),
        )
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

        let err = write_endpoint_record_with_receipt_and_canonical(
            &noncanonical,
            &canonical,
            &test_pid_receipt(std::process::id()),
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
        let receipt = write_pid_file(
            &canonical.pid_file,
            std::process::id(),
            &std::env::current_exe().unwrap(),
        )
        .expect("canonical pid receipt");
        write_endpoint_record_with_receipt_and_canonical(&canonical, &canonical, &receipt)
            .expect("endpoint record");
        let endpoint = endpoint_file_for_state(canonical.pid_file.parent().unwrap());
        assert!(endpoint.exists());

        let noncanonical = DaemonPaths {
            pid_file: canonical.pid_file.with_file_name("other.pid"),
            socket: canonical.socket.clone(),
            ephemeral: false,
        };
        let receipt = write_pid_file(
            &noncanonical.pid_file,
            std::process::id(),
            &std::env::current_exe().unwrap(),
        )
        .expect("noncanonical pid file");
        let mut guard =
            ForegroundMetadataGuard::new(noncanonical.pid_file, noncanonical.socket, None, receipt);
        guard.cleanup().expect("guard cleanup");

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
        wait_for_socket(&socket_a);

        let paths_a = canonical_in(&state_home, &runtime_a);
        let receipt = write_pid_file(
            &paths_a.pid_file,
            std::process::id(),
            &std::env::current_exe().unwrap(),
        )
        .expect("canonical pid receipt");
        write_endpoint_record_with_receipt_and_canonical(&paths_a, &paths_a, &receipt)
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

    /// The leak-reveal socket path is a pure function of the control socket:
    /// same parent, `{control_stem}-leak-reveal.sock`. Independent literals are
    /// used for the expected values (no re-derivation via the fn under test).
    #[test]
    fn leak_reveal_socket_path_derivation() {
        let cases = [
            (
                "/run/user/1000/cockpit/cockpit.sock",
                "/run/user/1000/cockpit/cockpit-leak-reveal.sock",
            ),
            (
                "/home/u/.local/state/cockpit/daemon.sock",
                "/home/u/.local/state/cockpit/daemon-leak-reveal.sock",
            ),
            (
                "/run/user/1000/cockpit/cockpit-eph-1-aaa.sock",
                "/run/user/1000/cockpit/cockpit-eph-1-aaa-leak-reveal.sock",
            ),
        ];
        for (control, expected) in cases {
            assert_eq!(
                DaemonPaths::leak_reveal_socket_path(Path::new(control)),
                PathBuf::from(expected),
                "derivation for {control}"
            );
        }
        // A `DaemonPaths` value exposes the same derivation via the method.
        let paths = DaemonPaths {
            pid_file: PathBuf::from("/run/user/1000/cockpit/cockpit.pid"),
            socket: PathBuf::from("/run/user/1000/cockpit/cockpit.sock"),
            ephemeral: false,
        };
        assert_eq!(
            paths.leak_reveal_socket(),
            PathBuf::from("/run/user/1000/cockpit/cockpit-leak-reveal.sock")
        );
    }

    /// Two ephemeral daemons (distinct control stems) in one runtime dir get
    /// distinct reveal sockets that also differ from their control sockets, and
    /// both bind concurrently without collision.
    #[cfg(unix)]
    #[tokio::test]
    async fn leak_reveal_ephemeral_sockets_distinct() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = DaemonPaths::ephemeral_with_nonce_in(
            1,
            "aaa".to_owned(),
            &dir.path().join("state"),
            Some(&dir.path().join("runtime")),
        )
        .expect("ephemeral a");
        let b = DaemonPaths::ephemeral_with_nonce_in(
            2,
            "bbb".to_owned(),
            &dir.path().join("state"),
            Some(&dir.path().join("runtime")),
        )
        .expect("ephemeral b");
        let ra = a.leak_reveal_socket();
        let rb = b.leak_reveal_socket();
        assert_ne!(ra, rb, "distinct ephemeral reveal sockets");
        assert_ne!(ra, a.socket);
        assert_ne!(rb, b.socket);
        let la = bind_private_socket(&ra).expect("bind reveal a");
        let lb = bind_private_socket(&rb).expect("bind reveal b concurrently");
        assert_eq!(mode(&ra), 0o600);
        assert_eq!(mode(&rb), 0o600);
        drop(la);
        drop(lb);
    }

    #[tokio::test]
    async fn ephemeral_reaps_when_first_lifetime_client_disconnect_precedes_reaper() {
        let (presence_tx, presence_rx) =
            tokio::sync::watch::channel(server::ClientPresence::default());
        let reaped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let reaped_c = reaped.clone();
        let task = tokio::spawn(ephemeral_last_client_reaper(presence_rx, move || {
            reaped_c.store(true, std::sync::atomic::Ordering::SeqCst);
            server::EphemeralReapDecision::Shutdown
        }));
        presence_tx.send_modify(|presence| {
            presence.count = 1;
            presence.has_lifetime_client = true;
        });
        presence_tx.send_modify(|presence| presence.count = 0);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("the durable first-connection marker must survive a coalesced disconnect")
            .expect("reaper task joins");
        assert!(reaped.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn promoted_owner_does_not_reap_after_its_last_client_detaches() {
        let (presence_tx, presence_rx) =
            tokio::sync::watch::channel(server::ClientPresence::default());
        let ephemeral = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let reaped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ephemeral_for_reaper = ephemeral.clone();
        let reaped_for_reaper = reaped.clone();
        let task = tokio::spawn(ephemeral_last_client_reaper(presence_rx, move || {
            if !ephemeral_for_reaper.load(std::sync::atomic::Ordering::SeqCst) {
                return server::EphemeralReapDecision::Persistent;
            }
            reaped_for_reaper.store(true, std::sync::atomic::Ordering::SeqCst);
            server::EphemeralReapDecision::Shutdown
        }));

        presence_tx.send_modify(|presence| {
            presence.count = 1;
            presence.has_lifetime_client = true;
        });
        ephemeral.store(false, std::sync::atomic::Ordering::SeqCst);
        presence_tx.send_modify(|presence| presence.count = 0);
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(!reaped.load(std::sync::atomic::Ordering::SeqCst));
        task.abort();
    }

    #[tokio::test]
    async fn ephemeral_reaper_waits_for_live_work_that_races_last_detach() {
        let (presence_tx, presence_rx) =
            tokio::sync::watch::channel(server::ClientPresence::default());
        let live = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let reaped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reaper_live = live.clone();
        let reaper_reaped = reaped.clone();
        let task = tokio::spawn(ephemeral_last_client_reaper(presence_rx, move || {
            if reaper_live.load(std::sync::atomic::Ordering::Acquire) {
                return server::EphemeralReapDecision::WaitingForLiveWork;
            }
            reaper_reaped.store(true, std::sync::atomic::Ordering::Release);
            server::EphemeralReapDecision::Shutdown
        }));

        presence_tx.send_modify(|presence| {
            presence.count = 1;
            presence.has_lifetime_client = true;
        });
        presence_tx.send_modify(|presence| presence.count = 0);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !reaped.load(std::sync::atomic::Ordering::Acquire),
            "last-client teardown must not destroy daemon-owned live work"
        );

        live.store(false, std::sync::atomic::Ordering::Release);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("reaper retries after live work settles")
            .expect("reaper task joins");
        assert!(reaped.load(std::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test]
    async fn promotion_holds_the_last_client_reaper_decision_until_lifetime_changes() {
        let (presence_tx, presence_rx) =
            tokio::sync::watch::channel(server::ClientPresence::default());
        let decision = std::sync::Arc::new(std::sync::Mutex::new(()));
        let ephemeral = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let reaped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let reaper_decision = decision.clone();
        let reaper_ephemeral = ephemeral.clone();
        let reaper_reaped = reaped.clone();
        let task = tokio::spawn(ephemeral_last_client_reaper(presence_rx, move || {
            let _decision = crate::sync::lock_or_recover(&reaper_decision);
            if !reaper_ephemeral.load(std::sync::atomic::Ordering::Acquire) {
                return server::EphemeralReapDecision::Persistent;
            }
            reaper_reaped.store(true, std::sync::atomic::Ordering::Release);
            server::EphemeralReapDecision::Shutdown
        }));

        presence_tx.send_modify(|presence| {
            presence.count = 1;
            presence.has_lifetime_client = true;
        });

        let promotion_decision = decision.clone();
        let promotion_ephemeral = ephemeral.clone();
        let (held_tx, held_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let promotion = tokio::task::spawn_blocking(move || {
            let _decision = crate::sync::lock_or_recover(&promotion_decision);
            held_tx
                .send(())
                .expect("test waits for promotion decision lock");
            release_rx.recv().expect("test releases promotion");
            promotion_ephemeral.store(false, std::sync::atomic::Ordering::Release);
        });
        held_rx.await.expect("promotion holds decision lock");

        // The reaper sees zero clients before promotion has changed the
        // lifetime flag, but must wait for the shared decision lock.
        presence_tx.send_modify(|presence| presence.count = 0);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !reaped.load(std::sync::atomic::Ordering::Acquire),
            "the reaper must not decide while promotion owns the lifecycle gate"
        );

        release_tx.send(()).expect("release promotion");
        promotion.await.expect("promotion task joins");
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("reaper observes the promoted lifetime")
            .expect("reaper task joins");
        assert!(
            !reaped.load(std::sync::atomic::Ordering::Acquire),
            "a zero-client observation before promotion must not reap its persistent owner"
        );
    }

    #[tokio::test]
    async fn ephemeral_socket_owner_reaps_after_connected_client_drops_before_request() {
        let harness = DaemonTestHarness::new();
        let _env =
            crate::test_env::TestEnvGuard::isolate_cockpit_home_at_async(&harness.state_home).await;
        let paths = harness.ephemeral_paths("detached-rpc-client");
        let daemon_paths = paths.clone();
        let daemon_db = harness.db.clone();
        let daemon_task = tokio::spawn(async move {
            run_foreground_inner_with_boot_db(
                daemon_paths,
                Duration::from_millis(300),
                false,
                crate::daemon::terminal::test_host_factory(),
                Some(daemon_db),
            )
            .await
        });
        wait_until(|| paths.socket.exists(), Duration::from_secs(2)).await;

        let client = cockpit_client::DaemonClient::connect(&paths.socket)
            .await
            .expect("connect detached socket client");
        drop(client);

        tokio::time::timeout(Duration::from_secs(3), daemon_task)
            .await
            .expect(
                "connected client drop before an application request must reap the ephemeral owner",
            )
            .expect("daemon task joins")
            .expect("daemon drain completes after detached client disconnect");
        assert!(!paths.socket.exists(), "last client removes the socket");
        assert!(
            !paths.pid_file.exists(),
            "last client removes the pid record"
        );
    }

    #[tokio::test]
    async fn ephemeral_socket_owner_waits_for_its_last_connected_client() {
        let harness = DaemonTestHarness::new();
        let _env =
            crate::test_env::TestEnvGuard::isolate_cockpit_home_at_async(&harness.state_home).await;
        let project = tempfile::tempdir().expect("project directory");
        harness
            .db
            .set_workspace_trust(
                project.path(),
                crate::db::workspace_trust::WorkspaceTrustMode::Trust,
            )
            .await
            .expect("trust project");

        let paths = harness.ephemeral_paths("two-socket-clients");
        let daemon_paths = paths.clone();
        let daemon_db = harness.db.clone();
        let daemon_task = tokio::spawn(async move {
            run_foreground_inner_with_boot_db(
                daemon_paths,
                Duration::from_millis(300),
                false,
                crate::daemon::terminal::test_host_factory(),
                Some(daemon_db),
            )
            .await
        });
        wait_until(|| paths.socket.exists(), Duration::from_secs(2)).await;

        let client_a = cockpit_client::DaemonClient::connect(&paths.socket)
            .await
            .expect("connect first socket client");
        let first = client_a
            .request_ok(proto::Request::Attach {
                session_id: None,
                since_seq: None,
                project_root: Some(project.path().to_string_lossy().into_owned()),
                initial_model: None,
                no_sandbox: false,
                interactive: true,
                session_entry_mode: proto::NonCodeSessionEntryMode::Assistant,
                model_override: None,
                client_protocol_version: proto::PROTOCOL_VERSION,
                env_snapshot: None,
                env_policy: crate::env_snapshot::EnvDriftPolicy::Daemon,
            })
            .await
            .expect("first socket client attaches");
        let proto::Response::Attached { session_id, .. } = first else {
            panic!("first socket client must receive Attached");
        };

        let client_b = cockpit_client::DaemonClient::connect(&paths.socket)
            .await
            .expect("connect second socket client");
        // The completed connection confirmation must retain the owner before
        // B sends any application request; otherwise this A -> B handoff can
        // race the ephemeral reaper into draining at count zero.
        drop(client_a);
        client_b
            .request_ok(proto::Request::Attach {
                session_id: Some(session_id),
                since_seq: None,
                project_root: None,
                initial_model: None,
                no_sandbox: false,
                interactive: true,
                session_entry_mode: proto::NonCodeSessionEntryMode::Assistant,
                model_override: None,
                client_protocol_version: proto::PROTOCOL_VERSION,
                env_snapshot: None,
                env_policy: crate::env_snapshot::EnvDriftPolicy::Daemon,
            })
            .await
            .expect("second socket client attaches");

        client_b
            .request_ok(proto::Request::DaemonStatus)
            .await
            .expect("second attached socket client retains the owner");
        assert!(
            paths.socket.exists(),
            "owner remains published for client B"
        );

        drop(client_b);
        tokio::time::timeout(Duration::from_secs(3), daemon_task)
            .await
            .expect("last socket client must drain and reap the ephemeral owner")
            .expect("daemon task joins")
            .expect("daemon drain cancels attached session work cleanly");
        assert!(!paths.socket.exists(), "last client removes the socket");
        assert!(
            !paths.pid_file.exists(),
            "last client removes the pid record"
        );
    }

    /// A persisted session must not, by itself, keep an ephemeral daemon alive
    /// after an explicit stop. We stand up a real ephemeral
    /// daemon, write a persisted `sessions` row into the very DB the daemon
    /// opened (the exact effect the first user message has via
    /// `persist_if_needed`), then trigger an explicit `StopDaemon`. The daemon
    /// must drain and reap — removing its socket + pid — within the grace.
    #[tokio::test]
    async fn owned_ephemeral_reaps_on_stop_even_with_persisted_session() {
        use crate::daemon::ephemeral_guard::stop_daemon_blocking;
        use crate::session::Session;

        let harness = DaemonTestHarness::new();
        let _env =
            crate::test_env::TestEnvGuard::isolate_cockpit_home_at_async(&harness.state_home).await;
        let drain_grace = Duration::from_millis(300);

        let eph = harness.ephemeral_paths("eph-with-session");
        let eph_clone = eph.clone();
        let daemon_db = harness.db.clone();
        let eph_task = tokio::spawn(async move {
            run_foreground_inner_with_boot_db(
                eph_clone,
                drain_grace,
                false,
                crate::daemon::terminal::test_host_factory(),
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
            let session = Session::create_for_test(
                harness.db.clone(),
                std::env::temp_dir(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .expect("persist a session row");
            assert!(session.is_persisted(), "row is persisted");
        }

        // Explicit administrative stop. Run it off the runtime thread because
        // this helper uses a blocking Unix socket.
        let socket = eph.socket.clone();
        tokio::task::spawn_blocking(move || stop_daemon_blocking(&socket))
            .await
            .unwrap();

        // The daemon must drain and exit — despite the persisted session.
        let reaped = tokio::time::timeout(Duration::from_secs(3), eph_task)
            .await
            .expect("ephemeral daemon did not reap on StopDaemon with a persisted session");
        reaped.expect("join").expect("run_foreground_inner ok");
        assert!(
            !eph.socket.exists(),
            "ephemeral socket removed on explicit teardown"
        );
        assert!(
            !eph.pid_file.exists(),
            "ephemeral pid removed on explicit teardown"
        );
    }

    #[cfg(unix)]
    fn test_paths(dir: &tempfile::TempDir) -> DaemonPaths {
        DaemonPaths {
            socket: dir.path().join("daemon.sock"),
            pid_file: dir.path().join("daemon.pid"),
            ephemeral: false,
        }
    }

    fn test_pid_receipt(pid: u32) -> DaemonPidReceipt {
        DaemonPidReceipt {
            pid,
            executable: std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
            process_start: cockpit_host::daemon_lifecycle::ProcessStartIdentity {
                primary: 0,
                secondary: 0,
            },
            publication_nonce: [0; 32],
        }
    }

    #[cfg(unix)]
    #[test]
    fn live_legacy_numeric_pid_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(&dir);
        std::fs::write(&paths.pid_file, std::process::id().to_string()).unwrap();

        let error = settle_legacy_stop(&paths, std::process::id()).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("refusing unbound numeric signaling")
        );
        assert!(paths.pid_file.exists());
    }

    #[cfg(unix)]
    #[test]
    fn receipt_cleanup_rejects_replaced_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(&dir);
        let executable = std::env::current_exe().unwrap();
        let old = write_pid_file(&paths.pid_file, std::process::id(), &executable).unwrap();
        cleanup_receipt_metadata(&paths, &old).unwrap();
        let replacement = write_pid_file(&paths.pid_file, std::process::id(), &executable).unwrap();
        std::fs::write(&paths.socket, "replacement socket").unwrap();

        cleanup_receipt_metadata(&paths, &old).unwrap();

        assert_eq!(
            read_daemon_pid_record(&paths.pid_file),
            Some(DaemonPidRecord::Receipt(replacement))
        );
        assert_eq!(
            std::fs::read_to_string(&paths.socket).unwrap(),
            "replacement socket"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unreachable_unverified_pid_is_not_reported_stale() {
        let status = status_for_pid_identity(PidIdentity::Unverified);

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
            shutdown::SHUTDOWN_DRAIN_GRACE + RESTART_RELEASE_CLEANUP_GRACE
        );
        assert_eq!(
            restart_release_timeout(Some(0)),
            RESTART_RELEASE_CLEANUP_GRACE
        );
        assert_eq!(
            restart_release_timeout(Some(7)),
            Duration::from_secs(7) + RESTART_RELEASE_CLEANUP_GRACE
        );
    }

    #[tokio::test]
    async fn restart_release_wait_preserves_live_metadata_after_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(&dir);
        std::fs::write(&paths.pid_file, "123").unwrap();
        std::fs::write(&paths.socket, "").unwrap();

        wait_for_restart_release(&paths, Some(123), Duration::ZERO).await;

        assert!(paths.pid_file.exists());
        assert!(paths.socket.exists());
    }

    #[cfg(unix)]
    #[test]
    fn restart_release_waits_for_old_pid_exit_not_just_unlinked_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_paths(&dir);
        assert!(
            !restart_metadata_released(&paths, Some(std::process::id())),
            "a still-live predecessor must block replacement spawn even after pid/socket unlink"
        );
        assert!(restart_metadata_released(&paths, None));
    }

    #[cfg(unix)]
    #[test]
    fn cmdline_identity_requires_cockpit_daemon_start() {
        assert!(argv_requests_daemon_start(&[
            "/usr/bin/cockpit".into(),
            "daemon".into(),
            "start".into(),
            "--foreground".into(),
        ]));
        assert!(!argv_requests_daemon_start(&[
            "/usr/bin/sleep".into(),
            "daemon".into(),
            "start".into(),
        ]));
        assert!(!argv_requests_daemon_start(&[
            "/usr/bin/cockpit".into(),
            "session".into(),
            "list".into(),
        ]));
    }

    #[cfg(target_os = "macos")]
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

    #[cfg(target_os = "macos")]
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
        assert!(argv_requests_daemon_start(&args));
    }

    #[cfg(target_os = "macos")]
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
        assert!(!argv_requests_daemon_start(&args));
    }

    #[cfg(unix)]
    #[test]
    fn proc_cmdline_split_drops_empty_segments() {
        assert_eq!(
            split_proc_cmdline(b"/bin/cockpit\0daemon\0start\0\0"),
            vec!["/bin/cockpit", "daemon", "start"]
        );
    }

    #[tokio::test]
    async fn in_process_owner_drop_begins_drain_and_releases_context() {
        let root = tempfile::tempdir().expect("daemon owner tempdir");
        let paths = temp_ephemeral_paths(root.path(), "in-process-owner-drop");
        let db = crate::db::Db::open_in_memory().expect("in-memory daemon db");
        let ctx = boot_in_process_with_db(paths.clone(), db)
            .await
            .expect("in-process daemon context");
        let shutdown = ctx.shutdown_signal().clone();
        let guard =
            spawn_in_process_shutdown_supervisor(ctx, Vec::new()).expect("shutdown supervisor");
        drop(guard);
        wait_until(|| shutdown.is_draining(), Duration::from_secs(1)).await;
        wait_until(
            || server::in_process_context(&paths.socket).is_none(),
            Duration::from_secs(1),
        )
        .await;
    }

    #[tokio::test]
    async fn cancelled_in_process_shutdown_waiter_does_not_cancel_cleanup() {
        let root = tempfile::tempdir().expect("daemon owner tempdir");
        let paths = temp_ephemeral_paths(root.path(), "in-process-owner-cancel");
        let db = crate::db::Db::open_in_memory().expect("in-memory daemon db");
        let ctx = boot_in_process_with_db(paths.clone(), db)
            .await
            .expect("in-process daemon context");
        let shutdown = ctx.shutdown_signal().clone();
        let guard =
            spawn_in_process_shutdown_supervisor(ctx, Vec::new()).expect("shutdown supervisor");
        let waiter = tokio::spawn(guard.shutdown());
        wait_until(|| shutdown.is_draining(), Duration::from_secs(1)).await;
        waiter.abort();
        let _ = waiter.await;
        wait_until(
            || server::in_process_context(&paths.socket).is_none(),
            Duration::from_secs(1),
        )
        .await;
    }

    #[test]
    fn in_process_shutdown_supervisor_outlives_originating_runtime() {
        let root = tempfile::tempdir().expect("daemon owner tempdir");
        let paths = temp_ephemeral_paths(root.path(), "in-process-owner-runtime-drop");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("originating runtime");
        let db = crate::db::Db::open_in_memory().expect("in-memory daemon db");
        let (ctx, guard) = runtime.block_on(async {
            let ctx = boot_in_process_with_db(paths.clone(), db)
                .await
                .expect("in-process daemon context");
            let guard = spawn_in_process_shutdown_supervisor(ctx.clone(), Vec::new())
                .expect("shutdown supervisor");
            (ctx, guard)
        });
        drop(ctx);
        drop(runtime);

        let completion_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("completion runtime");
        completion_runtime
            .block_on(guard.shutdown())
            .expect("runtime-independent shutdown");
        assert!(server::in_process_context(&paths.socket).is_none());
    }

    #[test]
    fn supervisor_reaper_unavailable_joins_retained_handle() {
        let completed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let completed_on_thread = completed.clone();
        let supervisor = std::thread::spawn(move || {
            completed_on_thread.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        submit_supervisor_reap(
            None,
            SupervisorReap {
                supervisor,
                completed: None,
            },
        );
        assert!(completed.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn disconnected_supervisor_reaper_recovers_and_joins_handle() {
        let (send, receive) = std::sync::mpsc::channel();
        drop(receive);
        let completed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let completed_on_thread = completed.clone();
        let supervisor = std::thread::spawn(move || {
            completed_on_thread.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        submit_supervisor_reap(
            Some(&send),
            SupervisorReap {
                supervisor,
                completed: None,
            },
        );
        assert!(completed.load(std::sync::atomic::Ordering::SeqCst));
    }

    async fn wait_until(mut cond: impl FnMut() -> bool, timeout: Duration) {
        let deadline = std::time::Instant::now() + timeout;
        while !cond() {
            if std::time::Instant::now() >= deadline {
                panic!("condition not met within {timeout:?}");
            }
            // Yield instead of sleeping so paused Tokio time cannot stall
            // the poll loop, and so sibling tasks (boot, drain) keep running.
            tokio::task::yield_now().await;
        }
    }
}

#[cfg(all(test, not(unix)))]
mod non_unix_tests {
    use super::*;

    #[test]
    fn daemon_discovery_reports_no_daemon_without_socket_transport() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = DaemonPaths {
            socket: dir.path().join("daemon.sock"),
            pid_file: dir.path().join("daemon.pid"),
            ephemeral: false,
        };

        let probe = discover_blocking_with_canonical(paths);

        assert_eq!(probe.status, DaemonStatus::NotRunning);
        assert!(probe.hello.is_none());
    }
}
