//! Stable local-daemon wrapper and its deliberately small admin boundary.
//!
//! The supervisor owns only process lifecycle, endpoint publication, the
//! inherited start clock, and the versioned `sup.ctl` protocol. It may depend
//! on `cockpit-host`, `cockpit-client`'s restart guard, and this module's socket
//! helpers. It must never import engine, provider, session-worker, registry, or
//! database implementation code; those remain worker-owned.
//!
//! Admin protocol version 1 is same-user trusted (see
//! `docs/security/same-user-boundary.md`) and is intentionally not part of the
//! public NDJSON protocol.

use std::path::{Path, PathBuf};
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, AtomicU8, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use super::{DaemonListener, DaemonPaths, DaemonStream};

pub const ADMIN_PROTOCOL_VERSION: u32 = 1;
const WORKER_ENV: &str = "COCKPIT_SUPERVISED_WORKER";
const GENERATION_ENV: &str = "COCKPIT_WORKER_GENERATION";
const OPENED_AT_ENV: &str = "COCKPIT_SUPERVISOR_OPENED_AT_UNIX_MS";
const SUPERVISOR_PID_ENV: &str = "COCKPIT_SUPERVISOR_PID";
#[cfg(windows)]
const WINDOWS_IDENTITY_ENV: &str = "COCKPIT_WORKER_IDENTITY_PATH";
#[cfg(windows)]
const WINDOWS_REVEAL_IDENTITY_ENV: &str = "COCKPIT_WORKER_REVEAL_IDENTITY_PATH";
#[cfg(unix)]
const REEXEC_STATE_ENV: &str = "COCKPIT_SUPERVISOR_REEXEC_STATE";
#[cfg(windows)]
const REEXEC_STATE_ENV: &str = "COCKPIT_SUPERVISOR_REEXEC_STATE";
#[cfg(unix)]
const READY_FD: libc::c_int = 4;
#[cfg(unix)]
const CONTROL_FD: libc::c_int = 3;
#[cfg(unix)]
const REVEAL_FD: libc::c_int = 5;
#[cfg(unix)]
const PROMOTION_FD: libc::c_int = 6;
#[cfg(unix)]
const HANDOVER_STANDBY_ENV: &str = "COCKPIT_WORKER_HANDOVER_STANDBY";
/// Read end of the supervisor-liveness pipe. The supervisor retains the only
/// write end for its whole lifetime (including across an in-place `reexec`);
/// the kernel closes it when the supervisor dies for any reason, SIGKILL
/// included, and the worker observes EOF here. Portable across Unix, and
/// unlike `PR_SET_PDEATHSIG` it is tied to the supervisor process rather than
/// to the (short-lived, blocking-pool) thread that happened to fork the worker.
#[cfg(unix)]
const LIVENESS_FD: libc::c_int = 7;
#[cfg(unix)]
const SUPERVISOR_LIVENESS_ENV: &str = "COCKPIT_SUPERVISOR_LIVENESS";
/// Exit status of a worker that outlived its supervisor. The worker exits
/// without a graceful park: a lost supervisor is a daemon crash, and durable
/// crash recovery (#441) in the next generation owns reconciliation.
#[cfg(unix)]
const SUPERVISOR_LOST_EXIT: libc::c_int = 70;
// Boundary reports carry one compact `(session, marker)` pair per active
// session. Keep the same-user admin protocol bounded while leaving room for a
// large live-session set.
const MAX_ADMIN_LINE: usize = 512 * 1024;
// `T_drain` and `T_hard` are worker-owned execution budgets. Once both have
// elapsed, the predecessor still needs a short, local admin RPC to announce
// its durable marker; do not race that acknowledgement against the work
// budget itself.
const HANDOVER_BOUNDARY_ANNOUNCE_SLACK: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy)]
pub(crate) struct WorkerHandoverRequest {
    pub generation: u64,
    pub timers: crate::config::config::extended::HandoverTimersConfig,
}

static WORKER_HANDOVER: OnceLock<std::sync::Mutex<Option<WorkerHandoverRequest>>> = OnceLock::new();
static WORKER_HANDOVER_ACTIVE: AtomicBool = AtomicBool::new(false);
// The hard-deadline cancellation phase is narrower than ordinary handover
// draining. A tool that naturally reaches its boundary during `T_drain` is a
// predecessor completion; a tool observing this flag has been cancelled and
// must leave its result uncommitted for the handover interruption record.
static WORKER_HANDOVER_HARD_INTERRUPT: AtomicBool = AtomicBool::new(false);
// The predecessor closes admission before it redirects clients.  Its accept
// loop waits for this edge before closing the established streams, so every
// attached client gets one bounded opportunity to receive `Reconnect`.
static WORKER_HANDOVER_RECONNECT_DISPATCHED: AtomicBool = AtomicBool::new(false);
// The predecessor must not redirect clients until the supervisor has a
// health-checked successor.  A signal is used here because this is strictly
// worker-local control; the public/admin protocol remains supervisor-owned.
static WORKER_HANDOVER_DECISION: AtomicU8 = AtomicU8::new(0);
static WORKER_HANDOVER_DECISION_NOTIFY: OnceLock<tokio::sync::Notify> = OnceLock::new();

pub(crate) fn begin_worker_handover(generation: u64) -> Result<()> {
    let timers = crate::config::config::extended::load_installation_handover_timers()
        .context("loading worker handover timers")?;
    if WORKER_HANDOVER_ACTIVE.swap(true, Ordering::AcqRel) {
        bail!("worker handover is already in progress");
    }
    WORKER_HANDOVER_DECISION.store(0, Ordering::Release);
    WORKER_HANDOVER_HARD_INTERRUPT.store(false, Ordering::Release);
    WORKER_HANDOVER_RECONNECT_DISPATCHED.store(false, Ordering::Release);
    let slot = WORKER_HANDOVER.get_or_init(|| std::sync::Mutex::new(None));
    *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
        Some(WorkerHandoverRequest { generation, timers });
    Ok(())
}

/// Whether this worker is draining a committed-or-pending handover.
pub(crate) fn worker_handover_active() -> bool {
    WORKER_HANDOVER_ACTIVE.load(Ordering::Acquire)
}

pub(crate) fn begin_worker_handover_hard_interrupt() {
    if worker_handover_active() {
        WORKER_HANDOVER_HARD_INTERRUPT.store(true, Ordering::Release);
    }
}

/// Whether an in-flight tool was cancelled because `T_hard` elapsed.
pub(crate) fn worker_handover_hard_interrupting() -> bool {
    WORKER_HANDOVER_HARD_INTERRUPT.load(Ordering::Acquire)
}

pub(crate) fn worker_handover_aborted() -> bool {
    WORKER_HANDOVER_DECISION.load(Ordering::Acquire) == 2
}

pub(crate) fn worker_handover_committed() -> bool {
    WORKER_HANDOVER_DECISION.load(Ordering::Acquire) == 1
}

pub(crate) fn worker_handover_reconnect_dispatched() {
    WORKER_HANDOVER_RECONNECT_DISPATCHED.store(true, Ordering::Release);
    WORKER_HANDOVER_DECISION_NOTIFY
        .get_or_init(tokio::sync::Notify::new)
        .notify_waiters();
}

/// Wait until a draining predecessor has either dispatched `Reconnect` or
/// been aborted.  The accept loop uses this to close established streams only
/// after the redirect has had its bounded flush interval.
pub(crate) async fn wait_for_worker_handover_reconnect_dispatch() -> bool {
    let notify = WORKER_HANDOVER_DECISION_NOTIFY.get_or_init(tokio::sync::Notify::new);
    loop {
        let notified = notify.notified();
        if WORKER_HANDOVER_RECONNECT_DISPATCHED.load(Ordering::Acquire) {
            return true;
        }
        if !worker_handover_active() {
            return false;
        }
        notified.await;
    }
}

pub(crate) fn abort_worker_handover() {
    WORKER_HANDOVER_DECISION.store(2, Ordering::Release);
    WORKER_HANDOVER_ACTIVE.store(false, Ordering::Release);
    WORKER_HANDOVER_HARD_INTERRUPT.store(false, Ordering::Release);
    if let Some(slot) = WORKER_HANDOVER.get() {
        *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
    WORKER_HANDOVER_DECISION_NOTIFY
        .get_or_init(tokio::sync::Notify::new)
        .notify_waiters();
}

/// Retire a committed predecessor which cannot dispatch `Reconnect`.
///
/// This is deliberately distinct from [`abort_worker_handover`]: after a
/// commit, the predecessor may already have cancelled live work and therefore
/// must not resume admission.  It only releases local waiters while ordinary
/// daemon shutdown retires the process.
pub(crate) fn retire_worker_handover() {
    WORKER_HANDOVER_ACTIVE.store(false, Ordering::Release);
    WORKER_HANDOVER_HARD_INTERRUPT.store(false, Ordering::Release);
    if let Some(slot) = WORKER_HANDOVER.get() {
        *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
    WORKER_HANDOVER_DECISION_NOTIFY
        .get_or_init(tokio::sync::Notify::new)
        .notify_waiters();
}

pub(crate) fn commit_worker_handover() {
    if worker_handover_active() {
        WORKER_HANDOVER_DECISION.store(1, Ordering::Release);
        WORKER_HANDOVER_DECISION_NOTIFY
            .get_or_init(tokio::sync::Notify::new)
            .notify_waiters();
    }
}

pub(crate) async fn wait_for_worker_handover_decision() -> Result<()> {
    let notify = WORKER_HANDOVER_DECISION_NOTIFY.get_or_init(tokio::sync::Notify::new);
    loop {
        let notified = notify.notified();
        match WORKER_HANDOVER_DECISION.load(Ordering::Acquire) {
            1 => return Ok(()),
            2 => bail!("worker handover was aborted before commit"),
            _ => notified.await,
        }
    }
}

/// Cooperatively cancel preparation when the supervisor aborts a staged roll.
/// A pending or committed decision is not an abort: preparation still owns the
/// boundary until it has announced it.
pub(crate) async fn wait_for_worker_handover_abort() -> Result<()> {
    let notify = WORKER_HANDOVER_DECISION_NOTIFY.get_or_init(tokio::sync::Notify::new);
    loop {
        let notified = notify.notified();
        if worker_handover_aborted() {
            bail!("worker handover was aborted before boundary completion");
        }
        notified.await;
    }
}

pub(crate) fn take_worker_handover() -> Option<WorkerHandoverRequest> {
    WORKER_HANDOVER.get().and_then(|slot| {
        slot.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    })
}

pub(crate) async fn announce_worker_boundary(
    paths: &DaemonPaths,
    generation: u64,
    last_boundary: Vec<super::proto::SessionBoundaryMarker>,
) -> Result<()> {
    let response = request(
        paths,
        AdminCommand::WorkerBoundary {
            worker_pid: std::process::id(),
            generation,
            last_boundary,
        },
    )
    .await?;
    match response {
        AdminResponse::Status { .. } => Ok(()),
        AdminResponse::Error { message, .. } => bail!(message),
        other => bail!("unexpected worker boundary acknowledgement: {other:?}"),
    }
}

/// Tell the supervisor that ordinary draining has ended and that the
/// predecessor is about to enter its hard-deadline phase.  This is deliberately
/// separate from the final boundary report: the supervisor must commit the
/// staged successor before the predecessor is allowed to cancel live work.
pub(crate) async fn announce_worker_handover_ready(
    paths: &DaemonPaths,
    generation: u64,
) -> Result<()> {
    let response = request(
        paths,
        AdminCommand::WorkerHandoverReady {
            worker_pid: std::process::id(),
            generation,
        },
    )
    .await?;
    match response {
        AdminResponse::Status { .. } => Ok(()),
        AdminResponse::Error { message, .. } => bail!(message),
        other => bail!("unexpected worker handover-ready acknowledgement: {other:?}"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum AdminCommand {
    Status,
    Roll,
    Upgrade {
        binary: PathBuf,
    },
    Stop,
    Reexec,
    /// Worker-internal acknowledgement that `T_drain` elapsed. The
    /// supervisor may now commit the staged successor, allowing the worker to
    /// use its `T_hard` cancellation path before it reports the final durable
    /// boundary.
    WorkerHandoverReady {
        worker_pid: u32,
        generation: u64,
    },
    /// Worker-internal report emitted after the predecessor has closed new
    /// turn admission and captured its durable per-session boundaries.
    WorkerBoundary {
        worker_pid: u32,
        generation: u64,
        last_boundary: Vec<super::proto::SessionBoundaryMarker>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminRequest {
    pub version: u32,
    #[serde(flatten)]
    pub command: AdminCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum AdminResponse {
    Status {
        version: u32,
        supervisor_pid: u32,
        worker_pid: u32,
        generation: u64,
        uptime_ms: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_handover: Option<String>,
    },
    Rolled {
        version: u32,
        old_worker_pid: u32,
        worker_pid: u32,
        generation: u64,
        uptime_ms: u64,
    },
    Stopping {
        version: u32,
    },
    Reexecing {
        version: u32,
    },
    Error {
        version: u32,
        message: String,
    },
}

#[cfg(unix)]
#[derive(Clone, Serialize, Deserialize)]
struct ReexecState {
    database_lock_fd: std::os::fd::RawFd,
    lifetime_fd: std::os::fd::RawFd,
    pid_lock_fd: std::os::fd::RawFd,
    control_fd: std::os::fd::RawFd,
    reveal_fd: std::os::fd::RawFd,
    admin_fd: std::os::fd::RawFd,
    /// Supervisor-liveness pipe `(read, write)`. Absent when reexecuted from a
    /// supervisor that predates the liveness pipe; the resumed supervisor then
    /// creates a fresh one for the workers it spawns.
    #[serde(default)]
    liveness_fds: Option<(std::os::fd::RawFd, std::os::fd::RawFd)>,
    worker_pid: u32,
    worker_binary: PathBuf,
    generation: u64,
    /// Highest worker generation the pre-reexec supervisor attempted
    /// (including burned, never-ready attempts). Absent from an older
    /// supervisor's state; the durable fence and `generation` then bound it.
    #[serde(default)]
    highest_attempted_generation: u64,
    opened_at_unix_ms: u64,
}

#[cfg(windows)]
#[derive(Clone, Serialize, Deserialize)]
struct ReexecState {
    worker_pid: u32,
    worker_binary: PathBuf,
    generation: u64,
    /// Highest worker generation the pre-reexec supervisor attempted
    /// (including burned, never-ready attempts). Absent from an older
    /// supervisor's state; the durable fence and `generation` then bound it.
    #[serde(default)]
    highest_attempted_generation: u64,
    opened_at_unix_ms: u64,
}

#[cfg(any(unix, windows))]
static EARLY_REEXEC_STATE: OnceLock<ReexecState> = OnceLock::new();
#[cfg(any(unix, windows))]
static EARLY_WORKER_PROCESS: OnceLock<bool> = OnceLock::new();
/// The inherited supervisor-liveness read end, captured at process entry and
/// consumed once by [`watch_supervisor_liveness`].
#[cfg(unix)]
static EARLY_SUPERVISOR_LIVENESS_FD: std::sync::atomic::AtomicI32 =
    std::sync::atomic::AtomicI32::new(-1);

pub fn is_worker_process() -> bool {
    #[cfg(any(unix, windows))]
    if EARLY_WORKER_PROCESS.get().copied().unwrap_or(false) {
        return true;
    }
    #[cfg(unix)]
    return std::env::var_os(WORKER_ENV).is_some();
    #[cfg(windows)]
    return std::env::var_os(WORKER_ENV).is_some()
        && std::env::var_os(WINDOWS_IDENTITY_ENV).is_some()
        && std::env::var_os(WINDOWS_REVEAL_IDENTITY_ENV).is_some();
    #[cfg(not(any(unix, windows)))]
    false
}

pub fn worker_generation() -> u64 {
    std::env::var(GENERATION_ENV)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

/// Seal supervisor/worker activation state before the process creates a
/// runtime or any helper process. `Command::pre_exec` cannot update the envp
/// Rust has already prepared for exec, so a worker publishes its own exact PID
/// here. A reexecuted supervisor similarly restores close-on-exec before the
/// CLI starts its protected process spawner.
pub fn prepare_process_entry_environment() -> Result<()> {
    #[cfg(any(unix, windows))]
    let worker_process = is_worker_process();
    #[cfg(any(unix, windows))]
    if worker_process {
        EARLY_WORKER_PROCESS
            .set(true)
            .map_err(|_| anyhow::anyhow!("worker process role was prepared twice"))?;
        // The entry hook is the single role-capture point. Do not make a
        // Cockpit helper subprocess mistake itself for the daemon worker.
        // SAFETY: this hook runs before the runtime or helper threads.
        unsafe { std::env::remove_var(WORKER_ENV) };
    }
    #[cfg(unix)]
    {
        let listen_pid = std::env::var("LISTEN_PID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok());
        if worker_process
            && std::env::var("LISTEN_FDS").as_deref() == Ok("1")
            && listen_pid.is_none_or(|pid| pid == std::process::id())
        {
            // SAFETY: the CLI and spawn harness call this at the top of their
            // synchronous entry point, before constructing a runtime or threads.
            unsafe { std::env::set_var("LISTEN_PID", std::process::id().to_string()) };
            set_close_on_exec(CONTROL_FD)?;
            set_close_on_exec(READY_FD)?;
            set_close_on_exec(REVEAL_FD)?;
        }
        if std::env::var_os(SUPERVISOR_LIVENESS_ENV).is_some() {
            if worker_process {
                set_close_on_exec(LIVENESS_FD)?;
                EARLY_SUPERVISOR_LIVENESS_FD
                    .store(LIVENESS_FD, std::sync::atomic::Ordering::SeqCst);
            }
            // SAFETY: this entry hook runs before the runtime or helper threads.
            unsafe { std::env::remove_var(SUPERVISOR_LIVENESS_ENV) };
        }
        if let Some(raw) = std::env::var_os(REEXEC_STATE_ENV) {
            let state: ReexecState = serde_json::from_str(&raw.to_string_lossy())
                .context("decoding early supervisor reexec state")?;
            for fd in [
                state.database_lock_fd,
                state.lifetime_fd,
                state.pid_lock_fd,
                state.control_fd,
                state.reveal_fd,
                state.admin_fd,
            ]
            .into_iter()
            .chain(
                state
                    .liveness_fds
                    .into_iter()
                    .flat_map(|(read, write)| [read, write]),
            ) {
                set_close_on_exec(fd)?;
            }
            EARLY_REEXEC_STATE
                .set(state)
                .map_err(|_| anyhow::anyhow!("supervisor reexec state was prepared twice"))?;
            // SAFETY: this entry hook runs before the runtime or helper threads.
            unsafe { std::env::remove_var(REEXEC_STATE_ENV) };
        }
    }
    #[cfg(windows)]
    if let Some(raw) = std::env::var_os(REEXEC_STATE_ENV) {
        let state: ReexecState = serde_json::from_str(&raw.to_string_lossy())
            .context("decoding early supervisor reexec state")?;
        EARLY_REEXEC_STATE
            .set(state)
            .map_err(|_| anyhow::anyhow!("supervisor reexec state was prepared twice"))?;
        // SAFETY: this entry hook runs before the runtime or helper threads.
        unsafe { std::env::remove_var(REEXEC_STATE_ENV) };
    }
    Ok(())
}

#[cfg(any(unix, windows))]
fn inherited_reexec_state() -> Result<Option<ReexecState>> {
    if let Some(state) = EARLY_REEXEC_STATE.get() {
        return Ok(Some(state.clone()));
    }
    std::env::var_os(REEXEC_STATE_ENV)
        .map(|state| serde_json::from_str::<ReexecState>(&state.to_string_lossy()))
        .transpose()
        .context("decoding inherited supervisor reexec state")
}

pub(crate) fn published_owner_pid(paths: &DaemonPaths) -> u32 {
    if is_worker_process()
        && let Some(receipt) =
            cockpit_host::daemon_lifecycle::read_daemon_pid_record(&paths.pid_file)
    {
        return receipt.pid;
    }
    if is_worker_process()
        && let Some(pid) = std::env::var(SUPERVISOR_PID_ENV)
            .ok()
            .and_then(|value| value.parse().ok())
    {
        return pid;
    }
    std::process::id()
}

pub(crate) fn published_uptime_secs(worker_uptime: Duration) -> u64 {
    if is_worker_process()
        && let Some(opened_at) = std::env::var(OPENED_AT_ENV)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
    {
        return now_unix_ms().saturating_sub(opened_at) / 1_000;
    }
    worker_uptime.as_secs()
}

pub(crate) type WorkerListeners = (DaemonListener, super::leak_reveal_socket::BoundRevealSocket);

/// A supervised worker must not outlive its supervisor. The supervisor owns
/// the pid receipt, lifetime lock, and restart budget; an orphaned worker would
/// keep serving the inherited public listener and holding the database after a
/// replacement supervisor has taken over the home, so clients would reach a
/// generation nobody supervises and the replacement worker would stall behind
/// the orphan's database ownership. Once the liveness pipe reports EOF the
/// worker terminates immediately, exactly as if the whole daemon had crashed;
/// the next generation's durable recovery reconciles any in-flight work.
///
/// Level-triggered: if the supervisor is already gone when this starts, the
/// first read returns EOF at once.
fn watch_supervisor_liveness() -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Read as _;
        use std::os::fd::FromRawFd as _;
        let fd = EARLY_SUPERVISOR_LIVENESS_FD.swap(-1, std::sync::atomic::Ordering::SeqCst);
        if fd < 0 {
            return Ok(());
        }
        // SAFETY: the supervisor installed the liveness read end at this fd and
        // the atomic swap above hands it out exactly once.
        let mut liveness = unsafe { std::fs::File::from_raw_fd(fd) };
        std::thread::Builder::new()
            .name("supervisor-liveness".to_owned())
            .spawn(move || {
                let mut byte = [0_u8; 1];
                loop {
                    match liveness.read(&mut byte) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
                // A replacement generation may replay idempotent intents of
                // calls still running here; kill every tool, hook, server,
                // and shell process group first so none outlives this
                // worker's exit.
                let killed = cockpit_host::process::kill_direct_child_process_groups();
                super::daemon_log::daemon_eprintln!(
                    "supervised worker pid {}: supervisor exited; killed {killed} child process group(s); terminating with it",
                    std::process::id()
                );
                // SAFETY: _exit is async-signal-safe and skips Rust teardown,
                // matching the crash the lost supervisor represents.
                unsafe { libc::_exit(SUPERVISOR_LOST_EXIT) }
            })
            .context("starting supervisor liveness watch")?;
    }
    Ok(())
}

/// Consume the supervisor-owned Unix listeners inherited at fd 3 and fd 5.
/// Windows workers deliberately return `None`: each generation prepares a new
/// hardened random pipe and publishes its identity only at readiness.
pub(crate) fn take_worker_listeners(paths: &DaemonPaths) -> Result<Option<WorkerListeners>> {
    if !is_worker_process() {
        return Ok(None);
    }
    watch_supervisor_liveness()?;
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd as _;
        let listen_fds = std::env::var("LISTEN_FDS").unwrap_or_default();
        let listen_pid = std::env::var("LISTEN_PID").unwrap_or_default();
        if listen_fds != "1" || listen_pid.parse::<u32>().ok() != Some(std::process::id()) {
            bail!("supervised worker received invalid LISTEN_FDS/LISTEN_PID activation");
        }
        // SAFETY: the supervisor installs owned listener duplicates at exactly
        // fd 3 and fd 5 before exec. This function consumes each exactly once.
        let control = unsafe { std::os::unix::net::UnixListener::from_raw_fd(CONTROL_FD) };
        // SAFETY: same fd-inheritance contract as fd 3 above.
        let reveal = unsafe { std::os::unix::net::UnixListener::from_raw_fd(REVEAL_FD) };
        set_close_on_exec(CONTROL_FD)?;
        set_close_on_exec(REVEAL_FD)?;
        control.set_nonblocking(true)?;
        reveal.set_nonblocking(true)?;
        let control = tokio::net::UnixListener::from_std(control)?;
        let reveal = tokio::net::UnixListener::from_std(reveal)?;
        Ok(Some((
            control,
            super::leak_reveal_socket::BoundRevealSocket::inherited(
                reveal,
                paths.leak_reveal_socket(),
            ),
        )))
    }
    #[cfg(windows)]
    {
        let _ = paths;
        Ok(None)
    }
}

/// Report the worker's readiness barrier to the supervisor.
///
/// An ordinary worker reports once, at its publication barrier. A rolling
/// standby reports its identity before boot and keeps fd 4 open: after fd-6
/// promotion it must report again through
/// [`report_promoted_worker_serving`] once it has reached the same publication
/// barrier, so the supervisor does not declare the roll complete while the
/// successor is still opening the database and clients' hellos would time out
/// in the inherited listener's backlog.
pub(crate) fn report_worker_ready() -> Result<()> {
    write_worker_ready_report(!worker_handover_standby())
}

/// Report that a promoted rolling successor has reached its publication
/// barrier and is about to accept from the inherited listener.
pub(crate) fn report_promoted_worker_serving() -> Result<()> {
    debug_assert!(worker_handover_standby());
    write_worker_ready_report(true)
}

fn write_worker_ready_report(close: bool) -> Result<()> {
    if !is_worker_process() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        let report = WorkerReadyReport {
            protocol_version: super::proto::PROTOCOL_VERSION,
            pid: std::process::id(),
            generation: worker_generation(),
            opened_at_unix_ms: std::env::var(OPENED_AT_ENV)
                .context("supervised worker missing inherited open time")?
                .parse()
                .context("supervised worker inherited malformed open time")?,
        };
        let mut encoded = serde_json::to_vec(&report)?;
        encoded.push(b'\n');
        // SAFETY: fd 4 is the inherited write end of this generation's
        // readiness pipe and `encoded` remains valid for the write.
        let written = unsafe { libc::write(READY_FD, encoded.as_ptr().cast(), encoded.len()) };
        if written != isize::try_from(encoded.len()).unwrap_or(-1) {
            return Err(std::io::Error::last_os_error()).context("signaling worker readiness");
        }
        if close {
            // SAFETY: fd 4 belongs to this process and is no longer needed.
            unsafe { libc::close(READY_FD) };
        }
    }
    #[cfg(not(unix))]
    let _ = close;
    Ok(())
}

pub(crate) fn worker_handover_standby() -> bool {
    #[cfg(unix)]
    {
        std::env::var_os(HANDOVER_STANDBY_ENV).is_some()
    }
    #[cfg(not(unix))]
    false
}

/// A rolling successor reports its non-recovery boot barrier and then waits
/// before it touches durable recovery or starts accepting from the inherited
/// listener. The supervisor releases it only after the predecessor has exited.
pub(crate) fn wait_for_worker_promotion() -> Result<()> {
    #[cfg(unix)]
    {
        if !worker_handover_standby() {
            return Ok(());
        }
        use std::io::Read as _;
        use std::os::fd::FromRawFd as _;
        // SAFETY: a rolling supervisor installs the read end at this exact fd.
        let mut promotion = unsafe { std::fs::File::from_raw_fd(PROMOTION_FD) };
        let mut byte = [0_u8; 1];
        promotion
            .read_exact(&mut byte)
            .context("waiting for supervisor handover promotion")?;
        anyhow::ensure!(byte == *b"P", "invalid supervisor handover promotion");
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct WorkerReadyReport {
    protocol_version: u32,
    pid: u32,
    generation: u64,
    opened_at_unix_ms: u64,
}

#[cfg(windows)]
pub(crate) fn worker_control_identity(canonical: &Path) -> PathBuf {
    std::env::var_os(WINDOWS_IDENTITY_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| canonical.to_path_buf())
}

#[cfg(windows)]
pub(crate) fn worker_reveal_identity(canonical: &Path) -> PathBuf {
    std::env::var_os(WINDOWS_REVEAL_IDENTITY_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| canonical.to_path_buf())
}

pub fn admin_socket(paths: &DaemonPaths) -> Result<PathBuf> {
    Ok(paths
        .pid_file
        .parent()
        .context("daemon pid path has no parent")?
        .join("sup.ctl"))
}

#[cfg(any(unix, windows))]
pub async fn run(paths: DaemonPaths, no_sandbox: bool, resume_all_sessions: bool) -> Result<()> {
    use cockpit_host::daemon_lifecycle::{ForegroundMetadataGuard, reclaim_stale_and_reserve};

    super::daemon_log::set_process_role(super::daemon_log::DaemonLogRole::Supervisor);
    super::validate_bind_socket_paths(&paths)?;
    let executable = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .context("resolving supervisor executable")?;
    let endpoint_record = paths.pid_file.parent().map(super::endpoint_file_for_state);
    let admin_path = admin_socket(&paths)?;
    let state_dir = paths
        .pid_file
        .parent()
        .context("daemon pid file has no parent")?;
    let log = super::spawn_notify::prepare_daemon_log(state_dir)?;
    let log_path = state_dir.join(super::DAEMON_LOG_FILE);
    super::daemon_log::write_run_marker(&log, super::daemon_log::DaemonLogRole::Supervisor);

    let inherited = inherited_reexec_state()?;

    let (
        receipt,
        mut metadata,
        endpoint_owner,
        mut admin,
        opened_at_unix_ms,
        mut generation,
        mut generations,
        mut worker,
        database_owner,
    ) = if let Some(inherited) = inherited {
        #[cfg(unix)]
        {
            let receipt =
                match cockpit_host::daemon_lifecycle::read_daemon_pid_record(&paths.pid_file) {
                    Some(receipt) if receipt.pid == std::process::id() => receipt,
                    _ => bail!("supervisor receipt changed during reexec"),
                };
            // SAFETY: these descriptors were exported by this same process
            // immediately before exec and each is consumed exactly once.
            let metadata = unsafe {
                ForegroundMetadataGuard::resume_after_reexec(
                    paths.pid_file.clone(),
                    paths.socket.clone(),
                    endpoint_record.clone(),
                    receipt.clone(),
                    inherited.lifetime_fd,
                    inherited.pid_lock_fd,
                )
            }?;
            // SAFETY: same inherited-descriptor contract as metadata above.
            let endpoint_owner = unsafe {
                UnixEndpointOwner::resume(
                    &paths,
                    inherited.control_fd,
                    inherited.reveal_fd,
                    inherited.liveness_fds,
                )?
            };
            // SAFETY: the inherited descriptor uniquely owns the admin listener.
            let admin = unsafe { resume_admin(inherited.admin_fd)? };
            let worker = resume_worker(inherited.worker_pid, &inherited.worker_binary)?;
            // SAFETY: this is the uniquely inherited descriptor retained by
            // the pre-exec supervisor owner.
            let database_owner = unsafe {
                crate::db::SupervisorDatabaseOwner::from_raw_fd(inherited.database_lock_fd)
            };
            let generations = WorkerGenerations::resume_after_reexec(
                &database_owner,
                inherited.generation,
                inherited.highest_attempted_generation,
            );
            (
                receipt,
                metadata,
                endpoint_owner,
                admin,
                inherited.opened_at_unix_ms,
                inherited.generation,
                generations,
                worker,
                database_owner,
            )
        }
        #[cfg(windows)]
        {
            let deadline = Instant::now() + super::DAEMON_SPAWN_TIMEOUT;
            let lifetime = loop {
                match cockpit_host::daemon_lifecycle::acquire_daemon_lifetime(&paths.pid_file) {
                    Ok(lifetime) => break lifetime,
                    Err(cockpit_host::daemon_lifecycle::AcquireDaemonLifetimeError::Busy)
                        if Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    Err(error) => {
                        return Err(error).context("acquiring reexec supervisor lifetime");
                    }
                }
            };
            let receipt =
                cockpit_host::daemon_lifecycle::reclaim_stale_and_reserve_preserving_endpoint(
                    &paths.pid_file,
                    std::process::id(),
                    &executable,
                )?;
            let mut metadata = ForegroundMetadataGuard::new_with_lifetime(
                paths.pid_file.clone(),
                paths.socket.clone(),
                endpoint_record.clone(),
                receipt.clone(),
                lifetime,
            )?;
            let endpoint_owner = WindowsEndpointOwner;
            remove_if_present(&admin_path)?;
            let admin = bind_admin(&admin_path)?;
            let worker = resume_worker(inherited.worker_pid, &inherited.worker_binary)?;
            let database_owner = acquire_database_owner_until(deadline)?;
            let generations = WorkerGenerations::resume_after_reexec(
                &database_owner,
                inherited.generation,
                inherited.highest_attempted_generation,
            );
            publish_generation(
                &paths,
                &receipt,
                inherited.worker_pid,
                inherited.generation,
                inherited.opened_at_unix_ms,
            )?;
            metadata.track_endpoint_record(endpoint_record.clone());
            (
                receipt,
                metadata,
                endpoint_owner,
                admin,
                inherited.opened_at_unix_ms,
                inherited.generation,
                generations,
                worker,
                database_owner,
            )
        }
    } else {
        let lifetime =
            super::acquire_daemon_lifetime_for_startup(&paths.pid_file).with_context(|| {
                format!("acquiring supervisor lifetime {}", paths.pid_file.display())
            })?;
        let database_owner = crate::db::SupervisorDatabaseOwner::acquire_default()
            .context("acquiring supervisor database lifetime")?;
        let receipt = reclaim_stale_and_reserve(
            &paths.pid_file,
            &paths.socket,
            endpoint_record.as_deref(),
            std::process::id(),
            &executable,
        )
        .with_context(|| format!("reserving supervisor pid file {}", paths.pid_file.display()))?;
        let mut metadata = ForegroundMetadataGuard::new_with_lifetime(
            paths.pid_file.clone(),
            paths.socket.clone(),
            None,
            receipt.clone(),
            lifetime,
        )?;
        remove_if_present(&paths.socket)?;
        remove_if_present(&paths.leak_reveal_socket())?;
        remove_if_present(&admin_path)?;
        #[cfg(unix)]
        let endpoint_owner = UnixEndpointOwner::bind(&paths)?;
        #[cfg(windows)]
        let endpoint_owner = WindowsEndpointOwner;
        let admin = bind_admin(&admin_path)?;
        let opened_at_unix_ms = now_unix_ms();
        // A previous supervisor on this home (restart, or SIGKILL followed by
        // a new client) left its last generation in the durable fence; the
        // first worker of this run must start strictly above it.
        let mut generations = WorkerGenerations::resume(&database_owner, 0)?;
        let generation = generations.allocate(&database_owner)?;
        let worker = spawn_ready_worker(WorkerSpawnRequest {
            endpoints: &endpoint_owner,
            binary: &executable,
            paths: &paths,
            log: &log,
            log_path: &log_path,
            generation,
            opened_at_unix_ms,
            no_sandbox,
            resume_all_sessions,
            hold_for_promotion: false,
        })
        .await?;
        publish_generation(&paths, &receipt, worker.pid, generation, opened_at_unix_ms)?;
        metadata.track_endpoint_record(endpoint_record.clone());
        super::spawn_notify::report_ready(&paths.socket);
        (
            receipt,
            metadata,
            endpoint_owner,
            admin,
            opened_at_unix_ms,
            generation,
            generations,
            worker,
            database_owner,
        )
    };
    let _database_owner = database_owner;

    let mut storm = cockpit_client::RestartStormGuard::default();
    let mut last_handover: Option<String> = None;
    'supervision: loop {
        tokio::select! {
            exit = worker.exited.recv() => {
                match exit {
                    Some(Ok(())) => {}
                    Some(Err(error)) => bail!("stable worker process watch failed: {error}"),
                    None => bail!("stable worker process watch stopped unexpectedly"),
                }
                let clean = worker_exit_succeeded(&mut worker);
                if paths.ephemeral && clean {
                    break;
                }
                let respawn_binary = worker.binary.clone();
                let Some(replacement) = retry_worker_spawn(
                    &mut storm,
                    &mut generations,
                    &_database_owner,
                    &mut generation,
                    |attempt_generation| spawn_ready_worker(WorkerSpawnRequest {
                        endpoints: &endpoint_owner,
                        binary: &respawn_binary,
                        paths: &paths,
                        log: &log,
                        log_path: &log_path,
                        generation: attempt_generation,
                        opened_at_unix_ms,
                        no_sandbox,
                        resume_all_sessions,
                        hold_for_promotion: false,
                    }),
                ).await else {
                    break 'supervision;
                };
                worker = replacement;
                publish_generation(
                    &paths,
                    &receipt,
                    worker.pid,
                    generation,
                    opened_at_unix_ms,
                )?;
            }
            accepted = accept_admin(&mut admin) => {
                let stream = accepted?;
                let request = read_admin(stream).await;
                let (request, mut stream) = match request {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::warn!(%error, "rejecting malformed supervisor admin request");
                        continue;
                    }
                };
                if request.version != ADMIN_PROTOCOL_VERSION {
                    reply_admin(&mut stream, &AdminResponse::Error {
                        version: ADMIN_PROTOCOL_VERSION,
                        message: format!("unsupported supervisor admin protocol {}", request.version),
                    }).await;
                    continue;
                }
                match request.command {
                    AdminCommand::Status => {
                        reply_admin(&mut stream, &status_response(worker.pid, generation, opened_at_unix_ms, last_handover.clone())).await;
                    }
                    AdminCommand::Stop => {
                        reply_admin(&mut stream, &AdminResponse::Stopping { version: ADMIN_PROTOCOL_VERSION }).await;
                        drain_and_reap_worker(&mut worker, false).await?;
                        break;
                    }
                    command @ (AdminCommand::Roll | AdminCommand::Upgrade { .. }) => {
                        #[cfg(windows)]
                        {
                            // Windows has no signal-based boundary protocol. Keep the
                            // pre-handover rolling replacement behavior here so `restart`
                            // and `upgrade` do not regress into permanent failures there.
                            let binary = match command {
                                AdminCommand::Upgrade { binary } => {
                                    match std::fs::canonicalize(&binary) {
                                        Ok(binary) => binary,
                                        Err(error) => {
                                            reply_admin(&mut stream, &AdminResponse::Error {
                                                version: ADMIN_PROTOCOL_VERSION,
                                                message: format!(
                                                    "resolving upgrade binary {}: {error}",
                                                    binary.display()
                                                ),
                                            })
                                            .await;
                                            continue;
                                        }
                                    }
                                }
                                AdminCommand::Roll => executable.clone(),
                                _ => unreachable!("roll command was matched above"),
                            };
                            let next_generation = match generations.allocate(&_database_owner) {
                                Ok(next_generation) => next_generation,
                                Err(error) => {
                                    reply_admin(&mut stream, &AdminResponse::Error {
                                        version: ADMIN_PROTOCOL_VERSION,
                                        message: format!("{error:#}"),
                                    })
                                    .await;
                                    continue;
                                }
                            };
                            let successor = match spawn_ready_worker(WorkerSpawnRequest {
                                endpoints: &endpoint_owner,
                                binary: &binary,
                                paths: &paths,
                                log: &log,
                                log_path: &log_path,
                                generation: next_generation,
                                opened_at_unix_ms,
                                no_sandbox,
                                resume_all_sessions,
                                hold_for_promotion: false,
                            })
                            .await
                            {
                                Ok(successor) => successor,
                                Err(error) => {
                                    reply_admin(&mut stream, &AdminResponse::Error {
                                        version: ADMIN_PROTOCOL_VERSION,
                                        message: format!("{error:#}"),
                                    })
                                    .await;
                                    continue;
                                }
                            };
                            let old_worker_pid = worker.pid;
                            publish_generation(
                                &paths,
                                &receipt,
                                successor.pid,
                                next_generation,
                                opened_at_unix_ms,
                            )?;
                            let predecessor = std::mem::replace(&mut worker, successor);
                            reap_retired_worker(predecessor);
                            generation = next_generation;
                            last_handover = Some(format!(
                                "completed without boundary handover: generation {generation}"
                            ));
                            reply_admin(&mut stream, &AdminResponse::Rolled {
                                version: ADMIN_PROTOCOL_VERSION,
                                old_worker_pid,
                                worker_pid: worker.pid,
                                generation,
                                uptime_ms: now_unix_ms().saturating_sub(opened_at_unix_ms),
                            }).await;
                            continue;
                        }
                        let handover_timers = match crate::config::config::extended::load_installation_handover_timers() {
                            Ok(timers) => timers,
                            Err(error) => {
                                let reason = format!("loading worker handover timers: {error:#}");
                                tracing::warn!(%reason, "worker handover aborted before readiness");
                                last_handover = Some(format!("aborted: {reason}"));
                                reply_admin(&mut stream, &AdminResponse::Error {
                                    version: ADMIN_PROTOCOL_VERSION,
                                    message: reason,
                                }).await;
                                continue;
                            }
                        };
                        let binary = match command {
                            AdminCommand::Upgrade { binary } => match std::fs::canonicalize(&binary) {
                                Ok(binary) => binary,
                                Err(error) => {
                                    let reason = format!("resolving upgrade binary {}: {error}", binary.display());
                                    tracing::warn!(%reason, "worker handover aborted before readiness");
                                    last_handover = Some(format!("aborted: {reason}"));
                                    reply_admin(&mut stream, &AdminResponse::Error {
                                        version: ADMIN_PROTOCOL_VERSION,
                                        message: reason,
                                    }).await;
                                    continue;
                                }
                            },
                            _ => executable.clone(),
                        };
                        // An aborted attempt burns its generation, so the
                        // retry never shares a number with a process that
                        // may still be exiting.
                        let next_generation = match generations.allocate(&_database_owner) {
                            Ok(next_generation) => next_generation,
                            Err(error) => {
                                let reason = format!("allocating successor generation: {error:#}");
                                tracing::warn!(%reason, "worker handover aborted before readiness");
                                last_handover = Some(format!("aborted: {reason}"));
                                reply_admin(&mut stream, &AdminResponse::Error {
                                    version: ADMIN_PROTOCOL_VERSION,
                                    message: reason,
                                }).await;
                                continue;
                            }
                        };
                        // Boot the successor to its readiness barrier first,
                        // but hold it before the accept loop.  This is the
                        // confirm-before-commit point: a bad binary, hello,
                        // or inherited-fd boot failure leaves the predecessor
                        // completely untouched.
                        let mut successor = match spawn_ready_worker(WorkerSpawnRequest {
                            endpoints: &endpoint_owner,
                            binary: &binary,
                            paths: &paths,
                            log: &log,
                            log_path: &log_path,
                            generation: next_generation,
                            opened_at_unix_ms,
                            no_sandbox,
                            resume_all_sessions,
                            hold_for_promotion: true,
                        }).await {
                            Ok(successor) => successor,
                            Err(error) => {
                                let reason = format!("staging successor readiness: {error:#}");
                                tracing::warn!(%reason, "worker handover aborted; predecessor remains serving");
                                last_handover = Some(format!("aborted: {reason}"));
                                reply_admin(&mut stream, &AdminResponse::Error {
                                    version: ADMIN_PROTOCOL_VERSION,
                                    message: reason,
                                }).await;
                                continue;
                            }
                        };
                        if let Err(error) = terminate_worker(&mut worker, true) {
                            let _ = terminate_worker(&mut successor, false);
                            reap_worker_after_exit(successor);
                            let reason = format!("starting predecessor boundary: {error:#}");
                            tracing::warn!(%reason, "worker handover aborted; predecessor remains serving");
                            last_handover = Some(format!("aborted: {reason}"));
                            reply_admin(&mut stream, &AdminResponse::Error {
                                version: ADMIN_PROTOCOL_VERSION,
                                message: reason,
                            }).await;
                            continue;
                        }
                        let ready = wait_for_worker_handover_ready(
                            &mut admin,
                            &mut successor,
                            worker.pid,
                            generation,
                            handover_timers.drain() + HANDOVER_BOUNDARY_ANNOUNCE_SLACK,
                            opened_at_unix_ms,
                            last_handover.clone(),
                        ).await;
                        match ready {
                            Ok(()) => {}
                            Err(error) => {
                                let stopping = error
                                    .to_string()
                                    .contains("administrative stop requested during worker handover");
                                // SIGUSR1 fenced the predecessor. Every
                                // pre-commit exit must release that fence so
                                // an aborted upgrade resumes admissions
                                // immediately instead of waiting for T_drain.
                                if let Err(abort_error) =
                                    signal_worker_handover_decision(&worker, false)
                                {
                                    tracing::warn!(%abort_error, pid = worker.pid, "could not abort predecessor handover fence");
                                }
                                let _ = terminate_worker(&mut successor, false);
                                reap_worker_after_exit(successor);
                                if stopping {
                                    drain_and_reap_worker(&mut worker, false).await?;
                                    break 'supervision;
                                }
                                let reason = format!("waiting for predecessor boundary: {error:#}");
                                tracing::warn!(%reason, "worker handover aborted before commit; predecessor remains serving");
                                last_handover = Some(format!("aborted: {reason}"));
                                reply_admin(&mut stream, &AdminResponse::Error {
                                    version: ADMIN_PROTOCOL_VERSION,
                                    message: reason,
                                }).await;
                                continue;
                            }
                        }
                        if let Err(error) = ensure_staged_successor_live(&mut successor) {
                            let _ = signal_worker_handover_decision(&worker, false);
                            let _ = terminate_worker(&mut successor, false);
                            reap_worker_after_exit(successor);
                            let reason = format!(
                                "checking staged successor before handover commitment: {error:#}"
                            );
                            tracing::warn!(%reason, "worker handover aborted; predecessor remains serving");
                            last_handover = Some(format!("aborted: {reason}"));
                            reply_admin(&mut stream, &AdminResponse::Error {
                                version: ADMIN_PROTOCOL_VERSION,
                                message: reason,
                            }).await;
                            continue;
                        }
                        if let Err(error) = signal_worker_handover_decision(&worker, true) {
                            let _ = signal_worker_handover_decision(&worker, false);
                            let _ = terminate_worker(&mut successor, false);
                            reap_worker_after_exit(successor);
                            let reason = format!("committing worker handover: {error:#}");
                            last_handover = Some(format!("aborted: {reason}"));
                            reply_admin(&mut stream, &AdminResponse::Error {
                                version: ADMIN_PROTOCOL_VERSION,
                                message: reason,
                            }).await;
                            continue;
                        }
                        let boundary = wait_for_worker_boundary(
                            &mut admin,
                            worker.pid,
                            generation,
                            handover_timers.hard() + HANDOVER_BOUNDARY_ANNOUNCE_SLACK,
                            opened_at_unix_ms,
                            last_handover.clone(),
                        )
                        .await;
                        let boundary = match boundary {
                            Ok(boundary) => boundary,
                            Err(error) => {
                                let stopping = error
                                    .to_string()
                                    .contains("administrative stop requested during worker handover");
                                // `SIGUSR2` committed the staged successor before the
                                // predecessor was permitted to cancel live work. Never
                                // report this as an abort-and-keep: a hard cancellation
                                // may already be in flight. Retire both workers and let
                                // the stable supervisor's ordinary crash-recovery path
                                // restore a sole durable owner.
                                let _ = terminate_worker(&mut successor, false);
                                reap_worker_after_exit(successor);
                                if stopping {
                                    drain_and_reap_worker(&mut worker, false).await?;
                                    break 'supervision;
                                }
                                let reason = format!(
                                    "waiting for predecessor boundary after handover commitment: {error:#}"
                                );
                                tracing::warn!(%reason, "worker handover failed after commitment; retiring predecessor");
                                last_handover = Some(format!("failed after commitment: {reason}"));
                                drain_and_reap_worker(&mut worker, false).await?;
                                let respawn_binary = worker.binary.clone();
                                let Some(replacement) = retry_worker_spawn(
                                    &mut storm,
                                    &mut generations,
                                    &_database_owner,
                                    &mut generation,
                                    |attempt_generation| spawn_ready_worker(WorkerSpawnRequest {
                                        endpoints: &endpoint_owner,
                                        binary: &respawn_binary,
                                        paths: &paths,
                                        log: &log,
                                        log_path: &log_path,
                                        generation: attempt_generation,
                                        opened_at_unix_ms,
                                        no_sandbox,
                                        resume_all_sessions,
                                        hold_for_promotion: false,
                                    }),
                                ).await else {
                                    bail!("{reason}; recovery worker readiness budget exhausted");
                                };
                                worker = replacement;
                                publish_generation(
                                    &paths,
                                    &receipt,
                                    worker.pid,
                                    generation,
                                    opened_at_unix_ms,
                                )?;
                                reply_admin(&mut stream, &AdminResponse::Error {
                                    version: ADMIN_PROTOCOL_VERSION,
                                    message: reason,
                                }).await;
                                continue;
                            }
                        };
                        let old_pid = worker.pid;
                        if let Err(error) = await_worker_exit(&mut worker).await {
                            // A committed predecessor must not share session
                            // ownership with its staged successor.  Force the
                            // existing shutdown path, then release only after
                            // the old process is definitely gone.
                            tracing::warn!(%error, pid = old_pid, "predecessor did not exit after handover commit; forcing it");
                            drain_and_reap_worker(&mut worker, false).await?;
                        }
                        if let Err(error) = release_ready_successor(
                            &mut successor,
                            next_generation,
                            opened_at_unix_ms,
                            &log_path,
                        )
                        .await
                        {
                            let reason = format!("{error:#}");
                            let recovery_binary = successor.binary.clone();
                            let _ = terminate_worker(&mut successor, false);
                            reap_worker_after_exit(successor);
                            // The predecessor has already exited, so failing
                            // the release (or the successor's boot after it)
                            // must not take the stable supervisor (and its
                            // listener) down with it.
                            // Recover through the ordinary readiness/restart
                            // budget, now that the successor is the sole
                            // durable owner.
                            generation = next_generation;
                            let Some(replacement) = retry_worker_spawn(
                                &mut storm,
                                &mut generations,
                                &_database_owner,
                                &mut generation,
                                |attempt_generation| spawn_ready_worker(WorkerSpawnRequest {
                                    endpoints: &endpoint_owner,
                                    binary: &recovery_binary,
                                    paths: &paths,
                                    log: &log,
                                    log_path: &log_path,
                                    generation: attempt_generation,
                                    opened_at_unix_ms,
                                    no_sandbox,
                                    resume_all_sessions,
                                    hold_for_promotion: false,
                                }),
                            )
                            .await
                            else {
                                bail!("{reason}; recovery worker readiness budget exhausted");
                            };
                            worker = replacement;
                            publish_generation(
                                &paths,
                                &receipt,
                                worker.pid,
                                generation,
                                opened_at_unix_ms,
                            )?;
                            last_handover = Some(format!(
                                "completed after successor release recovery: generation {generation}; {} session boundaries",
                                boundary.len()
                            ));
                            reply_admin(&mut stream, &AdminResponse::Rolled {
                                version: ADMIN_PROTOCOL_VERSION,
                                old_worker_pid: old_pid,
                                worker_pid: worker.pid,
                                generation,
                                uptime_ms: now_unix_ms().saturating_sub(opened_at_unix_ms),
                            }).await;
                            continue;
                        }
                        publish_generation(
                            &paths, &receipt, successor.pid, next_generation, opened_at_unix_ms,
                        )?;
                        worker = successor;
                        generation = next_generation;
                        last_handover = Some(format!(
                            "completed: generation {generation}; {} session boundaries",
                            boundary.len()
                        ));
                        reply_admin(&mut stream, &AdminResponse::Rolled {
                            version: ADMIN_PROTOCOL_VERSION,
                            old_worker_pid: old_pid,
                            worker_pid: worker.pid,
                            generation,
                            uptime_ms: now_unix_ms().saturating_sub(opened_at_unix_ms),
                        }).await;
                    }
                    AdminCommand::WorkerBoundary { .. } => {
                        // Boundary reports are accepted only by the dedicated
                        // handover wait loop, where the predecessor PID and
                        // generation are exact. Accepting one here lets a
                        // stale predecessor overwrite the committed result.
                        reply_admin(&mut stream, &AdminResponse::Error {
                            version: ADMIN_PROTOCOL_VERSION,
                            message: "stale worker boundary report".to_string(),
                        }).await;
                    }
                    AdminCommand::WorkerHandoverReady { .. } => {
                        reply_admin(&mut stream, &AdminResponse::Error {
                            version: ADMIN_PROTOCOL_VERSION,
                            message: "stale worker handover-ready report".to_string(),
                        }).await;
                    }
                    AdminCommand::Reexec => {
                        reply_admin(&mut stream, &AdminResponse::Reexecing { version: ADMIN_PROTOCOL_VERSION }).await;
                        reexec_supervisor(ReexecRequest {
                            executable: &executable,
                            #[cfg(unix)]
                            metadata: &metadata,
                            #[cfg(unix)]
                            endpoints: &endpoint_owner,
                            #[cfg(unix)]
                            admin: &admin,
                            #[cfg(unix)]
                            database_owner: &_database_owner,
                            worker: &worker,
                            generation,
                            highest_attempted_generation: generations.highest_attempted(),
                            opened_at_unix_ms,
                            no_sandbox,
                            resume_all_sessions,
                        })?;
                        unreachable!("successful reexec replaces the supervisor image")
                    }
                }
            }
            _ = shutdown_signal() => {
                drain_and_reap_worker(&mut worker, false).await?;
                break;
            }
        }
    }
    remove_if_present(&admin_path)?;
    #[cfg(windows)]
    remove_if_present(&paths.leak_reveal_socket())?;
    metadata.cleanup()?;
    Ok(())
}

/// Read access to the durable worker generation fence. The production
/// implementation is the supervisor's database-owner witness; the seam lets
/// allocation defer an unreadable fence without owning the witness itself.
trait DurableGenerationFence {
    fn read_durable_generation(&self) -> Result<u64>;
}

impl DurableGenerationFence for crate::db::SupervisorDatabaseOwner {
    fn read_durable_generation(&self) -> Result<u64> {
        self.durable_worker_generation()
            .context("reading durable worker generation fence")
    }
}

/// Allocates supervised worker generations strictly above the durable writer
/// fence and above every generation this supervisor has already attempted.
///
/// An attempt burns its generation whether or not it becomes ready: a worker
/// that failed after opening the database has already advanced the durable
/// fence, and the strict fence would reject a retry that reused its number.
#[derive(Debug)]
struct WorkerGenerations {
    highest_attempted: u64,
    /// The durable fence has not been folded into `highest_attempted` and
    /// nothing else proves allocation is above it: a reexec from a
    /// pre-upgrade supervisor (no inherited attempted generations) whose
    /// fence read failed. Burned attempts of the old supervisor may have
    /// advanced the fence past the live worker's generation, so every
    /// allocation re-reads the fence first and fails — that allocation only,
    /// never the supervisor — until the read succeeds.
    durable_unverified: bool,
}

impl WorkerGenerations {
    /// Resume allocation above both the durable fence and `current`, the
    /// generation of the worker this supervisor already owns (0 for none).
    #[cfg(any(unix, windows))]
    fn resume(fence: &impl DurableGenerationFence, current: u64) -> Result<Self> {
        let durable = fence.read_durable_generation()?;
        Ok(Self::above(durable.max(current)))
    }

    /// Resume allocation in a reexecuted supervisor, which already owns a
    /// live worker. The durable fence read is best-effort here: failing the
    /// reexec on a transient SQLite error would exit the supervisor and take
    /// that healthy worker down with it. The pre-reexec supervisor's
    /// `inherited_highest` (every attempted generation, ready or burned) and
    /// the live worker's `current` generation still bound allocation. A
    /// pre-upgrade supervisor's state carries no attempted generations
    /// (`inherited_highest == 0`); then only the durable fence bounds its
    /// burned attempts, and allocation stays deferred until it is read.
    #[cfg(any(unix, windows))]
    fn resume_after_reexec(
        fence: &impl DurableGenerationFence,
        current: u64,
        inherited_highest: u64,
    ) -> Self {
        match fence.read_durable_generation() {
            Ok(durable) => Self::above(durable.max(current).max(inherited_highest)),
            Err(error) if inherited_highest == 0 => {
                tracing::warn!(
                    error = %format!("{error:#}"),
                    current,
                    "reexecuted supervisor could not read the durable worker generation fence and inherited no attempted generations; deferring allocation until the fence is readable"
                );
                Self {
                    highest_attempted: current,
                    durable_unverified: true,
                }
            }
            Err(error) => {
                tracing::warn!(
                    error = %format!("{error:#}"),
                    current,
                    inherited_highest,
                    "reexecuted supervisor could not read the durable worker generation fence; allocating above its inherited generations"
                );
                Self::above(current.max(inherited_highest))
            }
        }
    }

    fn above(highest_attempted: u64) -> Self {
        Self {
            highest_attempted,
            durable_unverified: false,
        }
    }

    #[cfg(any(unix, windows))]
    fn highest_attempted(&self) -> u64 {
        self.highest_attempted
    }

    /// Whether allocation is deferred on an unreadable durable fence.
    fn durable_unverified(&self) -> bool {
        self.durable_unverified
    }

    fn allocate(&mut self, fence: &impl DurableGenerationFence) -> Result<u64> {
        if self.durable_unverified {
            let durable = fence
                .read_durable_generation()
                .context("worker generation allocation deferred on an unreadable durable fence")?;
            self.highest_attempted = self.highest_attempted.max(durable);
            self.durable_unverified = false;
        }
        let next = self
            .highest_attempted
            .checked_add(1)
            .context("supervised worker generations exhausted")?;
        self.highest_attempted = next;
        Ok(next)
    }
}

/// Pause before retrying a respawn whose generation allocation was deferred on
/// an unreadable durable fence, so the attempt does not spin through the
/// restart budget.
const DEFERRED_FENCE_RETRY_DELAY: Duration = Duration::from_millis(250);

async fn retry_worker_spawn<T, F, Fut>(
    storm: &mut cockpit_client::RestartStormGuard,
    generations: &mut WorkerGenerations,
    fence: &impl DurableGenerationFence,
    generation: &mut u64,
    mut spawn: F,
) -> Option<T>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    loop {
        if !storm.allow(Instant::now()) {
            tracing::error!(
                generation = *generation,
                "worker restart storm exhausted; supervisor is exiting"
            );
            return None;
        }
        *generation = match generations.allocate(fence) {
            Ok(next) => next,
            Err(error) if generations.durable_unverified() => {
                // Only this attempt fails: it consumes restart budget like a
                // spawn failure, and the next attempt re-reads the fence.
                tracing::error!(
                    error = %format!("{error:#}"),
                    "worker generation allocation deferred on an unreadable durable fence; retrying"
                );
                tokio::time::sleep(DEFERRED_FENCE_RETRY_DELAY).await;
                continue;
            }
            Err(error) => {
                tracing::error!(%error, "worker generation allocation failed; supervisor is exiting");
                return None;
            }
        };
        match spawn(*generation).await {
            Ok(worker) => return Some(worker),
            Err(error) => {
                tracing::error!(
                    generation = *generation,
                    %error,
                    "worker respawn failed before readiness; retrying"
                );
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
pub async fn run(_paths: DaemonPaths, _no_sandbox: bool, _resume_all_sessions: bool) -> Result<()> {
    bail!("daemon supervision is unsupported on this platform")
}

struct Worker {
    pid: u32,
    binary: PathBuf,
    #[cfg(windows)]
    receipt: cockpit_host::daemon_lifecycle::DaemonPidReceipt,
    #[cfg(windows)]
    exit_status: cockpit_host::daemon_lifecycle::VerifiedDaemonProcess,
    child: Option<std::process::Child>,
    exited: tokio::sync::mpsc::Receiver<std::result::Result<(), String>>,
    #[cfg(unix)]
    promotion: Option<std::fs::File>,
    /// A staged successor's fd-4 read end, kept open for its second report
    /// at the publication barrier after promotion.
    #[cfg(unix)]
    serving: Option<std::os::fd::OwnedFd>,
}

#[cfg(unix)]
struct UnixEndpointOwner {
    control: tokio::net::UnixListener,
    reveal: super::leak_reveal_socket::BoundRevealSocket,
    /// Supervisor-liveness pipe. Workers inherit a duplicate of `read` at
    /// [`LIVENESS_FD`]; `write` never leaves this process (close-on-exec,
    /// preserved only across this supervisor's own `reexec`).
    liveness_read: std::os::fd::OwnedFd,
    liveness_write: std::os::fd::OwnedFd,
}

#[cfg(unix)]
impl UnixEndpointOwner {
    fn bind(paths: &DaemonPaths) -> Result<Self> {
        let (liveness_read, liveness_write) = create_ready_pipe()?;
        Ok(Self {
            reveal: super::leak_reveal_socket::bind_reveal_socket(paths)?,
            control: super::bind_private_socket(&paths.socket)?,
            liveness_read,
            liveness_write,
        })
    }

    #[allow(clippy::type_complexity)]
    fn prepare_for_reexec(
        &self,
    ) -> Result<(
        std::os::fd::RawFd,
        std::os::fd::RawFd,
        (std::os::fd::RawFd, std::os::fd::RawFd),
    )> {
        use std::os::fd::AsRawFd as _;
        let control = self.control.as_raw_fd();
        let reveal = self.reveal.raw_fd();
        let liveness = (
            self.liveness_read.as_raw_fd(),
            self.liveness_write.as_raw_fd(),
        );
        clear_close_on_exec(control)?;
        clear_close_on_exec(reveal)?;
        // Keeping the write end open across exec is what lets live workers
        // survive an in-place supervisor reexec.
        clear_close_on_exec(liveness.0)?;
        clear_close_on_exec(liveness.1)?;
        Ok((control, reveal, liveness))
    }

    // SAFETY: callers transfer unique ownership of every inherited descriptor.
    unsafe fn resume(
        paths: &DaemonPaths,
        control_fd: std::os::fd::RawFd,
        reveal_fd: std::os::fd::RawFd,
        liveness_fds: Option<(std::os::fd::RawFd, std::os::fd::RawFd)>,
    ) -> Result<Self> {
        use std::os::fd::FromRawFd as _;
        let (liveness_read, liveness_write) = match liveness_fds {
            Some((read, write)) => {
                set_close_on_exec(read)?;
                set_close_on_exec(write)?;
                // SAFETY: upheld by this function's caller contract.
                unsafe {
                    (
                        std::os::fd::OwnedFd::from_raw_fd(read),
                        std::os::fd::OwnedFd::from_raw_fd(write),
                    )
                }
            }
            None => create_ready_pipe()?,
        };
        // SAFETY: upheld by this function's caller contract.
        let control = unsafe { std::os::unix::net::UnixListener::from_raw_fd(control_fd) };
        // SAFETY: upheld by this function's caller contract.
        let reveal = unsafe { std::os::unix::net::UnixListener::from_raw_fd(reveal_fd) };
        set_close_on_exec(control_fd)?;
        set_close_on_exec(reveal_fd)?;
        control.set_nonblocking(true)?;
        reveal.set_nonblocking(true)?;
        Ok(Self {
            control: tokio::net::UnixListener::from_std(control)?,
            reveal: super::leak_reveal_socket::BoundRevealSocket::new(
                tokio::net::UnixListener::from_std(reveal)?,
                paths.leak_reveal_socket(),
            ),
            liveness_read,
            liveness_write,
        })
    }
}

#[cfg(windows)]
struct WindowsEndpointOwner;

#[cfg(unix)]
type EndpointOwner = UnixEndpointOwner;
#[cfg(windows)]
type EndpointOwner = WindowsEndpointOwner;

struct WorkerSpawnRequest<'a> {
    endpoints: &'a EndpointOwner,
    binary: &'a Path,
    paths: &'a DaemonPaths,
    log: &'a std::fs::File,
    log_path: &'a Path,
    generation: u64,
    opened_at_unix_ms: u64,
    no_sandbox: bool,
    resume_all_sessions: bool,
    hold_for_promotion: bool,
}

struct OwnedWorkerSpawnRequest {
    binary: PathBuf,
    paths: DaemonPaths,
    log: std::fs::File,
    log_path: PathBuf,
    generation: u64,
    opened_at_unix_ms: u64,
    no_sandbox: bool,
    resume_all_sessions: bool,
    hold_for_promotion: bool,
    #[cfg(unix)]
    control_fd: std::os::fd::RawFd,
    #[cfg(unix)]
    reveal_fd: std::os::fd::RawFd,
    #[cfg(unix)]
    liveness_fd: std::os::fd::RawFd,
}

async fn spawn_ready_worker(request: WorkerSpawnRequest<'_>) -> Result<Worker> {
    #[cfg(unix)]
    let control_fd = {
        use std::os::fd::AsRawFd as _;
        request.endpoints.control.as_raw_fd()
    };
    #[cfg(unix)]
    let reveal_fd = request.endpoints.reveal.raw_fd();
    #[cfg(unix)]
    let liveness_fd = {
        use std::os::fd::AsRawFd as _;
        request.endpoints.liveness_read.as_raw_fd()
    };
    let request = OwnedWorkerSpawnRequest {
        binary: request.binary.to_path_buf(),
        paths: request.paths.clone(),
        log: request.log.try_clone()?,
        log_path: request.log_path.to_path_buf(),
        generation: request.generation,
        opened_at_unix_ms: request.opened_at_unix_ms,
        no_sandbox: request.no_sandbox,
        resume_all_sessions: request.resume_all_sessions,
        hold_for_promotion: request.hold_for_promotion,
        #[cfg(unix)]
        control_fd,
        #[cfg(unix)]
        reveal_fd,
        #[cfg(unix)]
        liveness_fd,
    };
    tokio::task::spawn_blocking(move || spawn_ready_worker_blocking(request))
        .await
        .context("joining worker readiness task")?
}

fn spawn_ready_worker_blocking(request: OwnedWorkerSpawnRequest) -> Result<Worker> {
    #[cfg(unix)]
    use std::os::unix::process::CommandExt as _;
    #[cfg(windows)]
    use std::os::windows::process::CommandExt as _;
    use std::process::{Command, Stdio};

    let stderr = request.log.try_clone()?;
    let mut command = Command::new(&request.binary);
    command
        .args(["daemon", "worker"])
        .env(WORKER_ENV, "1")
        .env(GENERATION_ENV, request.generation.to_string())
        .env(OPENED_AT_ENV, request.opened_at_unix_ms.to_string())
        .env(SUPERVISOR_PID_ENV, std::process::id().to_string())
        .env_remove(REEXEC_STATE_ENV)
        .env_remove("LISTEN_PID")
        .stdin(Stdio::null())
        .stdout(Stdio::from(request.log))
        .stderr(Stdio::from(stderr));
    if request.paths.ephemeral {
        command.env(super::DAEMON_LIFETIME_ENV, super::EPHEMERAL_LIFETIME);
    }
    if request.no_sandbox {
        command.arg("--no-sandbox");
    }
    if request.resume_all_sessions {
        command.arg("--resume-all-sessions");
    }

    #[cfg(windows)]
    let (staged_identity, staged_reveal_identity) =
        windows_staged_identities(&request.paths, request.generation)?;
    #[cfg(windows)]
    {
        remove_if_present(&staged_identity)?;
        remove_if_present(&staged_reveal_identity)?;
        command.env(WINDOWS_IDENTITY_ENV, &staged_identity);
        command.env(WINDOWS_REVEAL_IDENTITY_ENV, &staged_reveal_identity);
    }

    #[cfg(unix)]
    let (ready_read, ready_write) = create_ready_pipe()?;
    #[cfg(unix)]
    let (promotion_read, promotion_write) = if request.hold_for_promotion {
        let (read, write) = create_ready_pipe()?;
        (Some(read), Some(write))
    } else {
        (None, None)
    };
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        let ready_write_fd = ready_write.as_raw_fd();
        let promotion_read_fd = promotion_read.as_ref().map(|fd| fd.as_raw_fd());
        // SAFETY: pre_exec runs in the child. Each source descriptor remains
        // open through `spawn`; dup2 atomically installs the activation ABI.
        unsafe {
            command.pre_exec(move || {
                let safe_control = libc::fcntl(request.control_fd, libc::F_DUPFD, 16);
                let safe_ready = libc::fcntl(ready_write_fd, libc::F_DUPFD, 16);
                let safe_reveal = libc::fcntl(request.reveal_fd, libc::F_DUPFD, 16);
                let safe_liveness = libc::fcntl(request.liveness_fd, libc::F_DUPFD, 16);
                let safe_promotion = promotion_read_fd
                    .map(|fd| libc::fcntl(fd, libc::F_DUPFD, 16))
                    .unwrap_or(-1);
                if safe_control < 0
                    || safe_ready < 0
                    || safe_reveal < 0
                    || safe_liveness < 0
                    || (promotion_read_fd.is_some() && safe_promotion < 0)
                {
                    return Err(std::io::Error::last_os_error());
                }
                let installed = libc::dup2(safe_control, CONTROL_FD) >= 0
                    && libc::dup2(safe_ready, READY_FD) >= 0
                    && libc::dup2(safe_reveal, REVEAL_FD) >= 0
                    && libc::dup2(safe_liveness, LIVENESS_FD) >= 0
                    && (promotion_read_fd.is_none()
                        || libc::dup2(safe_promotion, PROMOTION_FD) >= 0);
                libc::close(safe_control);
                libc::close(safe_ready);
                libc::close(safe_reveal);
                libc::close(safe_liveness);
                if safe_promotion >= 0 {
                    libc::close(safe_promotion);
                }
                if !installed {
                    return Err(std::io::Error::last_os_error());
                }
                for fd in [CONTROL_FD, READY_FD, REVEAL_FD, LIVENESS_FD] {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        command.env("LISTEN_FDS", "1");
        command.env(SUPERVISOR_LIVENESS_ENV, "1");
        if request.hold_for_promotion {
            command.env(HANDOVER_STANDBY_ENV, "1");
        }
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
    let mut child = command.spawn().context("spawning supervised worker")?;
    let pid = child.id();
    #[cfg(unix)]
    {
        drop(ready_write);
        drop(promotion_read);
        enforce_unix_worker_readiness(
            &ready_read,
            &mut child,
            super::DAEMON_SPAWN_TIMEOUT,
            &request.log_path,
            request.generation,
            request.opened_at_unix_ms,
        )?;
    }
    #[cfg(windows)]
    {
        if !wait_windows_identity(&staged_identity, &mut child, super::DAEMON_SPAWN_TIMEOUT)? {
            super::spawn_notify::reap_or_kill(&mut child);
            let _ = remove_if_present(&staged_identity);
            let _ = remove_if_present(&staged_reveal_identity);
            return Err(super::spawn_notify::error_with_log_tail(
                format!("worker pid {pid} did not publish a ready pipe identity"),
                &request.log_path,
            ));
        }
        promote_windows_identity(&staged_reveal_identity, &request.paths.leak_reveal_socket())?;
        promote_windows_identity(&staged_identity, &request.paths.socket)?;
    }
    let receipt = worker_receipt(pid, &request.binary)?;
    #[cfg(windows)]
    let exit_status = match verified_worker_process(&receipt) {
        Ok(process) => process,
        Err(error) => {
            super::spawn_notify::reap_or_kill(&mut child);
            return Err(error);
        }
    };
    let exited = watch_worker(&receipt)?;
    Ok(Worker {
        pid,
        binary: std::fs::canonicalize(&request.binary)?,
        #[cfg(windows)]
        receipt,
        #[cfg(windows)]
        exit_status,
        child: Some(child),
        exited,
        #[cfg(unix)]
        promotion: promotion_write.map(std::fs::File::from),
        #[cfg(unix)]
        serving: request.hold_for_promotion.then_some(ready_read),
    })
}

fn resume_worker(pid: u32, binary: &Path) -> Result<Worker> {
    let receipt = worker_receipt(pid, binary)?;
    #[cfg(windows)]
    let exit_status = verified_worker_process(&receipt)?;
    Ok(Worker {
        pid,
        binary: std::fs::canonicalize(binary)?,
        #[cfg(windows)]
        receipt: receipt.clone(),
        #[cfg(windows)]
        exit_status,
        child: None,
        exited: watch_worker(&receipt)?,
        #[cfg(unix)]
        promotion: None,
        #[cfg(unix)]
        serving: None,
    })
}

fn worker_exit_succeeded(worker: &mut Worker) -> bool {
    if let Some(child) = worker.child.as_mut() {
        return child
            .try_wait()
            .ok()
            .flatten()
            .is_some_and(|status| status.success());
    }
    #[cfg(unix)]
    {
        let mut status = 0;
        // SAFETY: the worker remains a child across an in-place exec and the
        // stable process watcher has already observed its exit.
        let waited = unsafe { libc::waitpid(worker.pid as libc::pid_t, &mut status, 0) };
        waited > 0 && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }
    #[cfg(windows)]
    {
        worker.exit_status.exit_succeeded().unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    false
}

fn reap_worker_after_exit(mut worker: Worker) {
    tokio::spawn(async move {
        match worker.exited.recv().await {
            Some(Ok(())) => {}
            Some(Err(error)) => {
                tracing::error!(pid = worker.pid, %error, "retired worker process watch failed");
            }
            None => {
                tracing::error!(pid = worker.pid, "retired worker process watch stopped");
            }
        }
        if let Some(mut child) = worker.child {
            let _ = child.wait();
        } else {
            #[cfg(unix)]
            {
                let mut status = 0;
                // SAFETY: this process remains the worker's parent across exec.
                let _ = unsafe { libc::waitpid(worker.pid as libc::pid_t, &mut status, 0) };
            }
        }
    });
}

async fn drain_and_reap_worker(worker: &mut Worker, reconnect: bool) -> Result<()> {
    await_drained_worker_exit(worker, reconnect).await?;
    if let Some(child) = worker.child.as_mut() {
        child.wait().context("reaping supervised worker")?;
    } else {
        #[cfg(unix)]
        {
            let mut status = 0;
            // SAFETY: this process remains the worker's parent across exec.
            if unsafe { libc::waitpid(worker.pid as libc::pid_t, &mut status, 0) } < 0 {
                return Err(std::io::Error::last_os_error()).context("reaping supervised worker");
            }
        }
    }
    Ok(())
}

async fn await_drained_worker_exit(worker: &mut Worker, reconnect: bool) -> Result<()> {
    await_drained_worker_exit_with_timeout(worker, reconnect, super::shutdown::SHUTDOWN_DRAIN_GRACE)
        .await
}

async fn await_drained_worker_exit_with_timeout(
    worker: &mut Worker,
    reconnect: bool,
    timeout: Duration,
) -> Result<()> {
    terminate_worker(worker, reconnect)?;
    let exit = match tokio::time::timeout(timeout, worker.exited.recv()).await {
        Ok(exit) => exit,
        Err(_) => {
            tracing::warn!(
                pid = worker.pid,
                "worker exceeded the daemon drain grace; forcing shutdown"
            );
            force_kill_worker(worker)?;
            worker.exited.recv().await
        }
    };
    match exit {
        Some(Ok(())) => {}
        Some(Err(error)) => bail!("stable worker process watch failed while draining: {error}"),
        None => bail!("stable worker process watch stopped while draining"),
    }
    Ok(())
}

#[cfg(unix)]
fn create_ready_pipe() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::FromRawFd as _;
    let mut fds = [-1; 2];
    // Create both ends close-on-exec atomically where the platform can: with
    // a separate `fcntl`, a worker spawned from another thread between
    // `pipe` and `fcntl` would inherit the supervisor-only write end (for the
    // liveness pipe, that child would keep every worker alive past the
    // supervisor's death).
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "illumos",
        target_os = "solaris"
    ))]
    {
        // SAFETY: fds has room for the two descriptors returned by pipe2.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error()).context("creating worker readiness pipe");
        }
    }
    // macOS (and other targets without `pipe2`) fall back to `pipe` plus
    // `fcntl`. The supervisor forks only workers, each from
    // `spawn_ready_worker_blocking`, which dup2s exactly the descriptors a
    // worker may inherit onto fixed slots and relies on close-on-exec for
    // everything else, so the window is limited to a concurrent worker spawn.
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "illumos",
        target_os = "solaris"
    )))]
    {
        // SAFETY: fds has room for the two descriptors returned by pipe.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error()).context("creating worker readiness pipe");
        }
        for fd in fds {
            // SAFETY: successful pipe returned both live descriptors.
            if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                let error = std::io::Error::last_os_error();
                // SAFETY: both descriptors remain owned locally on this failure.
                unsafe {
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                }
                return Err(error).context("setting readiness pipe close-on-exec");
            }
        }
    }
    // SAFETY: a successful pipe/pipe2 returned two newly owned descriptors.
    Ok(unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(fds[0]),
            std::os::fd::OwnedFd::from_raw_fd(fds[1]),
        )
    })
}

#[cfg(unix)]
fn wait_ready_report(
    read: impl std::os::fd::AsFd,
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<Option<WorkerReadyReport>> {
    use std::os::fd::AsRawFd as _;
    let deadline = Instant::now() + timeout;
    let fd = read.as_fd().as_raw_fd();
    // A readiness writer is untrusted until its whole hello has been
    // validated. Make the pipe nonblocking so a partial frame cannot park
    // the supervisor after poll has reported its first byte.
    // SAFETY: fd is borrowed from the live readiness-pipe owner.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    // SAFETY: fd remains live and only its nonblocking status changes.
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error())
            .context("making worker readiness pipe nonblocking");
    }
    let mut encoded = Vec::new();
    loop {
        if child.try_wait()?.is_some() {
            return Ok(None);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("timed out waiting for worker pid {} readiness", child.id());
        }
        let millis = remaining.as_millis().min(100) as libc::c_int;
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd refers to the live pipe descriptor for one bounded wait.
        let ready = unsafe { libc::poll(&mut pollfd, 1, millis) };
        if ready < 0 {
            return Err(std::io::Error::last_os_error()).context("polling worker readiness");
        }
        if ready > 0 {
            let mut chunk = [0_u8; 4096];
            loop {
                // SAFETY: fd is owned by `read`, and chunk is a live writable
                // buffer for exactly this syscall.
                let bytes = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
                if bytes > 0 {
                    let bytes = usize::try_from(bytes).expect("positive read fits usize");
                    if encoded.len().saturating_add(bytes) > MAX_ADMIN_LINE {
                        bail!("worker readiness hello exceeds maximum frame length");
                    }
                    encoded.extend_from_slice(&chunk[..bytes]);
                    if let Some(newline) = encoded.iter().position(|byte| *byte == b'\n') {
                        return serde_json::from_slice(&encoded[..newline])
                            .map(Some)
                            .context("decoding worker readiness hello");
                    }
                    continue;
                }
                if bytes == 0 {
                    if encoded.is_empty() {
                        return Ok(None);
                    }
                    return serde_json::from_slice(&encoded)
                        .map(Some)
                        .context("decoding worker readiness hello");
                }
                let error = std::io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::EAGAIN) => break,
                    _ => return Err(error).context("reading worker readiness hello"),
                }
            }
        }
    }
}

#[cfg(unix)]
fn enforce_unix_worker_readiness(
    read: impl std::os::fd::AsFd,
    child: &mut std::process::Child,
    timeout: Duration,
    log_path: &Path,
    expected_generation: u64,
    expected_opened_at_unix_ms: u64,
) -> Result<()> {
    match wait_ready_report(read, child, timeout) {
        Ok(Some(report))
            if report.protocol_version == super::proto::PROTOCOL_VERSION
                && report.pid == child.id()
                && report.generation == expected_generation
                && report.opened_at_unix_ms == expected_opened_at_unix_ms =>
        {
            Ok(())
        }
        Ok(Some(report)) => {
            let pid = child.id();
            super::spawn_notify::reap_or_kill(child);
            Err(super::spawn_notify::error_with_log_tail(
                format!(
                    "worker pid {pid} readiness hello mismatch: expected protocol {} generation {expected_generation} open time {expected_opened_at_unix_ms}, got {report:?}",
                    super::proto::PROTOCOL_VERSION,
                ),
                log_path,
            ))
        }
        Ok(None) => {
            let pid = child.id();
            super::spawn_notify::reap_or_kill(child);
            Err(super::spawn_notify::error_with_log_tail(
                format!("worker pid {pid} exited before signaling readiness"),
                log_path,
            ))
        }
        Err(error) => {
            let pid = child.id();
            super::spawn_notify::reap_or_kill(child);
            Err(super::spawn_notify::error_with_log_tail(
                format!("worker pid {pid} readiness failed: {error:#}"),
                log_path,
            ))
        }
    }
}

#[cfg(windows)]
fn wait_windows_identity(
    identity: &Path,
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(false);
        }
        if cockpit_host::named_pipe::read_pipe_identity_if_present(identity)
            .ok()
            .flatten()
            .is_some_and(|pipe| cockpit_host::named_pipe::pipe_is_listening(&pipe))
        {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(windows)]
fn windows_staged_identities(paths: &DaemonPaths, generation: u64) -> Result<(PathBuf, PathBuf)> {
    let parent = paths
        .socket
        .parent()
        .context("daemon identity path has no parent")?;
    Ok((
        parent.join(format!("worker-{generation}.pipe.json")),
        parent.join(format!("worker-{generation}.reveal.pipe.json")),
    ))
}

#[cfg(windows)]
fn promote_windows_identity(staged: &Path, canonical: &Path) -> Result<()> {
    let pipe = cockpit_host::named_pipe::read_pipe_identity(staged)?;
    cockpit_host::named_pipe::write_pipe_identity(canonical, &pipe)?;
    remove_if_present(staged)
}

fn worker_receipt(
    pid: u32,
    binary: &Path,
) -> Result<cockpit_host::daemon_lifecycle::DaemonPidReceipt> {
    Ok(cockpit_host::daemon_lifecycle::DaemonPidReceipt {
        pid,
        executable: std::fs::canonicalize(binary)?,
        process_start: cockpit_host::daemon_lifecycle::process_start_identity(pid)?,
        publication_nonce: [0; 32],
    })
}

fn watch_worker(
    receipt: &cockpit_host::daemon_lifecycle::DaemonPidReceipt,
) -> Result<tokio::sync::mpsc::Receiver<std::result::Result<(), String>>> {
    watch_worker_with_interval(receipt, Duration::from_secs(365 * 24 * 60 * 60))
}

#[cfg(windows)]
fn verified_worker_process(
    receipt: &cockpit_host::daemon_lifecycle::DaemonPidReceipt,
) -> Result<cockpit_host::daemon_lifecycle::VerifiedDaemonProcess> {
    match cockpit_host::daemon_lifecycle::acquire_verified_daemon_process(receipt) {
        cockpit_host::daemon_lifecycle::VerifiedProcessOutcome::Verified(process) => Ok(process),
        cockpit_host::daemon_lifecycle::VerifiedProcessOutcome::Identity(identity) => {
            bail!("could not acquire stable worker exit-status witness: {identity:?}")
        }
    }
}

fn watch_worker_with_interval(
    receipt: &cockpit_host::daemon_lifecycle::DaemonPidReceipt,
    interval: Duration,
) -> Result<tokio::sync::mpsc::Receiver<std::result::Result<(), String>>> {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        windows
    ))]
    {
        use cockpit_host::daemon_lifecycle::{PidIdentity, VerifiedProcessOutcome};
        let process = match cockpit_host::daemon_lifecycle::acquire_verified_daemon_process(receipt)
        {
            VerifiedProcessOutcome::Verified(process) => process,
            VerifiedProcessOutcome::Identity(identity) => {
                bail!("could not acquire stable worker process witness: {identity:?}")
            }
        };
        let receipt = receipt.clone();
        tokio::spawn(async move {
            let mut process = process;
            let outcome = loop {
                match process.wait_for_exit(interval).await {
                    Ok(true) => break Ok(()),
                    Ok(false) => {
                        process =
                            match cockpit_host::daemon_lifecycle::acquire_verified_daemon_process(
                                &receipt,
                            ) {
                                VerifiedProcessOutcome::Verified(process) => process,
                                VerifiedProcessOutcome::Identity(
                                    PidIdentity::Missing | PidIdentity::NotDaemon,
                                ) => break Ok(()),
                                VerifiedProcessOutcome::Identity(identity) => {
                                    break Err(format!(
                                        "could not re-arm stable worker process witness: {identity:?}"
                                    ));
                                }
                            };
                    }
                    Err(error) => break Err(error.to_string()),
                }
            };
            let _ = tx.send(outcome).await;
        });
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        windows
    )))]
    {
        let _ = (receipt, tx);
    }
    Ok(rx)
}

fn publish_generation(
    paths: &DaemonPaths,
    receipt: &cockpit_host::daemon_lifecycle::DaemonPidReceipt,
    worker_pid: u32,
    generation: u64,
    opened_at_unix_ms: u64,
) -> Result<()> {
    let path = paths
        .pid_file
        .parent()
        .map(super::endpoint_file_for_state)
        .context("daemon pid path has no parent")?;
    let record = super::rendezvous::Record {
        pid: receipt.pid,
        start_time: receipt.process_start,
        socket_path: paths.socket.clone(),
        protocol_version: super::proto::PROTOCOL_VERSION,
        daemon_version: super::proto::DAEMON_VERSION.to_string(),
        worker_pid: Some(worker_pid),
        generation,
        opened_at_unix_ms,
        receipt: receipt.clone(),
        ephemeral: paths.ephemeral,
    };
    cockpit_host::daemon_lifecycle::with_lifecycle_lock(&paths.pid_file, || {
        if cockpit_host::daemon_lifecycle::read_daemon_pid_record(&paths.pid_file)
            != Some(receipt.clone())
        {
            bail!("supervisor receipt changed before generation publication");
        }
        super::rendezvous::write(&path, &record)
    })
}

fn status_response(
    worker_pid: u32,
    generation: u64,
    opened_at_unix_ms: u64,
    last_handover: Option<String>,
) -> AdminResponse {
    status_response_at(
        worker_pid,
        generation,
        opened_at_unix_ms,
        now_unix_ms(),
        last_handover,
    )
}

fn status_response_at(
    worker_pid: u32,
    generation: u64,
    opened_at_unix_ms: u64,
    now_unix_ms: u64,
    last_handover: Option<String>,
) -> AdminResponse {
    AdminResponse::Status {
        version: ADMIN_PROTOCOL_VERSION,
        supervisor_pid: std::process::id(),
        worker_pid,
        generation,
        uptime_ms: now_unix_ms.saturating_sub(opened_at_unix_ms),
        last_handover,
    }
}

#[cfg(unix)]
fn terminate_worker(worker: &mut Worker, reconnect: bool) -> Result<()> {
    let signal = if reconnect {
        libc::SIGUSR1
    } else {
        libc::SIGTERM
    };
    let pid = libc::pid_t::try_from(worker.pid).context("worker pid does not fit pid_t")?;
    // SAFETY: pid is range checked. The supervisor retains the exact Child and
    // stable watcher until this generation exits.
    if unsafe { libc::kill(pid, signal) } != 0 {
        return Err(std::io::Error::last_os_error()).context("signaling supervised worker");
    }
    Ok(())
}

#[cfg(unix)]
fn force_kill_worker(worker: &mut Worker) -> Result<()> {
    let pid = libc::pid_t::try_from(worker.pid).context("worker pid does not fit pid_t")?;
    // SAFETY: pid is range checked. The supervisor retains the exact Child and
    // stable watcher until this generation exits.
    if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
        let error = std::io::Error::last_os_error();
        // The watcher can lag a process which exited just as the grace timer
        // elapsed. There is nothing left to signal in that case; keep waiting
        // for its authoritative exit observation.
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error).context("force-killing supervised worker");
        }
    }
    Ok(())
}

#[cfg(unix)]
fn signal_worker_handover_decision(worker: &Worker, commit: bool) -> Result<()> {
    let signal = if commit { libc::SIGUSR2 } else { libc::SIGURG };
    let pid = libc::pid_t::try_from(worker.pid).context("worker pid does not fit pid_t")?;
    // SAFETY: the supervisor retains the exact Child and watcher for this worker.
    if unsafe { libc::kill(pid, signal) } != 0 {
        return Err(std::io::Error::last_os_error()).context("signaling worker handover decision");
    }
    Ok(())
}

#[cfg(windows)]
fn signal_worker_handover_decision(_worker: &Worker, _commit: bool) -> Result<()> {
    bail!("boundary-aware worker handover is not available on Windows")
}

/// Release a staged successor and wait until it reaches its publication
/// barrier.
///
/// A standby does no durable work before promotion, so it opens the database,
/// recovers, and builds its services only now. Clients queued on the inherited
/// listener get no hello until then, so the roll is not complete, and must not
/// be reported or published as complete, before the successor's second fd-4
/// report arrives.
async fn release_ready_successor(
    worker: &mut Worker,
    generation: u64,
    opened_at_unix_ms: u64,
    log_path: &Path,
) -> Result<()> {
    promote_ready_worker(worker).context("releasing ready successor")?;
    #[cfg(unix)]
    {
        let serving = worker
            .serving
            .take()
            .context("rolling successor has no serving report channel")?;
        let mut child = worker
            .child
            .take()
            .context("rolling successor is not a supervised child")?;
        let log_path = log_path.to_path_buf();
        // The wait owns the `Child` only for its duration and always hands it
        // back, a panic included, so the caller can still signal and reap the
        // exact child on any failure.
        let (child, serving) = tokio::task::spawn_blocking(move || {
            let serving = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                enforce_unix_worker_readiness(
                    &serving,
                    &mut child,
                    super::DAEMON_SPAWN_TIMEOUT,
                    &log_path,
                    generation,
                    opened_at_unix_ms,
                )
            }))
            .unwrap_or_else(|_| Err(anyhow::anyhow!("released successor serving wait panicked")));
            (child, serving)
        })
        .await
        .context("joining released successor serving wait")?;
        worker.child = Some(child);
        serving.context("waiting for released successor to serve")?;
    }
    #[cfg(not(unix))]
    let _ = (generation, opened_at_unix_ms, log_path);
    Ok(())
}

#[cfg(unix)]
fn promote_ready_worker(worker: &mut Worker) -> Result<()> {
    use std::io::Write as _;
    let mut promotion = worker
        .promotion
        .take()
        .context("rolling successor has no promotion channel")?;
    promotion
        .write_all(b"P")
        .context("releasing rolling successor")?;
    promotion
        .flush()
        .context("flushing rolling successor release")
}

#[cfg(windows)]
fn promote_ready_worker(_worker: &mut Worker) -> Result<()> {
    Ok(())
}

async fn await_worker_exit(worker: &mut Worker) -> Result<()> {
    match worker.exited.recv().await {
        Some(Ok(())) => {}
        Some(Err(error)) => {
            bail!("stable worker process watch failed while waiting for exit: {error}")
        }
        None => bail!("stable worker process watch stopped while waiting for exit"),
    }
    if let Some(child) = worker.child.as_mut() {
        child.wait().context("reaping retired worker")?;
    }
    Ok(())
}

#[cfg(windows)]
fn terminate_worker(worker: &mut Worker, _reconnect: bool) -> Result<()> {
    cockpit_host::daemon_lifecycle::terminate_verified_daemon_process(&worker.receipt)
        .context("terminating supervised worker")
}

#[cfg(windows)]
fn reap_retired_worker(mut worker: Worker) {
    tokio::spawn(async move {
        if let Err(error) = await_drained_worker_exit(&mut worker, true).await {
            tracing::error!(pid = worker.pid, %error, "retired worker process watch failed");
        }
        if let Some(mut child) = worker.child {
            let _ = child.wait();
        }
    });
}

#[cfg(windows)]
fn force_kill_worker(worker: &mut Worker) -> Result<()> {
    if let Some(child) = worker.child.as_mut() {
        child.kill().context("force-killing supervised worker")?;
        return Ok(());
    }
    cockpit_host::daemon_lifecycle::terminate_verified_daemon_process(&worker.receipt)
        .context("force-killing supervised worker")
}

async fn wait_for_worker_boundary(
    admin: &mut AdminListener,
    expected_worker_pid: u32,
    expected_generation: u64,
    timeout: Duration,
    opened_at_unix_ms: u64,
    last_handover: Option<String>,
) -> Result<Vec<super::proto::SessionBoundaryMarker>> {
    tokio::time::timeout(timeout, async {
        loop {
            let stream = accept_admin(admin).await?;
            // A malformed or vanished admin client is that connection's
            // failure, never the handover's.
            let (request, mut stream) = match read_admin(stream).await {
                Ok(value) => value,
                Err(error) => {
                    tracing::warn!(%error, "rejecting malformed supervisor admin request during handover");
                    continue;
                }
            };
            if request.version != ADMIN_PROTOCOL_VERSION {
                reply_admin(
                    &mut stream,
                    &AdminResponse::Error {
                        version: ADMIN_PROTOCOL_VERSION,
                        message: "unsupported supervisor admin protocol".to_string(),
                    },
                )
                .await;
                continue;
            }
            match request.command {
                AdminCommand::Status => {
                    reply_admin(
                        &mut stream,
                        &status_response(
                            expected_worker_pid,
                            expected_generation,
                            opened_at_unix_ms,
                            last_handover.clone(),
                        ),
                    )
                    .await;
                }
                AdminCommand::Stop => {
                    reply_admin(
                        &mut stream,
                        &AdminResponse::Stopping {
                            version: ADMIN_PROTOCOL_VERSION,
                        },
                    )
                    .await;
                    bail!("administrative stop requested during worker handover");
                }
                AdminCommand::WorkerBoundary {
                    worker_pid,
                    generation,
                    last_boundary,
                } if worker_pid == expected_worker_pid && generation == expected_generation => {
                    reply_admin(
                        &mut stream,
                        &status_response(
                            expected_worker_pid,
                            expected_generation,
                            opened_at_unix_ms,
                            last_handover,
                        ),
                    )
                    .await;
                    return Ok(last_boundary);
                }
                _ => {
                    reply_admin(
                        &mut stream,
                        &AdminResponse::Error {
                            version: ADMIN_PROTOCOL_VERSION,
                            message: "worker handover is in progress".to_string(),
                        },
                    )
                    .await;
                }
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("T_drain + T_hard elapsed before predecessor boundary"))?
}

async fn wait_for_worker_handover_ready(
    admin: &mut AdminListener,
    successor: &mut Worker,
    expected_worker_pid: u32,
    expected_generation: u64,
    timeout: Duration,
    opened_at_unix_ms: u64,
    last_handover: Option<String>,
) -> Result<()> {
    tokio::time::timeout(timeout, async {
        loop {
            let stream = tokio::select! {
                exit = successor.exited.recv() => match exit {
                    Some(Ok(())) => bail!("staged successor pid {} exited before handover commitment", successor.pid),
                    Some(Err(error)) => bail!("staged successor pid {} process watch failed before handover commitment: {error}", successor.pid),
                    None => bail!("staged successor pid {} process watch stopped before handover commitment", successor.pid),
                },
                stream = accept_admin(admin) => stream?,
            };
            // A malformed or vanished admin client is that connection's
            // failure, never the handover's.
            let (request, mut stream) = match read_admin(stream).await {
                Ok(value) => value,
                Err(error) => {
                    tracing::warn!(%error, "rejecting malformed supervisor admin request during handover");
                    continue;
                }
            };
            if request.version != ADMIN_PROTOCOL_VERSION {
                reply_admin(
                    &mut stream,
                    &AdminResponse::Error {
                        version: ADMIN_PROTOCOL_VERSION,
                        message: "unsupported supervisor admin protocol".to_string(),
                    },
                )
                .await;
                continue;
            }
            match request.command {
                AdminCommand::Status => {
                    reply_admin(
                        &mut stream,
                        &status_response(
                            expected_worker_pid,
                            expected_generation,
                            opened_at_unix_ms,
                            last_handover.clone(),
                        ),
                    )
                    .await;
                }
                AdminCommand::Stop => {
                    reply_admin(
                        &mut stream,
                        &AdminResponse::Stopping {
                            version: ADMIN_PROTOCOL_VERSION,
                        },
                    )
                    .await;
                    bail!("administrative stop requested during worker handover");
                }
                AdminCommand::WorkerHandoverReady {
                    worker_pid,
                    generation,
                } if worker_pid == expected_worker_pid && generation == expected_generation => {
                    ensure_staged_successor_live(successor)?;
                    reply_admin(
                        &mut stream,
                        &status_response(
                            expected_worker_pid,
                            expected_generation,
                            opened_at_unix_ms,
                            last_handover,
                        ),
                    )
                    .await;
                    return Ok(());
                }
                _ => {
                    reply_admin(
                        &mut stream,
                        &AdminResponse::Error {
                            version: ADMIN_PROTOCOL_VERSION,
                            message: "worker handover is in progress".to_string(),
                        },
                    )
                    .await;
                }
            }
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!("T_drain elapsed before predecessor handover-ready acknowledgement")
    })?
}

/// Close the tiny gap between an exit-watch wakeup and the predecessor's
/// commit signal.  The child handle is checked too because the process watch
/// is intentionally asynchronous.
fn ensure_staged_successor_live(successor: &mut Worker) -> Result<()> {
    match successor.exited.try_recv() {
        Ok(Ok(())) => bail!(
            "staged successor pid {} exited before handover commitment",
            successor.pid
        ),
        Ok(Err(error)) => bail!(
            "staged successor pid {} process watch failed before handover commitment: {error}",
            successor.pid
        ),
        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => bail!(
            "staged successor pid {} process watch stopped before handover commitment",
            successor.pid
        ),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
    }
    if let Some(child) = successor.child.as_mut()
        && let Some(status) = child
            .try_wait()
            .context("checking staged successor liveness before handover commitment")?
    {
        bail!(
            "staged successor pid {} exited with status {status} before handover commitment",
            successor.pid
        );
    }
    Ok(())
}

#[cfg(unix)]
type AdminListener = tokio::net::UnixListener;
#[cfg(windows)]
type AdminListener = super::windows_pipe::NamedPipeListener;

fn bind_admin(path: &Path) -> Result<AdminListener> {
    #[cfg(unix)]
    return super::bind_private_socket(path);
    #[cfg(windows)]
    return super::windows_pipe::NamedPipeListener::bind(path);
}

#[cfg(unix)]
fn prepare_admin_for_reexec(listener: &AdminListener) -> Result<std::os::fd::RawFd> {
    use std::os::fd::AsRawFd as _;
    let fd = listener.as_raw_fd();
    clear_close_on_exec(fd)?;
    Ok(fd)
}

#[cfg(unix)]
// SAFETY: callers transfer unique ownership of the inherited admin descriptor.
unsafe fn resume_admin(fd: std::os::fd::RawFd) -> Result<AdminListener> {
    use std::os::fd::FromRawFd as _;
    // SAFETY: upheld by this function's caller contract.
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    set_close_on_exec(fd)?;
    listener.set_nonblocking(true)?;
    Ok(tokio::net::UnixListener::from_std(listener)?)
}

async fn accept_admin(listener: &mut AdminListener) -> Result<DaemonStream> {
    #[cfg(unix)]
    return listener
        .accept()
        .await
        .map(|(stream, _)| stream)
        .context("accepting supervisor admin connection");
    #[cfg(windows)]
    return listener.accept().await;
}

/// Bound on one admin connection's request read and reply write. The
/// supervisor serves admin connections inline in its supervision loop (and in
/// the handover waits), so a client that connects and then stays silent — or
/// never drains its reply — must fail that connection alone instead of
/// stalling worker supervision, shutdown, and every other admin client.
/// Legitimate clients (the CLI and worker announcements) write their one
/// request line immediately after connecting.
const ADMIN_CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(2);

async fn read_admin<S>(stream: S) -> Result<(AdminRequest, S)>
where
    S: AsyncRead + Unpin,
{
    read_admin_within(stream, ADMIN_CONNECTION_IO_TIMEOUT).await
}

async fn read_admin_within<S>(stream: S, timeout: Duration) -> Result<(AdminRequest, S)>
where
    S: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(stream);
    let request = tokio::time::timeout(timeout, read_admin_request(&mut reader))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "supervisor admin client sent no request within {}ms",
                timeout.as_millis()
            )
        })??;
    Ok((request, reader.into_inner()))
}

async fn read_admin_request<R>(reader: &mut R) -> Result<AdminRequest>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut line = String::new();
    let read = reader.read_line(&mut line).await?;
    if read == 0 || line.len() > MAX_ADMIN_LINE {
        bail!("invalid supervisor admin frame length");
    }
    serde_json::from_str(line.trim_end()).context("decoding supervisor admin frame")
}

/// Reply on one admin connection. A reply failure (typically `EPIPE` from a
/// client that disconnected before reading) belongs to that connection alone:
/// it must never exit the supervisor, whose death would take the healthy
/// worker down with it through the liveness pipe.
async fn reply_admin<W>(stream: &mut W, response: &AdminResponse)
where
    W: AsyncWrite + Unpin,
{
    if let Err(error) = write_admin(stream, response).await {
        tracing::warn!(%error, "supervisor admin client went away before its reply");
    }
}

async fn write_admin<W>(stream: &mut W, response: &AdminResponse) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut line = serde_json::to_vec(response)?;
    line.push(b'\n');
    tokio::time::timeout(ADMIN_CONNECTION_IO_TIMEOUT, async {
        stream.write_all(&line).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "supervisor admin client did not accept its reply within {}ms",
            ADMIN_CONNECTION_IO_TIMEOUT.as_millis()
        )
    })??;
    Ok(())
}

pub async fn request(paths: &DaemonPaths, command: AdminCommand) -> Result<AdminResponse> {
    let path = admin_socket(paths)?;
    #[cfg(unix)]
    let stream = tokio::net::UnixStream::connect(&path)
        .await
        .with_context(|| format!("connecting supervisor admin socket {}", path.display()))?;
    #[cfg(windows)]
    let stream = {
        let pipe = cockpit_host::named_pipe::read_pipe_identity(&path)?;
        cockpit_host::named_pipe::connect_client_pipe(&pipe).await?
    };
    let mut stream = stream;
    let request = AdminRequest {
        version: ADMIN_PROTOCOL_VERSION,
        command,
    };
    let mut line = serde_json::to_vec(&request)?;
    line.push(b'\n');
    stream.write_all(&line).await?;
    stream.flush().await?;
    let mut reader = BufReader::new(stream);
    line.clear();
    let read = reader.read_until(b'\n', &mut line).await?;
    if read == 0 || line.len() > MAX_ADMIN_LINE {
        bail!("supervisor closed admin connection without a valid response");
    }
    serde_json::from_slice(&line).context("decoding supervisor admin response")
}

/// [`request`] bounded by `timeout` end to end (connect, write, and reading
/// the response). A supervisor that accepts the connection but never answers
/// — for example a wedged or foreign process holding the admin endpoint —
/// yields an error once the budget elapses instead of hanging the caller.
pub async fn request_with_timeout(
    paths: &DaemonPaths,
    command: AdminCommand,
    timeout: Duration,
) -> Result<AdminResponse> {
    tokio::time::timeout(timeout, request(paths, command))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "supervisor admin request did not complete within {}ms",
                timeout.as_millis()
            )
        })?
}

/// Synchronous compatibility entry point for lifecycle callers that predate
/// the async admin protocol, bounded by `timeout` like
/// [`request_with_timeout`]. The runtime lives on a dedicated thread so this
/// remains safe when called from a current-thread Tokio executor.
pub fn request_blocking(
    paths: &DaemonPaths,
    command: AdminCommand,
    timeout: Duration,
) -> Result<AdminResponse> {
    let paths = paths.clone();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building supervisor admin runtime")?
            .block_on(request_with_timeout(&paths, command, timeout))
    })
    .join()
    .map_err(|_| anyhow::anyhow!("supervisor admin request thread panicked"))?
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut int = signal(SignalKind::interrupt()).ok();
    let mut term = signal(SignalKind::terminate()).ok();
    tokio::select! {
        _ = async { if let Some(signal) = int.as_mut() { signal.recv().await; } } => {}
        _ = async { if let Some(signal) = term.as_mut() { signal.recv().await; } } => {}
    }
}

#[cfg(windows)]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(windows)]
fn acquire_database_owner_until(deadline: Instant) -> Result<crate::db::SupervisorDatabaseOwner> {
    loop {
        match crate::db::SupervisorDatabaseOwner::acquire_default() {
            Ok(owner) => return Ok(owner),
            Err(_error) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => {
                return Err(error).context("acquiring reexec supervisor database lifetime");
            }
        }
    }
}

#[cfg(unix)]
fn clear_close_on_exec(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    // SAFETY: callers provide a live descriptor and F_GETFD does not mutate it.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd remains live; only the close-on-exec bit changes.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn set_close_on_exec(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    // SAFETY: callers provide a live descriptor and F_GETFD does not mutate it.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd remains live; only the close-on-exec bit changes.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

struct ReexecRequest<'a> {
    executable: &'a Path,
    #[cfg(unix)]
    metadata: &'a cockpit_host::daemon_lifecycle::ForegroundMetadataGuard,
    #[cfg(unix)]
    endpoints: &'a EndpointOwner,
    #[cfg(unix)]
    admin: &'a AdminListener,
    #[cfg(unix)]
    database_owner: &'a crate::db::SupervisorDatabaseOwner,
    worker: &'a Worker,
    generation: u64,
    highest_attempted_generation: u64,
    opened_at_unix_ms: u64,
    no_sandbox: bool,
    resume_all_sessions: bool,
}

#[cfg(unix)]
fn reexec_supervisor(request: ReexecRequest<'_>) -> Result<()> {
    use std::os::unix::process::CommandExt as _;
    let (lifetime_fd, pid_lock_fd) = request.metadata.prepare_for_reexec()?;
    let (control_fd, reveal_fd, liveness_fds) = request.endpoints.prepare_for_reexec()?;
    let admin_fd = prepare_admin_for_reexec(request.admin)?;
    let database_lock_fd = request.database_owner.raw_fd();
    clear_close_on_exec(database_lock_fd)?;
    let state = serde_json::to_string(&ReexecState {
        database_lock_fd,
        lifetime_fd,
        pid_lock_fd,
        control_fd,
        reveal_fd,
        admin_fd,
        liveness_fds: Some(liveness_fds),
        worker_pid: request.worker.pid,
        worker_binary: request.worker.binary.clone(),
        generation: request.generation,
        highest_attempted_generation: request.highest_attempted_generation,
        opened_at_unix_ms: request.opened_at_unix_ms,
    })?;
    let mut command = std::process::Command::new(request.executable);
    command
        .args(["daemon", "supervise", "--reexec-child"])
        .env(REEXEC_STATE_ENV, state);
    if request.no_sandbox {
        command.arg("--no-sandbox");
    }
    if request.resume_all_sessions {
        command.arg("--resume-all-sessions");
    }
    let error = command.exec();
    Err(error).context("re-executing supervisor")
}

#[cfg(windows)]
fn reexec_supervisor(request: ReexecRequest<'_>) -> Result<()> {
    use std::os::windows::process::CommandExt as _;

    let state = serde_json::to_string(&ReexecState {
        worker_pid: request.worker.pid,
        worker_binary: request.worker.binary.clone(),
        generation: request.generation,
        highest_attempted_generation: request.highest_attempted_generation,
        opened_at_unix_ms: request.opened_at_unix_ms,
    })?;
    let mut command = std::process::Command::new(request.executable);
    command
        .args(["daemon", "supervise", "--reexec-child"])
        .env(REEXEC_STATE_ENV, state)
        .creation_flags(0x0800_0000);
    if request.no_sandbox {
        command.arg("--no-sandbox");
    }
    if request.resume_all_sessions {
        command.arg("--resume-all-sessions");
    }
    command.spawn().context("spawning replacement supervisor")?;
    // Windows has no exec(2). Exiting without Rust cleanup preserves the
    // worker-owned pipe identity until the replacement acquires the released
    // lifetime mutex and republishes the supervisor receipt.
    std::process::exit(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn retiring_committed_handover_releases_reconnect_waiter() {
        WORKER_HANDOVER_ACTIVE.store(true, Ordering::Release);
        WORKER_HANDOVER_HARD_INTERRUPT.store(true, Ordering::Release);
        WORKER_HANDOVER_RECONNECT_DISPATCHED.store(false, Ordering::Release);
        WORKER_HANDOVER_DECISION.store(1, Ordering::Release);

        let waiter = tokio::spawn(wait_for_worker_handover_reconnect_dispatch());
        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "a committed handover must wait for reconnect or retirement"
        );

        retire_worker_handover();
        assert!(
            !waiter.await.unwrap(),
            "retiring a committed handover must release the accept-loop waiter"
        );
        assert!(!worker_handover_active());
        assert!(!worker_handover_hard_interrupting());
        WORKER_HANDOVER_DECISION.store(0, Ordering::Release);
    }

    #[tokio::test]
    async fn admin_protocol_rejects_public_proto_shape() {
        let public_frame = format!(
            "{{\"v\":{},\"kind\":\"request\",\"id\":1,\"request\":{{\"type\":\"status\"}}}}\n",
            super::super::proto::PROTOCOL_VERSION
        );
        let mut reader = BufReader::new(std::io::Cursor::new(public_frame.into_bytes()));

        let error = read_admin_request(&mut reader).await.unwrap_err();

        assert!(format!("{error:#}").contains("decoding supervisor admin frame"));
    }

    #[test]
    fn status_clock_is_continuous_across_worker_generations() {
        let first = status_response_at(101, 4, 1_000, 6_000, None);
        let replacement = status_response_at(
            202,
            5,
            1_000,
            6_750,
            Some("completed: generation 5".to_string()),
        );
        assert!(matches!(
            first,
            AdminResponse::Status {
                worker_pid: 101,
                generation: 4,
                uptime_ms: 5_000,
                ..
            }
        ));
        assert!(matches!(
            replacement,
            AdminResponse::Status {
                worker_pid: 202,
                generation: 5,
                uptime_ms: 5_750,
                last_handover: Some(ref outcome),
                ..
            } if outcome == "completed: generation 5"
        ));
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        windows
    ))]
    #[tokio::test]
    async fn worker_watch_rearms_until_the_process_exits() {
        let binary = super::super::discover_daemon_spawn_harness_executable().unwrap();
        let mut child = std::process::Command::new(&binary)
            .args(["daemon", "worker"])
            .env("COCKPIT_WORKER_WATCH_TEST_HOLD", "1")
            .spawn()
            .unwrap();
        let receipt = worker_receipt(child.id(), &binary).unwrap();
        let mut exited = watch_worker_with_interval(&receipt, Duration::from_millis(10)).unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(60), exited.recv())
                .await
                .is_err(),
            "a live process must remain watched across repeated interval bounds"
        );
        child.kill().unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), exited.recv())
                .await
                .unwrap(),
            Some(Ok(()))
        );
        child.wait().unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn resumed_worker_clean_exit_is_recognized_after_windows_reexec() {
        let binary = super::super::discover_daemon_spawn_harness_executable().unwrap();
        let mut child = std::process::Command::new(&binary)
            .args(["daemon", "worker"])
            .env("COCKPIT_WORKER_WATCH_TEST_EXIT_SUCCESS", "1")
            .spawn()
            .unwrap();
        let receipt = worker_receipt(child.id(), &binary).unwrap();
        let mut worker = Worker {
            pid: child.id(),
            binary: std::fs::canonicalize(&binary).unwrap(),
            receipt: receipt.clone(),
            exit_status: verified_worker_process(&receipt).unwrap(),
            child: None,
            exited: watch_worker(&receipt).unwrap(),
        };

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), worker.exited.recv())
                .await
                .unwrap(),
            Some(Ok(()))
        );
        assert!(worker_exit_succeeded(&mut worker));
        child.wait().unwrap();
    }

    #[tokio::test]
    async fn readiness_failures_retry_until_a_worker_is_ready() {
        let mut storm = cockpit_client::RestartStormGuard::default();
        let mut generations = WorkerGenerations::above(7);
        let mut generation = 7;
        let mut attempts = Vec::new();

        let worker = retry_worker_spawn(
            &mut storm,
            &mut generations,
            &TestFence::readable(0),
            &mut generation,
            |attempt_generation| {
                attempts.push(attempt_generation);
                std::future::ready(if attempt_generation < 10 {
                    Err(anyhow::anyhow!("controlled readiness failure"))
                } else {
                    Ok(101_u32)
                })
            },
        )
        .await;

        assert_eq!(worker, Some(101));
        assert_eq!(generation, 10);
        assert_eq!(attempts, vec![8, 9, 10]);
    }

    #[tokio::test]
    async fn readiness_failures_exhaust_the_shared_restart_budget() {
        let mut storm = cockpit_client::RestartStormGuard::default();
        let mut generations = WorkerGenerations::above(11);
        let mut generation = 11;
        let mut attempts = Vec::new();

        let worker = retry_worker_spawn(
            &mut storm,
            &mut generations,
            &TestFence::readable(0),
            &mut generation,
            |attempt_generation| {
                attempts.push(attempt_generation);
                std::future::ready(Err::<u32, _>(anyhow::anyhow!(
                    "controlled readiness failure"
                )))
            },
        )
        .await;

        assert_eq!(worker, None);
        assert_eq!(generation, 14);
        assert_eq!(attempts, vec![12, 13, 14]);
    }

    #[cfg(unix)]
    #[test]
    fn reexec_state_carries_highest_attempted_and_accepts_older_state() {
        let older: ReexecState = serde_json::from_value(serde_json::json!({
            "database_lock_fd": 3,
            "lifetime_fd": 4,
            "pid_lock_fd": 5,
            "control_fd": 6,
            "reveal_fd": 7,
            "admin_fd": 8,
            "worker_pid": 42,
            "worker_binary": "/usr/bin/cockpit",
            "generation": 9,
            "opened_at_unix_ms": 1,
        }))
        .expect("a pre-upgrade supervisor's reexec state still decodes");
        assert_eq!(older.highest_attempted_generation, 0);
        assert!(older.liveness_fds.is_none());

        let mut current = older.clone();
        current.highest_attempted_generation = 12;
        let decoded: ReexecState =
            serde_json::from_str(&serde_json::to_string(&current).unwrap()).unwrap();
        assert_eq!(
            decoded.highest_attempted_generation, 12,
            "burned attempts survive reexec so a retry never reuses one"
        );
    }

    #[test]
    fn worker_generations_never_reuse_an_attempted_or_durable_generation() {
        // A fresh supervisor on a home whose previous run reached durable
        // generation 5 starts above it rather than at 1.
        let fence = TestFence::readable(5);
        let mut generations = WorkerGenerations::above(5);
        assert_eq!(generations.allocate(&fence).unwrap(), 6);
        // An aborted handover attempt (7) is burned: the retry after it rolls
        // from the still-serving generation 6 to 8, never back to 7.
        assert_eq!(generations.allocate(&fence).unwrap(), 7);
        assert_eq!(generations.allocate(&fence).unwrap(), 8);

        let mut exhausted = WorkerGenerations::above(u64::MAX);
        assert!(exhausted.allocate(&fence).is_err());
        assert!(
            exhausted.allocate(&fence).is_err(),
            "exhaustion must not wrap"
        );
    }

    /// Durable fence double: the first `failures` reads fail, later reads
    /// return `durable`.
    struct TestFence {
        durable: u64,
        failures: std::sync::atomic::AtomicUsize,
        reads: std::sync::atomic::AtomicUsize,
    }

    impl TestFence {
        fn readable(durable: u64) -> Self {
            Self::failing(durable, 0)
        }

        fn failing(durable: u64, failures: usize) -> Self {
            Self {
                durable,
                failures: std::sync::atomic::AtomicUsize::new(failures),
                reads: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl DurableGenerationFence for TestFence {
        fn read_durable_generation(&self) -> Result<u64> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let failed = self
                .failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                })
                .is_ok();
            if failed {
                bail!("controlled durable fence read failure");
            }
            Ok(self.durable)
        }
    }

    /// A reexec from a pre-upgrade supervisor inherits no attempted
    /// generations. Its burned attempts may have advanced the durable fence
    /// past the live worker (4 -> 5 here), so with the fence unreadable no
    /// generation is allocated at all — the live worker's `current + 1` would
    /// reuse the burned 5 — until the fence is read and folded in.
    #[cfg(any(unix, windows))]
    #[test]
    fn reexec_from_legacy_state_never_reuses_a_generation_on_an_unreadable_fence() {
        let fence = TestFence::failing(5, 3);
        let mut generations = WorkerGenerations::resume_after_reexec(&fence, 4, 0);
        assert!(generations.durable_unverified());

        for _ in 0..2 {
            let error = generations.allocate(&fence).unwrap_err();
            assert!(
                format!("{error:#}").contains("deferred on an unreadable durable fence"),
                "{error:#}"
            );
            assert!(generations.durable_unverified());
        }
        assert_eq!(
            generations.highest_attempted(),
            4,
            "failed reads burn nothing"
        );

        assert_eq!(generations.allocate(&fence).unwrap(), 6);
        assert!(!generations.durable_unverified());
        let reads = fence.reads();
        assert_eq!(generations.allocate(&fence).unwrap(), 7);
        assert_eq!(fence.reads(), reads, "a folded fence is not re-read");

        // Inherited attempted generations already bound every burned attempt,
        // so an unreadable fence does not defer allocation for current state.
        let fence = TestFence::failing(5, 1);
        let mut generations = WorkerGenerations::resume_after_reexec(&fence, 4, 5);
        assert!(!generations.durable_unverified());
        assert_eq!(generations.allocate(&fence).unwrap(), 6);
    }

    /// A deferred allocation fails only that respawn attempt: the retry loop
    /// keeps the supervisor alive and spawns above the fence once it reads.
    #[cfg(any(unix, windows))]
    #[tokio::test(start_paused = true)]
    async fn deferred_fence_allocation_fails_the_attempt_not_the_supervisor() {
        let fence = TestFence::failing(9, 2);
        let mut generations = WorkerGenerations::resume_after_reexec(&fence, 4, 0);
        let mut storm = cockpit_client::RestartStormGuard::default();
        let mut generation = 4;
        let mut attempts = Vec::new();

        let worker = retry_worker_spawn(
            &mut storm,
            &mut generations,
            &fence,
            &mut generation,
            |attempt_generation| {
                attempts.push(attempt_generation);
                std::future::ready(Ok::<_, anyhow::Error>(7_u32))
            },
        )
        .await;

        assert_eq!(worker, Some(7));
        assert_eq!(attempts, vec![10], "the first spawn is above the fence");
        assert_eq!(generation, 10);
    }

    #[tokio::test(start_paused = true)]
    async fn silent_admin_read_fails_that_connection_after_its_timeout() {
        let (_client, server) = tokio::io::duplex(64);

        let error = read_admin(server).await.unwrap_err();

        assert!(
            format!("{error:#}").contains("sent no request"),
            "{error:#}"
        );
    }

    /// A client that connects and never writes must not hold the supervisor's
    /// admin loop: the worker's boundary report behind it is still served
    /// well inside the handover deadline.
    #[cfg(unix)]
    #[tokio::test]
    async fn silent_admin_client_times_out_without_stalling_supervision() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sup.ctl");
        let mut admin = bind_admin(&path).unwrap();
        let _silent = tokio::net::UnixStream::connect(&path).await.unwrap();
        let reporter = tokio::spawn({
            let path = path.clone();
            async move {
                let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
                let mut line = serde_json::to_vec(&AdminRequest {
                    version: ADMIN_PROTOCOL_VERSION,
                    command: AdminCommand::WorkerBoundary {
                        worker_pid: 456,
                        generation: 7,
                        last_boundary: Vec::new(),
                    },
                })
                .unwrap();
                line.push(b'\n');
                stream.write_all(&line).await.unwrap();
                let mut reply = String::new();
                BufReader::new(stream).read_line(&mut reply).await.unwrap();
                reply
            }
        });

        let started = Instant::now();
        let boundary =
            wait_for_worker_boundary(&mut admin, 456, 7, ADMIN_CONNECTION_IO_TIMEOUT * 4, 1, None)
                .await
                .expect("the silent client must not consume the handover deadline");

        assert!(boundary.is_empty());
        assert!(started.elapsed() < ADMIN_CONNECTION_IO_TIMEOUT * 3);
        let reply: AdminResponse =
            serde_json::from_str(reporter.await.unwrap().trim_end()).unwrap();
        assert!(matches!(reply, AdminResponse::Status { .. }), "{reply:?}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn staged_successor_exit_aborts_before_predecessor_commit() {
        let directory = tempfile::tempdir().unwrap();
        let mut admin = bind_admin(&directory.path().join("sup.ctl")).unwrap();
        let (exited_tx, exited) = tokio::sync::mpsc::channel(1);
        exited_tx.send(Ok(())).await.unwrap();
        let mut successor = Worker {
            pid: 123,
            binary: std::fs::canonicalize(cockpit_test_support::system_true_executable()).unwrap(),
            child: None,
            exited,
            promotion: None,
            serving: None,
        };

        let error = wait_for_worker_handover_ready(
            &mut admin,
            &mut successor,
            456,
            7,
            Duration::from_secs(1),
            1,
            None,
        )
        .await
        .unwrap_err();

        assert!(format!("{error:#}").contains("staged successor pid 123 exited"));
    }

    #[cfg(unix)]
    #[test]
    fn readiness_timeout_kills_worker_and_includes_log_tail() {
        use std::io::Write as _;

        let directory = tempfile::tempdir().unwrap();
        let log_path = directory.path().join("daemon.log");
        let mut log = std::fs::File::create(&log_path).unwrap();
        writeln!(log, "readiness-timeout-evidence").unwrap();
        log.sync_all().unwrap();
        let (read, _write_kept_open) = create_ready_pipe().unwrap();
        let mut child = std::process::Command::new("sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .unwrap();

        let error = enforce_unix_worker_readiness(
            read,
            &mut child,
            Duration::from_millis(20),
            &log_path,
            1,
            1,
        )
        .unwrap_err();

        assert!(child.try_wait().unwrap().is_some());
        let message = format!("{error:#}");
        assert!(message.contains("timed out waiting for worker"));
        assert!(message.contains("readiness-timeout-evidence"));
    }

    #[cfg(unix)]
    #[test]
    fn partial_readiness_hello_cannot_outlive_spawn_timeout() {
        use std::io::Write as _;

        let directory = tempfile::tempdir().unwrap();
        let log_path = directory.path().join("daemon.log");
        std::fs::write(&log_path, b"partial-readiness-evidence\n").unwrap();
        let (read, write) = create_ready_pipe().unwrap();
        let mut writer = std::fs::File::from(write);
        writer.write_all(b"{").unwrap();
        writer.flush().unwrap();
        let mut child = std::process::Command::new("sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .unwrap();

        let error = enforce_unix_worker_readiness(
            read,
            &mut child,
            Duration::from_millis(20),
            &log_path,
            1,
            1,
        )
        .unwrap_err();

        assert!(child.try_wait().unwrap().is_some());
        let message = format!("{error:#}");
        assert!(message.contains("timed out waiting for worker"));
        assert!(message.contains("partial-readiness-evidence"));
        drop(writer);
    }

    #[cfg(unix)]
    #[test]
    fn readiness_hello_mismatch_aborts_before_predecessor_signal() {
        use std::io::Write as _;

        let directory = tempfile::tempdir().unwrap();
        let log_path = directory.path().join("daemon.log");
        std::fs::write(&log_path, b"predecessor-still-serving\n").unwrap();
        let (read, write) = create_ready_pipe().unwrap();
        let mut writer = std::fs::File::from(write);
        serde_json::to_writer(
            &mut writer,
            &WorkerReadyReport {
                protocol_version: super::super::proto::PROTOCOL_VERSION,
                pid: 999_999,
                generation: 8,
                opened_at_unix_ms: 1_001,
            },
        )
        .unwrap();
        writeln!(writer).unwrap();
        drop(writer);
        let mut child = std::process::Command::new("sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .unwrap();

        let error = enforce_unix_worker_readiness(
            read,
            &mut child,
            Duration::from_secs(1),
            &log_path,
            8,
            1_000,
        )
        .unwrap_err();

        assert!(child.try_wait().unwrap().is_some());
        let message = format!("{error:#}");
        assert!(message.contains("readiness hello mismatch"));
        assert!(message.contains("predecessor-still-serving"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_identity_promotion_replaces_only_at_readiness() {
        const CHILD_ENV: &str = "COCKPIT_WINDOWS_IDENTITY_READINESS_TEST_PATH";
        // Tokio named-pipe servers register with the I/O driver at creation,
        // so both the parent and the re-executed child need an entered
        // runtime even though the test body itself is synchronous.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _runtime_guard = runtime.enter();
        if let Some(staged) = std::env::var_os(CHILD_ENV) {
            std::thread::sleep(Duration::from_millis(100));
            let successor = super::super::windows_pipe::NamedPipeListener::prepare().unwrap();
            successor.publish(Path::new(&staged)).unwrap();
            std::thread::sleep(Duration::from_secs(30));
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let staged = directory.path().join("staged.json");
        let canonical = directory.path().join("daemon.json");
        let predecessor = super::super::windows_pipe::NamedPipeListener::prepare().unwrap();
        predecessor.publish(&canonical).unwrap();
        let predecessor_name = predecessor.pipe_name().clone();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "daemon::supervisor::tests::windows_identity_promotion_replaces_only_at_readiness",
                "--exact",
            ])
            .env(CHILD_ENV, &staged)
            .spawn()
            .unwrap();

        assert_eq!(
            cockpit_host::named_pipe::read_pipe_identity(&canonical).unwrap(),
            predecessor_name
        );
        assert!(wait_windows_identity(&staged, &mut child, Duration::from_secs(1)).unwrap());
        let successor_name = cockpit_host::named_pipe::read_pipe_identity(&staged).unwrap();
        promote_windows_identity(&staged, &canonical).unwrap();
        assert_eq!(
            cockpit_host::named_pipe::read_pipe_identity(&canonical).unwrap(),
            successor_name
        );
        assert!(!staged.exists());
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
