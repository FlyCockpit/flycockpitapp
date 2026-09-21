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
#[cfg(any(unix, windows))]
use std::sync::OnceLock;
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
const MAX_ADMIN_LINE: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum AdminCommand {
    Status,
    Roll,
    Upgrade { binary: PathBuf },
    Stop,
    Reexec,
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
    worker_pid: u32,
    worker_binary: PathBuf,
    generation: u64,
    opened_at_unix_ms: u64,
}

#[cfg(windows)]
#[derive(Clone, Serialize, Deserialize)]
struct ReexecState {
    worker_pid: u32,
    worker_binary: PathBuf,
    generation: u64,
    opened_at_unix_ms: u64,
}

#[cfg(any(unix, windows))]
static EARLY_REEXEC_STATE: OnceLock<ReexecState> = OnceLock::new();
#[cfg(any(unix, windows))]
static EARLY_WORKER_PROCESS: OnceLock<bool> = OnceLock::new();

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
            ] {
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
        && let Some(cockpit_host::daemon_lifecycle::DaemonPidRecord::Receipt(receipt)) =
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

/// Consume the supervisor-owned Unix listeners inherited at fd 3 and fd 5.
/// Windows workers deliberately return `None`: each generation prepares a new
/// hardened random pipe and publishes its identity only at readiness.
pub(crate) fn take_worker_listeners(paths: &DaemonPaths) -> Result<Option<WorkerListeners>> {
    if !is_worker_process() {
        return Ok(None);
    }
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

/// Signal the supervisor only after boot/recovery and listener construction
/// have reached the same publication barrier as an ordinary daemon.
pub(crate) fn report_worker_ready() -> Result<()> {
    if !is_worker_process() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        let byte = [1_u8];
        // SAFETY: fd 4 is the inherited write end of this generation's
        // readiness pipe and `byte` is valid for one byte.
        let written = unsafe { libc::write(READY_FD, byte.as_ptr().cast(), 1) };
        if written != 1 {
            return Err(std::io::Error::last_os_error()).context("signaling worker readiness");
        }
        // SAFETY: fd 4 belongs to this process and is no longer needed.
        unsafe { libc::close(READY_FD) };
    }
    Ok(())
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
    #[cfg(unix)]
    use cockpit_host::daemon_lifecycle::DaemonPidRecord;
    use cockpit_host::daemon_lifecycle::{ForegroundMetadataGuard, reclaim_stale_and_reserve};

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

    let inherited = inherited_reexec_state()?;

    let (
        receipt,
        mut metadata,
        endpoint_owner,
        mut admin,
        opened_at_unix_ms,
        mut generation,
        mut worker,
        database_owner,
    ) = if let Some(inherited) = inherited {
        #[cfg(unix)]
        {
            let receipt =
                match cockpit_host::daemon_lifecycle::read_daemon_pid_record(&paths.pid_file) {
                    Some(DaemonPidRecord::Receipt(receipt))
                        if receipt.pid == std::process::id() =>
                    {
                        receipt
                    }
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
                UnixEndpointOwner::resume(&paths, inherited.control_fd, inherited.reveal_fd)?
            };
            // SAFETY: the inherited descriptor uniquely owns the admin listener.
            let admin = unsafe { resume_admin(inherited.admin_fd)? };
            let worker = resume_worker(inherited.worker_pid, &inherited.worker_binary)?;
            // SAFETY: this is the uniquely inherited descriptor retained by
            // the pre-exec supervisor owner.
            let database_owner = unsafe {
                crate::db::SupervisorDatabaseOwner::from_raw_fd(inherited.database_lock_fd)
            };
            (
                receipt,
                metadata,
                endpoint_owner,
                admin,
                inherited.opened_at_unix_ms,
                inherited.generation,
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
                worker,
                database_owner,
            )
        }
    } else {
        let lifetime = cockpit_host::daemon_lifecycle::acquire_daemon_lifetime(&paths.pid_file)
            .with_context(|| {
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
        let generation = 1_u64;
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
            worker,
            database_owner,
        )
    };
    let _database_owner = database_owner;

    let mut storm = cockpit_client::RestartStormGuard::default();
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
                    write_admin(&mut stream, &AdminResponse::Error {
                        version: ADMIN_PROTOCOL_VERSION,
                        message: format!("unsupported supervisor admin protocol {}", request.version),
                    }).await?;
                    continue;
                }
                match request.command {
                    AdminCommand::Status => {
                        write_admin(&mut stream, &status_response(worker.pid, generation, opened_at_unix_ms)).await?;
                    }
                    AdminCommand::Stop => {
                        write_admin(&mut stream, &AdminResponse::Stopping { version: ADMIN_PROTOCOL_VERSION }).await?;
                        drain_and_reap_worker(&mut worker, false).await?;
                        break;
                    }
                    command @ (AdminCommand::Roll | AdminCommand::Upgrade { .. }) => {
                        let binary = match command {
                            AdminCommand::Upgrade { binary } => std::fs::canonicalize(&binary)
                                .with_context(|| format!("resolving upgrade binary {}", binary.display()))?,
                            _ => executable.clone(),
                        };
                        let next_generation = generation.saturating_add(1);
                        let successor = spawn_ready_worker(WorkerSpawnRequest {
                            endpoints: &endpoint_owner,
                            binary: &binary,
                            paths: &paths,
                            log: &log,
                            log_path: &log_path,
                            generation: next_generation,
                            opened_at_unix_ms,
                            no_sandbox,
                            resume_all_sessions,
                        }).await;
                        match successor {
                            Ok(successor) => {
                                let old_pid = worker.pid;
                                publish_generation(
                                    &paths, &receipt, successor.pid, next_generation, opened_at_unix_ms,
                                )?;
                                // Plain drain seam. #440 will replace this with
                                // boundary-aware handover timers.
                                let predecessor = std::mem::replace(&mut worker, successor);
                                reap_retired_worker(predecessor);
                                generation = next_generation;
                                write_admin(&mut stream, &AdminResponse::Rolled {
                                    version: ADMIN_PROTOCOL_VERSION,
                                    old_worker_pid: old_pid,
                                    worker_pid: worker.pid,
                                    generation,
                                    uptime_ms: now_unix_ms().saturating_sub(opened_at_unix_ms),
                                }).await?;
                            }
                            Err(error) => {
                                write_admin(&mut stream, &AdminResponse::Error {
                                    version: ADMIN_PROTOCOL_VERSION,
                                    message: format!("{error:#}"),
                                }).await?;
                            }
                        }
                    }
                    AdminCommand::Reexec => {
                        write_admin(&mut stream, &AdminResponse::Reexecing { version: ADMIN_PROTOCOL_VERSION }).await?;
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

async fn retry_worker_spawn<T, F, Fut>(
    storm: &mut cockpit_client::RestartStormGuard,
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
        *generation = generation.saturating_add(1);
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
}

#[cfg(unix)]
struct UnixEndpointOwner {
    control: tokio::net::UnixListener,
    reveal: super::leak_reveal_socket::BoundRevealSocket,
}

#[cfg(unix)]
impl UnixEndpointOwner {
    fn bind(paths: &DaemonPaths) -> Result<Self> {
        Ok(Self {
            reveal: super::leak_reveal_socket::bind_reveal_socket(paths)?,
            control: super::bind_private_socket(&paths.socket)?,
        })
    }

    fn prepare_for_reexec(&self) -> Result<(std::os::fd::RawFd, std::os::fd::RawFd)> {
        use std::os::fd::AsRawFd as _;
        let control = self.control.as_raw_fd();
        let reveal = self.reveal.raw_fd();
        clear_close_on_exec(control)?;
        clear_close_on_exec(reveal)?;
        Ok((control, reveal))
    }

    // SAFETY: callers transfer unique ownership of both inherited descriptors.
    unsafe fn resume(
        paths: &DaemonPaths,
        control_fd: std::os::fd::RawFd,
        reveal_fd: std::os::fd::RawFd,
    ) -> Result<Self> {
        use std::os::fd::FromRawFd as _;
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
    #[cfg(unix)]
    control_fd: std::os::fd::RawFd,
    #[cfg(unix)]
    reveal_fd: std::os::fd::RawFd,
}

async fn spawn_ready_worker(request: WorkerSpawnRequest<'_>) -> Result<Worker> {
    #[cfg(unix)]
    let control_fd = {
        use std::os::fd::AsRawFd as _;
        request.endpoints.control.as_raw_fd()
    };
    #[cfg(unix)]
    let reveal_fd = request.endpoints.reveal.raw_fd();
    let request = OwnedWorkerSpawnRequest {
        binary: request.binary.to_path_buf(),
        paths: request.paths.clone(),
        log: request.log.try_clone()?,
        log_path: request.log_path.to_path_buf(),
        generation: request.generation,
        opened_at_unix_ms: request.opened_at_unix_ms,
        no_sandbox: request.no_sandbox,
        resume_all_sessions: request.resume_all_sessions,
        #[cfg(unix)]
        control_fd,
        #[cfg(unix)]
        reveal_fd,
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
    {
        use std::os::fd::AsRawFd as _;
        let ready_write_fd = ready_write.as_raw_fd();
        // SAFETY: pre_exec runs in the child. Each source descriptor remains
        // open through `spawn`; dup2 atomically installs the activation ABI.
        unsafe {
            command.pre_exec(move || {
                let safe_control = libc::fcntl(request.control_fd, libc::F_DUPFD, 16);
                let safe_ready = libc::fcntl(ready_write_fd, libc::F_DUPFD, 16);
                let safe_reveal = libc::fcntl(request.reveal_fd, libc::F_DUPFD, 16);
                if safe_control < 0 || safe_ready < 0 || safe_reveal < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let installed = libc::dup2(safe_control, CONTROL_FD) >= 0
                    && libc::dup2(safe_ready, READY_FD) >= 0
                    && libc::dup2(safe_reveal, REVEAL_FD) >= 0;
                libc::close(safe_control);
                libc::close(safe_ready);
                libc::close(safe_reveal);
                if !installed {
                    return Err(std::io::Error::last_os_error());
                }
                for fd in [CONTROL_FD, READY_FD, REVEAL_FD] {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        command.env("LISTEN_FDS", "1");
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
        enforce_unix_worker_readiness(
            ready_read,
            &mut child,
            super::DAEMON_SPAWN_TIMEOUT,
            &request.log_path,
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

fn reap_retired_worker(mut worker: Worker) {
    tokio::spawn(async move {
        if let Err(error) = await_drained_worker_exit(&mut worker, true).await {
            tracing::error!(pid = worker.pid, %error, "retired worker process watch failed");
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
    terminate_worker(worker, reconnect)?;
    let exit =
        match tokio::time::timeout(super::shutdown::SHUTDOWN_DRAIN_GRACE, worker.exited.recv())
            .await
        {
            Ok(exit) => exit,
            Err(_) => {
                tracing::warn!(
                    pid = worker.pid,
                    "worker exceeded the daemon drain grace; forcing shutdown"
                );
                // The worker's shutdown authority treats a second stop signal as
                // the existing force transition. This is the ordinary daemon
                // drain bound, not #440's future boundary-aware roll policy.
                terminate_worker(worker, false)?;
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
    // SAFETY: successful pipe2 returned two newly owned descriptors.
    Ok(unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(fds[0]),
            std::os::fd::OwnedFd::from_raw_fd(fds[1]),
        )
    })
}

#[cfg(unix)]
fn wait_ready_byte(
    read: std::os::fd::OwnedFd,
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<bool> {
    use std::os::fd::AsRawFd as _;
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(false);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("timed out waiting for worker pid {} readiness", child.id());
        }
        let millis = remaining.as_millis().min(100) as libc::c_int;
        let mut pollfd = libc::pollfd {
            fd: read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd refers to the live pipe descriptor for one bounded wait.
        let ready = unsafe { libc::poll(&mut pollfd, 1, millis) };
        if ready < 0 {
            return Err(std::io::Error::last_os_error()).context("polling worker readiness");
        }
        if ready > 0 {
            let mut byte = [0_u8];
            // SAFETY: byte is valid for one byte and the pipe is readable.
            return Ok(unsafe { libc::read(read.as_raw_fd(), byte.as_mut_ptr().cast(), 1) } == 1);
        }
    }
}

#[cfg(unix)]
fn enforce_unix_worker_readiness(
    read: std::os::fd::OwnedFd,
    child: &mut std::process::Child,
    timeout: Duration,
    log_path: &Path,
) -> Result<()> {
    match wait_ready_byte(read, child, timeout) {
        Ok(true) => Ok(()),
        Ok(false) => {
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
            != Some(cockpit_host::daemon_lifecycle::DaemonPidRecord::Receipt(
                receipt.clone(),
            ))
        {
            bail!("supervisor receipt changed before generation publication");
        }
        super::rendezvous::write(&path, &record)
    })
}

fn status_response(worker_pid: u32, generation: u64, opened_at_unix_ms: u64) -> AdminResponse {
    status_response_at(worker_pid, generation, opened_at_unix_ms, now_unix_ms())
}

fn status_response_at(
    worker_pid: u32,
    generation: u64,
    opened_at_unix_ms: u64,
    now_unix_ms: u64,
) -> AdminResponse {
    AdminResponse::Status {
        version: ADMIN_PROTOCOL_VERSION,
        supervisor_pid: std::process::id(),
        worker_pid,
        generation,
        uptime_ms: now_unix_ms.saturating_sub(opened_at_unix_ms),
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

#[cfg(windows)]
fn terminate_worker(worker: &mut Worker, _reconnect: bool) -> Result<()> {
    cockpit_host::daemon_lifecycle::terminate_verified_daemon_process(&worker.receipt)
        .context("terminating supervised worker")
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

async fn read_admin<S>(stream: S) -> Result<(AdminRequest, S)>
where
    S: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(stream);
    let request = read_admin_request(&mut reader).await?;
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

async fn write_admin<W>(stream: &mut W, response: &AdminResponse) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut line = serde_json::to_vec(response)?;
    line.push(b'\n');
    stream.write_all(&line).await?;
    stream.flush().await?;
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

/// Synchronous compatibility entry point for lifecycle callers that predate
/// the async admin protocol. The runtime lives on a dedicated thread so this
/// remains safe when called from a current-thread Tokio executor.
pub fn request_blocking(paths: &DaemonPaths, command: AdminCommand) -> Result<AdminResponse> {
    let paths = paths.clone();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building supervisor admin runtime")?
            .block_on(request(&paths, command))
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
    opened_at_unix_ms: u64,
    no_sandbox: bool,
    resume_all_sessions: bool,
}

#[cfg(unix)]
fn reexec_supervisor(request: ReexecRequest<'_>) -> Result<()> {
    use std::os::unix::process::CommandExt as _;
    let (lifetime_fd, pid_lock_fd) = request.metadata.prepare_for_reexec()?;
    let (control_fd, reveal_fd) = request.endpoints.prepare_for_reexec()?;
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
        worker_pid: request.worker.pid,
        worker_binary: request.worker.binary.clone(),
        generation: request.generation,
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
        let first = status_response_at(101, 4, 1_000, 6_000);
        let replacement = status_response_at(202, 5, 1_000, 6_750);
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
                ..
            }
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
        let mut generation = 7;
        let mut attempts = Vec::new();

        let worker = retry_worker_spawn(&mut storm, &mut generation, |attempt_generation| {
            attempts.push(attempt_generation);
            std::future::ready(if attempt_generation < 10 {
                Err(anyhow::anyhow!("controlled readiness failure"))
            } else {
                Ok(101_u32)
            })
        })
        .await;

        assert_eq!(worker, Some(101));
        assert_eq!(generation, 10);
        assert_eq!(attempts, vec![8, 9, 10]);
    }

    #[tokio::test]
    async fn readiness_failures_exhaust_the_shared_restart_budget() {
        let mut storm = cockpit_client::RestartStormGuard::default();
        let mut generation = 11;
        let mut attempts = Vec::new();

        let worker = retry_worker_spawn(&mut storm, &mut generation, |attempt_generation| {
            attempts.push(attempt_generation);
            std::future::ready(Err::<u32, _>(anyhow::anyhow!(
                "controlled readiness failure"
            )))
        })
        .await;

        assert_eq!(worker, None);
        assert_eq!(generation, 14);
        assert_eq!(attempts, vec![12, 13, 14]);
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

        let error =
            enforce_unix_worker_readiness(read, &mut child, Duration::from_millis(20), &log_path)
                .unwrap_err();

        assert!(child.try_wait().unwrap().is_some());
        let message = format!("{error:#}");
        assert!(message.contains("timed out waiting for worker"));
        assert!(message.contains("readiness-timeout-evidence"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_identity_promotion_replaces_only_at_readiness() {
        const CHILD_ENV: &str = "COCKPIT_WINDOWS_IDENTITY_READINESS_TEST_PATH";
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
