//! Ownership contract for an ephemeral daemon spawned by a foreground
//! process (`cockpit run` and the daemonless TUI). One owner per
//! ephemeral daemon; the owner is responsible for reaping it on exit.
//!
//! [`EphemeralDaemonGuard`] is the single, shared mechanism — there is
//! no parallel teardown path. It guarantees the owned daemon is asked to
//! shut down on **every** exit path:
//!
//! - the happy path (an explicit [`EphemeralDaemonGuard::shutdown`]),
//! - an early `?`-return or a panic/unwind (the RAII `Drop`),
//! - SIGINT/SIGTERM (the task spawned by [`spawn_signal_shutdown`]).
//!
//! The shutdown it requests routes through the daemon's single graceful
//! drain path (`StopDaemon` → `server::request_shutdown`), so an in-flight
//! ephemeral daemon drains its work before exiting. The self-reaping idle
//! watchdog (Layer C, [`crate::daemon::EPHEMERAL_IDLE_GRACE`]) remains the
//! backstop for an *uncatchable* owner death (SIGKILL, power loss) that no
//! guard or signal handler can observe.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use cockpit_host::daemon_lifecycle::{
    DaemonPidReceipt, DaemonPidRecord, PidIdentity, read_daemon_pid_record,
    verify_cockpit_daemon_receipt_identity,
};

use crate::daemon::proto::{Envelope, Request};

#[derive(Clone)]
struct ProcessCleanup {
    paths: crate::daemon::DaemonPaths,
    child: Arc<std::sync::Mutex<Option<std::process::Child>>>,
    receipt: Arc<std::sync::Mutex<Option<DaemonPidReceipt>>>,
    launch_start: Option<cockpit_host::daemon_lifecycle::ProcessStartIdentity>,
    launch_executable: Option<PathBuf>,
}

struct ProcessReap {
    cleanup: ProcessCleanup,
    completed: Option<std::sync::mpsc::Sender<anyhow::Result<()>>>,
    attempts: u8,
}

#[derive(Debug)]
enum CleanupPhase {
    Pending,
    Running,
    Complete(Result<(), Arc<str>>),
}

#[derive(Debug)]
struct CleanupState {
    phase: std::sync::Mutex<CleanupPhase>,
    completed: std::sync::Condvar,
}

impl CleanupState {
    fn new() -> Self {
        Self {
            phase: std::sync::Mutex::new(CleanupPhase::Pending),
            completed: std::sync::Condvar::new(),
        }
    }

    fn disarm(&self) {
        let mut phase = self.phase.lock().unwrap_or_else(|error| error.into_inner());
        if matches!(*phase, CleanupPhase::Pending) {
            *phase = CleanupPhase::Complete(Ok(()));
            self.completed.notify_all();
        }
    }

    #[cfg(test)]
    fn is_pending(&self) -> bool {
        matches!(
            *self.phase.lock().unwrap_or_else(|error| error.into_inner()),
            CleanupPhase::Pending
        )
    }
}

static PROCESS_REAPER: std::sync::OnceLock<Option<std::sync::mpsc::Sender<ProcessReap>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
thread_local! {
    static INJECT_PROCESS_CLEANUP_PANIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static INJECT_CHILD_KILL_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static INJECT_CHILD_WAIT_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static INJECT_OWNER_GRACEFUL_STOP: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    static INJECT_OWNER_EXIT_TIMEOUT_MS: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

pub(crate) fn initialize_process_reaper() -> anyhow::Result<()> {
    PROCESS_REAPER
        .get_or_init(|| {
            let (send, receive) = std::sync::mpsc::channel::<ProcessReap>();
            std::thread::Builder::new()
                .name("cockpit-ephemeral-process-reaper".to_string())
                .spawn(move || {
                    let mut pending = std::collections::VecDeque::new();
                    loop {
                        if pending.is_empty() {
                            let Ok(reap) = receive.recv() else { break };
                            pending.push_back(reap);
                        }
                        while let Ok(reap) = receive.try_recv() {
                            pending.push_back(reap);
                        }
                        let Some(mut reap) = pending.pop_front() else {
                            continue;
                        };
                        let result = run_process_cleanup_recovering(&reap.cleanup);
                        if process_child_retained(&reap.cleanup) {
                            reap.attempts = reap.attempts.saturating_add(1);
                            let backoff_ms = 25_u64.saturating_mul(1_u64 << reap.attempts.min(5));
                            pending.push_back(reap);
                            std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
                            continue;
                        }
                        if let Some(completed) = reap.completed {
                            let _ = completed.send(result);
                        } else if let Err(error) = result {
                            tracing::error!(%error, "ephemeral process reaper failed");
                        }
                    }
                })
                .ok()
                .map(|_| send)
        })
        .as_ref()
        .map(|_| ())
        .ok_or_else(|| anyhow::anyhow!("starting ephemeral process reaper"))
}

fn process_child_retained(cleanup: &ProcessCleanup) -> bool {
    match cleanup.child.lock() {
        Ok(child) => child.is_some(),
        Err(poisoned) => poisoned.into_inner().is_some(),
    }
}

fn run_cleanup_fallback_until_released(cleanup: &ProcessCleanup) -> anyhow::Result<()> {
    let mut last_error = None;
    let mut attempt = 0_u8;
    while process_child_retained(cleanup) {
        if let Err(error) = run_process_cleanup_recovering(cleanup) {
            last_error = Some(error);
        }
        if process_child_retained(cleanup) {
            attempt = attempt.saturating_add(1);
            let backoff_ms = 25_u64.saturating_mul(1_u64 << attempt.min(5));
            std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
        }
    }
    match last_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn run_process_cleanup_recovering(cleanup: &ProcessCleanup) -> anyhow::Result<()> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        cleanup_exact_process(cleanup)
    }));
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => match emergency_kill_wait_and_retire(cleanup) {
            Ok(()) => Err(error),
            Err(emergency) => Err(anyhow::anyhow!(
                "{error}; emergency exact-child reap failed: {emergency}"
            )),
        },
        Err(_) => {
            emergency_kill_wait_and_retire(cleanup).map_err(|emergency| {
                anyhow::anyhow!(
                    "process cleanup panicked and emergency exact-child reap failed: {emergency}"
                )
            })?;
            Err(anyhow::anyhow!(
                "process cleanup panicked; exact child emergency-reaped"
            ))
        }
    }
}

fn emergency_kill_wait_and_retire(cleanup: &ProcessCleanup) -> anyhow::Result<()> {
    let mut child_slot = match cleanup.child.lock() {
        Ok(child) => child,
        Err(poisoned) => poisoned.into_inner(),
    };
    let expected_pid = child_slot
        .as_ref()
        .map(std::process::Child::id)
        .or_else(|| {
            let receipt = match cleanup.receipt.lock() {
                Ok(receipt) => receipt,
                Err(poisoned) => poisoned.into_inner(),
            };
            receipt.as_ref().map(|receipt| receipt.pid)
        });
    if let Some(child) = child_slot.as_mut() {
        kill_and_wait_exact_child(child)?;
    }
    *child_slot = None;
    drop(child_slot);
    if let Some(expected_pid) = expected_pid {
        let bound = match cleanup.receipt.lock() {
            Ok(receipt) => receipt.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        retire_late_exact_metadata(cleanup, expected_pid, bound.as_ref())?;
    }
    Ok(())
}

fn kill_and_wait_exact_child(child: &mut std::process::Child) -> anyhow::Result<()> {
    if child_try_wait(child)?.is_some() {
        return Ok(());
    }
    if let Err(kill_error) = child_kill(child) {
        if child_try_wait(child)?.is_none() {
            return Err(kill_error).context("terminating exact ephemeral child");
        }
        return Ok(());
    }
    child_wait(child)
        .context("reaping exact ephemeral child")
        .map(|_| ())
}

fn child_try_wait(
    child: &mut std::process::Child,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    child.try_wait()
}

fn child_kill(child: &mut std::process::Child) -> std::io::Result<()> {
    #[cfg(test)]
    if INJECT_CHILD_KILL_FAILURE.with(|inject| inject.replace(false)) {
        return Err(std::io::Error::other("injected child kill failure"));
    }
    child.kill()
}

fn child_wait(child: &mut std::process::Child) -> std::io::Result<std::process::ExitStatus> {
    #[cfg(test)]
    if INJECT_CHILD_WAIT_FAILURE.with(|inject| inject.replace(false)) {
        return Err(std::io::Error::other("injected child wait failure"));
    }
    child.wait()
}

fn process_reaper() -> anyhow::Result<&'static std::sync::mpsc::Sender<ProcessReap>> {
    initialize_process_reaper()?;
    PROCESS_REAPER
        .get()
        .and_then(Option::as_ref)
        .context("ephemeral process reaper unavailable")
}

fn cleanup_exact_process(cleanup: &ProcessCleanup) -> anyhow::Result<()> {
    #[cfg(test)]
    if INJECT_PROCESS_CLEANUP_PANIC.with(|inject| inject.replace(false)) {
        panic!("injected process cleanup panic");
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut child_slot = cleanup
        .child
        .lock()
        .map_err(|_| anyhow::anyhow!("ephemeral child handle poisoned"))?;
    let Some(child) = child_slot.as_mut() else {
        return Ok(());
    };
    let expected_pid = child.id();
    let mut expected = cleanup
        .receipt
        .lock()
        .map_err(|_| anyhow::anyhow!("ephemeral receipt lock poisoned"))?
        .clone();
    while expected.is_none() && std::time::Instant::now() < deadline {
        if child_try_wait(child)?.is_some() {
            let bound = expected.clone();
            *child_slot = None;
            drop(child_slot);
            retire_late_exact_metadata(cleanup, expected_pid, bound.as_ref())?;
            return Ok(());
        }
        if let Some(DaemonPidRecord::Receipt(receipt)) =
            read_daemon_pid_record(&cleanup.paths.pid_file)
            && receipt_matches_owned_launch(cleanup, expected_pid, &receipt)
        {
            *cleanup
                .receipt
                .lock()
                .map_err(|_| anyhow::anyhow!("ephemeral receipt lock poisoned"))? =
                Some(receipt.clone());
            expected = Some(receipt);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let bound_expected = expected.clone();
    let result = if let Some(expected) = expected {
        if read_daemon_pid_record(&cleanup.paths.pid_file)
            != Some(DaemonPidRecord::Receipt(expected.clone()))
        {
            kill_and_wait_exact_child(child)?;
            anyhow::bail!(
                "ephemeral daemon receipt changed before teardown; exact child was terminated without touching replacement metadata"
            );
        }
        request_owned_graceful_stop(cleanup, &expected)
    } else {
        kill_and_wait_exact_child(child)?;
        retire_late_exact_metadata(cleanup, expected_pid, None)?;
        anyhow::bail!(
            "ephemeral child never published an exact v2 PID receipt; terminated exact child"
        )
    };
    if result.is_err() {
        if let Err(reap_error) = kill_and_wait_exact_child(child) {
            let original = result
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unknown cleanup failure".to_string());
            return Err(anyhow::anyhow!(
                "{original}; exact child ownership retained after reap failure: {reap_error}"
            ));
        }
        *child_slot = None;
        drop(child_slot);
        if let Err(retire_error) =
            retire_late_exact_metadata(cleanup, expected_pid, bound_expected.as_ref())
        {
            return Err(anyhow::anyhow!(
                "{}; exact child exited but metadata retirement failed: {retire_error}",
                result
                    .as_ref()
                    .err()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown cleanup failure".to_string())
            ));
        }
        return result;
    }
    let exit_deadline = std::time::Instant::now() + owner_exit_timeout();
    let mut forced_exit = false;
    loop {
        if child_try_wait(child)?.is_some() {
            break;
        }
        if std::time::Instant::now() >= exit_deadline {
            kill_and_wait_exact_child(child)?;
            forced_exit = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    *child_slot = None;
    drop(child_slot);
    retire_late_exact_metadata(cleanup, expected_pid, bound_expected.as_ref())?;
    if forced_exit && result.is_ok() {
        anyhow::bail!("ephemeral daemon did not exit after verified stop; exact child was forced")
    }
    result
}

fn owner_exit_timeout() -> std::time::Duration {
    #[cfg(test)]
    if let Some(milliseconds) = INJECT_OWNER_EXIT_TIMEOUT_MS.with(|value| value.replace(None)) {
        return std::time::Duration::from_millis(milliseconds);
    }
    crate::daemon::restart_release_timeout(None)
}

fn request_owned_graceful_stop(
    cleanup: &ProcessCleanup,
    expected: &DaemonPidReceipt,
) -> anyhow::Result<()> {
    if read_daemon_pid_record(&cleanup.paths.pid_file)
        != Some(DaemonPidRecord::Receipt(expected.clone()))
    {
        anyhow::bail!("daemon receipt changed before owner graceful-stop request");
    }
    #[cfg(unix)]
    {
        #[cfg(test)]
        if let Some(succeed) = INJECT_OWNER_GRACEFUL_STOP.with(|value| value.replace(None)) {
            return if succeed {
                Ok(())
            } else {
                Err(anyhow::anyhow!("injected owner graceful-stop failure"))
            };
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building owner graceful-stop runtime")?;
        runtime.block_on(request_owned_graceful_stop_async(
            cleanup,
            expected,
            || {},
            || {},
        ))
    }
    #[cfg(not(unix))]
    {
        let _ = (cleanup, expected);
        anyhow::bail!("owner graceful-stop transport is unavailable on this platform")
    }
}

#[cfg(unix)]
async fn request_owned_graceful_stop_async(
    cleanup: &ProcessCleanup,
    expected: &DaemonPidReceipt,
    after_connect: impl FnOnce(),
    after_ack: impl FnOnce(),
) -> anyhow::Result<()> {
    let client = cockpit_client::DaemonClient::connect(&cleanup.paths.socket)
        .await
        .context("connecting exact owned daemon")?;
    after_connect();
    if read_daemon_pid_record(&cleanup.paths.pid_file)
        != Some(DaemonPidRecord::Receipt(expected.clone()))
    {
        anyhow::bail!(
            "daemon receipt changed during owner graceful-stop handshake; shutdown request was not sent"
        );
    }
    let response = client
        .request_ok(Request::StopDaemon { grace_secs: None })
        .await
        .context("requesting exact owned daemon shutdown")?;
    if !matches!(response, crate::daemon::proto::Response::Ack) {
        anyhow::bail!("unexpected owner shutdown response: {response:?}");
    }
    after_ack();
    match read_daemon_pid_record(&cleanup.paths.pid_file) {
        Some(DaemonPidRecord::Receipt(receipt)) if receipt == *expected => {}
        None if matches!(
            std::fs::symlink_metadata(&cleanup.paths.pid_file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ) =>
        {
            // The exact daemon may retire its own metadata after Ack and
            // before its process has fully exited. The retained Child handle
            // remains the authoritative object to await/reap.
        }
        Some(_) | None => {
            anyhow::bail!(
                "daemon receipt changed or became malformed after owner graceful-stop acknowledgement; replacement metadata was preserved"
            );
        }
    }
    Ok(())
}

fn receipt_matches_owned_launch(
    cleanup: &ProcessCleanup,
    expected_pid: u32,
    receipt: &DaemonPidReceipt,
) -> bool {
    receipt_matches_launch_fence(cleanup, expected_pid, receipt)
        && verify_cockpit_daemon_receipt_identity(receipt) == PidIdentity::VerifiedDaemon
}

fn receipt_matches_launch_fence(
    cleanup: &ProcessCleanup,
    expected_pid: u32,
    receipt: &DaemonPidReceipt,
) -> bool {
    cleanup.launch_start.as_ref().is_some_and(|launch_start| {
        let executable_matches = cleanup
            .launch_executable
            .as_ref()
            .is_some_and(|executable| executable == &receipt.executable);
        receipt.pid == expected_pid
            && &receipt.process_start == launch_start
            && receipt.publication_nonce != [0; 32]
            && executable_matches
    })
}

fn retire_late_exact_metadata(
    cleanup: &ProcessCleanup,
    expected_pid: u32,
    bound_expected: Option<&DaemonPidReceipt>,
) -> anyhow::Result<()> {
    let Some(DaemonPidRecord::Receipt(receipt)) = read_daemon_pid_record(&cleanup.paths.pid_file)
    else {
        return Ok(());
    };
    let exact = bound_expected.map_or_else(
        || receipt_matches_launch_fence(cleanup, expected_pid, &receipt),
        |expected| &receipt == expected,
    );
    if !exact {
        return Ok(());
    }
    cockpit_host::daemon_lifecycle::retire_metadata_if_receipt_matches(
        &cleanup.paths.pid_file,
        &cleanup.paths.socket,
        None,
        &receipt,
    )?;
    Ok(())
}

/// RAII backstop that shuts down an ephemeral daemon the current process
/// owns, on **every** exit path — early `?` returns, panics/unwinds, and
/// the normal end of the run/session (Layer A). A process that *attached*
/// to a pre-existing persistent daemon (`owns_daemon = false`) builds no
/// guard, so it never shuts anything down.
///
/// Drop joins the same process-reaper completion used by explicit and
/// signal-driven shutdown. Socket-only test guards retain the small blocking
/// fallback used outside an async runtime.
pub struct EphemeralDaemonGuard {
    socket: PathBuf,
    process: Option<ProcessCleanup>,
    /// One joinable teardown result shared by explicit shutdown, signal
    /// handling, and `Drop`. Claiming cleanup is distinct from completing it.
    cleanup_state: Arc<CleanupState>,
}

impl EphemeralDaemonGuard {
    pub fn new(
        paths: crate::daemon::DaemonPaths,
        child: crate::daemon::DetachedEphemeralChild,
    ) -> Self {
        let launch_start = child.process_start();
        let launch_executable = child.executable().to_path_buf();
        Self {
            socket: paths.socket.clone(),
            process: Some(ProcessCleanup {
                paths,
                child: Arc::new(std::sync::Mutex::new(Some(child.into_child()))),
                receipt: Arc::new(std::sync::Mutex::new(None)),
                launch_start: Some(launch_start),
                launch_executable: Some(launch_executable),
            }),
            cleanup_state: Arc::new(CleanupState::new()),
        }
    }

    #[cfg(test)]
    fn new_for_socket(socket: PathBuf) -> Self {
        Self {
            socket,
            process: None,
            cleanup_state: Arc::new(CleanupState::new()),
        }
    }

    /// Request shutdown and synchronously join its shared result. Idempotent:
    /// the first caller performs teardown and every concurrent/later caller
    /// observes the same completion.
    pub fn shutdown(&self) -> anyhow::Result<()> {
        shutdown_shared(&self.cleanup_state, &self.socket, self.process.clone())
    }

    pub fn bind_published_receipt(&self) -> anyhow::Result<()> {
        let Some(process) = &self.process else {
            return Ok(());
        };
        let pid = process
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("ephemeral child handle poisoned"))?
            .as_ref()
            .context("ephemeral child already reaped")?
            .id();
        let receipt = match read_daemon_pid_record(&process.paths.pid_file) {
            Some(DaemonPidRecord::Receipt(receipt))
                if receipt_matches_owned_launch(process, pid, &receipt) =>
            {
                receipt
            }
            Some(_) => anyhow::bail!("ephemeral daemon published a mismatching PID receipt"),
            None => anyhow::bail!("ephemeral daemon did not publish its v2 PID receipt"),
        };
        if verify_cockpit_daemon_receipt_identity(&receipt) != PidIdentity::VerifiedDaemon {
            anyhow::bail!("ephemeral daemon v2 receipt did not verify its exact process identity");
        }
        *process
            .receipt
            .lock()
            .map_err(|_| anyhow::anyhow!("ephemeral receipt lock poisoned"))? = Some(receipt);
        Ok(())
    }

    /// Transfer ownership away from this guard without stopping the daemon.
    /// Until an explicit handoff, dropping a provisional owner remains
    /// fail-safe and reaps the daemon it spawned.
    pub fn disarm(&self) {
        self.cleanup_state.disarm();
    }
}

fn shutdown_shared(
    state: &CleanupState,
    socket: &Path,
    process: Option<ProcessCleanup>,
) -> anyhow::Result<()> {
    let mut phase = state
        .phase
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    loop {
        match &*phase {
            CleanupPhase::Pending => {
                *phase = CleanupPhase::Running;
                break;
            }
            CleanupPhase::Running => {
                phase = state
                    .completed
                    .wait(phase)
                    .unwrap_or_else(|error| error.into_inner());
            }
            CleanupPhase::Complete(result) => {
                return result
                    .as_ref()
                    .map(|()| ())
                    .map_err(|error| anyhow::anyhow!(error.to_string()));
            }
        }
    }
    drop(phase);

    let result = if let Some(cleanup) = process {
        let (completed, completion) = std::sync::mpsc::channel();
        let reap = ProcessReap {
            cleanup: cleanup.clone(),
            completed: Some(completed),
            attempts: 0,
        };
        match process_reaper() {
            Ok(reaper) => match reaper.send(reap) {
                Ok(()) => completion
                    .recv()
                    .context("ephemeral process reaper dropped completion")
                    .and_then(|result| result),
                Err(error) => run_cleanup_fallback_until_released(&error.0.cleanup),
            },
            Err(error) => {
                let fallback = run_cleanup_fallback_until_released(&cleanup);
                match fallback {
                    Ok(()) => Err(error),
                    Err(fallback) => Err(anyhow::anyhow!(
                        "{error}; synchronous exact-child cleanup also failed: {fallback}"
                    )),
                }
            }
        }
    } else {
        stop_daemon_blocking(socket);
        Ok(())
    };
    publish_cleanup_result(state, result)
}

fn publish_cleanup_result(state: &CleanupState, result: anyhow::Result<()>) -> anyhow::Result<()> {
    let stored = result
        .as_ref()
        .map(|()| ())
        .map_err(|error| Arc::<str>::from(format!("{error:#}")));
    *state
        .phase
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = CleanupPhase::Complete(stored);
    state.completed.notify_all();
    result
}

/// Owns a newly spawned child before its OS start identity can be captured.
/// Dropping this value transfers the exact child handle to the process reaper;
/// consequently no identity-read error can orphan or detach the child.
pub(crate) struct ProvisionalEphemeralChild {
    cleanup: ProcessCleanup,
}

impl ProvisionalEphemeralChild {
    pub(crate) fn new(paths: crate::daemon::DaemonPaths, child: std::process::Child) -> Self {
        Self {
            cleanup: ProcessCleanup {
                paths,
                child: Arc::new(std::sync::Mutex::new(Some(child))),
                receipt: Arc::new(std::sync::Mutex::new(None)),
                launch_start: None,
                launch_executable: None,
            },
        }
    }

    pub(crate) fn id(&self) -> anyhow::Result<u32> {
        self.cleanup
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("ephemeral child handle poisoned"))?
            .as_ref()
            .map(std::process::Child::id)
            .context("ephemeral child already transferred")
    }

    pub(crate) fn into_child(mut self) -> anyhow::Result<std::process::Child> {
        let child = self
            .cleanup
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("ephemeral child handle poisoned"))?
            .take()
            .context("ephemeral child already transferred")?;
        Ok(child)
    }

    pub(crate) fn shutdown(self) -> anyhow::Result<()> {
        run_cleanup_fallback_until_released(&self.cleanup)
    }
}

impl Drop for ProvisionalEphemeralChild {
    fn drop(&mut self) {
        if !process_child_retained(&self.cleanup) {
            return;
        }
        let reap = ProcessReap {
            cleanup: self.cleanup.clone(),
            completed: None,
            attempts: 0,
        };
        match process_reaper() {
            Ok(reaper) => {
                if let Err(error) = reaper.send(reap) {
                    if let Err(cleanup_error) =
                        run_cleanup_fallback_until_released(&error.0.cleanup)
                    {
                        tracing::error!(%cleanup_error, "provisional child cleanup failed");
                    }
                }
            }
            Err(error) => {
                tracing::error!(%error, "process reaper unavailable for provisional child");
                if let Err(cleanup_error) = run_cleanup_fallback_until_released(&reap.cleanup) {
                    tracing::error!(%cleanup_error, "provisional child cleanup failed");
                }
            }
        }
    }
}

pub fn aggregate_shutdown_result<T>(
    command: anyhow::Result<T>,
    shutdown: anyhow::Result<()>,
) -> anyhow::Result<T> {
    match (command, shutdown) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(shutdown)) => Err(shutdown).context("shutting down owned daemon"),
        (Err(command), Err(shutdown)) => Err(anyhow::anyhow!(
            "command failed: {command:#}; owned daemon shutdown also failed: {shutdown:#}"
        )),
    }
}

impl Drop for EphemeralDaemonGuard {
    fn drop(&mut self) {
        if let Err(error) = shutdown_shared(&self.cleanup_state, &self.socket, self.process.clone())
        {
            tracing::error!(%error, "emergency ephemeral cleanup failed");
        }
    }
}

/// Best-effort synchronous `StopDaemon`. Connects to the daemon socket with
/// the blocking std `UnixStream`, writes one NDJSON request, and returns —
/// usable from `Drop`. Any failure (daemon already gone, socket removed) is
/// swallowed; the watchdog (Layer C) is the final backstop.
pub fn stop_daemon_blocking(socket: &Path) {
    let Ok(envelope) = serde_json::to_string(&Envelope::request(
        uuid::Uuid::new_v4(),
        Request::StopDaemon { grace_secs: None },
    )) else {
        return;
    };
    #[cfg(unix)]
    {
        use std::io::{Read as _, Write as _};
        use std::os::unix::net::UnixStream as StdUnixStream;
        use std::time::Duration;
        if let Ok(mut stream) = StdUnixStream::connect(socket) {
            let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            let _ = stream.write_all(envelope.as_bytes());
            let _ = stream.write_all(b"\n");
            let _ = stream.flush();
            // Block briefly for the daemon's reply before dropping the
            // connection. Without this, an immediate close races the daemon's
            // per-client task: the daemon sends its hello *first*, and if the
            // peer is already gone that send fails and the task returns before
            // it ever reads the `StopDaemon` line — losing the request. One
            // read (of the daemon's hello, or EOF/timeout) proves the task is
            // alive past its hello-send; it then reads our already-buffered
            // request off the kernel queue even after we close. The bytes are
            // discarded — we only need the daemon to have read.
            let mut sink = [0u8; 256];
            let _ = stream.read(&mut sink);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (socket, envelope);
    }
}

/// Spawn a task that fires the guard's synchronous shutdown on
/// SIGINT/SIGTERM (Ctrl-C / console-close on Windows). OS handlers are
/// installed synchronously before this function returns, so success means
/// there is no post-spawn registration window. Returns `Ok(None)` when there's
/// no guard (attached to a persistent daemon). Registration failure is
/// returned so the caller can immediately perform exact cleanup and fail
/// closed. `exit_on_signal` controls the post-reap behavior: `cockpit run`
/// exits the foreground promptly (it has no UI left to run), whereas the
/// TUI hands control back so its own restore path (leave alt-screen, print
/// the exit tail) still runs.
pub fn spawn_signal_shutdown(
    guard: Option<&EphemeralDaemonGuard>,
    exit_on_signal: bool,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    let Some(guard) = guard else {
        return Ok(None);
    };
    let signals = register_shutdown_signals()?;
    let cleanup_state = guard.cleanup_state.clone();
    let socket = guard.socket.clone();
    let process = guard.process.clone();
    Ok(Some(tokio::spawn(async move {
        if let Err(error) = wait_for_shutdown_signal(signals).await {
            tracing::error!(%error, "foreground signal watcher stopped without a signal");
            return;
        }
        let cleanup =
            tokio::task::spawn_blocking(move || shutdown_shared(&cleanup_state, &socket, process));
        match cleanup.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::error!(%error, "signal-triggered ephemeral cleanup failed"),
            Err(error) => tracing::error!(%error, "signal-triggered cleanup waiter failed"),
        }
        if exit_on_signal {
            // After reaping, exit the foreground promptly — the user asked
            // us to stop. The daemon is already (being) torn down.
            std::process::exit(130);
        }
    })))
}

#[cfg(unix)]
struct RegisteredShutdownSignals {
    interrupt: Option<RegisteredSignal>,
    terminate: Option<RegisteredSignal>,
}

#[cfg(unix)]
fn register_shutdown_signals() -> anyhow::Result<RegisteredShutdownSignals> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
    let mut terminate = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    Ok(RegisteredShutdownSignals {
        interrupt: Some(Box::pin(async move { interrupt.recv().await })),
        terminate: Some(Box::pin(async move { terminate.recv().await })),
    })
}

#[cfg(unix)]
async fn wait_for_shutdown_signal(signals: RegisteredShutdownSignals) -> anyhow::Result<()> {
    wait_for_registered_unix_signal(signals.interrupt, signals.terminate).await
}

#[cfg(unix)]
type RegisteredSignal =
    std::pin::Pin<Box<dyn std::future::Future<Output = Option<()>> + Send + 'static>>;

#[cfg(unix)]
async fn wait_for_registered_unix_signal(
    mut interrupt: Option<RegisteredSignal>,
    mut terminate: Option<RegisteredSignal>,
) -> anyhow::Result<()> {
    match (&mut interrupt, &mut terminate) {
        (Some(interrupt), Some(terminate)) => tokio::select! {
            signal = interrupt => signal.context("SIGINT stream ended"),
            signal = terminate => signal.context("SIGTERM stream ended"),
        },
        (Some(interrupt), None) => interrupt.await.context("SIGINT stream ended"),
        (None, Some(terminate)) => terminate.await.context("SIGTERM stream ended"),
        (None, None) => anyhow::bail!("neither SIGINT nor SIGTERM handler could be installed"),
    }
}

#[cfg(windows)]
struct RegisteredShutdownSignals {
    ctrl_c: tokio::signal::windows::CtrlC,
}

#[cfg(windows)]
fn register_shutdown_signals() -> anyhow::Result<RegisteredShutdownSignals> {
    Ok(RegisteredShutdownSignals {
        ctrl_c: tokio::signal::windows::ctrl_c().context("installing console shutdown handler")?,
    })
}

#[cfg(windows)]
async fn wait_for_shutdown_signal(mut signals: RegisteredShutdownSignals) -> anyhow::Result<()> {
    signals
        .ctrl_c
        .recv()
        .await
        .context("console shutdown signal stream ended")
}

#[cfg(not(any(unix, windows)))]
struct RegisteredShutdownSignals;

#[cfg(not(any(unix, windows)))]
fn register_shutdown_signals() -> anyhow::Result<RegisteredShutdownSignals> {
    anyhow::bail!("foreground signal cleanup is unsupported on this platform")
}

#[cfg(not(any(unix, windows)))]
async fn wait_for_shutdown_signal(_: RegisteredShutdownSignals) -> anyhow::Result<()> {
    anyhow::bail!("foreground signal cleanup is unsupported on this platform")
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use crate::daemon::proto::{Body, ProtoStream, RecvFrame, Response};
    use tokio::io::AsyncBufReadExt;
    use tokio::net::UnixListener;

    fn child_guard(
        root: &Path,
        name: &str,
    ) -> (EphemeralDaemonGuard, crate::daemon::DaemonPaths, u32) {
        let paths = crate::daemon::DaemonPaths {
            socket: root.join(format!("{name}.sock")),
            pid_file: root.join(format!("{name}.pid")),
            ephemeral: true,
        };
        let child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn fixture child");
        let pid = child.id();
        let process_start = cockpit_host::daemon_lifecycle::process_start_identity(pid)
            .expect("fixture child start identity");
        let guard = EphemeralDaemonGuard::new(
            paths.clone(),
            crate::daemon::DetachedEphemeralChild {
                child,
                process_start,
                executable: std::fs::canonicalize("/bin/sleep").unwrap(),
            },
        );
        (guard, paths, pid)
    }

    fn publish_owned_receipt(
        guard: &EphemeralDaemonGuard,
        paths: &crate::daemon::DaemonPaths,
        pid: u32,
    ) -> DaemonPidReceipt {
        let executable = std::fs::canonicalize("/bin/sleep").unwrap();
        let receipt =
            cockpit_host::daemon_lifecycle::write_pid_file(&paths.pid_file, pid, &executable)
                .unwrap();
        *guard.process.as_ref().unwrap().receipt.lock().unwrap() = Some(receipt.clone());
        receipt
    }

    fn hello_response(protocol_version: u32) -> Response {
        Response::DaemonStatus {
            pid: std::process::id(),
            uptime_secs: 0,
            active_sessions: 0,
            socket_path: "fixture.sock".to_string(),
            daemon_version: crate::daemon::proto::DAEMON_VERSION.to_string(),
            protocol_version,
            paused_sessions: 0,
            database_path: "fixture.db".to_string(),
            schema_version: 1,
        }
    }

    async fn send_hello(stream: &mut ProtoStream<tokio::net::UnixStream>, version: u32) {
        stream
            .send(&Envelope::response(
                uuid::Uuid::nil(),
                hello_response(version),
            ))
            .await
            .unwrap();
    }

    async fn receive_stop(stream: &mut ProtoStream<tokio::net::UnixStream>) -> uuid::Uuid {
        match stream.recv().await.unwrap().unwrap() {
            RecvFrame::Envelope(Envelope {
                body: Body::Request { id, request },
                ..
            }) => {
                assert!(matches!(request, Request::StopDaemon { grace_secs: None }));
                id
            }
            frame => panic!("expected StopDaemon request, got {frame:?}"),
        }
    }

    fn reap_fixture_child(guard: &EphemeralDaemonGuard) {
        let cleanup = guard.process.as_ref().unwrap();
        let mut child = cleanup.child.lock().unwrap();
        if let Some(child) = child.as_mut() {
            kill_and_wait_exact_child(child).unwrap();
        }
        *child = None;
    }

    /// Accept one connection on `socket`, read the first NDJSON line, and
    /// return it. Models the daemon's read side closely enough to assert
    /// the guard's synchronous `StopDaemon` actually lands on the wire.
    async fn accept_one_line(listener: UnixListener) -> Option<String> {
        let (stream, _) = listener.accept().await.ok()?;
        let mut reader = tokio::io::BufReader::new(stream);
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(n) if n > 0 => Some(line),
            _ => None,
        }
    }

    fn parse_request(line: &str) -> Request {
        let env: Envelope = serde_json::from_str(line.trim_end()).expect("valid envelope");
        match env.body {
            Body::Request { request, .. } => request,
            other => panic!("expected a request envelope, got {other:?}"),
        }
    }

    /// Layer A: dropping the guard (the path taken on an early `?` return
    /// or an unwind) sends a `StopDaemon` request to the daemon socket.
    #[tokio::test]
    async fn guard_drop_sends_stop_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(accept_one_line(listener));

        // Build then immediately drop the guard, off the runtime thread
        // (the real drop fires from sync `Drop`).
        let socket_for_guard = socket.clone();
        tokio::task::spawn_blocking(move || {
            let guard = EphemeralDaemonGuard::new_for_socket(socket_for_guard);
            drop(guard);
        })
        .await
        .unwrap();

        let line = tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .expect("server timed out")
            .unwrap()
            .expect("a line arrived");
        assert!(matches!(
            parse_request(&line),
            Request::StopDaemon { grace_secs: None }
        ));
    }

    /// Layer A: an explicit `shutdown()` (the happy path) disarms the
    /// guard, so the subsequent drop is a no-op and only one `StopDaemon`
    /// is ever sent. The daemon socket receives exactly one line.
    #[tokio::test]
    async fn guard_shutdown_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(accept_one_line(listener));

        let socket_for_guard = socket.clone();
        tokio::task::spawn_blocking(move || {
            let guard = EphemeralDaemonGuard::new_for_socket(socket_for_guard);
            assert!(guard.cleanup_state.is_pending());
            guard.shutdown().unwrap();
            // Disarmed: the second call and the drop must both be no-ops.
            assert!(!guard.cleanup_state.is_pending());
            guard.shutdown().unwrap();
            drop(guard);
        })
        .await
        .unwrap();

        // The one-and-only request landed.
        let line = tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .expect("server timed out")
            .unwrap()
            .expect("a line arrived");
        assert!(matches!(
            parse_request(&line),
            Request::StopDaemon { grace_secs: None }
        ));
    }

    #[test]
    fn replacement_receipt_with_same_pid_is_preserved() {
        initialize_process_reaper().expect("process reaper");
        let root = tempfile::tempdir().unwrap();
        let (guard, paths, pid) = child_guard(root.path(), "replacement");
        let executable = std::fs::canonicalize("/bin/sleep").unwrap();
        let expected =
            cockpit_host::daemon_lifecycle::write_pid_file(&paths.pid_file, pid, &executable)
                .unwrap();
        *guard.process.as_ref().unwrap().receipt.lock().unwrap() = Some(expected);
        std::fs::remove_file(&paths.pid_file).unwrap();
        let replacement =
            cockpit_host::daemon_lifecycle::write_pid_file(&paths.pid_file, pid, &executable)
                .unwrap();

        assert!(guard.shutdown().is_err());
        assert_eq!(
            read_daemon_pid_record(&paths.pid_file),
            Some(DaemonPidRecord::Receipt(replacement))
        );
    }

    #[test]
    fn provisional_drop_reaps_child_without_publication() {
        initialize_process_reaper().expect("process reaper");
        let root = tempfile::tempdir().unwrap();
        let (guard, _paths, _pid) = child_guard(root.path(), "unpublished");
        let child = guard.process.as_ref().unwrap().child.clone();
        drop(guard);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
        loop {
            let reaped = child
                .lock()
                .unwrap()
                .as_mut()
                .is_none_or(|child| child.try_wait().unwrap().is_some());
            if reaped {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "child was orphaned");
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    #[test]
    fn late_receipt_is_captured_before_exact_teardown() {
        initialize_process_reaper().expect("process reaper");
        let root = tempfile::tempdir().unwrap();
        let (guard, paths, pid) = child_guard(root.path(), "late-publication");
        let receipt = guard.process.as_ref().unwrap().receipt.clone();
        let child = guard.process.as_ref().unwrap().child.clone();
        let published_paths = paths.clone();
        let publisher = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let executable = std::fs::canonicalize("/bin/sleep").unwrap();
            let receipt = cockpit_host::daemon_lifecycle::write_pid_file(
                &published_paths.pid_file,
                pid,
                &executable,
            )
            .unwrap();
            std::fs::write(&published_paths.socket, b"stale socket").unwrap();
            receipt
        });
        drop(guard);
        let published = publisher.join().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while receipt.lock().unwrap().as_ref() != Some(&published) {
            assert!(
                std::time::Instant::now() < deadline,
                "reaper missed late receipt"
            );
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        while child.lock().unwrap().is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "reaper did not finish late-publication cleanup"
            );
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(!paths.pid_file.exists());
        assert!(!paths.socket.exists());
    }

    #[test]
    fn cleanup_panic_retains_and_reaps_exact_child() {
        let root = tempfile::tempdir().unwrap();
        let (guard, _paths, _pid) = child_guard(root.path(), "cleanup-panic");
        let cleanup = guard.process.as_ref().unwrap().clone();
        guard.disarm();
        INJECT_PROCESS_CLEANUP_PANIC.with(|inject| inject.set(true));
        assert!(run_process_cleanup_recovering(&cleanup).is_err());
        assert!(cleanup.child.lock().unwrap().is_none());
    }

    #[test]
    fn poisoned_child_mutex_still_emergency_reaps() {
        let root = tempfile::tempdir().unwrap();
        let (guard, _paths, _pid) = child_guard(root.path(), "poisoned-child");
        let cleanup = guard.process.as_ref().unwrap().clone();
        guard.disarm();
        let child = cleanup.child.clone();
        let _ = std::thread::spawn(move || {
            let _locked = child.lock().unwrap();
            panic!("poison child handle");
        })
        .join();
        assert!(run_process_cleanup_recovering(&cleanup).is_err());
        assert!(
            cleanup
                .child
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_none()
        );
    }

    #[test]
    fn injected_kill_failure_retains_child_for_retry() {
        let root = tempfile::tempdir().unwrap();
        let (guard, paths, _pid) = child_guard(root.path(), "kill-failure");
        let cleanup = guard.process.as_ref().unwrap().clone();
        guard.disarm();
        std::fs::write(&paths.socket, b"owned artifact").unwrap();
        INJECT_CHILD_KILL_FAILURE.with(|inject| inject.set(true));
        assert!(emergency_kill_wait_and_retire(&cleanup).is_err());
        assert!(process_child_retained(&cleanup));
        assert!(paths.socket.exists(), "metadata retired before proven exit");
        emergency_kill_wait_and_retire(&cleanup).expect("retry reaps exact child");
        assert!(!process_child_retained(&cleanup));
    }

    #[test]
    fn injected_wait_failure_retains_killed_child_until_reaped() {
        let root = tempfile::tempdir().unwrap();
        let (guard, _paths, _pid) = child_guard(root.path(), "wait-failure");
        let cleanup = guard.process.as_ref().unwrap().clone();
        guard.disarm();
        INJECT_CHILD_WAIT_FAILURE.with(|inject| inject.set(true));
        assert!(emergency_kill_wait_and_retire(&cleanup).is_err());
        assert!(process_child_retained(&cleanup));
        assert!(
            run_cleanup_fallback_until_released(&cleanup).is_err(),
            "the injected ownership-critical wait failure must remain visible"
        );
        assert!(!process_child_retained(&cleanup));
    }

    #[test]
    fn already_exited_child_clears_owner_and_exact_late_metadata() {
        let root = tempfile::tempdir().unwrap();
        let (guard, paths, pid) = child_guard(root.path(), "already-exited");
        let cleanup = guard.process.as_ref().unwrap().clone();
        guard.disarm();
        let executable = std::fs::canonicalize("/bin/sleep").unwrap();
        cockpit_host::daemon_lifecycle::write_pid_file(&paths.pid_file, pid, &executable).unwrap();
        std::fs::write(&paths.socket, b"stale socket").unwrap();
        {
            let mut child = cleanup.child.lock().unwrap();
            kill_and_wait_exact_child(child.as_mut().unwrap()).unwrap();
        }
        cleanup_exact_process(&cleanup).expect("already-exited cleanup");
        assert!(!process_child_retained(&cleanup));
        assert!(!paths.pid_file.exists());
        assert!(!paths.socket.exists());
    }

    #[tokio::test]
    async fn one_failed_signal_registration_waits_for_remaining_handler() {
        let delivered: RegisteredSignal = Box::pin(async { Some(()) });
        wait_for_registered_unix_signal(None, Some(delivered))
            .await
            .expect("remaining handler delivers signal");
    }

    #[tokio::test]
    async fn both_failed_signal_registrations_are_not_a_signal() {
        assert!(wait_for_registered_unix_signal(None, None).await.is_err());
    }

    #[test]
    fn identity_less_owner_reaps_child_but_preserves_same_pid_receipt() {
        initialize_process_reaper().expect("process reaper");
        let root = tempfile::tempdir().unwrap();
        let paths = crate::daemon::DaemonPaths {
            socket: root.path().join("identity-less.sock"),
            pid_file: root.path().join("identity-less.pid"),
            ephemeral: true,
        };
        let child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn fixture child");
        let pid = child.id();
        let provisional = ProvisionalEphemeralChild::new(paths.clone(), child);
        let executable = std::fs::canonicalize("/bin/sleep").unwrap();
        let first =
            cockpit_host::daemon_lifecycle::write_pid_file(&paths.pid_file, pid, &executable)
                .unwrap();
        std::fs::remove_file(&paths.pid_file).unwrap();
        let replacement =
            cockpit_host::daemon_lifecycle::write_pid_file(&paths.pid_file, pid, &executable)
                .unwrap();
        assert_ne!(first.publication_nonce, replacement.publication_nonce);
        std::fs::write(&paths.socket, b"replacement socket").unwrap();

        provisional
            .shutdown()
            .expect_err("identity-less cleanup reports forced unpublished-child teardown");

        assert_eq!(
            read_daemon_pid_record(&paths.pid_file),
            Some(DaemonPidRecord::Receipt(replacement))
        );
        assert!(paths.socket.exists());
    }

    #[tokio::test]
    async fn owner_protocol_hello_stop_ack_and_child_exit_is_valid() {
        let root = tempfile::tempdir().unwrap();
        let (guard, paths, pid) = child_guard(root.path(), "protocol-valid");
        let expected = publish_owned_receipt(&guard, &paths, pid);
        let listener = UnixListener::bind(&paths.socket).unwrap();
        let retired_paths = paths.clone();
        let (retired, retirement) = std::sync::mpsc::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = ProtoStream::new(socket);
            send_hello(&mut stream, crate::daemon::proto::PROTOCOL_VERSION).await;
            let id = receive_stop(&mut stream).await;
            stream
                .send(&Envelope::response(id, Response::Ack))
                .await
                .unwrap();
            std::fs::remove_file(&retired_paths.pid_file).unwrap();
            std::fs::remove_file(&retired_paths.socket).unwrap();
            retired.send(()).unwrap();
            // Model the real daemon exiting after its acknowledged drain.
            assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) }, 0);
        });

        let cleanup = guard.process.as_ref().unwrap().clone();
        request_owned_graceful_stop_async(
            &cleanup,
            &expected,
            || {},
            move || retirement.recv().unwrap(),
        )
        .await
        .unwrap();
        tokio::task::spawn_blocking(move || {
            let mut child = cleanup.child.lock().unwrap();
            child_wait(child.as_mut().unwrap()).unwrap();
            *child = None;
        })
        .await
        .unwrap();
        server.await.unwrap();
        guard.disarm();
        assert_eq!(
            read_daemon_pid_record(&paths.pid_file),
            None,
            "daemon self-retirement before process exit is accepted"
        );
        assert!(!paths.socket.exists());
        assert_ne!(expected.publication_nonce, [0; 32]);
    }

    #[tokio::test]
    async fn malformed_post_ack_receipt_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let (guard, paths, pid) = child_guard(root.path(), "protocol-malformed-post-ack");
        let expected = publish_owned_receipt(&guard, &paths, pid);
        let cleanup = guard.process.as_ref().unwrap().clone();
        let listener = UnixListener::bind(&paths.socket).unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = ProtoStream::new(socket);
            send_hello(&mut stream, crate::daemon::proto::PROTOCOL_VERSION).await;
            let id = receive_stop(&mut stream).await;
            stream
                .send(&Envelope::response(id, Response::Ack))
                .await
                .unwrap();
        });
        let malformed_path = paths.pid_file.clone();
        let error = request_owned_graceful_stop_async(
            &cleanup,
            &expected,
            || {},
            move || std::fs::write(&malformed_path, "not-a-receipt\n").unwrap(),
        )
        .await
        .unwrap_err();
        server.await.unwrap();
        assert!(error.to_string().contains("became malformed"));
        assert_eq!(
            std::fs::read_to_string(&paths.pid_file).unwrap(),
            "not-a-receipt\n"
        );
        guard.disarm();
        reap_fixture_child(&guard);
    }

    #[tokio::test]
    async fn owner_protocol_rejects_malformed_and_incompatible_hello() {
        use tokio::io::AsyncWriteExt as _;

        for (name, malformed) in [("malformed", true), ("incompatible", false)] {
            let root = tempfile::tempdir().unwrap();
            let (guard, paths, pid) = child_guard(root.path(), name);
            let expected = publish_owned_receipt(&guard, &paths, pid);
            let cleanup = guard.process.as_ref().unwrap().clone();
            let listener = UnixListener::bind(&paths.socket).unwrap();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                if malformed {
                    let mut socket = socket;
                    socket.write_all(b"not-json\n").await.unwrap();
                } else {
                    let mut stream = ProtoStream::new(socket);
                    send_hello(
                        &mut stream,
                        crate::daemon::proto::PROTOCOL_VERSION.saturating_add(1),
                    )
                    .await;
                }
            });

            assert!(
                request_owned_graceful_stop_async(&cleanup, &expected, || {}, || {})
                    .await
                    .is_err()
            );
            server.await.unwrap();
            guard.disarm();
            reap_fixture_child(&guard);
        }
    }

    #[tokio::test]
    async fn owner_protocol_rejects_unexpected_shutdown_response() {
        let root = tempfile::tempdir().unwrap();
        let (guard, paths, pid) = child_guard(root.path(), "protocol-unexpected");
        let expected = publish_owned_receipt(&guard, &paths, pid);
        let cleanup = guard.process.as_ref().unwrap().clone();
        let listener = UnixListener::bind(&paths.socket).unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = ProtoStream::new(socket);
            send_hello(&mut stream, crate::daemon::proto::PROTOCOL_VERSION).await;
            let id = receive_stop(&mut stream).await;
            stream
                .send(&Envelope::response(id, Response::Unknown))
                .await
                .unwrap();
        });

        assert!(
            request_owned_graceful_stop_async(&cleanup, &expected, || {}, || {})
                .await
                .unwrap_err()
                .to_string()
                .contains("unexpected owner shutdown response")
        );
        server.await.unwrap();
        guard.disarm();
        reap_fixture_child(&guard);
    }

    #[tokio::test]
    async fn replacement_during_hello_never_receives_stop_daemon() {
        let root = tempfile::tempdir().unwrap();
        let (guard, paths, pid) = child_guard(root.path(), "protocol-replacement");
        let expected = publish_owned_receipt(&guard, &paths, pid);
        let cleanup = guard.process.as_ref().unwrap().clone();
        let listener = UnixListener::bind(&paths.socket).unwrap();
        let (observed, received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = ProtoStream::new(socket);
            send_hello(&mut stream, crate::daemon::proto::PROTOCOL_VERSION).await;
            let request =
                tokio::time::timeout(std::time::Duration::from_millis(100), stream.recv()).await;
            let received_stop = matches!(
                request,
                Ok(Ok(Some(RecvFrame::Envelope(Envelope {
                    body: Body::Request {
                        request: Request::StopDaemon { .. },
                        ..
                    },
                    ..
                }))))
            );
            observed.send(received_stop).unwrap();
        });
        let replacement_path = paths.pid_file.clone();
        let executable = std::fs::canonicalize("/bin/sleep").unwrap();
        let result = request_owned_graceful_stop_async(
            &cleanup,
            &expected,
            move || {
                std::fs::remove_file(&replacement_path).unwrap();
                cockpit_host::daemon_lifecycle::write_pid_file(&replacement_path, pid, &executable)
                    .unwrap();
            },
            || {},
        )
        .await;

        assert!(result.unwrap_err().to_string().contains("receipt changed"));
        assert!(!received.await.unwrap(), "replacement received StopDaemon");
        server.await.unwrap();
        guard.disarm();
        reap_fixture_child(&guard);
    }

    #[tokio::test]
    async fn replacement_after_stop_ack_is_reported_and_preserved() {
        let root = tempfile::tempdir().unwrap();
        let (guard, paths, pid) = child_guard(root.path(), "protocol-post-ack-replacement");
        let expected = publish_owned_receipt(&guard, &paths, pid);
        let cleanup = guard.process.as_ref().unwrap().clone();
        let listener = UnixListener::bind(&paths.socket).unwrap();
        let replacement_path = paths.pid_file.clone();
        let executable = std::fs::canonicalize("/bin/sleep").unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = ProtoStream::new(socket);
            send_hello(&mut stream, crate::daemon::proto::PROTOCOL_VERSION).await;
            let id = receive_stop(&mut stream).await;
            std::fs::remove_file(&replacement_path).unwrap();
            let replacement =
                cockpit_host::daemon_lifecycle::write_pid_file(&replacement_path, pid, &executable)
                    .unwrap();
            stream
                .send(&Envelope::response(id, Response::Ack))
                .await
                .unwrap();
            replacement
        });

        let error = request_owned_graceful_stop_async(&cleanup, &expected, || {}, || {})
            .await
            .unwrap_err();
        let replacement = server.await.unwrap();
        assert!(error.to_string().contains("after owner graceful-stop"));
        assert_eq!(
            read_daemon_pid_record(&paths.pid_file),
            Some(DaemonPidRecord::Receipt(replacement))
        );
        guard.disarm();
        reap_fixture_child(&guard);
    }

    #[tokio::test]
    async fn acknowledged_stop_that_exceeds_drain_bound_forces_exact_child() {
        let root = tempfile::tempdir().unwrap();
        let (guard, paths, pid) = child_guard(root.path(), "protocol-timeout-force");
        publish_owned_receipt(&guard, &paths, pid);
        let cleanup = guard.process.as_ref().unwrap().clone();
        let listener = UnixListener::bind(&paths.socket).unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = ProtoStream::new(socket);
            send_hello(&mut stream, crate::daemon::proto::PROTOCOL_VERSION).await;
            let id = receive_stop(&mut stream).await;
            stream
                .send(&Envelope::response(id, Response::Ack))
                .await
                .unwrap();
        });

        let cleanup_result = tokio::task::spawn_blocking(move || {
            INJECT_OWNER_EXIT_TIMEOUT_MS.with(|value| value.set(Some(1)));
            cleanup_exact_process(&cleanup)
        })
        .await
        .unwrap();
        server.await.unwrap();
        assert!(cleanup_result.is_err());
        assert!(!process_child_retained(guard.process.as_ref().unwrap()));
        guard.disarm();
    }

    #[test]
    fn competing_shutdown_waiters_join_the_same_completion_result() {
        let state = Arc::new(CleanupState::new());
        *state.phase.lock().unwrap() = CleanupPhase::Running;
        let waiter_state = state.clone();
        let waiter =
            std::thread::spawn(move || shutdown_shared(&waiter_state, Path::new("unused"), None));
        std::thread::sleep(std::time::Duration::from_millis(25));
        let published = anyhow::anyhow!("deterministic teardown failure");
        assert!(publish_cleanup_result(&state, Err(published)).is_err());
        let joined = waiter.join().unwrap().unwrap_err().to_string();
        assert_eq!(joined, "deterministic teardown failure");
    }

    #[test]
    fn owned_graceful_ack_and_exit_is_clean() {
        let root = tempfile::tempdir().unwrap();
        let (guard, paths, pid) = child_guard(root.path(), "owner-graceful");
        let cleanup = guard.process.as_ref().unwrap().clone();
        guard.disarm();
        let executable = std::fs::canonicalize("/bin/sleep").unwrap();
        let receipt =
            cockpit_host::daemon_lifecycle::write_pid_file(&paths.pid_file, pid, &executable)
                .unwrap();
        *cleanup.receipt.lock().unwrap() = Some(receipt);
        {
            let mut child = cleanup.child.lock().unwrap();
            kill_and_wait_exact_child(child.as_mut().unwrap()).unwrap();
        }
        INJECT_OWNER_GRACEFUL_STOP.with(|value| value.set(Some(true)));

        cleanup_exact_process(&cleanup).expect("graceful owner exit is terminal success");
        assert!(!process_child_retained(&cleanup));
        assert!(!paths.pid_file.exists());
    }

    #[test]
    fn owned_graceful_timeout_forces_exact_child_and_reports_failure() {
        let root = tempfile::tempdir().unwrap();
        let (guard, paths, pid) = child_guard(root.path(), "owner-timeout");
        let cleanup = guard.process.as_ref().unwrap().clone();
        guard.disarm();
        let executable = std::fs::canonicalize("/bin/sleep").unwrap();
        let receipt =
            cockpit_host::daemon_lifecycle::write_pid_file(&paths.pid_file, pid, &executable)
                .unwrap();
        *cleanup.receipt.lock().unwrap() = Some(receipt);
        INJECT_OWNER_GRACEFUL_STOP.with(|value| value.set(Some(true)));
        INJECT_OWNER_EXIT_TIMEOUT_MS.with(|value| value.set(Some(1)));

        assert!(cleanup_exact_process(&cleanup).is_err());
        assert!(!process_child_retained(&cleanup));
        assert!(!paths.pid_file.exists());
    }
}
