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
use std::sync::atomic::{AtomicBool, Ordering};

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
}

struct ProcessReap {
    cleanup: ProcessCleanup,
    completed: Option<std::sync::mpsc::Sender<anyhow::Result<()>>>,
}

static PROCESS_REAPER: std::sync::OnceLock<Option<std::sync::mpsc::Sender<ProcessReap>>> =
    std::sync::OnceLock::new();

pub(crate) fn initialize_process_reaper() -> anyhow::Result<()> {
    PROCESS_REAPER
        .get_or_init(|| {
            let (send, receive) = std::sync::mpsc::channel::<ProcessReap>();
            std::thread::Builder::new()
                .name("cockpit-ephemeral-process-reaper".to_string())
                .spawn(move || {
                    while let Ok(reap) = receive.recv() {
                        let result = cleanup_exact_process(&reap.cleanup);
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

fn process_reaper() -> anyhow::Result<&'static std::sync::mpsc::Sender<ProcessReap>> {
    initialize_process_reaper()?;
    PROCESS_REAPER
        .get()
        .and_then(Option::as_ref)
        .context("ephemeral process reaper unavailable")
}

fn cleanup_exact_process(cleanup: &ProcessCleanup) -> anyhow::Result<()> {
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
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        if let Some(DaemonPidRecord::Receipt(receipt)) =
            read_daemon_pid_record(&cleanup.paths.pid_file)
            && receipt.pid == expected_pid
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
    let result = if let Some(expected) = expected {
        if read_daemon_pid_record(&cleanup.paths.pid_file)
            != Some(DaemonPidRecord::Receipt(expected.clone()))
        {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!(
                "ephemeral daemon receipt changed before teardown; exact child was terminated without touching replacement metadata"
            );
        }
        match crate::daemon::stop_exact(&cleanup.paths, &expected) {
            Ok(true) => Ok(()),
            Ok(false) => {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!(
                    "exact receipt no longer named a verified live daemon; exact child was reaped"
                )
            }
            Err(error) => Err(error),
        }
    } else {
        child
            .kill()
            .context("terminating unpublished ephemeral child")?;
        child
            .wait()
            .context("reaping unpublished ephemeral child")?;
        anyhow::bail!(
            "ephemeral child never published an exact v2 PID receipt; terminated exact child"
        )
    };
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        *child_slot = None;
        return result;
    }
    let exit_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut forced_exit = false;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if std::time::Instant::now() >= exit_deadline {
            child.kill().context("forcing exact ephemeral child exit")?;
            child.wait().context("reaping forced ephemeral child")?;
            forced_exit = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    *child_slot = None;
    if forced_exit && result.is_ok() {
        anyhow::bail!("ephemeral daemon did not exit after verified stop; exact child was forced")
    }
    result
}

/// RAII backstop that shuts down an ephemeral daemon the current process
/// owns, on **every** exit path — early `?` returns, panics/unwinds, and
/// the normal end of the run/session (Layer A). A process that *attached*
/// to a pre-existing persistent daemon (`owns_daemon = false`) builds no
/// guard, so it never shuts anything down.
///
/// The drop performs a best-effort *synchronous* `StopDaemon` so it works
/// from inside `Drop` without juggling the async runtime: it connects to
/// the daemon's Unix socket with the std (blocking) `UnixStream` and writes
/// one NDJSON `StopDaemon` request. The daemon routes it through its single
/// graceful drain (see `server::handle_request` / `server::request_shutdown`).
pub struct EphemeralDaemonGuard {
    socket: PathBuf,
    process: Option<ProcessCleanup>,
    /// Cleared once shutdown has been requested (happy path) so the drop
    /// doesn't fire a redundant second request.
    armed: Arc<AtomicBool>,
}

impl EphemeralDaemonGuard {
    pub fn new(
        paths: crate::daemon::DaemonPaths,
        child: crate::daemon::DetachedEphemeralChild,
    ) -> Self {
        Self {
            socket: paths.socket.clone(),
            process: Some(ProcessCleanup {
                paths,
                child: Arc::new(std::sync::Mutex::new(Some(child.into_child()))),
                receipt: Arc::new(std::sync::Mutex::new(None)),
            }),
            armed: Arc::new(AtomicBool::new(true)),
        }
    }

    #[cfg(test)]
    fn new_for_socket(socket: PathBuf) -> Self {
        Self {
            socket,
            process: None,
            armed: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Disarm and synchronously request shutdown. Idempotent: the first
    /// caller wins, later calls (including the drop) are no-ops.
    pub fn shutdown(&self) -> anyhow::Result<()> {
        if self.armed.swap(false, Ordering::SeqCst) {
            if let Some(cleanup) = self.process.clone() {
                let (completed, completion) = std::sync::mpsc::channel();
                let reap = ProcessReap {
                    cleanup,
                    completed: Some(completed),
                };
                if let Err(error) = process_reaper()?.send(reap) {
                    // Explicit shutdown runs on the lifecycle-owned OS thread.
                    // If the process-lifetime reaper unexpectedly retired,
                    // retain exact ownership and perform the same bounded
                    // cleanup synchronously while surfacing its result.
                    return cleanup_exact_process(&error.0.cleanup);
                }
                completion
                    .recv()
                    .context("ephemeral process reaper dropped completion")??;
            } else {
                stop_daemon_blocking(&self.socket);
            }
        }
        Ok(())
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
            Some(DaemonPidRecord::Receipt(receipt)) if receipt.pid == pid => receipt,
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
        self.armed.store(false, Ordering::SeqCst);
    }
}

impl Drop for EphemeralDaemonGuard {
    fn drop(&mut self) {
        if !self.armed.swap(false, Ordering::SeqCst) {
            return;
        }
        if let Some(cleanup) = self.process.clone() {
            match process_reaper().and_then(|reaper| {
                reaper
                    .send(ProcessReap {
                        cleanup,
                        completed: None,
                    })
                    .map_err(|_| anyhow::anyhow!("ephemeral process reaper stopped"))
            }) {
                Ok(()) => {}
                Err(error) => tracing::error!(%error, "failed to enqueue ephemeral process reap"),
            }
        } else {
            stop_daemon_blocking(&self.socket);
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
/// SIGINT/SIGTERM (Ctrl-C / console-close on Windows). Returns `None` when
/// there's no guard (attached to a persistent daemon) — there's nothing to
/// reap. `exit_on_signal` controls the post-reap behavior: `cockpit run`
/// exits the foreground promptly (it has no UI left to run), whereas the
/// TUI hands control back so its own restore path (leave alt-screen, print
/// the exit tail) still runs.
pub fn spawn_signal_shutdown(
    guard: Option<&EphemeralDaemonGuard>,
    exit_on_signal: bool,
) -> Option<tokio::task::JoinHandle<()>> {
    let guard = guard?;
    let armed = guard.armed.clone();
    let socket = guard.socket.clone();
    let process = guard.process.clone();
    Some(tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut int = signal(SignalKind::interrupt()).ok();
            let mut term = signal(SignalKind::terminate()).ok();
            tokio::select! {
                _ = async { if let Some(s) = int.as_mut() { s.recv().await; } } => {}
                _ = async { if let Some(s) = term.as_mut() { s.recv().await; } } => {}
            }
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await.ok();
        }
        if armed.swap(false, Ordering::SeqCst) {
            if let Some(cleanup) = process {
                let (completed, completion) = std::sync::mpsc::channel();
                let reap = ProcessReap {
                    cleanup,
                    completed: Some(completed),
                };
                match process_reaper() {
                    Ok(reaper) => match reaper.send(reap) {
                        Ok(()) => {
                            let _ = tokio::task::spawn_blocking(move || completion.recv()).await;
                        }
                        Err(error) => {
                            let cleanup = error.0.cleanup;
                            let _ = tokio::task::spawn_blocking(move || {
                                cleanup_exact_process(&cleanup)
                            })
                            .await;
                        }
                    },
                    Err(error) => {
                        tracing::error!(%error, "signal-triggered daemon reaper unavailable");
                    }
                }
            } else {
                stop_daemon_blocking(&socket);
            }
        }
        if exit_on_signal {
            // After reaping, exit the foreground promptly — the user asked
            // us to stop. The daemon is already (being) torn down.
            std::process::exit(130);
        }
    }))
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use crate::daemon::proto::Body;
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
        let guard = EphemeralDaemonGuard::new(
            paths.clone(),
            crate::daemon::DetachedEphemeralChild { child },
        );
        (guard, paths, pid)
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
            assert!(guard.armed.load(Ordering::SeqCst));
            guard.shutdown().unwrap();
            // Disarmed: the second call and the drop must both be no-ops.
            assert!(!guard.armed.load(Ordering::SeqCst));
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
        let publisher = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let executable = std::fs::canonicalize("/bin/sleep").unwrap();
            cockpit_host::daemon_lifecycle::write_pid_file(&paths.pid_file, pid, &executable)
                .unwrap()
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
    }
}
