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

use crate::daemon::proto::{Envelope, Request};

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
    /// Cleared once shutdown has been requested (happy path) so the drop
    /// doesn't fire a redundant second request.
    armed: Arc<AtomicBool>,
}

impl EphemeralDaemonGuard {
    pub fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            armed: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Disarm and synchronously request shutdown. Idempotent: the first
    /// caller wins, later calls (including the drop) are no-ops.
    pub fn shutdown(&self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            stop_daemon_blocking(&self.socket);
        }
    }
}

impl Drop for EphemeralDaemonGuard {
    fn drop(&mut self) {
        self.shutdown();
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
            stop_daemon_blocking(&socket);
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
            let guard = EphemeralDaemonGuard::new(socket_for_guard);
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
            let guard = EphemeralDaemonGuard::new(socket_for_guard);
            assert!(guard.armed.load(Ordering::SeqCst));
            guard.shutdown();
            // Disarmed: the second call and the drop must both be no-ops.
            assert!(!guard.armed.load(Ordering::SeqCst));
            guard.shutdown();
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
}
