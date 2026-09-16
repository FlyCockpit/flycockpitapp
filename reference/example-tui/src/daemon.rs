//! Foreground daemon: bind, accept, tick, last-client teardown.
//!
//! Analog of `crates/cockpit-core` daemon server + `ephemeral_last_client_reaper`.
//!
//! Bind order matches Cockpit:
//! 1. Reserve the pid file (exclusive claim).
//! 2. Unlink any stale socket — only the pid winner may do this.
//! 3. Finish boot (here: record `opened_at`).
//! 4. Bind the socket. Clients that see a socket expect a hello promptly.
//! 5. Accept.
//!
//! Lifetime: wait until at least one client has sent `Subscribe`, then begin
//! teardown as soon as the count returns to zero. Hello-only probes never
//! count. There is no idle timeout.

use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use tokio::net::UnixListener;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;

use crate::client::Control;
use crate::host::{
    self, GENERATION_VAR, LISTENER_FD_VAR, NOTIFY_FD_VAR, OPENED_AT_VAR, WORKER_VERSION_VAR,
    bind_private_socket, reserve_pid_file,
};
use crate::paths::Paths;
use crate::proto::{Envelope, EnvelopeBody, Event, ProtoStream, Request, Response};

const DEFAULT_TICK: Duration = Duration::from_secs(1);

/// How long a resetting daemon waits for its successor to bind the staging
/// endpoint and answer a matching hello before aborting the handoff.
const SUCCESSOR_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// After a successful handoff, how long the predecessor waits for its clients
/// to honor the reconnect before it force-shuts-down anyway.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientPresence {
    pub count: usize,
    /// Monotonic: once a lifetime client has connected, a later disconnect
    /// cannot make the reaper forget that the owner has been used.
    pub has_lifetime_client: bool,
}

/// The pid file and socket this daemon currently owns and must clean up. A
/// successor starts owning the staging pair and swaps to the canonical pair
/// the instant it promotes, so teardown always targets the live files.
#[derive(Clone)]
struct EffectivePaths {
    pid_file: PathBuf,
    socket: PathBuf,
}

/// How this daemon booted, which decides its paths and open time.
enum Role {
    /// A fresh daemon: canonical paths, its own open time.
    Primary,
    /// A handoff successor: staging paths, and the predecessor's open time so
    /// uptime stays continuous across the swap.
    Successor { inherited_opened_at_unix_ms: u64 },
}

struct DaemonState {
    pid: u32,
    opened_at: Instant,
    opened_at_unix_ms: u64,
    /// Version of this worker generation. The classic daemon reports 0; a
    /// supervised worker inherits the supervisor's rolling counter.
    worker_version: u32,
    /// Worker generation number. 0 for the classic daemon.
    generation: u32,
    /// Whether a client may drive a self-handoff via [`Request::Reset`]. The
    /// classic daemon owns its own endpoint and allows it; a supervised worker
    /// does not (the supervisor owns rollout), so it refuses.
    allow_reset: bool,
    paths: Paths,
    effective: Mutex<EffectivePaths>,
    presence: watch::Sender<ClientPresence>,
    ticks: broadcast::Sender<Event>,
    /// Fires once, carrying the successor pid, to tell lifetime clients to drop
    /// this connection and re-attach onto the promoted successor.
    reconnect: broadcast::Sender<u32>,
    shutdown: watch::Sender<bool>,
    /// Guards against overlapping resets on the predecessor.
    handoff_in_progress: AtomicBool,
    /// True once this daemon owns the canonical endpoint. A primary is born
    /// promoted; a successor flips it during [`promote`].
    promoted: AtomicBool,
}

impl DaemonState {
    fn snapshot(&self) -> Response {
        Response {
            pid: self.pid,
            opened_at_unix_ms: self.opened_at_unix_ms,
            elapsed_ms: elapsed_ms(self.opened_at),
            clients: self.presence.borrow().count,
            worker_version: self.worker_version,
            generation: self.generation,
        }
    }

    fn tick_event(&self) -> Event {
        Event {
            elapsed_ms: elapsed_ms(self.opened_at),
            clients: self.presence.borrow().count,
        }
    }

    fn track_client(self: &Arc<Self>) -> ClientGuard {
        self.presence.send_modify(|presence| {
            presence.count += 1;
            presence.has_lifetime_client = true;
        });
        ClientGuard {
            state: Arc::clone(self),
        }
    }
}

struct ClientGuard {
    state: Arc<DaemonState>,
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.state
            .presence
            .send_modify(|presence| presence.count = presence.count.saturating_sub(1));
    }
}

/// Cleans pid + socket on every exit path, but only while the pid file still
/// names this process. A replacement that won a later reservation — including a
/// promoted successor that took the canonical files via rename — must keep its
/// files. The target paths are read live from the daemon's [`EffectivePaths`],
/// so a successor cleans its staging pair before promotion and the canonical
/// pair after.
struct MetadataGuard {
    state: Arc<DaemonState>,
}

impl MetadataGuard {
    fn cleanup(&self) -> Result<()> {
        let effective = self
            .state
            .effective
            .lock()
            .expect("effective paths")
            .clone();
        if host::read_pid_file(&effective.pid_file) != Some(self.state.pid) {
            return Ok(());
        }
        let mut failures = Vec::new();
        if let Err(error) = std::fs::remove_file(&effective.pid_file)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            failures.push(format!("pid file: {error}"));
        }
        if let Err(error) = std::fs::remove_file(&effective.socket)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            failures.push(format!("socket: {error}"));
        }
        if failures.is_empty() {
            Ok(())
        } else {
            bail!(failures.join("; "))
        }
    }
}

impl Drop for MetadataGuard {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub async fn run_foreground() -> Result<()> {
    let role = match std::env::var("EXCOC_INHERIT_OPENED_AT_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        Some(inherited_opened_at_unix_ms) => Role::Successor {
            inherited_opened_at_unix_ms,
        },
        None => Role::Primary,
    };
    run_with_role(role).await
}

async fn run_with_role(role: Role) -> Result<()> {
    let paths = Paths::resolve()?;
    let pid = std::process::id();

    let (effective, promoted) = match &role {
        Role::Primary => (
            EffectivePaths {
                pid_file: paths.pid_file.clone(),
                socket: paths.socket.clone(),
            },
            true,
        ),
        Role::Successor { .. } => (
            EffectivePaths {
                pid_file: paths.staging_pid.clone(),
                socket: paths.staging_socket.clone(),
            },
            false,
        ),
    };

    // Reserve the pid file before any fallible step so the MetadataGuard,
    // installed immediately after state construction, owns cleanup from here.
    reserve_pid_file(&effective.pid_file, pid)?;

    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    let (opened_at, opened_at_unix_ms) = match &role {
        Role::Primary => (Instant::now(), now_unix_ms),
        Role::Successor {
            inherited_opened_at_unix_ms,
        } => {
            // Rebuild the monotonic anchor from the inherited wall-clock open
            // time so elapsed_ms continues unbroken across the handoff.
            let elapsed = now_unix_ms.saturating_sub(*inherited_opened_at_unix_ms);
            let opened_at = Instant::now()
                .checked_sub(Duration::from_millis(elapsed))
                .unwrap_or_else(Instant::now);
            (opened_at, *inherited_opened_at_unix_ms)
        }
    };

    let socket_path = effective.socket.clone();
    let (presence, presence_rx) = watch::channel(ClientPresence::default());
    let (ticks, _) = broadcast::channel(16);
    let (reconnect, _) = broadcast::channel(16);
    let (shutdown, _) = watch::channel(false);
    let state = Arc::new(DaemonState {
        pid,
        opened_at,
        opened_at_unix_ms,
        worker_version: 0,
        generation: 0,
        allow_reset: true,
        paths: paths.clone(),
        effective: Mutex::new(effective),
        presence,
        ticks,
        reconnect,
        shutdown,
        handoff_in_progress: AtomicBool::new(false),
        promoted: AtomicBool::new(promoted),
    });

    let metadata = MetadataGuard {
        state: Arc::clone(&state),
    };
    match std::fs::remove_file(&socket_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("removing stale daemon socket after reservation"),
    }

    let listener = bind_private_socket(&socket_path)?;
    let tick_ms = tick_interval();
    let ticker = spawn_ticker(Arc::clone(&state), tick_ms);
    let reaper = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            ephemeral_last_client_reaper(presence_rx, || {
                let _ = state.shutdown.send(true);
                ReapDecision::Shutdown
            })
            .await;
        })
    };
    let signals = spawn_signal_task(Arc::clone(&state));

    let accept = run_accept_loop(Arc::clone(&state), listener).await;
    ticker.abort();
    reaper.abort();
    signals.abort();
    metadata.cleanup()?;
    std::mem::forget(metadata);
    accept
}

/// Run as a **supervised worker** (`excoc worker`), spawned by the supervisor.
///
/// Unlike the classic daemon, a worker owns *no* lifecycle metadata: the
/// supervisor holds the pid file and the listening socket. The worker
///
/// - adopts the listening socket the supervisor passed down as [`LISTENER_FD_VAR`]
///   (fd 3) — the socket-activation handoff, so the endpoint never closes across
///   a worker swap;
/// - inherits `opened_at` from the supervisor (the durable state analog), so the
///   clock is continuous across upgrades *and* crashes;
/// - reports readiness by writing one byte to the notify pipe ([`NOTIFY_FD_VAR`],
///   fd 4), sd_notify-style, so the supervisor learns *this* worker is live
///   without racing on the shared socket;
/// - on `SIGTERM` (the supervisor's drain signal) stops accepting, tells its
///   lifetime clients to reconnect, drains, and exits — reconnects then land on
///   the already-ready successor;
/// - exits promptly if the supervisor disappears, so a crashed supervisor never
///   leaves an orphan worker holding the socket.
pub async fn run_worker() -> Result<()> {
    let paths = Paths::resolve()?;
    let pid = std::process::id();

    let listener_fd: i32 = env_u32(LISTENER_FD_VAR)
        .context("worker requires an inherited listener fd; run via `excoc supervise`")?
        as i32;
    let opened_at_unix_ms =
        env_u64(OPENED_AT_VAR).context("worker requires an inherited open time")?;
    let worker_version = env_u32(WORKER_VERSION_VAR).unwrap_or(0);
    let generation = env_u32(GENERATION_VAR).unwrap_or(0);

    // Adopt the inherited listener. `from_raw_fd` takes ownership of fd 3, which
    // the supervisor bound (and keeps a copy of), so this worker joining or
    // leaving the accept set never tears the socket down.
    // SAFETY: the supervisor placed a bound, listening Unix socket at this fd
    // via `dup2` before `exec`, and passes it to exactly one worker.
    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(listener_fd) };
    std_listener
        .set_nonblocking(true)
        .context("marking inherited listener non-blocking")?;
    let listener =
        UnixListener::from_std(std_listener).context("adopting inherited listener into tokio")?;

    // Rebuild the monotonic anchor from the inherited wall-clock open time, the
    // same trick the reset-design successor uses.
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(opened_at_unix_ms);
    let elapsed = now_unix_ms.saturating_sub(opened_at_unix_ms);
    let opened_at = Instant::now()
        .checked_sub(Duration::from_millis(elapsed))
        .unwrap_or_else(Instant::now);

    let (presence, presence_rx) = watch::channel(ClientPresence::default());
    let (ticks, _) = broadcast::channel(16);
    let (reconnect, _) = broadcast::channel(16);
    let (shutdown, _) = watch::channel(false);
    let state = Arc::new(DaemonState {
        pid,
        opened_at,
        opened_at_unix_ms,
        worker_version,
        generation,
        // A supervised worker never self-hands-off; rollout is the supervisor's job.
        allow_reset: false,
        paths: paths.clone(),
        // Unused: a worker cleans up no metadata. Populate with harmless values
        // so the shared MetadataGuard (which we never install here) has no claim.
        effective: Mutex::new(EffectivePaths {
            pid_file: paths.sup_pid.clone(),
            socket: paths.sup_socket.clone(),
        }),
        presence,
        ticks,
        reconnect,
        shutdown,
        handoff_in_progress: AtomicBool::new(false),
        // A worker is never "promoted" in the reset sense; mark it so the
        // Promote path can never fire.
        promoted: AtomicBool::new(true),
    });
    // `presence_rx` is unused: unlike the ephemeral classic daemon, a worker
    // does not reap itself when clients hit zero — the supervisor owns lifetime,
    // and the worker must stay up to receive reconnects after a swap.
    drop(presence_rx);

    let tick_ms = tick_interval();
    let ticker = spawn_ticker(Arc::clone(&state), tick_ms);
    let (stop_accept_tx, stop_accept_rx) = watch::channel(false);
    let signals = spawn_worker_drain_on_signal(Arc::clone(&state), stop_accept_tx);
    let supervisor_watch =
        spawn_supervisor_liveness_watch(Arc::clone(&state), paths.sup_pid.clone());

    // Announce readiness only once the accept path is wired up: the supervisor
    // blocks on this byte before draining the previous generation.
    notify_ready();

    let accept = run_worker_accept_loop(Arc::clone(&state), listener, stop_accept_rx).await;
    ticker.abort();
    signals.abort();
    supervisor_watch.abort();
    accept
}

/// Worker accept loop. Like [`run_accept_loop`] but it can *stop accepting*
/// without shutting down: on drain the worker drops its listener so reconnecting
/// clients deterministically land on the already-ready successor, while it keeps
/// serving in-flight clients until `shutdown` fires.
async fn run_worker_accept_loop(
    state: Arc<DaemonState>,
    listener: UnixListener,
    mut stop_accept: watch::Receiver<bool>,
) -> Result<()> {
    let mut clients: Vec<JoinHandle<()>> = Vec::new();
    let mut shutdown = state.shutdown.subscribe();
    let mut listener = Some(listener);
    loop {
        if *shutdown.borrow_and_update() {
            break;
        }
        if *stop_accept.borrow_and_update() {
            // Release our seat in the accept set; the supervisor and successor
            // still hold the socket open.
            listener = None;
        }
        match &listener {
            Some(active) => {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                    changed = stop_accept.changed() => {
                        if changed.is_err() || *stop_accept.borrow() {
                            listener = None;
                        }
                    }
                    accepted = active.accept() => {
                        let (stream, _) = match accepted {
                            Ok(pair) => pair,
                            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                            Err(error) => return Err(error).context("accepting worker client"),
                        };
                        let state = Arc::clone(&state);
                        clients.push(tokio::spawn(async move {
                            if let Err(error) = handle_client(state, ProtoStream::new(stream)).await {
                                tracing_error(error);
                            }
                        }));
                        clients.retain(|task| !task.is_finished());
                    }
                }
            }
            None => {
                // Not accepting anymore: just wait for the drain to complete.
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
        }
    }
    for task in clients {
        task.abort();
    }
    Ok(())
}

/// On `SIGTERM`/`SIGINT`, drain this worker: stop accepting, tell lifetime
/// clients to reconnect (they land on the successor), wait for them to leave
/// (bounded), then shut down.
fn spawn_worker_drain_on_signal(
    state: Arc<DaemonState>,
    stop_accept: watch::Sender<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(_) => return,
            };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        let _ = stop_accept.send(true);
        begin_drain(state, 0);
    })
}

/// Exit promptly if the supervisor process vanishes, so a crashed supervisor
/// never strands a worker holding the shared socket open.
fn spawn_supervisor_liveness_watch(
    state: Arc<DaemonState>,
    sup_pid_file: PathBuf,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(200)).await;
            match host::read_pid_file(&sup_pid_file) {
                Some(pid) if host::process_exists(pid) => {}
                // Supervisor gone (or replaced its pid file): stand down.
                _ => {
                    let _ = state.shutdown.send(true);
                    return;
                }
            }
        }
    })
}

/// Write the sd_notify-style readiness byte to the inherited notify pipe. Best
/// effort: if the pipe is absent (e.g. run by hand) the worker still serves.
fn notify_ready() {
    let Some(fd) = env_u32(NOTIFY_FD_VAR) else {
        return;
    };
    // SAFETY: the supervisor placed the write end of a pipe at this fd via
    // `dup2` before `exec`. Writing one byte and dropping closes our end.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd as i32) };
    let _ = std::io::Write::write_all(&mut file, b"1");
}

fn env_u32(key: &str) -> Option<u32> {
    std::env::var(key).ok()?.trim().parse().ok()
}

fn env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok()?.trim().parse().ok()
}

async fn run_accept_loop(state: Arc<DaemonState>, listener: UnixListener) -> Result<()> {
    let mut clients: Vec<JoinHandle<()>> = Vec::new();
    let mut shutdown = state.shutdown.subscribe();
    loop {
        if *shutdown.borrow_and_update() {
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error).context("accepting daemon client"),
                };
                let state = Arc::clone(&state);
                clients.push(tokio::spawn(async move {
                    if let Err(error) = handle_client(state, ProtoStream::new(stream)).await {
                        tracing_error(error);
                    }
                }));
                clients.retain(|task| !task.is_finished());
            }
        }
    }
    for task in clients {
        task.abort();
    }
    Ok(())
}

async fn handle_client(state: Arc<DaemonState>, mut stream: ProtoStream) -> Result<()> {
    stream
        .send(&Envelope::hello(
            state.pid,
            state.opened_at_unix_ms,
            state.worker_version,
            state.generation,
        ))
        .await?;
    let mut lifetime: Option<ClientGuard> = None;
    let mut ticks = state.ticks.subscribe();
    let mut reconnect = state.reconnect.subscribe();
    loop {
        tokio::select! {
            frame = stream.recv() => {
                match frame? {
                    None => return Ok(()),
                    Some(envelope) => {
                        match envelope.body {
                            EnvelopeBody::Req { id, body: Request::Subscribe } => {
                                if lifetime.is_none() {
                                    lifetime = Some(state.track_client());
                                }
                                stream.send(&Envelope::res(id, state.snapshot())).await?;
                            }
                            EnvelopeBody::Req { id, body: Request::Status } => {
                                stream.send(&Envelope::res(id, state.snapshot())).await?;
                            }
                            EnvelopeBody::Req { id, body: Request::Reset } => {
                                if !state.allow_reset {
                                    stream
                                        .send(&Envelope::error(
                                            Some(id),
                                            "this worker is supervised; use `excoc upgrade`",
                                        ))
                                        .await?;
                                } else if handle_reset(&state, &mut stream, id).await? {
                                    // Handoff committed; this connection is done
                                    // and the drain task will shut us down.
                                    return Ok(());
                                }
                            }
                            EnvelopeBody::Req { id, body: Request::Promote } => {
                                match promote(&state) {
                                    Ok(snapshot) => {
                                        stream.send(&Envelope::res(id, snapshot)).await?;
                                    }
                                    Err(error) => {
                                        stream
                                            .send(&Envelope::error(
                                                Some(id),
                                                format!("{error:#}"),
                                            ))
                                            .await?;
                                    }
                                }
                            }
                            EnvelopeBody::Hello { .. }
                            | EnvelopeBody::Res { .. }
                            | EnvelopeBody::Evt { .. }
                            | EnvelopeBody::Reconnect { .. }
                            | EnvelopeBody::Err { .. } => {
                                stream
                                    .send(&Envelope::error(None, "client sent a non-request frame"))
                                    .await?;
                            }
                        }
                    }
                }
            }
            tick = ticks.recv() => {
                if lifetime.is_none() {
                    continue;
                }
                match tick {
                    Ok(event) => stream.send(&Envelope::evt(event)).await?,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
            signal = reconnect.recv() => {
                match signal {
                    Ok(successor_pid) => {
                        stream.send(&Envelope::reconnect(successor_pid)).await?;
                        return Ok(());
                    }
                    // Missed the pid but a handoff still happened: force the
                    // reconnect anyway (the pid is only used for the log line).
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        stream.send(&Envelope::reconnect(0)).await?;
                        return Ok(());
                    }
                    Err(broadcast::error::RecvError::Closed) => {}
                }
            }
        }
    }
}

/// Handle a `Reset` on the predecessor. Returns `true` when the handoff
/// committed and the caller should close this connection. On failure the
/// predecessor keeps serving and the error is reported to the caller.
async fn handle_reset(state: &Arc<DaemonState>, stream: &mut ProtoStream, id: u64) -> Result<bool> {
    if state.handoff_in_progress.swap(true, Ordering::SeqCst) {
        stream
            .send(&Envelope::error(
                Some(id),
                "a handoff is already in progress",
            ))
            .await?;
        return Ok(false);
    }
    match perform_handoff(state).await {
        Ok(snapshot) => {
            let successor_pid = snapshot.pid;
            stream.send(&Envelope::res(id, snapshot)).await?;
            begin_drain(Arc::clone(state), successor_pid);
            Ok(true)
        }
        Err(error) => {
            state.handoff_in_progress.store(false, Ordering::SeqCst);
            stream
                .send(&Envelope::error(Some(id), format!("{error:#}")))
                .await?;
            Ok(false)
        }
    }
}

/// Spawn a successor, confirm it booted with the inherited clock, and drive it
/// through promotion onto the canonical endpoint. Returns the successor's
/// snapshot (new pid, continuous uptime). Any failure terminates the successor
/// and leaves this daemon serving untouched.
async fn perform_handoff(state: &Arc<DaemonState>) -> Result<Response> {
    let child_pid = host::spawn_detached_daemon(&state.paths, Some(state.opened_at_unix_ms))
        .context("spawning successor daemon")?;
    let outcome = drive_successor(state, child_pid).await;
    if outcome.is_err() {
        host::terminate(child_pid);
    }
    outcome
}

async fn drive_successor(state: &Arc<DaemonState>, child_pid: u32) -> Result<Response> {
    let deadline = Instant::now() + SUCCESSOR_READY_TIMEOUT;
    let mut admin = loop {
        match Control::connect(&state.paths.staging_socket).await {
            Ok(control)
                if control.hello.pid == child_pid
                    && control.hello.opened_at_unix_ms == state.opened_at_unix_ms =>
            {
                break control;
            }
            // A stale staging endpoint or a not-yet-ready successor: keep
            // waiting until the deadline rather than promoting the wrong peer.
            Ok(_) | Err(_) => {}
        }
        if Instant::now() >= deadline {
            if !host::process_exists(child_pid) {
                bail!("successor pid {child_pid} exited before its staging endpoint became ready");
            }
            bail!("timed out waiting for successor {child_pid} to bind its staging endpoint");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    let snapshot = admin
        .request(Request::Promote)
        .await
        .context("promoting successor")?;
    if snapshot.pid != child_pid || snapshot.opened_at_unix_ms != state.opened_at_unix_ms {
        bail!(
            "successor promoted with an unexpected identity (pid {} opened_at_ms {})",
            snapshot.pid,
            snapshot.opened_at_unix_ms
        );
    }
    Ok(snapshot)
}

/// Successor side of the swap: atomically move the staging endpoint onto the
/// canonical paths, then adopt them for cleanup. Idempotency is enforced so a
/// second `Promote` cannot double-rename.
fn promote(state: &Arc<DaemonState>) -> Result<Response> {
    if state.promoted.swap(true, Ordering::SeqCst) {
        bail!("this daemon has already been promoted");
    }
    let staging = state.effective.lock().expect("effective paths").clone();
    // Transfer pid ownership first (revertible), then flip the socket. The
    // socket rename is the atomic commit: before it the predecessor still owns
    // the canonical path; after it every new attach and reconnect reaches us,
    // with no window where the canonical path is missing.
    std::fs::rename(&staging.pid_file, &state.paths.pid_file).with_context(|| {
        format!(
            "promoting pid file {} -> {}",
            staging.pid_file.display(),
            state.paths.pid_file.display()
        )
    })?;
    if let Err(error) = std::fs::rename(&staging.socket, &state.paths.socket) {
        // Roll the pid move back so the predecessor keeps ownership and we stay
        // reachable on the staging socket.
        let _ = std::fs::rename(&state.paths.pid_file, &staging.pid_file);
        state.promoted.store(false, Ordering::SeqCst);
        return Err(error).with_context(|| {
            format!(
                "promoting socket {} -> {}",
                staging.socket.display(),
                state.paths.socket.display()
            )
        });
    }
    *state.effective.lock().expect("effective paths") = EffectivePaths {
        pid_file: state.paths.pid_file.clone(),
        socket: state.paths.socket.clone(),
    };
    Ok(state.snapshot())
}

/// After a committed handoff: tell lifetime clients to reconnect, wait for them
/// to drain (bounded by [`DRAIN_TIMEOUT`]), then shut down. If there were no
/// lifetime clients the wait returns immediately.
fn begin_drain(state: Arc<DaemonState>, successor_pid: u32) {
    tokio::spawn(async move {
        let _ = state.reconnect.send(successor_pid);
        let mut presence = state.presence.subscribe();
        let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
        while state.presence.borrow().count > 0 {
            tokio::select! {
                changed = presence.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                _ = tokio::time::sleep_until(deadline) => break,
            }
        }
        let _ = state.shutdown.send(true);
    });
}

fn spawn_ticker(state: Arc<DaemonState>, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if state.ticks.receiver_count() == 0 {
                continue;
            }
            let _ = state.ticks.send(state.tick_event());
        }
    })
}

fn spawn_signal_task(state: Arc<DaemonState>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(_) => return,
            };
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            let _ = state.shutdown.send(true);
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReapDecision {
    Shutdown,
    Wait,
}

/// Wait for an ephemeral owner to acquire its first lifetime client and then
/// request teardown as soon as the reference count returns to zero. The gate
/// prevents a freshly spawned daemon from racing its creator's initial
/// handshake or a hello-only reachability probe.
pub async fn ephemeral_last_client_reaper(
    mut presence: watch::Receiver<ClientPresence>,
    mut try_reap: impl FnMut() -> ReapDecision,
) {
    loop {
        let observed = *presence.borrow_and_update();
        if observed.has_lifetime_client && observed.count == 0 {
            match try_reap() {
                ReapDecision::Shutdown => return,
                ReapDecision::Wait => {
                    tokio::select! {
                        changed = presence.changed() => {
                            if changed.is_err() {
                                return;
                            }
                        }
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
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

fn elapsed_ms(opened_at: Instant) -> u64 {
    opened_at.elapsed().as_millis() as u64
}

fn tick_interval() -> Duration {
    match std::env::var("EXCOC_TICK_MS") {
        Ok(value) => value
            .parse::<u64>()
            .ok()
            .filter(|ms| *ms > 0)
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_TICK),
        Err(_) => DEFAULT_TICK,
    }
}

fn tracing_error(error: anyhow::Error) {
    eprintln!("excoc daemon: {error:#}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn reaper_ignores_zero_clients_until_first_subscribe() {
        let (tx, rx) = watch::channel(ClientPresence::default());
        let task = tokio::spawn(async move {
            ephemeral_last_client_reaper(rx, || ReapDecision::Shutdown).await;
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!task.is_finished(), "must not reap before first client");
        tx.send(ClientPresence {
            count: 1,
            has_lifetime_client: true,
        })
        .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !task.is_finished(),
            "must not reap while a lifetime client is attached"
        );
        tx.send(ClientPresence {
            count: 0,
            has_lifetime_client: true,
        })
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("reaper finishes after last client")
            .expect("reaper task");
    }
}
