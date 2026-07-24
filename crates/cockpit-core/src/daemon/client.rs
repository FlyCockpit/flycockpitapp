//! Typed client over the daemon's NDJSON protocol.
//!
//! Spawns one background "reader/writer" task that owns the
//! [`ProtoStream`]; callers interact through:
//!
//! - [`DaemonClient::request`] — send one [`proto::Request`], wait for
//!   the matching [`proto::Response`] (or [`proto::ErrorPayload`]).
//! - [`DaemonClient::event_stream`] — clone-able subscriber to
//!   server-pushed events.
//!
//! The split lets the TUI driver fan multiple in-flight requests
//! through one socket while also reading the event stream, without
//! any locking ceremony in user code.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

#[cfg(unix)]
use anyhow::Context;
use anyhow::{Result, anyhow};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::daemon::proto::{
    self, Body, Envelope, ErrorPayload, ProtoStream, RecvFrame, Request, Response,
};

static OWN_EPHEMERAL_PATHS: OnceLock<Mutex<Option<crate::daemon::DaemonPaths>>> = OnceLock::new();

/// Outbound queue depth. Generous — request payloads are tiny.
const REQUEST_QUEUE: usize = 64;

/// Inbound event queue depth. Lagging consumers drop incoming events and get a
/// typed lag marker once capacity returns. If the TUI cannot keep up, the
/// right answer is "reattach" (the server re-sends the current session state
/// on `Attach`).
const EVENT_QUEUE: usize = 1024;

/// Default request timeout. Most requests are < 50ms; we set a
/// generous ceiling so a hung daemon causes a loud error rather than
/// a stalled TUI.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BIASED_INBOUND_FRAMES: usize = 32;

thread_local! {
    static CONNECT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub fn reset_connect_call_count() {
    CONNECT_CALLS.with(|calls| calls.set(0));
}

pub fn connect_call_count() -> usize {
    CONNECT_CALLS.with(std::cell::Cell::get)
}

/// Public handle. Cheap to clone: every clone shares the same
/// background reader/writer task; only the event-stream subscription
/// differs.
#[derive(Clone)]
pub struct DaemonClient {
    backend: ClientBackend,
    negotiated: proto::NegotiatedProtocol,
    /// One channel per `DaemonClient` clone, hydrated by the reader
    /// task. We use `Arc<Mutex<_>>` because `mpsc::Receiver` isn't
    /// `Clone` — clones of `DaemonClient` share access to the
    /// receiver they were spawned with.
    events: Arc<tokio::sync::Mutex<mpsc::Receiver<proto::Event>>>,
}

#[cfg(unix)]
struct Pending {
    id: Uuid,
    request: Request,
    reply: oneshot::Sender<std::result::Result<Response, ErrorPayload>>,
}

#[derive(Clone)]
enum ClientBackend {
    #[cfg(unix)]
    Wire(mpsc::Sender<IoCommand>),
    InProcess(mpsc::Sender<crate::daemon::server::InProcessRequest>),
}

#[cfg(unix)]
enum IoCommand {
    Request(Box<Pending>),
    Cancel { id: Uuid },
}

impl DaemonClient {
    /// Connect to the daemon at `socket`. Spawns the background task
    /// before returning.
    pub async fn connect(socket: &Path) -> Result<Self> {
        CONNECT_CALLS.with(|calls| calls.set(calls.get() + 1));
        if let Some(ctx) = crate::daemon::server::in_process_context(socket) {
            return Ok(Self::from_in_process(ctx));
        }
        #[cfg(unix)]
        {
            let stream = UnixStream::connect(socket)
                .await
                .with_context(|| format!("connecting to {}", socket.display()))?;
            let mut proto = ProtoStream::new(stream);
            let negotiated = negotiate_hello(&mut proto).await?;
            proto.set_negotiated_version(negotiated.version);
            Ok(Self::from_proto_negotiated(proto, negotiated))
        }
        #[cfg(not(unix))]
        {
            Err(anyhow!(
                "daemon socket transport is not supported on this platform"
            ))
        }
    }

    pub(crate) fn from_in_process(ctx: Arc<crate::daemon::server::DaemonContext>) -> Self {
        let (request_tx, event_rx) = crate::daemon::server::spawn_in_process_client(ctx);
        Self {
            backend: ClientBackend::InProcess(request_tx),
            negotiated: proto::NegotiatedProtocol::current(),
            events: Arc::new(tokio::sync::Mutex::new(event_rx)),
        }
    }

    #[cfg(unix)]
    #[cfg(test)]
    fn from_proto(proto: ProtoStream<UnixStream>) -> Self {
        Self::from_proto_negotiated(proto, proto::NegotiatedProtocol::current())
    }

    #[cfg(unix)]
    fn from_proto_negotiated(
        proto: ProtoStream<UnixStream>,
        negotiated: proto::NegotiatedProtocol,
    ) -> Self {
        let (request_tx, request_rx) = mpsc::channel::<IoCommand>(REQUEST_QUEUE);
        let (event_tx, event_rx) = mpsc::channel::<proto::Event>(EVENT_QUEUE);
        tokio::spawn(run_io(proto, request_rx, event_tx));
        Self {
            backend: ClientBackend::Wire(request_tx),
            negotiated,
            events: Arc::new(tokio::sync::Mutex::new(event_rx)),
        }
    }

    pub fn negotiated(&self) -> &proto::NegotiatedProtocol {
        &self.negotiated
    }

    /// Send a request and wait for the matching response. Returns the
    /// daemon's typed [`proto::ErrorPayload`] when the request was
    /// rejected, distinct from transport / timeout errors which come
    /// back as `Err(anyhow)`.
    pub async fn request(
        &self,
        request: Request,
    ) -> Result<std::result::Result<Response, ErrorPayload>> {
        let (tx, rx) = oneshot::channel();
        let id = Uuid::new_v4();
        match &self.backend {
            ClientBackend::Wire(request_tx) => {
                request_tx
                    .send(IoCommand::Request(Box::new(Pending {
                        id,
                        request,
                        reply: tx,
                    })))
                    .await
                    .map_err(|_| anyhow!("daemon client task has stopped"))?;
                match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
                    Ok(Ok(result)) => Ok(result),
                    Ok(Err(_)) => Err(anyhow!("daemon client dropped reply channel")),
                    Err(_) => {
                        let _ = request_tx.send(IoCommand::Cancel { id }).await;
                        Err(anyhow!("request timed out after {:?}", REQUEST_TIMEOUT))
                    }
                }
            }
            ClientBackend::InProcess(request_tx) => {
                request_tx
                    .send(crate::daemon::server::InProcessRequest { request, reply: tx })
                    .await
                    .map_err(|_| anyhow!("in-process daemon client task has stopped"))?;
                match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
                    Ok(Ok(result)) => Ok(result),
                    Ok(Err(_)) => Err(anyhow!("in-process daemon client dropped reply channel")),
                    Err(_) => Err(anyhow!("request timed out after {:?}", REQUEST_TIMEOUT)),
                }
            }
        }
    }

    /// Convenience: send a request, unwrap typed errors as `Err`.
    pub async fn request_ok(&self, request: Request) -> Result<Response> {
        match self.request(request).await? {
            Ok(r) => Ok(r),
            Err(e) => Err(anyhow!("daemon error: {e}")),
        }
    }

    #[allow(dead_code)]
    pub async fn steer_delegation(
        &self,
        session_id: Uuid,
        task_call_id: impl Into<String>,
        label: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<proto::DelegationSteerResult> {
        match self
            .request_ok(Request::SteerDelegation {
                session_id,
                task_call_id: task_call_id.into(),
                label: label.into(),
                message: message.into(),
            })
            .await?
        {
            Response::DelegationSteer { result } => Ok(result),
            other => Err(anyhow!("unexpected steer delegation response: {other:?}")),
        }
    }

    /// Pull the next server-pushed event. Returns `None` when the
    /// connection has closed. Multi-call from multiple cloned
    /// clients is fine; each event is delivered to exactly one
    /// caller (we don't use broadcast on the client side because
    /// the TUI is the single consumer; the broadcast lives on the
    /// daemon side where multi-client is the design point).
    pub async fn next_event(&self) -> Option<proto::Event> {
        let mut events = self.events.lock().await;
        events.recv().await
    }

    pub fn is_socket_backed(&self) -> bool {
        #[cfg(unix)]
        {
            matches!(self.backend, ClientBackend::Wire(_))
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

#[cfg(unix)]
async fn negotiate_hello(
    proto_stream: &mut ProtoStream<UnixStream>,
) -> Result<proto::NegotiatedProtocol> {
    let line = match tokio::time::timeout(Duration::from_millis(500), proto_stream.recv_raw_line())
        .await
    {
        Ok(Ok(Some(line))) => line,
        Ok(Ok(None)) => {
            tracing::debug!("daemon hello absent; using current protocol version");
            return Ok(proto::NegotiatedProtocol::current());
        }
        Ok(Err(error)) => {
            tracing::debug!(error = %error, "daemon hello unreadable; using current protocol version");
            return Ok(proto::NegotiatedProtocol::current());
        }
        Err(_) => {
            tracing::debug!("daemon hello timed out; using current protocol version");
            return Ok(proto::NegotiatedProtocol::current());
        }
    };

    let Some(hello) = (match proto::parse_daemon_hello_line(&line) {
        Ok(hello) => hello,
        Err(error) => {
            tracing::debug!(error = %error, "daemon hello unparseable; using current protocol version");
            return Ok(proto::NegotiatedProtocol::current());
        }
    }) else {
        tracing::debug!("first daemon frame was not a hello; using current protocol version");
        return Ok(proto::NegotiatedProtocol::current());
    };

    proto::NegotiatedProtocol::from_hello(&hello).map_err(|error| anyhow!(error.message))
}

#[cfg(unix)]
async fn run_io(
    mut proto: ProtoStream<UnixStream>,
    mut request_rx: mpsc::Receiver<IoCommand>,
    event_tx: mpsc::Sender<proto::Event>,
) {
    let mut pending: HashMap<Uuid, oneshot::Sender<std::result::Result<Response, ErrorPayload>>> =
        HashMap::new();
    let mut inbound_burst = InboundBurst::default();
    let mut dropped_events: u64 = 0;
    let mut attached_session: Option<Uuid> = None;

    loop {
        if inbound_burst.should_probe_outbound() {
            match request_rx.try_recv() {
                Ok(cmd) => {
                    inbound_burst.reset();
                    if !handle_io_command(cmd, &mut proto, &mut pending).await {
                        break;
                    }
                    continue;
                }
                Err(mpsc::error::TryRecvError::Empty) => inbound_burst.reset(),
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        tokio::select! {
            biased;

            permit = event_tx.reserve(), if dropped_events > 0 => {
                match permit {
                    Ok(permit) => {
                        let dropped = dropped_events;
                        permit.send(proto::Event::EventStreamLagged {
                            session_id: None,
                            dropped,
                        });
                        dropped_events = 0;
                    }
                    Err(_) => {
                        break;
                    }
                }
            }

            // Inbound envelope from the daemon.
            recv = proto.recv() => {
                inbound_burst.record_inbound();
                match recv {
                    Ok(None) => {
                        tracing::debug!("daemon closed the connection");
                        break;
                    }
                    Ok(Some(RecvFrame::Envelope(env))) => {
                        match env.body {
                            Body::Response { id, response } => {
                                let response = *response;
                                if let Some(tx) = pending.remove(&id) {
                                    if let Response::Attached { session_id, .. } = &response {
                                        attached_session = Some(*session_id);
                                    }
                                    let _ = tx.send(Ok(response));
                                } else if is_nil_daemon_status_hello(id, &response) {
                                    tracing::debug!("daemon hello status received");
                                } else {
                                    tracing::warn!(id = %id, "daemon responded with unknown id");
                                }
                            }
                            Body::Error { id, error } => {
                                match id {
                                    Some(id) => {
                                        if let Some(tx) = pending.remove(&id) {
                                            let _ = tx.send(Err(error));
                                        } else {
                                            tracing::warn!(id = %id, ?error, "daemon error for unknown id");
                                        }
                                    }
                                    None => {
                                        tracing::warn!(?error, "out-of-band daemon error");
                                        let text = format!("daemon error: {error}");
                                        let event = match attached_session {
                                            Some(session_id) => proto::Event::Notice {
                                                session_id,
                                                text,
                                            },
                                            None => proto::Event::LspNotice { text },
                                        };
                                        try_forward_event(&event_tx, event, &mut dropped_events);
                                    }
                                }
                            }
                            Body::Event { event } => {
                                try_forward_event(&event_tx, event, &mut dropped_events);
                            }
                            Body::Request { id, request } => {
                                tracing::warn!(id = %id, ?request, "daemon sent a request to a client; ignoring");
                            }
                            Body::Unknown => {
                                tracing::debug!("dropping unknown daemon protocol body");
                            }
                        }
                    }
                    Ok(Some(RecvFrame::VersionMismatch { v, id, .. })) => {
                        if let Some(id) = id
                            && let Some(tx) = pending.remove(&id)
                        {
                            let _ = tx.send(Err(ErrorPayload {
                                code: proto::ErrorCode::ProtocolVersion,
                                message: proto::version_mismatch_message(v),
                            }));
                        }
                        break;
                    }
                    Ok(Some(RecvFrame::Unknown { v, kind, tag, id })) => {
                        if matches!(kind.as_str(), "res" | "err")
                            && let Some(id) = id
                            && let Some(tx) = pending.remove(&id)
                        {
                            let _ = tx.send(Err(proto::unsupported_request_error(v, tag.as_deref())));
                        } else {
                            tracing::debug!(
                                version = v,
                                kind,
                                ?tag,
                                ?id,
                                "dropping unknown daemon protocol frame"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = ?e, "daemon read failed; closing");
                        break;
                    }
                }
            }

            // Outbound request from the user.
            cmd = request_rx.recv() => {
                inbound_burst.reset();
                let Some(cmd) = cmd else {
                    break;
                };
                if !handle_io_command(cmd, &mut proto, &mut pending).await {
                    break;
                }
            }
        }
    }

    // Drain any pending requests with an explicit "connection closed."
    for (_, tx) in pending.drain() {
        let _ = tx.send(Err(ErrorPayload {
            code: proto::ErrorCode::Internal,
            message: "daemon connection closed".into(),
        }));
    }

    if dropped_events > 0 {
        emit_lag_marker_on_close(&event_tx, dropped_events).await;
    }
}

#[cfg(unix)]
async fn emit_lag_marker_on_close(event_tx: &mpsc::Sender<proto::Event>, dropped: u64) {
    if dropped == 0 {
        return;
    }
    if let Ok(permit) = event_tx.reserve().await {
        permit.send(proto::Event::EventStreamLagged {
            session_id: None,
            dropped,
        });
    }
}

#[cfg(unix)]
fn try_forward_event(
    event_tx: &mpsc::Sender<proto::Event>,
    event: proto::Event,
    dropped_events: &mut u64,
) {
    match event_tx.try_send(event) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            *dropped_events = dropped_events.saturating_add(1);
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            // The consumer dropped; keep reading the socket so OS buffers do
            // not fill while request senders wind down through their channel.
        }
    }
}

#[cfg(unix)]
#[derive(Default)]
struct InboundBurst {
    frames: usize,
}

#[cfg(unix)]
impl InboundBurst {
    fn record_inbound(&mut self) {
        self.frames = self.frames.saturating_add(1);
    }

    fn reset(&mut self) {
        self.frames = 0;
    }

    fn should_probe_outbound(&self) -> bool {
        self.frames >= MAX_BIASED_INBOUND_FRAMES
    }
}

#[cfg(unix)]
async fn handle_io_command(
    cmd: IoCommand,
    proto: &mut ProtoStream<UnixStream>,
    pending: &mut HashMap<Uuid, oneshot::Sender<std::result::Result<Response, ErrorPayload>>>,
) -> bool {
    match cmd {
        IoCommand::Cancel { id } => {
            if remove_pending_request(pending, id).is_some() {
                tracing::debug!(id = %id, "daemon request timed out; removed pending entry");
            }
            true
        }
        IoCommand::Request(p) => {
            let id = p.id;
            pending.insert(id, p.reply);
            let envelope = Envelope::request(id, p.request);
            if let Err(e) = proto.send(&envelope).await {
                tracing::warn!(error = ?e, "daemon write failed");
                if let Some(tx) = pending.remove(&id) {
                    let _ = tx.send(Err(ErrorPayload {
                        code: proto::ErrorCode::Internal,
                        message: format!("write to daemon failed: {e}"),
                    }));
                }
                false
            } else {
                true
            }
        }
    }
}

#[cfg(unix)]
fn remove_pending_request(
    pending: &mut HashMap<Uuid, oneshot::Sender<std::result::Result<Response, ErrorPayload>>>,
    id: Uuid,
) -> Option<oneshot::Sender<std::result::Result<Response, ErrorPayload>>> {
    pending.remove(&id)
}

fn is_nil_daemon_status_hello(id: Uuid, response: &Response) -> bool {
    id.is_nil() && matches!(response, Response::DaemonStatus { .. })
}

// ---- lifecycle helpers ----------------------------------------------------

/// Strategy for getting a daemon to talk to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleMode {
    /// "Attach if running, otherwise auto-promote a long-running
    /// background daemon." The TUI's default.
    AttachOrAutoPromote,
    /// "Attach if running, otherwise spawn a temporary daemon I'll
    /// stop on exit." Default for `cockpit run`. The flag name on
    /// the CLI is `--ephemeral`.
    AttachOrEphemeral,
    /// "Always spawn a fresh ephemeral daemon, even if one is
    /// running." Used by `cockpit run --ephemeral`.
    AlwaysEphemeral,
    /// "Attach to *my own* per-process ephemeral daemon if it's already
    /// running, otherwise spawn it." The daemonless TUI's mode
    /// (`DaemonChoice::ContinueWithout`): the first attach spawns the
    /// owned ephemeral daemon; every later re-attach in the same TUI
    /// (`/compact`, `/sessions` resume, `/new`) reconnects to that *same*
    /// cached instance path instead of spawning a second one. The path keeps
    /// the caller pid prefix plus a per-spawn nonce via
    /// [`crate::daemon::DaemonPaths::allocate_ephemeral`],
    /// so it never touches the canonical socket and stays isolated from
    /// any other TUI's ephemeral daemon. `owns_daemon = true`.
    AttachOwnEphemeral,
}

/// Connect-or-spawn result: a ready-to-use client plus a flag the
/// caller honors when it's time to shut down — `owns_daemon = true`
/// means "you spawned this daemon, so stop it on your way out."
pub struct ConnectedDaemon {
    pub client: DaemonClient,
    pub owns_daemon: bool,
    pub socket: PathBuf,
    pub startup_notice: Option<String>,
}

/// Find the daemon socket, optionally spawn the daemon, return a
/// connected client. Honors [`LifecycleMode`].
pub async fn probe_or_spawn(mode: LifecycleMode) -> Result<ConnectedDaemon> {
    use crate::daemon::{
        DaemonPaths, DaemonStatus, discover, spawn_detached, spawn_detached_ephemeral,
    };

    match mode {
        LifecycleMode::AttachOrAutoPromote | LifecycleMode::AttachOrEphemeral => {
            let discovered = discover().await;
            if matches!(discovered.status, DaemonStatus::Running) {
                if matches!(mode, LifecycleMode::AttachOrAutoPromote) {
                    match crate::daemon::skew_restart::restart_skewed_daemon_if_idle(
                        &discovered.paths,
                    )
                    .await
                    {
                        Ok(crate::daemon::skew_restart::SkewRestartOutcome::Restarted {
                            pid,
                            reason,
                        }) => {
                            tracing::info!(pid, "daemon version skew auto-restart completed");
                            let client = wait_for_daemon(&discovered.paths.socket).await?;
                            return Ok(ConnectedDaemon {
                                client,
                                owns_daemon: false,
                                socket: discovered.paths.socket,
                                startup_notice: Some(match reason {
                                    Some(reason) => {
                                        format!("daemon version skew resolved: {reason}")
                                    }
                                    None => "daemon version skew resolved by restarting the daemon"
                                        .to_string(),
                                }),
                            });
                        }
                        Ok(crate::daemon::skew_restart::SkewRestartOutcome::Refused {
                            reason,
                            skew_reason,
                        }) => {
                            tracing::info!(
                                reason = reason.as_deref().unwrap_or("unknown"),
                                "daemon version skew auto-restart deferred"
                            );
                            let startup_notice = format_skew_restart_notice(
                                skew_reason.as_deref(),
                                reason.as_deref(),
                            );
                            let client = DaemonClient::connect(&discovered.paths.socket).await?;
                            return Ok(ConnectedDaemon {
                                client,
                                owns_daemon: false,
                                socket: discovered.paths.socket,
                                startup_notice,
                            });
                        }
                        Ok(crate::daemon::skew_restart::SkewRestartOutcome::NoticeOnly {
                            reason,
                        }) => {
                            tracing::info!("daemon version skew surfaced without auto-restart");
                            let client = DaemonClient::connect(&discovered.paths.socket).await?;
                            return Ok(ConnectedDaemon {
                                client,
                                owns_daemon: false,
                                socket: discovered.paths.socket,
                                startup_notice: reason
                                    .map(|reason| format!("daemon version skew: {reason}")),
                            });
                        }
                        Ok(
                            crate::daemon::skew_restart::SkewRestartOutcome::NoSkew
                            | crate::daemon::skew_restart::SkewRestartOutcome::InProcess,
                        ) => {}
                        Err(error) => {
                            tracing::debug!(error = %error, "daemon version skew auto-restart check failed");
                        }
                    }
                }
                let client = DaemonClient::connect(&discovered.paths.socket).await?;
                return Ok(ConnectedDaemon {
                    client,
                    owns_daemon: false,
                    socket: discovered.paths.socket,
                    startup_notice: None,
                });
            }
            if matches!(
                discovered.status,
                DaemonStatus::IncompatibleProtocol
                    | DaemonStatus::LivePidSocketUnreachable
                    | DaemonStatus::UnverifiedPid
            ) {
                if let Some(hello) = discovered.hello.as_ref() {
                    anyhow::bail!(
                        "{}",
                        proto::incompatible_daemon_protocol_message(hello.protocol_version)
                    );
                } else {
                    anyhow::bail!(
                        "shared daemon pid is live but socket is unreachable: {}",
                        discovered.paths.socket.display()
                    );
                }
            }
        }
        LifecycleMode::AttachOwnEphemeral => {
            // Daemonless TUI sessions stay in this process. Existing helpers
            // still carry the owned ephemeral socket path as a stable lookup
            // key, but `DaemonClient::connect` resolves it to the registered
            // in-process context instead of opening a Unix socket.
            let own = own_ephemeral_paths()?;
            let ctx = crate::daemon::boot_in_process(
                own.clone(),
                crate::daemon::terminal::default_host_factory(),
            )?;
            return Ok(ConnectedDaemon {
                client: DaemonClient::from_in_process(ctx),
                owns_daemon: false,
                socket: own.socket,
                startup_notice: None,
            });
        }
        LifecycleMode::AlwaysEphemeral => {
            // Always spawn fresh on a unique pid+nonce ephemeral path
            // (Layer B). It never touches the canonical socket, so it
            // coexists with a persistent daemon — no "already running"
            // bail needed.
        }
    }

    // No reachable daemon to attach to — spawn one.
    //
    // `AttachOrAutoPromote` (the canonical TUI) promotes a *persistent*
    // daemon at the canonical path. The ephemeral modes spawn a unique
    // pid+nonce ephemeral daemon (Layer B): socket/pid the canonical
    // `daemon stop`/`status` never sees, with the self-reaping watchdog
    // armed (Layer C) so an uncatchable foreground death can't orphan it.
    let ephemeral = matches!(
        mode,
        LifecycleMode::AttachOrEphemeral
            | LifecycleMode::AlwaysEphemeral
            | LifecycleMode::AttachOwnEphemeral
    );

    let (paths, pid) = if ephemeral {
        // Allocate the exact ephemeral path set in the parent, then hand it
        // to the spawned daemon to bind. Daemonless TUI reattachments reuse
        // their cached owned path; `AlwaysEphemeral` allocates fresh here.
        let paths = match mode {
            LifecycleMode::AttachOwnEphemeral => own_ephemeral_paths()?,
            _ => DaemonPaths::allocate_ephemeral()?,
        };
        let pid = spawn_detached_ephemeral(&paths)?;
        (paths, pid)
    } else {
        // Auto-promoted persistent daemon: never `--no-sandbox` from a
        // client flag (that's a per-session default passed at attach;
        // sandboxing part 2 precedence). Only an explicit
        // `cockpit daemon start --no-sandbox` sets the daemon-level flag.
        let canonical = DaemonPaths::resolve_canonical()?;
        let pid = spawn_detached(false)?;
        (canonical, pid)
    };
    tracing::info!(pid = pid, ephemeral = ephemeral, "daemon spawned");

    // Wait for the socket + a successful handshake.
    let client = wait_for_daemon(&paths.socket).await?;

    Ok(ConnectedDaemon {
        client,
        owns_daemon: ephemeral,
        socket: paths.socket,
        startup_notice: None,
    })
}

fn format_skew_restart_notice(
    skew_reason: Option<&str>,
    deferred_reason: Option<&str>,
) -> Option<String> {
    let skew_reason = skew_reason?;
    Some(match deferred_reason {
        Some(deferred_reason) => {
            format!("daemon version skew: {skew_reason}; auto-restart deferred: {deferred_reason}")
        }
        None => format!("daemon version skew: {skew_reason}"),
    })
}

fn own_ephemeral_paths() -> Result<crate::daemon::DaemonPaths> {
    let slot = OWN_EPHEMERAL_PATHS.get_or_init(|| Mutex::new(None));
    let mut guard = slot
        .lock()
        .map_err(|_| anyhow!("owned ephemeral path cache poisoned"))?;
    if let Some(paths) = guard.clone() {
        return Ok(paths);
    }
    let paths = crate::daemon::DaemonPaths::allocate_ephemeral()?;
    *guard = Some(paths.clone());
    Ok(paths)
}

#[cfg(test)]
fn reset_own_ephemeral_paths_for_test() {
    if let Some(slot) = OWN_EPHEMERAL_PATHS.get() {
        *slot.lock().unwrap() = None;
    }
}

#[cfg(test)]
fn set_own_ephemeral_paths_for_test(paths: crate::daemon::DaemonPaths) {
    let slot = OWN_EPHEMERAL_PATHS.get_or_init(|| Mutex::new(None));
    *slot.lock().unwrap() = Some(paths);
}

/// Poll for the daemon socket and an actual DaemonStatus response.
/// 2ms initial backoff, doubling up to a 50ms ceiling; total cap 5s.
async fn wait_for_daemon(socket: &Path) -> Result<DaemonClient> {
    let mut timer = crate::startup::PhaseTimer::start("wait_for_daemon");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    // Tight initial backoff: a freshly-spawned daemon child binds and starts
    // accepting in ~15ms (exec + tokio init + a ~4ms boot on a multi-GB DB),
    // so the first retry must land near that mark, not 50ms later. Ramp gently
    // to a 50ms ceiling so a slow/contended spawn doesn't busy-spin.
    let mut backoff = Duration::from_millis(2);

    loop {
        if socket.exists() {
            // A connect error just means the socket exists but accept hasn't
            // started yet — fall through to the backoff retry.
            if let Ok(client) = DaemonClient::connect(socket).await {
                // Sanity check — first request after connect.
                if client.request_ok(Request::DaemonStatus).await.is_ok() {
                    timer.phase("spawn_to_ready");
                    timer.done();
                    return Ok(client);
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for daemon at {}", socket.display());
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_millis(50));
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use crate::daemon::DaemonPaths;
    use tokio::net::UnixListener;

    fn lsp_event(text: impl Into<String>) -> proto::Event {
        proto::Event::LspNotice { text: text.into() }
    }

    fn daemon_status_response() -> Response {
        daemon_status_response_with(proto::DAEMON_VERSION, proto::PROTOCOL_VERSION)
    }

    fn daemon_status_response_with(
        daemon_version: impl Into<String>,
        protocol_version: u32,
    ) -> Response {
        Response::DaemonStatus {
            pid: 1,
            uptime_secs: 2,
            active_sessions: 0,
            socket_path: "/tmp/cockpit.sock".to_string(),
            daemon_version: daemon_version.into(),
            protocol_version,
            paused_sessions: 0,
            database_path: ":memory:".to_string(),
            schema_version: crate::db::EXPECTED_SCHEMA_VERSION,
        }
    }

    fn attach_request(session_id: Option<Uuid>) -> Request {
        attach_request_with_client_protocol_version(session_id, proto::PROTOCOL_VERSION)
    }

    fn attach_request_with_client_protocol_version(
        session_id: Option<Uuid>,
        client_protocol_version: u32,
    ) -> Request {
        Request::Attach {
            session_id,
            since_seq: None,
            project_root: Some("/tmp".into()),
            no_sandbox: false,
            interactive: true,
            model_override: None,
            client_protocol_version,
            env_snapshot: None,
            env_policy: crate::env_snapshot::EnvDriftPolicy::Daemon,
        }
    }

    fn attached_response(session_id: Uuid) -> Response {
        Response::Attached {
            session_id,
            short_id: "abc123".to_string(),
            project_root: "/tmp".to_string(),
            project_id: "project".to_string(),
            active_agent: "Build".to_string(),
            active_agent_path: Vec::new(),
            foreground_target: None,
            active_subagent: None,
            active_model_state: None,
            history: Vec::new(),
            paused_work: Vec::new(),
            repair_required: None,
            daemon_version: proto::DAEMON_VERSION.to_string(),
            compatible: true,
            env_baseline: None,
            env_session: None,
            env_drift: None,
            env_policy_applied: crate::env_snapshot::EnvDriftPolicy::Daemon,
            btw_fork: None,
        }
    }

    async fn recv_request_id(daemon: &mut ProtoStream<UnixStream>) -> Uuid {
        match daemon.recv().await.unwrap().unwrap() {
            proto::RecvFrame::Envelope(env) => match env.body {
                Body::Request { id, .. } => id,
                other => panic!("expected request body, got {other:?}"),
            },
            other => panic!("expected request envelope, got {other:?}"),
        }
    }

    fn temp_ephemeral_paths(root: &std::path::Path, stem: &str) -> DaemonPaths {
        DaemonPaths {
            socket: root.join(format!("{stem}.sock")),
            pid_file: root.join(format!("{stem}.pid")),
            ephemeral: true,
        }
    }

    fn bind_test_socket() -> (tempfile::TempDir, PathBuf, UnixListener) {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).expect("bind daemon socket");
        (dir, socket, listener)
    }

    async fn send_daemon_hello(
        daemon: &mut ProtoStream<UnixStream>,
        daemon_version: impl Into<String>,
        protocol_version: u32,
    ) {
        daemon
            .send(&Envelope::response(
                Uuid::nil(),
                daemon_status_response_with(daemon_version, protocol_version),
            ))
            .await
            .unwrap();
    }

    #[test]
    fn nil_daemon_status_is_known_hello() {
        assert!(is_nil_daemon_status_hello(
            Uuid::nil(),
            &Response::DaemonStatus {
                pid: 1,
                uptime_secs: 1,
                active_sessions: 0,
                socket_path: "/tmp/cockpit.sock".to_string(),
                daemon_version: "0.1.test".to_string(),
                protocol_version: proto::PROTOCOL_VERSION,
                paused_sessions: 0,
                database_path: "/tmp/cockpit.db".to_string(),
                schema_version: crate::db::EXPECTED_SCHEMA_VERSION,
            },
        ));
    }

    #[test]
    fn non_nil_or_non_status_still_unknown() {
        assert!(!is_nil_daemon_status_hello(
            Uuid::new_v4(),
            &Response::DaemonStatus {
                pid: 1,
                uptime_secs: 1,
                active_sessions: 0,
                socket_path: "/tmp/cockpit.sock".to_string(),
                daemon_version: "0.1.test".to_string(),
                protocol_version: proto::PROTOCOL_VERSION,
                paused_sessions: 0,
                database_path: "/tmp/cockpit.db".to_string(),
                schema_version: crate::db::EXPECTED_SCHEMA_VERSION,
            },
        ));
        assert!(!is_nil_daemon_status_hello(Uuid::nil(), &Response::Ack));
    }

    #[tokio::test]
    async fn negotiation_parses_daemon_hello_on_connect() {
        let (_dir, socket, listener) = bind_test_socket();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut daemon = ProtoStream::new(stream);
            send_daemon_hello(&mut daemon, "0.1.handshake", proto::PROTOCOL_VERSION + 1).await;
        });

        let client = DaemonClient::connect(&socket).await.unwrap();

        assert_eq!(client.negotiated().daemon_version, "0.1.handshake");
        assert_eq!(
            client.negotiated().daemon_protocol_version,
            proto::PROTOCOL_VERSION + 1
        );
        assert_eq!(client.negotiated().version, proto::PROTOCOL_VERSION);
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn negotiation_falls_back_to_current_version_when_hello_is_absent() {
        let (_dir, socket, listener) = bind_test_socket();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let connect = tokio::spawn({
            let socket = socket.clone();
            async move { DaemonClient::connect(&socket).await.unwrap() }
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(500)).await;
        let client = connect.await.unwrap();

        assert_eq!(client.negotiated().version, proto::PROTOCOL_VERSION);
        assert_eq!(client.negotiated().daemon_version, "unknown");
        assert_eq!(
            client.negotiated().daemon_protocol_version,
            proto::PROTOCOL_VERSION
        );
        drop(client);
        server.abort();
    }

    #[tokio::test]
    async fn negotiation_sends_attach_with_negotiated_client_protocol_version() {
        let (_dir, socket, listener) = bind_test_socket();
        let session_id = Uuid::new_v4();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut daemon = ProtoStream::new(stream);
            send_daemon_hello(
                &mut daemon,
                "0.1.handshake",
                proto::MIN_SUPPORTED_PROTOCOL_VERSION,
            )
            .await;
            daemon.set_negotiated_version(proto::MIN_SUPPORTED_PROTOCOL_VERSION);
            let request_id = match daemon.recv().await.unwrap().unwrap() {
                proto::RecvFrame::Envelope(env) => match env.body {
                    Body::Request { id, request } => {
                        match request {
                            Request::Attach {
                                client_protocol_version,
                                ..
                            } => assert_eq!(
                                client_protocol_version,
                                proto::MIN_SUPPORTED_PROTOCOL_VERSION
                            ),
                            other => panic!("expected attach request, got {other:?}"),
                        }
                        id
                    }
                    other => panic!("expected request body, got {other:?}"),
                },
                other => panic!("expected request envelope, got {other:?}"),
            };
            daemon
                .send(&Envelope::response(
                    request_id,
                    attached_response(session_id),
                ))
                .await
                .unwrap();
        });

        let client = DaemonClient::connect(&socket).await.unwrap();
        client
            .request(attach_request_with_client_protocol_version(
                Some(session_id),
                client.negotiated().version,
            ))
            .await
            .unwrap()
            .unwrap();

        server.await.unwrap();
    }

    #[test]
    fn inbound_burst_probes_outbound_after_thirty_two_frames() {
        let mut burst = InboundBurst::default();
        for _ in 0..(MAX_BIASED_INBOUND_FRAMES - 1) {
            burst.record_inbound();
            assert!(!burst.should_probe_outbound());
        }
        burst.record_inbound();
        assert!(burst.should_probe_outbound());
        burst.reset();
        assert!(!burst.should_probe_outbound());
    }

    #[test]
    fn pending_cancel_removes_entry_and_late_repeat_is_ignored() {
        let id = Uuid::new_v4();
        let (tx, _rx) = oneshot::channel();
        let mut pending = HashMap::new();
        pending.insert(id, tx);

        assert!(remove_pending_request(&mut pending, id).is_some());
        assert!(pending.is_empty());
        assert!(remove_pending_request(&mut pending, id).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn full_event_queue_does_not_block_pending_requests() {
        let (client_stream, daemon_stream) = UnixStream::pair().expect("socket pair");
        let client = DaemonClient::from_proto(ProtoStream::new(client_stream));
        let mut daemon = ProtoStream::new(daemon_stream);

        let daemon_task = tokio::spawn(async move {
            for i in 0..(EVENT_QUEUE + 100) {
                daemon
                    .send(&Envelope::event(lsp_event(format!("event-{i}"))))
                    .await
                    .unwrap();
            }
            let id = recv_request_id(&mut daemon).await;
            daemon
                .send(&Envelope::response(id, daemon_status_response()))
                .await
                .unwrap();
        });

        let response = client
            .request(Request::DaemonStatus)
            .await
            .unwrap()
            .expect("full event queue must not block request handling");
        assert!(matches!(response, Response::DaemonStatus { .. }));
        daemon_task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn dropped_events_emit_exactly_one_lag_marker() {
        let (client_stream, daemon_stream) = UnixStream::pair().expect("socket pair");
        let client = DaemonClient::from_proto(ProtoStream::new(client_stream));
        let mut daemon = ProtoStream::new(daemon_stream);
        const DROPPED: usize = 7;

        let daemon_task = tokio::spawn(async move {
            for i in 0..EVENT_QUEUE {
                daemon
                    .send(&Envelope::event(lsp_event(format!("pre-{i}"))))
                    .await
                    .unwrap();
            }
            for i in 0..DROPPED {
                daemon
                    .send(&Envelope::event(lsp_event(format!("drop-{i}"))))
                    .await
                    .unwrap();
            }

            let id = recv_request_id(&mut daemon).await;
            daemon
                .send(&Envelope::response(id, daemon_status_response()))
                .await
                .unwrap();
        });

        client
            .request(Request::DaemonStatus)
            .await
            .unwrap()
            .expect("request proves all pre-lag frames were read before the response");

        for expected in 0..2 {
            assert!(matches!(
                client.next_event().await,
                Some(proto::Event::LspNotice { text }) if text == format!("pre-{expected}")
            ));
        }

        for expected in 2..EVENT_QUEUE {
            assert!(matches!(
                client.next_event().await,
                Some(proto::Event::LspNotice { text }) if text == format!("pre-{expected}")
            ));
        }

        assert!(matches!(
            client.next_event().await,
            Some(proto::Event::EventStreamLagged {
                session_id: None,
                dropped
            }) if dropped == DROPPED as u64
        ));
        match tokio::time::timeout(Duration::from_millis(1), client.next_event()).await {
            Err(_) | Ok(None) => {}
            Ok(Some(event)) => assert!(
                !matches!(event, proto::Event::EventStreamLagged { .. }),
                "one contiguous lag episode should produce exactly one marker"
            ),
        }
        daemon_task.await.unwrap();
    }

    #[tokio::test]
    async fn out_of_band_lag_error_is_surfaced_not_discarded() {
        let (client_stream, daemon_stream) = UnixStream::pair().expect("socket pair");
        let client = DaemonClient::from_proto(ProtoStream::new(client_stream));
        let mut daemon = ProtoStream::new(daemon_stream);
        let session_id = Uuid::new_v4();

        let request = client.request(attach_request(Some(session_id)));
        let daemon_reply = async {
            let attach_id = recv_request_id(&mut daemon).await;
            daemon
                .send(&Envelope::response(
                    attach_id,
                    attached_response(session_id),
                ))
                .await
                .unwrap();
            daemon
                .send(&Envelope::error(
                    None,
                    ErrorPayload {
                        code: proto::ErrorCode::Internal,
                        message: format!("event stream {} by 9; re-attach", "lagged"),
                    },
                ))
                .await
                .unwrap();
        };

        let (result, _) = tokio::join!(request, daemon_reply);
        result.unwrap().expect("attach succeeds");
        assert!(matches!(
            client.next_event().await,
            Some(proto::Event::Notice {
                session_id: observed,
                text
            }) if observed == session_id
                && text.contains(&format!("event stream {} by 9; re-attach", "lagged"))
        ));
    }

    #[tokio::test]
    async fn pre_attach_out_of_band_error_is_surfaced_not_discarded() {
        let (client_stream, daemon_stream) = UnixStream::pair().expect("socket pair");
        let client = DaemonClient::from_proto(ProtoStream::new(client_stream));
        let mut daemon = ProtoStream::new(daemon_stream);

        daemon
            .send(&Envelope::error(
                None,
                ErrorPayload {
                    code: proto::ErrorCode::Internal,
                    message: "daemon boot warning".to_string(),
                },
            ))
            .await
            .unwrap();

        assert!(matches!(
            client.next_event().await,
            Some(proto::Event::LspNotice { text })
                if text.contains("daemon boot warning")
        ));
    }

    #[tokio::test]
    async fn client_routes_protocol_version_error_to_pending_attach() {
        let (client_stream, daemon_stream) = UnixStream::pair().expect("socket pair");
        let client = DaemonClient::from_proto(ProtoStream::new(client_stream));
        let mut daemon = ProtoStream::new(daemon_stream);

        let request = client.request(Request::Attach {
            session_id: None,
            since_seq: None,
            project_root: Some("/tmp".into()),
            no_sandbox: false,
            interactive: true,
            model_override: None,
            client_protocol_version: proto::PROTOCOL_VERSION,
            env_snapshot: None,
            env_policy: crate::env_snapshot::EnvDriftPolicy::Daemon,
        });
        let daemon_reply = async {
            let id = match daemon.recv().await.unwrap().unwrap() {
                proto::RecvFrame::Envelope(env) => match env.body {
                    Body::Request { id, .. } => id,
                    other => panic!("expected request body, got {other:?}"),
                },
                other => panic!("expected request envelope, got {other:?}"),
            };
            daemon
                .send_raw_line(
                    serde_json::json!({
                        "v": 999,
                        "kind": "err",
                        "id": id,
                        "error": {
                            "code": "protocol_version",
                            "message": "too new"
                        }
                    })
                    .to_string(),
                )
                .await
                .unwrap();
        };

        let (result, _) = tokio::join!(request, daemon_reply);
        let err = result
            .unwrap()
            .expect_err("attach should receive typed protocol error");
        assert_eq!(err.code, proto::ErrorCode::ProtocolVersion);
        assert!(err.message.contains("wire protocol version mismatch"));
    }

    #[tokio::test]
    async fn unknown_frame_response_resolves_pending_request_with_error() {
        let (client_stream, daemon_stream) = UnixStream::pair().expect("socket pair");
        let client = DaemonClient::from_proto(ProtoStream::new(client_stream));
        let mut daemon = ProtoStream::new(daemon_stream);

        let daemon_reply = tokio::spawn(async move {
            let id = match daemon.recv().await.unwrap().unwrap() {
                proto::RecvFrame::Envelope(env) => match env.body {
                    Body::Request { id, .. } => id,
                    other => panic!("expected request body, got {other:?}"),
                },
                other => panic!("expected request envelope, got {other:?}"),
            };
            daemon
                .send_raw_line(
                    serde_json::json!({
                        "v": proto::PROTOCOL_VERSION,
                        "kind": "res",
                        "id": id,
                        "response": "future_response",
                        "data": { "future": true }
                    })
                    .to_string(),
                )
                .await
                .unwrap();
            let id = match daemon.recv().await.unwrap().unwrap() {
                proto::RecvFrame::Envelope(env) => match env.body {
                    Body::Request { id, .. } => id,
                    other => panic!("expected request body, got {other:?}"),
                },
                other => panic!("expected request envelope, got {other:?}"),
            };
            daemon
                .send(&Envelope::response(
                    id,
                    Response::DaemonStatus {
                        pid: 1,
                        uptime_secs: 2,
                        active_sessions: 0,
                        socket_path: "/tmp/cockpit.sock".to_string(),
                        daemon_version: proto::DAEMON_VERSION.to_string(),
                        protocol_version: proto::PROTOCOL_VERSION,
                        paused_sessions: 0,
                        database_path: ":memory:".to_string(),
                        schema_version: crate::db::EXPECTED_SCHEMA_VERSION,
                    },
                ))
                .await
                .unwrap();
        });

        let err = client
            .request(Request::DaemonStatus)
            .await
            .unwrap()
            .expect_err("unknown response should resolve pending request with error");
        assert_eq!(err.code, proto::ErrorCode::UnsupportedRequest);
        assert_eq!(
            err.message,
            format!(
                "unsupported request \"future_response\" in protocol v{}; this daemon speaks v{}",
                proto::PROTOCOL_VERSION,
                proto::PROTOCOL_VERSION
            )
        );

        let response = client
            .request(Request::DaemonStatus)
            .await
            .unwrap()
            .expect("unknown response must not close client IO loop");
        assert!(matches!(response, Response::DaemonStatus { .. }));
        daemon_reply.await.unwrap();
    }

    #[tokio::test]
    async fn unknown_frame_error_resolves_pending_request_with_error() {
        let (client_stream, daemon_stream) = UnixStream::pair().expect("socket pair");
        let client = DaemonClient::from_proto(ProtoStream::new(client_stream));
        let mut daemon = ProtoStream::new(daemon_stream);

        let request = client.request(Request::DaemonStatus);
        let daemon_reply = async {
            let id = match daemon.recv().await.unwrap().unwrap() {
                proto::RecvFrame::Envelope(env) => match env.body {
                    Body::Request { id, .. } => id,
                    other => panic!("expected request body, got {other:?}"),
                },
                other => panic!("expected request envelope, got {other:?}"),
            };
            daemon
                .send_raw_line(
                    serde_json::json!({
                        "v": proto::PROTOCOL_VERSION,
                        "kind": "err",
                        "id": id,
                        "error": {
                            "code": "future_error",
                            "message": "future error shape"
                        }
                    })
                    .to_string(),
                )
                .await
                .unwrap();
        };

        let (result, _) = tokio::join!(request, daemon_reply);
        let err = result
            .unwrap()
            .expect_err("unknown error should resolve pending request with error");
        assert_eq!(err.code, proto::ErrorCode::UnsupportedRequest);
        assert_eq!(
            err.message,
            format!(
                "unsupported request \"future_error\" in protocol v{}; this daemon speaks v{}",
                proto::PROTOCOL_VERSION,
                proto::PROTOCOL_VERSION
            )
        );
    }

    #[tokio::test]
    async fn unknown_frame_event_does_not_close_client_io_loop() {
        let (client_stream, daemon_stream) = UnixStream::pair().expect("socket pair");
        let client = DaemonClient::from_proto(ProtoStream::new(client_stream));
        let mut daemon = ProtoStream::new(daemon_stream);

        let request = client.request(Request::DaemonStatus);
        let daemon_reply = async {
            let id = match daemon.recv().await.unwrap().unwrap() {
                proto::RecvFrame::Envelope(env) => match env.body {
                    Body::Request { id, .. } => id,
                    other => panic!("expected request body, got {other:?}"),
                },
                other => panic!("expected request envelope, got {other:?}"),
            };
            daemon
                .send_raw_line(
                    serde_json::json!({
                        "v": proto::PROTOCOL_VERSION,
                        "kind": "evt",
                        "event": "future_event",
                        "data": { "future": true }
                    })
                    .to_string(),
                )
                .await
                .unwrap();
            daemon
                .send(&Envelope::response(
                    id,
                    Response::DaemonStatus {
                        pid: 1,
                        uptime_secs: 2,
                        active_sessions: 0,
                        socket_path: "/tmp/cockpit.sock".to_string(),
                        daemon_version: proto::DAEMON_VERSION.to_string(),
                        protocol_version: proto::PROTOCOL_VERSION,
                        paused_sessions: 0,
                        database_path: ":memory:".to_string(),
                        schema_version: crate::db::EXPECTED_SCHEMA_VERSION,
                    },
                ))
                .await
                .unwrap();
        };

        let (result, _) = tokio::join!(request, daemon_reply);
        let response = result
            .unwrap()
            .expect("unknown event must not close client IO loop");
        assert!(matches!(response, Response::DaemonStatus { .. }));
    }

    /// Daemonless = own ephemeral daemon (`daemonless-tui-ephemeral-lifecycle.md`
    /// §1). `LifecycleMode::AttachOwnEphemeral` attaches to this process's
    /// cached ephemeral daemon when it's already up and reports
    /// `owns_daemon = true` at that exact socket — i.e. a re-attach in the
    /// same daemonless TUI (`/compact`, `/sessions` resume, `/new`)
    /// reconnects to the owned daemon instead of spawning a second one. The
    /// daemon is run in-process at the cached path with isolated XDG dirs, so
    /// the spawn branch (which would launch a child) is never taken.
    #[tokio::test]
    async fn connect_uses_registered_in_process_context_without_socket() {
        let _guard = crate::test_env::lock_async().await;
        reset_own_ephemeral_paths_for_test();
        let root = tempfile::tempdir().expect("daemon path tempdir");

        let paths = temp_ephemeral_paths(root.path(), "cockpit-in-process-test");
        assert!(
            !paths.socket.exists(),
            "in-process transport must not require a socket file"
        );
        let db = crate::db::Db::open_in_memory().expect("in-memory daemon db");
        let ctx = crate::daemon::boot_in_process_with_db(paths.clone(), db)
            .expect("boot local daemon context");
        let client = DaemonClient::connect(&paths.socket)
            .await
            .expect("connect by local socket key");
        let response = client
            .request_ok(Request::DaemonStatus)
            .await
            .expect("local daemon status");
        match response {
            Response::DaemonStatus { socket_path, .. } => {
                assert_eq!(socket_path, paths.socket.display().to_string());
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert!(
            !paths.socket.exists(),
            "in-process transport must not create a socket file"
        );
        drop(client);
        drop(ctx);
        reset_own_ephemeral_paths_for_test();
    }

    #[tokio::test]
    async fn attach_own_ephemeral_uses_in_process_context() {
        let _guard = crate::test_env::lock_async().await;
        reset_own_ephemeral_paths_for_test();
        let root = tempfile::tempdir().expect("daemon path tempdir");

        let own = temp_ephemeral_paths(root.path(), "cockpit-eph-test-owned");
        set_own_ephemeral_paths_for_test(own.clone());
        let db = crate::db::Db::open_in_memory().expect("in-memory daemon db");
        let _ctx = crate::daemon::boot_in_process_with_db(own.clone(), db)
            .expect("boot local daemon context");

        let connected = probe_or_spawn(LifecycleMode::AttachOwnEphemeral)
            .await
            .expect("attach to own in-process daemon");
        assert!(
            !connected.owns_daemon,
            "in-process daemonless mode needs no child-process guard"
        );
        assert_eq!(
            connected.socket, own.socket,
            "must reuse the process-local owned path as the local transport key"
        );
        assert!(
            !connected.socket.exists(),
            "in-process daemonless mode must not bind a Unix socket"
        );
        connected
            .client
            .request_ok(Request::DaemonStatus)
            .await
            .expect("owned in-process daemon answers");

        reset_own_ephemeral_paths_for_test();
    }

    #[test]
    fn attach_own_ephemeral_reuses_cached_path() {
        let _guard = crate::test_env::lock();
        let root = tempfile::tempdir().expect("daemon path tempdir");
        let own = temp_ephemeral_paths(root.path(), "cockpit-eph-test-cache");
        reset_own_ephemeral_paths_for_test();
        set_own_ephemeral_paths_for_test(own.clone());

        let first = own_ephemeral_paths().expect("first owned path");
        let second = own_ephemeral_paths().expect("second owned path");

        assert_eq!(first.socket, own.socket);
        assert_eq!(first.socket, second.socket);
        assert_eq!(first.pid_file, own.pid_file);
        assert_eq!(first.pid_file, second.pid_file);
        reset_own_ephemeral_paths_for_test();
    }

    #[test]
    fn always_ephemeral_allocates_fresh_paths() {
        let root = tempfile::tempdir().expect("daemon path tempdir");
        let first = temp_ephemeral_paths(root.path(), "cockpit-eph-test-always-one");
        let second = temp_ephemeral_paths(root.path(), "cockpit-eph-test-always-two");

        assert_ne!(first.socket, second.socket);
        assert_ne!(first.pid_file, second.pid_file);
    }
}
