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
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use anyhow::Context;
use anyhow::{Result, anyhow};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;
use zeroize::Zeroizing;

use cockpit_proto::{self as proto, ErrorPayload, Request, Response};
#[cfg(unix)]
use cockpit_proto::{Body, Envelope, ProtoStream, RecvFrame};

/// A cloneable, capability-bearing endpoint for opening fresh in-process
/// client connections. Unlike the former pathname registry, possession of
/// this value is the authority to connect.
#[derive(Clone, Debug)]
pub struct InProcessEndpoint {
    connections: mpsc::Sender<oneshot::Sender<Option<InProcessConnection>>>,
    sensitive: mpsc::Sender<InProcessSensitiveRequest>,
}

pub struct InProcessSensitiveRequest {
    pub payload: Zeroizing<Vec<u8>>,
    pub reply: oneshot::Sender<Zeroizing<Vec<u8>>>,
}

impl InProcessEndpoint {
    pub fn new(
        connections: mpsc::Sender<oneshot::Sender<Option<InProcessConnection>>>,
        sensitive: mpsc::Sender<InProcessSensitiveRequest>,
    ) -> Self {
        Self {
            connections,
            sensitive,
        }
    }

    pub async fn sensitive_request(
        &self,
        payload: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let (reply, receive) = oneshot::channel();
        tokio::time::timeout(
            REQUEST_TIMEOUT,
            self.sensitive
                .send(InProcessSensitiveRequest { payload, reply }),
        )
        .await
        .map_err(|_| anyhow!("in-process sensitive request enqueue timed out"))?
        .map_err(|_| anyhow!("in-process sensitive endpoint has retired"))?;
        tokio::time::timeout(REQUEST_TIMEOUT, receive)
            .await
            .map_err(|_| anyhow!("in-process sensitive request timed out"))?
            .map_err(|_| anyhow!("in-process sensitive endpoint dropped its reply"))
    }

    async fn connect(&self) -> Result<InProcessConnection> {
        let (reply, receive) = oneshot::channel();
        tokio::time::timeout(REQUEST_TIMEOUT, self.connections.send(reply))
            .await
            .map_err(|_| anyhow!("in-process daemon connection enqueue timed out"))?
            .map_err(|_| anyhow!("in-process daemon endpoint has retired"))?;
        tokio::time::timeout(REQUEST_TIMEOUT, receive)
            .await
            .map_err(|_| anyhow!("in-process daemon connection timed out"))?
            .map_err(|_| anyhow!("in-process daemon endpoint dropped its reply"))?
            .ok_or_else(|| anyhow!("in-process daemon endpoint has retired"))
    }
}

/// Transport capability returned by lifecycle composition.
#[derive(Clone, Debug)]
pub enum ClientEndpoint {
    Wire(PathBuf),
    InProcess(InProcessEndpoint),
}

impl ClientEndpoint {
    /// Exchange one opaque, zeroizing payload over the endpoint's dedicated
    /// sensitive channel. The wire pathname and framing transport remain
    /// private to this client layer; presentation code cannot select or
    /// construct a raw sensitive socket path.
    pub async fn sensitive_request(
        &self,
        payload: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            Self::InProcess(endpoint) => endpoint.sensitive_request(payload).await,
            Self::Wire(control_socket) => {
                #[cfg(unix)]
                {
                    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                    let stem = control_socket
                        .file_stem()
                        .and_then(|stem| stem.to_str())
                        .unwrap_or("cockpit");
                    let socket = control_socket
                        .parent()
                        .map_or_else(PathBuf::new, Path::to_path_buf)
                        .join(format!("{stem}-leak-reveal.sock"));
                    let exchange = async move {
                        let mut stream = UnixStream::connect(socket).await?;
                        stream.write_all(&payload).await?;
                        stream.flush().await?;
                        stream.shutdown().await?;
                        const MAX_SENSITIVE_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
                        let mut response = Zeroizing::new(Vec::new());
                        stream
                            .take(MAX_SENSITIVE_RESPONSE_BYTES + 1)
                            .read_to_end(&mut response)
                            .await?;
                        if response.len() as u64 > MAX_SENSITIVE_RESPONSE_BYTES {
                            anyhow::bail!("sensitive endpoint response exceeded its byte limit");
                        }
                        Ok(response)
                    };
                    tokio::time::timeout(REQUEST_TIMEOUT, exchange)
                        .await
                        .map_err(|_| anyhow!("sensitive endpoint exchange timed out"))?
                }
                #[cfg(not(unix))]
                {
                    let _ = (control_socket, payload);
                    anyhow::bail!("wire sensitive transport is unavailable on this platform")
                }
            }
        }
    }
}

/// Presentation-owned lifecycle request. Resolution remains in the host
/// composition layer; the TUI never probes or spawns a daemon itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleIntent {
    AttachOrAutoPromote,
    AttachOrEphemeral,
    AlwaysEphemeral,
    AttachOwnEphemeral,
    EnsurePersistent,
}

pub struct LifecycleResolution {
    pub endpoint: ClientEndpoint,
    pub owns_daemon: bool,
    pub socket: PathBuf,
    pub startup_notice: Option<String>,
}

pub struct LifecycleRequest {
    pub intent: LifecycleIntent,
    pub reply: oneshot::Sender<Result<LifecycleResolution, String>>,
    /// The resolver retains any owned-daemon guard only after the requester
    /// acknowledges that it received the endpoint capability.
    pub accepted: oneshot::Receiver<()>,
}

#[derive(Clone)]
pub struct LifecycleClient {
    requests: mpsc::Sender<LifecycleRequest>,
}

impl LifecycleClient {
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<LifecycleRequest>) {
        let (requests, receive) = mpsc::channel(capacity);
        (Self { requests }, receive)
    }

    /// An explicitly unavailable lifecycle capability for presentation state
    /// that must be bound by its host before it can enqueue daemon work.
    pub fn disconnected() -> Self {
        let (client, receive) = Self::channel(1);
        drop(receive);
        client
    }

    pub async fn resolve(&self, intent: LifecycleIntent) -> Result<LifecycleResolution, String> {
        let (reply, receive) = oneshot::channel();
        let (accepted, acceptance) = oneshot::channel();
        tokio::time::timeout(
            REQUEST_TIMEOUT,
            self.requests.send(LifecycleRequest {
                intent,
                reply,
                accepted: acceptance,
            }),
        )
        .await
        .map_err(|_| "daemon lifecycle request enqueue timed out".to_string())?
        .map_err(|_| "daemon lifecycle resolver has stopped".to_string())?;
        let resolution = tokio::time::timeout(REQUEST_TIMEOUT, receive)
            .await
            .map_err(|_| "daemon lifecycle resolution timed out".to_string())?
            .map_err(|_| "daemon lifecycle resolver dropped its reply".to_string())??;
        accepted
            .send(())
            .map_err(|_| "daemon lifecycle resolver retired before acceptance".to_string())?;
        Ok(resolution)
    }
}

/// One request submitted to an in-process daemon transport.
pub struct InProcessRequest {
    pub request: Request,
    pub reply: oneshot::Sender<std::result::Result<Response, ErrorPayload>>,
}

/// A fresh client-side channel pair for an in-process daemon connection.
pub struct InProcessConnection {
    pub requests: mpsc::Sender<InProcessRequest>,
    pub events: mpsc::Receiver<proto::Event>,
}

#[cfg(unix)]
/// Outbound queue depth. Generous — request payloads are tiny.
const REQUEST_QUEUE: usize = 64;

#[cfg(unix)]
/// Inbound event queue depth. Lagging consumers drop incoming events and get a
/// typed lag marker once capacity returns. If the TUI cannot keep up, the
/// right answer is "reattach" (the server re-sends the current session state
/// on `Attach`).
const EVENT_QUEUE: usize = 1024;

/// Default request timeout. Most requests are < 50ms; we set a
/// generous ceiling so a hung daemon causes a loud error rather than
/// a stalled TUI.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(unix)]
const MAX_BIASED_INBOUND_FRAMES: usize = 32;

#[cfg(feature = "test-support")]
thread_local! {
    static CONNECT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(feature = "test-support")]
pub fn reset_connect_call_count() {
    CONNECT_CALLS.with(|calls| calls.set(0));
}

#[cfg(feature = "test-support")]
pub fn connect_call_count() -> usize {
    CONNECT_CALLS.with(std::cell::Cell::get)
}

/// Whether a daemon connection failed because the peer's wire protocol is
/// outside the supported range.
///
/// Keep this typed all the way through the `anyhow` boundary. Callers must not
/// classify transport failures by matching human-readable error text.
pub fn is_protocol_version_mismatch(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<proto::ErrorPayload>()
        .is_some_and(|payload| payload.code == proto::ErrorCode::ProtocolVersion)
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
    InProcess(mpsc::Sender<InProcessRequest>),
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
        #[cfg(feature = "test-support")]
        CONNECT_CALLS.with(|calls| calls.set(calls.get() + 1));
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

    pub async fn connect_endpoint(endpoint: &ClientEndpoint) -> Result<Self> {
        match endpoint {
            ClientEndpoint::Wire(socket) => Self::connect(socket).await,
            ClientEndpoint::InProcess(endpoint) => {
                Ok(Self::from_in_process(endpoint.connect().await?))
            }
        }
    }

    pub fn from_in_process(connection: InProcessConnection) -> Self {
        Self {
            backend: ClientBackend::InProcess(connection.requests),
            negotiated: proto::NegotiatedProtocol::current(),
            events: Arc::new(tokio::sync::Mutex::new(connection.events)),
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
        #[cfg(unix)]
        let id = Uuid::new_v4();
        match &self.backend {
            #[cfg(unix)]
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
                    .send(InProcessRequest { request, reply: tx })
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
            return Err(protocol_handshake_error(
                "daemon closed the connection before its hello",
            ));
        }
        Ok(Err(error)) => {
            tracing::debug!(error = %error, "daemon hello unreadable");
            return Err(protocol_handshake_error("daemon hello could not be read"));
        }
        Err(_) => {
            return Err(protocol_handshake_error("daemon hello timed out"));
        }
    };

    let Some(hello) = (match proto::parse_daemon_hello_line(&line) {
        Ok(hello) => hello,
        Err(error) => {
            tracing::debug!(error = %error, "daemon hello unparseable");
            return Err(protocol_handshake_error("daemon hello was malformed"));
        }
    }) else {
        return Err(protocol_handshake_error(
            "first daemon frame was not a daemon-status hello",
        ));
    };

    proto::NegotiatedProtocol::from_hello(&hello).map_err(anyhow::Error::new)
}

#[cfg(unix)]
fn protocol_handshake_error(reason: &'static str) -> anyhow::Error {
    anyhow::Error::new(proto::ErrorPayload {
        code: proto::ErrorCode::ProtocolVersion,
        message: format!(
            "daemon protocol handshake failed: {reason}; run `cockpit daemon restart`"
        ),
    })
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
                            Body::Request { id, request, .. } => {
                                tracing::warn!(id = %id, ?request, "daemon sent a request to a client; ignoring");
                            }
                            #[cfg(feature = "remote")]
                            Body::RemoteReplayRequest(_)
                            | Body::RemoteReplayResponse(_)
                            | Body::RemoteReplayAck(_)
                            | Body::RemoteReplayAckResponse(_) => {
                                tracing::debug!("ignoring remote replay control frame on local client transport");
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

#[cfg(unix)]
fn is_nil_daemon_status_hello(id: Uuid, response: &Response) -> bool {
    id.is_nil() && matches!(response, Response::DaemonStatus { .. })
}
#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
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
            schema_version: 1,
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
            initial_model: None,
            no_sandbox: false,
            interactive: true,
            model_override: None,
            client_protocol_version,
            env_snapshot: None,
            env_policy: proto::EnvDriftPolicy::Daemon,
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
            env_policy_applied: proto::EnvDriftPolicy::Daemon,
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
                schema_version: 1,
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
                schema_version: 1,
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
            send_daemon_hello(&mut daemon, "0.1.handshake", proto::PROTOCOL_VERSION).await;
        });

        let client = DaemonClient::connect(&socket).await.unwrap();

        assert_eq!(client.negotiated().daemon_version, "0.1.handshake");
        assert_eq!(
            client.negotiated().daemon_protocol_version,
            proto::PROTOCOL_VERSION
        );
        assert_eq!(client.negotiated().version, proto::PROTOCOL_VERSION);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn negotiation_preserves_typed_protocol_version_mismatch() {
        let (_dir, socket, listener) = bind_test_socket();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut daemon = ProtoStream::new(stream);
            send_daemon_hello(&mut daemon, "0.1.incompatible", proto::PROTOCOL_VERSION + 1).await;
        });

        let error = match DaemonClient::connect(&socket).await {
            Ok(_) => panic!("an incompatible daemon hello must reject the connection"),
            Err(error) => error,
        };

        assert!(is_protocol_version_mismatch(&error));
        let payload = error
            .downcast_ref::<proto::ErrorPayload>()
            .expect("the typed protocol error must survive the anyhow boundary");
        assert_eq!(payload.code, proto::ErrorCode::ProtocolVersion);
        assert!(!is_protocol_version_mismatch(&anyhow!(
            "wire protocol version mismatch in unrelated transport text"
        )));
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn negotiation_rejects_a_daemon_that_does_not_send_a_hello() {
        let (_dir, socket, listener) = bind_test_socket();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let connect = tokio::spawn({
            let socket = socket.clone();
            async move { DaemonClient::connect(&socket).await }
        });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(500)).await;
        let error = match connect.await.unwrap() {
            Ok(_) => panic!("missing hello must fail closed"),
            Err(error) => error,
        };
        assert!(is_protocol_version_mismatch(&error));
        let payload = error
            .downcast_ref::<proto::ErrorPayload>()
            .expect("missing hello must preserve a typed protocol error");
        assert_eq!(payload.code, proto::ErrorCode::ProtocolVersion);
        assert!(payload.message.contains("hello timed out"));
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
                    Body::Request { id, request, .. } => {
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
            initial_model: None,
            no_sandbox: false,
            interactive: true,
            model_override: None,
            client_protocol_version: proto::PROTOCOL_VERSION,
            env_snapshot: None,
            env_policy: proto::EnvDriftPolicy::Daemon,
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
                        schema_version: 1,
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
                        schema_version: 1,
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

    #[tokio::test]
    async fn lifecycle_resolution_requires_requester_acceptance() {
        let (client, mut requests) = LifecycleClient::channel(1);
        let resolve = tokio::spawn(async move {
            client
                .resolve(LifecycleIntent::AlwaysEphemeral)
                .await
                .expect("resolution")
        });
        let request = requests.recv().await.expect("lifecycle request");
        let (connections, _connection_requests) = mpsc::channel(1);
        let (sensitive, _sensitive_requests) = mpsc::channel(1);
        assert!(
            request
                .reply
                .send(Ok(LifecycleResolution {
                    endpoint: ClientEndpoint::InProcess(InProcessEndpoint::new(
                        connections,
                        sensitive,
                    )),
                    owns_daemon: true,
                    socket: PathBuf::from("in-process"),
                    startup_notice: None,
                }))
                .is_ok()
        );
        let _resolution = resolve.await.expect("resolve task");
        request.accepted.await.expect("endpoint acceptance");
    }

    #[tokio::test]
    async fn cancelled_lifecycle_resolution_closes_reply_and_acceptance() {
        let (client, mut requests) = LifecycleClient::channel(1);
        let resolve = tokio::spawn(async move {
            let _ = client.resolve(LifecycleIntent::AlwaysEphemeral).await;
        });
        let request = requests.recv().await.expect("lifecycle request");
        resolve.abort();
        let _ = resolve.await;
        assert!(request.reply.is_closed());
        assert!(request.accepted.await.is_err());
    }

    #[tokio::test]
    async fn in_process_endpoint_opens_reusable_fresh_connections() {
        let (connections, mut connection_requests) = mpsc::channel(2);
        let (sensitive, _sensitive_requests) = mpsc::channel(1);
        let endpoint = ClientEndpoint::InProcess(InProcessEndpoint::new(connections, sensitive));
        let broker = tokio::spawn(async move {
            for _ in 0..2 {
                let reply = connection_requests
                    .recv()
                    .await
                    .expect("connection request");
                let (requests, _request_receiver) = mpsc::channel(1);
                let (_events, event_receiver) = mpsc::channel(1);
                assert!(
                    reply
                        .send(Some(InProcessConnection {
                            requests,
                            events: event_receiver,
                        }))
                        .is_ok()
                );
            }
        });
        let _first = DaemonClient::connect_endpoint(&endpoint)
            .await
            .expect("first connection");
        let _second = DaemonClient::connect_endpoint(&endpoint)
            .await
            .expect("second connection");
        broker.await.expect("connection broker");
    }
}
