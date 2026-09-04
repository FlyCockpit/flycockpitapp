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
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(any(unix, windows))]
use anyhow::Context;
use anyhow::{Result, anyhow};
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeClient;
use tokio::sync::{mpsc, oneshot, watch};
use uuid::Uuid;
use zeroize::Zeroizing;

use cockpit_proto::{self as proto, ErrorPayload, Request, Response};
#[cfg(any(unix, windows))]
use cockpit_proto::{Body, Envelope, ProtoStream, RecvFrame};

#[cfg(unix)]
type WireStream = UnixStream;
#[cfg(windows)]
type WireStream = NamedPipeClient;

pub mod bulk_upload;
pub mod image_upload;
pub mod presentation;
pub mod submission;

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
    /// True when the endpoint is a discoverable OS transport owner: a Unix
    /// control socket or a Windows named-pipe identity path. Multi-window hosts
    /// such as ACP require this and reject the in-process optimization.
    pub fn is_discoverable_wire_owner(&self) -> bool {
        matches!(self, Self::Wire(_))
    }

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
                #[cfg(any(unix, windows))]
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
                        let mut stream = connect_wire(&socket).await?;
                        stream.write_all(&payload).await?;
                        stream.flush().await?;
                        stream.shutdown().await?;
                        const MAX_SENSITIVE_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
                        // Pre-size the zeroizing buffer to the response ceiling
                        // so `read_to_end` never reallocates: a realloc would
                        // copy the partial plaintext into a fresh allocation and
                        // free the old one WITHOUT zeroizing it, stranding
                        // revealed-secret fragments in freed heap (Zeroizing's
                        // drop only scrubs the final allocation). Any response
                        // within the ceiling now lands in this one buffer, and
                        // its full capacity is zeroed on drop.
                        let mut response = Zeroizing::new(Vec::with_capacity(
                            MAX_SENSITIVE_RESPONSE_BYTES as usize,
                        ));
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
                #[cfg(not(any(unix, windows)))]
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
    /// Attach to the current owner, or start a persistent owner.
    AttachOrPersistent,
    /// Attach to the current owner, or start a reference-counted ephemeral
    /// owner at the shared ledger socket.
    AttachOrEphemeral,
    /// Require a persistent owner. If the shared ledger is currently owned by
    /// an ephemeral daemon, the lifecycle host promotes it before returning.
    PromoteToPersistent,
}

impl LifecycleIntent {
    const fn as_u8(self) -> u8 {
        match self {
            Self::AttachOrPersistent => 0,
            Self::AttachOrEphemeral => 1,
            Self::PromoteToPersistent => 2,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::AttachOrPersistent,
            1 => Self::AttachOrEphemeral,
            2 => Self::PromoteToPersistent,
            _ => unreachable!("invalid lifecycle intent"),
        }
    }
}

#[derive(Debug)]
pub struct LifecycleResolution {
    pub endpoint: ClientEndpoint,
    pub owns_daemon: bool,
    /// Whether the resolved owner is reference-counted and therefore needs an
    /// explicit live-work detach decision.
    pub ephemeral_owner: bool,
    pub socket: PathBuf,
    pub startup_notice: Option<String>,
    /// The lifecycle host replaced an ephemeral owner while resolving this
    /// request. This is an ownership transition, not presentation text: a
    /// caller holding a client for the predecessor must reconnect.
    pub promoted_from_ephemeral: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleSpawnAuthorizationState {
    Active,
    CreatingOwner,
    OwnerCreated,
    Cancelled,
}

/// Request-scoped authority to create the first daemon owner.
///
/// Cancellation and owner creation serialize through this state. A caller
/// whose resolution timeout fires waits for an already-authorized creation to
/// finish before returning, so a request that has returned as cancelled can
/// no longer create an owner using its lifetime preference.
struct LifecycleSpawnAuthority {
    state: Mutex<LifecycleSpawnAuthorizationState>,
    changed: watch::Sender<()>,
}

impl LifecycleSpawnAuthority {
    fn new() -> Arc<Self> {
        let (changed, _) = watch::channel(());
        Arc::new(Self {
            state: Mutex::new(LifecycleSpawnAuthorizationState::Active),
            changed,
        })
    }

    fn is_cancelled(&self) -> bool {
        match self.state.lock() {
            Ok(state) => *state == LifecycleSpawnAuthorizationState::Cancelled,
            Err(_) => true,
        }
    }

    fn authorize_owner_spawn(self: &Arc<Self>) -> Result<LifecycleSpawnPermit, String> {
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "daemon lifecycle spawn authority was poisoned".to_string())?;
            match *state {
                LifecycleSpawnAuthorizationState::Active => {
                    *state = LifecycleSpawnAuthorizationState::CreatingOwner;
                }
                LifecycleSpawnAuthorizationState::Cancelled => {
                    return Err("daemon lifecycle request was cancelled before owner spawn".into());
                }
                LifecycleSpawnAuthorizationState::CreatingOwner
                | LifecycleSpawnAuthorizationState::OwnerCreated => {
                    return Err(
                        "daemon lifecycle request already used its owner-spawn authority".into(),
                    );
                }
            }
        }
        self.changed.send_replace(());
        Ok(LifecycleSpawnPermit {
            authority: Arc::clone(self),
            owner_created: false,
        })
    }

    fn release_authorization(&self) {
        let changed = match self.state.lock() {
            Ok(mut state) if *state == LifecycleSpawnAuthorizationState::CreatingOwner => {
                *state = LifecycleSpawnAuthorizationState::Active;
                true
            }
            Ok(_) => false,
            Err(_) => false,
        };
        if changed {
            self.changed.send_replace(());
        }
    }

    fn record_owner_created(&self) {
        let changed = match self.state.lock() {
            Ok(mut state) if *state == LifecycleSpawnAuthorizationState::CreatingOwner => {
                *state = LifecycleSpawnAuthorizationState::OwnerCreated;
                true
            }
            Ok(_) => false,
            Err(_) => false,
        };
        if changed {
            self.changed.send_replace(());
        }
    }

    fn cancel_if_active(&self) {
        let changed = match self.state.lock() {
            Ok(mut state) if *state == LifecycleSpawnAuthorizationState::Active => {
                *state = LifecycleSpawnAuthorizationState::Cancelled;
                true
            }
            Ok(_) => false,
            // A poisoned authority fails closed for future authorization.
            Err(_) => false,
        };
        if changed {
            self.changed.send_replace(());
        }
    }

    async fn cancel(&self) {
        loop {
            // Subscribe before inspecting the state so a creation completing
            // between the inspection and `changed` cannot be missed.
            let mut changed = self.changed.subscribe();
            let wait_for_creator = match self.state.lock() {
                Ok(mut state) => match *state {
                    LifecycleSpawnAuthorizationState::Active => {
                        *state = LifecycleSpawnAuthorizationState::Cancelled;
                        false
                    }
                    LifecycleSpawnAuthorizationState::CreatingOwner => true,
                    LifecycleSpawnAuthorizationState::OwnerCreated
                    | LifecycleSpawnAuthorizationState::Cancelled => return,
                },
                // A poisoned authority must never grant a later spawn.
                Err(_) => return,
            };
            if !wait_for_creator {
                self.changed.send_replace(());
                return;
            }
            let _ = changed.changed().await;
        }
    }
}

/// A linear permit held from authorization through the exact owner-creation
/// call. Dropping an unused permit returns the request to a cancellable state.
pub struct LifecycleSpawnPermit {
    authority: Arc<LifecycleSpawnAuthority>,
    owner_created: bool,
}

impl LifecycleSpawnPermit {
    /// Record that the owner-creation call succeeded. This releases a
    /// concurrent timeout only after that irreversible operation is complete.
    pub fn owner_created(&mut self) {
        self.authority.record_owner_created();
        self.owner_created = true;
    }
}

impl Drop for LifecycleSpawnPermit {
    fn drop(&mut self) {
        if !self.owner_created {
            self.authority.release_authorization();
        }
    }
}

pub struct LifecycleRequest {
    pub intent: LifecycleIntent,
    pub reply: oneshot::Sender<Result<LifecycleResolution, String>>,
    spawn_authority: Arc<LifecycleSpawnAuthority>,
}

impl LifecycleRequest {
    /// Atomically claim this request's one-time authority to create an owner.
    /// The returned permit must cover the exact owner-creation operation.
    pub fn authorize_owner_spawn(&self) -> Result<LifecycleSpawnPermit, String> {
        self.spawn_authority.authorize_owner_spawn()
    }

    /// Whether the waiting caller has cancelled this request. Discovery may
    /// still attach to an existing owner, but creation must fail closed.
    pub fn is_cancelled(&self) -> bool {
        self.spawn_authority.is_cancelled()
    }
}

struct LifecycleRequestCancellation {
    authority: Arc<LifecycleSpawnAuthority>,
    armed: bool,
}

impl LifecycleRequestCancellation {
    fn new(authority: Arc<LifecycleSpawnAuthority>) -> Self {
        Self {
            authority,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    async fn cancel(&mut self) {
        self.authority.cancel().await;
        self.disarm();
    }
}

impl Drop for LifecycleRequestCancellation {
    fn drop(&mut self) {
        if self.armed {
            self.authority.cancel_if_active();
        }
    }
}

#[derive(Clone)]
pub struct LifecycleClient {
    requests: mpsc::Sender<LifecycleRequest>,
    default_intent: Arc<AtomicU8>,
}

impl LifecycleClient {
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<LifecycleRequest>) {
        let (requests, receive) = mpsc::channel(capacity);
        (
            Self {
                requests,
                default_intent: Arc::new(AtomicU8::new(
                    LifecycleIntent::AttachOrPersistent.as_u8(),
                )),
            },
            receive,
        )
    }

    /// Bind the TUI's configured default lifetime to this presentation-owned
    /// capability. Explicit lifecycle resolution remains available for host
    /// composition; ordinary TUI consumers use [`Self::resolve_default`].
    pub fn with_default_intent(&self, default_intent: LifecycleIntent) -> Self {
        self.set_default_intent(default_intent);
        self.clone()
    }

    /// Update the selected default for every clone of this capability. The
    /// TUI calls this after applying a live config snapshot so subsequent
    /// background work cannot retain a stale lifetime preference.
    pub fn set_default_intent(&self, default_intent: LifecycleIntent) {
        self.default_intent
            .store(default_intent.as_u8(), Ordering::Release);
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
        let spawn_authority = LifecycleSpawnAuthority::new();
        let mut cancellation = LifecycleRequestCancellation::new(Arc::clone(&spawn_authority));
        let enqueue = tokio::time::timeout(
            REQUEST_TIMEOUT,
            self.requests.send(LifecycleRequest {
                intent,
                reply,
                spawn_authority,
            }),
        )
        .await
        .map_err(|_| "daemon lifecycle request enqueue timed out".to_string())?
        .map_err(|_| "daemon lifecycle resolver has stopped".to_string());
        if let Err(error) = enqueue {
            cancellation.cancel().await;
            return Err(error);
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, receive).await {
            Ok(Ok(resolution)) => {
                cancellation.disarm();
                resolution
            }
            Ok(Err(_)) => {
                cancellation.cancel().await;
                Err("daemon lifecycle resolver dropped its reply".to_string())
            }
            Err(_) => {
                // Do not return while a creation authorization is outstanding:
                // that would let a timed-out request retain write authority.
                cancellation.cancel().await;
                Err("daemon lifecycle resolution timed out".to_string())
            }
        }
    }

    /// Resolve using the lifetime selected for this presentation capability.
    /// The configured lifetime applies only if this request must create a new
    /// owner; the lifecycle host still attaches to an existing owner first.
    pub async fn resolve_default(&self) -> Result<LifecycleResolution, String> {
        let intent = LifecycleIntent::from_u8(self.default_intent.load(Ordering::Acquire));
        self.resolve(intent).await
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

#[cfg(any(unix, windows))]
/// Outbound queue depth. Generous — request payloads are tiny.
const REQUEST_QUEUE: usize = 64;

#[cfg(any(unix, windows))]
/// Inbound event queue depth. Lagging consumers drop incoming events and get a
/// typed lag marker once capacity returns. If the TUI cannot keep up, the
/// right answer is "reattach" (the server re-sends the current session state
/// on `Attach`).
const EVENT_QUEUE: usize = 1024;

/// Default request timeout. Most requests are < 50ms; we set a
/// generous ceiling so a hung daemon causes a loud error rather than
/// a stalled TUI.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Total sends for one `RetryLater`-eligible request, the first included. Small
/// on purpose: the daemon-side condition clears at a turn boundary, so a client
/// that keeps hammering would neither speed it up nor learn anything new.
pub const RETRY_LATER_ATTEMPTS: usize = 3;
/// Fixed pause between those attempts. Flat rather than exponential because the
/// wait is bounded by the daemon's own reconciliation, not by contention this
/// client can back off from.
pub const RETRY_LATER_BACKOFF: Duration = Duration::from_millis(200);
#[cfg(any(unix, windows))]
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

/// Typed request surface shared by [`DaemonClient`] and lifetime-bound
/// wrappers that must not convert back into a client handle.
pub trait DaemonRequestClient: Send + Sync {
    fn request(
        &self,
        request: Request,
    ) -> impl std::future::Future<Output = Result<std::result::Result<Response, ErrorPayload>>> + Send;
}

/// Public handle. Cheap to clone: every clone shares the same
/// background reader/writer task; only the event-stream subscription
/// differs.
#[derive(Clone, Debug)]
pub struct DaemonClient {
    backend: ClientBackend,
    negotiated: proto::NegotiatedProtocol,
    /// One channel per `DaemonClient` clone, hydrated by the reader
    /// task. We use `Arc<Mutex<_>>` because `mpsc::Receiver` isn't
    /// `Clone` — clones of `DaemonClient` share access to the
    /// receiver they were spawned with.
    events: Arc<tokio::sync::Mutex<mpsc::Receiver<proto::Event>>>,
    /// Daemon-private owner capability loaded from the 0600 file next to
    /// the control socket. In-process clients do not need it: possession of
    /// the endpoint is the capability. Issue #296 / follow-up #337.
    owner_capability: Option<proto::OwnerCapabilityToken>,
}

#[cfg(any(unix, windows))]
struct Pending {
    id: Uuid,
    request: Request,
    reply: oneshot::Sender<std::result::Result<Response, ErrorPayload>>,
}

#[derive(Clone, Debug)]
enum ClientBackend {
    #[cfg(any(unix, windows))]
    Wire(mpsc::Sender<IoCommand>),
    InProcess(mpsc::Sender<InProcessRequest>),
}

#[cfg(any(unix, windows))]
enum IoCommand {
    Request(Box<Pending>),
    Cancel { id: Uuid },
}

impl DaemonClient {
    /// Connect to the daemon at `socket`.
    ///
    /// A socket client confirms the negotiated daemon hello before this
    /// returns. That distinguishes an authenticated client from a raw
    /// hello-only discovery probe and gives an ephemeral daemon its lifetime
    /// reference before the caller can be cancelled, dropped, or hand a live
    /// owner off to another client.
    pub async fn connect(socket: &Path) -> Result<Self> {
        #[cfg(feature = "test-support")]
        CONNECT_CALLS.with(|calls| calls.set(calls.get() + 1));
        #[cfg(any(unix, windows))]
        {
            let stream = connect_wire(socket).await?;
            let mut proto = ProtoStream::new(stream);
            let negotiated = negotiate_hello(&mut proto).await?;
            proto.set_negotiated_version(negotiated.version);
            let initial_events = confirm_client_lifetime(&mut proto, negotiated.version).await?;
            let file_capability = load_owner_capability(socket);
            let owner_capability =
                exchange_peer_credential(&mut proto, negotiated.version, file_capability).await?;
            Ok(Self::from_proto_negotiated(
                proto,
                negotiated,
                initial_events,
                owner_capability,
            ))
        }
        #[cfg(not(any(unix, windows)))]
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
            owner_capability: None,
        }
    }

    /// True when this client can present the daemon-private owner capability
    /// (in-process endpoint, or a loaded socket token). ACP stdio ingress
    /// requires this (issue #296).
    pub fn has_owner_capability(&self) -> bool {
        match &self.backend {
            ClientBackend::InProcess(_) => true,
            #[cfg(any(unix, windows))]
            ClientBackend::Wire(_) => self.owner_capability.is_some(),
        }
    }

    #[cfg(any(unix, windows))]
    #[cfg(test)]
    fn from_proto<S>(proto: ProtoStream<S>) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        Self::from_proto_negotiated(
            proto,
            proto::NegotiatedProtocol::current(),
            Vec::new(),
            None,
        )
    }

    #[cfg(any(unix, windows))]
    fn from_proto_negotiated<S>(
        proto: ProtoStream<S>,
        negotiated: proto::NegotiatedProtocol,
        initial_events: Vec<proto::Event>,
        owner_capability: Option<proto::OwnerCapabilityToken>,
    ) -> Self
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (request_tx, request_rx) = mpsc::channel::<IoCommand>(REQUEST_QUEUE);
        let (event_tx, event_rx) = mpsc::channel::<proto::Event>(EVENT_QUEUE);
        for event in initial_events {
            // The confirmation exchange occurs before the client exposes its
            // event receiver. Preserve daemon events that arrive ahead of the
            // confirmation response so connection setup remains lossless.
            event_tx
                .try_send(event)
                .expect("bounded confirmation events fit the client queue");
        }
        tokio::spawn(run_io(
            proto,
            request_rx,
            event_tx,
            owner_capability.clone(),
        ));
        Self {
            backend: ClientBackend::Wire(request_tx),
            negotiated,
            events: Arc::new(tokio::sync::Mutex::new(event_rx)),
            owner_capability,
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
        self.request_with_timeout(request, REQUEST_TIMEOUT).await
    }

    /// Send a request with a caller-selected response deadline.
    ///
    /// Most daemon operations use [`Self::request`]'s short default deadline.
    /// Operations whose protocol explicitly includes a user wait, such as a
    /// device-code approval poll, must opt into a deadline that covers their
    /// documented lifetime. Timing out here only stops waiting for the reply;
    /// it does not cancel daemon-side work.
    pub async fn request_with_timeout(
        &self,
        request: Request,
        response_timeout: Duration,
    ) -> Result<std::result::Result<Response, ErrorPayload>> {
        let (tx, rx) = oneshot::channel();
        #[cfg(any(unix, windows))]
        let id = Uuid::now_v7();
        match &self.backend {
            #[cfg(any(unix, windows))]
            ClientBackend::Wire(request_tx) => {
                request_tx
                    .send(IoCommand::Request(Box::new(Pending {
                        id,
                        request,
                        reply: tx,
                    })))
                    .await
                    .map_err(|_| anyhow!("daemon client task has stopped"))?;
                match tokio::time::timeout(response_timeout, rx).await {
                    Ok(Ok(result)) => Ok(result),
                    Ok(Err(_)) => Err(anyhow!("daemon client dropped reply channel")),
                    Err(_) => {
                        let _ = request_tx.send(IoCommand::Cancel { id }).await;
                        Err(anyhow!("request timed out after {:?}", response_timeout))
                    }
                }
            }
            ClientBackend::InProcess(request_tx) => {
                request_tx
                    .send(InProcessRequest { request, reply: tx })
                    .await
                    .map_err(|_| anyhow!("in-process daemon client task has stopped"))?;
                match tokio::time::timeout(response_timeout, rx).await {
                    Ok(Ok(result)) => Ok(result),
                    Ok(Err(_)) => Err(anyhow!("in-process daemon client dropped reply channel")),
                    Err(_) => Err(anyhow!("request timed out after {:?}", response_timeout)),
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

    /// [`Self::request_ok`] with a bounded retry on [`proto::ErrorCode::RetryLater`].
    ///
    /// `RetryLater` is the daemon's typed promise that this exact request is
    /// being refused by a short-lived, self-resolving condition (today: a
    /// workspace-trust reconciliation holding a session's admission gate) and
    /// that re-sending it is the documented recovery. Clients must never infer
    /// that from the message text, and they must never retry forever: after
    /// [`RETRY_LATER_ATTEMPTS`] tries the error is surfaced normally so a
    /// genuinely stuck daemon is still visible.
    ///
    /// This lives in the client rather than at each call site because the
    /// transport is the one place every affected request kind — session-setup
    /// snapshot, inventory bundle, agent effective settings — already passes
    /// through, and because a retry needs the typed [`ErrorPayload`] that the
    /// upper layers have already flattened into a `String`.
    pub async fn request_ok_retrying_transient(&self, request: Request) -> Result<Response> {
        for attempt in 0..RETRY_LATER_ATTEMPTS {
            match self.request(request.clone()).await? {
                Ok(response) => return Ok(response),
                Err(error) if error.code == proto::ErrorCode::RetryLater => {
                    if attempt + 1 == RETRY_LATER_ATTEMPTS {
                        return Err(anyhow!("daemon error: {error}"));
                    }
                    tokio::time::sleep(RETRY_LATER_BACKOFF).await;
                }
                Err(error) => return Err(anyhow!("daemon error: {error}")),
            }
        }
        // `RETRY_LATER_ATTEMPTS` is a non-zero constant and the final attempt
        // returns from inside the loop, so this is unreachable.
        Err(anyhow!("daemon error: retry budget exhausted"))
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
        #[cfg(any(unix, windows))]
        {
            matches!(self.backend, ClientBackend::Wire(_))
        }
        #[cfg(not(any(unix, windows)))]
        {
            false
        }
    }
}

impl DaemonRequestClient for DaemonClient {
    async fn request(
        &self,
        request: Request,
    ) -> Result<std::result::Result<Response, ErrorPayload>> {
        DaemonClient::request(self, request).await
    }
}

#[cfg(any(unix, windows))]
async fn connect_wire(socket: &Path) -> Result<WireStream> {
    #[cfg(unix)]
    {
        UnixStream::connect(socket)
            .await
            .with_context(|| format!("connecting to {}", socket.display()))
    }
    #[cfg(windows)]
    {
        connect_named_pipe(socket).await
    }
}

#[cfg(windows)]
async fn connect_named_pipe(identity: &Path) -> Result<NamedPipeClient> {
    // Bounded busy-retry, stale-owner classification, and server-SID check
    // live in `cockpit_host::named_pipe` so every client open shares them.
    let pipe = cockpit_host::named_pipe::read_pipe_identity(identity)
        .with_context(|| format!("reading named-pipe identity {}", identity.display()))?;
    cockpit_host::named_pipe::connect_client_pipe(&pipe)
        .await
        .with_context(|| format!("connecting to {} ({})", identity.display(), pipe.as_str()))
}

#[cfg(any(unix, windows))]
async fn negotiate_hello<S>(proto_stream: &mut ProtoStream<S>) -> Result<proto::NegotiatedProtocol>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
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

/// Exchange a peer-bound credential after lifetime confirmation. Socket peers
/// must present this token on secret-bearing RPCs (issue #337).
#[cfg(any(unix, windows))]
async fn exchange_peer_credential<S>(
    proto_stream: &mut ProtoStream<S>,
    version: u32,
    owner_capability: Option<proto::OwnerCapabilityToken>,
) -> Result<Option<proto::OwnerCapabilityToken>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let id = Uuid::now_v7();
    proto_stream
        .send(&Envelope::request_with_owner_capability_at(
            version,
            id,
            Request::ExchangeLocalPeerCredential,
            owner_capability,
        ))
        .await
        .context("sending peer credential exchange")?;

    let exchange = async {
        loop {
            let frame = proto_stream.recv().await?;
            let Some(frame) = frame else {
                return Err(protocol_handshake_error(
                    "daemon closed before peer credential exchange",
                ));
            };
            match frame {
                RecvFrame::Envelope(envelope) => match envelope.body {
                    Body::Response {
                        id: response_id,
                        response,
                    } if response_id == id => match *response {
                        Response::LocalPeerCredential { token, .. } => return Ok(Some(token)),
                        _ => {
                            return Err(protocol_handshake_error(
                                "daemon returned an invalid peer credential exchange response",
                            ));
                        }
                    },
                    Body::Error {
                        id: Some(response_id),
                        error,
                    } if response_id == id => return Err(anyhow::Error::new(error)),
                    _ => {}
                },
                RecvFrame::Unknown { .. } | RecvFrame::VersionMismatch { .. } => {
                    return Err(protocol_handshake_error(
                        "daemon rejected the peer credential exchange version",
                    ));
                }
            }
        }
    };

    tokio::time::timeout(REQUEST_TIMEOUT, exchange)
        .await
        .map_err(|_| protocol_handshake_error("peer credential exchange timed out"))?
}

/// Confirm that a peer which parsed the daemon's hello is an actual client,
/// not a reachability probe that merely reads and drops that hello. The server
/// takes its ephemeral lifetime reference while it processes this request.
///
/// This happens before `run_io` owns the transport, so a returned
/// [`DaemonClient`] is already a live reference even if its caller is
/// immediately cancelled or dropped without making an application request.
#[cfg(any(unix, windows))]
async fn confirm_client_lifetime<S>(
    proto_stream: &mut ProtoStream<S>,
    version: u32,
) -> Result<Vec<proto::Event>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let id = Uuid::now_v7();
    proto_stream
        .send(&Envelope::request_at(version, id, Request::DaemonStatus))
        .await
        .context("sending daemon lifetime confirmation")?;

    let confirmation = async {
        let mut initial_events = Vec::new();
        loop {
            let frame = proto_stream.recv().await?;
            let Some(frame) = frame else {
                return Err(protocol_handshake_error(
                    "daemon closed before lifetime confirmation",
                ));
            };
            match frame {
                RecvFrame::Envelope(envelope) => match envelope.body {
                    Body::Event { event } => initial_events.push(event),
                    Body::Response {
                        id: response_id,
                        response,
                    } if response_id == id
                        && matches!(*response, Response::DaemonStatus { .. }) =>
                    {
                        return Ok(initial_events);
                    }
                    Body::Error {
                        id: Some(response_id),
                        error,
                    } if response_id == id => return Err(anyhow::Error::new(error)),
                    _ => {
                        return Err(protocol_handshake_error(
                            "daemon sent an invalid lifetime confirmation",
                        ));
                    }
                },
                RecvFrame::Unknown { .. } | RecvFrame::VersionMismatch { .. } => {
                    return Err(protocol_handshake_error(
                        "daemon rejected the lifetime confirmation version",
                    ));
                }
            }
        }
    };

    tokio::time::timeout(REQUEST_TIMEOUT, confirmation)
        .await
        .map_err(|_| protocol_handshake_error("daemon lifetime confirmation timed out"))?
}

#[cfg(any(unix, windows))]
fn protocol_handshake_error(reason: &'static str) -> anyhow::Error {
    anyhow::Error::new(proto::ErrorPayload {
        code: proto::ErrorCode::ProtocolVersion,
        message: format!(
            "daemon protocol handshake failed: {reason}; run `cockpit daemon restart`"
        ),
    })
}

#[cfg(any(unix, windows))]
async fn run_io<S>(
    mut proto: ProtoStream<S>,
    mut request_rx: mpsc::Receiver<IoCommand>,
    event_tx: mpsc::Sender<proto::Event>,
    owner_capability: Option<proto::OwnerCapabilityToken>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
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
                    if !handle_io_command(cmd, &mut proto, &mut pending, owner_capability.as_ref())
                        .await
                    {
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
                                    match &response {
                                        Response::Attached { session_id, .. } => {
                                            attached_session = Some(*session_id);
                                        }
                                        Response::CodeRootCreated(result) => {
                                            attached_session = Some(result.root.root_id.0);
                                        }
                                        Response::CodeRootAttached(result) => {
                                            attached_session = Some(result.root.root_id.0);
                                        }
                                        Response::CodeRootWithAcpIngressCreated(result) => {
                                            attached_session = Some(result.base.root.root_id.0);
                                        }
                                        Response::CodeRootWithAcpIngressAttached(result) => {
                                            attached_session = Some(result.base.root.root_id.0);
                                        }
                                        _ => {}
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
                if !handle_io_command(cmd, &mut proto, &mut pending, owner_capability.as_ref())
                    .await
                {
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

#[cfg(any(unix, windows))]
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

#[cfg(any(unix, windows))]
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

#[cfg(any(unix, windows))]
#[derive(Default)]
struct InboundBurst {
    frames: usize,
}

#[cfg(any(unix, windows))]
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

#[cfg(any(unix, windows))]
async fn handle_io_command<S>(
    cmd: IoCommand,
    proto: &mut ProtoStream<S>,
    pending: &mut HashMap<Uuid, oneshot::Sender<std::result::Result<Response, ErrorPayload>>>,
    owner_capability: Option<&proto::OwnerCapabilityToken>,
) -> bool
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
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
            let envelope =
                Envelope::request_with_owner_capability(id, p.request, owner_capability.cloned());
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

#[cfg(any(unix, windows))]
fn remove_pending_request(
    pending: &mut HashMap<Uuid, oneshot::Sender<std::result::Result<Response, ErrorPayload>>>,
    id: Uuid,
) -> Option<oneshot::Sender<std::result::Result<Response, ErrorPayload>>> {
    pending.remove(&id)
}

#[cfg(any(unix, windows))]
fn is_nil_daemon_status_hello(id: Uuid, response: &Response) -> bool {
    id.is_nil() && matches!(response, Response::DaemonStatus { .. })
}

/// Same derivation the daemon uses: `{stem}.owner-capability` next to the
/// control socket. Confined children are denied this path.
pub fn owner_capability_path(control_socket: &Path) -> PathBuf {
    let stem = control_socket
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("cockpit");
    let file_name = format!("{stem}.owner-capability");
    match control_socket.parent() {
        Some(parent) => parent.join(file_name),
        None => PathBuf::from(file_name),
    }
}

#[cfg(any(unix, windows))]
fn load_owner_capability(socket: &Path) -> Option<proto::OwnerCapabilityToken> {
    let path = owner_capability_path(socket);
    let bytes = std::fs::read(&path).ok()?;
    let token = String::from_utf8(bytes).ok()?;
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(proto::OwnerCapabilityToken::new(token.to_string()))
    }
}
#[cfg(test)]
#[cfg(any(unix, windows))]
mod tests {
    use super::*;
    #[cfg(unix)]
    use tokio::net::UnixListener;

    fn lsp_event(text: impl Into<String>) -> proto::Event {
        proto::Event::LspNotice { text: text.into() }
    }

    #[test]
    fn discoverable_wire_owner_matches_wire_endpoint() {
        assert!(ClientEndpoint::Wire(PathBuf::from("daemon.sock")).is_discoverable_wire_owner());
    }

    #[test]
    fn discoverable_wire_owner_rejects_in_process_endpoint() {
        let (connections, _connection_rx) = tokio::sync::mpsc::channel(1);
        let (sensitive, _sensitive_rx) = tokio::sync::mpsc::channel(1);
        let endpoint = ClientEndpoint::InProcess(InProcessEndpoint::new(connections, sensitive));
        assert!(!endpoint.is_discoverable_wire_owner());
    }

    #[test]
    fn owner_capability_path_is_a_pure_function_of_the_control_socket() {
        assert_eq!(
            owner_capability_path(Path::new("/run/user/1000/cockpit/cockpit.sock")),
            PathBuf::from("/run/user/1000/cockpit/cockpit.owner-capability")
        );
        assert_eq!(
            owner_capability_path(Path::new("/home/u/.local/state/cockpit/daemon.sock")),
            PathBuf::from("/home/u/.local/state/cockpit/daemon.owner-capability")
        );
        let dir = tempfile::tempdir().unwrap();
        assert!(load_owner_capability(&dir.path().join("cockpit.sock")).is_none());
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
            session_entry_mode: proto::NonCodeSessionEntryMode::Assistant,
            model_override: None,
            client_protocol_version,
            env_snapshot: None,
            env_policy: proto::EnvDriftPolicy::Daemon,
        }
    }

    fn attached_response(session_id: Uuid) -> Response {
        Response::Attached {
            session_id,
            session_entry_mode: proto::SessionEntryMode::Assistant,
            short_id: "abc123".to_string(),
            project_root: "/tmp".to_string(),
            project_id: "project".to_string(),
            active_agent: "Build".to_string(),
            active_agent_path: Vec::new(),
            foreground_target: None,
            active_subagent: None,
            active_model_state: None,
            history: Vec::new(),
            removed_user_message_seqs: Vec::new(),
            paused_work: Vec::new(),
            repair_required: None,
            resume_compaction_offer: None,
            daemon_version: proto::DAEMON_VERSION.to_string(),
            compatible: true,
            env_baseline: None,
            env_session: None,
            env_drift: None,
            env_policy_applied: proto::EnvDriftPolicy::Daemon,
            btw_fork: None,
        }
    }

    async fn recv_request_id<S>(daemon: &mut ProtoStream<S>) -> Uuid
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        match daemon.recv().await.unwrap().unwrap() {
            proto::RecvFrame::Envelope(env) => match env.body {
                Body::Request { id, .. } => id,
                other => panic!("expected request body, got {other:?}"),
            },
            other => panic!("expected request envelope, got {other:?}"),
        }
    }

    #[cfg(unix)]
    fn bind_test_socket() -> (tempfile::TempDir, PathBuf, UnixListener) {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).expect("bind daemon socket");
        (dir, socket, listener)
    }

    #[cfg(windows)]
    struct TestPipeListener {
        pending: tokio::net::windows::named_pipe::NamedPipeServer,
        name: String,
    }

    #[cfg(windows)]
    impl TestPipeListener {
        async fn accept(&mut self) -> tokio::net::windows::named_pipe::NamedPipeServer {
            self.pending.connect().await.expect("pipe connect");
            let connected = std::mem::replace(
                &mut self.pending,
                tokio::net::windows::named_pipe::ServerOptions::new()
                    .create(&self.name)
                    .expect("next pipe instance"),
            );
            connected
        }
    }

    #[cfg(windows)]
    fn bind_test_socket() -> (tempfile::TempDir, PathBuf, TestPipeListener) {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("daemon.sock");
        let sid = cockpit_host::named_pipe::current_user_sid().expect("sid");
        let pipe = cockpit_host::named_pipe::allocate_pipe_name(&sid).expect("pipe name");
        cockpit_host::named_pipe::write_pipe_identity(&socket, &pipe).expect("identity");
        let pending = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(pipe.as_str())
            .expect("bind named pipe");
        (
            dir,
            socket,
            TestPipeListener {
                pending,
                name: pipe.as_str().to_string(),
            },
        )
    }

    #[cfg(unix)]
    async fn accept_test(listener: &UnixListener) -> UnixStream {
        listener.accept().await.expect("accept").0
    }

    #[cfg(windows)]
    async fn accept_test(
        listener: &mut TestPipeListener,
    ) -> tokio::net::windows::named_pipe::NamedPipeServer {
        listener.accept().await
    }

    async fn send_daemon_hello<S>(
        daemon: &mut ProtoStream<S>,
        daemon_version: impl Into<String>,
        protocol_version: u32,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        daemon
            .send(&Envelope::response(
                Uuid::nil(),
                daemon_status_response_with(daemon_version, protocol_version),
            ))
            .await
            .unwrap();
    }

    async fn confirm_client_lifetime<S>(daemon: &mut ProtoStream<S>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        let id = match daemon.recv().await.unwrap().unwrap() {
            RecvFrame::Envelope(envelope) => match envelope.body {
                Body::Request {
                    id,
                    request: Request::DaemonStatus,
                    ..
                } => id,
                other => panic!("expected lifetime confirmation, got {other:?}"),
            },
            other => panic!("expected lifetime confirmation envelope, got {other:?}"),
        };
        daemon
            .send(&Envelope::response(id, daemon_status_response()))
            .await
            .unwrap();
    }

    async fn complete_wire_connect_handshake<S>(daemon: &mut ProtoStream<S>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        confirm_client_lifetime(daemon).await;
        let id = match daemon.recv().await.unwrap().unwrap() {
            RecvFrame::Envelope(envelope) => match envelope.body {
                Body::Request {
                    id,
                    request: Request::ExchangeLocalPeerCredential,
                    ..
                } => id,
                other => panic!("expected peer credential exchange, got {other:?}"),
            },
            other => panic!("expected peer credential exchange envelope, got {other:?}"),
        };
        daemon
            .send(&Envelope::response(
                id,
                Response::LocalPeerCredential {
                    token: proto::OwnerCapabilityToken::new("test-peer-token"),
                    role: proto::LocalClientRole::Cli,
                },
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
    async fn connect_fails_when_the_endpoint_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        DaemonClient::connect(&dir.path().join("missing.sock"))
            .await
            .expect_err("absent endpoint must fail closed");
    }

    #[tokio::test]
    async fn wire_connect_exchanges_peer_credential_for_acp_ingress() {
        let (dir, socket, mut listener) = bind_test_socket();

        let server = tokio::spawn(async move {
            let stream = accept_test(&mut listener).await;
            let mut daemon = ProtoStream::new(stream);
            send_daemon_hello(&mut daemon, "0.1.capability", proto::PROTOCOL_VERSION).await;
            complete_wire_connect_handshake(&mut daemon).await;
        });

        let client = DaemonClient::connect(&socket).await.unwrap();

        assert!(client.is_socket_backed());
        assert!(client.has_owner_capability());
        assert!(ClientEndpoint::Wire(socket).is_discoverable_wire_owner());
        drop(client);
        server.await.unwrap();
        drop(dir);
    }

    #[tokio::test]
    async fn negotiation_parses_daemon_hello_on_connect() {
        let (_dir, socket, mut listener) = bind_test_socket();
        let server = tokio::spawn(async move {
            let stream = accept_test(&mut listener).await;
            let mut daemon = ProtoStream::new(stream);
            send_daemon_hello(&mut daemon, "0.1.handshake", proto::PROTOCOL_VERSION).await;
            complete_wire_connect_handshake(&mut daemon).await;
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
        let (_dir, socket, mut listener) = bind_test_socket();
        let server = tokio::spawn(async move {
            let stream = accept_test(&mut listener).await;
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
        let (_dir, socket, mut listener) = bind_test_socket();
        let server = tokio::spawn(async move {
            let _stream = accept_test(&mut listener).await;
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
        let (_dir, socket, mut listener) = bind_test_socket();
        let session_id = Uuid::new_v4();
        let server = tokio::spawn(async move {
            let stream = accept_test(&mut listener).await;
            let mut daemon = ProtoStream::new(stream);
            send_daemon_hello(
                &mut daemon,
                "0.1.handshake",
                proto::MIN_SUPPORTED_PROTOCOL_VERSION,
            )
            .await;
            daemon.set_negotiated_version(proto::MIN_SUPPORTED_PROTOCOL_VERSION);
            complete_wire_connect_handshake(&mut daemon).await;
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
        let (client_stream, daemon_stream) = tokio::io::duplex(1024 * 1024);
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
    async fn caller_selected_request_timeout_outlives_the_default_deadline() {
        let (client_stream, daemon_stream) = tokio::io::duplex(1024 * 1024);
        let client = DaemonClient::from_proto(ProtoStream::new(client_stream));
        let mut daemon = ProtoStream::new(daemon_stream);
        let (received_tx, received_rx) = oneshot::channel();

        let daemon_task = tokio::spawn(async move {
            let id = recv_request_id(&mut daemon).await;
            received_tx.send(()).expect("test receives request");
            tokio::time::sleep(REQUEST_TIMEOUT + Duration::from_secs(1)).await;
            daemon
                .send(&Envelope::response(id, daemon_status_response()))
                .await
                .expect("test daemon sends delayed response");
        });
        let request = tokio::spawn({
            let client = client.clone();
            async move {
                client
                    .request_with_timeout(
                        Request::DaemonStatus,
                        REQUEST_TIMEOUT + Duration::from_secs(2),
                    )
                    .await
            }
        });

        received_rx.await.expect("request reaches daemon");
        // Let the server register its delayed response before advancing the
        // paused clock. Without this scheduling boundary the advance can run
        // before the delay exists, leaving the test to advance only the
        // caller deadline and making it race spuriously.
        tokio::task::yield_now().await;
        tokio::time::advance(REQUEST_TIMEOUT + Duration::from_secs(1)).await;

        let response = request
            .await
            .expect("request task joins")
            .expect("custom deadline accepts delayed response")
            .expect("daemon response succeeds");
        assert!(matches!(response, Response::DaemonStatus { .. }));
        daemon_task.await.expect("daemon task joins");
    }

    #[tokio::test(start_paused = true)]
    async fn dropped_events_emit_exactly_one_lag_marker() {
        let (client_stream, daemon_stream) = tokio::io::duplex(1024 * 1024);
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
        let (client_stream, daemon_stream) = tokio::io::duplex(1024 * 1024);
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
        let (client_stream, daemon_stream) = tokio::io::duplex(1024 * 1024);
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
        let (client_stream, daemon_stream) = tokio::io::duplex(1024 * 1024);
        let client = DaemonClient::from_proto(ProtoStream::new(client_stream));
        let mut daemon = ProtoStream::new(daemon_stream);

        let request = client.request(Request::Attach {
            session_id: None,
            since_seq: None,
            project_root: Some("/tmp".into()),
            initial_model: None,
            no_sandbox: false,
            interactive: true,
            session_entry_mode: proto::NonCodeSessionEntryMode::Assistant,
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
        let (client_stream, daemon_stream) = tokio::io::duplex(1024 * 1024);
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
        let (client_stream, daemon_stream) = tokio::io::duplex(1024 * 1024);
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
        let (client_stream, daemon_stream) = tokio::io::duplex(1024 * 1024);
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
    async fn lifecycle_resolution_returns_endpoint() {
        let (client, mut requests) = LifecycleClient::channel(1);
        let resolve = tokio::spawn(async move {
            client
                .resolve(LifecycleIntent::AttachOrEphemeral)
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
                    ephemeral_owner: true,
                    socket: PathBuf::from("in-process"),
                    startup_notice: None,
                    promoted_from_ephemeral: false,
                }))
                .is_ok()
        );
        let _resolution = resolve.await.expect("resolve task");
    }

    #[tokio::test]
    async fn configured_default_lifecycle_resolution_sends_selected_intent() {
        let (client, mut requests) = LifecycleClient::channel(1);
        let client = client.with_default_intent(LifecycleIntent::AttachOrEphemeral);
        let resolve = tokio::spawn(async move { client.resolve_default().await });
        let request = requests.recv().await.expect("lifecycle request");
        assert_eq!(request.intent, LifecycleIntent::AttachOrEphemeral);
        drop(request);
        assert!(resolve.await.expect("resolve task").is_err());
    }

    #[tokio::test]
    async fn cancelled_lifecycle_resolution_closes_reply() {
        let (client, mut requests) = LifecycleClient::channel(1);
        let resolve = tokio::spawn(async move {
            let _ = client.resolve(LifecycleIntent::AttachOrEphemeral).await;
        });
        let request = requests.recv().await.expect("lifecycle request");
        resolve.abort();
        let _ = resolve.await;
        assert!(request.reply.is_closed());
    }

    #[tokio::test]
    async fn cancellation_and_owner_creation_have_one_authority_winner() {
        let authority = LifecycleSpawnAuthority::new();
        let mut permit = authority
            .authorize_owner_spawn()
            .expect("active request may claim owner creation");

        let cancelling_authority = Arc::clone(&authority);
        let cancellation = tokio::spawn(async move {
            cancelling_authority.cancel().await;
        });
        tokio::task::yield_now().await;
        assert!(
            !cancellation.is_finished(),
            "cancellation must wait for an authorized creation to finish"
        );

        permit.owner_created();
        cancellation.await.expect("cancellation task");
        assert!(
            authority.authorize_owner_spawn().is_err(),
            "an already-resolved request cannot create a second owner"
        );
    }

    #[tokio::test]
    async fn cancellation_claimed_first_rejects_owner_creation() {
        let authority = LifecycleSpawnAuthority::new();
        authority.cancel().await;
        assert!(
            authority.authorize_owner_spawn().is_err(),
            "a cancelled request cannot create an owner"
        );
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
