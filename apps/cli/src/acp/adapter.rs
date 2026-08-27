//! ACP stdio peer adapter.
//!
//! Routes inbound frames through the owned classifier, the jsonrpsee method
//! table, and the outbound permission registry. Imports no proto ingress type
//! and does not call catalog `Install*` / `Release*` lifecycle methods.

use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

use super::AcpTransportCounters;
use super::classify::{ClassifyError, InboundMessage, classify};
use super::codec::{AcpFrameError, AcpLineReader, AcpLineWriter, FrameSink, write_diagnostic};
use super::dispatch::{
    DispatchResult, SessionIngress, UnavailableSessionIngress, dispatch_notification,
    dispatch_request, elicitation_is_rejected, is_session_method,
};
use super::envelope::{invalid_request, parse_error};
use super::registry::{ApprovalAck, OutboundPermissionRegistry, ResolveCodeRootInterrupt};

/// The only protocol-semantic non-success stdio exit. It means the editor
/// selected an issued permission option, but its durable delivery had already
/// reached a conflicting closed state, so the ACP session must fail rather
/// than acknowledge or fabricate a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcpPeerExitError {
    ClosedPermissionRefusal(cockpit_proto::ResolveCodeRootInterruptResultV1),
}

impl std::fmt::Display for AcpPeerExitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClosedPermissionRefusal(outcome) => {
                write!(f, "ACP permission delivery was closed: {outcome:?}")
            }
        }
    }
}

impl std::error::Error for AcpPeerExitError {}

pub struct AcpAdapter<S, R, A, I = UnavailableSessionIngress> {
    pub counters: AcpTransportCounters,
    pub registry: OutboundPermissionRegistry,
    pub resolve: R,
    pub ack: A,
    pub sink: S,
    pub(crate) session_ingress: Arc<Mutex<I>>,
    closed_refusal: Option<AcpPeerExitError>,
    pub connection_closed: bool,
}

impl<S, R, A> AcpAdapter<S, R, A, UnavailableSessionIngress>
where
    S: FrameSink,
    R: ResolveCodeRootInterrupt,
    A: ApprovalAck,
{
    pub fn new(sink: S, resolve: R, ack: A) -> Self {
        Self::new_with_session_ingress(sink, resolve, ack, UnavailableSessionIngress)
    }
}

impl<S, R, A, I> AcpAdapter<S, R, A, I>
where
    S: FrameSink,
    R: ResolveCodeRootInterrupt,
    A: ApprovalAck,
    I: SessionIngress + 'static,
{
    pub fn new_with_session_ingress(sink: S, resolve: R, ack: A, session_ingress: I) -> Self {
        Self {
            counters: AcpTransportCounters::default(),
            registry: OutboundPermissionRegistry::new(),
            resolve,
            ack,
            sink,
            session_ingress: Arc::new(Mutex::new(session_ingress)),
            closed_refusal: None,
            connection_closed: false,
        }
    }

    pub fn handle_frame(&mut self, json: &str) -> Option<String> {
        match classify(json) {
            Err(ClassifyError::DuplicateMember { request_id, .. }) => {
                self.counters.frames_rejected += 1;
                invalid_request(request_id.as_ref())
            }
            Err(ClassifyError::InvalidJson { request_id }) => {
                self.counters.frames_rejected += 1;
                parse_error(request_id.as_ref())
            }
            Err(ClassifyError::InvalidJsonrpc { request_id })
            | Err(ClassifyError::InvalidParams { request_id })
            | Err(ClassifyError::MissingMethod { request_id })
            | Err(ClassifyError::BothRequestAndResponse { request_id }) => {
                self.counters.frames_rejected += 1;
                invalid_request(request_id.as_ref())
            }
            Ok(InboundMessage::Response(response)) => {
                if let Some(outcome) = self.registry.on_inbound_response(
                    &response.id,
                    response.result.as_ref(),
                    &response.raw,
                    &mut self.resolve,
                    &mut self.ack,
                    &mut self.sink,
                    &mut self.counters,
                ) {
                    self.closed_refusal = Some(AcpPeerExitError::ClosedPermissionRefusal(outcome));
                    self.connection_closed = true;
                    self.registry.on_disconnect(&mut self.counters);
                }
                None
            }
            Ok(InboundMessage::Request(request)) => {
                if elicitation_is_rejected(&request.method) {
                    return Some(super::envelope::method_not_found(&request.id));
                }
                match dispatch_request(
                    &request,
                    Arc::clone(&self.session_ingress),
                    &mut self.counters,
                ) {
                    DispatchResult::Response(frame) => Some(frame),
                    DispatchResult::NotificationHandled | DispatchResult::NoResponse => None,
                }
            }
            Ok(InboundMessage::Notification(notification)) => {
                if is_session_method(&notification.method)
                    && !self
                        .session_ingress
                        .lock()
                        .expect("session ingress")
                        .is_available()
                {
                    self.counters.frames_rejected += 1;
                    self.disconnect();
                    return None;
                }
                dispatch_notification(
                    &notification.method,
                    &notification.raw,
                    Arc::clone(&self.session_ingress),
                    &mut self.counters,
                );
                None
            }
        }
    }

    pub fn write_protocol(&mut self, json: &str) -> Result<(), AcpFrameError> {
        match self.sink.write_json_value(json, &mut self.counters) {
            Ok(super::codec::WriteOutcome::Complete) => Ok(()),
            Ok(super::codec::WriteOutcome::Partial { .. })
            | Ok(super::codec::WriteOutcome::Failed) => {
                self.connection_closed = true;
                self.registry.on_disconnect(&mut self.counters);
                Err(AcpFrameError::Io("incomplete ACP stdout write".into()))
            }
            Err(err) => {
                self.connection_closed = true;
                self.registry.on_disconnect(&mut self.counters);
                Err(err)
            }
        }
    }

    pub fn disconnect(&mut self) {
        self.connection_closed = true;
        self.registry.on_disconnect(&mut self.counters);
    }
}

pub fn run_stdio_peer<In, Out, ErrOut, R, A>(
    stdin: In,
    stdout: Out,
    stderr: ErrOut,
    resolve: R,
    ack: A,
) -> io::Result<()>
where
    In: Read,
    Out: Write,
    ErrOut: Write,
    R: ResolveCodeRootInterrupt,
    A: ApprovalAck,
{
    let writer = AcpLineWriter::new(stdout);
    run_stdio_peer_with_adapter(stdin, stderr, AcpAdapter::new(writer, resolve, ack))
}

pub(crate) fn run_stdio_peer_with_adapter<In, ErrOut, S, R, A, I>(
    stdin: In,
    mut stderr: ErrOut,
    mut adapter: AcpAdapter<S, R, A, I>,
) -> io::Result<()>
where
    In: Read,
    ErrOut: Write,
    S: FrameSink,
    R: ResolveCodeRootInterrupt,
    A: ApprovalAck,
    I: SessionIngress + 'static,
{
    let mut reader = AcpLineReader::new(stdin);
    loop {
        match reader.read_frame(&mut adapter.counters) {
            Ok(None) => {
                adapter.disconnect();
                return Ok(());
            }
            Ok(Some(frame)) => {
                if let Some(response) = adapter.handle_frame(&frame.json)
                    && let Err(err) = adapter.write_protocol(&response)
                {
                    write_diagnostic(&mut stderr, &err);
                    return Err(io::Error::other(err));
                }
            }
            Err(err) => {
                write_diagnostic(&mut stderr, &err);
                if let Some(response) = match &err {
                    AcpFrameError::InvalidUtf8
                    | AcpFrameError::IncompleteEof { .. }
                    | AcpFrameError::Empty => None,
                    _ => None,
                } {
                    let _ = adapter.write_protocol(response);
                }
            }
        }
        if adapter.connection_closed || adapter.registry.connection_closed() {
            if let Some(exit) = adapter.closed_refusal {
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, exit));
            }
            return Ok(());
        }
    }
}
