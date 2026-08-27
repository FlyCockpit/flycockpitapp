//! ACP stdio peer adapter.
//!
//! Routes inbound frames through the owned classifier, the jsonrpsee method
//! table, and the outbound permission registry. Imports no proto ingress type
//! and does not call catalog `Install*` / `Release*` lifecycle methods.

use std::io::{self, Read, Write};

use super::AcpTransportCounters;
use super::bridge::BridgeFacade;
use super::classify::{ClassifyError, InboundMessage, classify};
use super::codec::{AcpFrameError, AcpLineReader, AcpLineWriter, FrameSink, write_diagnostic};
use super::dispatch::{
    DispatchResult, dispatch_notification, dispatch_request, elicitation_is_rejected,
};
use super::envelope::{invalid_request, parse_error};
use super::registry::{ApprovalAck, OutboundPermissionRegistry, ResolveCodeRootInterrupt};

pub struct AcpAdapter<S, R, A> {
    pub counters: AcpTransportCounters,
    pub registry: OutboundPermissionRegistry,
    pub bridge: BridgeFacade,
    pub resolve: R,
    pub ack: A,
    pub sink: S,
    pub cancelled_sessions: Vec<String>,
    pub connection_closed: bool,
}

impl<S, R, A> AcpAdapter<S, R, A>
where
    S: FrameSink,
    R: ResolveCodeRootInterrupt,
    A: ApprovalAck,
{
    pub fn new(sink: S, resolve: R, ack: A) -> Self {
        Self {
            counters: AcpTransportCounters::default(),
            registry: OutboundPermissionRegistry::new(),
            bridge: BridgeFacade,
            resolve,
            ack,
            sink,
            cancelled_sessions: Vec::new(),
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
            | Err(ClassifyError::MissingMethod { request_id })
            | Err(ClassifyError::BothRequestAndResponse { request_id }) => {
                self.counters.frames_rejected += 1;
                invalid_request(request_id.as_ref())
            }
            Ok(InboundMessage::Response(response)) => {
                self.registry.on_inbound_response(
                    &response.id,
                    response.result.as_ref(),
                    &response.raw,
                    &mut self.resolve,
                    &mut self.ack,
                    &mut self.sink,
                    &mut self.counters,
                );
                None
            }
            Ok(InboundMessage::Request(request)) => {
                if elicitation_is_rejected(&request.method) {
                    return Some(super::envelope::method_not_found(&request.id));
                }
                match dispatch_request(
                    &request,
                    &self.bridge,
                    &mut self.counters,
                    &mut self.cancelled_sessions,
                ) {
                    DispatchResult::Response(frame) => Some(frame),
                    DispatchResult::NotificationHandled | DispatchResult::NoResponse => None,
                }
            }
            Ok(InboundMessage::Notification(notification)) => {
                dispatch_notification(
                    &notification.method,
                    notification.raw_params.as_deref(),
                    notification.params.as_ref(),
                    &mut self.cancelled_sessions,
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
    mut stderr: ErrOut,
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
    let mut reader = AcpLineReader::new(stdin);
    let writer = AcpLineWriter::new(stdout);
    let mut adapter = AcpAdapter::new(writer, resolve, ack);
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
        if adapter.connection_closed {
            return Ok(());
        }
    }
}
