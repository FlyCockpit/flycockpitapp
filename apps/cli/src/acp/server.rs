//! Daemon-backed ACP stdio peer for Cockpit Code roots.
//!
//! The editor owns only this stdio connection. Root lifetime, prompt dispatch,
//! replay, and permissions remain behind the daemon's capability-checked Code
//! root routes, so ACP never becomes an editor execution authority.

use std::collections::HashMap;
use std::io::{self};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use cockpit_client::DaemonClient;
use cockpit_proto::{
    AckCodeRootDeliveriesV1Request, AttachExistingCodeRootV1Request,
    AttachExistingCodeRootWithAcpIngressV1Request, CodeRootAttachOptionsV1,
    CodeRootAttachmentCapabilityV1, CodeRootDeliveryPayloadV1, CodeRootIdV1,
    CodeRootWorkspaceSelectorV1, CreateCodeRootV1Request, CreateCodeRootWithAcpIngressV1Request,
    DiscoverCodeRootsV1Request, OpaqueAsciiId128V1, ReadCodeRootDeliveriesV1Request,
    ReadCodeRootV1Request, Request, Response,
};
use serde_json::{Value, json};
use tokio::runtime::Handle;
use uuid::Uuid;

use super::AcpTransportCounters;
use super::adapter::AcpAdapter;
use super::bridge::BridgeFacade;
use super::classify::{InboundMessage, InboundRequest, classify};
use super::codec::{AcpLineReader, AcpLineWriter, FrameSink, write_diagnostic};
use super::dispatch::{SessionIngress, SessionIngressError, validate_initialize};
use super::dto::{SessionAdmissionDto, SessionLoadDto, SessionNewDto};
use super::envelope::notification;
use super::envelope::{invalid_params, invalid_request, success_response};
use super::registry::{ApprovalAck, ResolveCodeRootInterrupt};

const DISCOVERY_PAGE_SIZE: u16 = 100;

/// Wait for `initialize` before acquiring the shared socket owner. This is
/// important: a malformed or abandoned editor launch must not create a daemon.
pub async fn run() -> Result<()> {
    let handle = Handle::current();
    tokio::task::block_in_place(|| run_blocking(&handle))
}

fn run_blocking(handle: &Handle) -> Result<()> {
    let mut stderr = io::stderr();
    let mut peer: Option<Peer> = None;
    let (frames, frame_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = AcpLineReader::new(io::stdin());
        let mut counters = AcpTransportCounters::default();
        loop {
            match reader.read_frame(&mut counters) {
                Ok(Some(frame)) if frames.send(ReaderEvent::Frame(frame)).is_ok() => {}
                Ok(Some(_)) | Ok(None) => {
                    let _ = frames.send(ReaderEvent::Eof);
                    break;
                }
                Err(error) => {
                    let _ = frames.send(ReaderEvent::Error(error));
                    break;
                }
            }
        }
    });

    loop {
        if let Some(peer) = peer.as_mut() {
            if peer.adapter.connection_closed || peer.adapter.registry.connection_closed() {
                break;
            }
            // Poll terminal events before accepting the next editor request.
            // In particular, a queued `SessionEnded` or a closed attachment
            // stream must unregister its capability before `session/load` can
            // decide whether an existing attachment is live.
            peer.drain_turn_events()?;
            peer.drain_deliveries()?;
            if peer.adapter.connection_closed || peer.adapter.registry.connection_closed() {
                break;
            }
        }
        match frame_rx.recv_timeout(Duration::from_millis(25)) {
            Ok(ReaderEvent::Frame(frame)) => {
                let mut counters = AcpTransportCounters::default();
                if peer.is_none() {
                    let Ok(InboundMessage::Request(request)) = classify(&frame.json) else {
                        continue;
                    };
                    if request.method != "initialize" {
                        if let Some(response) = invalid_request(Some(&request.id)) {
                            AcpLineWriter::new(io::stdout())
                                .write_json_value(&response, &mut counters)
                                .map_err(|error| anyhow!(error))?;
                        }
                        continue;
                    }
                    if let Err(message) = validate_initialize(request.raw_params.as_deref()) {
                        let response = invalid_params(&request.id, message);
                        AcpLineWriter::new(io::stdout())
                            .write_json_value(&response, &mut counters)
                            .map_err(|error| anyhow!(error))?;
                        continue;
                    }
                    let background_agents = background_agents_setting()?;
                    let client = handle
                        .block_on(super::acquire_ledger_owner(background_agents))
                        .context("acquiring the socket daemon for ACP")?;
                    peer = Some(Peer::new(handle.clone(), client, background_agents));
                }
                let peer = peer.as_mut().expect("initialized ACP peer");
                let prompt = match classify(&frame.json) {
                    Ok(InboundMessage::Request(request)) if request.method == "session/prompt" => {
                        Some(request)
                    }
                    _ => None,
                };
                if let Some(response) = peer.adapter.handle_frame(&frame.json) {
                    if let Some(request) = prompt.as_ref()
                        && peer.defer_prompt_response(request, &response)?
                    {
                        // The original request remains active until the
                        // session-specific daemon event settles this turn.
                    } else {
                        peer.adapter
                            .write_protocol(&response)
                            .map_err(|error| anyhow!(error))?;
                    }
                }
            }
            Ok(ReaderEvent::Eof) => break,
            Ok(ReaderEvent::Error(error)) => {
                write_diagnostic(&mut stderr, &error);
                return Err(anyhow!(error));
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    if let Some(mut peer) = peer {
        peer.close();
        peer.adapter.disconnect();
    }
    Ok(())
}

enum ReaderEvent {
    Frame(super::codec::AcpFrame),
    Eof,
    Error(super::codec::AcpFrameError),
}

/// #116 owns the typed setting. This temporary reader uses its exact persisted
/// name and default so the merge can replace only this implementation detail.
fn background_agents_setting() -> Result<bool> {
    let cwd = std::env::current_dir().context("resolving ACP current directory")?;
    let mut value = true;
    for path in crate::config::dirs::config_file_paths_for_load(&cwd) {
        let document = crate::config::extended::ExtendedConfigDoc::load(&path)?;
        if let Some(flag) = document
            .raw_field("daemon")
            .and_then(Value::as_object)
            .and_then(|daemon| daemon.get("background_agents"))
            .and_then(Value::as_bool)
        {
            value = flag;
        }
    }
    Ok(value)
}

#[derive(Clone)]
struct Attachment {
    client: DaemonClient,
    capability: CodeRootAttachmentCapabilityV1,
    cursor: cockpit_proto::CodeRootReplayCursorV1,
    rendered_initial: bool,
}

struct PendingPrompt {
    request_id: super::raw_json::JsonRpcId,
}

struct State {
    /// An unattached socket client used only for root discovery and to keep the
    /// daemon lifetime acquired by `initialize` alive. Every ACP root receives
    /// its own attached client below.
    client: DaemonClient,
    background_agents: bool,
    logical_client_id: OpaqueAsciiId128V1,
    attachments: HashMap<String, Attachment>,
    pending_prompts: HashMap<String, PendingPrompt>,
    permission_deliveries: HashMap<
        String,
        (
            DaemonClient,
            CodeRootAttachmentCapabilityV1,
            cockpit_proto::CodeRootReplayCursorV1,
        ),
    >,
}

struct Peer {
    state: Arc<Mutex<State>>,
    handle: Handle,
    adapter: AcpAdapter<AcpLineWriter<io::Stdout>, DaemonResolve, DaemonAck, DaemonIngress>,
}

impl Peer {
    fn new(handle: Handle, client: DaemonClient, background_agents: bool) -> Self {
        let state = Arc::new(Mutex::new(State {
            client,
            background_agents,
            logical_client_id: opaque("client"),
            attachments: HashMap::new(),
            pending_prompts: HashMap::new(),
            permission_deliveries: HashMap::new(),
        }));
        Self {
            adapter: AcpAdapter::new_with_session_ingress(
                AcpLineWriter::new(io::stdout()),
                DaemonResolve::new(handle.clone(), Arc::clone(&state)),
                DaemonAck::new(handle.clone(), Arc::clone(&state)),
                DaemonIngress::new(handle.clone(), Arc::clone(&state)),
            ),
            state,
            handle,
        }
    }

    fn close(&mut self) {
        let attachments: Vec<_> = self
            .state
            .lock()
            .expect("ACP state")
            .attachments
            .values()
            .cloned()
            .collect();
        for attachment in attachments {
            let _ = self.handle.block_on(attachment.client.request_ok(
                Request::CloseAcpCodeRootAttachmentV1(
                    cockpit_proto::CloseAcpCodeRootAttachmentV1Request {
                        attachment_capability: attachment.capability,
                        client_request_id: opaque("close"),
                    },
                ),
            ));
        }
    }

    fn drain_deliveries(&mut self) -> Result<()> {
        let attachments: Vec<_> = self
            .state
            .lock()
            .expect("ACP state")
            .attachments
            .iter()
            .map(|(session_id, attachment)| (session_id.clone(), attachment.clone()))
            .collect();
        for (session_id, attachment) in attachments {
            if !attachment.rendered_initial {
                let response = self.read_attachment(
                    &session_id,
                    &attachment.client,
                    Request::ReadCodeRootV1(ReadCodeRootV1Request {
                        attachment_capability: attachment.capability.clone(),
                    }),
                )?;
                let Response::CodeRootRead(root) = response else {
                    return Err(anyhow!("unexpected ACP Code-root read response"));
                };
                for entry in root.root.history {
                    if let cockpit_proto::HistoryEntry::Assistant {
                        text,
                        presentation_text,
                        ..
                    } = entry
                    {
                        self.emit_assistant(&session_id, presentation_text.unwrap_or(text))?;
                    }
                }
                self.state
                    .lock()
                    .expect("ACP state")
                    .attachments
                    .get_mut(&session_id)
                    .expect("known attachment")
                    .rendered_initial = true;
            }
            let mut cursor = attachment.cursor.clone();
            loop {
                let response = self.read_attachment(
                    &session_id,
                    &attachment.client,
                    Request::ReadCodeRootDeliveriesV1(ReadCodeRootDeliveriesV1Request {
                        attachment_capability: attachment.capability.clone(),
                        after: Some(cursor.clone()),
                        limit: DISCOVERY_PAGE_SIZE,
                    }),
                )?;
                let Response::CodeRootDeliveries(page) = response else {
                    return Err(anyhow!("unexpected ACP Code-root delivery response"));
                };
                let count = page.deliveries.len();
                for delivery in page.deliveries {
                    match delivery.payload {
                        CodeRootDeliveryPayloadV1::History { entry } => {
                            if let cockpit_proto::HistoryEntry::Assistant {
                                text,
                                presentation_text,
                                ..
                            } = entry
                            {
                                self.emit_assistant(
                                    &session_id,
                                    presentation_text.unwrap_or(text),
                                )?;
                            }
                        }
                        CodeRootDeliveryPayloadV1::Attention { entry } => {
                            self.issue_permission(
                                &session_id,
                                &attachment.client,
                                &attachment.capability,
                                delivery.delivery_id.to_string(),
                                entry.decision_request_id.to_string(),
                                entry.attention_id.to_string(),
                                entry.options_contract_json,
                                delivery.cursor.clone(),
                            )?;
                        }
                        CodeRootDeliveryPayloadV1::RootStateChanged => {}
                        CodeRootDeliveryPayloadV1::ClientIncompatible => {
                            return Err(anyhow!("daemon marked an ACP Code root incompatible"));
                        }
                    }
                    cursor = delivery.cursor.clone();
                    self.state
                        .lock()
                        .expect("ACP state")
                        .attachments
                        .get_mut(&session_id)
                        .expect("known attachment")
                        .cursor = delivery.cursor;
                }
                if count < usize::from(DISCOVERY_PAGE_SIZE) {
                    break;
                }
            }
        }
        Ok(())
    }

    /// A failed attachment read means this peer can no longer prove the
    /// attachment is usable. Remove that capability before returning the
    /// delivery failure so a later `session/load` must attach afresh, and so
    /// deferred ACP work follows the same terminal settlement path as a
    /// closed event stream.
    fn read_attachment(
        &mut self,
        session_id: &str,
        client: &DaemonClient,
        request: Request,
    ) -> Result<Response> {
        match self.handle.block_on(client.request_ok(request)) {
            Ok(response) => Ok(response),
            Err(error) => {
                self.terminate_session(session_id)
                    .context("settling failed ACP attachment")?;
                Err(error).context("reading ACP Code-root attachment")
            }
        }
    }

    /// Suppress the optimistic jsonrpsee response only after the daemon has
    /// accepted the prompt. The stored JSON-RPC id is completed from the
    /// session's own event stream, not by a later unrelated stdin frame.
    fn defer_prompt_response(&mut self, request: &InboundRequest, response: &str) -> Result<bool> {
        let value: Value = serde_json::from_str(response).context("decoding prompt response")?;
        if value.get("result").is_none() {
            return Ok(false);
        }
        let raw = request
            .raw_params
            .as_deref()
            .ok_or_else(|| anyhow!("prompt params missing after dispatch"))?;
        let session_id = serde_json::from_str::<Value>(raw)
            .ok()
            .and_then(|params| {
                params
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .ok_or_else(|| anyhow!("prompt session id missing after dispatch"))?;
        self.state
            .lock()
            .expect("ACP state")
            .pending_prompts
            .insert(
                session_id,
                PendingPrompt {
                    request_id: request.id.clone(),
                },
            );
        Ok(true)
    }

    fn drain_turn_events(&mut self) -> Result<()> {
        let attachments: Vec<_> = self
            .state
            .lock()
            .expect("ACP state")
            .attachments
            .iter()
            .map(|(session_id, attachment)| (session_id.clone(), attachment.client.clone()))
            .collect();
        for (session_id, client) in attachments {
            loop {
                let event = self.handle.block_on(async {
                    tokio::time::timeout(Duration::from_millis(0), client.next_event()).await
                });
                let event = match event {
                    Ok(Some(event)) => event,
                    // A closed attachment stream is a daemon-terminal path,
                    // not an idle poll. It must settle this root's deferred
                    // prompt and issued permission request(s).
                    Ok(None) => {
                        self.terminate_session(&session_id)?;
                        break;
                    }
                    Err(_) => break,
                };
                match event {
                    cockpit_proto::Event::AgentIdle {
                        session_id: root_id,
                        reason,
                        ..
                    } if root_id.to_string() == session_id => {
                        self.complete_prompt(&session_id, stop_reason(&reason))?;
                    }
                    cockpit_proto::Event::SessionEnded {
                        session_id: root_id,
                        ..
                    } if root_id.to_string() == session_id => {
                        self.terminate_session(&session_id)?;
                        break;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// A root can terminate without an `AgentIdle` event (for example, from
    /// another attachment or daemon shutdown). Finish its deferred prompt and
    /// cancel only this root's outstanding ACP permissions; other loaded
    /// roots continue to own their requests.
    fn terminate_session(&mut self, session_id: &str) -> Result<()> {
        let capability = {
            let mut state = self.state.lock().expect("ACP state");
            // `attachments` is the live attachment-capability registry, not a
            // record of every root this ACP process has seen. Removing before
            // settling outbound work makes terminal cleanup idempotent and
            // prevents `session/load` from accepting a stale attachment.
            let capability = state
                .attachments
                .remove(session_id)
                .map(|attachment| attachment.capability);
            if let Some(capability) = &capability {
                state
                    .permission_deliveries
                    .retain(|_, (_, delivery_capability, _)| delivery_capability != capability);
            }
            capability
        };
        if let Some(capability) = capability {
            self.adapter.registry.on_daemon_terminal_for_attachment(
                Some(capability.expose_opaque()),
                &mut self.adapter.sink,
                &mut self.adapter.counters,
            );
        }
        // ACP v1 has no session-ended stop reason. This is a terminal daemon
        // failure for an outstanding prompt, rather than a completed turn.
        self.complete_prompt(session_id, "refusal")
    }

    fn complete_prompt(&mut self, session_id: &str, stop_reason: &str) -> Result<()> {
        let pending = self
            .state
            .lock()
            .expect("ACP state")
            .pending_prompts
            .remove(session_id);
        let Some(pending) = pending else {
            return Ok(());
        };
        self.adapter
            .write_protocol(&success_response(
                &pending.request_id,
                json!({ "stopReason": stop_reason }),
            ))
            .map_err(|error| anyhow!(error))
    }

    fn emit_assistant(&mut self, session_id: &str, text: String) -> Result<()> {
        let frame = notification(
            "session/update",
            json!({
                "sessionId": session_id,
                "update": {
                    "sessionUpdate": "agent_message_chunk",
                    "content": { "type": "text", "text": text }
                }
            }),
        );
        self.adapter
            .write_protocol(&frame)
            .map_err(|error| anyhow!(error))
    }

    fn issue_permission(
        &mut self,
        session_id: &str,
        client: &DaemonClient,
        capability: &CodeRootAttachmentCapabilityV1,
        delivery_id: String,
        tool_call_id: String,
        attention_id: String,
        options_contract: String,
        cursor: cockpit_proto::CodeRootReplayCursorV1,
    ) -> Result<()> {
        let options = match permission_options(&options_contract) {
            Ok(options) => options,
            Err(error) => {
                // ACP v1's permission response carries only one option id. A
                // multi-select or free-text QuestionTool cannot be forged as
                // a scalar choice; cancel the exact root rather than emit an
                // unanswerable empty request or leave its turn parked.
                self.emit_assistant(
                    session_id,
                    format!("Cockpit cannot represent this QuestionTool over ACP v1: {error}"),
                )?;
                self.handle
                    .block_on(client.request_ok(Request::CancelTurn))
                    .context("cancelling an ACP-unrepresentable QuestionTool")?;
                return Ok(());
            }
        };
        let option_refs: Vec<_> = options.iter().map(String::as_str).collect();
        let params = super::registry::permission_params(session_id, &option_refs, &tool_call_id);
        self.state
            .lock()
            .expect("ACP state")
            .permission_deliveries
            .insert(
                delivery_id.clone(),
                (client.clone(), capability.clone(), cursor),
            );
        self.adapter
            .registry
            .issue_and_write(
                capability.expose_opaque().to_string(),
                delivery_id,
                attention_id,
                options,
                params,
                &mut self.adapter.sink,
                &mut self.adapter.counters,
            )
            .map_err(|error| anyhow!(error))
    }
}

struct DaemonIngress {
    handle: Handle,
    state: Arc<Mutex<State>>,
}

impl DaemonIngress {
    fn new(handle: Handle, state: Arc<Mutex<State>>) -> Self {
        Self { handle, state }
    }

    fn call(&self, request: Request) -> Result<Response> {
        let client = self.state.lock().expect("ACP state").client.clone();
        self.handle.block_on(client.request_ok(request))
    }

    fn options(&self) -> CodeRootAttachOptionsV1 {
        let version = self
            .state
            .lock()
            .expect("ACP state")
            .client
            .negotiated()
            .version;
        CodeRootAttachOptionsV1 {
            initial_model: None,
            model_override: None,
            no_sandbox: false,
            interactive: true,
            client_protocol_version: version,
            env_snapshot: None,
            env_policy: cockpit_proto::EnvDriftPolicy::default(),
        }
    }

    /// `workspace` is the optional ACP `cwd` filter. Its absence must remain
    /// absent through the daemon request so an editor can discover all roots.
    fn discover(&self, workspace: Option<&str>) -> Result<Vec<cockpit_proto::CodeRootSummaryV1>> {
        let logical_client_id = self
            .state
            .lock()
            .expect("ACP state")
            .logical_client_id
            .clone();
        let mut roots = Vec::new();
        let mut cursor = None;
        loop {
            let response = self.call(Request::DiscoverCodeRootsV1(DiscoverCodeRootsV1Request {
                workspace_selector: workspace.map(|path| CodeRootWorkspaceSelectorV1 {
                    path: path.to_string(),
                }),
                logical_client_id: logical_client_id.clone(),
                cursor,
                limit: DISCOVERY_PAGE_SIZE,
            }))?;
            let Response::CodeRootsDiscovered(page) = response else {
                return Err(anyhow!("unexpected Code-root discovery response"));
            };
            roots.extend(page.roots);
            let Some(next) = page.next_cursor else { break };
            cursor = Some(next);
        }
        Ok(roots)
    }

    fn attachment_client(&self) -> Result<DaemonClient> {
        let background_agents = self.state.lock().expect("ACP state").background_agents;
        self.handle
            .block_on(super::acquire_ledger_owner(background_agents))
            .context("opening an independent ACP Code-root attachment")
    }

    fn install(&self, attachment: cockpit_proto::CodeRootAttachmentV1, client: DaemonClient) {
        self.state.lock().expect("ACP state").attachments.insert(
            attachment.root_id.0.to_string(),
            Attachment {
                client,
                capability: attachment.attachment_capability,
                cursor: attachment.replay_cursor,
                rendered_initial: false,
            },
        );
    }
}

impl SessionIngress for DaemonIngress {
    fn is_available(&self) -> bool {
        true
    }

    fn admit(
        &mut self,
        admission: SessionAdmissionDto,
        counters: &mut AcpTransportCounters,
    ) -> Result<Value, SessionIngressError> {
        let ingress = BridgeFacade
            .to_ingress(&admission)
            .map_err(|_| SessionIngressError::InvalidAdmission)?;
        counters.bridge_conversions += 1;
        let client = self
            .attachment_client()
            .map_err(|_| SessionIngressError::Unavailable)?;
        let attachment = match admission {
            SessionAdmissionDto::New(SessionNewDto { cwd, .. }) => {
                let logical_client_id = self
                    .state
                    .lock()
                    .expect("ACP state")
                    .logical_client_id
                    .clone();
                let response = self
                    .handle
                    .block_on(client.request_ok(Request::CreateCodeRootWithAcpIngressV1(
                        CreateCodeRootWithAcpIngressV1Request {
                            base: CreateCodeRootV1Request {
                                workspace_selector: CodeRootWorkspaceSelectorV1 {
                                    path: cwd.clone(),
                                },
                                logical_client_id,
                                client_request_id: opaque("new"),
                                options: self.options(),
                            },
                            ingress,
                        },
                    )))
                    .map_err(|_| SessionIngressError::Unavailable)?;
                let Response::CodeRootWithAcpIngressCreated(result) = response else {
                    return Err(SessionIngressError::Unavailable);
                };
                result.base.attachment
            }
            SessionAdmissionDto::Load(SessionLoadDto {
                cwd, session_id, ..
            }) => {
                if self
                    .state
                    .lock()
                    .expect("ACP state")
                    .attachments
                    .contains_key(&session_id)
                {
                    return Ok(json!({ "sessionId": session_id }));
                }
                let root_id = Uuid::parse_str(&session_id)
                    .map_err(|_| SessionIngressError::InvalidAdmission)?;
                let root = self
                    .discover(Some(&cwd))
                    .map_err(|_| SessionIngressError::Unavailable)?
                    .into_iter()
                    .find(|summary| summary.root_id == CodeRootIdV1(root_id))
                    .ok_or(SessionIngressError::InvalidAdmission)?;
                let logical_client_id = self
                    .state
                    .lock()
                    .expect("ACP state")
                    .logical_client_id
                    .clone();
                let response = self
                    .handle
                    .block_on(
                        client.request_ok(Request::AttachExistingCodeRootWithAcpIngressV1(
                            AttachExistingCodeRootWithAcpIngressV1Request {
                                base: AttachExistingCodeRootV1Request {
                                    root_id: root.root_id,
                                    capture_generation: root.capture_generation,
                                    logical_client_id,
                                    client_request_id: opaque("load"),
                                    replay_cursor: None,
                                    since_seq: None,
                                    options: self.options(),
                                },
                                ingress,
                            },
                        )),
                    )
                    .map_err(|_| SessionIngressError::Unavailable)?;
                let Response::CodeRootWithAcpIngressAttached(result) = response else {
                    return Err(SessionIngressError::Unavailable);
                };
                result.base.attachment
            }
        };
        let session_id = attachment.root_id.0.to_string();
        self.install(attachment, client);
        counters.daemon_mutations += 1;
        Ok(json!({ "sessionId": session_id }))
    }

    fn list(
        &mut self,
        raw: &str,
        _counters: &mut AcpTransportCounters,
    ) -> Result<Value, SessionIngressError> {
        let params: Value =
            serde_json::from_str(raw).map_err(|_| SessionIngressError::InvalidAdmission)?;
        let params = params
            .as_object()
            .ok_or(SessionIngressError::InvalidAdmission)?;
        let cwd = match params.get("cwd") {
            Some(Value::String(cwd)) => Some(cwd.as_str()),
            Some(_) => return Err(SessionIngressError::InvalidAdmission),
            None => None,
        };
        let sessions = self
            .discover(cwd)
            .map_err(|_| SessionIngressError::Unavailable)?;
        Ok(json!({ "sessions": sessions.into_iter().map(|root| json!({
            "sessionId": root.root_id.0.to_string(),
            "cwd": root.workspace_path,
            "title": root.title,
        })).collect::<Vec<_>>() }))
    }

    fn cancel(
        &mut self,
        raw: &str,
        counters: &mut AcpTransportCounters,
    ) -> Result<Value, SessionIngressError> {
        let session_id = serde_json::from_str::<Value>(raw)
            .ok()
            .and_then(|params| {
                params
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .ok_or(SessionIngressError::InvalidAdmission)?;
        let client = self
            .state
            .lock()
            .expect("ACP state")
            .attachments
            .get(&session_id)
            .map(|attachment| attachment.client.clone())
            .ok_or(SessionIngressError::InvalidAdmission)?;
        self.handle
            .block_on(client.request_ok(Request::CancelTurn))
            .map_err(|_| SessionIngressError::Unavailable)?;
        counters.daemon_mutations += 1;
        Ok(Value::Null)
    }

    fn prompt(
        &mut self,
        raw: &str,
        counters: &mut AcpTransportCounters,
    ) -> Result<Value, SessionIngressError> {
        let params: Value =
            serde_json::from_str(raw).map_err(|_| SessionIngressError::InvalidAdmission)?;
        let session_id = params
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or(SessionIngressError::InvalidAdmission)?;
        let client = self
            .state
            .lock()
            .expect("ACP state")
            .attachments
            .get(session_id)
            .map(|attachment| attachment.client.clone())
            .ok_or(SessionIngressError::InvalidAdmission)?;
        if self
            .state
            .lock()
            .expect("ACP state")
            .pending_prompts
            .contains_key(session_id)
        {
            return Err(SessionIngressError::InvalidAdmission);
        }
        let text = params
            .get("prompt")
            .and_then(Value::as_array)
            .ok_or(SessionIngressError::InvalidAdmission)?
            .iter()
            .map(|block| match block.get("type").and_then(Value::as_str) {
                Some("text") => block.get("text").and_then(Value::as_str).map(str::to_owned),
                Some("resource_link") => {
                    let name = block.get("name").and_then(Value::as_str)?;
                    let uri = block.get("uri").and_then(Value::as_str)?;
                    Some(format!("Referenced resource: {name} ({uri})"))
                }
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(SessionIngressError::InvalidAdmission)?
            .join("\n");
        let message =
            cockpit_proto::send_user_message_v2::SendUserMessageV2::text_only(Uuid::now_v7(), text);
        self.handle
            .block_on(client.request_ok(Request::SendUserMessageV2 {
                ingress: cockpit_proto::send_user_message_v2::MessageIngressV2::local_direct(
                    Uuid::now_v7(),
                    session_id,
                    None,
                    None,
                    None,
                    message,
                ),
            }))
            .map_err(|_| SessionIngressError::Unavailable)?;
        counters.daemon_mutations += 1;
        Ok(json!({ "stopReason": "end_turn" }))
    }
}

struct DaemonResolve {
    handle: Handle,
    state: Arc<Mutex<State>>,
}
impl DaemonResolve {
    fn new(handle: Handle, state: Arc<Mutex<State>>) -> Self {
        Self { handle, state }
    }
}
impl ResolveCodeRootInterrupt for DaemonResolve {
    fn resolve(
        &mut self,
        request: cockpit_proto::ResolveCodeRootInterruptV1,
    ) -> cockpit_proto::ResolveCodeRootInterruptResultV1 {
        let client = self
            .state
            .lock()
            .expect("ACP state")
            .attachments
            .values()
            .find(|attachment| attachment.capability == request.attachment_capability)
            .map(|attachment| attachment.client.clone());
        let Some(client) = client else {
            return cockpit_proto::ResolveCodeRootInterruptResultV1::Cancelled;
        };
        match self
            .handle
            .block_on(client.request_ok(Request::ResolveCodeRootInterruptV1(request)))
        {
            Ok(Response::CodeRootInterruptResolved(result)) => result,
            _ => cockpit_proto::ResolveCodeRootInterruptResultV1::Cancelled,
        }
    }
}

struct DaemonAck {
    handle: Handle,
    state: Arc<Mutex<State>>,
}
impl DaemonAck {
    fn new(handle: Handle, state: Arc<Mutex<State>>) -> Self {
        Self { handle, state }
    }
}
impl ApprovalAck for DaemonAck {
    fn ack_approval_delivery(&mut self, delivery_id: &str) {
        let receipt = {
            let mut state = self.state.lock().expect("ACP state");
            let receipt = state.permission_deliveries.remove(delivery_id);
            receipt
        };
        let Some((client, capability, through)) = receipt else {
            return;
        };
        let _ = self
            .handle
            .block_on(client.request_ok(Request::AckCodeRootDeliveriesV1(
                AckCodeRootDeliveriesV1Request {
                    attachment_capability: capability,
                    through,
                    client_request_id: opaque("permission-ack"),
                },
            )));
    }
}

fn opaque(kind: &str) -> OpaqueAsciiId128V1 {
    OpaqueAsciiId128V1::new(format!("acp-{kind}-{}", Uuid::new_v4()))
        .expect("generated ACP id is bounded ASCII")
}

fn stop_reason(reason: &cockpit_proto::IdleReason) -> &'static str {
    match reason {
        cockpit_proto::IdleReason::Completed | cockpit_proto::IdleReason::GoalComplete => {
            "end_turn"
        }
        cockpit_proto::IdleReason::BudgetLimited | cockpit_proto::IdleReason::UsageLimited => {
            "max_turn_requests"
        }
        cockpit_proto::IdleReason::NeedsIntervention { .. }
        | cockpit_proto::IdleReason::Error { .. } => "refusal",
        cockpit_proto::IdleReason::Interrupted => "cancelled",
    }
}

fn permission_options(contract: &str) -> Result<Vec<String>> {
    let parsed: Value =
        serde_json::from_str(contract).context("parsing Code-root decision options")?;
    let options = parsed
        .get("options")
        .and_then(Value::as_array)
        .or_else(|| parsed.as_array())
        .cloned()
        .unwrap_or_default();
    if !options.is_empty() {
        return options.iter().map(permission_option_id).collect();
    }
    let questions = parsed
        .get("interrupt_response_contract")
        .and_then(|contract| contract.get("questions"))
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("Code-root decision options are not an array"))?;
    // ACP v1 permission outcomes name exactly one offered option. A linked
    // QuestionTool can therefore be projected only when its durable contract
    // is one single-select question with real choices. Do not emit an empty
    // request for forms ACP cannot represent.
    if questions.len() != 1 {
        return Err(anyhow!(
            "ACP cannot represent a multi-question continuation"
        ));
    }
    if questions[0].get("kind").and_then(Value::as_str) != Some("single") {
        return Err(anyhow!(
            "ACP cannot represent a multi-select or free-text continuation"
        ));
    }
    let option_ids = questions[0]
        .get("option_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("QuestionTool continuation has no ACP choices"))?;
    if option_ids.is_empty() {
        return Err(anyhow!(
            "ACP cannot represent a free-text-only continuation"
        ));
    }
    option_ids
        .iter()
        .map(|option| {
            option
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("QuestionTool option id is invalid"))
        })
        .collect()
}

fn permission_option_id(option: &Value) -> Result<String> {
    option
        .get("id")
        .or_else(|| option.get("option_id"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("Code-root decision option has no id"))
}

#[cfg(test)]
mod tests {
    use cockpit_client::InProcessConnection;

    use super::*;

    fn closed_client() -> DaemonClient {
        let (requests, request_receiver) = tokio::sync::mpsc::channel(1);
        drop(request_receiver);
        let (event_sender, events) = tokio::sync::mpsc::channel(1);
        drop(event_sender);
        DaemonClient::from_in_process(InProcessConnection { requests, events })
    }

    fn attachment() -> Attachment {
        Attachment {
            client: closed_client(),
            capability: CodeRootAttachmentCapabilityV1::from_daemon_random(Uuid::new_v4()),
            cursor: cockpit_proto::CodeRootReplayCursorV1::from_daemon_random(Uuid::new_v4()),
            rendered_initial: false,
        }
    }

    fn peer() -> (tokio::runtime::Runtime, Peer) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("test runtime");
        let peer = Peer::new(runtime.handle().clone(), closed_client(), true);
        (runtime, peer)
    }

    #[test]
    fn terminal_attachment_is_removed_from_the_live_registry() {
        let (_runtime, mut peer) = peer();
        peer.state
            .lock()
            .expect("ACP state")
            .attachments
            .insert("root".to_string(), attachment());

        peer.terminate_session("root").expect("terminal cleanup");

        assert!(
            !peer
                .state
                .lock()
                .expect("ACP state")
                .attachments
                .contains_key("root")
        );
    }

    #[test]
    fn delivery_read_failure_settles_and_unregisters_the_attachment() {
        let (_runtime, mut peer) = peer();
        peer.state
            .lock()
            .expect("ACP state")
            .attachments
            .insert("root".to_string(), attachment());

        let error = peer.drain_deliveries().expect_err("closed attachment read");

        assert!(
            error
                .to_string()
                .contains("reading ACP Code-root attachment")
        );
        assert!(
            !peer
                .state
                .lock()
                .expect("ACP state")
                .attachments
                .contains_key("root")
        );
    }
}
