//! Daemon-backed ACP stdio peer for Cockpit Code roots.
//!
//! The editor owns only this stdio connection. Root lifetime, prompt dispatch,
//! replay, and permissions remain behind the daemon's capability-checked Code
//! root routes, so ACP never becomes an editor execution authority.

use std::collections::HashMap;
use std::io::{self};
use std::sync::{Arc, Mutex};

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
use super::classify::{InboundMessage, classify};
use super::codec::{AcpLineReader, AcpLineWriter, FrameSink, write_diagnostic};
use super::dispatch::{SessionIngress, SessionIngressError};
use super::dto::{SessionAdmissionDto, SessionLoadDto, SessionNewDto};
use super::envelope::invalid_request;
use super::envelope::notification;
use super::registry::{ApprovalAck, ResolveCodeRootInterrupt};

const DISCOVERY_PAGE_SIZE: u16 = 100;

/// Wait for `initialize` before acquiring the shared socket owner. This is
/// important: a malformed or abandoned editor launch must not create a daemon.
pub async fn run() -> Result<()> {
    let handle = Handle::current();
    tokio::task::block_in_place(|| run_blocking(&handle))
}

fn run_blocking(handle: &Handle) -> Result<()> {
    let mut reader = AcpLineReader::new(io::stdin());
    let mut stderr = io::stderr();
    let mut peer: Option<Peer> = None;

    loop {
        let mut counters = AcpTransportCounters::default();
        let frame = match reader.read_frame(&mut counters) {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(error) => {
                write_diagnostic(&mut stderr, &error);
                return Err(anyhow!(error));
            }
        };
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
            let client = handle
                .block_on(super::acquire_ledger_owner(background_agents_setting()?))
                .context("acquiring the socket daemon for ACP")?;
            peer = Some(Peer::new(handle.clone(), client));
        }
        let peer = peer.as_mut().expect("initialized ACP peer");
        if let Some(response) = peer.adapter.handle_frame(&frame.json) {
            peer.adapter
                .write_protocol(&response)
                .map_err(|error| anyhow!(error))?;
        }
        peer.drain_deliveries()?;
        if peer.adapter.connection_closed || peer.adapter.registry.connection_closed() {
            break;
        }
    }
    if let Some(mut peer) = peer {
        peer.close();
        peer.adapter.disconnect();
    }
    Ok(())
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
    capability: CodeRootAttachmentCapabilityV1,
    cursor: cockpit_proto::CodeRootReplayCursorV1,
    rendered_initial: bool,
}

struct State {
    client: DaemonClient,
    logical_client_id: OpaqueAsciiId128V1,
    attachments: HashMap<String, Attachment>,
    permission_deliveries: HashMap<
        String,
        (
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
    fn new(handle: Handle, client: DaemonClient) -> Self {
        let state = Arc::new(Mutex::new(State {
            client,
            logical_client_id: opaque("client"),
            attachments: HashMap::new(),
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
            let client = self.state.lock().expect("ACP state").client.clone();
            let _ = self
                .handle
                .block_on(client.request_ok(Request::CloseAcpCodeRootAttachmentV1(
                    cockpit_proto::CloseAcpCodeRootAttachmentV1Request {
                        attachment_capability: attachment.capability,
                        client_request_id: opaque("close"),
                    },
                )));
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
            let client = self.state.lock().expect("ACP state").client.clone();
            if !attachment.rendered_initial {
                let response = self
                    .handle
                    .block_on(client.request_ok(Request::ReadCodeRootV1(
                        ReadCodeRootV1Request {
                            attachment_capability: attachment.capability.clone(),
                        },
                    )))?;
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
            let client = self.state.lock().expect("ACP state").client.clone();
            let response =
                self.handle
                    .block_on(client.request_ok(Request::ReadCodeRootDeliveriesV1(
                        ReadCodeRootDeliveriesV1Request {
                            attachment_capability: attachment.capability.clone(),
                            after: Some(attachment.cursor),
                            limit: DISCOVERY_PAGE_SIZE,
                        },
                    )))?;
            let Response::CodeRootDeliveries(page) = response else {
                return Err(anyhow!("unexpected ACP Code-root delivery response"));
            };
            for delivery in page.deliveries {
                match delivery.payload {
                    CodeRootDeliveryPayloadV1::History { entry } => {
                        if let cockpit_proto::HistoryEntry::Assistant {
                            text,
                            presentation_text,
                            ..
                        } = entry
                        {
                            self.emit_assistant(&session_id, presentation_text.unwrap_or(text))?;
                        }
                    }
                    CodeRootDeliveryPayloadV1::Attention { entry } => {
                        self.issue_permission(
                            &session_id,
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
                self.state
                    .lock()
                    .expect("ACP state")
                    .attachments
                    .get_mut(&session_id)
                    .expect("known attachment")
                    .cursor = delivery.cursor;
            }
        }
        Ok(())
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
        capability: &CodeRootAttachmentCapabilityV1,
        delivery_id: String,
        tool_call_id: String,
        attention_id: String,
        options_contract: String,
        cursor: cockpit_proto::CodeRootReplayCursorV1,
    ) -> Result<()> {
        let options = permission_options(&options_contract)?;
        let option_refs: Vec<_> = options.iter().map(String::as_str).collect();
        let params = super::registry::permission_params(session_id, &option_refs, &tool_call_id);
        self.state
            .lock()
            .expect("ACP state")
            .permission_deliveries
            .insert(delivery_id.clone(), (capability.clone(), cursor));
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

    fn discover(&self, workspace: &str) -> Result<Vec<cockpit_proto::CodeRootSummaryV1>> {
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
                workspace_selector: CodeRootWorkspaceSelectorV1 {
                    path: workspace.to_string(),
                },
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

    fn install(&self, attachment: cockpit_proto::CodeRootAttachmentV1) {
        self.state.lock().expect("ACP state").attachments.insert(
            attachment.root_id.0.to_string(),
            Attachment {
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
        let attachment = match admission {
            SessionAdmissionDto::New(SessionNewDto { cwd, .. }) => {
                let logical_client_id = self
                    .state
                    .lock()
                    .expect("ACP state")
                    .logical_client_id
                    .clone();
                let response = self
                    .call(Request::CreateCodeRootWithAcpIngressV1(
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
                    ))
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
                    .discover(&cwd)
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
                    .call(Request::AttachExistingCodeRootWithAcpIngressV1(
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
                    ))
                    .map_err(|_| SessionIngressError::Unavailable)?;
                let Response::CodeRootWithAcpIngressAttached(result) = response else {
                    return Err(SessionIngressError::Unavailable);
                };
                result.base.attachment
            }
        };
        let session_id = attachment.root_id.0.to_string();
        self.install(attachment);
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
        let cwd = match params.get("cwd").and_then(Value::as_str) {
            Some(cwd) => cwd.to_string(),
            None => std::env::current_dir()
                .map_err(|_| SessionIngressError::Unavailable)?
                .display()
                .to_string(),
        };
        let sessions = self
            .discover(&cwd)
            .map_err(|_| SessionIngressError::Unavailable)?;
        Ok(json!({ "sessions": sessions.into_iter().map(|root| json!({
            "sessionId": root.root_id.0.to_string(),
            "cwd": root.workspace_path,
            "title": root.title,
        })).collect::<Vec<_>>() }))
    }

    fn cancel(
        &mut self,
        _raw: &str,
        counters: &mut AcpTransportCounters,
    ) -> Result<Value, SessionIngressError> {
        self.call(Request::CancelTurn)
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
        if !self
            .state
            .lock()
            .expect("ACP state")
            .attachments
            .contains_key(session_id)
        {
            return Err(SessionIngressError::InvalidAdmission);
        }
        let text = params
            .get("prompt")
            .and_then(Value::as_array)
            .ok_or(SessionIngressError::InvalidAdmission)?
            .iter()
            .map(|block| {
                block
                    .get("text")
                    .and_then(Value::as_str)
                    .filter(|_| block.get("type").and_then(Value::as_str) == Some("text"))
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(SessionIngressError::InvalidAdmission)?
            .join("\n");
        let message =
            cockpit_proto::send_user_message_v2::SendUserMessageV2::text_only(Uuid::now_v7(), text);
        self.call(Request::SendUserMessageV2 {
            ingress: cockpit_proto::send_user_message_v2::MessageIngressV2::local_direct(
                Uuid::now_v7(),
                session_id,
                None,
                None,
                None,
                message,
            ),
        })
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
        let client = self.state.lock().expect("ACP state").client.clone();
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
        let (client, receipt) = {
            let mut state = self.state.lock().expect("ACP state");
            let receipt = state.permission_deliveries.remove(delivery_id);
            (state.client.clone(), receipt)
        };
        let Some((capability, through)) = receipt else {
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

fn permission_options(contract: &str) -> Result<Vec<String>> {
    let parsed: Value =
        serde_json::from_str(contract).context("parsing Code-root decision options")?;
    let options = parsed
        .get("options")
        .and_then(Value::as_array)
        .or_else(|| parsed.as_array())
        .ok_or_else(|| anyhow!("Code-root decision options are not an array"))?;
    options
        .iter()
        .map(|option| {
            option
                .get("id")
                .or_else(|| option.get("option_id"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| anyhow!("Code-root decision option has no id"))
        })
        .collect()
}
