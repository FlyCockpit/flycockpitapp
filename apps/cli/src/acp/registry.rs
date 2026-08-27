//! Outbound `session/request_permission` pending-id registry.
//!
//! Closed state:
//! `Reserved -> Issued -> TerminalReserved -> Resolving -> Terminal -> Released`
//! with alternate edges for incomplete output, cancellation, and disconnect.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use cockpit_proto::{ResolveCodeRootInterruptResultV1, ResolveCodeRootInterruptV1};
use serde_json::{Value, json};

use super::AcpTransportCounters;
use super::codec::{FrameSink, WriteOutcome, prepare_outbound_json};
use super::envelope::{cancel_request_notification, request};
use super::raw_json::{JsonRpcId, RawNode};

pub const ACP_OUTBOUND_PERMISSION_MAX_ENTRIES_V1: usize = 64;
pub const ACP_OUTBOUND_PERMISSION_MAX_CHARGED_BYTES_V1: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    OutboundRequestCapacityExhausted,
    AttachmentAlreadyLive,
    ConnectionClosed,
    WriterOverflow,
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutboundRequestCapacityExhausted => {
                f.write_str("outbound_request_capacity_exhausted")
            }
            Self::AttachmentAlreadyLive => {
                f.write_str("one live permission request per attachment")
            }
            Self::ConnectionClosed => f.write_str("ACP connection closed"),
            Self::WriterOverflow => f.write_str("outbound permission frame exceeds cap"),
        }
    }
}

impl std::error::Error for RegistryError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionStateName {
    Reserved,
    Issued,
    TerminalReserved,
    Resolving,
    Terminal,
    Released,
    Cancelling,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PermissionEntry {
    request_id: String,
    attachment: String,
    delivery_id: String,
    attention_id: String,
    issued_options: HashSet<String>,
    frame: String,
    charge: usize,
    state: PermissionStateName,
    selected_choice: Option<String>,
    resolve_request_id: Option<String>,
    daemon_outcome: Option<ResolveCodeRootInterruptResultV1>,
    charge_held: bool,
}

#[derive(Debug)]
struct Inner {
    next_id: u64,
    used_ids: HashSet<String>,
    live_attachments: HashSet<String>,
    entries: HashMap<String, PermissionEntry>,
    charged_entries: usize,
    charged_bytes: usize,
    charge_releases: u64,
    connection_closed: bool,
    writable: bool,
}

impl Inner {
    fn new() -> Self {
        Self {
            next_id: 1,
            used_ids: HashSet::new(),
            live_attachments: HashSet::new(),
            entries: HashMap::new(),
            charged_entries: 0,
            charged_bytes: 0,
            charge_releases: 0,
            connection_closed: false,
            writable: true,
        }
    }

    fn release_by_id(&mut self, request_id: &str) {
        let Some(entry) = self.entries.get_mut(request_id) else {
            return;
        };
        let attachment = entry.attachment.clone();
        let charge = entry.charge;
        let held = entry.charge_held;
        entry.charge_held = false;
        entry.state = PermissionStateName::Released;
        if held {
            self.charged_entries = self.charged_entries.saturating_sub(1);
            self.charged_bytes = self.charged_bytes.saturating_sub(charge);
            self.charge_releases += 1;
        }
        self.live_attachments.remove(&attachment);
    }
}

pub trait ResolveCodeRootInterrupt {
    fn resolve(&mut self, request: ResolveCodeRootInterruptV1) -> ResolveCodeRootInterruptResultV1;
}

pub trait ApprovalAck {
    fn ack_approval_delivery(&mut self, delivery_id: &str);
}

#[derive(Debug, Default)]
pub struct RecordingResolve {
    pub calls: Vec<ResolveCodeRootInterruptV1>,
    pub next: Option<ResolveCodeRootInterruptResultV1>,
}

impl ResolveCodeRootInterrupt for RecordingResolve {
    fn resolve(&mut self, request: ResolveCodeRootInterruptV1) -> ResolveCodeRootInterruptResultV1 {
        self.calls.push(request);
        self.next
            .unwrap_or(ResolveCodeRootInterruptResultV1::Accepted)
    }
}

#[derive(Debug, Default)]
pub struct RecordingAck {
    pub ids: Vec<String>,
}

impl ApprovalAck for RecordingAck {
    fn ack_approval_delivery(&mut self, delivery_id: &str) {
        self.ids.push(delivery_id.to_string());
    }
}

pub struct OutboundPermissionRegistry {
    inner: Mutex<Inner>,
}

impl Default for OutboundPermissionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl OutboundPermissionRegistry {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::new()),
        }
    }

    pub fn charged_entries(&self) -> usize {
        self.inner.lock().expect("registry").charged_entries
    }

    pub fn charged_bytes(&self) -> usize {
        self.inner.lock().expect("registry").charged_bytes
    }

    pub fn charge_releases(&self) -> u64 {
        self.inner.lock().expect("registry").charge_releases
    }

    pub fn daemon_outcome_of(&self, request_id: &str) -> Option<ResolveCodeRootInterruptResultV1> {
        self.inner
            .lock()
            .expect("registry")
            .entries
            .get(request_id)
            .and_then(|entry| entry.daemon_outcome)
    }

    pub fn resolve_request_id_of(&self, request_id: &str) -> Option<String> {
        self.inner
            .lock()
            .expect("registry")
            .entries
            .get(request_id)
            .and_then(|entry| entry.resolve_request_id.clone())
    }

    pub fn state_of(&self, request_id: &str) -> Option<PermissionStateName> {
        self.inner
            .lock()
            .expect("registry")
            .entries
            .get(request_id)
            .map(|entry| entry.state)
    }

    pub fn connection_closed(&self) -> bool {
        self.inner.lock().expect("registry").connection_closed
    }

    /// Allocate, serialize, charge, and bind atomically before any byte is visible.
    pub fn reserve_permission(
        &self,
        attachment: String,
        delivery_id: String,
        attention_id: String,
        issued_options: Vec<String>,
        params: Value,
        counters: &mut AcpTransportCounters,
    ) -> Result<ReservedPermission, RegistryError> {
        let mut inner = self.inner.lock().expect("registry");
        if inner.connection_closed {
            return Err(RegistryError::ConnectionClosed);
        }
        if inner.charged_entries >= ACP_OUTBOUND_PERMISSION_MAX_ENTRIES_V1
            || inner.live_attachments.contains(&attachment)
        {
            let _ = counters;
            if inner.live_attachments.contains(&attachment) {
                return Err(RegistryError::AttachmentAlreadyLive);
            }
            return Err(RegistryError::OutboundRequestCapacityExhausted);
        }
        let request_id = allocate_id(&mut inner);
        let frame = request(&request_id, "session/request_permission", params);
        prepare_outbound_json(&frame).map_err(|_| RegistryError::WriterOverflow)?;
        let charge = frame.len();
        if inner.charged_bytes.saturating_add(charge) > ACP_OUTBOUND_PERMISSION_MAX_CHARGED_BYTES_V1
        {
            return Err(RegistryError::OutboundRequestCapacityExhausted);
        }
        inner.charged_entries += 1;
        inner.charged_bytes += charge;
        inner.live_attachments.insert(attachment.clone());
        let options: HashSet<String> = issued_options.into_iter().collect();
        inner.entries.insert(
            request_id.clone(),
            PermissionEntry {
                request_id: request_id.clone(),
                attachment,
                delivery_id: delivery_id.clone(),
                attention_id,
                issued_options: options,
                frame: frame.clone(),
                charge,
                state: PermissionStateName::Reserved,
                selected_choice: None,
                resolve_request_id: None,
                daemon_outcome: None,
                charge_held: true,
            },
        );
        Ok(ReservedPermission { request_id, frame })
    }

    pub fn complete_write(
        &self,
        request_id: &str,
        outcome: WriteOutcome,
        sink: &mut dyn FrameSink,
        counters: &mut AcpTransportCounters,
    ) -> Result<(), RegistryError> {
        let mut inner = self.inner.lock().expect("registry");
        let state = inner
            .entries
            .get(request_id)
            .map(|entry| entry.state)
            .ok_or(RegistryError::ConnectionClosed)?;
        if state != PermissionStateName::Reserved {
            return Ok(());
        }
        match outcome {
            WriteOutcome::Complete => {
                if let Some(entry) = inner.entries.get_mut(request_id) {
                    entry.state = PermissionStateName::Issued;
                }
                Ok(())
            }
            WriteOutcome::Partial { .. } | WriteOutcome::Failed => {
                inner.connection_closed = true;
                inner.writable = false;
                inner.release_by_id(request_id);
                let _ = sink;
                let _ = counters;
                Err(RegistryError::ConnectionClosed)
            }
        }
    }

    pub fn issue_and_write(
        &self,
        attachment: String,
        delivery_id: String,
        attention_id: String,
        issued_options: Vec<String>,
        params: Value,
        sink: &mut dyn FrameSink,
        counters: &mut AcpTransportCounters,
    ) -> Result<String, RegistryError> {
        let reserved = self.reserve_permission(
            attachment,
            delivery_id,
            attention_id,
            issued_options,
            params,
            counters,
        )?;
        let outcome = match sink.write_json_value(&reserved.frame, counters) {
            Ok(outcome) => outcome,
            Err(_) => WriteOutcome::Failed,
        };
        self.complete_write(&reserved.request_id, outcome, sink, counters)?;
        Ok(reserved.request_id)
    }

    pub fn on_inbound_response(
        &self,
        id: &JsonRpcId,
        result: Option<&RawNode>,
        input: &str,
        resolve: &mut dyn ResolveCodeRootInterrupt,
        ack: &mut dyn ApprovalAck,
        sink: &mut dyn FrameSink,
        counters: &mut AcpTransportCounters,
    ) {
        let JsonRpcId::String(request_id) = id else {
            return;
        };
        let parsed = match result.and_then(|node| parse_permission_outcome(node, input)) {
            Some(parsed) => parsed,
            None => return,
        };
        let resolve_request = {
            let mut inner = self.inner.lock().expect("registry");
            match parsed {
                PermissionOutcome::Cancelled => {
                    let issued = inner
                        .entries
                        .get(request_id)
                        .is_some_and(|entry| entry.state == PermissionStateName::Issued);
                    if issued {
                        inner.release_by_id(request_id);
                    }
                    return;
                }
                PermissionOutcome::Selected(choice) => {
                    let admissible = inner.entries.get(request_id).is_some_and(|entry| {
                        entry.state == PermissionStateName::Issued
                            && entry.issued_options.contains(&choice)
                    });
                    if !admissible {
                        return;
                    }
                    let Some(entry) = inner.entries.get_mut(request_id) else {
                        return;
                    };
                    entry.state = PermissionStateName::TerminalReserved;
                    entry.selected_choice = Some(choice.clone());
                    let resolve_request_id = format!("acp:{request_id}");
                    entry.resolve_request_id = Some(resolve_request_id.clone());
                    Some(ResolveCodeRootInterruptV1 {
                        client_request_id: resolve_request_id,
                        selected_choice: choice,
                    })
                }
            }
        };
        let Some(resolve_request) = resolve_request else {
            return;
        };
        {
            let mut inner = self.inner.lock().expect("registry");
            if let Some(entry) = inner.entries.get_mut(request_id) {
                if entry.state == PermissionStateName::TerminalReserved {
                    entry.state = PermissionStateName::Resolving;
                } else {
                    return;
                }
            } else {
                return;
            }
        }
        counters.resolve_calls += 1;
        let outcome = resolve.resolve(resolve_request);
        let mut inner = self.inner.lock().expect("registry");
        let Some(entry) = inner.entries.get_mut(request_id) else {
            return;
        };
        if entry.state != PermissionStateName::Resolving {
            return;
        }
        entry.daemon_outcome = Some(outcome);
        entry.state = PermissionStateName::Terminal;
        let delivery_id = entry.delivery_id.clone();
        drop(entry);
        match outcome {
            ResolveCodeRootInterruptResultV1::Accepted
            | ResolveCodeRootInterruptResultV1::AlreadyResolvedSame => {
                counters.approval_acks += 1;
                inner.release_by_id(request_id);
                drop(inner);
                ack.ack_approval_delivery(&delivery_id);
            }
            ResolveCodeRootInterruptResultV1::AlreadyResolvedOther
            | ResolveCodeRootInterruptResultV1::Cancelled
            | ResolveCodeRootInterruptResultV1::Expired => {
                inner.release_by_id(request_id);
            }
        }
        let _ = sink;
    }

    pub fn on_disconnect(&self, counters: &mut AcpTransportCounters) {
        let mut inner = self.inner.lock().expect("registry");
        inner.connection_closed = true;
        inner.writable = false;
        let ids: Vec<String> = inner.entries.keys().cloned().collect();
        for id in ids {
            let skip = inner.entries.get(&id).is_some_and(|entry| {
                entry.state == PermissionStateName::Released
                    || entry.state == PermissionStateName::Terminal
            });
            if !skip {
                inner.release_by_id(&id);
            }
        }
        let _ = counters;
    }

    pub fn on_daemon_terminal(
        &self,
        sink: &mut dyn FrameSink,
        counters: &mut AcpTransportCounters,
    ) {
        let mut queued = Vec::new();
        {
            let mut inner = self.inner.lock().expect("registry");
            let ids: Vec<String> = inner.entries.keys().cloned().collect();
            for id in ids {
                let issued = inner
                    .entries
                    .get(&id)
                    .is_some_and(|entry| entry.state == PermissionStateName::Issued);
                if !issued {
                    continue;
                }
                if inner.writable {
                    queued.push(cancel_request_notification(&id));
                    counters.cancel_notifications_queued += 1;
                }
                inner.release_by_id(&id);
            }
        }
        for frame in queued {
            let _ = sink.write_json_value(&frame, counters);
        }
    }

    pub fn on_local_cancel(
        &self,
        request_id: &str,
        sink: &mut dyn FrameSink,
        counters: &mut AcpTransportCounters,
    ) {
        let mut cancel = None;
        {
            let mut inner = self.inner.lock().expect("registry");
            let issued = inner
                .entries
                .get(request_id)
                .is_some_and(|entry| entry.state == PermissionStateName::Issued);
            if !issued {
                return;
            }
            if inner.writable {
                cancel = Some(cancel_request_notification(request_id));
                counters.cancel_notifications_queued += 1;
            }
            inner.release_by_id(request_id);
        }
        if let Some(frame) = cancel {
            let _ = sink.write_json_value(&frame, counters);
        }
    }

    pub fn legal_edge(
        from: PermissionStateName,
        to: PermissionStateName,
        reason: EdgeReason,
    ) -> bool {
        use PermissionStateName::*;
        match (from, to, reason) {
            (Reserved, Issued, EdgeReason::FullWrite) => true,
            (Reserved, Released, EdgeReason::IncompleteOutput) => true,
            (Issued, TerminalReserved, EdgeReason::SelectedResponse) => true,
            (Issued, Cancelling, EdgeReason::DaemonTerminal) => true,
            (Cancelling, Released, EdgeReason::DaemonTerminal) => true,
            (Issued, Released, EdgeReason::Disconnect) => true,
            (TerminalReserved, Released, EdgeReason::Disconnect) => true,
            (Resolving, Released, EdgeReason::Disconnect) => true,
            (TerminalReserved, Resolving, EdgeReason::ResolveStart) => true,
            (Resolving, Terminal, EdgeReason::DaemonOutcome) => true,
            (Terminal, Released, EdgeReason::AckOrClose) => true,
            (Issued, Released, EdgeReason::AcpCancelled) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeReason {
    FullWrite,
    IncompleteOutput,
    SelectedResponse,
    DaemonTerminal,
    Disconnect,
    ResolveStart,
    DaemonOutcome,
    AckOrClose,
    AcpCancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedPermission {
    pub request_id: String,
    pub frame: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PermissionOutcome {
    Selected(String),
    Cancelled,
}

fn allocate_id(inner: &mut Inner) -> String {
    loop {
        let candidate = inner.next_id.to_string();
        inner.next_id += 1;
        if inner.used_ids.insert(candidate.clone()) {
            return candidate;
        }
    }
}

fn parse_permission_outcome(result: &RawNode, input: &str) -> Option<PermissionOutcome> {
    let _ = input;
    let outcome = result.member("outcome")?;
    match outcome.member("outcome").and_then(RawNode::as_str) {
        Some("cancelled") => Some(PermissionOutcome::Cancelled),
        Some("selected") => outcome
            .member("optionId")
            .and_then(RawNode::as_str)
            .map(|id| PermissionOutcome::Selected(id.to_string())),
        _ => None,
    }
}

pub fn permission_params(session_id: &str, options: &[&str], tool_call_id: &str) -> Value {
    json!({
        "sessionId": session_id,
        "options": options.iter().map(|id| json!({
            "optionId": *id,
            "name": *id,
            "kind": "allow_once"
        })).collect::<Vec<_>>(),
        "toolCall": {
            "toolCallId": tool_call_id,
            "title": "permission",
            "kind": "other",
            "status": "pending"
        }
    })
}
