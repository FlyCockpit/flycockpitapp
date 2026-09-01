//! Host-only runtime and terminal tools for the sealed acquisition profile.
//! The task-local runtime is the user-conferred capability: merely declaring
//! the profile in an agent definition never makes these tools operational.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::engine::tool::{
    CanonicalToolResultContents, Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AcquisitionTerminalMove {
    Capture { source_tool_call_id: String },
    RequiresUser { reason: String, prompt: String },
    Failed,
}

#[derive(Default)]
struct AcquisitionRuntimeState {
    quarantined: HashMap<String, Zeroizing<String>>,
    terminal: Option<AcquisitionTerminalMove>,
}

#[derive(Clone)]
pub(crate) struct AcquisitionRuntime {
    allowed_sealed_record_ids: Arc<BTreeSet<String>>,
    child_approval_mode: crate::config::extended::ApprovalMode,
    state: Arc<Mutex<AcquisitionRuntimeState>>,
}

impl AcquisitionRuntime {
    pub(crate) fn new(
        allowed_sealed_record_ids: BTreeSet<String>,
        parent_approval_mode: crate::config::extended::ApprovalMode,
    ) -> Self {
        Self {
            allowed_sealed_record_ids: Arc::new(allowed_sealed_record_ids),
            child_approval_mode: match parent_approval_mode {
                crate::config::extended::ApprovalMode::Yolo => {
                    crate::config::extended::ApprovalMode::Yolo
                }
                crate::config::extended::ApprovalMode::Auto
                | crate::config::extended::ApprovalMode::Manual => {
                    crate::config::extended::ApprovalMode::Manual
                }
            },
            state: Arc::new(Mutex::new(AcquisitionRuntimeState::default())),
        }
    }

    pub(crate) fn terminal(&self) -> Option<AcquisitionTerminalMove> {
        self.state.lock().unwrap().terminal.clone()
    }

    pub(crate) fn take_quarantined(&self, source_tool_call_id: &str) -> Option<Zeroizing<String>> {
        self.state
            .lock()
            .unwrap()
            .quarantined
            .remove(source_tool_call_id)
    }
}

pub(crate) fn effective_approval_mode(
    session_mode: crate::config::extended::ApprovalMode,
) -> crate::config::extended::ApprovalMode {
    CURRENT_ACQUISITION_RUNTIME
        .try_with(|runtime| runtime.child_approval_mode)
        .unwrap_or(session_mode)
}

tokio::task_local! {
    static CURRENT_ACQUISITION_RUNTIME: AcquisitionRuntime;
}

pub(crate) async fn with_acquisition_runtime<F>(runtime: AcquisitionRuntime, future: F) -> F::Output
where
    F: std::future::Future,
{
    CURRENT_ACQUISITION_RUNTIME.scope(runtime, future).await
}

/// Production-time quarantine. This runs immediately after successful bash
/// dispatch and before hooks, audit rows, artifacts, timeline events, or model
/// history can observe the result. Only the task-local coordinator can later
/// resolve the exact call id; every durable/model lane receives the placeholder.
pub(crate) fn quarantine_bash_result(
    call_id: &str,
    tool: &str,
    output: &mut ToolOutput,
) -> bool {
    let Ok(runtime) = CURRENT_ACQUISITION_RUNTIME.try_with(Clone::clone) else {
        return false;
    };
    if tool != "bash" || output.exit_code.is_some_and(|code| code != 0) {
        return false;
    }
    let raw = output
        .display_content
        .take()
        .unwrap_or_else(|| output.content.model_text().to_owned());
    runtime
        .state
        .lock()
        .unwrap()
        .quarantined
        .insert(call_id.to_owned(), Zeroizing::new(raw));
    output.content = CanonicalToolResultContents::text(format!(
        "sensitive command output quarantined by host; capture by source tool-call reference `{call_id}`"
    ));
    output.truncated = false;
    output.text_artifact_capture = None;
    output.text_artifact_captures.clear();
    output.notices.clear();
    output.output_sidecar = None;
    true
}

pub(crate) fn acquisition_allows_sealed_reference(record_id: &str) -> bool {
    CURRENT_ACQUISITION_RUNTIME
        .try_with(|runtime| runtime.allowed_sealed_record_ids.contains(record_id))
        .unwrap_or(true)
}

fn set_terminal(move_: AcquisitionTerminalMove) -> Result<()> {
    let runtime = CURRENT_ACQUISITION_RUNTIME
        .try_with(Clone::clone)
        .map_err(|_| invalid_input("acquisition capability is not active"))?;
    let mut state = runtime.state.lock().unwrap();
    if state.terminal.is_some() {
        return Err(invalid_input("an acquisition terminal move was already selected"));
    }
    if let AcquisitionTerminalMove::Capture {
        source_tool_call_id,
    } = &move_
        && !state.quarantined.contains_key(source_tool_call_id)
    {
        return Err(invalid_input(
            "source_tool_call_id does not name quarantined output from this acquisition",
        ));
    }
    state.terminal = Some(move_);
    Ok(())
}

pub struct CaptureSealedValueTool;

#[async_trait]
impl Tool for CaptureSealedValueTool {
    fn name(&self) -> &str { "capture_sealed_value" }
    fn description(&self) -> &str { "Capture quarantined command output by source tool-call reference" }
    fn effect(&self) -> ToolEffect { ToolEffect::Mutating }
    fn authorizes_own_effects(&self) -> bool { true }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": { "source_tool_call_id": { "type": "string" } },
            "required": ["source_tool_call_id"],
            "additionalProperties": false
        })
    }
    async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        let source = args.get("source_tool_call_id").and_then(Value::as_str)
            .filter(|source| !source.is_empty())
            .ok_or_else(|| invalid_input("source_tool_call_id is required"))?;
        set_terminal(AcquisitionTerminalMove::Capture { source_tool_call_id: source.to_owned() })?;
        Ok(ToolOutput::text("capture accepted"))
    }
}

pub struct AcquisitionRequiresUserTool;

#[async_trait]
impl Tool for AcquisitionRequiresUserTool {
    fn name(&self) -> &str { "acquisition_requires_user" }
    fn description(&self) -> &str { "End acquisition with one bounded owner question" }
    fn effect(&self) -> ToolEffect { ToolEffect::ReadOnly }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "reason": { "type": "string", "enum": ["missing_credential", "interactive_login", "owner_knowledge"] },
                "prompt": { "type": "string", "maxLength": 240 }
            },
            "required": ["reason", "prompt"],
            "additionalProperties": false
        })
    }
    async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        let reason = args.get("reason").and_then(Value::as_str).unwrap_or("");
        let prompt = args.get("prompt").and_then(Value::as_str).unwrap_or("");
        match crate::engine::trusted_child_acquisition::RequiresUser::parse(reason, prompt) {
            crate::engine::trusted_child_acquisition::AcquisitionOutcome::RequiresUser(_) => {}
            _ => return Err(invalid_input("reason or prompt is not a valid owner question")),
        }
        set_terminal(AcquisitionTerminalMove::RequiresUser { reason: reason.to_owned(), prompt: prompt.to_owned() })?;
        Ok(ToolOutput::text("owner question accepted"))
    }
}

pub struct AcquisitionFailTool;

#[async_trait]
impl Tool for AcquisitionFailTool {
    fn name(&self) -> &str { "acquisition_fail" }
    fn description(&self) -> &str { "End acquisition without capturing a value" }
    fn effect(&self) -> ToolEffect { ToolEffect::ReadOnly }
    fn parameters(&self) -> Value { serde_json::json!({ "type": "object", "additionalProperties": false }) }
    async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        if args.as_object().is_none_or(|object| !object.is_empty()) {
            return Err(invalid_input("acquisition_fail takes no arguments"));
        }
        set_terminal(AcquisitionTerminalMove::Failed)?;
        Ok(ToolOutput::text("acquisition failed"))
    }
}
