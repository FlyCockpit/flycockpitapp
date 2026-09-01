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
    quarantined: HashMap<String, QuarantinedOutput>,
    terminal: Option<AcquisitionTerminalMove>,
    command_started: bool,
}

struct QuarantinedOutput {
    value: Zeroizing<String>,
    truncated: bool,
}

#[derive(Clone)]
pub(crate) struct AcquisitionRuntime {
    allowed_sealed_record_ids: Arc<BTreeSet<String>>,
    child_approval_mode: crate::config::extended::ApprovalMode,
    command: Option<Arc<str>>,
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
            command: None,
            state: Arc::new(Mutex::new(AcquisitionRuntimeState::default())),
        }
    }

    pub(crate) fn with_untrusted_command(mut self, command: String) -> Self {
        self.command = Some(Arc::from(command));
        self
    }

    pub(crate) fn terminal(&self) -> Option<AcquisitionTerminalMove> {
        self.state.lock().unwrap().terminal.clone()
    }

    /// Spend the one command-execution permit for this acquisition before
    /// entering bash. The permit is intentionally not restored when bash
    /// errors: command execution may have already started or had side effects.
    fn take_untrusted_command(&self) -> Result<Arc<str>> {
        let command = self
            .command
            .clone()
            .ok_or_else(|| invalid_input("host acquisition command is unavailable"))?;
        let mut state = self.state.lock().unwrap();
        if state.command_started {
            return Err(invalid_input(
                "the host acquisition command has already been started",
            ));
        }
        state.command_started = true;
        Ok(command)
    }

    pub(crate) fn take_quarantined(&self, source_tool_call_id: &str) -> Option<Zeroizing<String>> {
        self.state
            .lock()
            .unwrap()
            .quarantined
            .remove(source_tool_call_id)
            .filter(|output| !output.truncated)
            .map(|output| output.value)
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

/// Tokio task-locals are not inherited by `tokio::spawn`. Every scheduler lane
/// enters through this wrapper, preserving the exact acquisition capability
/// when one is active while leaving ordinary non-acquisition turns unchanged.
pub(crate) async fn with_inherited_acquisition_runtime<F>(future: F) -> F::Output
where
    F: std::future::Future,
{
    match CURRENT_ACQUISITION_RUNTIME.try_with(Clone::clone) {
        Ok(runtime) => CURRENT_ACQUISITION_RUNTIME.scope(runtime, future).await,
        Err(_) => future.await,
    }
}

/// Production-time quarantine. This runs immediately after successful bash
/// dispatch and before hooks, audit rows, artifacts, timeline events, or model
/// history can observe the result. Only the task-local coordinator can later
/// resolve the exact call id; every durable/model lane receives the placeholder.
pub(crate) fn quarantine_bash_result(call_id: &str, tool: &str, output: &mut ToolOutput) -> bool {
    let Ok(runtime) = CURRENT_ACQUISITION_RUNTIME.try_with(|runtime| runtime.clone()) else {
        return false;
    };
    if !matches!(tool, "bash" | "run_acquisition_command") {
        return false;
    }
    let assembled = output
        .display_content
        .take()
        .unwrap_or_else(|| output.content.model_text().to_owned());
    let (stdout, stderr) = crate::engine::bash_hints::split_bash_body(&assembled);
    let raw = if stdout.is_empty() { stderr } else { stdout };
    let raw = raw
        .trim_end_matches(|ch| matches!(ch, '\r' | '\n'))
        .to_owned();
    runtime.state.lock().unwrap().quarantined.insert(
        call_id.to_owned(),
        QuarantinedOutput {
            value: Zeroizing::new(raw),
            // The visible representation is not the command result when bash
            // capped it. Keep that integrity fact in host-only state; a
            // terminal capture then fails closed rather than sealing a head /
            // tail rendering as a credential.
            truncated: output.truncated,
        },
    );
    output.content = CanonicalToolResultContents::text(format!(
        "sensitive command output quarantined by host; capture by source tool-call reference `{call_id}`"
    ));
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
        .try_with(|runtime| runtime.clone())
        .map_err(|_| invalid_input("acquisition capability is not active"))?;
    let mut state = runtime.state.lock().unwrap();
    if state.terminal.is_some() {
        return Err(invalid_input(
            "an acquisition terminal move was already selected",
        ));
    }
    if let AcquisitionTerminalMove::Capture {
        source_tool_call_id,
    } = &move_
        && !state
            .quarantined
            .get(source_tool_call_id)
            .is_some_and(|output| !output.truncated)
    {
        return Err(invalid_input(
            "source_tool_call_id does not name quarantined output from this acquisition",
        ));
    }
    state.terminal = Some(move_);
    Ok(())
}

pub struct CaptureSealedValueTool;

/// Run the one host-supplied command for this acquisition. The child never
/// receives command bytes in its instruction channel or tool arguments.
pub struct RunAcquisitionCommandTool;

#[async_trait]
impl Tool for RunAcquisitionCommandTool {
    fn name(&self) -> &str {
        "run_acquisition_command"
    }
    fn description(&self) -> &str {
        "Run the single host-supplied acquisition command under normal bash sandbox and approval policy"
    }
    fn effect(&self) -> ToolEffect {
        ToolEffect::Dynamic
    }
    fn honors_dispatch_cancel(&self) -> bool {
        // This wrapper awaits `BashTool::call` with the exact dispatch context.
        // Bash observes that child cancellation token and cleans up its process
        // tree before returning, so this outer tool must receive the same
        // bounded dispatcher grace rather than being dropped immediately.
        true
    }
    fn parameters(&self) -> Value {
        serde_json::json!({ "type": "object", "additionalProperties": false })
    }
    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        if args.as_object().is_none_or(|object| !object.is_empty()) {
            return Err(invalid_input("run_acquisition_command takes no arguments"));
        }
        let command = CURRENT_ACQUISITION_RUNTIME
            .try_with(|runtime| runtime.take_untrusted_command())
            .map_err(|_| invalid_input("acquisition capability is not active"))??;
        crate::tools::bash::BashTool::new()
            .call(serde_json::json!({ "command": command.as_ref() }), ctx)
            .await
    }
}

/// Parent-facing request. Dispatch intercepts this tool and supplies the
/// host-only execution context; its body is deliberately unreachable so an
/// MCP/catalog context cannot manufacture that authority from a bare ToolCtx.
pub struct AcquireSealedValueTool;

#[async_trait]
impl Tool for AcquireSealedValueTool {
    fn name(&self) -> &str {
        "acquire_sealed_value"
    }
    fn description(&self) -> &str {
        "Delegate one command to the trusted acquisition child and return only sealed, requires-user, or failed"
    }
    fn effect(&self) -> ToolEffect {
        ToolEffect::Mutating
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "name": { "type": "string" },
                "description": { "type": "string" },
                "command": { "type": "string" }
            },
            "required": ["name", "description", "command"],
            "additionalProperties": false
        })
    }
    async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        Err(invalid_input(
            "acquire_sealed_value is available only from a live parent agent dispatch",
        ))
    }
}

#[async_trait]
impl Tool for CaptureSealedValueTool {
    fn name(&self) -> &str {
        "capture_sealed_value"
    }
    fn description(&self) -> &str {
        "Capture quarantined command output by source tool-call reference"
    }
    fn effect(&self) -> ToolEffect {
        ToolEffect::Mutating
    }
    fn authorizes_own_effects(&self) -> bool {
        true
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": { "source_tool_call_id": { "type": "string" } },
            "required": ["source_tool_call_id"],
            "additionalProperties": false
        })
    }
    async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        let source = args
            .get("source_tool_call_id")
            .and_then(Value::as_str)
            .filter(|source| !source.is_empty())
            .ok_or_else(|| invalid_input("source_tool_call_id is required"))?;
        set_terminal(AcquisitionTerminalMove::Capture {
            source_tool_call_id: source.to_owned(),
        })?;
        Ok(ToolOutput::text("capture accepted"))
    }
}

pub struct AcquisitionRequiresUserTool;

#[async_trait]
impl Tool for AcquisitionRequiresUserTool {
    fn name(&self) -> &str {
        "acquisition_requires_user"
    }
    fn description(&self) -> &str {
        "End acquisition with one bounded owner question"
    }
    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }
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
            _ => {
                return Err(invalid_input(
                    "reason or prompt is not a valid owner question",
                ));
            }
        }
        set_terminal(AcquisitionTerminalMove::RequiresUser {
            reason: reason.to_owned(),
            prompt: prompt.to_owned(),
        })?;
        Ok(ToolOutput::text("owner question accepted"))
    }
}

pub struct AcquisitionFailTool;

#[async_trait]
impl Tool for AcquisitionFailTool {
    fn name(&self) -> &str {
        "acquisition_fail"
    }
    fn description(&self) -> &str {
        "End acquisition without capturing a value"
    }
    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }
    fn parameters(&self) -> Value {
        serde_json::json!({ "type": "object", "additionalProperties": false })
    }
    async fn call(&self, args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        if args.as_object().is_none_or(|object| !object.is_empty()) {
            return Err(invalid_input("acquisition_fail takes no arguments"));
        }
        set_terminal(AcquisitionTerminalMove::Failed)?;
        Ok(ToolOutput::text("acquisition failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-quarantined-acquisition-value-123456";

    #[tokio::test]
    async fn successful_bash_stdout_is_replaced_before_any_consumer_sees_it() {
        let runtime =
            AcquisitionRuntime::new(BTreeSet::new(), crate::config::extended::ApprovalMode::Auto);
        let inspect = runtime.clone();
        with_acquisition_runtime(runtime, async move {
            let mut output = ToolOutput::text(format!(
                "stdout:\n{SECRET}\nstderr:\ndiagnostic without secret\nexit: 0\n"
            ))
            .with_exit_code(0);
            assert!(quarantine_bash_result("call-secret", "bash", &mut output));

            let durable_projection = output.content.model_text();
            assert!(!durable_projection.contains(SECRET));
            assert!(durable_projection.contains("call-secret"));
            assert!(output.display_content.is_none());
            assert!(output.text_artifact_capture.is_none());
            assert!(output.text_artifact_captures.is_empty());
            assert!(output.output_sidecar.is_none());

            let captured = inspect
                .take_quarantined("call-secret")
                .expect("host retains the exact referenced stdout");
            assert_eq!(captured.as_str(), SECRET);
            assert!(inspect.take_quarantined("call-secret").is_none());
        })
        .await;
    }

    #[tokio::test]
    async fn capture_accepts_only_a_quarantined_call_and_is_single_terminal() {
        let runtime = AcquisitionRuntime::new(
            BTreeSet::new(),
            crate::config::extended::ApprovalMode::Manual,
        );
        let inspect = runtime.clone();
        with_acquisition_runtime(runtime, async move {
            assert!(
                set_terminal(AcquisitionTerminalMove::Capture {
                    source_tool_call_id: "missing".to_owned(),
                })
                .is_err()
            );

            let mut output =
                ToolOutput::text(format!("stdout:\n{SECRET}\nexit: 0\n")).with_exit_code(0);
            assert!(quarantine_bash_result("exact", "bash", &mut output));
            set_terminal(AcquisitionTerminalMove::Capture {
                source_tool_call_id: "exact".to_owned(),
            })
            .unwrap();
            assert_eq!(
                inspect.terminal(),
                Some(AcquisitionTerminalMove::Capture {
                    source_tool_call_id: "exact".to_owned(),
                })
            );
            assert!(set_terminal(AcquisitionTerminalMove::Failed).is_err());
        })
        .await;
    }

    #[test]
    fn host_command_execution_permit_is_single_use() {
        let runtime = AcquisitionRuntime::new(
            BTreeSet::new(),
            crate::config::extended::ApprovalMode::Manual,
        )
        .with_untrusted_command("printf secret".to_owned());

        assert_eq!(
            runtime.take_untrusted_command().unwrap().as_ref(),
            "printf secret"
        );
        assert!(runtime.take_untrusted_command().is_err());
    }

    #[tokio::test]
    async fn truncated_bash_output_cannot_be_selected_for_capture() {
        let runtime = AcquisitionRuntime::new(
            BTreeSet::new(),
            crate::config::extended::ApprovalMode::Manual,
        );
        with_acquisition_runtime(runtime, async move {
            let mut output = ToolOutput::text(format!("stdout:\n{SECRET}\nexit: 0\n"));
            output.truncated = true;
            assert!(quarantine_bash_result("truncated", "bash", &mut output));
            assert!(
                set_terminal(AcquisitionTerminalMove::Capture {
                    source_tool_call_id: "truncated".to_owned(),
                })
                .is_err()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn scheduler_spawn_inherits_the_exact_acquisition_custody_boundary() {
        let mut allowed = BTreeSet::new();
        allowed.insert("allowed-record".to_owned());
        let runtime = AcquisitionRuntime::new(allowed, crate::config::extended::ApprovalMode::Auto);
        with_acquisition_runtime(runtime, async {
            let inherited = tokio::spawn(with_inherited_acquisition_runtime(async {
                (
                    acquisition_allows_sealed_reference("allowed-record"),
                    acquisition_allows_sealed_reference("owner-record"),
                    effective_approval_mode(crate::config::extended::ApprovalMode::Auto),
                )
            }))
            .await
            .unwrap();
            assert_eq!(
                inherited,
                (true, false, crate::config::extended::ApprovalMode::Manual)
            );
        })
        .await;
    }

    #[tokio::test]
    async fn nonzero_bash_output_is_quarantined_too() {
        let runtime = AcquisitionRuntime::new(
            BTreeSet::new(),
            crate::config::extended::ApprovalMode::Manual,
        );
        let inspect = runtime.clone();
        with_acquisition_runtime(runtime, async move {
            let mut output =
                ToolOutput::text(format!("stderr:\n{SECRET}\nexit: 7\n")).with_exit_code(7);
            assert!(quarantine_bash_result("failed-call", "bash", &mut output));
            assert!(!output.content.model_text().contains(SECRET));
            assert_eq!(
                inspect.take_quarantined("failed-call").unwrap().as_str(),
                SECRET
            );
        })
        .await;
    }

    #[tokio::test]
    async fn acquisition_description_scope_is_exact_and_empty_by_default() {
        assert!(acquisition_allows_sealed_reference("outside-acquisition"));
        let runtime = AcquisitionRuntime::new(
            BTreeSet::from(["allowed-record".to_owned()]),
            crate::config::extended::ApprovalMode::Yolo,
        );
        with_acquisition_runtime(runtime, async {
            assert!(acquisition_allows_sealed_reference("allowed-record"));
            assert!(!acquisition_allows_sealed_reference("owner-record"));
        })
        .await;
    }
}
