//! Explicit sandbox escalation tool.

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::config::extended::ApprovalMode;
use crate::engine::safety_gate::{SafetyOutcome, evaluate};
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input, typed_args};

pub struct EscalateTool;

#[derive(Debug, Deserialize)]
struct EscalateArgs {
    call_id: String,
}

#[async_trait]
impl Tool for EscalateTool {
    fn name(&self) -> &str {
        "escalate"
    }

    fn description(&self) -> &str {
        "Re-run a sandbox-failed bash call outside the sandbox"
    }

    fn defensive_description(&self) -> Option<String> {
        Some("Use only with the call_id of a prior failed bash call from this session that failed while sandboxed or because the sandbox could not start; reruns the exact stored command outside the sandbox after approval.".to_string())
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "call_id": { "type": "string", "description": "Prior bash tool call id" }
            },
            "required": ["call_id"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "call_id": { "type": "string", "description": "The exact call_id of a previous bash tool call in this session that failed under shell confinement or returned the sandbox-unavailable refusal" }
            },
            "required": ["call_id"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        if !ctx.session.sandbox_escalation_enabled() {
            return Err(invalid_input(
                "sandbox escalation is disabled for this session; ask the user to enable `/sandbox-escalate allow` before using `escalate`",
            ));
        }

        let args: EscalateArgs = typed_args(args)?;
        let call_id = args.call_id.trim();
        if call_id.is_empty() {
            return Err(invalid_input("`call_id` must not be empty"));
        }

        let Some(row) = ctx
            .session
            .db
            .get_tool_call_by_call_id(ctx.session.id, call_id)?
        else {
            return Err(invalid_input(format!(
                "unknown tool call id `{call_id}` in this session"
            )));
        };
        if row.tool != "bash" {
            return Err(invalid_input(format!(
                "tool call `{call_id}` used `{}`; only prior bash calls can be escalated",
                row.tool
            )));
        }

        let command = row
            .wire_input_json
            .get("command")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                invalid_input(format!(
                    "bash call `{call_id}` has no usable stored command to rerun"
                ))
            })?;

        let failed = row.hard_fail
            || row.sandbox_unavailable_reason.is_some()
            || row.exit_code.is_some_and(|code| code != 0);
        if !failed {
            return Err(invalid_input(format!(
                "bash call `{call_id}` did not fail; escalation only reruns failed calls"
            )));
        }

        let sandbox_related =
            row.sandboxed || row.sandbox_unavailable_reason.is_some() || !row.sandbox_enabled;
        if !sandbox_related {
            return Err(invalid_input(format!(
                "bash call `{call_id}` did not run confined and was not a sandbox-unavailable refusal"
            )));
        }

        let approval_scope = approval_for_escalation(ctx, command, &row).await?;
        let Some(approval_scope) = approval_scope else {
            return Ok(ToolOutput::text(
                "Escalation denied by user or policy; the command was not rerun outside the sandbox.",
            ));
        };

        crate::tools::bash::rerun_escalated_bash(row.wire_input_json.clone(), ctx, approval_scope)
            .await
    }
}

async fn approval_for_escalation(
    ctx: &ToolCtx,
    command: &str,
    row: &crate::db::tool_calls::ToolCallEvent,
) -> Result<Option<Option<String>>> {
    match ctx.session.approval_mode() {
        ApprovalMode::Yolo => Ok(Some(None)),
        ApprovalMode::Manual => prompt_user(ctx, command, row).await,
        ApprovalMode::Auto => {
            let (extended, providers) = crate::auto_title::load_configs_for(&ctx.cwd);
            match evaluate(
                extended.guard_model_ref(),
                &providers,
                ctx.redact.clone(),
                ctx.session.trusted_only_flag(),
                "bash",
                command,
            )
            .await
            {
                SafetyOutcome::Rated(verdict) if verdict.safe => Ok(Some(None)),
                SafetyOutcome::Rated(_) | SafetyOutcome::Unavailable => {
                    prompt_user(ctx, command, row).await
                }
            }
        }
    }
}

async fn prompt_user(
    ctx: &ToolCtx,
    command: &str,
    row: &crate::db::tool_calls::ToolCallEvent,
) -> Result<Option<Option<String>>> {
    let Some(approver) = ctx.approver.as_ref() else {
        return Ok(None);
    };
    let confined_exit = row.exit_code.unwrap_or(1);
    let confined_detail = if let Some(reason) = &row.sandbox_unavailable_reason {
        format!("sandbox unavailable: {reason}")
    } else {
        row.output.clone()
    };
    match approver
        .approve_command_escalated(command, confined_exit, confined_detail)
        .await?
    {
        crate::approval::Decision::Allow { scope } => Ok(Some(Some(scope.as_str().to_string()))),
        crate::approval::Decision::Deny => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tool::Tool;
    use crate::session::{ToolCallProviderIdentity, ToolCallRow};
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    fn record_bash_call(ctx: &ToolCtx, call_id: &str, exit_code: Option<i32>) {
        ctx.session
            .record_tool_call(ToolCallRow {
                event_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                agent: "builder".to_string(),
                call_id: call_id.to_string(),
                identity: ToolCallProviderIdentity::default(),
                tool: "bash".to_string(),
                path: None,
                original_input_json: json!({ "command": "printf escalated" }),
                wire_input_json: json!({ "command": "printf escalated" }),
                recovery: crate::db::tool_calls::Recovery::Clean,
                hard_fail: false,
                exit_code,
                sandbox_enabled: true,
                sandboxed: true,
                sandbox_unavailable_reason: None,
                output: "stderr:\nblocked\nexit: 1".to_string(),
                truncated: false,
                duration_ms: 1,
                llm_mode: crate::config::extended::LlmMode::Normal,
                shape_fingerprint: None,
                hint: None,
            })
            .unwrap();
    }

    #[tokio::test]
    async fn disabled_flag_rejects_stale_escalate_call() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.session.set_sandbox_escalation_enabled(false);
        let err = EscalateTool
            .call(json!({ "call_id": "missing" }), &ctx)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("sandbox escalation is disabled"));
    }

    #[tokio::test]
    async fn yolo_reruns_failed_sandboxed_bash_unconfined() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.session
            .set_approval_mode(crate::config::extended::ApprovalMode::Yolo);
        ctx.session.set_sandbox_enabled(true);
        ctx.session.set_sandbox_escalation_enabled(true);
        record_bash_call(&ctx, "call-esc-1", Some(1));

        let out = EscalateTool
            .call(json!({ "call_id": "call-esc-1" }), &ctx)
            .await
            .unwrap();
        assert!(out.content.contains("escalated"), "{}", out.content);
        let sandbox = out.sandbox.expect("bash rerun carries sandbox metadata");
        assert!(sandbox.escalated);
        assert!(!sandbox.confined);
    }

    #[test]
    fn lookup_round_trips_typed_sandbox_failure_columns() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        record_bash_call(&ctx, "call-lookup", Some(13));

        let row = ctx
            .session
            .db
            .get_tool_call_by_call_id(ctx.session.id, "call-lookup")
            .unwrap()
            .expect("stored row");
        assert_eq!(row.exit_code, Some(13));
        assert!(row.sandbox_enabled);
        assert!(row.sandboxed);
        assert!(row.sandbox_unavailable_reason.is_none());
    }
}
