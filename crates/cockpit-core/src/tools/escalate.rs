//! Explicit sandbox escalation tool.

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

use crate::config::extended::ApprovalMode;
use crate::engine::safety_gate::{SafetyOutcome, evaluate};
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input, typed_args};
use crate::tools::shell_sandbox::SandboxPathAccess;

const MAX_SUGGESTED_PATHS: usize = 8;

pub struct EscalateTool;

#[derive(Debug, Deserialize)]
struct EscalateArgs {
    call_id: String,
    #[serde(default)]
    suggested_paths: Vec<String>,
    #[serde(default)]
    access: EscalateAccess,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum EscalateAccess {
    Read,
    #[default]
    ReadWrite,
}

impl From<EscalateAccess> for SandboxPathAccess {
    fn from(value: EscalateAccess) -> Self {
        match value {
            EscalateAccess::Read => Self::Read,
            EscalateAccess::ReadWrite => Self::ReadWrite,
        }
    }
}

#[async_trait]
impl Tool for EscalateTool {
    fn name(&self) -> &str {
        "escalate"
    }

    fn description(&self) -> &str {
        "Re-run a sandbox-failed bash call after approval; prefer suggested_paths so future commands keep working inside the sandbox, and escalate without paths only when a durable grant would not help."
    }

    fn defensive_description(&self) -> Option<String> {
        Some("Use only with the call_id of a prior failed bash call from this session that failed while sandboxed or because the sandbox could not start; optionally include suggested_paths so the user can grant path access and retry inside the sandbox.".to_string())
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "call_id": { "type": "string", "description": "Prior bash tool call id" },
                "suggested_paths": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Optional file or directory paths the sandbox likely blocked; relative paths resolve against the failed call cwd",
                    "maxItems": MAX_SUGGESTED_PATHS
                },
                "access": {
                    "type": "string",
                    "enum": ["read", "read-write"],
                    "description": "Access needed for every suggested path; defaults to read-write"
                }
            },
            "required": ["call_id"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "call_id": { "type": "string", "description": "The exact call_id of a previous bash tool call in this session that failed under shell confinement or returned the sandbox-unavailable refusal" },
                "suggested_paths": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Optional file or directory paths the sandbox likely blocked; relative paths resolve against the failed call cwd",
                    "maxItems": MAX_SUGGESTED_PATHS
                },
                "access": {
                    "type": "string",
                    "enum": ["read", "read-write"],
                    "description": "Access needed for every suggested path; defaults to read-write"
                }
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

        let command_cwd = failed_call_cwd(&row.wire_input_json, &ctx.cwd);
        let grant_offer =
            validate_grant_offer(args.suggested_paths, args.access.into(), &command_cwd)?;
        match approval_for_escalation(ctx, command, &row, grant_offer.as_ref()).await? {
            EscalationApproval::Deny => Ok(ToolOutput::text(
                "Escalation denied by user or policy; the command was not rerun.",
            )),
            EscalationApproval::NoninteractiveDeny => {
                Ok(ToolOutput::text(crate::approval::NONINTERACTIVE_RUN_DENIAL))
            }
            EscalationApproval::RunUnconfinedOnce => {
                crate::tools::bash::rerun_escalated_bash(row.wire_input_json.clone(), ctx, None)
                    .await
            }
            EscalationApproval::GrantAndRetryConfined => {
                crate::tools::bash::rerun_escalated_bash_confined(row.wire_input_json.clone(), ctx)
                    .await
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscalationApproval {
    GrantAndRetryConfined,
    RunUnconfinedOnce,
    Deny,
    NoninteractiveDeny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EscalationRoute {
    RunUnconfinedOnce,
    PromptHuman,
}

pub(crate) fn escalation_route(
    mode: ApprovalMode,
    safety_outcome: Option<SafetyOutcome>,
) -> EscalationRoute {
    match mode {
        ApprovalMode::Yolo => EscalationRoute::RunUnconfinedOnce,
        ApprovalMode::Manual => EscalationRoute::PromptHuman,
        ApprovalMode::Auto => match safety_outcome {
            Some(SafetyOutcome::Rated(verdict)) if verdict.safe => {
                EscalationRoute::RunUnconfinedOnce
            }
            Some(SafetyOutcome::Rated(_)) | Some(SafetyOutcome::Unavailable) | None => {
                EscalationRoute::PromptHuman
            }
        },
    }
}

fn failed_call_cwd(wire_input_json: &Value, session_cwd: &Path) -> PathBuf {
    wire_input_json
        .get("cwd")
        .and_then(Value::as_str)
        .map(|cwd| crate::tools::common::resolve(cwd, session_cwd))
        .unwrap_or_else(|| session_cwd.to_path_buf())
}

fn validate_grant_offer(
    suggested_paths: Vec<String>,
    access: SandboxPathAccess,
    command_cwd: &Path,
) -> Result<Option<crate::approval::SandboxEscalationGrantOffer>> {
    let mut paths = Vec::new();
    for raw in suggested_paths {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if paths.len() >= MAX_SUGGESTED_PATHS {
            return Err(invalid_input(format!(
                "`suggested_paths` accepts at most {MAX_SUGGESTED_PATHS} non-empty paths"
            )));
        }
        let path = crate::tools::common::resolve(raw, command_cwd);
        if !paths.iter().any(|existing| existing == &path) {
            paths.push(path);
        }
    }
    Ok((!paths.is_empty())
        .then_some(crate::approval::SandboxEscalationGrantOffer { paths, access }))
}

async fn approval_for_escalation(
    ctx: &ToolCtx,
    command: &str,
    row: &crate::db::tool_calls::ToolCallEvent,
    grant_offer: Option<&crate::approval::SandboxEscalationGrantOffer>,
) -> Result<EscalationApproval> {
    match ctx.session.approval_mode() {
        ApprovalMode::Yolo => Ok(EscalationApproval::RunUnconfinedOnce),
        ApprovalMode::Manual => prompt_user(ctx, command, row, grant_offer).await,
        ApprovalMode::Auto => {
            let (extended, providers) = ctx.config.configs();
            let outcome = evaluate(
                extended.guard_model_ref(),
                &providers,
                ctx.redact.clone(),
                ctx.session.trusted_only_flag(),
                None,
                "bash",
                command,
            )
            .await;
            match escalation_route(ApprovalMode::Auto, Some(outcome)) {
                EscalationRoute::RunUnconfinedOnce => Ok(EscalationApproval::RunUnconfinedOnce),
                EscalationRoute::PromptHuman => prompt_user(ctx, command, row, grant_offer).await,
            }
        }
    }
}

async fn prompt_user(
    ctx: &ToolCtx,
    command: &str,
    row: &crate::db::tool_calls::ToolCallEvent,
    grant_offer: Option<&crate::approval::SandboxEscalationGrantOffer>,
) -> Result<EscalationApproval> {
    let Some(approver) = ctx.approver.as_ref() else {
        return Ok(EscalationApproval::Deny);
    };
    let confined_exit = row.exit_code.unwrap_or(1);
    let confined_detail = if let Some(reason) = &row.sandbox_unavailable_reason {
        format!("sandbox unavailable: {reason}")
    } else {
        row.output.clone()
    };
    match approver
        .approve_sandbox_escalation(command, confined_exit, confined_detail, grant_offer, None)
        .await?
    {
        crate::approval::SandboxEscalationApproval::GrantAndRetryConfined { .. } => {
            Ok(EscalationApproval::GrantAndRetryConfined)
        }
        crate::approval::SandboxEscalationApproval::RunUnconfinedOnce => {
            Ok(EscalationApproval::RunUnconfinedOnce)
        }
        crate::approval::SandboxEscalationApproval::Deny => Ok(EscalationApproval::Deny),
        crate::approval::SandboxEscalationApproval::NoninteractiveDeny => {
            Ok(EscalationApproval::NoninteractiveDeny)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tool::Tool;
    use crate::session::{ToolCallProviderIdentity, ToolCallRow};
    use chrono::Utc;
    use serde_json::json;
    use std::sync::Arc;
    use uuid::Uuid;

    fn record_bash_call(ctx: &ToolCtx, call_id: &str, exit_code: Option<i32>) {
        ctx.session
            .record_tool_call(ToolCallRow {
                event_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                agent: "builder".to_string(),
                call_id: call_id.to_string(),
                parent_call_id: None,
                parent_child_index: None,
                identity: ToolCallProviderIdentity::default(),
                tool: "bash".to_string(),
                path: None,
                mcp_server: None,
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

    fn ctx_with_approver(
        root: &std::path::Path,
    ) -> (
        ToolCtx,
        Arc<crate::approval::Approver>,
        crate::db::Db,
        uuid::Uuid,
        Arc<crate::engine::interrupt::InterruptHub>,
    ) {
        let mut ctx = crate::tools::common::test_ctx(root);
        let db = ctx.session.db.clone();
        let hub = Arc::new(crate::engine::interrupt::InterruptHub::detached());
        let session_id = ctx.session.id;
        let store = crate::approval::store::GrantStore::new(
            db.clone(),
            session_id,
            root.to_path_buf(),
            ctx.config.clone(),
        );
        let approver = Arc::new(crate::approval::Approver::new(
            store,
            db.clone(),
            session_id,
            "builder",
            hub.clone(),
        ));
        ctx.approver = Some(approver.clone());
        (ctx, approver, db, session_id, hub)
    }

    fn resolve_next_interrupt(
        db: crate::db::Db,
        session_id: uuid::Uuid,
        hub: Arc<crate::engine::interrupt::InterruptHub>,
        selected_id: &'static str,
    ) -> tokio::task::JoinHandle<()> {
        let initial: Vec<uuid::Uuid> = db
            .list_open_interrupts(session_id)
            .unwrap()
            .into_iter()
            .map(|row| row.interrupt_id)
            .collect();
        tokio::spawn(async move {
            loop {
                let open = db.list_open_interrupts(session_id).unwrap();
                if let Some(row) = open.iter().find(|row| !initial.contains(&row.interrupt_id))
                    && hub.resolve(
                        row.interrupt_id,
                        crate::daemon::proto::ResolveResponse::Single {
                            selected_id: selected_id.to_string(),
                        },
                    )
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
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
    async fn approval_routing_respects_manual_auto_and_yolo_grant_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let (ctx, approver, db, session_id, hub) = ctx_with_approver(tmp.path());
        ctx.session.set_sandbox_escalation_enabled(true);
        record_bash_call(&ctx, "call-route", Some(1));
        let row = ctx
            .session
            .db
            .get_tool_call_by_call_id(ctx.session.id, "call-route")
            .unwrap()
            .expect("stored row");
        let offer = crate::approval::SandboxEscalationGrantOffer {
            paths: vec![tmp.path().join("cache")],
            access: SandboxPathAccess::ReadWrite,
        };

        ctx.session
            .set_approval_mode(crate::config::extended::ApprovalMode::Yolo);
        assert_eq!(
            approval_for_escalation(&ctx, "printf escalated", &row, Some(&offer))
                .await
                .unwrap(),
            EscalationApproval::RunUnconfinedOnce
        );
        assert!(
            !approver
                .store()
                .is_path_granted_for(&offer.paths[0], SandboxPathAccess::ReadWrite),
            "yolo must not record grants"
        );

        ctx.session
            .set_approval_mode(crate::config::extended::ApprovalMode::Manual);
        let resolver = resolve_next_interrupt(
            db.clone(),
            session_id,
            hub.clone(),
            crate::approval::ID_ESCALATE_GRANT_SESSION,
        );
        assert_eq!(
            approval_for_escalation(&ctx, "printf escalated", &row, Some(&offer))
                .await
                .unwrap(),
            EscalationApproval::GrantAndRetryConfined
        );
        resolver.await.unwrap();
        assert!(
            approver
                .store()
                .is_path_granted_for(&offer.paths[0], SandboxPathAccess::ReadWrite),
            "manual human grant records path"
        );

        let safe = SafetyOutcome::Rated(crate::engine::safety_gate::SafetyVerdict {
            safe: true,
            recheck_result: false,
        });
        let unsafe_outcome = SafetyOutcome::Rated(crate::engine::safety_gate::SafetyVerdict {
            safe: false,
            recheck_result: false,
        });
        assert_eq!(
            escalation_route(crate::config::extended::ApprovalMode::Auto, Some(safe)),
            EscalationRoute::RunUnconfinedOnce
        );
        assert_eq!(
            escalation_route(
                crate::config::extended::ApprovalMode::Auto,
                Some(unsafe_outcome)
            ),
            EscalationRoute::PromptHuman
        );
        assert_eq!(
            escalation_route(
                crate::config::extended::ApprovalMode::Auto,
                Some(SafetyOutcome::Unavailable)
            ),
            EscalationRoute::PromptHuman
        );
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

    #[test]
    fn suggested_paths_resolve_against_failed_call_cwd_and_are_capped() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("subdir");
        let offer = validate_grant_offer(
            vec![" cache ".to_string(), "".to_string(), "cache".to_string()],
            SandboxPathAccess::ReadWrite,
            &cwd,
        )
        .unwrap()
        .expect("non-empty offer");
        assert_eq!(offer.paths, vec![cwd.join("cache")]);

        let too_many = (0..=MAX_SUGGESTED_PATHS)
            .map(|idx| format!("p{idx}"))
            .collect();
        let err = validate_grant_offer(too_many, SandboxPathAccess::Read, &cwd).unwrap_err();
        assert!(format!("{err}").contains("at most"));
    }

    #[test]
    fn base_description_carries_suggested_paths_guidance() {
        let tool = EscalateTool;
        let normal = crate::engine::tool::definition_of(
            &tool,
            crate::config::extended::LlmMode::Normal,
            None,
        );
        let frontier = crate::engine::tool::definition_of(
            &tool,
            crate::config::extended::LlmMode::Frontier,
            None,
        );
        assert!(normal.description.contains("prefer suggested_paths"));
        assert_eq!(normal.description, frontier.description);
    }
}
