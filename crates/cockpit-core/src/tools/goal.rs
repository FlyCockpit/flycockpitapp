//! Compact tool for the persisted session goal.

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::db::session_goals::{GoalStatus, GoalUpdateOutcome};
use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input, typed_args};

pub struct GoalTool;

#[derive(Debug, Deserialize)]
struct GoalArgs {
    action: String,
    objective: Option<String>,
    context: Option<String>,
    token_budget: Option<i64>,
    include_context: Option<bool>,
    status: Option<String>,
    evidence: Option<String>,
    blocker: Option<String>,
    context_delta: Option<String>,
}

#[async_trait]
impl Tool for GoalTool {
    fn name(&self) -> &str {
        "goal"
    }

    fn description(&self) -> &str {
        "Manage the one control-plane session goal, not todo details; the driver reads it for continuation, budget, pause/block/complete state, and the user steers it with /goal"
    }

    fn defensive_description(&self) -> Option<String> {
        Some("Manage the one control-plane objective for this session. The driver reads this goal to decide whether to keep working, how much token budget remains, and when to pause, block, or complete; the user sees and steers it with /goal. Do not use it as a todo list or detail reader; todos are many data-plane work items.".to_string())
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::Dynamic
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "description": "Operation", "enum": ["create", "get", "update"] },
                "objective": { "type": "string", "description": "Short completion-checkable objective for create" },
                "context": { "type": "string", "description": "Settled findings, constraints, acceptance criteria for create" },
                "token_budget": { "type": "integer", "description": "Positive token budget", "minimum": 1 },
                "include_context": { "type": "boolean", "description": "Include long context for get" },
                "status": { "type": "string", "description": "Goal status for update", "enum": ["active", "paused", "blocked", "complete"] },
                "evidence": { "type": "string", "description": "Evidence for complete" },
                "blocker": { "type": "string", "description": "Blocker for blocked" },
                "context_delta": { "type": "string", "description": "Append-only context update" }
            },
            "required": ["action"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "description": "create the session goal, get current goal state, or update goal status/context", "enum": ["create", "get", "update"] },
                "objective": { "type": "string", "description": "Required for create; a short completion-checkable objective" },
                "context": { "type": "string", "description": "Optional settled context for create" },
                "token_budget": { "type": "integer", "description": "Optional positive token budget for create", "minimum": 1 },
                "include_context": { "type": "boolean", "description": "Optional for get; include long settled context only when needed" },
                "status": { "type": "string", "description": "Required for update; model-settable statuses only", "enum": ["active", "paused", "blocked", "complete"] },
                "evidence": { "type": "string", "description": "Required by the database when setting complete" },
                "blocker": { "type": "string", "description": "Required by the database when setting blocked" },
                "context_delta": { "type": "string", "description": "Optional append-only progress/context note for update" }
            },
            "required": ["action"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let args: GoalArgs = typed_args(args)?;
        match args.action.as_str() {
            "create" => handle_create(args, ctx),
            "get" => handle_get(args, ctx),
            "update" => handle_update(args, ctx),
            other => Err(invalid_input(format!(
                "`action` must be create, get, or update (got `{other}`)"
            ))),
        }
    }
}

fn handle_create(args: GoalArgs, ctx: &ToolCtx) -> Result<ToolOutput> {
    let objective = required_opt_str(args.objective.as_deref(), "objective")?;
    let goal = ctx.session.db.create_session_goal(
        ctx.session.id,
        &ctx.session.project_id,
        objective,
        args.context.as_deref(),
        args.token_budget,
    )?;
    Ok(ToolOutput::text(format!(
        "Created goal `{}` [{}]: {}",
        goal.id,
        goal.status.as_str(),
        goal.objective
    )))
}

fn handle_get(args: GoalArgs, ctx: &ToolCtx) -> Result<ToolOutput> {
    ctx.session.db.refresh_session_goal_usage(ctx.session.id)?;
    let include_context = args.include_context.unwrap_or(false);
    let Some(goal) = ctx.session.db.current_session_goal(ctx.session.id, true)? else {
        return Ok(ToolOutput::text("No goal for this session."));
    };
    let elapsed = chrono::Utc::now()
        .timestamp()
        .saturating_sub(goal.created_at);
    let mut out = format!(
        "Goal `{}`\nstatus: {}\nobjective: {}\ntokens_used: {}\ntoken_budget: {}\nelapsed_seconds: {}",
        goal.id,
        goal.status.as_str(),
        goal.objective,
        goal.tokens_used,
        goal.token_budget
            .map(|n| n.to_string())
            .unwrap_or_else(|| "none".to_string()),
        elapsed
    );
    if include_context && let Some(context) = goal.context {
        out.push_str("\ncontext:\n");
        out.push_str(&context);
    }
    Ok(ToolOutput::text(out))
}

fn handle_update(args: GoalArgs, ctx: &ToolCtx) -> Result<ToolOutput> {
    let status = match required_opt_str(args.status.as_deref(), "status")? {
        "active" => GoalStatus::Active,
        "paused" => GoalStatus::Paused,
        "blocked" => GoalStatus::Blocked,
        "complete" => GoalStatus::Complete,
        other => {
            return Err(invalid_input(format!(
                "invalid goal status `{other}`; valid statuses: active, paused, blocked, complete"
            )));
        }
    };
    match ctx.session.db.update_session_goal(
        ctx.session.id,
        status,
        args.evidence.as_deref(),
        args.blocker.as_deref(),
        args.context_delta.as_deref(),
    )? {
        GoalUpdateOutcome::Updated(goal) => Ok(ToolOutput::text(format!(
            "Goal `{}` status is now `{}`.",
            goal.id,
            goal.status.as_str()
        ))),
        GoalUpdateOutcome::BlockAttempt { attempts, required } => Ok(ToolOutput::text(format!(
            "Blocked not accepted yet ({attempts}/{required}). Keep working if possible, or call goal(action=\"update\", status=\"blocked\") again only after the same blocker still prevents progress."
        ))),
    }
}

fn required_opt_str<'a>(value: Option<&'a str>, key: &str) -> Result<&'a str> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid_input(format!("`{key}` is required")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tool::{Tool, ToolFailKind, classify_failure};

    fn enum_values(schema: Value, property: &str) -> Vec<String> {
        schema["properties"][property]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn goal_tool_actions_enum_is_exact() {
        assert_eq!(
            enum_values(GoalTool.parameters(), "action"),
            ["create", "get", "update"]
        );
    }

    #[tokio::test]
    async fn goal_tool_status_enum_excludes_driver_owned_states() {
        assert_eq!(
            enum_values(GoalTool.parameters(), "status"),
            ["active", "paused", "blocked", "complete"]
        );
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let err = GoalTool
            .call(
                serde_json::json!({"action": "update", "status": "budget_limited"}),
                &ctx,
            )
            .await
            .unwrap_err();
        assert_eq!(classify_failure(&err), ToolFailKind::Invocation);
        assert!(err.to_string().contains("valid statuses"));
    }

    #[test]
    fn goal_tool_token_budget_has_minimum() {
        assert_eq!(
            GoalTool.parameters()["properties"]["token_budget"]["minimum"],
            1
        );
        assert_eq!(
            GoalTool.defensive_parameters().unwrap()["properties"]["token_budget"]["minimum"],
            1
        );
    }

    #[test]
    fn goal_tool_has_defensive_parameters() {
        assert!(GoalTool.defensive_parameters().is_some());
    }

    #[test]
    fn goal_tool_description_states_control_plane_role() {
        let description = GoalTool.description().to_ascii_lowercase();
        assert!(description.contains("one"));
        assert!(description.contains("control-plane"));
        assert!(description.contains("driver"));
        assert!(description.contains("continuation"));
        assert!(description.contains("/goal"));
    }

    #[tokio::test]
    async fn goal_get_action_reports_none_after_completion() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.session
            .db
            .create_session_goal(
                ctx.session.id,
                &ctx.session.project_id,
                "ship feature",
                None,
                None,
            )
            .unwrap();
        ctx.session
            .db
            .current_session_goal(ctx.session.id, true)
            .unwrap();
        ctx.session
            .db
            .update_session_goal(
                ctx.session.id,
                GoalStatus::Complete,
                Some("done"),
                None,
                None,
            )
            .unwrap();

        let out = GoalTool
            .call(serde_json::json!({"action": "get"}), &ctx)
            .await
            .unwrap();

        assert_eq!(out.content, "No goal for this session.");
    }
}
