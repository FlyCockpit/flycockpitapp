//! Compact tools for persisted session goals.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::db::session_goals::{GoalStatus, GoalUpdateOutcome};
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};

pub struct CreateGoalTool;
pub struct GetGoalTool;
pub struct UpdateGoalTool;

#[async_trait]
impl Tool for CreateGoalTool {
    fn name(&self) -> &str {
        "create_goal"
    }

    fn description(&self) -> &str {
        "Persist one session goal after clarification"
    }

    fn defensive_description(&self) -> Option<String> {
        Some("Create the session goal only after the user accepts the clarified objective/context; fails when another open goal exists.".to_string())
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "objective": { "type": "string", "description": "Short completion-checkable objective" },
                "context": { "type": "string", "description": "Settled findings, constraints, acceptance criteria" },
                "token_budget": { "type": "integer", "description": "Positive token budget" }
            },
            "required": ["objective"]
        })
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let objective = required_str(&args, "objective")?;
        let context = args.get("context").and_then(Value::as_str);
        let token_budget = args.get("token_budget").and_then(Value::as_i64);
        let goal = ctx.session.db.create_session_goal(
            ctx.session.id,
            &ctx.session.project_id,
            objective,
            context,
            token_budget,
        )?;
        Ok(ToolOutput::text(format!(
            "Created goal `{}` [{}]: {}",
            goal.id,
            goal.status.as_str(),
            goal.objective
        )))
    }
}

#[async_trait]
impl Tool for GetGoalTool {
    fn name(&self) -> &str {
        "get_goal"
    }

    fn description(&self) -> &str {
        "Read current goal status and budget"
    }

    fn defensive_description(&self) -> Option<String> {
        Some("Read the current goal before terminal updates; include_context only when detailed settled context is needed.".to_string())
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "include_context": { "type": "boolean", "description": "Include long context" }
            }
        })
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        ctx.session.db.refresh_session_goal_usage(ctx.session.id)?;
        let include_context = args
            .get("include_context")
            .and_then(Value::as_bool)
            .unwrap_or(false);
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
}

#[async_trait]
impl Tool for UpdateGoalTool {
    fn name(&self) -> &str {
        "update_goal"
    }

    fn description(&self) -> &str {
        "Update goal status or append context"
    }

    fn defensive_description(&self) -> Option<String> {
        Some("Set complete only after get_goal plus evidence; set blocked only after repeated true blockers; context_delta appends without erasing settled context.".to_string())
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "status": { "type": "string", "description": "Goal status", "enum": ["active", "paused", "blocked", "complete", "budget_limited", "usage_limited"] },
                "evidence": { "type": "string", "description": "Evidence for complete" },
                "blocker": { "type": "string", "description": "Blocker for blocked" },
                "context_delta": { "type": "string", "description": "Append-only context update" }
            },
            "required": ["status"]
        })
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let status = match required_str(&args, "status")? {
            "active" => GoalStatus::Active,
            "paused" => GoalStatus::Paused,
            "blocked" => GoalStatus::Blocked,
            "complete" => GoalStatus::Complete,
            "budget_limited" => GoalStatus::BudgetLimited,
            "usage_limited" => GoalStatus::UsageLimited,
            other => return Err(invalid_input(format!("invalid goal status `{other}`"))),
        };
        match ctx.session.db.update_session_goal(
            ctx.session.id,
            status,
            args.get("evidence").and_then(Value::as_str),
            args.get("blocker").and_then(Value::as_str),
            args.get("context_delta").and_then(Value::as_str),
        )? {
            GoalUpdateOutcome::Updated(goal) => Ok(ToolOutput::text(format!(
                "Goal `{}` status is now `{}`.",
                goal.id,
                goal.status.as_str()
            ))),
            GoalUpdateOutcome::BlockAttempt { attempts, required } => {
                Ok(ToolOutput::text(format!(
                    "Blocked not accepted yet ({attempts}/{required}). Keep working if possible, or call update_goal(status=\"blocked\") again only after the same blocker still prevents progress."
                )))
            }
        }
    }
}

fn required_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid_input(format!("`{key}` is required")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tool::Tool;

    #[tokio::test]
    async fn get_goal_reports_none_after_completion() {
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

        let out = GetGoalTool.call(serde_json::json!({}), &ctx).await.unwrap();

        assert_eq!(out.content, "No goal for this session.");
    }
}
