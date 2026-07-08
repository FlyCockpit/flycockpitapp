//! `defer_to_orchestrator` — a subagent records an out-of-scope ask for the
//! parent instead of silently expanding its own work (`plan.md §3d`).
//!
//! General, not Plan-specific: any subagent under a primary may defer.
//! Appends the message to the frame's deferred-log buffer
//! ([`crate::engine::deferred`]) and returns control so the subagent keeps
//! doing its assigned work. On the subagent's return the driver drains the
//! buffer and folds it into the report `{ report, deferred_log }` the parent
//! ingests, which then addresses each item.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};

pub struct DeferTool;

#[async_trait]
impl Tool for DeferTool {
    fn name(&self) -> &str {
        "defer_to_orchestrator"
    }

    fn description(&self) -> &str {
        "Record an out-of-scope request for the orchestrator and keep doing your assigned work."
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Hand a request that is OUTSIDE your assigned subtask back to the orchestrator that \
             delegated to you, without abandoning your own job. Use this when, while doing your \
             narrow task, you notice something that needs doing but isn't yours to do — record it \
             here in one message and keep working on what you were asked to do. The orchestrator \
             collects every deferred note when you finish and decides what to do with it. This \
             does not pause you or ask anyone a question; it just files the note for later."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Out-of-scope ask to hand back to the orchestrator"
                }
            },
            "required": ["message"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "A self-contained description of the out-of-scope work or observation to hand back to the orchestrator; write it so the orchestrator understands it without your context"
                }
            },
            "required": ["message"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let message = args
            .get("message")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_input("`message` is required and non-empty"))?;

        ctx.deferred_log.push(message);
        let n = ctx.deferred_log.len();
        Ok(ToolOutput::text(format!(
            "deferred to the orchestrator ({n} pending); continue your assigned work"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn appends_to_frame_deferred_log() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(dir.path());
        DeferTool
            .call(
                serde_json::json!({ "message": "also rename the module" }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(ctx.deferred_log.drain(), vec!["also rename the module"]);
    }

    #[tokio::test]
    async fn rejects_empty_message() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(dir.path());
        let err = DeferTool
            .call(serde_json::json!({ "message": "   " }), &ctx)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("message"), "{err}");
    }
}
