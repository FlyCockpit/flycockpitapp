//! `return` — a delegated subagent's structured finish tool.
//!
//! Structural, like `done`/`handoff`/`task`: the engine intercepts it by name
//! in [`crate::engine::agent::turn`] and routes the model-authored fields to
//! the driver, which assembles the structured summary envelope the caller
//! ingests as this delegation's tool result (see
//! [`crate::engine::envelope`]). Every delegated subagent
//! (`builder`/`explore` + custom subagents) holds it from session
//! start, so the prompt cache is never busted. The `files_changed` slot is
//! **host-authored** — derived deterministically from the child's own
//! write/edit ledger, never the model — so it is not a parameter here. The
//! trait impl exists only to advertise the schema; calling it directly is a
//! loud error.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput};

pub struct ReturnTool;

#[async_trait]
impl Tool for ReturnTool {
    fn name(&self) -> &str {
        "return"
    }

    fn description(&self) -> &str {
        "Finish and report a structured summary to your caller: what you did, decisions, context for its next step, and follow-ups."
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Finish your delegation by reporting a structured summary to the agent that called you \
             — this is how you return, so call it once your task is complete. Fill each field: \
             `accomplished` (what you actually did), `decisions_made` (decisions you took so the \
             caller does not re-litigate them), `context_for_next` (anything the caller needs to \
             guide its next step), and `remaining` (what you deliberately did NOT do / follow-ups). \
             Do not list the files you changed — the harness records those for you."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "accomplished": { "type": "string", "description": "What you did" },
                "decisions_made": { "type": "string", "description": "Decisions taken" },
                "context_for_next": { "type": "string", "description": "What the caller needs for its next step" },
                "remaining": { "type": "string", "description": "Deliberately-not-done / follow-ups" }
            },
            "required": ["accomplished"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "accomplished": { "type": "string", "description": "What you actually did" },
                "decisions_made": { "type": "string", "description": "Decisions you took while doing it" },
                "context_for_next": { "type": "string", "description": "Anything the caller needs to guide its next step" },
                "remaining": { "type": "string", "description": "What you deliberately did not do, or follow-ups" }
            },
            "required": ["accomplished"]
        }))
    }

    async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        Err(anyhow::anyhow!(
            "`return` is intercepted by the engine dispatcher; this code path should be unreachable"
        ))
    }
}
