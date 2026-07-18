//! `handoff` — the `Auto` front-door agent's primary-swap tool.
//!
//! Structural, like `task`/`schedule`: the engine intercepts it by name in
//! [`crate::engine::agent::turn`] and routes the chosen target to the
//! driver, which performs the swap through the same idle-boundary
//! [`crate::engine::driver::Driver::swap_primary`] machinery `/plan` and
//! `/build` already use. The trait impl exists only to advertise the
//! schema in one place; calling it directly is a loud error.
//!
//! Only `Auto` (the default initial primary) holds this tool. Once it
//! hands off, the chosen primary owns the conversation and `Auto` is no
//! longer in the loop.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput};

/// The primary agents `Auto` may hand the conversation to.
pub const HANDOFF_TARGETS: &[&str] = &["Plan", "Build"];

pub struct HandoffTool;

#[async_trait]
impl Tool for HandoffTool {
    fn name(&self) -> &str {
        "handoff"
    }

    fn description(&self) -> &str {
        "Hand the conversation to a primary agent (`Plan` or `Build`) once the user's intent is clear."
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Hand the whole conversation over to one of the primary agents and step out of the \
             loop. Use `target=\"Plan\"` when the user wants to design or decompose a multi-step \
             change into a plan, and `target=\"Build\"` when the user wants a change made now \
             (fix, implement, edit). Only call this once you can tell which the user wants — if \
             it is still ambiguous, keep talking to the user (or use `question`) instead. After \
             this call the chosen agent owns the conversation and answers the user directly."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "enum": HANDOFF_TARGETS,
                    "description": "Primary agent to hand off to"
                }
            },
            "required": ["target"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "enum": HANDOFF_TARGETS,
                    "description": "Which primary agent to hand the conversation to: `Plan` to author a multi-step plan, or `Build` to make the change now"
                }
            },
            "required": ["target"]
        }))
    }

    async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        Err(anyhow::anyhow!(
            "`handoff` is intercepted by the engine dispatcher; this code path should be unreachable"
        ))
    }
}
