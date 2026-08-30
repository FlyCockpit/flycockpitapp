//! `thread_start` — create a fresh persistent child thread from a message.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolEffect, ToolOutput, invalid_input};

/// Lets an assistant split a follow-up into its own durable conversation
/// without copying the current transcript into it.
pub struct ThreadStartTool;

#[async_trait]
impl Tool for ThreadStartTool {
    fn name(&self) -> &str {
        "thread_start"
    }

    fn description(&self) -> &str {
        "Start a fresh persistent child thread from a message in this chat"
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::Mutating
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "message_seq": {
                    "type": "integer",
                    "description": "Recorded user or assistant message sequence to use as the thread anchor"
                }
            },
            "required": ["message_seq"]
        })
    }

    async fn call(&self, args: Value, ctx: &crate::engine::tool::ToolCtx) -> Result<ToolOutput> {
        let seq = args
            .get("message_seq")
            .and_then(Value::as_i64)
            .filter(|seq| *seq > 0)
            .ok_or_else(|| invalid_input("`message_seq` must be a positive recorded message sequence"))?;
        let thread = ctx
            .session
            .db
            .create_thread(ctx.session.id, seq.to_string())
            .await?;
        let short_id = thread.short_id.unwrap_or_else(|| thread.session_id.to_string());
        Ok(ToolOutput::text(format!(
            "Started fresh thread {short_id} from message {seq}. Its transcript is empty; the parent/message anchor is retained for navigation and history search."
        )))
    }
}
