//! `raise` — let a persistent assistant thread place a structured item in its
//! assistant's main inbox.
//!
//! This is intentionally not a parent-message shortcut.  The database resolves
//! the main session from the thread lineage and owns the per-assistant loop and
//! rate guard, so a child cannot select another thread as a destination.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::{
    db::assistant_inbox::AssistantInboxDelivery,
    engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input},
};

pub struct RaiseTool;

#[async_trait]
impl Tool for RaiseTool {
    fn name(&self) -> &str {
        "raise"
    }

    fn description(&self) -> &str {
        "Raise a concise structured item from this assistant thread to the main thread inbox. Choose immediate to wake main at its next idle boundary, defer to wait for its next human turn or periodic heartbeat, or notify to alert the human without agent work."
    }

    fn verbose_description(&self) -> Option<String> {
        Some(
            "Use this only when the main thread needs a self-contained update, decision, or escalation from this persistent assistant thread. State the useful result in `summary`; Cockpit records the raising thread/session backlink automatically. `immediate` never interrupts a user turn and is injected only at the next idle turn start. `defer` is visible in the inbox immediately, does not wake main early, and enters agent context at its next human turn or periodic heartbeat. `notify` is for a human alert and does not wake or inject the agent."
                .to_string(),
        )
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::Mutating
    }

    fn honors_dispatch_cancel(&self) -> bool {
        true
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "Self-contained summary for the main thread (maximum 4000 bytes)"
                },
                "delivery": {
                    "type": "string",
                    "enum": ["immediate", "defer", "notify"],
                    "description": "How the main inbox should deliver this item"
                }
            },
            "required": ["summary", "delivery"]
        })
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let summary = args
            .get("summary")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|summary| !summary.is_empty())
            .ok_or_else(|| invalid_input("`summary` is required and non-empty"))?
            .to_string();
        let delivery = match args.get("delivery").and_then(Value::as_str) {
            Some("immediate") => AssistantInboxDelivery::Immediate,
            Some("defer") => AssistantInboxDelivery::Defer,
            Some("notify") => AssistantInboxDelivery::Notify,
            _ => {
                return Err(invalid_input(
                    "`delivery` must be one of `immediate`, `defer`, or `notify`",
                ));
            }
        };
        let operation_scope = ctx
            .current_tool_call_scope
            .clone()
            .ok_or_else(|| anyhow::anyhow!("`raise` requires a daemon-owned tool-call scope"))?;
        let operation_id = ctx
            .current_tool_call_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("`raise` requires a tool-call correlation identity"))?;
        let durable_write = ctx.session.db.raise_assistant_inbox_item(
            ctx.session.id,
            operation_scope,
            operation_id,
            summary,
            delivery,
        );
        tokio::pin!(durable_write);
        let item = tokio::select! {
            biased;
            _ = ctx.cancel.cancelled() => {
                return Ok(ToolOutput::text(
                    "raise was cancelled before its durable outcome was observed; retrying this tool call is idempotent",
                ).with_unknown_host_effect());
            }
            result = &mut durable_write => result?,
        };

        let delivery_text = match delivery {
            AssistantInboxDelivery::Immediate => {
                "queued for the main thread's next idle turn boundary"
            }
            AssistantInboxDelivery::Defer => {
                "visible in the inbox and waiting for the main thread's next human turn or periodic heartbeat"
            }
            AssistantInboxDelivery::Notify => {
                // TODO(remote): publish this durable notify item through the
                // remote human-notification track without waking the agent.
                "recorded in the local human-visible inbox; remote notification is unavailable and was not sent"
            }
        };
        Ok(ToolOutput::text(format!(
            "Raised inbox item {} ({delivery_text}).",
            item.inbox_item_id
        )))
    }
}
