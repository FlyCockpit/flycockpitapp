//! `unlock` — release a held lock without writing.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput, ToolPresentation, path_or_readable_args};
use crate::tools::common::resolve;

pub struct UnlockTool;

#[async_trait]
impl Tool for UnlockTool {
    fn name(&self) -> &str {
        "unlock"
    }

    fn description(&self) -> &str {
        "Release a `readlock` without writing; use `writeunlock` or `editunlock` when you want to save"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Release a lock you took with `readlock` WITHOUT saving any changes — use this when \
             you decided not to edit the file after all, so the lock doesn't stay held. If you \
             DO want to save changes, use `writeunlock` or `editunlock` instead (they release \
             the lock as part of saving); `unlock` discards nothing on disk but throws away the \
             right to write that you were holding."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "Path to unlock" }
            },
            "required": ["path"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "Path to the file whose lock to release, absolute or relative to the session working directory; must be a file you currently hold a lock on" }
            },
            "required": ["path"]
        }))
    }

    fn presentation(&self, args: &Value) -> ToolPresentation {
        let (summary, full_input) = path_or_readable_args(args);
        ToolPresentation::with_parts(Some("🔓"), self.name(), summary, full_input)
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let path_arg = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::engine::tool::invalid_input("`path` is required"))?;
        let path = resolve(path_arg, &ctx.cwd);
        ctx.locks.release(&path, &ctx.agent_id, ctx.session.id)?;
        Ok(ToolOutput::text(format!("unlocked `{}`", path.display())))
    }
}
