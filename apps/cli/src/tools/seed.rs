//! `seed` — a re-queryable read-only subagent hands a small, directly-relevant
//! read-only result up to its caller (GOALS §3c).
//!
//! The subagent calls `seed({tool, args})` to mark a read-only result
//! (`read` / `grep` / `glob` / intel `search` / other read-only intel tools)
//! that the caller should receive directly. The entry is appended to the
//! frame's [`crate::engine::seed_collector::SeedCollector`]; on the
//! subagent's return the driver re-executes it in the caller's cwd and
//! injects it into the caller's transcript as a native tool-call/result pair,
//! capped under the subagent-report budget (GOALS §10).
//!
//! Read-only only: write/lock/`bash` are rejected at validation. This tool
//! is registered **only** on read-only noninteractive subagents in `normal`
//! mode (the capability is gated, not the description text — see
//! [`crate::engine::tool::Capability`]); the driver re-exec is the hard gate.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::compact::{SeedTool, is_read_only_seed_tool};
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};

pub struct SeedEmitTool;

#[async_trait]
impl Tool for SeedEmitTool {
    fn name(&self) -> &str {
        "seed"
    }

    fn description(&self) -> &str {
        "Hand one directly-relevant read-only result up to your caller; seed nothing that isn't."
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "tool": {
                    "type": "string",
                    "description": "Read-only tool name (read/grep/glob/intel search)"
                },
                "args": {
                    "type": "object",
                    "description": "Args for that tool (file path, line range, query)"
                }
            },
            "required": ["tool", "args"]
        })
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let tool = args
            .get("tool")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_input("`tool` is required and non-empty"))?;
        // Read-only only — never seed a write/lock/bash path into the caller.
        if !is_read_only_seed_tool(tool) {
            return Err(invalid_input(format!(
                "`{tool}` is not a read-only tool; only read-only results may be seeded"
            )));
        }
        let seed_args = args
            .get("args")
            .cloned()
            .filter(Value::is_object)
            .ok_or_else(|| invalid_input("`args` is required and must be an object"))?;

        ctx.seeds.push(SeedTool {
            tool: tool.to_string(),
            args: seed_args,
        });
        let n = ctx.seeds.len();
        Ok(ToolOutput::text(format!(
            "seeded `{tool}` for the caller ({n} queued); continue, and seed only what is directly relevant"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn queues_a_read_only_seed() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(dir.path());
        SeedEmitTool
            .call(
                serde_json::json!({ "tool": "read", "args": { "path": "/a.rs" } }),
                &ctx,
            )
            .await
            .unwrap();
        let drained = ctx.seeds.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].tool, "read");
    }

    #[tokio::test]
    async fn rejects_a_write_tool() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(dir.path());
        let err = SeedEmitTool
            .call(
                serde_json::json!({ "tool": "bash", "args": { "command": "rm -rf /" } }),
                &ctx,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("read-only"), "{err}");
        assert_eq!(ctx.seeds.len(), 0);
    }

    #[tokio::test]
    async fn requires_object_args() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(dir.path());
        let err = SeedEmitTool
            .call(serde_json::json!({ "tool": "read", "args": "/a.rs" }), &ctx)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("args"), "{err}");
    }
}
