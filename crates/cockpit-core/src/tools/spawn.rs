//! `spawn` — the recursive `Swarm`/`bee` fan-out tool (GOALS §24).
//!
//! Structural, like `task`/`schedule`: the engine intercepts it by
//! name in [`crate::engine::agent::turn`] and routes the spawn request to
//! the driver's single async-job authority (GOALS §22), which owns the
//! queue, enforces the depth ceiling + global concurrency cap, and
//! schedules the child `bee` worker as a background job. The trait impl
//! exists only to advertise the schema in one place; calling it directly
//! is a loud error.
//!
//! Only the `Swarm` primary and its `bee` worker hold this tool. It is the
//! **sole** documented exception to leaf-termination: these agents may
//! recursively fan out parallel `bee` workers. No other agent gets it, and a
//! `bee` still cannot spawn `Plan`/`Build`/etc.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput};

/// The recursive `Swarm` fan-out tool. Carries the per-task effective
/// depth in its description so the model can self-limit (GOALS §24).
pub struct SpawnTool {
    description: String,
}

impl SpawnTool {
    /// Build the tool, baking the per-task effective depth (`depth` of this
    /// caller) and the ceiling into the description so the model knows how
    /// much recursion budget remains.
    pub fn for_depth(depth: u32, ceiling: u32) -> Self {
        let remaining = ceiling.saturating_sub(depth);
        // One noun-phrase-dense sentence (token economy §10). `write_scope` is
        // an authority transfer, not an output suggestion: the guidance that it
        // must be a dedicated strict subtree lives in the description text.
        let description = format!(
            "Fan out to a parallel `bee` worker (depth {depth} of ceiling {ceiling}; {remaining} recursion left); give each child a dedicated `write_scope` — a strict workspace-relative directory subtree of your own write authority."
        );
        Self { description }
    }
}

#[async_trait]
impl Tool for SpawnTool {
    fn name(&self) -> &str {
        "spawn"
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn verbose_description(&self) -> Option<String> {
        Some(format!(
            // A directive, not an enforcement claim. Nothing reserves a child's
            // subtree against its parent, so promising the parent is locked out
            // of it would assert a boundary the engine does not provide. State
            // the expected behaviour instead, and let the inventory test in
            // `write_scope::tests::spawn_rename_inventory` keep it that way.
            "{} Use this only when the current slice can be split into independent child work; write a complete brief and a dedicated write_scope for every child. Treat each child's write_scope as that child's working area for the duration: do not write inside it yourself until the child returns.",
            self.description
        ))
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "Self-contained brief for the child: goal, scope of this slice, what to save and return"
                },
                "write_scope": {
                    "type": "string",
                    "description": "Required strict workspace-relative directory subtree of your own write authority, transferred to the child for the whole run; reads stay workspace-wide"
                },
                "model": {
                    "type": "string",
                    "description": "Optional child model selector (`provider/model` or `provider:model`). Capability/cost only: data custody is host policy, so a capture-capable child cannot be requested here and delegated routing always applies the redacted untrusted filter"
                }
            },
            "required": ["prompt", "write_scope"]
        })
    }

    async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        Err(anyhow::anyhow!(
            "`spawn` is intercepted by the engine dispatcher; this code path should be unreachable"
        ))
    }
}
