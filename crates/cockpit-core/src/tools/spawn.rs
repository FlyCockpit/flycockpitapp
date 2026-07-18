//! `spawn` — the recursive `Swarm`/`bee` fan-out tool (GOALS §24).
//!
//! Structural, like `task`/`schedule`/`handoff`: the engine intercepts it by
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
        // One noun-phrase-dense sentence (token economy §10). The
        // dedicated-output-folder guidance is in the description text itself.
        let description = format!(
            "Fan out a slice of the task to a parallel background `bee` worker \
             (you are at depth {depth} of ceiling {ceiling}; {remaining} level(s) of recursion left) \
             — give each child its own dedicated `output_dir` (or a distinct DB path) to save \
             results into so concurrent branches never write the same file."
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

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "Self-contained brief for the child: goal, scope of this slice, what to save and return"
                },
                "output_dir": {
                    "type": "string",
                    "description": "Dedicated folder/DB path the child writes its results into (avoids same-file contention)"
                },
                "model": {
                    "type": "string",
                    "description": "Optional child model selector (`provider/model` or `provider:model`)"
                }
            },
            "required": ["prompt", "output_dir"]
        })
    }

    async fn call(&self, _args: Value, _ctx: &ToolCtx) -> Result<ToolOutput> {
        Err(anyhow::anyhow!(
            "`spawn` is intercepted by the engine dispatcher; this code path should be unreachable"
        ))
    }
}
