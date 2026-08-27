//! Optional coding-path capability: edit in place, fan out to managed
//! worktrees, merge selected artifacts, or apply them uncommitted.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};
use crate::worktree_orchestration::OrchestrationAction;

pub struct WorktreeOrchestrateTool;

#[async_trait]
impl Tool for WorktreeOrchestrateTool {
    fn name(&self) -> &str {
        "worktree_orchestrate"
    }

    fn description(&self) -> &str {
        "Optional: edit in place, fan out to worktrees, merge selected, or apply uncommitted; never commits."
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Use this optional coding capability only when asked to isolate work in managed \
             worktrees or to bring selected artifacts back. Call it with action edit_in_place \
             to keep editing the current tree, fan_out to create isolated worktrees, \
             merge_selected for ordered commitless composition, or apply_uncommitted to land \
             patches without a commit. Do not treat it as a mandatory role; never commit, \
             never stage unrelated files, and never force-remove a pinned or uncertain \
             worktree. Prefer ordinary write/edit when you are already in the target tree. \
             Conflict specialists return combined/choose_left/choose_right/unresolved and \
             the parent decides; cancellation of in-place edits preserves visible changes \
             without rollback."
                .to_string(),
        )
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::Mutating
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["edit_in_place", "fan_out", "merge_selected", "apply_uncommitted"],
                    "description": "Orchestration action"
                },
                "labels": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Fan-out child labels"
                },
                "artifact_ids": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Selected artifact ids"
                }
            },
            "required": ["action"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["edit_in_place", "fan_out", "merge_selected", "apply_uncommitted"],
                    "description": "Use edit_in_place for the current tree, fan_out to isolate orthogonal work, merge_selected for ordered commitless composition, apply_uncommitted to land patches without creating a commit"
                },
                "labels": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Labels for fan_out children; each becomes a managed worktree"
                },
                "artifact_ids": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Artifact ids to merge or apply, in the exact order they must compose"
                }
            },
            "required": ["action"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let action = args
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`action` is required"))?;
        let action =
            OrchestrationAction::parse(action).map_err(|err| invalid_input(err.to_string()))?;
        match action {
            OrchestrationAction::EditInPlace => Ok(ToolOutput::text(
                "edit_in_place: continue in the current worktree. Commit remains an explicit user/agent action; cancelling preserves already-visible edits.",
            )),
            OrchestrationAction::FanOut
            | OrchestrationAction::MergeSelected
            | OrchestrationAction::ApplyUncommitted => {
                if ctx.agent_instance_id.is_none() {
                    return Err(invalid_input(
                        "worktree_orchestrate requires a host-issued agent instance",
                    ));
                }
                if ctx.workspace_lease.is_none() {
                    return Err(invalid_input(
                        "worktree_orchestrate fan_out/merge/apply requires a live workspace lease",
                    ));
                }
                // Launch scope is local CLI/TUI only. Remote/web/relay surfaces
                // are not wired here.
                // TODO: remote-facing worktree orchestration (relay/web) is out of launch scope.
                let labels = args
                    .get("labels")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let ids = args
                    .get("artifact_ids")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                Ok(ToolOutput::text(format!(
                    "{} accepted for local orchestration (labels=[{labels}] artifact_ids=[{ids}]). No commit will be created.",
                    action.as_str()
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tool::Tool;
    use crate::tools::common::test_ctx;

    #[test]
    fn terse_description_stays_in_budget() {
        let tool = WorktreeOrchestrateTool;
        assert!(tool.description().len() <= 200, "{}", tool.description());
        assert!(tool.defensive_description().unwrap().len() > tool.description().len());
    }

    #[tokio::test]
    async fn edit_in_place_does_not_require_a_lease() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let out = WorktreeOrchestrateTool
            .call(serde_json::json!({"action": "edit_in_place"}), &ctx)
            .await
            .unwrap();
        assert!(out.content.contains("edit_in_place"), "{}", out.content);
        assert!(out.content.contains("preserves"), "{}", out.content);
    }

    #[tokio::test]
    async fn fan_out_without_lease_is_invocation_error() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let err = WorktreeOrchestrateTool
            .call(serde_json::json!({"action": "fan_out"}), &ctx)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("agent instance")
                || err.to_string().contains("workspace lease")
        );
    }
}
