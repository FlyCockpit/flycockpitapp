//! Optional coding-path capability: edit in place, fan out to managed
//! worktrees, merge selected artifacts, or apply them uncommitted.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::path::PathBuf;
use uuid::Uuid;

use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};
use crate::worktree_orchestration::{
    FanOutSpec, OrchestrationAction, OrchestratorInit, WorktreeOrchestrator,
};

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
                    "enum": ["edit_in_place", "surface_artifacts", "fan_out", "produce_artifact", "request_conflict_specialist", "inspect_conflict_request", "submit_conflict_resolution", "merge_selected", "apply_uncommitted"],
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
                },
                "conflict_specialist_lease_id": {
                    "type": "string",
                    "description": "Bounded specialist lease id whose durable result the parent may explicitly accept"
                },
                "parent_conflict_decision": {
                    "type": "string",
                    "enum": ["accept_specialist", "reject_specialist"],
                    "description": "Explicit parent decision; required with conflict_specialist_lease_id"
                },
                "specialist_verdict": {
                    "type": "string",
                    "enum": ["combined", "choose_left", "choose_right", "unresolved"],
                    "description": "Closed result submitted only by the bounded conflict specialist"
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
                    "enum": ["edit_in_place", "surface_artifacts", "fan_out", "produce_artifact", "request_conflict_specialist", "inspect_conflict_request", "submit_conflict_resolution", "merge_selected", "apply_uncommitted"],
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
                },
                "conflict_specialist_lease_id": {
                    "type": "string",
                    "description": "Bounded specialist lease id whose durable result the parent may explicitly accept"
                },
                "parent_conflict_decision": {
                    "type": "string",
                    "enum": ["accept_specialist", "reject_specialist"],
                    "description": "Explicit parent decision; required with conflict_specialist_lease_id"
                },
                "specialist_verdict": {
                    "type": "string",
                    "enum": ["combined", "choose_left", "choose_right", "unresolved"],
                    "description": "Closed result submitted only by the bounded conflict specialist"
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
            OrchestrationAction::SurfaceArtifacts
            | OrchestrationAction::FanOut
            | OrchestrationAction::ProduceArtifact
            | OrchestrationAction::RequestConflictSpecialist
            | OrchestrationAction::InspectConflictRequest
            | OrchestrationAction::SubmitConflictResolution
            | OrchestrationAction::MergeSelected
            | OrchestrationAction::ApplyUncommitted => {
                if ctx.agent_instance_id.is_none() {
                    return Err(invalid_input(
                        "worktree_orchestrate requires a host-issued agent instance",
                    ));
                }
                // Launch scope is local CLI/TUI only. Remote/web/relay surfaces
                // are not wired here.
                // TODO: remote-facing worktree orchestration (relay/web) is out of launch scope.
                let labels =
                    args.get("labels")
                        .and_then(Value::as_array)
                        .map(|items| {
                            items
                                .iter()
                                .map(|value| {
                                    value.as_str().map(str::to_owned).ok_or_else(|| {
                                        invalid_input("every label must be a string")
                                    })
                                })
                                .collect::<Result<Vec<_>>>()
                        })
                        .transpose()?
                        .unwrap_or_default();
                let ids = args
                    .get("artifact_ids")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .map(|value| {
                                value
                                    .as_str()
                                    .ok_or_else(|| {
                                        invalid_input("every artifact id must be a string")
                                    })
                                    .and_then(|raw| {
                                        Uuid::parse_str(raw).map_err(|_| {
                                            invalid_input("artifact ids must be UUIDs")
                                        })
                                    })
                            })
                            .collect::<Result<Vec<_>>>()
                    })
                    .transpose()?
                    .unwrap_or_default();
                let specialist_lease_id = args
                    .get("conflict_specialist_lease_id")
                    .and_then(Value::as_str)
                    .map(|raw| {
                        Uuid::parse_str(raw).map_err(|_| {
                            invalid_input("conflict_specialist_lease_id must be a UUID")
                        })
                    })
                    .transpose()?;
                let current_worktree = crate::git::find_worktree_root(&ctx.cwd)
                    .ok_or_else(|| invalid_input("worktree_orchestrate requires a Git worktree"))?;
                let current_worktree = crate::git::resolve_git_path(&current_worktree)?;
                let issued_root;
                let lease = if let Some(lease) = ctx.workspace_lease.as_ref() {
                    lease
                } else if action == OrchestrationAction::FanOut {
                    let agent = ctx.agent_instance_id.expect("checked above");
                    let scopes = ctx
                        .session
                        .db
                        .list_write_scope_leases_for_session(ctx.session.id)
                        .await?;
                    let scope = scopes
                        .into_iter()
                        .find(|scope| {
                            scope.state == "active"
                                && scope.owner_id == agent.to_string()
                                && std::path::Path::new(&scope.scope_path) == current_worktree
                        })
                        .ok_or_else(|| {
                            invalid_input("root write-scope lease is unavailable for fan_out")
                        })?;
                    let receipt = crate::worktree_orchestration::capture_workspace_receipt(
                        &current_worktree,
                    )?;
                    let row = ctx.session.db.create_workspace_lease(crate::db::workspace_lease_artifacts::NewWorkspaceLease {
                        session_id: ctx.session.id, agent_instance_id: agent, write_scope_lease_id: scope.lease_id,
                        parent_workspace_lease_id: None,
                        canonical_repository_id: crate::worktree_orchestration::receipt_repository_id(&current_worktree)?,
                        canonical_root: current_worktree.to_string_lossy().into_owned(),
                        kind: crate::db::workspace_lease_artifacts::WorkspaceLeaseKind::SameRoot,
                        allowed_ops: crate::workspace_lease::WorkspaceLeaseOps::for_coding().to_bits(),
                        base_sha_digest: receipt.head_digest, base_ref_digest: receipt.ref_digest,
                        managed_path: current_worktree.to_string_lossy().into_owned(), private_ref_digest: crate::db::workspace_lease_artifacts::WorkspaceDigest::of(b"same_root"),
                        expires_at_unix_ms: crate::workspace_lease::now_unix_ms().saturating_add(24 * 60 * 60 * 1000),
                    }, crate::workspace_lease::now_unix_ms()).await?;
                    issued_root = std::sync::Arc::new(
                        crate::workspace_lease::WorkspaceLease::from_row(&row)?,
                    );
                    &issued_root
                } else {
                    return Err(invalid_input(
                        "worktree_orchestrate merge/apply/produce requires a live workspace lease",
                    ));
                };
                if lease.session_id != ctx.session.id {
                    return Err(invalid_input(
                        "workspace lease is not owned by this session",
                    ));
                }
                let specialist_result_action = matches!(
                    action,
                    OrchestrationAction::InspectConflictRequest
                        | OrchestrationAction::SubmitConflictResolution
                );
                if !lease.allowed_ops.write || !lease.covers_path(&current_worktree) {
                    return Err(invalid_input(
                        "workspace lease does not grant writes to the current worktree",
                    ));
                }
                let durable_lease = ctx
                    .session
                    .db
                    .workspace_lease(ctx.session.id, lease.owner_agent_instance_id, lease.id)
                    .await?
                    .ok_or_else(|| invalid_input("workspace lease is not durable"))?;
                let now = crate::workspace_lease::now_unix_ms();
                if durable_lease.state
                    != crate::db::workspace_lease_artifacts::WorkspaceLeaseState::Active
                    || durable_lease.expires_at_unix_ms <= now
                    || durable_lease.revision != lease.revision
                {
                    return Err(invalid_input(
                        "workspace lease is stale, expired, or revoked",
                    ));
                }
                let scope = ctx
                    .session
                    .db
                    .get_write_scope_lease(lease.write_scope_lease_id)
                    .await?
                    .ok_or_else(|| invalid_input("workspace write-scope lease is missing"))?;
                if scope.state != "active"
                    || scope.session_id != ctx.session.id
                    || (!durable_lease.host_issued
                        && scope.owner_id != lease.owner_agent_instance_id.to_string())
                {
                    return Err(invalid_input(
                        "workspace write-scope lease is not active for this workspace lease",
                    ));
                }
                if specialist_result_action && !lease.is_durable_host_issued_managed_worktree() {
                    return Err(invalid_input(
                        "conflict handoff actions require a bounded host-issued managed worktree",
                    ));
                }
                let state_dir = cockpit_config::config::resolve::cockpit_state_dir()?;
                let orchestrator = WorktreeOrchestrator::new(OrchestratorInit {
                    db: ctx.session.db.clone(),
                    locks: ctx.locks.clone(),
                    state_dir,
                    session_id: ctx.session.id,
                    agent_instance_id: lease.owner_agent_instance_id,
                    lock_identity: ctx.lock_identity.clone(),
                    primary_repo: current_worktree.clone(),
                    parent_workspace_lease_id: lease.id,
                    parent_workspace_lease_revision: durable_lease.revision,
                    write_scope_lease_id: scope.lease_id,
                    write_scope_generation: scope.generation,
                    write_scope_revision: scope.version,
                })?
                .with_cancel(ctx.cancel.clone());
                match action {
                    OrchestrationAction::SurfaceArtifacts => {
                        let visible = orchestrator.surface_for_parent().await?;
                        Ok(ToolOutput::text(serde_json::to_string(&visible.iter().map(|item| serde_json::json!({
                            "artifact_id": item.artifact.artifact_id,
                            "source_workspace_lease_id": item.artifact.source_workspace_lease_id,
                            "state": item.artifact.state.as_str(),
                            "parent_result": item.artifact.parent_result,
                            "receipt": item.receipt.as_ref().map(|receipt| serde_json::json!({
                                "target_canonical_repository_id": receipt.target_canonical_repository_id,
                                "target_canonical_root": receipt.target_canonical_root,
                                "target_head_digest": receipt.target_head_digest.as_str(),
                                "target_ref_digest": receipt.target_ref_digest.as_str(),
                                "target_index_digest": receipt.target_index_digest.as_str(),
                                "changed_path_manifest_digest": receipt.changed_path_manifest_digest.as_str(),
                                "target_write_scope_lease_id": receipt.target_write_scope_lease_id,
                                "expected_target_generation": receipt.expected_target_generation,
                                "expected_target_revision": receipt.expected_target_revision,
                                "created_at_unix_ms": receipt.created_at_unix_ms,
                            })),
                            "touched_paths": item.touched_paths,
                            "untracked_paths": item.untracked_paths,
                        })).collect::<Vec<_>>())?))
                    }
                    OrchestrationAction::FanOut => {
                        if labels.is_empty() {
                            return Err(invalid_input("fan_out requires at least one label"));
                        }
                        let children = orchestrator
                            .fan_out(
                                labels
                                    .into_iter()
                                    .map(|label| FanOutSpec { label })
                                    .collect(),
                                now,
                            )
                            .await?;
                        Ok(ToolOutput::text(serde_json::to_string(&children.iter().map(|child| serde_json::json!({"label": child.label, "path": child.path, "workspace_lease_id": child.lease.workspace_lease_id})).collect::<Vec<_>>())?))
                    }
                    OrchestrationAction::ProduceArtifact => {
                        if !lease.is_durable_host_issued_managed_worktree() {
                            return Err(invalid_input(
                                "produce_artifact is only valid inside a host-issued managed child worktree",
                            ));
                        }
                        let receipts = orchestrator.store().fanout_receipts(lease.id)?;
                        if receipts.target.head_digest != lease.base_sha_digest
                            || receipts.target.ref_digest != lease.base_ref_digest
                        {
                            return Err(invalid_input(
                                "managed child fan-out receipt does not match its durable lease",
                            ));
                        }
                        let patch = crate::git::capture_uncommitted_patch(&current_worktree)?;
                        let primary = primary_worktree_for_validation(&current_worktree)?;
                        let validation =
                            crate::worktree_orchestration::CandidateValidation::for_primary(
                                primary,
                            )
                            .with_cancel(ctx.cancel.clone())
                            .with_locks(
                                ctx.locks.clone(),
                                ctx.lock_identity.clone(),
                                ctx.session.id,
                            );
                        let evidence = validation
                            .validate_patch(&patch, &["test", "--locked", "--workspace"])
                            .await?;
                        if evidence.exit_code != 0 {
                            return Err(invalid_input(format!(
                                "candidate validation failed in the primary tree (exit {})",
                                evidence.exit_code
                            )));
                        }
                        // Capture once, validate those exact bytes, then refuse
                        // publication if the worker changed underneath us.  The
                        // persisted patch and digest can therefore never differ
                        // from the validation candidate.
                        if crate::git::capture_uncommitted_patch(&current_worktree)? != patch {
                            return Err(invalid_input(
                                "worker tree changed after validation; recapture and validate again",
                            ));
                        }
                        let produced = crate::worktree_orchestration::produce_artifact_from_patch(
                            &ctx.session.db,
                            orchestrator.store(),
                            &current_worktree,
                            lease.id,
                            ctx.session.id,
                            lease.owner_agent_instance_id,
                            now,
                            crate::worktree_orchestration::evidence_digest(&evidence),
                            Some(&receipts),
                            patch,
                        )
                        .await?;
                        Ok(ToolOutput::text(serde_json::json!({"artifact_id": produced.row.artifact_id, "state": produced.row.state.as_str()}).to_string()))
                    }
                    OrchestrationAction::RequestConflictSpecialist => {
                        if ids.len() != 2 {
                            return Err(invalid_input(
                                "request_conflict_specialist requires exactly two ordered artifact_ids",
                            ));
                        }
                        let request = orchestrator
                            .request_conflict_specialist(ids[0], ids[1], now)
                            .await?;
                        Ok(ToolOutput::text(
                            serde_json::json!({
                                "workspace_lease_id": request.lease_id,
                                "artifact_ids": [ids[0], ids[1]],
                                "next": "launch the specialist with this lease, inspect_conflict_request, then submit_conflict_resolution"
                            })
                            .to_string(),
                        ))
                    }
                    OrchestrationAction::InspectConflictRequest => {
                        let request = orchestrator.inspect_conflict_request(lease.id)?;
                        Ok(ToolOutput::text(serde_json::to_string(&request)?))
                    }
                    OrchestrationAction::SubmitConflictResolution => {
                        let raw = args
                            .get("specialist_verdict")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                invalid_input(
                                    "submit_conflict_resolution requires specialist_verdict",
                                )
                            })?;
                        let verdict =
                            crate::worktree_orchestration::ConflictSpecialistVerdict::parse(raw)
                                .map_err(|error| invalid_input(error.to_string()))?;
                        let specialist =
                            crate::worktree_orchestration::ConflictSpecialist::bounded_by(
                                crate::workspace_lease::WorkspaceLease::from_row(&durable_lease)?,
                            );
                        orchestrator.submit_conflict_resolution(specialist, verdict)?;
                        Ok(ToolOutput::text(
                            "conflict specialist result submitted for explicit parent review",
                        ))
                    }
                    OrchestrationAction::MergeSelected | OrchestrationAction::ApplyUncommitted => {
                        let decision = args.get("parent_conflict_decision").and_then(Value::as_str);
                        let result = match (specialist_lease_id, decision) {
                            (None, None) => match action {
                                OrchestrationAction::MergeSelected => {
                                    orchestrator.merge_selected(ids, now).await?
                                }
                                OrchestrationAction::ApplyUncommitted => {
                                    orchestrator.apply_uncommitted(ids, now).await?
                                }
                                _ => unreachable!(),
                            },
                            (Some(specialist), Some("accept_specialist")) => {
                                let mode = if action == OrchestrationAction::MergeSelected {
                                    crate::worktree_orchestration::IntegrationMode::OrderedMerge
                                } else {
                                    crate::worktree_orchestration::IntegrationMode::ApplyUncommitted
                                };
                                orchestrator
                                    .integrate_with_conflict_specialist(
                                        ids, mode, specialist, true, now,
                                    )
                                    .await?
                            }
                            (Some(specialist), Some("reject_specialist")) => {
                                let mode = if action == OrchestrationAction::MergeSelected {
                                    crate::worktree_orchestration::IntegrationMode::OrderedMerge
                                } else {
                                    crate::worktree_orchestration::IntegrationMode::ApplyUncommitted
                                };
                                orchestrator
                                    .integrate_with_conflict_specialist(
                                        ids, mode, specialist, false, now,
                                    )
                                    .await?
                            }
                            _ => {
                                return Err(invalid_input(
                                    "merge/apply requires both conflict_specialist_lease_id and parent_conflict_decision, or neither",
                                ));
                            }
                        };
                        Ok(ToolOutput::text(format!("{result:?}")))
                    }
                    OrchestrationAction::EditInPlace => unreachable!(),
                }
            }
        }
    }
}

fn primary_worktree_for_validation(cwd: &std::path::Path) -> Result<PathBuf> {
    let listing = crate::git::run_git_checked(cwd, &["worktree", "list", "--porcelain"])?;
    let root = listing
        .lines()
        .find_map(|line| line.strip_prefix("worktree "))
        .ok_or_else(|| {
            invalid_input("git did not report a primary worktree for candidate validation")
        })?;
    let primary = crate::git::resolve_git_path(&PathBuf::from(root))?;
    crate::worktree_orchestration::worker_must_not_invoke_cargo(&primary)?;
    Ok(primary)
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
