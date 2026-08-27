//! Pre-integration target lock, receipt comparison, and commitless apply.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::db::Db;
use crate::db::workspace_lease_artifacts::{
    ArtifactCasOutcome, IntegrationTarget, TaskArtifactRow, TaskArtifactState,
};
use crate::git::{self, ByteIdenticalReceipt, UncommittedPatch};
use crate::locks::LockManager;

use super::artifact::ArtifactStore;
use super::conflict::{ConflictSpecialist, ConflictSpecialistVerdict};
use super::receipt::{self, WorkspaceReceipt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrationMode {
    ApplyUncommitted,
    OrderedMerge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleReason {
    Head,
    Ref,
    Index,
    TouchedPaths,
    UntrackedPaths,
}

#[derive(Debug, Clone)]
pub struct IntegrationRequest {
    pub artifact_ids: Vec<Uuid>,
    pub mode: IntegrationMode,
    pub target: PathBuf,
    pub target_write_scope_lease_id: Uuid,
    pub expected_target_generation: u64,
    pub expected_target_revision: u64,
}

#[derive(Debug, Clone)]
pub enum IntegrationResult {
    Integrated {
        artifacts: Vec<TaskArtifactRow>,
        private_ref: Option<String>,
    },
    Stale {
        reason: StaleReason,
        artifacts: Vec<TaskArtifactRow>,
        target_receipt: ByteIdenticalReceipt,
    },
    Conflict {
        artifacts: Vec<TaskArtifactRow>,
        verdict: ConflictSpecialistVerdict,
        target_receipt: ByteIdenticalReceipt,
    },
    Cancelled {
        artifacts: Vec<TaskArtifactRow>,
        target_receipt: ByteIdenticalReceipt,
    },
    Failed {
        message: String,
        artifacts: Vec<TaskArtifactRow>,
        target_receipt: ByteIdenticalReceipt,
    },
}

pub async fn integrate_artifacts(
    db: &Db,
    store: &ArtifactStore,
    locks: &Arc<LockManager>,
    lock_identity: &str,
    session_id: Uuid,
    agent_instance_id: Uuid,
    now_ms: i64,
    request: IntegrationRequest,
    specialist: Option<&ConflictSpecialist>,
    cancel: &CancellationToken,
) -> Result<IntegrationResult> {
    let target = git::resolve_git_path(&request.target)?;
    locks
        .acquire(&target, lock_identity, session_id)
        .await
        .context("acquiring target workspace lock")?;
    let before = match git::byte_identical_receipt(&target) {
        Ok(receipt) => receipt,
        Err(error) => {
            let _ = locks.release(&target, lock_identity, session_id).await;
            return Err(error);
        }
    };
    let result = integrate_locked(
        db,
        store,
        session_id,
        agent_instance_id,
        now_ms,
        &request,
        &target,
        &before,
        specialist,
        cancel,
    )
    .await;
    let _ = locks.release(&target, lock_identity, session_id).await;
    result
}

async fn integrate_locked(
    db: &Db,
    store: &ArtifactStore,
    session_id: Uuid,
    agent_instance_id: Uuid,
    now_ms: i64,
    request: &IntegrationRequest,
    target: &Path,
    before: &ByteIdenticalReceipt,
    specialist: Option<&ConflictSpecialist>,
    cancel: &CancellationToken,
) -> Result<IntegrationResult> {
    let mut loaded = Vec::new();
    for id in &request.artifact_ids {
        let Some(row) = db.task_artifact(session_id, agent_instance_id, *id).await? else {
            return finish_failed(
                db,
                session_id,
                agent_instance_id,
                now_ms,
                Vec::new(),
                target,
                before,
                None,
                format!("artifact `{id}` is not owned"),
            )
            .await;
        };
        let patch = store.load_patch(&row)?;
        loaded.push((row, patch));
    }

    let mut begun = Vec::new();
    for (row, patch) in loaded {
        if cancel.is_cancelled() {
            return abort_cancel(
                db,
                session_id,
                agent_instance_id,
                now_ms,
                begun,
                target,
                before,
                None,
            )
            .await;
        }
        match db
            .begin_task_artifact_integration(
                session_id,
                agent_instance_id,
                row.artifact_id,
                row.revision,
                now_ms,
            )
            .await?
        {
            ArtifactCasOutcome::Transitioned(updated) => begun.push((updated, patch)),
            ArtifactCasOutcome::AlreadyTerminal(updated) => {
                return finish_failed(
                    db,
                    session_id,
                    agent_instance_id,
                    now_ms,
                    begun.into_iter().map(|(row, _)| row).collect(),
                    target,
                    before,
                    None,
                    format!("artifact `{}` is already terminal", updated.artifact_id),
                )
                .await;
            }
            ArtifactCasOutcome::RevisionConflict => {
                return finish_failed(
                    db,
                    session_id,
                    agent_instance_id,
                    now_ms,
                    begun.into_iter().map(|(row, _)| row).collect(),
                    target,
                    before,
                    None,
                    "artifact integration revision conflict".into(),
                )
                .await;
            }
        }
    }

    let live = receipt::capture_workspace_receipt(target)?;
    if let Some(reason) = stale_reason(&live, &begun, target)? {
        let mut finished = Vec::new();
        for (row, _) in begun {
            finished.push(
                finish_state(
                    db,
                    session_id,
                    agent_instance_id,
                    row.artifact_id,
                    row.revision,
                    now_ms,
                    TaskArtifactState::Stale,
                )
                .await?,
            );
        }
        let after = git::byte_identical_receipt(target)?;
        ensure_unchanged(before, &after)?;
        return Ok(IntegrationResult::Stale {
            reason,
            artifacts: finished,
            target_receipt: after,
        });
    }

    let (composed, contributors) = match compose_patches(&begun, specialist) {
        Ok(patch) => patch,
        Err(verdict) => {
            let mut finished = Vec::new();
            for (row, _) in begun {
                finished.push(
                    finish_state(
                        db,
                        session_id,
                        agent_instance_id,
                        row.artifact_id,
                        row.revision,
                        now_ms,
                        TaskArtifactState::Conflict,
                    )
                    .await?,
                );
            }
            let after = git::byte_identical_receipt(target)?;
            ensure_unchanged(before, &after)?;
            return Ok(IntegrationResult::Conflict {
                artifacts: finished,
                verdict,
                target_receipt: after,
            });
        }
    };
    let mut selected = Vec::new();
    for (row, patch) in begun {
        if contributors.contains(&row.artifact_id) {
            selected.push((row, patch));
        } else {
            finish_state(
                db,
                session_id,
                agent_instance_id,
                row.artifact_id,
                row.revision,
                now_ms,
                TaskArtifactState::Conflict,
            )
            .await?;
        }
    }
    let begun = selected;

    if cancel.is_cancelled() {
        return abort_cancel(
            db,
            session_id,
            agent_instance_id,
            now_ms,
            begun,
            target,
            before,
            None,
        )
        .await;
    }

    if !git::apply_uncommitted_patch_check(target, &composed.diff)? {
        let mut finished = Vec::new();
        for (row, _) in begun {
            finished.push(
                finish_state(
                    db,
                    session_id,
                    agent_instance_id,
                    row.artifact_id,
                    row.revision,
                    now_ms,
                    TaskArtifactState::Conflict,
                )
                .await?,
            );
        }
        let after = git::byte_identical_receipt(target)?;
        ensure_unchanged(before, &after)?;
        return Ok(IntegrationResult::Conflict {
            artifacts: finished,
            verdict: ConflictSpecialistVerdict::Unresolved,
            target_receipt: after,
        });
    }

    let touched_snapshot = snapshot_paths(target, &composed.touched_paths)?;
    if let Err(error) = git::apply_uncommitted_patch(target, &composed.diff) {
        restore_paths(target, &touched_snapshot)?;
        return finish_failed(
            db,
            session_id,
            agent_instance_id,
            now_ms,
            begun.into_iter().map(|(row, _)| row).collect(),
            target,
            before,
            Some(&touched_snapshot),
            error.to_string(),
        )
        .await;
    }
    if cancel.is_cancelled() {
        git::reverse_uncommitted_patch(target, &composed.diff)?;
        return abort_cancel(
            db,
            session_id,
            agent_instance_id,
            now_ms,
            begun,
            target,
            before,
            None,
        )
        .await;
    }

    let private_ref = if request.mode == IntegrationMode::OrderedMerge {
        let name = format!(
            "refs/cockpit/merges/{}",
            request
                .artifact_ids
                .first()
                .copied()
                .unwrap_or_else(Uuid::nil)
        );
        if let Err(error) = git::store_private_blob_ref(target, &name, composed.diff.as_bytes()) {
            git::reverse_uncommitted_patch(target, &composed.diff)?;
            return finish_failed(
                db,
                session_id,
                agent_instance_id,
                now_ms,
                begun.into_iter().map(|(row, _)| row).collect(),
                target,
                before,
                None,
                error.to_string(),
            )
            .await;
        }
        Some(name)
    } else {
        None
    };

    let prepared = (|| -> Result<IntegrationTarget> {
        let changed =
            git::manifest_digest(target, composed.touched_paths.iter().map(String::as_str))?;
        let repo_id = receipt::repository_id(target)?;
        let after_receipt = receipt::capture_workspace_receipt(target)?;
        Ok(IntegrationTarget {
            target_canonical_repository_id: repo_id,
            target_canonical_root: target.to_string_lossy().into_owned(),
            target_head_digest: after_receipt.head_digest,
            target_ref_digest: after_receipt.ref_digest,
            target_index_digest: after_receipt.index_digest,
            changed_path_manifest_digest: changed,
            target_write_scope_lease_id: request.target_write_scope_lease_id,
            expected_target_generation: request.expected_target_generation,
            expected_target_revision: request.expected_target_revision,
        })
    })();
    let target_spec = match prepared {
        Ok(spec) => spec,
        Err(error) => {
            git::reverse_uncommitted_patch(target, &composed.diff)?;
            if let Some(name) = &private_ref {
                let _ = git::delete_private_ref(target, name);
            }
            return finish_failed(
                db,
                session_id,
                agent_instance_id,
                now_ms,
                begun.into_iter().map(|(row, _)| row).collect(),
                target,
                before,
                None,
                error.to_string(),
            )
            .await;
        }
    };
    let expected = begun
        .iter()
        .map(|(row, _)| (row.artifact_id, row.revision))
        .collect();
    let integrated = match db
        .integrate_task_artifacts(session_id, agent_instance_id, expected, target_spec, now_ms)
        .await
    {
        Ok(Some(rows)) => rows,
        Ok(None) => {
            git::reverse_uncommitted_patch(target, &composed.diff)?;
            if let Some(name) = &private_ref {
                let _ = git::delete_private_ref(target, name);
            }
            return finish_failed(
                db,
                session_id,
                agent_instance_id,
                now_ms,
                begun.into_iter().map(|(row, _)| row).collect(),
                target,
                before,
                None,
                "atomic integration CAS failed".into(),
            )
            .await;
        }
        Err(error) => {
            git::reverse_uncommitted_patch(target, &composed.diff)?;
            if let Some(name) = &private_ref {
                let _ = git::delete_private_ref(target, name);
            }
            return finish_failed(
                db,
                session_id,
                agent_instance_id,
                now_ms,
                begun.into_iter().map(|(row, _)| row).collect(),
                target,
                before,
                None,
                error.to_string(),
            )
            .await;
        }
    };

    Ok(IntegrationResult::Integrated {
        artifacts: integrated,
        private_ref,
    })
}

fn stale_reason(
    live: &WorkspaceReceipt,
    loaded: &[(TaskArtifactRow, UncommittedPatch)],
    target: &Path,
) -> Result<Option<StaleReason>> {
    for (row, patch) in loaded {
        if live.head_digest != row.base_head_digest {
            return Ok(Some(StaleReason::Head));
        }
        if live.ref_digest != row.base_ref_digest {
            return Ok(Some(StaleReason::Ref));
        }
        if live.index_digest != row.base_index_digest {
            return Ok(Some(StaleReason::Index));
        }
        let untracked = receipt::live_manifest(target, &patch.untracked_paths)?;
        if untracked != row.untracked_manifest_digest {
            return Ok(Some(StaleReason::UntrackedPaths));
        }
        let touched = receipt::live_manifest(target, &patch.touched_paths)?;
        if touched != row.touched_manifest_digest {
            return Ok(Some(StaleReason::TouchedPaths));
        }
    }
    Ok(None)
}

fn compose_patches(
    begun: &[(TaskArtifactRow, UncommittedPatch)],
    specialist: Option<&ConflictSpecialist>,
) -> Result<(UncommittedPatch, BTreeSet<Uuid>), ConflictSpecialistVerdict> {
    if begun.is_empty() {
        return Ok((
            UncommittedPatch {
                diff: String::new(),
                touched_paths: Vec::new(),
                untracked_paths: Vec::new(),
            },
            BTreeSet::new(),
        ));
    }
    let mut acc = begun[0].1.clone();
    let mut contributors = BTreeSet::from([begun[0].0.artifact_id]);
    for (row, next) in begun.iter().skip(1) {
        if paths_overlap(&acc, next) {
            let Some(specialist) = specialist else {
                return Err(ConflictSpecialistVerdict::Unresolved);
            };
            let verdict = specialist.resolve(&acc, next);
            acc = specialist
                .compose(&acc, next, verdict)
                .map_err(|_| verdict)?;
            match verdict {
                ConflictSpecialistVerdict::Combined => {
                    contributors.insert(row.artifact_id);
                }
                ConflictSpecialistVerdict::ChooseLeft => {}
                ConflictSpecialistVerdict::ChooseRight => {
                    contributors.clear();
                    contributors.insert(row.artifact_id);
                }
                ConflictSpecialistVerdict::Unresolved => unreachable!(),
            }
        } else {
            acc = concatenate(&acc, next);
            contributors.insert(row.artifact_id);
        }
    }
    Ok((acc, contributors))
}

fn paths_overlap(left: &UncommittedPatch, right: &UncommittedPatch) -> bool {
    left.touched_paths
        .iter()
        .any(|path| right.touched_paths.iter().any(|other| other == path))
}

fn concatenate(left: &UncommittedPatch, right: &UncommittedPatch) -> UncommittedPatch {
    let mut diff = left.diff.clone();
    if !diff.ends_with('\n') && !diff.is_empty() && !right.diff.is_empty() {
        diff.push('\n');
    }
    diff.push_str(&right.diff);
    let mut touched = left.touched_paths.clone();
    for path in &right.touched_paths {
        if !touched.iter().any(|existing| existing == path) {
            touched.push(path.clone());
        }
    }
    let mut untracked = left.untracked_paths.clone();
    for path in &right.untracked_paths {
        if !untracked.iter().any(|existing| existing == path) {
            untracked.push(path.clone());
        }
    }
    UncommittedPatch {
        diff,
        touched_paths: touched,
        untracked_paths: untracked,
    }
}

async fn finish_state(
    db: &Db,
    session: Uuid,
    agent: Uuid,
    id: Uuid,
    revision: i64,
    now_ms: i64,
    state: TaskArtifactState,
) -> Result<TaskArtifactRow> {
    match db
        .finish_task_artifact(session, agent, id, revision, state, now_ms)
        .await?
    {
        ArtifactCasOutcome::Transitioned(row) | ArtifactCasOutcome::AlreadyTerminal(row) => Ok(row),
        ArtifactCasOutcome::RevisionConflict => bail!("artifact `{id}` revision conflict"),
    }
}

async fn abort_cancel(
    db: &Db,
    session: Uuid,
    agent: Uuid,
    now_ms: i64,
    begun: Vec<(TaskArtifactRow, UncommittedPatch)>,
    target: &Path,
    before: &ByteIdenticalReceipt,
    snapshot: Option<&BTreeMap<String, Option<Vec<u8>>>>,
) -> Result<IntegrationResult> {
    if let Some(snapshot) = snapshot {
        restore_paths(target, snapshot)?;
    }
    let mut finished = Vec::new();
    for (row, _) in begun {
        match db
            .cancel_task_artifact(session, agent, row.artifact_id, row.revision, now_ms)
            .await?
        {
            ArtifactCasOutcome::Transitioned(updated)
            | ArtifactCasOutcome::AlreadyTerminal(updated) => finished.push(updated),
            ArtifactCasOutcome::RevisionConflict => {
                bail!("cancel raced a concurrent artifact revision")
            }
        }
    }
    let after = git::byte_identical_receipt(target)?;
    ensure_unchanged(before, &after)?;
    Ok(IntegrationResult::Cancelled {
        artifacts: finished,
        target_receipt: after,
    })
}

async fn finish_failed(
    db: &Db,
    session: Uuid,
    agent: Uuid,
    now_ms: i64,
    begun: Vec<TaskArtifactRow>,
    target: &Path,
    before: &ByteIdenticalReceipt,
    snapshot: Option<&BTreeMap<String, Option<Vec<u8>>>>,
    message: String,
) -> Result<IntegrationResult> {
    if let Some(snapshot) = snapshot {
        restore_paths(target, snapshot)?;
    }
    let mut finished = Vec::new();
    for row in begun {
        finished.push(
            finish_state(
                db,
                session,
                agent,
                row.artifact_id,
                row.revision,
                now_ms,
                TaskArtifactState::Failed,
            )
            .await?,
        );
    }
    let after = git::byte_identical_receipt(target)?;
    ensure_unchanged(before, &after)?;
    Ok(IntegrationResult::Failed {
        message,
        artifacts: finished,
        target_receipt: after,
    })
}

fn restore_paths(dir: &Path, snapshot: &BTreeMap<String, Option<Vec<u8>>>) -> Result<()> {
    for (rel, bytes) in snapshot {
        let abs = dir.join(rel);
        match bytes {
            Some(content) => {
                if let Some(parent) = abs.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&abs, content)
                    .with_context(|| format!("restoring `{}`", abs.display()))?;
            }
            None if abs.exists() => {
                std::fs::remove_file(&abs)
                    .with_context(|| format!("removing applied `{}`", abs.display()))?;
            }
            None => {}
        }
    }
    Ok(())
}

fn ensure_unchanged(before: &ByteIdenticalReceipt, after: &ByteIdenticalReceipt) -> Result<()> {
    if before != after {
        bail!(
            "target receipt drifted after a non-integrating attempt (head {} -> {}, ref {} -> {})",
            before.head,
            after.head,
            before.git_ref,
            after.git_ref
        );
    }
    Ok(())
}

fn snapshot_paths(dir: &Path, paths: &[String]) -> Result<BTreeMap<String, Option<Vec<u8>>>> {
    let mut out = BTreeMap::new();
    for rel in paths {
        let abs = dir.join(rel);
        out.insert(
            rel.clone(),
            if abs.exists() {
                Some(std::fs::read(&abs)?)
            } else {
                None
            },
        );
    }
    Ok(out)
}
