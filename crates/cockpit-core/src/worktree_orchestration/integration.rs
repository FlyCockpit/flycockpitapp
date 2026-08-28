//! Pre-integration target lock, receipt comparison, and commitless apply.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::db::Db;
use crate::db::workspace_lease_artifacts::{
    ArtifactCasOutcome, IntegrationTarget, TaskArtifactRow, TaskArtifactState, WorkspaceDigest,
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
    pub target_workspace_lease_id: Uuid,
    pub expected_target_workspace_lease_revision: i64,
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
    let target_lease = db
        .workspace_lease_for_tools(
            session_id,
            agent_instance_id,
            request.target_workspace_lease_id,
            now_ms,
        )
        .await?
        .context("target workspace lease is revoked, expired, or unavailable")?;
    let target_root = target.to_string_lossy().into_owned();
    if target_lease.canonical_root != target_root
        || target_lease.write_scope_lease_id != request.target_write_scope_lease_id
        || target_lease.revision != request.expected_target_workspace_lease_revision
    {
        bail!("target workspace lease no longer authorizes this integration target");
    }
    locks
        .acquire(&target, lock_identity, session_id)
        .await
        .context("acquiring target workspace lock")?;
    // The repository-root lock is a coarse integration claim, but ordinary
    // write tools lock individual files. Hold the complete affected path set
    // too, before reading any receipt, and retain it through rollback and DB
    // finalization. This is the bridge between the two lock granularities.
    let mut path_locks = BTreeSet::new();
    for id in &request.artifact_ids {
        let row = match db.task_artifact(session_id, agent_instance_id, *id).await {
            Ok(Some(row)) => row,
            Ok(None) => {
                let _ = locks.release(&target, lock_identity, session_id).await;
                bail!("artifact `{id}` is not owned");
            }
            Err(error) => {
                let _ = locks.release(&target, lock_identity, session_id).await;
                return Err(error).context("loading artifact before integration lock");
            }
        };
        let patch = match store.load_patch(&row) {
            Ok(patch) => patch,
            Err(error) => {
                let _ = locks.release(&target, lock_identity, session_id).await;
                return Err(error).context("loading artifact patch before integration lock");
            }
        };
        for rel in patch.touched_paths.iter().chain(&patch.untracked_paths) {
            path_locks.insert(target.join(rel));
        }
    }
    let mut acquired_paths = Vec::new();
    for path in path_locks {
        if let Err(error) = locks.acquire(&path, lock_identity, session_id).await {
            for held in acquired_paths.into_iter().rev() {
                let _ = locks.release(&held, lock_identity, session_id).await;
            }
            let _ = locks.release(&target, lock_identity, session_id).await;
            return Err(error).context("acquiring integration affected-path lock");
        }
        acquired_paths.push(path);
    }
    let before = match git::byte_identical_receipt(&target) {
        Ok(receipt) => receipt,
        Err(error) => {
            for path in acquired_paths.into_iter().rev() {
                let _ = locks.release(&path, lock_identity, session_id).await;
            }
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
    for path in acquired_paths.into_iter().rev() {
        let _ = locks.release(&path, lock_identity, session_id).await;
    }
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

    let journal = match store.begin_integration_journal(target, &composed, before, &selected) {
        Ok(journal) => journal,
        Err(error) => {
            return finish_failed(
                db,
                session_id,
                agent_instance_id,
                now_ms,
                begun.into_iter().map(|(row, _)| row).collect(),
                target,
                before,
                error.to_string(),
            )
            .await;
        }
    };
    // This is the final durable authority read before the synchronous Git
    // mutation. We hold the target and affected-path locks, and introduce no
    // await between this proof and `git apply`. The receipt transaction later
    // repeats the proof before publishing the result.
    let authority = effect_boundary_authority(request, target)?;
    if !db
        .integration_target_is_live(
            session_id,
            agent_instance_id,
            authority,
            crate::workspace_lease::now_unix_ms(),
        )
        .await?
    {
        store.finish_integration_journal(journal)?;
        return finish_failed(
            db,
            session_id,
            agent_instance_id,
            now_ms,
            begun.into_iter().map(|(row, _)| row).collect(),
            target,
            before,
            "target workspace lease or write scope was revoked before integration".into(),
        )
        .await;
    }
    if let Err(error) = git::apply_uncommitted_patch(target, &composed.diff) {
        // Do not restore a byte snapshot when Git reports failure: replaying
        // it can overwrite external changes and cannot preserve modes or
        // symlinks. A changed target is retained with its journal for
        // recovery; a proven-unmodified target may finish as failed.
        let after = git::byte_identical_receipt(target)?;
        if &after != before {
            return Err(error).context(
                "git apply reported failure after target drift; integration journal retained for recovery",
            );
        }
        store.finish_integration_journal(journal)?;
        return finish_failed(
            db,
            session_id,
            agent_instance_id,
            now_ms,
            begun.into_iter().map(|(row, _)| row).collect(),
            target,
            before,
            error.to_string(),
        )
        .await;
    }
    let applied = git::byte_identical_receipt(target)
        .context("capturing full receipt after successful integration apply")?;
    if cancel.is_cancelled() {
        reverse_or_record_terminal_failure(
            db,
            session_id,
            agent_instance_id,
            now_ms,
            &begun,
            target,
            before,
            &applied,
            &composed.diff,
        )
        .await?;
        store.finish_integration_journal(journal)?;
        return abort_cancel(
            db,
            session_id,
            agent_instance_id,
            now_ms,
            begun,
            target,
            before,
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
            reverse_or_record_terminal_failure(
                db,
                session_id,
                agent_instance_id,
                now_ms,
                &begun,
                target,
                before,
                &applied,
                &composed.diff,
            )
            .await?;
            store.finish_integration_journal(journal)?;
            return finish_failed(
                db,
                session_id,
                agent_instance_id,
                now_ms,
                begun.into_iter().map(|(row, _)| row).collect(),
                target,
                before,
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
            target_workspace_lease_id: request.target_workspace_lease_id,
            expected_target_workspace_lease_revision: request
                .expected_target_workspace_lease_revision,
        })
    })();
    let target_spec = match prepared {
        Ok(spec) => spec,
        Err(error) => {
            reverse_or_record_terminal_failure(
                db,
                session_id,
                agent_instance_id,
                now_ms,
                &begun,
                target,
                before,
                &applied,
                &composed.diff,
            )
            .await?;
            store.finish_integration_journal(journal)?;
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
        .integrate_task_artifacts(
            session_id,
            agent_instance_id,
            expected,
            target_spec,
            crate::workspace_lease::now_unix_ms(),
        )
        .await
    {
        Ok(Some(rows)) => rows,
        Ok(None) => {
            reverse_or_record_terminal_failure(
                db,
                session_id,
                agent_instance_id,
                now_ms,
                &begun,
                target,
                before,
                &applied,
                &composed.diff,
            )
            .await?;
            store.finish_integration_journal(journal)?;
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
                "atomic integration CAS failed".into(),
            )
            .await;
        }
        Err(error) => {
            reverse_or_record_terminal_failure(
                db,
                session_id,
                agent_instance_id,
                now_ms,
                &begun,
                target,
                before,
                &applied,
                &composed.diff,
            )
            .await?;
            store.finish_integration_journal(journal)?;
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
                error.to_string(),
            )
            .await;
        }
    };

    store.finish_integration_journal(journal)?;
    Ok(IntegrationResult::Integrated {
        artifacts: integrated,
        private_ref,
    })
}

/// Build only the authority-bearing portion of an integration target for the
/// final pre-apply revalidation. The receipt fields are deliberately dummy
/// values: `integration_target_is_live` reads only the exact workspace lease
/// and write-scope predicates, while the post-apply transaction records the
/// real receipt.
fn effect_boundary_authority(
    request: &IntegrationRequest,
    target: &Path,
) -> Result<IntegrationTarget> {
    Ok(IntegrationTarget {
        target_canonical_repository_id: receipt::repository_id(target)?,
        target_canonical_root: target.to_string_lossy().into_owned(),
        target_head_digest: WorkspaceDigest::of(b"effect-boundary"),
        target_ref_digest: WorkspaceDigest::of(b"effect-boundary"),
        target_index_digest: WorkspaceDigest::of(b"effect-boundary"),
        changed_path_manifest_digest: WorkspaceDigest::of(b"effect-boundary"),
        target_write_scope_lease_id: request.target_write_scope_lease_id,
        expected_target_generation: request.expected_target_generation,
        expected_target_revision: request.expected_target_revision,
        target_workspace_lease_id: request.target_workspace_lease_id,
        expected_target_workspace_lease_revision: request.expected_target_workspace_lease_revision,
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
    // Keep independently composed pieces instead of handing the whole
    // accumulator to a specialist.  Otherwise A,C,B (where A/B overlap and
    // C is disjoint) asks the specialist to resolve A+C against B and loses
    // the durable A/B handoff identity or silently drops C.
    let mut pieces = vec![(begun[0].1.clone(), BTreeSet::from([begun[0].0.artifact_id]))];
    for (row, next) in begun.iter().skip(1) {
        if let Some(index) = pieces
            .iter()
            .position(|(piece, _)| paths_overlap(piece, next))
        {
            let Some(specialist) = specialist else {
                return Err(ConflictSpecialistVerdict::Unresolved);
            };
            let (left, mut left_contributors) = pieces.remove(index);
            let verdict = specialist.resolve(&left, next);
            let resolved = specialist
                .compose(&left, next, verdict)
                .map_err(|_| verdict)?;
            match verdict {
                ConflictSpecialistVerdict::Combined => {
                    left_contributors.insert(row.artifact_id);
                }
                ConflictSpecialistVerdict::ChooseLeft => {}
                ConflictSpecialistVerdict::ChooseRight => {
                    left_contributors.clear();
                    left_contributors.insert(row.artifact_id);
                }
                ConflictSpecialistVerdict::Unresolved => unreachable!(),
            }
            pieces.insert(index, (resolved, left_contributors));
        } else {
            pieces.push((next.clone(), BTreeSet::from([row.artifact_id])));
        }
    }
    let mut acc = UncommittedPatch {
        diff: String::new(),
        touched_paths: Vec::new(),
        untracked_paths: Vec::new(),
    };
    let mut contributors = BTreeSet::new();
    for (piece, piece_contributors) in pieces {
        acc = concatenate(&acc, &piece);
        contributors.extend(piece_contributors);
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

/// Roll back only the exact state produced by this integration.  A full
/// receipt check rejects external drift before reverse application, and the
/// postcondition proves Git restored the exact pre-apply state (including
/// modes, symlinks, index, and untracked paths).  The caller retains the
/// journal on every failure for recovery; no handwritten file restoration is
/// safe here.
async fn reverse_or_record_terminal_failure(
    db: &Db,
    session: Uuid,
    agent: Uuid,
    now_ms: i64,
    begun: &[(TaskArtifactRow, UncommittedPatch)],
    target: &Path,
    before: &ByteIdenticalReceipt,
    applied: &ByteIdenticalReceipt,
    diff: &str,
) -> Result<()> {
    let live = git::byte_identical_receipt(target)
        .context("capturing receipt before integration rollback")?;
    if &live != applied {
        bail!(
            "refusing integration rollback after external target drift; journal retained for recovery"
        );
    }
    if let Err(rollback) = git::reverse_uncommitted_patch(target, diff) {
        for (row, _) in begun {
            match db
                .finish_task_artifact(
                    session,
                    agent,
                    row.artifact_id,
                    row.revision,
                    TaskArtifactState::Failed,
                    now_ms,
                )
                .await?
            {
                ArtifactCasOutcome::Transitioned(_) | ArtifactCasOutcome::AlreadyTerminal(_) => {}
                ArtifactCasOutcome::RevisionConflict => bail!(
                    "artifact `{}` revision changed while recording rollback failure",
                    row.artifact_id
                ),
            }
        }
        return Err(rollback).context(
            "integration rollback failed; artifacts were marked failed and the journal was retained",
        );
    }
    let restored = git::byte_identical_receipt(target)
        .context("capturing receipt after integration rollback")?;
    if &restored != before {
        bail!(
            "integration reverse patch did not restore the exact pre-apply receipt; journal retained for recovery"
        );
    }
    Ok(())
}

async fn abort_cancel(
    db: &Db,
    session: Uuid,
    agent: Uuid,
    now_ms: i64,
    begun: Vec<(TaskArtifactRow, UncommittedPatch)>,
    target: &Path,
    before: &ByteIdenticalReceipt,
) -> Result<IntegrationResult> {
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
    message: String,
) -> Result<IntegrationResult> {
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
