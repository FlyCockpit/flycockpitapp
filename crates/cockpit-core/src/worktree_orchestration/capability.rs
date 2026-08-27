//! Optional orchestration capability: edit in place, fan out, merge, apply.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::db::Db;
use crate::db::workspace_lease_artifacts::{
    NewWorkspaceLease, TaskArtifactState, WorkspaceDigest, WorkspaceLeaseKind, WorkspaceLeaseRow,
};
use crate::db::write_scope_leases::WriteScopeLeaseRow;
use crate::git;
use crate::locks::LockManager;
use crate::workspace_lease::{self, WorkspaceLease, WorkspaceLeaseOps, now_unix_ms};

use super::artifact::{self, ArtifactStore, ParentVisibleArtifact, ProducedArtifact};
use super::conflict::ConflictSpecialist;
use super::integration::{self, IntegrationMode, IntegrationRequest, IntegrationResult};
use super::lifecycle;
use super::receipt::{self, WorkspaceReceipt};
use super::validation::CandidateValidation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrchestrationAction {
    EditInPlace,
    FanOut,
    ProduceArtifact,
    MergeSelected,
    ApplyUncommitted,
}

impl OrchestrationAction {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "edit_in_place" => Ok(Self::EditInPlace),
            "fan_out" => Ok(Self::FanOut),
            "produce_artifact" => Ok(Self::ProduceArtifact),
            "merge_selected" => Ok(Self::MergeSelected),
            "apply_uncommitted" => Ok(Self::ApplyUncommitted),
            other => bail!("unknown orchestration action `{other}`"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EditInPlace => "edit_in_place",
            Self::FanOut => "fan_out",
            Self::ProduceArtifact => "produce_artifact",
            Self::MergeSelected => "merge_selected",
            Self::ApplyUncommitted => "apply_uncommitted",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FanOutSpec {
    pub label: String,
}

#[derive(Debug, Clone)]
pub struct ManagedChildWorktree {
    pub label: String,
    pub lease: WorkspaceLeaseRow,
    pub path: PathBuf,
    pub base_receipt: WorkspaceReceipt,
}

#[derive(Debug, Clone)]
pub struct DirectEditSession {
    pub started_at_unix_ms: i64,
    pub cancelled: bool,
}

#[derive(Debug, Clone)]
pub struct OrchestrationCapability;

pub struct WorktreeOrchestrator {
    db: Db,
    locks: Arc<LockManager>,
    state_dir: PathBuf,
    session_id: Uuid,
    agent_instance_id: Uuid,
    lock_identity: String,
    primary_repo: PathBuf,
    write_scope_lease_id: Uuid,
    write_scope_generation: u64,
    write_scope_revision: u64,
    store: ArtifactStore,
    cancel: CancellationToken,
    specialist: Option<ConflictSpecialist>,
    pub validation: CandidateValidation,
    edit_in_place: Option<DirectEditSession>,
    children: Vec<ManagedChildWorktree>,
}

pub struct OrchestratorInit {
    pub db: Db,
    pub locks: Arc<LockManager>,
    pub state_dir: PathBuf,
    pub session_id: Uuid,
    pub agent_instance_id: Uuid,
    pub lock_identity: String,
    pub primary_repo: PathBuf,
    pub write_scope_lease_id: Uuid,
    pub write_scope_generation: u64,
    pub write_scope_revision: u64,
}

impl WorktreeOrchestrator {
    pub fn new(init: OrchestratorInit) -> Result<Self> {
        let primary_repo = git::resolve_git_path(&init.primary_repo)?;
        let validation = CandidateValidation::for_primary(&primary_repo);
        Ok(Self {
            store: ArtifactStore::new(&init.state_dir),
            state_dir: init.state_dir,
            db: init.db,
            locks: init.locks,
            session_id: init.session_id,
            agent_instance_id: init.agent_instance_id,
            lock_identity: init.lock_identity,
            write_scope_lease_id: init.write_scope_lease_id,
            write_scope_generation: init.write_scope_generation,
            write_scope_revision: init.write_scope_revision,
            cancel: CancellationToken::new(),
            specialist: None,
            edit_in_place: None,
            children: Vec::new(),
            primary_repo,
            validation,
        })
    }

    pub fn with_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel = cancel;
        self
    }

    pub fn with_specialist(mut self, specialist: ConflictSpecialist) -> Self {
        self.specialist = Some(specialist);
        self
    }

    pub fn primary_repo(&self) -> &Path {
        &self.primary_repo
    }

    pub fn store(&self) -> &ArtifactStore {
        &self.store
    }

    pub fn children(&self) -> &[ManagedChildWorktree] {
        &self.children
    }

    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// Direct current-worktree editing is not artifact integration. Cancelling
    /// it preserves already-visible edits.
    pub fn edit_in_place(&mut self) -> DirectEditSession {
        let session = DirectEditSession {
            started_at_unix_ms: now_unix_ms(),
            cancelled: false,
        };
        self.edit_in_place = Some(session.clone());
        session
    }

    pub fn cancel_edit_in_place(&mut self) -> Result<DirectEditSession> {
        let Some(mut session) = self.edit_in_place.take() else {
            bail!("no in-place edit is active");
        };
        session.cancelled = true;
        Ok(session)
    }

    pub async fn fan_out(
        &mut self,
        specs: Vec<FanOutSpec>,
        now_ms: i64,
    ) -> Result<Vec<ManagedChildWorktree>> {
        let worktrees = self.state_dir.join("worktrees");
        std::fs::create_dir_all(&worktrees)
            .with_context(|| format!("creating `{}`", worktrees.display()))?;
        let base = git::head_sha(&self.primary_repo)?;
        let repo_id = receipt::repository_id(&self.primary_repo)?;
        let base_receipt = receipt::capture_workspace_receipt(&self.primary_repo)?;
        let mut created = Vec::new();
        for spec in specs {
            let lease_id = Uuid::new_v4();
            let path = workspace_lease::managed_worktree_path(&self.state_dir, lease_id);
            git::assert_worktree_destination_under(&worktrees, &path)?;
            let scope = Uuid::new_v4();
            let root = path.to_string_lossy().into_owned();
            self.db
                .insert_write_scope_lease(WriteScopeLeaseRow {
                    lease_id: scope,
                    parent_lease_id: Some(self.write_scope_lease_id),
                    session_id: self.session_id,
                    task_id: None,
                    scope_path: root.clone(),
                    generation: 1,
                    state: "active".into(),
                    owner_id: self.agent_instance_id.to_string(),
                    version: 0,
                    created_at_wall_ms: now_ms,
                    updated_at_wall_ms: now_ms,
                    released_at_wall_ms: None,
                })
                .await
                .context("inserting child write-scope lease")?;
            let row = self
                .db
                .create_workspace_lease(
                    NewWorkspaceLease {
                        session_id: self.session_id,
                        agent_instance_id: self.agent_instance_id,
                        write_scope_lease_id: scope,
                        canonical_repository_id: repo_id.clone(),
                        canonical_root: root,
                        kind: WorkspaceLeaseKind::ManagedWorktree,
                        allowed_ops: WorkspaceLeaseOps::for_coding().to_bits(),
                        base_sha_digest: base_receipt.head_digest.clone(),
                        base_ref_digest: base_receipt.ref_digest.clone(),
                        managed_path: path.to_string_lossy().into_owned(),
                        private_ref_digest: WorkspaceDigest::of(format!(
                            "cockpit-lease/{lease_id}"
                        )),
                        expires_at_unix_ms: now_ms.saturating_add(24 * 60 * 60 * 1000),
                    },
                    now_ms,
                )
                .await
                .context("creating managed worktree lease")?;
            if let Err(error) = self
                .store
                .write_fanout_receipt(row.workspace_lease_id, &base_receipt)
            {
                let _ = self
                    .db
                    .mark_workspace_lease_uncertain(
                        self.session_id,
                        self.agent_instance_id,
                        row.workspace_lease_id,
                        row.revision,
                        crate::db::workspace_lease_artifacts::WorkspaceLeaseTerminalReason::RestartUncertain,
                        now_ms,
                    )
                    .await;
                return Err(error).context("persisting managed-child pre-fan-out receipt");
            }
            // Publish authority before the filesystem object. If checkout
            // fails or the host crashes, recovery sees a durable lease and
            // marks the missing path uncertain instead of stranding an
            // unowned linked worktree.
            // A managed tree has a private branch as part of its durable
            // identity. Detached worktrees cannot satisfy recovery's
            // identity proof and must never be issued here.
            let branch = format!("cockpit-lease/{lease_id}");
            if let Err(error) = git::worktree_add(&self.primary_repo, &path, &branch, &base) {
                let _ = self
                    .db
                    .mark_workspace_lease_uncertain(
                        self.session_id,
                        self.agent_instance_id,
                        row.workspace_lease_id,
                        row.revision,
                        crate::db::workspace_lease_artifacts::WorkspaceLeaseTerminalReason::RestartUncertain,
                        now_ms,
                    )
                    .await;
                return Err(error).context("creating managed child worktree");
            }
            created.push(ManagedChildWorktree {
                label: spec.label,
                lease: row,
                path,
                base_receipt: base_receipt.clone(),
            });
        }
        self.children.extend(created.iter().cloned());
        Ok(created)
    }

    pub async fn produce_from_child(
        &self,
        child: &ManagedChildWorktree,
        now_ms: i64,
        validation: WorkspaceDigest,
    ) -> Result<ProducedArtifact> {
        let receipt = self.store.fanout_receipt(child.lease.workspace_lease_id)?;
        artifact::produce_artifact(
            &self.db,
            &self.store,
            &child.path,
            child.lease.workspace_lease_id,
            self.session_id,
            self.agent_instance_id,
            now_ms,
            validation,
            Some(&receipt),
        )
        .await
    }

    pub async fn apply_uncommitted(
        &self,
        artifact_ids: Vec<Uuid>,
        now_ms: i64,
    ) -> Result<IntegrationResult> {
        self.integrate(artifact_ids, IntegrationMode::ApplyUncommitted, now_ms)
            .await
    }

    pub async fn merge_selected(
        &self,
        artifact_ids: Vec<Uuid>,
        now_ms: i64,
    ) -> Result<IntegrationResult> {
        self.integrate(artifact_ids, IntegrationMode::OrderedMerge, now_ms)
            .await
    }

    async fn integrate(
        &self,
        artifact_ids: Vec<Uuid>,
        mode: IntegrationMode,
        now_ms: i64,
    ) -> Result<IntegrationResult> {
        let request = IntegrationRequest {
            artifact_ids,
            mode,
            target: self.primary_repo.clone(),
            target_write_scope_lease_id: self.write_scope_lease_id,
            expected_target_generation: self.write_scope_generation,
            expected_target_revision: self.write_scope_revision,
        };
        integration::integrate_artifacts(
            &self.db,
            &self.store,
            &self.locks,
            &self.lock_identity,
            self.session_id,
            self.agent_instance_id,
            now_ms,
            request,
            self.specialist.as_ref(),
            &self.cancel,
        )
        .await
    }

    pub async fn surface_for_parent(&self) -> Result<Vec<ParentVisibleArtifact>> {
        let visible = artifact::surface_for_parent(&self.db, &self.store, self.session_id).await?;
        artifact::assert_no_transcripts(&visible)?;
        Ok(visible)
    }

    pub async fn pin_child(
        &self,
        child: &ManagedChildWorktree,
        now_ms: i64,
    ) -> Result<WorkspaceLeaseRow> {
        lifecycle::pin_managed_worktree(
            &self.db,
            self.session_id,
            self.agent_instance_id,
            child.lease.workspace_lease_id,
            child.lease.revision,
            now_ms,
        )
        .await
    }

    pub async fn cleanup_child(
        &self,
        child: &ManagedChildWorktree,
        now_ms: i64,
    ) -> Result<lifecycle::CleanupOutcome> {
        lifecycle::cleanup_managed_worktree(
            &self.db,
            self.session_id,
            self.agent_instance_id,
            child.lease.workspace_lease_id,
            child.lease.revision,
            now_ms,
            &self.primary_repo,
        )
        .await
    }

    pub async fn recover(&self, now_ms: i64) -> Result<Vec<WorkspaceLeaseRow>> {
        self.store
            .reconcile_integration_journals(&self.db, self.session_id, now_ms)
            .await?;
        lifecycle::recover_managed_worktrees(&self.db, self.session_id, now_ms).await
    }

    pub fn conflict_specialist_for(&self, lease: WorkspaceLease) -> ConflictSpecialist {
        ConflictSpecialist::bounded_by(lease)
    }

    /// Issue a short-lived, read-only integration lease for a conflict
    /// specialist.  It is distinct from the parent's primary lease: the
    /// specialist is handed only left/right patches and may return only its
    /// verdict (and a replacement patch), never target-write authority.
    pub async fn issue_conflict_specialist(&self, now_ms: i64) -> Result<ConflictSpecialist> {
        let root = receipt::canonical_root(&self.primary_repo)?;
        let scope_id = Uuid::new_v4();
        self.db
            .insert_write_scope_lease(WriteScopeLeaseRow {
                lease_id: scope_id,
                parent_lease_id: Some(self.write_scope_lease_id),
                session_id: self.session_id,
                task_id: None,
                scope_path: root.clone(),
                generation: 1,
                state: "active".into(),
                owner_id: self.agent_instance_id.to_string(),
                version: 0,
                created_at_wall_ms: now_ms,
                updated_at_wall_ms: now_ms,
                released_at_wall_ms: None,
            })
            .await
            .context("creating conflict-specialist integration scope")?;
        let receipt = receipt::capture_workspace_receipt(&self.primary_repo)?;
        let row = self
            .db
            .create_workspace_lease(
                NewWorkspaceLease {
                    session_id: self.session_id,
                    agent_instance_id: self.agent_instance_id,
                    write_scope_lease_id: scope_id,
                    canonical_repository_id: receipt::repository_id(&self.primary_repo)?,
                    canonical_root: root,
                    kind: WorkspaceLeaseKind::SameRoot,
                    allowed_ops: WorkspaceLeaseOps {
                        read: true,
                        write: false,
                        execute: false,
                        computer: false,
                    }
                    .to_bits(),
                    base_sha_digest: receipt.head_digest,
                    base_ref_digest: receipt.ref_digest,
                    managed_path: String::new(),
                    private_ref_digest: WorkspaceDigest::of(format!(
                        "cockpit-conflict-specialist-{}",
                        Uuid::new_v4()
                    )),
                    expires_at_unix_ms: now_ms.saturating_add(5 * 60 * 1000),
                },
                now_ms,
            )
            .await
            .context("creating bounded conflict-specialist integration lease")?;
        Ok(ConflictSpecialist::bounded_by(WorkspaceLease::from_row(
            &row,
        )?))
    }

    pub fn coding_ops() -> WorkspaceLeaseOps {
        WorkspaceLeaseOps::for_coding()
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    pub fn agent_instance_id(&self) -> Uuid {
        self.agent_instance_id
    }
}

pub fn no_user_visible_commit(before: u64, after: u64) -> Result<()> {
    if before != after {
        bail!("orchestration created a user-visible commit ({before} -> {after})");
    }
    Ok(())
}

pub fn assert_not_force_removing(source: &str) -> Result<()> {
    if source.contains("worktree_remove(") && source.contains("--force") {
        // The capability module must not call the forced helper.
        if source.contains("git::worktree_remove(") {
            bail!("orchestration must not force-remove a worktree");
        }
    }
    Ok(())
}

pub fn artifact_is_terminal(state: TaskArtifactState) -> bool {
    state.is_terminal()
}
