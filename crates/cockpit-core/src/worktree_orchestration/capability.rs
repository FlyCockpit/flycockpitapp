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
use super::conflict::{ConflictSpecialist, ConflictSpecialistRequest, ConflictSpecialistVerdict};
use super::integration::{self, IntegrationMode, IntegrationRequest, IntegrationResult};
use super::lifecycle;
use super::receipt::{self, WorkspaceReceipt};
use super::validation::CandidateValidation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrchestrationAction {
    EditInPlace,
    SurfaceArtifacts,
    FanOut,
    ProduceArtifact,
    RequestConflictSpecialist,
    InspectConflictRequest,
    SubmitConflictResolution,
    MergeSelected,
    ApplyUncommitted,
}

impl OrchestrationAction {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "edit_in_place" => Ok(Self::EditInPlace),
            "surface_artifacts" => Ok(Self::SurfaceArtifacts),
            "fan_out" => Ok(Self::FanOut),
            "produce_artifact" => Ok(Self::ProduceArtifact),
            "request_conflict_specialist" => Ok(Self::RequestConflictSpecialist),
            "inspect_conflict_request" => Ok(Self::InspectConflictRequest),
            "submit_conflict_resolution" => Ok(Self::SubmitConflictResolution),
            "merge_selected" => Ok(Self::MergeSelected),
            "apply_uncommitted" => Ok(Self::ApplyUncommitted),
            other => bail!("unknown orchestration action `{other}`"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EditInPlace => "edit_in_place",
            Self::SurfaceArtifacts => "surface_artifacts",
            Self::FanOut => "fan_out",
            Self::ProduceArtifact => "produce_artifact",
            Self::RequestConflictSpecialist => "request_conflict_specialist",
            Self::InspectConflictRequest => "inspect_conflict_request",
            Self::SubmitConflictResolution => "submit_conflict_resolution",
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
    parent_workspace_lease_id: Uuid,
    parent_workspace_lease_revision: i64,
    write_scope_lease_id: Uuid,
    write_scope_generation: u64,
    write_scope_revision: u64,
    store: ArtifactStore,
    cancel: CancellationToken,
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
    /// The durable lease for the integration tree. Every child authority
    /// issued by this capability is a descendant of this lease.
    pub parent_workspace_lease_id: Uuid,
    pub parent_workspace_lease_revision: i64,
    pub write_scope_lease_id: Uuid,
    pub write_scope_generation: u64,
    pub write_scope_revision: u64,
}

impl WorktreeOrchestrator {
    pub fn new(init: OrchestratorInit) -> Result<Self> {
        let primary_repo = git::resolve_git_path(&init.primary_repo)?;
        let validation = CandidateValidation::for_primary(&primary_repo).with_locks(
            init.locks.clone(),
            init.lock_identity.clone(),
            init.session_id,
        );
        Ok(Self {
            store: ArtifactStore::new(&init.state_dir),
            state_dir: init.state_dir,
            db: init.db,
            locks: init.locks,
            session_id: init.session_id,
            agent_instance_id: init.agent_instance_id,
            lock_identity: init.lock_identity,
            parent_workspace_lease_id: init.parent_workspace_lease_id,
            parent_workspace_lease_revision: init.parent_workspace_lease_revision,
            write_scope_lease_id: init.write_scope_lease_id,
            write_scope_generation: init.write_scope_generation,
            write_scope_revision: init.write_scope_revision,
            cancel: CancellationToken::new(),
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

    pub fn primary_repo(&self) -> &Path {
        &self.primary_repo
    }

    pub fn store(&self) -> &ArtifactStore {
        &self.store
    }

    pub fn lock_manager(&self) -> &Arc<LockManager> {
        &self.locks
    }

    pub fn lock_identity(&self) -> &str {
        &self.lock_identity
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
        let repo_id = receipt::repository_id(&self.primary_repo)?;
        let base_receipt = receipt::capture_workspace_receipt(&self.primary_repo)?;
        let base = base_receipt.head.clone();
        let parent = self
            .db
            .workspace_lease(
                self.session_id,
                self.agent_instance_id,
                self.parent_workspace_lease_id,
            )
            .await?
            .context("parent workspace lease is unavailable for fan-out")?;
        if parent.revision != self.parent_workspace_lease_revision {
            bail!("parent workspace lease changed before fan-out");
        }
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
                .create_host_issued_child_workspace_lease(
                    NewWorkspaceLease {
                        session_id: self.session_id,
                        agent_instance_id: self.agent_instance_id,
                        write_scope_lease_id: scope,
                        parent_workspace_lease_id: Some(self.parent_workspace_lease_id),
                        canonical_repository_id: repo_id.clone(),
                        canonical_root: root,
                        kind: WorkspaceLeaseKind::ManagedWorktree,
                        allowed_ops: WorkspaceLeaseOps::for_coding()
                            .intersect(WorkspaceLeaseOps::from_bits(parent.allowed_ops)?)
                            .to_bits(),
                        base_sha_digest: base_receipt.head_digest.clone(),
                        base_ref_digest: base_receipt.ref_digest.clone(),
                        managed_path: path.to_string_lossy().into_owned(),
                        private_ref_digest: WorkspaceDigest::of(format!(
                            "cockpit-lease/{lease_id}"
                        )),
                        expires_at_unix_ms: now_ms.saturating_add(24 * 60 * 60 * 1000),
                    },
                    lease_id,
                    now_ms,
                )
                .await
                .context("creating managed worktree lease")?;
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
            // The target receipt is taken before the fan-out.  The child
            // receipt is taken after checkout because linked worktrees have
            // their own clean index; comparing it to unrelated staged primary
            // changes would incorrectly reject a valid artifact.
            let child_receipt = match receipt::capture_workspace_receipt(&path) {
                Ok(receipt) => receipt,
                Err(error) => {
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
                    return Err(error).context("capturing managed-child checkout receipt");
                }
            };
            // A child is meaningful only if its checkout is the exact HEAD
            // serialized in the target receipt.  Refuse a moving fan-out
            // rather than publishing a receipt whose recorded base no longer
            // names the child's actual checkout.
            if child_receipt.head != base
                || child_receipt.head_digest != base_receipt.head_digest
                || receipt::capture_workspace_receipt(&self.primary_repo)? != base_receipt
            {
                let _ = self.db.mark_workspace_lease_uncertain(
                    self.session_id,
                    self.agent_instance_id,
                    row.workspace_lease_id,
                    row.revision,
                    crate::db::workspace_lease_artifacts::WorkspaceLeaseTerminalReason::RestartUncertain,
                    now_ms,
                ).await;
                bail!(
                    "fan-out base receipt changed or child checkout did not match its recorded HEAD"
                );
            }
            if let Err(error) = self.store.write_fanout_receipts(
                row.workspace_lease_id,
                &base_receipt,
                &child_receipt,
            ) {
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
                return Err(error).context("persisting managed-child pre-edit receipts");
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
        let receipts = self.store.fanout_receipts(child.lease.workspace_lease_id)?;
        artifact::produce_artifact(
            &self.db,
            &self.store,
            &child.path,
            child.lease.workspace_lease_id,
            self.session_id,
            self.agent_instance_id,
            now_ms,
            validation,
            Some(&receipts),
        )
        .await
    }

    pub async fn apply_uncommitted(
        &self,
        artifact_ids: Vec<Uuid>,
        now_ms: i64,
    ) -> Result<IntegrationResult> {
        self.integrate(
            artifact_ids,
            IntegrationMode::ApplyUncommitted,
            None,
            now_ms,
        )
        .await
    }

    pub async fn merge_selected(
        &self,
        artifact_ids: Vec<Uuid>,
        now_ms: i64,
    ) -> Result<IntegrationResult> {
        self.integrate(artifact_ids, IntegrationMode::OrderedMerge, None, now_ms)
            .await
    }

    /// The parent explicitly opts into a completed specialist result.  The
    /// result is loaded from the durable handoff, never reconstructed from a
    /// caller-supplied patch.
    pub async fn integrate_with_conflict_specialist(
        &self,
        artifact_ids: Vec<Uuid>,
        mode: IntegrationMode,
        specialist_lease_id: Uuid,
        parent_accepts_result: bool,
        now_ms: i64,
    ) -> Result<IntegrationResult> {
        if !parent_accepts_result {
            return self.integrate(artifact_ids, mode, None, now_ms).await;
        }
        let row = self
            .db
            .workspace_lease_for_conflict_handoff(
                self.session_id,
                self.agent_instance_id,
                specialist_lease_id,
                self.parent_workspace_lease_id,
                self.write_scope_lease_id,
                now_unix_ms(),
            )
            .await?
            .context("conflict-specialist lease is unavailable")?;
        let lease = WorkspaceLease::from_row(&row)?;
        if !lease.is_durable_host_issued_managed_worktree() {
            bail!("conflict-specialist lease is not a bounded host-issued managed worktree");
        }
        let request = self.store.conflict_request(specialist_lease_id)?;
        let resolution = self.store.conflict_resolution(specialist_lease_id)?;
        let specialist = ConflictSpecialist::with_handoff(lease, request, resolution)?;
        self.integrate(artifact_ids, mode, Some(&specialist), now_ms)
            .await
    }

    async fn integrate(
        &self,
        artifact_ids: Vec<Uuid>,
        mode: IntegrationMode,
        specialist: Option<&ConflictSpecialist>,
        now_ms: i64,
    ) -> Result<IntegrationResult> {
        let request = IntegrationRequest {
            artifact_ids,
            mode,
            target: self.primary_repo.clone(),
            target_write_scope_lease_id: self.write_scope_lease_id,
            expected_target_generation: self.write_scope_generation,
            expected_target_revision: self.write_scope_revision,
            target_workspace_lease_id: self.parent_workspace_lease_id,
            expected_target_workspace_lease_revision: self.parent_workspace_lease_revision,
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
            specialist,
            &self.cancel,
        )
        .await
    }

    pub async fn surface_for_parent(&self) -> Result<Vec<ParentVisibleArtifact>> {
        let visible = artifact::surface_for_parent(
            &self.db,
            &self.store,
            self.session_id,
            self.agent_instance_id,
        )
        .await?;
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
            Some(&self.cancel),
        )
        .await
    }

    pub async fn recover(&self, now_ms: i64) -> Result<Vec<WorkspaceLeaseRow>> {
        self.store
            .reconcile_integration_journals(&self.db, self.session_id, now_ms)
            .await?;
        lifecycle::recover_managed_worktrees(&self.db, self.session_id, now_ms).await
    }

    /// Allocate a bounded child and publish the exact ordered artifact pair it
    /// may consider. The host launches the child with the returned durable
    /// lease id; the child can inspect this handoff and submit only a closed
    /// verdict plus an isolated-worktree-derived patch.
    pub async fn request_conflict_specialist(
        &self,
        left: Uuid,
        right: Uuid,
        now_ms: i64,
    ) -> Result<ConflictSpecialistRequest> {
        let left = self
            .db
            .task_artifact(self.session_id, self.agent_instance_id, left)
            .await?
            .context("left conflict artifact is not owned")?;
        let right = self
            .db
            .task_artifact(self.session_id, self.agent_instance_id, right)
            .await?
            .context("right conflict artifact is not owned")?;
        let specialist = self.issue_conflict_specialist(now_ms).await?;
        let request = ConflictSpecialistRequest {
            lease_id: specialist.lease().id,
            left: self.store.load_patch(&left)?,
            right: self.store.load_patch(&right)?,
        };
        self.store.write_conflict_request(&request)?;
        Ok(request)
    }

    pub fn inspect_conflict_request(&self, lease_id: Uuid) -> Result<ConflictSpecialistRequest> {
        self.store.conflict_request(lease_id)
    }

    pub fn submit_conflict_resolution(
        &self,
        specialist: ConflictSpecialist,
        verdict: ConflictSpecialistVerdict,
    ) -> Result<()> {
        let request = self.store.conflict_request(specialist.lease().id)?;
        let resolution = specialist.capture_resolution(&request, verdict)?;
        self.store
            .write_conflict_resolution(specialist.lease().id, &resolution)
    }

    /// Issue a short-lived isolated worktree for a conflict specialist. Its
    /// write authority ends at that worktree so it can derive a combined
    /// patch, never mutate the integration target.
    pub async fn issue_conflict_specialist(&self, now_ms: i64) -> Result<ConflictSpecialist> {
        let worktrees = self.state_dir.join("worktrees");
        std::fs::create_dir_all(&worktrees)
            .with_context(|| format!("creating `{}`", worktrees.display()))?;
        let lease_id = Uuid::new_v4();
        let path = workspace_lease::managed_worktree_path(&self.state_dir, lease_id);
        git::assert_worktree_destination_under(&worktrees, &path)?;
        let scope_id = Uuid::new_v4();
        self.db
            .insert_write_scope_lease(WriteScopeLeaseRow {
                lease_id: scope_id,
                parent_lease_id: Some(self.write_scope_lease_id),
                session_id: self.session_id,
                task_id: None,
                scope_path: path.to_string_lossy().into_owned(),
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
            .create_host_issued_child_workspace_lease(
                NewWorkspaceLease {
                    session_id: self.session_id,
                    agent_instance_id: self.agent_instance_id,
                    write_scope_lease_id: scope_id,
                    parent_workspace_lease_id: Some(self.parent_workspace_lease_id),
                    canonical_repository_id: receipt::repository_id(&self.primary_repo)?,
                    canonical_root: path.to_string_lossy().into_owned(),
                    kind: WorkspaceLeaseKind::ManagedWorktree,
                    allowed_ops: WorkspaceLeaseOps {
                        read: true,
                        // The specialist may edit only its own isolated tree
                        // to derive a combined patch. It never receives the
                        // integration target lease or a publication path.
                        write: true,
                        execute: false,
                        computer: false,
                    }
                    .to_bits(),
                    base_sha_digest: receipt.head_digest,
                    base_ref_digest: receipt.ref_digest,
                    managed_path: path.to_string_lossy().into_owned(),
                    private_ref_digest: WorkspaceDigest::of(format!("cockpit-lease/{lease_id}")),
                    expires_at_unix_ms: now_ms.saturating_add(5 * 60 * 1000),
                },
                lease_id,
                now_ms,
            )
            .await
            .context("creating bounded conflict-specialist integration lease")?;
        let branch = format!("cockpit-lease/{lease_id}");
        if let Err(error) = git::worktree_add(
            &self.primary_repo,
            &path,
            &branch,
            &git::head_sha(&self.primary_repo)?,
        ) {
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
            return Err(error).context("creating isolated conflict-specialist worktree");
        }
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
    let forced = concat!("git::worktree", "_remove(");
    let force_flag = concat!("--", "force");
    if source.contains(forced) && source.contains(force_flag) {
        bail!("orchestration must not force-remove a worktree");
    }
    Ok(())
}

pub fn artifact_is_terminal(state: TaskArtifactState) -> bool {
    state.is_terminal()
}
