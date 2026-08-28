//! Host-issued workspace leases for bounded recursive delegation.
//!
//! A workspace lease is separate from a write-scope lease. It binds owner
//! lineage, repository identity, a canonical root, kind (`same_root`,
//! `subdirectory`, `managed_worktree`), the child's visibility root, the base
//! receipt/ref, allowed operations, and expiry/revocation. Durable recovery
//! state lives in `cockpit_db::db::workspace_lease_artifacts`; this module is
//! the runtime authority token consumed by vNext preflight, `task`, `ToolCtx`,
//! path checks, the shell sandbox, and computer-use gating.
//!
//! Managed worktrees are rooted at `<daemon-state>/worktrees/<lease-uuid>`.
//! Crash recovery marks a lease `uncertain` instead of deleting the path.
//! Revocation (expiry → grace, or an explicit host mark) blocks new starts
//! and releases writer grants; it never force-deletes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use uuid::Uuid;

use crate::agents::{DelegationTarget, EffectiveVnextGrant, ExecutionKind};
use crate::db::workspace_lease_artifacts::{
    LeaseCasOutcome, NewWorkspaceLease, WorkspaceDigest, WorkspaceLeaseKind as DbLeaseKind,
    WorkspaceLeaseRow, WorkspaceLeaseState, WorkspaceLeaseTerminalReason,
};

/// Runtime workspace-lease kind. Kept in lockstep with the SQL CHECK and
/// [`DbLeaseKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkspaceLeaseKind {
    SameRoot,
    Subdirectory,
    ManagedWorktree,
}

impl WorkspaceLeaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SameRoot => "same_root",
            Self::Subdirectory => "subdirectory",
            Self::ManagedWorktree => "managed_worktree",
        }
    }

    pub fn from_db(kind: DbLeaseKind) -> Self {
        match kind {
            DbLeaseKind::SameRoot => Self::SameRoot,
            DbLeaseKind::Subdirectory => Self::Subdirectory,
            DbLeaseKind::ManagedWorktree => Self::ManagedWorktree,
        }
    }

    pub fn to_db(self) -> DbLeaseKind {
        match self {
            Self::SameRoot => DbLeaseKind::SameRoot,
            Self::Subdirectory => DbLeaseKind::Subdirectory,
            Self::ManagedWorktree => DbLeaseKind::ManagedWorktree,
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        Ok(Self::from_db(DbLeaseKind::parse(value)?))
    }

    pub fn as_delegation_target(self) -> DelegationTarget {
        match self {
            Self::SameRoot => DelegationTarget::SameRoot,
            Self::Subdirectory => DelegationTarget::Subdirectory,
            Self::ManagedWorktree => DelegationTarget::ManagedWorktree,
        }
    }
}

/// Closed set of operations a live lease may grant. Intersection with the
/// parent's [`EffectiveVnextGrant`] can only clear bits, never set them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WorkspaceLeaseOps {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub computer: bool,
}

impl WorkspaceLeaseOps {
    const READ: u8 = 0b0001;
    const WRITE: u8 = 0b0010;
    const EXECUTE: u8 = 0b0100;
    const COMPUTER: u8 = 0b1000;

    pub fn to_bits(self) -> u8 {
        (if self.read { Self::READ } else { 0 })
            | (if self.write { Self::WRITE } else { 0 })
            | (if self.execute { Self::EXECUTE } else { 0 })
            | (if self.computer { Self::COMPUTER } else { 0 })
    }

    pub fn from_bits(bits: u8) -> Result<Self> {
        if bits > 0b1111 {
            bail!("workspace lease allowed_ops is outside the closed bit set");
        }
        Ok(Self {
            read: bits & Self::READ != 0,
            write: bits & Self::WRITE != 0,
            execute: bits & Self::EXECUTE != 0,
            computer: bits & Self::COMPUTER != 0,
        })
    }
    pub fn none() -> Self {
        Self {
            read: false,
            write: false,
            execute: false,
            computer: false,
        }
    }

    pub fn for_coding() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
            computer: false,
        }
    }

    pub fn for_computer() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
            computer: true,
        }
    }

    pub fn intersect(self, other: Self) -> Self {
        Self {
            read: self.read && other.read,
            write: self.write && other.write,
            execute: self.execute && other.execute,
            computer: self.computer && other.computer,
        }
    }

    /// Computer-use is a same-root desktop grant. A subtree or managed
    /// worktree cannot widen the child onto the host desktop.
    pub fn confined_to_kind(self, kind: WorkspaceLeaseKind) -> Self {
        match kind {
            WorkspaceLeaseKind::SameRoot => self,
            WorkspaceLeaseKind::Subdirectory | WorkspaceLeaseKind::ManagedWorktree => Self {
                computer: false,
                ..self
            },
        }
    }
}

/// Typed host-issued workspace lease. This is the authority token threaded
/// into vNext preflight and the child's [`crate::engine::tool::ToolCtx`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceLease {
    pub id: Uuid,
    pub session_id: Uuid,
    pub owner_agent_instance_id: Uuid,
    pub write_scope_lease_id: Uuid,
    pub parent_workspace_lease_id: Option<Uuid>,
    pub canonical_repository_id: String,
    pub canonical_root: PathBuf,
    pub kind: WorkspaceLeaseKind,
    pub visibility_root: PathBuf,
    pub base_sha_digest: WorkspaceDigest,
    pub base_ref_digest: WorkspaceDigest,
    pub managed_path: PathBuf,
    pub private_ref_digest: WorkspaceDigest,
    pub allowed_ops: WorkspaceLeaseOps,
    /// Only the daemon host may mint a durable lease.  This is carried into
    /// runtime admission so a UUID-shaped or test-only token can never stand
    /// in for a managed worktree authority.
    host_issued: bool,
    pub expires_at_unix_ms: i64,
    pub state: WorkspaceLeaseState,
    pub revision: i64,
}

impl WorkspaceLease {
    pub fn from_row(row: &WorkspaceLeaseRow) -> Result<Self> {
        let kind = WorkspaceLeaseKind::from_db(row.kind);
        let canonical_root = PathBuf::from(&row.canonical_root);
        let managed_path = PathBuf::from(&row.managed_path);
        let visibility_root = match kind {
            WorkspaceLeaseKind::SameRoot | WorkspaceLeaseKind::Subdirectory => {
                canonical_root.clone()
            }
            WorkspaceLeaseKind::ManagedWorktree => {
                if !managed_path.as_os_str().is_empty() {
                    managed_path.clone()
                } else {
                    canonical_root.clone()
                }
            }
        };
        Ok(Self {
            id: row.workspace_lease_id,
            session_id: row.session_id,
            owner_agent_instance_id: row.agent_instance_id,
            write_scope_lease_id: row.write_scope_lease_id,
            parent_workspace_lease_id: row.parent_workspace_lease_id,
            canonical_repository_id: row.canonical_repository_id.clone(),
            canonical_root,
            kind,
            visibility_root,
            base_sha_digest: row.base_sha_digest.clone(),
            base_ref_digest: row.base_ref_digest.clone(),
            managed_path,
            private_ref_digest: row.private_ref_digest.clone(),
            allowed_ops: WorkspaceLeaseOps::from_bits(row.allowed_ops)?.confined_to_kind(kind),
            host_issued: row.host_issued,
            expires_at_unix_ms: row.expires_at_unix_ms,
            state: row.state,
            revision: row.revision,
        })
    }

    /// Synthesize a preflight token without a durable row. Used when the
    /// parent grant already permits same-root or subdirectory by path, or in
    /// unit tests. Managed worktrees must still be host-issued (a real id and
    /// daemon-state path) before they grant authority.
    pub fn ephemeral(
        kind: WorkspaceLeaseKind,
        visibility_root: PathBuf,
        allowed_ops: WorkspaceLeaseOps,
        expires_at_unix_ms: i64,
    ) -> Self {
        let visibility_root = visibility_root;
        Self {
            id: Uuid::nil(),
            session_id: Uuid::nil(),
            owner_agent_instance_id: Uuid::nil(),
            write_scope_lease_id: Uuid::nil(),
            parent_workspace_lease_id: None,
            canonical_repository_id: "ephemeral".into(),
            canonical_root: visibility_root.clone(),
            kind,
            managed_path: visibility_root.clone(),
            private_ref_digest: WorkspaceDigest::of(b"ephemeral"),
            visibility_root,
            base_sha_digest: WorkspaceDigest::of(b"ephemeral"),
            base_ref_digest: WorkspaceDigest::of(b"ephemeral"),
            allowed_ops: allowed_ops.confined_to_kind(kind),
            host_issued: false,
            expires_at_unix_ms,
            state: WorkspaceLeaseState::Active,
            revision: 0,
        }
    }

    pub fn is_live(&self, now_ms: i64) -> bool {
        self.state == WorkspaceLeaseState::Active && self.expires_at_unix_ms > now_ms
    }

    pub fn is_revoked_or_expired(&self, now_ms: i64) -> bool {
        !self.is_live(now_ms)
    }

    /// Revalidate a durable token immediately before a native effect boundary.
    /// `ToolCtx` intentionally contains a cheap snapshot for confinement, but
    /// that snapshot cannot authorize a tool after another actor has expired
    /// or revoked its durable row. Ephemeral tokens are test/preflight-only;
    /// production tokens must have both a durable owner and a live ledger row.
    ///
    /// Wall-clock expiry is persisted here (Active→Grace) so host cleanup can
    /// settle the row without waiting for crash recovery.
    pub async fn revalidate_for_tools(&self, db: &crate::db::Db) -> Result<()> {
        if self.id.is_nil() {
            return Ok(());
        }
        expire_active_workspace_lease_if_due(db, self).await?;
        let row = db
            .workspace_lease_for_tools(
                self.session_id,
                self.owner_agent_instance_id,
                self.id,
                now_unix_ms(),
            )
            .await?
            .context("workspace lease is revoked, expired, or no longer owner-scoped")?;
        let durable = Self::from_row(&row)?;
        if durable.canonical_repository_id != self.canonical_repository_id
            || durable.canonical_root != self.canonical_root
            || durable.kind != self.kind
            || durable.visibility_root != self.visibility_root
            || durable.host_issued != self.host_issued
            || self.allowed_ops.intersect(durable.allowed_ops) != self.allowed_ops
        {
            bail!("workspace lease durable record no longer matches this tool context");
        }
        Ok(())
    }

    /// Managed worktrees are daemon-owned filesystem objects.  They must
    /// never be admitted from an ephemeral preflight token, even in tests or
    /// recovery code where a non-nil UUID is easy to synthesize.
    pub fn is_durable_host_issued_managed_worktree(&self) -> bool {
        self.kind == WorkspaceLeaseKind::ManagedWorktree && !self.id.is_nil() && self.host_issued
    }

    /// Test helper for the public grant seam: a non-nil, host-issued managed
    /// worktree token. Production minting remains `issue_*` / `from_row`.
    #[cfg(test)]
    pub fn host_issued_managed_worktree(
        id: Uuid,
        visibility_root: PathBuf,
        allowed_ops: WorkspaceLeaseOps,
        expires_at_unix_ms: i64,
    ) -> Self {
        Self {
            id,
            host_issued: true,
            ..Self::ephemeral(
                WorkspaceLeaseKind::ManagedWorktree,
                visibility_root,
                allowed_ops,
                expires_at_unix_ms,
            )
        }
    }

    pub fn allows_read(&self) -> bool {
        self.allowed_ops.read
    }

    pub fn allows_write(&self) -> bool {
        self.allowed_ops.write
    }

    pub fn allows_execute(&self) -> bool {
        self.allowed_ops.execute
    }

    pub fn allows_computer(&self) -> bool {
        self.allowed_ops.computer && self.kind == WorkspaceLeaseKind::SameRoot
    }

    pub fn as_delegation_target(&self) -> DelegationTarget {
        self.kind.as_delegation_target()
    }

    /// Syscall-effective containment: `path` is the visibility root or a
    /// descendant. Sibling managed worktrees and the primary repository are
    /// not implicitly readable.
    pub fn covers_path(&self, path: &Path) -> bool {
        cockpit_host::path_containment::contained_under(&self.visibility_root, path)
    }

    pub fn covers_cwd(&self, cwd: &Path) -> bool {
        let Ok(cwd) = cockpit_host::path_containment::effective_path(cwd) else {
            return false;
        };
        let Ok(root) = cockpit_host::path_containment::effective_path(&self.visibility_root) else {
            return false;
        };
        match self.kind {
            WorkspaceLeaseKind::SameRoot => cwd == root,
            WorkspaceLeaseKind::Subdirectory | WorkspaceLeaseKind::ManagedWorktree => {
                cwd == root || cockpit_host::path_containment::contained_under(&root, &cwd)
            }
        }
    }

    /// Durable identity check used at crash recovery. This verifies the
    /// recorded repository identity, base receipts, and private branch rather
    /// than accepting any Git worktree that happens to occupy the path. HEAD
    /// movement from in-lease work is allowed, but a replacement becomes
    /// uncertain and is never cleaned automatically.
    pub fn identity_matches_disk(&self) -> bool {
        let Ok(root) = cockpit_host::path_containment::effective_path(&self.visibility_root) else {
            return false;
        };
        if !root.is_dir() {
            return false;
        }
        let Some(worktree_root) = crate::git::find_worktree_root(&root) else {
            return false;
        };
        let Ok(worktree_root) = cockpit_host::path_containment::effective_path(&worktree_root)
        else {
            return false;
        };
        match self.kind {
            // A same-root or subtree lease deliberately records its visibility
            // root, which can be below the Git worktree root.  It must still
            // resolve inside that same worktree, never merely to a similarly
            // named repository elsewhere.
            WorkspaceLeaseKind::SameRoot | WorkspaceLeaseKind::Subdirectory
                if !cockpit_host::path_containment::contained_under(&worktree_root, &root) =>
            {
                return false;
            }
            // Managed worktrees are host-owned filesystem identities: their
            // leased root is the worktree root exactly, not an arbitrary
            // subdirectory within it.
            WorkspaceLeaseKind::ManagedWorktree if worktree_root != root => return false,
            _ => {}
        }
        let Ok(repository_id) = canonical_repository_identity(&worktree_root) else {
            return false;
        };
        if repository_id != self.canonical_repository_id {
            return false;
        }
        // The receipt hashes deliberately avoid persisting raw refs/SHAs.
        // Recompute against Git's complete durable object/ref lists to prove
        // that the recorded base still belongs to this repository.
        let Ok(commits) = crate::git::run_git_checked(&worktree_root, &["rev-list", "--all"])
        else {
            return false;
        };
        if !commits
            .lines()
            .any(|sha| WorkspaceDigest::of(sha.trim()) == self.base_sha_digest)
        {
            return false;
        }
        let Ok(refs) =
            crate::git::run_git_checked(&worktree_root, &["for-each-ref", "--format=%(refname)"])
        else {
            return false;
        };
        if !refs
            .lines()
            .any(|reference| WorkspaceDigest::of(reference.trim()) == self.base_ref_digest)
            && !commits
                .lines()
                .any(|sha| WorkspaceDigest::of(sha.trim()) == self.base_ref_digest)
        {
            return false;
        }
        if self.kind == WorkspaceLeaseKind::ManagedWorktree {
            let expected_branch = format!("cockpit-lease/{}", self.id);
            let Ok(branch) =
                crate::git::run_git_checked(&worktree_root, &["rev-parse", "--abbrev-ref", "HEAD"])
            else {
                return false;
            };
            return branch.trim() == expected_branch
                && WorkspaceDigest::of(&expected_branch) == self.private_ref_digest;
        }
        true
    }
}

/// `<daemon-state>/worktrees/<lease-uuid>`.
pub fn managed_worktree_path(state_dir: &Path, lease_id: Uuid) -> PathBuf {
    state_dir.join("worktrees").join(lease_id.to_string())
}

/// Live host-issued lease IDs for one background noninteractive job.
///
/// Outer spawn snapshots the first-level tokens. Nested Kind mints and
/// isolated harness mints taken *inside* that already-spawned task append
/// here so exits that never reach a child-future retire can still CAS the
/// row out of Active. Whole-job abort, delivered completion, and delivered
/// `Err` read this list. Pause `Drop` still leaves the rows Active.
pub type JobIssuedWorkspaceLeaseIds = Arc<Mutex<Vec<Option<String>>>>;

tokio::task_local! {
    static JOB_ISSUED_WORKSPACE_LEASE_IDS: JobIssuedWorkspaceLeaseIds;
}

pub fn new_job_issued_workspace_lease_ids(
    initial: Vec<Option<String>>,
) -> JobIssuedWorkspaceLeaseIds {
    Arc::new(Mutex::new(initial))
}

pub fn snapshot_job_issued_workspace_lease_ids(
    ids: &JobIssuedWorkspaceLeaseIds,
) -> Vec<Option<String>> {
    ids.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

pub async fn with_job_issued_workspace_lease_ids<F, T>(ids: JobIssuedWorkspaceLeaseIds, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    JOB_ISSUED_WORKSPACE_LEASE_IDS.scope(ids, fut).await
}

fn record_job_issued_workspace_lease_id(id: Uuid) {
    if id.is_nil() {
        return;
    }
    let _ = JOB_ISSUED_WORKSPACE_LEASE_IDS.try_with(|ids| {
        ids.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Some(id.to_string()));
    });
}

#[derive(Clone, Eq, PartialEq, Hash)]
struct InFlightHarnessLeaseKey {
    session_id: Uuid,
    owner_agent_instance_id: Uuid,
    tool_call_id: String,
}

fn in_flight_harness_leases() -> &'static Mutex<HashMap<InFlightHarnessLeaseKey, WorkspaceLease>> {
    static MAP: OnceLock<Mutex<HashMap<InFlightHarnessLeaseKey, WorkspaceLease>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

fn harness_in_flight_key(
    session_id: Uuid,
    owner_agent_instance_id: Uuid,
    tool_call_id: Option<&str>,
) -> InFlightHarnessLeaseKey {
    InFlightHarnessLeaseKey {
        session_id,
        owner_agent_instance_id,
        tool_call_id: tool_call_id.unwrap_or("").to_string(),
    }
}

/// Remember a harness-issued managed row for the dispatcher abandon hook.
/// Timeout/cancel drops `call` before the Ok/Err retire arms; `on_abandon`
/// takes this identity and leaves the row non-Active.
pub fn attach_in_flight_harness_lease(lease: &WorkspaceLease, tool_call_id: Option<&str>) {
    if lease.id.is_nil() {
        return;
    }
    in_flight_harness_leases()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(
            harness_in_flight_key(
                lease.session_id,
                lease.owner_agent_instance_id,
                tool_call_id,
            ),
            lease.clone(),
        );
}

pub fn detach_in_flight_harness_lease(
    session_id: Uuid,
    owner_agent_instance_id: Uuid,
    tool_call_id: Option<&str>,
) -> Option<WorkspaceLease> {
    in_flight_harness_leases()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&harness_in_flight_key(
            session_id,
            owner_agent_instance_id,
            tool_call_id,
        ))
}

pub async fn abandon_in_flight_harness_lease(
    db: &crate::db::Db,
    session_id: Uuid,
    owner_agent_instance_id: Uuid,
    tool_call_id: Option<&str>,
) -> Result<()> {
    let Some(lease) =
        detach_in_flight_harness_lease(session_id, owner_agent_instance_id, tool_call_id)
    else {
        return Ok(());
    };
    mark_harness_lease_uncertain(db, &lease).await
}

/// Issue a task workspace lease at the daemon boundary.
///
/// `task` may describe a desired containment kind, but it never supplies an
/// authority token.  This function is the only producer for those requests:
/// it derives the repository, root write-scope binding, receipts, operations,
/// expiry, and (for managed worktrees) destination from daemon state and the
/// already-live parent grant.  Callers must still run the normal child
/// definition/model/tool/depth/concurrency preflight before starting a child;
/// the resulting token is deliberately only an input to that intersection.
///
/// A managed destination is recorded before `git worktree add`.  A command
/// error is therefore uncertain rather than a reason to delete a possibly
/// created user-visible worktree.
pub async fn issue_task_workspace_lease(
    db: &crate::db::Db,
    session_id: Uuid,
    owner_agent_instance_id: Uuid,
    parent_grant: &EffectiveVnextGrant,
    parent_workspace_lease: Option<&WorkspaceLease>,
    parent_cwd: &Path,
    requested_child_cwd: Option<&Path>,
    kind: WorkspaceLeaseKind,
) -> Result<WorkspaceLease> {
    let delegation = parent_grant
        .delegation
        .as_ref()
        .context("parent effective vNext grant has no delegation authority")?;
    if !delegation.targets.contains(&kind.as_delegation_target()) {
        bail!(
            "parent grant does not permit workspace lease kind `{}`",
            kind.as_str()
        );
    }
    if let Some(parent) = parent_workspace_lease {
        parent
            .revalidate_for_tools(db)
            .await
            .context("revalidating parent workspace lease before child issuance")?;
    }

    let parent_cwd = cockpit_host::path_containment::effective_path(parent_cwd)
        .context("resolving parent cwd for workspace lease issuance")?;
    let repository = crate::git::find_worktree_root(&parent_cwd)
        .context("task workspace lease requires a git worktree")?;
    let repository = crate::git::resolve_git_path(&repository)?;
    let write_scope_lease_id = db
        .list_write_scope_leases_for_session(session_id)
        .await?
        .into_iter()
        .find(|lease| lease.parent_lease_id.is_none() && lease.state == "active")
        .map(|lease| lease.lease_id)
        .context("task workspace lease requires the daemon root write scope")?;

    let lease_id = Uuid::new_v4();
    let (canonical_root, managed_path) = match kind {
        WorkspaceLeaseKind::SameRoot => (parent_cwd.clone(), parent_cwd.clone()),
        WorkspaceLeaseKind::Subdirectory => {
            let child =
                requested_child_cwd.context("subdirectory workspace lease requires a child cwd")?;
            let child = cockpit_host::path_containment::effective_path(child)
                .context("resolving subdirectory workspace lease cwd")?;
            if child == parent_cwd
                || !cockpit_host::path_containment::contained_under(&parent_cwd, &child)
            {
                bail!("subdirectory workspace lease must be a strict child of the parent cwd");
            }
            (child.clone(), child)
        }
        WorkspaceLeaseKind::ManagedWorktree => {
            let state_dir = cockpit_config::config::resolve::cockpit_state_dir()
                .context("resolving daemon state directory for managed task worktree")?;
            let worktrees = state_dir.join("worktrees");
            std::fs::create_dir_all(&worktrees)
                .with_context(|| format!("creating `{}`", worktrees.display()))?;
            let worktrees = cockpit_host::path_containment::effective_path(&worktrees)
                .with_context(|| format!("resolving `{}`", worktrees.display()))?;
            let path = worktrees.join(lease_id.to_string());
            crate::git::assert_worktree_destination_under(&worktrees, &path)?;
            (path.clone(), path)
        }
    };

    let head = crate::git::head_sha(&repository)?;
    let reference = crate::git::run_git(&repository, &["symbolic-ref", "--quiet", "HEAD"])
        .ok()
        .filter(|output| output.success)
        .map(|output| output.stdout)
        .unwrap_or_else(|| head.clone());
    let private_ref = format!("cockpit-lease/{lease_id}");
    let now = now_unix_ms();
    let row = db
        .create_host_workspace_lease(
            NewWorkspaceLease {
                session_id,
                agent_instance_id: owner_agent_instance_id,
                write_scope_lease_id,
                parent_workspace_lease_id: parent_workspace_lease
                    .map(|lease| lease.id)
                    .filter(|id| !id.is_nil()),
                canonical_repository_id: canonical_repository_identity(&repository)?,
                canonical_root: canonical_root.display().to_string(),
                kind: kind.to_db(),
                // A host-issued child token is never a fresh ambient coding
                // grant.  It starts at the parent's currently effective
                // operations and later admission can only intersect further.
                allowed_ops: parent_workspace_lease
                    .map(|lease| lease.allowed_ops)
                    .unwrap_or_else(|| {
                        if kind == WorkspaceLeaseKind::SameRoot
                            && parent_grant.computer_delegation_enabled()
                        {
                            WorkspaceLeaseOps::for_computer()
                        } else {
                            WorkspaceLeaseOps::for_coding()
                        }
                    })
                    .confined_to_kind(kind)
                    .to_bits(),
                base_sha_digest: WorkspaceDigest::of(head.clone()),
                base_ref_digest: WorkspaceDigest::of(reference),
                managed_path: managed_path.display().to_string(),
                private_ref_digest: WorkspaceDigest::of(&private_ref),
                expires_at_unix_ms: now.saturating_add(24 * 60 * 60 * 1000),
            },
            lease_id,
            now,
        )
        .await
        .context("persisting host-issued task workspace lease")?;
    record_job_issued_workspace_lease_id(lease_id);
    let lease = WorkspaceLease::from_row(&row)?;

    if kind == WorkspaceLeaseKind::ManagedWorktree {
        if let Err(error) = lease.revalidate_for_tools(db).await {
            grace_retain_rejected_workspace_lease(db, &lease).await?;
            return Err(error)
                .context("revalidating managed workspace lease before worktree creation");
        }
        let branch = format!("cockpit-lease/{lease_id}");
        if let Err(error) = crate::git::worktree_add(&repository, &managed_path, &branch, &head) {
            mark_harness_lease_uncertain(db, &lease).await?;
            return Err(error).context("allocating persisted managed task worktree");
        }
    }
    Ok(lease)
}

/// Host-only issuance for an isolated external harness.  The caller has
/// already selected the harness under the normal approval and tool-surface
/// gates; no model argument supplies any of this provenance.  We persist the
/// lease *before* `git worktree add`, so crash recovery can retain and inspect
/// an incomplete directory rather than treating it as disposable scratch.
///
/// The durable row is owned by the current agent-tree executor but binds to
/// the daemon-owned root write-scope lease.  Session roots intentionally have
/// no agent owner, so ordinary agent-owned lease creation cannot represent
/// this host operation.  The DB's dedicated host method verifies that exact
/// root authority is still active in this session.
pub async fn issue_managed_worktree_lease_for_harness(
    db: &crate::db::Db,
    session_id: Uuid,
    owner_agent_instance_id: Uuid,
    cwd: &Path,
    daemon_state_dir: &Path,
) -> Result<WorkspaceLease> {
    let repository = crate::git::find_worktree_root(cwd)
        .context("isolated harness workspace lease requires a git worktree")?;
    let repository = crate::git::resolve_git_path(&repository)?;
    let write_scope_lease_id = db
        .list_write_scope_leases_for_session(session_id)
        .await?
        .into_iter()
        .find(|lease| lease.parent_lease_id.is_none() && lease.state == "active")
        .map(|lease| lease.lease_id)
        .context("isolated harness workspace lease requires the daemon root write scope")?;

    // It is safe to create the daemon-owned container before persistence; the
    // leased directory itself is not created until `Worktree::create` runs.
    let worktrees = daemon_state_dir.join("worktrees");
    std::fs::create_dir_all(&worktrees)
        .with_context(|| format!("creating `{}`", worktrees.display()))?;
    let worktrees = cockpit_host::path_containment::effective_path(&worktrees)
        .with_context(|| format!("resolving `{}`", worktrees.display()))?;
    let lease_id = Uuid::new_v4();
    let managed_path = worktrees.join(lease_id.to_string());
    crate::git::assert_worktree_destination_under(&worktrees, &managed_path)?;

    let head = crate::git::head_sha(&repository)?;
    let reference = crate::git::run_git(&repository, &["symbolic-ref", "--quiet", "HEAD"])
        .ok()
        .filter(|output| output.success)
        .map(|output| output.stdout)
        .unwrap_or_else(|| head.clone());
    let private_ref = format!("cockpit-lease/{lease_id}");
    let row = db
        .create_host_workspace_lease(
            NewWorkspaceLease {
                session_id,
                agent_instance_id: owner_agent_instance_id,
                write_scope_lease_id,
                parent_workspace_lease_id: None,
                canonical_repository_id: canonical_repository_identity(&repository)?,
                canonical_root: managed_path.display().to_string(),
                kind: DbLeaseKind::ManagedWorktree,
                allowed_ops: WorkspaceLeaseOps::for_coding().to_bits(),
                base_sha_digest: WorkspaceDigest::of(head),
                base_ref_digest: WorkspaceDigest::of(reference),
                managed_path: managed_path.display().to_string(),
                private_ref_digest: WorkspaceDigest::of(private_ref),
                expires_at_unix_ms: now_unix_ms().saturating_add(24 * 60 * 60 * 1000),
            },
            lease_id,
            now_unix_ms(),
        )
        .await
        .context("persisting host-managed harness workspace lease")?;
    record_job_issued_workspace_lease_id(lease_id);
    WorkspaceLease::from_row(&row)
}

/// Explicit host lifecycle action for a retained managed worktree.
///
/// This is intentionally not a task tool and is never called from normal
/// completion.  The daemon host must supply the owner-scoped lease identity;
/// the service proves the recorded Git identity before removal, leaves the DB
/// row untouched when disk removal fails, and only then commits the durable
/// `cleaned` transition.  A CAS race after removal is surfaced for operator
/// recovery rather than silently treating a stale row as cleaned.
pub async fn explicitly_clean_managed_worktree(
    db: &crate::db::Db,
    session_id: Uuid,
    owner_agent_instance_id: Uuid,
    lease_id: Uuid,
) -> Result<()> {
    let row = db
        .workspace_lease(session_id, owner_agent_instance_id, lease_id)
        .await?
        .context("managed workspace lease is not owned by this host lifecycle request")?;
    let mut lease = WorkspaceLease::from_row(&row)?;
    if !lease.is_durable_host_issued_managed_worktree() {
        bail!("explicit cleanup requires a durable host-issued managed workspace lease");
    }
    // Idle expiry has no later tool/native-access/recovery hook. Persist
    // Active→Grace here so an expired managed row can be settled instead of
    // remaining Active-but-inadmissible forever.
    if lease.state == WorkspaceLeaseState::Active {
        expire_active_workspace_lease_if_due(db, &lease).await?;
        let row = db
            .workspace_lease(session_id, owner_agent_instance_id, lease_id)
            .await?
            .context("managed workspace lease is not owned by this host lifecycle request")?;
        lease = WorkspaceLease::from_row(&row)?;
    }
    if !matches!(
        lease.state,
        WorkspaceLeaseState::Grace | WorkspaceLeaseState::Uncertain
    ) {
        bail!("explicit cleanup requires a retained or uncertain managed workspace lease");
    }
    if !lease.identity_matches_disk() {
        let _ = db
            .mark_workspace_lease_uncertain(
                session_id,
                owner_agent_instance_id,
                lease_id,
                lease.revision,
                WorkspaceLeaseTerminalReason::IdentityMismatch,
                now_unix_ms(),
            )
            .await;
        bail!("managed workspace identity does not match disk; retained for inspection");
    }
    // Resolve the surviving primary checkout *before* removing this linked
    // worktree. After removal the old cwd is invalid, so using it for branch
    // deletion leaks the lease's private branch while incorrectly marking the
    // lifecycle row cleaned.
    let cleanup_repository = crate::git::primary_worktree_root(&lease.visibility_root)
        .context("resolving a surviving primary checkout for managed workspace cleanup")?;
    crate::git::worktree_remove(&cleanup_repository, &lease.visibility_root)
        .context("removing identity-checked managed workspace")?;
    if let Err(error) =
        crate::git::branch_delete(&cleanup_repository, &format!("cockpit-lease/{lease_id}"))
    {
        let _ = db
            .mark_workspace_lease_uncertain(
                session_id,
                owner_agent_instance_id,
                lease_id,
                lease.revision,
                WorkspaceLeaseTerminalReason::RestartUncertain,
                now_unix_ms(),
            )
            .await;
        return Err(error).context(
            "managed workspace was removed but private branch cleanup failed; lease retained as uncertain for operator reconciliation",
        );
    }
    match db
        .clean_workspace_lease(
            session_id,
            owner_agent_instance_id,
            lease_id,
            lease.revision,
            true,
            now_unix_ms(),
        )
        .await?
    {
        LeaseCasOutcome::Transitioned(_) | LeaseCasOutcome::AlreadyTerminal(_) => Ok(()),
        LeaseCasOutcome::RevisionConflict => bail!(
            "managed workspace was removed, but its durable lifecycle changed concurrently; operator reconciliation is required"
        ),
    }
}

/// A worktree creation/spawn failure is ambiguous: git may have created the
/// directory or registered it before reporting an error.  Retain it and make
/// that ambiguity durable for recovery instead of removing a path.
pub async fn mark_harness_lease_uncertain(
    db: &crate::db::Db,
    lease: &WorkspaceLease,
) -> Result<()> {
    if lease.id.is_nil() {
        return Ok(());
    }
    match db
        .mark_workspace_lease_uncertain(
            lease.session_id,
            lease.owner_agent_instance_id,
            lease.id,
            lease.revision,
            WorkspaceLeaseTerminalReason::RestartUncertain,
            now_unix_ms(),
        )
        .await
        .context("marking failed managed harness lease uncertain")?
    {
        LeaseCasOutcome::Transitioned(_) | LeaseCasOutcome::AlreadyTerminal(_) => Ok(()),
        LeaseCasOutcome::RevisionConflict => prove_workspace_lease_not_active(db, lease).await,
    }
}

/// True when `lease` is the same UUID a still-live parent holds. Child
/// reject/completion must not grace-retain that ancestor token: the parent
/// is still running and later native tools plus `clean-worktree` would
/// observe a revoked owner.
pub fn lease_is_inherited_from(parent: Option<&WorkspaceLease>, lease: &WorkspaceLease) -> bool {
    parent.is_some_and(|parent| parent.id == lease.id)
}

/// Fold a failed Active→Grace/Uncertain proof into a caller-facing report
/// so a reject/completion exit cannot look successful while the UUID stays
/// adoptable.
pub fn report_with_lease_retire_failure(report: impl Into<String>, retire: Result<()>) -> String {
    let report = report.into();
    match retire {
        Ok(()) => report,
        Err(error) => {
            if report.is_empty() {
                format!(
                    "Error: managed workspace lease could not be retired from Active: {error:#}"
                )
            } else {
                format!(
                    "{}; managed workspace lease could not be retired from Active: {error:#}",
                    report.trim_end_matches('.')
                )
            }
        }
    }
}

/// Normal harness completion retains the worktree for the grace window.  A
/// pin is a durable lifecycle observation without falsely labelling a
/// successfully completed lease as an expiry.
pub async fn grace_retain_completed_harness_lease(
    db: &crate::db::Db,
    lease: &WorkspaceLease,
) -> Result<()> {
    // Completion retention is for host-managed directories only. A same-root
    // or subtree token may be inherited by several still-live children; one
    // child's terminal result must never revoke that shared parent authority.
    retire_managed_workspace_lease_from_active(db, lease).await
}

/// Child completion/reject of a host-minted managed worktree. Inherited
/// clones of a still-live ancestor UUID are left Active.
pub async fn grace_retain_completed_child_workspace_lease(
    db: &crate::db::Db,
    parent: Option<&WorkspaceLease>,
    lease: &WorkspaceLease,
) -> Result<()> {
    retire_child_workspace_lease_on_exit(db, parent, Some(lease)).await
}

/// An allocated task lease that fails pure admission is not an active child
/// authority. Retain any managed directory for inspection, but make the row
/// non-live so a later request cannot accidentally adopt rejected authority.
pub async fn grace_retain_rejected_workspace_lease(
    db: &crate::db::Db,
    lease: &WorkspaceLease,
) -> Result<()> {
    retire_managed_workspace_lease_from_active(db, lease).await
}

/// All-or-nothing batch admission may allocate several managed worktrees
/// before a later entry is rejected.  Roll every allocation this admission
/// minted back to grace, including the entry that failed after issuance, so
/// none remains live and adoptable merely because an earlier sibling reached
/// preflight first. Inherited ancestor UUIDs are left Active.
pub async fn grace_retain_rejected_workspace_leases(
    db: &crate::db::Db,
    parent: Option<&WorkspaceLease>,
    leases: impl IntoIterator<Item = Option<&WorkspaceLease>>,
) -> Result<()> {
    retire_child_workspace_leases_on_exit(db, parent, leases).await
}

async fn retire_child_workspace_lease_on_exit(
    db: &crate::db::Db,
    parent: Option<&WorkspaceLease>,
    lease: Option<&WorkspaceLease>,
) -> Result<()> {
    let Some(lease) = lease else {
        return Ok(());
    };
    if lease_is_inherited_from(parent, lease) {
        return Ok(());
    }
    retire_managed_workspace_lease_from_active(db, lease).await
}

async fn retire_child_workspace_leases_on_exit(
    db: &crate::db::Db,
    parent: Option<&WorkspaceLease>,
    leases: impl IntoIterator<Item = Option<&WorkspaceLease>>,
) -> Result<()> {
    let mut first_error = None;
    for lease in leases.into_iter().flatten() {
        if let Err(error) = retire_child_workspace_lease_on_exit(db, parent, Some(lease)).await {
            tracing::error!(
                error = %error,
                lease = %lease.id,
                "failed to retire managed workspace lease from Active"
            );
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Persist Active→Grace when a durable token's wall-clock has elapsed so
/// `cockpit daemon clean-worktree` can settle the row during a live session.
/// Ephemeral (nil-id) tokens have no ledger row. Already non-Active rows are
/// success. CAS conflict is not success unless the re-read is non-Active.
pub async fn expire_active_workspace_lease_if_due(
    db: &crate::db::Db,
    lease: &WorkspaceLease,
) -> Result<()> {
    if lease.id.is_nil() {
        return Ok(());
    }
    let now = now_unix_ms();
    if lease.state == WorkspaceLeaseState::Active && lease.expires_at_unix_ms > now {
        return Ok(());
    }
    if lease.state != WorkspaceLeaseState::Active {
        return Ok(());
    }
    match db
        .expire_workspace_lease(
            lease.session_id,
            lease.owner_agent_instance_id,
            lease.id,
            lease.revision,
            now,
        )
        .await
        .context("expiring wall-clock Active workspace lease")?
    {
        LeaseCasOutcome::Transitioned(_) | LeaseCasOutcome::AlreadyTerminal(_) => Ok(()),
        LeaseCasOutcome::RevisionConflict => prove_workspace_lease_not_active(db, lease).await,
    }
}

async fn prove_workspace_lease_not_active(
    db: &crate::db::Db,
    lease: &WorkspaceLease,
) -> Result<()> {
    let Some(current) = db
        .workspace_lease(lease.session_id, lease.owner_agent_instance_id, lease.id)
        .await
        .context("re-reading workspace lease after lifecycle CAS conflict")?
    else {
        bail!(
            "workspace lease `{}` disappeared while proving it is not Active",
            lease.id
        );
    };
    if current.state != WorkspaceLeaseState::Active {
        return Ok(());
    }
    match db
        .mark_workspace_lease_uncertain(
            lease.session_id,
            lease.owner_agent_instance_id,
            lease.id,
            current.revision,
            WorkspaceLeaseTerminalReason::RestartUncertain,
            now_unix_ms(),
        )
        .await
        .context("marking workspace lease uncertain after lifecycle CAS conflict")?
    {
        LeaseCasOutcome::Transitioned(_) | LeaseCasOutcome::AlreadyTerminal(_) => Ok(()),
        LeaseCasOutcome::RevisionConflict => bail!(
            "workspace lease `{}` could not be retired from Active",
            lease.id
        ),
    }
}

/// Prove a managed worktree row is no longer `Active`. Grace CAS conflict is
/// not success: re-read, accept an already-non-Active row, otherwise mark
/// uncertain. Never leave a completed/rejected UUID adoptable.
async fn retire_managed_workspace_lease_from_active(
    db: &crate::db::Db,
    lease: &WorkspaceLease,
) -> Result<()> {
    if lease.id.is_nil() || lease.kind != WorkspaceLeaseKind::ManagedWorktree {
        return Ok(());
    }
    match db
        .grace_retain_workspace_lease(
            lease.session_id,
            lease.owner_agent_instance_id,
            lease.id,
            lease.revision,
            now_unix_ms(),
        )
        .await
    {
        Ok(LeaseCasOutcome::Transitioned(_) | LeaseCasOutcome::AlreadyTerminal(_)) => Ok(()),
        Ok(LeaseCasOutcome::RevisionConflict) => prove_workspace_lease_not_active(db, lease).await,
        Err(error) => mark_harness_lease_uncertain(db, lease)
            .await
            .context(error)
            .context("retiring managed workspace lease from Active"),
    }
}

/// Canonical identity shared by every linked Git worktree in one repository.
/// `--git-common-dir` avoids treating a replacement worktree with a matching
/// filename as the recorded repository merely because it is itself a Git repo.
fn canonical_repository_identity(root: &Path) -> Result<String> {
    let common = crate::git::run_git_checked(root, &["rev-parse", "--git-common-dir"])?;
    let common = common.trim();
    let common = Path::new(common);
    let common = if common.is_absolute() {
        common.to_path_buf()
    } else {
        root.join(common)
    };
    let common = cockpit_host::path_containment::effective_path(&common)
        .context("resolving canonical Git common directory")?;
    Ok(WorkspaceDigest::of(common.to_string_lossy().as_bytes())
        .as_str()
        .to_string())
}

/// The only authority to leave the primary workspace boundary. A UUID-shaped
/// directory is never trusted: the caller must carry an owner-scoped, live
/// durable lease whose canonical managed root exactly names the requested cwd.
pub fn authorizes_managed_worktree_cwd(lease: Option<&WorkspaceLease>, path: &Path) -> bool {
    let Some(lease) = lease else {
        return false;
    };
    if !lease.is_durable_host_issued_managed_worktree() || !lease.is_live(now_unix_ms()) {
        return false;
    }
    let Ok(path) = cockpit_host::path_containment::effective_path(path) else {
        return false;
    };
    let Ok(visibility) = cockpit_host::path_containment::effective_path(&lease.visibility_root)
    else {
        return false;
    };
    let Ok(managed) = cockpit_host::path_containment::effective_path(&lease.managed_path) else {
        return false;
    };
    let lease_directory = lease.id.to_string();
    path == visibility
        && visibility == managed
        && managed
            .file_name()
            .is_some_and(|name| name == std::ffi::OsStr::new(&lease_directory))
        && managed
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == "worktrees")
}

pub fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Parse a `task` `workspace_lease` argument. A UUID selects a host-issued
/// row; a kind name requests that kind (subdirectory still needs `cwd`;
/// `managed_worktree` is issued by the host when the parent grant allows it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceLeaseSelection {
    Id(Uuid),
    Kind(WorkspaceLeaseKind),
}

impl WorkspaceLeaseSelection {
    pub fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            bail!("workspace_lease is empty");
        }
        if let Ok(kind) = WorkspaceLeaseKind::parse(raw) {
            return Ok(Self::Kind(kind));
        }
        let id = Uuid::parse_str(raw).context("workspace_lease is not a UUID or kind")?;
        Ok(Self::Id(id))
    }
}

/// Build a preflight lease from a `task` argument. Kind names synthesize an
/// ephemeral token at the parent/child cwd. A UUID must already have been
/// loaded by the host (`loaded`).
pub fn lease_from_task_argument(
    raw: Option<&str>,
    parent_cwd: &Path,
    child_cwd: &Path,
    loaded: Option<WorkspaceLease>,
) -> std::result::Result<Option<WorkspaceLease>, String> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    match WorkspaceLeaseSelection::parse(raw).map_err(|error| error.to_string())? {
        WorkspaceLeaseSelection::Kind(kind) => {
            if kind == WorkspaceLeaseKind::ManagedWorktree {
                return Err(
                    "managed_worktree requires a live host-issued workspace lease UUID".into(),
                );
            }
            let root = match kind {
                WorkspaceLeaseKind::SameRoot => parent_cwd.to_path_buf(),
                WorkspaceLeaseKind::Subdirectory => child_cwd.to_path_buf(),
                WorkspaceLeaseKind::ManagedWorktree => unreachable!("rejected above"),
            };
            Ok(Some(WorkspaceLease::ephemeral(
                kind,
                root,
                WorkspaceLeaseOps::for_coding(),
                now_unix_ms().saturating_add(24 * 60 * 60 * 1000),
            )))
        }
        WorkspaceLeaseSelection::Id(id) => {
            let Some(loaded) = loaded else {
                return Err(format!(
                    "workspace lease `{id}` is not a live host-issued lease"
                ));
            };
            if loaded.id != id {
                return Err(format!(
                    "workspace lease `{id}` does not match the loaded host token"
                ));
            }
            Ok(Some(loaded))
        }
    }
}

/// Resolve a task-selected lease from the durable agent-tree lineage ledger.
/// Task arguments never mint authority: kind spellings are documentation
/// helpers, while an actual launch must name a live host-issued UUID owned by
/// the current agent or one of its durable ancestors.
pub async fn load_lease_from_task_argument(
    db: &crate::db::Db,
    session_id: Uuid,
    owner_agent_instance_id: Option<Uuid>,
    raw: Option<&str>,
) -> std::result::Result<Option<WorkspaceLease>, String> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let selection = WorkspaceLeaseSelection::parse(raw).map_err(|error| error.to_string())?;
    let WorkspaceLeaseSelection::Id(id) = selection else {
        return Err(format!(
            "workspace lease kind `{raw}` must be issued by the host before launch; pass its UUID"
        ));
    };
    let owner = owner_agent_instance_id
        .ok_or_else(|| "workspace lease selection requires a durable agent owner".to_string())?;
    let row = db
        .workspace_lease_for_tools(session_id, owner, id, now_unix_ms())
        .await
        .map_err(|error| format!("loading workspace lease `{id}`: {error:#}"))?
        .ok_or_else(|| {
            format!("workspace lease `{id}` is not live and owned by this agent or an ancestor")
        })?;
    WorkspaceLease::from_row(&row)
        .map(Some)
        .map_err(|error| format!("loading workspace lease `{id}`: {error:#}"))
}

/// A leased parent cannot shed its confinement by omitting `workspace_lease`.
/// A child either selects an owner-scoped descendant lease or inherits the
/// parent's typed token; both paths are revalidated at every native boundary.
pub fn inherit_or_select_lease(
    parent: Option<&WorkspaceLease>,
    selected: Option<WorkspaceLease>,
) -> std::result::Result<Option<WorkspaceLease>, String> {
    let Some(parent) = parent else {
        return Ok(selected);
    };
    if !parent.is_live(now_unix_ms()) {
        return Err(format!(
            "parent workspace lease `{}` is expired, revoked, or unavailable",
            parent.id
        ));
    }
    match selected {
        // A child-selected token is still bounded by its caller's live token.
        // This survives descriptor/recovery reloads and closes the old path
        // where `grant_rejection` observed an intersection but constructors
        // received the selected token's wider operation set.
        Some(mut selected) => {
            selected.allowed_ops = selected
                .allowed_ops
                .intersect(parent.allowed_ops)
                .confined_to_kind(selected.kind);
            Ok(Some(selected))
        }
        None => Ok(Some(parent.clone())),
    }
}

/// Result of intersecting a selected lease with the parent's live grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseIntersection {
    pub lease: WorkspaceLease,
    pub child_cwd: PathBuf,
    pub write_scope: Option<PathBuf>,
    pub allowed_ops: WorkspaceLeaseOps,
}

/// Materialize the write boundary that a lease leaves to a child after the
/// structural intersection has been admitted. Omitting `write_scope` means
/// inheritance, not an ambient cwd grant.
pub fn effective_write_scope_for_lease(
    requested: Option<PathBuf>,
    parent_scope: Option<&Path>,
    lease: &WorkspaceLease,
) -> Option<PathBuf> {
    // This is the materialized value delivered to child constructors. Never
    // hand a constructor the original wider request after preflight merely
    // proved an intersection exists; choose the narrowest overlapping scope.
    let requested = requested.filter(|scope| lease.covers_path(scope));
    match (requested, parent_scope) {
        (Some(scope), Some(parent))
            if cockpit_host::path_containment::contained_under(parent, &scope) =>
        {
            Some(scope)
        }
        (Some(_), Some(parent))
            if cockpit_host::path_containment::contained_under(&lease.visibility_root, parent) =>
        {
            Some(lease.visibility_root.clone())
        }
        (Some(_), Some(_)) => Some(lease.visibility_root.clone()),
        (Some(scope), None) => Some(scope),
        (None, Some(parent))
            if cockpit_host::path_containment::contained_under(parent, &lease.visibility_root) =>
        {
            Some(lease.visibility_root.clone())
        }
        (None, Some(parent))
            if cockpit_host::path_containment::contained_under(&lease.visibility_root, parent) =>
        {
            Some(parent.to_path_buf())
        }
        (None, Some(_)) | (None, None) => Some(lease.visibility_root.clone()),
    }
}

/// Intersect a selected workspace lease with the parent's live grant, the
/// requested child cwd/write_scope, and the child execution kind.
///
/// No tool argument can widen cwd, sandbox visibility, tools, model role,
/// child depth, or concurrency. Those last four are enforced by the existing
/// vNext grant/preflight seams; this function is the workspace half.
pub fn intersect_lease_with_parent_grant(
    parent: &EffectiveVnextGrant,
    parent_cwd: &Path,
    parent_write_scope: Option<&Path>,
    parent_lease: Option<&WorkspaceLease>,
    child_kind: ExecutionKind,
    requested_cwd: &Path,
    requested_write_scope: Option<&Path>,
    selected: &WorkspaceLease,
    now_ms: i64,
) -> Result<LeaseIntersection, String> {
    if !selected.is_live(now_ms) {
        return Err(format!(
            "workspace lease `{}` is not live (state {:?}, expired={})",
            selected.id,
            selected.state,
            selected.expires_at_unix_ms <= now_ms
        ));
    }
    let Some(delegation) = parent.delegation.as_ref() else {
        return Err("parent effective vNext grant has no delegation authority".into());
    };
    let target = selected.as_delegation_target();
    if !delegation.targets.contains(&target) {
        return Err(format!(
            "parent grant does not permit workspace lease kind `{}`",
            selected.kind.as_str()
        ));
    }

    let parent_cwd = cockpit_host::path_containment::effective_path(parent_cwd).map_err(|err| {
        format!(
            "parent cwd `{}` does not resolve: {err}",
            parent_cwd.display()
        )
    })?;
    let child_cwd =
        cockpit_host::path_containment::effective_path(requested_cwd).map_err(|err| {
            format!(
                "child cwd `{}` does not resolve: {err}",
                requested_cwd.display()
            )
        })?;
    let visibility = cockpit_host::path_containment::effective_path(&selected.visibility_root)
        .map_err(|err| {
            format!(
                "lease visibility root `{}` does not resolve: {err}",
                selected.visibility_root.display()
            )
        })?;

    if !selected.covers_cwd(&child_cwd) {
        return Err(format!(
            "child cwd `{}` is outside workspace lease visibility `{}`",
            child_cwd.display(),
            visibility.display()
        ));
    }

    match selected.kind {
        WorkspaceLeaseKind::SameRoot => {
            if child_cwd != parent_cwd {
                return Err(
                    "same_root workspace lease cannot move the child cwd off the parent root"
                        .into(),
                );
            }
            if visibility != parent_cwd {
                return Err(
                    "same_root workspace lease visibility cannot widen past the parent cwd".into(),
                );
            }
        }
        WorkspaceLeaseKind::Subdirectory => {
            if child_cwd == parent_cwd
                || !cockpit_host::path_containment::contained_under(&parent_cwd, &child_cwd)
            {
                return Err(
                    "subdirectory workspace lease must be a strict descendant of the parent cwd"
                        .into(),
                );
            }
            if let Some(parent_lease) = parent_lease
                && !parent_lease.covers_cwd(&child_cwd)
            {
                return Err(
                    "subdirectory workspace lease cannot widen past the parent's leased visibility"
                        .into(),
                );
            }
        }
        WorkspaceLeaseKind::ManagedWorktree => {
            if !selected.is_durable_host_issued_managed_worktree() {
                return Err(
                    "managed_worktree requires a durable host-issued workspace lease".into(),
                );
            }
            if child_cwd == parent_cwd
                || cockpit_host::path_containment::contained_under(&parent_cwd, &child_cwd)
            {
                return Err(
                    "managed_worktree lease cwd must be the host-issued worktree, not the parent repository"
                        .into(),
                );
            }
            if child_cwd != visibility {
                return Err(format!(
                    "managed_worktree child cwd `{}` must equal lease visibility `{}`",
                    child_cwd.display(),
                    visibility.display()
                ));
            }
        }
    }

    let effective_write_scope = if let Some(scope) = requested_write_scope {
        let scope = cockpit_host::path_containment::effective_path(scope)
            .map_err(|err| format!("write_scope `{}` does not resolve: {err}", scope.display()))?;
        if !selected.covers_path(&scope) {
            return Err(format!(
                "write_scope `{}` is outside workspace lease visibility `{}`",
                scope.display(),
                visibility.display()
            ));
        }
        if let Some(parent_scope) = parent_write_scope {
            let parent_scope = cockpit_host::path_containment::effective_path(parent_scope)
                .map_err(|err| {
                    format!(
                        "parent write_scope `{}` does not resolve: {err}",
                        parent_scope.display()
                    )
                })?;
            if !cockpit_host::path_containment::contained_under(&parent_scope, &scope) {
                return Err(
                    "workspace lease cannot widen write_scope past the parent's write-scope lease"
                        .into(),
                );
            }
        }
        Some(scope)
    } else if let Some(parent_scope) = parent_write_scope {
        let parent_scope =
            cockpit_host::path_containment::effective_path(parent_scope).map_err(|err| {
                format!(
                    "parent write_scope `{}` does not resolve: {err}",
                    parent_scope.display()
                )
            })?;
        if !selected.covers_path(&parent_scope)
            && !cockpit_host::path_containment::contained_under(&visibility, &parent_scope)
            && !cockpit_host::path_containment::contained_under(&parent_scope, &visibility)
        {
            return Err(
                "workspace lease is disjoint from the parent's write-scope and cannot inherit it"
                    .into(),
            );
        }
        // An omitted child scope inherits only the overlap with the lease
        // visibility, never the caller's original wider scope.
        Some(
            if cockpit_host::path_containment::contained_under(&parent_scope, &visibility) {
                visibility.clone()
            } else {
                parent_scope
            },
        )
    } else {
        // A lease is itself the default writable boundary.  Preserve that
        // concrete scope in ToolCtx so later native and shell gates do not
        // accidentally fall back to their ambient cwd semantics.
        Some(visibility.clone())
    };

    let mut ops = selected.allowed_ops.confined_to_kind(selected.kind);
    if child_kind == ExecutionKind::Computer {
        if !parent.computer_delegation_enabled() || !ops.computer {
            return Err("workspace lease does not permit computer use".into());
        }
    } else {
        ops.computer = false;
    }
    if let Some(parent_lease) = parent_lease {
        ops = ops.intersect(parent_lease.allowed_ops);
    }

    Ok(LeaseIntersection {
        lease: WorkspaceLease {
            allowed_ops: ops,
            visibility_root: visibility,
            canonical_root: selected.canonical_root.clone(),
            ..selected.clone()
        },
        child_cwd,
        write_scope: effective_write_scope,
        allowed_ops: ops,
    })
}

/// Deny attempts to use a workspace lease as a way around write-scope
/// overlap. The write-scope pair check remains authoritative; this helper
/// is the explicit proof used by tests and preflight.
pub fn workspace_lease_cannot_bypass_write_scope_overlap(
    left_write_scope: &Path,
    right_write_scope: &Path,
    _left_lease: Option<&WorkspaceLease>,
    _right_lease: Option<&WorkspaceLease>,
) -> bool {
    cockpit_host::path_containment::contained_under(left_write_scope, right_write_scope)
        || cockpit_host::path_containment::contained_under(right_write_scope, left_write_scope)
}

/// Crash recovery: expire wall-clock `Active` rows to grace, mark
/// identity-mismatched live leases `uncertain`, and never remove the path.
/// Only a later host-authorized cleanup may delete. A CAS conflict is not
/// success: recovery fails closed rather than admitting a still-`Active`
/// identity-mismatched tree to tools.
pub async fn recover_session_workspace_leases(
    db: &crate::db::Db,
    session: Uuid,
    now_ms: i64,
) -> Result<Vec<WorkspaceLeaseRow>> {
    let rows = db
        .list_workspace_leases_for_session_recovery(session)
        .await
        .context("listing workspace leases for crash recovery")?;
    let mut recovered = Vec::with_capacity(rows.len());
    for row in rows {
        let row = expire_recovered_active_lease(db, session, row, now_ms).await?;
        let lease = WorkspaceLease::from_row(&row)?;
        if lease.identity_matches_disk() {
            recovered.push(row);
            continue;
        }
        match db
            .mark_workspace_lease_uncertain(
                session,
                row.agent_instance_id,
                row.workspace_lease_id,
                row.revision,
                WorkspaceLeaseTerminalReason::RestartUncertain,
                now_ms,
            )
            .await
            .context("marking mismatched workspace lease uncertain")?
        {
            LeaseCasOutcome::Transitioned(updated) | LeaseCasOutcome::AlreadyTerminal(updated) => {
                recovered.push(updated);
            }
            LeaseCasOutcome::RevisionConflict => bail!(
                "workspace lease `{}` changed concurrently during crash recovery; refusing to admit a still-live mismatched tree",
                row.workspace_lease_id
            ),
        }
    }
    Ok(recovered)
}

async fn expire_recovered_active_lease(
    db: &crate::db::Db,
    session: Uuid,
    row: WorkspaceLeaseRow,
    now_ms: i64,
) -> Result<WorkspaceLeaseRow> {
    if row.state != WorkspaceLeaseState::Active || row.expires_at_unix_ms > now_ms {
        return Ok(row);
    }
    match db
        .expire_workspace_lease(
            session,
            row.agent_instance_id,
            row.workspace_lease_id,
            row.revision,
            now_ms,
        )
        .await
        .context("expiring wall-clock Active workspace lease during crash recovery")?
    {
        LeaseCasOutcome::Transitioned(updated) | LeaseCasOutcome::AlreadyTerminal(updated) => {
            Ok(updated)
        }
        LeaseCasOutcome::RevisionConflict => {
            let Some(current) = db
                .workspace_lease(session, row.agent_instance_id, row.workspace_lease_id)
                .await
                .context("re-reading workspace lease after expiry CAS conflict")?
            else {
                bail!(
                    "workspace lease `{}` disappeared while expiring it during crash recovery",
                    row.workspace_lease_id
                );
            };
            if current.state == WorkspaceLeaseState::Active {
                bail!(
                    "workspace lease `{}` remained Active after a wall-clock expiry CAS conflict",
                    row.workspace_lease_id
                );
            }
            Ok(current)
        }
    }
}

/// Persist wall-clock Active→Grace for every due row in this session so
/// `cockpit daemon clean-worktree` can settle idle managed worktrees without
/// waiting for a later tool, native-access, or crash-recovery hook.
pub async fn expire_session_active_workspace_leases_if_due(
    db: &crate::db::Db,
    session: Uuid,
) -> Result<()> {
    let rows = db
        .list_workspace_leases_for_session_recovery(session)
        .await
        .context("listing workspace leases to persist wall-clock expiry")?;
    let mut first_error = None;
    for row in rows {
        let lease = match WorkspaceLease::from_row(&row) {
            Ok(lease) => lease,
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
                continue;
            }
        };
        if let Err(error) = expire_active_workspace_lease_if_due(db, &lease).await {
            tracing::error!(
                error = %error,
                lease = %lease.id,
                "failed to persist wall-clock Active workspace lease expiry"
            );
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Terminal session shutdown: every host-minted managed worktree that is still
/// Active must leave this worker non-Active so it cannot be adopted and
/// `clean-worktree` can settle it. Pause-for-resume must not call this: the
/// next worker reattaches unexpired Active rows.
pub async fn retire_session_managed_workspace_leases(
    db: &crate::db::Db,
    session: Uuid,
) -> Result<()> {
    let rows = db
        .list_workspace_leases_for_session_recovery(session)
        .await
        .context("listing workspace leases to retire on session shutdown")?;
    let mut first_error = None;
    for row in rows {
        let lease = match WorkspaceLease::from_row(&row) {
            Ok(lease) => lease,
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
                continue;
            }
        };
        if let Err(error) = retire_managed_workspace_lease_from_active(db, &lease).await {
            tracing::error!(
                error = %error,
                lease = %lease.id,
                "failed to retire managed workspace lease from Active on session shutdown"
            );
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

pub fn share(lease: WorkspaceLease) -> Arc<WorkspaceLease> {
    Arc::new(lease)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::{
        AllowedChild, DelegationPolicy, ExecutionKind, ModelCapability, ModelLocality, ModelSlot,
        ProhibitedQuestionClass, VerificationBudget, VnextAgentDef, VnextHostPolicy,
    };
    use crate::db::workspace_lease_artifacts::WorkspaceLeaseKind as DbKind;
    use crate::db::write_scope_leases::WriteScopeLeaseRow;
    use crate::db::{Db, agent_tree_decisions::NewAgentInstance};
    use std::collections::BTreeSet;

    fn host() -> VnextHostPolicy {
        VnextHostPolicy {
            max_descendant_depth: 8,
            max_concurrent_children: 4,
            allowed_targets: BTreeSet::from([
                DelegationTarget::SameRoot,
                DelegationTarget::Subdirectory,
                DelegationTarget::ManagedWorktree,
            ]),
            computer_delegation_enabled: true,
            non_auto_resolvable: BTreeSet::from([ProhibitedQuestionClass::Credential]),
            max_question_timeout_seconds: 60,
            verification_ceiling: VerificationBudget {
                max_candidates: 5,
                max_total_tokens: 1_000,
                max_estimated_cost_microusd: 2_000,
                max_collection_millis: 3_000,
            },
        }
    }

    fn parent_grant(targets: Vec<DelegationTarget>) -> EffectiveVnextGrant {
        let def = VnextAgentDef {
            schema_version: crate::agents::SCHEMA_VERSION,
            agent_id: "acme/orchestrator".into(),
            execution_kind: ExecutionKind::Coding,
            model_slots: std::collections::BTreeMap::from([(
                "primary".to_string(),
                ModelSlot {
                    purpose: "code".into(),
                    min_context_tokens: 1,
                    required_capabilities: vec![ModelCapability::TextGeneration],
                    locality: ModelLocality::Any,
                    allow_default_fallback: false,
                    suggested_models: vec![],
                },
            )]),
            delegation: DelegationPolicy {
                allowed_children: vec![AllowedChild::PortableRef {
                    portable_agent_ref: "acme/child".into(),
                }],
                max_descendant_depth: Some(2),
                max_concurrent_children: Some(2),
                targets,
            },
            questions: None,
            verification: None,
        };
        def.resolve_grant(&host()).unwrap()
    }

    fn git_repo(dir: &Path) {
        for args in [
            vec!["init", "-q"],
            vec!["config", "user.email", "t@t"],
            vec!["config", "user.name", "t"],
        ] {
            crate::git::run_git_checked(dir, &args).unwrap();
        }
        std::fs::write(dir.join("seed.txt"), "seed\n").unwrap();
        crate::git::run_git_checked(dir, &["add", "seed.txt"]).unwrap();
        crate::git::run_git_checked(dir, &["commit", "-q", "-m", "init"]).unwrap();
    }

    fn future_expiry() -> i64 {
        now_unix_ms() + 60_000
    }

    #[test]
    fn same_root_subdirectory_and_managed_worktree_kinds_round_trip() {
        for kind in [
            WorkspaceLeaseKind::SameRoot,
            WorkspaceLeaseKind::Subdirectory,
            WorkspaceLeaseKind::ManagedWorktree,
        ] {
            assert_eq!(WorkspaceLeaseKind::parse(kind.as_str()).unwrap(), kind);
            assert_eq!(kind.to_db().as_str(), kind.as_str());
        }
    }

    #[test]
    fn same_root_lease_covers_parent_cwd_and_rejects_escapes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        let sibling = tmp.path().join("sibling");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        let lease = WorkspaceLease::ephemeral(
            WorkspaceLeaseKind::SameRoot,
            root.clone(),
            WorkspaceLeaseOps::for_coding(),
            future_expiry(),
        );
        assert!(lease.covers_path(&root.join("src/main.rs")));
        assert!(!lease.covers_path(&sibling.join("x")));
        assert!(lease.covers_cwd(&root));
        assert!(!lease.covers_cwd(&sibling));
    }

    #[test]
    fn subdirectory_lease_rejects_ancestor_and_sibling_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        let sub = root.join("pkg");
        let other = root.join("other");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let lease = WorkspaceLease::ephemeral(
            WorkspaceLeaseKind::Subdirectory,
            sub.clone(),
            WorkspaceLeaseOps::for_coding(),
            future_expiry(),
        );
        assert!(lease.covers_path(&sub.join("lib.rs")));
        assert!(!lease.covers_path(&root));
        assert!(!lease.covers_path(&other.join("x")));
        assert!(!lease.covers_cwd(&root));
    }

    #[test]
    fn managed_worktree_lease_does_not_see_primary_or_sibling() {
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("repo");
        let state = tmp.path().join("state");
        let id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let wt = managed_worktree_path(&state, id);
        let sibling = managed_worktree_path(&state, other);
        std::fs::create_dir_all(&primary).unwrap();
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        let lease = WorkspaceLease::ephemeral(
            WorkspaceLeaseKind::ManagedWorktree,
            wt.clone(),
            WorkspaceLeaseOps::for_coding(),
            future_expiry(),
        );
        assert!(lease.covers_path(&wt.join("src")));
        assert!(!lease.covers_path(&primary.join("src")));
        assert!(!lease.covers_path(&sibling.join("src")));
        assert!(!lease.allows_computer());
    }

    #[test]
    fn symlink_and_dotdot_cannot_escape_lease_visibility() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), "nope").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, root.join("sub").join("escape")).unwrap();
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(&outside, root.join("sub").join("escape")).unwrap();
        }
        let lease = WorkspaceLease::ephemeral(
            WorkspaceLeaseKind::Subdirectory,
            root.join("sub"),
            WorkspaceLeaseOps::for_coding(),
            future_expiry(),
        );
        assert!(
            !lease.covers_path(&root.join("sub/escape/secret.txt")),
            "symlink escape must not grant visibility"
        );
        assert!(!lease.covers_path(&root.join("sub/../secret-not-there")));
        assert!(!lease.covers_path(&outside));
    }

    #[test]
    fn expired_and_grace_leases_are_not_live() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path()).unwrap();
        let mut lease = WorkspaceLease::ephemeral(
            WorkspaceLeaseKind::SameRoot,
            tmp.path().to_path_buf(),
            WorkspaceLeaseOps::for_coding(),
            now_unix_ms() - 1,
        );
        assert!(!lease.is_live(now_unix_ms()));
        lease.expires_at_unix_ms = future_expiry();
        lease.state = WorkspaceLeaseState::Grace;
        assert!(!lease.is_live(now_unix_ms()));
        lease.state = WorkspaceLeaseState::Uncertain;
        assert!(!lease.is_live(now_unix_ms()));
        lease.state = WorkspaceLeaseState::Cleaned;
        assert!(!lease.is_live(now_unix_ms()));
    }

    #[test]
    fn intersection_denies_widening_cwd_visibility_computer_and_write_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        let sub = root.join("pkg");
        let other = root.join("other");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let grant = parent_grant(vec![DelegationTarget::SameRoot]);
        let same = WorkspaceLease::ephemeral(
            WorkspaceLeaseKind::SameRoot,
            root.clone(),
            WorkspaceLeaseOps::for_coding(),
            future_expiry(),
        );
        intersect_lease_with_parent_grant(
            &grant,
            &root,
            None,
            None,
            ExecutionKind::Coding,
            &root,
            None,
            &same,
            now_unix_ms(),
        )
        .unwrap();

        let err = intersect_lease_with_parent_grant(
            &grant,
            &root,
            None,
            None,
            ExecutionKind::Coding,
            &sub,
            None,
            &same,
            now_unix_ms(),
        )
        .unwrap_err();
        assert!(
            err.contains("same_root") || err.contains("outside workspace lease"),
            "{err}"
        );

        let sub_lease = WorkspaceLease::ephemeral(
            WorkspaceLeaseKind::Subdirectory,
            sub.clone(),
            WorkspaceLeaseOps::for_coding(),
            future_expiry(),
        );
        let err = intersect_lease_with_parent_grant(
            &grant,
            &root,
            None,
            None,
            ExecutionKind::Coding,
            &sub,
            None,
            &sub_lease,
            now_unix_ms(),
        )
        .unwrap_err();
        assert!(
            err.contains("does not permit workspace lease kind"),
            "{err}"
        );

        let grant_sub = parent_grant(vec![
            DelegationTarget::SameRoot,
            DelegationTarget::Subdirectory,
        ]);
        intersect_lease_with_parent_grant(
            &grant_sub,
            &root,
            Some(&root),
            None,
            ExecutionKind::Coding,
            &sub,
            Some(&sub),
            &sub_lease,
            now_unix_ms(),
        )
        .unwrap();
        let err = intersect_lease_with_parent_grant(
            &grant_sub,
            &root,
            Some(&sub),
            None,
            ExecutionKind::Coding,
            &sub,
            Some(&root),
            &sub_lease,
            now_unix_ms(),
        )
        .unwrap_err();
        assert!(
            err.contains("outside workspace lease") || err.contains("cannot widen write_scope"),
            "{err}"
        );

        let computer_lease = WorkspaceLease::ephemeral(
            WorkspaceLeaseKind::SameRoot,
            root.clone(),
            WorkspaceLeaseOps::for_coding(),
            future_expiry(),
        );
        let err = intersect_lease_with_parent_grant(
            &grant,
            &root,
            None,
            None,
            ExecutionKind::Computer,
            &root,
            None,
            &computer_lease,
            now_unix_ms(),
        )
        .unwrap_err();
        assert!(err.contains("computer"), "{err}");
    }

    #[test]
    fn managed_worktree_requires_typed_lease_and_stays_off_the_primary() {
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("repo");
        let state = tmp.path().join("state");
        git_repo(&primary);
        let id = Uuid::new_v4();
        let wt = managed_worktree_path(&state, id);
        std::fs::create_dir_all(wt.parent().unwrap()).unwrap();
        crate::git::worktree_add(&primary, &wt, &format!("lease-{id}"), "HEAD").unwrap();
        let grant = parent_grant(vec![DelegationTarget::ManagedWorktree]);
        let ephemeral = WorkspaceLease::ephemeral(
            WorkspaceLeaseKind::ManagedWorktree,
            wt.clone(),
            WorkspaceLeaseOps::for_coding(),
            future_expiry(),
        );
        let error = intersect_lease_with_parent_grant(
            &grant,
            &primary,
            None,
            None,
            ExecutionKind::Coding,
            &wt,
            None,
            &ephemeral,
            now_unix_ms(),
        )
        .unwrap_err();
        assert!(error.contains("durable host-issued"), "{error}");
        let lease = WorkspaceLease {
            id,
            host_issued: true,
            ..WorkspaceLease::ephemeral(
                WorkspaceLeaseKind::ManagedWorktree,
                wt.clone(),
                WorkspaceLeaseOps::for_coding(),
                future_expiry(),
            )
        };
        let ok = intersect_lease_with_parent_grant(
            &grant,
            &primary,
            None,
            None,
            ExecutionKind::Coding,
            &wt,
            None,
            &lease,
            now_unix_ms(),
        )
        .unwrap();
        assert_eq!(ok.child_cwd, wt);
        let err = intersect_lease_with_parent_grant(
            &grant,
            &primary,
            None,
            None,
            ExecutionKind::Coding,
            &primary,
            None,
            &lease,
            now_unix_ms(),
        )
        .unwrap_err();
        assert!(err.contains("managed_worktree"), "{err}");
        assert!(!grant.permits_target(&primary, &wt));
        assert!(
            !grant.permits_target_with_lease(&primary, &wt, Some(&ephemeral)),
            "an ephemeral managed-worktree token is not a host-issued grant"
        );
        assert!(grant.permits_target_with_lease(&primary, &wt, Some(&lease)));
        assert!(!grant.permits_target_with_lease(&primary, &primary, Some(&lease)));
        assert!(!wt.starts_with(std::env::temp_dir().join("cockpit-harness-")));
        assert!(wt.ends_with(Path::new("worktrees").join(id.to_string())));
    }

    #[test]
    fn nested_declared_grants_succeed_and_minimal_agent_stays_a_leaf() {
        // AC3 topology: root orchestrator -> worktree orchestrator ->
        // implementer/reviewer -> specialist. Each hop carries an explicit
        // declaration; a similarly capable but undeclared hop is refused.
        let root = parent_grant(vec![DelegationTarget::ManagedWorktree]);
        let worktree_orchestrator = parent_grant(vec![DelegationTarget::Subdirectory]);
        let mut implementer = parent_grant(vec![DelegationTarget::Subdirectory]);
        let mut reviewer = parent_grant(vec![DelegationTarget::SameRoot]);
        implementer.agent_id = "acme/implementer".into();
        reviewer.agent_id = "acme/reviewer".into();
        assert!(root.permits_child(
            &AllowedChild::PortableRef {
                portable_agent_ref: "acme/child".into(),
            },
            ExecutionKind::Coding,
        ));
        let mut worktree_orchestrator = worktree_orchestrator;
        worktree_orchestrator
            .delegation
            .as_mut()
            .unwrap()
            .allowed_children = vec![
            AllowedChild::PortableRef {
                portable_agent_ref: "acme/implementer".into(),
            },
            AllowedChild::PortableRef {
                portable_agent_ref: "acme/reviewer".into(),
            },
        ];
        assert!(worktree_orchestrator.permits_child(
            &AllowedChild::PortableRef {
                portable_agent_ref: "acme/implementer".into(),
            },
            implementer.execution_kind,
        ));
        assert!(worktree_orchestrator.permits_child(
            &AllowedChild::PortableRef {
                portable_agent_ref: "acme/reviewer".into(),
            },
            reviewer.execution_kind,
        ));
        for parent in [&mut implementer, &mut reviewer] {
            parent.delegation.as_mut().unwrap().allowed_children =
                vec![AllowedChild::PortableRef {
                    portable_agent_ref: "acme/specialist".into(),
                }];
            assert!(parent.permits_child(
                &AllowedChild::PortableRef {
                    portable_agent_ref: "acme/specialist".into(),
                },
                ExecutionKind::Coding,
            ));
        }
        assert!(!worktree_orchestrator.permits_child(
            &AllowedChild::PortableRef {
                portable_agent_ref: "acme/undeclared".into(),
            },
            ExecutionKind::Coding,
        ));
        let leaf = VnextAgentDef {
            schema_version: crate::agents::SCHEMA_VERSION,
            agent_id: "acme/minimal".into(),
            execution_kind: ExecutionKind::Coding,
            model_slots: std::collections::BTreeMap::from([(
                "primary".to_string(),
                ModelSlot {
                    purpose: "code".into(),
                    min_context_tokens: 1,
                    required_capabilities: vec![ModelCapability::TextGeneration],
                    locality: ModelLocality::Any,
                    allow_default_fallback: false,
                    suggested_models: vec![],
                },
            )]),
            delegation: DelegationPolicy::default(),
            questions: None,
            verification: None,
        };
        let leaf_grant = leaf.resolve_grant(&host()).unwrap();
        assert!(
            leaf_grant.delegation.is_none(),
            "no declared delegation means no children"
        );
        assert!(!leaf_grant.permits_child(
            &AllowedChild::PortableRef {
                portable_agent_ref: "acme/child".into(),
            },
            ExecutionKind::Coding
        ));
    }

    #[test]
    fn workspace_lease_cannot_bypass_write_scope_overlap() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let inner = a.join("sub");
        std::fs::create_dir_all(&inner).unwrap();
        let left = WorkspaceLease::ephemeral(
            WorkspaceLeaseKind::Subdirectory,
            a.clone(),
            WorkspaceLeaseOps::for_coding(),
            future_expiry(),
        );
        let right = WorkspaceLease::ephemeral(
            WorkspaceLeaseKind::Subdirectory,
            inner.clone(),
            WorkspaceLeaseOps::for_coding(),
            future_expiry(),
        );
        assert!(workspace_lease_cannot_bypass_write_scope_overlap(
            &a,
            &inner,
            Some(&left),
            Some(&right)
        ));
        let remapped_left =
            effective_write_scope_for_lease(Some(a.clone()), None, &left).expect("left scope");
        let remapped_right = effective_write_scope_for_lease(Some(inner.clone()), None, &right)
            .expect("right scope");
        assert!(
            workspace_lease_cannot_bypass_write_scope_overlap(
                &remapped_left,
                &remapped_right,
                Some(&left),
                Some(&right)
            ),
            "lease issuance remapping must not hide write-scope overlap"
        );
        let disjoint = tmp.path().join("b");
        std::fs::create_dir_all(&disjoint).unwrap();
        assert!(!workspace_lease_cannot_bypass_write_scope_overlap(
            &a,
            &disjoint,
            Some(&left),
            None
        ));
    }

    #[tokio::test]
    async fn durable_row_round_trip_and_restart_marks_uncertain_without_deleting() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("lease", repo.to_str().unwrap(), "root")
            .await
            .unwrap();
        let agent = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                1,
            )
            .await
            .unwrap();
        let _ = db
            .transition_agent_instance(
                session.session_id,
                agent.agent_instance_id,
                0,
                crate::db::agent_tree_decisions::AgentInstanceState::Running,
                r#"{"state":"running"}"#,
                2,
            )
            .await
            .unwrap();
        let scope = Uuid::new_v4();
        db.insert_write_scope_lease(WriteScopeLeaseRow {
            lease_id: scope,
            parent_lease_id: None,
            session_id: session.session_id,
            task_id: None,
            scope_path: repo.to_string_lossy().into_owned(),
            generation: 1,
            state: "active".into(),
            owner_id: agent.agent_instance_id.to_string(),
            version: 0,
            created_at_wall_ms: 1,
            updated_at_wall_ms: 1,
            released_at_wall_ms: None,
        })
        .await
        .unwrap();
        let row = db
            .create_workspace_lease(
                NewWorkspaceLease {
                    session_id: session.session_id,
                    agent_instance_id: agent.agent_instance_id,
                    write_scope_lease_id: scope,
                    parent_workspace_lease_id: None,
                    canonical_repository_id: "repo-id".into(),
                    canonical_root: repo.to_string_lossy().into_owned(),
                    kind: DbKind::SameRoot,
                    allowed_ops: WorkspaceLeaseOps::for_coding().to_bits(),
                    base_sha_digest: WorkspaceDigest::of(b"head"),
                    base_ref_digest: WorkspaceDigest::of(b"ref"),
                    managed_path: repo.to_string_lossy().into_owned(),
                    private_ref_digest: WorkspaceDigest::of(b"private"),
                    expires_at_unix_ms: now_unix_ms() + 60_000,
                },
                now_unix_ms(),
            )
            .await
            .unwrap();
        assert_eq!(row.kind, DbKind::SameRoot);
        let runtime = WorkspaceLease::from_row(&row).unwrap();
        assert_eq!(runtime.kind, WorkspaceLeaseKind::SameRoot);
        assert_eq!(runtime.allowed_ops, WorkspaceLeaseOps::for_coding());
        assert!(runtime.is_live(now_unix_ms()));
        runtime.revalidate_for_tools(&db).await.unwrap();
        let retained = db
            .grace_retain_workspace_lease(
                session.session_id,
                agent.agent_instance_id,
                row.workspace_lease_id,
                row.revision,
                now_unix_ms(),
            )
            .await
            .unwrap();
        assert!(matches!(retained, LeaseCasOutcome::Transitioned(_)));
        assert!(
            runtime.revalidate_for_tools(&db).await.is_err(),
            "a ToolCtx snapshot must fail closed after durable revocation"
        );

        std::fs::remove_dir_all(&repo).unwrap();
        let recovered = recover_session_workspace_leases(&db, session.session_id, now_unix_ms())
            .await
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].state, WorkspaceLeaseState::Uncertain);
        assert!(
            !repo.exists(),
            "recovery must not recreate or delete via force-remove of a missing path"
        );
    }

    #[tokio::test]
    async fn recovery_expires_wall_clock_active_leases_to_grace() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git_repo(&repo);
        let repository_id = canonical_repository_identity(&repo).unwrap();
        let head = crate::git::run_git_checked(&repo, &["rev-parse", "HEAD"]).unwrap();
        let refs =
            crate::git::run_git_checked(&repo, &["for-each-ref", "--format=%(refname)"]).unwrap();
        let reference = refs.lines().next().expect("git repo has a ref");
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("lease-expire", repo.to_str().unwrap(), "root")
            .await
            .unwrap();
        let agent = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                1,
            )
            .await
            .unwrap();
        let _ = db
            .transition_agent_instance(
                session.session_id,
                agent.agent_instance_id,
                0,
                crate::db::agent_tree_decisions::AgentInstanceState::Running,
                r#"{"state":"running"}"#,
                2,
            )
            .await
            .unwrap();
        let scope = Uuid::new_v4();
        db.insert_write_scope_lease(WriteScopeLeaseRow {
            lease_id: scope,
            parent_lease_id: None,
            session_id: session.session_id,
            task_id: None,
            scope_path: repo.to_string_lossy().into_owned(),
            generation: 1,
            state: "active".into(),
            owner_id: agent.agent_instance_id.to_string(),
            version: 0,
            created_at_wall_ms: 1,
            updated_at_wall_ms: 1,
            released_at_wall_ms: None,
        })
        .await
        .unwrap();
        let row = db
            .create_workspace_lease(
                NewWorkspaceLease {
                    session_id: session.session_id,
                    agent_instance_id: agent.agent_instance_id,
                    write_scope_lease_id: scope,
                    parent_workspace_lease_id: None,
                    canonical_repository_id: repository_id,
                    canonical_root: repo.to_string_lossy().into_owned(),
                    kind: DbKind::SameRoot,
                    allowed_ops: WorkspaceLeaseOps::for_coding().to_bits(),
                    base_sha_digest: WorkspaceDigest::of(head.trim()),
                    base_ref_digest: WorkspaceDigest::of(reference.trim()),
                    managed_path: repo.to_string_lossy().into_owned(),
                    private_ref_digest: WorkspaceDigest::of(b"private"),
                    expires_at_unix_ms: 100,
                },
                50,
            )
            .await
            .unwrap();
        assert_eq!(row.state, WorkspaceLeaseState::Active);
        let recovered = recover_session_workspace_leases(&db, session.session_id, 200)
            .await
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(
            recovered[0].state,
            WorkspaceLeaseState::Grace,
            "wall-clock expiry must perform Active→Grace so host cleanup can settle the row"
        );
        assert_ne!(recovered[0].state, WorkspaceLeaseState::Active);
    }

    #[tokio::test]
    async fn explicit_cleanup_uses_primary_checkout_and_removes_private_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git_repo(&repo);
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("lease-cleanup", repo.to_str().unwrap(), "root")
            .await
            .unwrap();
        let owner = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                1,
            )
            .await
            .unwrap();
        let _ = db
            .transition_agent_instance(
                session.session_id,
                owner.agent_instance_id,
                0,
                crate::db::agent_tree_decisions::AgentInstanceState::Running,
                r#"{"state":"running"}"#,
                2,
            )
            .await
            .unwrap();
        let host_scope = Uuid::new_v4();
        db.insert_write_scope_lease(WriteScopeLeaseRow {
            lease_id: host_scope,
            parent_lease_id: None,
            session_id: session.session_id,
            task_id: None,
            scope_path: repo.to_string_lossy().into_owned(),
            generation: 1,
            state: "active".into(),
            owner_id: "session-root".into(),
            version: 0,
            created_at_wall_ms: 2,
            updated_at_wall_ms: 2,
            released_at_wall_ms: None,
        })
        .await
        .unwrap();
        let state = tmp.path().join("state");
        let lease = issue_managed_worktree_lease_for_harness(
            &db,
            session.session_id,
            owner.agent_instance_id,
            &repo,
            &state,
        )
        .await
        .unwrap();
        let branch = format!("cockpit-lease/{}", lease.id);
        crate::git::worktree_add(&repo, &lease.visibility_root, &branch, "HEAD").unwrap();
        let retained = db
            .grace_retain_workspace_lease(
                session.session_id,
                owner.agent_instance_id,
                lease.id,
                lease.revision,
                now_unix_ms(),
            )
            .await
            .unwrap();
        let retained = match retained {
            LeaseCasOutcome::Transitioned(row) => row,
            other => panic!("expected retained lease, got {other:?}"),
        };

        explicitly_clean_managed_worktree(
            &db,
            session.session_id,
            owner.agent_instance_id,
            retained.workspace_lease_id,
        )
        .await
        .unwrap();

        assert!(!lease.visibility_root.exists());
        assert!(
            !crate::git::run_git(
                &repo,
                &[
                    "show-ref",
                    "--verify",
                    "--quiet",
                    &format!("refs/heads/{branch}")
                ]
            )
            .unwrap()
            .success,
            "cleanup must delete the private branch from the surviving primary checkout"
        );
        assert_eq!(
            db.workspace_lease(session.session_id, owner.agent_instance_id, lease.id)
                .await
                .unwrap()
                .unwrap()
                .state,
            WorkspaceLeaseState::Cleaned
        );
    }

    #[tokio::test]
    async fn host_issue_records_uuid_on_live_job_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git_repo(&repo);
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("lease-job-registry", repo.to_str().unwrap(), "root")
            .await
            .unwrap();
        let owner = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                1,
            )
            .await
            .unwrap();
        let _ = db
            .transition_agent_instance(
                session.session_id,
                owner.agent_instance_id,
                0,
                crate::db::agent_tree_decisions::AgentInstanceState::Running,
                r#"{"state":"running"}"#,
                2,
            )
            .await
            .unwrap();
        let host_scope = Uuid::new_v4();
        db.insert_write_scope_lease(WriteScopeLeaseRow {
            lease_id: host_scope,
            parent_lease_id: None,
            session_id: session.session_id,
            task_id: None,
            scope_path: repo.to_string_lossy().into_owned(),
            generation: 1,
            state: "active".into(),
            owner_id: "session-root".into(),
            version: 0,
            created_at_wall_ms: 2,
            updated_at_wall_ms: 2,
            released_at_wall_ms: None,
        })
        .await
        .unwrap();
        let ids = new_job_issued_workspace_lease_ids(Vec::new());
        let state = tmp.path().join("state");
        let lease = with_job_issued_workspace_lease_ids(ids.clone(), async {
            issue_managed_worktree_lease_for_harness(
                &db,
                session.session_id,
                owner.agent_instance_id,
                &repo,
                &state,
            )
            .await
            .unwrap()
        })
        .await;
        let recorded = snapshot_job_issued_workspace_lease_ids(&ids);
        assert!(
            recorded
                .iter()
                .any(|id| id.as_deref() == Some(lease.id.to_string().as_str())),
            "host mint inside a spawned job must append to the live abort list: {recorded:?}"
        );
    }

    #[tokio::test]
    async fn abandon_in_flight_harness_lease_leaves_managed_row_non_active() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("harness-abandon", repo.to_str().unwrap(), "root")
            .await
            .unwrap();
        let owner = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                1,
            )
            .await
            .unwrap();
        let _ = db
            .transition_agent_instance(
                session.session_id,
                owner.agent_instance_id,
                0,
                crate::db::agent_tree_decisions::AgentInstanceState::Running,
                r#"{"state":"running"}"#,
                2,
            )
            .await
            .unwrap();
        let scope = Uuid::new_v4();
        db.insert_write_scope_lease(WriteScopeLeaseRow {
            lease_id: scope,
            parent_lease_id: None,
            session_id: session.session_id,
            task_id: None,
            scope_path: repo.to_string_lossy().into_owned(),
            generation: 1,
            state: "active".into(),
            owner_id: owner.agent_instance_id.to_string(),
            version: 0,
            created_at_wall_ms: 1,
            updated_at_wall_ms: 1,
            released_at_wall_ms: None,
        })
        .await
        .unwrap();
        let now = now_unix_ms();
        let row = db
            .create_workspace_lease(
                NewWorkspaceLease {
                    session_id: session.session_id,
                    agent_instance_id: owner.agent_instance_id,
                    write_scope_lease_id: scope,
                    parent_workspace_lease_id: None,
                    canonical_repository_id: "repo-id".into(),
                    canonical_root: repo.to_string_lossy().into_owned(),
                    kind: DbKind::ManagedWorktree,
                    allowed_ops: WorkspaceLeaseOps::for_coding().to_bits(),
                    base_sha_digest: WorkspaceDigest::of(b"head"),
                    base_ref_digest: WorkspaceDigest::of(b"ref"),
                    managed_path: repo.to_string_lossy().into_owned(),
                    private_ref_digest: WorkspaceDigest::of(b"private"),
                    expires_at_unix_ms: now + 60_000,
                },
                now,
            )
            .await
            .unwrap();
        let lease = WorkspaceLease::from_row(&row).unwrap();
        attach_in_flight_harness_lease(&lease, Some("call-abandon"));
        abandon_in_flight_harness_lease(
            &db,
            session.session_id,
            owner.agent_instance_id,
            Some("call-abandon"),
        )
        .await
        .unwrap();
        let current = db
            .workspace_lease(session.session_id, owner.agent_instance_id, lease.id)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            current.state,
            WorkspaceLeaseState::Active,
            "harness abandon must leave the issued managed row non-Active"
        );
    }

    #[test]
    fn managed_worktree_escape_requires_the_live_typed_lease() {
        let tmp = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        let real = managed_worktree_path(tmp.path(), id);
        std::fs::create_dir_all(&real).unwrap();
        let lease = WorkspaceLease {
            id,
            managed_path: real.clone(),
            host_issued: true,
            ..WorkspaceLease::ephemeral(
                WorkspaceLeaseKind::ManagedWorktree,
                real.clone(),
                WorkspaceLeaseOps::for_coding(),
                future_expiry(),
            )
        };
        assert!(authorizes_managed_worktree_cwd(Some(&lease), &real));
        assert!(!authorizes_managed_worktree_cwd(None, &real));
        assert!(!authorizes_managed_worktree_cwd(Some(&lease), tmp.path()));
        assert!(!authorizes_managed_worktree_cwd(
            Some(&lease),
            &tmp.path().join("worktrees").join("not-a-uuid")
        ));
    }

    #[test]
    fn managed_worktree_path_is_never_temp_harness_prefix() {
        let state = PathBuf::from("/var/lib/cockpit");
        let id = Uuid::new_v4();
        let path = managed_worktree_path(&state, id);
        assert_eq!(path, state.join("worktrees").join(id.to_string()));
        assert!(!path.to_string_lossy().contains("cockpit-harness-"));
    }

    #[test]
    fn computer_ops_are_stripped_from_subtree_and_worktree_leases() {
        let ops = WorkspaceLeaseOps::for_computer();
        assert!(ops.confined_to_kind(WorkspaceLeaseKind::SameRoot).computer);
        assert!(
            !ops.confined_to_kind(WorkspaceLeaseKind::Subdirectory)
                .computer
        );
        assert!(
            !ops.confined_to_kind(WorkspaceLeaseKind::ManagedWorktree)
                .computer
        );
    }

    #[test]
    fn lease_selection_parses_kind_or_uuid() {
        assert_eq!(
            WorkspaceLeaseSelection::parse("same_root").unwrap(),
            WorkspaceLeaseSelection::Kind(WorkspaceLeaseKind::SameRoot)
        );
        assert_eq!(
            WorkspaceLeaseSelection::parse("subdirectory").unwrap(),
            WorkspaceLeaseSelection::Kind(WorkspaceLeaseKind::Subdirectory)
        );
        assert_eq!(
            WorkspaceLeaseSelection::parse("managed_worktree").unwrap(),
            WorkspaceLeaseSelection::Kind(WorkspaceLeaseKind::ManagedWorktree)
        );
        let id = Uuid::new_v4();
        assert_eq!(
            WorkspaceLeaseSelection::parse(&id.to_string()).unwrap(),
            WorkspaceLeaseSelection::Id(id)
        );
        assert!(WorkspaceLeaseSelection::parse("nope").is_err());
    }

    #[test]
    fn omitted_selection_inherits_the_parent_uuid() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path()).unwrap();
        let parent = WorkspaceLease::host_issued_managed_worktree(
            Uuid::new_v4(),
            tmp.path().to_path_buf(),
            WorkspaceLeaseOps::for_coding(),
            future_expiry(),
        );
        let inherited = inherit_or_select_lease(Some(&parent), None)
            .unwrap()
            .expect("omitted selection inherits");
        assert_eq!(inherited.id, parent.id);
        assert!(lease_is_inherited_from(Some(&parent), &inherited));
        let minted = WorkspaceLease::host_issued_managed_worktree(
            Uuid::new_v4(),
            tmp.path().to_path_buf(),
            WorkspaceLeaseOps::for_coding(),
            future_expiry(),
        );
        assert!(!lease_is_inherited_from(Some(&parent), &minted));
        assert!(!lease_is_inherited_from(None, &minted));
    }

    async fn durable_managed_fixture() -> (tempfile::TempDir, Db, Uuid, Uuid, WorkspaceLease) {
        let now = now_unix_ms();
        durable_managed_fixture_at(now, now + 60_000).await
    }

    async fn durable_managed_fixture_at(
        created_at_unix_ms: i64,
        expires_at_unix_ms: i64,
    ) -> (tempfile::TempDir, Db, Uuid, Uuid, WorkspaceLease) {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("lease-lifecycle", repo.to_str().unwrap(), "root")
            .await
            .unwrap();
        let agent = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: session.session_id,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                1,
            )
            .await
            .unwrap();
        let _ = db
            .transition_agent_instance(
                session.session_id,
                agent.agent_instance_id,
                0,
                crate::db::agent_tree_decisions::AgentInstanceState::Running,
                r#"{"state":"running"}"#,
                2,
            )
            .await
            .unwrap();
        let scope = Uuid::new_v4();
        db.insert_write_scope_lease(WriteScopeLeaseRow {
            lease_id: scope,
            parent_lease_id: None,
            session_id: session.session_id,
            task_id: None,
            scope_path: repo.to_string_lossy().into_owned(),
            generation: 1,
            state: "active".into(),
            owner_id: agent.agent_instance_id.to_string(),
            version: 0,
            created_at_wall_ms: 1,
            updated_at_wall_ms: 1,
            released_at_wall_ms: None,
        })
        .await
        .unwrap();
        let row = db
            .create_workspace_lease(
                NewWorkspaceLease {
                    session_id: session.session_id,
                    agent_instance_id: agent.agent_instance_id,
                    write_scope_lease_id: scope,
                    parent_workspace_lease_id: None,
                    canonical_repository_id: "repo-id".into(),
                    canonical_root: repo.to_string_lossy().into_owned(),
                    kind: DbKind::ManagedWorktree,
                    allowed_ops: WorkspaceLeaseOps::for_coding().to_bits(),
                    base_sha_digest: WorkspaceDigest::of(b"head"),
                    base_ref_digest: WorkspaceDigest::of(b"ref"),
                    managed_path: repo.to_string_lossy().into_owned(),
                    private_ref_digest: WorkspaceDigest::of(b"private"),
                    expires_at_unix_ms,
                },
                created_at_unix_ms,
            )
            .await
            .unwrap();
        let lease = WorkspaceLease::from_row(&row).unwrap();
        (tmp, db, session.session_id, agent.agent_instance_id, lease)
    }

    #[tokio::test]
    async fn reject_and_completion_do_not_retire_an_inherited_ancestor_uuid() {
        let (_tmp, db, session, owner, parent) = durable_managed_fixture().await;
        let inherited = inherit_or_select_lease(Some(&parent), None)
            .unwrap()
            .expect("inherited clone");
        grace_retain_rejected_workspace_leases(&db, Some(&parent), [Some(&inherited)])
            .await
            .unwrap();
        grace_retain_completed_child_workspace_lease(&db, Some(&parent), &inherited)
            .await
            .unwrap();
        let current = db
            .workspace_lease(session, owner, parent.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            current.state,
            WorkspaceLeaseState::Active,
            "a still-live ancestor UUID must stay Active across child reject/completion"
        );
    }

    #[tokio::test]
    async fn minted_child_reject_retires_managed_row_from_active() {
        let (_tmp, db, session, owner, lease) = durable_managed_fixture().await;
        let parent = WorkspaceLease::host_issued_managed_worktree(
            Uuid::new_v4(),
            lease.visibility_root.clone(),
            WorkspaceLeaseOps::for_coding(),
            future_expiry(),
        );
        grace_retain_rejected_workspace_leases(&db, Some(&parent), [Some(&lease)])
            .await
            .unwrap();
        let current = db
            .workspace_lease(session, owner, lease.id)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(current.state, WorkspaceLeaseState::Active);
    }

    #[tokio::test]
    async fn tool_revalidate_expires_wall_clock_active_lease_to_grace() {
        let (_tmp, db, session, owner, lease) = durable_managed_fixture_at(50, 100).await;
        assert!(
            lease.revalidate_for_tools(&db).await.is_err(),
            "expired snapshot must fail closed at the tool boundary"
        );
        let current = db
            .workspace_lease(session, owner, lease.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            current.state,
            WorkspaceLeaseState::Grace,
            "live-session wall-clock expiry must persist Active→Grace"
        );
    }

    #[tokio::test]
    async fn session_idle_expiry_persists_active_to_grace_without_a_tool() {
        let (_tmp, db, session, owner, lease) = durable_managed_fixture_at(50, 100).await;
        expire_session_active_workspace_leases_if_due(&db, session)
            .await
            .unwrap();
        let current = db
            .workspace_lease(session, owner, lease.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            current.state,
            WorkspaceLeaseState::Grace,
            "idle wall-clock expiry must persist Active→Grace without a later tool"
        );
    }

    #[tokio::test]
    async fn session_shutdown_retires_unexpired_managed_active_rows() {
        let (_tmp, db, session, owner, lease) = durable_managed_fixture().await;
        assert_eq!(lease.state, WorkspaceLeaseState::Active);
        retire_session_managed_workspace_leases(&db, session)
            .await
            .unwrap();
        let current = db
            .workspace_lease(session, owner, lease.id)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            current.state,
            WorkspaceLeaseState::Active,
            "terminal shutdown must leave managed rows non-Active"
        );
    }
}
