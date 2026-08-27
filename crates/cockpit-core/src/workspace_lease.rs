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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use uuid::Uuid;

use crate::agents::{DelegationTarget, EffectiveVnextGrant, ExecutionKind};
use crate::db::workspace_lease_artifacts::{
    LeaseCasOutcome, WorkspaceDigest, WorkspaceLeaseKind as DbLeaseKind, WorkspaceLeaseRow,
    WorkspaceLeaseState, WorkspaceLeaseTerminalReason,
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
    pub canonical_repository_id: String,
    pub canonical_root: PathBuf,
    pub kind: WorkspaceLeaseKind,
    pub visibility_root: PathBuf,
    pub base_sha_digest: WorkspaceDigest,
    pub base_ref_digest: WorkspaceDigest,
    pub managed_path: PathBuf,
    pub allowed_ops: WorkspaceLeaseOps,
    pub expires_at_unix_ms: i64,
    pub state: WorkspaceLeaseState,
    pub revision: i64,
}

impl WorkspaceLease {
    pub fn from_row(row: &WorkspaceLeaseRow, allowed_ops: WorkspaceLeaseOps) -> Result<Self> {
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
            canonical_repository_id: row.canonical_repository_id.clone(),
            canonical_root,
            kind,
            visibility_root,
            base_sha_digest: row.base_sha_digest.clone(),
            base_ref_digest: row.base_ref_digest.clone(),
            managed_path,
            allowed_ops: allowed_ops.confined_to_kind(kind),
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
            canonical_repository_id: "ephemeral".into(),
            canonical_root: visibility_root.clone(),
            kind,
            managed_path: visibility_root.clone(),
            visibility_root,
            base_sha_digest: WorkspaceDigest::of(b"ephemeral"),
            base_ref_digest: WorkspaceDigest::of(b"ephemeral"),
            allowed_ops: allowed_ops.confined_to_kind(kind),
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

    /// Durable identity check used at crash recovery. A missing path or a
    /// managed worktree that is no longer a git directory is a mismatch; the
    /// host marks the lease uncertain rather than deleting it. HEAD movement
    /// from in-lease work is not a mismatch.
    pub fn identity_matches_disk(&self) -> bool {
        let Ok(root) = cockpit_host::path_containment::effective_path(&self.visibility_root) else {
            return false;
        };
        if !root.is_dir() {
            return false;
        }
        if self.kind == WorkspaceLeaseKind::ManagedWorktree {
            return crate::git::find_worktree_root(&root).is_some();
        }
        true
    }
}

/// `<daemon-state>/worktrees/<lease-uuid>`.
pub fn managed_worktree_path(state_dir: &Path, lease_id: Uuid) -> PathBuf {
    state_dir.join("worktrees").join(lease_id.to_string())
}

/// True when `path` is a host-managed worktree directory
/// (`.../worktrees/<lease-uuid>`), so child cwd resolution may leave the
/// primary repository.
pub fn is_managed_worktree_path(path: &Path) -> bool {
    let Ok(path) = cockpit_host::path_containment::effective_path(path) else {
        return false;
    };
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        if component.as_os_str() == "worktrees"
            && let Some(id) = components.peek()
            && Uuid::parse_str(&id.as_os_str().to_string_lossy()).is_ok()
        {
            return true;
        }
    }
    false
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

/// Resolve a task-selected lease from the durable owner-scoped ledger. Task
/// arguments never mint authority: kind spellings are documentation helpers,
/// while an actual launch must name a live host-issued UUID.
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
        .ok_or_else(|| format!("workspace lease `{id}` is not live and owned by this agent"))?;
    WorkspaceLease::from_row(&row, WorkspaceLeaseOps::for_coding())
        .map(Some)
        .map_err(|error| format!("loading workspace lease `{id}`: {error:#}"))
}

/// Result of intersecting a selected lease with the parent's live grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseIntersection {
    pub lease: WorkspaceLease,
    pub child_cwd: PathBuf,
    pub write_scope: Option<PathBuf>,
    pub allowed_ops: WorkspaceLeaseOps,
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

    if let Some(scope) = requested_write_scope {
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
    }

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
        write_scope: requested_write_scope.map(Path::to_path_buf),
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

/// Crash recovery: mark identity-mismatched live leases `uncertain` and
/// never remove the path. Only a later host-authorized cleanup may delete.
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
        let lease = WorkspaceLease::from_row(&row, WorkspaceLeaseOps::for_coding())?;
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
            LeaseCasOutcome::RevisionConflict => recovered.push(row),
        }
    }
    Ok(recovered)
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
    use crate::db::workspace_lease_artifacts::{NewWorkspaceLease, WorkspaceLeaseKind as DbKind};
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
        let lease = WorkspaceLease {
            id,
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
        assert!(grant.permits_target_with_lease(&primary, &wt, Some(&lease)));
        assert!(!grant.permits_target_with_lease(&primary, &primary, Some(&lease)));
        assert!(!wt.starts_with(std::env::temp_dir().join("cockpit-harness-")));
        assert!(wt.ends_with(Path::new("worktrees").join(id.to_string())));
    }

    #[test]
    fn nested_declared_grants_succeed_and_minimal_agent_stays_a_leaf() {
        let orchestrator = parent_grant(vec![DelegationTarget::SameRoot]);
        assert!(orchestrator.delegation.is_some());
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
        let _ = orchestrator;
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
                    canonical_repository_id: "repo-id".into(),
                    canonical_root: repo.to_string_lossy().into_owned(),
                    kind: DbKind::SameRoot,
                    base_sha_digest: WorkspaceDigest::of(b"head"),
                    base_ref_digest: WorkspaceDigest::of(b"ref"),
                    managed_path: repo.to_string_lossy().into_owned(),
                    private_ref_digest: WorkspaceDigest::of(b"private"),
                    expires_at_unix_ms: 10_000,
                },
                3,
            )
            .await
            .unwrap();
        assert_eq!(row.kind, DbKind::SameRoot);
        let runtime = WorkspaceLease::from_row(&row, WorkspaceLeaseOps::for_coding()).unwrap();
        assert_eq!(runtime.kind, WorkspaceLeaseKind::SameRoot);
        assert!(runtime.is_live(4));

        std::fs::remove_dir_all(&repo).unwrap();
        let recovered = recover_session_workspace_leases(&db, session.session_id, 5)
            .await
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].state, WorkspaceLeaseState::Uncertain);
        assert!(
            !repo.exists(),
            "recovery must not recreate or delete via force-remove of a missing path"
        );
    }

    #[test]
    fn is_managed_worktree_path_requires_worktrees_uuid_segment() {
        let tmp = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        let real = managed_worktree_path(tmp.path(), id);
        std::fs::create_dir_all(&real).unwrap();
        assert!(is_managed_worktree_path(&real));
        assert!(!is_managed_worktree_path(tmp.path()));
        assert!(!is_managed_worktree_path(
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
}
