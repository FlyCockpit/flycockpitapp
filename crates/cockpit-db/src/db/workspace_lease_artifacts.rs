//! Daemon-owned workspace lease and commitless task-artifact persistence.
//!
//! This module intentionally stores only canonical identities and fixed-size
//! digests.  It is not a filesystem API: callers prove identity outside this
//! crate and report the redacted result through the CAS transitions below.

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::db::Db;

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A fixed, lower-case SHA-256 receipt. Raw patches, refs, manifests and
/// provider values never cross this durable boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkspaceDigest(String);

impl WorkspaceDigest {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("workspace receipt must be a lower-case SHA-256 digest");
        }
        Ok(Self(value))
    }

    pub fn of(bytes: impl AsRef<[u8]>) -> Self {
        Self(sha256_hex(bytes.as_ref()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceLeaseKind {
    Worktree,
    Repository,
}
impl WorkspaceLeaseKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Worktree => "worktree",
            Self::Repository => "repository",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "worktree" => Ok(Self::Worktree),
            "repository" => Ok(Self::Repository),
            _ => bail!("unknown workspace lease kind"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceLeaseState {
    Active,
    Grace,
    Cleaned,
    Uncertain,
}
impl WorkspaceLeaseState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Cleaned => "cleaned",
            Self::Uncertain => "uncertain",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "active" => Ok(Self::Active),
            "grace" => Ok(Self::Grace),
            "cleaned" => Ok(Self::Cleaned),
            "uncertain" => Ok(Self::Uncertain),
            _ => bail!("unknown workspace lease state"),
        }
    }
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Cleaned)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceLeaseTerminalReason {
    Expired,
    IdentityMismatch,
    HostCleanup,
    RestartUncertain,
}
impl WorkspaceLeaseTerminalReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::IdentityMismatch => "identity_mismatch",
            Self::HostCleanup => "host_cleanup",
            Self::RestartUncertain => "restart_uncertain",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "expired" => Ok(Self::Expired),
            "identity_mismatch" => Ok(Self::IdentityMismatch),
            "host_cleanup" => Ok(Self::HostCleanup),
            "restart_uncertain" => Ok(Self::RestartUncertain),
            _ => bail!("unknown workspace lease terminal reason"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskArtifactState {
    Produced,
    Integrating,
    Integrated,
    Stale,
    Conflict,
    Cancelled,
    Failed,
}
impl TaskArtifactState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Produced => "produced",
            Self::Integrating => "integrating",
            Self::Integrated => "integrated",
            Self::Stale => "stale",
            Self::Conflict => "conflict",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "produced" => Ok(Self::Produced),
            "integrating" => Ok(Self::Integrating),
            "integrated" => Ok(Self::Integrated),
            "stale" => Ok(Self::Stale),
            "conflict" => Ok(Self::Conflict),
            "cancelled" => Ok(Self::Cancelled),
            "failed" => Ok(Self::Failed),
            _ => bail!("unknown task artifact state"),
        }
    }
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Produced | Self::Integrating)
    }
}

/// Closed, redacted parent result retained with an artifact. The enum makes a
/// secret-shaped or free-form classification impossible to persist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactResultClass {
    Produced,
    Cancelled,
    Integrated,
    Stale,
    Conflict,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedArtifactResult {
    pub class: ArtifactResultClass,
    pub digest: WorkspaceDigest,
}
impl RedactedArtifactResult {
    pub fn new(class: ArtifactResultClass, digest: WorkspaceDigest) -> Self {
        Self { class, digest }
    }
    fn encode(&self) -> Result<String> {
        serde_json::to_string(self).context("encoding redacted artifact result")
    }
    fn decode(raw: &str) -> Result<Self> {
        serde_json::from_str(raw).context("decoding redacted artifact result")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceLeaseRow {
    pub workspace_lease_id: Uuid,
    pub session_id: Uuid,
    pub agent_instance_id: Uuid,
    pub write_scope_lease_id: Uuid,
    pub canonical_repository_id: String,
    pub canonical_root: String,
    pub kind: WorkspaceLeaseKind,
    pub base_sha_digest: WorkspaceDigest,
    pub base_ref_digest: WorkspaceDigest,
    pub managed_path: String,
    pub private_ref_digest: WorkspaceDigest,
    pub state: WorkspaceLeaseState,
    pub expires_at_unix_ms: i64,
    pub revision: i64,
    pub terminal_reason: Option<WorkspaceLeaseTerminalReason>,
    /// Nonterminal recovery/expiry reason. It is retained through cleanup so
    /// restart inspection can distinguish an ordinary expiry from ambiguity.
    pub uncertain_reason: Option<WorkspaceLeaseTerminalReason>,
    pub pinned_at_unix_ms: Option<i64>,
    pub pinned_by_agent_instance_id: Option<Uuid>,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskArtifactRow {
    pub artifact_id: Uuid,
    pub source_workspace_lease_id: Uuid,
    pub session_id: Uuid,
    pub agent_instance_id: Uuid,
    pub base_head_digest: WorkspaceDigest,
    pub base_ref_digest: WorkspaceDigest,
    pub base_index_digest: WorkspaceDigest,
    pub touched_manifest_digest: WorkspaceDigest,
    pub untracked_manifest_digest: WorkspaceDigest,
    pub ordered_patch_digest: WorkspaceDigest,
    pub validation_receipt_digest: WorkspaceDigest,
    pub parent_result: RedactedArtifactResult,
    pub state: TaskArtifactState,
    pub revision: i64,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskArtifactIntegrationReceipt {
    pub artifact_id: Uuid,
    pub session_id: Uuid,
    pub target_canonical_repository_id: String,
    pub target_canonical_root: String,
    pub target_head_digest: WorkspaceDigest,
    pub target_ref_digest: WorkspaceDigest,
    pub target_index_digest: WorkspaceDigest,
    pub changed_path_manifest_digest: WorkspaceDigest,
    pub target_write_scope_lease_id: Uuid,
    pub expected_target_generation: u64,
    pub expected_target_revision: u64,
    pub created_at_unix_ms: i64,
}

#[derive(Debug, Clone)]
pub struct NewWorkspaceLease {
    pub session_id: Uuid,
    pub agent_instance_id: Uuid,
    pub write_scope_lease_id: Uuid,
    pub canonical_repository_id: String,
    pub canonical_root: String,
    pub kind: WorkspaceLeaseKind,
    pub base_sha_digest: WorkspaceDigest,
    pub base_ref_digest: WorkspaceDigest,
    pub managed_path: String,
    pub private_ref_digest: WorkspaceDigest,
    pub expires_at_unix_ms: i64,
}

#[derive(Debug, Clone)]
pub struct NewTaskArtifact {
    pub source_workspace_lease_id: Uuid,
    pub session_id: Uuid,
    pub agent_instance_id: Uuid,
    pub base_head_digest: WorkspaceDigest,
    pub base_ref_digest: WorkspaceDigest,
    pub base_index_digest: WorkspaceDigest,
    pub touched_manifest_digest: WorkspaceDigest,
    pub untracked_manifest_digest: WorkspaceDigest,
    pub ordered_patch_digest: WorkspaceDigest,
    pub validation_receipt_digest: WorkspaceDigest,
    pub parent_result: RedactedArtifactResult,
}

#[derive(Debug, Clone)]
pub struct IntegrationTarget {
    pub target_canonical_repository_id: String,
    /// Canonical root of the target worktree. It may differ from the source
    /// lease root while remaining in the same canonical repository.
    pub target_canonical_root: String,
    pub target_head_digest: WorkspaceDigest,
    pub target_ref_digest: WorkspaceDigest,
    pub target_index_digest: WorkspaceDigest,
    pub changed_path_manifest_digest: WorkspaceDigest,
    pub target_write_scope_lease_id: Uuid,
    pub expected_target_generation: u64,
    pub expected_target_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseCasOutcome {
    Transitioned(WorkspaceLeaseRow),
    AlreadyTerminal(WorkspaceLeaseRow),
    RevisionConflict,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactCasOutcome {
    Transitioned(TaskArtifactRow),
    AlreadyTerminal(TaskArtifactRow),
    RevisionConflict,
}

const LEASE_COLS: &str = "workspace_lease_id, session_id, agent_instance_id, write_scope_lease_id, canonical_repository_id, canonical_root, kind, base_sha_digest, base_ref_digest, managed_path, private_ref_digest, state, expires_at_unix_ms, revision, terminal_reason, uncertain_reason, pinned_at_unix_ms, pinned_by_agent_instance_id, created_at_unix_ms, updated_at_unix_ms";
const ARTIFACT_COLS: &str = "artifact_id, source_workspace_lease_id, session_id, agent_instance_id, base_head_digest, base_ref_digest, base_index_digest, touched_manifest_digest, untracked_manifest_digest, ordered_patch_digest, validation_receipt_digest, parent_result_json, state, revision, created_at_unix_ms, updated_at_unix_ms";

fn uuid(raw: String, index: usize) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&raw).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, Box::new(e))
    })
}
fn digest(raw: String, index: usize) -> rusqlite::Result<WorkspaceDigest> {
    WorkspaceDigest::parse(raw).map_err(|error| invalid_persisted_error(index, error))
}
fn bounded_identity(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 2048
        || value.bytes().any(|b| b.is_ascii_control())
        || value.contains("..")
        || value.contains("@")
        || value.contains("://")
    {
        bail!("{field} is not a safe canonical identity");
    }
    Ok(())
}
fn map_lease(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkspaceLeaseRow> {
    let terminal: Option<String> = row.get(14)?;
    let uncertain: Option<String> = row.get(15)?;
    let pinned: Option<String> = row.get(17)?;
    Ok(WorkspaceLeaseRow {
        workspace_lease_id: uuid(row.get(0)?, 0)?,
        session_id: uuid(row.get(1)?, 1)?,
        agent_instance_id: uuid(row.get(2)?, 2)?,
        write_scope_lease_id: uuid(row.get(3)?, 3)?,
        canonical_repository_id: row.get(4)?,
        canonical_root: row.get(5)?,
        kind: WorkspaceLeaseKind::parse(&row.get::<_, String>(6)?).map_err(to_sql)?,
        base_sha_digest: digest(row.get(7)?, 7)?,
        base_ref_digest: digest(row.get(8)?, 8)?,
        managed_path: row.get(9)?,
        private_ref_digest: digest(row.get(10)?, 10)?,
        state: WorkspaceLeaseState::parse(&row.get::<_, String>(11)?).map_err(to_sql)?,
        expires_at_unix_ms: row.get(12)?,
        revision: row.get(13)?,
        terminal_reason: terminal
            .map(|v| WorkspaceLeaseTerminalReason::parse(&v).map_err(to_sql))
            .transpose()?,
        uncertain_reason: uncertain
            .map(|v| WorkspaceLeaseTerminalReason::parse(&v).map_err(to_sql))
            .transpose()?,
        pinned_at_unix_ms: row.get(16)?,
        pinned_by_agent_instance_id: pinned.map(|v| uuid(v, 17)).transpose()?,
        created_at_unix_ms: row.get(18)?,
        updated_at_unix_ms: row.get(19)?,
    })
}
fn map_artifact(row: &rusqlite::Row<'_>) -> rusqlite::Result<TaskArtifactRow> {
    let raw: String = row.get(11)?;
    Ok(TaskArtifactRow {
        artifact_id: uuid(row.get(0)?, 0)?,
        source_workspace_lease_id: uuid(row.get(1)?, 1)?,
        session_id: uuid(row.get(2)?, 2)?,
        agent_instance_id: uuid(row.get(3)?, 3)?,
        base_head_digest: digest(row.get(4)?, 4)?,
        base_ref_digest: digest(row.get(5)?, 5)?,
        base_index_digest: digest(row.get(6)?, 6)?,
        touched_manifest_digest: digest(row.get(7)?, 7)?,
        untracked_manifest_digest: digest(row.get(8)?, 8)?,
        ordered_patch_digest: digest(row.get(9)?, 9)?,
        validation_receipt_digest: digest(row.get(10)?, 10)?,
        parent_result: RedactedArtifactResult::decode(&raw).map_err(to_sql)?,
        state: TaskArtifactState::parse(&row.get::<_, String>(12)?).map_err(to_sql)?,
        revision: row.get(13)?,
        created_at_unix_ms: row.get(14)?,
        updated_at_unix_ms: row.get(15)?,
    })
}
fn invalid_persisted_error(index: usize, error: anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        index,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.to_string(),
        )),
    )
}
fn to_sql(error: anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        error.to_string(),
    )))
}
fn lease_for_owner(
    conn: &Connection,
    session: Uuid,
    agent: Uuid,
    lease: Uuid,
) -> Result<Option<WorkspaceLeaseRow>> {
    conn.query_row(&format!("SELECT {LEASE_COLS} FROM workspace_leases WHERE workspace_lease_id=?1 AND session_id=?2 AND agent_instance_id=?3"), params![lease.to_string(),session.to_string(),agent.to_string()], map_lease).optional().context("loading authorized workspace lease")
}
fn artifact_for_owner(
    conn: &Connection,
    session: Uuid,
    agent: Uuid,
    artifact: Uuid,
) -> Result<Option<TaskArtifactRow>> {
    conn.query_row(&format!("SELECT {ARTIFACT_COLS} FROM task_artifacts WHERE artifact_id=?1 AND session_id=?2 AND agent_instance_id=?3"), params![artifact.to_string(),session.to_string(),agent.to_string()], map_artifact).optional().context("loading authorized task artifact")
}
fn scope_is_owned_active(
    conn: &Connection,
    session: Uuid,
    agent: Uuid,
    scope: Uuid,
    canonical_root: &str,
    expected: Option<(u64, u64)>,
) -> Result<bool> {
    let found: Option<(i64, i64, String, String)> = conn
        .query_row(
            "SELECT generation, version, state, scope_path
             FROM write_scope_leases
             WHERE lease_id=?1 AND session_id=?2 AND owner_id=?3
               AND (agent_instance_id IS NULL OR agent_instance_id=?3)",
            params![scope.to_string(), session.to_string(), agent.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    Ok(
        found.is_some_and(|(generation, revision, state, scope_path)| {
            state == "active"
                && scope_path == canonical_root
                && expected.is_none_or(|(g, r)| generation == g as i64 && revision == r as i64)
        }),
    )
}

impl Db {
    /// Creates a lease only when the host-authorized agent still owns active
    /// write scope. This is deliberately an atomic proof + insert.
    pub async fn create_workspace_lease(
        &self,
        input: NewWorkspaceLease,
        now: i64,
    ) -> Result<WorkspaceLeaseRow> {
        bounded_identity(&input.canonical_repository_id, "repository identity")?;
        bounded_identity(&input.canonical_root, "canonical root")?;
        bounded_identity(&input.managed_path, "managed path")?;
        if input.expires_at_unix_ms <= now {
            bail!("workspace lease expiry must be in the future");
        }
        let id = Uuid::new_v4();
        self.transaction(move |conn| {
            if !scope_is_owned_active(conn,input.session_id,input.agent_instance_id,input.write_scope_lease_id,&input.canonical_root,None)? { bail!("write scope is not active at this workspace root and owned by this agent"); }
            conn.execute("INSERT INTO workspace_leases (workspace_lease_id,session_id,agent_instance_id,write_scope_lease_id,canonical_repository_id,canonical_root,kind,base_sha_digest,base_ref_digest,managed_path,private_ref_digest,state,expires_at_unix_ms,revision,terminal_reason,uncertain_reason,pinned_at_unix_ms,pinned_by_agent_instance_id,created_at_unix_ms,updated_at_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'active',?12,0,NULL,NULL,NULL,NULL,?13,?13)", params![id.to_string(),input.session_id.to_string(),input.agent_instance_id.to_string(),input.write_scope_lease_id.to_string(),input.canonical_repository_id,input.canonical_root,input.kind.as_str(),input.base_sha_digest.as_str(),input.base_ref_digest.as_str(),input.managed_path,input.private_ref_digest.as_str(),input.expires_at_unix_ms,now]).context("inserting workspace lease")?;
            lease_for_owner(conn,input.session_id,input.agent_instance_id,id)?.context("created workspace lease missing")
        }).await
    }
    pub async fn workspace_lease(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
    ) -> Result<Option<WorkspaceLeaseRow>> {
        self.read(move |c| lease_for_owner(c, session, agent, id))
            .await
    }
    /// Tool admission is read-only and refuses grace, uncertain, cleaned and
    /// expired-active rows. Pinning intentionally does not change this rule.
    pub async fn workspace_lease_for_tools(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        now: i64,
    ) -> Result<Option<WorkspaceLeaseRow>> {
        self.read(move |c| {
            let Some(row) = lease_for_owner(c, session, agent, id)? else {
                return Ok(None);
            };
            Ok((row.state == WorkspaceLeaseState::Active
                && row.expires_at_unix_ms > now
                && scope_is_owned_active(
                    c,
                    session,
                    agent,
                    row.write_scope_lease_id,
                    &row.canonical_root,
                    None,
                )?)
            .then_some(row))
        })
        .await
    }
    pub async fn renew_workspace_lease(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        expected_revision: i64,
        new_expiry: i64,
        now: i64,
    ) -> Result<LeaseCasOutcome> {
        if new_expiry <= now {
            bail!("renewed expiry must be in the future");
        }
        self.transaction(move |c| { let Some(current)=lease_for_owner(c,session,agent,id)? else { return Ok(LeaseCasOutcome::RevisionConflict) }; if current.state.is_terminal(){return Ok(LeaseCasOutcome::AlreadyTerminal(current))}; if current.state != WorkspaceLeaseState::Active || current.expires_at_unix_ms <= now || current.revision != expected_revision || !scope_is_owned_active(c,session,agent,current.write_scope_lease_id,&current.canonical_root,None)? { return Ok(LeaseCasOutcome::RevisionConflict) }; c.execute("UPDATE workspace_leases SET expires_at_unix_ms=?1,revision=revision+1,updated_at_unix_ms=?2 WHERE workspace_lease_id=?3 AND revision=?4 AND state='active' AND expires_at_unix_ms>?2",params![new_expiry,now,id.to_string(),expected_revision])?; Ok(LeaseCasOutcome::Transitioned(lease_for_owner(c,session,agent,id)?.context("renewed lease missing")?)) }).await
    }
    pub async fn expire_workspace_lease(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        expected_revision: i64,
        now: i64,
    ) -> Result<LeaseCasOutcome> {
        self.transition_lease(
            session,
            agent,
            id,
            expected_revision,
            WorkspaceLeaseState::Active,
            WorkspaceLeaseState::Grace,
            None,
            Some(WorkspaceLeaseTerminalReason::Expired),
            now,
            false,
        )
        .await
    }
    /// Marks any live lease uncertain when restart identity proof fails. It
    /// never deletes the workspace; only a later host identity check may clean.
    pub async fn mark_workspace_lease_uncertain(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        expected_revision: i64,
        reason: WorkspaceLeaseTerminalReason,
        now: i64,
    ) -> Result<LeaseCasOutcome> {
        if !matches!(
            reason,
            WorkspaceLeaseTerminalReason::IdentityMismatch
                | WorkspaceLeaseTerminalReason::RestartUncertain
        ) {
            bail!("uncertain state requires an ambiguity reason");
        }
        self.transaction(move |c| { let Some(current)=lease_for_owner(c,session,agent,id)? else{return Ok(LeaseCasOutcome::RevisionConflict)}; if current.state.is_terminal(){return Ok(LeaseCasOutcome::AlreadyTerminal(current))}; if current.revision != expected_revision || !matches!(current.state,WorkspaceLeaseState::Active|WorkspaceLeaseState::Grace){return Ok(LeaseCasOutcome::RevisionConflict)}; c.execute("UPDATE workspace_leases SET state='uncertain',terminal_reason=NULL,uncertain_reason=?1,revision=revision+1,updated_at_unix_ms=?2 WHERE workspace_lease_id=?3 AND revision=?4 AND state IN ('active','grace')",params![reason.as_str(),now,id.to_string(),expected_revision])?; Ok(LeaseCasOutcome::Transitioned(lease_for_owner(c,session,agent,id)?.context("uncertain lease missing")?)) }).await
    }
    pub async fn pin_workspace_lease(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        expected_revision: i64,
        now: i64,
    ) -> Result<LeaseCasOutcome> {
        self.transaction(move |c| { let Some(current)=lease_for_owner(c,session,agent,id)? else{return Ok(LeaseCasOutcome::RevisionConflict)}; if current.state.is_terminal(){return Ok(LeaseCasOutcome::AlreadyTerminal(current))}; if current.revision != expected_revision{return Ok(LeaseCasOutcome::RevisionConflict)}; c.execute("UPDATE workspace_leases SET pinned_at_unix_ms=COALESCE(pinned_at_unix_ms,?1),pinned_by_agent_instance_id=COALESCE(pinned_by_agent_instance_id,?2),revision=revision+1,updated_at_unix_ms=?1 WHERE workspace_lease_id=?3 AND revision=?4",params![now,agent.to_string(),id.to_string(),expected_revision])?; Ok(LeaseCasOutcome::Transitioned(lease_for_owner(c,session,agent,id)?.context("pinned lease missing")?)) }).await
    }
    /// Host cleanup requires a successful identity proof. `uncertain` cannot
    /// turn into deletion merely because a timer fired.
    pub async fn clean_workspace_lease(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        expected_revision: i64,
        identity_matches: bool,
        now: i64,
    ) -> Result<LeaseCasOutcome> {
        if !identity_matches {
            return self
                .mark_workspace_lease_uncertain(
                    session,
                    agent,
                    id,
                    expected_revision,
                    WorkspaceLeaseTerminalReason::IdentityMismatch,
                    now,
                )
                .await;
        }
        self.transition_lease(
            session,
            agent,
            id,
            expected_revision,
            WorkspaceLeaseState::Grace,
            WorkspaceLeaseState::Cleaned,
            Some(WorkspaceLeaseTerminalReason::HostCleanup),
            None,
            now,
            true,
        )
        .await
    }
    // Lease transitions intentionally expose each owner/CAS/state/reason
    // predicate; a generic payload would weaken this lifecycle boundary.
    #[allow(clippy::too_many_arguments)]
    async fn transition_lease(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        expected: i64,
        from: WorkspaceLeaseState,
        to: WorkspaceLeaseState,
        reason: Option<WorkspaceLeaseTerminalReason>,
        uncertain_reason: Option<WorkspaceLeaseTerminalReason>,
        now: i64,
        allow_uncertain: bool,
    ) -> Result<LeaseCasOutcome> {
        self.transaction(move |c| { let Some(current)=lease_for_owner(c,session,agent,id)? else{return Ok(LeaseCasOutcome::RevisionConflict)}; if current.state.is_terminal(){return Ok(LeaseCasOutcome::AlreadyTerminal(current))}; if current.revision != expected || !(current.state == from || allow_uncertain && current.state == WorkspaceLeaseState::Uncertain) || (from == WorkspaceLeaseState::Active && current.expires_at_unix_ms > now) {return Ok(LeaseCasOutcome::RevisionConflict)}; c.execute("UPDATE workspace_leases SET state=?1,terminal_reason=?2,uncertain_reason=COALESCE(?3, uncertain_reason),revision=revision+1,updated_at_unix_ms=?4 WHERE workspace_lease_id=?5 AND revision=?6",params![to.as_str(),reason.map(|v|v.as_str()),uncertain_reason.map(|v|v.as_str()),now,id.to_string(),expected])?; Ok(LeaseCasOutcome::Transitioned(lease_for_owner(c,session,agent,id)?.context("transitioned workspace lease missing")?)) }).await
    }

    pub async fn create_task_artifact(
        &self,
        input: NewTaskArtifact,
        now: i64,
    ) -> Result<TaskArtifactRow> {
        let id = Uuid::new_v4();
        self.transaction(move |c| { let lease=lease_for_owner(c,input.session_id,input.agent_instance_id,input.source_workspace_lease_id)?.context("source workspace lease is not owned")?; if lease.state != WorkspaceLeaseState::Active || lease.expires_at_unix_ms <= now || !scope_is_owned_active(c,input.session_id,input.agent_instance_id,lease.write_scope_lease_id,&lease.canonical_root,None)? { bail!("source workspace lease is unavailable for artifact production"); } let parent=input.parent_result.encode()?; c.execute("INSERT INTO task_artifacts (artifact_id,source_workspace_lease_id,session_id,agent_instance_id,base_head_digest,base_ref_digest,base_index_digest,touched_manifest_digest,untracked_manifest_digest,ordered_patch_digest,validation_receipt_digest,parent_result_json,state,revision,created_at_unix_ms,updated_at_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'produced',0,?13,?13)",params![id.to_string(),input.source_workspace_lease_id.to_string(),input.session_id.to_string(),input.agent_instance_id.to_string(),input.base_head_digest.as_str(),input.base_ref_digest.as_str(),input.base_index_digest.as_str(),input.touched_manifest_digest.as_str(),input.untracked_manifest_digest.as_str(),input.ordered_patch_digest.as_str(),input.validation_receipt_digest.as_str(),parent,now])?; artifact_for_owner(c,input.session_id,input.agent_instance_id,id)?.context("created artifact missing") }).await
    }
    pub async fn task_artifact(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
    ) -> Result<Option<TaskArtifactRow>> {
        self.read(move |c| artifact_for_owner(c, session, agent, id))
            .await
    }
    pub async fn begin_task_artifact_integration(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        expected: i64,
        now: i64,
    ) -> Result<ArtifactCasOutcome> {
        self.transition_artifact(
            session,
            agent,
            id,
            expected,
            TaskArtifactState::Produced,
            TaskArtifactState::Integrating,
            now,
        )
        .await
    }
    pub async fn retry_task_artifact_integration(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        expected: i64,
        now: i64,
    ) -> Result<ArtifactCasOutcome> {
        self.transaction(move |c| {
            let Some(current) = artifact_for_owner(c, session, agent, id)? else {
                return Ok(ArtifactCasOutcome::RevisionConflict);
            };
            if current.state.is_terminal() {
                return Ok(ArtifactCasOutcome::AlreadyTerminal(current));
            }
            if current.state != TaskArtifactState::Integrating || current.revision != expected {
                return Ok(ArtifactCasOutcome::RevisionConflict);
            }
            // A receipt is the durable point at which target mutation became
            // visible. Retrying is allowed only before that point.
            let has_receipt: bool = c.query_row(
                "SELECT EXISTS(SELECT 1 FROM task_artifact_integration_receipts WHERE artifact_id=?1 AND session_id=?2)",
                params![id.to_string(), session.to_string()],
                |r| r.get(0),
            )?;
            if has_receipt {
                return Ok(ArtifactCasOutcome::RevisionConflict);
            }
            c.execute(
                "UPDATE task_artifacts SET state='produced',revision=revision+1,updated_at_unix_ms=?1 WHERE artifact_id=?2 AND revision=?3 AND state='integrating'",
                params![now, id.to_string(), expected],
            )?;
            Ok(ArtifactCasOutcome::Transitioned(
                artifact_for_owner(c, session, agent, id)?.context("retried artifact missing")?,
            ))
        })
        .await
    }
    pub async fn finish_task_artifact(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        expected: i64,
        state: TaskArtifactState,
        now: i64,
    ) -> Result<ArtifactCasOutcome> {
        if !matches!(
            state,
            TaskArtifactState::Stale
                | TaskArtifactState::Conflict
                | TaskArtifactState::Cancelled
                | TaskArtifactState::Failed
        ) {
            bail!("only a non-integrated terminal result can be finished directly");
        }
        self.transition_artifact(
            session,
            agent,
            id,
            expected,
            TaskArtifactState::Integrating,
            state,
            now,
        )
        .await
    }
    pub async fn cancel_task_artifact(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        expected: i64,
        now: i64,
    ) -> Result<ArtifactCasOutcome> {
        self.transaction(move |c| { let Some(current)=artifact_for_owner(c,session,agent,id)? else{return Ok(ArtifactCasOutcome::RevisionConflict)}; if current.state.is_terminal(){return Ok(ArtifactCasOutcome::AlreadyTerminal(current))}; if current.revision != expected{return Ok(ArtifactCasOutcome::RevisionConflict)}; c.execute("UPDATE task_artifacts SET state='cancelled',revision=revision+1,updated_at_unix_ms=?1 WHERE artifact_id=?2 AND revision=?3 AND state IN ('produced','integrating')",params![now,id.to_string(),expected])?; Ok(ArtifactCasOutcome::Transitioned(artifact_for_owner(c,session,agent,id)?.context("cancelled artifact missing")?)) }).await
    }
    // Artifact transitions preserve distinct owner, revision and graph-state
    // predicates for the same reason as lease transitions above.
    #[allow(clippy::too_many_arguments)]
    async fn transition_artifact(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        expected: i64,
        from: TaskArtifactState,
        to: TaskArtifactState,
        now: i64,
    ) -> Result<ArtifactCasOutcome> {
        self.transaction(move |c| { let Some(current)=artifact_for_owner(c,session,agent,id)? else{return Ok(ArtifactCasOutcome::RevisionConflict)}; if current.state.is_terminal(){return Ok(ArtifactCasOutcome::AlreadyTerminal(current))}; if current.revision != expected || current.state != from{return Ok(ArtifactCasOutcome::RevisionConflict)}; c.execute("UPDATE task_artifacts SET state=?1,revision=revision+1,updated_at_unix_ms=?2 WHERE artifact_id=?3 AND revision=?4 AND state=?5",params![to.as_str(),now,id.to_string(),expected,from.as_str()])?; Ok(ArtifactCasOutcome::Transitioned(artifact_for_owner(c,session,agent,id)?.context("transitioned artifact missing")?)) }).await
    }
    /// Commits the target-generation proof, immutable integration receipt, and
    /// `integrated` artifact state in one transaction. An unrelated dirty file
    /// never appears in this digest-only API and therefore cannot block it.
    pub async fn integrate_task_artifact(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        expected: i64,
        target: IntegrationTarget,
        now: i64,
    ) -> Result<ArtifactCasOutcome> {
        bounded_identity(
            &target.target_canonical_repository_id,
            "target repository identity",
        )?;
        bounded_identity(&target.target_canonical_root, "target canonical root")?;
        self.transaction(move |c| { let Some(current)=artifact_for_owner(c,session,agent,id)? else{return Ok(ArtifactCasOutcome::RevisionConflict)}; if current.state.is_terminal(){return Ok(ArtifactCasOutcome::AlreadyTerminal(current))}; if current.state != TaskArtifactState::Integrating || current.revision != expected{return Ok(ArtifactCasOutcome::RevisionConflict)}; let source=lease_for_owner(c,session,agent,current.source_workspace_lease_id)?.context("artifact source workspace lease missing")?; if target.target_canonical_repository_id != source.canonical_repository_id || !scope_is_owned_active(c,session,agent,target.target_write_scope_lease_id,&target.target_canonical_root,Some((target.expected_target_generation,target.expected_target_revision)))? { return Ok(ArtifactCasOutcome::RevisionConflict); } let changed=target.changed_path_manifest_digest.as_str().to_owned(); let inserted=c.execute("INSERT OR IGNORE INTO task_artifact_integration_receipts (artifact_id,session_id,target_canonical_repository_id,target_canonical_root,target_head_digest,target_ref_digest,target_index_digest,changed_path_manifest_digest,target_write_scope_lease_id,expected_target_generation,expected_target_revision,result_state,created_at_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'integrated',?12)",params![id.to_string(),session.to_string(),target.target_canonical_repository_id,target.target_canonical_root,target.target_head_digest.as_str(),target.target_ref_digest.as_str(),target.target_index_digest.as_str(),changed,target.target_write_scope_lease_id.to_string(),target.expected_target_generation as i64,target.expected_target_revision as i64,now])?; if inserted != 1 { bail!("integration receipt already exists for a nonterminal artifact"); } c.execute("UPDATE task_artifacts SET state='integrated',revision=revision+1,updated_at_unix_ms=?1 WHERE artifact_id=?2 AND revision=?3 AND state='integrating'",params![now,id.to_string(),expected])?; Ok(ArtifactCasOutcome::Transitioned(artifact_for_owner(c,session,agent,id)?.context("integrated artifact missing")?)) }).await
    }
    pub async fn task_artifact_integration_receipt(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
    ) -> Result<Option<TaskArtifactIntegrationReceipt>> {
        self.read(move |c| { if artifact_for_owner(c,session,agent,id)?.is_none() { return Ok(None); } c.query_row("SELECT artifact_id,session_id,target_canonical_repository_id,target_canonical_root,target_head_digest,target_ref_digest,target_index_digest,changed_path_manifest_digest,target_write_scope_lease_id,expected_target_generation,expected_target_revision,created_at_unix_ms FROM task_artifact_integration_receipts WHERE artifact_id=?1 AND session_id=?2",params![id.to_string(),session.to_string()],|r| Ok(TaskArtifactIntegrationReceipt { artifact_id:uuid(r.get(0)?,0)?,session_id:uuid(r.get(1)?,1)?,target_canonical_repository_id:r.get(2)?,target_canonical_root:r.get(3)?,target_head_digest:digest(r.get(4)?,4)?,target_ref_digest:digest(r.get(5)?,5)?,target_index_digest:digest(r.get(6)?,6)?,changed_path_manifest_digest:digest(r.get(7)?,7)?,target_write_scope_lease_id:uuid(r.get(8)?,8)?,expected_target_generation:r.get::<_,i64>(9)? as u64,expected_target_revision:r.get::<_,i64>(10)? as u64,created_at_unix_ms:r.get(11)?})).optional().context("loading integration receipt") }).await
    }
    pub async fn list_workspace_leases_for_recovery(
        &self,
        session: Uuid,
        agent: Uuid,
    ) -> Result<Vec<WorkspaceLeaseRow>> {
        self.read(move |c| { let mut stmt=c.prepare(&format!("SELECT {LEASE_COLS} FROM workspace_leases WHERE session_id=?1 AND agent_instance_id=?2 AND state IN ('active','grace','uncertain') ORDER BY created_at_unix_ms,workspace_lease_id"))?; stmt.query_map(params![session.to_string(),agent.to_string()],map_lease)?.collect::<std::result::Result<Vec<_>,_>>().context("loading workspace recovery leases") }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::agent_tree_decisions::{
        AgentInstanceState, AgentTransitionOutcome, NewAgentInstance,
    };
    use crate::db::write_scope_leases::{CasWriteScopeLease, WriteScopeLeaseRow};

    fn d(label: &str) -> WorkspaceDigest {
        WorkspaceDigest::of(label)
    }
    async fn owner(db: &Db, now: i64) -> (Uuid, Uuid, Uuid) {
        let session = db
            .create_session("lease-test", "/repo", "root")
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
                now,
            )
            .await
            .unwrap();
        assert!(matches!(
            db.transition_agent_instance(
                session.session_id,
                agent.agent_instance_id,
                0,
                AgentInstanceState::Running,
                r#"{"state":"running"}"#,
                now + 1
            )
            .await
            .unwrap(),
            AgentTransitionOutcome::Transitioned(_)
        ));
        let scope = Uuid::new_v4();
        db.insert_write_scope_lease(WriteScopeLeaseRow {
            lease_id: scope,
            parent_lease_id: None,
            session_id: session.session_id,
            task_id: None,
            scope_path: "/repo/work".into(),
            generation: 7,
            state: "active".into(),
            owner_id: agent.agent_instance_id.to_string(),
            version: 3,
            created_at_wall_ms: now,
            updated_at_wall_ms: now,
            released_at_wall_ms: None,
        })
        .await
        .unwrap();
        (session.session_id, agent.agent_instance_id, scope)
    }
    fn lease_input(session: Uuid, agent: Uuid, scope: Uuid, expiry: i64) -> NewWorkspaceLease {
        NewWorkspaceLease {
            session_id: session,
            agent_instance_id: agent,
            write_scope_lease_id: scope,
            canonical_repository_id: "repo-id".into(),
            canonical_root: "/repo/work".into(),
            kind: WorkspaceLeaseKind::Worktree,
            base_sha_digest: d("head"),
            base_ref_digest: d("ref"),
            managed_path: "agents/one".into(),
            private_ref_digest: d("private"),
            expires_at_unix_ms: expiry,
        }
    }
    fn artifact_input(session: Uuid, agent: Uuid, lease: Uuid) -> NewTaskArtifact {
        NewTaskArtifact {
            source_workspace_lease_id: lease,
            session_id: session,
            agent_instance_id: agent,
            base_head_digest: d("head"),
            base_ref_digest: d("ref"),
            base_index_digest: d("index"),
            touched_manifest_digest: d("touched"),
            untracked_manifest_digest: d("untracked"),
            ordered_patch_digest: d("patch"),
            validation_receipt_digest: d("validation"),
            parent_result: RedactedArtifactResult::new(ArtifactResultClass::Produced, d("result")),
        }
    }
    #[tokio::test]
    async fn workspace_lease_artifact_db_lifecycle_expiry_pin_and_receipt_are_exactly_once() {
        let db = Db::open_in_memory().unwrap();
        let (s, a, scope) = owner(&db, 100).await;
        let lease = db
            .create_workspace_lease(lease_input(s, a, scope, 200), 100)
            .await
            .unwrap();
        assert!(
            db.workspace_lease_for_tools(s, a, lease.workspace_lease_id, 199)
                .await
                .unwrap()
                .is_some()
        );
        // Retention is permitted after wall-clock expiry while the row is
        // still active, but it must not resurrect tool or renewal authority.
        let pinned = match db
            .pin_workspace_lease(s, a, lease.workspace_lease_id, 0, 200)
            .await
            .unwrap()
        {
            LeaseCasOutcome::Transitioned(v) => v,
            _ => panic!(),
        };
        assert!(
            db.workspace_lease_for_tools(s, a, lease.workspace_lease_id, 200)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            db.renew_workspace_lease(s, a, lease.workspace_lease_id, pinned.revision, 300, 200)
                .await
                .unwrap(),
            LeaseCasOutcome::RevisionConflict
        ));
        let grace = match db
            .expire_workspace_lease(s, a, lease.workspace_lease_id, pinned.revision, 201)
            .await
            .unwrap()
        {
            LeaseCasOutcome::Transitioned(v) => v,
            _ => panic!(),
        };
        assert!(
            db.workspace_lease_for_tools(s, a, lease.workspace_lease_id, 201)
                .await
                .unwrap()
                .is_none()
        );
        let cleaned = match db
            .clean_workspace_lease(s, a, lease.workspace_lease_id, grace.revision, true, 202)
            .await
            .unwrap()
        {
            LeaseCasOutcome::Transitioned(v) => v,
            _ => panic!(),
        };
        assert_eq!(cleaned.state, WorkspaceLeaseState::Cleaned);
        assert!(matches!(
            db.renew_workspace_lease(s, a, lease.workspace_lease_id, cleaned.revision, 400, 203)
                .await
                .unwrap(),
            LeaseCasOutcome::AlreadyTerminal(_)
        ));
    }
    #[tokio::test]
    async fn workspace_lease_artifact_db_integration_cas_isolated_and_generation_bound() {
        let db = Db::open_in_memory().unwrap();
        let (s, a, scope) = owner(&db, 10).await;
        let lease = db
            .create_workspace_lease(lease_input(s, a, scope, 100), 10)
            .await
            .unwrap();
        let artifact = db
            .create_task_artifact(artifact_input(s, a, lease.workspace_lease_id), 11)
            .await
            .unwrap();
        let integrating = match db
            .begin_task_artifact_integration(s, a, artifact.artifact_id, 0, 12)
            .await
            .unwrap()
        {
            ArtifactCasOutcome::Transitioned(v) => v,
            _ => panic!(),
        };
        let child_scope = Uuid::new_v4();
        db.insert_write_scope_lease(WriteScopeLeaseRow {
            lease_id: child_scope,
            parent_lease_id: Some(scope),
            session_id: s,
            task_id: None,
            scope_path: "/repo/isolated".into(),
            generation: 9,
            state: "active".into(),
            owner_id: a.to_string(),
            version: 1,
            created_at_wall_ms: 12,
            updated_at_wall_ms: 12,
            released_at_wall_ms: None,
        })
        .await
        .unwrap();
        let target = IntegrationTarget {
            target_canonical_repository_id: "repo-id".into(),
            target_canonical_root: "/repo/isolated".into(),
            target_head_digest: d("target-head"),
            target_ref_digest: d("target-ref"),
            target_index_digest: d("target-index"),
            changed_path_manifest_digest: d("changed"),
            target_write_scope_lease_id: child_scope,
            expected_target_generation: 9,
            expected_target_revision: 1,
        };
        let integrated = match db
            .integrate_task_artifact(
                s,
                a,
                artifact.artifact_id,
                integrating.revision,
                target.clone(),
                13,
            )
            .await
            .unwrap()
        {
            ArtifactCasOutcome::Transitioned(v) => v,
            _ => panic!(),
        };
        assert_eq!(integrated.state, TaskArtifactState::Integrated);
        assert_eq!(
            db.task_artifact_integration_receipt(s, a, artifact.artifact_id)
                .await
                .unwrap()
                .unwrap()
                .target_canonical_root,
            "/repo/isolated"
        );
        assert!(
            db.task_artifact_integration_receipt(s, a, artifact.artifact_id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            db.integrate_task_artifact(s, a, artifact.artifact_id, integrated.revision, target, 14)
                .await
                .unwrap(),
            ArtifactCasOutcome::AlreadyTerminal(_)
        ));
        let other = Uuid::new_v4();
        assert!(
            db.workspace_lease(s, other, lease.workspace_lease_id)
                .await
                .unwrap()
                .is_none()
        );
    }
    #[tokio::test]
    async fn workspace_lease_artifact_db_uncertain_never_deletes_without_identity() {
        let db = Db::open_in_memory().unwrap();
        let (s, a, scope) = owner(&db, 1).await;
        let lease = db
            .create_workspace_lease(lease_input(s, a, scope, 10), 1)
            .await
            .unwrap();
        let uncertain = match db
            .clean_workspace_lease(s, a, lease.workspace_lease_id, 0, false, 2)
            .await
            .unwrap()
        {
            LeaseCasOutcome::Transitioned(v) => v,
            _ => panic!(),
        };
        assert_eq!(uncertain.state, WorkspaceLeaseState::Uncertain);
        assert_eq!(
            uncertain.uncertain_reason,
            Some(WorkspaceLeaseTerminalReason::IdentityMismatch)
        );
        let cleaned = match db
            .clean_workspace_lease(s, a, lease.workspace_lease_id, uncertain.revision, true, 3)
            .await
            .unwrap()
        {
            LeaseCasOutcome::Transitioned(row) => row,
            other => panic!("unexpected cleanup outcome: {other:?}"),
        };
        assert_eq!(
            cleaned.terminal_reason,
            Some(WorkspaceLeaseTerminalReason::HostCleanup)
        );
        assert_eq!(
            cleaned.uncertain_reason,
            Some(WorkspaceLeaseTerminalReason::IdentityMismatch)
        );
    }

    #[tokio::test]
    async fn workspace_lease_artifact_db_rejects_unsafe_or_cross_session_authority() {
        let db = Db::open_in_memory().unwrap();
        let (s, a, scope) = owner(&db, 1).await;
        let mut unsafe_input = lease_input(s, a, scope, 20);
        unsafe_input.canonical_root = "/repo/../escape".into();
        assert!(db.create_workspace_lease(unsafe_input, 1).await.is_err());

        let lease = db
            .create_workspace_lease(lease_input(s, a, scope, 20), 1)
            .await
            .unwrap();
        let (other_session, other_agent, _) = owner(&db, 2).await;
        assert!(
            db.workspace_lease(other_session, other_agent, lease.workspace_lease_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.task_artifact(other_session, other_agent, Uuid::new_v4())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.create_task_artifact(
                artifact_input(other_session, other_agent, lease.workspace_lease_id),
                3,
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn workspace_lease_artifact_db_rejects_stale_target_and_terminal_rewrites() {
        let db = Db::open_in_memory().unwrap();
        let (s, a, scope) = owner(&db, 1).await;
        let lease = db
            .create_workspace_lease(lease_input(s, a, scope, 100), 1)
            .await
            .unwrap();
        let artifact = db
            .create_task_artifact(artifact_input(s, a, lease.workspace_lease_id), 2)
            .await
            .unwrap();
        let integrating = match db
            .begin_task_artifact_integration(s, a, artifact.artifact_id, 0, 3)
            .await
            .unwrap()
        {
            ArtifactCasOutcome::Transitioned(row) => row,
            other => panic!("unexpected transition outcome: {other:?}"),
        };
        let stale_target = IntegrationTarget {
            target_canonical_repository_id: "repo-id".into(),
            target_canonical_root: "/repo/work".into(),
            target_head_digest: d("target-head"),
            target_ref_digest: d("target-ref"),
            target_index_digest: d("target-index"),
            changed_path_manifest_digest: d("changed"),
            target_write_scope_lease_id: scope,
            expected_target_generation: 8,
            expected_target_revision: 3,
        };
        assert!(matches!(
            db.integrate_task_artifact(
                s,
                a,
                artifact.artifact_id,
                integrating.revision,
                stale_target,
                4
            )
            .await
            .unwrap(),
            ArtifactCasOutcome::RevisionConflict
        ));
        let cross_repo = IntegrationTarget {
            target_canonical_repository_id: "another-repo".into(),
            target_canonical_root: "/repo/work".into(),
            target_head_digest: d("target-head"),
            target_ref_digest: d("target-ref"),
            target_index_digest: d("target-index"),
            changed_path_manifest_digest: d("changed"),
            target_write_scope_lease_id: scope,
            expected_target_generation: 7,
            expected_target_revision: 3,
        };
        assert!(matches!(
            db.integrate_task_artifact(
                s,
                a,
                artifact.artifact_id,
                integrating.revision,
                cross_repo,
                4,
            )
            .await
            .unwrap(),
            ArtifactCasOutcome::RevisionConflict
        ));
        assert!(
            db.task_artifact_integration_receipt(s, a, artifact.artifact_id)
                .await
                .unwrap()
                .is_none()
        );
        let retry = match db
            .retry_task_artifact_integration(s, a, artifact.artifact_id, integrating.revision, 5)
            .await
            .unwrap()
        {
            ArtifactCasOutcome::Transitioned(row) => row,
            other => panic!("unexpected retry outcome: {other:?}"),
        };
        let cancelled = match db
            .cancel_task_artifact(s, a, artifact.artifact_id, retry.revision, 6)
            .await
            .unwrap()
        {
            ArtifactCasOutcome::Transitioned(row) => row,
            other => panic!("unexpected cancellation outcome: {other:?}"),
        };
        assert_eq!(cancelled.state, TaskArtifactState::Cancelled);
        assert!(matches!(
            db.begin_task_artifact_integration(s, a, artifact.artifact_id, cancelled.revision, 7)
                .await
                .unwrap(),
            ArtifactCasOutcome::AlreadyTerminal(_)
        ));
    }

    #[tokio::test]
    async fn workspace_lease_artifact_db_restart_lookup_and_expiry_race_are_deterministic() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("leases.sqlite");
        let first = Db::open(&path).unwrap();
        let (s, a, scope) = owner(&first, 10).await;
        let lease = first
            .create_workspace_lease(lease_input(s, a, scope, 20), 10)
            .await
            .unwrap();
        let artifact = first
            .create_task_artifact(artifact_input(s, a, lease.workspace_lease_id), 11)
            .await
            .unwrap();
        let integrating = match first
            .begin_task_artifact_integration(s, a, artifact.artifact_id, artifact.revision, 12)
            .await
            .unwrap()
        {
            ArtifactCasOutcome::Transitioned(row) => row,
            other => panic!("unexpected setup outcome: {other:?}"),
        };
        drop(first);

        let left = Db::open(&path).unwrap();
        let right = Db::open(&path).unwrap();
        let (one, two) = tokio::join!(
            left.expire_workspace_lease(s, a, lease.workspace_lease_id, 0, 20),
            right.expire_workspace_lease(s, a, lease.workspace_lease_id, 0, 20)
        );
        let winners = [one.unwrap(), two.unwrap()]
            .iter()
            .filter(|outcome| matches!(outcome, LeaseCasOutcome::Transitioned(_)))
            .count();
        assert_eq!(winners, 1);
        let recovery = left.list_workspace_leases_for_recovery(s, a).await.unwrap();
        assert_eq!(recovery.len(), 1);
        assert_eq!(recovery[0].state, WorkspaceLeaseState::Grace);

        let target = IntegrationTarget {
            target_canonical_repository_id: "repo-id".into(),
            target_canonical_root: "/repo/work".into(),
            target_head_digest: d("target-head"),
            target_ref_digest: d("target-ref"),
            target_index_digest: d("target-index"),
            changed_path_manifest_digest: d("changed"),
            target_write_scope_lease_id: scope,
            expected_target_generation: 7,
            expected_target_revision: 3,
        };
        let (first_settle, second_settle) = tokio::join!(
            left.integrate_task_artifact(
                s,
                a,
                artifact.artifact_id,
                integrating.revision,
                target.clone(),
                21
            ),
            right.integrate_task_artifact(
                s,
                a,
                artifact.artifact_id,
                integrating.revision,
                target,
                21
            )
        );
        let winners = [first_settle.unwrap(), second_settle.unwrap()]
            .iter()
            .filter(|outcome| matches!(outcome, ArtifactCasOutcome::Transitioned(_)))
            .count();
        assert_eq!(winners, 1);
        assert!(
            left.task_artifact_integration_receipt(s, a, artifact.artifact_id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn workspace_lease_artifact_db_artifact_terminal_matrix_and_illegal_edges() {
        let db = Db::open_in_memory().unwrap();
        let (s, a, scope) = owner(&db, 1).await;
        let lease = db
            .create_workspace_lease(lease_input(s, a, scope, 100), 1)
            .await
            .unwrap();
        for terminal in [
            TaskArtifactState::Stale,
            TaskArtifactState::Conflict,
            TaskArtifactState::Cancelled,
            TaskArtifactState::Failed,
        ] {
            let artifact = db
                .create_task_artifact(artifact_input(s, a, lease.workspace_lease_id), 2)
                .await
                .unwrap();
            assert!(matches!(
                db.finish_task_artifact(s, a, artifact.artifact_id, artifact.revision, terminal, 3)
                    .await
                    .unwrap(),
                ArtifactCasOutcome::RevisionConflict
            ));
            let integrating = match db
                .begin_task_artifact_integration(s, a, artifact.artifact_id, artifact.revision, 4)
                .await
                .unwrap()
            {
                ArtifactCasOutcome::Transitioned(row) => row,
                other => panic!("unexpected begin outcome: {other:?}"),
            };
            let terminal_row = match db
                .finish_task_artifact(
                    s,
                    a,
                    artifact.artifact_id,
                    integrating.revision,
                    terminal,
                    5,
                )
                .await
                .unwrap()
            {
                ArtifactCasOutcome::Transitioned(row) => row,
                other => panic!("unexpected terminal outcome: {other:?}"),
            };
            assert_eq!(terminal_row.state, terminal);
            assert!(matches!(
                db.retry_task_artifact_integration(
                    s,
                    a,
                    artifact.artifact_id,
                    terminal_row.revision,
                    6
                )
                .await
                .unwrap(),
                ArtifactCasOutcome::AlreadyTerminal(_)
            ));
        }
        let lease = db
            .workspace_lease(s, a, lease.workspace_lease_id)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            db.expire_workspace_lease(s, a, lease.workspace_lease_id, lease.revision, 99)
                .await
                .unwrap(),
            LeaseCasOutcome::RevisionConflict
        ));
    }

    #[tokio::test]
    async fn workspace_lease_artifact_db_scope_transfer_revokes_admission_and_renewal() {
        let db = Db::open_in_memory().unwrap();
        let (s, a, scope) = owner(&db, 1).await;
        let lease = db
            .create_workspace_lease(lease_input(s, a, scope, 100), 1)
            .await
            .unwrap();
        assert!(
            db.cas_write_scope_lease(CasWriteScopeLease {
                lease_id: scope,
                expected_state: "active".into(),
                expected_generation: 7,
                expected_version: 3,
                new_state: "transferring".into(),
                new_generation: 8,
                now_wall_ms: 2,
                released: false,
            })
            .await
            .unwrap()
            .is_some()
        );
        assert!(
            db.workspace_lease_for_tools(s, a, lease.workspace_lease_id, 3)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            db.renew_workspace_lease(s, a, lease.workspace_lease_id, 0, 200, 3)
                .await
                .unwrap(),
            LeaseCasOutcome::RevisionConflict
        ));
        assert!(
            db.create_task_artifact(artifact_input(s, a, lease.workspace_lease_id), 3)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn workspace_lease_artifact_db_provenance_and_receipts_are_storage_immutable() {
        let db = Db::open_in_memory().unwrap();
        let (s, a, scope) = owner(&db, 1).await;
        let lease = db
            .create_workspace_lease(lease_input(s, a, scope, 100), 1)
            .await
            .unwrap();
        let lease_id = lease.workspace_lease_id.to_string();
        assert!(db
            .write(move |conn| {
                conn.execute(
                    "UPDATE workspace_leases SET canonical_root='/changed', revision=revision+1 WHERE workspace_lease_id=?1",
                    [lease_id],
                )?;
                Ok(())
            })
            .await
            .is_err());
        let artifact = db
            .create_task_artifact(artifact_input(s, a, lease.workspace_lease_id), 2)
            .await
            .unwrap();
        let artifact_id = artifact.artifact_id.to_string();
        assert!(db
            .write(move |conn| {
                let different = d("different").as_str().to_owned();
                conn.execute(
                    "UPDATE task_artifacts SET ordered_patch_digest=?1, revision=revision+1 WHERE artifact_id=?2",
                    params![different, artifact_id],
                )?;
                Ok(())
            })
            .await
            .is_err());
        let integrating = match db
            .begin_task_artifact_integration(s, a, artifact.artifact_id, 0, 3)
            .await
            .unwrap()
        {
            ArtifactCasOutcome::Transitioned(row) => row,
            other => panic!("unexpected integration begin: {other:?}"),
        };
        let target = IntegrationTarget {
            target_canonical_repository_id: "repo-id".into(),
            target_canonical_root: "/repo/work".into(),
            target_head_digest: d("target-head"),
            target_ref_digest: d("target-ref"),
            target_index_digest: d("target-index"),
            changed_path_manifest_digest: d("changed"),
            target_write_scope_lease_id: scope,
            expected_target_generation: 7,
            expected_target_revision: 3,
        };
        assert!(matches!(
            db.integrate_task_artifact(s, a, artifact.artifact_id, integrating.revision, target, 4)
                .await
                .unwrap(),
            ArtifactCasOutcome::Transitioned(_)
        ));
        let receipt_id = artifact.artifact_id.to_string();
        let receipt_count = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM task_artifact_integration_receipts WHERE artifact_id=?1",
                    [receipt_id],
                    |row| row.get::<_, i64>(0),
                )
                .context("counting artifact integration receipts")
            })
            .await
            .unwrap();
        assert_eq!(receipt_count, 1);
        let receipt_id = artifact.artifact_id.to_string();
        assert!(db
            .write(move |conn| {
                let forged = d("forged").as_str().to_owned();
                conn.execute(
                    "UPDATE task_artifact_integration_receipts SET target_head_digest=?1 WHERE artifact_id=?2",
                    params![forged, receipt_id],
                )?;
                Ok(())
            })
            .await
            .is_err());
        let receipt_id = artifact.artifact_id.to_string();
        assert!(
            db.write(move |conn| {
                conn.execute(
                    "DELETE FROM task_artifact_integration_receipts WHERE artifact_id=?1",
                    [receipt_id],
                )?;
                Ok(())
            })
            .await
            .is_err()
        );
        db.write(move |conn| {
            conn.execute("DELETE FROM sessions WHERE session_id=?1", [s.to_string()])?;
            Ok(())
        })
        .await
        .unwrap();
        let receipt_id = artifact.artifact_id.to_string();
        let receipt_count = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM task_artifact_integration_receipts WHERE artifact_id=?1",
                    [receipt_id],
                    |row| row.get::<_, i64>(0),
                )
                .context("counting cascaded integration receipts")
            })
            .await
            .unwrap();
        assert_eq!(receipt_count, 0);
    }

    #[tokio::test]
    async fn workspace_lease_artifact_db_grace_to_uncertain_retains_closed_reason() {
        let db = Db::open_in_memory().unwrap();
        let (s, a, scope) = owner(&db, 1).await;
        let lease = db
            .create_workspace_lease(lease_input(s, a, scope, 10), 1)
            .await
            .unwrap();
        let grace = match db
            .expire_workspace_lease(s, a, lease.workspace_lease_id, 0, 10)
            .await
            .unwrap()
        {
            LeaseCasOutcome::Transitioned(row) => row,
            other => panic!("unexpected expiry outcome: {other:?}"),
        };
        assert_eq!(
            grace.uncertain_reason,
            Some(WorkspaceLeaseTerminalReason::Expired)
        );
        let uncertain = match db
            .mark_workspace_lease_uncertain(
                s,
                a,
                lease.workspace_lease_id,
                grace.revision,
                WorkspaceLeaseTerminalReason::RestartUncertain,
                11,
            )
            .await
            .unwrap()
        {
            LeaseCasOutcome::Transitioned(row) => row,
            other => panic!("unexpected uncertainty outcome: {other:?}"),
        };
        assert_eq!(
            uncertain.uncertain_reason,
            Some(WorkspaceLeaseTerminalReason::RestartUncertain)
        );
        assert_eq!(
            db.list_workspace_leases_for_recovery(s, a).await.unwrap(),
            vec![uncertain]
        );
    }

    #[tokio::test]
    async fn workspace_lease_artifact_db_uncertainty_reason_survives_restart_lookup() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("uncertain.sqlite");
        let first = Db::open(&path).unwrap();
        let (s, a, scope) = owner(&first, 1).await;
        let lease = first
            .create_workspace_lease(lease_input(s, a, scope, 100), 1)
            .await
            .unwrap();
        let uncertain = match first
            .mark_workspace_lease_uncertain(
                s,
                a,
                lease.workspace_lease_id,
                lease.revision,
                WorkspaceLeaseTerminalReason::RestartUncertain,
                2,
            )
            .await
            .unwrap()
        {
            LeaseCasOutcome::Transitioned(row) => row,
            other => panic!("unexpected uncertainty outcome: {other:?}"),
        };
        drop(first);
        let reopened = Db::open(&path).unwrap();
        assert_eq!(
            reopened
                .list_workspace_leases_for_recovery(s, a)
                .await
                .unwrap(),
            vec![uncertain]
        );
    }

    #[test]
    fn workspace_lease_artifact_db_redacted_result_is_closed_and_digest_only() {
        assert!(WorkspaceDigest::parse("secret-token").is_err());
        assert!(RedactedArtifactResult::decode(
            r#"{"class":"produced","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","token":"secret"}"#
        )
        .is_err());
        assert!(RedactedArtifactResult::decode(
            r#"{"class":"unclassified","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#
        )
        .is_err());
    }
}
