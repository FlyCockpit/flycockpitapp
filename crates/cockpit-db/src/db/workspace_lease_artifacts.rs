//! Daemon-owned workspace lease and commitless task-artifact persistence.
//!
//! This module intentionally stores only canonical identities and fixed-size
//! digests.  It is not a filesystem API: callers prove identity outside this
//! crate and report the redacted result through the CAS transitions below.

use anyhow::{Context, Result, bail, ensure};
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
    SameRoot,
    Subdirectory,
    ManagedWorktree,
}
pub const WORKSPACE_LEASE_KINDS: &[&str] = &["same_root", "subdirectory", "managed_worktree"];
impl WorkspaceLeaseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SameRoot => "same_root",
            Self::Subdirectory => "subdirectory",
            Self::ManagedWorktree => "managed_worktree",
        }
    }
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "same_root" => Ok(Self::SameRoot),
            "subdirectory" => Ok(Self::Subdirectory),
            "managed_worktree" => Ok(Self::ManagedWorktree),
            _ => bail!("unknown workspace lease kind"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceLeaseState {
    Active,
    Grace,
    Cleaning,
    Cleaned,
    Uncertain,
}
pub const WORKSPACE_LEASE_STATES: &[&str] =
    &["active", "grace", "cleaning", "cleaned", "uncertain"];
pub const WORKSPACE_LEASE_TERMINAL_STATES: &[&str] = &["cleaned"];
pub const WORKSPACE_LEASE_LEGAL_EDGES: &[(&str, &str)] = &[
    ("active", "grace"),
    ("active", "uncertain"),
    ("grace", "cleaning"),
    ("grace", "cleaned"),
    ("grace", "uncertain"),
    // A clean removal can still be refused by Git (for example because a
    // process dirtied the worktree after the cleanup claim).  Releasing this
    // exclusive claim keeps the path retryable instead of stranding it in
    // `cleaning` forever.
    ("cleaning", "grace"),
    ("cleaning", "cleaned"),
    ("cleaning", "uncertain"),
    ("uncertain", "cleaned"),
];
fn workspace_lease_transition_allowed(from: WorkspaceLeaseState, to: WorkspaceLeaseState) -> bool {
    WORKSPACE_LEASE_LEGAL_EDGES.contains(&(from.as_str(), to.as_str()))
}
impl WorkspaceLeaseState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Cleaning => "cleaning",
            Self::Cleaned => "cleaned",
            Self::Uncertain => "uncertain",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "active" => Ok(Self::Active),
            "grace" => Ok(Self::Grace),
            "cleaning" => Ok(Self::Cleaning),
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
    MissingManagedPath,
    HostCleanup,
    RestartUncertain,
}
impl WorkspaceLeaseTerminalReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::IdentityMismatch => "identity_mismatch",
            Self::MissingManagedPath => "missing_managed_path",
            Self::HostCleanup => "host_cleanup",
            Self::RestartUncertain => "restart_uncertain",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "expired" => Ok(Self::Expired),
            "identity_mismatch" => Ok(Self::IdentityMismatch),
            "missing_managed_path" => Ok(Self::MissingManagedPath),
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
pub const TASK_ARTIFACT_STATES: &[&str] = &[
    "produced",
    "integrating",
    "integrated",
    "stale",
    "conflict",
    "cancelled",
    "failed",
];
pub const TASK_ARTIFACT_TERMINAL_STATES: &[&str] =
    &["integrated", "stale", "conflict", "cancelled", "failed"];
pub const TASK_ARTIFACT_LEGAL_EDGES: &[(&str, &str)] = &[
    ("produced", "integrating"),
    ("produced", "cancelled"),
    ("integrating", "produced"),
    ("integrating", "integrated"),
    ("integrating", "stale"),
    ("integrating", "conflict"),
    ("integrating", "cancelled"),
    ("integrating", "failed"),
];
fn task_artifact_transition_allowed(from: TaskArtifactState, to: TaskArtifactState) -> bool {
    TASK_ARTIFACT_LEGAL_EDGES.contains(&(from.as_str(), to.as_str()))
}
impl TaskArtifactState {
    pub fn as_str(self) -> &'static str {
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
    /// Durable workspace authority parent. Every ancestor must remain live
    /// before this lease can authorize a native effect.
    pub parent_workspace_lease_id: Option<Uuid>,
    pub canonical_repository_id: String,
    pub canonical_root: String,
    pub kind: WorkspaceLeaseKind,
    /// Closed four-bit authority set: read=1, write=2, execute=4, computer=8.
    /// The initial-schema CHECK and this decoder keep persisted values closed.
    pub allowed_ops: u8,
    /// Only the daemon host may bind this row to the daemon-owned root write
    /// scope. Ordinary agent-owned rows must retain their stricter scope proof.
    pub host_issued: bool,
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
    pub parent_workspace_lease_id: Option<Uuid>,
    pub canonical_repository_id: String,
    pub canonical_root: String,
    pub kind: WorkspaceLeaseKind,
    /// Closed four-bit authority set: read=1, write=2, execute=4, computer=8.
    pub allowed_ops: u8,
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
    /// The target workspace lease is checked in the final transaction as
    /// well as before acquiring the filesystem lock. This closes a
    /// revoke/expiry race between patch application and durable finalization.
    pub target_workspace_lease_id: Uuid,
    pub expected_target_workspace_lease_revision: i64,
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

const LEASE_COLS: &str = "workspace_lease_id, session_id, agent_instance_id, write_scope_lease_id, parent_workspace_lease_id, canonical_repository_id, canonical_root, kind, allowed_ops, host_issued, base_sha_digest, base_ref_digest, managed_path, private_ref_digest, state, expires_at_unix_ms, revision, terminal_reason, uncertain_reason, pinned_at_unix_ms, pinned_by_agent_instance_id, created_at_unix_ms, updated_at_unix_ms";
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
    let allowed_ops: i64 = row.get(8)?;
    if !(0..=15).contains(&allowed_ops) {
        return Err(invalid_persisted_error(
            8,
            anyhow::anyhow!("workspace lease allowed_ops is outside the closed bit set"),
        ));
    }
    let host_issued: i64 = row.get(9)?;
    if !(0..=1).contains(&host_issued) {
        return Err(invalid_persisted_error(
            9,
            anyhow::anyhow!("workspace lease host_issued is outside the closed bit set"),
        ));
    }
    let terminal: Option<String> = row.get(17)?;
    let uncertain: Option<String> = row.get(18)?;
    let pinned: Option<String> = row.get(20)?;
    Ok(WorkspaceLeaseRow {
        workspace_lease_id: uuid(row.get(0)?, 0)?,
        session_id: uuid(row.get(1)?, 1)?,
        agent_instance_id: uuid(row.get(2)?, 2)?,
        write_scope_lease_id: uuid(row.get(3)?, 3)?,
        parent_workspace_lease_id: row
            .get::<_, Option<String>>(4)?
            .map(|value| uuid(value, 4))
            .transpose()?,
        canonical_repository_id: row.get(5)?,
        canonical_root: row.get(6)?,
        kind: WorkspaceLeaseKind::parse(&row.get::<_, String>(7)?).map_err(to_sql)?,
        allowed_ops: allowed_ops as u8,
        host_issued: host_issued == 1,
        base_sha_digest: digest(row.get(10)?, 10)?,
        base_ref_digest: digest(row.get(11)?, 11)?,
        managed_path: row.get(12)?,
        private_ref_digest: digest(row.get(13)?, 13)?,
        state: WorkspaceLeaseState::parse(&row.get::<_, String>(14)?).map_err(to_sql)?,
        expires_at_unix_ms: row.get(15)?,
        revision: row.get(16)?,
        terminal_reason: terminal
            .map(|v| WorkspaceLeaseTerminalReason::parse(&v).map_err(to_sql))
            .transpose()?,
        uncertain_reason: uncertain
            .map(|v| WorkspaceLeaseTerminalReason::parse(&v).map_err(to_sql))
            .transpose()?,
        pinned_at_unix_ms: row.get(19)?,
        pinned_by_agent_instance_id: pinned.map(|v| uuid(v, 20)).transpose()?,
        created_at_unix_ms: row.get(21)?,
        updated_at_unix_ms: row.get(22)?,
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

/// A task lease is issued by its direct parent, but is deliberately carried by
/// that parent's child and may be used to issue a bounded grandchild lease.
/// Authorize that narrow hand-off by walking only the durable agent-tree
/// ancestry from the requesting agent to the row owner.  A sibling, another
/// root, or a cross-session UUID cannot manufacture this relationship.
fn lease_for_agent_tree_lineage(
    conn: &Connection,
    session: Uuid,
    agent: Uuid,
    lease: Uuid,
) -> Result<Option<WorkspaceLeaseRow>> {
    conn.query_row(
        &format!(
            "WITH RECURSIVE ancestors(agent_instance_id) AS (\
                 SELECT ?3\
                 UNION\
                 SELECT parent.parent_agent_instance_id\
                   FROM agent_instances parent\
                   JOIN ancestors child\
                     ON parent.agent_instance_id = child.agent_instance_id\
                  WHERE parent.session_id = ?2\
                    AND parent.parent_agent_instance_id IS NOT NULL\
             )\
             SELECT {LEASE_COLS} FROM workspace_leases\
              WHERE workspace_lease_id = ?1\
                AND session_id = ?2\
                AND agent_instance_id IN ancestors"
        ),
        params![lease.to_string(), session.to_string(), agent.to_string()],
        map_lease,
    )
    .optional()
    .context("loading workspace lease authorized by agent-tree lineage")
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

/// The daemon's root write-scope lease is deliberately owned by the host,
/// rather than by each agent-tree row.  A host-issued workspace lease may bind
/// to that root authority, but a model-facing consumer still has to name an
/// owner-scoped workspace-lease row.  Keep this narrower than
/// `scope_is_owned_active`: it proves the supplied durable write authority is
/// live for this session without pretending the agent owns the host root.
fn scope_is_host_active(conn: &Connection, session: Uuid, scope: Uuid) -> Result<bool> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM write_scope_leases
             WHERE lease_id=?1 AND session_id=?2
               AND owner_id='session-root'
               AND parent_lease_id IS NULL
               AND agent_instance_id IS NULL
               AND state='active'",
            params![scope.to_string(), session.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

/// A descendant can never outlive a parent workspace lease.  Resolve the
/// immutable parent chain inside the same DB read/transaction as the caller's
/// admission check, and fail closed on a missing row, cycle, expired row, or
/// invalid ancestor write authority.
fn workspace_lease_lineage_is_live(
    conn: &Connection,
    lease: &WorkspaceLeaseRow,
    now: i64,
) -> Result<bool> {
    let mut current = lease.clone();
    let mut seen = std::collections::BTreeSet::new();
    loop {
        if !seen.insert(current.workspace_lease_id)
            || current.state != WorkspaceLeaseState::Active
            || current.expires_at_unix_ms <= now
        {
            return Ok(false);
        }
        let scope_live = if current.host_issued {
            // Host-issued roots use the daemon-owned session scope, while
            // host-issued fan-out children use a narrower agent-owned child
            // scope. Both forms are created only by dedicated host issuance
            // methods and must remain live for task admission.
            scope_is_host_active(conn, current.session_id, current.write_scope_lease_id)?
                || scope_is_owned_active(
                    conn,
                    current.session_id,
                    current.agent_instance_id,
                    current.write_scope_lease_id,
                    &current.canonical_root,
                    None,
                )?
        } else {
            scope_is_owned_active(
                conn,
                current.session_id,
                current.agent_instance_id,
                current.write_scope_lease_id,
                &current.canonical_root,
                None,
            )?
        };
        if !scope_live {
            return Ok(false);
        }
        let Some(parent_id) = current.parent_workspace_lease_id else {
            return Ok(true);
        };
        let Some(parent) = conn
            .query_row(
                &format!(
                    "SELECT {LEASE_COLS} FROM workspace_leases \
                     WHERE workspace_lease_id=?1 AND session_id=?2"
                ),
                params![parent_id.to_string(), current.session_id.to_string()],
                map_lease,
            )
            .optional()
            .context("loading workspace lease ancestor")?
        else {
            return Ok(false);
        };
        current = parent;
    }
}

/// Integration may target the daemon-issued root write scope.  Artifact
/// ownership remains checked independently through `artifact_for_owner`; this
/// only proves the host target is still the exact root/generation requested.
fn scope_is_authorized_integration_target(
    conn: &Connection,
    session: Uuid,
    agent: Uuid,
    scope: Uuid,
    root: &str,
    expected: (u64, u64),
) -> Result<bool> {
    if scope_is_owned_active(conn, session, agent, scope, root, Some(expected))? {
        return Ok(true);
    }
    let row: Option<(String, String, i64, i64)> = conn
        .query_row(
            "SELECT state,scope_path,generation,version FROM write_scope_leases
             WHERE lease_id=?1 AND session_id=?2
               AND owner_id='session-root'
               AND parent_lease_id IS NULL
               AND agent_instance_id IS NULL",
            params![scope.to_string(), session.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    Ok(matches!(
        row,
        Some((state, path, generation, version))
            if state == "active"
                && path == root
                && generation == expected.0 as i64
                && version == expected.1 as i64
    ))
}

fn workspace_lease_is_authorized_integration_target(
    conn: &Connection,
    session: Uuid,
    agent: Uuid,
    target: &IntegrationTarget,
    now: i64,
) -> Result<bool> {
    let Some(lease) = lease_for_owner(conn, session, agent, target.target_workspace_lease_id)?
    else {
        return Ok(false);
    };
    Ok(
        lease.canonical_repository_id == target.target_canonical_repository_id
            && lease.canonical_root == target.target_canonical_root
            && lease.write_scope_lease_id == target.target_write_scope_lease_id
            && lease.revision == target.expected_target_workspace_lease_revision
            && workspace_lease_lineage_is_live(conn, &lease, now)?,
    )
}

fn workspace_lease_descends_from(
    conn: &Connection,
    session: Uuid,
    descendant: Uuid,
    ancestor: Uuid,
) -> Result<bool> {
    let found: Option<i64> = conn
        .query_row(
            "WITH RECURSIVE lineage(workspace_lease_id, parent_workspace_lease_id) AS (
                 SELECT workspace_lease_id, parent_workspace_lease_id
                   FROM workspace_leases
                  WHERE workspace_lease_id=?1 AND session_id=?2
                 UNION ALL
                 SELECT parent.workspace_lease_id, parent.parent_workspace_lease_id
                   FROM workspace_leases parent
                   JOIN lineage child
                     ON parent.workspace_lease_id = child.parent_workspace_lease_id
                  WHERE parent.session_id=?2
             )
             SELECT 1 FROM lineage WHERE workspace_lease_id=?3 LIMIT 1",
            params![
                descendant.to_string(),
                session.to_string(),
                ancestor.to_string()
            ],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

fn write_scope_descends_from(
    conn: &Connection,
    session: Uuid,
    descendant: Uuid,
    ancestor: Uuid,
) -> Result<bool> {
    let found: Option<i64> = conn
        .query_row(
            "WITH RECURSIVE lineage(lease_id, parent_lease_id) AS (
                 SELECT lease_id, parent_lease_id
                   FROM write_scope_leases
                  WHERE lease_id=?1 AND session_id=?2
                 UNION ALL
                 SELECT parent.lease_id, parent.parent_lease_id
                   FROM write_scope_leases parent
                   JOIN lineage child ON parent.lease_id = child.parent_lease_id
                  WHERE parent.session_id=?2
             )
             SELECT 1 FROM lineage WHERE lease_id=?3 LIMIT 1",
            params![
                descendant.to_string(),
                session.to_string(),
                ancestor.to_string()
            ],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
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
        if input.allowed_ops > 15 {
            bail!("workspace lease allowed_ops is outside the closed bit set");
        }
        if input.expires_at_unix_ms <= now {
            bail!("workspace lease expiry must be in the future");
        }
        let id = Uuid::new_v4();
        self.transaction(move |conn| {
            if !scope_is_owned_active(conn,input.session_id,input.agent_instance_id,input.write_scope_lease_id,&input.canonical_root,None)? { bail!("write scope is not active at this workspace root and owned by this agent"); }
            if let Some(parent_id) = input.parent_workspace_lease_id {
                let parent = lease_for_agent_tree_lineage(
                    conn,
                    input.session_id,
                    input.agent_instance_id,
                    parent_id,
                )?
                .context("parent workspace lease is not owned by this agent or an ancestor")?;
                if !workspace_lease_lineage_is_live(conn, &parent, now)? {
                    bail!("parent workspace lease is revoked, expired, or no longer live");
                }
                if input.allowed_ops & !parent.allowed_ops != 0 {
                    bail!("child workspace lease operations exceed its parent lease");
                }
            }
            conn.execute("INSERT INTO workspace_leases (workspace_lease_id,session_id,agent_instance_id,write_scope_lease_id,parent_workspace_lease_id,canonical_repository_id,canonical_root,kind,allowed_ops,host_issued,base_sha_digest,base_ref_digest,managed_path,private_ref_digest,state,expires_at_unix_ms,revision,terminal_reason,uncertain_reason,pinned_at_unix_ms,pinned_by_agent_instance_id,created_at_unix_ms,updated_at_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0,?10,?11,?12,?13,'active',?14,0,NULL,NULL,NULL,NULL,?15,?15)", params![id.to_string(),input.session_id.to_string(),input.agent_instance_id.to_string(),input.write_scope_lease_id.to_string(),input.parent_workspace_lease_id.map(|value| value.to_string()),input.canonical_repository_id,input.canonical_root,input.kind.as_str(),i64::from(input.allowed_ops),input.base_sha_digest.as_str(),input.base_ref_digest.as_str(),input.managed_path,input.private_ref_digest.as_str(),input.expires_at_unix_ms,now]).context("inserting workspace lease")?;
            lease_for_owner(conn,input.session_id,input.agent_instance_id,id)?.context("created workspace lease missing")
        }).await
    }

    /// Insert a workspace lease at the daemon host boundary.
    ///
    /// The root write scope is daemon-owned (`owner_id = session-root`) and
    /// therefore cannot satisfy the per-agent proof required by
    /// [`Self::create_workspace_lease`].  This is the sole alternative for
    /// host lifecycle code which has already authenticated an agent-tree owner
    /// and selected a lease kind under its effective grant.  The row remains
    /// owner-scoped on every model/tool read, and is still bound to a live
    /// write-scope lease in the same session.
    pub async fn create_host_workspace_lease(
        &self,
        input: NewWorkspaceLease,
        id: Uuid,
        now: i64,
    ) -> Result<WorkspaceLeaseRow> {
        bounded_identity(&input.canonical_repository_id, "repository identity")?;
        bounded_identity(&input.canonical_root, "canonical root")?;
        bounded_identity(&input.managed_path, "managed path")?;
        if input.allowed_ops > 15 {
            bail!("workspace lease allowed_ops is outside the closed bit set");
        }
        if input.expires_at_unix_ms <= now {
            bail!("workspace lease expiry must be in the future");
        }
        self.transaction(move |conn| {
            if !scope_is_host_active(conn, input.session_id, input.write_scope_lease_id)? {
                bail!("host write scope is not active for this workspace lease session");
            }
            if let Some(parent_id) = input.parent_workspace_lease_id {
                let parent = lease_for_agent_tree_lineage(
                    conn,
                    input.session_id,
                    input.agent_instance_id,
                    parent_id,
                )?
                .context("parent workspace lease is not owned by this agent or an ancestor")?;
                if !workspace_lease_lineage_is_live(conn, &parent, now)? {
                    bail!("parent workspace lease is revoked, expired, or no longer live");
                }
                if input.allowed_ops & !parent.allowed_ops != 0 {
                    bail!("child workspace lease operations exceed its parent lease");
                }
            }
            conn.execute("INSERT INTO workspace_leases (workspace_lease_id,session_id,agent_instance_id,write_scope_lease_id,parent_workspace_lease_id,canonical_repository_id,canonical_root,kind,allowed_ops,host_issued,base_sha_digest,base_ref_digest,managed_path,private_ref_digest,state,expires_at_unix_ms,revision,terminal_reason,uncertain_reason,pinned_at_unix_ms,pinned_by_agent_instance_id,created_at_unix_ms,updated_at_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,1,?10,?11,?12,?13,'active',?14,0,NULL,NULL,NULL,NULL,?15,?15)", params![id.to_string(),input.session_id.to_string(),input.agent_instance_id.to_string(),input.write_scope_lease_id.to_string(),input.parent_workspace_lease_id.map(|value| value.to_string()),input.canonical_repository_id,input.canonical_root,input.kind.as_str(),i64::from(input.allowed_ops),input.base_sha_digest.as_str(),input.base_ref_digest.as_str(),input.managed_path,input.private_ref_digest.as_str(),input.expires_at_unix_ms,now]).context("inserting host workspace lease")?;
            lease_for_owner(conn,input.session_id,input.agent_instance_id,id)?.context("created host workspace lease missing")
        }).await
    }

    /// Host-only issuance for a managed child beneath an agent-owned scope.
    ///
    /// Fan-out worktrees are created by the daemon capability, not by the
    /// model that later runs inside them.  They therefore need the same
    /// durable host provenance as every other managed-worktree launch, while
    /// retaining the narrower child write scope and parent lineage proof.
    /// This is intentionally separate from `create_workspace_lease`: the
    /// latter is for ordinary agent-issued SameRoot/Subdirectory tokens and
    /// always records `host_issued=0`.
    pub async fn create_host_issued_child_workspace_lease(
        &self,
        input: NewWorkspaceLease,
        id: Uuid,
        now: i64,
    ) -> Result<WorkspaceLeaseRow> {
        bounded_identity(&input.canonical_repository_id, "repository identity")?;
        bounded_identity(&input.canonical_root, "canonical root")?;
        bounded_identity(&input.managed_path, "managed path")?;
        if input.kind != WorkspaceLeaseKind::ManagedWorktree {
            bail!("host-issued child workspace lease must be a managed worktree");
        }
        if input.parent_workspace_lease_id.is_none() {
            bail!("host-issued child workspace lease requires a parent lease");
        }
        if input.allowed_ops > 15 {
            bail!("workspace lease allowed_ops is outside the closed bit set");
        }
        if input.expires_at_unix_ms <= now {
            bail!("workspace lease expiry must be in the future");
        }
        self.transaction(move |conn| {
            if !scope_is_owned_active(
                conn,
                input.session_id,
                input.agent_instance_id,
                input.write_scope_lease_id,
                &input.canonical_root,
                None,
            )? {
                bail!("child write scope is not active at the managed workspace root");
            }
            let parent_id = input.parent_workspace_lease_id.expect("checked above");
            let parent = lease_for_agent_tree_lineage(
                conn,
                input.session_id,
                input.agent_instance_id,
                parent_id,
            )?
            .context("parent workspace lease is not owned by this agent or an ancestor")?;
            if !workspace_lease_lineage_is_live(conn, &parent, now)? {
                bail!("parent workspace lease is revoked, expired, or no longer live");
            }
            if input.allowed_ops & !parent.allowed_ops != 0 {
                bail!("child workspace lease operations exceed its parent lease");
            }
            conn.execute("INSERT INTO workspace_leases (workspace_lease_id,session_id,agent_instance_id,write_scope_lease_id,parent_workspace_lease_id,canonical_repository_id,canonical_root,kind,allowed_ops,host_issued,base_sha_digest,base_ref_digest,managed_path,private_ref_digest,state,expires_at_unix_ms,revision,terminal_reason,uncertain_reason,pinned_at_unix_ms,pinned_by_agent_instance_id,created_at_unix_ms,updated_at_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,1,?10,?11,?12,?13,'active',?14,0,NULL,NULL,NULL,NULL,?15,?15)", params![id.to_string(),input.session_id.to_string(),input.agent_instance_id.to_string(),input.write_scope_lease_id.to_string(),input.parent_workspace_lease_id.map(|value| value.to_string()),input.canonical_repository_id,input.canonical_root,input.kind.as_str(),i64::from(input.allowed_ops),input.base_sha_digest.as_str(),input.base_ref_digest.as_str(),input.managed_path,input.private_ref_digest.as_str(),input.expires_at_unix_ms,now]).context("inserting host-issued child workspace lease")?;
            lease_for_owner(conn, input.session_id, input.agent_instance_id, id)?
                .context("created host-issued child workspace lease missing")
        })
        .await
    }

    /// Revalidate the exact integration target under one database read.  The
    /// caller holds the target and affected-path locks and invokes this
    /// immediately before the synchronous Git effect boundary.
    pub async fn integration_target_is_live(
        &self,
        session: Uuid,
        agent: Uuid,
        target: IntegrationTarget,
        now: i64,
    ) -> Result<bool> {
        self.read(move |conn| {
            Ok(scope_is_authorized_integration_target(
                conn,
                session,
                agent,
                target.target_write_scope_lease_id,
                &target.target_canonical_root,
                (
                    target.expected_target_generation,
                    target.expected_target_revision,
                ),
            )? && workspace_lease_is_authorized_integration_target(
                conn, session, agent, &target, now,
            )?)
        })
        .await
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

    pub async fn workspace_lease_for_session(
        &self,
        session: Uuid,
        id: Uuid,
    ) -> Result<Option<WorkspaceLeaseRow>> {
        self.read(move |c| {
            c.query_row(
                &format!("SELECT {LEASE_COLS} FROM workspace_leases WHERE session_id=?1 AND workspace_lease_id=?2"),
                params![session.to_string(), id.to_string()],
                map_lease,
            ).optional().context("loading session workspace lease")
        }).await
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
            let Some(row) = lease_for_agent_tree_lineage(c, session, agent, id)? else {
                return Ok(None);
            };
            Ok(workspace_lease_lineage_is_live(c, &row, now)?.then_some(row))
        })
        .await
    }
    /// Load a conflict-specialist lease only when it remains a live
    /// descendant of this orchestrator's exact workspace and write-scope
    /// authority. Agent ownership alone is insufficient: a same-session
    /// sibling tree cannot supply a handoff to this parent.
    pub async fn workspace_lease_for_conflict_handoff(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        parent_workspace_lease_id: Uuid,
        parent_write_scope_lease_id: Uuid,
        now: i64,
    ) -> Result<Option<WorkspaceLeaseRow>> {
        self.read(move |conn| {
            let Some(row) = lease_for_owner(conn, session, agent, id)? else {
                return Ok(None);
            };
            Ok((row.workspace_lease_id != parent_workspace_lease_id
                && row.write_scope_lease_id != parent_write_scope_lease_id
                && workspace_lease_lineage_is_live(conn, &row, now)?
                && workspace_lease_descends_from(
                    conn,
                    session,
                    row.workspace_lease_id,
                    parent_workspace_lease_id,
                )?
                && write_scope_descends_from(
                    conn,
                    session,
                    row.write_scope_lease_id,
                    parent_write_scope_lease_id,
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
        self.transaction(move |c| { let Some(current)=lease_for_owner(c,session,agent,id)? else { return Ok(LeaseCasOutcome::RevisionConflict) }; if current.state.is_terminal(){return Ok(LeaseCasOutcome::AlreadyTerminal(current))}; if current.state != WorkspaceLeaseState::Active || current.expires_at_unix_ms <= now || current.revision != expected_revision || !workspace_lease_lineage_is_live(c,&current,now)? { return Ok(LeaseCasOutcome::RevisionConflict) }; c.execute("UPDATE workspace_leases SET expires_at_unix_ms=?1,revision=revision+1,updated_at_unix_ms=?2 WHERE workspace_lease_id=?3 AND revision=?4 AND state='active' AND expires_at_unix_ms>?2",params![new_expiry,now,id.to_string(),expected_revision])?; Ok(LeaseCasOutcome::Transitioned(lease_for_owner(c,session,agent,id)?.context("renewed lease missing")?)) }).await
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
    /// Normal completion stops a lease from looking live forever while
    /// retaining its workspace for the grace/pin/explicit-clean lifecycle.
    pub async fn grace_retain_workspace_lease(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        expected_revision: i64,
        now: i64,
    ) -> Result<LeaseCasOutcome> {
        self.transaction(move |c| {
            let Some(current) = lease_for_owner(c, session, agent, id)? else {
                return Ok(LeaseCasOutcome::RevisionConflict);
            };
            if current.state.is_terminal() {
                return Ok(LeaseCasOutcome::AlreadyTerminal(current));
            }
            if current.state != WorkspaceLeaseState::Active || current.revision != expected_revision {
                return Ok(LeaseCasOutcome::RevisionConflict);
            }
            c.execute(
                "UPDATE workspace_leases SET state='grace', expires_at_unix_ms=?1, uncertain_reason='expired', revision=revision+1, updated_at_unix_ms=?1 WHERE workspace_lease_id=?2 AND revision=?3 AND state='active'",
                params![now, id.to_string(), expected_revision],
            )?;
            Ok(LeaseCasOutcome::Transitioned(
                lease_for_owner(c, session, agent, id)?.context("grace-retained lease missing")?,
            ))
        })
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
                | WorkspaceLeaseTerminalReason::MissingManagedPath
                | WorkspaceLeaseTerminalReason::RestartUncertain
        ) {
            bail!("uncertain state requires an ambiguity reason");
        }
        self.transaction(move |c| { let Some(current)=lease_for_owner(c,session,agent,id)? else{return Ok(LeaseCasOutcome::RevisionConflict)}; if current.state.is_terminal(){return Ok(LeaseCasOutcome::AlreadyTerminal(current))}; if current.revision != expected_revision || !matches!(current.state,WorkspaceLeaseState::Active|WorkspaceLeaseState::Grace|WorkspaceLeaseState::Cleaning){return Ok(LeaseCasOutcome::RevisionConflict)}; c.execute("UPDATE workspace_leases SET state='uncertain',terminal_reason=NULL,uncertain_reason=?1,revision=revision+1,updated_at_unix_ms=?2 WHERE workspace_lease_id=?3 AND revision=?4 AND state IN ('active','grace','cleaning')",params![reason.as_str(),now,id.to_string(),expected_revision])?; Ok(LeaseCasOutcome::Transitioned(lease_for_owner(c,session,agent,id)?.context("uncertain lease missing")?)) }).await
    }
    pub async fn pin_workspace_lease(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        expected_revision: i64,
        now: i64,
    ) -> Result<LeaseCasOutcome> {
        self.transaction(move |c| { let Some(current)=lease_for_owner(c,session,agent,id)? else{return Ok(LeaseCasOutcome::RevisionConflict)}; if current.state.is_terminal(){return Ok(LeaseCasOutcome::AlreadyTerminal(current))}; if current.state == WorkspaceLeaseState::Cleaning || current.revision != expected_revision{return Ok(LeaseCasOutcome::RevisionConflict)}; c.execute("UPDATE workspace_leases SET pinned_at_unix_ms=COALESCE(pinned_at_unix_ms,?1),pinned_by_agent_instance_id=COALESCE(pinned_by_agent_instance_id,?2),revision=revision+1,updated_at_unix_ms=?1 WHERE workspace_lease_id=?3 AND revision=?4 AND state IN ('active','grace')",params![now,agent.to_string(),id.to_string(),expected_revision])?; Ok(LeaseCasOutcome::Transitioned(lease_for_owner(c,session,agent,id)?.context("pinned lease missing")?)) }).await
    }
    /// Claim the exclusive filesystem-deletion interval.  This is a durable
    /// CAS boundary: after it succeeds, a concurrent pin can no longer race a
    /// remover that has not yet touched the path.
    pub async fn claim_workspace_lease_cleanup(
        &self,
        session: Uuid,
        agent: Uuid,
        id: Uuid,
        expected_revision: i64,
        now: i64,
    ) -> Result<LeaseCasOutcome> {
        self.transaction(move |c| {
            let Some(current) = lease_for_owner(c, session, agent, id)? else {
                return Ok(LeaseCasOutcome::RevisionConflict);
            };
            if current.state.is_terminal() {
                return Ok(LeaseCasOutcome::AlreadyTerminal(current));
            }
            if current.state != WorkspaceLeaseState::Grace
                || current.pinned_at_unix_ms.is_some()
                || current.revision != expected_revision
            {
                return Ok(LeaseCasOutcome::RevisionConflict);
            }
            c.execute(
                "UPDATE workspace_leases SET state='cleaning',revision=revision+1,updated_at_unix_ms=?1 WHERE workspace_lease_id=?2 AND revision=?3 AND state='grace' AND pinned_at_unix_ms IS NULL",
                params![now, id.to_string(), expected_revision],
            )?;
            Ok(LeaseCasOutcome::Transitioned(
                lease_for_owner(c, session, agent, id)?.context("claimed cleanup lease missing")?,
            ))
        }).await
    }
    /// Release an exclusive cleanup claim when no filesystem mutation was
    /// made.  This is deliberately a narrow `cleaning -> grace` CAS: it
    /// cannot resurrect a cleaned or uncertain lease, and a concurrent
    /// pin/cleanup transition still wins by revision.
    pub async fn release_workspace_lease_cleanup(
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
            WorkspaceLeaseState::Cleaning,
            WorkspaceLeaseState::Grace,
            None,
            None,
            now,
            false,
        )
        .await
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
            WorkspaceLeaseState::Cleaning,
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
        ensure!(
            workspace_lease_transition_allowed(from, to)
                || allow_uncertain
                    && workspace_lease_transition_allowed(WorkspaceLeaseState::Uncertain, to),
            "illegal workspace lease transition"
        );
        self.transaction(move |c| { let Some(current)=lease_for_owner(c,session,agent,id)? else{return Ok(LeaseCasOutcome::RevisionConflict)}; if current.state.is_terminal(){return Ok(LeaseCasOutcome::AlreadyTerminal(current))}; if current.revision != expected || !(current.state == from || allow_uncertain && current.state == WorkspaceLeaseState::Uncertain) || (from == WorkspaceLeaseState::Active && current.expires_at_unix_ms > now) {return Ok(LeaseCasOutcome::RevisionConflict)}; c.execute("UPDATE workspace_leases SET state=?1,terminal_reason=?2,uncertain_reason=COALESCE(?3, uncertain_reason),revision=revision+1,updated_at_unix_ms=?4 WHERE workspace_lease_id=?5 AND revision=?6",params![to.as_str(),reason.map(|v|v.as_str()),uncertain_reason.map(|v|v.as_str()),now,id.to_string(),expected])?; Ok(LeaseCasOutcome::Transitioned(lease_for_owner(c,session,agent,id)?.context("transitioned workspace lease missing")?)) }).await
    }

    pub async fn create_task_artifact(
        &self,
        input: NewTaskArtifact,
        now: i64,
    ) -> Result<TaskArtifactRow> {
        self.create_task_artifact_with_id(Uuid::new_v4(), input, now)
            .await
    }

    pub async fn create_task_artifact_with_id(
        &self,
        id: Uuid,
        input: NewTaskArtifact,
        now: i64,
    ) -> Result<TaskArtifactRow> {
        self.transaction(move |c| { let lease=lease_for_owner(c,input.session_id,input.agent_instance_id,input.source_workspace_lease_id)?.context("source workspace lease is not owned")?; if !workspace_lease_lineage_is_live(c,&lease,now)? { bail!("source workspace lease is unavailable for artifact production"); } let parent=input.parent_result.encode()?; c.execute("INSERT INTO task_artifacts (artifact_id,source_workspace_lease_id,session_id,agent_instance_id,base_head_digest,base_ref_digest,base_index_digest,touched_manifest_digest,untracked_manifest_digest,ordered_patch_digest,validation_receipt_digest,parent_result_json,state,revision,created_at_unix_ms,updated_at_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'produced',0,?13,?13)",params![id.to_string(),input.source_workspace_lease_id.to_string(),input.session_id.to_string(),input.agent_instance_id.to_string(),input.base_head_digest.as_str(),input.base_ref_digest.as_str(),input.base_index_digest.as_str(),input.touched_manifest_digest.as_str(),input.untracked_manifest_digest.as_str(),input.ordered_patch_digest.as_str(),input.validation_receipt_digest.as_str(),parent,now])?; artifact_for_owner(c,input.session_id,input.agent_instance_id,id)?.context("created artifact missing") }).await
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
    /// Release artifact attempts left in `integrating` before an integration
    /// intent could be published. Call this only after the filesystem journal
    /// has been fully reconciled: a receipt proves an applied target was
    /// durably finalized, while any journal-backed attempt is handled by the
    /// journal's target-receipt comparison instead of this reset.
    pub async fn release_receiptless_integrating_artifacts_for_recovery(
        &self,
        session: Uuid,
        now: i64,
    ) -> Result<Vec<TaskArtifactRow>> {
        self.transaction(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {ARTIFACT_COLS} FROM task_artifacts a
                 WHERE a.session_id=?1 AND a.state='integrating'
                   AND NOT EXISTS (
                     SELECT 1 FROM task_artifact_integration_receipts r
                      WHERE r.artifact_id=a.artifact_id AND r.session_id=a.session_id
                   )
                 ORDER BY a.created_at_unix_ms, a.artifact_id"
            ))?;
            let candidates = stmt
                .query_map(params![session.to_string()], map_artifact)?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            drop(stmt);
            let mut released = Vec::with_capacity(candidates.len());
            for current in candidates {
                let changed = conn.execute(
                    "UPDATE task_artifacts SET state='produced',revision=revision+1,updated_at_unix_ms=?1
                     WHERE artifact_id=?2 AND session_id=?3 AND revision=?4 AND state='integrating'
                       AND NOT EXISTS (
                         SELECT 1 FROM task_artifact_integration_receipts r
                          WHERE r.artifact_id=?2 AND r.session_id=?3
                       )",
                    params![
                        now,
                        current.artifact_id.to_string(),
                        session.to_string(),
                        current.revision,
                    ],
                )?;
                ensure!(
                    changed == 1,
                    "receiptless integrating artifact changed during crash recovery"
                );
                released.push(
                    artifact_for_owner(
                        conn,
                        session,
                        current.agent_instance_id,
                        current.artifact_id,
                    )?
                    .context("released recovery artifact missing")?,
                );
            }
            Ok(released)
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
        ensure!(
            task_artifact_transition_allowed(from, to),
            "illegal task artifact transition"
        );
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
        self.transaction(move |c| { let Some(current)=artifact_for_owner(c,session,agent,id)? else{return Ok(ArtifactCasOutcome::RevisionConflict)}; if current.state.is_terminal(){return Ok(ArtifactCasOutcome::AlreadyTerminal(current))}; if current.state != TaskArtifactState::Integrating || current.revision != expected{return Ok(ArtifactCasOutcome::RevisionConflict)}; let source=lease_for_owner(c,session,agent,current.source_workspace_lease_id)?.context("artifact source workspace lease missing")?; if target.target_canonical_repository_id != source.canonical_repository_id || !scope_is_authorized_integration_target(c,session,agent,target.target_write_scope_lease_id,&target.target_canonical_root,(target.expected_target_generation,target.expected_target_revision))? || !workspace_lease_is_authorized_integration_target(c,session,agent,&target,now)? { return Ok(ArtifactCasOutcome::RevisionConflict); } let changed=target.changed_path_manifest_digest.as_str().to_owned(); let inserted=c.execute("INSERT OR IGNORE INTO task_artifact_integration_receipts (artifact_id,session_id,target_canonical_repository_id,target_canonical_root,target_head_digest,target_ref_digest,target_index_digest,changed_path_manifest_digest,target_write_scope_lease_id,expected_target_generation,expected_target_revision,result_state,created_at_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'integrated',?12)",params![id.to_string(),session.to_string(),target.target_canonical_repository_id,target.target_canonical_root,target.target_head_digest.as_str(),target.target_ref_digest.as_str(),target.target_index_digest.as_str(),changed,target.target_write_scope_lease_id.to_string(),target.expected_target_generation as i64,target.expected_target_revision as i64,now])?; if inserted != 1 { bail!("integration receipt already exists for a nonterminal artifact"); } c.execute("UPDATE task_artifacts SET state='integrated',revision=revision+1,updated_at_unix_ms=?1 WHERE artifact_id=?2 AND revision=?3 AND state='integrating'",params![now,id.to_string(),expected])?; Ok(ArtifactCasOutcome::Transitioned(artifact_for_owner(c,session,agent,id)?.context("integrated artifact missing")?)) }).await
    }

    /// Atomically publishes one ordered integration attempt. Either every
    /// selected artifact receives its immutable receipt and becomes integrated,
    /// or no artifact state changes.
    pub async fn integrate_task_artifacts(
        &self,
        session: Uuid,
        agent: Uuid,
        artifacts: Vec<(Uuid, i64)>,
        target: IntegrationTarget,
        now: i64,
    ) -> Result<Option<Vec<TaskArtifactRow>>> {
        bounded_identity(
            &target.target_canonical_repository_id,
            "target repository identity",
        )?;
        bounded_identity(&target.target_canonical_root, "target canonical root")?;
        self.transaction(move |c| {
            if artifacts.is_empty() {
                return Ok(Some(Vec::new()));
            }
            if !scope_is_authorized_integration_target(
                c,
                session,
                agent,
                target.target_write_scope_lease_id,
                &target.target_canonical_root,
                (target.expected_target_generation, target.expected_target_revision),
            )? {
                return Ok(None);
            }
            if !workspace_lease_is_authorized_integration_target(c, session, agent, &target, now)? {
                return Ok(None);
            }
            for (id, expected) in &artifacts {
                let Some(current) = artifact_for_owner(c, session, agent, *id)? else {
                    return Ok(None);
                };
                if current.state != TaskArtifactState::Integrating || current.revision != *expected {
                    return Ok(None);
                }
                let source = lease_for_owner(c, session, agent, current.source_workspace_lease_id)?
                    .context("artifact source workspace lease missing")?;
                if source.canonical_repository_id != target.target_canonical_repository_id {
                    return Ok(None);
                }
                let exists: bool = c.query_row(
                    "SELECT EXISTS(SELECT 1 FROM task_artifact_integration_receipts WHERE artifact_id=?1 AND session_id=?2)",
                    params![id.to_string(), session.to_string()],
                    |row| row.get(0),
                )?;
                if exists {
                    return Ok(None);
                }
            }
            for (id, expected) in &artifacts {
                c.execute(
                    "INSERT INTO task_artifact_integration_receipts (artifact_id,session_id,target_canonical_repository_id,target_canonical_root,target_head_digest,target_ref_digest,target_index_digest,changed_path_manifest_digest,target_write_scope_lease_id,expected_target_generation,expected_target_revision,result_state,created_at_unix_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'integrated',?12)",
                    params![id.to_string(),session.to_string(),target.target_canonical_repository_id,target.target_canonical_root,target.target_head_digest.as_str(),target.target_ref_digest.as_str(),target.target_index_digest.as_str(),target.changed_path_manifest_digest.as_str(),target.target_write_scope_lease_id.to_string(),target.expected_target_generation as i64,target.expected_target_revision as i64,now],
                )?;
                c.execute(
                    "UPDATE task_artifacts SET state='integrated',revision=revision+1,updated_at_unix_ms=?1 WHERE artifact_id=?2 AND revision=?3 AND state='integrating'",
                    params![now, id.to_string(), expected],
                )?;
            }
            let rows = artifacts
                .iter()
                .map(|(id, _)| artifact_for_owner(c, session, agent, *id)?.context("integrated artifact missing"))
                .collect::<Result<Vec<_>>>()?;
            Ok(Some(rows))
        }).await
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
        self.read(move |c| { let mut stmt=c.prepare(&format!("SELECT {LEASE_COLS} FROM workspace_leases WHERE session_id=?1 AND agent_instance_id=?2 AND state IN ('active','grace','cleaning','uncertain') ORDER BY created_at_unix_ms,workspace_lease_id"))?; stmt.query_map(params![session.to_string(),agent.to_string()],map_lease)?.collect::<std::result::Result<Vec<_>,_>>().context("loading workspace recovery leases") }).await
    }
    /// Session-wide crash recovery: every nonterminal lease, regardless of owner.
    /// Missing or identity-mismatched worktrees are marked uncertain by the
    /// host; this listing never deletes a path.
    pub async fn list_workspace_leases_for_session_recovery(
        &self,
        session: Uuid,
    ) -> Result<Vec<WorkspaceLeaseRow>> {
        self.read(move |c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {LEASE_COLS} FROM workspace_leases
                 WHERE session_id=?1 AND state IN ('active','grace','cleaning','uncertain')
                 ORDER BY created_at_unix_ms,workspace_lease_id"
            ))?;
            stmt.query_map(params![session.to_string()], map_lease)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("loading session workspace recovery leases")
        })
        .await
    }

    /// Session-owned artifacts surfaced to the parent. Rows carry only
    /// redacted receipts; child transcripts are not stored here.
    pub async fn list_task_artifacts_for_session(
        &self,
        session: Uuid,
    ) -> Result<Vec<TaskArtifactRow>> {
        self.read(move |c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {ARTIFACT_COLS} FROM task_artifacts
                 WHERE session_id=?1
                 ORDER BY created_at_unix_ms, artifact_id"
            ))?;
            stmt.query_map(params![session.to_string()], map_artifact)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("listing session task artifacts")
        })
        .await
    }

    pub async fn list_task_artifact_integration_receipts_for_session(
        &self,
        session: Uuid,
    ) -> Result<Vec<TaskArtifactIntegrationReceipt>> {
        self.read(move |c| {
            let mut stmt = c.prepare(
                "SELECT artifact_id,session_id,target_canonical_repository_id,target_canonical_root,target_head_digest,target_ref_digest,target_index_digest,changed_path_manifest_digest,target_write_scope_lease_id,expected_target_generation,expected_target_revision,created_at_unix_ms
                 FROM task_artifact_integration_receipts
                 WHERE session_id=?1
                 ORDER BY created_at_unix_ms, artifact_id",
            )?;
            stmt.query_map(params![session.to_string()], map_receipt)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("listing session artifact integration receipts")
        })
        .await
    }
}

fn map_receipt(row: &rusqlite::Row<'_>) -> rusqlite::Result<TaskArtifactIntegrationReceipt> {
    Ok(TaskArtifactIntegrationReceipt {
        artifact_id: uuid(row.get(0)?, 0)?,
        session_id: uuid(row.get(1)?, 1)?,
        target_canonical_repository_id: row.get(2)?,
        target_canonical_root: row.get(3)?,
        target_head_digest: digest(row.get(4)?, 4)?,
        target_ref_digest: digest(row.get(5)?, 5)?,
        target_index_digest: digest(row.get(6)?, 6)?,
        changed_path_manifest_digest: digest(row.get(7)?, 7)?,
        target_write_scope_lease_id: uuid(row.get(8)?, 8)?,
        expected_target_generation: row.get::<_, i64>(9)? as u64,
        expected_target_revision: row.get::<_, i64>(10)? as u64,
        created_at_unix_ms: row.get(11)?,
    })
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
            parent_workspace_lease_id: None,
            canonical_repository_id: "repo-id".into(),
            canonical_root: "/repo/work".into(),
            kind: WorkspaceLeaseKind::ManagedWorktree,
            allowed_ops: 0b0111,
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
    async fn host_issued_workspace_lease_is_owner_scoped_and_tool_live() {
        let db = Db::open_in_memory().unwrap();
        let (session, owner_id, agent_scope) = owner(&db, 10).await;
        assert!(
            db.create_host_workspace_lease(
                lease_input(session, owner_id, agent_scope, 100),
                Uuid::new_v4(),
                10,
            )
            .await
            .is_err(),
            "host-issued rows must bind the session-root scope, not an agent-owned root"
        );
        let scope = Uuid::new_v4();
        db.insert_write_scope_lease(WriteScopeLeaseRow {
            lease_id: scope,
            parent_lease_id: None,
            session_id: session,
            task_id: None,
            scope_path: "/repo/work".into(),
            generation: 8,
            state: "active".into(),
            owner_id: "session-root".into(),
            version: 0,
            created_at_wall_ms: 10,
            updated_at_wall_ms: 10,
            released_at_wall_ms: None,
        })
        .await
        .unwrap();
        let id = Uuid::new_v4();
        let lease = db
            .create_host_workspace_lease(lease_input(session, owner_id, scope, 100), id, 10)
            .await
            .unwrap();
        assert_eq!(lease.workspace_lease_id, id);
        assert!(lease.host_issued);
        assert!(
            db.workspace_lease_for_tools(session, owner_id, id, 11)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            db.workspace_lease_for_tools(session, Uuid::new_v4(), id, 11)
                .await
                .unwrap()
                .is_none()
        );
        // Host-issued rows bind to the daemon root write scope, not an
        // agent-owned scope. Both artifact production and renewal must still
        // use that live host provenance rather than rejecting the row through
        // the agent-owned validation path.
        let renewed = db
            .renew_workspace_lease(session, owner_id, id, lease.revision, 200, 11)
            .await
            .unwrap();
        let LeaseCasOutcome::Transitioned(renewed) = renewed else {
            panic!("host-issued lease renewal must retain CAS semantics");
        };
        let artifact = db
            .create_task_artifact(
                artifact_input(session, owner_id, renewed.workspace_lease_id),
                12,
            )
            .await
            .unwrap();
        assert_eq!(
            artifact.source_workspace_lease_id,
            renewed.workspace_lease_id
        );
        let integrating = match db
            .begin_task_artifact_integration(
                session,
                owner_id,
                artifact.artifact_id,
                artifact.revision,
                13,
            )
            .await
            .unwrap()
        {
            ArtifactCasOutcome::Transitioned(row) => row,
            other => panic!("unexpected host-root integration begin: {other:?}"),
        };
        let integrated = db
            .integrate_task_artifact(
                session,
                owner_id,
                artifact.artifact_id,
                integrating.revision,
                IntegrationTarget {
                    target_canonical_repository_id: "repo-id".into(),
                    target_canonical_root: "/repo/work".into(),
                    target_head_digest: d("host-target-head"),
                    target_ref_digest: d("host-target-ref"),
                    target_index_digest: d("host-target-index"),
                    changed_path_manifest_digest: d("host-target-changed"),
                    target_write_scope_lease_id: scope,
                    expected_target_generation: 8,
                    expected_target_revision: 0,
                    target_workspace_lease_id: renewed.workspace_lease_id,
                    expected_target_workspace_lease_revision: renewed.revision,
                },
                14,
            )
            .await
            .unwrap();
        assert!(
            matches!(integrated, ArtifactCasOutcome::Transitioned(ref row) if row.state == TaskArtifactState::Integrated)
        );
        assert!(
            db.task_artifact_integration_receipt(session, owner_id, artifact.artifact_id)
                .await
                .unwrap()
                .is_some(),
            "an active session-root target scope must satisfy the receipt trigger"
        );
    }

    #[tokio::test]
    async fn inherited_host_lease_authorizes_only_agent_tree_descendants() {
        let db = Db::open_in_memory().unwrap();
        let (session, parent, _) = owner(&db, 10).await;
        let child = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: session,
                    parent_agent_instance_id: Some(parent),
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                11,
            )
            .await
            .unwrap();
        let unrelated = db
            .create_agent_instance(
                NewAgentInstance {
                    session_id: session,
                    parent_agent_instance_id: None,
                    task_delegation_job_id: None,
                    task_delegation_child_uuid: None,
                    resolved_profile_snapshot_id: None,
                    workspace_ref: None,
                    auto_answer_enabled: false,
                },
                11,
            )
            .await
            .unwrap();
        let host_scope = Uuid::new_v4();
        db.insert_write_scope_lease(WriteScopeLeaseRow {
            lease_id: host_scope,
            parent_lease_id: None,
            session_id: session,
            task_id: None,
            scope_path: "/repo".into(),
            generation: 8,
            state: "active".into(),
            owner_id: "session-root".into(),
            version: 0,
            created_at_wall_ms: 11,
            updated_at_wall_ms: 11,
            released_at_wall_ms: None,
        })
        .await
        .unwrap();
        let parent_lease = db
            .create_host_workspace_lease(
                lease_input(session, parent, host_scope, 100),
                Uuid::new_v4(),
                12,
            )
            .await
            .unwrap();

        assert!(
            db.workspace_lease_for_tools(
                session,
                child.agent_instance_id,
                parent_lease.workspace_lease_id,
                13,
            )
            .await
            .unwrap()
            .is_some(),
            "a direct child can use its issuing parent's selected lease"
        );
        let mut grandchild_lease = lease_input(session, child.agent_instance_id, host_scope, 100);
        grandchild_lease.parent_workspace_lease_id = Some(parent_lease.workspace_lease_id);
        grandchild_lease.managed_path = "agents/grandchild".into();
        assert!(
            db.create_host_workspace_lease(grandchild_lease, Uuid::new_v4(), 13)
                .await
                .is_ok(),
            "a child can issue a descendant lease only through its inherited parent lease"
        );
        assert!(
            db.workspace_lease_for_tools(
                session,
                unrelated.agent_instance_id,
                parent_lease.workspace_lease_id,
                13,
            )
            .await
            .unwrap()
            .is_none(),
            "an unrelated agent cannot adopt an ancestor's lease"
        );
    }

    #[tokio::test]
    async fn child_workspace_lease_fails_closed_when_parent_is_revoked() {
        let db = Db::open_in_memory().unwrap();
        let (session, agent, scope) = owner(&db, 10).await;
        let parent = db
            .create_workspace_lease(lease_input(session, agent, scope, 100), 10)
            .await
            .unwrap();
        let mut child_input = lease_input(session, agent, scope, 100);
        child_input.parent_workspace_lease_id = Some(parent.workspace_lease_id);
        child_input.managed_path = "agents/two".into();
        let child = db.create_workspace_lease(child_input, 11).await.unwrap();
        assert!(
            db.workspace_lease_for_tools(session, agent, child.workspace_lease_id, 12)
                .await
                .unwrap()
                .is_some()
        );
        db.grace_retain_workspace_lease(
            session,
            agent,
            parent.workspace_lease_id,
            parent.revision,
            13,
        )
        .await
        .unwrap();
        assert!(
            db.workspace_lease_for_tools(session, agent, child.workspace_lease_id, 14)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn child_workspace_lease_insert_rechecks_parent_lineage_transactionally() {
        let db = Db::open_in_memory().unwrap();
        let (session, agent, scope) = owner(&db, 10).await;
        let parent = db
            .create_workspace_lease(lease_input(session, agent, scope, 100), 10)
            .await
            .unwrap();
        db.grace_retain_workspace_lease(
            session,
            agent,
            parent.workspace_lease_id,
            parent.revision,
            11,
        )
        .await
        .unwrap();
        let mut child = lease_input(session, agent, scope, 100);
        child.parent_workspace_lease_id = Some(parent.workspace_lease_id);
        child.managed_path = "agents/revoked-parent-child".into();
        assert!(
            db.create_workspace_lease(child, 12).await.is_err(),
            "a child insert must not race a revoked parent snapshot"
        );
    }

    #[tokio::test]
    async fn host_issued_lease_can_produce_an_owner_scoped_artifact_from_host_scope() {
        let db = Db::open_in_memory().unwrap();
        let (session, agent, _) = owner(&db, 10).await;
        let scope = Uuid::new_v4();
        db.insert_write_scope_lease(WriteScopeLeaseRow {
            lease_id: scope,
            parent_lease_id: None,
            session_id: session,
            task_id: None,
            scope_path: "/daemon-root".into(),
            generation: 1,
            state: "active".into(),
            owner_id: "session-root".into(),
            version: 0,
            created_at_wall_ms: 10,
            updated_at_wall_ms: 10,
            released_at_wall_ms: None,
        })
        .await
        .unwrap();
        let lease = db
            .create_host_workspace_lease(
                lease_input(session, agent, scope, 100),
                Uuid::new_v4(),
                10,
            )
            .await
            .unwrap();
        let artifact = db
            .create_task_artifact(artifact_input(session, agent, lease.workspace_lease_id), 11)
            .await
            .unwrap();
        assert_eq!(artifact.source_workspace_lease_id, lease.workspace_lease_id);
        assert!(
            db.task_artifact(session, Uuid::new_v4(), artifact.artifact_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn workspace_lease_artifact_db_lifecycle_expiry_pin_and_receipt_are_exactly_once() {
        let db = Db::open_in_memory().unwrap();
        let (s, a, scope) = owner(&db, 100).await;
        let lease = db
            .create_workspace_lease(lease_input(s, a, scope, 200), 100)
            .await
            .unwrap();
        assert_eq!(
            lease.allowed_ops, 0b0111,
            "allowed operations round-trip exactly"
        );
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
        let cleaning = match db
            .claim_workspace_lease_cleanup(s, a, lease.workspace_lease_id, grace.revision, 202)
            .await
            .unwrap()
        {
            LeaseCasOutcome::Transitioned(v) => v,
            _ => panic!(),
        };
        let released = match db
            .release_workspace_lease_cleanup(s, a, lease.workspace_lease_id, cleaning.revision, 202)
            .await
            .unwrap()
        {
            LeaseCasOutcome::Transitioned(v) => v,
            other => panic!("cleanup release must retain CAS semantics: {other:?}"),
        };
        assert_eq!(released.state, WorkspaceLeaseState::Grace);
        let cleaning = match db
            .claim_workspace_lease_cleanup(s, a, lease.workspace_lease_id, released.revision, 202)
            .await
            .unwrap()
        {
            LeaseCasOutcome::Transitioned(v) => v,
            _ => panic!(),
        };
        let cleaned = match db
            .clean_workspace_lease(s, a, lease.workspace_lease_id, cleaning.revision, true, 202)
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
            target_workspace_lease_id: lease.workspace_lease_id,
            expected_target_workspace_lease_revision: lease.revision,
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
            "/repo/work"
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
            target_workspace_lease_id: lease.workspace_lease_id,
            expected_target_workspace_lease_revision: lease.revision,
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
        let stale_workspace_lease = IntegrationTarget {
            target_canonical_repository_id: "repo-id".into(),
            target_canonical_root: "/repo/work".into(),
            target_head_digest: d("target-head"),
            target_ref_digest: d("target-ref"),
            target_index_digest: d("target-index"),
            changed_path_manifest_digest: d("changed"),
            target_write_scope_lease_id: scope,
            expected_target_generation: 7,
            expected_target_revision: 3,
            target_workspace_lease_id: lease.workspace_lease_id,
            expected_target_workspace_lease_revision: lease.revision + 1,
        };
        assert!(matches!(
            db.integrate_task_artifact(
                s,
                a,
                artifact.artifact_id,
                integrating.revision,
                stale_workspace_lease,
                4,
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
            target_workspace_lease_id: lease.workspace_lease_id,
            expected_target_workspace_lease_revision: lease.revision,
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
    async fn receiptless_integrating_artifact_is_released_only_for_crash_recovery() {
        let db = Db::open_in_memory().unwrap();
        let (session, agent, scope) = owner(&db, 1).await;
        let lease = db
            .create_workspace_lease(lease_input(session, agent, scope, 100), 1)
            .await
            .unwrap();
        let artifact = db
            .create_task_artifact(artifact_input(session, agent, lease.workspace_lease_id), 2)
            .await
            .unwrap();
        let integrating = match db
            .begin_task_artifact_integration(
                session,
                agent,
                artifact.artifact_id,
                artifact.revision,
                3,
            )
            .await
            .unwrap()
        {
            ArtifactCasOutcome::Transitioned(row) => row,
            other => panic!("unexpected crash-gap setup outcome: {other:?}"),
        };
        let released = db
            .release_receiptless_integrating_artifacts_for_recovery(session, 4)
            .await
            .unwrap();
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].artifact_id, artifact.artifact_id);
        assert_eq!(released[0].state, TaskArtifactState::Produced);
        assert_eq!(released[0].revision, integrating.revision + 1);
        assert!(
            db.task_artifact_integration_receipt(session, agent, artifact.artifact_id)
                .await
                .unwrap()
                .is_none(),
            "only receipt-less rows may be reset after the pre-journal crash gap"
        );
    }

    #[tokio::test]
    async fn conflict_handoff_requires_workspace_and_scope_descendance() {
        let db = Db::open_in_memory().unwrap();
        let (session, agent, root_scope) = owner(&db, 1).await;
        let root = db
            .create_workspace_lease(lease_input(session, agent, root_scope, 100), 1)
            .await
            .unwrap();

        let make_child = |scope: Uuid, parent_scope: Uuid, path: &str| WriteScopeLeaseRow {
            lease_id: scope,
            parent_lease_id: Some(parent_scope),
            session_id: session,
            task_id: None,
            scope_path: path.into(),
            generation: 1,
            state: "active".into(),
            owner_id: agent.to_string(),
            version: 0,
            created_at_wall_ms: 2,
            updated_at_wall_ms: 2,
            released_at_wall_ms: None,
        };
        let parent_scope = Uuid::new_v4();
        db.insert_write_scope_lease(make_child(parent_scope, root_scope, "/repo/parent"))
            .await
            .unwrap();
        let mut parent_input = lease_input(session, agent, parent_scope, 100);
        parent_input.parent_workspace_lease_id = Some(root.workspace_lease_id);
        parent_input.canonical_root = "/repo/parent".into();
        parent_input.managed_path = "agents/parent".into();
        let parent = db
            .create_host_issued_child_workspace_lease(parent_input, Uuid::new_v4(), 2)
            .await
            .unwrap();

        let sibling_scope = Uuid::new_v4();
        db.insert_write_scope_lease(make_child(sibling_scope, root_scope, "/repo/sibling"))
            .await
            .unwrap();
        let mut sibling_input = lease_input(session, agent, sibling_scope, 100);
        sibling_input.parent_workspace_lease_id = Some(root.workspace_lease_id);
        sibling_input.canonical_root = "/repo/sibling".into();
        sibling_input.managed_path = "agents/sibling".into();
        let sibling = db
            .create_host_issued_child_workspace_lease(sibling_input, Uuid::new_v4(), 2)
            .await
            .unwrap();

        assert!(
            db.workspace_lease_for_conflict_handoff(
                session,
                agent,
                sibling.workspace_lease_id,
                parent.workspace_lease_id,
                parent_scope,
                3,
            )
            .await
            .unwrap()
            .is_none(),
            "a same-agent sibling lease cannot be presented as this parent's specialist"
        );

        let specialist_scope = Uuid::new_v4();
        db.insert_write_scope_lease(make_child(
            specialist_scope,
            parent_scope,
            "/repo/specialist",
        ))
        .await
        .unwrap();
        let mut specialist_input = lease_input(session, agent, specialist_scope, 100);
        specialist_input.parent_workspace_lease_id = Some(parent.workspace_lease_id);
        specialist_input.canonical_root = "/repo/specialist".into();
        specialist_input.managed_path = "agents/specialist".into();
        let specialist = db
            .create_host_issued_child_workspace_lease(specialist_input, Uuid::new_v4(), 3)
            .await
            .unwrap();
        assert!(
            db.workspace_lease_for_conflict_handoff(
                session,
                agent,
                specialist.workspace_lease_id,
                parent.workspace_lease_id,
                parent_scope,
                4,
            )
            .await
            .unwrap()
            .is_some()
        );
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
            target_workspace_lease_id: lease.workspace_lease_id,
            expected_target_workspace_lease_revision: lease.revision,
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
            target_workspace_lease_id: lease.workspace_lease_id,
            expected_target_workspace_lease_revision: lease.revision,
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
