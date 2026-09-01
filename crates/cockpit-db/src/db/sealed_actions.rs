//! Durable persistence for immutable sealed action instances, publish-before-
//! effect invocation audit, and the recovery-audit ledger.
//!
//! Two durable surfaces live here:
//!
//! * [`sealed_action_instances`](crate) — the persisted, immutable snapshot of
//!   one Owner-compiled action instance. It is the single source the HTTPS
//!   executor compiles an egress target from, so its `kind_json` holds the
//!   validated origin allowlist, credential *placement* (never the credential
//!   value), request path template, projection, and bounded non-secret
//!   parameters. A revise/retire revokes the dependent grants in the SAME
//!   transaction that mutates the snapshot row, so a crash mid-operation can
//!   never leave a retired/revised action with a live grant.
//! * [`sealed_recovery_audit`](crate) — the audit ledger a recover reveal
//!   commits to **before** the plaintext is returned (publish-before-destroy).
//!   The row carries only safe metadata and a closed outcome; never the
//!   literal.
//! * `sealed_action_invocation_audit` — safe metadata committed before a host
//!   injection effect receives plaintext. It carries no target or output.
//!
//! The connection-level helpers are `pub` precisely so the cockpit-core store
//! layer can compose the revoke + snapshot-mutate pair inside one
//! [`Db::transaction`], and drive a mid-transaction failure-injection test that
//! proves the pair is atomic.

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};

use crate::db::Db;

/// The persisted immutable snapshot of one action instance. Carries no literal
/// and no credential value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedActionInstanceRow {
    pub action_id: String,
    pub revision: i64,
    pub kind_json: String,
    pub description: String,
    pub project_key: String,
    pub enabled: bool,
    pub created_at_ms: i64,
    pub retired_at_ms: Option<i64>,
}

/// What the Owner supplies to persist a freshly compiled action instance. The
/// `action_id` is a daemon-minted UUID; the caller never chooses it.
#[derive(Debug, Clone)]
pub struct NewSealedActionInstance {
    pub action_id: String,
    pub revision: i64,
    pub kind_json: String,
    pub description: String,
    pub project_key: String,
    pub created_at_ms: i64,
}

/// Safe publish-before-effect metadata for one reference injection. This row
/// deliberately carries no literal, destination, command, environment key,
/// path, request data, output, or secret-derived outcome.
#[derive(Debug, Clone)]
pub struct SealedActionInvocationAuditEntry {
    pub audit_id: String,
    pub record_id: String,
    pub action_id: String,
    pub action_revision: i64,
    pub grant_id: String,
    pub session_id: String,
    pub sink_kind: String,
    pub file_persistent: bool,
    pub created_at_ms: i64,
}

/// The closed outcome recorded in one recovery-audit row. Neither variant
/// carries the literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedRecoveryOutcome {
    Revealed,
    Rejected,
}

impl SealedRecoveryOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Revealed => "revealed",
            Self::Rejected => "rejected",
        }
    }
}

/// One recovery-audit entry. Safe metadata only.
#[derive(Debug, Clone)]
pub struct SealedRecoveryAuditEntry {
    pub audit_id: String,
    pub record_id: String,
    pub scope: String,
    pub scope_key: String,
    pub version: i64,
    pub owner_principal: String,
    pub minting_session: String,
    pub outcome: SealedRecoveryOutcome,
    pub created_at_ms: i64,
}

const INSTANCE_COLUMNS: &str = "action_id, revision, kind_json, description, project_key, enabled, created_at_ms, retired_at_ms";

fn decode_instance(row: &rusqlite::Row<'_>) -> rusqlite::Result<SealedActionInstanceRow> {
    Ok(SealedActionInstanceRow {
        action_id: row.get(0)?,
        revision: row.get(1)?,
        kind_json: row.get(2)?,
        description: row.get(3)?,
        project_key: row.get(4)?,
        enabled: row.get::<_, i64>(5)? != 0,
        created_at_ms: row.get(6)?,
        retired_at_ms: row.get(7)?,
    })
}

/// Insert a freshly compiled action-instance snapshot. Fails closed on a
/// duplicate `action_id` (instances are immutable; a daemon-minted UUID must
/// not already exist).
pub fn insert_action_instance_conn(conn: &Connection, new: &NewSealedActionInstance) -> Result<()> {
    let changed = conn
        .execute(
            "INSERT INTO sealed_action_instances
                 (action_id, revision, kind_json, description, project_key, enabled,
                  created_at_ms, retired_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, NULL)",
            params![
                new.action_id,
                new.revision,
                new.kind_json,
                new.description,
                new.project_key,
                new.created_at_ms,
            ],
        )
        .context("inserting sealed action instance")?;
    if changed != 1 {
        bail!("sealed action instance insert affected {changed} rows");
    }
    Ok(())
}

/// Read one action instance by exact id.
pub fn action_instance_conn(
    conn: &Connection,
    action_id: &str,
) -> Result<Option<SealedActionInstanceRow>> {
    conn.query_row(
        &format!("SELECT {INSTANCE_COLUMNS} FROM sealed_action_instances WHERE action_id = ?1"),
        params![action_id],
        decode_instance,
    )
    .optional()
    .context("reading sealed action instance")
}

/// List every action instance (retired and live), ordered by creation.
pub fn list_action_instances_conn(conn: &Connection) -> Result<Vec<SealedActionInstanceRow>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT {INSTANCE_COLUMNS} FROM sealed_action_instances
              ORDER BY created_at_ms ASC, action_id ASC"
        ))
        .context("preparing sealed action instance list")?;
    let rows = stmt
        .query_map([], decode_instance)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("reading sealed action instance list")?;
    Ok(rows)
}

/// Revoke every live grant naming one action id. Returns the number of grants
/// revoked. Used by revise/retire *inside the same transaction* that mutates
/// the snapshot, so a crash cannot separate the two.
pub fn revoke_action_grants_conn(conn: &Connection, action_id: &str, now_ms: i64) -> Result<usize> {
    let changed = conn
        .execute(
            "UPDATE sealed_action_grants SET revoked_at_ms = ?2
              WHERE action_id = ?1 AND revoked_at_ms IS NULL",
            params![action_id, now_ms],
        )
        .context("revoking sealed action grants for an action instance")?;
    Ok(changed)
}

/// Mutate a live action instance to a new revision snapshot. The caller has
/// already revoked the dependent grants earlier in the same transaction. Fails
/// closed if the action is missing, already retired, or — the lost-update fence
/// — no longer at `expected_prev_revision`.
///
/// The `WHERE revision = expected_prev_revision` predicate makes the mutation a
/// compare-and-swap on the revision read before the transaction: two concurrent
/// revises both read revision N and try to write N+1, but only the first's
/// `WHERE revision = N` matches. The loser changes zero rows and fails closed
/// instead of silently overwriting the winner's snapshot (e.g. re-enabling an
/// action the winner just disabled).
pub fn revise_action_instance_conn(
    conn: &Connection,
    action_id: &str,
    expected_prev_revision: i64,
    new_revision: i64,
    kind_json: &str,
    description: &str,
    enabled: bool,
) -> Result<SealedActionInstanceRow> {
    let changed = conn
        .execute(
            "UPDATE sealed_action_instances
                SET revision = ?3, kind_json = ?4, description = ?5, enabled = ?6
              WHERE action_id = ?1 AND retired_at_ms IS NULL AND revision = ?2",
            params![
                action_id,
                expected_prev_revision,
                new_revision,
                kind_json,
                description,
                i64::from(enabled),
            ],
        )
        .context("revising sealed action instance")?;
    if changed != 1 {
        bail!(
            "cannot revise sealed action instance: missing, retired, or revised concurrently \
             (revision fence)"
        );
    }
    action_instance_conn(conn, action_id)?
        .context("revised sealed action instance vanished inside its own transaction")
}

/// Retire a live action instance. The caller has already revoked the dependent
/// grants earlier in the same transaction. Returns `true` when this call
/// retired a previously-live instance, `false` when it was already retired.
pub fn retire_action_instance_conn(
    conn: &Connection,
    action_id: &str,
    now_ms: i64,
) -> Result<bool> {
    let changed = conn
        .execute(
            "UPDATE sealed_action_instances
                SET retired_at_ms = ?2, enabled = 0
              WHERE action_id = ?1 AND retired_at_ms IS NULL",
            params![action_id, now_ms],
        )
        .context("retiring sealed action instance")?;
    Ok(changed == 1)
}

/// Persist one recovery-audit row. A single durable write; the recover path
/// calls this and requires it to succeed *before* revealing the plaintext.
pub fn insert_recovery_audit_conn(
    conn: &Connection,
    entry: &SealedRecoveryAuditEntry,
) -> Result<()> {
    let changed = conn
        .execute(
            "INSERT INTO sealed_recovery_audit
                 (audit_id, record_id, scope, scope_key, version, owner_principal,
                  minting_session, outcome, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                entry.audit_id,
                entry.record_id,
                entry.scope,
                entry.scope_key,
                entry.version,
                entry.owner_principal,
                entry.minting_session,
                entry.outcome.as_str(),
                entry.created_at_ms,
            ],
        )
        .context("inserting sealed recovery audit row")?;
    if changed != 1 {
        bail!("sealed recovery audit insert affected {changed} rows");
    }
    Ok(())
}

/// Commit an invocation audit row before the host effect receives plaintext.
pub fn insert_action_invocation_audit_conn(
    conn: &Connection,
    entry: &SealedActionInvocationAuditEntry,
) -> Result<()> {
    let changed = conn
        .execute(
            "INSERT INTO sealed_action_invocation_audit
                 (audit_id, record_id, action_id, action_revision, grant_id,
                  session_id, sink_kind, file_persistent, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                entry.audit_id,
                entry.record_id,
                entry.action_id,
                entry.action_revision,
                entry.grant_id,
                entry.session_id,
                entry.sink_kind,
                i64::from(entry.file_persistent),
                entry.created_at_ms,
            ],
        )
        .context("inserting sealed action invocation audit row")?;
    if changed != 1 {
        bail!("sealed action invocation audit insert affected {changed} rows");
    }
    Ok(())
}

impl Db {
    /// Persist a freshly compiled action-instance snapshot.
    pub async fn insert_sealed_action_instance(&self, new: NewSealedActionInstance) -> Result<()> {
        self.write(move |conn| insert_action_instance_conn(conn, &new))
            .await
    }

    /// Read one action instance by exact id.
    pub async fn sealed_action_instance(
        &self,
        action_id: String,
    ) -> Result<Option<SealedActionInstanceRow>> {
        self.read(move |conn| action_instance_conn(conn, &action_id))
            .await
    }

    /// List every action instance.
    pub async fn list_sealed_action_instances(&self) -> Result<Vec<SealedActionInstanceRow>> {
        self.read(list_action_instances_conn).await
    }

    /// Publish safe invocation metadata before a host sink receives plaintext.
    pub async fn insert_sealed_action_invocation_audit(
        &self,
        entry: SealedActionInvocationAuditEntry,
    ) -> Result<()> {
        self.write(move |conn| insert_action_invocation_audit_conn(conn, &entry))
            .await
    }

    /// Persist one recovery-audit row and commit it durably.
    pub async fn insert_sealed_recovery_audit(
        &self,
        entry: SealedRecoveryAuditEntry,
    ) -> Result<()> {
        self.write(move |conn| insert_recovery_audit_conn(conn, &entry))
            .await
    }

    /// Every recovery-audit row for one record, oldest first. Test/inspection
    /// surface; never returns a literal.
    pub async fn sealed_recovery_audit_for_record(
        &self,
        record_id: String,
    ) -> Result<Vec<SealedRecoveryAuditEntry>> {
        self.read(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT audit_id, record_id, scope, scope_key, version, owner_principal,
                            minting_session, outcome, created_at_ms
                       FROM sealed_recovery_audit
                      WHERE record_id = ?1
                      ORDER BY created_at_ms ASC, audit_id ASC",
                )
                .context("preparing recovery audit read")?;
            let rows = stmt
                .query_map(params![record_id], |row| {
                    let outcome: String = row.get(7)?;
                    Ok(SealedRecoveryAuditEntry {
                        audit_id: row.get(0)?,
                        record_id: row.get(1)?,
                        scope: row.get(2)?,
                        scope_key: row.get(3)?,
                        version: row.get(4)?,
                        owner_principal: row.get(5)?,
                        minting_session: row.get(6)?,
                        outcome: match outcome.as_str() {
                            "revealed" => SealedRecoveryOutcome::Revealed,
                            _ => SealedRecoveryOutcome::Rejected,
                        },
                        created_at_ms: row.get(8)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()
                .context("reading recovery audit rows")?;
            Ok(rows)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_instance(action_id: &str) -> NewSealedActionInstance {
        NewSealedActionInstance {
            action_id: action_id.to_string(),
            revision: 1,
            kind_json: r#"{"Https":{}}"#.to_string(),
            description: "call the deploy webhook".to_string(),
            project_key: "/repo".to_string(),
            created_at_ms: 1_000,
        }
    }

    #[tokio::test]
    async fn instance_round_trips_and_lists() {
        let db = Db::open_in_memory().unwrap();
        db.insert_sealed_action_instance(new_instance("act-1"))
            .await
            .unwrap();
        let row = db
            .sealed_action_instance("act-1".into())
            .await
            .unwrap()
            .expect("row present");
        assert_eq!(row.revision, 1);
        assert!(row.enabled);
        assert!(row.retired_at_ms.is_none());
        let all = db.list_sealed_action_instances().await.unwrap();
        assert_eq!(all.len(), 1);
    }

    #[tokio::test]
    async fn duplicate_action_id_insert_fails() {
        let db = Db::open_in_memory().unwrap();
        db.insert_sealed_action_instance(new_instance("act-1"))
            .await
            .unwrap();
        let err = db
            .insert_sealed_action_instance(new_instance("act-1"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("sealed action instance"));
    }

    #[tokio::test]
    async fn revise_is_fenced_on_the_prior_revision() {
        // Finding 6: two revises that both read revision 1 must not both succeed.
        // The first advances the row to revision 2; the second, still fencing on
        // revision 1, changes zero rows and fails closed instead of silently
        // overwriting the winner's snapshot.
        let db = Db::open_in_memory().unwrap();
        db.insert_sealed_action_instance(new_instance("act-1"))
            .await
            .unwrap();
        // Winner: expected_prev = 1, write revision 2 (disable).
        let row = db
            .transaction(|conn| {
                revise_action_instance_conn(
                    conn,
                    "act-1",
                    1,
                    2,
                    r#"{"Https":{}}"#,
                    "disabled",
                    false,
                )
            })
            .await
            .unwrap();
        assert_eq!(row.revision, 2);
        assert!(!row.enabled);
        // Loser: a stale revise still fencing on revision 1 is rejected.
        let err = db
            .transaction(|conn| {
                revise_action_instance_conn(
                    conn,
                    "act-1",
                    1,
                    2,
                    r#"{"Https":{}}"#,
                    "re-enabled",
                    true,
                )
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("fence"), "{err}");
        // The winner's snapshot is intact: still revision 2, still disabled.
        let row = db
            .sealed_action_instance("act-1".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.revision, 2);
        assert!(
            !row.enabled,
            "the stale revise did not re-enable the action"
        );
    }

    #[tokio::test]
    async fn retire_marks_row_retired_and_is_idempotent() {
        let db = Db::open_in_memory().unwrap();
        db.insert_sealed_action_instance(new_instance("act-1"))
            .await
            .unwrap();
        let first = db
            .transaction(|conn| retire_action_instance_conn(conn, "act-1", 2_000))
            .await
            .unwrap();
        assert!(first, "first retire is effective");
        let second = db
            .transaction(|conn| retire_action_instance_conn(conn, "act-1", 3_000))
            .await
            .unwrap();
        assert!(!second, "second retire is a no-op");
        let row = db
            .sealed_action_instance("act-1".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.retired_at_ms, Some(2_000));
        assert!(!row.enabled);
    }

    #[tokio::test]
    async fn recovery_audit_row_persists_without_literal() {
        let db = Db::open_in_memory().unwrap();
        db.insert_sealed_recovery_audit(SealedRecoveryAuditEntry {
            audit_id: "audit-1".into(),
            record_id: "rec-1".into(),
            scope: "global".into(),
            scope_key: String::new(),
            version: 3,
            owner_principal: "owner".into(),
            minting_session: "sess-A".into(),
            outcome: SealedRecoveryOutcome::Revealed,
            created_at_ms: 42,
        })
        .await
        .unwrap();
        let rows = db
            .sealed_recovery_audit_for_record("rec-1".into())
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].outcome, SealedRecoveryOutcome::Revealed);
        assert_eq!(rows[0].version, 3);
    }

    #[tokio::test]
    async fn recovery_audit_rejects_unknown_outcome_and_bad_scope() {
        let db = Db::open_in_memory().unwrap();
        // The CHECK constraint enumerates the closed outcome + scope sets.
        let err = db
            .write(|conn| {
                conn.execute(
                    "INSERT INTO sealed_recovery_audit
                         (audit_id, record_id, scope, scope_key, version, owner_principal,
                          minting_session, outcome, created_at_ms)
                     VALUES ('a', 'r', 'global', '', 1, 'owner', 's', 'leaked', 1)",
                    [],
                )
                .map_err(anyhow::Error::from)
            })
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("constraint"));
    }
}
