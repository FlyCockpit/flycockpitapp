//! Durable, redacted operation state for daemon-owned agent installation.
//!
//! This is intentionally not an alternative installation API.  In particular
//! `finish_operation` cannot write an installation, binding, profile snapshot,
//! or revision.  The daemon calls the owning `agent_installations` transaction
//! first, then records a receipt here.  That separation makes recovery replay
//! a receipt rather than accidentally repeating the mutation.

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallationOperationKind {
    Install,
    Update,
    Bind,
    Create,
}

impl InstallationOperationKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Update => "update",
            Self::Bind => "bind",
            Self::Create => "create",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "install" => Ok(Self::Install),
            "update" => Ok(Self::Update),
            "bind" => Ok(Self::Bind),
            "create" => Ok(Self::Create),
            _ => bail!("unknown installation operation kind"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallationOperationState {
    PendingChoice,
    Running,
    Terminal,
}
impl InstallationOperationState {
    fn as_str(self) -> &'static str {
        match self {
            Self::PendingChoice => "pending_choice",
            Self::Running => "running",
            Self::Terminal => "terminal",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "pending_choice" => Ok(Self::PendingChoice),
            "running" => Ok(Self::Running),
            "terminal" => Ok(Self::Terminal),
            _ => bail!("unknown installation operation state"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationOperationRow {
    pub operation_id: Uuid,
    pub idempotency_key: String,
    pub request_fingerprint: String,
    pub kind: InstallationOperationKind,
    pub canonical_workspace_id: Option<String>,
    pub state: InstallationOperationState,
    /// A daemon-redacted terminal receipt only. It is opaque to the DB so the
    /// protocol may evolve without making the storage layer a wire dependency.
    pub terminal_receipt_json: Option<String>,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginInstallationOperation {
    Created(InstallationOperationRow),
    Replay(InstallationOperationRow),
    KeyConflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallationJournalCheckpoint {
    Staged,
    DbCommitted,
    FileRenamed,
    Complete,
}
impl InstallationJournalCheckpoint {
    fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::DbCommitted => "db_committed",
            Self::FileRenamed => "file_renamed",
            Self::Complete => "complete",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        match value {
            "staged" => Ok(Self::Staged),
            "db_committed" => Ok(Self::DbCommitted),
            "file_renamed" => Ok(Self::FileRenamed),
            "complete" => Ok(Self::Complete),
            _ => bail!("unknown installation journal checkpoint"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationJournalRow {
    pub journal_id: Uuid,
    pub operation_id: Uuid,
    pub checkpoint: InstallationJournalCheckpoint,
    pub staged_file_metadata_json: Option<String>,
    pub prior_file_metadata_json: Option<String>,
    pub expected_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationContinuationRow {
    pub continuation_token: Uuid,
    pub operation_id: Uuid,
    /// Redacted choice DTOs; never source paths, headers, or credentials.
    pub choice_set_json: String,
    pub expires_at_unix_ms: i64,
    pub submitted_choice_id: Option<String>,
}

/// A single SQLite read snapshot of a continuation and its owning operation.
/// Callers use this after a claim/expiry CAS loses so they never combine a
/// stale continuation row with a newer terminal receipt or submitted choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationContinuationState {
    pub continuation: InstallationContinuationRow,
    pub operation: InstallationOperationRow,
}

impl Db {
    pub async fn begin_installation_operation(
        &self,
        idempotency_key: String,
        request_fingerprint: String,
        kind: InstallationOperationKind,
        canonical_workspace_id: Option<String>,
        now_unix_ms: i64,
    ) -> Result<BeginInstallationOperation> {
        self.transaction(move |conn| {
            begin_operation_conn(
                conn,
                &idempotency_key,
                &request_fingerprint,
                kind,
                canonical_workspace_id.as_deref(),
                now_unix_ms,
            )
        })
        .await
    }

    /// Atomically create a fresh install/update operation and its immutable
    /// staged-source journal. A replay only reads the existing operation; it
    /// never replaces that operation's pinned source with bytes fetched by a
    /// later retry. This closes the otherwise observable crash window between
    /// operation creation and journal persistence.
    pub async fn begin_installation_operation_with_staged_journal(
        &self,
        idempotency_key: String,
        request_fingerprint: String,
        kind: InstallationOperationKind,
        canonical_workspace_id: Option<String>,
        staged_file_metadata_json: String,
        expected_digest: String,
        now_unix_ms: i64,
    ) -> Result<BeginInstallationOperation> {
        self.transaction(move |conn| {
            let begun = begin_operation_conn(
                conn,
                &idempotency_key,
                &request_fingerprint,
                kind,
                canonical_workspace_id.as_deref(),
                now_unix_ms,
            )?;
            if let BeginInstallationOperation::Created(operation) = &begun {
                record_journal_conn(
                    conn,
                    &InstallationJournalRow {
                        journal_id: Uuid::new_v4(),
                        operation_id: operation.operation_id,
                        checkpoint: InstallationJournalCheckpoint::Staged,
                        staged_file_metadata_json: Some(staged_file_metadata_json),
                        // The daemon records the owned-file observation after
                        // resolving its held target path, immediately before
                        // staging. It must not trust a client path here.
                        prior_file_metadata_json: None,
                        expected_digest,
                    },
                    now_unix_ms,
                )?;
            }
            Ok(begun)
        })
        .await
    }

    pub async fn installation_operation(
        &self,
        key: String,
    ) -> Result<Option<InstallationOperationRow>> {
        self.read(move |conn| operation_by_key(conn, &key)).await
    }

    pub async fn installation_operation_by_id(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<InstallationOperationRow>> {
        self.read(move |conn| operation_by_id(conn, operation_id))
            .await
    }

    pub async fn create_installation_continuation(
        &self,
        operation_id: Uuid,
        choice_set_json: String,
        expires_at_unix_ms: i64,
        now_unix_ms: i64,
    ) -> Result<InstallationContinuationRow> {
        self.transaction(move |conn| {
            create_continuation_conn(
                conn,
                operation_id,
                &choice_set_json,
                expires_at_unix_ms,
                now_unix_ms,
            )
        })
        .await
    }

    /// Atomically claims a live continuation.  A terminal receipt wins expiry
    /// races because callers must check/replay its operation before invoking
    /// this method.
    pub async fn claim_installation_continuation(
        &self,
        token: Uuid,
        choice_id: String,
        now_unix_ms: i64,
    ) -> Result<Option<InstallationOperationRow>> {
        self.transaction(move |conn| claim_continuation_conn(conn, token, &choice_id, now_unix_ms))
            .await
    }

    pub async fn installation_continuation(
        &self,
        token: Uuid,
    ) -> Result<Option<InstallationContinuationRow>> {
        self.read(move |conn| continuation_row_by_token(conn, token))
            .await
    }

    /// Read continuation and operation from one durable snapshot. This is the
    /// required CAS-loser reconciliation boundary for choice submission.
    pub async fn installation_continuation_state(
        &self,
        token: Uuid,
    ) -> Result<Option<InstallationContinuationState>> {
        self.read(move |conn| {
            let Some(continuation) = continuation_row_by_token(conn, token)? else {
                return Ok(None);
            };
            let operation = operation_by_id(conn, continuation.operation_id)?
                .context("installation operation disappeared")?;
            Ok(Some(InstallationContinuationState {
                continuation,
                operation,
            }))
        })
        .await
    }

    /// Return the single durable continuation for an operation.  Daemon
    /// restart/retry uses this to replay the original redacted choice set
    /// instead of refetching or recreating a continuation.
    pub async fn installation_continuation_for_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<InstallationContinuationRow>> {
        self.read(move |conn| continuation_row_by_operation(conn, operation_id))
            .await
    }

    pub async fn expire_installation_continuation(
        &self,
        token: Uuid,
        now_unix_ms: i64,
        receipt_json: String,
    ) -> Result<Option<InstallationOperationRow>> {
        self.transaction(move |conn| {
            expire_continuation_conn(conn, token, now_unix_ms, &receipt_json)
        })
        .await
    }

    pub async fn record_installation_journal(
        &self,
        row: InstallationJournalRow,
        now_unix_ms: i64,
    ) -> Result<()> {
        self.transaction(move |conn| record_journal_conn(conn, &row, now_unix_ms))
            .await
    }

    pub async fn installation_journal(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<InstallationJournalRow>> {
        self.read(move |conn| journal_by_operation(conn, operation_id))
            .await
    }

    /// Marks an operation terminal.  No installation mutation occurs here.
    pub async fn finish_installation_operation(
        &self,
        operation_id: Uuid,
        receipt_json: String,
        now_unix_ms: i64,
    ) -> Result<InstallationOperationRow> {
        self.transaction(move |conn| {
            finish_operation_conn(conn, operation_id, &receipt_json, now_unix_ms)
        })
        .await
    }
}

pub fn begin_operation_conn(
    conn: &Connection,
    key: &str,
    fingerprint: &str,
    kind: InstallationOperationKind,
    workspace: Option<&str>,
    now: i64,
) -> Result<BeginInstallationOperation> {
    validate_input(key, fingerprint, workspace)?;
    if let Some(existing) = operation_by_key(conn, key)? {
        return Ok(if existing.request_fingerprint == fingerprint {
            BeginInstallationOperation::Replay(existing)
        } else {
            BeginInstallationOperation::KeyConflict
        });
    }
    let row = InstallationOperationRow {
        operation_id: Uuid::new_v4(),
        idempotency_key: key.into(),
        request_fingerprint: fingerprint.into(),
        kind,
        canonical_workspace_id: workspace.map(str::to_owned),
        state: InstallationOperationState::Running,
        terminal_receipt_json: None,
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
    };
    conn.execute("INSERT INTO installation_operations(operation_id,idempotency_key,request_fingerprint,operation_kind,canonical_workspace_id,state,created_at_unix_ms,updated_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?7)", params![row.operation_id.to_string(), key, fingerprint, kind.as_str(), workspace, row.state.as_str(), now]).context("creating installation operation")?;
    Ok(BeginInstallationOperation::Created(row))
}

fn create_continuation_conn(
    conn: &Connection,
    operation_id: Uuid,
    choices: &str,
    expires: i64,
    now: i64,
) -> Result<InstallationContinuationRow> {
    ensure!(
        !choices.is_empty() && choices.len() <= 256 * 1024,
        "invalid redacted installation choice set"
    );
    ensure!(
        expires > now,
        "installation continuation must expire in the future"
    );
    let op = operation_by_id(conn, operation_id)?.context("installation operation not found")?;
    ensure!(
        op.state == InstallationOperationState::Running,
        "terminal or pending installation operation cannot create a continuation"
    );
    let row = InstallationContinuationRow {
        continuation_token: Uuid::new_v4(),
        operation_id,
        choice_set_json: choices.into(),
        expires_at_unix_ms: expires,
        submitted_choice_id: None,
    };
    conn.execute("INSERT INTO installation_continuations(continuation_token,operation_id,choice_set_json,expires_at_unix_ms,state,created_at_unix_ms,updated_at_unix_ms) VALUES(?1,?2,?3,?4,'pending',?5,?5)", params![row.continuation_token.to_string(), operation_id.to_string(), choices, expires, now]).context("creating installation continuation")?;
    conn.execute("UPDATE installation_operations SET state='pending_choice',updated_at_unix_ms=?2 WHERE operation_id=?1", params![operation_id.to_string(), now]).context("marking installation operation pending")?;
    Ok(row)
}

fn claim_continuation_conn(
    conn: &Connection,
    token: Uuid,
    choice: &str,
    now: i64,
) -> Result<Option<InstallationOperationRow>> {
    ensure!(
        !choice.is_empty() && choice.len() <= 1024,
        "invalid installation choice"
    );
    let continuation = continuation_by_token(conn, token)?;
    let Some((operation_id, expires, state)) = continuation else {
        return Ok(None);
    };
    if state != "pending" || expires <= now {
        return Ok(None);
    }
    let changed = conn.execute("UPDATE installation_continuations SET state='claimed',submitted_choice_id=?2,updated_at_unix_ms=?3 WHERE continuation_token=?1 AND state='pending' AND expires_at_unix_ms>?3", params![token.to_string(), choice, now]).context("claiming installation continuation")?;
    if changed != 1 {
        return Ok(None);
    }
    conn.execute("UPDATE installation_operations SET state='running',updated_at_unix_ms=?2 WHERE operation_id=?1 AND state='pending_choice'", params![operation_id.to_string(), now]).context("resuming installation operation")?;
    operation_by_id(conn, operation_id)
}

fn expire_continuation_conn(
    conn: &Connection,
    token: Uuid,
    now: i64,
    receipt: &str,
) -> Result<Option<InstallationOperationRow>> {
    let Some((operation_id, expires, state)) = continuation_by_token(conn, token)? else {
        return Ok(None);
    };
    if state != "pending" || expires > now {
        return Ok(None);
    }
    if conn.execute("UPDATE installation_continuations SET state='expired',updated_at_unix_ms=?2 WHERE continuation_token=?1 AND state='pending' AND expires_at_unix_ms<=?2", params![token.to_string(), now]).context("expiring installation continuation")? != 1 { return Ok(None) }
    Ok(Some(finish_operation_conn(
        conn,
        operation_id,
        receipt,
        now,
    )?))
}

fn record_journal_conn(conn: &Connection, row: &InstallationJournalRow, now: i64) -> Result<()> {
    ensure!(
        !row.expected_digest.is_empty() && row.expected_digest.len() <= 128,
        "invalid installation journal digest"
    );
    let operation =
        operation_by_id(conn, row.operation_id)?.context("installation operation not found")?;
    ensure!(
        operation.state != InstallationOperationState::Terminal,
        "cannot journal a terminal installation operation"
    );
    let existing = journal_by_operation(conn, row.operation_id)?;
    if let Some(existing) = existing {
        ensure!(
            existing.journal_id == row.journal_id,
            "installation operation already has another journal"
        );
        ensure!(
            checkpoint_rank(row.checkpoint) >= checkpoint_rank(existing.checkpoint),
            "installation journal checkpoint may not move backwards"
        );
        conn.execute("UPDATE installation_journals SET checkpoint=?2,staged_file_metadata_json=?3,prior_file_metadata_json=?4,expected_digest=?5,updated_at_unix_ms=?6 WHERE operation_id=?1", params![row.operation_id.to_string(), row.checkpoint.as_str(), row.staged_file_metadata_json, row.prior_file_metadata_json, row.expected_digest, now]).context("advancing installation journal")?;
    } else {
        conn.execute("INSERT INTO installation_journals(journal_id,operation_id,checkpoint,staged_file_metadata_json,prior_file_metadata_json,expected_digest,created_at_unix_ms,updated_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?7)", params![row.journal_id.to_string(),row.operation_id.to_string(),row.checkpoint.as_str(),row.staged_file_metadata_json,row.prior_file_metadata_json,row.expected_digest,now]).context("creating installation journal")?;
    }
    Ok(())
}

fn finish_operation_conn(
    conn: &Connection,
    operation_id: Uuid,
    receipt: &str,
    now: i64,
) -> Result<InstallationOperationRow> {
    ensure!(
        !receipt.is_empty() && receipt.len() <= 256 * 1024,
        "invalid redacted installation receipt"
    );
    let current =
        operation_by_id(conn, operation_id)?.context("installation operation not found")?;
    if current.state == InstallationOperationState::Terminal {
        ensure!(
            current.terminal_receipt_json.as_deref() == Some(receipt),
            "terminal installation receipt is immutable"
        );
        return Ok(current);
    }
    conn.execute("UPDATE installation_operations SET state='terminal',terminal_receipt_json=?2,updated_at_unix_ms=?3 WHERE operation_id=?1", params![operation_id.to_string(), receipt, now]).context("finishing installation operation")?;
    conn.execute("UPDATE installation_continuations SET state='completed',updated_at_unix_ms=?2 WHERE operation_id=?1 AND state='claimed'", params![operation_id.to_string(), now]).context("completing installation continuation")?;
    operation_by_id(conn, operation_id)?.context("finished installation operation disappeared")
}

fn operation_by_key(conn: &Connection, key: &str) -> Result<Option<InstallationOperationRow>> {
    conn.query_row("SELECT operation_id,idempotency_key,request_fingerprint,operation_kind,canonical_workspace_id,state,terminal_receipt_json,created_at_unix_ms,updated_at_unix_ms FROM installation_operations WHERE idempotency_key=?1", [key], decode_operation).optional().context("looking up installation operation")
}
fn operation_by_id(conn: &Connection, id: Uuid) -> Result<Option<InstallationOperationRow>> {
    conn.query_row("SELECT operation_id,idempotency_key,request_fingerprint,operation_kind,canonical_workspace_id,state,terminal_receipt_json,created_at_unix_ms,updated_at_unix_ms FROM installation_operations WHERE operation_id=?1", [id.to_string()], decode_operation).optional().context("looking up installation operation")
}
fn decode_operation(row: &rusqlite::Row<'_>) -> rusqlite::Result<InstallationOperationRow> {
    (|| -> Result<_> {
        Ok(InstallationOperationRow {
            operation_id: Uuid::parse_str(&row.get::<_, String>(0)?)
                .context("invalid installation operation id")?,
            idempotency_key: row.get(1)?,
            request_fingerprint: row.get(2)?,
            kind: InstallationOperationKind::parse(&row.get::<_, String>(3)?)?,
            canonical_workspace_id: row.get(4)?,
            state: InstallationOperationState::parse(&row.get::<_, String>(5)?)?,
            terminal_receipt_json: row.get(6)?,
            created_at_unix_ms: row.get(7)?,
            updated_at_unix_ms: row.get(8)?,
        })
    })()
    .map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}
fn continuation_by_token(conn: &Connection, token: Uuid) -> Result<Option<(Uuid, i64, String)>> {
    conn.query_row("SELECT operation_id,expires_at_unix_ms,state FROM installation_continuations WHERE continuation_token=?1", [token.to_string()], |r| Ok((Uuid::parse_str(&r.get::<_, String>(0)?).map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?, r.get(1)?, r.get(2)?))).optional().context("looking up installation continuation")
}

fn continuation_row_by_token(
    conn: &Connection,
    token: Uuid,
) -> Result<Option<InstallationContinuationRow>> {
    conn.query_row("SELECT continuation_token,operation_id,choice_set_json,expires_at_unix_ms,submitted_choice_id FROM installation_continuations WHERE continuation_token=?1", [token.to_string()], |row| {
        Ok(InstallationContinuationRow {
            continuation_token: Uuid::parse_str(&row.get::<_, String>(0)?).map_err(|error| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error)))?,
            operation_id: Uuid::parse_str(&row.get::<_, String>(1)?).map_err(|error| rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(error)))?,
            choice_set_json: row.get(2)?,
            expires_at_unix_ms: row.get(3)?,
            submitted_choice_id: row.get(4)?,
        })
    }).optional().context("looking up installation continuation row")
}
fn continuation_row_by_operation(
    conn: &Connection,
    operation_id: Uuid,
) -> Result<Option<InstallationContinuationRow>> {
    conn.query_row("SELECT continuation_token,operation_id,choice_set_json,expires_at_unix_ms,submitted_choice_id FROM installation_continuations WHERE operation_id=?1", [operation_id.to_string()], |row| {
        Ok(InstallationContinuationRow {
            continuation_token: Uuid::parse_str(&row.get::<_, String>(0)?).map_err(|error| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error)))?,
            operation_id: Uuid::parse_str(&row.get::<_, String>(1)?).map_err(|error| rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(error)))?,
            choice_set_json: row.get(2)?,
            expires_at_unix_ms: row.get(3)?,
            submitted_choice_id: row.get(4)?,
        })
    }).optional().context("looking up installation continuation by operation")
}
fn journal_by_operation(
    conn: &Connection,
    operation_id: Uuid,
) -> Result<Option<InstallationJournalRow>> {
    conn.query_row("SELECT journal_id,operation_id,checkpoint,staged_file_metadata_json,prior_file_metadata_json,expected_digest FROM installation_journals WHERE operation_id=?1", [operation_id.to_string()], |r| { (|| -> Result<_> { Ok(InstallationJournalRow { journal_id: Uuid::parse_str(&r.get::<_, String>(0)?).context("invalid installation journal id")?, operation_id: Uuid::parse_str(&r.get::<_, String>(1)?).context("invalid installation operation id")?, checkpoint: InstallationJournalCheckpoint::parse(&r.get::<_, String>(2)?)?, staged_file_metadata_json: r.get(3)?, prior_file_metadata_json: r.get(4)?, expected_digest: r.get(5)? }) })().map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))) }).optional().context("looking up installation journal")
}
fn checkpoint_rank(value: InstallationJournalCheckpoint) -> u8 {
    match value {
        InstallationJournalCheckpoint::Staged => 0,
        InstallationJournalCheckpoint::DbCommitted => 1,
        InstallationJournalCheckpoint::FileRenamed => 2,
        InstallationJournalCheckpoint::Complete => 3,
    }
}
fn validate_input(key: &str, fingerprint: &str, workspace: Option<&str>) -> Result<()> {
    ensure!(
        !key.trim().is_empty() && key.len() <= 256,
        "invalid installation idempotency key"
    );
    ensure!(
        !fingerprint.is_empty() && fingerprint.len() <= 128,
        "invalid installation request fingerprint"
    );
    ensure!(
        workspace.is_none_or(|v| !v.is_empty() && v.len() <= 4096),
        "invalid canonical workspace identity"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn agent_installation_daemon_idempotency_continuation_and_terminal_race() {
        let db = Db::open_in_memory().unwrap();
        let BeginInstallationOperation::Created(operation) = db
            .begin_installation_operation(
                "idempotency".into(),
                "fingerprint".into(),
                InstallationOperationKind::Install,
                Some("workspace-id".into()),
                1,
            )
            .await
            .unwrap()
        else {
            panic!("expected create")
        };
        assert!(matches!(
            db.begin_installation_operation(
                "idempotency".into(),
                "fingerprint".into(),
                InstallationOperationKind::Install,
                Some("workspace-id".into()),
                2
            )
            .await
            .unwrap(),
            BeginInstallationOperation::Replay(_)
        ));
        assert!(matches!(
            db.begin_installation_operation(
                "idempotency".into(),
                "other".into(),
                InstallationOperationKind::Install,
                None,
                2
            )
            .await
            .unwrap(),
            BeginInstallationOperation::KeyConflict
        ));
        let pending = db
            .create_installation_continuation(
                operation.operation_id,
                r#"[{"id":"first"}]"#.into(),
                10,
                3,
            )
            .await
            .unwrap();
        let claimed = db
            .claim_installation_continuation(pending.continuation_token, "first".into(), 4)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claimed.state, InstallationOperationState::Running);
        let terminal = db
            .finish_installation_operation(
                operation.operation_id,
                r#"{"status":"installed"}"#.into(),
                5,
            )
            .await
            .unwrap();
        assert_eq!(terminal.state, InstallationOperationState::Terminal);
        assert!(
            db.expire_installation_continuation(
                pending.continuation_token,
                20,
                r#"{"status":"timeout"}"#.into()
            )
            .await
            .unwrap()
            .is_none()
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_continuation_cas_loser_reads_current_claim_and_terminal() {
        let db = Db::open_in_memory().unwrap();
        let BeginInstallationOperation::Created(operation) = db
            .begin_installation_operation(
                "choice-race".into(),
                "fingerprint".into(),
                InstallationOperationKind::Bind,
                None,
                1,
            )
            .await
            .unwrap()
        else {
            panic!("expected operation")
        };
        let continuation = db
            .create_installation_continuation(
                operation.operation_id,
                r#"[{"id":"first"}]"#.into(),
                10,
                1,
            )
            .await
            .unwrap();
        assert!(
            db.claim_installation_continuation(continuation.continuation_token, "first".into(), 2)
                .await
                .unwrap()
                .is_some()
        );
        // A simultaneous same-choice submit loses its CAS, then must inspect
        // the current claim rather than the stale pre-CAS row.
        assert!(
            db.claim_installation_continuation(continuation.continuation_token, "first".into(), 2)
                .await
                .unwrap()
                .is_none()
        );
        let current = db
            .installation_continuation_state(continuation.continuation_token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            current.continuation.submitted_choice_id.as_deref(),
            Some("first")
        );
        assert_eq!(current.operation.state, InstallationOperationState::Running);
        db.finish_installation_operation(operation.operation_id, r#"{"status":"bound"}"#.into(), 3)
            .await
            .unwrap();
        // An expiry CAS that loses to a claim/terminal transition must replay
        // the winner rather than manufacture a timeout receipt.
        assert!(
            db.expire_installation_continuation(
                continuation.continuation_token,
                20,
                r#"{"status":"timed_out"}"#.into(),
            )
            .await
            .unwrap()
            .is_none()
        );
        let current = db
            .installation_continuation_state(continuation.continuation_token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            current.operation.terminal_receipt_json.as_deref(),
            Some(r#"{"status":"bound"}"#)
        );
    }

    #[tokio::test]
    async fn agent_installation_daemon_journal_checkpoints_are_monotonic_and_never_mutate_bindings()
    {
        let db = Db::open_in_memory().unwrap();
        let BeginInstallationOperation::Created(operation) = db
            .begin_installation_operation(
                "journal-key".into(),
                "journal-fingerprint".into(),
                InstallationOperationKind::Install,
                None,
                1,
            )
            .await
            .unwrap()
        else {
            panic!("expected operation")
        };
        let journal = InstallationJournalRow {
            journal_id: Uuid::new_v4(),
            operation_id: operation.operation_id,
            checkpoint: InstallationJournalCheckpoint::Staged,
            staged_file_metadata_json: Some("{}".into()),
            prior_file_metadata_json: None,
            expected_digest: "digest".into(),
        };
        db.record_installation_journal(journal.clone(), 2)
            .await
            .unwrap();
        for checkpoint in [
            InstallationJournalCheckpoint::DbCommitted,
            InstallationJournalCheckpoint::FileRenamed,
            InstallationJournalCheckpoint::Complete,
        ] {
            db.record_installation_journal(
                InstallationJournalRow {
                    checkpoint,
                    ..journal.clone()
                },
                3,
            )
            .await
            .unwrap();
        }
        assert!(db.record_installation_journal(journal, 4).await.is_err());
        let binding_count = db
            .read(|conn| {
                Ok(
                    conn.query_row("SELECT COUNT(*) FROM agent_model_bindings", [], |row| {
                        row.get::<_, i64>(0)
                    })?,
                )
            })
            .await
            .unwrap();
        assert_eq!(binding_count, 0);
    }
}
