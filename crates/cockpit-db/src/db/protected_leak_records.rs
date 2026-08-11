//! Durable protected leak-containment records: SQLite coordination only.
//!
//! This module owns the durable half of the `report_leak` containment flow.
//! It stores **only safe metadata** for each accepted leak report: report id,
//! keyed fingerprint, host-derived provenance, closed source, closed category,
//! optional canonical connector id, status, timestamps, and rotation
//! disposition. The encrypted literal itself lives in
//! `protected_redaction_history` (source = `ContainedLeak`) and is referenced
//! by `history_id`; this table never holds plaintext, a prefix, a length, a
//! ciphertext, a nonce, or a key version.
//!
//! Two properties are load-bearing and enforced here rather than left to
//! callers:
//!
//! * **No literal leakage.** Every row type exposed by this module
//!   ([`ProtectedLeakRecord`], [`ProtectedLeakRecordRef`]) carries only
//!   opaque IDs, safe metadata, and the `history_id` link. There is no
//!   plaintext field anywhere in the generic row shape.
//! * **Atomic containment commit.** [`insert_leak_record_conn`] and the
//!   protected-redaction-history append compose inside one
//!   [`crate::db::Db::transaction`] closure, so a crash at either ordering
//!   point commits neither the encrypted literal nor the containment record.
//!
//! A `pending` row is never listable by the generic audit/list/export surface:
//! [`list_listable_refs_conn`] filters to `contained`/`rotated`/`superseded`
//! only. Deduplication is on `(session_id, leak_fingerprint)`: a re-report
//! updates safe `seen` metadata and clears rotation state.

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;
use crate::db::protected_redaction_history::ProtectedRedactionSource;

/// Closed source set for a leak report. The host derives provider/model/session
/// provenance separately; `source` is the model-supplied closed classification
/// of where the leaked material was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeakSource {
    ModelOutput,
    ToolOutput,
    Reasoning,
    EnvLeak,
    CredentialLeak,
    Other,
}

impl LeakSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ModelOutput => "model_output",
            Self::ToolOutput => "tool_output",
            Self::Reasoning => "reasoning",
            Self::EnvLeak => "env_leak",
            Self::CredentialLeak => "credential_leak",
            Self::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "model_output" => Ok(Self::ModelOutput),
            "tool_output" => Ok(Self::ToolOutput),
            "reasoning" => Ok(Self::Reasoning),
            "env_leak" => Ok(Self::EnvLeak),
            "credential_leak" => Ok(Self::CredentialLeak),
            "other" => Ok(Self::Other),
            other => bail!("unknown leak source: {other}"),
        }
    }
}

impl std::fmt::Display for LeakSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Closed category for the kind of sensitive material reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeakCategory {
    Secret,
    Token,
    Key,
    Password,
    Pii,
    Other,
}

impl LeakCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Token => "token",
            Self::Key => "key",
            Self::Password => "password",
            Self::Pii => "pii",
            Self::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "secret" => Ok(Self::Secret),
            "token" => Ok(Self::Token),
            "key" => Ok(Self::Key),
            "password" => Ok(Self::Password),
            "pii" => Ok(Self::Pii),
            "other" => Ok(Self::Other),
            other => bail!("unknown leak category: {other}"),
        }
    }
}

impl std::fmt::Display for LeakCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Closed status for a leak containment record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeakRecordStatus {
    Pending,
    Contained,
    Rotated,
    Superseded,
    Deleted,
}

impl LeakRecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Contained => "contained",
            Self::Rotated => "rotated",
            Self::Superseded => "superseded",
            Self::Deleted => "deleted",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "pending" => Ok(Self::Pending),
            "contained" => Ok(Self::Contained),
            "rotated" => Ok(Self::Rotated),
            "superseded" => Ok(Self::Superseded),
            "deleted" => Ok(Self::Deleted),
            other => bail!("unknown leak record status: {other}"),
        }
    }
}

/// Closed rotation disposition for a leak containment record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeakRotation {
    None,
    PendingUser,
    Rotated,
    NotApplicable,
}

impl LeakRotation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::PendingUser => "pending_user",
            Self::Rotated => "rotated",
            Self::NotApplicable => "not_applicable",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "none" => Ok(Self::None),
            "pending_user" => Ok(Self::PendingUser),
            "rotated" => Ok(Self::Rotated),
            "not_applicable" => Ok(Self::NotApplicable),
            other => bail!("unknown leak rotation: {other}"),
        }
    }
}

/// Host-derived provenance stamped from the active route. Never model-supplied.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LeakProvenance {
    pub provider_id: Option<String>,
    pub model_id: Option<String>,
    pub generation: Option<i64>,
    pub connector_id: Option<String>,
}

/// One protected leak containment record (full row, owner-sensitive read).
/// Carries no plaintext, prefix, length, ciphertext, nonce, or key version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedLeakRecord {
    pub report_id: String,
    pub session_id: String,
    pub history_id: String,
    pub leak_fingerprint: String,
    pub source: LeakSource,
    pub category: LeakCategory,
    pub provider_id: Option<String>,
    pub model_id: Option<String>,
    pub generation: Option<i64>,
    pub connector_id: Option<String>,
    pub status: LeakRecordStatus,
    pub seen_count: i64,
    pub rotation: LeakRotation,
    pub first_reported_ms: i64,
    pub last_reported_ms: i64,
    pub contained_at_ms: Option<i64>,
    pub retired_at_ms: Option<i64>,
}

/// Safe metadata projection for export/diagnostics: no plaintext, no
/// ciphertext, no nonce, no key version, no `history_id` (the link to the
/// encrypted literal is owner-sensitive only). Only opaque report id, safe
/// provenance, closed source/category/status, and timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedLeakRecordRef {
    pub report_id: String,
    pub session_id: String,
    pub source: LeakSource,
    pub category: LeakCategory,
    pub provider_id: Option<String>,
    pub model_id: Option<String>,
    pub generation: Option<i64>,
    pub connector_id: Option<String>,
    pub status: LeakRecordStatus,
    pub seen_count: i64,
    pub rotation: LeakRotation,
    pub first_reported_ms: i64,
    pub last_reported_ms: i64,
    pub contained_at_ms: Option<i64>,
}

impl ProtectedLeakRecordRef {
    /// Project a full row into the safe export/diagnostics reference. Strips
    /// `history_id` (the link to the encrypted literal) and `retired_at_ms`.
    pub fn from_row(row: &ProtectedLeakRecord) -> Self {
        Self {
            report_id: row.report_id.clone(),
            session_id: row.session_id.clone(),
            source: row.source,
            category: row.category,
            provider_id: row.provider_id.clone(),
            model_id: row.model_id.clone(),
            generation: row.generation,
            connector_id: row.connector_id.clone(),
            status: row.status,
            seen_count: row.seen_count,
            rotation: row.rotation,
            first_reported_ms: row.first_reported_ms,
            last_reported_ms: row.last_reported_ms,
            contained_at_ms: row.contained_at_ms,
        }
    }
}

/// Insert-input for a new leak containment record. Built by `cockpit-core`
/// from the closed ingress classification; the encrypted literal is appended
/// to `protected_redaction_history` separately and linked by `history_id`.
#[derive(Debug, Clone)]
pub struct InsertLeakRecordInput {
    pub report_id: String,
    pub session_id: String,
    pub history_id: String,
    pub leak_fingerprint: String,
    pub source: LeakSource,
    pub category: LeakCategory,
    pub provenance: LeakProvenance,
    pub status: LeakRecordStatus,
    pub now_ms: i64,
}

/// Result of [`insert_leak_record_conn`]: either a newly created row or an
/// existing deduplicated row (same session + keyed fingerprint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertLeakResult {
    Created {
        report_id: String,
    },
    /// Deduplicated against an existing row with the same session + keyed
    /// fingerprint. `seen_count` was incremented and rotation cleared.
    Existing {
        report_id: String,
        seen_count: i64,
    },
}

#[allow(dead_code)]
fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

impl Db {
    /// List all protected leak records for a session (full rows, including
    /// the `history_id` link). Owner-sensitive read only.
    pub async fn protected_leak_records_list(
        &self,
        session_id: &str,
    ) -> Result<Vec<ProtectedLeakRecord>> {
        let session_id = session_id.to_owned();
        self.read(move |conn| list_leak_records_conn(conn, &session_id))
            .await
    }

    /// List safe reference projections for a session. This is the only shape
    /// suitable for export/diagnostics. Filters out `pending` and `deleted`
    /// rows: a pending record is not listable until it transitions to
    /// `contained`.
    pub async fn protected_leak_records_refs(
        &self,
        session_id: &str,
    ) -> Result<Vec<ProtectedLeakRecordRef>> {
        let session_id = session_id.to_owned();
        self.read(move |conn| {
            let rows = list_listable_refs_conn(conn, &session_id)?;
            Ok(rows)
        })
        .await
    }

    /// Count accepted leak reports for a session within the last hour. Used
    /// for rate limiting (32 accepted reports/session/hour).
    pub async fn protected_leak_records_count_recent(
        &self,
        session_id: &str,
        since_ms: i64,
    ) -> Result<i64> {
        let session_id = session_id.to_owned();
        self.read(move |conn| count_recent_conn(conn, &session_id, since_ms))
            .await
    }

    /// Get one leak record by report id (full row). Owner-sensitive read only.
    pub async fn protected_leak_record_get(
        &self,
        report_id: &str,
    ) -> Result<Option<ProtectedLeakRecord>> {
        let report_id = report_id.to_owned();
        self.read(move |conn| get_leak_record_conn(conn, &report_id))
            .await
    }
}

// ---- Connection-scoped writers (compose inside one transaction) ------------

/// Insert a protected leak containment record, deduplicating on
/// `(session_id, leak_fingerprint)`. Connection-scoped so callers compose it
/// inside one [`crate::db::Db::transaction`] alongside the
/// protected-redaction-history append. A re-report increments `seen_count`,
/// clears rotation to `none`, and refreshes `last_reported_ms`; it does not
/// create a second row.
///
/// Returns the report id (new or existing) and, for dedup, the new seen count.
pub fn insert_leak_record_conn(
    conn: &Connection,
    input: &InsertLeakRecordInput,
) -> Result<InsertLeakResult> {
    if let Some(existing) =
        get_leak_record_by_fingerprint_conn(conn, &input.session_id, &input.leak_fingerprint)?
    {
        // Re-report: increment seen_count, clear rotation, refresh timestamp.
        let new_seen = existing.seen_count + 1;
        conn.execute(
            "UPDATE protected_leak_records
             SET seen_count = ?1, rotation = 'none', last_reported_ms = ?2
             WHERE report_id = ?3",
            params![new_seen, input.now_ms, existing.report_id],
        )
        .context("updating deduplicated protected leak record")?;
        return Ok(InsertLeakResult::Existing {
            report_id: existing.report_id,
            seen_count: new_seen,
        });
    }
    let report_id = if input.report_id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        input.report_id.clone()
    };
    conn.execute(
        "INSERT INTO protected_leak_records
            (report_id, session_id, history_id, leak_fingerprint, source, category,
             provider_id, model_id, generation, connector_id, status, seen_count,
             rotation, first_reported_ms, last_reported_ms, contained_at_ms, retired_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1, 'none', ?12, ?12, NULL, NULL)",
        params![
            report_id,
            input.session_id,
            input.history_id,
            input.leak_fingerprint,
            input.source.as_str(),
            input.category.as_str(),
            input.provenance.provider_id,
            input.provenance.model_id,
            input.provenance.generation,
            input.provenance.connector_id,
            input.status.as_str(),
            input.now_ms,
        ],
    )
    .context("inserting protected leak record row")?;
    Ok(InsertLeakResult::Created { report_id })
}

/// Transition a leak record's status. Connection-scoped so callers compose it
/// inside one transaction. Used by the containment handler to move a record
/// from `pending` to `contained` after the protected-redaction-history append
/// and redaction install commit.
pub fn transition_leak_status_conn(
    conn: &Connection,
    report_id: &str,
    new_status: LeakRecordStatus,
    now_ms: i64,
) -> Result<()> {
    let contained_at = if matches!(new_status, LeakRecordStatus::Contained) {
        Some(now_ms)
    } else {
        None
    };
    let n = conn
        .execute(
            "UPDATE protected_leak_records
             SET status = ?1, contained_at_ms = COALESCE(?2, contained_at_ms)
             WHERE report_id = ?3",
            params![new_status.as_str(), contained_at, report_id],
        )
        .context("transitioning protected leak record status")?;
    if n == 0 {
        bail!("protected leak record not found: {report_id}");
    }
    Ok(())
}

/// Retire (soft-delete) a leak record. Sets `retired_at_ms` and status to
/// `deleted`. The encrypted literal in `protected_redaction_history` is
/// retained so historical redaction continues to scrub the value.
pub fn retire_leak_record_conn(conn: &Connection, report_id: &str, now_ms: i64) -> Result<()> {
    let n = conn
        .execute(
            "UPDATE protected_leak_records
             SET status = 'deleted', retired_at_ms = ?1
             WHERE report_id = ?2",
            params![now_ms, report_id],
        )
        .context("retiring protected leak record")?;
    if n == 0 {
        bail!("protected leak record not found: {report_id}");
    }
    Ok(())
}

// ---- Connection-scoped readers --------------------------------------------

/// Load one leak record by report id (full row).
pub fn get_leak_record_conn(
    conn: &Connection,
    report_id: &str,
) -> Result<Option<ProtectedLeakRecord>> {
    conn.query_row(
        "SELECT report_id, session_id, history_id, leak_fingerprint, source, category,
                provider_id, model_id, generation, connector_id, status, seen_count,
                rotation, first_reported_ms, last_reported_ms, contained_at_ms, retired_at_ms
         FROM protected_leak_records WHERE report_id = ?1",
        [report_id],
        map_leak_row,
    )
    .optional()
    .context("loading protected leak record")
}

/// Load one leak record by `(session_id, leak_fingerprint)` (dedup lookup).
pub fn get_leak_record_by_fingerprint_conn(
    conn: &Connection,
    session_id: &str,
    leak_fingerprint: &str,
) -> Result<Option<ProtectedLeakRecord>> {
    conn.query_row(
        "SELECT report_id, session_id, history_id, leak_fingerprint, source, category,
                provider_id, model_id, generation, connector_id, status, seen_count,
                rotation, first_reported_ms, last_reported_ms, contained_at_ms, retired_at_ms
         FROM protected_leak_records
         WHERE session_id = ?1 AND leak_fingerprint = ?2
         ORDER BY first_reported_ms ASC LIMIT 1",
        params![session_id, leak_fingerprint],
        map_leak_row,
    )
    .optional()
    .context("loading protected leak record by fingerprint")
}

/// List all leak records for a session (full rows). Owner-sensitive read only.
pub fn list_leak_records_conn(
    conn: &Connection,
    session_id: &str,
) -> Result<Vec<ProtectedLeakRecord>> {
    let mut stmt = conn.prepare(
        "SELECT report_id, session_id, history_id, leak_fingerprint, source, category,
                provider_id, model_id, generation, connector_id, status, seen_count,
                rotation, first_reported_ms, last_reported_ms, contained_at_ms, retired_at_ms
         FROM protected_leak_records
         WHERE session_id = ?1
         ORDER BY first_reported_ms ASC, report_id ASC",
    )?;
    let rows = stmt.query_map([session_id], map_leak_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing protected leak records")
}

/// List safe reference projections for a session, filtering out `pending` and
/// `deleted` rows. This is the only shape suitable for export/diagnostics.
pub fn list_listable_refs_conn(
    conn: &Connection,
    session_id: &str,
) -> Result<Vec<ProtectedLeakRecordRef>> {
    let mut stmt = conn.prepare(
        "SELECT report_id, session_id, history_id, leak_fingerprint, source, category,
                provider_id, model_id, generation, connector_id, status, seen_count,
                rotation, first_reported_ms, last_reported_ms, contained_at_ms, retired_at_ms
         FROM protected_leak_records
         WHERE session_id = ?1 AND status IN ('contained', 'rotated', 'superseded')
         ORDER BY first_reported_ms ASC, report_id ASC",
    )?;
    let rows = stmt.query_map([session_id], map_leak_row)?;
    let records: Vec<ProtectedLeakRecord> = rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("listing listable protected leak records")?;
    Ok(records
        .iter()
        .map(ProtectedLeakRecordRef::from_row)
        .collect())
}

/// Count leak records for a session accepted since `since_ms`. Used for the
/// 32-reports/session/hour rate limit.
pub fn count_recent_conn(conn: &Connection, session_id: &str, since_ms: i64) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM protected_leak_records
         WHERE session_id = ?1 AND last_reported_ms >= ?2
           AND status != 'deleted'",
        params![session_id, since_ms],
        |row| row.get(0),
    )
    .context("counting recent protected leak records")
}

// ---- Row mappers -----------------------------------------------------------

fn map_leak_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProtectedLeakRecord> {
    let source: String = row.get(4)?;
    let category: String = row.get(5)?;
    let status: String = row.get(10)?;
    let rotation: String = row.get(12)?;
    Ok(ProtectedLeakRecord {
        report_id: row.get(0)?,
        session_id: row.get(1)?,
        history_id: row.get(2)?,
        leak_fingerprint: row.get(3)?,
        source: LeakSource::parse(&source).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        category: LeakCategory::parse(&category).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                5,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        provider_id: row.get(6)?,
        model_id: row.get(7)?,
        generation: row.get(8)?,
        connector_id: row.get(9)?,
        status: LeakRecordStatus::parse(&status).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                10,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        seen_count: row.get(11)?,
        rotation: LeakRotation::parse(&rotation).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                12,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        first_reported_ms: row.get(13)?,
        last_reported_ms: row.get(14)?,
        contained_at_ms: row.get(15)?,
        retired_at_ms: row.get(16)?,
    })
}

/// Re-export the protected-redaction-history source so callers do not depend
/// on the db crate directly for the `ContainedLeak` classification.
pub fn contained_leak_source() -> ProtectedRedactionSource {
    ProtectedRedactionSource::ContainedLeak
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::db::protected_redaction_history::{
        AppendHistoryResult, ProtectedRedactionHistoryAppend, append_history_conn,
    };

    fn test_db() -> Db {
        Db::open_in_memory().unwrap()
    }

    fn session_id() -> &'static str {
        "bbbbbbbb-bbbb-bbbb-bbbb-222222222222"
    }

    fn append_history(conn: &Connection) -> String {
        let fp = "c1d2e3f4a5b6c1d2e3f4a5b6c1d2e3f4c1d2e3f4a5b6c1d2e3f4a5b6c1d2e3f4";
        let input = ProtectedRedactionHistoryAppend {
            session_id: session_id().to_owned(),
            sealed_record_id: None,
            sealed_version: None,
            source: ProtectedRedactionSource::ContainedLeak,
            fingerprint: fp.to_owned(),
            ciphertext: vec![0u8; 32],
            nonce: vec![0u8; 12],
            key_version: 1,
        };
        let r = append_history_conn(conn, &input).unwrap();
        match r {
            AppendHistoryResult::Created { history_id } => history_id,
            AppendHistoryResult::Existing { history_id } => history_id,
        }
    }

    #[tokio::test]
    async fn insert_dedup_and_list() {
        let db = test_db();
        let history_id = db
            .write(move |conn| Ok(append_history(conn)))
            .await
            .unwrap();

        let input = InsertLeakRecordInput {
            report_id: String::new(),
            session_id: session_id().to_owned(),
            history_id: history_id.clone(),
            leak_fingerprint: "deadbeef".to_owned(),
            source: LeakSource::ModelOutput,
            category: LeakCategory::Token,
            provenance: LeakProvenance {
                provider_id: Some("openai".to_owned()),
                model_id: Some("gpt-4".to_owned()),
                generation: Some(7),
                connector_id: None,
            },
            status: LeakRecordStatus::Contained,
            now_ms: 1000,
        };
        let report_id = db
            .write(move |conn| {
                let r = insert_leak_record_conn(conn, &input)?;
                Ok(match r {
                    InsertLeakResult::Created { report_id } => report_id,
                    InsertLeakResult::Existing { report_id, .. } => report_id,
                })
            })
            .await
            .unwrap();

        // Dedup: same fingerprint returns existing with incremented seen_count.
        let input2 = InsertLeakRecordInput {
            report_id: String::new(),
            session_id: session_id().to_owned(),
            history_id: history_id.clone(),
            leak_fingerprint: "deadbeef".to_owned(),
            source: LeakSource::ModelOutput,
            category: LeakCategory::Token,
            provenance: LeakProvenance {
                provider_id: Some("openai".to_owned()),
                model_id: Some("gpt-4".to_owned()),
                generation: Some(7),
                connector_id: None,
            },
            status: LeakRecordStatus::Contained,
            now_ms: 2000,
        };
        let result = db
            .write(move |conn| insert_leak_record_conn(conn, &input2))
            .await
            .unwrap();
        match result {
            InsertLeakResult::Existing {
                report_id: rid,
                seen_count,
            } => {
                assert_eq!(rid, report_id);
                assert_eq!(seen_count, 2);
            }
            _ => panic!("expected dedup"),
        }

        // List returns one row (the deduped one).
        let rows = db.protected_leak_records_list(session_id()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].seen_count, 2);
        assert_eq!(rows[0].last_reported_ms, 2000);
    }

    #[tokio::test]
    async fn pending_rows_are_not_listable() {
        let db = test_db();
        let history_id = db
            .write(move |conn| Ok(append_history(conn)))
            .await
            .unwrap();

        let input = InsertLeakRecordInput {
            report_id: String::new(),
            session_id: session_id().to_owned(),
            history_id,
            leak_fingerprint: "cafebabe".to_owned(),
            source: LeakSource::Reasoning,
            category: LeakCategory::Key,
            provenance: LeakProvenance {
                provider_id: None,
                model_id: None,
                generation: None,
                connector_id: None,
            },
            status: LeakRecordStatus::Pending,
            now_ms: 1000,
        };
        db.write(move |conn| insert_leak_record_conn(conn, &input))
            .await
            .unwrap();

        // Pending rows are not listable via the safe refs surface.
        let refs = db.protected_leak_records_refs(session_id()).await.unwrap();
        assert!(refs.is_empty());

        // But the full list (owner-sensitive) still shows it.
        let rows = db.protected_leak_records_list(session_id()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, LeakRecordStatus::Pending);
    }

    #[tokio::test]
    async fn transition_pending_to_contained() {
        let db = test_db();
        let history_id = db
            .write(move |conn| Ok(append_history(conn)))
            .await
            .unwrap();

        let input = InsertLeakRecordInput {
            report_id: String::new(),
            session_id: session_id().to_owned(),
            history_id,
            leak_fingerprint: "f00dface".to_owned(),
            source: LeakSource::ToolOutput,
            category: LeakCategory::Password,
            provenance: LeakProvenance::default(),
            status: LeakRecordStatus::Pending,
            now_ms: 1000,
        };
        let report_id = db
            .write(move |conn| {
                let r = insert_leak_record_conn(conn, &input)?;
                Ok(match r {
                    InsertLeakResult::Created { report_id } => report_id,
                    InsertLeakResult::Existing { report_id, .. } => report_id,
                })
            })
            .await
            .unwrap();

        db.write(move |conn| {
            transition_leak_status_conn(conn, &report_id, LeakRecordStatus::Contained, 2000)
        })
        .await
        .unwrap();

        let row = db
            .protected_leak_record_get(&report_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, LeakRecordStatus::Contained);
        assert_eq!(row.contained_at_ms, Some(2000));

        // Now listable.
        let refs = db.protected_leak_records_refs(session_id()).await.unwrap();
        assert_eq!(refs.len(), 1);
    }
}
