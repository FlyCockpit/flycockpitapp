//! Durable protected redaction-history store: SQLite coordination only.
//!
//! This module owns the durable half of protected redaction history. It stores
//! **encrypted literal material** (ciphertext + nonce) keyed by an opaque
//! history ID and the local key-store key version. No plaintext, prefix,
//! length, ciphertext, nonce, or key version ever appears in a generic,
//! protocol, diagnostics, or export query surface — those columns are consumed
//! solely by the local Owner-sensitive rehydration frame in `cockpit-core`.
//!
//! Two properties are load-bearing and enforced here rather than left to
//! callers:
//!
//! * **No literal leakage.** Every row type exposed by this module
//!   ([`ProtectedRedactionHistoryRow`], [`ProtectedRedactionArtifactRef`])
//!   carries only opaque IDs, safe source/fingerprint metadata, and encrypted
//!   blobs. There is no plaintext field, no prefix, no length, and no
//!   unencrypted literal anywhere in the generic row shape.
//! * **Atomic attach.** [`append_history_conn`] and [`attach_artifact_ref_conn`]
//!   are connection-scoped so callers compose them inside one
//!   [`crate::db::Db::transaction`] closure alongside the raw artifact write.
//!   A crash at either ordering point commits neither.

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

/// Closed source set for a protected redaction-history row. No caller may
/// introduce a new source without a matching closed-writer classification in
/// `cockpit-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectedRedactionSource {
    Sealed,
    Environment,
    Credential,
    ContainedLeak,
}

impl ProtectedRedactionSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "Sealed",
            Self::Environment => "Environment",
            Self::Credential => "Credential",
            Self::ContainedLeak => "ContainedLeak",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "Sealed" => Ok(Self::Sealed),
            "Environment" => Ok(Self::Environment),
            "Credential" => Ok(Self::Credential),
            "ContainedLeak" => Ok(Self::ContainedLeak),
            other => bail!("unknown protected redaction source: {other}"),
        }
    }
}

impl std::fmt::Display for ProtectedRedactionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Durable artifact kind that may reference a protected redaction-history row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectedRedactionArtifactKind {
    Request,
    Response,
    Tool,
    Event,
    Attempt,
}

impl ProtectedRedactionArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
            Self::Tool => "tool",
            Self::Event => "event",
            Self::Attempt => "attempt",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "request" => Ok(Self::Request),
            "response" => Ok(Self::Response),
            "tool" => Ok(Self::Tool),
            "event" => Ok(Self::Event),
            "attempt" => Ok(Self::Attempt),
            other => bail!("unknown protected redaction artifact kind: {other}"),
        }
    }
}

impl std::fmt::Display for ProtectedRedactionArtifactKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One protected redaction-history row. Carries encrypted literal material
/// only; no plaintext field exists in this struct.
///
/// The `ciphertext` and `nonce` blobs are consumed solely by the local
/// Owner-sensitive rehydration frame in `cockpit-core`. They must never be
/// serialized into a generic, protocol, diagnostics, or export payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedRedactionHistoryRow {
    pub history_id: String,
    pub session_id: String,
    pub sealed_record_id: Option<String>,
    pub sealed_version: Option<i64>,
    pub source: ProtectedRedactionSource,
    /// SHA-256 fingerprint of the literal (safe deduplication key).
    pub fingerprint: String,
    /// Encrypted literal material (local rehydration frame only).
    pub ciphertext: Vec<u8>,
    /// AEAD nonce (local rehydration frame only).
    pub nonce: Vec<u8>,
    /// Local key-store key version that encrypted this row.
    pub key_version: i64,
    pub ref_count: i64,
    pub created_at_ms: i64,
    pub retired_at_ms: Option<i64>,
}

/// One opaque artifact-to-history reference. Carries no literal, ciphertext,
/// nonce, or key version — only opaque IDs and the artifact kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedRedactionArtifactRef {
    pub artifact_kind: ProtectedRedactionArtifactKind,
    pub artifact_id: String,
    pub history_id: String,
    pub created_at_ms: i64,
}

/// Safe metadata projection for export/diagnostics: no literal, prefix,
/// length, ciphertext, nonce, or key version. Only opaque IDs and safe
/// source/fingerprint metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedRedactionHistoryRef {
    pub history_id: String,
    pub session_id: String,
    pub source: ProtectedRedactionSource,
    pub fingerprint: String,
    pub ref_count: i64,
    pub created_at_ms: i64,
    pub retired_at_ms: Option<i64>,
}

impl ProtectedRedactionHistoryRef {
    /// Project a full row into the safe export/diagnostics reference.
    /// This strips ciphertext, nonce, key version, sealed record/version.
    pub fn from_row(row: &ProtectedRedactionHistoryRow) -> Self {
        Self {
            history_id: row.history_id.clone(),
            session_id: row.session_id.clone(),
            source: row.source,
            fingerprint: row.fingerprint.clone(),
            ref_count: row.ref_count,
            created_at_ms: row.created_at_ms,
            retired_at_ms: row.retired_at_ms,
        }
    }
}

/// Append-input: the encrypted literal material and safe metadata for one
/// history row. Built by `cockpit-core` from the closed-writer classification;
/// no plaintext enters this struct.
#[derive(Debug, Clone)]
pub struct ProtectedRedactionHistoryAppend {
    pub session_id: String,
    pub sealed_record_id: Option<String>,
    pub sealed_version: Option<i64>,
    pub source: ProtectedRedactionSource,
    pub fingerprint: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_version: i64,
}

/// Result of [`append_history_conn`]: either a newly created row or an
/// existing deduplicated row (same session + fingerprint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendHistoryResult {
    Created {
        history_id: String,
    },
    /// Deduplicated against an existing row with the same session + fingerprint.
    Existing {
        history_id: String,
    },
}

/// Current epoch milliseconds.
fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

impl Db {
    /// List all protected redaction-history rows for a session (full rows,
    /// including encrypted material). Owner-sensitive read only.
    pub async fn protected_redaction_history_list(
        &self,
        session_id: &str,
    ) -> Result<Vec<ProtectedRedactionHistoryRow>> {
        let session_id = session_id.to_owned();
        self.read(move |conn| list_history_conn(conn, &session_id))
            .await
    }

    /// List safe reference projections for a session (no encrypted material).
    /// This is the only shape suitable for export/diagnostics.
    pub async fn protected_redaction_history_refs(
        &self,
        session_id: &str,
    ) -> Result<Vec<ProtectedRedactionHistoryRef>> {
        let session_id = session_id.to_owned();
        self.read(move |conn| {
            let rows = list_history_conn(conn, &session_id)?;
            Ok(rows
                .iter()
                .map(ProtectedRedactionHistoryRef::from_row)
                .collect())
        })
        .await
    }

    /// List artifact references for one artifact (opaque IDs only).
    pub async fn protected_redaction_artifact_refs_for_artifact(
        &self,
        artifact_kind: ProtectedRedactionArtifactKind,
        artifact_id: &str,
    ) -> Result<Vec<ProtectedRedactionArtifactRef>> {
        let artifact_id = artifact_id.to_owned();
        self.read(move |conn| {
            list_artifact_refs_for_artifact_conn(conn, artifact_kind, &artifact_id)
        })
        .await
    }

    /// Retire history rows that have zero remaining artifact references for a
    /// session. Returns the number of rows retired. Must be called inside a
    /// transaction if combined with artifact deletion.
    pub async fn protected_redaction_history_retire_zero_ref(
        &self,
        session_id: &str,
    ) -> Result<i64> {
        let session_id = session_id.to_owned();
        self.write(move |conn| retire_zero_ref_conn(conn, &session_id))
            .await
    }
}

// ---- Connection-scoped writers (compose inside one transaction) ------------

/// Append a protected redaction-history row, deduplicating on
/// `(session_id, fingerprint)`. Connection-scoped so callers compose it
/// inside one [`Db::transaction`] alongside the artifact write and
/// [`attach_artifact_ref_conn`].
///
/// Returns the history ID (new or existing). Does NOT attach an artifact
/// reference — use [`attach_artifact_ref_conn`] for that.
pub fn append_history_conn(
    conn: &Connection,
    input: &ProtectedRedactionHistoryAppend,
) -> Result<AppendHistoryResult> {
    // Deduplicate: same session + fingerprint.
    if let Some(existing) =
        get_history_by_fingerprint_conn(conn, &input.session_id, &input.fingerprint)?
    {
        return Ok(AppendHistoryResult::Existing {
            history_id: existing.history_id,
        });
    }
    let history_id = Uuid::new_v4().to_string();
    let created_at_ms = now_ms();
    conn.execute(
        "INSERT INTO protected_redaction_history
            (history_id, session_id, sealed_record_id, sealed_version, source,
             fingerprint, ciphertext, nonce, key_version, ref_count,
             created_at_ms, retired_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, NULL)",
        params![
            history_id,
            input.session_id,
            input.sealed_record_id,
            input.sealed_version,
            input.source.as_str(),
            input.fingerprint,
            input.ciphertext,
            input.nonce,
            input.key_version,
            created_at_ms,
        ],
    )
    .context("inserting protected redaction history row")?;
    Ok(AppendHistoryResult::Created { history_id })
}

/// Attach an opaque artifact-to-history reference. Connection-scoped so
/// callers compose it inside one [`Db::transaction`] alongside the artifact
/// write and [`append_history_conn`]. Idempotent for the same triple.
///
/// Increments the history row's `ref_count`. A history row may only be
/// referenced if it is not retired.
pub fn attach_artifact_ref_conn(
    conn: &Connection,
    artifact_kind: ProtectedRedactionArtifactKind,
    artifact_id: &str,
    history_id: &str,
) -> Result<()> {
    // Verify the history row exists and is not retired.
    let row = get_history_conn(conn, history_id)?
        .with_context(|| format!("protected redaction history not found: {history_id}"))?;
    if row.retired_at_ms.is_some() {
        bail!("cannot attach to retired protected redaction history: {history_id}");
    }

    let created_at_ms = now_ms();
    // Idempotent insert.
    let n = conn
        .execute(
            "INSERT OR IGNORE INTO protected_redaction_artifact_refs
            (artifact_kind, artifact_id, history_id, created_at_ms)
         VALUES (?1, ?2, ?3, ?4)",
            params![
                artifact_kind.as_str(),
                artifact_id,
                history_id,
                created_at_ms
            ],
        )
        .context("inserting protected redaction artifact ref")?;

    if n > 0 {
        // New reference: increment ref_count.
        conn.execute(
            "UPDATE protected_redaction_history SET ref_count = ref_count + 1
             WHERE history_id = ?1",
            [history_id],
        )
        .context("incrementing protected redaction history ref_count")?;
    }
    Ok(())
}

/// Detach an opaque artifact-to-history reference. Connection-scoped so
/// callers compose it inside one [`Db::transaction`] alongside the artifact
/// deletion. Decrements the history row's `ref_count`.
pub fn detach_artifact_ref_conn(
    conn: &Connection,
    artifact_kind: ProtectedRedactionArtifactKind,
    artifact_id: &str,
    history_id: &str,
) -> Result<()> {
    let n = conn
        .execute(
            "DELETE FROM protected_redaction_artifact_refs
         WHERE artifact_kind = ?1 AND artifact_id = ?2 AND history_id = ?3",
            params![artifact_kind.as_str(), artifact_id, history_id],
        )
        .context("deleting protected redaction artifact ref")?;
    if n > 0 {
        conn.execute(
            "UPDATE protected_redaction_history
             SET ref_count = MAX(ref_count - 1, 0)
             WHERE history_id = ?1",
            [history_id],
        )
        .context("decrementing protected redaction history ref_count")?;
    }
    Ok(())
}

/// Retire a specific history row. Fails if artifact references remain.
pub fn retire_history_conn(conn: &Connection, history_id: &str) -> Result<()> {
    let refs = count_artifact_refs_conn(conn, history_id)?;
    if refs > 0 {
        bail!("cannot retire protected redaction history with {refs} live artifact references");
    }
    let now = now_ms();
    let n = conn
        .execute(
            "UPDATE protected_redaction_history SET retired_at_ms = ?1
         WHERE history_id = ?2 AND retired_at_ms IS NULL",
            params![now, history_id],
        )
        .context("retiring protected redaction history row")?;
    if n == 0 {
        // Already retired or not found — idempotent for already-retired.
        let row = get_history_conn(conn, history_id)?;
        match row {
            Some(r) if r.retired_at_ms.is_some() => Ok(()),
            None => bail!("protected redaction history not found: {history_id}"),
            _ => bail!("retire CAS failed for protected redaction history: {history_id}"),
        }
    } else {
        Ok(())
    }
}

/// Retire all zero-ref history rows for a session. Returns the count retired.
pub fn retire_zero_ref_conn(conn: &Connection, session_id: &str) -> Result<i64> {
    let now = now_ms();
    let n = conn
        .execute(
            "UPDATE protected_redaction_history SET retired_at_ms = ?1
         WHERE session_id = ?2 AND retired_at_ms IS NULL AND ref_count = 0",
            params![now, session_id],
        )
        .context("retiring zero-ref protected redaction history rows")?;
    Ok(n as i64)
}

// ---- Connection-scoped readers --------------------------------------------

/// Load one history row by ID (full row, including encrypted material).
/// Owner-sensitive read only.
pub fn get_history_conn(
    conn: &Connection,
    history_id: &str,
) -> Result<Option<ProtectedRedactionHistoryRow>> {
    conn.query_row(
        "SELECT history_id, session_id, sealed_record_id, sealed_version, source,
                fingerprint, ciphertext, nonce, key_version, ref_count,
                created_at_ms, retired_at_ms
         FROM protected_redaction_history WHERE history_id = ?1",
        [history_id],
        map_history_row,
    )
    .optional()
    .context("loading protected redaction history row")
}

/// Load one history row by `(session_id, fingerprint)` (deduplication lookup).
pub fn get_history_by_fingerprint_conn(
    conn: &Connection,
    session_id: &str,
    fingerprint: &str,
) -> Result<Option<ProtectedRedactionHistoryRow>> {
    conn.query_row(
        "SELECT history_id, session_id, sealed_record_id, sealed_version, source,
                fingerprint, ciphertext, nonce, key_version, ref_count,
                created_at_ms, retired_at_ms
         FROM protected_redaction_history
         WHERE session_id = ?1 AND fingerprint = ?2
         ORDER BY created_at_ms ASC LIMIT 1",
        params![session_id, fingerprint],
        map_history_row,
    )
    .optional()
    .context("loading protected redaction history by fingerprint")
}

/// List all history rows for a session (full rows, encrypted material).
/// Owner-sensitive read only.
pub fn list_history_conn(
    conn: &Connection,
    session_id: &str,
) -> Result<Vec<ProtectedRedactionHistoryRow>> {
    let mut stmt = conn.prepare(
        "SELECT history_id, session_id, sealed_record_id, sealed_version, source,
                fingerprint, ciphertext, nonce, key_version, ref_count,
                created_at_ms, retired_at_ms
         FROM protected_redaction_history
         WHERE session_id = ?1
         ORDER BY created_at_ms ASC, history_id ASC",
    )?;
    let rows = stmt.query_map([session_id], map_history_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing protected redaction history rows")
}

/// Count artifact references for a history row.
pub fn count_artifact_refs_conn(conn: &Connection, history_id: &str) -> Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM protected_redaction_artifact_refs WHERE history_id = ?1",
        [history_id],
        |row| row.get(0),
    )
    .context("counting protected redaction artifact refs")
}

/// List artifact references for one artifact (opaque IDs only).
pub fn list_artifact_refs_for_artifact_conn(
    conn: &Connection,
    artifact_kind: ProtectedRedactionArtifactKind,
    artifact_id: &str,
) -> Result<Vec<ProtectedRedactionArtifactRef>> {
    let mut stmt = conn.prepare(
        "SELECT artifact_kind, artifact_id, history_id, created_at_ms
         FROM protected_redaction_artifact_refs
         WHERE artifact_kind = ?1 AND artifact_id = ?2
         ORDER BY created_at_ms ASC, history_id ASC",
    )?;
    let rows = stmt.query_map(params![artifact_kind.as_str(), artifact_id], map_ref_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing protected redaction artifact refs")
}

/// List all artifact references for a session's history rows.
/// Used by export to build a stable graph snapshot.
pub fn list_artifact_refs_for_session_conn(
    conn: &Connection,
    session_id: &str,
) -> Result<Vec<ProtectedRedactionArtifactRef>> {
    let mut stmt = conn.prepare(
        "SELECT r.artifact_kind, r.artifact_id, r.history_id, r.created_at_ms
         FROM protected_redaction_artifact_refs r
         INNER JOIN protected_redaction_history h ON r.history_id = h.history_id
         WHERE h.session_id = ?1
         ORDER BY r.created_at_ms ASC, r.history_id ASC",
    )?;
    let rows = stmt.query_map([session_id], map_ref_row)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing protected redaction artifact refs for session")
}

/// List all history rows referenced by a given artifact (full rows).
/// Owner-sensitive read: used by the rehydration frame.
pub fn list_history_for_artifact_conn(
    conn: &Connection,
    artifact_kind: ProtectedRedactionArtifactKind,
    artifact_id: &str,
) -> Result<Vec<ProtectedRedactionHistoryRow>> {
    let mut stmt = conn.prepare(
        "SELECT h.history_id, h.session_id, h.sealed_record_id, h.sealed_version,
                h.source, h.fingerprint, h.ciphertext, h.nonce, h.key_version,
                h.ref_count, h.created_at_ms, h.retired_at_ms
         FROM protected_redaction_history h
         INNER JOIN protected_redaction_artifact_refs r
           ON r.history_id = h.history_id
         WHERE r.artifact_kind = ?1 AND r.artifact_id = ?2
         ORDER BY h.created_at_ms ASC, h.history_id ASC",
    )?;
    let rows = stmt.query_map(
        params![artifact_kind.as_str(), artifact_id],
        map_history_row,
    )?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("listing protected redaction history for artifact")
}

// ---- Row mappers -----------------------------------------------------------

fn map_history_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProtectedRedactionHistoryRow> {
    let source: String = row.get(4)?;
    Ok(ProtectedRedactionHistoryRow {
        history_id: row.get(0)?,
        session_id: row.get(1)?,
        sealed_record_id: row.get(2)?,
        sealed_version: row.get(3)?,
        source: ProtectedRedactionSource::parse(&source).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        fingerprint: row.get(5)?,
        ciphertext: row.get(6)?,
        nonce: row.get(7)?,
        key_version: row.get(8)?,
        ref_count: row.get(9)?,
        created_at_ms: row.get(10)?,
        retired_at_ms: row.get(11)?,
    })
}

fn map_ref_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProtectedRedactionArtifactRef> {
    let kind: String = row.get(0)?;
    Ok(ProtectedRedactionArtifactRef {
        artifact_kind: ProtectedRedactionArtifactKind::parse(&kind).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(e.to_string())),
            )
        })?,
        artifact_id: row.get(1)?,
        history_id: row.get(2)?,
        created_at_ms: row.get(3)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn append_dedup_and_attach() {
        let db = Db::open_in_memory().unwrap();
        let session_id = "11111111-1111-1111-1111-111111111111";
        // 64-char hex SHA-256-length fingerprint (schema enforces length 64).
        let fp = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let input = ProtectedRedactionHistoryAppend {
            session_id: session_id.to_owned(),
            sealed_record_id: None,
            sealed_version: None,
            source: ProtectedRedactionSource::Environment,
            fingerprint: fp.to_owned(),
            ciphertext: vec![0u8; 32],
            nonce: vec![0u8; 12],
            key_version: 1,
        };
        let id1 = db
            .write(move |conn| {
                let r = append_history_conn(conn, &input)?;
                let id = match r {
                    AppendHistoryResult::Created { history_id } => history_id,
                    AppendHistoryResult::Existing { history_id } => history_id,
                };
                Ok(id)
            })
            .await
            .unwrap();
        // Dedup: same fingerprint returns existing.
        let input2 = ProtectedRedactionHistoryAppend {
            session_id: session_id.to_owned(),
            sealed_record_id: None,
            sealed_version: None,
            source: ProtectedRedactionSource::Environment,
            fingerprint: fp.to_owned(),
            ciphertext: vec![0u8; 32],
            nonce: vec![0u8; 12],
            key_version: 1,
        };
        let id2 = db
            .write(move |conn| {
                let r = append_history_conn(conn, &input2)?;
                let id = match r {
                    AppendHistoryResult::Created { history_id } => history_id,
                    AppendHistoryResult::Existing { history_id } => history_id,
                };
                Ok(id)
            })
            .await
            .unwrap();
        assert_eq!(id1, id2);

        // Attach a reference.
        let id_attach = id1.clone();
        db.write(move |conn| {
            attach_artifact_ref_conn(
                conn,
                ProtectedRedactionArtifactKind::Request,
                "req-1",
                &id_attach,
            )
        })
        .await
        .unwrap();

        // ref_count is now 1.
        let id_read = id1.clone();
        let row = db
            .read(move |conn| get_history_conn(conn, &id_read))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.ref_count, 1);

        // Cannot retire with live references.
        let id_retire = id1.clone();
        let err = db
            .write(move |conn| retire_history_conn(conn, &id_retire))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("live artifact references"));

        // Detach, then retire succeeds.
        let id_detach = id1.clone();
        db.write(move |conn| {
            detach_artifact_ref_conn(
                conn,
                ProtectedRedactionArtifactKind::Request,
                "req-1",
                &id_detach,
            )
        })
        .await
        .unwrap();
        db.write(move |conn| retire_history_conn(conn, &id1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn safe_ref_excludes_encrypted_material() {
        let db = Db::open_in_memory().unwrap();
        let session_id = "22222222-2222-2222-1111-111111111111";
        let input = ProtectedRedactionHistoryAppend {
            session_id: session_id.to_owned(),
            sealed_record_id: None,
            sealed_version: None,
            source: ProtectedRedactionSource::Credential,
            fingerprint: "d1e2f3a4b5c6d1e2f3a4b5c6d1e2f3a4b5c6d1e2f3a4b5c6d1e2f3a4b5c6d1e2"
                .to_owned(),
            ciphertext: vec![1u8; 32],
            nonce: vec![2u8; 12],
            key_version: 1,
        };
        let id = db
            .write(move |conn| {
                let r = append_history_conn(conn, &input)?;
                Ok(match r {
                    AppendHistoryResult::Created { history_id } => history_id,
                    AppendHistoryResult::Existing { history_id } => history_id,
                })
            })
            .await
            .unwrap();

        let refs = db
            .protected_redaction_history_refs(session_id)
            .await
            .unwrap();
        assert_eq!(refs.len(), 1);
        let r = &refs[0];
        assert_eq!(r.history_id, id);
        assert_eq!(r.source, ProtectedRedactionSource::Credential);
        assert_eq!(
            r.fingerprint,
            "d1e2f3a4b5c6d1e2f3a4b5c6d1e2f3a4b5c6d1e2f3a4b5c6d1e2f3a4b5c6d1e2"
        );
        // The safe ref type has no ciphertext/nonce/key_version fields.
        // (Compile-time guarantee: ProtectedRedactionHistoryRef has no such fields.)
    }

    #[tokio::test]
    async fn cannot_attach_to_retired() {
        let db = Db::open_in_memory().unwrap();
        let session_id = "33333333-3333-3333-1111-111111111111";
        let input = ProtectedRedactionHistoryAppend {
            session_id: session_id.to_owned(),
            sealed_record_id: None,
            sealed_version: None,
            source: ProtectedRedactionSource::Sealed,
            fingerprint: "g1h2i3j4k5l6g1h2i3j4k5l6g1h2i3j4k5l6g1h2i3j4k5l6g1h2i3j4k5l6g1h2"
                .to_owned(),
            ciphertext: vec![3u8; 32],
            nonce: vec![4u8; 12],
            key_version: 1,
        };
        let id = db
            .write(move |conn| {
                let r = append_history_conn(conn, &input)?;
                Ok(match r {
                    AppendHistoryResult::Created { history_id } => history_id,
                    AppendHistoryResult::Existing { history_id } => history_id,
                })
            })
            .await
            .unwrap();
        // Retire (no refs).
        let id_retire = id.clone();
        db.write(move |conn| retire_history_conn(conn, &id_retire))
            .await
            .unwrap();
        // Attach fails.
        let err = db
            .write(move |conn| {
                attach_artifact_ref_conn(
                    conn,
                    ProtectedRedactionArtifactKind::Response,
                    "resp-1",
                    &id,
                )
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("retired"));
    }

    #[tokio::test]
    async fn atomic_attach_in_transaction() {
        let db = Db::open_in_memory().unwrap();
        let session_id = "44444444-4444-4444-1111-111111111111";
        let input = ProtectedRedactionHistoryAppend {
            session_id: session_id.to_owned(),
            sealed_record_id: Some("rec-1".to_owned()),
            sealed_version: Some(2),
            source: ProtectedRedactionSource::ContainedLeak,
            fingerprint: "j1k2l3m4n5o6j1k2l3m4n5o6j1k2l3m4n5o6j1k2l3m4n5o6j1k2l3m4n5o6j1k2"
                .to_owned(),
            ciphertext: vec![5u8; 32],
            nonce: vec![6u8; 12],
            key_version: 1,
        };
        // Simulate a crash between append and attach: the transaction fails
        // after append, so neither commits.
        let result: Result<()> = db
            .transaction(move |conn| {
                let _r = append_history_conn(conn, &input)?;
                // Simulate crash: bail before attach.
                bail!("simulated crash before attach");
            })
            .await;
        assert!(result.is_err());
        // History row should NOT exist (transaction rolled back).
        let rows = db
            .protected_redaction_history_list(session_id)
            .await
            .unwrap();
        assert!(
            rows.is_empty(),
            "history row should not persist after crash"
        );
    }
}
