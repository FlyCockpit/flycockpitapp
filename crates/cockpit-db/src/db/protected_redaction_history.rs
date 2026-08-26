//! Durable protected redaction-history store: SQLite coordination only.
//!
//! This module owns the durable half of protected redaction history. It stores
//! **AEAD ciphertext + nonce** (ChaCha20-Poly1305; crypto lives in
//! `cockpit-core`) keyed by an opaque history ID and the local key-store key
//! version. The ciphertext length is bucket-padded, so it reveals only a coarse
//! bucket, never the literal length. No plaintext, prefix, exact length,
//! ciphertext, nonce, key version, or fingerprint ever appears in the
//! export/diagnostics projection ([`ProtectedRedactionHistoryRef`]) — the
//! encrypted columns are consumed solely by the local Owner-sensitive
//! rehydration frame in `cockpit-core`.
//!
//! Two properties are load-bearing and enforced here rather than left to
//! callers:
//!
//! * **No literal leakage.** The export projection
//!   ([`ProtectedRedactionHistoryRef`]) carries only opaque IDs, source,
//!   ref-count, and timestamps — no fingerprint, ciphertext, nonce, or key
//!   version. The full row ([`ProtectedRedactionHistoryRow`]) and
//!   ([`ProtectedRedactionArtifactRef`]) never carry a plaintext field, prefix,
//!   exact length, or unencrypted literal.
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
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedRedactionHistoryRow {
    pub history_id: String,
    pub session_id: String,
    pub sealed_record_id: Option<String>,
    pub sealed_version: Option<i64>,
    pub source: ProtectedRedactionSource,
    /// Keyed-MAC fingerprint of the literal (`HMAC-SHA-256` under a store-derived
    /// subkey). Safe same-session deduplication key; not an offline guessing
    /// oracle and never exported. Zeroed to 64 `'0'` chars on retirement.
    pub fingerprint: String,
    /// AEAD ciphertext (ChaCha20-Poly1305 over the bucket-padded frame, with the
    /// 16-byte tag appended). Length reveals only a coarse bucket, never the
    /// literal length. Local rehydration frame only; zeroed on retirement.
    pub ciphertext: Vec<u8>,
    /// AEAD nonce (local rehydration frame only; zeroed on retirement).
    pub nonce: Vec<u8>,
    /// Local key-store key version that encrypted this row.
    pub key_version: i64,
    pub ref_count: i64,
    pub created_at_ms: i64,
    pub retired_at_ms: Option<i64>,
}

impl std::fmt::Debug for ProtectedRedactionHistoryRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose the keyed-MAC fingerprint or encrypted material in a
        // diagnostics projection (decision 6/14): redact the fingerprint and
        // reduce ciphertext/nonce to lengths.
        f.debug_struct("ProtectedRedactionHistoryRow")
            .field("history_id", &self.history_id)
            .field("session_id", &self.session_id)
            .field("sealed_record_id", &self.sealed_record_id)
            .field("sealed_version", &self.sealed_version)
            .field("source", &self.source)
            .field(
                "fingerprint",
                &format_args!("[REDACTED MAC; len {}]", self.fingerprint.len()),
            )
            .field(
                "ciphertext",
                &format_args!("[{} bytes]", self.ciphertext.len()),
            )
            .field("nonce", &format_args!("[{} bytes]", self.nonce.len()))
            .field("key_version", &self.key_version)
            .field("ref_count", &self.ref_count)
            .field("created_at_ms", &self.created_at_ms)
            .field("retired_at_ms", &self.retired_at_ms)
            .finish()
    }
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
/// length, ciphertext, nonce, key version, or fingerprint. Only opaque IDs and
/// safe source/ref-count/timestamp metadata. The keyed-MAC fingerprint is
/// deliberately **not** exported — even a keyed MAC does not belong in
/// export/diagnostics; `history_id` is the correlation key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedRedactionHistoryRef {
    pub history_id: String,
    pub session_id: String,
    pub source: ProtectedRedactionSource,
    pub ref_count: i64,
    pub created_at_ms: i64,
    pub retired_at_ms: Option<i64>,
}

impl ProtectedRedactionHistoryRef {
    /// Project a full row into the safe export/diagnostics reference.
    /// This strips ciphertext, nonce, key version, sealed record/version, and
    /// the keyed-MAC fingerprint.
    pub fn from_row(row: &ProtectedRedactionHistoryRow) -> Self {
        Self {
            history_id: row.history_id.clone(),
            session_id: row.session_id.clone(),
            source: row.source,
            ref_count: row.ref_count,
            created_at_ms: row.created_at_ms,
            retired_at_ms: row.retired_at_ms,
        }
    }
}

/// Append-input: the encrypted literal material and safe metadata for one
/// history row. Built by `cockpit-core` from the closed-writer classification;
/// no plaintext enters this struct.
#[derive(Clone)]
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

impl std::fmt::Debug for ProtectedRedactionHistoryAppend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The keyed MAC (`fingerprint`) is session-scoped sensitive metadata that
        // is never surfaced in any diagnostics projection; the derived Debug
        // emitted it verbatim, so redact it (and reduce ciphertext/nonce to
        // lengths) here — the DB-layer twin of `PreparedProtectedAppend` (G4d).
        f.debug_struct("ProtectedRedactionHistoryAppend")
            .field("session_id", &self.session_id)
            .field("sealed_record_id", &self.sealed_record_id)
            .field("sealed_version", &self.sealed_version)
            .field("source", &self.source)
            .field(
                "fingerprint",
                &format_args!("[REDACTED; {}]", self.fingerprint.len()),
            )
            .field(
                "ciphertext",
                &format_args!("[{} bytes]", self.ciphertext.len()),
            )
            .field("nonce", &format_args!("[{} bytes]", self.nonce.len()))
            .field("key_version", &self.key_version)
            .finish()
    }
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

    /// Load one protected redaction-history row by id (full row, including
    /// encrypted material). Owner-sensitive read only; used by the leaks-page
    /// reveal path to rehydrate the literal on the protected local channel.
    pub async fn protected_redaction_history_get(
        &self,
        history_id: &str,
    ) -> Result<Option<ProtectedRedactionHistoryRow>> {
        let history_id = history_id.to_owned();
        self.read(move |conn| get_history_conn(conn, &history_id))
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
        // Sealed rotation-to-same-literal advance (r9-6). A sealed record rotated
        // to a NEW version but the SAME literal MACs to the SAME fingerprint under
        // the same key version, so dedup returns this existing live row. Without
        // this, the journal row would keep its OLD `sealed_version` while the
        // sealed record has advanced — a stale version tag on an otherwise-correct,
        // still-protected row. When the incoming append carries a strictly-newer
        // sealed version, advance the row's sealed identity to the current
        // adoption. Guarded and monotonic, so dedup semantics for every caller are
        // preserved:
        //   - non-sealed sources (Environment/Credential/ContainedLeak) pass
        //     `sealed_version = None`, so this never fires — their dedup is
        //     unchanged;
        //   - a Sealed literal later matched under a non-sealed source never
        //     downgrades the row's sealed identity (None fails the guard);
        //   - an out-of-order OLDER sealed version never overwrites a newer one;
        //   - `sealed_record_id` advances only when the incoming value is present
        //     (COALESCE keeps the stored id otherwise — a rotation keeps the same
        //     record id, so this is normally a no-op).
        // The dedup key `(session_id, fingerprint)`, the `Existing` return
        // contract, and `ref_count` are all untouched — only the sealed-version /
        // record-id metadata advances.
        if let Some(new_version) = input.sealed_version
            && existing.sealed_version.is_none_or(|cur| new_version > cur)
        {
            conn.execute(
                "UPDATE protected_redaction_history
                    SET sealed_version = ?1,
                        sealed_record_id = COALESCE(?2, sealed_record_id)
                  WHERE history_id = ?3",
                params![new_version, input.sealed_record_id, existing.history_id],
            )
            .context("advancing sealed_version on deduplicated protected redaction history row")?;
        }
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
///
/// Retirement is **forget**: the same UPDATE that stamps `retired_at_ms`
/// overwrites `ciphertext` with `zeroblob(length(ciphertext))` (length
/// preserved so the bucket CHECK holds; lengths are bucketed so nothing new
/// leaks), `nonce` with 12 zero bytes, and `fingerprint` with 64 `'0'` chars.
/// A retired row can no longer be decrypted, and its zeroed fingerprint sits
/// outside the partial unique index so the same literal can be re-journaled.
pub fn retire_history_conn(conn: &Connection, history_id: &str) -> Result<()> {
    let refs = count_artifact_refs_conn(conn, history_id)?;
    if refs > 0 {
        bail!("cannot retire protected redaction history with {refs} live artifact references");
    }
    let now = now_ms();
    let n = conn
        .execute(
            "UPDATE protected_redaction_history
         SET retired_at_ms = ?1,
             ciphertext = zeroblob(length(ciphertext)),
             nonce = zeroblob(12),
             fingerprint = ?3
         WHERE history_id = ?2 AND retired_at_ms IS NULL",
            params![now, history_id, ZEROED_FINGERPRINT],
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

/// Force-retire a specific history row **regardless of live artifact
/// references** — the destructive delete primitive for leak-report protected
/// value deletion. Like [`retire_history_conn`] this is **forget**: the same
/// UPDATE that stamps `retired_at_ms` overwrites `ciphertext` with
/// `zeroblob(length(ciphertext))` (length preserved so the bucket CHECK holds;
/// the appended 16-byte AEAD tag lives inside `ciphertext`, so zeroing the
/// blob zeroes the tag too), `nonce` with 12 zero bytes, and `fingerprint`
/// with 64 `'0'` chars.
///
/// Unlike [`retire_history_conn`], it does **not** count or reject on
/// `ref_count`: artifact references may keep pointing at the now-zeroed row and
/// every artifact-side rehydrate fails closed (a retired row can no longer be
/// decrypted). Idempotent for an already-retired row. No error path references
/// `ref_count` — deletion never surfaces a reference count.
pub fn force_retire_history_conn(conn: &Connection, history_id: &str) -> Result<()> {
    let now = now_ms();
    // `ref_count` is reset to 0 in the SAME update: the schema invariant
    // `CHECK ((retired_at_ms IS NULL) OR (ref_count = 0))` requires a retired
    // row to carry no live-ref count. Any `protected_redaction_artifact_refs`
    // rows survive (now orphaned, pointing at a zeroed/retired row that
    // rehydrates fail-closed); a later `detach_artifact_ref_conn` clamps at
    // `MAX(ref_count - 1, 0)`, so the counter never underflows.
    let n = conn
        .execute(
            "UPDATE protected_redaction_history
         SET retired_at_ms = ?1,
             ciphertext = zeroblob(length(ciphertext)),
             nonce = zeroblob(12),
             fingerprint = ?3,
             ref_count = 0
         WHERE history_id = ?2 AND retired_at_ms IS NULL",
            params![now, history_id, ZEROED_FINGERPRINT],
        )
        .context("force-retiring protected redaction history row")?;
    if n == 0 {
        // Already retired or not found — idempotent for already-retired.
        let row = get_history_conn(conn, history_id)?;
        match row {
            Some(r) if r.retired_at_ms.is_some() => Ok(()),
            None => bail!("protected redaction history not found: {history_id}"),
            _ => bail!("force-retire CAS failed for protected redaction history: {history_id}"),
        }
    } else {
        Ok(())
    }
}

/// Retire all zero-ref history rows for a session. Returns the count retired.
/// Zeroizes ciphertext, nonce, and fingerprint in the same UPDATE (see
/// [`retire_history_conn`]).
pub fn retire_zero_ref_conn(conn: &Connection, session_id: &str) -> Result<i64> {
    let now = now_ms();
    let n = conn
        .execute(
            "UPDATE protected_redaction_history
         SET retired_at_ms = ?1,
             ciphertext = zeroblob(length(ciphertext)),
             nonce = zeroblob(12),
             fingerprint = ?3
         WHERE session_id = ?2 AND retired_at_ms IS NULL AND ref_count = 0",
            params![now, session_id, ZEROED_FINGERPRINT],
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

/// Load one live (non-retired) history row by `(session_id, fingerprint)`
/// (deduplication lookup). Retired rows are excluded so a retired row never
/// blocks or aliases a fresh append of the same literal — its fingerprint slot
/// was zeroed on retirement and it sits outside the partial unique index.
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
         WHERE session_id = ?1 AND fingerprint = ?2 AND retired_at_ms IS NULL
         ORDER BY created_at_ms ASC LIMIT 1",
        params![session_id, fingerprint],
        map_history_row,
    )
    .optional()
    .context("loading protected redaction history by fingerprint")
}

/// The zeroed-fingerprint sentinel written on retirement: 64 `'0'` characters,
/// length-preserving so the schema `CHECK (length(fingerprint) = 64)` holds.
const ZEROED_FINGERPRINT: &str = "0000000000000000000000000000000000000000000000000000000000000000";

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

    // protected_redaction_history.session_id carries a cascading FK to
    // sessions(session_id), so the referenced session row must exist before
    // any history row is appended.
    async fn seed_session(db: &Db, session_id: &str) {
        let session_id = session_id.to_owned();
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO sessions(session_id,project_id,project_root,started_at_unix_ms,last_active_at_unix_ms) \
                 VALUES(?1,'p','/redacted',1,1)",
                [session_id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn append_dedup_and_attach() {
        let db = Db::open_in_memory().unwrap();
        let session_id = "11111111-1111-1111-1111-111111111111";
        seed_session(&db, session_id).await;
        // 64-char hex SHA-256-length fingerprint (schema enforces length 64).
        let fp = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let input = ProtectedRedactionHistoryAppend {
            session_id: session_id.to_owned(),
            sealed_record_id: None,
            sealed_version: None,
            source: ProtectedRedactionSource::Environment,
            fingerprint: fp.to_owned(),
            ciphertext: vec![0u8; 272],
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
            ciphertext: vec![0u8; 272],
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
        seed_session(&db, session_id).await;
        let input = ProtectedRedactionHistoryAppend {
            session_id: session_id.to_owned(),
            sealed_record_id: None,
            sealed_version: None,
            source: ProtectedRedactionSource::Credential,
            fingerprint: "d1e2f3a4b5c6d1e2f3a4b5c6d1e2f3a4b5c6d1e2f3a4b5c6d1e2f3a4b5c6d1e2"
                .to_owned(),
            ciphertext: vec![1u8; 272],
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
        // The safe ref type has no ciphertext/nonce/key_version/fingerprint
        // fields. This is a compile-time guarantee: ProtectedRedactionHistoryRef
        // no longer carries the keyed-MAC fingerprint (or any encrypted
        // material), so even a keyed MAC never reaches export/diagnostics. The
        // struct-literal below would fail to compile if a `fingerprint` field
        // were ever re-added to the export projection.
        let _shape = ProtectedRedactionHistoryRef {
            history_id: r.history_id.clone(),
            session_id: r.session_id.clone(),
            source: r.source,
            ref_count: r.ref_count,
            created_at_ms: r.created_at_ms,
            retired_at_ms: r.retired_at_ms,
        };
    }

    #[tokio::test]
    async fn cannot_attach_to_retired() {
        let db = Db::open_in_memory().unwrap();
        let session_id = "33333333-3333-3333-1111-111111111111";
        seed_session(&db, session_id).await;
        let input = ProtectedRedactionHistoryAppend {
            session_id: session_id.to_owned(),
            sealed_record_id: None,
            sealed_version: None,
            source: ProtectedRedactionSource::Sealed,
            fingerprint: "g1h2i3j4k5l6g1h2i3j4k5l6g1h2i3j4k5l6g1h2i3j4k5l6g1h2i3j4k5l6g1h2"
                .to_owned(),
            ciphertext: vec![3u8; 272],
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
        seed_session(&db, session_id).await;
        let input = ProtectedRedactionHistoryAppend {
            session_id: session_id.to_owned(),
            sealed_record_id: Some("rec-1".to_owned()),
            sealed_version: Some(2),
            source: ProtectedRedactionSource::ContainedLeak,
            fingerprint: "j1k2l3m4n5o6j1k2l3m4n5o6j1k2l3m4n5o6j1k2l3m4n5o6j1k2l3m4n5o6j1k2"
                .to_owned(),
            ciphertext: vec![5u8; 272],
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

    // 64-char valid hex fingerprint fixture.
    fn fp(seed: char) -> String {
        std::iter::repeat_n(seed, 64).collect()
    }

    fn bucketed_append(session_id: &str, fingerprint: &str) -> ProtectedRedactionHistoryAppend {
        ProtectedRedactionHistoryAppend {
            session_id: session_id.to_owned(),
            sealed_record_id: None,
            sealed_version: None,
            source: ProtectedRedactionSource::Environment,
            fingerprint: fingerprint.to_owned(),
            // 272 = smallest bucket (256) + 16-byte tag.
            ciphertext: vec![7u8; 272],
            nonce: vec![9u8; 12],
            key_version: 1,
        }
    }

    /// AC3 (db half): the schema CHECK rejects an off-bucket ciphertext length.
    #[tokio::test]
    async fn ciphertext_length_is_bucketed_by_schema_check() {
        let db = Db::open_in_memory().unwrap();
        let session_id = "55555555-5555-5555-1111-111111111111";
        seed_session(&db, session_id).await;

        // Every valid bucket length inserts.
        for (i, &len) in [272usize, 1040, 4112, 16404].iter().enumerate() {
            let mut input = bucketed_append(session_id, &fp(char::from(b'a' + i as u8)));
            input.ciphertext = vec![1u8; len];
            let r = db
                .write(move |conn| append_history_conn(conn, &input))
                .await;
            assert!(r.is_ok(), "bucket length {len} should insert: {r:?}");
        }

        // An off-bucket length (256, i.e. no tag / not a bucket) is rejected.
        for &bad in &[256usize, 271, 273, 1024, 16388] {
            let mut input = bucketed_append(session_id, &fp('z'));
            input.ciphertext = vec![1u8; bad];
            let err = db
                .write(move |conn| append_history_conn(conn, &input))
                .await
                .unwrap_err();
            // The rejection is the SQLite CHECK (append_history_conn does no
            // Rust-side length check); the CHECK message lives in the error
            // source chain, so inspect the Debug chain, not just the top context.
            let msg = format!("{err:?}").to_lowercase();
            assert!(
                msg.contains("constraint") || msg.contains("check"),
                "off-bucket length {bad} must be rejected by the schema CHECK, got: {err:?}"
            );
        }
    }

    /// AC6: retirement zeroizes ciphertext, nonce, and fingerprint in the same
    /// transaction that stamps retired_at_ms, and a failure after the retire
    /// UPDATE rolls back both the stamp and the zeroing.
    #[tokio::test]
    async fn retire_zeroizes_ciphertext_nonce_and_fingerprint_in_same_transaction() {
        let db = Db::open_in_memory().unwrap();
        let session_id = "66666666-6666-6666-1111-111111111111";
        seed_session(&db, session_id).await;
        let input = bucketed_append(session_id, &fp('c'));
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

        // A transaction that retires then fails must roll BOTH the stamp and the
        // zeroing back: the row keeps its original ciphertext/nonce/fingerprint.
        let id_rb = id.clone();
        let rolled: Result<()> = db
            .transaction(move |conn| {
                retire_history_conn(conn, &id_rb)?;
                bail!("simulated failure after retire UPDATE");
            })
            .await;
        assert!(rolled.is_err());
        let id_read = id.clone();
        let row = db
            .read(move |conn| get_history_conn(conn, &id_read))
            .await
            .unwrap()
            .unwrap();
        assert!(row.retired_at_ms.is_none(), "retire must have rolled back");
        assert_eq!(row.ciphertext, vec![7u8; 272], "ciphertext must be intact");
        assert_eq!(row.fingerprint, fp('c'), "fingerprint must be intact");

        // Now retire for real and read raw columns on the same connection.
        let id_retire = id.clone();
        db.write(move |conn| retire_history_conn(conn, &id_retire))
            .await
            .unwrap();
        let id_read2 = id.clone();
        let row = db
            .read(move |conn| get_history_conn(conn, &id_read2))
            .await
            .unwrap()
            .unwrap();
        assert!(row.retired_at_ms.is_some(), "retired_at_ms must be set");
        assert_eq!(row.ciphertext.len(), 272, "ciphertext length preserved");
        assert!(
            row.ciphertext.iter().all(|&b| b == 0),
            "ciphertext bytes must be all zero after retire"
        );
        assert_eq!(row.nonce, vec![0u8; 12], "nonce must be 12 zero bytes");
        assert_eq!(
            row.fingerprint,
            "0".repeat(64),
            "fingerprint must be 64 '0' chars"
        );
    }

    /// AC6: after retirement, appending the same literal (same session +
    /// fingerprint) creates a fresh non-retired row via the partial unique
    /// index, and the dedup lookup never returns retired rows.
    #[tokio::test]
    async fn retired_fingerprint_slot_allows_new_append() {
        let db = Db::open_in_memory().unwrap();
        let session_id = "77777777-7777-7777-1111-111111111111";
        seed_session(&db, session_id).await;
        let fingerprint = fp('d');

        let input = bucketed_append(session_id, &fingerprint);
        let id1 = db
            .write(move |conn| {
                let r = append_history_conn(conn, &input)?;
                Ok(match r {
                    AppendHistoryResult::Created { history_id } => history_id,
                    AppendHistoryResult::Existing { history_id } => history_id,
                })
            })
            .await
            .unwrap();

        // Retire it (zeroing the fingerprint slot).
        let id_retire = id1.clone();
        db.write(move |conn| retire_history_conn(conn, &id_retire))
            .await
            .unwrap();

        // The dedup lookup must not return the retired row.
        let sess = session_id.to_owned();
        let fp_lookup = fingerprint.clone();
        let found = db
            .read(move |conn| get_history_by_fingerprint_conn(conn, &sess, &fp_lookup))
            .await
            .unwrap();
        assert!(found.is_none(), "dedup lookup must skip retired rows");

        // Appending the same literal creates a fresh, distinct, non-retired row.
        let input2 = bucketed_append(session_id, &fingerprint);
        let result2 = db
            .write(move |conn| append_history_conn(conn, &input2))
            .await
            .unwrap();
        let id2 = match result2 {
            AppendHistoryResult::Created { history_id } => history_id,
            AppendHistoryResult::Existing { history_id } => {
                panic!("expected a fresh Created row, got Existing {history_id}")
            }
        };
        assert_ne!(id1, id2, "fresh append must be a new row");
        let id_read = id2.clone();
        let row = db
            .read(move |conn| get_history_conn(conn, &id_read))
            .await
            .unwrap()
            .unwrap();
        assert!(row.retired_at_ms.is_none());
        assert_eq!(row.fingerprint, fingerprint);
    }

    /// r9-6: a sealed record rotated to a NEW version but the SAME literal MACs
    /// to the same fingerprint, so dedup returns the existing live row. The
    /// append must ADVANCE that row's `sealed_version`/`sealed_record_id` to the
    /// current rotation so the journal reflects the current adoption — while
    /// preserving dedup semantics for every other caller (no downgrade on a
    /// non-sealed or older-version re-append).
    #[tokio::test]
    async fn sealed_rotation_to_same_literal_advances_sealed_version_on_dedup() {
        let db = Db::open_in_memory().unwrap();
        let session_id = "88888888-8888-8888-1111-111111111111";
        seed_session(&db, session_id).await;
        let fingerprint = fp('e');

        // Initial sealed adoption at version 1.
        let mut v1 = bucketed_append(session_id, &fingerprint);
        v1.source = ProtectedRedactionSource::Sealed;
        v1.sealed_record_id = Some("rec-1".to_owned());
        v1.sealed_version = Some(1);
        let id = db
            .write(move |conn| {
                let r = append_history_conn(conn, &v1)?;
                Ok(match r {
                    AppendHistoryResult::Created { history_id } => history_id,
                    AppendHistoryResult::Existing { history_id } => history_id,
                })
            })
            .await
            .unwrap();

        // Rotation to the SAME literal at version 2 dedups to the existing row
        // and advances its sealed identity.
        let mut v2 = bucketed_append(session_id, &fingerprint);
        v2.source = ProtectedRedactionSource::Sealed;
        v2.sealed_record_id = Some("rec-1".to_owned());
        v2.sealed_version = Some(2);
        let r2 = db
            .write(move |conn| append_history_conn(conn, &v2))
            .await
            .unwrap();
        assert!(
            matches!(r2, AppendHistoryResult::Existing { .. }),
            "rotation to the same literal must dedup, not create a new row"
        );
        let id_read = id.clone();
        let row = db
            .read(move |conn| get_history_conn(conn, &id_read))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.sealed_version,
            Some(2),
            "the journal row's sealed_version must advance to the current rotation"
        );
        assert_eq!(row.sealed_record_id.as_deref(), Some("rec-1"));

        // A later NON-sealed match of the same literal (sealed_version None) must
        // NOT downgrade the row's sealed identity.
        let mut env_hit = bucketed_append(session_id, &fingerprint);
        env_hit.source = ProtectedRedactionSource::Environment;
        let r3 = db
            .write(move |conn| append_history_conn(conn, &env_hit))
            .await
            .unwrap();
        assert!(matches!(r3, AppendHistoryResult::Existing { .. }));
        let id_read = id.clone();
        let row = db
            .read(move |conn| get_history_conn(conn, &id_read))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.sealed_version,
            Some(2),
            "a non-sealed re-append must not clear the sealed version"
        );
        assert_eq!(row.sealed_record_id.as_deref(), Some("rec-1"));

        // An OLDER sealed version arriving out of order must not overwrite the
        // newer one (monotonic advance only).
        let mut stale = bucketed_append(session_id, &fingerprint);
        stale.source = ProtectedRedactionSource::Sealed;
        stale.sealed_record_id = Some("rec-1".to_owned());
        stale.sealed_version = Some(1);
        db.write(move |conn| append_history_conn(conn, &stale))
            .await
            .unwrap();
        let id_read = id.clone();
        let row = db
            .read(move |conn| get_history_conn(conn, &id_read))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.sealed_version,
            Some(2),
            "an out-of-order older sealed version must not overwrite the newer one"
        );
    }
}
