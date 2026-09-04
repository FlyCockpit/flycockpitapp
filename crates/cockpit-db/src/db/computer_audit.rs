//! Append-only computer-use audit-chain bodies (issue #271).
//!
//! The HMAC signing key and sealed chain head live in the machine-local
//! protected secret store. This module stores the ordered 424-byte entries
//! and their MACs so verification can detect SQLite mutation, reorder,
//! insertion, tail deletion, and index-column relabeling. Typed rule values,
//! rationale, pixels, OCR, and raw target text never enter this table.

use anyhow::{Context, Result, anyhow};
use rusqlite::{ErrorCode, OptionalExtension, params};

use crate::db::Db;

/// Canonical ComputerAuditEntryV1 encoding length.
pub const COMPUTER_AUDIT_ENTRY_LEN: usize = 424;
/// HMAC-SHA-256 tag length.
pub const COMPUTER_AUDIT_MAC_LEN: usize = 32;
/// RFC 4122 / proposal-id slot length.
pub const COMPUTER_AUDIT_ID_LEN: usize = 16;

/// 0-indexed ComputerAuditEntryV1 offsets inside the 424-byte body.
/// Must stay aligned with `ComputerAuditEntryV1::encode`.
pub const COMPUTER_AUDIT_EVENT_KIND_OFFSET: usize = 5;
pub const COMPUTER_AUDIT_SEQUENCE_OFFSET: usize = 10;
pub const COMPUTER_AUDIT_SEQUENCE_LEN: usize = 8;
pub const COMPUTER_AUDIT_PROPOSAL_ID_OFFSET: usize = 114;
pub const COMPUTER_AUDIT_KEY_VERSION_OFFSET: usize = 420;
pub const COMPUTER_AUDIT_KEY_VERSION_LEN: usize = 4;
pub const COMPUTER_AUDIT_WALL_UNIX_MS_OFFSET: usize = 408;
pub const COMPUTER_AUDIT_WALL_UNIX_MS_LEN: usize = 8;
pub const COMPUTER_AUDIT_JOURNAL_VERSION_OFFSET: usize = 392;
pub const COMPUTER_AUDIT_JOURNAL_VERSION_LEN: usize = 8;
pub const COMPUTER_AUDIT_MONOTONIC_NANOS_OFFSET: usize = 400;
pub const COMPUTER_AUDIT_MONOTONIC_NANOS_LEN: usize = 8;

/// Prune-checkpoint event kind (`AuditEventKind::PruneCheckpoint`).
pub const PRUNE_CHECKPOINT: u8 = 27;

const _: () = {
    assert!(COMPUTER_AUDIT_EVENT_KIND_OFFSET + 1 == 6);
    assert!(COMPUTER_AUDIT_SEQUENCE_OFFSET + 1 == 11);
    assert!(COMPUTER_AUDIT_PROPOSAL_ID_OFFSET + 1 == 115);
    assert!(COMPUTER_AUDIT_KEY_VERSION_OFFSET + 1 == 421);
    assert!(COMPUTER_AUDIT_SEQUENCE_OFFSET + COMPUTER_AUDIT_SEQUENCE_LEN == 18);
    assert!(COMPUTER_AUDIT_PROPOSAL_ID_OFFSET + COMPUTER_AUDIT_ID_LEN == 130);
    assert!(COMPUTER_AUDIT_KEY_VERSION_OFFSET + COMPUTER_AUDIT_KEY_VERSION_LEN == 424);
    assert!(COMPUTER_AUDIT_WALL_UNIX_MS_OFFSET + COMPUTER_AUDIT_WALL_UNIX_MS_LEN == 416);
    assert!(COMPUTER_AUDIT_JOURNAL_VERSION_OFFSET + COMPUTER_AUDIT_JOURNAL_VERSION_LEN == 400);
    assert!(COMPUTER_AUDIT_MONOTONIC_NANOS_OFFSET + COMPUTER_AUDIT_MONOTONIC_NANOS_LEN == 408);
};

/// Guidance-proposal audit kinds (must stay aligned with
/// `AuditEventKind::{GuidanceProposalCreated, Accepted, Rejected, Expired}`).
pub const GUIDANCE_PROPOSAL_CREATED: u8 = 20;
pub const GUIDANCE_PROPOSAL_ACCEPTED: u8 = 21;
pub const GUIDANCE_PROPOSAL_REJECTED: u8 = 22;
pub const GUIDANCE_PROPOSAL_EXPIRED: u8 = 23;

/// Lookup by the authenticated `(kind, proposal_id)` projection of `entry_bytes`.
const GUIDANCE_BODY_LOOKUP_SQL: &str = concat!(
    "SELECT sequence, entry_bytes, mac, event_kind, proposal_id, key_version ",
    "FROM computer_audit_entries WHERE ",
    "substr(entry_bytes, 6, 1) = ?1 AND substr(entry_bytes, 115, 16) = ?2"
);

const COMPUTER_AUDIT_DELETE_TRIGGER_SQL: &str = "
CREATE TRIGGER computer_audit_entries_immutable_delete
BEFORE DELETE ON computer_audit_entries
BEGIN
    SELECT RAISE(ABORT, 'computer_audit_entries is append-only');
END;
";

/// Authorization to delete a bounded audit prefix. Only constructible after
/// verifying a matching signed `PruneCheckpoint` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputerAuditPruneAuthorization {
    pub prefix_end_inclusive: u64,
}

/// Project `journal_version` / `monotonic_nanos` from a prune-checkpoint body.
pub fn projected_prune_checkpoint_bounds(
    entry_bytes: &[u8; COMPUTER_AUDIT_ENTRY_LEN],
) -> Option<(u64, u64)> {
    if entry_bytes[COMPUTER_AUDIT_EVENT_KIND_OFFSET] != PRUNE_CHECKPOINT {
        return None;
    }
    let mut prefix_start_bytes = [0u8; COMPUTER_AUDIT_JOURNAL_VERSION_LEN];
    prefix_start_bytes.copy_from_slice(
        &entry_bytes[COMPUTER_AUDIT_JOURNAL_VERSION_OFFSET
            ..COMPUTER_AUDIT_JOURNAL_VERSION_OFFSET + COMPUTER_AUDIT_JOURNAL_VERSION_LEN],
    );
    let mut prefix_end_bytes = [0u8; COMPUTER_AUDIT_MONOTONIC_NANOS_LEN];
    prefix_end_bytes.copy_from_slice(
        &entry_bytes[COMPUTER_AUDIT_MONOTONIC_NANOS_OFFSET
            ..COMPUTER_AUDIT_MONOTONIC_NANOS_OFFSET + COMPUTER_AUDIT_MONOTONIC_NANOS_LEN],
    );
    Some((
        u64::from_be_bytes(prefix_start_bytes),
        u64::from_be_bytes(prefix_end_bytes),
    ))
}

struct ImmutableDeleteTriggerGuard<'a> {
    conn: &'a rusqlite::Connection,
    active: bool,
}

impl Drop for ImmutableDeleteTriggerGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.conn.execute_batch(COMPUTER_AUDIT_DELETE_TRIGGER_SQL);
        }
    }
}

fn drop_immutable_delete_trigger(
    conn: &rusqlite::Connection,
) -> Result<ImmutableDeleteTriggerGuard<'_>> {
    conn.execute(
        "DROP TRIGGER IF EXISTS computer_audit_entries_immutable_delete",
        [],
    )
    .context("dropping computer audit delete trigger")?;
    Ok(ImmutableDeleteTriggerGuard { conn, active: true })
}

fn verify_prune_checkpoint_authorizes_conn(
    conn: &rusqlite::Connection,
    prefix_end_inclusive: u64,
) -> Result<()> {
    if prefix_end_inclusive == 0 {
        bail!("computer audit truncate requires a non-zero prefix end");
    }
    let mut stmt = conn.prepare(
        "SELECT entry_bytes
           FROM computer_audit_entries
          WHERE event_kind = ?1
          ORDER BY sequence DESC",
    )?;
    let rows = stmt
        .query_map(params![i64::from(PRUNE_CHECKPOINT)], |row| {
            row.get::<_, Vec<u8>>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let authorized = rows.into_iter().any(|bytes| {
        bytes
            .try_into()
            .ok()
            .and_then(|entry_bytes: [u8; COMPUTER_AUDIT_ENTRY_LEN]| {
                projected_prune_checkpoint_bounds(&entry_bytes)
            })
            .is_some_and(|(_, prefix_end)| prefix_end == prefix_end_inclusive)
    });
    anyhow::ensure!(
        authorized,
        "computer audit truncate requires a matching prune checkpoint for prefix_end {prefix_end_inclusive}"
    );
    Ok(())
}

/// One stored chain entry. `entry_bytes` is the sole canonical body.
/// `sequence`, `event_kind`, `proposal_id`, and `key_version` are projections
/// of that body for indexes and idempotent replay — never independent
/// identity. Insert and schema CHECK reject a mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputerAuditEntryRow {
    pub sequence: u64,
    pub entry_bytes: [u8; COMPUTER_AUDIT_ENTRY_LEN],
    pub mac: [u8; COMPUTER_AUDIT_MAC_LEN],
    pub event_kind: u8,
    pub proposal_id: [u8; COMPUTER_AUDIT_ID_LEN],
    pub key_version: u32,
}

/// Project the index fields from the canonical body.
pub fn projected_index_fields(
    entry_bytes: &[u8; COMPUTER_AUDIT_ENTRY_LEN],
) -> (u64, u8, [u8; COMPUTER_AUDIT_ID_LEN], u32) {
    let event_kind = entry_bytes[COMPUTER_AUDIT_EVENT_KIND_OFFSET];
    let mut seq_bytes = [0u8; COMPUTER_AUDIT_SEQUENCE_LEN];
    seq_bytes.copy_from_slice(
        &entry_bytes[COMPUTER_AUDIT_SEQUENCE_OFFSET
            ..COMPUTER_AUDIT_SEQUENCE_OFFSET + COMPUTER_AUDIT_SEQUENCE_LEN],
    );
    let mut proposal_id = [0u8; COMPUTER_AUDIT_ID_LEN];
    proposal_id.copy_from_slice(
        &entry_bytes[COMPUTER_AUDIT_PROPOSAL_ID_OFFSET
            ..COMPUTER_AUDIT_PROPOSAL_ID_OFFSET + COMPUTER_AUDIT_ID_LEN],
    );
    let mut key_bytes = [0u8; COMPUTER_AUDIT_KEY_VERSION_LEN];
    key_bytes.copy_from_slice(
        &entry_bytes[COMPUTER_AUDIT_KEY_VERSION_OFFSET
            ..COMPUTER_AUDIT_KEY_VERSION_OFFSET + COMPUTER_AUDIT_KEY_VERSION_LEN],
    );
    (
        u64::from_be_bytes(seq_bytes),
        event_kind,
        proposal_id,
        u32::from_be_bytes(key_bytes),
    )
}

/// Project `wall_unix_ms` from the canonical body.
pub fn projected_wall_unix_ms(entry_bytes: &[u8; COMPUTER_AUDIT_ENTRY_LEN]) -> i64 {
    let mut wall_bytes = [0u8; COMPUTER_AUDIT_WALL_UNIX_MS_LEN];
    wall_bytes.copy_from_slice(
        &entry_bytes[COMPUTER_AUDIT_WALL_UNIX_MS_OFFSET
            ..COMPUTER_AUDIT_WALL_UNIX_MS_OFFSET + COMPUTER_AUDIT_WALL_UNIX_MS_LEN],
    );
    i64::from_be_bytes(wall_bytes)
}

fn index_columns_match_entry_bytes(row: &ComputerAuditEntryRow) -> bool {
    let (sequence, event_kind, proposal_id, key_version) = projected_index_fields(&row.entry_bytes);
    row.sequence == sequence
        && row.event_kind == event_kind
        && row.proposal_id == proposal_id
        && row.key_version == key_version
}

fn blob_array<const N: usize>(bytes: Vec<u8>, field: &str) -> rusqlite::Result<[u8; N]> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            format!("{field} must be {N} bytes, got {}", bytes.len()).into(),
        )
    })
}

fn parse_entry_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ComputerAuditEntryRow> {
    let sequence: i64 = row.get("sequence")?;
    if sequence < 1 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            "computer audit sequence must be >= 1".into(),
        ));
    }
    let event_kind: i64 = row.get("event_kind")?;
    if !(1..=29).contains(&event_kind) {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            format!("computer audit event_kind {event_kind} is not 1..=29").into(),
        ));
    }
    let key_version: i64 = row.get("key_version")?;
    if key_version < 1 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            "computer audit key_version must be >= 1".into(),
        ));
    }
    Ok(ComputerAuditEntryRow {
        sequence: sequence as u64,
        entry_bytes: blob_array(row.get("entry_bytes")?, "entry_bytes")?,
        mac: blob_array(row.get("mac")?, "mac")?,
        event_kind: event_kind as u8,
        proposal_id: blob_array(row.get("proposal_id")?, "proposal_id")?,
        key_version: key_version as u32,
    })
}

fn is_constraint(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(info, _) if info.code == ErrorCode::ConstraintViolation
    )
}

fn is_guidance_kind(event_kind: u8) -> bool {
    matches!(
        event_kind,
        GUIDANCE_PROPOSAL_CREATED
            | GUIDANCE_PROPOSAL_ACCEPTED
            | GUIDANCE_PROPOSAL_REJECTED
            | GUIDANCE_PROPOSAL_EXPIRED
    )
}

impl Db {
    /// Ordered chain bodies, sequence ascending.
    ///
    /// Load does not re-prove index-column projections so an offline relabel
    /// can be classified as chain corruption rather than a read error.
    pub async fn list_computer_audit_entries(&self) -> Result<Vec<ComputerAuditEntryRow>> {
        self.read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT sequence, entry_bytes, mac, event_kind, proposal_id, key_version
                 FROM computer_audit_entries
                 ORDER BY sequence ASC",
            )?;
            let rows = stmt
                .query_and_then([], parse_entry_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
    }

    /// The highest stored sequence, or 0 when the log is empty.
    pub async fn computer_audit_head_sequence(&self) -> Result<u64> {
        self.read(|conn| {
            let seq: Option<i64> = conn.query_row(
                "SELECT MAX(sequence) FROM computer_audit_entries",
                [],
                |row| row.get(0),
            )?;
            Ok(seq.unwrap_or(0) as u64)
        })
        .await
    }

    /// Look up a guidance-proposal event by the authenticated
    /// `(kind, proposal_id)` projection of `entry_bytes`.
    ///
    /// This uniqueness key locates at most one row. It is not event
    /// identity: a caller that treats a hit as replay success must compare
    /// the canonical body (as `insert_computer_audit_entry` does).
    pub async fn computer_audit_guidance_entry(
        &self,
        event_kind: u8,
        proposal_id: [u8; COMPUTER_AUDIT_ID_LEN],
    ) -> Result<Option<ComputerAuditEntryRow>> {
        anyhow::ensure!(
            is_guidance_kind(event_kind),
            "computer_audit_guidance_entry requires a guidance-proposal event kind"
        );
        let kind_blob = [event_kind];
        self.read(move |conn| {
            let row = conn
                .query_row(
                    GUIDANCE_BODY_LOOKUP_SQL,
                    params![kind_blob.as_slice(), proposal_id.as_slice()],
                    parse_entry_row,
                )
                .optional()?;
            Ok(row)
        })
        .await
    }

    /// Append one chain entry. Returns `Ok(true)` when inserted, `Ok(false)`
    /// only when a guidance-proposal replay hits the unique index *and* the
    /// existing row matches `sequence`, `entry_bytes`, `mac`, and
    /// `key_version`. Any other constraint (including a sequence clash or a
    /// same-identity row with different bytes) is an error: the chain must
    /// not fork.
    ///
    /// Index columns must be the projection of `entry_bytes`. A mismatch is
    /// refused here so a caller cannot persist an unauthenticated identity.
    pub async fn insert_computer_audit_entry(&self, row: ComputerAuditEntryRow) -> Result<bool> {
        anyhow::ensure!(row.sequence >= 1, "computer audit sequence must be >= 1");
        anyhow::ensure!(
            (1..=29).contains(&row.event_kind),
            "computer audit event_kind must be 1..=29"
        );
        anyhow::ensure!(
            row.key_version >= 1,
            "computer audit key_version must be >= 1"
        );
        anyhow::ensure!(
            index_columns_match_entry_bytes(&row),
            "computer audit index columns must match entry_bytes"
        );
        let wall_unix_ms = projected_wall_unix_ms(&row.entry_bytes);
        let kind_blob = [row.event_kind];
        self.write(move |conn| {
            match conn.execute(
                "INSERT INTO computer_audit_entries
                     (sequence, entry_bytes, mac, event_kind, proposal_id, key_version, wall_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    row.sequence as i64,
                    row.entry_bytes.as_slice(),
                    row.mac.as_slice(),
                    i64::from(row.event_kind),
                    row.proposal_id.as_slice(),
                    i64::from(row.key_version),
                    wall_unix_ms,
                ],
            ) {
                Ok(1) => Ok(true),
                Ok(changed) => Err(anyhow!(
                    "computer audit insert changed {changed} rows, expected 1"
                )),
                Err(err) if is_constraint(&err) && is_guidance_kind(row.event_kind) => {
                    let existing = conn
                        .query_row(
                            GUIDANCE_BODY_LOOKUP_SQL,
                            params![kind_blob.as_slice(), row.proposal_id.as_slice()],
                            parse_entry_row,
                        )
                        .optional()
                        .context("checking guidance audit replay")?;
                    match existing {
                        Some(existing)
                            if existing.sequence == row.sequence
                                && existing.entry_bytes == row.entry_bytes
                                && existing.mac == row.mac
                                && existing.key_version == row.key_version =>
                        {
                            Ok(false)
                        }
                        _ => Err(anyhow!("computer audit insert constraint: {err}")),
                    }
                }
                Err(err) => Err(anyhow!("computer audit insert failed: {err}")),
            }
        })
        .await
    }

    /// Delete a bounded prefix after a matching signed `PruneCheckpoint` entry.
    /// Only the machine-local audit writer may call this.
    pub(crate) async fn truncate_computer_audit_prefix_verified(
        &self,
        authorization: ComputerAuditPruneAuthorization,
    ) -> Result<u64> {
        self.write(move |conn| {
            verify_prune_checkpoint_authorizes_conn(conn, authorization.prefix_end_inclusive)?;
            truncate_computer_audit_prefix_conn(conn, authorization.prefix_end_inclusive)
        })
        .await
    }
}

/// Delete `sequence <= through_sequence_inclusive` in bounded batches.
pub(crate) fn truncate_computer_audit_prefix_conn(
    conn: &rusqlite::Connection,
    through_sequence_inclusive: u64,
) -> Result<u64> {
    if through_sequence_inclusive == 0 {
        return Ok(0);
    }
    let batch = i64::try_from(super::ledger_retention::LEDGER_RETENTION_BATCH)
        .context("computer audit truncate batch overflow")?;
    let through = i64::try_from(through_sequence_inclusive)
        .context("computer audit truncate sequence overflow")?;
    let _trigger_guard = drop_immutable_delete_trigger(conn)?;
    let mut total = 0_u64;
    loop {
        let deleted = conn
            .execute(
                "DELETE FROM computer_audit_entries
                  WHERE sequence IN (
                      SELECT sequence
                        FROM computer_audit_entries
                       WHERE sequence <= ?1
                       ORDER BY sequence ASC
                       LIMIT ?2
                  )",
                params![through, batch],
            )
            .context("truncating computer audit prefix")? as u64;
        total = total.saturating_add(deleted);
        if deleted < batch as u64 {
            break;
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn sample(sequence: u64, kind: u8, proposal: u8) -> ComputerAuditEntryRow {
        let mut proposal_id = [0u8; COMPUTER_AUDIT_ID_LEN];
        proposal_id[0] = proposal;
        proposal_id[15] = proposal;
        let key_version = 1u32;
        let mut entry_bytes = [0u8; COMPUTER_AUDIT_ENTRY_LEN];
        entry_bytes[COMPUTER_AUDIT_EVENT_KIND_OFFSET] = kind;
        entry_bytes[COMPUTER_AUDIT_SEQUENCE_OFFSET
            ..COMPUTER_AUDIT_SEQUENCE_OFFSET + COMPUTER_AUDIT_SEQUENCE_LEN]
            .copy_from_slice(&sequence.to_be_bytes());
        entry_bytes[COMPUTER_AUDIT_PROPOSAL_ID_OFFSET
            ..COMPUTER_AUDIT_PROPOSAL_ID_OFFSET + COMPUTER_AUDIT_ID_LEN]
            .copy_from_slice(&proposal_id);
        entry_bytes[COMPUTER_AUDIT_KEY_VERSION_OFFSET
            ..COMPUTER_AUDIT_KEY_VERSION_OFFSET + COMPUTER_AUDIT_KEY_VERSION_LEN]
            .copy_from_slice(&key_version.to_be_bytes());
        let wall_unix_ms = 1_700_000_000_000_i64;
        entry_bytes[COMPUTER_AUDIT_WALL_UNIX_MS_OFFSET
            ..COMPUTER_AUDIT_WALL_UNIX_MS_OFFSET + COMPUTER_AUDIT_WALL_UNIX_MS_LEN]
            .copy_from_slice(&wall_unix_ms.to_be_bytes());
        let mut mac = [0u8; COMPUTER_AUDIT_MAC_LEN];
        mac[0] = sequence as u8;
        mac[31] = kind;
        ComputerAuditEntryRow {
            sequence,
            entry_bytes,
            mac,
            event_kind: kind,
            proposal_id,
            key_version,
        }
    }

    #[tokio::test]
    async fn append_list_round_trip() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.computer_audit_head_sequence().await.unwrap(), 0);
        assert!(
            db.insert_computer_audit_entry(sample(1, GUIDANCE_PROPOSAL_CREATED, 9))
                .await
                .unwrap()
        );
        assert!(
            db.insert_computer_audit_entry(sample(2, GUIDANCE_PROPOSAL_ACCEPTED, 9))
                .await
                .unwrap()
        );
        assert_eq!(db.computer_audit_head_sequence().await.unwrap(), 2);
        let rows = db.list_computer_audit_entries().await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].sequence, 1);
        assert_eq!(rows[1].event_kind, GUIDANCE_PROPOSAL_ACCEPTED);
    }

    #[tokio::test]
    async fn guidance_replay_is_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let row = sample(1, GUIDANCE_PROPOSAL_CREATED, 3);
        assert!(db.insert_computer_audit_entry(row.clone()).await.unwrap());
        assert!(!db.insert_computer_audit_entry(row.clone()).await.unwrap());
        assert_eq!(db.list_computer_audit_entries().await.unwrap().len(), 1);
        let found = db
            .computer_audit_guidance_entry(GUIDANCE_PROPOSAL_CREATED, row.proposal_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.sequence, 1);
    }

    #[tokio::test]
    async fn guidance_replay_at_a_different_sequence_is_not_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let first = sample(1, GUIDANCE_PROPOSAL_CREATED, 3);
        assert!(db.insert_computer_audit_entry(first.clone()).await.unwrap());
        let err = db
            .insert_computer_audit_entry(sample(2, GUIDANCE_PROPOSAL_CREATED, 3))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("computer audit insert constraint"),
            "{err}"
        );
        let rows = db.list_computer_audit_entries().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], first);
    }

    #[tokio::test]
    async fn guidance_replay_byte_mismatch_is_not_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let first = sample(1, GUIDANCE_PROPOSAL_CREATED, 3);
        assert!(db.insert_computer_audit_entry(first.clone()).await.unwrap());
        let mut mismatched = first.clone();
        // Mutate a non-index byte so the unique body identity still collides.
        mismatched.entry_bytes[50] = 0xff;
        mismatched.mac[1] = 0xff;
        let err = db
            .insert_computer_audit_entry(mismatched)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("computer audit insert constraint"),
            "{err}"
        );
        let rows = db.list_computer_audit_entries().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], first);
    }

    #[tokio::test]
    async fn sequence_clash_is_not_idempotent() {
        let db = Db::open_in_memory().unwrap();
        assert!(
            db.insert_computer_audit_entry(sample(1, GUIDANCE_PROPOSAL_CREATED, 1))
                .await
                .unwrap()
        );
        let err = db
            .insert_computer_audit_entry(sample(1, GUIDANCE_PROPOSAL_REJECTED, 2))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("computer audit insert"), "{err}");
        assert_eq!(db.list_computer_audit_entries().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn insert_rejects_index_columns_that_do_not_match_entry_bytes() {
        let db = Db::open_in_memory().unwrap();
        let base = sample(1, GUIDANCE_PROPOSAL_CREATED, 3);
        let mut kind = base.clone();
        kind.event_kind = GUIDANCE_PROPOSAL_ACCEPTED;
        let mut proposal = base.clone();
        proposal.proposal_id[0] = 9;
        let mut sequence = base.clone();
        sequence.sequence = 2;
        let mut key_version = base.clone();
        key_version.key_version = 2;
        for (name, row) in [
            ("event_kind", kind),
            ("proposal_id", proposal),
            ("sequence", sequence),
            ("key_version", key_version),
        ] {
            let err = db.insert_computer_audit_entry(row).await.unwrap_err();
            assert!(
                err.to_string()
                    .contains("computer audit index columns must match entry_bytes"),
                "{name}: {err}"
            );
        }
        assert!(db.list_computer_audit_entries().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn schema_rejects_raw_insert_whose_columns_do_not_match_entry_bytes() {
        let db = Db::open_in_memory().unwrap();
        let row = sample(1, GUIDANCE_PROPOSAL_CREATED, 3);
        let err = db
            .write(move |conn| {
                conn.execute(
                    "INSERT INTO computer_audit_entries
                         (sequence, entry_bytes, mac, event_kind, proposal_id, key_version, wall_unix_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        row.sequence as i64,
                        row.entry_bytes.as_slice(),
                        row.mac.as_slice(),
                        i64::from(GUIDANCE_PROPOSAL_ACCEPTED),
                        row.proposal_id.as_slice(),
                        i64::from(row.key_version),
                        projected_wall_unix_ms(&row.entry_bytes),
                    ],
                )
                .map_err(Into::into)
            })
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("CHECK") || err.to_string().contains("constraint"),
            "{err}"
        );
        assert!(db.list_computer_audit_entries().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn entries_are_append_only() {
        let db = Db::open_in_memory().unwrap();
        db.insert_computer_audit_entry(sample(1, GUIDANCE_PROPOSAL_CREATED, 1))
            .await
            .unwrap();
        let update = db
            .write(|conn| {
                conn.execute("UPDATE computer_audit_entries SET key_version = 2", [])
                    .map_err(Into::into)
            })
            .await;
        assert!(update.is_err());
        let delete = db
            .write(|conn| {
                conn.execute("DELETE FROM computer_audit_entries", [])
                    .map_err(Into::into)
            })
            .await;
        assert!(delete.is_err());
        assert_eq!(db.list_computer_audit_entries().await.unwrap().len(), 1);
    }
}
