//! Append-only computer-use audit-chain bodies (issue #271).
//!
//! The HMAC signing key and sealed chain head live in the machine-local
//! protected secret store. This module stores the ordered 424-byte entries
//! and their MACs so verification can detect SQLite mutation, reorder,
//! insertion, and tail deletion. Typed rule values, rationale, pixels, OCR,
//! and raw target text never enter this table.

use anyhow::{Context, Result, anyhow};
use rusqlite::{ErrorCode, OptionalExtension, params};

use crate::db::Db;

/// Canonical ComputerAuditEntryV1 encoding length.
pub const COMPUTER_AUDIT_ENTRY_LEN: usize = 424;
/// HMAC-SHA-256 tag length.
pub const COMPUTER_AUDIT_MAC_LEN: usize = 32;
/// RFC 4122 / proposal-id slot length.
pub const COMPUTER_AUDIT_ID_LEN: usize = 16;

/// Guidance-proposal audit kinds (must stay aligned with
/// `AuditEventKind::{GuidanceProposalCreated, Accepted, Rejected, Expired}`).
pub const GUIDANCE_PROPOSAL_CREATED: u8 = 20;
pub const GUIDANCE_PROPOSAL_ACCEPTED: u8 = 21;
pub const GUIDANCE_PROPOSAL_REJECTED: u8 = 22;
pub const GUIDANCE_PROPOSAL_EXPIRED: u8 = 23;

/// One stored chain entry. `entry_bytes` is the sole canonical body;
/// extracted columns exist for indexes and idempotent replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputerAuditEntryRow {
    pub sequence: u64,
    pub entry_bytes: [u8; COMPUTER_AUDIT_ENTRY_LEN],
    pub mac: [u8; COMPUTER_AUDIT_MAC_LEN],
    pub event_kind: u8,
    pub proposal_id: [u8; COMPUTER_AUDIT_ID_LEN],
    pub key_version: u32,
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

    /// Look up a guidance-proposal event by `(kind, proposal_id)`.
    pub async fn computer_audit_guidance_entry(
        &self,
        event_kind: u8,
        proposal_id: [u8; COMPUTER_AUDIT_ID_LEN],
    ) -> Result<Option<ComputerAuditEntryRow>> {
        anyhow::ensure!(
            is_guidance_kind(event_kind),
            "computer_audit_guidance_entry requires a guidance-proposal event kind"
        );
        self.read(move |conn| {
            let row = conn
                .query_row(
                    "SELECT sequence, entry_bytes, mac, event_kind, proposal_id, key_version
                     FROM computer_audit_entries
                     WHERE event_kind = ?1 AND proposal_id = ?2",
                    params![i64::from(event_kind), proposal_id.as_slice()],
                    parse_entry_row,
                )
                .optional()?;
            Ok(row)
        })
        .await
    }

    /// Append one chain entry. Returns `Ok(true)` when inserted, `Ok(false)`
    /// when a guidance-proposal `(kind, proposal_id)` replay hits the unique
    /// index (idempotent). Any other constraint (including a sequence clash)
    /// is an error: the chain must not fork.
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
        self.write(move |conn| {
            match conn.execute(
                "INSERT INTO computer_audit_entries
                     (sequence, entry_bytes, mac, event_kind, proposal_id, key_version)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    row.sequence as i64,
                    row.entry_bytes.as_slice(),
                    row.mac.as_slice(),
                    i64::from(row.event_kind),
                    row.proposal_id.as_slice(),
                    i64::from(row.key_version),
                ],
            ) {
                Ok(1) => Ok(true),
                Ok(changed) => Err(anyhow!(
                    "computer audit insert changed {changed} rows, expected 1"
                )),
                Err(err) if is_constraint(&err) && is_guidance_kind(row.event_kind) => {
                    let existing: Option<i64> = conn
                        .query_row(
                            "SELECT sequence FROM computer_audit_entries
                             WHERE event_kind = ?1 AND proposal_id = ?2",
                            params![i64::from(row.event_kind), row.proposal_id.as_slice()],
                            |r| r.get(0),
                        )
                        .optional()
                        .context("checking guidance audit replay")?;
                    if existing.is_some() {
                        Ok(false)
                    } else {
                        Err(anyhow!("computer audit insert constraint: {err}"))
                    }
                }
                Err(err) => Err(anyhow!("computer audit insert failed: {err}")),
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn sample(sequence: u64, kind: u8, proposal: u8) -> ComputerAuditEntryRow {
        let mut entry_bytes = [0u8; COMPUTER_AUDIT_ENTRY_LEN];
        entry_bytes[0] = sequence as u8;
        entry_bytes[1] = kind;
        let mut mac = [0u8; COMPUTER_AUDIT_MAC_LEN];
        mac[0] = sequence as u8;
        mac[31] = kind;
        let mut proposal_id = [0u8; COMPUTER_AUDIT_ID_LEN];
        proposal_id[0] = proposal;
        proposal_id[15] = proposal;
        ComputerAuditEntryRow {
            sequence,
            entry_bytes,
            mac,
            event_kind: kind,
            proposal_id,
            key_version: 1,
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
