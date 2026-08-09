//! Durable per-attachment operation reservation and replay metadata.
//!
//! This module intentionally accepts only bounded identifiers, digests, and
//! safe response bytes. Canonical request bytes, credentials, grants, and
//! transport metadata have no representation here.

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

pub const MAX_OPERATION_ROWS_PER_ATTACHMENT: u64 = 100_000;
pub const MAX_SAFE_RESPONSE_BYTES_PER_ATTACHMENT: u64 = 512 * 1024 * 1024;
pub const MAX_SAFE_RESPONSE_BYTES: usize = 512 * 1024;
pub const MAX_OUTBOX_EVENTS_PER_ATTACHMENT: u64 = 200_000;
pub const MAX_OUTBOX_PAYLOAD_BYTES_PER_ATTACHMENT: u64 = 2 * 1024 * 1024 * 1024;
pub const MAX_OUTBOX_PAYLOAD_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteOperationClass {
    TransactionalMutation,
    IdempotentAdapterMutation,
    NonrepeatableMutation,
}

impl RemoteOperationClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::TransactionalMutation => "transactional_mutation",
            Self::IdempotentAdapterMutation => "idempotent_adapter_mutation",
            Self::NonrepeatableMutation => "nonrepeatable_mutation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteOperationReservation {
    pub operation_seq: u64,
    pub state: String,
    pub safe_response: Option<Vec<u8>>,
    pub event_high_water_mark: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReserveRemoteOperationOutcome {
    Reserved(RemoteOperationReservation),
    Replay(RemoteOperationReservation),
    OperationConflict,
    OperationActorConflict,
    AttachmentLedgerCapacity,
}

#[derive(Debug, Clone)]
pub struct ReserveRemoteOperation<'a> {
    pub logical_attachment_id: &'a str,
    pub operation_id: &'a str,
    pub authenticated_device_id: &'a str,
    pub authenticated_device_generation: u64,
    pub operation_class: RemoteOperationClass,
    pub request_hash: [u8; 32],
    pub now_ms: i64,
}

#[derive(Debug, Clone)]
pub struct CommitRemoteOperation<'a> {
    pub logical_attachment_id: &'a str,
    pub operation_id: &'a str,
    pub safe_response: &'a [u8],
    pub outbox_delivery_id: &'a str,
    pub outbox_kind: &'a str,
    pub outbox_payload: &'a [u8],
    pub now_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitRemoteOperationOutcome {
    Committed { operation_seq: u64, event_seq: u64 },
    AttachmentLedgerCapacity,
    AttachmentOutboxCapacity,
}

impl Db {
    pub async fn reserve_remote_attachment_operation(
        &self,
        request: ReserveRemoteOperation<'_>,
    ) -> Result<ReserveRemoteOperationOutcome> {
        let owned = OwnedReserveRemoteOperation {
            logical_attachment_id: request.logical_attachment_id.to_owned(),
            operation_id: request.operation_id.to_owned(),
            authenticated_device_id: request.authenticated_device_id.to_owned(),
            authenticated_device_generation: request.authenticated_device_generation,
            operation_class: request.operation_class,
            request_hash: request.request_hash,
            now_ms: request.now_ms,
        };
        self.transaction(move |conn| reserve_conn(conn, &owned))
            .await
    }

    /// Atomically commits a bounded safe outcome and its authoritative outbox
    /// event. Capacity checks and writes share one `BEGIN IMMEDIATE` boundary.
    pub async fn commit_remote_attachment_operation(
        &self,
        request: CommitRemoteOperation<'_>,
    ) -> Result<CommitRemoteOperationOutcome> {
        let owned = OwnedCommitRemoteOperation {
            logical_attachment_id: request.logical_attachment_id.to_owned(),
            operation_id: request.operation_id.to_owned(),
            safe_response: request.safe_response.to_vec(),
            outbox_delivery_id: request.outbox_delivery_id.to_owned(),
            outbox_kind: request.outbox_kind.to_owned(),
            outbox_payload: request.outbox_payload.to_vec(),
            now_ms: request.now_ms,
        };
        self.transaction(move |conn| commit_conn(conn, &owned))
            .await
    }
}

struct OwnedCommitRemoteOperation {
    logical_attachment_id: String,
    operation_id: String,
    safe_response: Vec<u8>,
    outbox_delivery_id: String,
    outbox_kind: String,
    outbox_payload: Vec<u8>,
    now_ms: i64,
}

struct OwnedReserveRemoteOperation {
    logical_attachment_id: String,
    operation_id: String,
    authenticated_device_id: String,
    authenticated_device_generation: u64,
    operation_class: RemoteOperationClass,
    request_hash: [u8; 32],
    now_ms: i64,
}

fn reserve_conn(
    conn: &Connection,
    request: &OwnedReserveRemoteOperation,
) -> Result<ReserveRemoteOperationOutcome> {
    validate_uuid("logical attachment id", &request.logical_attachment_id)?;
    validate_operation_id(&request.operation_id)?;
    validate_uuid("authenticated device id", &request.authenticated_device_id)?;
    if request.authenticated_device_generation == 0 {
        bail!("authenticated device generation must be positive");
    }
    let actor_generation = i64::try_from(request.authenticated_device_generation)
        .context("device generation exceeds SQLite INTEGER")?;
    let existing = conn
        .query_row(
            "SELECT authenticated_device_id, authenticated_device_generation, request_hash,
                    operation_class, operation_seq, state, safe_response, event_high_water_mark
             FROM remote_attachment_operations
             WHERE logical_attachment_id = ?1 AND operation_id = ?2",
            params![request.logical_attachment_id, request.operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            },
        )
        .optional()
        .context("looking up remote operation reservation")?;
    if let Some((device_id, generation, hash, class, seq, state, response, high_water)) = existing {
        if device_id != request.authenticated_device_id || generation != actor_generation {
            return Ok(ReserveRemoteOperationOutcome::OperationActorConflict);
        }
        if class != request.operation_class.as_str() || hash.as_slice() != request.request_hash {
            return Ok(ReserveRemoteOperationOutcome::OperationConflict);
        }
        return Ok(ReserveRemoteOperationOutcome::Replay(reservation(
            seq, state, response, high_water,
        )?));
    }

    let (row_count, response_bytes): (i64, i64) = conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(length(safe_response)), 0)
         FROM remote_attachment_operations WHERE logical_attachment_id = ?1",
        [&request.logical_attachment_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if row_count >= MAX_OPERATION_ROWS_PER_ATTACHMENT as i64
        || response_bytes >= MAX_SAFE_RESPONSE_BYTES_PER_ATTACHMENT as i64
    {
        return Ok(ReserveRemoteOperationOutcome::AttachmentLedgerCapacity);
    }
    let next_seq: i64 = conn.query_row(
        "SELECT COALESCE(MAX(operation_seq), 0) + 1
         FROM remote_attachment_operations WHERE logical_attachment_id = ?1",
        [&request.logical_attachment_id],
        |row| row.get(0),
    )?;
    conn.execute(
        "INSERT INTO remote_attachment_operations
         (logical_attachment_id, operation_id, authenticated_device_id,
          authenticated_device_generation, operation_seq, operation_class, state,
          request_hash, created_at_ms, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'reserved', ?7, ?8, ?8)",
        params![
            request.logical_attachment_id,
            request.operation_id,
            request.authenticated_device_id,
            actor_generation,
            next_seq,
            request.operation_class.as_str(),
            request.request_hash.as_slice(),
            request.now_ms,
        ],
    )
    .context("reserving remote attachment operation")?;
    Ok(ReserveRemoteOperationOutcome::Reserved(reservation(
        next_seq,
        "reserved".to_owned(),
        None,
        None,
    )?))
}

fn commit_conn(
    conn: &Connection,
    request: &OwnedCommitRemoteOperation,
) -> Result<CommitRemoteOperationOutcome> {
    validate_uuid("logical attachment id", &request.logical_attachment_id)?;
    validate_operation_id(&request.operation_id)?;
    validate_uuid("outbox delivery id", &request.outbox_delivery_id)?;
    if request.safe_response.len() > MAX_SAFE_RESPONSE_BYTES {
        bail!("safe response exceeds 512 KiB");
    }
    if request.outbox_payload.len() > MAX_OUTBOX_PAYLOAD_BYTES {
        bail!("outbox payload exceeds 512 KiB");
    }
    if request.outbox_kind.is_empty() || request.outbox_kind.len() > 255 {
        bail!("outbox kind length must be 1..=255 bytes");
    }
    let (operation_seq, state): (i64, String) = conn
        .query_row(
            "SELECT operation_seq, state FROM remote_attachment_operations
             WHERE logical_attachment_id = ?1 AND operation_id = ?2",
            params![request.logical_attachment_id, request.operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("loading reserved remote operation")?;
    if state != "reserved" {
        bail!("remote operation is already terminal");
    }
    let response_bytes: i64 = conn.query_row(
        "SELECT COALESCE(SUM(length(safe_response)), 0)
         FROM remote_attachment_operations WHERE logical_attachment_id = ?1",
        [&request.logical_attachment_id],
        |row| row.get(0),
    )?;
    if response_bytes.saturating_add(request.safe_response.len() as i64)
        > MAX_SAFE_RESPONSE_BYTES_PER_ATTACHMENT as i64
    {
        return Ok(CommitRemoteOperationOutcome::AttachmentLedgerCapacity);
    }
    let (event_count, payload_bytes, next_event_seq): (i64, i64, i64) = conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(length(canonical_payload)), 0),
                COALESCE(MAX(event_seq), 0) + 1
         FROM remote_attachment_outbox WHERE logical_attachment_id = ?1",
        [&request.logical_attachment_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if event_count >= MAX_OUTBOX_EVENTS_PER_ATTACHMENT as i64
        || payload_bytes.saturating_add(request.outbox_payload.len() as i64)
            > MAX_OUTBOX_PAYLOAD_BYTES_PER_ATTACHMENT as i64
    {
        return Ok(CommitRemoteOperationOutcome::AttachmentOutboxCapacity);
    }
    conn.execute(
        "INSERT INTO remote_attachment_outbox
         (logical_attachment_id, event_seq, delivery_id, operation_seq, kind,
          canonical_payload, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            request.logical_attachment_id,
            next_event_seq,
            request.outbox_delivery_id,
            operation_seq,
            request.outbox_kind,
            request.outbox_payload,
            request.now_ms,
        ],
    )?;
    conn.execute(
        "UPDATE remote_attachment_operations
         SET state = 'committed', safe_response = ?3, event_high_water_mark = ?4,
             updated_at_ms = ?5
         WHERE logical_attachment_id = ?1 AND operation_id = ?2 AND state = 'reserved'",
        params![
            request.logical_attachment_id,
            request.operation_id,
            request.safe_response,
            next_event_seq,
            request.now_ms,
        ],
    )?;
    Ok(CommitRemoteOperationOutcome::Committed {
        operation_seq: operation_seq.try_into()?,
        event_seq: next_event_seq.try_into()?,
    })
}

fn validate_uuid(label: &str, value: &str) -> Result<()> {
    let parsed = Uuid::parse_str(value).with_context(|| format!("invalid {label}"))?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        bail!("{label} must be a canonical nonnil UUID");
    }
    Ok(())
}

fn validate_operation_id(value: &str) -> Result<()> {
    validate_uuid("operation id", value)?;
    if Uuid::parse_str(value)?.get_version_num() != 7 {
        bail!("operation id must be an RFC 9562 UUIDv7");
    }
    Ok(())
}

fn reservation(
    operation_seq: i64,
    state: String,
    safe_response: Option<Vec<u8>>,
    event_high_water_mark: Option<i64>,
) -> Result<RemoteOperationReservation> {
    Ok(RemoteOperationReservation {
        operation_seq: operation_seq
            .try_into()
            .context("negative operation sequence")?,
        state,
        safe_response,
        event_high_water_mark: event_high_water_mark
            .map(u64::try_from)
            .transpose()
            .context("negative event high-water mark")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTACHMENT: &str = "00000000-0000-4000-8000-000000000001";
    const DEVICE: &str = "00000000-0000-4000-8000-000000000002";

    fn reserve<'a>(operation_id: &'a str, hash: [u8; 32]) -> ReserveRemoteOperation<'a> {
        ReserveRemoteOperation {
            logical_attachment_id: ATTACHMENT,
            operation_id,
            authenticated_device_id: DEVICE,
            authenticated_device_generation: 1,
            operation_class: RemoteOperationClass::TransactionalMutation,
            request_hash: hash,
            now_ms: 10,
        }
    }

    #[tokio::test]
    async fn actor_conflict_precedes_hash_and_class_conflicts() {
        let db = Db::open_in_memory().unwrap();
        let operation = "01890f3e-4c00-7000-8000-000000000003";
        assert!(matches!(
            db.reserve_remote_attachment_operation(reserve(operation, [1; 32]))
                .await
                .unwrap(),
            ReserveRemoteOperationOutcome::Reserved(_)
        ));
        let changed = ReserveRemoteOperation {
            authenticated_device_id: "00000000-0000-4000-8000-000000000004",
            operation_class: RemoteOperationClass::NonrepeatableMutation,
            request_hash: [2; 32],
            ..reserve(operation, [1; 32])
        };
        assert_eq!(
            db.reserve_remote_attachment_operation(changed)
                .await
                .unwrap(),
            ReserveRemoteOperationOutcome::OperationActorConflict
        );
    }

    #[tokio::test]
    async fn class_mismatch_conflicts_and_sequences_are_attachment_linear() {
        let db = Db::open_in_memory().unwrap();
        let first_id = "01890f3e-4c00-7000-8000-000000000005";
        let second_id = "01890f3e-4c00-7000-8000-000000000006";
        let ReserveRemoteOperationOutcome::Reserved(first) = db
            .reserve_remote_attachment_operation(reserve(first_id, [1; 32]))
            .await
            .unwrap()
        else {
            panic!("first reservation")
        };
        let mismatch = ReserveRemoteOperation {
            operation_class: RemoteOperationClass::NonrepeatableMutation,
            ..reserve(first_id, [1; 32])
        };
        assert_eq!(
            db.reserve_remote_attachment_operation(mismatch)
                .await
                .unwrap(),
            ReserveRemoteOperationOutcome::OperationConflict
        );
        let ReserveRemoteOperationOutcome::Reserved(second) = db
            .reserve_remote_attachment_operation(reserve(second_id, [2; 32]))
            .await
            .unwrap()
        else {
            panic!("second reservation")
        };
        assert_eq!((first.operation_seq, second.operation_seq), (1, 2));
    }

    #[tokio::test]
    async fn commit_is_atomic_and_replay_returns_byte_identical_outcome() {
        let db = Db::open_in_memory().unwrap();
        let operation = "01890f3e-4c00-7000-8000-000000000007";
        db.reserve_remote_attachment_operation(reserve(operation, [7; 32]))
            .await
            .unwrap();
        assert_eq!(
            db.commit_remote_attachment_operation(CommitRemoteOperation {
                logical_attachment_id: ATTACHMENT,
                operation_id: operation,
                safe_response: b"safe typed outcome",
                outbox_delivery_id: "00000000-0000-4000-8000-000000000008",
                outbox_kind: "operation_committed",
                outbox_payload: b"bounded event",
                now_ms: 11,
            })
            .await
            .unwrap(),
            CommitRemoteOperationOutcome::Committed {
                operation_seq: 1,
                event_seq: 1
            }
        );
        let ReserveRemoteOperationOutcome::Replay(replay) = db
            .reserve_remote_attachment_operation(reserve(operation, [7; 32]))
            .await
            .unwrap()
        else {
            panic!("committed operation must replay")
        };
        assert_eq!(replay.state, "committed");
        assert_eq!(
            replay.safe_response.as_deref(),
            Some(b"safe typed outcome".as_slice())
        );
        assert_eq!(replay.event_high_water_mark, Some(1));
    }

    #[tokio::test]
    async fn rejects_noncanonical_identity_and_zero_generation() {
        let db = Db::open_in_memory().unwrap();
        let mut invalid = reserve("01890f3e-4c00-7000-8000-000000000009", [1; 32]);
        invalid.authenticated_device_generation = 0;
        assert!(
            db.reserve_remote_attachment_operation(invalid)
                .await
                .is_err()
        );
        let invalid = ReserveRemoteOperation {
            operation_id: "00000000000040008000000000000009",
            ..reserve("01890f3e-4c00-7000-8000-000000000009", [1; 32])
        };
        assert!(
            db.reserve_remote_attachment_operation(invalid)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn concurrent_reservations_allocate_one_row_and_sequence() {
        let db = Db::open_in_memory().unwrap();
        let operation = "01890f3e-4c00-7000-8000-000000000010";
        let left = db.clone();
        let right = db.clone();
        let (left, right) = tokio::join!(
            left.reserve_remote_attachment_operation(reserve(operation, [9; 32])),
            right.reserve_remote_attachment_operation(reserve(operation, [9; 32])),
        );
        let outcomes = [left.unwrap(), right.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ReserveRemoteOperationOutcome::Reserved(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ReserveRemoteOperationOutcome::Replay(_)))
                .count(),
            1
        );
        for outcome in outcomes {
            let seq = match outcome {
                ReserveRemoteOperationOutcome::Reserved(row)
                | ReserveRemoteOperationOutcome::Replay(row) => row.operation_seq,
                other => panic!("unexpected concurrent outcome: {other:?}"),
            };
            assert_eq!(seq, 1);
        }
    }

    #[tokio::test]
    async fn concurrent_distinct_operations_get_distinct_contiguous_sequences() {
        let db = Db::open_in_memory().unwrap();
        let left = db.clone();
        let right = db.clone();
        let (left, right) = tokio::join!(
            left.reserve_remote_attachment_operation(reserve(
                "01890f3e-4c00-7000-8000-000000000011",
                [1; 32]
            )),
            right.reserve_remote_attachment_operation(reserve(
                "01890f3e-4c00-7000-8000-000000000012",
                [2; 32]
            )),
        );
        let mut sequences = [left.unwrap(), right.unwrap()].map(|outcome| match outcome {
            ReserveRemoteOperationOutcome::Reserved(row) => row.operation_seq,
            other => panic!("unexpected distinct reservation: {other:?}"),
        });
        sequences.sort_unstable();
        assert_eq!(sequences, [1, 2]);
    }

    #[tokio::test]
    async fn snapshot_cursors_and_timestamp_are_monotonic() {
        let db = Db::open_in_memory().unwrap();
        db.write(|conn| {
            conn.execute(
                "INSERT INTO remote_attachment_outbox_snapshots
                 (logical_attachment_id, compacted_through_event_seq,
                  snapshot_high_water_mark, updated_at_ms) VALUES (?1, 5, 8, 10)",
                [ATTACHMENT],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        for sql in [
            "UPDATE remote_attachment_outbox_snapshots SET compacted_through_event_seq = 4 WHERE logical_attachment_id = ?1",
            "UPDATE remote_attachment_outbox_snapshots SET snapshot_high_water_mark = 7 WHERE logical_attachment_id = ?1",
            "UPDATE remote_attachment_outbox_snapshots SET updated_at_ms = 9 WHERE logical_attachment_id = ?1",
        ] {
            assert!(
                db.write(move |conn| {
                    conn.execute(sql, [ATTACHMENT])?;
                    Ok(())
                })
                .await
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn terminal_first_write_is_rejected_and_atomic_commit_is_final() {
        let db = Db::open_in_memory().unwrap();
        let operation = "01890f3e-4c00-7000-8000-000000000020";
        db.reserve_remote_attachment_operation(reserve(operation, [4; 32]))
            .await
            .unwrap();
        let attachment = ATTACHMENT.to_owned();
        let operation_for_write = operation.to_owned();
        assert!(
            db.write(move |conn| {
                conn.execute(
                    "UPDATE remote_attachment_operations
                     SET state = 'committed', safe_response = X'01', event_high_water_mark = 1,
                         updated_at_ms = 11
                     WHERE logical_attachment_id = ?1 AND operation_id = ?2",
                    params![attachment, operation_for_write],
                )?;
                Ok(())
            })
            .await
            .is_err(),
            "a terminal write without its outbox evidence must fail"
        );
        db.commit_remote_attachment_operation(CommitRemoteOperation {
            logical_attachment_id: ATTACHMENT,
            operation_id: operation,
            safe_response: b"committed",
            outbox_delivery_id: "00000000-0000-4000-8000-000000000021",
            outbox_kind: "committed",
            outbox_payload: b"event",
            now_ms: 12,
        })
        .await
        .unwrap();
        let attachment = ATTACHMENT.to_owned();
        let operation_for_write = operation.to_owned();
        assert!(
            db.write(move |conn| {
                conn.execute(
                    "UPDATE remote_attachment_operations SET state = 'reserved', updated_at_ms = 13
                     WHERE logical_attachment_id = ?1 AND operation_id = ?2",
                    params![attachment, operation_for_write],
                )?;
                Ok(())
            })
            .await
            .is_err(),
            "committed state must be final"
        );
    }
}
