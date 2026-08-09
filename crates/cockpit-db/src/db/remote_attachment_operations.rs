//! Durable per-attachment operation reservation and replay metadata.
//!
//! This module intentionally accepts only bounded identifiers, digests, and
//! safe response bytes. Canonical request bytes, credentials, grants, and
//! transport metadata have no representation here.

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

pub const MAX_OPERATION_ROWS_PER_ATTACHMENT: u64 = 100_000;
pub const MAX_SAFE_RESPONSE_BYTES_PER_ATTACHMENT: u64 = 512 * 1024 * 1024;
pub const MAX_SAFE_RESPONSE_BYTES: usize = 512 * 1024;
pub const MAX_OUTBOX_EVENTS_PER_ATTACHMENT: u64 = 200_000;
pub const MAX_OUTBOX_PAYLOAD_BYTES_PER_ATTACHMENT: u64 = 2 * 1024 * 1024 * 1024;
pub const MAX_OUTBOX_PAYLOAD_BYTES: usize = 512 * 1024;

fn operation_reservation_at_capacity(row_count: u64, response_bytes: u64) -> bool {
    row_count >= MAX_OPERATION_ROWS_PER_ATTACHMENT
        || response_bytes >= MAX_SAFE_RESPONSE_BYTES_PER_ATTACHMENT
}

fn response_would_exceed_capacity(response_bytes: u64, added_bytes: usize) -> bool {
    response_bytes.saturating_add(added_bytes as u64) > MAX_SAFE_RESPONSE_BYTES_PER_ATTACHMENT
}

fn outbox_would_exceed_capacity(event_count: u64, payload_bytes: u64, added_bytes: usize) -> bool {
    event_count >= MAX_OUTBOX_EVENTS_PER_ATTACHMENT
        || payload_bytes.saturating_add(added_bytes as u64)
            > MAX_OUTBOX_PAYLOAD_BYTES_PER_ATTACHMENT
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionalRemoteOperationOutcome<T> {
    Applied(T),
    Replay(Vec<u8>),
    OperationConflict,
    OperationActorConflict,
    AttachmentLedgerCapacity,
}

pub struct TransactionalRemoteMutation<T> {
    pub value: T,
    pub safe_response: Vec<u8>,
    pub outbox_kind: String,
    pub outbox_payload: Vec<u8>,
}

impl Db {
    /// Reserve, perform one domain mutation, and commit its replay response and
    /// outbox event in one writer transaction. No reserved intermediate state
    /// or connection-level ledger primitive escapes this API.
    pub async fn execute_transactional_remote_operation<T, F>(
        &self,
        request: ReserveRemoteOperation<'_>,
        mutation: F,
    ) -> Result<TransactionalRemoteOperationOutcome<T>>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<TransactionalRemoteMutation<T>> + Send + 'static,
    {
        ensure!(
            request.operation_class == RemoteOperationClass::TransactionalMutation,
            "transactional executor requires transactional_mutation class"
        );
        let owned = OwnedReserveRemoteOperation {
            logical_attachment_id: request.logical_attachment_id.to_owned(),
            operation_id: request.operation_id.to_owned(),
            authenticated_device_id: request.authenticated_device_id.to_owned(),
            authenticated_device_generation: request.authenticated_device_generation,
            operation_class: request.operation_class,
            request_hash: request.request_hash,
            now_ms: request.now_ms,
        };
        self.transaction(move |conn| match reserve_conn(conn, &owned)? {
            ReserveRemoteOperationOutcome::Reserved(_) => {
                let result = mutation(conn)?;
                let delivery_id = Uuid::now_v7().to_string();
                let committed = commit_conn(
                    conn,
                    &OwnedCommitRemoteOperation {
                        logical_attachment_id: owned.logical_attachment_id.clone(),
                        operation_id: owned.operation_id.clone(),
                        safe_response: result.safe_response,
                        outbox_delivery_id: delivery_id,
                        outbox_kind: result.outbox_kind,
                        outbox_payload: result.outbox_payload,
                        now_ms: owned.now_ms,
                    },
                )?;
                match committed {
                    CommitRemoteOperationOutcome::Committed { .. } => {
                        Ok(TransactionalRemoteOperationOutcome::Applied(result.value))
                    }
                    CommitRemoteOperationOutcome::AttachmentLedgerCapacity => {
                        bail!("transactional remote operation ledger capacity")
                    }
                    CommitRemoteOperationOutcome::AttachmentOutboxCapacity => {
                        bail!("transactional remote operation outbox capacity")
                    }
                }
            }
            ReserveRemoteOperationOutcome::Replay(replay) if replay.state == "committed" => {
                Ok(TransactionalRemoteOperationOutcome::Replay(
                    replay
                        .safe_response
                        .context("committed operation missing safe response")?,
                ))
            }
            ReserveRemoteOperationOutcome::Replay(_) => {
                bail!("transactional remote operation is indeterminate")
            }
            ReserveRemoteOperationOutcome::OperationConflict => {
                Ok(TransactionalRemoteOperationOutcome::OperationConflict)
            }
            ReserveRemoteOperationOutcome::OperationActorConflict => {
                Ok(TransactionalRemoteOperationOutcome::OperationActorConflict)
            }
            ReserveRemoteOperationOutcome::AttachmentLedgerCapacity => {
                Ok(TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity)
            }
        })
        .await
    }

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
    if operation_reservation_at_capacity(row_count.try_into()?, response_bytes.try_into()?) {
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
    if response_would_exceed_capacity(response_bytes.try_into()?, request.safe_response.len()) {
        return Ok(CommitRemoteOperationOutcome::AttachmentLedgerCapacity);
    }
    let (event_count, payload_bytes, next_event_seq): (i64, i64, i64) = conn.query_row(
        "SELECT COUNT(*), COALESCE(SUM(length(canonical_payload)), 0),
                COALESCE(MAX(event_seq), 0) + 1
         FROM remote_attachment_outbox WHERE logical_attachment_id = ?1",
        [&request.logical_attachment_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if outbox_would_exceed_capacity(
        event_count.try_into()?,
        payload_bytes.try_into()?,
        request.outbox_payload.len(),
    ) {
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

    #[tokio::test]
    async fn transactional_executor_replays_conflicts_and_rolls_back_domain_failure() {
        let db = Db::open_in_memory().unwrap();
        let operation = "01890f3e-4c00-7000-8000-000000000099";
        let request = || ReserveRemoteOperation {
            logical_attachment_id: "00000000-0000-4000-8000-000000000001",
            operation_id: operation,
            authenticated_device_id: "00000000-0000-4000-8000-000000000002",
            authenticated_device_generation: 1,
            operation_class: RemoteOperationClass::TransactionalMutation,
            request_hash: [9; 32],
            now_ms: 1,
        };
        let applied = db
            .execute_transactional_remote_operation(request(), |conn| {
                Db::mark_app_flag_seen_versioned_conn(conn, "daemon-autostart", 0)?;
                Ok(TransactionalRemoteMutation {
                    value: 1_u8,
                    safe_response: b"one".to_vec(),
                    outbox_kind: "test".into(),
                    outbox_payload: b"one".to_vec(),
                })
            })
            .await
            .unwrap();
        assert!(matches!(
            applied,
            TransactionalRemoteOperationOutcome::Applied(1)
        ));
        let replay = db
            .execute_transactional_remote_operation(request(), |_| {
                panic!("replay must not execute domain closure")
            })
            .await
            .unwrap();
        assert_eq!(
            replay,
            TransactionalRemoteOperationOutcome::Replay(b"one".to_vec())
        );
        let mut changed = request();
        changed.request_hash = [8; 32];
        assert!(matches!(
            db.execute_transactional_remote_operation(changed, |_| panic!(
                "conflict must not execute domain closure"
            ))
            .await
            .unwrap(),
            TransactionalRemoteOperationOutcome::OperationConflict
        ));

        let failed_operation = "01890f3e-4c00-7000-8000-000000000098";
        let mut failed = request();
        failed.operation_id = failed_operation;
        failed.request_hash = [7; 32];
        assert!(
            db.execute_transactional_remote_operation::<(), _>(failed, |conn| {
                conn.execute(
                    "INSERT INTO app_flags(key,seen_at) VALUES ('rollback-test',1)",
                    [],
                )?;
                anyhow::bail!("injected crash")
            })
            .await
            .is_err()
        );
        assert_eq!(
            db.read(|conn| Db::app_flag_version_conn(conn, "rollback-test"))
                .await
                .unwrap(),
            0
        );
        let mut retry = request();
        retry.operation_id = failed_operation;
        retry.request_hash = [7; 32];
        let retried = db
            .execute_transactional_remote_operation(retry, |conn| {
                Db::mark_app_flag_seen_versioned_conn(conn, "rollback-test", 0)?;
                Ok(TransactionalRemoteMutation {
                    value: 2_u8,
                    safe_response: b"two".to_vec(),
                    outbox_kind: "test".into(),
                    outbox_payload: b"two".to_vec(),
                })
            })
            .await
            .unwrap();
        assert_eq!(retried, TransactionalRemoteOperationOutcome::Applied(2));

        let mut wrong_class = request();
        wrong_class.operation_id = "01890f3e-4c00-7000-8000-000000000097";
        wrong_class.operation_class = RemoteOperationClass::IdempotentAdapterMutation;
        assert!(
            db.execute_transactional_remote_operation::<(), _>(wrong_class, |_| {
                panic!("wrong-class operation must not execute domain closure")
            })
            .await
            .unwrap_err()
            .to_string()
            .contains("requires transactional_mutation class")
        );
    }

    #[tokio::test]
    async fn committed_goal_clear_survives_reopen_before_wake_and_replays() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("goal-wake-crash.db");
        let db = Db::open(&path).unwrap();
        let session = db.create_session("p", "/repo", "Build").await.unwrap();
        let session_id = session.session_id;
        db.create_session_goal(session.session_id, "p", "finish", None, Some(100))
            .await
            .unwrap();
        let request = || ReserveRemoteOperation {
            logical_attachment_id: "00000000-0000-4000-8000-000000000011",
            operation_id: "01890f3e-4c00-7000-8000-000000000096",
            authenticated_device_id: "00000000-0000-4000-8000-000000000012",
            authenticated_device_generation: 1,
            operation_class: RemoteOperationClass::TransactionalMutation,
            request_hash: [6; 32],
            now_ms: 1,
        };
        let applied = db
            .execute_transactional_remote_operation(request(), move |conn| {
                assert!(Db::clear_session_goal_conn(conn, session_id)?);
                Ok(TransactionalRemoteMutation {
                    value: (),
                    safe_response: b"cleared".to_vec(),
                    outbox_kind: "clear_goal".into(),
                    outbox_payload: b"cleared".to_vec(),
                })
            })
            .await
            .unwrap();
        assert_eq!(applied, TransactionalRemoteOperationOutcome::Applied(()));

        // Simulate process loss after commit and before the in-memory WakeGoal.
        drop(db);
        let reopened = Db::open(&path).unwrap();
        assert!(
            reopened
                .current_session_goal(session_id, false)
                .await
                .unwrap()
                .is_none()
        );
        let replay = reopened
            .execute_transactional_remote_operation(request(), |_| {
                panic!("reopen replay must not repeat goal transition")
            })
            .await
            .unwrap();
        assert_eq!(
            replay,
            TransactionalRemoteOperationOutcome::Replay(b"cleared".to_vec())
        );
    }

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
        let mut overflow = reserve("01890f3e-4c00-7000-8000-000000000009", [1; 32]);
        overflow.authenticated_device_generation = u64::MAX;
        assert!(
            db.reserve_remote_attachment_operation(overflow)
                .await
                .is_err()
        );
    }

    #[test]
    fn exact_capacity_boundaries_are_inclusive_without_large_allocations() {
        assert!(!operation_reservation_at_capacity(99_999, 536_870_911));
        assert!(operation_reservation_at_capacity(100_000, 0));
        assert!(operation_reservation_at_capacity(0, 536_870_912));
        assert!(!response_would_exceed_capacity(536_870_911, 1));
        assert!(response_would_exceed_capacity(536_870_912, 1));
        assert!(!outbox_would_exceed_capacity(199_999, 2_147_483_647, 1));
        assert!(outbox_would_exceed_capacity(200_000, 0, 0));
        assert!(outbox_would_exceed_capacity(0, 2_147_483_648, 1));
        let schema = include_str!("migrations/0001_initial.sql");
        for required in [
            "remote_attachment_operation_capacity_insert",
            "remote_attachment_operation_response_capacity",
            "remote_attachment_outbox_capacity_insert",
            ">= 100000",
            "> 536870912",
            ">= 200000",
            "> 2147483648",
        ] {
            assert!(
                schema.contains(required),
                "missing schema bound: {required}"
            );
        }
    }

    #[test]
    fn lowered_limit_trigger_fixture_proves_count_and_aggregate_byte_behavior() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE ops (attachment TEXT NOT NULL, response BLOB);
             CREATE TRIGGER ops_rows BEFORE INSERT ON ops
             WHEN (SELECT COUNT(*) FROM ops WHERE attachment = NEW.attachment) >= 2
             BEGIN SELECT RAISE(ABORT, 'attachment_ledger_capacity'); END;
             CREATE TRIGGER ops_bytes BEFORE UPDATE OF response ON ops
             WHEN (SELECT COALESCE(SUM(length(response)), 0) FROM ops WHERE attachment = NEW.attachment)
                  - COALESCE(length(OLD.response), 0) + COALESCE(length(NEW.response), 0) > 8
             BEGIN SELECT RAISE(ABORT, 'attachment_ledger_capacity'); END;
             CREATE TABLE events (attachment TEXT NOT NULL, payload BLOB NOT NULL);
             CREATE TRIGGER event_cap BEFORE INSERT ON events
             WHEN (SELECT COUNT(*) FROM events WHERE attachment = NEW.attachment) >= 2
               OR (SELECT COALESCE(SUM(length(payload)), 0) FROM events WHERE attachment = NEW.attachment)
                  + length(NEW.payload) > 8
             BEGIN SELECT RAISE(ABORT, 'attachment_outbox_capacity'); END;",
        )
        .unwrap();
        conn.execute("INSERT INTO ops VALUES ('a', NULL)", [])
            .unwrap();
        conn.execute("INSERT INTO ops VALUES ('a', NULL)", [])
            .unwrap();
        assert!(
            conn.execute("INSERT INTO ops VALUES ('a', NULL)", [])
                .is_err()
        );
        conn.execute("UPDATE ops SET response = zeroblob(4) WHERE rowid = 1", [])
            .unwrap();
        conn.execute("UPDATE ops SET response = zeroblob(4) WHERE rowid = 2", [])
            .unwrap();
        assert!(
            conn.execute("UPDATE ops SET response = zeroblob(5) WHERE rowid = 2", [])
                .is_err()
        );
        conn.execute("INSERT INTO events VALUES ('a', zeroblob(4))", [])
            .unwrap();
        conn.execute("INSERT INTO events VALUES ('a', zeroblob(4))", [])
            .unwrap();
        assert!(
            conn.execute("INSERT INTO events VALUES ('a', zeroblob(1))", [])
                .is_err()
        );
    }

    #[tokio::test]
    async fn commit_rejects_single_response_and_event_over_512_kib() {
        let db = Db::open_in_memory().unwrap();
        let operation = "01890f3e-4c00-7000-8000-000000000098";
        db.reserve_remote_attachment_operation(reserve(operation, [8; 32]))
            .await
            .unwrap();
        let oversized = vec![0_u8; MAX_SAFE_RESPONSE_BYTES + 1];
        assert!(
            db.commit_remote_attachment_operation(CommitRemoteOperation {
                logical_attachment_id: ATTACHMENT,
                operation_id: operation,
                safe_response: &oversized,
                outbox_delivery_id: "00000000-0000-4000-8000-000000000098",
                outbox_kind: "oversized",
                outbox_payload: b"event",
                now_ms: 2,
            })
            .await
            .is_err()
        );
        assert!(
            db.commit_remote_attachment_operation(CommitRemoteOperation {
                logical_attachment_id: ATTACHMENT,
                operation_id: operation,
                safe_response: b"safe",
                outbox_delivery_id: "00000000-0000-4000-8000-000000000098",
                outbox_kind: "oversized",
                outbox_payload: &oversized,
                now_ms: 2,
            })
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn schema_rejects_malformed_nil_wrong_version_and_extra_hyphen_ids() {
        for (index, operation_id) in [
            "00000000-0000-0000-0000-000000000000",
            "01890f3e-4c00-4000-8000-000000000001",
            "01890f3e-4c00-7000-8000-00000-000001",
        ]
        .into_iter()
        .enumerate()
        {
            let db = Db::open_in_memory().unwrap();
            let operation_id = operation_id.to_owned();
            assert!(
                db.write(move |conn| {
                    conn.execute(
                        "INSERT INTO remote_attachment_operations
                         (logical_attachment_id, operation_id, authenticated_device_id,
                          authenticated_device_generation, operation_seq, operation_class,
                          state, request_hash, created_at_ms, updated_at_ms)
                         VALUES (?1, ?2, ?3, 1, ?4, 'transactional_mutation',
                                 'reserved', zeroblob(32), 1, 1)",
                        params![ATTACHMENT, operation_id, DEVICE, index as i64 + 1],
                    )?;
                    Ok(())
                })
                .await
                .is_err(),
                "schema accepted malformed operation id at case {index}"
            );
        }

        for (attachment, device) in [
            ("00000000-0000-0000-0000-000000000000", DEVICE),
            (ATTACHMENT, "00000000-0000-0000-0000-000000000000"),
            (ATTACHMENT, "00000000-0000-4000-7000-000000000002"),
        ] {
            let db = Db::open_in_memory().unwrap();
            let attachment = attachment.to_owned();
            let device = device.to_owned();
            assert!(
                db.write(move |conn| {
                    conn.execute(
                        "INSERT INTO remote_attachment_operations
                         (logical_attachment_id, operation_id, authenticated_device_id,
                          authenticated_device_generation, operation_seq, operation_class,
                          state, request_hash, created_at_ms, updated_at_ms)
                         VALUES (?1, '01890f3e-4c00-7000-8000-000000000099', ?2, 1, 1,
                                 'transactional_mutation', 'reserved', zeroblob(32), 1, 1)",
                        params![attachment, device],
                    )?;
                    Ok(())
                })
                .await
                .is_err()
            );
        }
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
    async fn direct_sql_guards_every_operation_and_outbox_mutation_axis() {
        let db = Db::open_in_memory().unwrap();
        let operation = "01890f3e-4c00-7000-8000-000000000030";
        let reserved_operation = "01890f3e-4c00-7000-8000-000000000032";
        db.reserve_remote_attachment_operation(reserve(operation, [3; 32]))
            .await
            .unwrap();
        db.reserve_remote_attachment_operation(reserve(reserved_operation, [4; 32]))
            .await
            .unwrap();
        db.commit_remote_attachment_operation(CommitRemoteOperation {
            logical_attachment_id: ATTACHMENT,
            operation_id: operation,
            safe_response: b"original",
            outbox_delivery_id: "00000000-0000-4000-8000-000000000031",
            outbox_kind: "committed",
            outbox_payload: b"event",
            now_ms: 20,
        })
        .await
        .unwrap();
        let attachment = ATTACHMENT.to_owned();
        let operation = operation.to_owned();
        let reserved_operation = reserved_operation.to_owned();
        db.write(move |conn| {
            let operation_updates = [
                "authenticated_device_id = '00000000-0000-4000-8000-000000000099'",
                "request_hash = zeroblob(32)",
                "operation_class = 'nonrepeatable_mutation'",
                "operation_seq = 2",
                "dispatch_generation = -1",
                "updated_at_ms = 19",
                "event_high_water_mark = 0",
                "safe_response = X'02'",
                "safe_response = NULL",
            ];
            for assignment in operation_updates {
                let sql = format!(
                    "UPDATE remote_attachment_operations SET {assignment}
                     WHERE logical_attachment_id = ?1 AND operation_id = ?2"
                );
                assert!(
                    conn.execute(&sql, params![attachment, operation]).is_err(),
                    "guard accepted {assignment}"
                );
            }
            conn.execute(
                "UPDATE remote_attachment_operations SET dispatch_generation = 2, updated_at_ms = 21
                 WHERE logical_attachment_id = ?1 AND operation_id = ?2",
                params![attachment, reserved_operation],
            )?;
            assert!(conn.execute(
                "UPDATE remote_attachment_operations SET dispatch_generation = 1, updated_at_ms = 22
                 WHERE logical_attachment_id = ?1 AND operation_id = ?2",
                params![attachment, reserved_operation],
            ).is_err());
            conn.execute(
                "UPDATE remote_attachment_operations SET retire_at_ms = 100
                 WHERE logical_attachment_id = ?1 AND operation_id = ?2",
                params![attachment, operation],
            )?;
            for retire in ["retire_at_ms = NULL", "retire_at_ms = 101"] {
                let sql = format!(
                    "UPDATE remote_attachment_operations SET {retire}
                     WHERE logical_attachment_id = ?1 AND operation_id = ?2"
                );
                assert!(conn.execute(&sql, params![attachment, operation]).is_err());
            }
            assert!(
                conn.execute(
                    "UPDATE remote_attachment_outbox SET kind = 'changed'
                 WHERE logical_attachment_id = ?1 AND event_seq = 1",
                    [&attachment],
                )
                .is_err()
            );
            assert!(
                conn.execute(
                    "DELETE FROM remote_attachment_outbox
                 WHERE logical_attachment_id = ?1 AND event_seq = 1",
                    [&attachment],
                )
                .is_err()
            );
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn outbox_compaction_requires_snapshot_cursor_and_releases_operation_fk() {
        let db = Db::open_in_memory().unwrap();
        let operation = "01890f3e-4c00-7000-8000-000000000040";
        db.reserve_remote_attachment_operation(reserve(operation, [5; 32]))
            .await
            .unwrap();
        db.commit_remote_attachment_operation(CommitRemoteOperation {
            logical_attachment_id: ATTACHMENT,
            operation_id: operation,
            safe_response: b"committed",
            outbox_delivery_id: "00000000-0000-4000-8000-000000000041",
            outbox_kind: "committed",
            outbox_payload: b"event",
            now_ms: 30,
        })
        .await
        .unwrap();
        let attachment = ATTACHMENT.to_owned();
        assert!(
            db.write(move |conn| {
                conn.execute(
                    "DELETE FROM remote_attachment_outbox
                     WHERE logical_attachment_id = ?1 AND event_seq = 1",
                    [&attachment],
                )?;
                Ok(())
            })
            .await
            .is_err(),
            "an event without snapshot authority must not compact"
        );
        let attachment = ATTACHMENT.to_owned();
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO remote_attachment_outbox_snapshots
                 (logical_attachment_id, compacted_through_event_seq,
                  snapshot_high_water_mark, updated_at_ms) VALUES (?1, 0, 1, 31)",
                [&attachment],
            )?;
            assert!(
                conn.execute(
                    "DELETE FROM remote_attachment_outbox
                     WHERE logical_attachment_id = ?1 AND event_seq = 1",
                    [&attachment],
                )
                .is_err(),
                "an event above the cursor must not compact"
            );
            conn.execute(
                "UPDATE remote_attachment_outbox_snapshots
                 SET compacted_through_event_seq = 1, updated_at_ms = 32
                 WHERE logical_attachment_id = ?1",
                [&attachment],
            )?;
            conn.execute(
                "DELETE FROM remote_attachment_outbox
                 WHERE logical_attachment_id = ?1 AND event_seq = 1",
                [&attachment],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        let attachment = ATTACHMENT.to_owned();
        let operation = operation.to_owned();
        db.write(move |conn| {
            conn.execute(
                "DELETE FROM remote_attachment_operations
                 WHERE logical_attachment_id = ?1 AND operation_id = ?2",
                params![attachment, operation],
            )?;
            Ok(())
        })
        .await
        .expect("snapshot-authorized event deletion must release the operation FK");
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
