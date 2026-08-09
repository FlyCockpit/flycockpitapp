//! Durable per-attachment operation reservation and replay metadata.
//!
//! This module intentionally accepts only bounded identifiers, digests, and
//! safe response bytes. Canonical request bytes, credentials, grants, and
//! transport metadata have no representation here.

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};

use crate::db::Db;

pub const MAX_OPERATION_ROWS_PER_ATTACHMENT: u64 = 100_000;
pub const MAX_SAFE_RESPONSE_BYTES_PER_ATTACHMENT: u64 = 512 * 1024 * 1024;
pub const MAX_SAFE_RESPONSE_BYTES: usize = 512 * 1024;

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
    if request.logical_attachment_id.is_empty()
        || request.operation_id.is_empty()
        || request.authenticated_device_id.is_empty()
    {
        bail!("remote operation identifiers must not be empty");
    }
    let actor_generation = i64::try_from(request.authenticated_device_generation)
        .context("device generation exceeds SQLite INTEGER")?;
    let existing = conn
        .query_row(
            "SELECT authenticated_device_id, authenticated_device_generation, request_hash,
                    operation_seq, state, safe_response, event_high_water_mark
             FROM remote_attachment_operations
             WHERE logical_attachment_id = ?1 AND operation_id = ?2",
            params![request.logical_attachment_id, request.operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            },
        )
        .optional()
        .context("looking up remote operation reservation")?;
    if let Some((device_id, generation, hash, seq, state, response, high_water)) = existing {
        if device_id != request.authenticated_device_id || generation != actor_generation {
            return Ok(ReserveRemoteOperationOutcome::OperationActorConflict);
        }
        if hash.as_slice() != request.request_hash {
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
