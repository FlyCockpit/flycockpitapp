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
pub const REMOTE_ATTACHMENT_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1_000;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginNonrepeatableRemoteOperationOutcome {
    Dispatch {
        operation_seq: u64,
        dispatch_generation: u64,
    },
    Replay(Vec<u8>),
    OutcomeUnknown(Vec<u8>),
    OperationConflict,
    OperationActorConflict,
    AttachmentLedgerCapacity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginIdempotentAdapterRemoteOperationOutcome {
    Dispatch {
        operation_seq: u64,
        dispatch_generation: u64,
    },
    Replay(Vec<u8>),
    OperationConflict,
    OperationActorConflict,
    AttachmentLedgerCapacity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRenameEvidence {
    pub artifact_id: String,
    pub dispatch_generation: u64,
    pub state: String,
    pub source_identity: RemoteFilesystemIdentityV1,
    pub source_parent_identity: RemoteFilesystemIdentityV1,
    pub target_parent_identity: RemoteFilesystemIdentityV1,
    pub observed_target_identity: Option<RemoteFilesystemIdentityV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRenameArtifactCleanupIntent {
    pub logical_attachment_id: String,
    pub operation_id: String,
    pub artifact_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareRemoteRenameOutcome {
    Prepared(RemoteRenameEvidence),
    Reconcile(RemoteRenameEvidence),
    Replay(Vec<u8>),
    OutcomeUnknown(Vec<u8>),
    OperationConflict,
    OperationActorConflict,
    AttachmentLedgerCapacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteFilesystemIdentityV1 {
    pub filesystem_id: u64,
    pub object_id: u128,
    pub kind: u8,
    pub len: u64,
    pub mode: u32,
    pub owner_id: u64,
    pub link_count: u64,
}

impl RemoteFilesystemIdentityV1 {
    pub const ENCODED_LEN: usize = 57;
    pub fn encode(self) -> Result<[u8; Self::ENCODED_LEN]> {
        self.validate()?;
        let mut out = [0; Self::ENCODED_LEN];
        out[..4].copy_from_slice(b"RFI1");
        out[4..12].copy_from_slice(&self.filesystem_id.to_be_bytes());
        out[12..28].copy_from_slice(&self.object_id.to_be_bytes());
        out[28] = self.kind;
        out[29..37].copy_from_slice(&self.len.to_be_bytes());
        out[37..41].copy_from_slice(&self.mode.to_be_bytes());
        out[41..49].copy_from_slice(&self.owner_id.to_be_bytes());
        out[49..57].copy_from_slice(&self.link_count.to_be_bytes());
        Ok(out)
    }
    fn validate(self) -> Result<()> {
        ensure!(
            matches!(self.kind, 1 | 2),
            "invalid remote filesystem identity kind"
        );
        ensure!(
            self.link_count > 0,
            "remote filesystem identity has no links"
        );
        let mode_kind = self.mode & 0o170000;
        ensure!(
            (self.kind == 1 && mode_kind == 0o100000) || (self.kind == 2 && mode_kind == 0o040000),
            "remote filesystem identity kind and mode disagree"
        );
        Ok(())
    }
    pub fn decode(value: &[u8]) -> Result<Self> {
        ensure!(
            value.len() == Self::ENCODED_LEN && &value[..4] == b"RFI1",
            "invalid remote filesystem identity codec"
        );
        let array =
            |range: std::ops::Range<usize>| -> Result<[u8; 8]> { Ok(value[range].try_into()?) };
        let decoded = Self {
            filesystem_id: u64::from_be_bytes(array(4..12)?),
            object_id: u128::from_be_bytes(value[12..28].try_into()?),
            kind: value[28],
            len: u64::from_be_bytes(array(29..37)?),
            mode: u32::from_be_bytes(value[37..41].try_into()?),
            owner_id: u64::from_be_bytes(array(41..49)?),
            link_count: u64::from_be_bytes(array(49..57)?),
        };
        decoded.validate()?;
        Ok(decoded)
    }
}

pub struct TransactionalRemoteMutation<T> {
    pub value: T,
    pub safe_response: Vec<u8>,
    pub outbox_kind: String,
    pub outbox_payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteOutboxDeliveryLease {
    pub logical_attachment_id: String,
    pub event_seq: u64,
    pub delivery_id: String,
    pub kind: String,
    pub canonical_payload: Vec<u8>,
    pub lease_id: String,
    pub attempts: u32,
    pub lease_expires_at_ms: i64,
}

impl Db {
    pub async fn remote_rename_artifact_cleanup_intents(
        &self,
    ) -> Result<Vec<RemoteRenameArtifactCleanupIntent>> {
        self.read(|conn| {
            let mut statement = conn.prepare("SELECT logical_attachment_id,operation_id,artifact_id FROM remote_rename_artifact_cleanup_intents ORDER BY created_at_ms,operation_id")?;
            Ok(statement
                .query_map([], |row| Ok(RemoteRenameArtifactCleanupIntent {
                    logical_attachment_id: row.get(0)?,
                    operation_id: row.get(1)?,
                    artifact_id: row.get(2)?,
                }))?
                .collect::<std::result::Result<Vec<_>, _>>()?)
        }).await
    }

    pub async fn complete_remote_rename_artifact_cleanup(
        &self,
        logical_attachment_id: &str,
        operation_id: &str,
        artifact_id: &str,
    ) -> Result<bool> {
        validate_uuid("logical attachment id", logical_attachment_id)?;
        validate_operation_id(operation_id)?;
        validate_uuid("rename artifact id", artifact_id)?;
        let attachment = logical_attachment_id.to_owned();
        let operation = operation_id.to_owned();
        let artifact = artifact_id.to_owned();
        self.transaction(move |conn| Ok(conn.execute(
            "DELETE FROM remote_rename_artifact_cleanup_intents WHERE logical_attachment_id=?1 AND operation_id=?2 AND artifact_id=?3",
            params![attachment,operation,artifact],
        )? == 1)).await
    }

    pub async fn remote_rename_evidence(
        &self,
        logical_attachment_id: &str,
        operation_id: &str,
    ) -> Result<RemoteRenameEvidence> {
        validate_uuid("logical attachment id", logical_attachment_id)?;
        validate_operation_id(operation_id)?;
        let attachment = logical_attachment_id.to_owned();
        let operation = operation_id.to_owned();
        self.read(move |conn| load_remote_rename_evidence(conn, &attachment, &operation))
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_remote_rename_operation(
        &self,
        request: ReserveRemoteOperation<'_>,
        source_identity: Option<RemoteFilesystemIdentityV1>,
        source_parent_identity: Option<RemoteFilesystemIdentityV1>,
        target_parent_identity: Option<RemoteFilesystemIdentityV1>,
    ) -> Result<PrepareRemoteRenameOutcome> {
        ensure!(
            request.operation_class == RemoteOperationClass::IdempotentAdapterMutation,
            "remote rename requires adapter class"
        );
        for parent in [source_parent_identity, target_parent_identity]
            .into_iter()
            .flatten()
        {
            ensure!(
                parent.kind == 2,
                "remote rename parent identity must be a directory"
            );
        }
        let owned = OwnedReserveRemoteOperation {
            logical_attachment_id: request.logical_attachment_id.into(),
            operation_id: request.operation_id.into(),
            authenticated_device_id: request.authenticated_device_id.into(),
            authenticated_device_generation: request.authenticated_device_generation,
            operation_class: request.operation_class,
            request_hash: request.request_hash,
            now_ms: request.now_ms,
        };
        let source = source_identity
            .map(RemoteFilesystemIdentityV1::encode)
            .transpose()?;
        let source_parent = source_parent_identity
            .map(RemoteFilesystemIdentityV1::encode)
            .transpose()?;
        let target_parent = target_parent_identity
            .map(RemoteFilesystemIdentityV1::encode)
            .transpose()?;
        self.transaction(move |conn| match reserve_conn(conn,&owned)? {
            ReserveRemoteOperationOutcome::Reserved(_) => {
                let source=source.context("new rename lacks source identity")?;
                let source_parent=source_parent.context("new rename lacks source parent identity")?;
                let target_parent=target_parent.context("new rename lacks target parent identity")?;
                let artifact=Uuid::now_v7().to_string();
                conn.execute("UPDATE remote_attachment_operations SET state='dispatched',operation_kind='staged_rename',dispatch_generation=1 WHERE logical_attachment_id=?1 AND operation_id=?2 AND state='reserved'",params![owned.logical_attachment_id,owned.operation_id])?;
                conn.execute("INSERT INTO remote_rename_journal(logical_attachment_id,operation_id,artifact_id,source_identity,source_parent_identity,target_parent_identity,dispatch_generation,state,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,?5,?6,1,'prepared',?7,?7)",params![owned.logical_attachment_id,owned.operation_id,artifact,source,source_parent,target_parent,owned.now_ms])?;
                Ok(PrepareRemoteRenameOutcome::Prepared(load_remote_rename_evidence(conn,&owned.logical_attachment_id,&owned.operation_id)?))
            }
            ReserveRemoteOperationOutcome::Replay(replay) if replay.state=="committed" => Ok(PrepareRemoteRenameOutcome::Replay(replay.safe_response.context("committed rename lacks response")?)),
            ReserveRemoteOperationOutcome::Replay(replay) if replay.state=="dispatched" => {
                let stored=load_remote_rename_evidence(conn,&owned.logical_attachment_id,&owned.operation_id)?;
                let next:i64=conn.query_row("UPDATE remote_attachment_operations SET dispatch_generation=dispatch_generation+1,updated_at_ms=MAX(updated_at_ms,?3) WHERE logical_attachment_id=?1 AND operation_id=?2 AND dispatch_generation=?4 RETURNING dispatch_generation",params![owned.logical_attachment_id,owned.operation_id,owned.now_ms,i64::try_from(stored.dispatch_generation)?],|row|row.get(0))?;
                let changed=conn.execute("UPDATE remote_rename_journal SET dispatch_generation=?3,updated_at_ms=MAX(updated_at_ms,?4) WHERE logical_attachment_id=?1 AND operation_id=?2 AND dispatch_generation=?5",params![owned.logical_attachment_id,owned.operation_id,next,owned.now_ms,i64::try_from(stored.dispatch_generation)?])?;
                ensure!(changed==1,"rename journal generation CAS lost");
                Ok(PrepareRemoteRenameOutcome::Reconcile(load_remote_rename_evidence(conn,&owned.logical_attachment_id,&owned.operation_id)?))
            }
            ReserveRemoteOperationOutcome::Replay(replay) if replay.state=="outcome_unknown" => Ok(PrepareRemoteRenameOutcome::OutcomeUnknown(replay.safe_response.context("outcome-unknown rename lacks response")?)),
            ReserveRemoteOperationOutcome::Replay(_)=>bail!("invalid remote rename state"),
            ReserveRemoteOperationOutcome::OperationConflict=>Ok(PrepareRemoteRenameOutcome::OperationConflict),
            ReserveRemoteOperationOutcome::OperationActorConflict=>Ok(PrepareRemoteRenameOutcome::OperationActorConflict),
            ReserveRemoteOperationOutcome::AttachmentLedgerCapacity=>Ok(PrepareRemoteRenameOutcome::AttachmentLedgerCapacity),
        }).await
    }

    pub async fn advance_remote_rename_operation(
        &self,
        logical_attachment_id: &str,
        operation_id: &str,
        dispatch_generation: u64,
        from: &str,
        to: &str,
        now_ms: i64,
    ) -> Result<bool> {
        validate_uuid("logical attachment id", logical_attachment_id)?;
        validate_operation_id(operation_id)?;
        ensure!(
            matches!(
                (from, to),
                ("prepared", "artifact_synced")
                    | ("artifact_synced", "renamed")
                    | ("renamed", "source_parent_synced")
                    | ("source_parent_synced", "target_parent_synced")
                    | ("target_parent_synced", "applied")
            ),
            "invalid rename barrier"
        );
        let attachment = logical_attachment_id.to_owned();
        let operation = operation_id.to_owned();
        let from = from.to_owned();
        let to = to.to_owned();
        let generation = i64::try_from(dispatch_generation)?;
        self.transaction(move|conn|Ok(conn.execute("UPDATE remote_rename_journal SET state=?5,updated_at_ms=?6 WHERE logical_attachment_id=?1 AND operation_id=?2 AND dispatch_generation=?3 AND state=?4",params![attachment,operation,generation,from,to,now_ms])?==1)).await
    }

    pub async fn record_remote_rename_applied_mismatch(
        &self,
        logical_attachment_id: &str,
        operation_id: &str,
        dispatch_generation: u64,
        observed_target_identity: RemoteFilesystemIdentityV1,
        safe_response: &[u8],
        now_ms: i64,
    ) -> Result<bool> {
        validate_uuid("logical attachment id", logical_attachment_id)?;
        validate_operation_id(operation_id)?;
        ensure!(
            !safe_response.is_empty() && safe_response.len() <= MAX_SAFE_RESPONSE_BYTES,
            "rename mismatch response must be bounded and nonempty"
        );
        let attachment = logical_attachment_id.to_owned();
        let operation = operation_id.to_owned();
        let generation = i64::try_from(dispatch_generation)?;
        let observed = observed_target_identity.encode()?.to_vec();
        let response = safe_response.to_vec();
        self.transaction(move |conn| {
            let journal = conn.execute(
                "UPDATE remote_rename_journal SET state='applied_mismatch',observed_target_identity=?4,updated_at_ms=?5 WHERE logical_attachment_id=?1 AND operation_id=?2 AND dispatch_generation=?3 AND state='artifact_synced'",
                params![attachment, operation, generation, observed, now_ms],
            )?;
            ensure!(journal == 1, "rename mismatch requires artifact-synced expected generation");
            let operation_changed = conn.execute(
                "UPDATE remote_attachment_operations SET state='outcome_unknown',safe_response=?4,updated_at_ms=?5 WHERE logical_attachment_id=?1 AND operation_id=?2 AND dispatch_generation=?3 AND operation_kind='staged_rename' AND state='dispatched'",
                params![attachment, operation, generation, response, now_ms],
            )?;
            ensure!(operation_changed == 1, "rename mismatch lost operation generation authority");
            conn.execute("INSERT OR IGNORE INTO remote_rename_artifact_cleanup_intents(logical_attachment_id,operation_id,artifact_id,created_at_ms) SELECT logical_attachment_id,operation_id,artifact_id,?3 FROM remote_rename_journal WHERE logical_attachment_id=?1 AND operation_id=?2",params![attachment,operation,now_ms])?;
            Ok(true)
        }).await
    }

    pub async fn record_remote_rename_effect_unknown(
        &self,
        logical_attachment_id: &str,
        operation_id: &str,
        dispatch_generation: u64,
        safe_response: &[u8],
        now_ms: i64,
    ) -> Result<bool> {
        validate_uuid("logical attachment id", logical_attachment_id)?;
        validate_operation_id(operation_id)?;
        ensure!(
            !safe_response.is_empty() && safe_response.len() <= MAX_SAFE_RESPONSE_BYTES,
            "rename unknown response must be bounded and nonempty"
        );
        let attachment = logical_attachment_id.to_owned();
        let operation = operation_id.to_owned();
        let generation = i64::try_from(dispatch_generation)?;
        let response = safe_response.to_vec();
        self.transaction(move |conn| {
            let journal = conn.execute(
                "UPDATE remote_rename_journal SET state='effect_unknown',updated_at_ms=?4 WHERE logical_attachment_id=?1 AND operation_id=?2 AND dispatch_generation=?3 AND state IN ('prepared','artifact_synced','renamed','source_parent_synced','target_parent_synced')",
                params![attachment, operation, generation, now_ms],
            )?;
            ensure!(journal == 1, "rename unknown requires artifact-synced expected generation");
            let operation_changed = conn.execute(
                "UPDATE remote_attachment_operations SET state='outcome_unknown',safe_response=?4,updated_at_ms=?5 WHERE logical_attachment_id=?1 AND operation_id=?2 AND dispatch_generation=?3 AND operation_kind='staged_rename' AND state='dispatched'",
                params![attachment, operation, generation, response, now_ms],
            )?;
            ensure!(operation_changed == 1, "rename unknown lost operation generation authority");
            conn.execute("INSERT OR IGNORE INTO remote_rename_artifact_cleanup_intents(logical_attachment_id,operation_id,artifact_id,created_at_ms) SELECT logical_attachment_id,operation_id,artifact_id,?3 FROM remote_rename_journal WHERE logical_attachment_id=?1 AND operation_id=?2",params![attachment,operation,now_ms])?;
            Ok(true)
        }).await
    }
    /// Reserves an adapter effect before dispatch. A process restart may claim
    /// the same immutable request again with a higher dispatch generation;
    /// the adapter's durable evidence decides whether to finish or reconcile.
    pub async fn begin_idempotent_adapter_remote_operation(
        &self,
        request: ReserveRemoteOperation<'_>,
    ) -> Result<BeginIdempotentAdapterRemoteOperationOutcome> {
        ensure!(
            request.operation_class == RemoteOperationClass::IdempotentAdapterMutation,
            "adapter dispatcher requires idempotent_adapter_mutation class"
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
            ReserveRemoteOperationOutcome::Reserved(reservation) => {
                conn.execute(
                    "UPDATE remote_attachment_operations
                     SET state='dispatched', dispatch_generation=1, updated_at_ms=?3
                     WHERE logical_attachment_id=?1 AND operation_id=?2 AND state='reserved'",
                    params![
                        owned.logical_attachment_id,
                        owned.operation_id,
                        owned.now_ms
                    ],
                )?;
                Ok(BeginIdempotentAdapterRemoteOperationOutcome::Dispatch {
                    operation_seq: reservation.operation_seq,
                    dispatch_generation: 1,
                })
            }
            ReserveRemoteOperationOutcome::Replay(replay) if replay.state == "committed" => {
                Ok(BeginIdempotentAdapterRemoteOperationOutcome::Replay(
                    replay
                        .safe_response
                        .context("committed operation missing safe response")?,
                ))
            }
            ReserveRemoteOperationOutcome::Replay(replay) if replay.state == "dispatched" => {
                let generation: i64 = conn.query_row(
                    "UPDATE remote_attachment_operations
                     SET dispatch_generation=dispatch_generation+1, updated_at_ms=?3
                     WHERE logical_attachment_id=?1 AND operation_id=?2 AND state='dispatched'
                     RETURNING dispatch_generation",
                    params![
                        owned.logical_attachment_id,
                        owned.operation_id,
                        owned.now_ms
                    ],
                    |row| row.get(0),
                )?;
                Ok(BeginIdempotentAdapterRemoteOperationOutcome::Dispatch {
                    operation_seq: replay.operation_seq,
                    dispatch_generation: generation.try_into()?,
                })
            }
            ReserveRemoteOperationOutcome::Replay(_) => bail!("invalid adapter replay state"),
            ReserveRemoteOperationOutcome::OperationConflict => {
                Ok(BeginIdempotentAdapterRemoteOperationOutcome::OperationConflict)
            }
            ReserveRemoteOperationOutcome::OperationActorConflict => {
                Ok(BeginIdempotentAdapterRemoteOperationOutcome::OperationActorConflict)
            }
            ReserveRemoteOperationOutcome::AttachmentLedgerCapacity => {
                Ok(BeginIdempotentAdapterRemoteOperationOutcome::AttachmentLedgerCapacity)
            }
        })
        .await
    }

    /// Reserve and durably mark a nonrepeatable operation dispatched in one
    /// writer transaction. The caller may perform the external/in-memory
    /// effect only after receiving `Dispatch`.
    pub async fn begin_nonrepeatable_remote_operation(
        &self,
        request: ReserveRemoteOperation<'_>,
    ) -> Result<BeginNonrepeatableRemoteOperationOutcome> {
        ensure!(
            request.operation_class == RemoteOperationClass::NonrepeatableMutation,
            "nonrepeatable executor requires nonrepeatable_mutation class"
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
            ReserveRemoteOperationOutcome::Reserved(reservation) => {
                conn.execute(
                    "UPDATE remote_attachment_operations
                     SET state='dispatched', dispatch_generation=dispatch_generation+1, updated_at_ms=?3
                     WHERE logical_attachment_id=?1 AND operation_id=?2 AND state='reserved'",
                    params![owned.logical_attachment_id, owned.operation_id, owned.now_ms],
                )?;
                Ok(BeginNonrepeatableRemoteOperationOutcome::Dispatch {
                    operation_seq: reservation.operation_seq,
                    dispatch_generation: 1,
                })
            }
            ReserveRemoteOperationOutcome::Replay(replay) if replay.state == "committed" =>
                Ok(BeginNonrepeatableRemoteOperationOutcome::Replay(
                    replay.safe_response.context("committed operation missing safe response")?)),
            ReserveRemoteOperationOutcome::Replay(replay)
                if matches!(replay.state.as_str(), "dispatched" | "outcome_unknown") =>
                Ok(BeginNonrepeatableRemoteOperationOutcome::OutcomeUnknown(
                    replay.safe_response.unwrap_or_else(|| b"{\"outcome\":\"unknown\"}".to_vec()))),
            ReserveRemoteOperationOutcome::Replay(_) => bail!("invalid nonrepeatable replay state"),
            ReserveRemoteOperationOutcome::OperationConflict => Ok(BeginNonrepeatableRemoteOperationOutcome::OperationConflict),
            ReserveRemoteOperationOutcome::OperationActorConflict => Ok(BeginNonrepeatableRemoteOperationOutcome::OperationActorConflict),
            ReserveRemoteOperationOutcome::AttachmentLedgerCapacity => Ok(BeginNonrepeatableRemoteOperationOutcome::AttachmentLedgerCapacity),
        }).await
    }

    /// Recovery closes a dispatched operation without retrying its effect.
    pub async fn mark_nonrepeatable_remote_operation_outcome_unknown(
        &self,
        logical_attachment_id: &str,
        operation_id: &str,
        safe_response: &[u8],
        now_ms: i64,
    ) -> Result<bool> {
        ensure!(
            !safe_response.is_empty() && safe_response.len() <= MAX_SAFE_RESPONSE_BYTES,
            "outcome-unknown response must be bounded and nonempty"
        );
        validate_uuid("logical attachment id", logical_attachment_id)?;
        validate_operation_id(operation_id)?;
        let attachment = logical_attachment_id.to_owned();
        let operation = operation_id.to_owned();
        let response = safe_response.to_vec();
        self.transaction(move |conn| {
            let changed = conn.execute(
                "UPDATE remote_attachment_operations SET state='outcome_unknown', safe_response=?3, updated_at_ms=?4
                 WHERE logical_attachment_id=?1 AND operation_id=?2 AND state='dispatched' AND operation_class='nonrepeatable_mutation'",
                params![attachment, operation, response, now_ms],
            )?;
            Ok(changed == 1)
        }).await
    }

    pub async fn remote_operation_status(
        &self,
        logical_attachment_id: &str,
        operation_id: &str,
    ) -> Result<Option<RemoteOperationReservation>> {
        validate_uuid("logical attachment id", logical_attachment_id)?;
        validate_operation_id(operation_id)?;
        let attachment = logical_attachment_id.to_owned();
        let operation = operation_id.to_owned();
        self.read(move |conn| {
            conn.query_row(
                "SELECT operation_seq,state,safe_response,event_high_water_mark
                 FROM remote_attachment_operations
                 WHERE logical_attachment_id=?1 AND operation_id=?2",
                params![attachment, operation],
                |row| {
                    Ok(RemoteOperationReservation {
                        operation_seq: row.get::<_, i64>(0)? as u64,
                        state: row.get(1)?,
                        safe_response: row.get(2)?,
                        event_high_water_mark: row
                            .get::<_, Option<i64>>(3)?
                            .map(|value| value as u64),
                    })
                },
            )
            .optional()
            .context("querying remote operation status")
        })
        .await
    }

    /// Records the authoritative close instant once and schedules terminal
    /// operation rows for the mandatory thirty-day retention window.
    pub async fn close_remote_attachment_operation_ledger(
        &self,
        logical_attachment_id: &str,
        closed_at_ms: i64,
    ) -> Result<i64> {
        validate_uuid("logical attachment id", logical_attachment_id)?;
        ensure!(closed_at_ms >= 0, "close timestamp must be nonnegative");
        let retain_until_ms = closed_at_ms
            .checked_add(REMOTE_ATTACHMENT_RETENTION_MS)
            .context("remote attachment retention deadline overflow")?;
        let attachment = logical_attachment_id.to_owned();
        self.transaction(move |conn| {
            let existing: Option<(i64, i64)> = conn
                .query_row(
                    "SELECT closed_at_ms, retain_until_ms FROM remote_attachment_lifecycle
                     WHERE logical_attachment_id=?1",
                    [&attachment],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some(existing) = existing {
                ensure!(
                    existing == (closed_at_ms, retain_until_ms),
                    "remote attachment already closed at a different instant"
                );
                return Ok(retain_until_ms);
            }
            conn.execute(
                "INSERT INTO remote_attachment_lifecycle
                 (logical_attachment_id, closed_at_ms, retain_until_ms) VALUES (?1,?2,?3)",
                params![attachment, closed_at_ms, retain_until_ms],
            )?;
            conn.execute(
                "UPDATE remote_attachment_operations SET retire_at_ms=?2
                 WHERE logical_attachment_id=?1 AND state IN ('committed','rejected','outcome_unknown')
                   AND retire_at_ms IS NULL",
                params![attachment, retain_until_ms],
            )?;
            Ok(retain_until_ms)
        })
        .await
    }

    /// Advances the client snapshot authority, compacts only covered immutable
    /// events, and retires terminal operations only after the close deadline.
    pub async fn compact_closed_remote_attachment_operation_ledger(
        &self,
        logical_attachment_id: &str,
        compacted_through_event_seq: u64,
        snapshot_high_water_mark: u64,
        now_ms: i64,
    ) -> Result<u64> {
        validate_uuid("logical attachment id", logical_attachment_id)?;
        ensure!(
            snapshot_high_water_mark >= compacted_through_event_seq,
            "snapshot high-water mark precedes compacted cursor"
        );
        let cursor = i64::try_from(compacted_through_event_seq)?;
        let high_water = i64::try_from(snapshot_high_water_mark)?;
        let attachment = logical_attachment_id.to_owned();
        self.transaction(move |conn| {
            let retain_until: i64 = conn.query_row(
                "SELECT retain_until_ms FROM remote_attachment_lifecycle
                 WHERE logical_attachment_id=?1",
                [&attachment],
                |row| row.get(0),
            ).context("remote attachment must be authoritatively closed before compaction")?;
            validate_snapshot_high_water(conn, &attachment, high_water)?;
            conn.execute(
                "INSERT INTO remote_attachment_outbox_snapshots
                 (logical_attachment_id, compacted_through_event_seq, snapshot_high_water_mark, updated_at_ms)
                 VALUES (?1,?2,?3,?4)
                 ON CONFLICT(logical_attachment_id) DO UPDATE SET
                   compacted_through_event_seq=excluded.compacted_through_event_seq,
                   snapshot_high_water_mark=excluded.snapshot_high_water_mark,
                   updated_at_ms=excluded.updated_at_ms",
                params![attachment, cursor, high_water, now_ms],
            )?;
            conn.execute(
                "DELETE FROM remote_attachment_outbox
                 WHERE logical_attachment_id=?1 AND event_seq<=?2",
                params![attachment, cursor],
            )?;
            if now_ms < retain_until {
                return Ok(0);
            }
            let deleted = conn.execute(
                "DELETE FROM remote_attachment_operations
                 WHERE logical_attachment_id=?1 AND retire_at_ms<=?2
                   AND state IN ('committed','rejected','outcome_unknown')
                   AND (event_high_water_mark IS NULL OR event_high_water_mark<=?3)",
                params![attachment, now_ms, cursor],
            )?;
            Ok(deleted as u64)
        })
        .await
    }

    /// Compacts replay events for an active attachment only behind a snapshot
    /// high-water mark observed in this same writer transaction. Operation
    /// outcomes remain queryable for the full active lifetime.
    pub async fn compact_active_remote_attachment_outbox(
        &self,
        logical_attachment_id: &str,
        compacted_through_event_seq: u64,
        snapshot_high_water_mark: u64,
        now_ms: i64,
    ) -> Result<u64> {
        validate_uuid("logical attachment id", logical_attachment_id)?;
        ensure!(
            snapshot_high_water_mark >= compacted_through_event_seq,
            "snapshot high-water mark precedes compacted cursor"
        );
        let cursor = i64::try_from(compacted_through_event_seq)?;
        let high_water = i64::try_from(snapshot_high_water_mark)?;
        let attachment = logical_attachment_id.to_owned();
        self.transaction(move |conn| {
            let closed: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM remote_attachment_lifecycle WHERE logical_attachment_id=?1)",
                [&attachment],
                |row| row.get(0),
            )?;
            ensure!(!closed, "closed attachment requires closed-ledger compaction");
            validate_snapshot_high_water(conn, &attachment, high_water)?;
            conn.execute(
                "INSERT INTO remote_attachment_outbox_snapshots
                 (logical_attachment_id, compacted_through_event_seq, snapshot_high_water_mark, updated_at_ms)
                 VALUES (?1,?2,?3,?4)
                 ON CONFLICT(logical_attachment_id) DO UPDATE SET
                   compacted_through_event_seq=excluded.compacted_through_event_seq,
                   snapshot_high_water_mark=excluded.snapshot_high_water_mark,
                   updated_at_ms=excluded.updated_at_ms",
                params![attachment, cursor, high_water, now_ms],
            )?;
            let deleted = conn.execute(
                "DELETE FROM remote_attachment_outbox
                 WHERE logical_attachment_id=?1 AND event_seq<=?2",
                params![attachment, cursor],
            )?;
            Ok(deleted as u64)
        })
        .await
    }
    pub async fn remote_outbox_high_water(&self, logical_attachment_id: &str) -> Result<u64> {
        validate_uuid("logical attachment id", logical_attachment_id)?;
        let attachment = logical_attachment_id.to_owned();
        self.read(move |conn| {
            let value: i64 = conn.query_row(
                "SELECT COALESCE(MAX(event_seq),0) FROM remote_attachment_outbox WHERE logical_attachment_id=?1",
                [&attachment], |row| row.get(0),
            )?;
            value.try_into().context("negative remote outbox high water")
        }).await
    }
    /// Claims the oldest event for one independent consumer. A worker ack is
    /// deliberately unrelated to the snapshot cursor used for client replay.
    pub async fn claim_remote_outbox_delivery(
        &self,
        consumer_kind: &str,
        outbox_kind: &str,
        logical_attachment_id: Option<&str>,
        after_event_seq: Option<u64>,
        now_ms: i64,
        lease_duration_ms: i64,
    ) -> Result<Option<RemoteOutboxDeliveryLease>> {
        ensure!(
            !consumer_kind.is_empty() && consumer_kind.len() <= 64,
            "invalid consumer kind"
        );
        ensure!(
            !outbox_kind.is_empty() && outbox_kind.len() <= 255,
            "invalid outbox kind"
        );
        ensure!(
            lease_duration_ms > 0 && lease_duration_ms <= 300_000,
            "invalid delivery lease duration"
        );
        let consumer_kind = consumer_kind.to_owned();
        let outbox_kind = outbox_kind.to_owned();
        let attachment_filter = logical_attachment_id.map(str::to_owned);
        self.transaction(move |conn| {
            let candidate: Option<(String, i64, String, String, Vec<u8>, Option<i64>)> = conn
                .query_row(
                    "SELECT o.logical_attachment_id, o.event_seq, o.delivery_id, o.kind,
                            o.canonical_payload, d.attempts
                       FROM remote_attachment_outbox o
                       LEFT JOIN remote_attachment_outbox_deliveries d
                         ON d.logical_attachment_id=o.logical_attachment_id
                        AND d.delivery_id=o.delivery_id AND d.consumer_kind=?1
                      WHERE (?3='*' OR o.kind=?3) AND o.event_seq>?4
                        AND (?5 IS NULL OR o.logical_attachment_id=?5)
                        AND (d.state IS NULL OR (d.state='leased' AND d.lease_expires_at_ms<=?2))
                      ORDER BY o.created_at_ms, o.logical_attachment_id, o.event_seq LIMIT 1",
                    params![consumer_kind, now_ms, outbox_kind, after_event_seq.unwrap_or(0) as i64, attachment_filter],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
                )
                .optional()?;
            let Some((attachment, event_seq, delivery_id, kind, payload, prior_attempts)) = candidate else {
                return Ok(None);
            };
            let attempts = prior_attempts.unwrap_or(0).checked_add(1).context("delivery attempts overflow")?;
            ensure!(attempts <= 1_000_000, "delivery attempts exhausted");
            let lease_id = Uuid::now_v7().to_string();
            let expires = now_ms.checked_add(lease_duration_ms).context("delivery lease expiry overflow")?;
            conn.execute(
                "INSERT INTO remote_attachment_outbox_deliveries
                 (logical_attachment_id, delivery_id, consumer_kind, state, lease_id,
                  lease_expires_at_ms, attempts, first_claimed_at_ms, updated_at_ms, acked_at_ms)
                 VALUES (?1,?2,?3,'leased',?4,?5,?6,?7,?7,NULL)
                 ON CONFLICT(logical_attachment_id,delivery_id,consumer_kind) DO UPDATE SET
                   state='leased', lease_id=excluded.lease_id,
                   lease_expires_at_ms=excluded.lease_expires_at_ms,
                   attempts=excluded.attempts, updated_at_ms=excluded.updated_at_ms, acked_at_ms=NULL",
                params![attachment, delivery_id, consumer_kind, lease_id, expires, attempts, now_ms],
            )?;
            Ok(Some(RemoteOutboxDeliveryLease {
                logical_attachment_id: attachment, event_seq: event_seq.try_into()?, delivery_id,
                kind, canonical_payload: payload, lease_id,
                attempts: attempts.try_into()?, lease_expires_at_ms: expires,
            }))
        }).await
    }

    pub async fn ack_remote_outbox_delivery(
        &self,
        logical_attachment_id: &str,
        delivery_id: &str,
        consumer_kind: &str,
        lease_id: &str,
        now_ms: i64,
    ) -> Result<bool> {
        validate_uuid("logical attachment id", logical_attachment_id)?;
        validate_uuid("delivery id", delivery_id)?;
        validate_uuid("lease id", lease_id)?;
        ensure!(
            !consumer_kind.is_empty() && consumer_kind.len() <= 64,
            "invalid consumer kind"
        );
        let attachment = logical_attachment_id.to_owned();
        let delivery = delivery_id.to_owned();
        let consumer = consumer_kind.to_owned();
        let lease = lease_id.to_owned();
        self.transaction(move |conn| {
            let changed = conn.execute(
                "UPDATE remote_attachment_outbox_deliveries
                    SET state='acked', lease_id=NULL, lease_expires_at_ms=NULL,
                        updated_at_ms=?1, acked_at_ms=?1
                  WHERE logical_attachment_id=?2 AND delivery_id=?3 AND consumer_kind=?4
                    AND state='leased' AND lease_id=?5 AND lease_expires_at_ms>?1",
                params![now_ms, attachment, delivery, consumer, lease],
            )?;
            Ok(changed == 1)
        })
        .await
    }
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

    /// Atomically persist an adapter's authoritative desired/domain state and
    /// its replay receipt. The live adapter effect occurs after this commit
    /// and may be reconciled from the durable domain state after a crash.
    pub async fn execute_idempotent_adapter_remote_operation<T, F>(
        &self,
        request: ReserveRemoteOperation<'_>,
        mutation: F,
    ) -> Result<TransactionalRemoteOperationOutcome<T>>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<TransactionalRemoteMutation<T>> + Send + 'static,
    {
        ensure!(
            request.operation_class == RemoteOperationClass::IdempotentAdapterMutation,
            "adapter executor requires idempotent_adapter_mutation class"
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
                match commit_conn(
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
                )? {
                    CommitRemoteOperationOutcome::Committed { .. } => {
                        Ok(TransactionalRemoteOperationOutcome::Applied(result.value))
                    }
                    CommitRemoteOperationOutcome::AttachmentLedgerCapacity => {
                        bail!("adapter operation ledger capacity")
                    }
                    CommitRemoteOperationOutcome::AttachmentOutboxCapacity => {
                        bail!("adapter operation outbox capacity")
                    }
                }
            }
            ReserveRemoteOperationOutcome::Replay(replay) if replay.state == "committed" => {
                Ok(TransactionalRemoteOperationOutcome::Replay(
                    replay
                        .safe_response
                        .context("committed adapter operation missing safe response")?,
                ))
            }
            ReserveRemoteOperationOutcome::Replay(_) => bail!("adapter operation is indeterminate"),
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

    /// Commits a staged rename only after its exact dispatch generation has
    /// crossed every filesystem durability barrier. The journal transition,
    /// safe response, and outbox append share one transaction.
    pub async fn commit_remote_rename_operation(
        &self,
        request: CommitRemoteOperation<'_>,
        expected_dispatch_generation: u64,
    ) -> Result<CommitRemoteOperationOutcome> {
        ensure!(
            expected_dispatch_generation > 0,
            "rename generation must be positive"
        );
        let generation = i64::try_from(expected_dispatch_generation)?;
        let owned = OwnedCommitRemoteOperation {
            logical_attachment_id: request.logical_attachment_id.to_owned(),
            operation_id: request.operation_id.to_owned(),
            safe_response: request.safe_response.to_vec(),
            outbox_delivery_id: request.outbox_delivery_id.to_owned(),
            outbox_kind: request.outbox_kind.to_owned(),
            outbox_payload: request.outbox_payload.to_vec(),
            now_ms: request.now_ms,
        };
        self.transaction(move |conn| {
            let effective_now: i64 = conn.query_row(
                "SELECT MAX(?3,o.updated_at_ms,j.updated_at_ms)
                 FROM remote_attachment_operations o
                 JOIN remote_rename_journal j USING(logical_attachment_id,operation_id)
                 WHERE o.logical_attachment_id=?1 AND o.operation_id=?2",
                params![owned.logical_attachment_id, owned.operation_id, owned.now_ms],
                |row| row.get(0),
            )?;
            let mut owned = owned;
            owned.now_ms = effective_now;
            let outcome = commit_conn_with_policy(conn, &owned, true)?;
            if !matches!(outcome, CommitRemoteOperationOutcome::Committed { .. }) {
                return Ok(outcome);
            }
            let changed = conn.execute(
                "UPDATE remote_rename_journal SET state='ledger_committed',updated_at_ms=MAX(updated_at_ms,?4)
                 WHERE logical_attachment_id=?1 AND operation_id=?2 AND state='applied'
                   AND dispatch_generation=?3
                   AND dispatch_generation=(SELECT dispatch_generation FROM remote_attachment_operations
                     WHERE logical_attachment_id=?1 AND operation_id=?2
                       AND operation_kind='staged_rename')",
                params![owned.logical_attachment_id, owned.operation_id, generation, owned.now_ms],
            )?;
            ensure!(changed == 1, "rename commit requires one applied row at the expected generation");
            conn.execute("INSERT OR IGNORE INTO remote_rename_artifact_cleanup_intents(logical_attachment_id,operation_id,artifact_id,created_at_ms) SELECT logical_attachment_id,operation_id,artifact_id,?3 FROM remote_rename_journal WHERE logical_attachment_id=?1 AND operation_id=?2",params![owned.logical_attachment_id,owned.operation_id,owned.now_ms])?;
            Ok(outcome)
        })
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
    let closed: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM remote_attachment_lifecycle WHERE logical_attachment_id=?1)",
        [&request.logical_attachment_id],
        |row| row.get(0),
    )?;
    ensure!(!closed, "remote attachment operation ledger is closed");

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

fn load_remote_rename_evidence(
    conn: &Connection,
    attachment: &str,
    operation: &str,
) -> Result<RemoteRenameEvidence> {
    let (artifact_id, generation, state, source, source_parent, target_parent, observed): (
        String,
        i64,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
    ) = conn.query_row("SELECT artifact_id,dispatch_generation,state,source_identity,source_parent_identity,target_parent_identity,observed_target_identity FROM remote_rename_journal WHERE logical_attachment_id=?1 AND operation_id=?2",params![attachment,operation],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?))).context("loading remote rename evidence")?;
    Ok(RemoteRenameEvidence {
        artifact_id,
        dispatch_generation: generation.try_into()?,
        state,
        source_identity: RemoteFilesystemIdentityV1::decode(&source)?,
        source_parent_identity: RemoteFilesystemIdentityV1::decode(&source_parent)?,
        target_parent_identity: RemoteFilesystemIdentityV1::decode(&target_parent)?,
        observed_target_identity: observed
            .map(|value| RemoteFilesystemIdentityV1::decode(&value))
            .transpose()?,
    })
}

fn validate_snapshot_high_water(
    conn: &Connection,
    logical_attachment_id: &str,
    supplied_high_water: i64,
) -> Result<()> {
    let observed: i64 = conn.query_row(
        "SELECT MAX(
             COALESCE((SELECT MAX(event_seq) FROM remote_attachment_outbox
                       WHERE logical_attachment_id=?1), 0),
             COALESCE((SELECT snapshot_high_water_mark FROM remote_attachment_outbox_snapshots
                       WHERE logical_attachment_id=?1), 0)
         )",
        [logical_attachment_id],
        |row| row.get(0),
    )?;
    ensure!(
        supplied_high_water == observed,
        "snapshot high-water mark does not match the authoritative outbox boundary"
    );
    Ok(())
}

fn commit_conn(
    conn: &Connection,
    request: &OwnedCommitRemoteOperation,
) -> Result<CommitRemoteOperationOutcome> {
    commit_conn_with_policy(conn, request, false)
}

fn commit_conn_with_policy(
    conn: &Connection,
    request: &OwnedCommitRemoteOperation,
    allow_remote_rename: bool,
) -> Result<CommitRemoteOperationOutcome> {
    validate_uuid("logical attachment id", &request.logical_attachment_id)?;
    validate_operation_id(&request.operation_id)?;
    validate_uuid("outbox delivery id", &request.outbox_delivery_id)?;
    if !allow_remote_rename {
        let has_rename: bool = conn.query_row(
            "SELECT operation_kind='staged_rename' FROM remote_attachment_operations WHERE logical_attachment_id=?1 AND operation_id=?2",
            params![request.logical_attachment_id, request.operation_id],
            |row| row.get(0),
        )?;
        ensure!(
            !has_rename,
            "remote rename requires generation-bound commit"
        );
    }
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
    if !matches!(state.as_str(), "reserved" | "dispatched") {
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
         WHERE logical_attachment_id = ?1 AND operation_id = ?2 AND state IN ('reserved','dispatched')",
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
        let replay: TransactionalRemoteOperationOutcome<()> = db
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
            db.execute_transactional_remote_operation::<(), _>(changed, |_| panic!(
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
        let replay: TransactionalRemoteOperationOutcome<()> = reopened
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

    fn filesystem_identity(seed: u64, kind: u8) -> RemoteFilesystemIdentityV1 {
        RemoteFilesystemIdentityV1 {
            filesystem_id: 7,
            object_id: u128::from(seed),
            kind,
            len: seed,
            mode: if kind == 1 { 0o100700 } else { 0o040700 },
            owner_id: 42,
            link_count: 1,
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

    #[tokio::test]
    async fn outbox_delivery_claim_expiry_ack_and_consumers_are_independent() {
        let db = Db::open_in_memory().unwrap();
        let operation = "01890f3e-4c00-7000-8000-000000000060";
        let delivery = "00000000-0000-4000-8000-000000000061";
        db.reserve_remote_attachment_operation(reserve(operation, [6; 32]))
            .await
            .unwrap();
        db.commit_remote_attachment_operation(CommitRemoteOperation {
            logical_attachment_id: ATTACHMENT,
            operation_id: operation,
            safe_response: b"ack",
            outbox_delivery_id: delivery,
            outbox_kind: "wake_goal",
            outbox_payload: b"{}",
            now_ms: 10,
        })
        .await
        .unwrap();
        let first = db
            .claim_remote_outbox_delivery("worker", "wake_goal", None, None, 20, 100)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.attempts, 1);
        assert!(
            db.claim_remote_outbox_delivery("worker", "wake_goal", None, None, 119, 100)
                .await
                .unwrap()
                .is_none()
        );
        let second = db
            .claim_remote_outbox_delivery("worker", "wake_goal", None, None, 120, 100)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.delivery_id, first.delivery_id);
        assert_eq!(second.attempts, 2);
        assert_ne!(second.lease_id, first.lease_id);
        assert!(
            !db.ack_remote_outbox_delivery(ATTACHMENT, delivery, "worker", &first.lease_id, 121)
                .await
                .unwrap()
        );
        assert!(
            db.ack_remote_outbox_delivery(ATTACHMENT, delivery, "worker", &second.lease_id, 121)
                .await
                .unwrap()
        );
        assert!(
            db.claim_remote_outbox_delivery("worker", "wake_goal", None, None, 500, 100)
                .await
                .unwrap()
                .is_none()
        );
        let transport = db
            .claim_remote_outbox_delivery("transport", "wake_goal", None, None, 500, 100)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            transport.attempts, 1,
            "consumer delivery state must be independent"
        );

        let attachment = ATTACHMENT.to_owned();
        assert!(db.write(move |conn| {
            conn.execute(
                "DELETE FROM remote_attachment_outbox WHERE logical_attachment_id=?1 AND event_seq=1",
                [&attachment],
            )?;
            Ok(())
        }).await.is_err(), "consumer ack must not authorize replay compaction");

        let attachment = ATTACHMENT.to_owned();
        db.write(move |conn| {
            conn.execute(
                "INSERT INTO remote_attachment_outbox_snapshots
                 (logical_attachment_id, compacted_through_event_seq, snapshot_high_water_mark, updated_at_ms)
                 VALUES (?1,1,1,600)",
                [&attachment],
            )?;
            conn.execute(
                "DELETE FROM remote_attachment_outbox WHERE logical_attachment_id=?1 AND event_seq=1",
                [&attachment],
            )?;
            Ok(())
        }).await.unwrap();
        assert!(
            db.claim_remote_outbox_delivery("transport", "wake_goal", None, None, 700, 100)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn outbox_delivery_lease_survives_process_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delivery-reopen.sqlite3");
        let attachment = "00000000-0000-4000-8000-000000000081";
        let operation = "01890f3e-4c00-7000-8000-000000000082";
        let delivery = "00000000-0000-4000-8000-000000000083";
        {
            let db = Db::open(&path).unwrap();
            db.reserve_remote_attachment_operation(ReserveRemoteOperation {
                logical_attachment_id: attachment,
                operation_id: operation,
                authenticated_device_id: "00000000-0000-4000-8000-000000000084",
                authenticated_device_generation: 1,
                operation_class: RemoteOperationClass::TransactionalMutation,
                request_hash: [8; 32],
                now_ms: 1,
            })
            .await
            .unwrap();
            db.commit_remote_attachment_operation(CommitRemoteOperation {
                logical_attachment_id: attachment,
                operation_id: operation,
                safe_response: b"ack",
                outbox_delivery_id: delivery,
                outbox_kind: "restart_effect",
                outbox_payload: b"payload",
                now_ms: 2,
            })
            .await
            .unwrap();
            let lease = db
                .claim_remote_outbox_delivery("worker", "restart_effect", None, None, 10, 100)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(lease.attempts, 1);
            // Dropping the DB models process death after effect dispatch and
            // before acknowledgement; no shutdown path clears this lease.
        }
        {
            let db = Db::open(&path).unwrap();
            assert!(
                db.claim_remote_outbox_delivery("worker", "restart_effect", None, None, 109, 100)
                    .await
                    .unwrap()
                    .is_none()
            );
            let lease = db
                .claim_remote_outbox_delivery("worker", "restart_effect", None, None, 110, 100)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(lease.delivery_id, delivery);
            assert_eq!(lease.attempts, 2);
            assert!(db
                .ack_remote_outbox_delivery(attachment, delivery, "worker", &lease.lease_id, 111,)
                .await
                .unwrap());
            let attachment_owned = attachment.to_owned();
            assert!(
                db.write(move |conn| {
                    conn.execute(
                        "DELETE FROM remote_attachment_outbox WHERE logical_attachment_id=?1",
                        [&attachment_owned],
                    )?;
                    Ok(())
                })
                .await
                .is_err(),
                "delivery ack must not become compaction authority after reopen"
            );
        }
    }

    #[tokio::test]
    async fn nonrepeatable_dispatch_is_durable_and_replay_never_redispatches() {
        let db = Db::open_in_memory().unwrap();
        let request = || ReserveRemoteOperation {
            logical_attachment_id: "00000000-0000-4000-8000-000000000001",
            operation_id: "01890f3e-4c00-7000-8000-000000000097",
            authenticated_device_id: "00000000-0000-4000-8000-000000000002",
            authenticated_device_generation: 1,
            operation_class: RemoteOperationClass::NonrepeatableMutation,
            request_hash: [6; 32],
            now_ms: 1,
        };
        assert!(matches!(
            db.begin_nonrepeatable_remote_operation(request())
                .await
                .unwrap(),
            BeginNonrepeatableRemoteOperationOutcome::Dispatch {
                dispatch_generation: 1,
                ..
            }
        ));
        assert!(matches!(
            db.begin_nonrepeatable_remote_operation(request())
                .await
                .unwrap(),
            BeginNonrepeatableRemoteOperationOutcome::OutcomeUnknown(_)
        ));
        assert!(
            db.mark_nonrepeatable_remote_operation_outcome_unknown(
                request().logical_attachment_id,
                request().operation_id,
                br#"{"outcome":"unknown"}"#,
                2,
            )
            .await
            .unwrap()
        );
        assert_eq!(
            db.begin_nonrepeatable_remote_operation(request())
                .await
                .unwrap(),
            BeginNonrepeatableRemoteOperationOutcome::OutcomeUnknown(
                br#"{"outcome":"unknown"}"#.to_vec()
            )
        );
    }

    #[tokio::test]
    async fn adapter_dispatch_generation_advances_for_reconciliation_then_replays_commit() {
        let db = Db::open_in_memory().unwrap();
        let operation = "01890f3e-4c00-7000-8000-00000000009d";
        let request = || ReserveRemoteOperation {
            operation_class: RemoteOperationClass::IdempotentAdapterMutation,
            ..reserve(operation, [11; 32])
        };
        assert!(matches!(
            db.begin_idempotent_adapter_remote_operation(request())
                .await
                .unwrap(),
            BeginIdempotentAdapterRemoteOperationOutcome::Dispatch {
                dispatch_generation: 1,
                ..
            }
        ));
        assert!(matches!(
            db.begin_idempotent_adapter_remote_operation(request())
                .await
                .unwrap(),
            BeginIdempotentAdapterRemoteOperationOutcome::Dispatch {
                dispatch_generation: 2,
                ..
            }
        ));
        db.commit_remote_attachment_operation(CommitRemoteOperation {
            logical_attachment_id: ATTACHMENT,
            operation_id: operation,
            safe_response: b"adapter-safe",
            outbox_delivery_id: "00000000-0000-4000-8000-00000000009e",
            outbox_kind: "adapter_test",
            outbox_payload: b"adapter-event",
            now_ms: 12,
        })
        .await
        .unwrap();
        assert_eq!(
            db.begin_idempotent_adapter_remote_operation(request())
                .await
                .unwrap(),
            BeginIdempotentAdapterRemoteOperationOutcome::Replay(b"adapter-safe".to_vec())
        );
    }

    #[tokio::test]
    async fn rename_journal_reopens_with_exact_evidence_and_rejects_stale_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rename.db");
        let operation = "01890f3e-4c00-7000-8000-0000000000a4";
        let request = || ReserveRemoteOperation {
            operation_class: RemoteOperationClass::IdempotentAdapterMutation,
            ..reserve(operation, [15; 32])
        };
        let artifact;
        {
            let db = Db::open(&path).unwrap();
            let PrepareRemoteRenameOutcome::Prepared(evidence) = db
                .prepare_remote_rename_operation(
                    request(),
                    Some(filesystem_identity(1, 1)),
                    Some(filesystem_identity(2, 2)),
                    Some(filesystem_identity(3, 2)),
                )
                .await
                .unwrap()
            else {
                panic!("prepared")
            };
            artifact = evidence.artifact_id;
            assert!(
                db.advance_remote_rename_operation(
                    ATTACHMENT,
                    operation,
                    1,
                    "prepared",
                    "artifact_synced",
                    11
                )
                .await
                .unwrap()
            );
        }
        let db = Db::open(&path).unwrap();
        let PrepareRemoteRenameOutcome::Reconcile(evidence) = db
            .prepare_remote_rename_operation(request(), None, None, None)
            .await
            .unwrap()
        else {
            panic!("reconcile")
        };
        assert_eq!(evidence.artifact_id, artifact);
        assert_eq!(evidence.dispatch_generation, 2);
        assert_eq!(evidence.state, "artifact_synced");
        assert_eq!(
            db.read(move |conn| Ok(conn.query_row(
                "SELECT updated_at_ms FROM remote_rename_journal WHERE logical_attachment_id=?1 AND operation_id=?2",
                params![ATTACHMENT, operation],
                |row| row.get::<_, i64>(0),
            )?))
            .await
            .unwrap(),
            11,
            "reconciliation generation advance cannot regress durable barrier time"
        );
        assert!(
            !db.advance_remote_rename_operation(
                ATTACHMENT,
                operation,
                1,
                "artifact_synced",
                "renamed",
                12
            )
            .await
            .unwrap(),
            "late generation cannot advance a barrier"
        );
        assert!(
            db.advance_remote_rename_operation(
                ATTACHMENT,
                operation,
                2,
                "artifact_synced",
                "renamed",
                12
            )
            .await
            .unwrap()
        );
        let commit = || CommitRemoteOperation {
            logical_attachment_id: ATTACHMENT,
            operation_id: operation,
            safe_response: b"rename-ack",
            outbox_delivery_id: "00000000-0000-4000-8000-0000000000a5",
            outbox_kind: "filesystem_changed",
            outbox_payload: b"rename",
            now_ms: 20,
        };
        assert!(
            db.commit_remote_rename_operation(commit(), 2)
                .await
                .is_err()
        );
        assert!(
            db.commit_remote_attachment_operation(commit())
                .await
                .is_err()
        );
        let (state, outbox): (String, i64) = db
            .transaction(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM remote_attachment_operations WHERE logical_attachment_id=?1 AND operation_id=?2",
                        params![ATTACHMENT, operation],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM remote_attachment_outbox WHERE logical_attachment_id=?1",
                        [ATTACHMENT],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(state, "dispatched");
        assert_eq!(outbox, 0);
        for (from, to) in [
            ("renamed", "source_parent_synced"),
            ("source_parent_synced", "target_parent_synced"),
            ("target_parent_synced", "applied"),
        ] {
            assert!(
                db.advance_remote_rename_operation(ATTACHMENT, operation, 2, from, to, 21)
                    .await
                    .unwrap()
            );
        }
        assert!(
            db.commit_remote_rename_operation(commit(), 1)
                .await
                .is_err()
        );
        assert!(matches!(
            db.commit_remote_rename_operation(commit(), 2)
                .await
                .unwrap(),
            CommitRemoteOperationOutcome::Committed { .. }
        ));
        drop(db);
        let db = Db::open(&path).unwrap();
        let (journal_state, journal_updated_at, operation_updated_at, outbox_created_at, outbox_count): (String, i64, i64, i64, i64) = db
            .transaction(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM remote_rename_journal WHERE logical_attachment_id=?1 AND operation_id=?2",
                        params![ATTACHMENT, operation],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT updated_at_ms FROM remote_rename_journal WHERE logical_attachment_id=?1 AND operation_id=?2",
                        params![ATTACHMENT, operation],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT updated_at_ms FROM remote_attachment_operations WHERE logical_attachment_id=?1 AND operation_id=?2",
                        params![ATTACHMENT, operation],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT created_at_ms FROM remote_attachment_outbox WHERE logical_attachment_id=?1 AND operation_seq=(SELECT operation_seq FROM remote_attachment_operations WHERE logical_attachment_id=?1 AND operation_id=?2)",
                        params![ATTACHMENT, operation],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM remote_attachment_outbox WHERE logical_attachment_id=?1 AND operation_seq=(SELECT operation_seq FROM remote_attachment_operations WHERE logical_attachment_id=?1 AND operation_id=?2)",
                        params![ATTACHMENT, operation],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(journal_state, "ledger_committed");
        assert_eq!(
            (journal_updated_at, operation_updated_at, outbox_created_at),
            (21, 21, 21)
        );
        assert_eq!(outbox_count, 1);
        assert!(
            db.commit_remote_rename_operation(commit(), 2)
                .await
                .is_err()
        );
        let outbox_after_second: i64 = db
            .transaction(move |conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM remote_attachment_outbox WHERE logical_attachment_id=?1 AND operation_seq=(SELECT operation_seq FROM remote_attachment_operations WHERE logical_attachment_id=?1 AND operation_id=?2)",
                    params![ATTACHMENT, operation],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(outbox_after_second, 1);
        assert_eq!(
            db.prepare_remote_rename_operation(request(), None, None, None)
                .await
                .unwrap(),
            PrepareRemoteRenameOutcome::Replay(b"rename-ack".to_vec())
        );
    }

    #[test]
    fn remote_filesystem_identity_codec_is_versioned_and_strict() {
        let identity = filesystem_identity(9, 1);
        let encoded = identity.encode().unwrap();
        assert_eq!(
            RemoteFilesystemIdentityV1::decode(&encoded).unwrap(),
            identity
        );
        let mut bad_magic = encoded;
        bad_magic[3] = b'2';
        assert!(RemoteFilesystemIdentityV1::decode(&bad_magic).is_err());
        let mut bad_kind = encoded;
        bad_kind[28] = 3;
        assert!(RemoteFilesystemIdentityV1::decode(&bad_kind).is_err());
        assert!(RemoteFilesystemIdentityV1::decode(&encoded[..56]).is_err());
        let mut mismatched = identity;
        mismatched.mode = 0o040700;
        assert!(mismatched.encode().is_err());
    }

    #[tokio::test]
    async fn rename_discriminator_survives_journal_deletion_and_parent_roles_are_strict() {
        let db = Db::open_in_memory().unwrap();
        let operation = "01890f3e-4c00-7000-8000-0000000000a6";
        let request = || ReserveRemoteOperation {
            operation_class: RemoteOperationClass::IdempotentAdapterMutation,
            ..reserve(operation, [16; 32])
        };
        assert!(
            db.prepare_remote_rename_operation(
                request(),
                Some(filesystem_identity(1, 1)),
                Some(filesystem_identity(2, 1)),
                Some(filesystem_identity(3, 2)),
            )
            .await
            .is_err()
        );
        assert!(
            db.prepare_remote_rename_operation(
                request(),
                Some(filesystem_identity(1, 1)),
                Some(filesystem_identity(2, 2)),
                Some(filesystem_identity(3, 1)),
            )
            .await
            .is_err()
        );
        let PrepareRemoteRenameOutcome::Prepared(_) = db
            .prepare_remote_rename_operation(
                request(),
                Some(filesystem_identity(1, 1)),
                Some(filesystem_identity(2, 2)),
                Some(filesystem_identity(3, 2)),
            )
            .await
            .unwrap()
        else {
            panic!("prepared")
        };
        db.transaction(move |conn| {
            conn.execute(
                "DELETE FROM remote_rename_journal WHERE logical_attachment_id=?1 AND operation_id=?2",
                params![ATTACHMENT, operation],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            db.commit_remote_attachment_operation(CommitRemoteOperation {
                logical_attachment_id: ATTACHMENT,
                operation_id: operation,
                safe_response: b"forbidden",
                outbox_delivery_id: "00000000-0000-4000-8000-0000000000a7",
                outbox_kind: "filesystem_changed",
                outbox_payload: b"rename",
                now_ms: 30,
            })
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn specialized_rename_commit_rejects_a_forged_generic_applied_journal() {
        let db = Db::open_in_memory().unwrap();
        let operation = "01890f3e-4c00-7000-8000-0000000000a8";
        let generic = ReserveRemoteOperation {
            operation_class: RemoteOperationClass::IdempotentAdapterMutation,
            ..reserve(operation, [17; 32])
        };
        db.reserve_remote_attachment_operation(generic)
            .await
            .unwrap();
        let source = filesystem_identity(1, 1).encode().unwrap().to_vec();
        let parent = filesystem_identity(2, 2).encode().unwrap().to_vec();
        db.transaction(move |conn| {
            assert!(conn.execute(
                "INSERT INTO remote_rename_journal(logical_attachment_id,operation_id,artifact_id,source_identity,source_parent_identity,target_parent_identity,dispatch_generation,state,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,?5,?5,1,'applied',10,10)",
                params![ATTACHMENT,operation,"00000000-0000-4000-8000-0000000000a9",source,parent],
            ).is_err(), "schema must reject a journal without staged authority");
            conn.execute("DROP TRIGGER remote_rename_journal_insert_authority", [])?;
            conn.execute(
                "INSERT INTO remote_rename_journal(logical_attachment_id,operation_id,artifact_id,source_identity,source_parent_identity,target_parent_identity,dispatch_generation,state,created_at_ms,updated_at_ms) VALUES(?1,?2,?3,?4,?5,?5,1,'applied',10,10)",
                params![ATTACHMENT,operation,"00000000-0000-4000-8000-0000000000a9",source,parent],
            )?;
            Ok(())
        }).await.unwrap();
        assert!(
            db.commit_remote_rename_operation(
                CommitRemoteOperation {
                    logical_attachment_id: ATTACHMENT,
                    operation_id: operation,
                    safe_response: b"forbidden",
                    outbox_delivery_id: "00000000-0000-4000-8000-0000000000aa",
                    outbox_kind: "filesystem_changed",
                    outbox_payload: b"rename",
                    now_ms: 30,
                },
                1
            )
            .await
            .is_err()
        );
        let (state, outbox): (String, i64) = db.transaction(move |conn| Ok((
            conn.query_row("SELECT state FROM remote_attachment_operations WHERE logical_attachment_id=?1 AND operation_id=?2", params![ATTACHMENT,operation], |row| row.get(0))?,
            conn.query_row("SELECT COUNT(*) FROM remote_attachment_outbox WHERE logical_attachment_id=?1", [ATTACHMENT], |row| row.get(0))?,
        ))).await.unwrap();
        assert_eq!(state, "reserved");
        assert_eq!(outbox, 0);
    }

    #[tokio::test]
    async fn rename_applied_identity_mismatch_is_durable_and_never_redispatched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rename-mismatch.db");
        let operation = "01890f3e-4c00-7000-8000-0000000000ab";
        let request = || ReserveRemoteOperation {
            operation_class: RemoteOperationClass::IdempotentAdapterMutation,
            ..reserve(operation, [18; 32])
        };
        let observed = filesystem_identity(99, 1);
        {
            let db = Db::open(&path).unwrap();
            assert!(matches!(
                db.prepare_remote_rename_operation(
                    request(),
                    Some(filesystem_identity(1, 1)),
                    Some(filesystem_identity(2, 2)),
                    Some(filesystem_identity(3, 2)),
                )
                .await
                .unwrap(),
                PrepareRemoteRenameOutcome::Prepared(_)
            ));
            assert!(
                db.advance_remote_rename_operation(
                    ATTACHMENT,
                    operation,
                    1,
                    "prepared",
                    "artifact_synced",
                    11,
                )
                .await
                .unwrap()
            );
            assert!(
                db.record_remote_rename_applied_mismatch(
                    ATTACHMENT,
                    operation,
                    1,
                    observed,
                    b"{\"outcome\":\"unknown\"}",
                    12,
                )
                .await
                .unwrap()
            );
        }
        let db = Db::open(&path).unwrap();
        assert_eq!(
            db.prepare_remote_rename_operation(request(), None, None, None)
                .await
                .unwrap(),
            PrepareRemoteRenameOutcome::OutcomeUnknown(b"{\"outcome\":\"unknown\"}".to_vec())
        );
        let evidence = db
            .transaction(move |conn| load_remote_rename_evidence(conn, ATTACHMENT, operation))
            .await
            .unwrap();
        assert_eq!(evidence.state, "applied_mismatch");
        assert_eq!(evidence.observed_target_identity, Some(observed));
        assert!(
            db.commit_remote_rename_operation(
                CommitRemoteOperation {
                    logical_attachment_id: ATTACHMENT,
                    operation_id: operation,
                    safe_response: b"forbidden",
                    outbox_delivery_id: "00000000-0000-4000-8000-0000000000ac",
                    outbox_kind: "filesystem_changed",
                    outbox_payload: b"rename",
                    now_ms: 13,
                },
                1,
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn prepared_rename_can_close_unknown_atomically_and_never_redispatch() {
        let db = Db::open_in_memory().unwrap();
        let operation = "01890f3e-4c00-7000-8000-0000000000ae";
        let request = || ReserveRemoteOperation {
            operation_class: RemoteOperationClass::IdempotentAdapterMutation,
            ..reserve(operation, [19; 32])
        };
        assert!(matches!(
            db.prepare_remote_rename_operation(
                request(),
                Some(filesystem_identity(1, 1)),
                Some(filesystem_identity(2, 2)),
                Some(filesystem_identity(3, 2)),
            )
            .await
            .unwrap(),
            PrepareRemoteRenameOutcome::Prepared(_)
        ));
        assert!(
            db.record_remote_rename_effect_unknown(
                ATTACHMENT,
                operation,
                1,
                b"{\"outcome\":\"unknown\"}",
                11,
            )
            .await
            .unwrap()
        );
        assert_eq!(
            db.prepare_remote_rename_operation(request(), None, None, None)
                .await
                .unwrap(),
            PrepareRemoteRenameOutcome::OutcomeUnknown(b"{\"outcome\":\"unknown\"}".to_vec())
        );
        let (journal, operation_state, outbox): (String, String, i64) = db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM remote_rename_journal WHERE logical_attachment_id=?1 AND operation_id=?2",
                        params![ATTACHMENT, operation],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT state FROM remote_attachment_operations WHERE logical_attachment_id=?1 AND operation_id=?2",
                        params![ATTACHMENT, operation],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM remote_attachment_outbox WHERE logical_attachment_id=?1",
                        [ATTACHMENT],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            (journal.as_str(), operation_state.as_str(), outbox),
            ("effect_unknown", "outcome_unknown", 0)
        );
    }

    #[tokio::test]
    async fn closed_attachment_retains_replay_for_thirty_days_then_snapshot_retires_it() {
        let db = Db::open_in_memory().unwrap();
        let operation = "01890f3e-4c00-7000-8000-000000000098";
        db.reserve_remote_attachment_operation(reserve(operation, [8; 32]))
            .await
            .unwrap();
        db.commit_remote_attachment_operation(CommitRemoteOperation {
            logical_attachment_id: ATTACHMENT,
            operation_id: operation,
            safe_response: b"closed-safe-response",
            outbox_delivery_id: "00000000-0000-4000-8000-000000000099",
            outbox_kind: "closed_test",
            outbox_payload: b"closed-event",
            now_ms: 11,
        })
        .await
        .unwrap();

        let deadline = db
            .close_remote_attachment_operation_ledger(ATTACHMENT, 100)
            .await
            .unwrap();
        assert_eq!(deadline, 100 + REMOTE_ATTACHMENT_RETENTION_MS);
        assert!(matches!(
            db.reserve_remote_attachment_operation(reserve(operation, [8; 32]))
                .await
                .unwrap(),
            ReserveRemoteOperationOutcome::Replay(_)
        ));
        assert!(
            db.reserve_remote_attachment_operation(reserve(
                "01890f3e-4c00-7000-8000-00000000009a",
                [9; 32],
            ))
            .await
            .is_err(),
            "close authority rejects new operations"
        );
        assert_eq!(
            db.compact_closed_remote_attachment_operation_ledger(ATTACHMENT, 1, 1, deadline - 1,)
                .await
                .unwrap(),
            0
        );
        assert!(
            db.remote_operation_status(ATTACHMENT, operation)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            db.compact_closed_remote_attachment_operation_ledger(ATTACHMENT, 1, 1, deadline)
                .await
                .unwrap(),
            1
        );
        assert!(
            db.remote_operation_status(ATTACHMENT, operation)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn close_authority_is_immutable_and_snapshot_cursor_is_required_for_fk_cleanup() {
        let db = Db::open_in_memory().unwrap();
        let operation = "01890f3e-4c00-7000-8000-00000000009b";
        db.reserve_remote_attachment_operation(reserve(operation, [10; 32]))
            .await
            .unwrap();
        db.commit_remote_attachment_operation(CommitRemoteOperation {
            logical_attachment_id: ATTACHMENT,
            operation_id: operation,
            safe_response: b"safe",
            outbox_delivery_id: "00000000-0000-4000-8000-00000000009c",
            outbox_kind: "retention_test",
            outbox_payload: b"event",
            now_ms: 11,
        })
        .await
        .unwrap();
        let deadline = db
            .close_remote_attachment_operation_ledger(ATTACHMENT, 100)
            .await
            .unwrap();
        assert!(
            db.close_remote_attachment_operation_ledger(ATTACHMENT, 101)
                .await
                .is_err()
        );
        assert_eq!(
            db.compact_closed_remote_attachment_operation_ledger(ATTACHMENT, 0, 1, deadline)
                .await
                .unwrap(),
            0,
            "an uncovered event remains authoritative and prevents retirement"
        );
        assert!(
            db.remote_operation_status(ATTACHMENT, operation)
                .await
                .unwrap()
                .is_some()
        );
        let (events, operations, cursor): (i64, i64, i64) = db
            .read(|conn| {
                Ok((
                    conn.query_row(
                        "SELECT COUNT(*) FROM remote_attachment_outbox WHERE logical_attachment_id=?1",
                        [ATTACHMENT],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM remote_attachment_operations WHERE logical_attachment_id=?1",
                        [ATTACHMENT],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT compacted_through_event_seq FROM remote_attachment_outbox_snapshots WHERE logical_attachment_id=?1",
                        [ATTACHMENT],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!((events, operations, cursor), (1, 1, 0));
    }

    #[tokio::test]
    async fn active_snapshot_compacts_events_but_preserves_queryable_operation_outcomes() {
        let db = Db::open_in_memory().unwrap();
        let operation = "01890f3e-4c00-7000-8000-0000000000a0";
        db.reserve_remote_attachment_operation(reserve(operation, [12; 32]))
            .await
            .unwrap();
        db.commit_remote_attachment_operation(CommitRemoteOperation {
            logical_attachment_id: ATTACHMENT,
            operation_id: operation,
            safe_response: b"active-safe",
            outbox_delivery_id: "00000000-0000-4000-8000-0000000000a1",
            outbox_kind: "active_snapshot_test",
            outbox_payload: b"active-event",
            now_ms: 11,
        })
        .await
        .unwrap();
        assert!(
            db.compact_active_remote_attachment_outbox(ATTACHMENT, 1, 2, 12)
                .await
                .is_err(),
            "a caller cannot invent a snapshot high-water mark"
        );
        assert_eq!(
            db.compact_active_remote_attachment_outbox(ATTACHMENT, 1, 1, 12)
                .await
                .unwrap(),
            1
        );
        assert!(
            db.remote_operation_status(ATTACHMENT, operation)
                .await
                .unwrap()
                .is_some(),
            "active snapshot compaction never deletes a queryable outcome"
        );
        assert_eq!(
            db.compact_active_remote_attachment_outbox(ATTACHMENT, 1, 1, 13)
                .await
                .unwrap(),
            0,
            "the recorded historical high-water makes compaction idempotent"
        );
    }
}
