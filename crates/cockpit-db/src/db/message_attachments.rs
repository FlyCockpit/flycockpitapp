//! Atomic exactly-once persistence seam for typed user-message attachments.
//!
//! FCOR decoding, authority, model capability, and typed-media ownership remain
//! owned by their respective layers. They are checked inside this transaction
//! through [`MessageAcceptanceJoin`], so no receipt/reference can commit after
//! a stale out-of-transaction decision.

use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

/// Database-local queue ceiling. This mirrors the protocol contract without
/// introducing a production cockpit-db to cockpit-proto dependency.
pub const MAX_QUEUED_CANONICAL_MESSAGE_BYTES: usize = 17_439_564;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageActor {
    LocalOwner,
    ExternalPrincipal { id: [u8; 16], generation: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageAttachmentReferenceInput {
    pub attachment_id: [u8; 16],
    pub attachment_version: u64,
    pub checksum: [u8; 32],
    pub kind: u8,
}

#[derive(Debug, Clone)]
pub struct AcceptMessageInput {
    pub session_id: Uuid,
    pub operation_id: [u8; 16],
    pub actor: MessageActor,
    pub request_hash: [u8; 32],
    pub message_request_digest: [u8; 32],
    pub attachment_set_digest: [u8; 32],
    pub client_submission_id: [u8; 16],
    pub queue_item_id: [u8; 16],
    pub canonical_message: Vec<u8>,
    pub attachments: Vec<MessageAttachmentReferenceInput>,
    pub outbox_sequence: i64,
    pub now_ms: i64,
    /// Optional tool-media-subject binding to insert atomically with the
    /// accepted message. Core owns receipt/seal encoding and passes the
    /// opaque byte DTO through here.
    pub tool_media_subject_binding:
        Option<crate::db::tool_media_subject_bindings::ToolMediaSubjectBindingInsertV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptMessageResult {
    Accepted,
    Replayed { safe_outcome: MessageSafeOutcome },
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageSafeOutcome {
    Accepted { queue_item_id: [u8; 16] },
    Materialized { message_seq: u64 },
    TerminalRejected,
    Removed,
}

impl MessageSafeOutcome {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = b"FCMS\x01".to_vec();
        match self {
            Self::Accepted { queue_item_id } => {
                out.push(1);
                out.extend_from_slice(queue_item_id);
            }
            Self::Materialized { message_seq } => {
                out.push(2);
                out.extend_from_slice(&message_seq.to_be_bytes());
            }
            Self::TerminalRejected => out.push(3),
            Self::Removed => out.push(4),
        }
        out
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.starts_with(b"FCMS\x01"),
            "invalid message safe outcome"
        );
        match bytes.get(5).copied() {
            Some(1) if bytes.len() == 22 => Ok(Self::Accepted {
                queue_item_id: bytes[6..22].try_into()?,
            }),
            Some(2) if bytes.len() == 14 => Ok(Self::Materialized {
                message_seq: u64::from_be_bytes(bytes[6..14].try_into()?),
            }),
            Some(3) if bytes.len() == 6 => Ok(Self::TerminalRejected),
            Some(4) if bytes.len() == 6 => Ok(Self::Removed),
            _ => anyhow::bail!("invalid message safe outcome"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalMessageState {
    TerminalRejected,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageAttachmentReceiptIdentity {
    pub client_submission_id: [u8; 16],
    pub ordinal: u8,
    pub attachment_id: [u8; 16],
    pub attachment_version: u64,
    pub checksum: [u8; 32],
    pub kind: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageReceiptStatus {
    pub operation_id: [u8; 16],
    pub client_submission_id: [u8; 16],
    pub actor_kind: String,
    pub actor_generation: u64,
    pub request_hash: [u8; 32],
    pub message_request_digest: [u8; 32],
    pub state: String,
    pub safe_outcome: MessageSafeOutcome,
    pub message_seq: Option<i64>,
    pub fold_ordinal: Option<i64>,
    pub attachments: Vec<MessageAttachmentReceiptIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedMessageQueueRow {
    pub queue_item_id: [u8; 16],
    pub client_submission_id: [u8; 16],
    pub canonical_message: Vec<u8>,
}

/// Prerequisite integrations invoked while the one SQLite writer transaction
/// is open. Remote implementations reserve the FCOR ledger/outbox row here;
/// local-owner implementations only recheck attachment/model admission.
pub trait MessageAcceptanceJoin: Send + Sync {
    fn validate_and_join(&self, conn: &Connection, input: &AcceptMessageInput) -> Result<()>;
}

impl Db {
    /// Return a previously committed local-owner acceptance before any caller
    /// allocates fresh authority material.  The durable operation receipt is
    /// the replay authority; in particular a new key version or randomized
    /// locator seal must not be required to replay it.
    pub async fn exact_local_message_replay_outcome(
        &self,
        session_id: Uuid,
        operation_id: [u8; 16],
        client_submission_id: [u8; 16],
        request_hash: [u8; 32],
        message_request_digest: [u8; 32],
        attachment_set_digest: [u8; 32],
    ) -> Result<Option<MessageSafeOutcome>> {
        self.read(move |conn| {
            let outcome = conn
                .query_row(
                    "SELECT o.safe_outcome
                       FROM message_operation_receipts o
                       JOIN message_submission_receipts s
                         ON s.session_id = o.session_id
                        AND s.operation_id = o.operation_id
                      WHERE o.session_id = ?1
                        AND o.operation_id = ?2
                        AND o.actor_kind = 'local_owner'
                        AND o.actor_id IS NULL
                        AND o.actor_generation = ?3
                        AND o.client_submission_id = ?4
                        AND o.request_hash = ?5
                        AND o.message_request_digest = ?6
                        AND s.attachment_set_digest = ?7",
                    params![
                        session_id.to_string(),
                        operation_id.as_slice(),
                        0_u64.to_be_bytes().as_slice(),
                        client_submission_id.as_slice(),
                        request_hash.as_slice(),
                        message_request_digest.as_slice(),
                        attachment_set_digest.as_slice(),
                    ],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?;
            outcome
                .map(|bytes| MessageSafeOutcome::decode(&bytes))
                .transpose()
        })
        .await
    }

    pub async fn accept_message_with_attachments(
        &self,
        input: AcceptMessageInput,
        join: Arc<dyn MessageAcceptanceJoin>,
    ) -> Result<AcceptMessageResult> {
        self.transaction(move |conn| accept_conn(conn, &input, join.as_ref()))
            .await
    }

    pub async fn materialize_message_submissions(
        &self,
        session_id: Uuid,
        submissions: Vec<[u8; 16]>,
        agent: Option<String>,
        origin_principal: Option<String>,
        history_data_json: String,
        now_ms: i64,
    ) -> Result<i64> {
        self.transaction(move |conn| {
            ensure!(!submissions.is_empty(), "no submissions to materialize");
            let message_seq = Db::insert_session_event_json_conn(
                conn,
                session_id,
                crate::db::session_log::SessionEventKind::UserMessage,
                agent.as_deref(),
                None,
                crate::db::session_log::SessionEventContext {
                    origin_principal: origin_principal.as_deref(),
                    ..Default::default()
                },
                now_ms,
                &history_data_json,
            )?;
            for (fold_ordinal, submission) in submissions.iter().enumerate() {
                let outcome = MessageSafeOutcome::Materialized { message_seq: message_seq as u64 }.encode();
                let changed = conn.execute("UPDATE message_submission_receipts SET state='materialized',message_seq=?3,fold_ordinal=?4,safe_outcome=?5,updated_at=?6 WHERE session_id=?1 AND client_submission_id=?2 AND state='accepted'", params![session_id.to_string(),submission.as_slice(),message_seq,fold_ordinal as i64,outcome,now_ms])?;
                ensure!(changed == 1, "message receipt is not accepted");
                let operation_changed = conn.execute("UPDATE message_operation_receipts SET state='materialized',safe_outcome=?3,updated_at=?4 WHERE session_id=?1 AND client_submission_id=?2 AND state='accepted'", params![session_id.to_string(),submission.as_slice(),outcome,now_ms])?;
                ensure!(operation_changed == 1, "message operation is not accepted");
                let queue_changed = conn.execute("UPDATE message_queue_items SET state='materialized',updated_at=?3 WHERE session_id=?1 AND client_submission_id=?2 AND state IN ('accepted','folding')", params![session_id.to_string(),submission.as_slice(),now_ms])?;
                ensure!(queue_changed == 1, "message queue item is not accepted");
                release_message_attachment_references_conn(
                    conn,
                    session_id,
                    submission,
                    now_ms,
                )?;
            }
            Ok(message_seq)
        }).await
    }

    pub async fn terminate_accepted_message(
        &self,
        session_id: Uuid,
        submission: [u8; 16],
        state: TerminalMessageState,
        now_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let state = match state { TerminalMessageState::TerminalRejected => "terminal_rejected", TerminalMessageState::Removed => "removed" };
            let safe_outcome = match state { "terminal_rejected" => MessageSafeOutcome::TerminalRejected, _ => MessageSafeOutcome::Removed }.encode();
            let changed = conn.execute("UPDATE message_submission_receipts SET state=?3,safe_outcome=?4,updated_at=?5 WHERE session_id=?1 AND client_submission_id=?2 AND state='accepted'", params![session_id.to_string(),submission.as_slice(),state,safe_outcome,now_ms])?;
            if changed == 0 { return Ok(false); }
            let invocation_id = Uuid::from_bytes(submission);
            let (terminal_reason, invocation_state) = match state {
                "removed" => ("cancelled", "cancelled"),
                _ => ("failed", "failed"),
            };
            crate::db::run_invocations::mark_run_invocation_terminal_conn(
                conn,
                invocation_id,
                Some(session_id),
                terminal_reason,
                invocation_state,
                now_ms,
            )?;
            conn.execute("UPDATE message_operation_receipts SET state=?3,safe_outcome=?4,updated_at=?5 WHERE session_id=?1 AND client_submission_id=?2 AND state='accepted'", params![session_id.to_string(),submission.as_slice(),state,safe_outcome,now_ms])?;
            conn.execute("UPDATE message_queue_items SET state=?3,updated_at=?4 WHERE session_id=?1 AND client_submission_id=?2 AND state IN ('accepted','folding')", params![session_id.to_string(),submission.as_slice(),state,now_ms])?;
            release_message_attachment_references_conn(conn, session_id, &submission, now_ms)?;
            // A terminal submission has no in-flight turn left to consume its
            // media authority. Remove the binding in the same authoritative
            // transition and begin secure-key release immediately.
            crate::db::tool_media_subject_bindings::release_tool_media_subject_binding_conn(
                conn,
                &session_id.to_string(),
                &submission,
            )?;
            Ok(true)
        }).await
    }

    pub async fn message_attachment_receipts(
        &self,
        session_id: Uuid,
        submission: [u8; 16],
    ) -> Result<Vec<MessageAttachmentReceiptIdentity>> {
        self.read(move |conn| {
            let mut stmt = conn.prepare("SELECT ordinal,attachment_id,attachment_version,checksum,kind FROM message_attachment_references WHERE session_id=?1 AND client_submission_id=?2 ORDER BY ordinal")?;
            let rows = stmt.query_map(params![session_id.to_string(),submission.as_slice()], |row| {
                let attachment_id: Vec<u8> = row.get(1)?; let version: Vec<u8> = row.get(2)?; let checksum: Vec<u8> = row.get(3)?;
                Ok(MessageAttachmentReceiptIdentity { client_submission_id: submission, ordinal: row.get::<_,i64>(0)? as u8, attachment_id: attachment_id.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?, attachment_version: u64::from_be_bytes(version.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?), checksum: checksum.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?, kind: row.get(4)? })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
        }).await
    }

    /// Read the durable disposition for a submission identity. Workers use
    /// this immediately before materialization so an in-memory delivery that
    /// raced a terminal transition can never reach provider I/O.
    pub async fn message_submission_safe_outcome(
        &self,
        session_id: Uuid,
        submission: [u8; 16],
    ) -> Result<Option<MessageSafeOutcome>> {
        self.read(move |conn| {
            let outcome = conn
                .query_row(
                    "SELECT safe_outcome FROM message_submission_receipts WHERE session_id=?1 AND client_submission_id=?2",
                    params![session_id.to_string(), submission.as_slice()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?;
            outcome
                .map(|outcome| MessageSafeOutcome::decode(&outcome))
                .transpose()
        })
        .await
    }

    pub async fn accepted_message_queue(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<AcceptedMessageQueueRow>> {
        self.read(move |conn| {
            let mut stmt = conn.prepare("SELECT queue_item_id,client_submission_id,canonical_message FROM message_queue_items WHERE session_id=?1 AND state='accepted' ORDER BY created_at,queue_item_id")?;
            let rows = stmt.query_map([session_id.to_string()], |row| {
                let queue: Vec<u8> = row.get(0)?; let submission: Vec<u8> = row.get(1)?;
                Ok(AcceptedMessageQueueRow { queue_item_id: queue.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?, client_submission_id: submission.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?, canonical_message: row.get(2)? })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
        }).await
    }

    pub async fn canonical_message_for_operation(
        &self,
        session_id: Uuid,
        operation_id: [u8; 16],
    ) -> Result<Option<Vec<u8>>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT q.canonical_message FROM message_operation_receipts o JOIN message_queue_items q ON q.session_id=o.session_id AND q.client_submission_id=o.client_submission_id WHERE o.session_id=?1 AND o.operation_id=?2",
                params![session_id.to_string(), operation_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
        })
        .await
    }

    pub async fn message_receipt_status(
        &self,
        session_id: Uuid,
        operation_id: [u8; 16],
    ) -> Result<Option<MessageReceiptStatus>> {
        self.read(move |conn| {
            let row = conn.query_row("SELECT o.client_submission_id,o.actor_kind,o.actor_generation,o.request_hash,o.message_request_digest,o.state,o.safe_outcome,s.message_seq,s.fold_ordinal FROM message_operation_receipts o JOIN message_submission_receipts s ON s.session_id=o.session_id AND s.operation_id=o.operation_id WHERE o.session_id=?1 AND o.operation_id=?2", params![session_id.to_string(),operation_id.as_slice()], |row| Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,String>(1)?,row.get::<_,Vec<u8>>(2)?,row.get::<_,Vec<u8>>(3)?,row.get::<_,Vec<u8>>(4)?,row.get::<_,String>(5)?,row.get::<_,Vec<u8>>(6)?,row.get::<_,Option<i64>>(7)?,row.get::<_,Option<i64>>(8)?))).optional()?;
            let Some((submission,actor_kind,generation,request_hash,message_digest,state,outcome,message_seq,fold_ordinal)) = row else { return Ok(None); };
            let submission: [u8;16] = submission.try_into().map_err(|_| anyhow::anyhow!("invalid stored submission id"))?;
            let mut stmt = conn.prepare("SELECT ordinal,attachment_id,attachment_version,checksum,kind FROM message_attachment_references WHERE session_id=?1 AND client_submission_id=?2 ORDER BY ordinal")?;
            let attachments = stmt.query_map(params![session_id.to_string(),submission.as_slice()], |row| {
                let id:Vec<u8>=row.get(1)?;let version:Vec<u8>=row.get(2)?;let checksum:Vec<u8>=row.get(3)?;
                Ok(MessageAttachmentReceiptIdentity { client_submission_id:submission, ordinal:row.get::<_,i64>(0)? as u8, attachment_id:id.try_into().map_err(|_|rusqlite::Error::InvalidQuery)?, attachment_version:u64::from_be_bytes(version.try_into().map_err(|_|rusqlite::Error::InvalidQuery)?), checksum:checksum.try_into().map_err(|_|rusqlite::Error::InvalidQuery)?, kind:row.get(4)? })
            })?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(Some(MessageReceiptStatus { operation_id, client_submission_id:submission, actor_kind, actor_generation:u64::from_be_bytes(generation.try_into().map_err(|_|anyhow::anyhow!("invalid stored actor generation"))?), request_hash:request_hash.try_into().map_err(|_|anyhow::anyhow!("invalid stored request hash"))?, message_request_digest:message_digest.try_into().map_err(|_|anyhow::anyhow!("invalid stored message digest"))?, state, safe_outcome:MessageSafeOutcome::decode(&outcome)?, message_seq, fold_ordinal, attachments }))
        }).await
    }
}

fn release_message_attachment_references_conn(
    conn: &Connection,
    session_id: Uuid,
    submission: &[u8; 16],
    now_ms: i64,
) -> Result<()> {
    conn.execute(
        "UPDATE message_attachment_references
            SET released_at=?3
          WHERE session_id=?1 AND client_submission_id=?2 AND released_at IS NULL",
        params![session_id.to_string(), submission.as_slice(), now_ms],
    )?;
    let consumer_id = Uuid::from_bytes(*submission).to_string();
    conn.execute(
        "UPDATE media_attachment_references
            SET released_at_unix_ms=?3
          WHERE consumer_kind='message'
            AND consumer_id=?2
            AND attachment_id IN (
                SELECT attachment_id FROM media_attachments WHERE session_id=?1
            )
            AND released_at_unix_ms IS NULL",
        params![session_id.to_string(), consumer_id, now_ms],
    )?;
    Ok(())
}

pub(crate) fn accept_conn(
    conn: &Connection,
    input: &AcceptMessageInput,
    join: &dyn MessageAcceptanceJoin,
) -> Result<AcceptMessageResult> {
    ensure!(
        input.canonical_message.len() <= MAX_QUEUED_CANONICAL_MESSAGE_BYTES,
        "canonical message exceeds FCM2 maximum"
    );
    ensure!(
        input.canonical_message.len() >= 5 && input.canonical_message.starts_with(b"FCM2"),
        "canonical message is not a non-empty FCM2 envelope"
    );
    ensure!(
        input.attachments.len() <= 16,
        "too many message attachments"
    );
    ensure!(
        input.operation_id != [0; 16] && input.client_submission_id != [0; 16],
        "nil durable identity"
    );
    ensure!(
        input.operation_id != input.client_submission_id,
        "operation and submission identities must differ"
    );
    ensure!(input.outbox_sequence >= 0, "negative outbox sequence");
    if let MessageActor::ExternalPrincipal { id, generation } = input.actor {
        ensure!(
            id != [0; 16] && generation > 0,
            "invalid remote actor binding"
        );
    }
    let mut attachment_ids = std::collections::HashSet::new();
    for attachment in &input.attachments {
        ensure!(
            attachment.attachment_id != [0; 16],
            "nil attachment identity"
        );
        ensure!(attachment.attachment_version > 0, "zero attachment version");
        ensure!(
            (1..=3).contains(&attachment.kind),
            "unknown attachment kind"
        );
        ensure!(
            attachment_ids.insert(attachment.attachment_id),
            "duplicate attachment identity"
        );
    }
    let session = input.session_id.to_string();
    if let Some(binding) = &input.tool_media_subject_binding {
        ensure!(
            binding.session_id == input.session_id
                && binding.client_submission_id == input.client_submission_id,
            "tool-media-subject binding identity does not match accepted message"
        );
    }
    let existing = conn.query_row(
        "SELECT o.actor_kind,o.actor_id,o.actor_generation,o.request_hash,o.message_request_digest,o.client_submission_id,o.safe_outcome,s.attachment_set_digest
           FROM message_operation_receipts o LEFT JOIN message_submission_receipts s ON s.session_id=o.session_id AND s.operation_id=o.operation_id
          WHERE o.session_id=?1 AND o.operation_id=?2",
        params![session, input.operation_id.as_slice()],
        |row| Ok((row.get::<_,String>(0)?, row.get::<_,Option<Vec<u8>>>(1)?, row.get::<_,Vec<u8>>(2)?, row.get::<_,Vec<u8>>(3)?, row.get::<_,Vec<u8>>(4)?, row.get::<_,Vec<u8>>(5)?, row.get::<_,Vec<u8>>(6)?, row.get::<_,Option<Vec<u8>>>(7)?)),
    ).optional().context("reading message operation receipt")?;
    if let Some((
        kind,
        id,
        generation,
        request_hash,
        message_digest,
        submission,
        outcome,
        attachment_digest,
    )) = existing
    {
        let (expected_kind, expected_id, expected_generation) = actor_parts(input.actor);
        if kind == expected_kind
            && id.as_deref() == expected_id.as_deref()
            && generation == expected_generation
            && request_hash == input.request_hash
            && message_digest == input.message_request_digest
            && submission == input.client_submission_id
            && attachment_digest.as_deref() == Some(input.attachment_set_digest.as_slice())
            && tool_media_binding_replay_matches_conn(conn, &session, input)?
        {
            return Ok(AcceptMessageResult::Replayed {
                safe_outcome: MessageSafeOutcome::decode(&outcome)?,
            });
        }
        return Ok(AcceptMessageResult::Conflict);
    }
    let paired_conflict: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM message_operation_receipts WHERE session_id=?1 AND client_submission_id=?2)",
        params![session, input.client_submission_id.as_slice()], |row| row.get(0),
    ).context("checking submission pairing")?;
    if paired_conflict {
        return Ok(AcceptMessageResult::Conflict);
    }
    join.validate_and_join(conn, input)?;
    let (actor_kind, actor_id, actor_generation) = actor_parts(input.actor);
    let safe_outcome = MessageSafeOutcome::Accepted {
        queue_item_id: input.queue_item_id,
    }
    .encode();
    conn.execute("INSERT INTO message_operation_receipts
      (session_id,operation_id,actor_kind,actor_id,actor_generation,request_hash,message_request_digest,client_submission_id,state,safe_outcome,outbox_sequence,created_at,updated_at)
      VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'accepted',?9,?10,?11,?11)",
      params![session,input.operation_id.as_slice(),actor_kind,actor_id,actor_generation,input.request_hash.as_slice(),input.message_request_digest.as_slice(),input.client_submission_id.as_slice(),safe_outcome,input.outbox_sequence,input.now_ms])?;
    conn.execute("INSERT INTO message_submission_receipts
      (session_id,client_submission_id,operation_id,message_request_digest,attachment_set_digest,state,queue_item_id,safe_outcome,created_at,updated_at)
      VALUES (?1,?2,?3,?4,?5,'accepted',?6,?7,?8,?8)", params![session,input.client_submission_id.as_slice(),input.operation_id.as_slice(),input.message_request_digest.as_slice(),input.attachment_set_digest.as_slice(),input.queue_item_id.as_slice(),safe_outcome,input.now_ms])?;
    conn.execute("INSERT INTO message_queue_items (session_id,queue_item_id,client_submission_id,canonical_message,state,created_at,updated_at) VALUES (?1,?2,?3,?4,'accepted',?5,?5)", params![session,input.queue_item_id.as_slice(),input.client_submission_id.as_slice(),input.canonical_message,input.now_ms])?;
    for (ordinal, attachment) in input.attachments.iter().enumerate() {
        conn.execute("INSERT INTO message_attachment_references (session_id,client_submission_id,ordinal,attachment_id,attachment_version,checksum,kind,acquired_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", params![session,input.client_submission_id.as_slice(),ordinal as i64,attachment.attachment_id.as_slice(),attachment.attachment_version.to_be_bytes().as_slice(),attachment.checksum.as_slice(),attachment.kind,input.now_ms])?;
    }
    // Atomically insert the tool-media-subject binding if present.
    //
    // Secure-key ref lifecycle (issue #70 piece 4): reserve the consumer ref
    // BEFORE the binding insert, then activate it AFTER the binding row is
    // reachable — all in the same transaction. A failed reservation
    // (NotFound/NotReservable/Conflict) fails the entire acceptance
    // transaction so no durable binding can outlive its key reference.
    if let Some(binding) = &input.tool_media_subject_binding {
        let submission_hex: String = binding
            .client_submission_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let consumer_id = format!("{session}/{submission_hex}");

        // 1. Reserve the consumer ref (Reserved → Active is the next step).
        use crate::db::secure_key::{ReserveResult, reserve_consumer_ref_conn};
        let reserve_result = reserve_consumer_ref_conn(
            conn,
            &binding.secure_key_reference_id,
            &binding.key_namespace,
            binding.key_version,
            // The consumer kind matches the constant in cockpit-core's
            // tool_media_authority module: "tool_media_subject_binding".
            "tool_media_subject_binding",
            &consumer_id,
        )
        .context("reserving tool-media-subject-binding secure-key ref")?;
        match reserve_result {
            ReserveResult::Reserved(_) | ReserveResult::Idempotent(_) => {}
            ReserveResult::NotFound => {
                anyhow::bail!(
                    "secure-key version not found for tool-media-subject-binding ref: \
                     namespace={}, version={}",
                    binding.key_namespace,
                    binding.key_version
                );
            }
            ReserveResult::Retiring => {
                anyhow::bail!(
                    "secure-key version is retiring; cannot reserve tool-media-subject-binding ref"
                );
            }
            ReserveResult::NotReservable { state } => {
                anyhow::bail!(
                    "secure-key version not reservable (state={:?}); \
                     cannot reserve tool-media-subject-binding ref",
                    state
                );
            }
            ReserveResult::Conflict => {
                anyhow::bail!("secure-key consumer ref conflict for tool-media-subject-binding");
            }
        }

        // 2. Insert the binding row — this makes the consumer data reachable.
        Db::insert_tool_media_subject_binding_conn(conn, binding)?;

        // 3. Activate the consumer ref now that the binding is reachable.
        use crate::db::secure_key::activate_consumer_ref_conn;
        let activated = activate_consumer_ref_conn(conn, &binding.secure_key_reference_id)
            .context("activating tool-media-subject-binding secure-key ref")?;
        if !activated {
            anyhow::bail!(
                "failed to activate tool-media-subject-binding secure-key ref \
                 (not in Reserved state after insert)"
            );
        }
    }
    Ok(AcceptMessageResult::Accepted)
}

fn tool_media_binding_replay_matches_conn(
    conn: &Connection,
    session_id: &str,
    input: &AcceptMessageInput,
) -> Result<bool> {
    // The receipt/seal are daemon-private acceptance artifacts, not client
    // request identity.  Once the durable operation, canonical message, and
    // attachment set above match exactly, replay must succeed even after the
    // binding has been released or a current key would produce a randomized
    // new seal. Keep this helper as an explicit read of the row so corruption
    // surfaces as a DB error rather than silently widening the replay query.
    let _ =
        Db::load_tool_media_subject_binding_conn(conn, session_id, &input.client_submission_id)?;
    Ok(true)
}

fn actor_parts(actor: MessageActor) -> (&'static str, Option<Vec<u8>>, Vec<u8>) {
    match actor {
        MessageActor::LocalOwner => ("local_owner", None, 0u64.to_be_bytes().to_vec()),
        MessageActor::ExternalPrincipal { id, generation } => (
            "external_principal",
            Some(id.to_vec()),
            generation.to_be_bytes().to_vec(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_binding_receipt(session_id: Uuid, version: u8) -> Vec<u8> {
        let mut bytes = vec![version, 1];
        bytes.extend_from_slice(&[0xAA; 32]);
        bytes.extend_from_slice(&[0xBB; 32]);
        bytes.extend_from_slice(session_id.as_bytes());
        bytes.extend_from_slice(&0_u64.to_be_bytes());
        bytes.extend_from_slice(&[0xCC; 32]);
        bytes
    }

    struct Allow;
    impl MessageAcceptanceJoin for Allow {
        fn validate_and_join(&self, _: &Connection, _: &AcceptMessageInput) -> Result<()> {
            Ok(())
        }
    }

    fn input(session_id: Uuid) -> AcceptMessageInput {
        AcceptMessageInput {
            session_id,
            operation_id: [1; 16],
            actor: MessageActor::LocalOwner,
            request_hash: [2; 32],
            message_request_digest: [3; 32],
            attachment_set_digest: [4; 32],
            client_submission_id: [5; 16],
            queue_item_id: [6; 16],
            canonical_message: b"FCM2\x02".to_vec(),
            attachments: vec![MessageAttachmentReferenceInput {
                attachment_id: [7; 16],
                attachment_version: u64::MAX,
                checksum: [8; 32],
                kind: 2,
            }],
            outbox_sequence: 1,
            now_ms: 10,
            tool_media_subject_binding: None,
        }
    }

    #[tokio::test]
    async fn message_attachment_exactly_once_accept_replay_conflict_and_release() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/workspace", "Build")
            .await
            .unwrap();
        let original = input(session.session_id);
        assert_eq!(
            db.accept_message_with_attachments(original.clone(), Arc::new(Allow))
                .await
                .unwrap(),
            AcceptMessageResult::Accepted
        );
        assert_eq!(
            db.accept_message_with_attachments(original.clone(), Arc::new(Allow))
                .await
                .unwrap(),
            AcceptMessageResult::Replayed {
                safe_outcome: MessageSafeOutcome::Accepted {
                    queue_item_id: [6; 16]
                }
            }
        );
        let mut changed = original.clone();
        changed.request_hash[0] ^= 1;
        assert_eq!(
            db.accept_message_with_attachments(changed, Arc::new(Allow))
                .await
                .unwrap(),
            AcceptMessageResult::Conflict
        );
        let mut changed_attachments = original.clone();
        changed_attachments.attachment_set_digest[0] ^= 1;
        assert_eq!(
            db.accept_message_with_attachments(changed_attachments, Arc::new(Allow))
                .await
                .unwrap(),
            AcceptMessageResult::Conflict
        );
        let mut changed_message = original.clone();
        changed_message.message_request_digest[0] ^= 1;
        assert_eq!(
            db.accept_message_with_attachments(changed_message, Arc::new(Allow))
                .await
                .unwrap(),
            AcceptMessageResult::Conflict
        );
        let mut changed_submission = original.clone();
        changed_submission.client_submission_id = [9; 16];
        assert_eq!(
            db.accept_message_with_attachments(changed_submission, Arc::new(Allow))
                .await
                .unwrap(),
            AcceptMessageResult::Conflict
        );
        let mut changed_actor = original.clone();
        changed_actor.actor = MessageActor::ExternalPrincipal {
            id: [10; 16],
            generation: 1,
        };
        assert_eq!(
            db.accept_message_with_attachments(changed_actor, Arc::new(Allow))
                .await
                .unwrap(),
            AcceptMessageResult::Conflict
        );
        assert_eq!(
            db.message_attachment_receipts(session.session_id, original.client_submission_id)
                .await
                .unwrap()
                .len(),
            1
        );
        let queue = db.accepted_message_queue(session.session_id).await.unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].canonical_message, b"FCM2\x02");
        let status = db
            .message_receipt_status(session.session_id, original.operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.actor_kind, "local_owner");
        assert_eq!(status.actor_generation, 0);
        assert_eq!(status.attachments[0].attachment_version, u64::MAX);
        assert!(
            db.terminate_accepted_message(
                session.session_id,
                original.client_submission_id,
                TerminalMessageState::Removed,
                11
            )
            .await
            .unwrap()
        );
        assert!(
            !db.terminate_accepted_message(
                session.session_id,
                original.client_submission_id,
                TerminalMessageState::Removed,
                12
            )
            .await
            .unwrap()
        );
        assert_eq!(
            db.accept_message_with_attachments(original, Arc::new(Allow))
                .await
                .unwrap(),
            AcceptMessageResult::Replayed {
                safe_outcome: MessageSafeOutcome::Removed
            }
        );
    }

    struct Deny;
    impl MessageAcceptanceJoin for Deny {
        fn validate_and_join(&self, _: &Connection, _: &AcceptMessageInput) -> Result<()> {
            anyhow::bail!("capability changed")
        }
    }

    #[tokio::test]
    async fn message_attachment_cleanup_race_denial_leaves_no_partial_rows() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/workspace", "Build")
            .await
            .unwrap();
        let input = input(session.session_id);
        assert!(
            db.accept_message_with_attachments(input.clone(), Arc::new(Deny))
                .await
                .is_err()
        );
        assert!(
            db.message_attachment_receipts(session.session_id, input.client_submission_id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn canonical_message_limit_direct_sql_rejects_type_magic_and_outer_bound_bypasses() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/workspace", "Build")
            .await
            .unwrap();
        let accepted = input(session.session_id);
        db.accept_message_with_attachments(accepted.clone(), Arc::new(Allow))
            .await
            .unwrap();

        let session_id = session.session_id.to_string();
        let queue_item_id = accepted.queue_item_id;
        db.transaction(move |conn| {
            let update = |canonical_message: &dyn rusqlite::ToSql| {
                conn.execute(
                    "UPDATE message_queue_items SET canonical_message=?1
                      WHERE session_id=?2 AND queue_item_id=?3",
                    rusqlite::params![canonical_message, session_id, queue_item_id.as_slice()],
                )
            };
            let text_value = "FCM2\\x02".to_owned();
            let under_five = b"FCM2".to_vec();
            let wrong_magic = b"NOPE\\x02".to_vec();
            assert!(
                update(&text_value).is_err(),
                "TEXT must not pass the BLOB guard"
            );
            assert!(update(&under_five).is_err(), "under-five BLOB must fail");
            assert!(update(&wrong_magic).is_err(), "wrong-magic BLOB must fail");
            let mut one_over = vec![b'x'; MAX_QUEUED_CANONICAL_MESSAGE_BYTES + 1];
            one_over[..4].copy_from_slice(b"FCM2");
            assert!(
                update(&one_over).is_err(),
                "outer-cap-plus-one BLOB must fail"
            );
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn message_attachment_materialization_mismatch_rolls_back_history_and_states() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/workspace", "Build")
            .await
            .unwrap();
        let input = input(session.session_id);
        db.accept_message_with_attachments(input.clone(), Arc::new(Allow))
            .await
            .unwrap();
        assert!(
            db.materialize_message_submissions(
                session.session_id,
                vec![input.client_submission_id, [99; 16]],
                None,
                None,
                "{\"client_submission_ids\":[]}".into(),
                20
            )
            .await
            .is_err()
        );
        let accepted_outcome = MessageSafeOutcome::Accepted {
            queue_item_id: input.queue_item_id,
        }
        .encode();
        let (events, operation, submission, queue) = db.read(move |conn| {
            let events: i64 = conn.query_row(
                "SELECT COUNT(*) FROM session_events WHERE session_id=?1 AND type='user_message'",
                [session.session_id.to_string()],
                |row| row.get(0),
            )?;
            let operation = conn.query_row("SELECT state,safe_outcome,created_at,updated_at FROM message_operation_receipts WHERE session_id=?1 AND operation_id=?2", params![session.session_id.to_string(),input.operation_id.as_slice()], |row| Ok((row.get::<_,String>(0)?,row.get::<_,Vec<u8>>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?)))?;
            let submission = conn.query_row("SELECT state,safe_outcome,message_seq,fold_ordinal,created_at,updated_at FROM message_submission_receipts WHERE session_id=?1 AND client_submission_id=?2", params![session.session_id.to_string(),input.client_submission_id.as_slice()], |row| Ok((row.get::<_,String>(0)?,row.get::<_,Vec<u8>>(1)?,row.get::<_,Option<i64>>(2)?,row.get::<_,Option<i64>>(3)?,row.get::<_,i64>(4)?,row.get::<_,i64>(5)?)))?;
            let queue = conn.query_row("SELECT state,created_at,updated_at FROM message_queue_items WHERE session_id=?1 AND queue_item_id=?2", params![session.session_id.to_string(),input.queue_item_id.as_slice()], |row| Ok((row.get::<_,String>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?)))?;
            Ok((events, operation, submission, queue))
        }).await.unwrap();
        assert_eq!(events, 0);
        assert_eq!(
            operation,
            ("accepted".into(), accepted_outcome.clone(), 10, 10)
        );
        assert_eq!(
            submission,
            ("accepted".into(), accepted_outcome, None, None, 10, 10)
        );
        assert_eq!(queue, ("accepted".into(), 10, 10));
    }

    #[tokio::test]
    async fn message_attachment_remote_actor_id_and_generation_rebinding_conflict() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/workspace", "Build")
            .await
            .unwrap();
        let mut original = input(session.session_id);
        original.actor = MessageActor::ExternalPrincipal {
            id: [11; 16],
            generation: 2,
        };
        assert_eq!(
            db.accept_message_with_attachments(original.clone(), Arc::new(Allow))
                .await
                .unwrap(),
            AcceptMessageResult::Accepted
        );
        let mut changed_id = original.clone();
        changed_id.actor = MessageActor::ExternalPrincipal {
            id: [12; 16],
            generation: 2,
        };
        assert_eq!(
            db.accept_message_with_attachments(changed_id, Arc::new(Allow))
                .await
                .unwrap(),
            AcceptMessageResult::Conflict
        );
        let mut changed_generation = original;
        changed_generation.actor = MessageActor::ExternalPrincipal {
            id: [11; 16],
            generation: 3,
        };
        assert_eq!(
            db.accept_message_with_attachments(changed_generation, Arc::new(Allow))
                .await
                .unwrap(),
            AcceptMessageResult::Conflict
        );
    }

    // ---- Secure-key ref lifecycle (issue #70 piece 4) -----------------------

    use crate::db::secure_key::{
        SecureKeyRefState, SecureKeyVersionState, ensure_namespace_conn, get_ref_by_id_conn,
    };

    /// Hex-encode a 16-byte submission id.
    fn submission_hex(id: &[u8; 16]) -> String {
        id.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Set up a secure-key namespace with an Active version 1 so that a
    /// consumer ref can be reserved against it.
    fn setup_active_key_version(conn: &Connection) -> Result<()> {
        ensure_namespace_conn(conn, "tool_media_subject_binding")?;
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT INTO secure_key_versions
                (namespace, version, state, key_digest, created_at, updated_at)
             VALUES (?1, 1, ?2, 'test-digest', ?3, ?3)",
            params![
                "tool_media_subject_binding",
                SecureKeyVersionState::Active.as_str(),
                now
            ],
        )?;
        conn.execute(
            "UPDATE secure_key_namespaces SET active_version = 1, updated_at = ?1
             WHERE namespace = ?2",
            params![now, "tool_media_subject_binding"],
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn accept_with_binding_reserves_and_activates_secure_key_ref() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/workspace", "Build")
            .await
            .unwrap();

        // Provision the secure-key namespace + active version 1.
        db.write(setup_active_key_version).await.unwrap();

        let mut input = input(session.session_id);
        input.tool_media_subject_binding = Some(
            crate::db::tool_media_subject_bindings::ToolMediaSubjectBindingInsertV1 {
                session_id: session.session_id,
                client_submission_id: input.client_submission_id,
                receipt_version: 1,
                issuer_kind: 1,
                principal_digest: [0xAA; 32],
                project_digest: [0xBB; 32],
                authorization_epoch: 0,
                subject_digest: [0xCC; 32],
                seal_version: 1,
                key_namespace: "tool_media_subject_binding".to_string(),
                key_version: 1,
                nonce: [0xDD; 24],
                ciphertext: vec![0xEE; 48],
                secure_key_reference_id: format!(
                    "tool-media-subject-binding/{}/{}/1",
                    session.session_id,
                    submission_hex(&input.client_submission_id)
                ),
                receipt_bytes: test_binding_receipt(session.session_id, 1),
                now_ms: 20,
            },
        );

        let result = db
            .accept_message_with_attachments(input.clone(), Arc::new(Allow))
            .await
            .unwrap();
        assert_eq!(result, AcceptMessageResult::Accepted);

        // An exact durable acceptance is discoverable before a caller mints
        // another seal/key binding. This remains the replay path after key
        // rotation or normal post-turn binding release.
        let replay = db
            .exact_local_message_replay_outcome(
                session.session_id,
                input.operation_id,
                input.client_submission_id,
                input.request_hash,
                input.message_request_digest,
                input.attachment_set_digest,
            )
            .await
            .unwrap();
        assert_eq!(
            replay,
            Some(MessageSafeOutcome::Accepted {
                queue_item_id: input.queue_item_id,
            })
        );

        // The secure-key consumer ref should be Active.
        let ref_id = input
            .tool_media_subject_binding
            .as_ref()
            .unwrap()
            .secure_key_reference_id
            .clone();
        let ref_state = db
            .read(move |conn| {
                let r = get_ref_by_id_conn(conn, &ref_id)?.unwrap();
                Ok(r.state)
            })
            .await
            .unwrap();
        assert_eq!(ref_state, SecureKeyRefState::Active);

        // The binding row should exist.
        let row = db
            .load_tool_media_subject_binding(session.session_id, input.client_submission_id)
            .await
            .unwrap();
        assert!(row.is_some());
    }

    #[tokio::test]
    async fn accept_with_binding_fails_when_key_version_missing() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/workspace", "Build")
            .await
            .unwrap();

        // Do NOT provision the secure-key namespace — reserve must fail.
        let mut input = input(session.session_id);
        input.tool_media_subject_binding = Some(
            crate::db::tool_media_subject_bindings::ToolMediaSubjectBindingInsertV1 {
                session_id: session.session_id,
                client_submission_id: input.client_submission_id,
                receipt_version: 1,
                issuer_kind: 1,
                principal_digest: [0xAA; 32],
                project_digest: [0xBB; 32],
                authorization_epoch: 0,
                subject_digest: [0xCC; 32],
                seal_version: 1,
                key_namespace: "tool_media_subject_binding".to_string(),
                key_version: 1,
                nonce: [0xDD; 24],
                ciphertext: vec![0xEE; 48],
                secure_key_reference_id: "tool-media-subject-binding/missing/1".to_string(),
                receipt_bytes: test_binding_receipt(session.session_id, 1),
                now_ms: 20,
            },
        );

        let result = db
            .accept_message_with_attachments(input.clone(), Arc::new(Allow))
            .await;
        assert!(
            result.is_err(),
            "acceptance must fail when the secure-key version is missing — no partial binding"
        );

        // No binding row should exist (transaction rolled back).
        let row = db
            .load_tool_media_subject_binding(session.session_id, input.client_submission_id)
            .await
            .unwrap();
        assert!(row.is_none());

        // No submission receipt either — the whole transaction rolled back.
        let receipts = db
            .message_attachment_receipts(session.session_id, input.client_submission_id)
            .await
            .unwrap();
        assert!(receipts.is_empty());
    }

    #[tokio::test]
    async fn accept_with_binding_rollback_on_insert_failure_releases_ref() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/workspace", "Build")
            .await
            .unwrap();

        db.write(setup_active_key_version).await.unwrap();

        let mut input = input(session.session_id);
        let ref_id = format!(
            "tool-media-subject-binding/{}/{}/1",
            session.session_id,
            submission_hex(&input.client_submission_id)
        );
        input.tool_media_subject_binding = Some(
            crate::db::tool_media_subject_bindings::ToolMediaSubjectBindingInsertV1 {
                session_id: session.session_id,
                client_submission_id: input.client_submission_id,
                // Invalid: validate_insert rejects receipt_version != 1
                // *after* the consumer ref is reserved.
                receipt_version: 2,
                issuer_kind: 1,
                principal_digest: [0xAA; 32],
                project_digest: [0xBB; 32],
                authorization_epoch: 0,
                subject_digest: [0xCC; 32],
                seal_version: 1,
                key_namespace: "tool_media_subject_binding".to_string(),
                key_version: 1,
                nonce: [0xDD; 24],
                ciphertext: vec![0xEE; 48],
                secure_key_reference_id: ref_id.clone(),
                receipt_bytes: test_binding_receipt(session.session_id, 2),
                now_ms: 20,
            },
        );

        // Reserve succeeds (key version exists), then binding insert fails
        // validation — the entire transaction, including the reserved ref
        // and the submission receipts, must roll back.
        let result = db
            .accept_message_with_attachments(input.clone(), Arc::new(Allow))
            .await;
        assert!(
            result.is_err(),
            "acceptance must fail when binding insert is invalid — no partial binding"
        );

        // No binding, no ref, no receipt.
        let row = db
            .load_tool_media_subject_binding(session.session_id, input.client_submission_id)
            .await
            .unwrap();
        assert!(row.is_none());

        let receipts = db
            .message_attachment_receipts(session.session_id, input.client_submission_id)
            .await
            .unwrap();
        assert!(receipts.is_empty());

        let ref_exists = db
            .read(move |conn| Ok(get_ref_by_id_conn(conn, &ref_id)?.is_some()))
            .await
            .unwrap();
        assert!(
            !ref_exists,
            "rolled-back acceptance must not leave a dangling secure-key ref"
        );
    }
}
