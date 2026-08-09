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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageActor {
    LocalOwner,
    RemoteDevice { id: [u8; 16], generation: u64 },
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
    fn encode(&self) -> Vec<u8> {
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
        history_data_json: String,
        now_ms: i64,
    ) -> Result<i64> {
        self.transaction(move |conn| {
            ensure!(!submissions.is_empty(), "no submissions to materialize");
            conn.execute("INSERT INTO session_events (session_id,ts_ms,type,data_json) VALUES (?1,?2,'user_message',?3)", params![session_id.to_string(),now_ms,history_data_json])?;
            let message_seq = conn.last_insert_rowid();
            for (fold_ordinal, submission) in submissions.iter().enumerate() {
                let outcome = MessageSafeOutcome::Materialized { message_seq: message_seq as u64 }.encode();
                let changed = conn.execute("UPDATE message_submission_receipts SET state='materialized',message_seq=?3,fold_ordinal=?4,safe_outcome=?5,updated_at=?6 WHERE session_id=?1 AND client_submission_id=?2 AND state='accepted'", params![session_id.to_string(),submission.as_slice(),message_seq,fold_ordinal as i64,outcome,now_ms])?;
                ensure!(changed == 1, "message receipt is not accepted");
                let operation_changed = conn.execute("UPDATE message_operation_receipts SET state='materialized',safe_outcome=?3,updated_at=?4 WHERE session_id=?1 AND client_submission_id=?2 AND state='accepted'", params![session_id.to_string(),submission.as_slice(),outcome,now_ms])?;
                ensure!(operation_changed == 1, "message operation is not accepted");
                let queue_changed = conn.execute("UPDATE message_queue_items SET state='materialized',updated_at=?3 WHERE session_id=?1 AND client_submission_id=?2 AND state IN ('accepted','folding')", params![session_id.to_string(),submission.as_slice(),now_ms])?;
                ensure!(queue_changed == 1, "message queue item is not accepted");
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
            conn.execute("UPDATE message_operation_receipts SET state=?3,safe_outcome=?4,updated_at=?5 WHERE session_id=?1 AND client_submission_id=?2 AND state='accepted'", params![session_id.to_string(),submission.as_slice(),state,safe_outcome,now_ms])?;
            conn.execute("UPDATE message_queue_items SET state=?3,updated_at=?4 WHERE session_id=?1 AND client_submission_id=?2 AND state IN ('accepted','folding')", params![session_id.to_string(),submission.as_slice(),state,now_ms])?;
            conn.execute("UPDATE message_attachment_references SET released_at=?3 WHERE session_id=?1 AND client_submission_id=?2 AND released_at IS NULL", params![session_id.to_string(),submission.as_slice(),now_ms])?;
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

fn accept_conn(
    conn: &Connection,
    input: &AcceptMessageInput,
    join: &dyn MessageAcceptanceJoin,
) -> Result<AcceptMessageResult> {
    ensure!(
        input.canonical_message.len() <= 2_631_500,
        "canonical message exceeds FCM2 maximum"
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
    if let MessageActor::RemoteDevice { id, generation } = input.actor {
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
    Ok(AcceptMessageResult::Accepted)
}

fn actor_parts(actor: MessageActor) -> (&'static str, Option<Vec<u8>>, Vec<u8>) {
    match actor {
        MessageActor::LocalOwner => ("local_owner", None, 0u64.to_be_bytes().to_vec()),
        MessageActor::RemoteDevice { id, generation } => (
            "remote_device",
            Some(id.to_vec()),
            generation.to_be_bytes().to_vec(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            canonical_message: b"FCM2".to_vec(),
            attachments: vec![MessageAttachmentReferenceInput {
                attachment_id: [7; 16],
                attachment_version: u64::MAX,
                checksum: [8; 32],
                kind: 2,
            }],
            outbox_sequence: 1,
            now_ms: 10,
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
        changed_actor.actor = MessageActor::RemoteDevice {
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
        assert_eq!(queue[0].canonical_message, b"FCM2");
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
            let events = conn.query_row("SELECT COUNT(*) FROM session_events WHERE session_id=?1 AND type='user_message'", [session.session_id.to_string()], |row| row.get(0))?;
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
        original.actor = MessageActor::RemoteDevice {
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
        changed_id.actor = MessageActor::RemoteDevice {
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
        changed_generation.actor = MessageActor::RemoteDevice {
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
}
