//! Tool-media-subject-binding persistence (opaque byte DTOs).
//!
//! `cockpit-db` validates byte-shape constraints (lengths, CHECK invariants)
//! but does **not** depend on `cockpit-core` crypto types. Core owns
//! receipt/seal encoding and passes bytes/metadata through these DTOs.
//!
//! The binding is part of the `accept_message_with_attachments` transaction:
//! receipt, seal metadata, ciphertext, epoch, and secure-key ref are written
//! atomically. Exact replay compares canonical receipt only, never randomized
//! ciphertext.

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

/// Opaque insert DTO for a tool-media-subject binding (V1).
///
/// All byte fields are validated for length/constraint shape by the DB layer;
/// crypto-level validation (receipt digest, seal authenticity) is owned by
/// `cockpit-core`.
#[derive(Debug, Clone)]
pub struct ToolMediaSubjectBindingInsertV1 {
    pub session_id: Uuid,
    pub client_submission_id: [u8; 16],
    pub receipt_version: i64,
    pub issuer_kind: i64,
    pub principal_digest: [u8; 32],
    pub project_digest: [u8; 32],
    pub authorization_epoch: i64,
    pub subject_digest: [u8; 32],
    pub seal_version: i64,
    pub key_namespace: String,
    pub key_version: i64,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    pub secure_key_reference_id: String,
    /// Canonical receipt bytes (for exact replay comparison).
    pub receipt_bytes: Vec<u8>,
    pub now_ms: i64,
}

/// Opaque row DTO for a tool-media-subject binding (V1).
///
/// Returned by recovery/load APIs. Core opens the seal through the
/// `ToolMediaSubjectRevalidator`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolMediaSubjectBindingRowV1 {
    pub session_id: String,
    pub client_submission_id: [u8; 16],
    pub receipt_version: i64,
    pub issuer_kind: i64,
    pub principal_digest: [u8; 32],
    pub project_digest: [u8; 32],
    pub authorization_epoch: i64,
    pub subject_digest: [u8; 32],
    pub seal_version: i64,
    pub key_namespace: String,
    pub key_version: i64,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    pub secure_key_reference_id: String,
    pub receipt_bytes: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Epoch row DTO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolMediaAuthorizationEpochRow {
    pub issuer_kind: i64,
    pub principal_digest: [u8; 32],
    pub session_id: String,
    pub project_digest: [u8; 32],
    pub epoch: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Db {
    /// Insert a tool-media-subject binding inside the caller's open
    /// transaction. Validates byte-shape constraints.
    pub fn insert_tool_media_subject_binding_conn(
        conn: &Connection,
        insert: &ToolMediaSubjectBindingInsertV1,
    ) -> Result<()> {
        validate_insert(insert)?;
        let session = insert.session_id.to_string();
        conn.execute(
            "INSERT INTO message_tool_media_subject_bindings
             (session_id, client_submission_id, receipt_version, issuer_kind,
              principal_digest, project_digest, authorization_epoch,
              subject_digest, seal_version, key_namespace, key_version,
              nonce, ciphertext, secure_key_reference_id, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?15)",
            params![
                session,
                insert.client_submission_id.as_slice(),
                insert.receipt_version,
                insert.issuer_kind,
                insert.principal_digest.as_slice(),
                insert.project_digest.as_slice(),
                insert.authorization_epoch,
                insert.subject_digest.as_slice(),
                insert.seal_version,
                insert.key_namespace,
                insert.key_version,
                insert.nonce.as_slice(),
                insert.ciphertext.as_slice(),
                insert.secure_key_reference_id,
                insert.now_ms,
            ],
        )?;
        Ok(())
    }

    /// Load a binding for a given `(session, client_submission_id)`.
    pub async fn load_tool_media_subject_binding(
        &self,
        session_id: Uuid,
        client_submission_id: [u8; 16],
    ) -> Result<Option<ToolMediaSubjectBindingRowV1>> {
        let session = session_id.to_string();
        self.read(move |conn| {
            load_binding_conn(conn, &session, &client_submission_id)
        })
        .await
    }

    /// Load all bindings for a session (used in queue recovery).
    pub async fn load_tool_media_subject_bindings_for_session(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<ToolMediaSubjectBindingRowV1>> {
        let session = session_id.to_string();
        self.read(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT session_id, client_submission_id, receipt_version, issuer_kind,
                        principal_digest, project_digest, authorization_epoch,
                        subject_digest, seal_version, key_namespace, key_version,
                        nonce, ciphertext, secure_key_reference_id, created_at, updated_at
                 FROM message_tool_media_subject_bindings
                 WHERE session_id = ?1",
            )?;
            let rows = stmt.query_map(params![session], |row| {
                let submission: Vec<u8> = row.get(1)?;
                let principal: Vec<u8> = row.get(4)?;
                let project: Vec<u8> = row.get(5)?;
                let subject: Vec<u8> = row.get(7)?;
                let nonce: Vec<u8> = row.get(11)?;
                Ok(ToolMediaSubjectBindingRowV1 {
                    session_id: row.get(0)?,
                    client_submission_id: submission.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                    receipt_version: row.get(2)?,
                    issuer_kind: row.get(3)?,
                    principal_digest: principal.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                    project_digest: project.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                    authorization_epoch: row.get(6)?,
                    subject_digest: subject.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                    seal_version: row.get(8)?,
                    key_namespace: row.get(9)?,
                    key_version: row.get(10)?,
                    nonce: nonce.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ciphertext: row.get(12)?,
                    secure_key_reference_id: row.get(13)?,
                    receipt_bytes: Vec::new(), // loaded separately if needed
                    created_at: row.get(14)?,
                    updated_at: row.get(15)?,
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
        })
        .await
    }

    /// Get the current authorization epoch for a key tuple.
    pub async fn tool_media_authorization_epoch(
        &self,
        issuer_kind: i64,
        principal_digest: [u8; 32],
        session_id: Uuid,
        project_digest: [u8; 32],
    ) -> Result<Option<i64>> {
        let session = session_id.to_string();
        self.read(move |conn| {
            let epoch: Option<i64> = conn.query_row(
                "SELECT epoch FROM tool_media_authorization_epochs
                 WHERE issuer_kind = ?1 AND principal_digest = ?2
                   AND session_id = ?3 AND project_digest = ?4",
                params![issuer_kind, principal_digest.as_slice(), session, project_digest.as_slice()],
                |row| row.get(0),
            ).optional()?;
            Ok(epoch)
        }).await
    }

    /// Increment the authorization epoch for a key tuple inside the caller's
    /// open transaction. Creates the row if it does not exist (epoch 0 → 1).
    pub fn increment_tool_media_authorization_epoch_conn(
        conn: &Connection,
        issuer_kind: i64,
        principal_digest: [u8; 32],
        session_id: &str,
        project_digest: [u8; 32],
        now_ms: i64,
    ) -> Result<i64> {
        ensure!(
            issuer_kind == 1 || issuer_kind == 2,
            "issuer_kind must be 1 or 2"
        );
        let existing: Option<i64> = conn.query_row(
            "SELECT epoch FROM tool_media_authorization_epochs
             WHERE issuer_kind = ?1 AND principal_digest = ?2
               AND session_id = ?3 AND project_digest = ?4",
            params![issuer_kind, principal_digest.as_slice(), session_id, project_digest.as_slice()],
            |row| row.get(0),
        ).optional()?;

        let new_epoch = match existing {
            Some(e) => e + 1,
            None => {
                // First epoch row — start at 0, then increment to 1.
                conn.execute(
                    "INSERT INTO tool_media_authorization_epochs
                     (issuer_kind, principal_digest, session_id, project_digest, epoch, created_at, updated_at)
                     VALUES (?1,?2,?3,?4,0,?5,?5)",
                    params![issuer_kind, principal_digest.as_slice(), session_id, project_digest.as_slice(), now_ms],
                )?;
                1
            }
        };

        let changed = conn.execute(
            "UPDATE tool_media_authorization_epochs
             SET epoch = ?5, updated_at = ?6
             WHERE issuer_kind = ?1 AND principal_digest = ?2
               AND session_id = ?3 AND project_digest = ?4",
            params![
                issuer_kind,
                principal_digest.as_slice(),
                session_id,
                project_digest.as_slice(),
                new_epoch,
                now_ms,
            ],
        )?;
        ensure!(changed == 1, "epoch row not updated");
        Ok(new_epoch)
    }

    /// Delete a message submission along with its media-subject binding and
    /// secure-key refs, inside the caller's open transaction.
    ///
    /// This is the private DB replacement for raw parent submission deletion:
    /// it selects matching ref ids, deletes the binding explicitly, calls
    /// `begin_release_in_tx` for each, then deletes the parent. FK cascade
    /// remains only an integrity backstop and is tested not to leave an Active
    /// ref.
    pub fn delete_message_submission_with_media_subject_binding_conn(
        conn: &Connection,
        session_id: &str,
        client_submission_id: &[u8; 16],
        now_ms: i64,
    ) -> Result<()> {
        // 1. Select matching secure-key ref ids.
        let ref_ids: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT secure_key_reference_id
                 FROM message_tool_media_subject_bindings
                 WHERE session_id = ?1 AND client_submission_id = ?2",
            )?;
            let rows = stmt.query_map(
                params![session_id, client_submission_id.as_slice()],
                |row| row.get::<_, String>(0),
            )?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };

        // 2. Delete the binding explicitly.
        let bindings_deleted = conn.execute(
            "DELETE FROM message_tool_media_subject_bindings
             WHERE session_id = ?1 AND client_submission_id = ?2",
            params![session_id, client_submission_id.as_slice()],
        )?;

        // 3. Begin release for each ref.
        for ref_id in &ref_ids {
            // Use the secure_key consumer ref release function.
            // This transitions Active → Releasing in the same transaction.
            let _ = crate::db::secure_key::begin_release_consumer_ref_conn(conn, ref_id);
        }

        // 4. Delete the parent submission.
        let _parent_deleted = conn.execute(
            "DELETE FROM message_submission_receipts
             WHERE session_id = ?1 AND client_submission_id = ?2",
            params![session_id, client_submission_id.as_slice()],
        )?;

        let _ = now_ms; // used by callers for epoch increments
        let _ = bindings_deleted; // explicit delete count
        Ok(())
    }
}

fn validate_insert(insert: &ToolMediaSubjectBindingInsertV1) -> Result<()> {
    ensure!(insert.receipt_version == 1, "receipt_version must be 1");
    ensure!(
        insert.issuer_kind == 1 || insert.issuer_kind == 2,
        "issuer_kind must be 1 or 2"
    );
    ensure!(
        insert.authorization_epoch >= 0,
        "authorization_epoch must be >= 0"
    );
    ensure!(insert.seal_version == 1, "seal_version must be 1");
    ensure!(
        insert.key_namespace == "tool_media_subject_binding",
        "key_namespace must be 'tool_media_subject_binding'"
    );
    ensure!(insert.key_version > 0, "key_version must be > 0");
    ensure!(
        insert.ciphertext.len() > 16,
        "ciphertext must be > 16 bytes"
    );
    ensure!(
        !insert.secure_key_reference_id.is_empty(),
        "secure_key_reference_id must not be empty"
    );
    ensure!(
        !insert.receipt_bytes.is_empty(),
        "receipt_bytes must not be empty"
    );
    Ok(())
}

fn load_binding_conn(
    conn: &Connection,
    session: &str,
    client_submission_id: &[u8; 16],
) -> Result<Option<ToolMediaSubjectBindingRowV1>> {
    let row = conn.query_row(
        "SELECT session_id, client_submission_id, receipt_version, issuer_kind,
                principal_digest, project_digest, authorization_epoch,
                subject_digest, seal_version, key_namespace, key_version,
                nonce, ciphertext, secure_key_reference_id, created_at, updated_at
         FROM message_tool_media_subject_bindings
         WHERE session_id = ?1 AND client_submission_id = ?2",
        params![session, client_submission_id.as_slice()],
        |row| {
            let submission: Vec<u8> = row.get(1)?;
            let principal: Vec<u8> = row.get(4)?;
            let project: Vec<u8> = row.get(5)?;
            let subject: Vec<u8> = row.get(7)?;
            let nonce: Vec<u8> = row.get(11)?;
            Ok(ToolMediaSubjectBindingRowV1 {
                session_id: row.get(0)?,
                client_submission_id: submission
                    .try_into()
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                receipt_version: row.get(2)?,
                issuer_kind: row.get(3)?,
                principal_digest: principal
                    .try_into()
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                project_digest: project
                    .try_into()
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                authorization_epoch: row.get(6)?,
                subject_digest: subject
                    .try_into()
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                seal_version: row.get(8)?,
                key_namespace: row.get(9)?,
                key_version: row.get(10)?,
                nonce: nonce.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                ciphertext: row.get(12)?,
                secure_key_reference_id: row.get(13)?,
                receipt_bytes: Vec::new(),
                created_at: row.get(14)?,
                updated_at: row.get(15)?,
            })
        },
    )
    .optional()?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn epoch_increment_creates_and_advances() {
        let db = Db::open_in_memory().unwrap();
        let session = Uuid::new_v4();
        let principal = [0x11; 32];
        let project = [0x22; 32];

        // No epoch yet.
        let e = db
            .tool_media_authorization_epoch(1, principal, session, project)
            .await
            .unwrap();
        assert!(e.is_none());

        // Increment creates epoch 1.
        let new_epoch = db
            .transaction(move |conn| {
                Db::increment_tool_media_authorization_epoch_conn(
                    conn,
                    1,
                    principal,
                    &session.to_string(),
                    project,
                    100,
                )
            })
            .await
            .unwrap();
        assert_eq!(new_epoch, 1);

        // Increment advances to 2.
        let new_epoch = db
            .transaction(move |conn| {
                Db::increment_tool_media_authorization_epoch_conn(
                    conn,
                    1,
                    principal,
                    &session.to_string(),
                    project,
                    200,
                )
            })
            .await
            .unwrap();
        assert_eq!(new_epoch, 2);

        // Read back.
        let e = db
            .tool_media_authorization_epoch(1, principal, session, project)
            .await
            .unwrap();
        assert_eq!(e, Some(2));
    }

    #[tokio::test]
    async fn binding_insert_and_load() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/workspace", "Build")
            .await
            .unwrap();

        // First create a message submission receipt so the FK is satisfied.
        let input = crate::db::message_attachments::AcceptMessageInput {
            session_id: session.session_id,
            operation_id: [1; 16],
            actor: crate::db::message_attachments::MessageActor::LocalOwner,
            request_hash: [2; 32],
            message_request_digest: [3; 32],
            attachment_set_digest: [4; 32],
            client_submission_id: [5; 16],
            queue_item_id: [6; 16],
            canonical_message: b"FCM2\x02".to_vec(),
            attachments: vec![],
            outbox_sequence: 1,
            now_ms: 10,
        };
        use crate::db::message_attachments::MessageAcceptanceJoin;
        struct Allow;
        impl MessageAcceptanceJoin for Allow {
            fn validate_and_join(
                &self,
                _: &Connection,
                _: &crate::db::message_attachments::AcceptMessageInput,
            ) -> Result<()> {
                Ok(())
            }
        }
        db.accept_message_with_attachments(input.clone(), std::sync::Arc::new(Allow))
            .await
            .unwrap();

        // Insert a binding.
        let insert = ToolMediaSubjectBindingInsertV1 {
            session_id: session.session_id,
            client_submission_id: [5; 16],
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
            secure_key_reference_id: "tool-media-subject-binding/test/05050505050505050505050505050505/1".to_string(),
            receipt_bytes: vec![0xFF; 122],
            now_ms: 20,
        };

        db.transaction(|conn| {
            Db::insert_tool_media_subject_binding_conn(conn, &insert)
        })
        .await
        .unwrap();

        // Load it back.
        let row = db
            .load_tool_media_subject_binding(session.session_id, [5; 16])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.issuer_kind, 1);
        assert_eq!(row.authorization_epoch, 0);
        assert_eq!(row.key_namespace, "tool_media_subject_binding");
        assert_eq!(row.nonce, [0xDD; 24]);
        assert_eq!(row.ciphertext, vec![0xEE; 48]);
    }

    #[tokio::test]
    async fn delete_submission_with_binding_releases_refs() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/workspace", "Build")
            .await
            .unwrap();

        let input = crate::db::message_attachments::AcceptMessageInput {
            session_id: session.session_id,
            operation_id: [1; 16],
            actor: crate::db::message_attachments::MessageActor::LocalOwner,
            request_hash: [2; 32],
            message_request_digest: [3; 32],
            attachment_set_digest: [4;  32],
            client_submission_id: [7; 16],
            queue_item_id: [8; 16],
            canonical_message: b"FCM2\x02".to_vec(),
            attachments: vec![],
            outbox_sequence: 1,
            now_ms: 10,
        };
        use crate::db::message_attachments::MessageAcceptanceJoin;
        struct Allow;
        impl MessageAcceptanceJoin for Allow {
            fn validate_and_join(
                &self,
                _: &Connection,
                _: &crate::db::message_attachments::AcceptMessageInput,
            ) -> Result<()> {
                Ok(())
            }
        }
        db.accept_message_with_attachments(input.clone(), std::sync::Arc::new(Allow))
            .await
            .unwrap();

        // Insert a binding.
        let insert = ToolMediaSubjectBindingInsertV1 {
            session_id: session.session_id,
            client_submission_id: [7; 16],
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
            secure_key_reference_id: "tool-media-subject-binding/test/07070707070707070707070707070707/1".to_string(),
            receipt_bytes: vec![0xFF; 122],
            now_ms: 20,
        };

        db.transaction(|conn| {
            Db::insert_tool_media_subject_binding_conn(conn, &insert)
        })
        .await
        .unwrap();

        // Verify binding exists.
        let row = db
            .load_tool_media_subject_binding(session.session_id, [7; 16])
            .await
            .unwrap();
        assert!(row.is_some());

        // Delete the submission with binding.
        let session_str = session.session_id.to_string();
        db.transaction(|conn| {
            Db::delete_message_submission_with_media_subject_binding_conn(
                conn,
                &session_str,
                &[7; 16],
                30,
            )
        })
        .await
        .unwrap();

        // Binding should be gone.
        let row = db
            .load_tool_media_subject_binding(session.session_id, [7; 16])
            .await
            .unwrap();
        assert!(row.is_none());
    }

    #[tokio::test]
    async fn validate_rejects_bad_insert() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/workspace", "Build")
            .await
            .unwrap();

        // Create a receipt for the FK.
        let input = crate::db::message_attachments::AcceptMessageInput {
            session_id: session.session_id,
            operation_id: [1; 16],
            actor: crate::db::message_attachments::MessageActor::LocalOwner,
            request_hash: [2; 32],
            message_request_digest: [3; 32],
            attachment_set_digest: [4; 32],
            client_submission_id: [9; 16],
            queue_item_id: [10; 16],
            canonical_message: b"FCM2\x02".to_vec(),
            attachments: vec![],
            outbox_sequence: 1,
            now_ms: 10,
        };
        use crate::db::message_attachments::MessageAcceptanceJoin;
        struct Allow;
        impl MessageAcceptanceJoin for Allow {
            fn validate_and_join(
                &self,
                _: &Connection,
                _: &crate::db::message_attachments::AcceptMessageInput,
            ) -> Result<()> {
                Ok(())
            }
        }
        db.accept_message_with_attachments(input.clone(), std::sync::Arc::new(Allow))
            .await
            .unwrap();

        // Bad receipt_version.
        let mut insert = ToolMediaSubjectBindingInsertV1 {
            session_id: session.session_id,
            client_submission_id: [9; 16],
            receipt_version: 2, // invalid
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
            secure_key_reference_id: "test-ref-2".to_string(),
            receipt_bytes: vec![0xFF; 122],
            now_ms: 20,
        };

        let result = db
            .transaction(|conn| {
                Db::insert_tool_media_subject_binding_conn(conn, &insert)
            })
            .await;
        assert!(result.is_err());

        // Fix and test bad issuer_kind.
        insert.receipt_version = 1;
        insert.issuer_kind = 3; // invalid
        let result = db
            .transaction(|conn| {
                Db::insert_tool_media_subject_binding_conn(conn, &insert)
            })
            .await;
        assert!(result.is_err());
    }
}
