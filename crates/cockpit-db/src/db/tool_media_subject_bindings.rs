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
    /// Materialize epoch zero (or return the current epoch) before core mints
    /// a receipt. Acceptance rechecks the same row in its writer transaction,
    /// so an invalidation racing between this call and insert fails closed.
    pub async fn ensure_tool_media_authorization_epoch(
        &self,
        issuer_kind: i64,
        principal_digest: [u8; 32],
        session_id: Uuid,
        project_digest: [u8; 32],
        now_ms: i64,
    ) -> Result<i64> {
        self.transaction(move |conn| {
            ensure!(
                issuer_kind == 1 || issuer_kind == 2,
                "issuer_kind must be 1 or 2"
            );
            let session_id = session_id.to_string();
            conn.execute(
                "INSERT INTO tool_media_authorization_epochs
                 (issuer_kind, principal_digest, session_id, project_digest, epoch, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)
                 ON CONFLICT(issuer_kind, principal_digest, session_id, project_digest) DO NOTHING",
                params![
                    issuer_kind,
                    principal_digest.as_slice(),
                    session_id,
                    project_digest.as_slice(),
                    now_ms,
                ],
            )?;
            conn.query_row(
                "SELECT epoch FROM tool_media_authorization_epochs
                  WHERE issuer_kind=?1 AND principal_digest=?2
                    AND session_id=?3 AND project_digest=?4",
                params![
                    issuer_kind,
                    principal_digest.as_slice(),
                    session_id,
                    project_digest.as_slice(),
                ],
                |row| row.get(0),
            )
            .map_err(Into::into)
        })
        .await
    }

    /// Insert a tool-media-subject binding inside the caller's open
    /// transaction. Validates byte-shape constraints.
    pub fn insert_tool_media_subject_binding_conn(
        conn: &Connection,
        insert: &ToolMediaSubjectBindingInsertV1,
    ) -> Result<()> {
        validate_insert(insert)?;
        let session = insert.session_id.to_string();
        // Materialize the initial epoch in the same transaction as the
        // binding.  A concurrent authoritative invalidation either commits
        // before us (and makes this stale receipt reject here) or after us
        // (and invalidates the just-accepted receipt); it can never leave an
        // accepted binding attached to an implicit missing epoch.
        conn.execute(
            "INSERT INTO tool_media_authorization_epochs
             (issuer_kind, principal_digest, session_id, project_digest, epoch, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)
             ON CONFLICT(issuer_kind, principal_digest, session_id, project_digest) DO NOTHING",
            params![
                insert.issuer_kind,
                insert.principal_digest.as_slice(),
                &session,
                insert.project_digest.as_slice(),
                insert.now_ms,
            ],
        )?;
        let current_epoch: i64 = conn.query_row(
            "SELECT epoch FROM tool_media_authorization_epochs
             WHERE issuer_kind = ?1 AND principal_digest = ?2
               AND session_id = ?3 AND project_digest = ?4",
            params![
                insert.issuer_kind,
                insert.principal_digest.as_slice(),
                &session,
                insert.project_digest.as_slice(),
            ],
            |row| row.get(0),
        )?;
        ensure!(
            current_epoch == insert.authorization_epoch,
            "tool-media-subject binding authorization epoch changed before acceptance"
        );
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
        self.read(move |conn| load_binding_conn(conn, &session, &client_submission_id))
            .await
    }

    pub fn load_tool_media_subject_binding_conn(
        conn: &Connection,
        session_id: &str,
        client_submission_id: &[u8; 16],
    ) -> Result<Option<ToolMediaSubjectBindingRowV1>> {
        load_binding_conn(conn, session_id, client_submission_id)
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
            let rows = stmt.query_map(params![session], map_binding_row)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Into::into)
        })
        .await
    }

    /// Load only the retained binding set owned by the currently materialized
    /// turn. Accepted retry/requeue rows are deliberately excluded so a parked
    /// continuation cannot absorb authority from later queued work.
    pub async fn load_tool_media_subject_bindings_for_materialized_session(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<ToolMediaSubjectBindingRowV1>> {
        let session = session_id.to_string();
        self.read(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT b.session_id, b.client_submission_id, b.receipt_version, b.issuer_kind,
                        b.principal_digest, b.project_digest, b.authorization_epoch,
                        b.subject_digest, b.seal_version, b.key_namespace, b.key_version,
                        b.nonce, b.ciphertext, b.secure_key_reference_id, b.created_at, b.updated_at
                   FROM message_tool_media_subject_bindings b
                   JOIN message_submission_receipts r
                     ON r.session_id=b.session_id
                    AND r.client_submission_id=b.client_submission_id
                  WHERE b.session_id=?1 AND r.state='materialized'
                  ORDER BY r.fold_ordinal, b.client_submission_id",
            )?;
            let rows = stmt.query_map(params![session], map_binding_row)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(Into::into)
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
            let epoch: Option<i64> = conn
                .query_row(
                    "SELECT epoch FROM tool_media_authorization_epochs
                 WHERE issuer_kind = ?1 AND principal_digest = ?2
                   AND session_id = ?3 AND project_digest = ?4",
                    params![
                        issuer_kind,
                        principal_digest.as_slice(),
                        session,
                        project_digest.as_slice()
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(epoch)
        })
        .await
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
        let existing: Option<i64> = conn
            .query_row(
                "SELECT epoch FROM tool_media_authorization_epochs
             WHERE issuer_kind = ?1 AND principal_digest = ?2
               AND session_id = ?3 AND project_digest = ?4",
                params![
                    issuer_kind,
                    principal_digest.as_slice(),
                    session_id,
                    project_digest.as_slice()
                ],
                |row| row.get(0),
            )
            .optional()?;

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
            ensure!(
                crate::db::secure_key::begin_release_consumer_ref_conn(conn, ref_id)?,
                "tool-media-subject binding has no active secure-key reference"
            );
        }

        // 4. Delete the parent submission.
        let parent_deleted = conn.execute(
            "DELETE FROM message_submission_receipts
             WHERE session_id = ?1 AND client_submission_id = ?2",
            params![session_id, client_submission_id.as_slice()],
        )?;

        ensure!(
            bindings_deleted == ref_ids.len(),
            "binding/reference cardinality mismatch"
        );
        ensure!(parent_deleted == 1, "message submission not found");
        let _ = now_ms;
        Ok(())
    }
}

/// Invalidate every media binding attached to a session inside the caller's
/// authoritative session-state transaction. Session termination has no
/// surviving valid subject, so the update is deliberately broad over the
/// session rather than relying on a caller to reconstruct principal tuples.
pub fn invalidate_tool_media_authorization_epochs_for_session_conn(
    conn: &Connection,
    session_id: Uuid,
    now_ms: i64,
) -> Result<u64> {
    let changed = conn.execute(
        "UPDATE tool_media_authorization_epochs
         SET epoch = epoch + 1, updated_at = ?1
         WHERE session_id = ?2",
        params![now_ms, session_id.to_string()],
    )?;
    Ok(changed as u64)
}

/// Advance every local-owner media epoch. Used when the daemon installation
/// identity singleton is inserted (first create after sessions already exist,
/// or recreate after the identity row was lost). Remote-device epochs are
/// left alone.
pub fn invalidate_tool_media_authorization_epochs_for_local_owner_conn(
    conn: &Connection,
    now_ms: i64,
) -> Result<u64> {
    let changed = conn.execute(
        "UPDATE tool_media_authorization_epochs
         SET epoch = epoch + 1, updated_at = ?1
         WHERE issuer_kind = 1",
        params![now_ms],
    )?;
    Ok(changed as u64)
}

/// Remove a binding after its owning turn has completed and start release of
/// its retained secure-key version.  The message receipt deliberately remains
/// durable for exact replay; only the private, live authority is discarded.
pub fn release_tool_media_subject_binding_conn(
    conn: &Connection,
    session_id: &str,
    client_submission_id: &[u8; 16],
) -> Result<bool> {
    let reference_id: Option<String> = conn
        .query_row(
            "SELECT secure_key_reference_id
             FROM message_tool_media_subject_bindings
             WHERE session_id = ?1 AND client_submission_id = ?2",
            params![session_id, client_submission_id.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(reference_id) = reference_id else {
        return Ok(false);
    };
    let changed = conn.execute(
        "DELETE FROM message_tool_media_subject_bindings
         WHERE session_id = ?1 AND client_submission_id = ?2",
        params![session_id, client_submission_id.as_slice()],
    )?;
    ensure!(
        changed == 1,
        "tool-media-subject binding release lost its row"
    );
    ensure!(
        crate::db::secure_key::begin_release_consumer_ref_conn(conn, &reference_id)?,
        "tool-media-subject binding has no active secure-key reference"
    );
    Ok(true)
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
        insert.receipt_bytes == canonical_insert_receipt_bytes(insert)?,
        "receipt_bytes must exactly match canonical binding fields"
    );
    Ok(())
}

fn canonical_insert_receipt_bytes(insert: &ToolMediaSubjectBindingInsertV1) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(122);
    bytes.push(u8::try_from(insert.receipt_version)?);
    bytes.push(u8::try_from(insert.issuer_kind)?);
    bytes.extend_from_slice(&insert.principal_digest);
    bytes.extend_from_slice(&insert.project_digest);
    bytes.extend_from_slice(insert.session_id.as_bytes());
    bytes.extend_from_slice(&u64::try_from(insert.authorization_epoch)?.to_be_bytes());
    bytes.extend_from_slice(&insert.subject_digest);
    ensure!(bytes.len() == 122, "canonical receipt length must be 122");
    Ok(bytes)
}

fn load_binding_conn(
    conn: &Connection,
    session: &str,
    client_submission_id: &[u8; 16],
) -> Result<Option<ToolMediaSubjectBindingRowV1>> {
    let row = conn
        .query_row(
            "SELECT session_id, client_submission_id, receipt_version, issuer_kind,
                principal_digest, project_digest, authorization_epoch,
                subject_digest, seal_version, key_namespace, key_version,
                nonce, ciphertext, secure_key_reference_id, created_at, updated_at
         FROM message_tool_media_subject_bindings
         WHERE session_id = ?1 AND client_submission_id = ?2",
            params![session, client_submission_id.as_slice()],
            map_binding_row,
        )
        .optional()?;
    Ok(row)
}

fn map_binding_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ToolMediaSubjectBindingRowV1> {
    let session_id: String = row.get(0)?;
    let submission: Vec<u8> = row.get(1)?;
    let receipt_version: i64 = row.get(2)?;
    let issuer_kind: i64 = row.get(3)?;
    let principal: Vec<u8> = row.get(4)?;
    let project: Vec<u8> = row.get(5)?;
    let authorization_epoch: i64 = row.get(6)?;
    let subject: Vec<u8> = row.get(7)?;
    let nonce: Vec<u8> = row.get(11)?;
    let session_uuid = Uuid::parse_str(&session_id).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let mut receipt_bytes = Vec::with_capacity(122);
    receipt_bytes.push(u8::try_from(receipt_version).map_err(|_| rusqlite::Error::InvalidQuery)?);
    receipt_bytes.push(u8::try_from(issuer_kind).map_err(|_| rusqlite::Error::InvalidQuery)?);
    receipt_bytes.extend_from_slice(&principal);
    receipt_bytes.extend_from_slice(&project);
    receipt_bytes.extend_from_slice(session_uuid.as_bytes());
    receipt_bytes.extend_from_slice(
        &u64::try_from(authorization_epoch)
            .map_err(|_| rusqlite::Error::InvalidQuery)?
            .to_be_bytes(),
    );
    receipt_bytes.extend_from_slice(&subject);
    if receipt_bytes.len() != 122 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(ToolMediaSubjectBindingRowV1 {
        session_id,
        client_submission_id: submission
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        receipt_version,
        issuer_kind,
        principal_digest: principal
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        project_digest: project
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        authorization_epoch,
        subject_digest: subject
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        seal_version: row.get(8)?,
        key_namespace: row.get(9)?,
        key_version: row.get(10)?,
        nonce: nonce
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        ciphertext: row.get(12)?,
        secure_key_reference_id: row.get(13)?,
        receipt_bytes,
        created_at: row.get(14)?,
        updated_at: row.get(15)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_active_tool_media_key(conn: &Connection) -> Result<()> {
        use crate::db::secure_key::{SecureKeyVersionState, ensure_namespace_conn};

        ensure_namespace_conn(conn, "tool_media_subject_binding")?;
        conn.execute(
            "INSERT INTO secure_key_versions
             (namespace, version, state, key_digest, created_at, updated_at)
             VALUES (?1, 1, ?2, 'tool-media-test-key', ?3, ?3)",
            params![
                "tool_media_subject_binding",
                SecureKeyVersionState::Active.as_str(),
                10_i64,
            ],
        )?;
        conn.execute(
            "UPDATE secure_key_namespaces SET active_version = 1, updated_at = 10
             WHERE namespace = 'tool_media_subject_binding'",
            [],
        )?;
        Ok(())
    }

    fn test_binding_receipt(session_id: Uuid) -> Vec<u8> {
        let mut bytes = vec![1, 1];
        bytes.extend_from_slice(&[0xAA; 32]);
        bytes.extend_from_slice(&[0xBB; 32]);
        bytes.extend_from_slice(session_id.as_bytes());
        bytes.extend_from_slice(&0_u64.to_be_bytes());
        bytes.extend_from_slice(&[0xCC; 32]);
        bytes
    }

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
        let session_str = session.to_string();
        let new_epoch = db
            .transaction(move |conn| {
                Db::increment_tool_media_authorization_epoch_conn(
                    conn,
                    1,
                    principal,
                    &session_str,
                    project,
                    100,
                )
            })
            .await
            .unwrap();
        assert_eq!(new_epoch, 1);

        // Increment advances to 2.
        let session_str = session.to_string();
        let new_epoch = db
            .transaction(move |conn| {
                Db::increment_tool_media_authorization_epoch_conn(
                    conn,
                    1,
                    principal,
                    &session_str,
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
            tool_media_subject_binding: None,
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
            secure_key_reference_id:
                "tool-media-subject-binding/test/05050505050505050505050505050505/1".to_string(),
            receipt_bytes: test_binding_receipt(session.session_id),
            now_ms: 20,
            tool_media_subject_binding: None,
        };

        db.transaction(move |conn| Db::insert_tool_media_subject_binding_conn(conn, &insert))
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
            attachment_set_digest: [4; 32],
            client_submission_id: [7; 16],
            queue_item_id: [8; 16],
            canonical_message: b"FCM2\x02".to_vec(),
            attachments: vec![],
            outbox_sequence: 1,
            now_ms: 10,
            tool_media_subject_binding: None,
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

        // The private deletion path must release an active ref before it
        // removes the binding.  Model the production reserve → reachable row
        // → activate order in this integration test.
        db.write(setup_active_tool_media_key).await.unwrap();

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
            secure_key_reference_id:
                "tool-media-subject-binding/test/07070707070707070707070707070707/1".to_string(),
            receipt_bytes: test_binding_receipt(session.session_id),
            now_ms: 20,
            tool_media_subject_binding: None,
        };

        db.transaction(move |conn| {
            use crate::db::secure_key::{
                ReserveResult, activate_consumer_ref_conn, reserve_consumer_ref_conn,
            };
            let reference_id = insert.secure_key_reference_id.clone();
            let reservation = reserve_consumer_ref_conn(
                conn,
                &reference_id,
                "tool_media_subject_binding",
                1,
                "tool_media_subject_binding",
                "session/07070707070707070707070707070707",
            )?;
            assert!(matches!(reservation, ReserveResult::Reserved(_)));
            Db::insert_tool_media_subject_binding_conn(conn, &insert)?;
            assert!(activate_consumer_ref_conn(conn, &reference_id)?);
            Ok(())
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
        db.transaction(move |conn| {
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

        let reference_id =
            "tool-media-subject-binding/test/07070707070707070707070707070707/1".to_string();
        let state = db
            .read(move |conn| {
                Ok(
                    crate::db::secure_key::get_ref_by_id_conn(conn, &reference_id)?
                        .expect("released ref is retained for reconciliation")
                        .state,
                )
            })
            .await
            .unwrap();
        assert_eq!(state, crate::db::secure_key::SecureKeyRefState::Releasing);
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
            tool_media_subject_binding: None,
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
            receipt_bytes: test_binding_receipt(session.session_id),
            now_ms: 20,
            tool_media_subject_binding: None,
        };

        let result = db
            .transaction({
                let insert = insert.clone();
                move |conn| Db::insert_tool_media_subject_binding_conn(conn, &insert)
            })
            .await;
        assert!(result.is_err());

        // Fix and test bad issuer_kind.
        insert.receipt_version = 1;
        insert.issuer_kind = 3; // invalid
        let result = db
            .transaction(move |conn| Db::insert_tool_media_subject_binding_conn(conn, &insert))
            .await;
        assert!(result.is_err());
    }
}
