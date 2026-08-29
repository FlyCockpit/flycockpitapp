//! Named test suites for `tool-media-subject-authority-foundation` (#70).
//!
//! Each test name matches the focused nextest filter in the issue:
//!
//! ```sh
//! cargo nextest run --locked --workspace -E 'test(tool_media_subject_binding_replay_and_propagation) |
//!   test(tool_media_secure_key_lifecycle) | test(tool_media_mixed_principal_fold) |
//!   test(tool_media_source_authority) | test(tool_media_context_stripping) |
//!   test(media_tool_availability_materialization)'
//! ```

#![cfg(test)]

use std::sync::Arc;

use async_trait::async_trait;

use crate::mcp::builtin::HostContext;

use super::availability::MediaToolAvailability;
use super::locator::LocatorV1;
use super::receipt::{IssuerKind, ToolMediaSubjectReceiptV1};
use super::revalidator::{
    RemoteStatusProjection, RevalidatedSubject, RevalidatorError, SecureKeyResolver,
    ToolMediaSubjectRevalidator,
};
use super::seal;
use super::session_authority::{
    AdmissionDenial, AdmittedAttachment, AdmittedLocalHandle, AdmittedRetainedSource,
    AttachmentResolver, LocalPathPolicy, RetainedHttpsPolicy, SessionMediaAuthority,
};

// ---------------------------------------------------------------------------
// Helpers shared across suites
// ---------------------------------------------------------------------------

struct FakeKeyResolver {
    key: [u8; 32],
    available: bool,
}

impl SecureKeyResolver for FakeKeyResolver {
    fn resolve_key(
        &self,
        _namespace: &str,
        _version: i64,
    ) -> Result<Option<crate::secure_key::SecureKeyBytes>, RevalidatorError> {
        if self.available {
            Ok(Some(crate::secure_key::SecureKeyBytes::from_array(
                self.key,
            )))
        } else {
            Ok(None)
        }
    }
}

struct FakeProjection {
    device_active: bool,
    authority_active: bool,
    epoch: u64,
}

impl RemoteStatusProjection for FakeProjection {
    fn device_active(
        &self,
        _device_uuid: &[u8; 16],
        _generation: u64,
    ) -> Result<bool, RevalidatorError> {
        Ok(self.device_active)
    }
    fn authority_active(&self, _principal_digest: &[u8; 32]) -> Result<bool, RevalidatorError> {
        Ok(self.authority_active)
    }
    fn current_epoch(
        &self,
        _issuer_kind: IssuerKind,
        _principal_digest: &[u8; 32],
        _session_id: &str,
        _project_digest: &[u8; 32],
    ) -> Result<u64, RevalidatorError> {
        Ok(self.epoch)
    }
}

fn make_sealed_local_binding(
    key: &[u8; 32],
    epoch: u64,
    session_id: [u8; 16],
    client_submission_id: [u8; 16],
) -> (ToolMediaSubjectReceiptV1, Vec<u8>, [u8; 24], Vec<u8>) {
    let locator = LocatorV1::local_owner();
    let project_uuid = [0xAB; 16];
    let project_digest = LocatorV1::project_digest(&project_uuid);
    let receipt = ToolMediaSubjectReceiptV1::new(
        IssuerKind::LocalOwner,
        &locator,
        project_digest,
        session_id,
        epoch,
    );
    let receipt_bytes = receipt.canonical_bytes();
    let sealed = seal::seal_locator(
        key,
        &session_id,
        &client_submission_id,
        &receipt_bytes,
        &locator,
    )
    .unwrap();
    (receipt, receipt_bytes, sealed.nonce, sealed.ciphertext)
}

fn make_sealed_remote_binding(
    key: &[u8; 32],
    epoch: u64,
    device_uuid: [u8; 16],
    device_generation: u64,
    session_id: [u8; 16],
    client_submission_id: [u8; 16],
) -> (ToolMediaSubjectReceiptV1, Vec<u8>, [u8; 24], Vec<u8>) {
    let locator = LocatorV1::remote_device(device_uuid, device_generation);
    let project_uuid = [0xAB; 16];
    let project_digest = LocatorV1::project_digest(&project_uuid);
    let receipt = ToolMediaSubjectReceiptV1::new(
        IssuerKind::RemoteDevice,
        &locator,
        project_digest,
        session_id,
        epoch,
    );
    let receipt_bytes = receipt.canonical_bytes();
    let sealed = seal::seal_locator(
        key,
        &session_id,
        &client_submission_id,
        &receipt_bytes,
        &locator,
    )
    .unwrap();
    (receipt, receipt_bytes, sealed.nonce, sealed.ciphertext)
}

fn make_revalidator(key: &[u8; 32], projection: FakeProjection) -> ToolMediaSubjectRevalidator {
    ToolMediaSubjectRevalidator::new(
        Arc::new(projection),
        Arc::new(FakeKeyResolver {
            key: *key,
            available: true,
        }),
    )
}

// ---------------------------------------------------------------------------
// Suite 1: tool_media_subject_binding_replay_and_propagation
// ---------------------------------------------------------------------------

#[test]
fn tool_media_subject_binding_seal_fail_closed_matrix() {
    let key = [0x42; 32];
    let session_id = [0xCD; 16];
    let submission_a = [0x01; 16];
    let submission_b = [0x02; 16];

    // Create two bindings (simulating root + subagent propagation).
    let (receipt_a, bytes_a, nonce_a, ct_a) =
        make_sealed_local_binding(&key, 0, session_id, submission_a);
    let (receipt_b, bytes_b, nonce_b, ct_b) =
        make_sealed_local_binding(&key, 0, session_id, submission_b);

    // Receipts are byte-identical in canonical form (same issuer/principal/
    // project/session/epoch).
    assert_eq!(
        receipt_a.canonical_bytes(),
        receipt_b.canonical_bytes(),
        "root and subagent receipts must be byte-identical for propagation"
    );

    // Revalidate both — simulating restart/recovery.
    let revalidator = make_revalidator(
        &key,
        FakeProjection {
            device_active: true,
            authority_active: true,
            epoch: 0,
        },
    );

    let subject_a = revalidator
        .revalidate(
            &bytes_a,
            &nonce_a,
            &ct_a,
            "tool_media_subject_binding",
            1,
            &submission_a,
        )
        .unwrap();
    let subject_b = revalidator
        .revalidate(
            &bytes_b,
            &nonce_b,
            &ct_b,
            "tool_media_subject_binding",
            1,
            &submission_b,
        )
        .unwrap();

    // Both subjects are byte-identical in receipt.
    assert_eq!(subject_a.receipt, subject_b.receipt);

    // --- Failed seal/key/revalidator branches have no Owner fallback ---

    // Wrong key → fail closed.
    let bad_revalidator = make_revalidator(
        &[0x99; 32],
        FakeProjection {
            device_active: true,
            authority_active: true,
            epoch: 0,
        },
    );
    let result = bad_revalidator.revalidate(
        &bytes_a,
        &nonce_a,
        &ct_a,
        "tool_media_subject_binding",
        1,
        &submission_a,
    );
    assert!(
        matches!(result, Err(RevalidatorError::Unseal(_))),
        "wrong key must fail closed, no Owner fallback"
    );

    // Stale epoch → fail closed.
    let stale_revalidator = make_revalidator(
        &key,
        FakeProjection {
            device_active: true,
            authority_active: true,
            epoch: 5, // epoch advanced
        },
    );
    let result = stale_revalidator.revalidate(
        &bytes_a,
        &nonce_a,
        &ct_a,
        "tool_media_subject_binding",
        1,
        &submission_a,
    );
    assert!(
        matches!(result, Err(RevalidatorError::StaleEpoch { .. })),
        "stale epoch must fail closed, no Owner fallback"
    );

    // Authority inactive → fail closed.
    let inactive_revalidator = make_revalidator(
        &key,
        FakeProjection {
            device_active: true,
            authority_active: false,
            epoch: 0,
        },
    );
    let result = inactive_revalidator.revalidate(
        &bytes_a,
        &nonce_a,
        &ct_a,
        "tool_media_subject_binding",
        1,
        &submission_a,
    );
    assert!(
        matches!(result, Err(RevalidatorError::AuthorityStatusInvalid)),
        "inactive authority must fail closed, no Owner fallback"
    );

    // Key unavailable → fail closed.
    let nokey_revalidator = ToolMediaSubjectRevalidator::new(
        Arc::new(FakeProjection {
            device_active: true,
            authority_active: true,
            epoch: 0,
        }),
        Arc::new(FakeKeyResolver {
            key,
            available: false,
        }),
    );
    let result = nokey_revalidator.revalidate(
        &bytes_a,
        &nonce_a,
        &ct_a,
        "tool_media_subject_binding",
        1,
        &submission_a,
    );
    assert!(
        matches!(result, Err(RevalidatorError::KeyUnavailable)),
        "missing key must fail closed, no Owner fallback"
    );
}

// ---------------------------------------------------------------------------
// Suite 2: tool_media_secure_key_lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tool_media_secure_key_lifecycle() {
    use crate::db::message_attachments::{
        AcceptMessageInput, AcceptMessageResult, MessageAcceptanceJoin, MessageActor,
    };
    use crate::db::secure_key::{SecureKeyRefState, get_ref_by_id_conn};
    use crate::db::tool_media_subject_bindings::ToolMediaSubjectBindingInsertV1;
    use crate::secure_key::{
        CompositeConsumerReconciler, FailClosedReconciler, SecureKeyActor,
        ToolMediaSubjectBindingDbProbe,
    };

    struct Allow;
    impl MessageAcceptanceJoin for Allow {
        fn validate_and_join(
            &self,
            _: &rusqlite::Connection,
            _: &AcceptMessageInput,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn receipt(session_id: uuid::Uuid, version: u8) -> Vec<u8> {
        let mut bytes = vec![version, 1];
        bytes.extend_from_slice(&[0xAA; 32]);
        bytes.extend_from_slice(&[0xBB; 32]);
        bytes.extend_from_slice(session_id.as_bytes());
        bytes.extend_from_slice(&0_u64.to_be_bytes());
        bytes.extend_from_slice(&[0xCC; 32]);
        bytes
    }

    fn input(session_id: uuid::Uuid, marker: u8, key_version: i64) -> AcceptMessageInput {
        let submission = [marker; 16];
        let submission_hex: String = submission
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        AcceptMessageInput {
            session_id,
            operation_id: [marker.wrapping_add(1); 16],
            actor: MessageActor::LocalOwner,
            request_hash: [marker.wrapping_add(2); 32],
            message_request_digest: [marker.wrapping_add(3); 32],
            attachment_set_digest: [marker.wrapping_add(4); 32],
            client_submission_id: submission,
            queue_item_id: [marker.wrapping_add(5); 16],
            canonical_message: b"FCM2\x02".to_vec(),
            attachments: Vec::new(),
            outbox_sequence: i64::from(marker),
            now_ms: 100 + i64::from(marker),
            tool_media_subject_binding: Some(ToolMediaSubjectBindingInsertV1 {
                session_id,
                client_submission_id: submission,
                receipt_version: 1,
                issuer_kind: 1,
                principal_digest: [0xAA; 32],
                project_digest: [0xBB; 32],
                authorization_epoch: 0,
                subject_digest: [0xCC; 32],
                seal_version: 1,
                key_namespace: "tool_media_subject_binding".to_owned(),
                key_version,
                nonce: [marker; 24],
                ciphertext: vec![marker; 48],
                secure_key_reference_id: format!(
                    "tool-media-subject-binding/{session_id}/{submission_hex}/{key_version}"
                ),
                receipt_bytes: receipt(session_id, 1),
                now_ms: 100 + i64::from(marker),
            }),
        }
    }

    async fn ref_state(db: &crate::db::Db, reference_id: String) -> Option<SecureKeyRefState> {
        db.read(move |conn| Ok(get_ref_by_id_conn(conn, &reference_id)?.map(|row| row.state)))
            .await
            .unwrap()
    }

    let db = crate::db::Db::open_in_memory().unwrap();
    let session = db
        .create_session("project", "/workspace", "Build")
        .await
        .unwrap();
    let reconciler = Arc::new(CompositeConsumerReconciler::new(
        FailClosedReconciler,
        ToolMediaSubjectBindingDbProbe::new(db.clone()),
    ));
    let actor_db = db.clone();
    let actor = tokio::task::spawn_blocking(move || {
        SecureKeyActor::start_with_store(
            actor_db,
            Box::new(crate::secure_key::fake::FakeNativeStore::new()),
            reconciler,
        )
    })
    .await
    .unwrap()
    .unwrap();
    let key = actor.handle();
    let (version_one, _) = key
        .create_or_load("tool_media_subject_binding")
        .await
        .unwrap();
    assert_eq!(version_one, 1);

    // Real acceptance performs Reserved -> reachable binding -> Active in one
    // transaction.
    let first = input(session.session_id, 0x11, version_one);
    let first_ref = first
        .tool_media_subject_binding
        .as_ref()
        .unwrap()
        .secure_key_reference_id
        .clone();
    assert_eq!(
        db.accept_message_with_attachments(first.clone(), Arc::new(Allow))
            .await
            .unwrap(),
        AcceptMessageResult::Accepted
    );
    assert_eq!(
        ref_state(&db, first_ref.clone()).await,
        Some(SecureKeyRefState::Active)
    );
    assert!(
        db.load_tool_media_subject_binding(session.session_id, first.client_submission_id)
            .await
            .unwrap()
            .is_some()
    );

    // A failure after reservation rolls the entire acceptance back: no ref,
    // parent receipt, or binding survives.
    let mut rolled_back = input(session.session_id, 0x22, version_one);
    let rolled_back_ref = rolled_back
        .tool_media_subject_binding
        .as_ref()
        .unwrap()
        .secure_key_reference_id
        .clone();
    let invalid = rolled_back.tool_media_subject_binding.as_mut().unwrap();
    invalid.receipt_version = 2;
    invalid.receipt_bytes[0] = 2;
    assert!(
        db.accept_message_with_attachments(rolled_back.clone(), Arc::new(Allow))
            .await
            .is_err()
    );
    assert_eq!(ref_state(&db, rolled_back_ref).await, None);
    assert!(
        db.load_tool_media_subject_binding(session.session_id, rolled_back.client_submission_id)
            .await
            .unwrap()
            .is_none()
    );
    let rollback_session = session.session_id.to_string();
    let rollback_submission = rolled_back.client_submission_id;
    let rollback_receipts: i64 = db
        .read(move |conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM message_submission_receipts
                 WHERE session_id=?1 AND client_submission_id=?2",
                rusqlite::params![rollback_session, rollback_submission.as_slice()],
                |row| row.get(0),
            )
            .map_err(Into::into)
        })
        .await
        .unwrap();
    assert_eq!(rollback_receipts, 0);

    // Rotation retains V1 while its Active binding blocks retirement.
    let (version_two, _) = key.rotate("tool_media_subject_binding").await.unwrap();
    assert_eq!(version_two, 2);
    assert!(matches!(
        key.retire("tool_media_subject_binding", version_one).await,
        Err(crate::secure_key::SecureKeyError::InUse(_))
    ));

    // Explicit parent deletion removes the binding and begins release; the
    // production composite DB probe then lets crash reconciliation finish it.
    let first_session = session.session_id.to_string();
    let first_submission = first.client_submission_id;
    db.transaction(move |conn| {
        crate::db::Db::delete_message_submission_with_media_subject_binding_conn(
            conn,
            &first_session,
            &first_submission,
            500,
        )
    })
    .await
    .unwrap();
    assert_eq!(
        ref_state(&db, first_ref.clone()).await,
        Some(SecureKeyRefState::Releasing)
    );
    key.reconcile().await.unwrap();
    assert_eq!(
        ref_state(&db, first_ref).await,
        Some(SecureKeyRefState::Released)
    );
    key.retire("tool_media_subject_binding", version_one)
        .await
        .unwrap();

    // The FK-cascade backstop must also move an Active ref to Releasing before
    // SQLite removes the binding. Reconciliation proves the absent consumer
    // and releases it.
    let cascaded = input(session.session_id, 0x33, version_two);
    let cascaded_ref = cascaded
        .tool_media_subject_binding
        .as_ref()
        .unwrap()
        .secure_key_reference_id
        .clone();
    db.accept_message_with_attachments(cascaded.clone(), Arc::new(Allow))
        .await
        .unwrap();
    let cascade_session = session.session_id.to_string();
    let cascade_submission = cascaded.client_submission_id;
    db.transaction(move |conn| {
        conn.execute(
            "UPDATE message_submission_receipts
                SET updated_at=unixepoch() * 1000
              WHERE session_id=?1 AND client_submission_id=?2",
            rusqlite::params![&cascade_session, cascade_submission.as_slice()],
        )?;
        conn.execute(
            "DELETE FROM message_submission_receipts
             WHERE session_id=?1 AND client_submission_id=?2",
            rusqlite::params![&cascade_session, cascade_submission.as_slice()],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    let cascade_clock_ref = cascaded_ref.clone();
    let (cascade_updated_at, database_now): (i64, i64) = db
        .read(move |conn| {
            conn.query_row(
                "SELECT updated_at, unixepoch() FROM secure_key_consumer_refs
                 WHERE reference_id=?1",
                [cascade_clock_ref],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(Into::into)
        })
        .await
        .unwrap();
    assert!(
        cascade_updated_at <= database_now,
        "FK backstop timestamps use secure-key Unix seconds, not receipt milliseconds"
    );
    assert_eq!(
        ref_state(&db, cascaded_ref.clone()).await,
        Some(SecureKeyRefState::Releasing)
    );
    key.reconcile().await.unwrap();
    assert_eq!(
        ref_state(&db, cascaded_ref).await,
        Some(SecureKeyRefState::Released)
    );

    // Crash residue: a committed Reserved ref with no binding is handled by
    // the same actor reconciliation path and actual DB-existence probe.
    let orphan_ref = "tool-media-subject-binding/orphan/2";
    key.reserve(
        orphan_ref,
        "tool_media_subject_binding",
        version_two,
        "tool_media_subject_binding",
        "missing-session/ffffffffffffffffffffffffffffffff",
    )
    .await
    .unwrap();
    key.reconcile().await.unwrap();
    assert_eq!(
        ref_state(&db, orphan_ref.to_owned()).await,
        Some(SecureKeyRefState::Released)
    );

    let leaked_bindings: i64 = db
        .read(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM message_tool_media_subject_bindings",
                [],
                |row| row.get(0),
            )
            .map_err(Into::into)
        })
        .await
        .unwrap();
    assert_eq!(leaked_bindings, 0);
}

// ---------------------------------------------------------------------------
// Suite 3: tool_media_mixed_principal_fold
// ---------------------------------------------------------------------------

#[test]
fn tool_media_mixed_principal_fold() {
    let key = [0x42; 32];
    let session_id = [0xCD; 16];
    let submission_a = [0x01; 16];
    let submission_b = [0x02; 16];
    let submission_c = [0x03; 16];

    // Same binding (same receipt) for a and b.
    let (_, bytes_a, nonce_a, ct_a) = make_sealed_local_binding(&key, 0, session_id, submission_a);
    let (_, bytes_b, nonce_b, ct_b) = make_sealed_local_binding(&key, 0, session_id, submission_b);

    // Mixed issuer: c is a remote device.
    let (_, bytes_c, nonce_c, ct_c) =
        make_sealed_remote_binding(&key, 0, [0xFF; 16], 1, session_id, submission_c);

    let revalidator = make_revalidator(
        &key,
        FakeProjection {
            device_active: true,
            authority_active: true,
            epoch: 0,
        },
    );

    // a and b have byte-identical canonical receipts → same valid set.
    assert_eq!(bytes_a, bytes_b);
    let subject_a = revalidator
        .revalidate(
            &bytes_a,
            &nonce_a,
            &ct_a,
            "tool_media_subject_binding",
            1,
            &submission_a,
        )
        .unwrap();
    let subject_b = revalidator
        .revalidate(
            &bytes_b,
            &nonce_b,
            &ct_b,
            "tool_media_subject_binding",
            1,
            &submission_b,
        )
        .unwrap();
    assert_eq!(subject_a.receipt, subject_b.receipt);

    // c has a different issuer → mixed principal fold. Only the same valid
    // set (a, b) receives authority; c is a different subject.
    let subject_c = revalidator
        .revalidate(
            &bytes_c,
            &nonce_c,
            &ct_c,
            "tool_media_subject_binding",
            1,
            &submission_c,
        )
        .unwrap();
    assert_ne!(
        subject_a.receipt, subject_c.receipt,
        "mixed issuer yields a different subject — fold gets no shared authority"
    );

    // --- Tampered binding ---
    let mut tampered = bytes_a.clone();
    tampered[5] ^= 1;
    let result = revalidator.revalidate(
        &tampered,
        &nonce_a,
        &ct_a,
        "tool_media_subject_binding",
        1,
        &submission_a,
    );
    assert!(
        result.is_err(),
        "tampered binding must fail closed — no authority"
    );

    // --- Live revalidation failure (stale epoch) ---
    let stale = make_revalidator(
        &key,
        FakeProjection {
            device_active: true,
            authority_active: true,
            epoch: 99,
        },
    );
    let result = stale.revalidate(
        &bytes_a,
        &nonce_a,
        &ct_a,
        "tool_media_subject_binding",
        1,
        &submission_a,
    );
    assert!(
        matches!(result, Err(RevalidatorError::StaleEpoch { .. })),
        "stale epoch must deny — no authority"
    );

    // --- Recovered-after-restart fold: epoch matches after restart ---
    let recovered = make_revalidator(
        &key,
        FakeProjection {
            device_active: true,
            authority_active: true,
            epoch: 0, // same epoch as binding
        },
    );
    let result = recovered.revalidate(
        &bytes_a,
        &nonce_a,
        &ct_a,
        "tool_media_subject_binding",
        1,
        &submission_a,
    );
    assert!(
        result.is_ok(),
        "recovered-after-restart fold with matching epoch receives authority"
    );

    // --- Live-revalidation denial reaches none of the injected content seams. ---
    let (revoked_authority, io) = make_revoked_session_authority(session_id);
    let session = uuid::Uuid::from_bytes(session_id).to_string();
    assert!(matches!(
        revoked_authority.resolve_attachment(&session, &[0x44; 16]),
        Err(AdmissionDenial::SubjectMismatch)
    ));
    assert!(matches!(
        revoked_authority.admit_local_path(&session, "image.png"),
        Err(AdmissionDenial::SubjectMismatch)
    ));
    assert!(matches!(
        revoked_authority.admit_retained_https(&session, "https://example.com/image.png"),
        Err(AdmissionDenial::SubjectMismatch)
    ));
    io.assert_zero();
}

// ---------------------------------------------------------------------------
// Suite 4: tool_media_source_authority
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FakeSourceIo {
    source_opens: std::sync::atomic::AtomicU64,
    source_reads: std::sync::atomic::AtomicU64,
    fetches: std::sync::atomic::AtomicU64,
    reservations: std::sync::atomic::AtomicU64,
    derivatives: std::sync::atomic::AtomicU64,
    runner_calls: std::sync::atomic::AtomicU64,
}

impl FakeSourceIo {
    fn assert_zero(&self) {
        use std::sync::atomic::Ordering;
        assert_eq!(self.source_opens.load(Ordering::SeqCst), 0);
        assert_eq!(self.source_reads.load(Ordering::SeqCst), 0);
        assert_eq!(self.fetches.load(Ordering::SeqCst), 0);
        assert_eq!(self.reservations.load(Ordering::SeqCst), 0);
        assert_eq!(self.derivatives.load(Ordering::SeqCst), 0);
        assert_eq!(self.runner_calls.load(Ordering::SeqCst), 0);
    }

    fn assert_exercised(&self) {
        use std::sync::atomic::Ordering;
        assert!(self.source_opens.load(Ordering::SeqCst) > 0);
        assert!(self.source_reads.load(Ordering::SeqCst) > 0);
        assert!(self.fetches.load(Ordering::SeqCst) > 0);
        assert!(self.reservations.load(Ordering::SeqCst) > 0);
        assert!(self.derivatives.load(Ordering::SeqCst) > 0);
        assert!(self.runner_calls.load(Ordering::SeqCst) > 0);
    }

    fn reset(&self) {
        use std::sync::atomic::Ordering;
        for counter in [
            &self.source_opens,
            &self.source_reads,
            &self.fetches,
            &self.reservations,
            &self.derivatives,
            &self.runner_calls,
        ] {
            counter.store(0, Ordering::SeqCst);
        }
    }
}

struct FakeAttachmentResolver {
    attachments: std::collections::HashMap<[u8; 16], AdmittedAttachment>,
}

#[async_trait]
impl AttachmentResolver for FakeAttachmentResolver {
    fn resolve(
        &self,
        _session_id: &str,
        attachment_id: &[u8; 16],
        max_bytes: usize,
    ) -> Result<Option<AdmittedAttachment>, AdmissionDenial> {
        Ok(self
            .attachments
            .get(attachment_id)
            .filter(|attachment| attachment.content.len() <= max_bytes)
            .cloned())
    }
}

struct FakeLocalPathPolicy {
    io: Arc<FakeSourceIo>,
}

impl LocalPathPolicy for FakeLocalPathPolicy {
    fn admit(
        &self,
        _session_id: &str,
        path: &str,
        max_bytes: usize,
    ) -> Result<super::session_authority::AdmittedLocalHandle, AdmissionDenial> {
        if path.contains("denied") {
            return Err(AdmissionDenial::LocalPathDenied);
        }
        self.io
            .source_opens
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.io
            .source_reads
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.io
            .reservations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.io
            .derivatives
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.io
            .runner_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let content = std::fs::read(path).unwrap_or_default();
        if content.len() > max_bytes {
            return Err(AdmissionDenial::Internal("input too large".into()));
        }
        Ok(
            super::session_authority::AdmittedLocalHandle::from_held_bytes(
                std::path::PathBuf::from(path),
                super::session_authority::HandleEvidence {
                    metadata_fingerprint: [0xAA; 32],
                },
                content,
            ),
        )
    }
}

struct AlwaysLive(RevalidatedSubject);

impl super::session_authority::SubjectLiveness for AlwaysLive {
    fn revalidate(&self) -> Result<RevalidatedSubject, AdmissionDenial> {
        Ok(self.0.clone())
    }
}

struct NeverLive;

impl super::session_authority::SubjectLiveness for NeverLive {
    fn revalidate(&self) -> Result<RevalidatedSubject, AdmissionDenial> {
        Err(AdmissionDenial::SubjectMismatch)
    }
}

struct FakeRetainedHttpsPolicy {
    io: Arc<FakeSourceIo>,
}

impl RetainedHttpsPolicy for FakeRetainedHttpsPolicy {
    fn admit(
        &self,
        _session_id: &str,
        url: &str,
        max_bytes: usize,
    ) -> Result<AdmittedRetainedSource, AdmissionDenial> {
        if url.contains("denied") {
            return Err(AdmissionDenial::HttpsDenied);
        }
        self.io
            .fetches
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.io
            .source_reads
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.io
            .reservations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.io
            .derivatives
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.io
            .runner_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let content = b"fake-content".to_vec();
        if content.len() > max_bytes {
            return Err(AdmissionDenial::Internal("input too large".into()));
        }
        Ok(AdmittedRetainedSource {
            canonical_url: url.to_string(),
            content,
            content_type: "image/png".to_string(),
        })
    }
}

fn make_session_authority(session_id: [u8; 16]) -> (SessionMediaAuthority, Arc<FakeSourceIo>) {
    let subject = RevalidatedSubject {
        receipt: ToolMediaSubjectReceiptV1 {
            issuer_kind: IssuerKind::LocalOwner,
            principal_digest: [0x11; 32],
            project_digest: [0x22; 32],
            session_id,
            authorization_epoch: 0,
            subject_digest: [0x33; 32],
        },
        issuer_kind: IssuerKind::LocalOwner,
        principal_digest: [0x11; 32],
        project_digest: [0x22; 32],
        session_id,
        authorization_epoch: 0,
    };
    let mut attachments = std::collections::HashMap::new();
    attachments.insert(
        [0x44; 16],
        AdmittedAttachment {
            attachment_id: [0x44; 16],
            attachment_version: 1,
            checksum: [0x55; 32],
            kind: 2,
            content: Vec::new(),
        },
    );
    let io = Arc::new(FakeSourceIo::default());
    (
        SessionMediaAuthority::new(
            subject.clone(),
            Arc::new(AlwaysLive(subject)),
            Arc::new(FakeAttachmentResolver { attachments }),
            Arc::new(FakeLocalPathPolicy { io: io.clone() }),
            Arc::new(FakeRetainedHttpsPolicy { io: io.clone() }),
        ),
        io,
    )
}

fn make_revoked_session_authority(
    session_id: [u8; 16],
) -> (SessionMediaAuthority, Arc<FakeSourceIo>) {
    let (live, io) = make_session_authority(session_id);
    let subject = live.subject().clone();
    (
        SessionMediaAuthority::new(
            subject,
            Arc::new(NeverLive),
            Arc::new(FakeAttachmentResolver {
                attachments: std::collections::HashMap::new(),
            }),
            Arc::new(FakeLocalPathPolicy { io: io.clone() }),
            Arc::new(FakeRetainedHttpsPolicy { io: io.clone() }),
        ),
        io,
    )
}

#[test]
fn tool_media_source_authority() {
    let session_id = [0xCD; 16];
    let (auth, io) = make_session_authority(session_id);
    let session_hex = uuid::Uuid::from_bytes(session_id).to_string();

    // Attachment admission — only matching subject.
    let att = auth.resolve_attachment(&session_hex, &[0x44; 16]).unwrap();
    assert_eq!(att.attachment_id(), [0x44; 16]);

    // Wrong session → subject mismatch, no existence oracle.
    let result = auth.resolve_attachment("wrong-session", &[0x44; 16]);
    assert!(matches!(result, Err(AdmissionDenial::SubjectMismatch)));
    io.assert_zero();

    // Missing attachment → existence-hiding denial.
    let result = auth.resolve_attachment(&session_hex, &[0x99; 16]);
    assert!(matches!(result, Err(AdmissionDenial::AttachmentNotFound)));
    io.assert_zero();

    // Local path admission — exact canonical authorization.
    let handle = auth
        .admit_local_path(&session_hex, "/tmp/image.png")
        .unwrap();
    assert_eq!(
        handle.canonical_path(),
        &std::path::PathBuf::from("/tmp/image.png")
    );

    // Local path denied.
    let result = auth.admit_local_path(&session_hex, "/tmp/denied.png");
    assert!(matches!(result, Err(AdmissionDenial::LocalPathDenied)));

    // HTTPS admission — retained source.
    let source = auth
        .admit_retained_https(&session_hex, "https://example.com/image.png")
        .unwrap();
    assert_eq!(source.canonical_url(), "https://example.com/image.png");
    assert_eq!(source.content_type(), "image/png");

    // HTTPS denied.
    let result = auth.admit_retained_https(&session_hex, "https://denied.example.com/x");
    assert!(matches!(result, Err(AdmissionDenial::HttpsDenied)));
    // Every counter has a success-path positive control. Reset those
    // observations, then prove each denial performed no
    // content operation in the injected policies. These are the fakes the
    // authority actually called, not counters owned by the authority itself.
    io.assert_exercised();
    io.reset();
    let _ = auth.resolve_attachment("wrong-session", &[0x44; 16]);
    let _ = auth.admit_local_path(&session_hex, "/tmp/denied.png");
    let _ = auth.admit_retained_https(&session_hex, "https://denied.example.com/x");
    io.assert_zero();
}

// ---------------------------------------------------------------------------
// Suite 5: tool_media_context_stripping
// ---------------------------------------------------------------------------

#[test]
fn tool_media_context_stripping() {
    // This suite proves that public constructors, HostContext::from_tool_ctx,
    // catalog contexts, and external MCP cannot construct/recover a subject
    // or register/call source-admitting tools.
    //
    // The external-crate construction boundary is covered by the
    // `compile_fail` doctest on `tool_media_authority`; these runtime
    // inventories cover the independently observable registry surface.

    // 1. MediaToolAvailability is Copy + 1 byte — no authority data.
    let avail = MediaToolAvailability::available();
    assert_eq!(std::mem::size_of_val(&avail), 1);

    // 2. Drive a real ToolCtx -> HostContext conversion and inspect the
    // structurally stripped native context retained by catalog/MCP.
    let tmp = tempfile::tempdir().unwrap();
    let mut direct = crate::tools::common::test_ctx(tmp.path());
    direct.available_tools = Arc::new(
        super::availability::MEDIA_TOOL_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
    );
    direct.media_availability = MediaToolAvailability::available();
    direct = direct.with_media_authority(Arc::new(make_session_authority([0xCD; 16]).0));
    assert!(direct.media_authority().is_some());
    let public_view = direct.view();
    assert_eq!(public_view.agent_id, direct.agent_id);
    assert!(public_view.available_tools.contains("read_image"));

    let host = HostContext::from_tool_ctx(&direct);
    let stripped = host
        .native_tool_ctx
        .as_ref()
        .expect("host context retains only the stripped native context");
    assert!(stripped.media_authority().is_none());
    assert!(!stripped.media_availability.is_available());
    for &name in super::availability::MEDIA_TOOL_NAMES {
        assert!(!stripped.available_tools.contains(name));
    }

    // 3. MediaToolAvailability::unavailable().omitted_tool_names() contains
    // all direct-native media tools.
    let omitted = MediaToolAvailability::unavailable().omitted_tool_names();
    for name in super::availability::MEDIA_TOOL_NAMES {
        assert!(
            omitted.contains(name),
            "{name} must be omitted without authority"
        );
        assert!(
            !crate::engine::tool::is_monty_builtin_adaptable(name),
            "{name} must never enter the Monty/MCP builtin registry"
        );
    }

    // 4. When available, no tools are omitted.
    assert!(
        MediaToolAvailability::available()
            .omitted_tool_names()
            .is_empty()
    );

    // 5. Runtime inventory: neither the default catalog registry nor the
    // per-agent stripped registry exposes a source-admitting name.
    let default_inventory = crate::mcp::builtin::builtin_presentations();
    for &media_name in super::availability::MEDIA_TOOL_NAMES {
        assert!(
            default_inventory
                .iter()
                .all(|(registered, _)| registered != media_name),
            "{media_name} leaked into the default MCP/Monty inventory"
        );
        assert!(
            crate::mcp::builtin::search(&host, media_name)
                .iter()
                .all(|hit| hit.tool != *media_name),
            "{media_name} leaked into the stripped host registry"
        );
    }

    // 6. A catalog context created without a native caller has no retained
    // ToolCtx at all.
    let empty = HostContext::empty_for_tests();
    assert!(empty.native_tool_ctx.is_none());

    // 7. External-crate compile-fail fixtures plus a source-structure gate.
    // rustdoc `compile_fail` doctests are outside this nextest filter; these
    // fixtures are the equivalent external-crate attempts, and the syn
    // assertions fail this named test if ToolCtx becomes Clone or
    // `media_authority` / `SessionMediaAuthority::new` become public.
    assert_compile_fail_fixtures();
}

fn vis_is_public(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_))
}

fn derives_clone(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("derive") {
            return false;
        }
        let Ok(paths) = attr.parse_args_with(
            syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
        ) else {
            return false;
        };
        paths
            .iter()
            .any(|path| path.segments.last().is_some_and(|seg| seg.ident == "Clone"))
    })
}

fn use_tree_contains(tree: &syn::UseTree, name: &str) -> bool {
    match tree {
        syn::UseTree::Name(name_use) => name_use.ident == name,
        syn::UseTree::Rename(rename) => rename.ident == name || rename.rename == name,
        syn::UseTree::Path(path) => use_tree_contains(&path.tree, name),
        syn::UseTree::Group(group) => group.items.iter().any(|item| use_tree_contains(item, name)),
        syn::UseTree::Glob(_) => false,
    }
}

fn impls_clone_for(file: &syn::File, type_name: &str) -> bool {
    file.items.iter().any(|item| {
        let syn::Item::Impl(imp) = item else {
            return false;
        };
        let Some((_, trait_path, _)) = &imp.trait_ else {
            return false;
        };
        if !trait_path
            .segments
            .last()
            .is_some_and(|seg| seg.ident == "Clone")
        {
            return false;
        }
        match &*imp.self_ty {
            syn::Type::Path(path) => path
                .path
                .segments
                .last()
                .is_some_and(|seg| seg.ident == type_name),
            _ => false,
        }
    })
}

fn assert_compile_fail_fixtures() {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures = manifest.join("tests/fixtures/tool_media_context_stripping");
    let clone_src = std::fs::read_to_string(fixtures.join("clone_tool_ctx.rs")).unwrap();
    let field_src = std::fs::read_to_string(fixtures.join("access_media_authority.rs")).unwrap();
    let ctor_src =
        std::fs::read_to_string(fixtures.join("construct_session_media_authority.rs")).unwrap();
    let literal_src = std::fs::read_to_string(fixtures.join("struct_literal.rs")).unwrap();
    assert!(clone_src.contains("ctx.clone()"));
    assert!(field_src.contains("ctx.media_authority"));
    assert!(ctor_src.contains("SessionMediaAuthority::new"));
    assert!(literal_src.contains("SessionMediaAuthority {}"));
    for source in [&clone_src, &field_src, &ctor_src, &literal_src] {
        syn::parse_file(source).expect("compile-fail fixture must parse as Rust");
    }

    let tool_ctx_src =
        std::fs::read_to_string(manifest.join("src/engine/tool.rs")).expect("tool.rs");
    let tool_file = syn::parse_file(&tool_ctx_src).expect("tool.rs parses");
    let tool_ctx = tool_file.items.iter().find_map(|item| match item {
        syn::Item::Struct(item) if item.ident == "ToolCtx" => Some(item),
        _ => None,
    });
    let tool_ctx = tool_ctx.expect("ToolCtx struct");
    assert!(
        !derives_clone(&tool_ctx.attrs),
        "ToolCtx must not derive Clone (external-crate fixture clone_tool_ctx.rs)"
    );
    assert!(
        !impls_clone_for(&tool_file, "ToolCtx"),
        "ToolCtx must not implement Clone (external-crate fixture clone_tool_ctx.rs)"
    );
    let media_authority = tool_ctx.fields.iter().find(|field| {
        field
            .ident
            .as_ref()
            .is_some_and(|ident| ident == "media_authority")
    });
    let media_authority = media_authority.expect("ToolCtx.media_authority");
    assert!(
        !vis_is_public(&media_authority.vis),
        "ToolCtx.media_authority must not be public (external-crate fixture access_media_authority.rs)"
    );

    let authority_src = std::fs::read_to_string(manifest.join("src/tool_media_authority.rs"))
        .expect("tool_media_authority.rs");
    let authority_file = syn::parse_file(&authority_src).expect("tool_media_authority.rs parses");
    let session_mod_is_public = authority_file.items.iter().any(|item| match item {
        syn::Item::Mod(item_mod) => {
            item_mod.ident == "session_authority" && vis_is_public(&item_mod.vis)
        }
        _ => false,
    });
    assert!(
        !session_mod_is_public,
        "session_authority must stay crate-private so an external crate cannot name SessionMediaAuthority"
    );
    let reexport_is_public = authority_file.items.iter().any(|item| match item {
        syn::Item::Use(item_use) => {
            vis_is_public(&item_use.vis)
                && use_tree_contains(&item_use.tree, "SessionMediaAuthority")
        }
        _ => false,
    });
    assert!(
        !reexport_is_public,
        "SessionMediaAuthority must not be a public re-export"
    );

    let session_src =
        std::fs::read_to_string(manifest.join("src/tool_media_authority/session_authority.rs"))
            .expect("session_authority.rs");
    let session_file = syn::parse_file(&session_src).expect("session_authority.rs parses");
    let session_struct = session_file.items.iter().find_map(|item| match item {
        syn::Item::Struct(item) if item.ident == "SessionMediaAuthority" => Some(item),
        _ => None,
    });
    let session_struct = session_struct.expect("SessionMediaAuthority struct");
    for field in &session_struct.fields {
        assert!(
            !vis_is_public(&field.vis),
            "SessionMediaAuthority fields must not be public (struct_literal.rs)"
        );
    }
    let new_is_public = session_file.items.iter().any(|item| {
        let syn::Item::Impl(imp) = item else {
            return false;
        };
        imp.items.iter().any(|impl_item| {
            let syn::ImplItem::Fn(func) = impl_item else {
                return false;
            };
            func.sig.ident == "new" && vis_is_public(&func.vis)
        })
    });
    assert!(
        !new_is_public,
        "SessionMediaAuthority::new must not be public (construct_session_media_authority.rs)"
    );
}

// ---------------------------------------------------------------------------
// Suite 6: media_tool_availability_materialization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn media_tool_availability_materialization() {
    use crate::engine::builtin::materialize_tool_by_name;
    use crate::engine::tool::ToolBox;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = crate::engine::builtin::tests::test_spawn_args(tmp.path());
    args.interactive = true;

    // False availability omits all media tools before ToolCtx: materializing
    // under `unavailable()` must not register a callable media tool. A
    // regression that did `tb.with(ReadImageTool)` here would fail.
    args.media_availability = MediaToolAvailability::unavailable();
    assert!(!args.media_availability.is_available());
    for &name in super::availability::MEDIA_TOOL_NAMES {
        let toolbox = materialize_tool_by_name(ToolBox::new(), name, None, &args).unwrap();
        assert!(
            toolbox.get(name).is_none(),
            "{name} must be omitted from the callable toolbox before ToolCtx"
        );
        assert!(!toolbox.has_direct_native_media());
        assert!(!toolbox.names().iter().any(|registered| *registered == name));
    }

    // True availability carries no authority data and may register the
    // factory. The snapshot is one byte; it cannot authorize admission.
    args.media_availability = MediaToolAvailability::available();
    assert!(args.media_availability.is_available());
    assert!(args.media_availability.omitted_tool_names().is_empty());
    assert_eq!(std::mem::size_of_val(&args.media_availability), 1);
    let registered = materialize_tool_by_name(ToolBox::new(), "read_image", None, &args).unwrap();
    assert!(
        registered.get("read_image").is_some(),
        "available() must actually register the media factory"
    );

    // turn_toolbox still omits callable media tools when the live session
    // has no authority, even if spawn-time availability was true.
    let mut agent = crate::engine::builtin::default_build(&args);
    let mut tools = ToolBox::new();
    for &name in super::availability::MEDIA_TOOL_NAMES {
        tools = materialize_tool_by_name(tools, name, None, &args).unwrap();
    }
    agent.tools = tools;
    let session = crate::session::Session::create_for_test(
        crate::db::Db::open_in_memory().unwrap(),
        tmp.path().to_path_buf(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
    let omitted = crate::engine::agent::turn_toolbox(
        &agent,
        &session,
        tmp.path(),
        &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path()),
    )
    .await;
    for &name in super::availability::MEDIA_TOOL_NAMES {
        assert!(
            omitted.get(name).is_none(),
            "{name} must stay omitted without live session authority"
        );
    }

    // Revocation after registration denies before content I/O.
    let session_id = [0xCD; 16];
    let (auth, io) = make_revoked_session_authority(session_id);
    let session_hex = uuid::Uuid::from_bytes(session_id).to_string();
    assert!(matches!(
        auth.admit_local_path(&session_hex, "/tmp/image.png"),
        Err(AdmissionDenial::SubjectMismatch)
    ));
    assert!(matches!(
        auth.admit_retained_https(&session_hex, "https://example.com/image.png"),
        Err(AdmissionDenial::SubjectMismatch)
    ));
    io.assert_zero();
}

// ---------------------------------------------------------------------------
// Extended suites: five acceptance-criteria pieces (issue #70)
// ---------------------------------------------------------------------------

// --- Piece 1: Queue recovery / materialization -----------------------------

#[tokio::test]
async fn tool_media_subject_binding_replay_and_propagation() {
    // Production daemon-accept → restart → queue → root/subagent composition is
    // `tool_media_subject_binding_replay_and_propagation_daemon_restart_and_release`.
    use super::recovery::{
        RecoveredBinding, SpawnContext, derive_folded_root_subject, media_availability_for_context,
        recover_session_bindings_with_failures,
    };
    use super::revalidator::{ActorSecureKeyResolver, LocalOwnerProjection};
    use super::runtime::ToolMediaRuntime;
    use crate::db::message_attachments::MessageAcceptanceJoin;
    use crate::secure_key::fake::FakeNativeStore;
    use crate::secure_key::{MapReconciler, SecureKeyActor};

    struct Allow;
    impl MessageAcceptanceJoin for Allow {
        fn validate_and_join(
            &self,
            _: &rusqlite::Connection,
            _: &crate::db::message_attachments::AcceptMessageInput,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let workspace = tmp.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let db_path = tmp.path().join("tool-media-restart.sqlite");
    let db = crate::db::Db::open(&db_path).unwrap();
    let native_store = FakeNativeStore::new();
    let session = crate::session::Session::create_for_test(
        db.clone(),
        workspace.clone(),
        "Build",
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap();
    let session_id = session.id;
    let actor = SecureKeyActor::start_with_store(
        db.clone(),
        Box::new(native_store.clone()),
        Arc::new(MapReconciler::new().with_kind("tool_media_subject_binding", |_| true)),
    )
    .unwrap();
    let media_storage = Arc::new(
        crate::media_storage::MediaStorageRecovery::open_or_create(
            db.clone(),
            &tmp.path().join("media"),
        )
        .unwrap(),
    );
    let runtime = ToolMediaRuntime::new(actor.handle(), media_storage.clone());
    let submission = uuid::Uuid::from_bytes([5; 16]);
    let insert = runtime
        .binding_for_acceptance(
            &session,
            crate::db::message_attachments::MessageActor::LocalOwner,
            submission,
            20,
        )
        .await
        .unwrap();
    let input = crate::db::message_attachments::AcceptMessageInput {
        session_id,
        operation_id: [1; 16],
        actor: crate::db::message_attachments::MessageActor::LocalOwner,
        request_hash: [2; 32],
        message_request_digest: [3; 32],
        attachment_set_digest: [4; 32],
        client_submission_id: *submission.as_bytes(),
        queue_item_id: [6; 16],
        canonical_message: b"FCM2\x02".to_vec(),
        attachments: vec![],
        outbox_sequence: 1,
        now_ms: 20,
        tool_media_subject_binding: Some(insert),
    };
    db.accept_message_with_attachments(input, Arc::new(Allow))
        .await
        .unwrap();
    assert_eq!(
        db.accepted_message_queue(session_id).await.unwrap().len(),
        1
    );

    // Production fold path: LocalOwnerProjection + authority_for_fold.
    let authority = runtime
        .authority_for_fold(&session, &[submission])
        .await
        .expect("live local-owner fold must mint authority");
    assert!(authority.subject().issuer_kind == IssuerKind::LocalOwner);

    let projection = LocalOwnerProjection::for_session(&session)
        .await
        .expect("production projection requires an installation identity");
    let revalidator = ToolMediaSubjectRevalidator::new(
        Arc::new(projection),
        Arc::new(ActorSecureKeyResolver::new(actor.handle())),
    );
    let recoveries = recover_session_bindings_with_failures(&db, session_id, &revalidator)
        .await
        .unwrap();
    assert_eq!(recoveries.len(), 1);
    assert!(recoveries[0].result.is_ok());
    let root_subject = recoveries[0].result.as_ref().unwrap().clone();
    let folded = derive_folded_root_subject(&[RecoveredBinding {
        client_submission_id: *submission.as_bytes(),
        result: Ok(root_subject.clone()),
    }]);
    assert!(folded.is_some());
    assert!(
        media_availability_for_context(&SpawnContext::UserRoot, folded.is_some()).is_available()
    );
    assert!(
        media_availability_for_context(
            &SpawnContext::DelegatedChild {
                inherited_valid_root_authority: true,
            },
            folded.is_some(),
        )
        .is_available()
    );
    assert!(
        !media_availability_for_context(
            &SpawnContext::DelegatedChild {
                inherited_valid_root_authority: false,
            },
            true,
        )
        .is_available()
    );

    drop(authority);
    drop(revalidator);
    drop(runtime);
    drop(actor);
    drop(session);
    drop(media_storage);
    drop(db);

    // Restart: reopen SQLite, resume the session, reconstruct production
    // runtime over the same native-store keys. LocalOnlyProjection is not
    // used — a fail-open Owner fallback would still pass that fake.
    let db = crate::db::Db::open(&db_path).unwrap();
    assert_eq!(
        db.accepted_message_queue(session_id).await.unwrap().len(),
        1
    );
    let session = crate::session::Session::resume_for_test(
        db.clone(),
        session_id,
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap()
    .expect("resumed session");
    let actor = SecureKeyActor::start_with_store(
        db.clone(),
        Box::new(native_store.clone()),
        Arc::new(MapReconciler::new().with_kind("tool_media_subject_binding", |_| true)),
    )
    .unwrap();
    let media_storage = Arc::new(
        crate::media_storage::MediaStorageRecovery::open_or_create(
            db.clone(),
            &tmp.path().join("media"),
        )
        .unwrap(),
    );
    let runtime = ToolMediaRuntime::new(actor.handle(), media_storage.clone());
    assert!(
        runtime
            .authority_for_fold(&session, &[submission])
            .await
            .is_some(),
        "restart recovery must revalidate through LocalOwnerProjection"
    );

    // Failed seal: tampered ciphertext must not fall back to Owner.
    db.write(|conn| {
        conn.execute(
            "UPDATE message_tool_media_subject_bindings SET ciphertext = ?1",
            [vec![0u8; 32]],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    assert!(
        runtime
            .authority_for_fold(&session, &[submission])
            .await
            .is_none(),
        "failed unseal must not fall back to Owner"
    );

    // Restore a well-formed ciphertext from the persisted row shape by
    // re-accepting is not needed: missing installation is a separate
    // fail-closed branch of LocalOwnerProjection itself.
    db.write(|conn| {
        conn.execute("DELETE FROM installation_identity", [])?;
        Ok(())
    })
    .await
    .unwrap();
    assert!(
        matches!(
            LocalOwnerProjection::for_session(&session).await,
            Err(RevalidatorError::OwnerInstallationUnavailable)
        ),
        "replaced/missing installation must fail closed"
    );
    assert!(
        runtime
            .authority_for_fold(&session, &[submission])
            .await
            .is_none(),
        "missing installation must deny authority_for_fold with no Owner fallback"
    );
}

// --- Piece 2: Folded root subject derivation -------------------------------

#[test]
fn tool_media_mixed_principal_fold_derivation() {
    use super::recovery::{RecoveredBinding, derive_folded_root_subject};

    let key = [0x42; 32];
    let session_id = [0xCD; 16];

    // Case 1: all identical → Some.
    {
        let sub_a = [0x01; 16];
        let sub_b = [0x02; 16];
        let (_, bytes_a, nonce_a, ct_a) = make_sealed_local_binding(&key, 0, session_id, sub_a);
        let (_, bytes_b, nonce_b, ct_b) = make_sealed_local_binding(&key, 0, session_id, sub_b);
        assert_eq!(bytes_a, bytes_b);

        let revalidator = make_revalidator(
            &key,
            FakeProjection {
                device_active: true,
                authority_active: true,
                epoch: 0,
            },
        );

        let recoveries = vec![
            RecoveredBinding {
                client_submission_id: sub_a,
                result: revalidator.revalidate(
                    &bytes_a,
                    &nonce_a,
                    &ct_a,
                    "tool_media_subject_binding",
                    1,
                    &sub_a,
                ),
            },
            RecoveredBinding {
                client_submission_id: sub_b,
                result: revalidator.revalidate(
                    &bytes_b,
                    &nonce_b,
                    &ct_b,
                    "tool_media_subject_binding",
                    1,
                    &sub_b,
                ),
            },
        ];

        assert!(derive_folded_root_subject(&recoveries).is_some());
    }

    // Case 2: mixed issuer → None.
    {
        let sub_a = [0x01; 16];
        let sub_c = [0x03; 16];
        let (_, bytes_a, nonce_a, ct_a) = make_sealed_local_binding(&key, 0, session_id, sub_a);
        let (_, bytes_c, nonce_c, ct_c) =
            make_sealed_remote_binding(&key, 0, [0xFF; 16], 1, session_id, sub_c);

        let revalidator = make_revalidator(
            &key,
            FakeProjection {
                device_active: true,
                authority_active: true,
                epoch: 0,
            },
        );

        let recoveries = vec![
            RecoveredBinding {
                client_submission_id: sub_a,
                result: revalidator.revalidate(
                    &bytes_a,
                    &nonce_a,
                    &ct_a,
                    "tool_media_subject_binding",
                    1,
                    &sub_a,
                ),
            },
            RecoveredBinding {
                client_submission_id: sub_c,
                result: revalidator.revalidate(
                    &bytes_c,
                    &nonce_c,
                    &ct_c,
                    "tool_media_subject_binding",
                    1,
                    &sub_c,
                ),
            },
        ];

        assert!(derive_folded_root_subject(&recoveries).is_none());
    }

    // Case 3: any failed revalidation → None.
    {
        let sub_a = [0x01; 16];
        let sub_b = [0x02; 16];
        let (_, bytes_a, nonce_a, ct_a) = make_sealed_local_binding(&key, 0, session_id, sub_a);
        let (_, bytes_b, nonce_b, ct_b) = make_sealed_local_binding(&key, 0, session_id, sub_b);
        assert_eq!(bytes_a, bytes_b);

        let ok_rev = make_revalidator(
            &key,
            FakeProjection {
                device_active: true,
                authority_active: true,
                epoch: 0,
            },
        );
        let stale_rev = make_revalidator(
            &key,
            FakeProjection {
                device_active: true,
                authority_active: true,
                epoch: 99,
            },
        );

        let recoveries = vec![
            RecoveredBinding {
                client_submission_id: sub_a,
                result: ok_rev.revalidate(
                    &bytes_a,
                    &nonce_a,
                    &ct_a,
                    "tool_media_subject_binding",
                    1,
                    &sub_a,
                ),
            },
            RecoveredBinding {
                client_submission_id: sub_b,
                result: stale_rev.revalidate(
                    &bytes_b,
                    &nonce_b,
                    &ct_b,
                    "tool_media_subject_binding",
                    1,
                    &sub_b,
                ),
            },
        ];

        assert!(derive_folded_root_subject(&recoveries).is_none());
    }

    // Case 4: empty → None.
    assert!(derive_folded_root_subject(&[]).is_none());
}

// --- Piece 3: Scheduled / background / headless enforcement ----------------

#[test]
fn media_tool_availability_materialization_spawn_context() {
    use super::recovery::{
        SpawnContext, context_eligible_for_authority, media_availability_for_context,
    };

    // UserRoot with valid binding → available.
    assert!(media_availability_for_context(&SpawnContext::UserRoot, true).is_available());
    assert!(context_eligible_for_authority(&SpawnContext::UserRoot));

    // UserRoot without binding → unavailable.
    assert!(!media_availability_for_context(&SpawnContext::UserRoot, false).is_available());

    // ScheduledRoot → never available, never eligible (even with binding).
    assert!(!media_availability_for_context(&SpawnContext::ScheduledRoot, true).is_available());
    assert!(!context_eligible_for_authority(
        &SpawnContext::ScheduledRoot
    ));

    // BackgroundRoot → never available, never eligible.
    assert!(!media_availability_for_context(&SpawnContext::BackgroundRoot, true).is_available());
    assert!(!context_eligible_for_authority(
        &SpawnContext::BackgroundRoot
    ));

    // HeadlessRoot → never available, never eligible.
    assert!(!media_availability_for_context(&SpawnContext::HeadlessRoot, true).is_available());
    assert!(!context_eligible_for_authority(&SpawnContext::HeadlessRoot));

    // DelegatedChild with inherited authority + binding → available.
    let child_with = SpawnContext::DelegatedChild {
        inherited_valid_root_authority: true,
    };
    assert!(media_availability_for_context(&child_with, true).is_available());
    assert!(context_eligible_for_authority(&child_with));

    // DelegatedChild without inherited authority → unavailable.
    let child_without = SpawnContext::DelegatedChild {
        inherited_valid_root_authority: false,
    };
    assert!(!media_availability_for_context(&child_without, true).is_available());
    assert!(!context_eligible_for_authority(&child_without));

    // DelegatedChild with inherited authority but no binding → unavailable.
    assert!(!media_availability_for_context(&child_with, false).is_available());
}

// --- Piece 4: Secure-key ref lifecycle (core-level smoke) ------------------
//
// The DB-level reserve/activate/release lifecycle is tested in
// cockpit-db's `message_attachments` tests. Here we verify the composite
// reconciler routing and the ref-id/consumer-id formatting that the
// lifecycle depends on.

#[test]
fn tool_media_secure_key_lifecycle_ref_ids() {
    // The ref-id format must match what the DB layer writes in accept_conn.
    let ref_id =
        super::binding_key_reference_id("session-abc", "0102030405060708090a0b0c0d0e0f10", 2);
    assert_eq!(
        ref_id,
        "tool-media-subject-binding/session-abc/0102030405060708090a0b0c0d0e0f10/2"
    );

    let consumer_id = super::binding_consumer_id("session-abc", "0102030405060708090a0b0c0d0e0f10");
    assert_eq!(consumer_id, "session-abc/0102030405060708090a0b0c0d0e0f10");

    // The consumer kind constant must be "tool_media_subject_binding".
    assert_eq!(
        super::TOOL_MEDIA_SUBJECT_BINDING_CONSUMER_KIND,
        "tool_media_subject_binding"
    );
    assert_eq!(
        super::TOOL_MEDIA_SUBJECT_BINDING_NAMESPACE,
        "tool_media_subject_binding"
    );
}

// --- Piece 5: Epoch increment on control-state changes ---------------------

#[tokio::test]
async fn tool_media_epoch_increment_on_control_state_changes() {
    use super::recovery::{ControlStateChange, apply_control_state_change_conn};

    let db = crate::db::Db::open_in_memory().unwrap();
    let session = uuid::Uuid::from_bytes([0xCD; 16]);
    let principal = [0x11; 32];
    let project = [0x22; 32];

    // 1. Authority status transition (local owner, issuer_kind=1).
    let auth_change = ControlStateChange::AuthorityStatusTransition {
        issuer_kind: IssuerKind::LocalOwner,
        principal_digest: principal,
        session_id: session,
        project_digest: project,
    };
    let e1 = db
        .transaction(move |conn| apply_control_state_change_conn(conn, auth_change, 100))
        .await
        .unwrap();
    assert_eq!(e1, 1);

    // The epoch is now 1 — a binding at epoch 0 would fail revalidation.
    let current = db
        .tool_media_authorization_epoch(1, principal, session, project)
        .await
        .unwrap();
    assert_eq!(current, Some(1));

    // 2. Local membership/read-path change (local owner, issuer_kind=1).
    let membership_change = ControlStateChange::LocalMembershipReadPathChange {
        principal_digest: principal,
        session_id: session,
        project_digest: project,
    };
    let e2 = db
        .transaction(move |conn| apply_control_state_change_conn(conn, membership_change, 200))
        .await
        .unwrap();
    assert_eq!(e2, 2);

    // 3. Device revocation (remote device, issuer_kind=2) — different tuple.
    let device_change = ControlStateChange::DeviceRevocation {
        device_uuid: [0xFF; 16],
        principal_digest: [0x33; 32], // different principal for the remote device
        session_id: session,
        project_digest: project,
    };
    let e3 = db
        .transaction(move |conn| apply_control_state_change_conn(conn, device_change, 300))
        .await
        .unwrap();
    assert_eq!(e3, 1); // new tuple → starts at 1

    // The remote device epoch is independent from the local owner epoch.
    let remote_epoch = db
        .tool_media_authorization_epoch(2, [0x33; 32], session, project)
        .await
        .unwrap();
    assert_eq!(remote_epoch, Some(1));

    // The local owner epoch is still 2 (unaffected by the device revocation
    // for a different principal).
    let local_epoch = db
        .tool_media_authorization_epoch(1, principal, session, project)
        .await
        .unwrap();
    assert_eq!(local_epoch, Some(2));

    // 4. A second authority status transition increments to 3.
    let e4 = db
        .transaction(move |conn| apply_control_state_change_conn(conn, auth_change, 400))
        .await
        .unwrap();
    assert_eq!(e4, 3);
}
