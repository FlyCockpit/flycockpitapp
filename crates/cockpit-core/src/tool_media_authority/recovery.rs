//! Queue recovery, folded-root subject derivation, spawn-context enforcement,
//! and epoch increment for tool-media authority.
//!
//! This module wires the five acceptance-criteria pieces of issue #70:
//!
//! 1. **Queue recovery/materialization** — loads the binding for every
//!    accepted `UserSubmission` via
//!    `Db::load_tool_media_subject_bindings_for_session` and revalidates each
//!    through `ToolMediaSubjectRevalidator`. Only successfully revalidated
//!    bindings produce a `RevalidatedSubject`; every failure is fail-closed
//!    with no Owner fallback.
//! 2. **Folded root subject derivation** — a folded root gets a subject only
//!    if ALL contributors have byte-identical canonical receipts and each
//!    live revalidation succeeds; otherwise it stays folded with NO authority.
//! 3. **Scheduled/background/headless roots** and children without inherited
//!    valid root authority get no media availability and no authority.
//! 4. **Secure-key ref lifecycle** — the `accept_message_with_attachments`
//!    transaction reserves the consumer ref before the binding insert and
//!    activates it after (see `cockpit-db` `accept_conn`). This module owns
//!    the ref-id/consumer-id formatting helpers.
//! 5. **Epoch increment** on control-state changes (device revocation,
//!    authority status transition, local membership/read-path change) inside
//!    the authoritative write transaction.

use std::collections::HashMap;

use uuid::Uuid;

use super::availability::MediaToolAvailability;
use super::receipt::{CANONICAL_LEN, IssuerKind, RECEIPT_VERSION, ToolMediaSubjectReceiptV1};
use super::revalidator::{RevalidatedSubject, RevalidatorError, ToolMediaSubjectRevalidator};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error during binding recovery — always fail-closed (no authority).
#[derive(Debug, Clone, thiserror::Error)]
pub enum RecoveryError {
    #[error("database error: {0}")]
    Database(String),
    #[error("invalid issuer kind in binding row: {0}")]
    InvalidIssuerKind(i64),
    #[error("invalid session id in binding row: {0}")]
    InvalidSessionId(String),
    #[error("receipt reconstruction failed: {0}")]
    ReceiptReconstruction(String),
    #[error("unsupported stored receipt version: {0}")]
    UnsupportedReceiptVersion(i64),
    #[error("unsupported stored seal version: {0}")]
    UnsupportedSealVersion(i64),
    #[error("revalidation failed: {0}")]
    Revalidation(#[from] RevalidatorError),
}

// ---------------------------------------------------------------------------
// 1. Queue recovery / materialization
// ---------------------------------------------------------------------------

/// Reconstruct a `ToolMediaSubjectReceiptV1` from a persisted binding row's
/// individual stored fields.
///
/// The binding table stores the receipt components as separate columns (not
/// the canonical byte blob). This function reassembles the 122-byte canonical
/// encoding and validates the `subject_digest` via `decode`.
pub fn receipt_from_binding_row(
    row: &crate::db::tool_media_subject_bindings::ToolMediaSubjectBindingRowV1,
) -> Result<ToolMediaSubjectReceiptV1, RecoveryError> {
    if row.receipt_version != i64::from(RECEIPT_VERSION) {
        return Err(RecoveryError::UnsupportedReceiptVersion(
            row.receipt_version,
        ));
    }
    if row.seal_version != i64::from(super::seal::SEAL_VERSION) {
        return Err(RecoveryError::UnsupportedSealVersion(row.seal_version));
    }
    let issuer_kind = u8::try_from(row.issuer_kind)
        .ok()
        .and_then(IssuerKind::from_u8)
        .ok_or(RecoveryError::InvalidIssuerKind(row.issuer_kind))?;

    let session_uuid = Uuid::parse_str(&row.session_id)
        .map_err(|e| RecoveryError::InvalidSessionId(e.to_string()))?;
    let session_id: [u8; 16] = *session_uuid.as_bytes();

    // Reassemble canonical bytes: version | issuer | principal | project |
    // session | epoch(BE) | subject_digest
    let mut bytes = Vec::with_capacity(CANONICAL_LEN);
    bytes.push(u8::try_from(row.receipt_version).map_err(|_| {
        RecoveryError::ReceiptReconstruction("receipt version is outside u8".to_owned())
    })?);
    bytes.push(issuer_kind.as_u8());
    bytes.extend_from_slice(&row.principal_digest);
    bytes.extend_from_slice(&row.project_digest);
    bytes.extend_from_slice(&session_id);
    let authorization_epoch = u64::try_from(row.authorization_epoch).map_err(|_| {
        RecoveryError::ReceiptReconstruction(format!(
            "negative authorization_epoch: {}",
            row.authorization_epoch
        ))
    })?;
    bytes.extend_from_slice(&authorization_epoch.to_be_bytes());
    bytes.extend_from_slice(&row.subject_digest);

    debug_assert_eq!(bytes.len(), CANONICAL_LEN);

    ToolMediaSubjectReceiptV1::decode(&bytes)
        .map_err(|e| RecoveryError::ReceiptReconstruction(e.to_string()))
}

/// A recovered binding: the revalidated subject (on success) or the
/// revalidation error (on failure). Failures are fail-closed — the caller
/// must not grant authority for a failed binding.
#[derive(Debug)]
pub struct RecoveredBinding {
    /// The `client_submission_id` this binding was accepted for.
    pub client_submission_id: [u8; 16],
    /// The revalidation outcome. `Ok` carries the fresh private subject;
    /// `Err` is fail-closed (no authority, no Owner fallback).
    pub result: Result<RevalidatedSubject, RevalidatorError>,
}

/// Load and revalidate every persisted tool-media-subject binding for a
/// session.
///
/// This is the queue recovery / materialization path. Each binding is
/// revalidated live through the `ToolMediaSubjectRevalidator`; a failure
/// (missing key, stale epoch, revoked device, tampered receipt/seal, etc.)
/// yields `Err` and the caller must treat that submission as having no
/// authority. There is no Owner fallback.
///
/// Returns a map of `client_submission_id → RevalidatedSubject` for the
/// bindings that revalidated successfully. Failed bindings are absent from
/// the map.
pub async fn recover_session_bindings(
    db: &crate::db::Db,
    session_id: Uuid,
    revalidator: &ToolMediaSubjectRevalidator,
) -> Result<HashMap<[u8; 16], RevalidatedSubject>, RecoveryError> {
    let rows = db
        .load_tool_media_subject_bindings_for_session(session_id)
        .await
        .map_err(|e| RecoveryError::Database(e.to_string()))?;

    let mut recovered = HashMap::new();
    for row in rows {
        let receipt = receipt_from_binding_row(&row)?;
        let receipt_bytes = receipt.canonical_bytes();

        let result = revalidator.revalidate(
            &receipt_bytes,
            &row.nonce,
            &row.ciphertext,
            &row.key_namespace,
            row.key_version,
            &row.client_submission_id,
        );

        match result {
            Ok(subject) => {
                recovered.insert(row.client_submission_id, subject);
            }
            Err(_err) => {
                // Fail-closed: a failed revalidation contributes no authority.
                // The submission is still in the queue but gets no media tools.
                tracing::warn!(
                    session = %row.session_id,
                    "tool-media-subject binding revalidation failed during recovery — no authority granted"
                );
            }
        }
    }
    Ok(recovered)
}

/// Recover all bindings (including failures) for inspection / fold logic.
///
/// Unlike [`recover_session_bindings`], this returns every binding's
/// revalidation outcome so the fold logic can enforce the "ALL contributors
/// must succeed" rule.
pub async fn recover_session_bindings_with_failures(
    db: &crate::db::Db,
    session_id: Uuid,
    revalidator: &ToolMediaSubjectRevalidator,
) -> Result<Vec<RecoveredBinding>, RecoveryError> {
    let rows = db
        .load_tool_media_subject_bindings_for_session(session_id)
        .await
        .map_err(|e| RecoveryError::Database(e.to_string()))?;

    let mut recovered = Vec::with_capacity(rows.len());
    for row in rows {
        let receipt = receipt_from_binding_row(&row)?;
        let receipt_bytes = receipt.canonical_bytes();

        let result = revalidator.revalidate(
            &receipt_bytes,
            &row.nonce,
            &row.ciphertext,
            &row.key_namespace,
            row.key_version,
            &row.client_submission_id,
        );

        recovered.push(RecoveredBinding {
            client_submission_id: row.client_submission_id,
            result,
        });
    }
    Ok(recovered)
}

// ---------------------------------------------------------------------------
// 2. Folded root subject derivation
// ---------------------------------------------------------------------------

/// Derive the subject for a folded root turn.
///
/// A folded root gets a subject only if **ALL** contributors have
/// byte-identical canonical receipts **and** each live revalidation succeeds.
/// Otherwise the fold stays with no authority (fail closed).
///
/// # Arguments
///
/// * `recoveries` — the revalidation outcomes for every contributor to the
///   fold. The caller must include every contributor; omitting a failed
///   binding would silently weaken the fold.
///
/// # Returns
///
/// `Some(subject)` if all contributors revalidated successfully and share
/// byte-identical canonical receipts. `None` if the slice is empty, any
/// contributor failed revalidation, or the canonical receipts differ.
pub fn derive_folded_root_subject(recoveries: &[RecoveredBinding]) -> Option<RevalidatedSubject> {
    if recoveries.is_empty() {
        return None;
    }

    // Every contributor must revalidate successfully.
    let mut canonical_bytes: Option<Vec<u8>> = None;
    let mut shared_subject: Option<RevalidatedSubject> = None;

    for binding in recoveries {
        let subject = match &binding.result {
            Ok(s) => s,
            Err(_) => {
                // Any failed revalidation → no authority for the fold.
                return None;
            }
        };

        let bytes = subject.receipt.canonical_bytes();

        match &canonical_bytes {
            None => {
                canonical_bytes = Some(bytes);
                shared_subject = Some(subject.clone());
            }
            Some(existing) => {
                if existing != &bytes {
                    // Mixed canonical receipts → no shared authority.
                    return None;
                }
            }
        }
    }

    shared_subject
}

// ---------------------------------------------------------------------------
// 3. Scheduled / background / headless enforcement
// ---------------------------------------------------------------------------

/// The spawn context for a media-availability decision.
///
/// Only a `UserRoot` with a valid recovered binding (or a `DelegatedChild`
/// that inherits valid root authority) may receive media tool availability.
/// Scheduled, background, and headless roots never do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnContext {
    /// The interactive user-facing root session with a recovered binding.
    UserRoot,
    /// A scheduled / cron-driven root — no user submission, no authority.
    ScheduledRoot,
    /// A background root — no user submission, no authority.
    BackgroundRoot,
    /// A headless / non-interactive root — no user submission, no authority.
    HeadlessRoot,
    /// A delegated child agent. Authority is inherited only when the parent
    /// root had a valid revalidated binding.
    DelegatedChild {
        inherited_valid_root_authority: bool,
    },
}

/// Whether a spawn context is eligible for media tool availability at all.
///
/// This is the data-free gate checked before `ToolCtx` construction. Even
/// when eligible, the actual `SessionMediaAuthority` is constructed fresh on
/// each tool call from the persisted binding and live revalidator — this
/// gate only controls whether the media tools appear in the toolbox.
pub fn media_availability_for_context(
    context: &SpawnContext,
    has_valid_binding: bool,
) -> MediaToolAvailability {
    match context {
        SpawnContext::UserRoot if has_valid_binding => MediaToolAvailability::authority_only(),
        SpawnContext::DelegatedChild {
            inherited_valid_root_authority: true,
        } if has_valid_binding => MediaToolAvailability::authority_only(),
        _ => MediaToolAvailability::unavailable(),
    }
}

/// Whether a spawn context is eligible to carry a `SessionMediaAuthority`.
///
/// This is the authority-level gate. Scheduled/background/headless roots and
/// children without inherited valid root authority always return `false`.
pub fn context_eligible_for_authority(context: &SpawnContext) -> bool {
    match context {
        SpawnContext::UserRoot => true,
        SpawnContext::DelegatedChild {
            inherited_valid_root_authority,
        } => *inherited_valid_root_authority,
        SpawnContext::ScheduledRoot | SpawnContext::BackgroundRoot | SpawnContext::HeadlessRoot => {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Secure-key ref lifecycle helpers
// ---------------------------------------------------------------------------

/// Build the secure-key consumer id for a binding from DB-level string
/// components.
///
/// Format: `<session>/<client-submission-hex>`
pub fn binding_consumer_id_from_parts(session_id: &str, client_submission_hex: &str) -> String {
    super::binding_consumer_id(session_id, client_submission_hex)
}

/// Build the secure-key reference id for a binding from DB-level string
/// components.
///
/// Format: `tool-media-subject-binding/<session>/<client-submission-hex>/<key-version>`
pub fn binding_key_reference_id_from_parts(
    session_id: &str,
    client_submission_hex: &str,
    key_version: i64,
) -> String {
    super::binding_key_reference_id(session_id, client_submission_hex, key_version)
}

// ---------------------------------------------------------------------------
// 5. Epoch increment on control-state changes
// ---------------------------------------------------------------------------

/// A control-state change that invalidates existing tool-media-subject
/// bindings by incrementing the authorization epoch.
///
/// Each variant maps to a `Db::increment_tool_media_authorization_epoch_conn`
/// call inside the authoritative write transaction. After the increment,
/// every binding with the old epoch fails revalidation with `StaleEpoch`.
#[derive(Debug, Clone, Copy)]
pub enum ControlStateChange {
    /// A remote device was revoked or deleted. All bindings issued by that
    /// device for the `(principal, session, project)` tuple are invalidated.
    DeviceRevocation {
        device_uuid: [u8; 16],
        principal_digest: [u8; 32],
        session_id: Uuid,
        project_digest: [u8; 32],
    },
    /// An authority status transition (active → paused/expired/revoked or
    /// vice versa) for the `(issuer, principal, session, project)` tuple.
    AuthorityStatusTransition {
        issuer_kind: IssuerKind,
        principal_digest: [u8; 32],
        session_id: Uuid,
        project_digest: [u8; 32],
    },
    /// A local membership or read-path change (e.g. the session's read scope
    /// or local Owner installation membership changed) for the tuple.
    LocalMembershipReadPathChange {
        principal_digest: [u8; 32],
        session_id: Uuid,
        project_digest: [u8; 32],
    },
}

impl ControlStateChange {
    /// The issuer kind affected by this control-state change.
    pub fn issuer_kind(&self) -> IssuerKind {
        match self {
            Self::DeviceRevocation { .. } => IssuerKind::RemoteDevice,
            Self::AuthorityStatusTransition { issuer_kind, .. } => *issuer_kind,
            Self::LocalMembershipReadPathChange { .. } => IssuerKind::LocalOwner,
        }
    }

    /// The principal digest affected by this control-state change.
    pub fn principal_digest(&self) -> [u8; 32] {
        match self {
            Self::DeviceRevocation {
                principal_digest, ..
            }
            | Self::AuthorityStatusTransition {
                principal_digest, ..
            }
            | Self::LocalMembershipReadPathChange {
                principal_digest, ..
            } => *principal_digest,
        }
    }

    /// The session id affected by this control-state change.
    pub fn session_id(&self) -> Uuid {
        match self {
            Self::DeviceRevocation { session_id, .. }
            | Self::AuthorityStatusTransition { session_id, .. }
            | Self::LocalMembershipReadPathChange { session_id, .. } => *session_id,
        }
    }

    /// The project digest affected by this control-state change.
    pub fn project_digest(&self) -> [u8; 32] {
        match self {
            Self::DeviceRevocation { project_digest, .. }
            | Self::AuthorityStatusTransition { project_digest, .. }
            | Self::LocalMembershipReadPathChange { project_digest, .. } => *project_digest,
        }
    }
}

/// Apply a control-state change by incrementing the authorization epoch
/// inside the caller's open write transaction.
///
/// Returns the new epoch value. After this call, all bindings with the
/// previous epoch will fail live revalidation with `StaleEpoch`.
///
/// Session-wide live membership/ownership writes (collaborator sharing,
/// created-by principal, session end) go through
/// `invalidate_tool_media_authorization_epochs_for_session_conn` in the
/// same SQLite transaction as the control-state mutation. This helper is
/// the tuple-specific path for device revocation and authority-status
/// transitions that already know `(issuer, principal, session, project)`.
pub fn apply_control_state_change_conn(
    conn: &rusqlite::Connection,
    change: ControlStateChange,
    now_ms: i64,
) -> Result<i64, anyhow::Error> {
    let issuer_kind = change.issuer_kind();
    let principal_digest = change.principal_digest();
    let session_id = change.session_id().to_string();
    let project_digest = change.project_digest();

    crate::db::Db::increment_tool_media_authorization_epoch_conn(
        conn,
        i64::from(issuer_kind.as_u8()),
        principal_digest,
        &session_id,
        project_digest,
        now_ms,
    )
    .map_err(Into::into)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool_media_authority::locator::LocatorV1;
    use crate::tool_media_authority::revalidator::{
        LocalOnlyProjection, RemoteStatusProjection, SecureKeyResolver,
    };
    use crate::tool_media_authority::seal;
    use std::sync::Arc;

    // -- Helpers --

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

    fn make_revalidator(key: &[u8; 32], projection: FakeProjection) -> ToolMediaSubjectRevalidator {
        ToolMediaSubjectRevalidator::new(
            Arc::new(projection),
            Arc::new(FakeKeyResolver {
                key: *key,
                available: true,
            }),
        )
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

    // -- Receipt reconstruction --

    #[test]
    fn receipt_from_row_round_trips() {
        let key = [0x42; 32];
        let session_id = [0xCD; 16];
        let submission = [0x01; 16];
        let (receipt, receipt_bytes, nonce, ciphertext) =
            make_sealed_local_binding(&key, 0, session_id, submission);

        let session_uuid = Uuid::from_bytes(session_id);
        let row = crate::db::tool_media_subject_bindings::ToolMediaSubjectBindingRowV1 {
            session_id: session_uuid.to_string(),
            client_submission_id: submission,
            receipt_version: 1,
            issuer_kind: 1,
            principal_digest: receipt.principal_digest,
            project_digest: receipt.project_digest,
            authorization_epoch: 0,
            subject_digest: receipt.subject_digest,
            seal_version: 1,
            key_namespace: "tool_media_subject_binding".to_string(),
            key_version: 1,
            nonce,
            ciphertext,
            secure_key_reference_id: "test-ref".to_string(),
            receipt_bytes: Vec::new(),
            created_at: 10,
            updated_at: 10,
        };

        let reconstructed = receipt_from_binding_row(&row).unwrap();
        assert_eq!(reconstructed, receipt);
        assert_eq!(reconstructed.canonical_bytes(), receipt_bytes);

        let mut bad_receipt_version = row.clone();
        bad_receipt_version.receipt_version = 2;
        assert!(matches!(
            receipt_from_binding_row(&bad_receipt_version),
            Err(RecoveryError::UnsupportedReceiptVersion(2))
        ));

        let mut bad_seal_version = row;
        bad_seal_version.seal_version = 2;
        assert!(matches!(
            receipt_from_binding_row(&bad_seal_version),
            Err(RecoveryError::UnsupportedSealVersion(2))
        ));
    }

    #[test]
    fn receipt_from_row_detects_tampered_subject_digest() {
        let key = [0x42; 32];
        let session_id = [0xCD; 16];
        let submission = [0x01; 16];
        let (receipt, _receipt_bytes, nonce, ciphertext) =
            make_sealed_local_binding(&key, 0, session_id, submission);

        let mut bad_digest = receipt.subject_digest;
        bad_digest[0] ^= 1;

        let session_uuid = Uuid::from_bytes(session_id);
        let row = crate::db::tool_media_subject_bindings::ToolMediaSubjectBindingRowV1 {
            session_id: session_uuid.to_string(),
            client_submission_id: submission,
            receipt_version: 1,
            issuer_kind: 1,
            principal_digest: receipt.principal_digest,
            project_digest: receipt.project_digest,
            authorization_epoch: 0,
            subject_digest: bad_digest,
            seal_version: 1,
            key_namespace: "tool_media_subject_binding".to_string(),
            key_version: 1,
            nonce,
            ciphertext,
            secure_key_reference_id: "test-ref".to_string(),
            receipt_bytes: Vec::new(),
            created_at: 10,
            updated_at: 10,
        };

        assert!(receipt_from_binding_row(&row).is_err());
    }

    #[test]
    fn receipt_from_row_rejects_invalid_issuer_kind() {
        let key = [0x42; 32];
        let session_id = [0xCD; 16];
        let submission = [0x01; 16];
        let (receipt, _, nonce, ciphertext) =
            make_sealed_local_binding(&key, 0, session_id, submission);

        let session_uuid = Uuid::from_bytes(session_id);
        let row = crate::db::tool_media_subject_bindings::ToolMediaSubjectBindingRowV1 {
            session_id: session_uuid.to_string(),
            client_submission_id: submission,
            receipt_version: 1,
            issuer_kind: 99, // invalid
            principal_digest: receipt.principal_digest,
            project_digest: receipt.project_digest,
            authorization_epoch: 0,
            subject_digest: receipt.subject_digest,
            seal_version: 1,
            key_namespace: "tool_media_subject_binding".to_string(),
            key_version: 1,
            nonce,
            ciphertext,
            secure_key_reference_id: "test-ref".to_string(),
            receipt_bytes: Vec::new(),
            created_at: 10,
            updated_at: 10,
        };

        let result = receipt_from_binding_row(&row);
        assert!(matches!(result, Err(RecoveryError::InvalidIssuerKind(99))));
    }

    // -- Folded root subject derivation --

    #[test]
    fn fold_empty_returns_none() {
        assert!(derive_folded_root_subject(&[]).is_none());
    }

    #[test]
    fn fold_all_identical_returns_some() {
        let key = [0x42; 32];
        let session_id = [0xCD; 16];
        let sub_a = [0x01; 16];
        let sub_b = [0x02; 16];
        let sub_c = [0x03; 16];

        let (_, bytes_a, nonce_a, ct_a) = make_sealed_local_binding(&key, 0, session_id, sub_a);
        let (_, bytes_b, nonce_b, ct_b) = make_sealed_local_binding(&key, 0, session_id, sub_b);
        let (_, bytes_c, nonce_c, ct_c) = make_sealed_local_binding(&key, 0, session_id, sub_c);

        // All three have byte-identical canonical receipts (same issuer/
        // principal/project/session/epoch).
        assert_eq!(bytes_a, bytes_b);
        assert_eq!(bytes_a, bytes_c);

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

        let folded = derive_folded_root_subject(&recoveries);
        assert!(
            folded.is_some(),
            "all-identical fold must receive authority"
        );
        let subject = folded.unwrap();
        assert_eq!(subject.receipt.canonical_bytes(), bytes_a);
    }

    #[test]
    fn fold_mixed_issuer_returns_none() {
        let key = [0x42; 32];
        let session_id = [0xCD; 16];
        let sub_a = [0x01; 16];
        let sub_b = [0x02; 16];

        let (_, bytes_a, nonce_a, ct_a) = make_sealed_local_binding(&key, 0, session_id, sub_a);
        // sub_b is a remote device — different issuer/principal.
        let (_, bytes_b, nonce_b, ct_b) =
            make_sealed_remote_binding(&key, 0, [0xFF; 16], 1, session_id, sub_b);

        assert_ne!(bytes_a, bytes_b);

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

        let folded = derive_folded_root_subject(&recoveries);
        assert!(
            folded.is_none(),
            "mixed-issuer fold must fail closed — no authority"
        );
    }

    #[test]
    fn fold_any_failed_revalidation_returns_none() {
        let key = [0x42; 32];
        let session_id = [0xCD; 16];
        let sub_a = [0x01; 16];
        let sub_b = [0x02; 16];

        let (_, bytes_a, nonce_a, ct_a) = make_sealed_local_binding(&key, 0, session_id, sub_a);
        let (_, bytes_b, nonce_b, ct_b) = make_sealed_local_binding(&key, 0, session_id, sub_b);

        assert_eq!(bytes_a, bytes_b);

        // sub_a revalidates successfully; sub_b sees a stale epoch.
        let ok_revalidator = make_revalidator(
            &key,
            FakeProjection {
                device_active: true,
                authority_active: true,
                epoch: 0,
            },
        );
        let stale_revalidator = make_revalidator(
            &key,
            FakeProjection {
                device_active: true,
                authority_active: true,
                epoch: 5, // epoch advanced
            },
        );

        let recoveries = vec![
            RecoveredBinding {
                client_submission_id: sub_a,
                result: ok_revalidator.revalidate(
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
                result: stale_revalidator.revalidate(
                    &bytes_b,
                    &nonce_b,
                    &ct_b,
                    "tool_media_subject_binding",
                    1,
                    &sub_b,
                ),
            },
        ];

        let folded = derive_folded_root_subject(&recoveries);
        assert!(
            folded.is_none(),
            "fold with any failed revalidation must fail closed"
        );
    }

    #[test]
    fn fold_different_epoch_returns_none() {
        let key = [0x42; 32];
        let session_id = [0xCD; 16];
        let sub_a = [0x01; 16];
        let sub_b = [0x02; 16];

        // Same issuer but different epochs → different canonical receipts.
        let (_, bytes_a, nonce_a, ct_a) = make_sealed_local_binding(&key, 0, session_id, sub_a);
        let (_, bytes_b, nonce_b, ct_b) = make_sealed_local_binding(&key, 1, session_id, sub_b);

        assert_ne!(bytes_a, bytes_b, "different epochs → different receipts");

        // Use a projection that accepts epoch 0 for a and epoch 1 for b.
        // Since FakeProjection returns a single epoch, we use two revalidators.
        let rev_a = make_revalidator(
            &key,
            FakeProjection {
                device_active: true,
                authority_active: true,
                epoch: 0,
            },
        );
        let rev_b = make_revalidator(
            &key,
            FakeProjection {
                device_active: true,
                authority_active: true,
                epoch: 1,
            },
        );

        let recoveries = vec![
            RecoveredBinding {
                client_submission_id: sub_a,
                result: rev_a.revalidate(
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
                result: rev_b.revalidate(
                    &bytes_b,
                    &nonce_b,
                    &ct_b,
                    "tool_media_subject_binding",
                    1,
                    &sub_b,
                ),
            },
        ];

        let folded = derive_folded_root_subject(&recoveries);
        assert!(
            folded.is_none(),
            "fold with different epochs (different canonical receipts) must fail closed"
        );
    }

    #[test]
    fn fold_single_successful_returns_some() {
        let key = [0x42; 32];
        let session_id = [0xCD; 16];
        let sub_a = [0x01; 16];

        let (_, bytes_a, nonce_a, ct_a) = make_sealed_local_binding(&key, 0, session_id, sub_a);

        let revalidator = make_revalidator(
            &key,
            FakeProjection {
                device_active: true,
                authority_active: true,
                epoch: 0,
            },
        );

        let recoveries = vec![RecoveredBinding {
            client_submission_id: sub_a,
            result: revalidator.revalidate(
                &bytes_a,
                &nonce_a,
                &ct_a,
                "tool_media_subject_binding",
                1,
                &sub_a,
            ),
        }];

        let folded = derive_folded_root_subject(&recoveries);
        assert!(
            folded.is_some(),
            "single successful contributor receives authority"
        );
    }

    // -- Spawn context enforcement --

    #[test]
    fn scheduled_root_gets_no_availability() {
        let avail = media_availability_for_context(
            &SpawnContext::ScheduledRoot,
            true, // even with a valid binding
        );
        assert!(!avail.is_available());
        assert!(!context_eligible_for_authority(
            &SpawnContext::ScheduledRoot
        ));
    }

    #[test]
    fn background_root_gets_no_availability() {
        let avail = media_availability_for_context(&SpawnContext::BackgroundRoot, true);
        assert!(!avail.is_available());
        assert!(!context_eligible_for_authority(
            &SpawnContext::BackgroundRoot
        ));
    }

    #[test]
    fn headless_root_gets_no_availability() {
        let avail = media_availability_for_context(&SpawnContext::HeadlessRoot, true);
        assert!(!avail.is_available());
        assert!(!context_eligible_for_authority(&SpawnContext::HeadlessRoot));
    }

    #[test]
    fn user_root_with_binding_gets_availability() {
        let avail = media_availability_for_context(&SpawnContext::UserRoot, true);
        assert!(avail.is_available());
        assert!(context_eligible_for_authority(&SpawnContext::UserRoot));
    }

    #[test]
    fn user_root_without_binding_gets_no_availability() {
        let avail = media_availability_for_context(&SpawnContext::UserRoot, false);
        assert!(!avail.is_available());
    }

    #[test]
    fn delegated_child_with_inherited_authority_gets_availability() {
        let avail = media_availability_for_context(
            &SpawnContext::DelegatedChild {
                inherited_valid_root_authority: true,
            },
            true,
        );
        assert!(avail.is_available());
        assert!(context_eligible_for_authority(
            &SpawnContext::DelegatedChild {
                inherited_valid_root_authority: true,
            }
        ));
    }

    #[test]
    fn delegated_child_without_inherited_authority_gets_none() {
        let avail = media_availability_for_context(
            &SpawnContext::DelegatedChild {
                inherited_valid_root_authority: false,
            },
            true,
        );
        assert!(!avail.is_available());
        assert!(!context_eligible_for_authority(
            &SpawnContext::DelegatedChild {
                inherited_valid_root_authority: false,
            }
        ));
    }

    #[test]
    fn delegated_child_with_inherited_authority_but_no_binding_gets_none() {
        let avail = media_availability_for_context(
            &SpawnContext::DelegatedChild {
                inherited_valid_root_authority: true,
            },
            false,
        );
        assert!(!avail.is_available());
    }

    // -- ControlStateChange --

    #[test]
    fn control_state_change_device_revocation_uses_remote_issuer() {
        let change = ControlStateChange::DeviceRevocation {
            device_uuid: [0xFF; 16],
            principal_digest: [0x11; 32],
            session_id: Uuid::from_bytes([0xCD; 16]),
            project_digest: [0x22; 32],
        };
        assert_eq!(change.issuer_kind(), IssuerKind::RemoteDevice);
        assert_eq!(change.principal_digest(), [0x11; 32]);
        assert_eq!(change.project_digest(), [0x22; 32]);
    }

    #[test]
    fn control_state_change_authority_transition_preserves_issuer() {
        let change = ControlStateChange::AuthorityStatusTransition {
            issuer_kind: IssuerKind::LocalOwner,
            principal_digest: [0x11; 32],
            session_id: Uuid::from_bytes([0xCD; 16]),
            project_digest: [0x22; 32],
        };
        assert_eq!(change.issuer_kind(), IssuerKind::LocalOwner);
    }

    #[test]
    fn control_state_change_local_membership_uses_local_issuer() {
        let change = ControlStateChange::LocalMembershipReadPathChange {
            principal_digest: [0x11; 32],
            session_id: Uuid::from_bytes([0xCD; 16]),
            project_digest: [0x22; 32],
        };
        assert_eq!(change.issuer_kind(), IssuerKind::LocalOwner);
    }

    #[tokio::test]
    async fn apply_control_state_change_increments_epoch() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Uuid::from_bytes([0xCD; 16]);
        let principal = [0x11; 32];
        let project = [0x22; 32];

        let change = ControlStateChange::AuthorityStatusTransition {
            issuer_kind: IssuerKind::LocalOwner,
            principal_digest: principal,
            session_id: session,
            project_digest: project,
        };

        // First increment → epoch 1.
        let epoch1 = db
            .transaction(move |conn| apply_control_state_change_conn(conn, change, 100))
            .await
            .unwrap();
        assert_eq!(epoch1, 1);

        // Second increment → epoch 2.
        let epoch2 = db
            .transaction(move |conn| apply_control_state_change_conn(conn, change, 200))
            .await
            .unwrap();
        assert_eq!(epoch2, 2);

        // Read back.
        let current = db
            .tool_media_authorization_epoch(1, principal, session, project)
            .await
            .unwrap();
        assert_eq!(current, Some(2));
    }

    #[tokio::test]
    async fn apply_control_state_change_device_revocation_increments_epoch() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Uuid::from_bytes([0xCD; 16]);
        let principal = [0x11; 32];
        let project = [0x22; 32];

        let change = ControlStateChange::DeviceRevocation {
            device_uuid: [0xFF; 16],
            principal_digest: principal,
            session_id: session,
            project_digest: project,
        };

        let epoch = db
            .transaction(move |conn| apply_control_state_change_conn(conn, change, 100))
            .await
            .unwrap();
        assert_eq!(epoch, 1);

        // Remote device issuer_kind is 2.
        let current = db
            .tool_media_authorization_epoch(2, principal, session, project)
            .await
            .unwrap();
        assert_eq!(current, Some(1));
    }

    #[tokio::test]
    async fn apply_control_state_change_local_membership_increments_epoch() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Uuid::from_bytes([0xCD; 16]);
        let principal = [0x11; 32];
        let project = [0x22; 32];

        let change = ControlStateChange::LocalMembershipReadPathChange {
            principal_digest: principal,
            session_id: session,
            project_digest: project,
        };

        let epoch = db
            .transaction(move |conn| apply_control_state_change_conn(conn, change, 100))
            .await
            .unwrap();
        assert_eq!(epoch, 1);

        // Local owner issuer_kind is 1.
        let current = db
            .tool_media_authorization_epoch(1, principal, session, project)
            .await
            .unwrap();
        assert_eq!(current, Some(1));
    }

    // -- Secure-key ref id helpers --

    #[test]
    fn binding_consumer_id_format() {
        let id = binding_consumer_id_from_parts("session-uuid", "0102030405060708090a0b0c0d0e0f10");
        assert_eq!(id, "session-uuid/0102030405060708090a0b0c0d0e0f10");
    }

    #[test]
    fn binding_key_reference_id_format() {
        let id = binding_key_reference_id_from_parts(
            "session-uuid",
            "0102030405060708090a0b0c0d0e0f10",
            3,
        );
        assert_eq!(
            id,
            "tool-media-subject-binding/session-uuid/0102030405060708090a0b0c0d0e0f10/3"
        );
    }

    // -- Full recovery + fold integration --

    #[tokio::test]
    async fn recover_session_bindings_full_round_trip() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/workspace", "Build")
            .await
            .unwrap();

        // Create a message submission receipt so the FK is satisfied.
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
                _: &rusqlite::Connection,
                _: &crate::db::message_attachments::AcceptMessageInput,
            ) -> anyhow::Result<()> {
                Ok(())
            }
        }
        db.accept_message_with_attachments(input, Arc::new(Allow))
            .await
            .unwrap();

        // Build a real sealed binding.
        let key = [0x42; 32];
        let session_bytes = *session.session_id.as_bytes();
        let submission = [5; 16];
        let locator = LocatorV1::local_owner();
        let project_uuid = [0xAB; 16];
        let project_digest = LocatorV1::project_digest(&project_uuid);
        let receipt = ToolMediaSubjectReceiptV1::new(
            IssuerKind::LocalOwner,
            &locator,
            project_digest,
            session_bytes,
            0,
        );
        let receipt_bytes = receipt.canonical_bytes();
        let sealed =
            seal::seal_locator(&key, &session_bytes, &submission, &receipt_bytes, &locator)
                .unwrap();

        let session_str = session.session_id.to_string();
        let submission_hex: String = submission.iter().map(|b| format!("{b:02x}")).collect();
        let ref_id = binding_key_reference_id_from_parts(&session_str, &submission_hex, 1);

        let insert = crate::db::tool_media_subject_bindings::ToolMediaSubjectBindingInsertV1 {
            session_id: session.session_id,
            client_submission_id: submission,
            receipt_version: 1,
            issuer_kind: 1,
            principal_digest: receipt.principal_digest,
            project_digest: receipt.project_digest,
            authorization_epoch: 0,
            subject_digest: receipt.subject_digest,
            seal_version: 1,
            key_namespace: "tool_media_subject_binding".to_string(),
            key_version: 1,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            secure_key_reference_id: ref_id,
            receipt_bytes: receipt_bytes.clone(),
            now_ms: 20,
        };

        db.transaction(move |conn| {
            crate::db::Db::insert_tool_media_subject_binding_conn(conn, &insert)
        })
        .await
        .unwrap();

        // Recover with a revalidator that has the right key and epoch.
        let revalidator = ToolMediaSubjectRevalidator::new(
            Arc::new(LocalOnlyProjection),
            Arc::new(FakeKeyResolver {
                key,
                available: true,
            }),
        );

        let recovered = recover_session_bindings(&db, session.session_id, &revalidator)
            .await
            .unwrap();

        assert_eq!(recovered.len(), 1);
        let subject = recovered.get(&submission).unwrap();
        assert_eq!(subject.receipt, receipt);
        assert_eq!(subject.issuer_kind, IssuerKind::LocalOwner);
        assert_eq!(subject.authorization_epoch, 0);
    }

    #[tokio::test]
    async fn recover_session_bindings_stale_epoch_fail_closed() {
        let db = crate::db::Db::open_in_memory().unwrap();
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
                _: &rusqlite::Connection,
                _: &crate::db::message_attachments::AcceptMessageInput,
            ) -> anyhow::Result<()> {
                Ok(())
            }
        }
        db.accept_message_with_attachments(input, Arc::new(Allow))
            .await
            .unwrap();

        // Build a binding at epoch 0.
        let key = [0x42; 32];
        let session_bytes = *session.session_id.as_bytes();
        let submission = [5; 16];
        let locator = LocatorV1::local_owner();
        let project_uuid = [0xAB; 16];
        let project_digest = LocatorV1::project_digest(&project_uuid);
        let receipt = ToolMediaSubjectReceiptV1::new(
            IssuerKind::LocalOwner,
            &locator,
            project_digest,
            session_bytes,
            0,
        );
        let receipt_bytes = receipt.canonical_bytes();
        let sealed =
            seal::seal_locator(&key, &session_bytes, &submission, &receipt_bytes, &locator)
                .unwrap();

        let session_str = session.session_id.to_string();
        let submission_hex: String = submission.iter().map(|b| format!("{b:02x}")).collect();
        let ref_id = binding_key_reference_id_from_parts(&session_str, &submission_hex, 1);

        let insert = crate::db::tool_media_subject_bindings::ToolMediaSubjectBindingInsertV1 {
            session_id: session.session_id,
            client_submission_id: submission,
            receipt_version: 1,
            issuer_kind: 1,
            principal_digest: receipt.principal_digest,
            project_digest: receipt.project_digest,
            authorization_epoch: 0,
            subject_digest: receipt.subject_digest,
            seal_version: 1,
            key_namespace: "tool_media_subject_binding".to_string(),
            key_version: 1,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            secure_key_reference_id: ref_id,
            receipt_bytes: receipt_bytes.clone(),
            now_ms: 20,
        };

        db.transaction(move |conn| {
            crate::db::Db::insert_tool_media_subject_binding_conn(conn, &insert)
        })
        .await
        .unwrap();

        // Advance the epoch to 1 — the binding at epoch 0 is now stale.
        let principal = receipt.principal_digest;
        let project = receipt.project_digest;
        let session_str = session.session_id.to_string();
        db.transaction(move |conn| {
            crate::db::Db::increment_tool_media_authorization_epoch_conn(
                conn,
                1,
                principal,
                &session_str,
                project,
                30,
            )
        })
        .await
        .unwrap();

        // Recover with a projection that returns epoch 1. The binding was
        // stored at epoch 0, so live revalidation must fail closed.
        let stale_revalidator = ToolMediaSubjectRevalidator::new(
            Arc::new(FakeProjection {
                device_active: true,
                authority_active: true,
                epoch: 1, // epoch advanced
            }),
            Arc::new(FakeKeyResolver {
                key,
                available: true,
            }),
        );

        let recovered = recover_session_bindings(&db, session.session_id, &stale_revalidator)
            .await
            .unwrap();

        // Stale epoch → no authority (fail closed).
        assert!(
            recovered.is_empty(),
            "stale epoch binding must produce no authority"
        );
    }
}
