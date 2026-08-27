//! `ToolMediaSubjectRevalidator` — live revalidation of persisted media
//! authority bindings.
//!
//! Injected only into daemon/session-worker production composition. It owns
//! live revocation, local Owner installation checks, session/project/read-path
//! checks, and the media authorization epoch at ingress and each tool call.
//!
//! A revoked/missing device, stale/expired/paused authority status, or
//! unavailable control projection is fail-closed with no authority.

use std::sync::Arc;

use super::receipt::{IssuerKind, ToolMediaSubjectReceiptV1};

/// The live revalidation outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevalidatedSubject {
    /// The canonical receipt that was validated.
    pub receipt: ToolMediaSubjectReceiptV1,
    /// The issuer kind confirmed by live revalidation.
    pub issuer_kind: IssuerKind,
    /// The principal digest confirmed by live revalidation.
    pub principal_digest: [u8; 32],
    /// The project digest confirmed by live revalidation.
    pub project_digest: [u8; 32],
    /// The session id (raw UUID 16 bytes network order).
    pub session_id: [u8; 16],
    /// The authorization epoch at the time of revalidation.
    pub authorization_epoch: u64,
}

/// Error from revalidation — always fail-closed (no authority).
#[derive(Debug, Clone, thiserror::Error)]
pub enum RevalidatorError {
    #[error("binding not found")]
    NotFound,
    #[error("receipt decode failed: {0}")]
    ReceiptDecode(String),
    #[error("seal unseal failed: {0}")]
    Unseal(String),
    #[error("missing or retired key version")]
    KeyUnavailable,
    #[error("stale authorization epoch (binding={binding}, current={current})")]
    StaleEpoch { binding: u64, current: u64 },
    #[error("device revoked or missing")]
    DeviceRevoked,
    #[error("authority status is stale, expired, or paused")]
    AuthorityStatusInvalid,
    #[error("control projection unavailable")]
    ControlProjectionUnavailable,
    #[error("owner installation unavailable")]
    OwnerInstallationUnavailable,
    #[error("session mismatch")]
    SessionMismatch,
    #[error("project mismatch")]
    ProjectMismatch,
    #[error("issuer mismatch")]
    IssuerMismatch,
    #[error("principal mismatch")]
    PrincipalMismatch,
    #[error("internal error: {0}")]
    Internal(String),
}

/// Live remote-status projection snapshot consumed by the revalidator.
///
/// This is the continuity dependency's verified FCRC projection. It carries
/// the minimal information needed for fail-closed revalidation. The actual
/// remote identity primitive lives in the `remote` feature; this trait is
/// authority-free so the local-only launch scope compiles without it.
pub trait RemoteStatusProjection: Send + Sync {
    /// Whether the device is currently verified and not revoked.
    fn device_active(&self, device_uuid: &[u8; 16]) -> Result<bool, RevalidatorError>;
    /// Current authority status for the principal. `Ok(true)` means active.
    fn authority_active(&self, principal_digest: &[u8; 32]) -> Result<bool, RevalidatorError>;
    /// The current authorization epoch for the key tuple.
    fn current_epoch(
        &self,
        issuer_kind: IssuerKind,
        principal_digest: &[u8; 32],
        session_id: &str,
        project_digest: &[u8; 32],
    ) -> Result<u64, RevalidatorError>;
}

/// A no-op projection for local-only launch scope.
///
/// Remote device revalidation is stubbed: `device_active` returns `Ok(false)`
/// (fail-closed for remote issuers) and `authority_active` returns `Ok(true)`
/// for local owners. The epoch is always 0 for local owners.
pub struct LocalOnlyProjection;

impl RemoteStatusProjection for LocalOnlyProjection {
    fn device_active(&self, _device_uuid: &[u8; 16]) -> Result<bool, RevalidatorError> {
        // Remote devices are not supported in local-only launch scope.
        Ok(false)
    }

    fn authority_active(&self, _principal_digest: &[u8; 32]) -> Result<bool, RevalidatorError> {
        // Local owner authority is always active in local-only scope.
        Ok(true)
    }

    fn current_epoch(
        &self,
        _issuer_kind: IssuerKind,
        _principal_digest: &[u8; 32],
        _session_id: &str,
        _project_digest: &[u8; 32],
    ) -> Result<u64, RevalidatorError> {
        Ok(0)
    }
}

/// The key material resolver — returns the raw 32-byte key for a given
/// `(namespace, version)` pair, or `None` if the key is retired/missing.
///
/// This is a synchronous trait because the revalidator runs in the daemon's
/// secure-key actor thread, not a Tokio worker.
pub trait SecureKeyResolver: Send + Sync {
    fn resolve_key(
        &self,
        namespace: &str,
        version: i64,
    ) -> Result<Option<[u8; 32]>, RevalidatorError>;
}

/// `ToolMediaSubjectRevalidator` — the server-private revalidator.
///
/// Production composition injects a real `RemoteStatusProjection` and
/// `SecureKeyResolver`. Tests inject fakes.
pub struct ToolMediaSubjectRevalidator {
    projection: Arc<dyn RemoteStatusProjection>,
    key_resolver: Arc<dyn SecureKeyResolver>,
}

impl std::fmt::Debug for ToolMediaSubjectRevalidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolMediaSubjectRevalidator")
            .finish_non_exhaustive()
    }
}

impl ToolMediaSubjectRevalidator {
    pub fn new(
        projection: Arc<dyn RemoteStatusProjection>,
        key_resolver: Arc<dyn SecureKeyResolver>,
    ) -> Self {
        Self {
            projection,
            key_resolver,
        }
    }

    /// Revalidate a persisted binding and return a fresh private subject.
    ///
    /// This is the single admission path. It:
    /// 1. Validates the receipt (canonical bytes, subject_digest).
    /// 2. Opens the seal through the referenced secure-key version.
    /// 3. Resolves live identity via the projection.
    /// 4. Validates digest/session/project/issuer/current epoch.
    /// 5. Mints a fresh private subject only on full success.
    ///
    /// Any failure returns `Err` — no Owner fallback, no existence oracle.
    pub fn revalidate(
        &self,
        receipt_bytes: &[u8],
        seal_nonce: &[u8; 24],
        seal_ciphertext: &[u8],
        key_namespace: &str,
        key_version: i64,
        client_submission_id: &[u8; 16],
    ) -> Result<RevalidatedSubject, RevalidatorError> {
        // 1. Decode and validate the receipt.
        let receipt = ToolMediaSubjectReceiptV1::decode(receipt_bytes)
            .map_err(|e| RevalidatorError::ReceiptDecode(e.to_string()))?;

        // 2. Resolve the key.
        let key_bytes = self
            .key_resolver
            .resolve_key(key_namespace, key_version)?
            .ok_or(RevalidatorError::KeyUnavailable)?;

        // 3. Unseal the locator.
        let sealed = super::seal::SealedLocator {
            nonce: *seal_nonce,
            ciphertext: seal_ciphertext.to_vec(),
        };
        let unsealed = super::seal::unseal_locator(
            &key_bytes,
            &receipt.session_id,
            client_submission_id,
            receipt_bytes,
            &sealed,
        )
        .map_err(|e| RevalidatorError::Unseal(e.to_string()))?;

        let locator = unsealed.locator();

        // 4. Validate the locator's principal_digest matches the receipt.
        let live_principal = locator.principal_digest();
        if live_principal != receipt.principal_digest {
            return Err(RevalidatorError::PrincipalMismatch);
        }

        // 5. Check live identity via the projection.
        let session_hex = hex::encode(receipt.session_id);

        match receipt.issuer_kind {
            IssuerKind::LocalOwner => {
                // Local owner must be active.
                if !self
                    .projection
                    .authority_active(&receipt.principal_digest)?
                {
                    return Err(RevalidatorError::AuthorityStatusInvalid);
                }
            }
            IssuerKind::RemoteDevice => {
                // Extract device UUID from the locator.
                let raw = locator.raw_bytes();
                if raw.len() != 25 || raw[0] != 2 {
                    return Err(RevalidatorError::Internal(
                        "remote locator malformed".into(),
                    ));
                }
                let device_uuid: [u8; 16] = raw[1..17]
                    .try_into()
                    .map_err(|_| RevalidatorError::Internal("device uuid".into()))?;
                if !self.projection.device_active(&device_uuid)? {
                    return Err(RevalidatorError::DeviceRevoked);
                }
                if !self
                    .projection
                    .authority_active(&receipt.principal_digest)?
                {
                    return Err(RevalidatorError::AuthorityStatusInvalid);
                }
            }
        }

        // 6. Validate current epoch.
        let current_epoch = self.projection.current_epoch(
            receipt.issuer_kind,
            &receipt.principal_digest,
            &session_hex,
            &receipt.project_digest,
        )?;
        if receipt.authorization_epoch != current_epoch {
            return Err(RevalidatorError::StaleEpoch {
                binding: receipt.authorization_epoch,
                current: current_epoch,
            });
        }

        // 7. Mint the fresh private subject.
        Ok(RevalidatedSubject {
            receipt,
            issuer_kind: receipt.issuer_kind,
            principal_digest: live_principal,
            project_digest: receipt.project_digest,
            session_id: receipt.session_id,
            authorization_epoch: current_epoch,
        })
    }
}

/// Minimal hex encoding (avoids pulling in a hex crate dependency just for
/// the session-id string used in epoch lookups).
pub(crate) mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::locator::LocatorV1;
    use super::super::receipt::ToolMediaSubjectReceiptV1;
    use super::super::seal;
    use super::*;
    use std::sync::Mutex;

    struct FakeKeyResolver {
        key: [u8; 32],
        available: bool,
    }

    impl SecureKeyResolver for FakeKeyResolver {
        fn resolve_key(
            &self,
            _namespace: &str,
            _version: i64,
        ) -> Result<Option<[u8; 32]>, RevalidatorError> {
            if self.available {
                Ok(Some(self.key))
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
        fn device_active(&self, _device_uuid: &[u8; 16]) -> Result<bool, RevalidatorError> {
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

    fn make_local_binding(key: &[u8; 32], epoch: u64) -> (Vec<u8>, [u8; 24], Vec<u8>, [u8; 16]) {
        let locator = LocatorV1::local_owner();
        let project_uuid = [0xAB; 16];
        let project_digest = LocatorV1::project_digest(&project_uuid);
        let session_id = [0xCD; 16];
        let client_submission_id = [0xEF; 16];
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
        (
            receipt_bytes,
            sealed.nonce,
            sealed.ciphertext,
            client_submission_id,
        )
    }

    #[test]
    fn revalidate_succeeds_local_owner() {
        let key = [0x42; 32];
        let (receipt_bytes, nonce, ciphertext, submission) = make_local_binding(&key, 0);

        let revalidator = ToolMediaSubjectRevalidator::new(
            Arc::new(FakeProjection {
                device_active: true,
                authority_active: true,
                epoch: 0,
            }),
            Arc::new(FakeKeyResolver {
                key,
                available: true,
            }),
        );

        let result = revalidator.revalidate(
            &receipt_bytes,
            &nonce,
            &ciphertext,
            "tool_media_subject_binding",
            1,
            &submission,
        );
        assert!(result.is_ok());
        let subject = result.unwrap();
        assert_eq!(subject.issuer_kind, IssuerKind::LocalOwner);
        assert_eq!(subject.authorization_epoch, 0);
    }

    #[test]
    fn revalidate_fails_stale_epoch() {
        let key = [0x42; 32];
        let (receipt_bytes, nonce, ciphertext, submission) = make_local_binding(&key, 0);

        let revalidator = ToolMediaSubjectRevalidator::new(
            Arc::new(FakeProjection {
                device_active: true,
                authority_active: true,
                epoch: 1, // epoch has advanced
            }),
            Arc::new(FakeKeyResolver {
                key,
                available: true,
            }),
        );

        let result = revalidator.revalidate(
            &receipt_bytes,
            &nonce,
            &ciphertext,
            "tool_media_subject_binding",
            1,
            &submission,
        );
        assert!(matches!(result, Err(RevalidatorError::StaleEpoch { .. })));
    }

    #[test]
    fn revalidate_fails_key_unavailable() {
        let key = [0x42; 32];
        let (receipt_bytes, nonce, ciphertext, submission) = make_local_binding(&key, 0);

        let revalidator = ToolMediaSubjectRevalidator::new(
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

        let result = revalidator.revalidate(
            &receipt_bytes,
            &nonce,
            &ciphertext,
            "tool_media_subject_binding",
            1,
            &submission,
        );
        assert!(matches!(result, Err(RevalidatorError::KeyUnavailable)));
    }

    #[test]
    fn revalidate_fails_authority_inactive() {
        let key = [0x42; 32];
        let (receipt_bytes, nonce, ciphertext, submission) = make_local_binding(&key, 0);

        let revalidator = ToolMediaSubjectRevalidator::new(
            Arc::new(FakeProjection {
                device_active: true,
                authority_active: false,
                epoch: 0,
            }),
            Arc::new(FakeKeyResolver {
                key,
                available: true,
            }),
        );

        let result = revalidator.revalidate(
            &receipt_bytes,
            &nonce,
            &ciphertext,
            "tool_media_subject_binding",
            1,
            &submission,
        );
        assert!(matches!(
            result,
            Err(RevalidatorError::AuthorityStatusInvalid)
        ));
    }

    #[test]
    fn revalidate_fails_tampered_receipt() {
        let key = [0x42; 32];
        let (mut receipt_bytes, nonce, ciphertext, submission) = make_local_binding(&key, 0);
        receipt_bytes[5] ^= 1; // tamper

        let revalidator = ToolMediaSubjectRevalidator::new(
            Arc::new(FakeProjection {
                device_active: true,
                authority_active: true,
                epoch: 0,
            }),
            Arc::new(FakeKeyResolver {
                key,
                available: true,
            }),
        );

        let result = revalidator.revalidate(
            &receipt_bytes,
            &nonce,
            &ciphertext,
            "tool_media_subject_binding",
            1,
            &submission,
        );
        assert!(result.is_err());
    }

    #[test]
    fn revalidate_fails_wrong_key() {
        let key = [0x42; 32];
        let (receipt_bytes, nonce, ciphertext, submission) = make_local_binding(&key, 0);

        let revalidator = ToolMediaSubjectRevalidator::new(
            Arc::new(FakeProjection {
                device_active: true,
                authority_active: true,
                epoch: 0,
            }),
            Arc::new(FakeKeyResolver {
                key: [0x43; 32], // wrong key
                available: true,
            }),
        );

        let result = revalidator.revalidate(
            &receipt_bytes,
            &nonce,
            &ciphertext,
            "tool_media_subject_binding",
            1,
            &submission,
        );
        assert!(matches!(result, Err(RevalidatorError::Unseal(_))));
    }
}
