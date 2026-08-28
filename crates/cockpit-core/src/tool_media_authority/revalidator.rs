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

use rusqlite::OptionalExtension;

use super::receipt::{IssuerKind, ToolMediaSubjectReceiptV1};
use crate::secure_key::SecureKeyBytes;

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
    fn device_active(
        &self,
        device_uuid: &[u8; 16],
        generation: u64,
    ) -> Result<bool, RevalidatorError>;
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

/// Persisted local-owner projection used by daemon/session-worker production
/// composition. Remote control state deliberately has no local fallback: a
/// remote receipt returns `ControlProjectionUnavailable` until the verified
/// remote continuity projection is installed.
pub(crate) struct LocalOwnerProjection {
    db: crate::db::Db,
    session_id: String,
    project_id: String,
    project_uuid: [u8; 16],
    project_root: std::path::PathBuf,
    canonical_project_root: std::path::PathBuf,
    /// Opened once for this authority and compared on every use. The host
    /// primitive pins stable platform identity (Unix device/inode; Windows
    /// volume/file index), so a directory replacement or symlink retarget is
    /// not mistaken for the same project just because its spelling matches.
    project_root_identity: String,
    owner_principal_digest: [u8; 32],
}

impl LocalOwnerProjection {
    pub(crate) fn for_session(session: &crate::session::Session) -> Result<Self, RevalidatorError> {
        let project_id = session.project_id.clone();
        let project_uuid = session
            .db
            .blocking_read_for_sync_ui({
                let project_id = project_id.clone();
                move |conn| crate::db::Db::authoritative_project_uuid_conn(conn, &project_id)
            })
            .map_err(|_| RevalidatorError::ProjectMismatch)?
            .ok_or(RevalidatorError::ProjectMismatch)?;
        let canonical_project_root = std::fs::canonicalize(&session.project_root)
            .map_err(|_| RevalidatorError::ProjectMismatch)?;
        let held = cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::open_existing(
            &canonical_project_root,
        )
        .map_err(|_| RevalidatorError::ProjectMismatch)?;
        Ok(Self {
            db: session.db.clone(),
            session_id: session.id.to_string(),
            project_id,
            project_uuid,
            project_root: session.project_root.clone(),
            canonical_project_root,
            project_root_identity: held.identity().to_owned(),
            owner_principal_digest: super::locator::LocatorV1::local_owner().principal_digest(),
        })
    }

    fn local_owner_installation_active(
        &self,
        principal_digest: &[u8; 32],
    ) -> Result<bool, RevalidatorError> {
        if principal_digest != &self.owner_principal_digest {
            return Ok(false);
        }
        self.db
            .blocking_read_for_sync_ui(|conn| {
                Ok(
                    crate::db::installation_identity::load_installation_identity_conn(conn)?
                        .is_some(),
                )
            })
            .map_err(|_error| RevalidatorError::OwnerInstallationUnavailable)
    }

    /// A replaced/repointed project root is authoritative local control-state
    /// change, not merely a failed read. Advance the same durable epoch used
    /// by receipt validation so every binding for this root is invalidated in
    /// one transaction. The caller still denies if the increment itself
    /// fails; there is no best-effort continuation.
    fn invalidate_replaced_project_root(
        &self,
        principal_digest: &[u8; 32],
        session_id: &str,
        project_digest: &[u8; 32],
    ) -> Result<(), RevalidatorError> {
        let session_id = session_id.to_owned();
        let principal_digest = *principal_digest;
        let project_digest = *project_digest;
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                crate::db::Db::increment_tool_media_authorization_epoch_conn(
                    conn,
                    i64::from(IssuerKind::LocalOwner.as_u8()),
                    principal_digest,
                    &session_id,
                    project_digest,
                    chrono::Utc::now().timestamp_millis(),
                )?;
                Ok(())
            })
            .map_err(|error| RevalidatorError::Internal(error.to_string()))
    }
}

impl RemoteStatusProjection for LocalOwnerProjection {
    fn device_active(
        &self,
        _device_uuid: &[u8; 16],
        _generation: u64,
    ) -> Result<bool, RevalidatorError> {
        // There is no persisted verified remote control projection in this
        // daemon launch scope. Returning an error, rather than false, keeps
        // the missing dependency observable and fail-closed.
        Err(RevalidatorError::ControlProjectionUnavailable)
    }

    fn authority_active(&self, principal_digest: &[u8; 32]) -> Result<bool, RevalidatorError> {
        self.local_owner_installation_active(principal_digest)
    }

    fn current_epoch(
        &self,
        issuer_kind: IssuerKind,
        principal_digest: &[u8; 32],
        session_id: &str,
        project_digest: &[u8; 32],
    ) -> Result<u64, RevalidatorError> {
        if issuer_kind != IssuerKind::LocalOwner || session_id != self.session_id {
            return Err(RevalidatorError::SessionMismatch);
        }
        if principal_digest != &self.owner_principal_digest {
            return Err(RevalidatorError::PrincipalMismatch);
        }
        let expected_project_digest = super::project_digest_for_project_uuid(&self.project_uuid);
        if project_digest != &expected_project_digest {
            return Err(RevalidatorError::ProjectMismatch);
        }
        // A vanished or replaced project root invalidates local-owner media
        // before any attachment/path policy receives a source spelling.
        let canonical_root = match std::fs::canonicalize(&self.project_root) {
            Ok(root) => root,
            Err(_) => {
                self.invalidate_replaced_project_root(
                    principal_digest,
                    session_id,
                    project_digest,
                )?;
                return Err(RevalidatorError::ProjectMismatch);
            }
        };
        if canonical_root != self.canonical_project_root || !canonical_root.is_dir() {
            self.invalidate_replaced_project_root(principal_digest, session_id, project_digest)?;
            return Err(RevalidatorError::ProjectMismatch);
        }
        let current_root = cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::open_existing(
            &canonical_root,
        )
        .map_err(|_| RevalidatorError::ProjectMismatch)?;
        if current_root.identity() != self.project_root_identity {
            self.invalidate_replaced_project_root(principal_digest, session_id, project_digest)?;
            return Err(RevalidatorError::ProjectMismatch);
        }
        let expected_project_root = self.project_root.to_string_lossy().into_owned();
        self.db
            .blocking_read_for_sync_ui(|conn| {
                let row: Option<(String, String, Option<i64>)> = conn
                    .query_row(
                        "SELECT project_id, project_root, ended_at_unix_ms FROM sessions WHERE session_id = ?1",
                        rusqlite::params![session_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?;
                let Some((stored_project_id, stored_project_root, ended_at)) = row else {
                    return Err(anyhow::anyhow!("session missing"));
                };
                if stored_project_id != self.project_id
                    || stored_project_root != expected_project_root
                    || ended_at.is_some()
                {
                    return Err(anyhow::anyhow!("session/project no longer live"));
                }
                let epoch: Option<i64> = conn
                    .query_row(
                        "SELECT epoch FROM tool_media_authorization_epochs
                         WHERE issuer_kind = ?1 AND principal_digest = ?2
                           AND session_id = ?3 AND project_digest = ?4",
                        rusqlite::params![
                            i64::from(IssuerKind::LocalOwner.as_u8()),
                            principal_digest.as_slice(),
                            session_id,
                            project_digest.as_slice(),
                        ],
                        |row| row.get(0),
                    )
                    .optional()?;
                epoch.ok_or_else(|| anyhow::anyhow!("authorization epoch missing"))
            })
            .map_err(|_| RevalidatorError::ControlProjectionUnavailable)
            .and_then(|epoch| {
                u64::try_from(epoch)
                    .map_err(|_| RevalidatorError::ControlProjectionUnavailable)
            })
    }
}

/// Production secure-key resolver. It talks only to the daemon-owned actor;
/// no database or OS key-store fallback is permitted.
pub(crate) struct ActorSecureKeyResolver {
    secure_key: crate::secure_key::SecureKeyHandle,
}

impl ActorSecureKeyResolver {
    pub(crate) fn new(secure_key: crate::secure_key::SecureKeyHandle) -> Self {
        Self { secure_key }
    }
}

impl SecureKeyResolver for ActorSecureKeyResolver {
    fn resolve_key(
        &self,
        namespace: &str,
        version: i64,
    ) -> Result<Option<SecureKeyBytes>, RevalidatorError> {
        // `blocking_recv` must never run on a Tokio task, including a
        // `spawn_blocking` closure whose runtime context remains installed.
        // The key actor itself is an independent OS thread, so a short-lived
        // plain thread is a sound blocking seam: it cannot deadlock a Tokio
        // worker and an actor failure is propagated as a denial.
        let secure_key = self.secure_key.clone();
        let namespace = namespace.to_owned();
        let result = std::thread::scope(|scope| {
            scope
                .spawn(move || secure_key.load_version_blocking(&namespace, version))
                .join()
                .map_err(|_| {
                    RevalidatorError::Internal("secure-key resolution thread panicked".into())
                })
        })?;
        match result {
            Ok((_version, bytes)) => Ok(Some(bytes)),
            Err(crate::secure_key::SecureKeyError::NotFound(_)) => Ok(None),
            Err(error) => Err(RevalidatorError::Internal(error.to_string())),
        }
    }
}

/// Test-only projection. Production must inject the persisted installation,
/// authorization, and epoch projection; there is deliberately no Owner
/// fallback implementation.
#[cfg(test)]
pub struct LocalOnlyProjection;

#[cfg(test)]
impl RemoteStatusProjection for LocalOnlyProjection {
    fn device_active(
        &self,
        _device_uuid: &[u8; 16],
        _generation: u64,
    ) -> Result<bool, RevalidatorError> {
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

/// The key material resolver — returns zeroizing 32-byte key material for a
/// given `(namespace, version)`, or `None` if the key is retired/missing.
///
/// This remains synchronous because the revalidator's production resolver
/// crosses a dedicated non-Tokio blocking seam to the daemon-owned key actor.
pub trait SecureKeyResolver: Send + Sync {
    fn resolve_key(
        &self,
        namespace: &str,
        version: i64,
    ) -> Result<Option<SecureKeyBytes>, RevalidatorError>;
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
    pub(crate) fn new(
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
            key_bytes.as_array(),
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
        let session_id = uuid::Uuid::from_bytes(receipt.session_id).to_string();

        match receipt.issuer_kind {
            IssuerKind::LocalOwner => {
                if !locator.is_local_owner() {
                    return Err(RevalidatorError::IssuerMismatch);
                }
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
                let generation = u64::from_be_bytes(
                    raw[17..25]
                        .try_into()
                        .map_err(|_| RevalidatorError::Internal("device generation".into()))?,
                );
                if !self.projection.device_active(&device_uuid, generation)? {
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
            &session_id,
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
        ) -> Result<Option<SecureKeyBytes>, RevalidatorError> {
            if self.available {
                Ok(Some(SecureKeyBytes::from_array(self.key)))
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
