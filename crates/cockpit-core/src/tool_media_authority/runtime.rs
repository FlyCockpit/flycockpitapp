//! Daemon/session-worker composition for private tool-media authority.
//!
//! The runtime is installed only after the secure-key actor is available. It
//! materializes an authority for one accepted user-root fold. Local paths are
//! opened beneath a held workspace directory and HTTPS is retained through
//! the existing private media-storage policy; consumers receive held/immutable
//! sources, never a model-controlled re-open authority.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::SessionMediaAuthority;
use super::recovery::{RecoveredBinding, receipt_from_binding_row};
use super::revalidator::{
    ActorSecureKeyResolver, LocalOwnerProjection, RevalidatedSubject, ToolMediaSubjectRevalidator,
};
use super::session_authority::{
    AdmissionDenial, AdmittedAttachment, AdmittedRetainedSource, AttachmentResolver,
    HandleEvidence, LocalPathPolicy, RetainedHttpsPolicy, SubjectLiveness,
};

/// Production runtime installed by the daemon after the secure-key actor has
/// started. It has no remote fallback: local-owner projection is explicit and
/// remote receipts are denied until a persisted remote control projection is
/// supplied by the remote transport owner.
pub(crate) struct ToolMediaRuntime {
    secure_key: crate::secure_key::SecureKeyHandle,
    media_storage: Arc<crate::media_storage::MediaStorageRecovery>,
}

impl ToolMediaRuntime {
    pub(crate) fn new(
        secure_key: crate::secure_key::SecureKeyHandle,
        media_storage: Arc<crate::media_storage::MediaStorageRecovery>,
    ) -> Self {
        Self {
            secure_key,
            media_storage,
        }
    }

    fn revalidator_for(
        &self,
        session: &crate::session::Session,
    ) -> Option<Arc<ToolMediaSubjectRevalidator>> {
        Some(Arc::new(ToolMediaSubjectRevalidator::new(
            Arc::new(LocalOwnerProjection::for_session(session).ok()?),
            Arc::new(ActorSecureKeyResolver::new(self.secure_key.clone())),
        )))
    }

    /// Materialize a root authority for exactly one folded user submission.
    /// Every contributor must have a binding and all live receipts must match;
    /// otherwise `None` is a deliberate fail-closed outcome.
    pub(crate) async fn authority_for_fold(
        &self,
        session: &crate::session::Session,
        submissions: &[Uuid],
    ) -> Option<Arc<SessionMediaAuthority>> {
        if submissions.is_empty() {
            return None;
        }
        let revalidator = self.revalidator_for(session)?;
        let mut recovered = Vec::with_capacity(submissions.len());
        for submission in submissions {
            let row = session
                .db
                .load_tool_media_subject_binding(session.id, *submission.as_bytes())
                .await
                .ok()??;
            let receipt = receipt_from_binding_row(&row).ok()?;
            let receipt_bytes = receipt.canonical_bytes();
            // Secure-key resolution is actor-thread blocking by design. Keep
            // it off the session worker's Tokio task; a join failure becomes
            // an ordinary fail-closed revalidation error.
            let revalidator_for_call = revalidator.clone();
            let nonce = row.nonce;
            let ciphertext = row.ciphertext.clone();
            let key_namespace = row.key_namespace.clone();
            let key_version = row.key_version;
            let client_submission_id = row.client_submission_id;
            let result = tokio::task::spawn_blocking(move || {
                revalidator_for_call.revalidate(
                    &receipt_bytes,
                    &nonce,
                    &ciphertext,
                    &key_namespace,
                    key_version,
                    &client_submission_id,
                )
            })
            .await
            .unwrap_or_else(|error| {
                Err(super::revalidator::RevalidatorError::Internal(
                    error.to_string(),
                ))
            });
            recovered.push(RecoveredBinding {
                client_submission_id: row.client_submission_id,
                result,
            });
        }
        let subject = super::derive_folded_root_subject(&recovered)?;
        let canonical_project_root = std::fs::canonicalize(&session.project_root).ok()?;
        let held_project_root = Arc::new(
            cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::open_existing(
                &canonical_project_root,
            )
            .ok()?,
        );
        Some(Arc::new(SessionMediaAuthority::new(
            subject,
            Arc::new(PersistedBindingLiveness {
                db: session.db.clone(),
                session_id: session.id,
                // A root fold is authorized only while every contributor is
                // still live.  Do not collapse this to the last row: a
                // revoked, deleted, or resealed earlier submission must deny
                // the entire fold before source admission.
                client_submission_ids: recovered
                    .iter()
                    .map(|binding| binding.client_submission_id)
                    .collect(),
                revalidator,
            }),
            Arc::new(UnwiredAttachmentResolver),
            Arc::new(HeldLocalPathPolicy {
                project_root: canonical_project_root,
                held_project_root,
            }),
            Arc::new(MediaStorageRetainedHttpsPolicy {
                media_storage: self.media_storage.clone(),
            }),
        )))
    }
}

struct PersistedBindingLiveness {
    db: crate::db::Db,
    session_id: Uuid,
    client_submission_ids: Vec<[u8; 16]>,
    revalidator: Arc<ToolMediaSubjectRevalidator>,
}

impl SubjectLiveness for PersistedBindingLiveness {
    fn revalidate(&self) -> Result<RevalidatedSubject, AdmissionDenial> {
        let session_id = self.session_id.to_string();
        let mut shared = None;
        for client_submission_id in &self.client_submission_ids {
            let row = self
                .db
                .blocking_read_for_sync_ui(|conn| {
                    crate::db::Db::load_tool_media_subject_binding_conn(
                        conn,
                        &session_id,
                        client_submission_id,
                    )
                })
                .map_err(|error| AdmissionDenial::Internal(error.to_string()))?
                .ok_or(AdmissionDenial::SubjectMismatch)?;
            let receipt = receipt_from_binding_row(&row)
                .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
            let live = self
                .revalidator
                .revalidate(
                    &receipt.canonical_bytes(),
                    &row.nonce,
                    &row.ciphertext,
                    &row.key_namespace,
                    row.key_version,
                    &row.client_submission_id,
                )
                .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
            match &shared {
                Some(expected)
                    if expected.receipt.canonical_bytes() != live.receipt.canonical_bytes() =>
                {
                    return Err(AdmissionDenial::SubjectMismatch);
                }
                Some(_) => {}
                None => shared = Some(live),
            }
        }
        shared.ok_or(AdmissionDenial::SubjectMismatch)
    }
}

// Session attachments are not a path/URL source and remain unavailable until
// their consumer contract is separately installed.
struct UnwiredAttachmentResolver;
impl AttachmentResolver for UnwiredAttachmentResolver {
    fn resolve(
        &self,
        _session_id: &str,
        _attachment_id: &[u8; 16],
    ) -> Result<Option<AdmittedAttachment>, AdmissionDenial> {
        Ok(None)
    }
}

/// Local project source policy. It resolves only relative lexical components
/// beneath a held workspace directory; no model spelling is ever reopened.
struct HeldLocalPathPolicy {
    project_root: PathBuf,
    held_project_root:
        Arc<cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority>,
}

impl LocalPathPolicy for HeldLocalPathPolicy {
    fn authorize(
        &self,
        _session_id: &str,
        path: &str,
    ) -> Result<(PathBuf, Arc<std::fs::File>, HandleEvidence), AdmissionDenial> {
        let components = Path::new(path)
            .components()
            .map(|component| match component {
                Component::Normal(component) => {
                    component.to_str().ok_or(AdmissionDenial::LocalPathDenied)
                }
                _ => Err(AdmissionDenial::LocalPathDenied),
            })
            .collect::<Result<Vec<_>, _>>()?;
        if components.is_empty() {
            return Err(AdmissionDenial::LocalPathDenied);
        }
        let file = self
            .held_project_root
            .open_regular_file_relative(&components)
            .map_err(|_| AdmissionDenial::LocalPathDenied)?;
        let metadata = file
            .metadata()
            .map_err(|_| AdmissionDenial::LocalPathDenied)?;
        if !metadata.is_file() {
            return Err(AdmissionDenial::LocalPathDenied);
        }
        let mut evidence = Sha256::new();
        evidence.update(b"tool-media-held-local-v1\0");
        evidence.update(self.held_project_root.identity().as_bytes());
        evidence.update(path.as_bytes());
        evidence.update(metadata.len().to_be_bytes());
        Ok((
            self.project_root.join(path),
            Arc::new(file),
            HandleEvidence {
                metadata_fingerprint: evidence.finalize().into(),
            },
        ))
    }
}

/// Existing held-storage + SSRF/DNS/redirect retained-HTTPS policy, exposed
/// through the private direct-native authority only.
struct MediaStorageRetainedHttpsPolicy {
    media_storage: Arc<crate::media_storage::MediaStorageRecovery>,
}

impl RetainedHttpsPolicy for MediaStorageRetainedHttpsPolicy {
    fn admit(
        &self,
        _session_id: &str,
        url: &str,
    ) -> Result<AdmittedRetainedSource, AdmissionDenial> {
        let media_storage = self.media_storage.clone();
        let url = url.to_owned();
        let canonical_url = url.clone();
        let result = std::thread::scope(|scope| {
            scope
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
                    runtime
                        .block_on(media_storage.retain_https_source_for_tool(&url))
                        .map_err(|_| AdmissionDenial::HttpsDenied)
                })
                .join()
                .map_err(|_| {
                    AdmissionDenial::Internal("retained HTTPS authority thread panicked".into())
                })
        })??;
        Ok(AdmittedRetainedSource {
            canonical_url,
            content: result,
            content_type: "application/octet-stream".to_owned(),
        })
    }
}
