//! Daemon/session-worker composition for private tool-media authority.
//!
//! The runtime is installed only after the secure-key actor is available. It
//! materializes an authority for one accepted user-root fold. Local paths are
//! opened beneath a held workspace directory and HTTPS is retained through
//! the existing private media-storage policy; consumers receive held/immutable
//! sources, never a model-controlled re-open authority.

use std::io::Read as _;
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

    async fn revalidator_for(
        &self,
        session: &crate::session::Session,
    ) -> Option<Arc<ToolMediaSubjectRevalidator>> {
        Some(Arc::new(ToolMediaSubjectRevalidator::new(
            Arc::new(LocalOwnerProjection::for_session(session).await.ok()?),
            Arc::new(ActorSecureKeyResolver::new(self.secure_key.clone())),
        )))
    }

    /// Mint the binding for a newly accepted user submission. This is shared
    /// by inline/media and oversized-text acceptance so neither path can write
    /// a durable accepted receipt without the same sealed subject and
    /// secure-key consumer lifecycle.
    pub(crate) async fn binding_for_acceptance(
        &self,
        session: &crate::session::Session,
        actor: crate::db::message_attachments::MessageActor,
        client_submission_id: Uuid,
        now_ms: i64,
    ) -> anyhow::Result<crate::db::tool_media_subject_bindings::ToolMediaSubjectBindingInsertV1>
    {
        build_binding_for_acceptance(
            session,
            &self.secure_key,
            actor,
            client_submission_id,
            now_ms,
        )
        .await
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
        let revalidator = self.revalidator_for(session).await?;
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
        let media_project_digest = Sha256::digest(session.project_root.to_str()?.as_bytes()).into();
        let project_root = session.project_root.clone();
        let (canonical_project_root, held_project_root) = tokio::task::spawn_blocking(move || {
            let canonical_project_root = std::fs::canonicalize(&project_root).ok()?;
            let held = cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::open_existing(
                &canonical_project_root,
            )
            .ok()?;
            Some((canonical_project_root, Arc::new(held)))
        })
        .await
        .ok()??;
        Some(Arc::new(
            SessionMediaAuthority::new(
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
                Arc::new(PersistedAttachmentResolver {
                    media_storage: self.media_storage.clone(),
                    session_id: session.id,
                    client_submission_ids: recovered
                        .iter()
                        .map(|binding| binding.client_submission_id)
                        .collect(),
                }),
                Arc::new(HeldLocalPathPolicy {
                    project_root: canonical_project_root,
                    held_project_root,
                }),
                Arc::new(MediaStorageRetainedHttpsPolicy {
                    media_storage: self.media_storage.clone(),
                }),
                session.message_media_authority(),
            )
            .with_durable_storage(Arc::clone(&self.media_storage), media_project_digest),
        ))

    }

    /// Rehydrate the one retained authority-bearing turn after a daemon
    /// restart before replaying its parked direct-native call. Terminal turns
    /// delete their bindings, so every remaining row must belong to the same
    /// byte-identical fold; `authority_for_fold` still revalidates all rows and
    /// fails closed on mixed/missing/stale contributors.
    pub(crate) async fn authority_for_retained_turn(
        &self,
        session: &crate::session::Session,
    ) -> Option<Arc<SessionMediaAuthority>> {
        let rows = session
            .db
            .load_tool_media_subject_bindings_for_materialized_session(session.id)
            .await
            .ok()?;
        let submissions = rows
            .iter()
            .map(|row| Uuid::from_bytes(row.client_submission_id))
            .collect::<Vec<_>>();
        self.authority_for_fold(session, &submissions).await
    }
}

/// Shared binding producer used by every accepted user-message lane. It does
/// not require source storage, so dispatch can use it before the worker runtime
/// is installed while oversized worker acceptance delegates through the same
/// function.
pub(crate) async fn build_binding_for_acceptance(
    session: &crate::session::Session,
    secure_key: &crate::secure_key::SecureKeyHandle,
    actor: crate::db::message_attachments::MessageActor,
    client_submission_id: Uuid,
    now_ms: i64,
) -> anyhow::Result<crate::db::tool_media_subject_bindings::ToolMediaSubjectBindingInsertV1> {
    use super::locator::LocatorV1;
    use super::receipt::{IssuerKind, ToolMediaSubjectReceiptV1};
    use super::seal::{SEAL_VERSION, seal_locator};

    let project_uuid = session
        .db
        .authoritative_project_uuid(&session.project_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("authoritative project UUID is unavailable"))?;
    let project_digest = super::project_digest_for_project_uuid(&project_uuid);
    let (issuer_kind, locator) = match actor {
        crate::db::message_attachments::MessageActor::LocalOwner => {
            (IssuerKind::LocalOwner, LocatorV1::local_owner())
        }
        crate::db::message_attachments::MessageActor::ExternalPrincipal { id, generation } => (
            IssuerKind::RemoteDevice,
            LocatorV1::remote_device(id, generation),
        ),
    };
    let (key_version, key_material) = secure_key
        .create_or_load(super::TOOL_MEDIA_SUBJECT_BINDING_NAMESPACE)
        .await?;
    let key_bytes: &[u8; 32] = key_material
        .as_ref()
        .try_into()
        .map_err(|_| anyhow::anyhow!("tool-media secure key has an invalid length"))?;
    let epoch = session
        .db
        .ensure_tool_media_authorization_epoch(
            i64::from(issuer_kind.as_u8()),
            locator.principal_digest(),
            session.id,
            project_digest,
            now_ms,
        )
        .await?;
    let authorization_epoch = u64::try_from(epoch)
        .map_err(|_| anyhow::anyhow!("tool-media authorization epoch is invalid"))?;
    let receipt = ToolMediaSubjectReceiptV1::new(
        issuer_kind,
        &locator,
        project_digest,
        *session.id.as_bytes(),
        authorization_epoch,
    );
    let receipt_bytes = receipt.canonical_bytes();
    let submission = *client_submission_id.as_bytes();
    let sealed = seal_locator(
        key_bytes,
        session.id.as_bytes(),
        &submission,
        &receipt_bytes,
        &locator,
    )?;
    let submission_hex = submission
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    Ok(
        crate::db::tool_media_subject_bindings::ToolMediaSubjectBindingInsertV1 {
            session_id: session.id,
            client_submission_id: submission,
            receipt_version: 1,
            issuer_kind: i64::from(issuer_kind.as_u8()),
            principal_digest: receipt.principal_digest,
            project_digest: receipt.project_digest,
            authorization_epoch: epoch,
            subject_digest: receipt.subject_digest,
            seal_version: i64::from(SEAL_VERSION),
            key_namespace: super::TOOL_MEDIA_SUBJECT_BINDING_NAMESPACE.to_owned(),
            key_version,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            secure_key_reference_id: super::binding_key_reference_id(
                &session.id.to_string(),
                &submission_hex,
                key_version,
            ),
            receipt_bytes,
            now_ms,
        },
    )
}

struct PersistedBindingLiveness {
    db: crate::db::Db,
    session_id: Uuid,
    client_submission_ids: Vec<[u8; 16]>,
    revalidator: Arc<ToolMediaSubjectRevalidator>,
}

impl SubjectLiveness for PersistedBindingLiveness {
    fn revalidate(&self) -> Result<RevalidatedSubject, AdmissionDenial> {
        run_off_tokio_worker(|| {
            let session_id = self.session_id.to_string();
            let mut shared: Option<RevalidatedSubject> = None;
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
        })
    }
}

/// Authority-owned attachment resolver. The accepted message references are
/// the capability inventory; media storage verifies their current durable
/// attachment projection without opening content on any denial.
struct PersistedAttachmentResolver {
    media_storage: Arc<crate::media_storage::MediaStorageRecovery>,
    session_id: Uuid,
    client_submission_ids: Vec<[u8; 16]>,
}

impl AttachmentResolver for PersistedAttachmentResolver {
    fn resolve(
        &self,
        session_id: &str,
        attachment_id: &[u8; 16],
        max_bytes: usize,
    ) -> Result<Option<AdmittedAttachment>, AdmissionDenial> {
        if session_id != self.session_id.to_string() {
            return Ok(None);
        }
        run_off_tokio_worker(|| {
            self.media_storage
                .resolve_tool_attachment_for_fold(
                    self.session_id,
                    &self.client_submission_ids,
                    *attachment_id,
                    max_bytes,
                )
                .map_err(|_| AdmissionDenial::AttachmentNotFound)
        })
    }

    fn open(
        &self,
        session_id: &str,
        attachment: &AdmittedAttachment,
    ) -> Result<Option<super::session_authority::AdmittedHandle>, AdmissionDenial> {
        if session_id != self.session_id.to_string() {
            return Ok(None);
        }
        let bytes = self
            .media_storage
            .resolve_tool_attachment_content_for_fold(
                self.session_id,
                &self.client_submission_ids,
                attachment,
            )
            .map_err(|_| AdmissionDenial::AttachmentNotFound)?;
        Ok(bytes.map(|content| {
            super::session_authority::AdmittedHandle::RetainedHttps(AdmittedRetainedSource {
                canonical_url: format!("attachment:{}", Uuid::from_bytes(attachment.attachment_id)),
                content,
                content_type: "application/octet-stream".to_owned(),
            })
        }))
    }
}

/// Dedicated OS thread for DB/FS work entered from the session-worker Tokio
/// task. Matches the secure-key resolver seam: a `spawn_blocking` closure
/// still has a runtime context installed, so the SQLite pool Condvar must not
/// wait on that worker.
fn run_off_tokio_worker<T, E, F>(work: F) -> Result<T, E>
where
    T: Send,
    E: Send + From<AdmissionDenial>,
    F: FnOnce() -> Result<T, E> + Send,
{
    std::thread::scope(|scope| {
        scope.spawn(work).join().map_err(|_| {
            E::from(AdmissionDenial::Internal(
                "tool-media admission thread panicked".into(),
            ))
        })
    })?
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
    ) -> Result<(std::fs::File, HandleEvidence), AdmissionDenial> {
        let (file, evidence, _) = self.open_authorized(path)?;
        Ok((file, evidence))
    }

    fn admit(
        &self,
        _session_id: &str,
        path: &str,
        max_bytes: usize,
    ) -> Result<super::session_authority::AdmittedLocalHandle, AdmissionDenial> {
        let (file, evidence, canonical_path) = self.open_authorized(path)?;
        let metadata = file
            .metadata()
            .map_err(|_| AdmissionDenial::LocalPathDenied)?;
        if metadata.len() > max_bytes as u64 {
            return Err(AdmissionDenial::LocalPathDenied);
        }
        let mut content = Vec::with_capacity(metadata.len() as usize);
        (&file)
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut content)
            .map_err(|_| AdmissionDenial::LocalPathDenied)?;
        if content.len() > max_bytes {
            return Err(AdmissionDenial::LocalPathDenied);
        }
        Ok(
            super::session_authority::AdmittedLocalHandle::from_held_bytes(
                canonical_path,
                evidence,
                content,
            ),
        )
    }
}

impl HeldLocalPathPolicy {
    fn open_authorized(
        &self,
        path: &str,
    ) -> Result<(std::fs::File, HandleEvidence, PathBuf), AdmissionDenial> {
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
        let lexical_path = self.project_root.join(path);
        let canonical_path =
            std::fs::canonicalize(&lexical_path).map_err(|_| AdmissionDenial::LocalPathDenied)?;
        // Exact means no symlink/reparse spelling is accepted. Canonicalize is
        // metadata-only admission; the held no-follow open happens only after
        // this check succeeds.
        if canonical_path != lexical_path || !canonical_path.starts_with(&self.project_root) {
            return Err(AdmissionDenial::LocalPathDenied);
        }
        // Bind the exact canonical spelling to stable identity through a
        // metadata-only lookup. This deliberately acquires no content-read
        // descriptor: the held, relative, no-follow capability below is the
        // only source open. Its identity must still match in case the name was
        // replaced between authorization and the held open.
        let authorized_identity = cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::regular_file_authorization_identity(&canonical_path)
            .map_err(|_| AdmissionDenial::LocalPathDenied)?;
        run_before_local_held_open_hook();
        let file = self
            .held_project_root
            .open_regular_file_relative(&components)
            .map_err(|_| AdmissionDenial::LocalPathDenied)?;
        let held_identity = cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::regular_file_identity(&file)
            .map_err(|_| AdmissionDenial::LocalPathDenied)?;
        if authorized_identity != held_identity {
            return Err(AdmissionDenial::HandleReplacement);
        }
        let metadata = file
            .metadata()
            .map_err(|_| AdmissionDenial::LocalPathDenied)?;
        if !metadata.is_file() {
            return Err(AdmissionDenial::LocalPathDenied);
        }
        let mut evidence = Sha256::new();
        evidence.update(b"tool-media-held-local-v1\0");
        evidence.update(self.held_project_root.identity().as_bytes());
        evidence.update(held_identity.as_bytes());
        evidence.update(path.as_bytes());
        evidence.update(metadata.len().to_be_bytes());
        Ok((
            file,
            HandleEvidence {
                metadata_fingerprint: evidence.finalize().into(),
            },
            canonical_path,
        ))
    }
}

#[cfg(test)]
thread_local! {
    static BEFORE_LOCAL_HELD_OPEN_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_before_local_held_open_hook() {
    if let Some(hook) = BEFORE_LOCAL_HELD_OPEN_HOOK.with(|slot| slot.borrow_mut().take()) {
        hook();
    }
}

#[cfg(not(test))]
fn run_before_local_held_open_hook() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn local_authorization_rejects_replacement_between_metadata_and_held_open() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(workspace.path().join("source.bin"), b"authorized").unwrap();
        std::fs::write(workspace.path().join("replacement.bin"), b"replacement").unwrap();
        let project_root = std::fs::canonicalize(workspace.path()).unwrap();
        let policy = HeldLocalPathPolicy {
            project_root: project_root.clone(),
            held_project_root: Arc::new(
                cockpit_host::private_fs::held_directory::HeldWorkspaceDirectoryAuthority::open_existing(
                    &project_root,
                )
                .unwrap(),
            ),
        };
        let source = project_root.join("source.bin");
        let displaced = project_root.join("displaced.bin");
        let replacement = project_root.join("replacement.bin");
        BEFORE_LOCAL_HELD_OPEN_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(&source, displaced).unwrap();
                std::fs::rename(replacement, source).unwrap();
            }));
        });

        let denial = policy.admit("unused", "source.bin", 1024).unwrap_err();
        assert!(matches!(denial, AdmissionDenial::HandleReplacement));
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
        max_bytes: usize,
    ) -> Result<AdmittedRetainedSource, AdmissionDenial> {
        crate::media_https::preflight_retained_https_url(url)
            .map_err(|_| AdmissionDenial::HttpsDenied)?;
        // Fetch-layer denials (hostname DNS/SSRF, redirect, timeout,
        // non-success) are decided inside `retain_https_source_for_tool`
        // against an in-memory sink before any private reservation.
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
                        .block_on(media_storage.retain_https_source_for_tool(&url, max_bytes))
                        .map_err(|_| AdmissionDenial::HttpsDenied)
                })
                .join()
                .map_err(|_| {
                    AdmissionDenial::Internal("retained HTTPS authority thread panicked".into())
                })
        })??;
        if result.len() > max_bytes {
            return Err(AdmissionDenial::HttpsDenied);
        }
        Ok(AdmittedRetainedSource {
            canonical_url,
            content: result,
            content_type: "application/octet-stream".to_owned(),
        })
    }
}
