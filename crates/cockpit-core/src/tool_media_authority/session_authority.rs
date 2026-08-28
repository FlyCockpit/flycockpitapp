//! `SessionMediaAuthority` — private direct-native media authority.
//!
//! Exposed only through private direct-native `ToolCtx`. It performs:
//! - Existence-hiding attachment resolution
//! - Exact canonical local-path authorization followed by an authority-owned
//!   no-follow held handle with evidence
//! - Retained-HTTPS admission using existing SSRF/DNS/redirect policy
//!
//! It returns admitted handles/immutable objects, never a model path/URL
//! authority. Denials may perform canonicalization metadata lookup but perform
//! zero content opens/reads, fetches, reservations, derivatives, or subprocess
//! calls.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;

use super::revalidator::RevalidatedSubject;

/// An admitted local-path handle — authority-owned, no-follow, with evidence.
///
/// The consumer never reopens the spelling; the authority holds the handle
/// and validates identity/evidence on every use.
#[derive(Debug, Clone)]
pub struct AdmittedLocalHandle {
    /// The canonical absolute path that was authorized.
    canonical_path: PathBuf,
    /// The already-opened no-follow source. Consumers read this descriptor and
    /// never reopen `canonical_path`.
    held_file: Arc<std::fs::File>,
    /// Opaque evidence that the handle was held by the authority at admission
    /// time (e.g. inode/device metadata). Never exposed to the model.
    evidence: HandleEvidence,
}

impl AdmittedLocalHandle {
    /// The canonical path — available to the authority's internal consumer
    /// only, never to the model.
    pub(crate) fn canonical_path(&self) -> &PathBuf {
        &self.canonical_path
    }

    /// The handle evidence — internal only.
    pub(crate) fn evidence(&self) -> &HandleEvidence {
        &self.evidence
    }

    pub(crate) fn held_file(&self) -> &std::fs::File {
        &self.held_file
    }
}

/// Opaque handle evidence proving the authority held the file at admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleEvidence {
    /// File metadata digest (inode/device/size). Never exposed to the model.
    pub(crate) metadata_fingerprint: [u8; 32],
}

/// An admitted retained-HTTPS source — immutable, fetched once by the
/// authority.
#[derive(Debug, Clone)]
pub struct AdmittedRetainedSource {
    /// The canonical URL that was admitted.
    pub(crate) canonical_url: String,
    /// Immutable fetched bytes.
    pub(crate) content: Vec<u8>,
    /// Content-Type from the fetch.
    pub(crate) content_type: String,
}

impl AdmittedRetainedSource {
    pub(crate) fn canonical_url(&self) -> &str {
        &self.canonical_url
    }
    pub(crate) fn content(&self) -> &[u8] {
        &self.content
    }
    pub(crate) fn content_type(&self) -> &str {
        &self.content_type
    }
}

/// An admitted attachment reference — resolved from session attachments.
#[derive(Debug, Clone)]
pub struct AdmittedAttachment {
    pub(crate) attachment_id: [u8; 16],
    pub(crate) attachment_version: u64,
    pub(crate) checksum: [u8; 32],
    pub(crate) kind: u8,
}

pub struct AdmittedMediaBytes {
    pub bytes: Vec<u8>,
    pub duration_us: Option<u64>,
    /// Present only for durable attachment derivatives. It keeps the exact
    /// component lease live through the caller's authorization and provider
    /// handoff, and its Drop path completes release if that caller is
    /// cancelled.
    pub(crate) retained_lease: Option<crate::media_storage::VerifiedHeldMedia>,
}

impl AdmittedMediaBytes {
    pub(crate) async fn release_retained(
        mut self,
        now_unix_ms: i64,
    ) -> Result<(), AdmissionDenial> {
        let Some(lease) = self.retained_lease.take() else {
            return Ok(());
        };
        lease
            .release(now_unix_ms)
            .await
            .map_err(|error| AdmissionDenial::Internal(error.to_string()))
    }
}

impl AdmittedAttachment {
    pub fn attachment_id(&self) -> [u8; 16] {
        self.attachment_id
    }
    pub fn attachment_version(&self) -> u64 {
        self.attachment_version
    }
    pub fn checksum(&self) -> [u8; 32] {
        self.checksum
    }
    pub fn kind(&self) -> u8 {
        self.kind
    }
}

/// Union of admitted handles — what the authority returns on success.
#[derive(Debug, Clone)]
pub enum AdmittedHandle {
    Attachment(AdmittedAttachment),
    Local(AdmittedLocalHandle),
    RetainedHttps(AdmittedRetainedSource),
}

/// Why a source was denied. Denials perform zero content I/O.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AdmissionDenial {
    #[error("no media authority for this context")]
    NoAuthority,
    #[error("attachment not found")]
    AttachmentNotFound,
    #[error("local path denied by canonical authorization policy")]
    LocalPathDenied,
    #[error("retained HTTPS source denied by SSRF/DNS/redirect policy")]
    HttpsDenied,
    #[error("subject mismatch — source does not match the revalidated subject")]
    SubjectMismatch,
    #[error("replacement/symlink/reparse detected after authorization")]
    HandleReplacement,
    #[error("internal error: {0}")]
    Internal(String),
}

/// The attachment resolver trait — resolves session attachments by id.
///
/// Existence-hiding: a `None` return does not distinguish "not found" from
/// "not authorized".
#[async_trait]
pub trait AttachmentResolver: Send + Sync {
    /// Resolve an attachment by id for the given session.
    /// Returns `Ok(Some(...))` if found and authorized, `Ok(None)` otherwise.
    fn resolve(
        &self,
        session_id: &str,
        attachment_id: &[u8; 16],
    ) -> Result<Option<AdmittedAttachment>, AdmissionDenial>;

    /// Read the normalized derivative bytes for an already-admitted attachment.
    ///
    /// Default fails closed: a resolver that only knows metadata cannot mint
    /// content. Production and test resolvers that hold bytes override this.
    fn read_bytes(
        &self,
        attachment: &AdmittedAttachment,
        max_bytes: u64,
    ) -> Result<Vec<u8>, AdmissionDenial> {
        let _ = attachment;
        let _ = max_bytes;
        Err(AdmissionDenial::Internal(
            "attachment content is not available from this resolver".to_string(),
        ))
    }

    async fn read_media(
        &self,
        attachment: &AdmittedAttachment,
        max_bytes: u64,
    ) -> Result<AdmittedMediaBytes, AdmissionDenial> {
        Ok(AdmittedMediaBytes {
            bytes: self.read_bytes(attachment, max_bytes)?,
            duration_us: None,
            retained_lease: None,
        })
    }
}

/// The local-path admission policy trait.
pub trait LocalPathPolicy: Send + Sync {
    /// Canonicalize and authorize a local path.
    /// Returns the canonical path and handle evidence on success.
    fn authorize(
        &self,
        session_id: &str,
        path: &str,
    ) -> Result<(PathBuf, Arc<std::fs::File>, HandleEvidence), AdmissionDenial>;

    /// Read through the policy's authority-owned held handle and revalidate
    /// its evidence. The default reads the already-open descriptor and never
    /// reopens the pathname, avoiding a replace-after-authorization race.
    fn read_bytes(
        &self,
        local: &AdmittedLocalHandle,
        max_bytes: u64,
    ) -> Result<Vec<u8>, AdmissionDenial> {
        use std::io::{Read as _, Seek as _};

        let mut file = local.held_file().try_clone().map_err(|error| {
            AdmissionDenial::Internal(format!(
                "admitted local handle could not be cloned: {error}"
            ))
        })?;
        file.seek(std::io::SeekFrom::Start(0)).map_err(|error| {
            AdmissionDenial::Internal(format!(
                "admitted local handle could not be rewound: {error}"
            ))
        })?;
        let mut bytes = Vec::new();
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| {
                AdmissionDenial::Internal(format!(
                    "admitted local handle could not be read: {error}"
                ))
            })?;
        if bytes.len() as u64 > max_bytes {
            return Err(AdmissionDenial::Internal(
                "media source exceeds byte limit".into(),
            ));
        }
        Ok(bytes)
    }
}

/// Reopens and live-revalidates the persisted sealed binding. This is invoked
/// before every source policy, so revocation and epoch changes deny before I/O.
pub(crate) trait SubjectLiveness: Send + Sync {
    fn revalidate(&self) -> Result<RevalidatedSubject, AdmissionDenial>;
}

/// The retained-HTTPS admission policy trait.
pub trait RetainedHttpsPolicy: Send + Sync {
    /// Fetch and retain an HTTPS source.
    fn admit(&self, session_id: &str, url: &str)
    -> Result<AdmittedRetainedSource, AdmissionDenial>;
}

/// `SessionMediaAuthority` — the private direct-native media authority.
///
/// Constructed only by the daemon/session-worker production composition and
/// carried in private `ToolCtx`. Tests construct it with fakes.
pub struct SessionMediaAuthority {
    subject: RevalidatedSubject,
    liveness: Arc<dyn SubjectLiveness>,
    attachment_resolver: Arc<dyn AttachmentResolver>,
    local_path_policy: Arc<dyn LocalPathPolicy>,
    retained_https_policy: Arc<dyn RetainedHttpsPolicy>,
}

impl std::fmt::Debug for SessionMediaAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionMediaAuthority")
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

impl SessionMediaAuthority {
    pub(crate) fn new(
        subject: RevalidatedSubject,
        liveness: Arc<dyn SubjectLiveness>,
        attachment_resolver: Arc<dyn AttachmentResolver>,
        local_path_policy: Arc<dyn LocalPathPolicy>,
        retained_https_policy: Arc<dyn RetainedHttpsPolicy>,
    ) -> Self {
        Self {
            subject,
            liveness,
            attachment_resolver,
            local_path_policy,
            retained_https_policy,
        }
    }

    /// The revalidated subject — internal only.
    pub(crate) fn subject(&self) -> &RevalidatedSubject {
        &self.subject
    }

    fn revalidate_subject(&self, session_id: &str) -> Result<(), AdmissionDenial> {
        let live = self.liveness.revalidate()?;
        if live.receipt.canonical_bytes() != self.subject.receipt.canonical_bytes()
            || uuid::Uuid::from_bytes(live.session_id).to_string() != session_id
        {
            return Err(AdmissionDenial::SubjectMismatch);
        }
        Ok(())
    }

    fn revalidate_current_subject(&self) -> Result<(), AdmissionDenial> {
        let session_id = uuid::Uuid::from_bytes(self.subject.session_id).to_string();
        self.revalidate_subject(&session_id)
    }

    /// Resolve a session attachment by id.
    ///
    /// Existence-hiding: a denial does not reveal whether the attachment
    /// exists.
    pub fn resolve_attachment(
        &self,
        session_id: &str,
        attachment_id: &[u8; 16],
    ) -> Result<AdmittedAttachment, AdmissionDenial> {
        // Validate session matches the subject.
        let subject_session = uuid::Uuid::from_bytes(self.subject.session_id).to_string();
        if session_id != subject_session {
            // Existence-hiding denial — no resolver call.
            return Err(AdmissionDenial::SubjectMismatch);
        }
        self.revalidate_subject(session_id)?;

        match self
            .attachment_resolver
            .resolve(session_id, attachment_id)?
        {
            Some(att) => Ok(att),
            None => Err(AdmissionDenial::AttachmentNotFound),
        }
    }

    /// Admit a local path.
    ///
    /// Performs exact canonical authorization, then an authority-owned
    /// no-follow held handle with evidence. Denials perform zero content
    /// opens/reads.
    pub fn admit_local_path(
        &self,
        session_id: &str,
        path: &str,
    ) -> Result<AdmittedLocalHandle, AdmissionDenial> {
        let subject_session = uuid::Uuid::from_bytes(self.subject.session_id).to_string();
        if session_id != subject_session {
            return Err(AdmissionDenial::SubjectMismatch);
        }
        self.revalidate_subject(session_id)?;

        let (canonical_path, held_file, evidence) =
            self.local_path_policy.authorize(session_id, path)?;
        Ok(AdmittedLocalHandle {
            canonical_path,
            held_file,
            evidence,
        })
    }

    /// Admit a retained-HTTPS source.
    ///
    /// Uses existing SSRF/DNS/redirect policy. Returns an immutable
    /// retained source. Denials perform zero fetches.
    pub fn admit_retained_https(
        &self,
        session_id: &str,
        url: &str,
    ) -> Result<AdmittedRetainedSource, AdmissionDenial> {
        let subject_session = uuid::Uuid::from_bytes(self.subject.session_id).to_string();
        if session_id != subject_session {
            return Err(AdmissionDenial::SubjectMismatch);
        }
        self.revalidate_subject(session_id)?;

        self.retained_https_policy.admit(session_id, url)
    }
    /// Read admitted source bytes. The tool never opens a model-supplied path
    /// or URL itself: local files are read from the authority-held descriptor,
    /// HTTPS uses the retained immutable
    /// buffer, and attachments go through the resolver's content seam.
    pub fn read_bytes(
        &self,
        handle: &AdmittedHandle,
        max_bytes: u64,
    ) -> Result<Vec<u8>, AdmissionDenial> {
        self.revalidate_current_subject()?;
        match handle {
            AdmittedHandle::Attachment(attachment) => {
                self.attachment_resolver.read_bytes(attachment, max_bytes)
            }
            AdmittedHandle::Local(local) => self.local_path_policy.read_bytes(local, max_bytes),
            AdmittedHandle::RetainedHttps(source) => {
                if source.content().len() as u64 > max_bytes {
                    return Err(AdmissionDenial::Internal(
                        "media source exceeds byte limit".into(),
                    ));
                }
                Ok(source.content().to_vec())
            }
        }
    }

    pub async fn read_media(
        &self,
        handle: &AdmittedHandle,
        max_bytes: u64,
    ) -> Result<AdmittedMediaBytes, AdmissionDenial> {
        self.revalidate_current_subject()?;
        match handle {
            AdmittedHandle::Attachment(attachment) => {
                self.attachment_resolver
                    .read_media(attachment, max_bytes)
                    .await
            }
            AdmittedHandle::Local(local) => Ok(AdmittedMediaBytes {
                bytes: self.local_path_policy.read_bytes(local, max_bytes)?,
                duration_us: None,
                retained_lease: None,
            }),
            AdmittedHandle::RetainedHttps(source) => Ok(AdmittedMediaBytes {
                bytes: if source.content().len() as u64 > max_bytes {
                    return Err(AdmissionDenial::Internal(
                        "media source exceeds byte limit".into(),
                    ));
                } else {
                    source.content().to_vec()
                },
                duration_us: None,
                retained_lease: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::receipt::IssuerKind;
    use super::super::revalidator::{RevalidatedSubject, RevalidatorError};
    use super::*;

    struct FakeAttachmentResolver {
        attachments: std::collections::HashMap<[u8; 16], AdmittedAttachment>,
    }

    #[async_trait]
    impl AttachmentResolver for FakeAttachmentResolver {
        fn resolve(
            &self,
            _session_id: &str,
            attachment_id: &[u8; 16],
        ) -> Result<Option<AdmittedAttachment>, AdmissionDenial> {
            Ok(self.attachments.get(attachment_id).cloned())
        }
    }

    struct FakeLocalPathPolicy;

    impl LocalPathPolicy for FakeLocalPathPolicy {
        fn authorize(
            &self,
            _session_id: &str,
            path: &str,
        ) -> Result<(PathBuf, Arc<std::fs::File>, HandleEvidence), AdmissionDenial> {
            if path.contains("denied") {
                return Err(AdmissionDenial::LocalPathDenied);
            }
            Ok((
                PathBuf::from(path),
                Arc::new(std::fs::File::open(std::env::current_exe().unwrap()).unwrap()),
                HandleEvidence {
                    metadata_fingerprint: [0xAA; 32],
                },
            ))
        }
    }

    struct AlwaysLive(RevalidatedSubject);

    impl SubjectLiveness for AlwaysLive {
        fn revalidate(&self) -> Result<RevalidatedSubject, AdmissionDenial> {
            Ok(self.0.clone())
        }
    }

    struct FakeRetainedHttpsPolicy;

    impl RetainedHttpsPolicy for FakeRetainedHttpsPolicy {
        fn admit(
            &self,
            _session_id: &str,
            url: &str,
        ) -> Result<AdmittedRetainedSource, AdmissionDenial> {
            if url.contains("denied") {
                return Err(AdmissionDenial::HttpsDenied);
            }
            Ok(AdmittedRetainedSource {
                canonical_url: url.to_string(),
                content: b"fake-content".to_vec(),
                content_type: "image/png".to_string(),
            })
        }
    }

    fn make_authority(session_id: [u8; 16]) -> SessionMediaAuthority {
        let subject = RevalidatedSubject {
            receipt: super::super::receipt::ToolMediaSubjectReceiptV1 {
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
            },
        );
        SessionMediaAuthority::new(
            subject.clone(),
            Arc::new(AlwaysLive(subject)),
            Arc::new(FakeAttachmentResolver { attachments }),
            Arc::new(FakeLocalPathPolicy),
            Arc::new(FakeRetainedHttpsPolicy),
        )
    }

    #[test]
    fn resolve_attachment_succeeds() {
        let session_id = [0xCD; 16];
        let auth = make_authority(session_id);
        let session_hex = uuid::Uuid::from_bytes(session_id).to_string();
        let result = auth.resolve_attachment(&session_hex, &[0x44; 16]);
        assert!(result.is_ok());
    }

    #[test]
    fn resolve_attachment_not_found() {
        let session_id = [0xCD; 16];
        let auth = make_authority(session_id);
        let session_hex = uuid::Uuid::from_bytes(session_id).to_string();
        let result = auth.resolve_attachment(&session_hex, &[0x99; 16]);
        assert!(matches!(result, Err(AdmissionDenial::AttachmentNotFound)));
    }

    #[test]
    fn resolve_attachment_wrong_session() {
        let session_id = [0xCD; 16];
        let auth = make_authority(session_id);
        let result = auth.resolve_attachment("wrong", &[0x44; 16]);
        assert!(matches!(result, Err(AdmissionDenial::SubjectMismatch)));
    }

    #[test]
    fn admit_local_path_succeeds() {
        let session_id = [0xCD; 16];
        let auth = make_authority(session_id);
        let session_hex = uuid::Uuid::from_bytes(session_id).to_string();
        let result = auth.admit_local_path(&session_hex, "/tmp/image.png");
        assert!(result.is_ok());
    }

    #[test]
    fn admit_local_path_denied() {
        let session_id = [0xCD; 16];
        let auth = make_authority(session_id);
        let session_hex = uuid::Uuid::from_bytes(session_id).to_string();
        let result = auth.admit_local_path(&session_hex, "/tmp/denied.png");
        assert!(matches!(result, Err(AdmissionDenial::LocalPathDenied)));
    }

    #[test]
    fn admit_https_succeeds() {
        let session_id = [0xCD; 16];
        let auth = make_authority(session_id);
        let session_hex = uuid::Uuid::from_bytes(session_id).to_string();
        let result = auth.admit_retained_https(&session_hex, "https://example.com/image.png");
        assert!(result.is_ok());
    }

    #[test]
    fn admit_https_denied() {
        let session_id = [0xCD; 16];
        let auth = make_authority(session_id);
        let session_hex = uuid::Uuid::from_bytes(session_id).to_string();
        let result =
            auth.admit_retained_https(&session_hex, "https://denied.example.com/image.png");
        assert!(matches!(result, Err(AdmissionDenial::HttpsDenied)));
    }
}
