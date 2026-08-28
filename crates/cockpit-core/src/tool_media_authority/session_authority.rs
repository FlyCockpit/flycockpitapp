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

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::revalidator::RevalidatedSubject;

/// Image media kind (FCM2 wire code).
const IMAGE_KIND: u8 = 1;
const READ_IMAGE_MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// An admitted local-path handle — authority-owned, no-follow, with evidence.
///
/// The consumer never reopens the spelling; the authority holds the handle
/// and validates identity/evidence on every use.
#[derive(Debug, Clone)]
pub struct AdmittedLocalHandle {
    /// The canonical absolute path that was authorized.
    canonical_path: PathBuf,
    /// The already-opened no-follow source. Consumers read this descriptor and
    /// never reopen the authorized spelling.
    held_file: Option<Arc<std::sync::Mutex<std::fs::File>>>,
    /// Opaque evidence that the handle was held by the authority at admission
    /// time (e.g. inode/device metadata). Never exposed to the model.
    evidence: HandleEvidence,
    /// Bytes read through the policy's held, no-follow handle. Keeping them on
    /// the admitted object prevents consumers from reopening the path spelling.
    content: Vec<u8>,
}

impl AdmittedLocalHandle {
    pub(crate) fn from_held_bytes(
        canonical_path: PathBuf,
        evidence: HandleEvidence,
        content: Vec<u8>,
    ) -> Self {
        Self {
            canonical_path,
            held_file: None,
            evidence,
            content,
        }
    }

    pub(crate) fn from_held_file(
        canonical_path: PathBuf,
        held_file: std::fs::File,
        evidence: HandleEvidence,
    ) -> Self {
        Self {
            canonical_path,
            held_file: Some(Arc::new(std::sync::Mutex::new(held_file))),
            evidence,
            content: Vec::new(),
        }
    }

    /// The canonical path — available to the authority's internal consumer
    /// only, never to the model.
    pub(crate) fn canonical_path(&self) -> &PathBuf {
        &self.canonical_path
    }

    /// The handle evidence — internal only.
    pub(crate) fn evidence(&self) -> &HandleEvidence {
        &self.evidence
    }

    pub(crate) fn content(&self) -> &[u8] {
        &self.content
    }

    pub(crate) fn held_file(&self) -> Option<&std::sync::Mutex<std::fs::File>> {
        self.held_file.as_deref()
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

/// Nested closed `source` union: `{attachment_id}`, `{path}`, or `{url}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NestedMediaSource {
    AttachmentId(String),
    Path(String),
    Url(String),
}

/// Result of admitting a nested source. Path/URL admissions create a session
/// attachment; attachment-id reuse does not open or fetch again.
#[derive(Debug, Clone)]
pub struct SourceAdmission {
    pub handle: AdmittedHandle,
    pub attachment: AdmittedAttachment,
    pub newly_created: bool,
    /// Reservation that owns a newly persisted durable path/URL source. This
    /// stays crate-private so callers cannot detach durable quota ownership
    /// from the admitted source it protects.
    pub(crate) source_reservation: Option<DerivativeReservation>,
}

/// An admitted attachment reference — resolved from session attachments.
#[derive(Debug, Clone)]
pub struct AdmittedAttachment {
    pub(crate) attachment_id: [u8; 16],
    pub(crate) attachment_version: u64,
    pub(crate) checksum: [u8; 32],
    pub(crate) kind: u8,
    /// Bytes resolved through the durable attachment provider while admission
    /// is authorized. Consumers receive this held evidence and never perform a
    /// second lookup by attachment id.
    pub(crate) content: Vec<u8>,
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

    pub(crate) fn content(&self) -> &[u8] {
        &self.content
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
    #[error("source is not an image attachment")]
    NotImage,
}

/// Closed source arm for `read_image`. Exactly one of attachment/path/url.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadImageSource {
    Attachment { attachment_id: Uuid },
    Path { path: String },
    Url { url: String },
}

/// Immutable attachment identity yielded by source admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmutableAttachmentIdentity {
    pub attachment_id: Uuid,
    pub attachment_version: u64,
    pub checksum: [u8; 32],
    pub kind: u8,
}

/// Short-lived source lease. Held only for source-to-derivative processing.
pub struct ToolSource {
    shared: Arc<ToolSourceShared>,
    released: bool,
}

struct ToolSourceShared {
    bytes: Vec<u8>,
    identity: ImmutableAttachmentIdentity,
    release_count: AtomicU64,
    held: AtomicBool,
    model_leases: AtomicU64,
    preview_leases: AtomicU64,
    released_notify: Mutex<Vec<std::sync::mpsc::Sender<()>>>,
    activity: Arc<AuthorityActivity>,
}

impl std::fmt::Debug for ToolSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolSource")
            .field("attachment_id", &self.shared.identity.attachment_id)
            .field("released", &self.released)
            .finish_non_exhaustive()
    }
}

impl ToolSource {
    fn new(
        bytes: Vec<u8>,
        identity: ImmutableAttachmentIdentity,
        activity: Arc<AuthorityActivity>,
    ) -> Self {
        Self {
            shared: Arc::new(ToolSourceShared {
                bytes,
                identity,
                release_count: AtomicU64::new(0),
                held: AtomicBool::new(true),
                model_leases: AtomicU64::new(0),
                preview_leases: AtomicU64::new(0),
                released_notify: Mutex::new(Vec::new()),
                activity,
            }),
            released: false,
        }
    }

    /// Authority-owned source bytes. Never a second open by spelling.
    pub fn bytes(&self) -> Result<&[u8], AdmissionDenial> {
        if self.released || !self.shared.held.load(Ordering::SeqCst) {
            return Err(AdmissionDenial::Internal(
                "tool source released".to_string(),
            ));
        }
        Ok(&self.shared.bytes)
    }

    pub fn identity(&self) -> &ImmutableAttachmentIdentity {
        &self.shared.identity
    }

    /// Release the source lease. Idempotent; Drop also releases.
    pub fn release(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        self.shared.release_count.fetch_add(1, Ordering::SeqCst);
        self.shared
            .activity
            .source_releases
            .fetch_add(1, Ordering::SeqCst);
        self.shared.held.store(false, Ordering::SeqCst);
        let waiters = std::mem::take(&mut *self.shared.released_notify.lock().unwrap());
        for tx in waiters {
            let _ = tx.send(());
        }
    }

    pub fn is_released(&self) -> bool {
        self.released || !self.shared.held.load(Ordering::SeqCst)
    }

    pub fn release_count(&self) -> u64 {
        self.shared.release_count.load(Ordering::SeqCst)
    }

    pub fn model_lease_count(&self) -> u64 {
        self.shared.model_leases.load(Ordering::SeqCst)
    }

    pub fn preview_lease_count(&self) -> u64 {
        self.shared.preview_leases.load(Ordering::SeqCst)
    }

    fn wait_shared_until_released(shared: &Arc<ToolSourceShared>) {
        if !shared.held.load(Ordering::SeqCst) {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        shared.released_notify.lock().unwrap().push(tx);
        if !shared.held.load(Ordering::SeqCst) {
            return;
        }
        let _ = rx.recv();
    }
}

impl Drop for ToolSource {
    fn drop(&mut self) {
        self.release();
    }
}

/// Admitted read-image source: identity plus the held ToolSource lease.
pub struct AdmittedReadImage {
    pub identity: ImmutableAttachmentIdentity,
    pub tool_source: ToolSource,
}

/// Reservation for a read-image derivative. Cancelled on drop unless completed.
pub struct ImageDerivativeReservation {
    pub id: Uuid,
    completed: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    registry: Arc<Mutex<ImageRegistry>>,
    durable_storage: Option<Arc<crate::media_storage::MediaStorageRecovery>>,
}

impl Drop for ImageDerivativeReservation {
    fn drop(&mut self) {
        if self.completed.load(Ordering::SeqCst) || self.cancelled.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut registry = self.registry.lock().unwrap();
        registry.bytes.remove(self.id.as_bytes());
        registry.identities.remove(self.id.as_bytes());
        drop(registry);
        if let Some(storage) = &self.durable_storage {
            let _ = storage.cancel_tool_image_reservation(self.id);
        }
    }
}

impl ImageDerivativeReservation {
    pub fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn complete(&self) {
        self.completed.store(true, Ordering::SeqCst);
    }
}

#[derive(Debug, Default)]
pub struct AuthorityActivity {
    pub reservations: AtomicU64,
    pub derivative_writes: AtomicU64,
    pub model_leases: AtomicU64,
    pub preview_leases: AtomicU64,
    pub source_releases: AtomicU64,
    pub decode_opens: AtomicU64,
}

struct ImageRegistry {
    bytes: HashMap<[u8; 16], Vec<u8>>,
    identities: HashMap<[u8; 16], ImmutableAttachmentIdentity>,
    live_leases: HashMap<[u8; 16], Vec<Weak<ToolSourceShared>>>,
    cleanup_requested: HashMap<[u8; 16], Arc<AtomicBool>>,
}

/// Counter for denial I/O operations — tests verify zero on every denied path.
#[derive(Debug, Default, Clone)]
pub struct DenialIoCounters {
    pub source_opens: u64,
    pub source_reads: u64,
    pub fetches: u64,
    pub reservations: u64,
    pub derivatives: u64,
    pub runner_calls: u64,
}

/// Success-path I/O counters. Attachment-id reuse must not increment
/// path authorizations or fetches.
#[derive(Debug, Default, Clone)]
pub struct AdmissionIoCounters {
    pub path_authorizations: u64,
    pub path_reads: u64,
    pub fetches: u64,
    pub attachment_resolves: u64,
    pub attachment_opens: u64,
    pub attachments_created: u64,
    pub runner_calls: u64,
    pub reservations: u64,
    pub reservations_aborted: u64,
    pub derivatives_published: u64,
    pub derivatives_discarded: u64,
}

/// The attachment resolver trait — resolves session attachments by id.
///
/// Existence-hiding: a `None` return does not distinguish "not found" from
/// "not authorized".
pub trait AttachmentResolver: Send + Sync {
    /// Resolve an attachment by id for the given session.
    /// Returns `Ok(Some(...))` if found and authorized, `Ok(None)` otherwise.
    fn resolve(
        &self,
        session_id: &str,
        attachment_id: &[u8; 16],
        max_bytes: usize,
    ) -> Result<Option<AdmittedAttachment>, AdmissionDenial>;

    /// Resolve a non-canonical alias such as a test fixture id.
    fn resolve_alias(
        &self,
        _session_id: &str,
        _alias: &str,
    ) -> Result<Option<AdmittedAttachment>, AdmissionDenial> {
        Ok(None)
    }

    /// Open the already-authorized attachment through daemon-owned storage.
    /// Implementations must return a held/immutable content capability, never
    /// a storage pathname. `None` existence-hides missing or stale content.
    fn open(
        &self,
        _session_id: &str,
        _attachment: &AdmittedAttachment,
    ) -> Result<Option<AdmittedHandle>, AdmissionDenial> {
        Ok(None)
    }
}

/// The local-path admission policy trait.
pub trait LocalPathPolicy: Send + Sync {
    /// Canonicalize, authorize, and read a local path through one held,
    /// no-follow handle. Implementations must enforce `max_bytes` while
    /// reading, before allocating unbounded content.
    fn admit(
        &self,
        session_id: &str,
        path: &str,
        max_bytes: usize,
    ) -> Result<AdmittedLocalHandle, AdmissionDenial>;

    /// Canonicalize and authorize a local path without reading content.
    /// Audio/video admission uses the held file; image admission still
    /// reads through [`Self::admit`] with `max_bytes`.
    fn authorize(
        &self,
        session_id: &str,
        path: &str,
    ) -> Result<(std::fs::File, HandleEvidence), AdmissionDenial>;
}

/// Reopens and live-revalidates the persisted sealed binding. This is invoked
/// before every source policy, so revocation and epoch changes deny before I/O.
pub(crate) trait SubjectLiveness: Send + Sync {
    fn revalidate(&self) -> Result<RevalidatedSubject, AdmissionDenial>;
}

/// The retained-HTTPS admission policy trait.
pub trait RetainedHttpsPolicy: Send + Sync {
    /// Fetch and retain an HTTPS source.
    fn admit(
        &self,
        session_id: &str,
        url: &str,
        max_bytes: usize,
    ) -> Result<AdmittedRetainedSource, AdmissionDenial>;
}

/// In-session attachment ledger created by path/URL admissions.
struct SessionAttachmentLedger {
    by_id: std::collections::HashMap<[u8; 16], AdmittedAttachment>,
    aliases: std::collections::HashMap<String, [u8; 16]>,
    local_handles: std::collections::HashMap<[u8; 16], AdmittedLocalHandle>,
    https_bytes: std::collections::HashMap<[u8; 16], Vec<u8>>,
}

impl SessionAttachmentLedger {
    fn new() -> Self {
        Self {
            by_id: std::collections::HashMap::new(),
            aliases: std::collections::HashMap::new(),
            local_handles: std::collections::HashMap::new(),
            https_bytes: std::collections::HashMap::new(),
        }
    }
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
    registry: Arc<Mutex<ImageRegistry>>,
    activity: Arc<AuthorityActivity>,
    durable_storage: Option<Arc<crate::media_storage::MediaStorageRecovery>>,
    durable_project_digest: Option<[u8; 32]>,
    media_backend: Option<(
        Arc<crate::media_storage::MediaStorageRecovery>,
        crate::media_reservation::MediaReservationLedger,
    )>,
    /// I/O counters for denial verification (test instrumentation).
    denial_counters: std::sync::Mutex<DenialIoCounters>,
    io: std::sync::Mutex<AdmissionIoCounters>,
    ledger: std::sync::Mutex<SessionAttachmentLedger>,
    durable_submission_ids: Vec<[u8; 16]>,
    #[cfg(test)]
    cancel_after_publications: std::sync::Mutex<Option<(u64, tokio_util::sync::CancellationToken)>>,
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
        media_backend: Option<(
            Arc<crate::media_storage::MediaStorageRecovery>,
            crate::media_reservation::MediaReservationLedger,
        )>,
    ) -> Self {
        Self {
            subject,
            liveness,
            attachment_resolver,
            local_path_policy,
            retained_https_policy,
            registry: Arc::new(Mutex::new(ImageRegistry {
                bytes: HashMap::new(),
                identities: HashMap::new(),
                live_leases: HashMap::new(),
                cleanup_requested: HashMap::new(),
            })),
            activity: Arc::new(AuthorityActivity::default()),
            durable_storage: None,
            durable_project_digest: None,
            media_backend,
            denial_counters: std::sync::Mutex::new(DenialIoCounters::default()),
            io: std::sync::Mutex::new(AdmissionIoCounters::default()),
            ledger: std::sync::Mutex::new(SessionAttachmentLedger::new()),
            durable_submission_ids: Vec::new(),
            #[cfg(test)]
            cancel_after_publications: std::sync::Mutex::new(None),
        }
    }

    pub(crate) fn with_durable_storage(
        mut self,
        storage: Arc<crate::media_storage::MediaStorageRecovery>,
        project_digest: [u8; 32],
    ) -> Self {
        self.durable_storage = Some(storage);
        self.durable_project_digest = Some(project_digest);
        self
    }

    pub(crate) fn with_durable_fold(mut self, submissions: Vec<[u8; 16]>) -> Self {
        self.durable_submission_ids = submissions;
        self
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

        match self.attachment_resolver.resolve(
            session_id,
            attachment_id,
            READ_IMAGE_MAX_INPUT_BYTES,
        )? {
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

        let (held_file, evidence) = self.local_path_policy.authorize(session_id, path)?;
        Ok(AdmittedLocalHandle::from_held_file(
            PathBuf::from(path),
            held_file,
            evidence,
        ))
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

        self.retained_https_policy
            .admit(session_id, url, READ_IMAGE_MAX_INPUT_BYTES)
    }
    pub fn activity(&self) -> Arc<AuthorityActivity> {
        Arc::clone(&self.activity)
    }

    pub fn live_lease_ids(&self) -> Vec<Uuid> {
        let mut registry = self.registry.lock().unwrap();
        registry.live_leases.retain(|_, leases| {
            leases.retain(|lease| {
                lease
                    .upgrade()
                    .is_some_and(|shared| shared.held.load(Ordering::SeqCst))
            });
            !leases.is_empty()
        });
        registry
            .live_leases
            .keys()
            .copied()
            .map(Uuid::from_bytes)
            .collect()
    }

    /// Admit a read-image source. The only source admission the consumer may use.
    ///
    /// An existing attachment is checked for session/project/image identity.
    /// A path/URL is admitted and registered atomically as a session-owned
    /// typed image attachment. Yields the immutable identity plus a held
    /// [`ToolSource`]. The consumer must not look up or authorize again.
    pub fn admit_read_image_source(
        &self,
        subject: &RevalidatedSubject,
        source: ReadImageSource,
    ) -> Result<AdmittedReadImage, AdmissionDenial> {
        if subject.session_id != self.subject.session_id
            || subject.project_digest != self.subject.project_digest
            || subject.principal_digest != self.subject.principal_digest
            || subject.authorization_epoch != self.subject.authorization_epoch
        {
            return Err(AdmissionDenial::SubjectMismatch);
        }
        let session_hex = Uuid::from_bytes(self.subject.session_id).to_string();
        match source {
            ReadImageSource::Attachment { attachment_id } => {
                self.admit_attachment(&session_hex, attachment_id)
            }
            ReadImageSource::Path { path } => self.admit_path_as_image(&session_hex, &path),
            ReadImageSource::Url { url } => self.admit_url_as_image(&session_hex, &url),
        }
    }

    fn admit_attachment(
        &self,
        session_hex: &str,
        attachment_id: Uuid,
    ) -> Result<AdmittedReadImage, AdmissionDenial> {
        let id_bytes = *attachment_id.as_bytes();
        let att = self.resolve_attachment(session_hex, &id_bytes)?;
        if att.attachment_id != id_bytes || att.kind != IMAGE_KIND {
            return Err(AdmissionDenial::AttachmentNotFound);
        }
        if att.content().len() > READ_IMAGE_MAX_INPUT_BYTES {
            return Err(AdmissionDenial::Internal(
                "input image exceeds 67108864 bytes".to_string(),
            ));
        }
        let bytes = att.content().to_vec();
        let identity = ImmutableAttachmentIdentity {
            attachment_id,
            attachment_version: att.attachment_version,
            checksum: att.checksum,
            kind: att.kind,
        };
        self.hold_attachment_source(identity, bytes)
    }

    fn admit_path_as_image(
        &self,
        session_hex: &str,
        path: &str,
    ) -> Result<AdmittedReadImage, AdmissionDenial> {
        let handle = self.admit_local_path(session_hex, path)?;
        let bytes = if handle.content().is_empty() {
            use std::io::{Read as _, Seek as _, SeekFrom};
            let mut file = handle
                .held_file()
                .ok_or_else(|| AdmissionDenial::Internal("media source handle missing".into()))?
                .lock()
                .map_err(|_| AdmissionDenial::Internal("media source handle poisoned".into()))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
            let mut bytes = Vec::new();
            file.take(READ_IMAGE_MAX_INPUT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
            bytes
        } else {
            handle.content().to_vec()
        };
        if bytes.len() > READ_IMAGE_MAX_INPUT_BYTES {
            return Err(AdmissionDenial::Internal(
                "input image exceeds 67108864 bytes".to_string(),
            ));
        }
        self.register_bytes(
            bytes,
            cockpit_db::media_attachments::MediaSourceKind::LocalPath,
        )
    }

    fn admit_url_as_image(
        &self,
        session_hex: &str,
        url: &str,
    ) -> Result<AdmittedReadImage, AdmissionDenial> {
        let source = self.admit_retained_https(session_hex, url)?;
        if source.content().len() > READ_IMAGE_MAX_INPUT_BYTES {
            return Err(AdmissionDenial::Internal(
                "input image exceeds 67108864 bytes".to_string(),
            ));
        }
        self.register_bytes(
            source.content().to_vec(),
            cockpit_db::media_attachments::MediaSourceKind::RetainedHttps,
        )
    }

    fn register_bytes(
        &self,
        bytes: Vec<u8>,
        source_kind: cockpit_db::media_attachments::MediaSourceKind,
    ) -> Result<AdmittedReadImage, AdmissionDenial> {
        let mime = match image::guess_format(&bytes).map_err(|_| AdmissionDenial::NotImage)? {
            image::ImageFormat::Png => "image/png",
            image::ImageFormat::Jpeg => "image/jpeg",
            image::ImageFormat::WebP => "image/webp",
            image::ImageFormat::Gif => "image/gif",
            _ => return Err(AdmissionDenial::NotImage),
        };
        let attachment_id = if let Some(storage) = &self.durable_storage {
            let attachment_id = Uuid::now_v7();
            crate::media_image::preflight_exif_orientation(&bytes)
                .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
            storage
                .reserve_tool_image_source(
                    attachment_id,
                    Uuid::from_bytes(self.subject.session_id),
                    u64::try_from(bytes.len())
                        .map_err(|error| AdmissionDenial::Internal(error.to_string()))?,
                )
                .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
            match storage.persist_tool_image(
                attachment_id,
                Uuid::from_bytes(self.subject.session_id),
                self.durable_project_digest
                    .expect("durable storage requires project digest"),
                attachment_id.to_string(),
                &bytes,
                mime,
                source_kind,
                None,
            ) {
                Ok(identity) => identity.attachment_id,
                Err(error) => {
                    let cleanup = storage.cancel_tool_image_reservation(attachment_id);
                    return Err(AdmissionDenial::Internal(match cleanup {
                        Ok(()) => error.to_string(),
                        Err(cleanup_error) => format!(
                            "{error:#}; failed to abandon source reservation: {cleanup_error:#}"
                        ),
                    }));
                }
            }
        } else {
            Uuid::now_v7()
        };
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let checksum: [u8; 32] = hasher.finalize().into();
        let identity = ImmutableAttachmentIdentity {
            attachment_id,
            attachment_version: 1,
            checksum,
            kind: IMAGE_KIND,
        };
        Ok(self.hold_source(identity, bytes))
    }

    fn hold_source(
        &self,
        identity: ImmutableAttachmentIdentity,
        bytes: Vec<u8>,
    ) -> AdmittedReadImage {
        let source = ToolSource::new(bytes, identity.clone(), Arc::clone(&self.activity));
        self.registry
            .lock()
            .unwrap()
            .live_leases
            .entry(*identity.attachment_id.as_bytes())
            .or_default()
            .push(Arc::downgrade(&source.shared));
        AdmittedReadImage {
            identity,
            tool_source: source,
        }
    }

    fn hold_attachment_source(
        &self,
        identity: ImmutableAttachmentIdentity,
        bytes: Vec<u8>,
    ) -> Result<AdmittedReadImage, AdmissionDenial> {
        let source = ToolSource::new(bytes, identity.clone(), Arc::clone(&self.activity));
        let mut registry = self.registry.lock().unwrap();
        if registry
            .cleanup_requested
            .get(identity.attachment_id.as_bytes())
            .is_some_and(|flag| flag.load(Ordering::SeqCst))
        {
            return Err(AdmissionDenial::AttachmentNotFound);
        }
        registry
            .live_leases
            .entry(*identity.attachment_id.as_bytes())
            .or_default()
            .push(Arc::downgrade(&source.shared));
        Ok(AdmittedReadImage {
            identity,
            tool_source: source,
        })
    }

    /// Reserve a derivative of `source`. Denials before this have zero write.
    ///
    /// `decode_width`/`decode_height` are the planned durable output of the
    /// transform, which is the pixel decode this reservation pays for.
    pub fn reserve_read_image_derivative(
        &self,
        _source: &ImmutableAttachmentIdentity,
        reserved_encoded_bytes: u64,
        decode_width: u32,
        decode_height: u32,
    ) -> Result<ImageDerivativeReservation, AdmissionDenial> {
        self.activity.reservations.fetch_add(1, Ordering::SeqCst);
        #[cfg(test)]
        crate::media_image::test_hooks::bump(|c| {
            c.reservation.fetch_add(1, Ordering::SeqCst);
        });
        let id = Uuid::now_v7();
        if let Some(storage) = &self.durable_storage {
            storage
                .reserve_tool_image_derivative(
                    id,
                    Uuid::from_bytes(self.subject.session_id),
                    reserved_encoded_bytes,
                    decode_width,
                    decode_height,
                )
                .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
        }
        Ok(ImageDerivativeReservation {
            id,
            completed: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            registry: Arc::clone(&self.registry),
            durable_storage: self.durable_storage.clone(),
        })
    }

    /// Persist the encoded derivative against an existing reservation.
    pub fn register_read_image_derivative(
        &self,
        reservation: ImageDerivativeReservation,
        cancel: &tokio_util::sync::CancellationToken,
        bytes: &[u8],
        _mime: &str,
        _width: u32,
        _height: u32,
        checksum_hex: &str,
    ) -> Result<ImmutableAttachmentIdentity, AdmissionDenial> {
        if reservation.is_cancelled() || cancel.is_cancelled() {
            return Err(AdmissionDenial::Internal(
                "derivative reservation cancelled".to_string(),
            ));
        }
        self.activity
            .derivative_writes
            .fetch_add(1, Ordering::SeqCst);
        #[cfg(test)]
        crate::media_image::test_hooks::bump(|c| {
            c.derivative_write.fetch_add(1, Ordering::SeqCst);
        });
        let attachment_id = reservation.id;
        let checksum =
            parse_sha256_hex(checksum_hex).map_err(|e| AdmissionDenial::Internal(e.to_string()))?;
        let identity = ImmutableAttachmentIdentity {
            attachment_id,
            attachment_version: 1,
            checksum,
            kind: IMAGE_KIND,
        };
        if let Some(storage) = &self.durable_storage {
            let persisted = storage
                .persist_tool_image(
                    attachment_id,
                    Uuid::from_bytes(self.subject.session_id),
                    self.durable_project_digest
                        .expect("durable storage requires project digest"),
                    reservation.id.to_string(),
                    bytes,
                    _mime,
                    cockpit_db::media_attachments::MediaSourceKind::AuthenticatedSessionUpload,
                    Some((_width, _height)),
                )
                .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
            if persisted.attachment_id != attachment_id || persisted.checksum != checksum {
                storage
                    .cancel_tool_image_reservation(attachment_id)
                    .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
                return Err(AdmissionDenial::Internal(
                    "durable derivative identity mismatch".to_string(),
                ));
            }
        }
        {
            let mut registry = self.registry.lock().unwrap();
            registry
                .bytes
                .insert(*attachment_id.as_bytes(), bytes.to_vec());
            registry
                .identities
                .insert(*attachment_id.as_bytes(), identity.clone());
        }
        #[cfg(test)]
        crate::media_image::test_hooks::wait_publication_barrier();
        if cancel.is_cancelled() {
            if let Some(storage) = &self.durable_storage {
                storage
                    .cancel_tool_image_reservation(attachment_id)
                    .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
            }
            return Err(AdmissionDenial::Internal(
                "derivative registration cancelled".to_string(),
            ));
        }
        reservation.complete();
        Ok(identity)
    }

    /// Cancel a reservation and drop any partial derivative exactly once.
    pub fn cancel_derivative(&self, reservation: &ImageDerivativeReservation) {
        if reservation.completed.load(Ordering::SeqCst) {
            return;
        }
        if reservation.cancelled.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut registry = self.registry.lock().unwrap();
        registry.bytes.remove(reservation.id.as_bytes());
        registry.identities.remove(reservation.id.as_bytes());
        drop(registry);
        if let Some(storage) = &reservation.durable_storage {
            let _ = storage.cancel_tool_image_reservation(reservation.id);
        }
    }

    /// Cleanup racing source processing: wait on a held lease, or win before decode.
    pub fn request_source_cleanup(&self, attachment_id: Uuid) -> CleanupRace {
        let id = *attachment_id.as_bytes();
        let (leases, already_held) = {
            let mut registry = self.registry.lock().unwrap();
            let flag = registry
                .cleanup_requested
                .entry(id)
                .or_insert_with(|| Arc::new(AtomicBool::new(false)))
                .clone();
            // Close admission before snapshotting leases. No later caller can
            // slip a new ToolSource into the set while cleanup waits.
            flag.store(true, Ordering::SeqCst);
            let leases: Vec<_> = registry
                .live_leases
                .get_mut(&id)
                .map(|entries| {
                    entries.retain(|entry| entry.strong_count() > 0);
                    entries.iter().filter_map(Weak::upgrade).collect()
                })
                .unwrap_or_default();
            (leases, flag)
        };
        if leases
            .iter()
            .any(|shared| shared.held.load(Ordering::SeqCst))
        {
            for shared in leases {
                if !shared.held.load(Ordering::SeqCst) {
                    continue;
                }
                ToolSource::wait_shared_until_released(&shared);
            }
            already_held.store(true, Ordering::SeqCst);
            CleanupRace::WaitedForLease
        } else {
            already_held.store(true, Ordering::SeqCst);
            CleanupRace::WonBeforeDecode
        }
    }

    /// Admit a nested closed source union. Path/URL branches create one
    /// session attachment; attachment-id reuse resolves only.
    pub fn admit_nested_source(
        &self,
        session_id: &str,
        source: &NestedMediaSource,
    ) -> Result<SourceAdmission, AdmissionDenial> {
        match source {
            NestedMediaSource::AttachmentId(id) => {
                let (attachment, handle) = self.resolve_attachment_source_ref(session_id, id)?;
                if let Ok(mut io) = self.io.lock() {
                    io.attachment_resolves += 1;
                }
                Ok(SourceAdmission {
                    handle,
                    attachment,
                    newly_created: false,
                    source_reservation: None,
                })
            }
            NestedMediaSource::Path(path) => {
                let local = self.admit_local_path(session_id, path)?;
                if let Ok(mut io) = self.io.lock() {
                    io.path_authorizations += 1;
                }
                let attachment = self.record_local_attachment(&local);
                Ok(SourceAdmission {
                    handle: AdmittedHandle::Local(local),
                    attachment,
                    newly_created: true,
                    source_reservation: None,
                })
            }
            NestedMediaSource::Url(url) => {
                let https = self.admit_retained_https(session_id, url)?;
                if let Ok(mut io) = self.io.lock() {
                    io.fetches += 1;
                }
                let attachment = self.record_https_attachment(&https);
                Ok(SourceAdmission {
                    handle: AdmittedHandle::RetainedHttps(https),
                    attachment,
                    newly_created: true,
                    source_reservation: None,
                })
            }
        }
    }

    /// Resolve an attachment by canonical hex/UUID or a fixture alias.
    pub fn resolve_attachment_ref(
        &self,
        session_id: &str,
        attachment_ref: &str,
    ) -> Result<AdmittedAttachment, AdmissionDenial> {
        self.validate_bound_session(session_id)?;
        if let Some(id) = parse_attachment_id(attachment_ref) {
            self.revalidate_subject(session_id)?;
            if let Ok(ledger) = self.ledger.lock() {
                if let Some(att) = ledger.by_id.get(&id) {
                    return Ok(att.clone());
                }
            }
            self.revalidate_subject(session_id)?;
            return match self.attachment_resolver.resolve(session_id, &id)? {
                Some(att) => Ok(att),
                None => Err(AdmissionDenial::AttachmentNotFound),
            };
        }
        self.revalidate_subject(session_id)?;
        if let Ok(ledger) = self.ledger.lock() {
            if let Some(id) = ledger.aliases.get(attachment_ref) {
                if let Some(att) = ledger.by_id.get(id) {
                    return Ok(att.clone());
                }
            }
        }
        self.revalidate_subject(session_id)?;
        match self
            .attachment_resolver
            .resolve_alias(session_id, attachment_ref)?
        {
            Some(att) => Ok(att),
            None => Err(AdmissionDenial::AttachmentNotFound),
        }
    }

    fn resolve_attachment_source_ref(
        &self,
        session_id: &str,
        attachment_ref: &str,
    ) -> Result<(AdmittedAttachment, AdmittedHandle), AdmissionDenial> {
        // Revalidate immediately before every id/alias/cache lookup. Do not
        // let a previously admitted object outlive its sealed subject.
        self.validate_bound_session(session_id)?;
        if let Some(id) = parse_attachment_id(attachment_ref) {
            self.revalidate_subject(session_id)?;
            if let Ok(ledger) = self.ledger.lock() {
                if let Some(att) = ledger.by_id.get(&id) {
                    let handle = held_handle_from_ledger(&ledger, att)
                        .ok_or(AdmissionDenial::AttachmentNotFound)?;
                    return Ok((att.clone(), handle));
                }
            }
            self.revalidate_subject(session_id)?;
            let attachment = self
                .attachment_resolver
                .resolve(session_id, &id)?
                .ok_or(AdmissionDenial::AttachmentNotFound)?;
            self.revalidate_subject(session_id)?;
            let handle = self
                .attachment_resolver
                .open(session_id, &attachment)?
                .ok_or(AdmissionDenial::AttachmentNotFound)?;
            if let Ok(mut io) = self.io.lock() {
                io.attachment_opens += 1;
            }
            return Ok((attachment, handle));
        }
        self.revalidate_subject(session_id)?;
        if let Ok(ledger) = self.ledger.lock() {
            if let Some(id) = ledger.aliases.get(attachment_ref) {
                if let Some(att) = ledger.by_id.get(id) {
                    let handle = held_handle_from_ledger(&ledger, att)
                        .ok_or(AdmissionDenial::AttachmentNotFound)?;
                    return Ok((att.clone(), handle));
                }
            }
        }
        self.revalidate_subject(session_id)?;
        let attachment = self
            .attachment_resolver
            .resolve_alias(session_id, attachment_ref)?
            .ok_or(AdmissionDenial::AttachmentNotFound)?;
        self.revalidate_subject(session_id)?;
        let handle = self
            .attachment_resolver
            .open(session_id, &attachment)?
            .ok_or(AdmissionDenial::AttachmentNotFound)?;
        if let Ok(mut io) = self.io.lock() {
            io.attachment_opens += 1;
        }
        Ok((attachment, handle))
    }

    fn validate_bound_session(&self, session_id: &str) -> Result<(), AdmissionDenial> {
        let subject_session = uuid::Uuid::from_bytes(self.subject.session_id).to_string();
        if session_id != subject_session {
            return Err(AdmissionDenial::SubjectMismatch);
        }
        Ok(())
    }

    fn record_local_attachment(&self, local: &AdmittedLocalHandle) -> AdmittedAttachment {
        let attachment = new_session_attachment(1, local.content().to_vec());
        if let Ok(mut ledger) = self.ledger.lock() {
            ledger
                .local_handles
                .insert(attachment.attachment_id, local.clone());
            ledger
                .aliases
                .insert(hex_id(&attachment.attachment_id), attachment.attachment_id);
            ledger
                .by_id
                .insert(attachment.attachment_id, attachment.clone());
        }
        if let Ok(mut io) = self.io.lock() {
            io.attachments_created += 1;
        }
        attachment
    }

    fn record_https_attachment(&self, https: &AdmittedRetainedSource) -> AdmittedAttachment {
        let attachment = new_session_attachment(3, https.content.clone());
        if let Ok(mut ledger) = self.ledger.lock() {
            ledger
                .https_bytes
                .insert(attachment.attachment_id, https.content.clone());
            ledger
                .aliases
                .insert(hex_id(&attachment.attachment_id), attachment.attachment_id);
            ledger
                .by_id
                .insert(attachment.attachment_id, attachment.clone());
        }
        if let Ok(mut io) = self.io.lock() {
            io.attachments_created += 1;
        }
        attachment
    }

    fn held_handle_for(&self, attachment: &AdmittedAttachment) -> AdmittedHandle {
        if let Ok(ledger) = self.ledger.lock() {
            if let Some(handle) = held_handle_from_ledger(&ledger, attachment) {
                return handle;
            }
        }
        AdmittedHandle::Attachment(attachment.clone())
    }

    /// Snapshot denial I/O counters (test instrumentation).
    #[cfg(test)]
    pub fn denial_counters(&self) -> DenialIoCounters {
        self.denial_counters.lock().unwrap().clone()
    }

    pub fn io_counters(&self) -> AdmissionIoCounters {
        self.io.lock().unwrap().clone()
    }

    #[cfg(test)]
    pub(crate) fn provisional_ledger_counts(&self) -> (usize, usize, usize, usize) {
        let ledger = self.ledger.lock().unwrap();
        (
            ledger.by_id.len(),
            ledger.local_handles.len(),
            ledger.https_bytes.len(),
            ledger.aliases.len(),
        )
    }

    #[cfg(test)]
    pub(crate) fn cancel_after_publications(
        &self,
        count: u64,
        token: tokio_util::sync::CancellationToken,
    ) {
        *self.cancel_after_publications.lock().unwrap() = Some((count, token));
    }

    fn record_derivative_published(&self) {
        let Ok(mut io) = self.io.lock() else {
            return;
        };
        io.derivatives_published += 1;
        #[cfg(test)]
        let published = io.derivatives_published;
        drop(io);
        #[cfg(test)]
        if let Ok(hook) = self.cancel_after_publications.lock()
            && let Some((target, token)) = hook.as_ref()
            && published >= *target
        {
            token.cancel();
        }
    }

    pub fn record_runner_call(&self) {
        if let Ok(mut io) = self.io.lock() {
            io.runner_calls += 1;
        }
    }

    pub fn record_reservation(&self) {
        if let Ok(mut io) = self.io.lock() {
            io.reservations += 1;
        }
    }

    pub fn attachment_id_hex(id: &[u8; 16]) -> String {
        hex_id(id)
    }

    pub(crate) fn approved_av_runtime_pair(
        &self,
    ) -> Result<(std::path::PathBuf, std::path::PathBuf), AdmissionDenial> {
        let Some((storage, _)) = &self.media_backend else {
            return Err(AdmissionDenial::Internal(
                "media runtime authority unavailable".to_owned(),
            ));
        };
        let runtime = storage
            .resolve_av_runtime()
            .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
        if !runtime.ffmpeg.is_absolute() || !runtime.ffprobe.is_absolute() {
            return Err(AdmissionDenial::Internal(
                "media runtime authority returned a non-absolute path".to_owned(),
            ));
        }
        Ok((runtime.ffmpeg, runtime.ffprobe))
    }

    pub(crate) fn approved_ffprobe_runtime(&self) -> Result<std::path::PathBuf, AdmissionDenial> {
        let Some((storage, _)) = &self.media_backend else {
            return Err(AdmissionDenial::Internal(
                "media runtime authority unavailable".to_owned(),
            ));
        };
        let ffprobe = storage
            .resolve_ffprobe_runtime()
            .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
        if !ffprobe.is_absolute() {
            return Err(AdmissionDenial::Internal(
                "media runtime authority returned a non-absolute path".to_owned(),
            ));
        }
        Ok(ffprobe)
    }

    /// Promote a freshly admitted path/URL source into daemon-owned typed
    /// storage before any media runner sees it. Tests without a daemon backend
    /// still replace mutable held descriptors with a bounded immutable byte
    /// snapshot; production never returns an in-memory-only attachment id.
    pub(crate) async fn persist_new_source(
        &self,
        admission: SourceAdmission,
        kind: cockpit_db::media_attachments::MediaKind,
        capability_generation: u64,
    ) -> Result<SourceAdmission, AdmissionDenial> {
        let provisional_id = admission
            .newly_created
            .then_some(admission.attachment.attachment_id);
        let result = self
            .persist_new_source_inner(admission, kind, capability_generation)
            .await;
        if result.is_err()
            && let Some(id) = provisional_id
        {
            self.remove_ledger_attachment(id);
        }
        result
    }

    async fn persist_new_source_inner(
        &self,
        mut admission: SourceAdmission,
        kind: cockpit_db::media_attachments::MediaKind,
        capability_generation: u64,
    ) -> Result<SourceAdmission, AdmissionDenial> {
        self.revalidate_subject(&uuid::Uuid::from_bytes(self.subject.session_id).to_string())?;
        if !admission.newly_created {
            return Ok(admission);
        }
        use std::io::{Read as _, Seek as _, SeekFrom};

        let declared = match &admission.handle {
            AdmittedHandle::Local(local) => {
                let file = local.held_file().ok_or_else(|| {
                    AdmissionDenial::Internal("media source handle missing".into())
                })?.lock().map_err(|_| {
                    AdmissionDenial::Internal("media source handle poisoned".into())
                })?;
                let declared = file
                    .metadata()
                    .map_err(|error| AdmissionDenial::Internal(error.to_string()))?
                    .len();
                if declared == 0 || declared > 4 * 1024 * 1024 {
                    return Err(AdmissionDenial::Internal("media resource denied".into()));
                }
                declared
            }
            AdmittedHandle::RetainedHttps(source) => source.content.len() as u64,
            AdmittedHandle::Attachment(_) => return Ok(admission),
        };
        if declared == 0 || declared > 4 * 1024 * 1024 {
            return Err(AdmissionDenial::Internal("media resource denied".into()));
        }
        let bytes = match &admission.handle {
            AdmittedHandle::Local(local) => {
                let read = (|| {
                    let mut file = local.held_file().ok_or_else(|| {
                        AdmissionDenial::Internal("media source handle missing".into())
                    })?.lock().map_err(|_| {
                        AdmissionDenial::Internal("media source handle poisoned".into())
                    })?;
                    file.seek(SeekFrom::Start(0))
                        .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
                    let mut bytes = Vec::with_capacity(declared as usize);
                    file.take(declared.saturating_add(1))
                        .read_to_end(&mut bytes)
                        .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
                    if bytes.len() as u64 != declared {
                        return Err(AdmissionDenial::HandleReplacement);
                    }
                    Ok(bytes)
                })();
                match read {
                    Ok(bytes) => bytes,
                    Err(error) => return Err(error),
                }
            }
            AdmittedHandle::RetainedHttps(source) => source.content.clone(),
            AdmittedHandle::Attachment(_) => unreachable!("handled before reservation"),
        };
        // From this boundary onward the admitted source is immutable verified
        // bytes. Never let a runner retain the mutable local descriptor used
        // during admission: an in-place write to that file must not change the
        // bytes executed by this call or a later attachment-id reuse.
        let immutable_handle = AdmittedHandle::RetainedHttps(AdmittedRetainedSource {
            canonical_url: hex_id(&admission.attachment.attachment_id),
            content: bytes.clone(),
            content_type: "application/octet-stream".into(),
        });
        if self.media_backend.is_none() {
            let id = admission.attachment.attachment_id;
            if let Ok(mut ledger) = self.ledger.lock() {
                ledger.local_handles.remove(&id);
                ledger.https_bytes.insert(id, bytes);
            }
            admission.handle = immutable_handle;
            return Ok(admission);
        }
        let reservation = self.reserve_derivative(1_000, declared, false).await?;
        let old_id = admission.attachment.attachment_id;
        let published = self
            .publish_owned_component(
                &reservation,
                cockpit_db::media_attachments::MediaSourceKind::ToolAdmittedSource,
                kind,
                match kind {
                    cockpit_db::media_attachments::MediaKind::Audio => "application/octet-stream",
                    cockpit_db::media_attachments::MediaKind::Video => "application/octet-stream",
                    cockpit_db::media_attachments::MediaKind::Image => "application/octet-stream",
                },
                bytes.clone(),
                capability_generation,
            )
            .await;
        let attachment = match published {
            Ok(attachment) => attachment,
            Err(error) => return Err(error),
        };
        if !self.durable_submission_ids.is_empty()
            && let Some((storage, _)) = &self.media_backend
            && let Err(error) = storage
                .bind_tool_admitted_source_to_fold(
                    uuid::Uuid::from_bytes(self.subject.session_id),
                    crate::intel::hex_lower(&self.subject.project_digest),
                    self.durable_submission_ids.clone(),
                    attachment.clone(),
                    chrono::Utc::now().timestamp_millis(),
                )
                .await
        {
            storage
                .discard_tool_derivative(attachment.attachment_id)
                .await
                .map_err(|cleanup| AdmissionDenial::Internal(cleanup.to_string()))?;
            self.abort_derivative_after_discard(&reservation).await?;
            return Err(AdmissionDenial::Internal(error.to_string()));
        }
        if let Ok(mut ledger) = self.ledger.lock() {
            ledger.by_id.remove(&old_id);
            ledger.local_handles.remove(&old_id);
            ledger.https_bytes.remove(&old_id);
            ledger.aliases.retain(|_, id| *id != old_id);
            ledger.https_bytes.insert(attachment.attachment_id, bytes);
            ledger
                .aliases
                .insert(hex_id(&attachment.attachment_id), attachment.attachment_id);
            ledger
                .by_id
                .insert(attachment.attachment_id, attachment.clone());
        }
        admission.handle = AdmittedHandle::RetainedHttps(AdmittedRetainedSource {
            canonical_url: hex_id(&attachment.attachment_id),
            content: match &immutable_handle {
                AdmittedHandle::RetainedHttps(source) => source.content.clone(),
                _ => unreachable!("new source snapshot is immutable bytes"),
            },
            content_type: "application/octet-stream".into(),
        });
        admission.attachment = attachment;
        admission.source_reservation = Some(reservation);
        Ok(admission)
    }

    fn remove_ledger_attachment(&self, id: [u8; 16]) {
        if let Ok(mut ledger) = self.ledger.lock() {
            ledger.by_id.remove(&id);
            ledger.local_handles.remove(&id);
            ledger.https_bytes.remove(&id);
            ledger.aliases.retain(|_, value| *value != id);
        }
    }

    /// Remove a source admitted by a call that failed before returning its
    /// durable id. Successful calls retain the fold-scoped reference for id
    /// reuse and restart recovery; failed calls must not orphan either bytes
    /// or authority rows.
    pub(crate) async fn discard_new_source(
        &self,
        admission: &SourceAdmission,
    ) -> Result<(), AdmissionDenial> {
        if !admission.newly_created {
            return Ok(());
        }
        let id = admission.attachment.attachment_id;
        if let Some((storage, _)) = &self.media_backend {
            if let Err(error) = storage
                .discard_tool_admitted_source_for_fold(
                    uuid::Uuid::from_bytes(self.subject.session_id),
                    self.durable_submission_ids.clone(),
                    id,
                    chrono::Utc::now().timestamp_millis(),
                )
                .await
            {
                // The durable reservation intentionally remains live when
                // byte/row destruction fails, but the unreturned source must
                // not remain addressable through the in-memory alias ledger.
                self.remove_ledger_attachment(id);
                return Err(AdmissionDenial::Internal(error.to_string()));
            }
        }
        let reservation_cleanup = if let Some(reservation) = &admission.source_reservation {
            // Durable bytes and rows must be gone before their accounting
            // reservation is abandoned/released.
            self.abort_derivative_after_discard(reservation).await
        } else {
            Ok(())
        };
        self.remove_ledger_attachment(id);
        reservation_cleanup
    }

    pub(crate) async fn reserve_derivative(
        &self,
        duration_ms: u64,
        output_ceiling: u64,
        reserve_decode: bool,
    ) -> Result<DerivativeReservation, AdmissionDenial> {
        let Some((_, ledger)) = &self.media_backend else {
            #[cfg(test)]
            {
                return Ok(DerivativeReservation {
                    reservation_id: format!("test-av:{}", uuid::Uuid::now_v7()),
                    version: 1,
                    durable: false,
                });
            }
            #[cfg(not(test))]
            return Err(AdmissionDenial::Internal(
                "media reservation authority unavailable".to_owned(),
            ));
        };
        use crate::config::media_budget::{
            MediaDimension, MediaEvaluationRequest, MediaResourcePolicy,
        };
        let policy = MediaResourcePolicy::default();
        let duration_seconds = duration_ms.div_ceil(1_000).max(1);
        let mut requested = vec![
            (MediaDimension::EncodedBytesPerObject, output_ceiling),
            (MediaDimension::RetainedBytesPerSession, output_ceiling),
            (MediaDimension::DurationSecondsPerObject, duration_seconds),
            (MediaDimension::LocalCpuJobsGlobal, 1),
            (MediaDimension::QueuedOperationsGlobal, 1),
            (MediaDimension::QueuedOperationsPerSession, 1),
            (MediaDimension::OperationDeadlineSeconds, 120),
        ];
        if reserve_decode {
            requested.extend([
                (
                    MediaDimension::DecodedEdgePixels,
                    policy.limits().decoded_edge_pixels,
                ),
                (
                    MediaDimension::DecodedImagePixels,
                    policy.limits().decoded_image_pixels,
                ),
                (
                    MediaDimension::AggregateDecodedPixelsPerRequest,
                    policy.limits().decoded_image_pixels,
                ),
            ]);
        }
        let plans = requested
            .into_iter()
            .map(|(dimension, requested)| {
                policy.evaluate(MediaEvaluationRequest {
                    dimension,
                    requested: Some(requested),
                    current_scope: 0,
                    profile: None,
                    adapter_limit: None,
                    request_limit: None,
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AdmissionDenial::Internal("media resource denied".to_owned()))?;
        let cpu_plan = plans
            .iter()
            .find(|plan| plan.dimension == MediaDimension::LocalCpuJobsGlobal)
            .cloned()
            .ok_or_else(|| AdmissionDenial::Internal("media CPU plan missing".to_owned()))?;
        let reservation_id = format!("av-tool:{}", uuid::Uuid::now_v7());
        let wall_ms = u64::try_from(chrono::Utc::now().timestamp_millis())
            .map_err(|_| AdmissionDenial::Internal("system clock before epoch".to_owned()))?;
        let receipt = ledger
            .reserve(crate::media_reservation::ReserveRequest {
                reservation_id: reservation_id.clone(),
                recovery_id: reservation_id.clone(),
                owner: crate::media_reservation::MediaOwner {
                    project_id: crate::intel::hex_lower(&self.subject.project_digest),
                    session_id: uuid::Uuid::from_bytes(self.subject.session_id).to_string(),
                },
                operation: "audio_video_tool".to_owned(),
                purpose: "typed_media_derivative".to_owned(),
                plans,
                wall_ms,
            })
            .await
            .map_err(|_| AdmissionDenial::Internal("media resource denied".to_owned()))?;
        let promoted = match ledger
            .promote(&reservation_id, receipt.version, cpu_plan, wall_ms)
            .await
        {
            Ok(promoted) => promoted,
            Err(_) => {
                let _ = ledger
                    .request_cancellation(&reservation_id, receipt.version, wall_ms)
                    .await;
                return Err(AdmissionDenial::Internal(
                    "media resource denied".to_owned(),
                ));
            }
        };
        Ok(DerivativeReservation {
            reservation_id,
            version: promoted.version,
            durable: true,
        })
    }

    pub(crate) async fn abort_derivative(
        &self,
        reservation: &DerivativeReservation,
    ) -> Result<(), AdmissionDenial> {
        if !reservation.durable {
            if let Ok(mut io) = self.io.lock() {
                io.reservations_aborted += 1;
            }
            return Ok(());
        }
        if let Some((_, ledger)) = &self.media_backend {
            ledger
                .abandon_local_operation(
                    &reservation.reservation_id,
                    &format!("av-tool-abandoned:{}", reservation.reservation_id),
                    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0),
                )
                .await
                .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
        }
        if let Ok(mut io) = self.io.lock() {
            io.reservations_aborted += 1;
        }
        Ok(())
    }

    async fn abort_derivative_after_discard(
        &self,
        reservation: &DerivativeReservation,
    ) -> Result<(), AdmissionDenial> {
        if !reservation.durable {
            if let Ok(mut io) = self.io.lock() {
                io.reservations_aborted += 1;
            }
            return Ok(());
        }
        if let Some((_, ledger)) = &self.media_backend {
            ledger
                .abandon_tool_operation_after_discard(
                    &reservation.reservation_id,
                    &format!("av-tool-discarded:{}", reservation.reservation_id),
                    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0),
                )
                .await
                .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
        }
        if let Ok(mut io) = self.io.lock() {
            io.reservations_aborted += 1;
        }
        Ok(())
    }

    /// Compensate a derivative that was already published but cannot be
    /// returned because a later member of the same storyboard failed. Durable
    /// bytes/rows are deleted before the settled reservation is released, so
    /// accounting never claims destruction ahead of storage cleanup.
    pub(crate) async fn discard_published_derivative(
        &self,
        reservation: &DerivativeReservation,
        attachment: &AdmittedAttachment,
    ) -> Result<(), AdmissionDenial> {
        if let Some((storage, _)) = &self.media_backend {
            storage
                .discard_tool_derivative(attachment.attachment_id)
                .await
                .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
        }
        self.abort_derivative_after_discard(reservation).await?;
        if let Ok(mut io) = self.io.lock() {
            io.derivatives_discarded += 1;
        }
        Ok(())
    }

    async fn discard_unreturned_component(
        &self,
        storage: &crate::media_storage::MediaStorageRecovery,
        reservation: &DerivativeReservation,
        attachment_id: [u8; 16],
    ) -> Result<(), AdmissionDenial> {
        storage
            .discard_tool_derivative(attachment_id)
            .await
            .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
        // Destruction is authoritative. Only release accounting after durable
        // bytes/rows are confirmed gone; otherwise retain the live reservation
        // for recovery and surface the cleanup failure.
        self.abort_derivative_after_discard(reservation).await
    }

    pub(crate) async fn publish_owned_component(
        &self,
        reservation: &DerivativeReservation,
        source_kind: cockpit_db::media_attachments::MediaSourceKind,
        kind: cockpit_db::media_attachments::MediaKind,
        mime: &str,
        bytes: Vec<u8>,
        capability_generation: u64,
    ) -> Result<AdmittedAttachment, AdmissionDenial> {
        let Some((storage, ledger)) = &self.media_backend else {
            #[cfg(test)]
            {
                let mut checksum = [0u8; 32];
                checksum.copy_from_slice(sha2::Sha256::digest(&bytes).as_slice());
                let attachment = AdmittedAttachment {
                    attachment_id: *uuid::Uuid::now_v7().as_bytes(),
                    attachment_version: 1,
                    checksum,
                    kind: kind.code(),
                    content: bytes,
                };
                self.record_derivative_published();
                return Ok(attachment);
            }
            #[cfg(not(test))]
            return Err(AdmissionDenial::Internal(
                "media artifact authority unavailable".to_owned(),
            ));
        };
        let now = chrono::Utc::now().timestamp_millis();
        let (attachment, publication_intent_id) = match storage
            .publish_tool_owned_component(
                &reservation.reservation_id,
                uuid::Uuid::from_bytes(self.subject.session_id),
                crate::intel::hex_lower(&self.subject.project_digest),
                kind,
                mime.to_owned(),
                bytes.clone(),
                source_kind,
                capability_generation,
                now,
            )
            .await
        {
            Ok(attachment) => attachment,
            Err(error) => {
                if error.cleanup_proven() {
                    self.abort_derivative(reservation).await?;
                }
                return Err(AdmissionDenial::Internal(error.to_string()));
            }
        };
        let mut version = reservation.version;
        for dimension in [
            crate::config::media_budget::MediaDimension::EncodedBytesPerObject,
            crate::config::media_budget::MediaDimension::RetainedBytesPerSession,
        ] {
            match ledger
                .reconcile_actual(
                    &reservation.reservation_id,
                    version,
                    dimension,
                    bytes.len() as u64,
                    false,
                    u64::try_from(now).unwrap_or(0),
                )
                .await
            {
                Ok(receipt) => version = receipt.version,
                Err(error) => {
                    self.discard_unreturned_component(
                        storage,
                        reservation,
                        attachment.attachment_id,
                    )
                    .await?;
                    return Err(AdmissionDenial::Internal(error.to_string()));
                }
            }
        }
        let completed = match ledger
            .complete_local_allocation(
                &reservation.reservation_id,
                version,
                u64::try_from(now).unwrap_or(0),
            )
            .await
        {
            Ok(completed) => completed,
            Err(error) => {
                self.discard_unreturned_component(storage, reservation, attachment.attachment_id)
                    .await?;
                return Err(AdmissionDenial::Internal(error.to_string()));
            }
        };
        let settled = match ledger
            .settle_verified(
                &reservation.reservation_id,
                completed.version,
                vec![
                    crate::config::media_budget::MediaDimension::DurationSecondsPerObject,
                    crate::config::media_budget::MediaDimension::OperationDeadlineSeconds,
                    crate::config::media_budget::MediaDimension::DecodedEdgePixels,
                    crate::config::media_budget::MediaDimension::DecodedImagePixels,
                    crate::config::media_budget::MediaDimension::AggregateDecodedPixelsPerRequest,
                ],
                u64::try_from(now).unwrap_or(0),
            )
            .await
        {
            Ok(settled) => settled,
            Err(error) => {
                self.discard_unreturned_component(storage, reservation, attachment.attachment_id)
                    .await?;
                return Err(AdmissionDenial::Internal(error.to_string()));
            }
        };
        if let Err(error) = ledger
            .authorize_tool_publication(&reservation.reservation_id, &publication_intent_id)
            .await
        {
            self.discard_unreturned_component(storage, reservation, attachment.attachment_id)
                .await?;
            return Err(AdmissionDenial::Internal(error.to_string()));
        }
        debug_assert!(settled.version > completed.version);
        self.record_derivative_published();
        Ok(attachment)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DerivativeReservation {
    pub(crate) reservation_id: String,
    version: u64,
    durable: bool,
}

fn held_handle_from_ledger(
    ledger: &SessionAttachmentLedger,
    attachment: &AdmittedAttachment,
) -> Option<AdmittedHandle> {
    if let Some(handle) = ledger.local_handles.get(&attachment.attachment_id) {
        return Some(AdmittedHandle::Local(handle.clone()));
    }
    ledger
        .https_bytes
        .get(&attachment.attachment_id)
        .map(|bytes| {
            AdmittedHandle::RetainedHttps(AdmittedRetainedSource {
                canonical_url: hex_id(&attachment.attachment_id),
                content: bytes.clone(),
                content_type: "application/octet-stream".into(),
            })
        })
}

/// Outcome of a cleanup race against a held ToolSource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupRace {
    WaitedForLease,
    WonBeforeDecode,
}

fn parse_sha256_hex(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err("checksum must be 64 hex chars".into());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

fn hex_id(id: &[u8; 16]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_attachment_id(value: &str) -> Option<[u8; 16]> {
    if let Ok(uuid) = uuid::Uuid::parse_str(value) {
        return Some(*uuid.as_bytes());
    }
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut id = [0u8; 16];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).ok()?;
        id[index] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(id)
}

fn new_session_attachment(kind: u8, content: Vec<u8>) -> AdmittedAttachment {
    let id = *uuid::Uuid::now_v7().as_bytes();
    let mut checksum = [0u8; 32];
    checksum[..16].copy_from_slice(&id);
    AdmittedAttachment {
        attachment_id: id,
        attachment_version: 1,
        checksum,
        kind,
        content,
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

    struct FakeLocalPathPolicy;

    impl LocalPathPolicy for FakeLocalPathPolicy {
        fn admit(
            &self,
            _session_id: &str,
            path: &str,
            max_bytes: usize,
        ) -> Result<AdmittedLocalHandle, AdmissionDenial> {
            if path.contains("denied") {
                return Err(AdmissionDenial::LocalPathDenied);
            }
            let content = std::fs::read(path).unwrap_or_default();
            if content.len() > max_bytes {
                return Err(AdmissionDenial::Internal("input too large".into()));
            }
            Ok(AdmittedLocalHandle::from_held_bytes(
                PathBuf::from(path),
                HandleEvidence {
                    metadata_fingerprint: [0xAA; 32],
                },
                content,
            ))
        }

        fn authorize(
            &self,
            _session_id: &str,
            path: &str,
        ) -> Result<(std::fs::File, HandleEvidence), AdmissionDenial> {
            if path.contains("denied") {
                return Err(AdmissionDenial::LocalPathDenied);
            }
            Ok((
                std::fs::File::open(std::env::current_exe().unwrap()).unwrap(),
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
            max_bytes: usize,
        ) -> Result<AdmittedRetainedSource, AdmissionDenial> {
            if url.contains("denied") {
                return Err(AdmissionDenial::HttpsDenied);
            }
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
                content: Vec::new(),
            },
        );
        SessionMediaAuthority::new(
            subject.clone(),
            Arc::new(AlwaysLive(subject)),
            Arc::new(FakeAttachmentResolver { attachments }),
            Arc::new(FakeLocalPathPolicy),
            Arc::new(FakeRetainedHttpsPolicy),
            None,
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
