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
            evidence,
            content,
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
pub struct DerivativeReservation {
    pub id: Uuid,
    completed: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    registry: Arc<Mutex<ImageRegistry>>,
}

impl Drop for DerivativeReservation {
    fn drop(&mut self) {
        if self.completed.load(Ordering::SeqCst) || self.cancelled.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut registry = self.registry.lock().unwrap();
        registry.bytes.remove(self.id.as_bytes());
        registry.identities.remove(self.id.as_bytes());
    }
}

impl DerivativeReservation {
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
            registry: Arc::new(Mutex::new(ImageRegistry {
                bytes: HashMap::new(),
                identities: HashMap::new(),
                live_leases: HashMap::new(),
                cleanup_requested: HashMap::new(),
            })),
            activity: Arc::new(AuthorityActivity::default()),
            durable_storage: None,
        }
    }

    pub(crate) fn with_durable_storage(
        mut self,
        storage: Arc<crate::media_storage::MediaStorageRecovery>,
    ) -> Self {
        self.durable_storage = Some(storage);
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

        self.local_path_policy
            .admit(session_id, path, READ_IMAGE_MAX_INPUT_BYTES)
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
        if handle.content().len() > READ_IMAGE_MAX_INPUT_BYTES {
            return Err(AdmissionDenial::Internal(
                "input image exceeds 67108864 bytes".to_string(),
            ));
        }
        let bytes = handle.content().to_vec();
        self.register_bytes(bytes)
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
        self.register_bytes(source.content().to_vec())
    }

    fn register_bytes(&self, bytes: Vec<u8>) -> Result<AdmittedReadImage, AdmissionDenial> {
        let attachment_id = if let Some(storage) = &self.durable_storage {
            storage
                .persist_tool_image(
                    Uuid::now_v7(),
                    Uuid::from_bytes(self.subject.session_id),
                    self.subject.project_digest,
                    &bytes,
                    "image/png",
                    None,
                )
                .map_err(|error| AdmissionDenial::Internal(error.to_string()))?
                .attachment_id
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
    pub fn reserve_read_image_derivative(
        &self,
        _source: &ImmutableAttachmentIdentity,
    ) -> Result<DerivativeReservation, AdmissionDenial> {
        self.activity.reservations.fetch_add(1, Ordering::SeqCst);
        #[cfg(test)]
        crate::media_image::test_hooks::bump(|c| {
            c.reservation.fetch_add(1, Ordering::SeqCst);
        });
        Ok(DerivativeReservation {
            id: Uuid::now_v7(),
            completed: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
            registry: Arc::clone(&self.registry),
        })
    }

    /// Persist the encoded derivative against an existing reservation.
    pub fn register_read_image_derivative(
        &self,
        reservation: DerivativeReservation,
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
                    self.subject.project_digest,
                    bytes,
                    _mime,
                    Some((_width, _height)),
                )
                .map_err(|error| AdmissionDenial::Internal(error.to_string()))?;
            if persisted.attachment_id != attachment_id || persisted.checksum != checksum {
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
        if cancel.is_cancelled() {
            return Err(AdmissionDenial::Internal(
                "derivative registration cancelled".to_string(),
            ));
        }
        reservation.complete();
        Ok(identity)
    }

    /// Cancel a reservation and drop any partial derivative exactly once.
    pub fn cancel_derivative(&self, reservation: &DerivativeReservation) {
        if reservation.completed.load(Ordering::SeqCst) {
            return;
        }
        if reservation.cancelled.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut registry = self.registry.lock().unwrap();
        registry.bytes.remove(reservation.id.as_bytes());
        registry.identities.remove(reservation.id.as_bytes());
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
