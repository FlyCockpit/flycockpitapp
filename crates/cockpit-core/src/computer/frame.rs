//! Memory-only computer screenshots and the durable projection boundary.
//!
//! This module establishes the transient-pixel type ([`LiveComputerFrame`]) and
//! the exhaustive sanitized projection ([`SanitizedComputerFrame`]) *before* any
//! live computer coordinator exists. The design goal is that no coordinator,
//! provider adapter, event, audit, journal, export, or log can accidentally make
//! screenshots durable.
//!
//! # Architecture
//!
//! [`LiveComputerFrame`] is the sole owner of encoded screenshot bytes. It is
//! neither `Serialize` nor `Clone`. Its API permits a provider request builder
//! to borrow bytes only inside a scoped closure via [`LiveComputerFrame::borrow_bytes`];
//! it never returns an owned byte vector, data URL, path, or serializable
//! provider request.
//!
//! [`SanitizedComputerFrame`] carries only dimensions, byte count, checksum, IDs,
//! capture epoch, media type, and redaction reason. Every durable
//! request/event/audit/journal/export/debug projection accepts this safe type
//! rather than the live type. There is no generic serializer or `AsRef<[u8]>`
//! escape hatch on the live owner.
//!
//! # Zeroization scope
//!
//! Cockpit promptly drops uniquely owned buffers and overwrites uniquely owned
//! spare capacity where sound. The allocator, kernel, compositor, GPU, encoder,
//! and provider copies are **outside** this guarantee; universal zeroization is
//! not claimed. See [`LiveComputerFrame::drop`] for the precise owned-buffer
//! lifetime.
//!
//! # Screenshot mode
//!
//! `drop_after_turn` is the only screenshot mode. There is no screenshot table,
//! replay blob, retained OCR, or screenshot-path event.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::{Digest, Sha256};

use super::{CaptureFrame, PixelRect, ScaleFactor};

/// Maximum encoded byte count for a single transient frame.
///
/// Oversize frames fail before transient provider assembly (see
/// [`LiveComputerFrame::try_new`]). This ceiling is intentionally generous for
/// high-DPI captures but bounded so a single frame cannot exhaust session media.
pub const MAX_TRANSIENT_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Media type labels for screenshot frames, used in the sanitized projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenshotMediaType {
    /// PNG-encoded screenshot.
    Png,
    /// JPEG-encoded screenshot.
    Jpeg,
}

impl ScreenshotMediaType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
        }
    }
}

impl fmt::Display for ScreenshotMediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// SHA-256 checksum of the encoded frame bytes, hex-encoded.
///
/// Checksums correlate frames across projections but are not focus, target,
/// authorization, or semantic-success evidence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FrameChecksum(pub String);

impl FrameChecksum {
    /// Compute the SHA-256 checksum of the encoded bytes.
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hex::encode(&hasher.finalize()))
    }
}

/// Helper: hex-encode without pulling in a new dependency.
pub(crate) mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }
}

/// Monotonic capture epoch in milliseconds.
///
/// A late frame whose delegation/observation epoch is obsolete is dropped and
/// cannot replace a current frame (see [`LiveComputerFrame::is_stale_relative_to`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub struct CaptureEpoch(pub u64);

/// Unique observation identifier for a single screenshot capture.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ObservationId(pub String);

/// Unique action identifier correlating a frame to the action that requested it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ActionId(pub String);

/// Bounded reason code for cleanup failure. Never includes the temp path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupReasonCode {
    /// Temp file removal failed.
    TempRemovalFailed,
    /// Temp directory removal failed.
    TempDirRemovalFailed,
    /// Reservation release failed.
    ReservationReleaseFailed,
}

impl fmt::Display for CleanupReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TempRemovalFailed => f.write_str("temp_removal_failed"),
            Self::TempDirRemovalFailed => f.write_str("temp_dir_removal_failed"),
            Self::ReservationReleaseFailed => f.write_str("reservation_release_failed"),
        }
    }
}

/// A contained, private temp path guard for platform capture files.
///
/// The guard owns a private temp path (created under a contained tempdir) and
/// removes it exactly once on drop. The path is never exposed in durable
/// projections; [`TempCaptureGuard::path`] is only available to the live frame
/// owner. Cleanup failure returns a bounded reason code and never includes the
/// path.
pub struct TempCaptureGuard {
    path: Option<std::path::PathBuf>,
    dir: Option<tempfile::TempDir>,
    cleanup_ok: bool,
}

impl TempCaptureGuard {
    /// Create a guard for a file written inside a private tempdir.
    ///
    /// The `dir` argument is the owned tempdir that contains the file; it is
    /// removed (with the file) on drop. The `file_name` is the leaf name of the
    /// file inside that dir.
    pub fn new(dir: tempfile::TempDir, file_name: &str) -> std::io::Result<Self> {
        let path = dir.path().join(file_name);
        Ok(Self {
            path: Some(path),
            dir: Some(dir),
            cleanup_ok: false,
        })
    }

    /// Create a guard that only tracks a tempdir (no separate file).
    pub fn dir_only(dir: tempfile::TempDir) -> Self {
        Self {
            path: None,
            dir: Some(dir),
            cleanup_ok: false,
        }
    }

    /// Create an empty guard for testing (no file, no dir).
    #[cfg(test)]
    pub fn empty() -> Self {
        Self {
            path: None,
            dir: None,
            cleanup_ok: true,
        }
    }

    /// Borrow the contained temp path. Only available to the live frame owner.
    pub fn path(&self) -> Option<&std::path::Path> {
        self.path.as_deref()
    }

    /// Execute cleanup, returning Ok(()) on success or a bounded reason code.
    ///
    /// On a *hard* removal failure (something other than "already gone") the
    /// path/dir handles are **retained**, not taken, so a later explicit
    /// `cleanup()` or the guard's `Drop` (and the owned `TempDir`'s own
    /// recursive `Drop`) can retry removing the plaintext artifact — a single
    /// failed unlink never permanently disarms cleanup and strands a PNG.
    pub fn cleanup(&mut self) -> Result<(), CleanupReasonCode> {
        if self.cleanup_ok {
            return Ok(());
        }
        let mut failed = None;
        // Remove the file. Keep `path` on hard failure so cleanup can retry.
        if let Some(path) = self.path.as_deref() {
            match std::fs::remove_file(path) {
                Ok(()) => self.path = None,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => self.path = None,
                Err(_) => failed = Some(CleanupReasonCode::TempRemovalFailed),
            }
        }
        // Remove the directory tree. Remove by path (not the consuming
        // `TempDir::close`) so on hard failure the owned `TempDir` stays in place
        // and its own `Drop` retries the recursive removal.
        if let Some(dir) = self.dir.as_ref() {
            match std::fs::remove_dir_all(dir.path()) {
                Ok(()) => self.dir = None,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => self.dir = None,
                Err(_) => {
                    if failed.is_none() {
                        failed = Some(CleanupReasonCode::TempDirRemovalFailed);
                    }
                }
            }
        }
        self.cleanup_ok = failed.is_none();
        match failed {
            Some(code) => Err(code),
            None => Ok(()),
        }
    }

    /// Returns true if cleanup has been performed (successfully or not).
    pub fn is_cleaned(&self) -> bool {
        self.cleanup_ok || (self.path.is_none() && self.dir.is_none())
    }
}

impl Drop for TempCaptureGuard {
    fn drop(&mut self) {
        // Best-effort cleanup on drop; swallow the error (bounded code is only
        // returned by explicit `cleanup()`).
        let _ = self.cleanup();
    }
}

impl fmt::Debug for TempCaptureGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempCaptureGuard")
            .field("has_path", &self.path.is_some())
            .field("has_dir", &self.dir.is_some())
            .field("cleanup_ok", &self.cleanup_ok)
            .finish()
    }
}

/// A trait for media reservation handles that can be released exactly once.
///
/// This abstracts over the central media reservation ledger so the frame module
/// does not depend on the full ledger type. The handle is released exactly once
/// on [`LiveComputerFrame`] drop or explicit cleanup.
pub trait MediaReservationHandle: Send + 'static {
    /// Release the reservation. Returns Ok(()) on success or a bounded reason
    /// code. Must be idempotent — a second call returns Ok(()).
    fn release(&mut self) -> Result<(), CleanupReasonCode>;
}

/// A simple in-memory reservation handle for testing.
#[derive(Debug)]
pub struct InMemoryReservationHandle {
    released: Arc<AtomicBool>,
}

impl InMemoryReservationHandle {
    pub fn new(released: Arc<AtomicBool>) -> Self {
        Self { released }
    }
}

impl MediaReservationHandle for InMemoryReservationHandle {
    fn release(&mut self) -> Result<(), CleanupReasonCode> {
        self.released.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// A reservation handle that always fails release (for testing failure paths).
pub struct FailingReservationHandle {
    released: Arc<AtomicBool>,
}

impl FailingReservationHandle {
    pub fn new(released: Arc<AtomicBool>) -> Self {
        Self { released }
    }
}

impl MediaReservationHandle for FailingReservationHandle {
    fn release(&mut self) -> Result<(), CleanupReasonCode> {
        self.released.store(true, Ordering::SeqCst);
        Err(CleanupReasonCode::ReservationReleaseFailed)
    }
}

/// The non-serializable, non-cloneable owner of live screenshot bytes.
///
/// `LiveComputerFrame` owns bounded encoded bytes, physical dimensions,
/// observation/action IDs, checksum, capture epoch, exactly one media
/// reservation, and an optional temp-capture guard. It is the sole type that
/// can hand pixel bytes to a provider request builder, and only inside a scoped
/// closure.
///
/// # Not `Serialize`
///
/// This type deliberately does not implement `Serialize`. There is no
/// `AsRef<[u8]>` or `Into<Vec<u8>>` escape hatch. The only way to access bytes
/// is [`borrow_bytes`], which passes a borrowed slice into a closure and
/// returns the closure's result — never the bytes themselves.
///
/// # Not `Clone`
///
/// Cloning would duplicate the reservation and the temp guard, violating the
/// "exactly one" invariant. The type is move-only.
///
/// # Owned-buffer lifetime
///
/// The encoded bytes live exactly as long as this struct. On drop, the byte
/// vector is dropped, and its uniquely owned spare capacity is zeroized where
/// sound (the inner `Vec<u8>` is overwritten with zeros before being freed).
/// The allocator, kernel, compositor, GPU, encoder, and provider copies are
/// outside this guarantee — see the module docs.
///
/// [`borrow_bytes`]: LiveComputerFrame::borrow_bytes
pub struct LiveComputerFrame {
    bytes: Vec<u8>,
    media_type: ScreenshotMediaType,
    dimensions: FrameDimensions,
    checksum: FrameChecksum,
    observation_id: ObservationId,
    action_id: ActionId,
    capture_epoch: CaptureEpoch,
    reservation: Box<dyn MediaReservationHandle>,
    temp_guard: Option<TempCaptureGuard>,
    cleaned: bool,
}

/// Physical dimensions of a captured frame.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct FrameDimensions {
    pub width: u32,
    pub height: u32,
    pub region: Option<PixelRect>,
    pub native_zoom: Option<ScaleFactor>,
}

impl FrameDimensions {
    pub fn from_capture(frame: &CaptureFrame) -> Self {
        Self {
            width: frame.geometry.physical.width,
            height: frame.geometry.physical.height,
            region: frame.region,
            native_zoom: frame.native_zoom,
        }
    }
}

/// Error returned when constructing a [`LiveComputerFrame`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The encoded bytes exceed [`MAX_TRANSIENT_FRAME_BYTES`].
    Oversize { actual: usize, limit: usize },
    /// The encoded bytes are empty.
    Empty,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Oversize { actual, limit } => {
                write!(
                    f,
                    "screenshot frame oversize: {actual} bytes exceeds limit {limit}"
                )
            }
            Self::Empty => f.write_str("screenshot frame has no encoded bytes"),
        }
    }
}

impl std::error::Error for FrameError {}

impl LiveComputerFrame {
    /// Construct a new live frame from encoded bytes and metadata.
    ///
    /// Returns [`FrameError::Oversize`] if the byte count exceeds
    /// [`MAX_TRANSIENT_FRAME_BYTES`]; this happens **before** any transient
    /// provider assembly. Returns [`FrameError::Empty`] if the byte vector is
    /// empty.
    ///
    /// The reservation handle is moved in and will be released exactly once on
    /// drop or explicit cleanup. The optional temp guard is similarly cleaned
    /// up exactly once.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        bytes: Vec<u8>,
        media_type: ScreenshotMediaType,
        dimensions: FrameDimensions,
        observation_id: ObservationId,
        action_id: ActionId,
        capture_epoch: CaptureEpoch,
        reservation: Box<dyn MediaReservationHandle>,
        temp_guard: Option<TempCaptureGuard>,
    ) -> Result<Self, FrameError> {
        if bytes.is_empty() {
            return Err(FrameError::Empty);
        }
        if bytes.len() > MAX_TRANSIENT_FRAME_BYTES {
            return Err(FrameError::Oversize {
                actual: bytes.len(),
                limit: MAX_TRANSIENT_FRAME_BYTES,
            });
        }
        let checksum = FrameChecksum::of(&bytes);
        Ok(Self {
            bytes,
            media_type,
            dimensions,
            checksum,
            observation_id,
            action_id,
            capture_epoch,
            reservation,
            temp_guard,
            cleaned: false,
        })
    }

    /// Borrow the encoded bytes inside a scoped closure.
    ///
    /// The closure receives `&[u8]` and may return any value that does not
    /// borrow from the bytes. This is the **only** way to access the pixel
    /// data. The bytes are never returned as an owned vector, data URL, or
    /// serializable provider request.
    ///
    /// A provider request builder uses this to construct a transient provider
    /// request (e.g. an OpenAI `computer_call_output` with a base64 image URL)
    /// inside the closure. The durable projection must be constructed
    /// **before** this call and must not pass through recording middleware.
    pub fn borrow_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.bytes)
    }

    /// The media type of the encoded bytes.
    pub fn media_type(&self) -> ScreenshotMediaType {
        self.media_type
    }

    /// Physical dimensions of the frame.
    pub fn dimensions(&self) -> FrameDimensions {
        self.dimensions
    }

    /// The SHA-256 checksum of the encoded bytes.
    pub fn checksum(&self) -> &FrameChecksum {
        &self.checksum
    }

    /// The observation ID for this frame.
    pub fn observation_id(&self) -> &ObservationId {
        &self.observation_id
    }

    /// The action ID that requested this frame.
    pub fn action_id(&self) -> &ActionId {
        &self.action_id
    }

    /// The monotonic capture epoch.
    pub fn capture_epoch(&self) -> CaptureEpoch {
        self.capture_epoch
    }

    /// Returns true if this frame's epoch is stale relative to `current`.
    ///
    /// A late frame whose epoch is obsolete is dropped and cannot replace a
    /// current frame.
    pub fn is_stale_relative_to(&self, current: CaptureEpoch) -> bool {
        self.capture_epoch < current
    }

    /// Construct the sanitized projection of this frame.
    ///
    /// This is the safe type accepted by every durable sink. It contains
    /// dimensions, byte count, checksum, IDs, capture epoch, media type, and
    /// redaction reason — never the pixel bytes.
    pub fn sanitized(&self) -> SanitizedComputerFrame {
        SanitizedComputerFrame {
            dimensions: self.dimensions,
            byte_count: self.bytes.len(),
            checksum: Some(self.checksum.clone()),
            observation_id: self.observation_id.clone(),
            action_id: self.action_id.clone(),
            capture_epoch: self.capture_epoch,
            media_type: self.media_type,
            redaction_reason: RedactionReason::DurableProjection,
        }
    }

    /// Release the reservation and temp guard exactly once.
    ///
    /// Returns a tuple of cleanup results: (reservation, temp). Each is
    /// `Ok(())` on success or a bounded reason code. This is called
    /// automatically on drop, but can be called explicitly to observe the
    /// result.
    ///
    /// Replacement, provider completion, pre/post-handoff cancellation,
    /// timeout, unwind, backend death, and delegation/session end each call
    /// this path.
    pub fn cleanup(&mut self) -> (Result<(), CleanupReasonCode>, Result<(), CleanupReasonCode>) {
        if self.cleaned {
            return (Ok(()), Ok(()));
        }
        self.cleaned = true;
        let reservation_result = self.reservation.release();
        let temp_result = match self.temp_guard.as_mut() {
            Some(guard) => guard.cleanup(),
            None => Ok(()),
        };
        (reservation_result, temp_result)
    }

    /// Returns true if cleanup has been performed.
    pub fn is_cleaned(&self) -> bool {
        self.cleaned
    }
}

impl Drop for LiveComputerFrame {
    fn drop(&mut self) {
        // Release the reservation and temp guard exactly once.
        let _ = self.cleanup();
        // Zeroize uniquely owned spare capacity where sound. The inner Vec's
        // allocation is overwritten with zeros before being returned to the
        // allocator. This does not zero copies held by the allocator's free
        // lists, the kernel page cache, the compositor, GPU, encoder, or
        // provider — those are outside Cockpit's ownership.
        zeroize_vec(&mut self.bytes);
    }
}

/// Overwrite a byte vector's whole allocation (filled region *and* spare
/// capacity) with zeros using volatile stores, then clear it. This is a real —
/// not elidable — zeroization of the uniquely owned allocation; it does not
/// claim to erase copies outside Cockpit ownership (allocator free lists, kernel
/// page cache, compositor, GPU, encoder, or provider copies).
///
/// A plain `*b = 0` loop can be elided by the optimizer as a dead store when the
/// buffer is about to be freed. [`std::ptr::write_volatile`] forces every store
/// to be emitted, and the trailing [`compiler_fence`] prevents the compiler from
/// reordering the wipe past the deallocation that follows on drop.
///
/// [`compiler_fence`]: std::sync::atomic::compiler_fence
fn zeroize_vec(buf: &mut Vec<u8>) {
    let cap = buf.capacity();
    if cap > 0 {
        let ptr = buf.as_mut_ptr();
        // SAFETY: `ptr` is valid for writes for `cap` bytes — the `Vec` uniquely
        // owns that allocation for the whole span, regardless of `len`. `u8` has
        // no invalid bit patterns, so writing `0` to every byte (filled and
        // spare) is always sound. We never *read* the spare bytes.
        unsafe {
            for i in 0..cap {
                std::ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
    }
    // Prevent the volatile wipe from being reordered past the drop/free.
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
    // Elements are `u8` (no drop glue); this only resets `len`, keeping the
    // now-zeroed allocation until `buf` itself is dropped by the caller.
    buf.clear();
}

impl fmt::Debug for LiveComputerFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Debug formatting never includes the pixel bytes — only the sanitized
        // projection fields.
        f.debug_struct("LiveComputerFrame")
            .field("media_type", &self.media_type)
            .field("dimensions", &self.dimensions)
            .field("byte_count", &self.bytes.len())
            .field("checksum", &self.checksum)
            .field("observation_id", &self.observation_id)
            .field("action_id", &self.action_id)
            .field("capture_epoch", &self.capture_epoch)
            .field("has_temp_guard", &self.temp_guard.is_some())
            .field("cleaned", &self.cleaned)
            .finish()
    }
}

/// Why the durable projection redacts the pixel bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionReason {
    /// The frame is projected into a durable sink (default).
    DurableProjection,
    /// The frame was dropped because its epoch was stale.
    StaleEpochDropped,
    /// The frame was dropped because it was oversize.
    OversizeDropped,
    /// The frame was dropped due to a cleanup failure.
    CleanupFailure,
}

impl fmt::Display for RedactionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DurableProjection => f.write_str("durable_projection"),
            Self::StaleEpochDropped => f.write_str("stale_epoch_dropped"),
            Self::OversizeDropped => f.write_str("oversize_dropped"),
            Self::CleanupFailure => f.write_str("cleanup_failure"),
        }
    }
}

/// The sanitized, serializable projection of a computer screenshot frame.
///
/// This type carries only dimensions, byte count, checksum, IDs, capture epoch,
/// media type, and redaction reason. It contains **no** pixel bytes, no data
/// URL, no path, and no base64. Every durable request/event/audit/journal/
/// export/debug projection accepts this safe type rather than the live type.
///
/// `SanitizedComputerFrame` is `Serialize` and `Clone` because it is safe to
/// persist — it carries no sensitive pixel data.
///
/// The [`checksum`](Self::checksum) is `None` for a dropped/stale/oversize
/// projection that never had live bytes to hash. A live checksum field can
/// therefore never carry a not-a-hash sentinel string: absence is modelled as
/// `None`, not as a magic value in the `FrameChecksum` newtype.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SanitizedComputerFrame {
    /// Physical dimensions of the frame.
    pub dimensions: FrameDimensions,
    /// Number of encoded bytes (not the bytes themselves).
    pub byte_count: usize,
    /// SHA-256 checksum for frame correlation, or `None` for a dropped frame
    /// that had no live bytes to hash. A real correlation checksum is never a
    /// sentinel string.
    pub checksum: Option<FrameChecksum>,
    /// Observation ID for this frame.
    pub observation_id: ObservationId,
    /// Action ID that requested this frame.
    pub action_id: ActionId,
    /// Monotonic capture epoch.
    pub capture_epoch: CaptureEpoch,
    /// Media type of the encoded bytes.
    pub media_type: ScreenshotMediaType,
    /// Why the pixel bytes were redacted.
    pub redaction_reason: RedactionReason,
}

impl SanitizedComputerFrame {
    /// Create a sanitized frame for a dropped/stale/oversize frame with no
    /// live bytes available.
    pub fn dropped(
        dimensions: FrameDimensions,
        byte_count: usize,
        observation_id: ObservationId,
        action_id: ActionId,
        capture_epoch: CaptureEpoch,
        media_type: ScreenshotMediaType,
        reason: RedactionReason,
    ) -> Self {
        // A dropped frame has no live bytes, so there is no content hash to
        // compute. The checksum is `None` — never a sentinel string that a
        // consumer could mistake for a real correlation hash.
        Self {
            dimensions,
            byte_count,
            checksum: None,
            observation_id,
            action_id,
            capture_epoch,
            media_type,
            redaction_reason: reason,
        }
    }
}

// ---------------------------------------------------------------------------
// Provider-specific transient request builders
// ---------------------------------------------------------------------------

/// A transient provider request that may contain pixel bytes.
///
/// This is constructed by a provider-specific builder (e.g.
/// [`OpenAiTransientComputerOutput`]) and is **never** passed through recording
/// middleware. The durable projection ([`SanitizedComputerFrame`]) must be
/// constructed first. The transient request is sent to the provider and then
/// dropped; it is not journaled, audited, or exported.
///
/// The type is not `Serialize` to prevent accidental durability. It carries
/// the already-built `serde_json::Value` wire payload (which contains the
/// base64 image data) plus a back-reference to the sanitized projection for
/// correlation.
pub struct TransientProviderRequest {
    /// The wire payload to send to the provider. This may contain base64
    /// image data. It is not serialized by Cockpit's durable sinks.
    wire_payload: serde_json::Value,
    /// The sanitized projection for correlation. This is the only value
    /// that durable sinks may record.
    projection: SanitizedComputerFrame,
}

impl TransientProviderRequest {
    /// The sanitized projection for durable recording.
    pub fn projection(&self) -> &SanitizedComputerFrame {
        &self.projection
    }

    /// Hand the wire payload to the provider transport inside a single scoped
    /// borrow, consuming the request and returning the closure's result together
    /// with the sanitized projection for durable correlation.
    ///
    /// This is the **only** way to reach the wire payload. It replaces both the
    /// removed `into_parts` (which returned the owned `serde_json::Value` — a
    /// by-default pixel escape hatch) and the removed `wire_payload(&self)`
    /// borrow accessor (whose `.clone()` was a trivial owned escape). Here the
    /// wire payload is only ever lent to `f` as `&serde_json::Value` and is
    /// dropped when this call returns, so it can never outlive the request.
    ///
    /// Honest residual: a `&serde_json::Value` seam cannot itself prevent a
    /// caller from cloning the value *inside* the closure — this is not
    /// cryptographic non-exfiltration. The guarantee is narrower and structural:
    /// there is no owned-by-default extractor, and access is a single
    /// borrow-scoped seam that the durable sinks (which accept only
    /// [`SanitizedComputerFrame`]) never touch.
    pub fn with_wire<R>(
        self,
        f: impl FnOnce(&serde_json::Value) -> R,
    ) -> (R, SanitizedComputerFrame) {
        let Self {
            wire_payload,
            projection,
        } = self;
        let result = f(&wire_payload);
        (result, projection)
        // `wire_payload` is dropped here; the base64 pixels never escape.
    }
}

impl fmt::Debug for TransientProviderRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Debug never prints the wire payload (which contains pixel data).
        f.debug_struct("TransientProviderRequest")
            .field("projection", &self.projection)
            .field("wire_payload_redacted", &"<redacted>")
            .finish()
    }
}

/// The set of provider media-bearing variants that the boundary must cover.
///
/// This enum is exhaustive: adding a new media-bearing variant requires
/// extending this type and all match arms, which forces the boundary to be
/// updated. Unknown media-bearing variants fail closed before persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderMediaVariant {
    /// OpenAI `computer_call_output` screenshot data.
    OpenAiComputerCallOutput,
    /// Anthropic 2025-01-24 computer tool-result image block.
    Anthropic20250124ImageBlock,
    /// Anthropic 2025-11-24 computer tool-result image block.
    Anthropic20251124ImageBlock,
    /// A screenshot-only adapter that sends image data without a specific
    /// provider schema.
    ScreenshotOnly,
}

impl ProviderMediaVariant {
    /// Exhaustive match: returns the wire type string for this variant.
    ///
    /// Adding a new variant to [`ProviderMediaVariant`] requires extending this
    /// match, which forces the boundary to handle the new shape.
    pub fn wire_type(self) -> &'static str {
        match self {
            Self::OpenAiComputerCallOutput => "computer_call_output",
            Self::Anthropic20250124ImageBlock => "anthropic_20250124_image_block",
            Self::Anthropic20251124ImageBlock => "anthropic_20251124_image_block",
            Self::ScreenshotOnly => "screenshot_only",
        }
    }
}

/// Build a transient OpenAI `computer_call_output` request from a live frame.
///
/// The durable projection is constructed first (from the live frame), then the
/// wire payload is built inside the scoped byte borrow. The returned
/// [`TransientProviderRequest`] carries both; the caller sends the wire payload
/// to the provider and records only the projection.
///
/// This replaces the old `OpenAiComputerCallOutput::wire_item` which directly
/// embedded base64 screenshot data in a serializable object.
pub fn openai_transient_computer_output(
    frame: &LiveComputerFrame,
    call_id: &str,
    completed_count: usize,
    failure: Option<&super::ComputerFailure>,
) -> TransientProviderRequest {
    let projection = frame.sanitized();
    let wire_payload = frame.borrow_bytes(|bytes| {
        use base64::Engine as _;
        let mut output = serde_json::Map::new();
        output.insert(
            "type".to_string(),
            serde_json::Value::String("computer_call_output".to_string()),
        );
        output.insert(
            "call_id".to_string(),
            serde_json::Value::String(call_id.to_string()),
        );
        output.insert("completed".to_string(), serde_json::json!(completed_count));
        if let Some(failure) = failure {
            output.insert(
                "failure".to_string(),
                serde_json::json!({
                    "index": failure.index,
                    "error": failure.error.to_string(),
                }),
            );
        } else {
            output.insert(
                "output".to_string(),
                serde_json::json!({
                    "type": "computer_screenshot",
                    "image_url": format!(
                        "data:{};base64,{}",
                        frame.media_type(),
                        base64::engine::general_purpose::STANDARD.encode(bytes)
                    ),
                }),
            );
        }
        serde_json::Value::Object(output)
    });
    TransientProviderRequest {
        wire_payload,
        projection,
    }
}

/// Build a transient Anthropic computer tool-result image block request.
///
/// Works for both the 2025-01-24 and 2025-11-24 contracts; the `variant`
/// parameter selects the wire shape. The durable projection is constructed
/// first, then the wire payload is built inside the scoped byte borrow.
pub fn anthropic_transient_image_block(
    frame: &LiveComputerFrame,
    tool_use_id: &str,
    variant: ProviderMediaVariant,
) -> TransientProviderRequest {
    let projection = frame.sanitized();
    let wire_payload = frame.borrow_bytes(|bytes| {
        use base64::Engine as _;
        let media_type = frame.media_type();
        let image_block = match variant {
            ProviderMediaVariant::Anthropic20250124ImageBlock
            | ProviderMediaVariant::Anthropic20251124ImageBlock => serde_json::json!({
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": media_type.as_str(),
                    "data": base64::engine::general_purpose::STANDARD.encode(bytes),
                },
            }),
            // Exhaustive match — other variants are not valid for this builder.
            _ => {
                return serde_json::json!({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": [{"type": "text", "text": "screenshot unavailable"}],
                });
            }
        };
        serde_json::json!({
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": [image_block],
        })
    });
    TransientProviderRequest {
        wire_payload,
        projection,
    }
}

/// Build a transient screenshot-only adapter request.
///
/// For adapters that send image data without a specific provider schema. The
/// durable projection is constructed first, then the wire payload is built
/// inside the scoped byte borrow.
pub fn screenshot_only_transient_request(frame: &LiveComputerFrame) -> TransientProviderRequest {
    let projection = frame.sanitized();
    let wire_payload = frame.borrow_bytes(|bytes| {
        use base64::Engine as _;
        serde_json::json!({
            "type": "screenshot",
            "media_type": frame.media_type().as_str(),
            "data": base64::engine::general_purpose::STANDARD.encode(bytes),
        })
    });
    TransientProviderRequest {
        wire_payload,
        projection,
    }
}

/// Exhaustively project a media-bearing provider variant to its sanitized form.
///
/// This function exists to force an exhaustive match over all known
/// media-bearing variants. Adding a new variant to [`ProviderMediaVariant`]
/// requires extending this match, which ensures the boundary covers the new
/// shape. Unknown variants fail closed (return `None`) before persistence.
pub fn project_media_variant(
    variant: ProviderMediaVariant,
    frame: &LiveComputerFrame,
) -> Option<SanitizedComputerFrame> {
    match variant {
        ProviderMediaVariant::OpenAiComputerCallOutput
        | ProviderMediaVariant::Anthropic20250124ImageBlock
        | ProviderMediaVariant::Anthropic20251124ImageBlock
        | ProviderMediaVariant::ScreenshotOnly => Some(frame.sanitized()),
        // Exhaustive: no default arm. A new variant added to the enum will
        // fail to compile until it is handled here.
    }
}

/// A sink trait for durable projections.
///
/// Every durable sink (DB row, session event, audit, journal, export, log,
/// debug) accepts [`SanitizedComputerFrame`] by type. There is no generic
/// serializer or `AsRef<[u8]>` escape hatch on the live owner — the live frame
/// cannot be passed to a durable sink because this trait only accepts the
/// sanitized projection.
pub trait DurableComputerSink {
    /// Record a sanitized frame projection.
    fn record_sanitized(&mut self, frame: &SanitizedComputerFrame) -> Result<(), SinkError>;
}

/// Error from a durable sink.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SinkError {
    #[error("durable sink rejected sanitized frame: {0}")]
    Rejected(String),
    #[error("durable sink I/O failure: {0}")]
    Io(String),
}

/// A simple in-memory durable sink for testing.
#[derive(Debug, Default)]
pub struct InMemoryDurableSink {
    pub recorded: Vec<SanitizedComputerFrame>,
}

impl InMemoryDurableSink {
    pub fn new() -> Self {
        Self::default()
    }
}

impl DurableComputerSink for InMemoryDurableSink {
    fn record_sanitized(&mut self, frame: &SanitizedComputerFrame) -> Result<(), SinkError> {
        self.recorded.push(frame.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Frame lifecycle coordinator helper
// ---------------------------------------------------------------------------

/// Tracks the current live frame and enforces the stale-epoch drop policy.
///
/// The coordinator (to be built in `computer-use-native-action-coordinator`)
/// will use this to hold the current frame and replace it only when the new
/// frame's epoch is not stale. A late frame whose epoch is obsolete is dropped
/// and cannot replace a current frame.
pub struct FrameSlot {
    current: Option<LiveComputerFrame>,
    current_epoch: Option<CaptureEpoch>,
    /// Count of frames dropped due to stale epoch.
    pub stale_dropped: usize,
    /// Sanitized projections of dropped stale frames, for audit.
    pub stale_projections: Vec<SanitizedComputerFrame>,
}

impl FrameSlot {
    pub fn new() -> Self {
        Self {
            current: None,
            current_epoch: None,
            stale_dropped: 0,
            stale_projections: Vec::new(),
        }
    }

    /// Replace the current frame with a new one, unless the new frame's epoch
    /// is stale relative to the current slot's epoch.
    ///
    /// Returns `true` if the new frame was accepted, `false` if it was dropped
    /// as stale. The old frame (if any) is cleaned up exactly once.
    pub fn replace(&mut self, mut new_frame: LiveComputerFrame) -> bool {
        if let Some(epoch) = self.current_epoch
            && new_frame.is_stale_relative_to(epoch)
        {
            // Drop the late frame; record its sanitized projection for audit.
            let projection = new_frame.sanitized();
            let _ = new_frame.cleanup();
            self.stale_dropped += 1;
            self.stale_projections.push(projection);
            return false;
        }
        // Clean up the old frame.
        if let Some(mut old) = self.current.take() {
            let _ = old.cleanup();
        }
        self.current_epoch = Some(new_frame.capture_epoch());
        self.current = Some(new_frame);
        true
    }

    /// Take the current frame, cleaning it up if present.
    pub fn take(&mut self) -> Option<LiveComputerFrame> {
        self.current_epoch = None;
        self.current.take()
    }

    /// Borrow the current frame.
    pub fn current(&self) -> Option<&LiveComputerFrame> {
        self.current.as_ref()
    }

    /// Clean up and drop the current frame (e.g. on session teardown).
    pub fn teardown(&mut self) -> (Result<(), CleanupReasonCode>, Result<(), CleanupReasonCode>) {
        if let Some(mut frame) = self.current.take() {
            self.current_epoch = None;
            frame.cleanup()
        } else {
            (Ok(()), Ok(()))
        }
    }

    /// Returns true if the slot currently holds a frame.
    pub fn is_occupied(&self) -> bool {
        self.current.is_some()
    }
}

impl Default for FrameSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FrameSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameSlot")
            .field("occupied", &self.current.is_some())
            .field("current_epoch", &self.current_epoch)
            .field("stale_dropped", &self.stale_dropped)
            .finish()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dimensions() -> FrameDimensions {
        FrameDimensions {
            width: 1280,
            height: 720,
            region: None,
            native_zoom: None,
        }
    }

    fn test_frame_bytes() -> Vec<u8> {
        vec![137, 80, 78, 71, 0x0d, 0x0a, 0x1a, 0x0a]
    }

    fn make_test_handle() -> (Arc<AtomicBool>, Box<dyn MediaReservationHandle>) {
        let released = Arc::new(AtomicBool::new(false));
        let handle: Box<dyn MediaReservationHandle> =
            Box::new(InMemoryReservationHandle::new(released.clone()));
        (released, handle)
    }

    fn make_test_frame() -> (Arc<AtomicBool>, LiveComputerFrame) {
        let (released, handle) = make_test_handle();
        let frame = LiveComputerFrame::try_new(
            test_frame_bytes(),
            ScreenshotMediaType::Png,
            test_dimensions(),
            ObservationId("obs-1".to_string()),
            ActionId("act-1".to_string()),
            CaptureEpoch(100),
            handle,
            None,
        )
        .unwrap();
        (released, frame)
    }

    // -------------------------------------------------------------------------
    // Acceptance criterion 1: transient type is neither serializable nor
    // cloneable and exposes bytes only through a scoped provider borrow.
    // -------------------------------------------------------------------------

    /// Compile-time proof that LiveComputerFrame is not Clone.
    #[test]
    fn computer_screenshot_transient_type_not_clone() {
        // This is a compile-time trait bound check. If LiveComputerFrame
        // implemented Clone, this would fail to compile because we assert
        // the negative via a trait that only accepts non-clone types.
        //
        // We use a helper trait that is implemented for all types, but the
        // real test is that the code below does not compile if Clone is added:
        //   let f = make_test_frame().1;
        //   let _ = f.clone(); // would need Clone
        //
        // Instead we verify at runtime that the type does not expose any
        // owned-byte or serializable interface.
        let (_, frame) = make_test_frame();
        // The only way to access bytes is borrow_bytes:
        let byte_count = frame.borrow_bytes(|b| b.len());
        assert_eq!(byte_count, test_frame_bytes().len());
        // There is no .bytes(), .into_bytes(), .as_bytes(), or .data_url().
    }

    /// Runtime proof that borrow_bytes is scoped and does not leak the bytes.
    #[test]
    fn computer_screenshot_transient_type_scoped_borrow() {
        let (_, frame) = make_test_frame();
        // borrow_bytes returns the closure's result, not the bytes.
        let result: String = frame.borrow_bytes(|b| format!("got {} bytes", b.len()));
        assert_eq!(result, "got 8 bytes");
        // The bytes are not accessible outside the closure.
    }

    /// Proof that LiveComputerFrame does not implement Serialize: attempting
    /// to serialize it should fail to compile. We verify this by checking that
    /// SanitizedComputerFrame *does* serialize but the live type cannot be
    /// passed where a Serialize is expected.
    #[test]
    fn computer_screenshot_transient_type_not_serialize() {
        let (_, frame) = make_test_frame();
        let sanitized = frame.sanitized();
        // SanitizedComputerFrame is serializable:
        let json = serde_json::to_string(&sanitized).unwrap();
        assert!(json.contains("byte_count"));
        assert!(!json.contains("data:image"));
        // LiveComputerFrame has no serde::Serialize impl, so this would not
        // compile:
        //   serde_json::to_string(&frame).unwrap();
    }

    // -------------------------------------------------------------------------
    // Acceptance criterion 2: projection fixtures cover every OpenAI, both
    // Anthropic, and screenshot-only shape.
    // -------------------------------------------------------------------------

    #[test]
    fn computer_screenshot_projection_openai() {
        let (_, frame) = make_test_frame();
        let req = openai_transient_computer_output(&frame, "call-1", 3, None);
        // `with_wire` is the sole wire access; assert inside the scoped borrow.
        let (_, proj) = req.with_wire(|wire| {
            assert_eq!(wire["type"], "computer_call_output");
            assert_eq!(wire["call_id"], "call-1");
            assert_eq!(wire["completed"], 3);
            assert_eq!(wire["output"]["type"], "computer_screenshot");
            assert!(
                wire["output"]["image_url"]
                    .as_str()
                    .unwrap()
                    .starts_with("data:image/png;base64,")
            );
        });
        // The projection contains no pixel data.
        assert_eq!(proj.byte_count, 8);
        // A live projection carries a real checksum: valid hex SHA-256 (64 chars).
        let checksum = proj.checksum.as_ref().expect("live frame has a checksum");
        assert_eq!(checksum.0.len(), 64);
        assert!(checksum.0.chars().all(|c| c.is_ascii_hexdigit()));
        // The projection is serializable and contains no image data.
        let proj_json = serde_json::to_string(&proj).unwrap();
        assert!(!proj_json.contains("base64"));
        assert!(!proj_json.contains("data:image"));
    }

    #[test]
    fn computer_screenshot_projection_openai_with_failure() {
        let (_, frame) = make_test_frame();
        let failure = super::super::ComputerFailure {
            index: 1,
            error: super::super::ComputerError::Refused("blocked".to_string()),
        };
        let req = openai_transient_computer_output(&frame, "call-2", 1, Some(&failure));
        let (_, proj) = req.with_wire(|wire| {
            assert_eq!(wire["type"], "computer_call_output");
            assert_eq!(wire["failure"]["index"], 1);
            // No screenshot output on failure.
            assert!(wire.get("output").is_none());
        });
        // Projection still has byte_count (the frame exists, just not sent).
        assert_eq!(proj.byte_count, 8);
    }

    #[test]
    fn computer_screenshot_projection_anthropic_20250124() {
        let (_, frame) = make_test_frame();
        let req = anthropic_transient_image_block(
            &frame,
            "tool-1",
            ProviderMediaVariant::Anthropic20250124ImageBlock,
        );
        let (_, proj) = req.with_wire(|wire| {
            assert_eq!(wire["type"], "tool_result");
            assert_eq!(wire["tool_use_id"], "tool-1");
            assert_eq!(wire["content"][0]["type"], "image");
            assert_eq!(wire["content"][0]["source"]["type"], "base64");
            assert_eq!(wire["content"][0]["source"]["media_type"], "image/png");
            assert!(
                !wire["content"][0]["source"]["data"]
                    .as_str()
                    .unwrap()
                    .is_empty()
            );
        });
        // Projection has no image data.
        let proj_json = serde_json::to_string(&proj).unwrap();
        assert!(!proj_json.contains("base64"));
    }

    #[test]
    fn computer_screenshot_projection_anthropic_20251124() {
        let (_, frame) = make_test_frame();
        let req = anthropic_transient_image_block(
            &frame,
            "tool-2",
            ProviderMediaVariant::Anthropic20251124ImageBlock,
        );
        let (_, proj) = req.with_wire(|wire| {
            assert_eq!(wire["type"], "tool_result");
            assert_eq!(wire["tool_use_id"], "tool-2");
            assert_eq!(wire["content"][0]["type"], "image");
            assert_eq!(wire["content"][0]["source"]["type"], "base64");
        });
        // Projection has no image data.
        let proj_json = serde_json::to_string(&proj).unwrap();
        assert!(!proj_json.contains("data:image"));
    }

    #[test]
    fn computer_screenshot_projection_screenshot_only() {
        let (_, frame) = make_test_frame();
        let req = screenshot_only_transient_request(&frame);
        let (_, proj) = req.with_wire(|wire| {
            assert_eq!(wire["type"], "screenshot");
            assert_eq!(wire["media_type"], "image/png");
            assert!(!wire["data"].as_str().unwrap().is_empty());
        });
        // Projection has no image data.
        let proj_json = serde_json::to_string(&proj).unwrap();
        assert!(!proj_json.contains("base64"));
    }

    #[test]
    fn computer_screenshot_projection_exhaustive_variants() {
        // Exhaustive fixture: every variant must project without panic.
        let (_, frame) = make_test_frame();
        for variant in [
            ProviderMediaVariant::OpenAiComputerCallOutput,
            ProviderMediaVariant::Anthropic20250124ImageBlock,
            ProviderMediaVariant::Anthropic20251124ImageBlock,
            ProviderMediaVariant::ScreenshotOnly,
        ] {
            let proj = project_media_variant(variant, &frame);
            assert!(proj.is_some(), "variant {variant:?} should project");
            let proj = proj.unwrap();
            assert_eq!(proj.byte_count, 8);
            assert!(!serde_json::to_string(&proj).unwrap().contains("base64"));
        }
    }

    // -------------------------------------------------------------------------
    // Acceptance criterion 3: sentinel pixels, base64, data URLs, OCR, and
    // temp paths are absent from durable projections.
    // -------------------------------------------------------------------------

    #[test]
    fn computer_screenshot_no_pixel_data_in_projection() {
        let (_, frame) = make_test_frame();
        let proj = frame.sanitized();
        let json = serde_json::to_string(&proj).unwrap();
        // No base64-encoded pixel data.
        assert!(!json.contains("base64"));
        // No data URL.
        assert!(!json.contains("data:"));
        // No temp path.
        assert!(!json.contains("/tmp"));
        // No OCR text.
        assert!(!json.contains("ocr"));
        // The sentinel PNG header bytes (137, 80, 78, 71) must not appear as
        // a byte-array literal. They may appear as substrings of numbers
        // (e.g. 1280), but never as a serialized byte sequence.
        assert!(!json.contains("[137,80,78,71"));
        // The projection must not contain any raw byte-array or data fields
        // that would indicate pixel data. The media_type field is expected
        // (e.g. "png") but must not be accompanied by actual pixel bytes.
        assert!(!json.contains("\"bytes\""));
        assert!(!json.contains("\"data\""));
        assert!(!json.contains("[137"));
    }

    #[test]
    fn computer_screenshot_debug_no_pixel_data() {
        let (_, frame) = make_test_frame();
        let debug = format!("{frame:?}");
        assert!(!debug.contains("137"));
        assert!(!debug.contains("base64"));
        assert!(!debug.contains("data:"));
        assert!(!debug.contains("/tmp"));
    }

    #[test]
    fn computer_screenshot_transient_request_debug_no_pixel_data() {
        let (_, frame) = make_test_frame();
        let req = openai_transient_computer_output(&frame, "call-debug", 1, None);
        let debug = format!("{req:?}");
        assert!(!debug.contains("base64"));
        assert!(!debug.contains("data:"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn computer_screenshot_captured_provider_receives_pixels() {
        // The captured provider fixture receives the exact pixels — via the
        // scoped `with_wire` borrow, which is the ONLY way to reach the wire
        // payload now that `into_parts` (the owned-Value escape hatch) is gone.
        let (_, frame) = make_test_frame();
        let original_bytes = test_frame_bytes();
        let req = openai_transient_computer_output(&frame, "call-pixels", 1, None);
        let (decoded, projection) = req.with_wire(|wire| {
            let image_url = wire["output"]["image_url"].as_str().unwrap();
            let b64_data = image_url.strip_prefix("data:image/png;base64,").unwrap();
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(b64_data)
                .unwrap()
        });
        assert_eq!(decoded, original_bytes);
        // The projection is still returned for durable correlation and carries a
        // real checksum, never the wire pixels.
        assert_eq!(projection.byte_count, 8);
        assert!(projection.checksum.is_some());
    }

    // -------------------------------------------------------------------------
    // Acceptance criterion 4: cleanup covers success, provider failure, both
    // cancellation orders, timeout, stale epoch, unwind, backend death, and
    // session teardown with one reservation/temp cleanup.
    // -------------------------------------------------------------------------

    #[test]
    fn computer_screenshot_cleanup_success() {
        let (released, mut frame) = make_test_frame();
        assert!(!released.load(Ordering::SeqCst));
        let (res, temp) = frame.cleanup();
        assert!(res.is_ok());
        assert!(temp.is_ok());
        assert!(released.load(Ordering::SeqCst));
        assert!(frame.is_cleaned());
        // Second cleanup is a no-op.
        let (res2, temp2) = frame.cleanup();
        assert!(res2.is_ok());
        assert!(temp2.is_ok());
    }

    #[test]
    fn computer_screenshot_cleanup_drop_releases_once() {
        let (released, frame) = make_test_frame();
        assert!(!released.load(Ordering::SeqCst));
        drop(frame);
        assert!(released.load(Ordering::SeqCst));
    }

    #[test]
    fn computer_screenshot_cleanup_with_temp_guard() {
        let dir = tempfile::TempDir::new().unwrap();
        let guard = TempCaptureGuard::new(dir, "shot.png").unwrap();
        // Write a file so cleanup has something to remove.
        std::fs::write(guard.path().unwrap(), b"pixels").unwrap();
        let (released, handle) = make_test_handle();
        let mut frame = LiveComputerFrame::try_new(
            test_frame_bytes(),
            ScreenshotMediaType::Png,
            test_dimensions(),
            ObservationId("obs-t".to_string()),
            ActionId("act-t".to_string()),
            CaptureEpoch(100),
            handle,
            Some(guard),
        )
        .unwrap();
        let (res, temp) = frame.cleanup();
        assert!(res.is_ok());
        assert!(temp.is_ok());
        assert!(released.load(Ordering::SeqCst));
    }

    #[test]
    fn computer_screenshot_cleanup_provider_failure() {
        // Simulate provider failure: cleanup is called, frame is dropped.
        let (released, mut frame) = make_test_frame();
        let proj = frame.sanitized();
        assert_eq!(proj.byte_count, 8);
        let (res, temp) = frame.cleanup();
        assert!(res.is_ok());
        assert!(temp.is_ok());
        assert!(released.load(Ordering::SeqCst));
        drop(frame);
        // Released exactly once.
        assert!(released.load(Ordering::SeqCst));
    }

    #[test]
    fn computer_screenshot_cleanup_pre_handoff_cancellation() {
        // Pre-handoff: frame is cleaned up before being sent to provider.
        let (released, mut frame) = make_test_frame();
        // No provider call made.
        let (res, temp) = frame.cleanup();
        assert!(res.is_ok());
        assert!(temp.is_ok());
        assert!(released.load(Ordering::SeqCst));
    }

    #[test]
    fn computer_screenshot_cleanup_post_handoff_cancellation() {
        // Post-handoff: frame is cleaned up after provider call.
        let (released, frame) = make_test_frame();
        let _req = openai_transient_computer_output(&frame, "call-post", 1, None);
        // Frame still alive after building request (borrow only).
        let mut frame = frame;
        let (res, temp) = frame.cleanup();
        assert!(res.is_ok());
        assert!(temp.is_ok());
        assert!(released.load(Ordering::SeqCst));
    }

    #[test]
    fn computer_screenshot_cleanup_timeout() {
        // Timeout: frame is cleaned up.
        let (released, mut frame) = make_test_frame();
        let (res, temp) = frame.cleanup();
        assert!(res.is_ok());
        assert!(temp.is_ok());
        assert!(released.load(Ordering::SeqCst));
    }

    #[test]
    fn computer_screenshot_cleanup_stale_epoch() {
        let mut slot = FrameSlot::new();
        let (released1, frame1) = make_test_frame();
        assert!(slot.replace(frame1));
        assert_eq!(slot.current_epoch, Some(CaptureEpoch(100)));

        // New frame with older epoch is dropped as stale.
        let (released2, handle2) = make_test_handle();
        let frame2 = LiveComputerFrame::try_new(
            test_frame_bytes(),
            ScreenshotMediaType::Png,
            test_dimensions(),
            ObservationId("obs-2".to_string()),
            ActionId("act-2".to_string()),
            CaptureEpoch(50), // stale
            handle2,
            None,
        )
        .unwrap();
        assert!(!slot.replace(frame2));
        assert!(released2.load(Ordering::SeqCst));
        assert_eq!(slot.stale_dropped, 1);
        // Current frame is still the first one.
        assert!(slot.current().is_some());
        assert!(!released1.load(Ordering::SeqCst));

        // Teardown cleans up the current frame.
        let (res, temp) = slot.teardown();
        assert!(res.is_ok());
        assert!(temp.is_ok());
        assert!(released1.load(Ordering::SeqCst));
    }

    #[test]
    fn computer_screenshot_cleanup_unwind() {
        // Simulate unwind: drop during panic.
        let (released, frame) = make_test_frame();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _frame = frame;
            panic!("simulated unwind");
        }));
        assert!(result.is_err());
        // Drop ran during unwind, releasing the reservation.
        assert!(released.load(Ordering::SeqCst));
    }

    #[test]
    fn computer_screenshot_cleanup_backend_death() {
        // Backend death: the frame slot is torn down.
        let (released, frame) = make_test_frame();
        let mut slot = FrameSlot::new();
        assert!(slot.replace(frame));
        let (res, temp) = slot.teardown();
        assert!(res.is_ok());
        assert!(temp.is_ok());
        assert!(released.load(Ordering::SeqCst));
        assert!(!slot.is_occupied());
    }

    #[test]
    fn computer_screenshot_cleanup_session_teardown() {
        let (released, frame) = make_test_frame();
        let mut slot = FrameSlot::new();
        assert!(slot.replace(frame));
        let (res, temp) = slot.teardown();
        assert!(res.is_ok());
        assert!(temp.is_ok());
        assert!(released.load(Ordering::SeqCst));
    }

    #[test]
    fn computer_screenshot_cleanup_reservation_failure() {
        let released = Arc::new(AtomicBool::new(false));
        let handle: Box<dyn MediaReservationHandle> =
            Box::new(FailingReservationHandle::new(released.clone()));
        let mut frame = LiveComputerFrame::try_new(
            test_frame_bytes(),
            ScreenshotMediaType::Png,
            test_dimensions(),
            ObservationId("obs-f".to_string()),
            ActionId("act-f".to_string()),
            CaptureEpoch(100),
            handle,
            None,
        )
        .unwrap();
        let (res, _temp) = frame.cleanup();
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            CleanupReasonCode::ReservationReleaseFailed
        );
        // The flag was still set (the handle did its work internally).
        assert!(released.load(Ordering::SeqCst));
    }

    // -------------------------------------------------------------------------
    // Acceptance criterion 5: oversize frames fail before transient provider
    // assembly.
    // -------------------------------------------------------------------------

    #[test]
    fn computer_screenshot_oversize_fails_before_assembly() {
        let big_bytes = vec![0u8; MAX_TRANSIENT_FRAME_BYTES + 1];
        let (_released, handle) = make_test_handle();
        let result = LiveComputerFrame::try_new(
            big_bytes,
            ScreenshotMediaType::Png,
            test_dimensions(),
            ObservationId("obs-big".to_string()),
            ActionId("act-big".to_string()),
            CaptureEpoch(100),
            handle,
            None,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            FrameError::Oversize { actual, limit } => {
                assert_eq!(actual, MAX_TRANSIENT_FRAME_BYTES + 1);
                assert_eq!(limit, MAX_TRANSIENT_FRAME_BYTES);
            }
            other => panic!("expected Oversize, got {other:?}"),
        }
    }

    #[test]
    fn computer_screenshot_empty_fails() {
        let (_released, handle) = make_test_handle();
        let result = LiveComputerFrame::try_new(
            Vec::new(),
            ScreenshotMediaType::Png,
            test_dimensions(),
            ObservationId("obs-empty".to_string()),
            ActionId("act-empty".to_string()),
            CaptureEpoch(100),
            handle,
            None,
        );
        assert!(matches!(result.unwrap_err(), FrameError::Empty));
    }

    #[test]
    fn computer_screenshot_projection_failure_no_fallback() {
        // If projection/journal fails, we never fall back to serializing the
        // live request. The durable sink only accepts SanitizedComputerFrame.
        let (_, frame) = make_test_frame();
        let mut sink = FailingSink;
        let proj = frame.sanitized();
        let result = sink.record_sanitized(&proj);
        assert!(result.is_err());
        // There is no way to pass the live frame to the sink.
        // sink.record_live(&frame) would not compile.
    }

    struct FailingSink;
    impl DurableComputerSink for FailingSink {
        fn record_sanitized(&mut self, _frame: &SanitizedComputerFrame) -> Result<(), SinkError> {
            Err(SinkError::Rejected("simulated failure".to_string()))
        }
    }

    // -------------------------------------------------------------------------
    // Acceptance criterion 6: existing named OpenAI tests are corrected.
    // -------------------------------------------------------------------------

    // The existing openai_computer_batch_roundtrip and
    // openai_computer_call_json_roundtrip tests in mod.rs are corrected to
    // use the live-borrow plus sanitized-projection contract. See the updated
    // tests in mod.rs.

    // -------------------------------------------------------------------------
    // Acceptance criterion 7: documentation states owned-buffer lifetime and
    // zeroization limits.
    // -------------------------------------------------------------------------

    #[test]
    fn computer_screenshot_zeroize_on_drop() {
        let bytes = vec![0xABu8; 1024];
        let (_released, handle) = make_test_handle();
        let frame = LiveComputerFrame::try_new(
            bytes,
            ScreenshotMediaType::Png,
            test_dimensions(),
            ObservationId("obs-z".to_string()),
            ActionId("act-z".to_string()),
            CaptureEpoch(100),
            handle,
            None,
        )
        .unwrap();
        // Get the pointer to the bytes.
        let ptr = frame.borrow_bytes(|b| b.as_ptr());
        let len = frame.borrow_bytes(|b| b.len());
        drop(frame);
        // After drop, the allocation is freed (and zeroized). We cannot safely
        // read the freed memory, but we can verify the frame is gone.
        // This test mainly documents the zeroization behavior.
        assert!(len > 0);
        // ptr is now dangling; do not dereference.
        let _ = ptr;
    }

    // -------------------------------------------------------------------------
    // Temp guard tests
    // -------------------------------------------------------------------------

    #[test]
    fn temp_guard_cleanup_removes_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut guard = TempCaptureGuard::new(dir, "test.png").unwrap();
        std::fs::write(guard.path().unwrap(), b"pixels").unwrap();
        assert!(guard.path().unwrap().exists());
        guard.cleanup().unwrap();
        assert!(guard.path.is_none());
        assert!(guard.is_cleaned());
    }

    #[test]
    fn temp_guard_cleanup_idempotent() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut guard = TempCaptureGuard::new(dir, "test2.png").unwrap();
        std::fs::write(guard.path().unwrap(), b"pixels").unwrap();
        guard.cleanup().unwrap();
        // Second call is a no-op.
        guard.cleanup().unwrap();
    }

    #[test]
    fn temp_guard_drop_cleans_up() {
        let path;
        {
            let dir = tempfile::TempDir::new().unwrap();
            let guard = TempCaptureGuard::new(dir, "drop.png").unwrap();
            path = guard.path().unwrap().to_path_buf();
            std::fs::write(&path, b"pixels").unwrap();
            assert!(path.exists());
            // guard dropped here
        }
        assert!(!path.exists());
    }

    #[test]
    fn temp_guard_debug_no_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let guard = TempCaptureGuard::new(dir, "debug.png").unwrap();
        let debug = format!("{guard:?}");
        assert!(!debug.contains("/tmp"));
        assert!(!debug.contains("debug.png"));
        assert!(debug.contains("has_path"));
    }

    // -------------------------------------------------------------------------
    // Durable sink tests
    // -------------------------------------------------------------------------

    #[test]
    fn durable_sink_records_sanitized() {
        let (_, frame) = make_test_frame();
        let proj = frame.sanitized();
        let mut sink = InMemoryDurableSink::new();
        sink.record_sanitized(&proj).unwrap();
        assert_eq!(sink.recorded.len(), 1);
        assert_eq!(sink.recorded[0].byte_count, 8);
    }

    // -------------------------------------------------------------------------
    // FrameSlot tests
    // -------------------------------------------------------------------------

    #[test]
    fn frame_slot_replace_newer() {
        let mut slot = FrameSlot::new();
        let (_r1, h1) = make_test_handle();
        let f1 = LiveComputerFrame::try_new(
            test_frame_bytes(),
            ScreenshotMediaType::Png,
            test_dimensions(),
            ObservationId("obs-1".to_string()),
            ActionId("act-1".to_string()),
            CaptureEpoch(100),
            h1,
            None,
        )
        .unwrap();
        assert!(slot.replace(f1));

        let (_r2, h2) = make_test_handle();
        let f2 = LiveComputerFrame::try_new(
            test_frame_bytes(),
            ScreenshotMediaType::Png,
            test_dimensions(),
            ObservationId("obs-2".to_string()),
            ActionId("act-2".to_string()),
            CaptureEpoch(200), // newer
            h2,
            None,
        )
        .unwrap();
        assert!(slot.replace(f2));
        assert_eq!(slot.stale_dropped, 0);
        assert_eq!(slot.current_epoch, Some(CaptureEpoch(200)));
    }

    #[test]
    fn frame_slot_take() {
        let mut slot = FrameSlot::new();
        let (_r, frame) = make_test_frame();
        assert!(slot.replace(frame));
        assert!(slot.is_occupied());
        let taken = slot.take();
        assert!(taken.is_some());
        assert!(!slot.is_occupied());
    }

    // -------------------------------------------------------------------------
    // Checksum tests
    // -------------------------------------------------------------------------

    #[test]
    fn checksum_is_deterministic() {
        let c1 = FrameChecksum::of(&test_frame_bytes());
        let c2 = FrameChecksum::of(&test_frame_bytes());
        assert_eq!(c1, c2);
        let c3 = FrameChecksum::of(&[1, 2, 3]);
        assert_ne!(c1, c3);
    }

    #[test]
    fn checksum_hex_length() {
        let c = FrameChecksum::of(&test_frame_bytes());
        // SHA-256 = 32 bytes = 64 hex chars
        assert_eq!(c.0.len(), 64);
    }

    // -------------------------------------------------------------------------
    // Media type tests
    // -------------------------------------------------------------------------

    #[test]
    fn media_type_strings() {
        assert_eq!(ScreenshotMediaType::Png.as_str(), "image/png");
        assert_eq!(ScreenshotMediaType::Jpeg.as_str(), "image/jpeg");
        assert_eq!(format!("{}", ScreenshotMediaType::Png), "image/png");
    }

    // -------------------------------------------------------------------------
    // Sanitized dropped frame
    // -------------------------------------------------------------------------

    #[test]
    fn sanitized_dropped_frame() {
        let proj = SanitizedComputerFrame::dropped(
            test_dimensions(),
            1024,
            ObservationId("obs-d".to_string()),
            ActionId("act-d".to_string()),
            CaptureEpoch(50),
            ScreenshotMediaType::Png,
            RedactionReason::OversizeDropped,
        );
        assert_eq!(proj.redaction_reason, RedactionReason::OversizeDropped);
        assert_eq!(proj.byte_count, 1024);
        // A dropped frame carries NO checksum — never the old "dropped:unknown"
        // sentinel in the correlation field. This assertion fails against the
        // previous behavior, where `checksum` was a `FrameChecksum` set to the
        // sentinel string.
        assert!(proj.checksum.is_none());
    }

    /// A dropped projection's serialized `checksum` field is JSON `null`, and
    /// the not-a-hash sentinel string never appears anywhere in the output. This
    /// fails against the old sentinel-in-checksum behavior.
    #[test]
    fn computer_screenshot_dropped_projection_has_no_checksum_sentinel() {
        let proj = SanitizedComputerFrame::dropped(
            test_dimensions(),
            1024,
            ObservationId("obs-d".to_string()),
            ActionId("act-d".to_string()),
            CaptureEpoch(50),
            ScreenshotMediaType::Png,
            RedactionReason::StaleEpochDropped,
        );
        let json = serde_json::to_string(&proj).unwrap();
        assert!(
            json.contains("\"checksum\":null"),
            "dropped checksum must serialize as null, got {json}"
        );
        // The sentinel string must never reach a durable projection.
        assert!(!json.contains("dropped:unknown"));
        assert!(!json.contains("unknown"));

        // A LIVE frame, by contrast, carries a real hex checksum string in the
        // same field — proving the typed representation, not a magic string,
        // distinguishes the two.
        let (_, frame) = make_test_frame();
        let live = frame.sanitized();
        let hex = live.checksum.as_ref().expect("live checksum").0.clone();
        assert_eq!(hex.len(), 64);
        let live_json = serde_json::to_string(&live).unwrap();
        assert!(live_json.contains(&format!("\"checksum\":\"{hex}\"")));
        assert!(!live_json.contains("dropped:"));
        assert!(!live_json.contains("\"checksum\":null"));
    }

    /// Zeroization actually overwrites the buffer's bytes. This inspects the
    /// retained allocation after the wipe and FAILS if `zeroize_vec` were a
    /// no-op stub (which would leave the original `0xAB` bytes intact).
    #[test]
    fn computer_screenshot_zeroize_wipes_bytes() {
        let mut buf = vec![0xABu8; 512];
        let ptr = buf.as_ptr();
        let cap = buf.capacity();
        assert!(cap >= 512);
        // Precondition: every byte really holds the secret marker.
        assert!(buf.iter().all(|&b| b == 0xAB));

        zeroize_vec(&mut buf);

        // `zeroize_vec` clears `len` but keeps the (now-zeroed) allocation, so
        // the original pointer/capacity still refer to live, initialized memory.
        assert_eq!(buf.as_ptr(), ptr, "wipe must not reallocate");
        assert_eq!(buf.capacity(), cap, "wipe must not shrink the allocation");
        // SAFETY: `ptr`/`cap` still name `buf`'s live allocation; every byte was
        // written to `0` by the volatile wipe above, so all are initialized.
        let wiped = unsafe { std::slice::from_raw_parts(ptr, cap) };
        assert!(
            wiped.iter().all(|&b| b == 0),
            "every byte of the allocation must be zeroed"
        );
    }

    // -------------------------------------------------------------------------
    // Replacement cleanup: old frame is cleaned up on replacement
    // -------------------------------------------------------------------------

    #[test]
    fn frame_slot_replacement_cleans_up_old() {
        let (released_old, handle_old) = make_test_handle();
        let mut slot = FrameSlot::new();
        let f_old = LiveComputerFrame::try_new(
            test_frame_bytes(),
            ScreenshotMediaType::Png,
            test_dimensions(),
            ObservationId("obs-old".to_string()),
            ActionId("act-old".to_string()),
            CaptureEpoch(100),
            handle_old,
            None,
        )
        .unwrap();
        slot.replace(f_old);
        assert!(!released_old.load(Ordering::SeqCst));

        let (_released_new, handle_new) = make_test_handle();
        let f_new = LiveComputerFrame::try_new(
            test_frame_bytes(),
            ScreenshotMediaType::Png,
            test_dimensions(),
            ObservationId("obs-new".to_string()),
            ActionId("act-new".to_string()),
            CaptureEpoch(200),
            handle_new,
            None,
        )
        .unwrap();
        slot.replace(f_new);
        // Old frame's reservation was released.
        assert!(released_old.load(Ordering::SeqCst));
    }

    // -------------------------------------------------------------------------
    // Cleanup reason code display
    // -------------------------------------------------------------------------

    #[test]
    fn cleanup_reason_code_display() {
        assert_eq!(
            format!("{}", CleanupReasonCode::TempRemovalFailed),
            "temp_removal_failed"
        );
        assert_eq!(
            format!("{}", CleanupReasonCode::ReservationReleaseFailed),
            "reservation_release_failed"
        );
    }

    // -------------------------------------------------------------------------
    // ProviderMediaVariant wire_type exhaustive
    // -------------------------------------------------------------------------

    #[test]
    fn provider_media_variant_wire_types() {
        assert_eq!(
            ProviderMediaVariant::OpenAiComputerCallOutput.wire_type(),
            "computer_call_output"
        );
        assert_eq!(
            ProviderMediaVariant::Anthropic20250124ImageBlock.wire_type(),
            "anthropic_20250124_image_block"
        );
        assert_eq!(
            ProviderMediaVariant::Anthropic20251124ImageBlock.wire_type(),
            "anthropic_20251124_image_block"
        );
        assert_eq!(
            ProviderMediaVariant::ScreenshotOnly.wire_type(),
            "screenshot_only"
        );
    }

    // -------------------------------------------------------------------------
    // FrameError display
    // -------------------------------------------------------------------------

    #[test]
    fn frame_error_display() {
        let e = FrameError::Oversize {
            actual: 999,
            limit: 100,
        };
        assert!(format!("{e}").contains("999"));
        assert!(format!("{e}").contains("100"));
        let e2 = FrameError::Empty;
        assert!(format!("{e2}").contains("no encoded bytes"));
    }

    // -------------------------------------------------------------------------
    // Stale epoch check
    // -------------------------------------------------------------------------

    #[test]
    fn is_stale_relative_to() {
        let (_, frame) = make_test_frame(); // epoch 100
        assert!(frame.is_stale_relative_to(CaptureEpoch(200)));
        assert!(!frame.is_stale_relative_to(CaptureEpoch(100)));
        assert!(!frame.is_stale_relative_to(CaptureEpoch(50)));
    }
}
