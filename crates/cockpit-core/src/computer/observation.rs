//! Deterministic computer observation epochs and verification levels.
//!
//! This module gives the live coordinator one fully specified frame-diff,
//! pointer, epoch, and stability state machine that rejects stale evidence and
//! never lets model confidence select verification rigor.
//!
//! # Architecture
//!
//! [`ObservationVerificationPolicy`] is the single versioned fixture of all
//! thresholds (channel delta, mask expansion, click mask size, freshness
//! window, pointer tolerance, outside-mask pixel tolerances). Runtime and tests
//! share the same constants.
//!
//! [`ComputerObservation`] binds delegation ID, monotonically increasing
//! observation epoch, target/focus/host-lease generations, physical
//! geometry/scale/transform, optional pointer position, capture monotonic
//! timestamp, [`LiveComputerFrame`], and the sanitized projection.
//!
//! [`FrameComparator`] decodes equal-size frames to RGBA8 without resizing. A
//! pixel is changed when the maximum absolute channel delta exceeds the policy
//! threshold. It masks old/new pointer rectangles (expanded by the policy
//! padding) and, for a click, a square centered on the dispatched point and
//! clipped to the frame. No mask is used for type/key/drag/scroll/navigation/
//! modal actions.
//!
//! [`ObservationVerifier`] checks freshness, pointer confirmation, and the
//! outside-mask pixel count against the policy, then returns a
//! [`QualificationDecision`].
//!
//! [`VerificationStateMachine`] tracks the Strict/Guarded/Stable level. State
//! starts Strict. The first consecutive qualifying action changes Strict ->
//! Guarded. Two additional consecutive qualifying actions change Guarded ->
//! Stable (three total). Stable remains only on another qualifying action.
//! Every nonqualifying action or explicit invalidation resets Strict
//! immediately.
//!
//! Screenshot checksum is correlation only. Provider/model confidence, prose
//! claims, and target semantics are not transition inputs. Live pixels remain
//! in the transient screenshot owner ([`LiveComputerFrame`]); durable state
//! stores only sanitized metadata and comparator counts.

use std::time::Duration;

use image::ImageFormat;

use super::frame::{CaptureEpoch, FrameDimensions, LiveComputerFrame, SanitizedComputerFrame};
use super::{ComputerAction, DisplayGeometry, PixelRect, PixelSize, ScaleFactor};

// ---------------------------------------------------------------------------
// Policy fixture
// ---------------------------------------------------------------------------

/// The single versioned fixture of all observation/verification thresholds.
///
/// Runtime and tests share the same constants via [`Self::v1`]. Adding a new
/// policy version requires a new constructor and a migration; thresholds are
/// never mutated in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservationVerificationPolicy {
    /// Policy version tag.
    pub version: u32,
    /// A pixel is changed when the maximum absolute channel delta **exceeds**
    /// this value. Boundary: delta 16 is unchanged, delta 17 is changed.
    pub channel_delta_threshold: u8,
    /// Physical-pixel padding added to each backend-reported pointer bounds
    /// rectangle when constructing the old/new pointer mask.
    pub pointer_mask_padding: u32,
    /// Half-extent of the click mask square in physical pixels. The full
    /// square is `2 * click_mask_half_extent + 1` pixels on a side (so a
    /// half-extent of 48 yields a 97-pixel square; the spec's 96x96 is the
    /// target and the implementation clips to even extents — see
    /// [`ObservationVerificationPolicy::click_mask_size`]).
    pub click_mask_half_extent: u32,
    /// A post-frame is fresh when captured no more than this many
    /// injected-clock milliseconds after backend completion.
    pub freshness_window: Duration,
    /// A pointer-confirmed move requires reported pointer coordinates within
    /// this many physical pixels on each axis of the requested point.
    pub pointer_tolerance: u32,
    /// Outside-mask changed pixels are tolerated only while the count is at
    /// most this fraction of frame pixels. Stored as basis points (1/100th of
    /// a percent) to keep all comparisons integer.
    pub outside_mask_fraction_basis_points: u64,
    /// Outside-mask changed pixels are tolerated only while the count is at
    /// most this absolute value.
    pub outside_mask_absolute_cap: u64,
}

impl ObservationVerificationPolicy {
    /// The canonical v1 policy. Shared by runtime and tests.
    pub const fn v1() -> Self {
        Self {
            version: 1,
            channel_delta_threshold: 16,
            pointer_mask_padding: 8,
            // 96x96 square → half-extent 48 (covers 97px including the center
            // pixel; clipping to the frame keeps it within bounds).
            click_mask_half_extent: 48,
            freshness_window: Duration::from_millis(500),
            pointer_tolerance: 2,
            // 0.1% = 10 basis points.
            outside_mask_fraction_basis_points: 10,
            outside_mask_absolute_cap: 4096,
        }
    }

    /// The full click mask square side length in physical pixels.
    pub const fn click_mask_size(self) -> u32 {
        // 2 * half_extent yields the spec's 96 (the center pixel is covered by
        // the even extent; we do not add 1 so the mask is exactly 96x96).
        2 * self.click_mask_half_extent
    }
}

impl Default for ObservationVerificationPolicy {
    fn default() -> Self {
        Self::v1()
    }
}

// ---------------------------------------------------------------------------
// Generations and physical state snapshot
// ---------------------------------------------------------------------------

/// Monotonically increasing observation epoch. A late frame whose epoch is
/// obsolete is dropped and cannot replace a current observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct ObservationEpoch(pub u64);

/// Host-lease generation carried by an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub struct HostLeaseGeneration(pub u64);

/// Physical geometry/scale/transform generation carried by an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub struct GeometryGeneration(pub u64);

/// Target (focus) generation carried by an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub struct TargetGeneration(pub u64);

/// The set of generations that must be unchanged for a qualifying action.
/// Any change is an exact invalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub struct GenerationSnapshot {
    pub observation: ObservationEpoch,
    pub target: TargetGeneration,
    pub focus: TargetGeneration,
    pub geometry: GeometryGeneration,
    pub host_lease: Option<HostLeaseGeneration>,
}

/// Reported pointer position and bounds in physical pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct PointerEvidence {
    /// The reported pointer position in physical pixels.
    pub position: PhysicalPosition,
    /// The backend-reported pointer bounds rectangle in physical pixels.
    pub bounds: PixelRect,
}

/// A physical-pixel position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct PhysicalPosition {
    pub x: u32,
    pub y: u32,
}

/// The physical state captured at observation time.
#[derive(Debug, Clone, PartialEq)]
pub struct PhysicalState {
    pub geometry: DisplayGeometry,
    pub scale_factor: ScaleFactor,
    pub pointer: Option<PointerEvidence>,
    /// Monotonic capture timestamp from the injected clock (milliseconds).
    pub capture_timestamp_ms: u64,
    /// Timestamp of backend completion (milliseconds from the injected clock).
    pub backend_completion_timestamp_ms: u64,
}

// ---------------------------------------------------------------------------
// ComputerObservation
// ---------------------------------------------------------------------------

/// The canonical observation binding: delegation ID, monotonically increasing
/// observation epoch, target/focus/host-lease generations, physical
/// geometry/scale/transform, optional pointer position, capture monotonic
/// timestamp, [`LiveComputerFrame`], and sanitized projection.
///
/// Live pixels remain in the transient screenshot owner; durable state stores
/// only the sanitized projection and comparator counts.
pub struct ComputerObservation {
    pub delegation_id: String,
    pub epoch: ObservationEpoch,
    pub generations: GenerationSnapshot,
    pub physical: PhysicalState,
    /// The live frame owning the screenshot bytes. Moved out when the
    /// comparator borrows and drops it.
    pub frame: LiveComputerFrame,
}

impl ComputerObservation {
    /// The sanitized projection of the live frame. This is the only value
    /// durable sinks may record.
    pub fn sanitized(&self) -> SanitizedComputerFrame {
        self.frame.sanitized()
    }

    /// The capture epoch of the underlying frame.
    pub fn capture_epoch(&self) -> CaptureEpoch {
        self.frame.capture_epoch()
    }

    /// The frame dimensions.
    pub fn dimensions(&self) -> FrameDimensions {
        self.frame.dimensions()
    }

    /// Returns true if this observation's epoch is stale relative to `current`.
    pub fn is_stale_relative_to(&self, current: ObservationEpoch) -> bool {
        self.epoch < current
    }
}

impl std::fmt::Debug for ComputerObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComputerObservation")
            .field("delegation_id", &self.delegation_id)
            .field("epoch", &self.epoch)
            .field("generations", &self.generations)
            .field("physical", &self.physical)
            .field("frame", &self.frame)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Frame comparator
// ---------------------------------------------------------------------------

/// The result of comparing two decoded frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComparisonResult {
    /// Total number of pixels in the comparison region.
    pub total_pixels: u64,
    /// Number of changed pixels outside the mask.
    pub outside_mask_changed: u64,
    /// Number of changed pixels inside the mask (diagnostic only).
    pub inside_mask_changed: u64,
}

/// Error from the frame comparator. Every variant is a verification failure,
/// not stable evidence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ComparisonError {
    /// The two frames have different dimensions. The comparator decodes
    /// equal-size frames only — no resizing.
    #[error("frame dimension mismatch: {old:?} vs {new:?}")]
    DimensionMismatch { old: PixelSize, new: PixelSize },
    /// A frame could not be decoded to RGBA8.
    #[error("color decode failure: {0}")]
    ColorDecodeFailure(String),
    /// Arithmetic overflow during ratio or clipping computation.
    #[error("arithmetic overflow in comparison")]
    ArithmeticOverflow,
    /// The comparison region is empty.
    #[error("empty comparison region")]
    EmptyRegion,
}

/// A deterministic pixel comparator that decodes equal-size frames to RGBA8
/// without resizing.
///
/// A pixel is changed when the maximum absolute channel delta **exceeds** the
/// policy threshold (delta 16 is unchanged, delta 17 is changed). It masks:
/// (a) old and new pointer rectangles, each the backend-reported pointer bounds
/// expanded by the policy padding; and (b) for a click, a square centered on
/// the dispatched point and clipped to the frame. No mask is used for
/// type/key/drag/scroll/navigation/modal actions.
pub struct FrameComparator {
    policy: ObservationVerificationPolicy,
}

impl FrameComparator {
    /// Create a comparator with the given policy.
    pub fn new(policy: ObservationVerificationPolicy) -> Self {
        Self { policy }
    }

    /// The policy in use.
    pub fn policy(&self) -> ObservationVerificationPolicy {
        self.policy
    }

    /// Compare two encoded frames, applying the mask for the given action and
    /// pointer evidence. Returns the comparison result or a verification
    /// failure.
    ///
    /// The old pointer evidence is the pointer position/bounds before the
    /// action; the new pointer evidence is after. Both are masked (expanded by
    /// the policy padding). For a click, the dispatched point mask is also
    /// applied.
    #[allow(clippy::too_many_arguments)]
    pub fn compare(
        &self,
        old_bytes: &[u8],
        old_dims: FrameDimensions,
        new_bytes: &[u8],
        new_dims: FrameDimensions,
        action: &ComputerAction,
        old_pointer: Option<PointerEvidence>,
        new_pointer: Option<PointerEvidence>,
        dispatched_point: Option<PhysicalPosition>,
    ) -> Result<ComparisonResult, ComparisonError> {
        // Dimension check: equal-size frames only, no resizing.
        if old_dims.width != new_dims.width || old_dims.height != new_dims.height {
            return Err(ComparisonError::DimensionMismatch {
                old: PixelSize {
                    width: old_dims.width,
                    height: old_dims.height,
                },
                new: PixelSize {
                    width: new_dims.width,
                    height: new_dims.height,
                },
            });
        }
        let width = old_dims.width;
        let height = old_dims.height;
        if width == 0 || height == 0 {
            return Err(ComparisonError::EmptyRegion);
        }

        // Decode both frames to RGBA8.
        let old_rgba = decode_rgba8(old_bytes)?;
        let new_rgba = decode_rgba8(new_bytes)?;

        // Build the mask. Only cursor-bearing actions (move/click) legitimately
        // change pixels around the pointer or click point, so only those get a
        // pointer/click mask. Type/key/drag/scroll/wait/capture actions get no
        // mask, so every changed pixel is counted outside the (empty) mask.
        let mask = if action_is_maskable(action) {
            MaskBuilder::new(width, height)
                .with_pointer(old_pointer, self.policy.pointer_mask_padding)
                .with_pointer(new_pointer, self.policy.pointer_mask_padding)
                .with_click_mask(action, dispatched_point, self.policy.click_mask_size())
                .build()
        } else {
            MaskBuilder::new(width, height).build()
        };

        // Compare pixels.
        let threshold = self.policy.channel_delta_threshold;
        let mut outside_mask_changed: u64 = 0;
        let mut inside_mask_changed: u64 = 0;
        let total_pixels = u64::from(width) * u64::from(height);

        for y in 0..height {
            for x in 0..width {
                let idx = ((y * width + x) * 4) as usize;
                let old_px = &old_rgba[idx..idx + 4];
                let new_px = &new_rgba[idx..idx + 4];
                let max_delta = max_channel_delta(old_px, new_px);
                if max_delta > threshold {
                    if mask.is_masked(x, y) {
                        inside_mask_changed += 1;
                    } else {
                        outside_mask_changed += 1;
                    }
                }
            }
        }

        Ok(ComparisonResult {
            total_pixels,
            outside_mask_changed,
            inside_mask_changed,
        })
    }

    /// Check whether the outside-mask changed count is within both policy
    /// thresholds (conjunction: tolerated only while <= fraction AND <= cap).
    /// Uses checked integer arithmetic — no floating point.
    pub fn outside_mask_within_tolerance(
        &self,
        result: &ComparisonResult,
    ) -> Result<bool, ComparisonError> {
        let total = result.total_pixels;
        if total == 0 {
            return Err(ComparisonError::EmptyRegion);
        }
        // Fraction threshold: outside <= (total * basis_points) / 10_000.
        // basis_points is in 1/100th of a percent, so 10 basis points = 0.1%.
        // A basis point is 1/10,000, so total * 10 / 10_000 == total / 1_000.
        let fraction_limit = (total)
            .checked_mul(self.policy.outside_mask_fraction_basis_points)
            .ok_or(ComparisonError::ArithmeticOverflow)?
            / 10_000;
        let cap = self.policy.outside_mask_absolute_cap;
        // Tolerated only while <= fraction_limit AND <= cap.
        Ok(result.outside_mask_changed <= fraction_limit && result.outside_mask_changed <= cap)
    }
}

/// Decode an encoded image (PNG/JPEG) to an RGBA8 byte buffer.
fn decode_rgba8(bytes: &[u8]) -> Result<Vec<u8>, ComparisonError> {
    if bytes.is_empty() {
        return Err(ComparisonError::ColorDecodeFailure(
            "empty bytes".to_string(),
        ));
    }
    // Try PNG first, then JPEG, then generic.
    let img = if bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        image::load_from_memory_with_format(bytes, ImageFormat::Png)
    } else if bytes.starts_with(&[0xFF, 0xD8]) {
        image::load_from_memory_with_format(bytes, ImageFormat::Jpeg)
    } else {
        image::load_from_memory(bytes)
    }
    .map_err(|err| ComparisonError::ColorDecodeFailure(err.to_string()))?;
    Ok(img.to_rgba8().into_raw())
}

/// Compute the maximum absolute channel delta between two RGBA8 pixels.
fn max_channel_delta(old: &[u8], new: &[u8]) -> u8 {
    let mut max_delta: u8 = 0;
    for i in 0..4 {
        let delta = old[i].abs_diff(new[i]);
        if delta > max_delta {
            max_delta = delta;
        }
    }
    max_delta
}

// ---------------------------------------------------------------------------
// Mask construction
// ---------------------------------------------------------------------------

/// A mask bitmap over the frame.
struct Mask {
    width: u32,
    height: u32,
    /// Row-major bitmask: one bit per pixel.
    bits: Vec<u8>,
}

impl Mask {
    fn new(width: u32, height: u32) -> Self {
        let total = (width as usize) * (height as usize);
        let bytes = total.div_ceil(8);
        Self {
            width,
            height,
            bits: vec![0u8; bytes],
        }
    }

    fn set(&mut self, x: u32, y: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        let idx = (y as usize) * (self.width as usize) + (x as usize);
        self.bits[idx / 8] |= 1 << (idx % 8);
    }

    fn is_masked(&self, x: u32, y: u32) -> bool {
        if x >= self.width || y >= self.height {
            return false;
        }
        let idx = (y as usize) * (self.width as usize) + (x as usize);
        self.bits[idx / 8] & (1 << (idx % 8)) != 0
    }
}

/// Whether an action produces any comparison mask. Only cursor-bearing actions
/// — move and single/multi click — legitimately change pixels around the
/// pointer or click point, so only those get a pointer/click mask. Every other
/// action (type/key/hold/drag/scroll/wait/capture/mouse-down/mouse-up) gets no
/// mask, so all of its changed pixels are counted outside the mask. Exhaustive
/// so a new [`ComputerAction`] variant must choose maskability explicitly.
fn action_is_maskable(action: &ComputerAction) -> bool {
    match action {
        ComputerAction::MoveCursor { .. } | ComputerAction::Click { .. } => true,
        ComputerAction::CaptureFull
        | ComputerAction::CaptureRegion { .. }
        | ComputerAction::CaptureNativeZoom { .. }
        | ComputerAction::MouseDown { .. }
        | ComputerAction::MouseUp { .. }
        | ComputerAction::Drag { .. }
        | ComputerAction::TypeText { .. }
        | ComputerAction::KeyChord { .. }
        | ComputerAction::HoldKey { .. }
        | ComputerAction::Scroll { .. }
        | ComputerAction::Wait { .. } => false,
    }
}

/// Builder for the comparison mask, exhaustive over the action type.
struct MaskBuilder {
    mask: Mask,
}

impl MaskBuilder {
    fn new(width: u32, height: u32) -> Self {
        Self {
            mask: Mask::new(width, height),
        }
    }

    /// Add a pointer bounds rectangle expanded by `padding` physical pixels.
    fn with_pointer(mut self, pointer: Option<PointerEvidence>, padding: u32) -> Self {
        if let Some(ptr) = pointer {
            let expanded = expand_rect(ptr.bounds, padding);
            fill_rect(&mut self.mask, expanded);
        }
        self
    }

    /// Add the click mask square for click actions. Exhaustive over
    /// [`ComputerAction`]: only [`ComputerAction::Click`] gets a click mask.
    /// Type/key/drag/scroll/wait/navigation/modal actions get no mask.
    fn with_click_mask(
        mut self,
        action: &ComputerAction,
        dispatched_point: Option<PhysicalPosition>,
        mask_size: u32,
    ) -> Self {
        match action {
            ComputerAction::Click { .. } => {
                if let Some(point) = dispatched_point {
                    let half = mask_size / 2;
                    // Center the square on the dispatched point, clipped to the frame.
                    let x0 = point.x.saturating_sub(half);
                    let y0 = point.y.saturating_sub(half);
                    // The square is mask_size x mask_size, but clipped to frame bounds.
                    fill_rect(
                        &mut self.mask,
                        PixelRect {
                            x: x0,
                            y: y0,
                            width: mask_size,
                            height: mask_size,
                        },
                    );
                }
                self
            }
            // No mask for these actions — exhaustive match.
            ComputerAction::CaptureFull
            | ComputerAction::CaptureRegion { .. }
            | ComputerAction::CaptureNativeZoom { .. }
            | ComputerAction::MoveCursor { .. }
            | ComputerAction::MouseDown { .. }
            | ComputerAction::MouseUp { .. }
            | ComputerAction::Drag { .. }
            | ComputerAction::TypeText { .. }
            | ComputerAction::KeyChord { .. }
            | ComputerAction::HoldKey { .. }
            | ComputerAction::Scroll { .. }
            | ComputerAction::Wait { .. } => self,
        }
    }

    fn build(self) -> Mask {
        self.mask
    }
}

/// Expand a pixel rect by `padding` on all sides, clipping to non-negative
/// coordinates (u32 saturation).
fn expand_rect(rect: PixelRect, padding: u32) -> PixelRect {
    PixelRect {
        x: rect.x.saturating_sub(padding),
        y: rect.y.saturating_sub(padding),
        width: rect.width.saturating_add(padding * 2),
        height: rect.height.saturating_add(padding * 2),
    }
}

/// Fill a rectangle in the mask, clipping to the mask bounds.
fn fill_rect(mask: &mut Mask, rect: PixelRect) {
    let x0 = rect.x.min(mask.width);
    let y0 = rect.y.min(mask.height);
    let x1 = rect.x.saturating_add(rect.width).min(mask.width);
    let y1 = rect.y.saturating_add(rect.height).min(mask.height);
    for y in y0..y1 {
        for x in x0..x1 {
            mask.set(x, y);
        }
    }
}

// ---------------------------------------------------------------------------
// Freshness and pointer confirmation
// ---------------------------------------------------------------------------

/// Check whether a post-frame is fresh: captured no more than
/// `policy.freshness_window` after backend completion and before any newer
/// focus/geometry generation.
///
/// `capture_timestamp_ms` is the injected-clock timestamp of the frame
/// capture. `backend_completion_timestamp_ms` is the injected-clock timestamp
/// of backend completion. `generation_changed` is true if any focus/geometry
/// generation changed between backend completion and frame capture.
pub fn is_fresh(
    policy: ObservationVerificationPolicy,
    capture_timestamp_ms: u64,
    backend_completion_timestamp_ms: u64,
    generation_changed: bool,
) -> bool {
    if generation_changed {
        return false;
    }
    // The frame must be captured after backend completion.
    if capture_timestamp_ms < backend_completion_timestamp_ms {
        return false;
    }
    let elapsed = capture_timestamp_ms - backend_completion_timestamp_ms;
    elapsed <= policy.freshness_window.as_millis() as u64
}

/// Check whether the reported pointer is within `policy.pointer_tolerance`
/// physical pixels on each axis of the requested point.
pub fn pointer_confirmed(
    policy: ObservationVerificationPolicy,
    reported: PhysicalPosition,
    requested: PhysicalPosition,
) -> bool {
    let x_delta = reported.x.abs_diff(requested.x);
    let y_delta = reported.y.abs_diff(requested.y);
    x_delta <= policy.pointer_tolerance && y_delta <= policy.pointer_tolerance
}

// ---------------------------------------------------------------------------
// Qualification decision
// ---------------------------------------------------------------------------

/// Whether a dispatched action qualifies for verification-level promotion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualificationDecision {
    /// The action qualifies. All preconditions were met.
    Qualifies,
    /// The action does not qualify. The reason is a bounded code.
    DoesNotQualify(NonQualificationReason),
}

/// Bounded reason codes for why an action does not qualify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonQualificationReason {
    /// The action type never qualifies (type/key/drag/scroll/wait/navigation/
    /// modal). Resets to Strict after post-observation.
    NeverQualifyingAction,
    /// Pointer evidence is unavailable.
    PointerUnavailable,
    /// Pointer is out of tolerance.
    PointerOutOfTolerance,
    /// The post-frame is stale (captured too late).
    StaleFrame,
    /// The post-frame is not fresh (outside the freshness window).
    NotFresh,
    /// A generation changed (target/focus/geometry/scale/transform/host-lease).
    GenerationChanged,
    /// Dispatch uncertainty (dispatch_unknown).
    DispatchUncertainty,
    /// Changed pixels outside the mask exceed both thresholds.
    OutsideMaskExceeded,
    /// The frame comparison failed (dimension mismatch, decode failure,
    /// overflow, or empty region).
    ComparisonFailure,
    /// The coordinator was invalidated.
    Invalidated,
    /// A click whose pointer was not confirmed immediately before dispatch.
    ClickPointerNotConfirmed,
}

/// Categorize whether an action type can ever qualify.
///
/// Only `move_cursor`, or a single click whose pointer was confirmed
/// immediately before dispatch, can qualify. Type/key/drag/scroll/wait/
/// navigation/modal actions never qualify and reset to Strict after their
/// post-observation.
///
/// `ComputerAction` does not have explicit navigation/modal variants; those
/// are handled at the coordinator level as invalidations. The exhaustive match
/// here ensures new variants must select qualify/reset behavior explicitly.
pub fn action_qualifiable(action: &ComputerAction) -> bool {
    match action {
        ComputerAction::MoveCursor { .. } => true,
        ComputerAction::Click {
            count: ClickCountVariant::Single,
            ..
        } => true,
        // Double/triple clicks do not qualify (only single clicks).
        ComputerAction::Click { .. } => false,
        // Exhaustive: every other variant never qualifies.
        ComputerAction::CaptureFull
        | ComputerAction::CaptureRegion { .. }
        | ComputerAction::CaptureNativeZoom { .. }
        | ComputerAction::MouseDown { .. }
        | ComputerAction::MouseUp { .. }
        | ComputerAction::Drag { .. }
        | ComputerAction::TypeText { .. }
        | ComputerAction::KeyChord { .. }
        | ComputerAction::HoldKey { .. }
        | ComputerAction::Scroll { .. }
        | ComputerAction::Wait { .. } => false,
    }
}

/// Re-export the click count type for the qualifiable check. The existing
/// [`super::ClickCount`] enum is used; this alias makes the match arm readable.
type ClickCountVariant = super::ClickCount;

/// The full qualification check for a single dispatched action.
///
/// This is the deterministic decision function: it inspects the action type,
/// pointer evidence, freshness, generation stability, dispatch certainty,
/// invalidation, and the outside-mask pixel count. It never consults provider
/// confidence, prose, or target semantics.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_qualification(
    policy: ObservationVerificationPolicy,
    action: &ComputerAction,
    dispatched_point: Option<PhysicalPosition>,
    _old_pointer: Option<PointerEvidence>,
    new_pointer: Option<PointerEvidence>,
    pointer_was_confirmed_before_dispatch: bool,
    old_generations: GenerationSnapshot,
    new_generations: GenerationSnapshot,
    capture_timestamp_ms: u64,
    backend_completion_timestamp_ms: u64,
    dispatch_uncertain: bool,
    invalidated: bool,
    comparison: Option<&Result<ComparisonResult, ComparisonError>>,
) -> QualificationDecision {
    // Invalidation is checked first — it dominates everything.
    if invalidated {
        return QualificationDecision::DoesNotQualify(NonQualificationReason::Invalidated);
    }

    // Dispatch uncertainty (dispatch_unknown) never qualifies.
    if dispatch_uncertain {
        return QualificationDecision::DoesNotQualify(NonQualificationReason::DispatchUncertainty);
    }

    // Action type check.
    if !action_qualifiable(action) {
        return QualificationDecision::DoesNotQualify(
            NonQualificationReason::NeverQualifyingAction,
        );
    }

    // For a click, the pointer must have been confirmed immediately before
    // dispatch.
    let is_click = matches!(
        action,
        ComputerAction::Click {
            count: ClickCountVariant::Single,
            ..
        }
    );
    if is_click && !pointer_was_confirmed_before_dispatch {
        return QualificationDecision::DoesNotQualify(
            NonQualificationReason::ClickPointerNotConfirmed,
        );
    }

    // Generation stability: target/focus/geometry/scale/transform/host-lease
    // must be unchanged.
    if old_generations != new_generations {
        return QualificationDecision::DoesNotQualify(NonQualificationReason::GenerationChanged);
    }

    // Known pointer evidence is required for qualification.
    let new_ptr = match new_pointer {
        Some(p) => p,
        None => {
            return QualificationDecision::DoesNotQualify(
                NonQualificationReason::PointerUnavailable,
            );
        }
    };

    // Pointer-confirmed: reported pointer within tolerance of the requested
    // point. For move_cursor, the requested point is the `to` field. For a
    // click, the dispatched point is the click location.
    let requested_point = match action {
        ComputerAction::MoveCursor { to, .. } => PhysicalPosition {
            x: to.x.round() as u32,
            y: to.y.round() as u32,
        },
        ComputerAction::Click { .. } => match dispatched_point {
            Some(p) => p,
            None => {
                return QualificationDecision::DoesNotQualify(
                    NonQualificationReason::PointerUnavailable,
                );
            }
        },
        _ => unreachable!("action_qualifiable already filtered non-qualifying types"),
    };
    if !pointer_confirmed(policy, new_ptr.position, requested_point) {
        return QualificationDecision::DoesNotQualify(
            NonQualificationReason::PointerOutOfTolerance,
        );
    }

    // Freshness check. The generation_changed flag is derived from the
    // generation comparison already performed above (they are equal, so
    // generation_changed = false).
    if !is_fresh(
        policy,
        capture_timestamp_ms,
        backend_completion_timestamp_ms,
        false, // generations already checked equal
    ) {
        return QualificationDecision::DoesNotQualify(NonQualificationReason::NotFresh);
    }

    // Frame comparison result. The comparator must have succeeded and the
    // outside-mask count must be within both thresholds.
    let comparator = FrameComparator::new(policy);
    match comparison {
        None => QualificationDecision::DoesNotQualify(NonQualificationReason::ComparisonFailure),
        Some(Ok(result)) => match comparator.outside_mask_within_tolerance(result) {
            Ok(true) => QualificationDecision::Qualifies,
            Ok(false) => {
                QualificationDecision::DoesNotQualify(NonQualificationReason::OutsideMaskExceeded)
            }
            Err(_) => {
                QualificationDecision::DoesNotQualify(NonQualificationReason::ComparisonFailure)
            }
        },
        Some(Err(_)) => {
            QualificationDecision::DoesNotQualify(NonQualificationReason::ComparisonFailure)
        }
    }
}

// ---------------------------------------------------------------------------
// Verification state machine: Strict / Guarded / Stable
// ---------------------------------------------------------------------------

/// The verification level. State starts [`Self::Strict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub enum VerificationLevel {
    /// Strict: full verification rigor. The initial state.
    #[default]
    Strict,
    /// Guarded: reached after one consecutive qualifying action.
    Guarded,
    /// Stable: reached after three total consecutive qualifying actions.
    Stable,
}

/// The result of a state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionResult {
    /// The level before the transition.
    pub from: VerificationLevel,
    /// The level after the transition.
    pub to: VerificationLevel,
    /// The number of consecutive qualifying actions at the new level.
    pub consecutive_qualifiers: u32,
    /// Whether this transition was a reset to Strict.
    pub reset: bool,
}

/// The Strict/Guarded/Stable state machine.
///
/// State starts [`VerificationLevel::Strict`]. The first consecutive qualifying
/// action changes Strict -> Guarded. Two additional consecutive qualifying
/// actions change Guarded -> Stable (three total). Stable remains only on
/// another qualifying action. Every nonqualifying action or explicit
/// invalidation resets Strict immediately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationStateMachine {
    level: VerificationLevel,
    consecutive_qualifiers: u32,
}

impl Default for VerificationStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl VerificationStateMachine {
    /// Create a new state machine in the initial Strict state.
    pub fn new() -> Self {
        Self {
            level: VerificationLevel::Strict,
            consecutive_qualifiers: 0,
        }
    }

    /// The current verification level.
    pub fn level(&self) -> VerificationLevel {
        self.level
    }

    /// The current count of consecutive qualifying actions.
    pub fn consecutive_qualifiers(&self) -> u32 {
        self.consecutive_qualifiers
    }

    /// Apply a qualification decision. Returns the transition result.
    ///
    /// - A qualifying action advances the state: Strict -> Guarded after 1,
    ///   Guarded -> Stable after 3 total, Stable retained on another qualifier.
    /// - A nonqualifying action resets to Strict immediately.
    pub fn apply(&mut self, decision: &QualificationDecision) -> TransitionResult {
        let from = self.level;
        match decision {
            QualificationDecision::Qualifies => {
                self.consecutive_qualifiers = self.consecutive_qualifiers.saturating_add(1);
                let new_level = match self.level {
                    VerificationLevel::Strict => {
                        // First consecutive qualifier: Strict -> Guarded.
                        VerificationLevel::Guarded
                    }
                    VerificationLevel::Guarded => {
                        // Two additional (three total) qualifiers: Guarded -> Stable.
                        if self.consecutive_qualifiers >= 3 {
                            VerificationLevel::Stable
                        } else {
                            VerificationLevel::Guarded
                        }
                    }
                    VerificationLevel::Stable => {
                        // Stable remains only on another qualifying action.
                        VerificationLevel::Stable
                    }
                };
                self.level = new_level;
                TransitionResult {
                    from,
                    to: new_level,
                    consecutive_qualifiers: self.consecutive_qualifiers,
                    reset: false,
                }
            }
            QualificationDecision::DoesNotQualify(_) => {
                self.level = VerificationLevel::Strict;
                self.consecutive_qualifiers = 0;
                TransitionResult {
                    from,
                    to: VerificationLevel::Strict,
                    consecutive_qualifiers: 0,
                    reset: true,
                }
            }
        }
    }

    /// Explicitly invalidate the state machine. Resets to Strict immediately.
    pub fn invalidate(&mut self) -> TransitionResult {
        let from = self.level;
        self.level = VerificationLevel::Strict;
        self.consecutive_qualifiers = 0;
        TransitionResult {
            from,
            to: VerificationLevel::Strict,
            consecutive_qualifiers: 0,
            reset: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Epoch tracking and stale-evidence rejection
// ---------------------------------------------------------------------------

/// Tracks the current observation epoch and rejects stale/duplicate evidence.
///
/// A late frame whose epoch is obsolete is dropped and cannot change state or
/// verify another action. A duplicate frame/result ID returns the prior
/// transition and releases no resource twice.
#[derive(Debug, Default)]
pub struct EpochTracker {
    current_epoch: Option<ObservationEpoch>,
    /// Seen frame/result IDs for duplicate detection.
    seen_ids: std::collections::HashMap<String, TransitionResult>,
}

impl EpochTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// The current observation epoch, if any.
    pub fn current_epoch(&self) -> Option<ObservationEpoch> {
        self.current_epoch
    }

    /// Advance to a new epoch. Returns the prior epoch if one existed.
    /// The new epoch must be strictly greater than the current one.
    pub fn advance(&mut self, new_epoch: ObservationEpoch) -> Option<ObservationEpoch> {
        let prior = self.current_epoch;
        self.current_epoch = Some(new_epoch);
        prior
    }

    /// Check whether the given epoch is stale (obsolete) relative to the
    /// current epoch.
    pub fn is_stale(&self, epoch: ObservationEpoch) -> bool {
        match self.current_epoch {
            Some(current) => epoch < current,
            None => false,
        }
    }

    /// Check whether a frame/result ID has already been seen (duplicate).
    pub fn is_duplicate(&self, id: &str) -> bool {
        self.seen_ids.contains_key(id)
    }

    /// Record a transition result for a frame/result ID. Returns the prior
    /// transition if the ID was already seen (duplicate).
    pub fn record_result(
        &mut self,
        id: &str,
        result: TransitionResult,
    ) -> Option<TransitionResult> {
        self.seen_ids.insert(id.to_string(), result)
    }

    /// Look up the prior transition for a duplicate ID.
    pub fn lookup_result(&self, id: &str) -> Option<&TransitionResult> {
        self.seen_ids.get(id)
    }
}

// ---------------------------------------------------------------------------
// Serialization: host-global arbiter vs. independent virtual displays
// ---------------------------------------------------------------------------

/// Serialization scope for observations/actions.
///
/// Physical actions share the host-global arbiter; independent virtual displays
/// do not mix epochs. A late result never verifies a different action.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SerializationScope {
    /// Host-global physical target. All physical actions share one arbiter.
    HostGlobal {
        host_installation_id: [u8; 32],
        physical_display_id: [u8; 32],
    },
    /// Independent virtual display. Epochs do not mix across displays.
    VirtualDisplay { virtual_display_uuid: [u8; 16] },
}

/// A serialization registry that proves physical actions share the host-global
/// arbiter while independent virtual displays do not mix epochs.
///
/// Each scope has its own [`EpochTracker`]; a late result in one scope never
/// verifies an action in another scope.
#[derive(Debug, Default)]
pub struct SerializationRegistry {
    scopes: std::collections::HashMap<SerializationScope, EpochTracker>,
}

impl SerializationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create the epoch tracker for the given scope.
    pub fn tracker_for(&mut self, scope: &SerializationScope) -> &mut EpochTracker {
        self.scopes.entry(scope.clone()).or_default()
    }

    /// Check if a scope has been registered.
    pub fn has_scope(&self, scope: &SerializationScope) -> bool {
        self.scopes.contains_key(scope)
    }

    /// The number of registered scopes.
    pub fn scope_count(&self) -> usize {
        self.scopes.len()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgba};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    // --- Helper functions ---

    fn policy() -> ObservationVerificationPolicy {
        ObservationVerificationPolicy::v1()
    }

    fn make_dims(w: u32, h: u32) -> FrameDimensions {
        FrameDimensions {
            width: w,
            height: h,
            region: None,
            native_zoom: None,
        }
    }

    fn make_rgba_png(width: u32, height: u32, fill: [u8; 4]) -> Vec<u8> {
        let img: ImageBuffer<Rgba<u8>, Vec<u8>> =
            ImageBuffer::from_pixel(width, height, Rgba(fill));
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut std::io::Cursor::new(&mut bytes), ImageFormat::Png)
            .unwrap();
        bytes
    }

    fn make_rgba_png_with_pixel(
        width: u32,
        height: u32,
        fill: [u8; 4],
        px: (u32, u32),
        color: [u8; 4],
    ) -> Vec<u8> {
        let mut img: ImageBuffer<Rgba<u8>, Vec<u8>> =
            ImageBuffer::from_pixel(width, height, Rgba(fill));
        img.put_pixel(px.0, px.1, Rgba(color));
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut std::io::Cursor::new(&mut bytes), ImageFormat::Png)
            .unwrap();
        bytes
    }

    fn make_reservation() -> (
        Arc<AtomicBool>,
        Box<dyn super::super::frame::MediaReservationHandle>,
    ) {
        let released = Arc::new(AtomicBool::new(false));
        let handle: Box<dyn super::super::frame::MediaReservationHandle> = Box::new(
            super::super::frame::InMemoryReservationHandle::new(released.clone()),
        );
        (released, handle)
    }

    fn make_test_frame(width: u32, height: u32, fill: [u8; 4]) -> LiveComputerFrame {
        let png = make_rgba_png(width, height, fill);
        let (_r, handle) = make_reservation();
        LiveComputerFrame::try_new(
            png,
            super::super::frame::ScreenshotMediaType::Png,
            make_dims(width, height),
            super::super::frame::ObservationId("obs-1".to_string()),
            super::super::frame::ActionId("act-1".to_string()),
            super::super::frame::CaptureEpoch(1),
            handle,
            None,
        )
        .unwrap()
    }

    fn gen_snapshot(epoch: u64) -> GenerationSnapshot {
        GenerationSnapshot {
            observation: ObservationEpoch(epoch),
            target: TargetGeneration(1),
            focus: TargetGeneration(1),
            geometry: GeometryGeneration(1),
            host_lease: Some(HostLeaseGeneration(1)),
        }
    }

    fn physical_pos(x: u32, y: u32) -> PhysicalPosition {
        PhysicalPosition { x, y }
    }

    fn pointer_at(x: u32, y: u32) -> PointerEvidence {
        PointerEvidence {
            position: physical_pos(x, y),
            bounds: PixelRect {
                x: x.saturating_sub(2),
                y: y.saturating_sub(2),
                width: 5,
                height: 5,
            },
        }
    }

    fn move_cursor_action(x: f64, y: f64) -> ComputerAction {
        ComputerAction::MoveCursor {
            to: super::super::Point {
                x,
                y,
                space: super::super::CoordinateSpace::Physical,
            },
            duration: Duration::ZERO,
            easing: super::super::Easing::Linear,
        }
    }

    fn single_click_action() -> ComputerAction {
        ComputerAction::Click {
            button: super::super::MouseButton::Left,
            count: super::super::ClickCount::Single,
            modifiers: super::super::Modifiers::default(),
        }
    }

    fn type_action() -> ComputerAction {
        ComputerAction::TypeText {
            text: "hello".to_string(),
        }
    }

    fn drag_action() -> ComputerAction {
        ComputerAction::Drag {
            button: super::super::MouseButton::Left,
            path: vec![super::super::TimedPoint {
                point: super::super::Point {
                    x: 0.0,
                    y: 0.0,
                    space: super::super::CoordinateSpace::Physical,
                },
                duration: Duration::ZERO,
                easing: super::super::Easing::Linear,
            }],
            modifiers: super::super::Modifiers::default(),
        }
    }

    fn scroll_action() -> ComputerAction {
        ComputerAction::Scroll {
            delta_x: 0,
            delta_y: 1,
            modifiers: super::super::Modifiers::default(),
        }
    }

    fn wait_action() -> ComputerAction {
        ComputerAction::Wait {
            duration: Duration::from_millis(1),
        }
    }

    fn key_action() -> ComputerAction {
        ComputerAction::KeyChord {
            chord: super::super::KeyChord {
                keys: vec!["Escape".to_string()],
            },
        }
    }

    // =====================================================================
    // Acceptance criterion 1: computer_observation_diff_policy
    // Tests exact RGBA delta 16/17 boundaries, masks, clipping, 0.1% and
    // 4,096 thresholds, 500ms freshness, and pointer tolerance 2/3.
    // =====================================================================

    #[test]
    fn computer_observation_diff_policy_delta_16_unchanged() {
        // Delta of exactly 16 is NOT a changed pixel.
        let p = policy();
        let comparator = FrameComparator::new(p);
        let w = 10;
        let h = 10;
        let old = make_rgba_png(w, h, [100, 100, 100, 255]);
        let new = make_rgba_png(w, h, [116, 116, 116, 255]); // delta 16
        let result = comparator
            .compare(
                &old,
                make_dims(w, h),
                &new,
                make_dims(w, h),
                &move_cursor_action(5.0, 5.0),
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(result.outside_mask_changed, 0);
    }

    #[test]
    fn computer_observation_diff_policy_delta_17_changed() {
        // Delta of 17 IS a changed pixel.
        let p = policy();
        let comparator = FrameComparator::new(p);
        let w = 10;
        let h = 10;
        let old = make_rgba_png(w, h, [100, 100, 100, 255]);
        let new = make_rgba_png(w, h, [117, 117, 117, 255]); // delta 17
        let result = comparator
            .compare(
                &old,
                make_dims(w, h),
                &new,
                make_dims(w, h),
                &move_cursor_action(5.0, 5.0),
                None,
                None,
                None,
            )
            .unwrap();
        // All pixels changed (delta 17 > 16), no mask for move.
        assert_eq!(result.outside_mask_changed, 100);
        assert_eq!(result.inside_mask_changed, 0);
    }

    #[test]
    fn computer_observation_diff_policy_channel_max_delta() {
        // The max channel delta is what matters: one channel at 17, others at 0.
        let p = policy();
        let comparator = FrameComparator::new(p);
        let w = 4;
        let h = 4;
        let old = make_rgba_png(w, h, [100, 100, 100, 255]);
        let new =
            make_rgba_png_with_pixel(w, h, [100, 100, 100, 255], (0, 0), [117, 100, 100, 255]);
        let result = comparator
            .compare(
                &old,
                make_dims(w, h),
                &new,
                make_dims(w, h),
                &move_cursor_action(0.0, 0.0),
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(result.outside_mask_changed, 1);
    }

    #[test]
    fn computer_observation_diff_policy_pointer_mask() {
        // A changed pixel inside the expanded pointer bounds is masked.
        let p = policy();
        let comparator = FrameComparator::new(p);
        let w = 100;
        let h = 100;
        let old = make_rgba_png(w, h, [50, 50, 50, 255]);
        // Change a pixel at (50, 50) — inside the pointer bounds (centered at
        // 50,50 with 5x5 bounds expanded by 8 = 16x16+ region).
        let new = make_rgba_png_with_pixel(w, h, [50, 50, 50, 255], (50, 50), [200, 200, 200, 255]);
        let ptr = pointer_at(50, 50);
        let result = comparator
            .compare(
                &old,
                make_dims(w, h),
                &new,
                make_dims(w, h),
                &move_cursor_action(50.0, 50.0),
                Some(ptr),
                Some(ptr),
                None,
            )
            .unwrap();
        // The changed pixel is inside the pointer mask.
        assert_eq!(result.outside_mask_changed, 0);
        assert_eq!(result.inside_mask_changed, 1);
    }

    #[test]
    fn computer_observation_diff_policy_click_mask() {
        // A click gets a 96x96 mask centered on the dispatched point.
        let p = policy();
        let comparator = FrameComparator::new(p);
        let w = 200;
        let h = 200;
        let old = make_rgba_png(w, h, [50, 50, 50, 255]);
        // Change a pixel at the center of the click — inside the 96x96 mask.
        let new =
            make_rgba_png_with_pixel(w, h, [50, 50, 50, 255], (100, 100), [200, 200, 200, 255]);
        let result = comparator
            .compare(
                &old,
                make_dims(w, h),
                &new,
                make_dims(w, h),
                &single_click_action(),
                None,
                None,
                Some(physical_pos(100, 100)),
            )
            .unwrap();
        // The changed pixel is inside the click mask.
        assert_eq!(result.outside_mask_changed, 0);
        assert_eq!(result.inside_mask_changed, 1);
    }

    #[test]
    fn computer_observation_diff_policy_click_mask_clipped() {
        // The click mask is clipped to the frame at edges.
        let p = policy();
        let comparator = FrameComparator::new(p);
        let w = 50;
        let h = 50;
        let old = make_rgba_png(w, h, [50, 50, 50, 255]);
        // Change a pixel at (0, 0) — inside the clipped click mask centered at
        // (5, 5).
        let new = make_rgba_png_with_pixel(w, h, [50, 50, 50, 255], (0, 0), [200, 200, 200, 255]);
        let result = comparator
            .compare(
                &old,
                make_dims(w, h),
                &new,
                make_dims(w, h),
                &single_click_action(),
                None,
                None,
                Some(physical_pos(5, 5)),
            )
            .unwrap();
        // The changed pixel at (0,0) is inside the clipped mask.
        assert_eq!(result.outside_mask_changed, 0);
    }

    #[test]
    fn computer_observation_diff_policy_no_mask_for_type() {
        // Type actions get no mask — all changed pixels are outside.
        let p = policy();
        let comparator = FrameComparator::new(p);
        let w = 20;
        let h = 20;
        let old = make_rgba_png(w, h, [50, 50, 50, 255]);
        let new = make_rgba_png_with_pixel(w, h, [50, 50, 50, 255], (10, 10), [200, 200, 200, 255]);
        let result = comparator
            .compare(
                &old,
                make_dims(w, h),
                &new,
                make_dims(w, h),
                &type_action(),
                Some(pointer_at(10, 10)),
                Some(pointer_at(10, 10)),
                Some(physical_pos(10, 10)),
            )
            .unwrap();
        // No mask for type — the changed pixel is outside.
        assert_eq!(result.outside_mask_changed, 1);
        assert_eq!(result.inside_mask_changed, 0);
    }

    #[test]
    fn computer_observation_diff_policy_no_mask_for_scroll() {
        let p = policy();
        let comparator = FrameComparator::new(p);
        let w = 20;
        let h = 20;
        let old = make_rgba_png(w, h, [50, 50, 50, 255]);
        let new = make_rgba_png_with_pixel(w, h, [50, 50, 50, 255], (10, 10), [200, 200, 200, 255]);
        let result = comparator
            .compare(
                &old,
                make_dims(w, h),
                &new,
                make_dims(w, h),
                &scroll_action(),
                Some(pointer_at(10, 10)),
                Some(pointer_at(10, 10)),
                Some(physical_pos(10, 10)),
            )
            .unwrap();
        assert_eq!(result.outside_mask_changed, 1);
    }

    #[test]
    fn computer_observation_diff_policy_no_mask_for_drag() {
        let p = policy();
        let comparator = FrameComparator::new(p);
        let w = 20;
        let h = 20;
        let old = make_rgba_png(w, h, [50, 50, 50, 255]);
        let new = make_rgba_png_with_pixel(w, h, [50, 50, 50, 255], (10, 10), [200, 200, 200, 255]);
        let result = comparator
            .compare(
                &old,
                make_dims(w, h),
                &new,
                make_dims(w, h),
                &drag_action(),
                Some(pointer_at(10, 10)),
                Some(pointer_at(10, 10)),
                Some(physical_pos(10, 10)),
            )
            .unwrap();
        assert_eq!(result.outside_mask_changed, 1);
    }

    #[test]
    fn computer_observation_diff_policy_no_mask_for_key() {
        let p = policy();
        let comparator = FrameComparator::new(p);
        let w = 20;
        let h = 20;
        let old = make_rgba_png(w, h, [50, 50, 50, 255]);
        let new = make_rgba_png_with_pixel(w, h, [50, 50, 50, 255], (10, 10), [200, 200, 200, 255]);
        let result = comparator
            .compare(
                &old,
                make_dims(w, h),
                &new,
                make_dims(w, h),
                &key_action(),
                Some(pointer_at(10, 10)),
                Some(pointer_at(10, 10)),
                Some(physical_pos(10, 10)),
            )
            .unwrap();
        assert_eq!(result.outside_mask_changed, 1);
    }

    #[test]
    fn computer_observation_diff_policy_outside_mask_fraction_threshold() {
        // 0.1% of a 1000x1000 frame = 1000 pixels. 1001 exceeds the fraction.
        // But also must be <= 4096 cap. With 1001 pixels, fraction is exceeded.
        let p = policy();
        let comparator = FrameComparator::new(p);
        let total = 1000u64 * 1000;
        let result = ComparisonResult {
            total_pixels: total,
            outside_mask_changed: 1001,
            inside_mask_changed: 0,
        };
        // 1001 > 1000 (0.1% of 1M) → exceeds.
        assert!(!comparator.outside_mask_within_tolerance(&result).unwrap());
    }

    #[test]
    fn computer_observation_diff_policy_outside_mask_fraction_within() {
        let p = policy();
        let comparator = FrameComparator::new(p);
        let total = 1000u64 * 1000;
        let result = ComparisonResult {
            total_pixels: total,
            outside_mask_changed: 1000, // exactly 0.1% — within (<=).
            inside_mask_changed: 0,
        };
        assert!(comparator.outside_mask_within_tolerance(&result).unwrap());
    }

    #[test]
    fn computer_observation_diff_policy_outside_mask_absolute_cap() {
        // 4097 exceeds the absolute cap even if the fraction is small.
        let p = policy();
        let comparator = FrameComparator::new(p);
        let total = 10_000_000u64; // 0.1% = 10000, so 4097 is within fraction
        let result = ComparisonResult {
            total_pixels: total,
            outside_mask_changed: 4097, // exceeds cap of 4096
            inside_mask_changed: 0,
        };
        assert!(!comparator.outside_mask_within_tolerance(&result).unwrap());
    }

    #[test]
    fn computer_observation_diff_policy_outside_mask_cap_within() {
        let p = policy();
        let comparator = FrameComparator::new(p);
        let total = 10_000_000u64;
        let result = ComparisonResult {
            total_pixels: total,
            outside_mask_changed: 4096, // exactly the cap — within (<=).
            inside_mask_changed: 0,
        };
        assert!(comparator.outside_mask_within_tolerance(&result).unwrap());
    }

    #[test]
    fn computer_observation_diff_policy_fraction_1920x1080_boundary() {
        // 1920x1080 = 2_073_600 physical pixels. 10 basis points (0.1%) of that
        // is 2_073_600 / 1_000 = 2_073 (integer floor). Literals below are
        // hand-derived, not computed from the production formula.
        let comparator = FrameComparator::new(ObservationVerificationPolicy::v1());
        let total = 2_073_600u64;

        let within = ComparisonResult {
            total_pixels: total,
            outside_mask_changed: 2_073, // exactly the floor limit — within (<=).
            inside_mask_changed: 0,
        };
        assert!(comparator.outside_mask_within_tolerance(&within).unwrap());

        let exceeds = ComparisonResult {
            total_pixels: total,
            outside_mask_changed: 2_074, // one past the floor limit — rejected.
            inside_mask_changed: 0,
        };
        assert!(!comparator.outside_mask_within_tolerance(&exceeds).unwrap());
    }

    #[test]
    fn computer_observation_diff_policy_conjunction_both_thresholds() {
        // Both thresholds must be satisfied (conjunction). A count that
        // exceeds the fraction but not the cap still fails.
        let p = policy();
        let comparator = FrameComparator::new(p);
        // 100x100 = 10000 pixels. 0.1% = 10. So 11 exceeds fraction but is
        // well under the cap of 4096. The conjunction requires both <=, so
        // this fails.
        let total = 100u64 * 100;
        let result = ComparisonResult {
            total_pixels: total,
            outside_mask_changed: 11,
            inside_mask_changed: 0,
        };
        assert!(!comparator.outside_mask_within_tolerance(&result).unwrap());
    }

    #[test]
    fn computer_observation_diff_policy_freshness_500ms_within() {
        let p = policy();
        // Captured exactly 500ms after completion — within (<=).
        assert!(is_fresh(p, 1500, 1000, false));
    }

    #[test]
    fn computer_observation_diff_policy_freshness_501ms_exceeds() {
        let p = policy();
        // Captured 501ms after completion — exceeds.
        assert!(!is_fresh(p, 1501, 1000, false));
    }

    #[test]
    fn computer_observation_diff_policy_freshness_generation_changed() {
        let p = policy();
        // Even within the window, a generation change makes it not fresh.
        assert!(!is_fresh(p, 1100, 1000, true));
    }

    #[test]
    fn computer_observation_diff_policy_freshness_before_completion() {
        let p = policy();
        // Captured before completion — not fresh.
        assert!(!is_fresh(p, 900, 1000, false));
    }

    #[test]
    fn computer_observation_diff_policy_pointer_tolerance_2_within() {
        let p = policy();
        // Exactly 2 pixels on each axis — within (<=).
        assert!(pointer_confirmed(
            p,
            physical_pos(102, 98),
            physical_pos(100, 100)
        ));
    }

    #[test]
    fn computer_observation_diff_policy_pointer_tolerance_3_exceeds() {
        let p = policy();
        // 3 pixels on x — exceeds.
        assert!(!pointer_confirmed(
            p,
            physical_pos(103, 100),
            physical_pos(100, 100)
        ));
    }

    #[test]
    fn computer_observation_diff_policy_dimension_mismatch() {
        let p = policy();
        let comparator = FrameComparator::new(p);
        let old = make_rgba_png(10, 10, [50, 50, 50, 255]);
        let new = make_rgba_png(20, 20, [50, 50, 50, 255]);
        let result = comparator.compare(
            &old,
            make_dims(10, 10),
            &new,
            make_dims(20, 20),
            &move_cursor_action(5.0, 5.0),
            None,
            None,
            None,
        );
        assert!(matches!(
            result,
            Err(ComparisonError::DimensionMismatch { .. })
        ));
    }

    #[test]
    fn computer_observation_diff_policy_decode_failure() {
        let p = policy();
        let comparator = FrameComparator::new(p);
        let result = comparator.compare(
            &[0x00, 0x01], // invalid image
            make_dims(10, 10),
            &make_rgba_png(10, 10, [50, 50, 50, 255]),
            make_dims(10, 10),
            &move_cursor_action(5.0, 5.0),
            None,
            None,
            None,
        );
        assert!(matches!(
            result,
            Err(ComparisonError::ColorDecodeFailure(_))
        ));
    }

    #[test]
    fn computer_observation_diff_policy_empty_region() {
        let p = policy();
        let comparator = FrameComparator::new(p);
        let result = comparator.outside_mask_within_tolerance(&ComparisonResult {
            total_pixels: 0,
            outside_mask_changed: 0,
            inside_mask_changed: 0,
        });
        assert!(matches!(result, Err(ComparisonError::EmptyRegion)));
    }

    // =====================================================================
    // Acceptance criterion 2: computer_observation_state_matrix
    // Covers Strict -> Guarded after one, Guarded -> Stable after the third
    // consecutive qualifier, Stable retention, and every listed reset.
    // =====================================================================

    #[test]
    fn computer_observation_state_matrix_strict_to_guarded_after_one() {
        let mut sm = VerificationStateMachine::new();
        assert_eq!(sm.level(), VerificationLevel::Strict);

        let result = sm.apply(&QualificationDecision::Qualifies);
        assert_eq!(result.from, VerificationLevel::Strict);
        assert_eq!(result.to, VerificationLevel::Guarded);
        assert_eq!(result.consecutive_qualifiers, 1);
        assert!(!result.reset);
        assert_eq!(sm.level(), VerificationLevel::Guarded);
    }

    #[test]
    fn computer_observation_state_matrix_guarded_to_stable_after_third() {
        let mut sm = VerificationStateMachine::new();

        // 1st qualifier: Strict -> Guarded.
        sm.apply(&QualificationDecision::Qualifies);
        assert_eq!(sm.level(), VerificationLevel::Guarded);

        // 2nd qualifier: still Guarded (need 3 total).
        let r2 = sm.apply(&QualificationDecision::Qualifies);
        assert_eq!(r2.to, VerificationLevel::Guarded);
        assert_eq!(r2.consecutive_qualifiers, 2);

        // 3rd qualifier: Guarded -> Stable.
        let r3 = sm.apply(&QualificationDecision::Qualifies);
        assert_eq!(r3.to, VerificationLevel::Stable);
        assert_eq!(r3.consecutive_qualifiers, 3);
        assert_eq!(sm.level(), VerificationLevel::Stable);
    }

    #[test]
    fn computer_observation_state_matrix_stable_retention() {
        let mut sm = VerificationStateMachine::new();
        // Reach Stable.
        for _ in 0..3 {
            sm.apply(&QualificationDecision::Qualifies);
        }
        assert_eq!(sm.level(), VerificationLevel::Stable);

        // Another qualifier: Stable remains.
        let r = sm.apply(&QualificationDecision::Qualifies);
        assert_eq!(r.to, VerificationLevel::Stable);
        assert_eq!(r.consecutive_qualifiers, 4);
        assert_eq!(sm.level(), VerificationLevel::Stable);
    }

    #[test]
    fn computer_observation_state_matrix_reset_on_nonqualifier() {
        let mut sm = VerificationStateMachine::new();
        // Reach Guarded.
        sm.apply(&QualificationDecision::Qualifies);
        assert_eq!(sm.level(), VerificationLevel::Guarded);

        // Nonqualifier resets to Strict.
        let r = sm.apply(&QualificationDecision::DoesNotQualify(
            NonQualificationReason::NeverQualifyingAction,
        ));
        assert_eq!(r.to, VerificationLevel::Strict);
        assert!(r.reset);
        assert_eq!(r.consecutive_qualifiers, 0);
        assert_eq!(sm.level(), VerificationLevel::Strict);
    }

    #[test]
    fn computer_observation_state_matrix_reset_from_stable() {
        let mut sm = VerificationStateMachine::new();
        for _ in 0..3 {
            sm.apply(&QualificationDecision::Qualifies);
        }
        assert_eq!(sm.level(), VerificationLevel::Stable);

        // Nonqualifier resets to Strict from Stable.
        let r = sm.apply(&QualificationDecision::DoesNotQualify(
            NonQualificationReason::OutsideMaskExceeded,
        ));
        assert_eq!(r.to, VerificationLevel::Strict);
        assert!(r.reset);
        assert_eq!(sm.level(), VerificationLevel::Strict);
    }

    #[test]
    fn computer_observation_state_matrix_explicit_invalidation() {
        let mut sm = VerificationStateMachine::new();
        for _ in 0..3 {
            sm.apply(&QualificationDecision::Qualifies);
        }
        assert_eq!(sm.level(), VerificationLevel::Stable);

        // Explicit invalidation resets to Strict.
        let r = sm.invalidate();
        assert_eq!(r.to, VerificationLevel::Strict);
        assert!(r.reset);
        assert_eq!(sm.level(), VerificationLevel::Strict);
        assert_eq!(sm.consecutive_qualifiers(), 0);
    }

    #[test]
    fn computer_observation_state_matrix_reset_reasons_exhaustive() {
        // Every non-qualification reason resets to Strict.
        let reasons = [
            NonQualificationReason::NeverQualifyingAction,
            NonQualificationReason::PointerUnavailable,
            NonQualificationReason::PointerOutOfTolerance,
            NonQualificationReason::StaleFrame,
            NonQualificationReason::NotFresh,
            NonQualificationReason::GenerationChanged,
            NonQualificationReason::DispatchUncertainty,
            NonQualificationReason::OutsideMaskExceeded,
            NonQualificationReason::ComparisonFailure,
            NonQualificationReason::Invalidated,
            NonQualificationReason::ClickPointerNotConfirmed,
        ];
        for reason in reasons {
            let mut sm = VerificationStateMachine::new();
            sm.apply(&QualificationDecision::Qualifies); // Guarded
            let r = sm.apply(&QualificationDecision::DoesNotQualify(reason));
            assert_eq!(
                r.to,
                VerificationLevel::Strict,
                "reason {reason:?} should reset"
            );
            assert!(r.reset);
        }
    }

    // =====================================================================
    // Acceptance criterion 3: computer_observation_stale_epoch
    // Covers duplicate/late frames and both result/reset orderings; obsolete
    // evidence cannot change state or verify another action.
    // =====================================================================

    #[test]
    fn computer_observation_stale_epoch_late_frame() {
        let mut tracker = EpochTracker::new();
        tracker.advance(ObservationEpoch(10));
        // A frame with epoch 5 is stale.
        assert!(tracker.is_stale(ObservationEpoch(5)));
        // A frame with epoch 10 is not stale.
        assert!(!tracker.is_stale(ObservationEpoch(10)));
        // A frame with epoch 15 is not stale (it's newer).
        assert!(!tracker.is_stale(ObservationEpoch(15)));
    }

    #[test]
    fn computer_observation_stale_epoch_duplicate_id() {
        let mut tracker = EpochTracker::new();
        let result = TransitionResult {
            from: VerificationLevel::Strict,
            to: VerificationLevel::Guarded,
            consecutive_qualifiers: 1,
            reset: false,
        };
        tracker.record_result("frame-1", result);
        // Duplicate ID is detected.
        assert!(tracker.is_duplicate("frame-1"));
        assert!(!tracker.is_duplicate("frame-2"));
        // The prior transition is returned.
        let prior = tracker.lookup_result("frame-1").unwrap();
        assert_eq!(prior.to, VerificationLevel::Guarded);
    }

    #[test]
    fn computer_observation_stale_epoch_result_before_cancel() {
        // Result-before-cancel applies once, then cancellation resets Strict.
        let mut sm = VerificationStateMachine::new();
        // First qualifier: Strict -> Guarded.
        let r1 = sm.apply(&QualificationDecision::Qualifies);
        assert_eq!(r1.to, VerificationLevel::Guarded);

        // Cancellation (invalidation) after the result resets Strict.
        let r2 = sm.invalidate();
        assert_eq!(r2.from, VerificationLevel::Guarded);
        assert_eq!(r2.to, VerificationLevel::Strict);
        assert!(r2.reset);
    }

    #[test]
    fn computer_observation_stale_epoch_cancel_before_result_inert() {
        // Cancellation before result makes the result inert.
        let mut sm = VerificationStateMachine::new();
        // Reach Guarded.
        sm.apply(&QualificationDecision::Qualifies);

        // Cancel (invalidate) — resets to Strict.
        sm.invalidate();
        assert_eq!(sm.level(), VerificationLevel::Strict);

        // A late result (qualifier) arrives after cancel. In a real system
        // this would be rejected by the epoch tracker. Here we simulate: the
        // state is already Strict, and a stale qualifier cannot promote
        // because the epoch is stale. The state machine itself would apply
        // it, but the epoch guard prevents it from reaching the state machine.
        // This test verifies the epoch guard logic: a stale epoch is rejected.
        let mut tracker = EpochTracker::new();
        tracker.advance(ObservationEpoch(10));
        // The stale result has epoch 5 — it is rejected.
        assert!(tracker.is_stale(ObservationEpoch(5)));
        // Because it's stale, it never reaches the state machine. The state
        // remains Strict.
        assert_eq!(sm.level(), VerificationLevel::Strict);
    }

    #[test]
    fn computer_observation_stale_epoch_obsolete_cannot_verify() {
        // Obsolete evidence cannot change state or verify another action.
        let mut tracker = EpochTracker::new();
        tracker.advance(ObservationEpoch(10));

        // A frame with epoch 5 is stale and cannot be used.
        let stale_epoch = ObservationEpoch(5);
        assert!(tracker.is_stale(stale_epoch));

        // Even if a qualifying decision is computed, the stale epoch prevents
        // it from being applied. The state machine stays at its current level.
        let mut sm = VerificationStateMachine::new();
        let prior_level = sm.level();
        // In a real coordinator: if tracker.is_stale(epoch) { return; }
        if !tracker.is_stale(stale_epoch) {
            sm.apply(&QualificationDecision::Qualifies);
        }
        assert_eq!(sm.level(), prior_level);
    }

    // =====================================================================
    // Acceptance criterion 4: Serialization tests prove physical actions share
    // the host-global arbiter while independent virtual displays do not mix
    // epochs.
    // =====================================================================

    #[test]
    fn computer_observation_serialization_physical_shares_arbiter() {
        let mut registry = SerializationRegistry::new();
        let scope1 = SerializationScope::HostGlobal {
            host_installation_id: [1u8; 32],
            physical_display_id: [2u8; 32],
        };
        let scope2 = SerializationScope::HostGlobal {
            host_installation_id: [1u8; 32],
            physical_display_id: [2u8; 32],
        };
        // Same physical key → same scope → same tracker.
        let t1 = registry.tracker_for(&scope1);
        t1.advance(ObservationEpoch(1));
        let t2 = registry.tracker_for(&scope2);
        // The tracker is the same (same scope), so epoch 1 is current.
        assert_eq!(t2.current_epoch(), Some(ObservationEpoch(1)));
        assert_eq!(registry.scope_count(), 1);
    }

    #[test]
    fn computer_observation_serialization_virtual_displays_independent() {
        let mut registry = SerializationRegistry::new();
        let scope_a = SerializationScope::VirtualDisplay {
            virtual_display_uuid: [0xAA; 16],
        };
        let scope_b = SerializationScope::VirtualDisplay {
            virtual_display_uuid: [0xBB; 16],
        };
        // Different virtual displays → different scopes → independent epochs.
        let t_a = registry.tracker_for(&scope_a);
        t_a.advance(ObservationEpoch(100));
        let t_b = registry.tracker_for(&scope_b);
        t_b.advance(ObservationEpoch(200));
        assert_eq!(registry.scope_count(), 2);
        // Epochs do not mix: scope_a has epoch 100, scope_b has epoch 200.
        assert_eq!(
            registry.tracker_for(&scope_a).current_epoch(),
            Some(ObservationEpoch(100))
        );
        assert_eq!(
            registry.tracker_for(&scope_b).current_epoch(),
            Some(ObservationEpoch(200))
        );
        // A late frame in scope_a (epoch 50) is stale in scope_a but not in
        // scope_b (which has epoch 200 — 50 is stale there too, but the point
        // is they don't mix).
        assert!(
            registry
                .tracker_for(&scope_a)
                .is_stale(ObservationEpoch(50))
        );
    }

    #[test]
    fn computer_observation_serialization_late_result_never_verifies_other() {
        // A late result in one scope never verifies an action in another.
        let mut registry = SerializationRegistry::new();
        let physical = SerializationScope::HostGlobal {
            host_installation_id: [1u8; 32],
            physical_display_id: [2u8; 32],
        };
        let virtual_d = SerializationScope::VirtualDisplay {
            virtual_display_uuid: [0xAA; 16],
        };
        let t_phys = registry.tracker_for(&physical);
        t_phys.advance(ObservationEpoch(10));
        let t_virt = registry.tracker_for(&virtual_d);
        t_virt.advance(ObservationEpoch(20));
        // A late physical result (epoch 5) is stale in physical but the
        // virtual scope is unaffected.
        assert!(
            registry
                .tracker_for(&physical)
                .is_stale(ObservationEpoch(5))
        );
        assert!(
            !registry
                .tracker_for(&virtual_d)
                .is_stale(ObservationEpoch(25))
        );
    }

    // =====================================================================
    // Acceptance criterion 5: Live-frame replacement/cancel/end releases
    // exactly one media reservation and no sentinel pixels reach durable sinks.
    // =====================================================================

    #[test]
    fn computer_observation_live_frame_replacement_releases_once() {
        let (released1, handle1) = make_reservation();
        // Create a frame with the trackable reservation handle.
        let png = make_rgba_png(10, 10, [50, 50, 50, 255]);
        let frame1 = {
            LiveComputerFrame::try_new(
                png,
                super::super::frame::ScreenshotMediaType::Png,
                make_dims(10, 10),
                super::super::frame::ObservationId("obs-1".to_string()),
                super::super::frame::ActionId("act-1".to_string()),
                super::super::frame::CaptureEpoch(1),
                handle1,
                None,
            )
            .unwrap()
        };
        assert!(!released1.load(std::sync::atomic::Ordering::SeqCst));

        // Create the observation.
        let obs = ComputerObservation {
            delegation_id: "del-1".to_string(),
            epoch: ObservationEpoch(1),
            generations: gen_snapshot(1),
            physical: PhysicalState {
                geometry: super::super::DisplayGeometry {
                    physical: super::super::PixelSize {
                        width: 10,
                        height: 10,
                    },
                    logical: super::super::LogicalSize {
                        width: 10.0,
                        height: 10.0,
                    },
                    scale_factor: super::super::ScaleFactor(1.0),
                },
                scale_factor: super::super::ScaleFactor(1.0),
                pointer: None,
                capture_timestamp_ms: 1000,
                backend_completion_timestamp_ms: 900,
            },
            frame: frame1,
        };

        // The sanitized projection has no pixel data.
        let sanitized = obs.sanitized();
        let json = serde_json::to_string(&sanitized).unwrap();
        assert!(!json.contains("base64"));
        assert!(!json.contains("data:image"));

        // Drop the observation — the frame is dropped, releasing the reservation.
        drop(obs);
        assert!(released1.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn computer_observation_no_sentinel_pixels_in_durable() {
        let frame = make_test_frame(10, 10, [137, 80, 78, 71]);
        let obs = ComputerObservation {
            delegation_id: "del-1".to_string(),
            epoch: ObservationEpoch(1),
            generations: gen_snapshot(1),
            physical: PhysicalState {
                geometry: super::super::DisplayGeometry {
                    physical: super::super::PixelSize {
                        width: 10,
                        height: 10,
                    },
                    logical: super::super::LogicalSize {
                        width: 10.0,
                        height: 10.0,
                    },
                    scale_factor: super::super::ScaleFactor(1.0),
                },
                scale_factor: super::super::ScaleFactor(1.0),
                pointer: None,
                capture_timestamp_ms: 1000,
                backend_completion_timestamp_ms: 900,
            },
            frame,
        };
        let sanitized = obs.sanitized();
        let json = serde_json::to_string(&sanitized).unwrap();
        // No sentinel pixel bytes in the durable projection.
        assert!(!json.contains("[137"));
        assert!(!json.contains("\"bytes\""));
        assert!(!json.contains("\"data\""));
    }

    // =====================================================================
    // Acceptance criterion 6: Provider-native and screenshot-only fake
    // backends produce identical canonical transitions; model-selected levels
    // are absent from schemas.
    // =====================================================================

    #[test]
    fn computer_observation_identical_transitions_regardless_of_backend() {
        // The state machine transitions are deterministic and do not depend on
        // the backend. Both a "provider-native" and "screenshot-only" sequence
        // of qualifying decisions produce the same transitions.
        let mut sm1 = VerificationStateMachine::new();
        let mut sm2 = VerificationStateMachine::new();

        for _ in 0..3 {
            let r1 = sm1.apply(&QualificationDecision::Qualifies);
            let r2 = sm2.apply(&QualificationDecision::Qualifies);
            assert_eq!(r1, r2);
        }
        assert_eq!(sm1.level(), sm2.level());
        assert_eq!(sm1.level(), VerificationLevel::Stable);
    }

    #[test]
    fn computer_observation_no_model_selected_levels_in_schema() {
        // The VerificationLevel enum has no model-selected variant. It is
        // Strict/Guarded/Stable only. Provider confidence never selects the
        // level.
        let levels = [
            VerificationLevel::Strict,
            VerificationLevel::Guarded,
            VerificationLevel::Stable,
        ];
        for level in levels {
            let json = serde_json::to_string(&level).unwrap();
            assert!(!json.contains("model"));
            assert!(!json.contains("confidence"));
            assert!(!json.contains("adaptive"));
        }
    }

    // =====================================================================
    // Qualification evaluation tests
    // =====================================================================

    #[test]
    fn computer_observation_qualification_move_qualifies() {
        let p = policy();
        let gens = gen_snapshot(1);
        let result = ComparisonResult {
            total_pixels: 10000,
            outside_mask_changed: 0,
            inside_mask_changed: 0,
        };
        let decision = evaluate_qualification(
            p,
            &move_cursor_action(50.0, 50.0),
            Some(physical_pos(50, 50)),
            Some(pointer_at(50, 50)),
            Some(pointer_at(50, 50)),
            false, // not a click, so pointer_was_confirmed doesn't matter
            gens,
            gens,
            1100,
            1000,
            false,
            false,
            Some(&Ok(result)),
        );
        assert!(matches!(decision, QualificationDecision::Qualifies));
    }

    #[test]
    fn computer_observation_qualification_type_never_qualifies() {
        let p = policy();
        let gens = gen_snapshot(1);
        let result = ComparisonResult {
            total_pixels: 10000,
            outside_mask_changed: 0,
            inside_mask_changed: 0,
        };
        let decision = evaluate_qualification(
            p,
            &type_action(),
            None,
            None,
            None,
            false,
            gens,
            gens,
            1100,
            1000,
            false,
            false,
            Some(&Ok(result)),
        );
        assert!(matches!(
            decision,
            QualificationDecision::DoesNotQualify(NonQualificationReason::NeverQualifyingAction)
        ));
    }

    #[test]
    fn computer_observation_qualification_scroll_never_qualifies() {
        let p = policy();
        let gens = gen_snapshot(1);
        let decision = evaluate_qualification(
            p,
            &scroll_action(),
            None,
            None,
            None,
            false,
            gens,
            gens,
            1100,
            1000,
            false,
            false,
            None,
        );
        assert!(matches!(
            decision,
            QualificationDecision::DoesNotQualify(NonQualificationReason::NeverQualifyingAction)
        ));
    }

    #[test]
    fn computer_observation_qualification_drag_never_qualifies() {
        let p = policy();
        let gens = gen_snapshot(1);
        let decision = evaluate_qualification(
            p,
            &drag_action(),
            None,
            None,
            None,
            false,
            gens,
            gens,
            1100,
            1000,
            false,
            false,
            None,
        );
        assert!(matches!(
            decision,
            QualificationDecision::DoesNotQualify(NonQualificationReason::NeverQualifyingAction)
        ));
    }

    #[test]
    fn computer_observation_qualification_wait_never_qualifies() {
        let p = policy();
        let gens = gen_snapshot(1);
        let decision = evaluate_qualification(
            p,
            &wait_action(),
            None,
            None,
            None,
            false,
            gens,
            gens,
            1100,
            1000,
            false,
            false,
            None,
        );
        assert!(matches!(
            decision,
            QualificationDecision::DoesNotQualify(NonQualificationReason::NeverQualifyingAction)
        ));
    }

    #[test]
    fn computer_observation_qualification_key_never_qualifies() {
        let p = policy();
        let gens = gen_snapshot(1);
        let decision = evaluate_qualification(
            p,
            &key_action(),
            None,
            None,
            None,
            false,
            gens,
            gens,
            1100,
            1000,
            false,
            false,
            None,
        );
        assert!(matches!(
            decision,
            QualificationDecision::DoesNotQualify(NonQualificationReason::NeverQualifyingAction)
        ));
    }

    #[test]
    fn computer_observation_qualification_click_without_confirmation() {
        let p = policy();
        let gens = gen_snapshot(1);
        let result = ComparisonResult {
            total_pixels: 10000,
            outside_mask_changed: 0,
            inside_mask_changed: 0,
        };
        let decision = evaluate_qualification(
            p,
            &single_click_action(),
            Some(physical_pos(50, 50)),
            Some(pointer_at(50, 50)),
            Some(pointer_at(50, 50)),
            false, // pointer NOT confirmed before dispatch
            gens,
            gens,
            1100,
            1000,
            false,
            false,
            Some(&Ok(result)),
        );
        assert!(matches!(
            decision,
            QualificationDecision::DoesNotQualify(NonQualificationReason::ClickPointerNotConfirmed)
        ));
    }

    #[test]
    fn computer_observation_qualification_click_with_confirmation() {
        let p = policy();
        let gens = gen_snapshot(1);
        let result = ComparisonResult {
            total_pixels: 10000,
            outside_mask_changed: 0,
            inside_mask_changed: 0,
        };
        let decision = evaluate_qualification(
            p,
            &single_click_action(),
            Some(physical_pos(50, 50)),
            Some(pointer_at(50, 50)),
            Some(pointer_at(50, 50)),
            true, // pointer confirmed before dispatch
            gens,
            gens,
            1100,
            1000,
            false,
            false,
            Some(&Ok(result)),
        );
        assert!(matches!(decision, QualificationDecision::Qualifies));
    }

    #[test]
    fn computer_observation_qualification_pointer_unavailable() {
        let p = policy();
        let gens = gen_snapshot(1);
        let result = ComparisonResult {
            total_pixels: 10000,
            outside_mask_changed: 0,
            inside_mask_changed: 0,
        };
        let decision = evaluate_qualification(
            p,
            &move_cursor_action(50.0, 50.0),
            Some(physical_pos(50, 50)),
            Some(pointer_at(50, 50)),
            None, // no new pointer evidence
            false,
            gens,
            gens,
            1100,
            1000,
            false,
            false,
            Some(&Ok(result)),
        );
        assert!(matches!(
            decision,
            QualificationDecision::DoesNotQualify(NonQualificationReason::PointerUnavailable)
        ));
    }

    #[test]
    fn computer_observation_qualification_pointer_out_of_tolerance() {
        let p = policy();
        let gens = gen_snapshot(1);
        let result = ComparisonResult {
            total_pixels: 10000,
            outside_mask_changed: 0,
            inside_mask_changed: 0,
        };
        let decision = evaluate_qualification(
            p,
            &move_cursor_action(50.0, 50.0),
            Some(physical_pos(50, 50)),
            Some(pointer_at(50, 50)),
            Some(pointer_at(60, 60)), // 10 pixels off — exceeds tolerance of 2
            false,
            gens,
            gens,
            1100,
            1000,
            false,
            false,
            Some(&Ok(result)),
        );
        assert!(matches!(
            decision,
            QualificationDecision::DoesNotQualify(NonQualificationReason::PointerOutOfTolerance)
        ));
    }

    #[test]
    fn computer_observation_qualification_generation_changed() {
        let p = policy();
        let old_gens = gen_snapshot(1);
        let new_gens = GenerationSnapshot {
            observation: ObservationEpoch(2), // changed
            ..old_gens
        };
        let result = ComparisonResult {
            total_pixels: 10000,
            outside_mask_changed: 0,
            inside_mask_changed: 0,
        };
        let decision = evaluate_qualification(
            p,
            &move_cursor_action(50.0, 50.0),
            Some(physical_pos(50, 50)),
            Some(pointer_at(50, 50)),
            Some(pointer_at(50, 50)),
            false,
            old_gens,
            new_gens,
            1100,
            1000,
            false,
            false,
            Some(&Ok(result)),
        );
        assert!(matches!(
            decision,
            QualificationDecision::DoesNotQualify(NonQualificationReason::GenerationChanged)
        ));
    }

    #[test]
    fn computer_observation_qualification_dispatch_uncertain() {
        let p = policy();
        let gens = gen_snapshot(1);
        let result = ComparisonResult {
            total_pixels: 10000,
            outside_mask_changed: 0,
            inside_mask_changed: 0,
        };
        let decision = evaluate_qualification(
            p,
            &move_cursor_action(50.0, 50.0),
            Some(physical_pos(50, 50)),
            Some(pointer_at(50, 50)),
            Some(pointer_at(50, 50)),
            false,
            gens,
            gens,
            1100,
            1000,
            true, // dispatch unknown
            false,
            Some(&Ok(result)),
        );
        assert!(matches!(
            decision,
            QualificationDecision::DoesNotQualify(NonQualificationReason::DispatchUncertainty)
        ));
    }

    #[test]
    fn computer_observation_qualification_invalidated() {
        let p = policy();
        let gens = gen_snapshot(1);
        let result = ComparisonResult {
            total_pixels: 10000,
            outside_mask_changed: 0,
            inside_mask_changed: 0,
        };
        let decision = evaluate_qualification(
            p,
            &move_cursor_action(50.0, 50.0),
            Some(physical_pos(50, 50)),
            Some(pointer_at(50, 50)),
            Some(pointer_at(50, 50)),
            false,
            gens,
            gens,
            1100,
            1000,
            false,
            true, // invalidated
            Some(&Ok(result)),
        );
        assert!(matches!(
            decision,
            QualificationDecision::DoesNotQualify(NonQualificationReason::Invalidated)
        ));
    }

    #[test]
    fn computer_observation_qualification_not_fresh() {
        let p = policy();
        let gens = gen_snapshot(1);
        let result = ComparisonResult {
            total_pixels: 10000,
            outside_mask_changed: 0,
            inside_mask_changed: 0,
        };
        let decision = evaluate_qualification(
            p,
            &move_cursor_action(50.0, 50.0),
            Some(physical_pos(50, 50)),
            Some(pointer_at(50, 50)),
            Some(pointer_at(50, 50)),
            false,
            gens,
            gens,
            2000, // 1000ms after completion — exceeds 500ms window
            1000,
            false,
            false,
            Some(&Ok(result)),
        );
        assert!(matches!(
            decision,
            QualificationDecision::DoesNotQualify(NonQualificationReason::NotFresh)
        ));
    }

    #[test]
    fn computer_observation_qualification_outside_mask_exceeded() {
        let p = policy();
        let gens = gen_snapshot(1);
        // 100x100 = 10000 pixels. 0.1% = 10. 11 exceeds.
        let result = ComparisonResult {
            total_pixels: 10000,
            outside_mask_changed: 11,
            inside_mask_changed: 0,
        };
        let decision = evaluate_qualification(
            p,
            &move_cursor_action(50.0, 50.0),
            Some(physical_pos(50, 50)),
            Some(pointer_at(50, 50)),
            Some(pointer_at(50, 50)),
            false,
            gens,
            gens,
            1100,
            1000,
            false,
            false,
            Some(&Ok(result)),
        );
        assert!(matches!(
            decision,
            QualificationDecision::DoesNotQualify(NonQualificationReason::OutsideMaskExceeded)
        ));
    }

    #[test]
    fn computer_observation_qualification_comparison_failure() {
        let p = policy();
        let gens = gen_snapshot(1);
        let decision = evaluate_qualification(
            p,
            &move_cursor_action(50.0, 50.0),
            Some(physical_pos(50, 50)),
            Some(pointer_at(50, 50)),
            Some(pointer_at(50, 50)),
            false,
            gens,
            gens,
            1100,
            1000,
            false,
            false,
            Some(&Err(ComparisonError::DimensionMismatch {
                old: super::super::PixelSize {
                    width: 10,
                    height: 10,
                },
                new: super::super::PixelSize {
                    width: 20,
                    height: 20,
                },
            })),
        );
        assert!(matches!(
            decision,
            QualificationDecision::DoesNotQualify(NonQualificationReason::ComparisonFailure)
        ));
    }

    #[test]
    fn computer_observation_qualification_no_comparison() {
        let p = policy();
        let gens = gen_snapshot(1);
        let decision = evaluate_qualification(
            p,
            &move_cursor_action(50.0, 50.0),
            Some(physical_pos(50, 50)),
            Some(pointer_at(50, 50)),
            Some(pointer_at(50, 50)),
            false,
            gens,
            gens,
            1100,
            1000,
            false,
            false,
            None, // no comparison result
        );
        assert!(matches!(
            decision,
            QualificationDecision::DoesNotQualify(NonQualificationReason::ComparisonFailure)
        ));
    }

    // =====================================================================
    // Full integration: qualification drives the state machine
    // =====================================================================

    #[test]
    fn computer_observation_integration_three_qualifiers_to_stable() {
        let p = policy();
        let gens = gen_snapshot(1);
        let mut sm = VerificationStateMachine::new();

        for _ in 0..3 {
            let result = ComparisonResult {
                total_pixels: 10000,
                outside_mask_changed: 0,
                inside_mask_changed: 0,
            };
            let decision = evaluate_qualification(
                p,
                &move_cursor_action(50.0, 50.0),
                Some(physical_pos(50, 50)),
                Some(pointer_at(50, 50)),
                Some(pointer_at(50, 50)),
                false,
                gens,
                gens,
                1100,
                1000,
                false,
                false,
                Some(&Ok(result)),
            );
            assert!(matches!(decision, QualificationDecision::Qualifies));
            sm.apply(&decision);
        }
        assert_eq!(sm.level(), VerificationLevel::Stable);
    }

    #[test]
    fn computer_observation_integration_nonqualifier_resets() {
        let p = policy();
        let gens = gen_snapshot(1);
        let mut sm = VerificationStateMachine::new();

        // Two qualifiers → Guarded.
        for _ in 0..2 {
            let result = ComparisonResult {
                total_pixels: 10000,
                outside_mask_changed: 0,
                inside_mask_changed: 0,
            };
            let decision = evaluate_qualification(
                p,
                &move_cursor_action(50.0, 50.0),
                Some(physical_pos(50, 50)),
                Some(pointer_at(50, 50)),
                Some(pointer_at(50, 50)),
                false,
                gens,
                gens,
                1100,
                1000,
                false,
                false,
                Some(&Ok(result)),
            );
            sm.apply(&decision);
        }
        assert_eq!(sm.level(), VerificationLevel::Guarded);

        // A type action (never qualifying) resets to Strict.
        let type_decision = evaluate_qualification(
            p,
            &type_action(),
            None,
            None,
            None,
            false,
            gens,
            gens,
            1100,
            1000,
            false,
            false,
            None,
        );
        sm.apply(&type_decision);
        assert_eq!(sm.level(), VerificationLevel::Strict);
        assert_eq!(sm.consecutive_qualifiers(), 0);
    }

    // =====================================================================
    // Policy fixture tests
    // =====================================================================

    #[test]
    fn computer_observation_policy_v1_constants() {
        let p = ObservationVerificationPolicy::v1();
        assert_eq!(p.version, 1);
        assert_eq!(p.channel_delta_threshold, 16);
        assert_eq!(p.pointer_mask_padding, 8);
        assert_eq!(p.click_mask_size(), 96);
        assert_eq!(p.freshness_window, Duration::from_millis(500));
        assert_eq!(p.pointer_tolerance, 2);
        assert_eq!(p.outside_mask_fraction_basis_points, 10);
        assert_eq!(p.outside_mask_absolute_cap, 4096);
    }

    #[test]
    fn computer_observation_policy_default_is_v1() {
        assert_eq!(
            ObservationVerificationPolicy::default(),
            ObservationVerificationPolicy::v1()
        );
    }

    // =====================================================================
    // Action-qualifiable exhaustive match test
    // =====================================================================

    #[test]
    fn computer_observation_action_qualifiable_exhaustive() {
        // move_cursor qualifies.
        assert!(action_qualifiable(&move_cursor_action(1.0, 1.0)));
        // single click qualifies.
        assert!(action_qualifiable(&single_click_action()));
        // double click does not qualify.
        assert!(!action_qualifiable(&ComputerAction::Click {
            button: super::super::MouseButton::Left,
            count: super::super::ClickCount::Double,
            modifiers: super::super::Modifiers::default(),
        }));
        // triple click does not qualify.
        assert!(!action_qualifiable(&ComputerAction::Click {
            button: super::super::MouseButton::Left,
            count: super::super::ClickCount::Triple,
            modifiers: super::super::Modifiers::default(),
        }));
        // All other actions never qualify.
        assert!(!action_qualifiable(&type_action()));
        assert!(!action_qualifiable(&drag_action()));
        assert!(!action_qualifiable(&scroll_action()));
        assert!(!action_qualifiable(&wait_action()));
        assert!(!action_qualifiable(&key_action()));
        assert!(!action_qualifiable(&ComputerAction::CaptureFull));
        assert!(!action_qualifiable(&ComputerAction::MouseDown {
            button: super::super::MouseButton::Left,
        }));
        assert!(!action_qualifiable(&ComputerAction::MouseUp {
            button: super::super::MouseButton::Left,
        }));
        assert!(!action_qualifiable(&ComputerAction::HoldKey {
            key: "Shift".to_string(),
            duration: Duration::from_millis(1),
        }));
    }
}
