//! Transient image-dossier coordinate bridge for computer use.
//!
//! This module lets a live computer turn borrow sidecar spatial observations
//! from the exact current screenshot while preventing dossier coordinates,
//! OCR, text, or pixels from becoming action authority or durable state.
//!
//! # Architecture
//!
//! [`ComputerDossier`] is a transient, memory-only dossier bound to a single
//! [`LiveComputerFrame`] by an exact key tuple
//! ([`ComputerDossierKey`]): session, delegation, observation epoch, focus
//! generation, display generation, frame checksum, dossier schema version,
//! and sidecar destination digest. It borrows the frame; it never creates a
//! typed retained attachment.
//!
//! Spatial entries use integer source-pixel rectangles
//! ([`SourcePixelRect`]) and `confidence_bp: u16` in `0..=10_000` basis
//! points. No float confidence is accepted or persisted.
//!
//! Conversion to physical coordinates applies the observation's checked
//! orientation/crop/scale/letterbox transform
//! ([`ObservationTransform`]) and returns an advisory
//! [`CoordinateCandidate`] containing source bounds, physical bounds,
//! confidence basis points, transform generation, element/region ID, and
//! uncertainty flags. It cannot construct [`crate::computer::ComputerAction`]
//! or bypass re-observation, target/focus generation checks, pointer
//! confirmation, Ask lease, host-global physical lease, audit, or action
//! sequencing.
//!
//! For computer-origin frames the entire dossier — summary, OCR text,
//! regions, elements, rationale, coordinates, and pixels — is memory-only
//! for that observation and is dropped on the first of action handoff, newer
//! observation, focus/display/lease change, cancellation, delegation terminal
//! state, or 60 injected-clock seconds. Durable sinks receive only
//! [`ComputerDossierSanitizedMetadata`]: `dossier_used: true`, schema
//! version, destination digest, frame checksum, and bounded counts; never
//! dossier content.
//!
//! # Privacy boundary
//!
//! The privacy boundary is stronger for live computer frames than for
//! user-retained attachments because OCR/element text can expose transient
//! screen content. The bridge types are non-serializable and module-private
//! except for the sanitized count metadata.

use std::sync::Mutex;

use super::{
    DOSSIER_SCHEMA_VERSION, DossierError, PixelBounds, StoragePayloadKind, StorageTarget,
    StorageWrite, StorageWriteTracker,
};
use crate::computer::PixelRect;
use crate::computer::frame::{FrameChecksum, FrameDimensions, LiveComputerFrame};
use crate::computer::observation::{GeometryGeneration, ObservationEpoch, TargetGeneration};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The injected-clock lifetime of a borrowed computer dossier: 60 seconds.
/// The dossier is dropped on the first of action handoff, newer observation,
/// focus/display/lease change, cancellation, delegation terminal state, or
/// this many injected-clock seconds.
pub const COMPUTER_DOSSIER_TTL_MS: u64 = 60_000;

/// Confidence threshold (basis points) below which a candidate is labeled
/// `low_confidence`. A candidate at or above 8,000bp is not labeled; a
/// candidate below 8,000bp is labeled. The label never changes action
/// authorization — there is no threshold that dispatches automatically.
pub const LOW_CONFIDENCE_THRESHOLD_BP: u16 = 8_000;

// ---------------------------------------------------------------------------
// Integer source-pixel rectangle
// ---------------------------------------------------------------------------

/// Integer source-pixel rectangle `[x_px, y_px, width_px, height_px]` with
/// positive width/height wholly inside the decoded source. Floating point,
/// NaN, infinity, and normalized/display coordinates are not representable.
///
/// This is the spatial-entry bounds type used by the computer dossier. It
/// mirrors [`PixelBounds`] but is kept distinct so the bridge cannot be
/// confused with the durable-attachment dossier schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePixelRect {
    pub x_px: u32,
    pub y_px: u32,
    pub width_px: u32,
    pub height_px: u32,
}

impl SourcePixelRect {
    /// Validate that width/height are positive and the bounds are wholly
    /// inside the decoded source of the given dimensions.
    pub fn validate(
        &self,
        source_width_px: u32,
        source_height_px: u32,
    ) -> Result<(), ComputerDossierError> {
        if self.width_px == 0 {
            return Err(ComputerDossierError::ZeroWidth);
        }
        if self.height_px == 0 {
            return Err(ComputerDossierError::ZeroHeight);
        }
        let right = self
            .x_px
            .checked_add(self.width_px)
            .ok_or(ComputerDossierError::BoundsOverflow)?;
        if right > source_width_px {
            return Err(ComputerDossierError::BoundsOutsideFrame);
        }
        let bottom = self
            .y_px
            .checked_add(self.height_px)
            .ok_or(ComputerDossierError::BoundsOverflow)?;
        if bottom > source_height_px {
            return Err(ComputerDossierError::BoundsOutsideFrame);
        }
        Ok(())
    }

    /// Convert to the durable-attachment [`PixelBounds`] type. This is used
    /// only when constructing the validated dossier entries; the bridge never
    /// persists the result.
    pub fn to_pixel_bounds(self) -> PixelBounds {
        PixelBounds {
            x_px: self.x_px,
            y_px: self.y_px,
            width_px: self.width_px,
            height_px: self.height_px,
        }
    }
}

impl From<PixelBounds> for SourcePixelRect {
    fn from(b: PixelBounds) -> Self {
        Self {
            x_px: b.x_px,
            y_px: b.y_px,
            width_px: b.width_px,
            height_px: b.height_px,
        }
    }
}

// ---------------------------------------------------------------------------
// Confidence — integer basis points 0..=10_000 (u16)
// ---------------------------------------------------------------------------

/// Integer basis points `0..=10_000` stored as `u16`. Floating point, NaN,
/// infinity, and normalized values are not representable.
///
/// This is the confidence type used by the computer dossier. It is kept
/// distinct from [`ConfidenceBps`] (which is `u32`) so the bridge enforces
/// the stricter `u16` range and never accepts a float shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfidenceBp(pub u16);

impl ConfidenceBp {
    pub const MAX: u16 = 10_000;

    /// Validate that the value is in `0..=10_000`. Since `u16` max is 65_535,
    /// values above 10_000 are rejected.
    pub fn validate(&self) -> Result<(), ComputerDossierError> {
        if self.0 > Self::MAX {
            return Err(ComputerDossierError::ConfidenceOutOfRange {
                actual: u32::from(self.0),
                max: u32::from(Self::MAX),
            });
        }
        Ok(())
    }

    /// Returns true if this candidate is below the low-confidence threshold.
    /// The label never changes action authorization.
    pub fn is_low_confidence(&self) -> bool {
        self.0 < LOW_CONFIDENCE_THRESHOLD_BP
    }
}

// ---------------------------------------------------------------------------
// Dossier key — exact binding tuple
// ---------------------------------------------------------------------------

/// The exact key tuple for a computer dossier. Keyed by session, delegation,
/// observation epoch, focus generation, display generation, frame checksum,
/// dossier schema version, and sidecar destination digest. Any change is an
/// exact invalidation.
///
/// This type is `PartialEq`/`Eq`/`Hash` but deliberately **not** `Serialize`
/// — it must never be persisted.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ComputerDossierKey {
    pub session_id: String,
    pub delegation_id: String,
    pub observation_epoch: ObservationEpoch,
    pub focus_generation: TargetGeneration,
    pub display_generation: GeometryGeneration,
    /// The SHA-256 checksum hex string of the borrowed frame. Stored as a
    /// plain `String` (not [`FrameChecksum`]) so the key can derive `Hash`.
    pub frame_checksum_hex: String,
    pub dossier_schema_version: u8,
    pub sidecar_destination_digest: String,
}

impl std::fmt::Debug for ComputerDossierKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComputerDossierKey")
            .field("session_id", &self.session_id)
            .field("delegation_id", &self.delegation_id)
            .field("observation_epoch", &self.observation_epoch)
            .field("focus_generation", &self.focus_generation)
            .field("display_generation", &self.display_generation)
            .field("frame_checksum_hex", &self.frame_checksum_hex)
            .field("dossier_schema_version", &self.dossier_schema_version)
            .field(
                "sidecar_destination_digest",
                &self.sidecar_destination_digest,
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Observation transform — integer rational orientation/crop/scale/letterbox
// ---------------------------------------------------------------------------

/// The checked orientation/crop/scale/letterbox transform carried by an
/// observation. All fields are integer rationals (numerator/denominator); no
/// floating point, no normalized 0..1 coordinates.
///
/// The transform maps a source-pixel rectangle to a physical-pixel rectangle.
/// Rotation is 0/90/180/270 degrees. Crop is an integer source-pixel offset.
/// Scale is an integer rational (numerator/denominator). Letterbox is an
/// integer physical-pixel inset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservationTransform {
    /// Rotation in degrees: 0, 90, 180, or 270.
    pub rotation_deg: u16,
    /// Crop offset in source pixels (applied before rotation/scale).
    pub crop_x_px: u32,
    pub crop_y_px: u32,
    /// Scale numerator/denominator. Physical = source * numerator / denominator.
    pub scale_numerator: u32,
    pub scale_denominator: u32,
    /// Letterbox inset in physical pixels (applied after scale).
    pub letterbox_x_px: u32,
    pub letterbox_y_px: u32,
    /// The geometry generation of this transform. A change is an exact
    /// invalidation.
    pub geometry_generation: GeometryGeneration,
    /// Source frame dimensions in pixels.
    pub source_width_px: u32,
    pub source_height_px: u32,
    /// Physical display dimensions in pixels.
    pub physical_width_px: u32,
    pub physical_height_px: u32,
}

/// Errors from transform application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransformError {
    #[error("arithmetic overflow in transform")]
    Overflow,
    #[error("noninvertible transform")]
    Noninvertible,
    #[error("bounds clip outside the observed frame")]
    BoundsClipOutsideFrame,
    #[error("invalid rotation: {0}")]
    InvalidRotation(u16),
    #[error("invalid scale denominator: 0")]
    ZeroDenominator,
    #[error("source bounds outside frame")]
    SourceBoundsOutsideFrame,
}

impl ObservationTransform {
    /// The identity transform (no rotation, no crop, 1:1 scale, no letterbox).
    pub fn identity(
        geometry_generation: GeometryGeneration,
        source_width_px: u32,
        source_height_px: u32,
        physical_width_px: u32,
        physical_height_px: u32,
    ) -> Self {
        Self {
            rotation_deg: 0,
            crop_x_px: 0,
            crop_y_px: 0,
            scale_numerator: 1,
            scale_denominator: 1,
            letterbox_x_px: 0,
            letterbox_y_px: 0,
            geometry_generation,
            source_width_px,
            source_height_px,
            physical_width_px,
            physical_height_px,
        }
    }

    /// Validate the transform fields.
    pub fn validate(&self) -> Result<(), TransformError> {
        if !matches!(self.rotation_deg, 0 | 90 | 180 | 270) {
            return Err(TransformError::InvalidRotation(self.rotation_deg));
        }
        if self.scale_denominator == 0 {
            return Err(TransformError::ZeroDenominator);
        }
        Ok(())
    }

    /// Apply the transform to a source-pixel rectangle, returning the
    /// physical-pixel rectangle.
    ///
    /// Rounding is floor for top/left and ceil for bottom/right so the
    /// physical box encloses the source box. All arithmetic is checked
    /// integer rational — no floating point.
    pub fn to_physical(&self, source: SourcePixelRect) -> Result<PixelRect, TransformError> {
        self.validate()?;
        // Validate source bounds are inside the source frame.
        source
            .validate(self.source_width_px, self.source_height_px)
            .map_err(|_| TransformError::SourceBoundsOutsideFrame)?;

        // Step 1: subtract crop offset.
        let (cx, cy) = (self.crop_x_px, self.crop_y_px);
        let x_after_crop = source
            .x_px
            .checked_sub(cx)
            .ok_or(TransformError::BoundsClipOutsideFrame)?;
        let y_after_crop = source
            .y_px
            .checked_sub(cy)
            .ok_or(TransformError::BoundsClipOutsideFrame)?;
        let right_after_crop = source
            .x_px
            .checked_add(source.width_px)
            .ok_or(TransformError::Overflow)?
            .checked_sub(cx)
            .ok_or(TransformError::BoundsClipOutsideFrame)?;
        let bottom_after_crop = source
            .y_px
            .checked_add(source.height_px)
            .ok_or(TransformError::Overflow)?
            .checked_sub(cy)
            .ok_or(TransformError::BoundsClipOutsideFrame)?;

        // Step 2: apply rotation. For 0/180, width/height are preserved.
        // For 90/270, width/height are swapped.
        let (x_rot, y_rot, right_rot, bottom_rot) = match self.rotation_deg {
            0 => (
                x_after_crop,
                y_after_crop,
                right_after_crop,
                bottom_after_crop,
            ),
            180 => {
                // 180: (x, y) -> (source_w - x - w, source_h - y - h)
                let src_w = self.source_width_px.saturating_sub(cx);
                let src_h = self.source_height_px.saturating_sub(cy);
                let new_x = src_w
                    .checked_sub(right_after_crop)
                    .ok_or(TransformError::Overflow)?;
                let new_y = src_h
                    .checked_sub(bottom_after_crop)
                    .ok_or(TransformError::Overflow)?;
                let new_right = src_w
                    .checked_sub(x_after_crop)
                    .ok_or(TransformError::Overflow)?;
                let new_bottom = src_h
                    .checked_sub(y_after_crop)
                    .ok_or(TransformError::Overflow)?;
                (new_x, new_y, new_right, new_bottom)
            }
            90 => {
                // 90 CW: (x, y) -> (src_h - y - h, x)
                let src_h = self.source_height_px.saturating_sub(cy);
                let new_x = src_h
                    .checked_sub(bottom_after_crop)
                    .ok_or(TransformError::Overflow)?;
                let new_y = x_after_crop;
                let new_right = src_h
                    .checked_sub(y_after_crop)
                    .ok_or(TransformError::Overflow)?;
                let new_bottom = right_after_crop;
                (new_x, new_y, new_right, new_bottom)
            }
            270 => {
                // 270 CW: (x, y) -> (y, src_w - x - w)
                let src_w = self.source_width_px.saturating_sub(cx);
                let new_x = y_after_crop;
                let new_y = src_w
                    .checked_sub(right_after_crop)
                    .ok_or(TransformError::Overflow)?;
                let new_right = bottom_after_crop;
                let new_bottom = src_w
                    .checked_sub(x_after_crop)
                    .ok_or(TransformError::Overflow)?;
                (new_x, new_y, new_right, new_bottom)
            }
            _ => return Err(TransformError::InvalidRotation(self.rotation_deg)),
        };

        // Step 3: apply scale (integer rational). Floor for top/left, ceil
        // for bottom/right so the physical box encloses the source box.
        let scale_num = self.scale_numerator;
        let scale_den = self.scale_denominator;
        let phys_left = floor_div(x_rot, scale_num, scale_den)?;
        let phys_top = floor_div(y_rot, scale_num, scale_den)?;
        let phys_right = ceil_div(right_rot, scale_num, scale_den)?;
        let phys_bottom = ceil_div(bottom_rot, scale_num, scale_den)?;

        // Step 4: apply letterbox inset.
        let phys_x = phys_left
            .checked_add(self.letterbox_x_px)
            .ok_or(TransformError::Overflow)?;
        let phys_y = phys_top
            .checked_add(self.letterbox_y_px)
            .ok_or(TransformError::Overflow)?;
        let phys_right = phys_right
            .checked_add(self.letterbox_x_px)
            .ok_or(TransformError::Overflow)?;
        let phys_bottom = phys_bottom
            .checked_add(self.letterbox_y_px)
            .ok_or(TransformError::Overflow)?;

        // Step 5: compute width/height. Ceil for bottom/right minus floor for
        // top/left so the box encloses the source.
        let phys_width = phys_right
            .checked_sub(phys_left)
            .ok_or(TransformError::Overflow)?;
        let phys_height = phys_bottom
            .checked_sub(phys_top)
            .ok_or(TransformError::Overflow)?;

        // Step 6: clip to physical display bounds.
        if phys_x > self.physical_width_px
            || phys_y > self.physical_height_px
            || phys_right > self.physical_width_px
            || phys_bottom > self.physical_height_px
        {
            return Err(TransformError::BoundsClipOutsideFrame);
        }

        Ok(PixelRect {
            x: phys_x,
            y: phys_y,
            width: phys_width,
            height: phys_height,
        })
    }
}

/// Floor division for transform: `(value * num) / den`, rounded down.
/// Returns the quotient floor.
fn floor_div(value: u32, num: u32, den: u32) -> Result<u32, TransformError> {
    if den == 0 {
        return Err(TransformError::ZeroDenominator);
    }
    let product = value.checked_mul(num).ok_or(TransformError::Overflow)?;
    Ok(product / den)
}

/// Ceil division for transform: `(value * num) / den`, rounded up.
/// Returns the quotient ceil.
fn ceil_div(value: u32, num: u32, den: u32) -> Result<u32, TransformError> {
    if den == 0 {
        return Err(TransformError::ZeroDenominator);
    }
    let product = value.checked_mul(num).ok_or(TransformError::Overflow)?;
    let q = product / den;
    let r = product % den;
    if r == 0 {
        Ok(q)
    } else {
        q.checked_add(1).ok_or(TransformError::Overflow)
    }
}

// ---------------------------------------------------------------------------
// Spatial dossier entries (memory-only)
// ---------------------------------------------------------------------------

/// A spatial dossier entry with integer source-pixel bounds, integer basis
/// points confidence, and an element/region ID. Memory-only; never persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DossierSpatialEntry {
    pub id: String,
    pub source_bounds: SourcePixelRect,
    pub confidence_bp: ConfidenceBp,
}

// ---------------------------------------------------------------------------
// Coordinate candidate — advisory planning evidence only
// ---------------------------------------------------------------------------

/// Uncertainty flags on a coordinate candidate. These are advisory only and
/// never change action authorization.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoordinateUncertaintyFlags {
    /// The candidate's confidence is below the low-confidence threshold.
    pub low_confidence: bool,
    /// The transform was non-identity (rotation/crop/scale/letterbox).
    pub transform_applied: bool,
    /// The source bounds are near the frame edge (within a few pixels).
    pub near_edge: bool,
}

/// An advisory coordinate candidate. Contains source bounds, physical bounds,
/// confidence basis points, transform generation, element/region ID, and
/// uncertainty flags.
///
/// This is **advisory planning evidence only**. It cannot be converted directly
/// to a [`crate::computer::ComputerAction`]; the coordinator must revalidate
/// exact observation/focus/display/host-lease generations immediately before
/// input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinateCandidate {
    pub source_bounds: SourcePixelRect,
    pub physical_bounds: PixelRect,
    pub confidence_bp: ConfidenceBp,
    pub transform_generation: GeometryGeneration,
    pub element_id: String,
    pub uncertainty: CoordinateUncertaintyFlags,
}

// ---------------------------------------------------------------------------
// Computer dossier errors
// ---------------------------------------------------------------------------

/// Errors from computer dossier operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ComputerDossierError {
    #[error("computer dossier already released")]
    AlreadyReleased,
    #[error("computer dossier key mismatch")]
    KeyMismatch,
    #[error("computer dossier expired")]
    Expired,
    #[error("sidecar destination digest mismatch")]
    DestinationMismatch,
    #[error("dossier schema version mismatch: actual {actual}, expected {expected}")]
    SchemaVersionMismatch { actual: u8, expected: u8 },
    #[error("confidence out of range: actual {actual}, max {max}")]
    ConfidenceOutOfRange { actual: u32, max: u32 },
    #[error("pixel bounds width is zero")]
    ZeroWidth,
    #[error("pixel bounds height is zero")]
    ZeroHeight,
    #[error("pixel bounds overflow")]
    BoundsOverflow,
    #[error("pixel bounds outside source frame")]
    BoundsOutsideFrame,
    #[error("duplicate element id: {id}")]
    DuplicateElementId { id: String },
    #[error("transform error: {0}")]
    Transform(TransformError),
    #[error("sidecar unavailable or disabled")]
    SidecarUnavailable,
}

impl From<TransformError> for ComputerDossierError {
    fn from(e: TransformError) -> Self {
        Self::Transform(e)
    }
}

impl From<DossierError> for ComputerDossierError {
    fn from(e: DossierError) -> Self {
        match e {
            DossierError::ConfidenceOutOfRange { actual, max } => {
                Self::ConfidenceOutOfRange { actual, max }
            }
            DossierError::ZeroWidth => Self::ZeroWidth,
            DossierError::ZeroHeight => Self::ZeroHeight,
            DossierError::BoundsOverflow => Self::BoundsOverflow,
            DossierError::BoundsOutsideImage => Self::BoundsOutsideFrame,
            DossierError::DuplicateUiElementId { id } => Self::DuplicateElementId { id },
            DossierError::SchemaVersionMismatch { actual, expected } => {
                Self::SchemaVersionMismatch { actual, expected }
            }
            _ => Self::SidecarUnavailable,
        }
    }
}

// ---------------------------------------------------------------------------
// Sanitized metadata — the only value durable sinks may record
// ---------------------------------------------------------------------------

/// The only value durable sinks may record for a computer dossier. Contains
/// `dossier_used: true`, schema version, destination digest, frame checksum,
/// and bounded counts. Never dossier content (no summary, OCR, text,
/// rationale, coordinates, or pixels).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ComputerDossierSanitizedMetadata {
    pub dossier_used: bool,
    pub schema_version: u8,
    pub destination_digest: String,
    pub frame_checksum: String,
    pub ocr_count: u32,
    pub layout_count: u32,
    pub element_count: u32,
    pub fact_count: u32,
}

// ---------------------------------------------------------------------------
// Computer dossier — transient, memory-only, borrowed frame
// ---------------------------------------------------------------------------

/// A transient, memory-only image-dossier coordinate bridge for a live
/// computer turn.
///
/// It borrows the exact [`LiveComputerFrame`] for one observation and is
/// dropped on the first of action handoff, newer observation, focus/display/
/// lease change, cancellation, delegation terminal state, or 60
/// injected-clock seconds. It never creates a typed retained attachment.
///
/// The entire dossier — summary, OCR text, regions, elements, rationale,
/// coordinates, and pixels — is memory-only for that observation. Durable
/// sinks receive only [`ComputerDossierSanitizedMetadata`].
///
/// This type is deliberately **not** `Serialize` and **not** `Clone`. It is
/// move-only and module-private except for the sanitized metadata.
pub struct ComputerDossier {
    key: ComputerDossierKey,
    entries: Vec<DossierSpatialEntry>,
    /// Borrowed frame reference. The dossier does not own the frame; it
    /// borrows it for the observation lifetime.
    frame_checksum: FrameChecksum,
    frame_dimensions: FrameDimensions,
    released: bool,
    created_at_ms: u64,
    /// Bounded counts for the sanitized metadata.
    ocr_count: u32,
    layout_count: u32,
    element_count: u32,
    fact_count: u32,
}

impl ComputerDossier {
    /// Construct a new computer dossier bound to a live frame by an exact key.
    /// The frame is borrowed (not moved); the dossier stores only its checksum
    /// and dimensions. The entries are validated before construction.
    ///
    /// `created_at_ms` is the injected-clock timestamp of creation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: ComputerDossierKey,
        frame: &LiveComputerFrame,
        entries: Vec<DossierSpatialEntry>,
        counts: ComputerDossierCounts,
        created_at_ms: u64,
    ) -> Result<Self, ComputerDossierError> {
        // Validate the schema version.
        if key.dossier_schema_version != DOSSIER_SCHEMA_VERSION {
            return Err(ComputerDossierError::SchemaVersionMismatch {
                actual: key.dossier_schema_version,
                expected: DOSSIER_SCHEMA_VERSION,
            });
        }
        // Validate the frame checksum matches the key.
        if frame.checksum().0 != key.frame_checksum_hex {
            return Err(ComputerDossierError::KeyMismatch);
        }
        let dims = frame.dimensions();
        // Validate each entry's bounds and confidence.
        let mut seen_ids = std::collections::BTreeSet::new();
        for entry in &entries {
            entry.confidence_bp.validate()?;
            entry.source_bounds.validate(dims.width, dims.height)?;
            if !seen_ids.insert(entry.id.clone()) {
                return Err(ComputerDossierError::DuplicateElementId {
                    id: entry.id.clone(),
                });
            }
        }
        Ok(Self {
            key,
            entries,
            frame_checksum: frame.checksum().clone(),
            frame_dimensions: dims,
            released: false,
            created_at_ms,
            ocr_count: counts.ocr_count,
            layout_count: counts.layout_count,
            element_count: counts.element_count,
            fact_count: counts.fact_count,
        })
    }

    /// The exact key tuple for this dossier.
    pub fn key(&self) -> &ComputerDossierKey {
        &self.key
    }

    /// Whether this dossier has been released.
    pub fn is_released(&self) -> bool {
        self.released
    }

    /// Whether this dossier is expired relative to the injected clock. The
    /// dossier expires 60 seconds after creation.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.created_at_ms) >= COMPUTER_DOSSIER_TTL_MS
    }

    /// Whether this dossier is stale relative to a newer observation epoch.
    pub fn is_stale_relative_to(&self, current_epoch: ObservationEpoch) -> bool {
        self.key.observation_epoch < current_epoch
    }

    /// Whether this dossier's generations match the current snapshot. Any
    /// change is an exact invalidation.
    pub fn generations_match(&self, focus: TargetGeneration, display: GeometryGeneration) -> bool {
        self.key.focus_generation == focus && self.key.display_generation == display
    }

    /// Borrow the spatial entries. The entries are memory-only; the caller
    /// must not persist them.
    pub fn entries(&self) -> &[DossierSpatialEntry] {
        &self.entries
    }

    /// Convert a spatial entry to an advisory coordinate candidate using the
    /// observation's checked transform. Returns advisory planning evidence
    /// only; it cannot construct a [`crate::computer::ComputerAction`].
    pub fn to_candidate(
        &self,
        entry_id: &str,
        transform: &ObservationTransform,
    ) -> Result<CoordinateCandidate, ComputerDossierError> {
        if self.released {
            return Err(ComputerDossierError::AlreadyReleased);
        }
        // The transform generation must match the dossier's display generation.
        if transform.geometry_generation != self.key.display_generation {
            return Err(ComputerDossierError::KeyMismatch);
        }
        let entry = self
            .entries
            .iter()
            .find(|e| e.id == entry_id)
            .ok_or(ComputerDossierError::KeyMismatch)?;
        let physical = transform
            .to_physical(entry.source_bounds)
            .map_err(ComputerDossierError::from)?;
        let low_conf = entry.confidence_bp.is_low_confidence();
        let transform_applied = *transform
            != ObservationTransform::identity(
                transform.geometry_generation,
                transform.source_width_px,
                transform.source_height_px,
                transform.physical_width_px,
                transform.physical_height_px,
            );
        let near_edge = is_near_edge(&entry.source_bounds, &self.frame_dimensions);
        Ok(CoordinateCandidate {
            source_bounds: entry.source_bounds,
            physical_bounds: physical,
            confidence_bp: entry.confidence_bp,
            transform_generation: transform.geometry_generation,
            element_id: entry.id.clone(),
            uncertainty: CoordinateUncertaintyFlags {
                low_confidence: low_conf,
                transform_applied,
                near_edge,
            },
        })
    }

    /// Construct the sanitized metadata for durable sinks. This is the only
    /// value durable sinks may record. It contains no dossier content.
    pub fn sanitized(&self) -> ComputerDossierSanitizedMetadata {
        ComputerDossierSanitizedMetadata {
            dossier_used: true,
            schema_version: self.key.dossier_schema_version,
            destination_digest: self.key.sidecar_destination_digest.clone(),
            frame_checksum: self.frame_checksum.0.clone(),
            ocr_count: self.ocr_count,
            layout_count: self.layout_count,
            element_count: self.element_count,
            fact_count: self.fact_count,
        }
    }

    /// Release the borrowed frame/dossier. Owned buffers are dropped. This is
    /// called on action handoff, newer observation, focus/display/lease
    /// change, cancellation, delegation terminal state, or 60s expiry. The
    /// release is exactly-once.
    pub fn release(&mut self) {
        self.released = true;
        // Drop the entries — they are memory-only.
        self.entries.clear();
    }
}

impl Drop for ComputerDossier {
    fn drop(&mut self) {
        // Ensure the entries are dropped — they are memory-only.
        self.entries.clear();
    }
}

/// Bounded counts for the sanitized metadata. These are the only counts
/// durable sinks receive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ComputerDossierCounts {
    pub ocr_count: u32,
    pub layout_count: u32,
    pub element_count: u32,
    pub fact_count: u32,
}

/// Returns true if the source bounds are near the frame edge (within 4 pixels).
fn is_near_edge(bounds: &SourcePixelRect, dims: &FrameDimensions) -> bool {
    const EDGE_TOLERANCE_PX: u32 = 4;
    bounds.x_px <= EDGE_TOLERANCE_PX
        || bounds.y_px <= EDGE_TOLERANCE_PX
        || bounds.x_px + bounds.width_px + EDGE_TOLERANCE_PX >= dims.width
        || bounds.y_px + bounds.height_px + EDGE_TOLERANCE_PX >= dims.height
}

// ---------------------------------------------------------------------------
// Computer dossier registry — tracks borrowed dossiers and enforces expiry
// ---------------------------------------------------------------------------

/// A registry of borrowed computer dossiers, keyed by delegation ID. Enforces
/// exactly-once release on expiry, newer observation, focus/display/lease
/// change, cancellation, or delegation terminal state.
///
/// This registry is memory-only and never persists dossier content. It uses
/// an injected clock so tests can control expiry.
pub struct ComputerDossierRegistry {
    dossiers: Mutex<Vec<RegisteredDossier>>,
}

struct RegisteredDossier {
    delegation_id: String,
    dossier: ComputerDossier,
}

/// A clock injected into the registry for testability.
pub trait ComputerDossierClock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// A fake clock for tests.
pub struct FakeComputerDossierClock {
    ms: Mutex<u64>,
}

impl FakeComputerDossierClock {
    pub fn new(start_ms: u64) -> Self {
        Self {
            ms: Mutex::new(start_ms),
        }
    }

    pub fn advance(&self, delta_ms: u64) {
        let mut ms = self.ms.lock().unwrap();
        *ms += delta_ms;
    }

    pub fn set(&self, ms: u64) {
        let mut val = self.ms.lock().unwrap();
        *val = ms;
    }
}

impl ComputerDossierClock for FakeComputerDossierClock {
    fn now_ms(&self) -> u64 {
        *self.ms.lock().unwrap()
    }
}

impl Default for ComputerDossierRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ComputerDossierRegistry {
    pub fn new() -> Self {
        Self {
            dossiers: Mutex::new(Vec::new()),
        }
    }

    /// Register a borrowed dossier for a delegation. Replaces any existing
    /// dossier for the same delegation (newer observation invalidates the old
    /// one, which is released exactly once).
    pub fn register(&self, dossier: ComputerDossier) {
        let mut dossiers = self.dossiers.lock().unwrap();
        // Replace any existing dossier for the same delegation.
        let delegation_id = dossier.key().delegation_id.clone();
        if let Some(idx) = dossiers
            .iter()
            .position(|d| d.delegation_id == delegation_id)
        {
            let mut old = dossiers.remove(idx);
            old.dossier.release();
        }
        dossiers.push(RegisteredDossier {
            delegation_id,
            dossier,
        });
    }

    /// Borrow the dossier for a delegation, returning a coordinate candidate.
    /// Validates that the dossier is not expired, not stale, and that the
    /// generations match.
    pub fn candidate(
        &self,
        delegation_id: &str,
        entry_id: &str,
        transform: &ObservationTransform,
        focus: TargetGeneration,
        display: GeometryGeneration,
        current_epoch: ObservationEpoch,
        clock: &dyn ComputerDossierClock,
    ) -> Result<CoordinateCandidate, ComputerDossierError> {
        let mut dossiers = self.dossiers.lock().unwrap();
        let idx = dossiers
            .iter()
            .position(|d| d.delegation_id == delegation_id)
            .ok_or(ComputerDossierError::KeyMismatch)?;
        let registered = &mut dossiers[idx];
        // Check expiry.
        if registered.dossier.is_expired(clock.now_ms()) {
            registered.dossier.release();
            return Err(ComputerDossierError::Expired);
        }
        // Check stale.
        if registered.dossier.is_stale_relative_to(current_epoch) {
            registered.dossier.release();
            return Err(ComputerDossierError::Expired);
        }
        // Check generations.
        if !registered.dossier.generations_match(focus, display) {
            registered.dossier.release();
            return Err(ComputerDossierError::KeyMismatch);
        }
        registered.dossier.to_candidate(entry_id, transform)
    }

    /// Release the dossier for a delegation exactly once. Called on action
    /// handoff, cancellation, or delegation terminal state.
    pub fn release(&self, delegation_id: &str) {
        let mut dossiers = self.dossiers.lock().unwrap();
        if let Some(idx) = dossiers
            .iter()
            .position(|d| d.delegation_id == delegation_id)
        {
            let mut removed = dossiers.remove(idx);
            removed.dossier.release();
        }
    }

    /// Evict all expired dossiers, releasing each exactly once. Called
    /// periodically by the coordinator.
    pub fn evict_expired(&self, clock: &dyn ComputerDossierClock) {
        let mut dossiers = self.dossiers.lock().unwrap();
        let now = clock.now_ms();
        dossiers.retain(|d| !d.dossier.is_expired(now));
        // The dropped entries' `Drop` impls clear their memory.
    }

    /// Evict all dossiers for a delegation that is in a terminal state.
    pub fn evict_delegation(&self, delegation_id: &str) {
        self.release(delegation_id);
    }

    /// The number of registered dossiers.
    pub fn len(&self) -> usize {
        self.dossiers.lock().unwrap().len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.dossiers.lock().unwrap().is_empty()
    }
}

// ---------------------------------------------------------------------------
// Privacy proof helper — assert no dossier content in storage writes
// ---------------------------------------------------------------------------

/// Assert that no storage write contains dossier content. Durable sinks
/// receive only [`ComputerDossierSanitizedMetadata`]; this helper proves that
/// no write contains summary, OCR, text, rationale, coordinates, or pixels.
pub fn assert_no_dossier_content_in_writes(tracker: &StorageWriteTracker) {
    let writes = tracker.writes();
    for w in &writes {
        // Only metadata writes are permitted.
        assert_eq!(
            w.payload_kind,
            StoragePayloadKind::Metadata,
            "non-metadata write to {:?}",
            w.target
        );
        // No body content.
        assert!(
            !w.payload_contains_body,
            "dossier body was written to {:?}",
            w.target
        );
    }
}

/// Record a sanitized metadata write to a storage tracker. This is the only
/// permitted write for a computer dossier.
pub fn record_sanitized_write(tracker: &StorageWriteTracker, target: StorageTarget) {
    tracker.record(StorageWrite {
        target,
        payload_kind: StoragePayloadKind::Metadata,
        payload_contains_body: false,
    });
}

// ---------------------------------------------------------------------------
// Sidecar policy — failure/disabled does not change base eligibility
// ---------------------------------------------------------------------------

/// Sidecar failure or disabled policy does not change base computer-use
/// eligibility or screenshot-only operation. This function is the explicit
/// guard: it returns the base eligibility unchanged regardless of sidecar
/// availability.
pub fn computer_use_eligibility_unchanged(
    base_computer_use_capable: bool,
    sidecar_available: bool,
) -> bool {
    // Sidecar availability is intentionally ignored.
    let _ = sidecar_available;
    base_computer_use_capable
}

#[cfg(test)]
mod tests;
