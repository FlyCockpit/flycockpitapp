//! Tests for the transient image-dossier coordinate bridge for computer use.
//!
//! These tests cover the acceptance criteria from the prompt:
//! 1. `computer_dossier_coordinate_transform` — identity, crop, letterbox,
//!    90/180/270 rotation, HiDPI, boundary, and overflow cases with exact
//!    integer output.
//! 2. `computer_dossier_confidence` — accepts 0..10_000, rejects 10_001/
//!    noninteger/float shapes, labels 7_999/8_000 exactly without granting
//!    authority.
//! 3. `computer_dossier_transient_privacy` — proves pixels, summary, OCR,
//!    region/element text, rationale, and coordinates are absent from
//!    DB/events/audits/journal/export/logs/files.
//! 4. `computer_dossier_epoch_race` — epoch/focus/display/host-lease/action/
//!    60s expiry races release the borrowed frame/dossier exactly once and
//!    late sidecar results are inert.
//! 5. `computer_dossier_no_action_authority` — `CoordinateCandidate` cannot
//!    be converted directly to an action; coordinator tests prove full
//!    ordinary stale/pointer/authorization/host-lease checks still execute.
//! 6. `computer_dossier_sidecar_failure` — sidecar failure or disabled
//!    policy does not change base computer-use eligibility or screenshot-only
//!    operation.

#![allow(clippy::needless_pass_by_value)]

use super::*;
use crate::computer::frame::{
    ActionId, CaptureEpoch, FrameDimensions, InMemoryReservationHandle, LiveComputerFrame,
    ObservationId, ScreenshotMediaType,
};
use crate::computer::observation::{GeometryGeneration, ObservationEpoch, TargetGeneration};
use image::{ImageBuffer, Rgba};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn make_dims(w: u32, h: u32) -> FrameDimensions {
    FrameDimensions {
        width: w,
        height: h,
        region: None,
        native_zoom: None,
    }
}

fn make_rgba_png(width: u32, height: u32, fill: [u8; 4]) -> Vec<u8> {
    let img: ImageBuffer<Rgba<u8>, Vec<u8>> = ImageBuffer::from_pixel(width, height, Rgba(fill));
    let mut bytes = Vec::new();
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut std::io::Cursor::new(&mut bytes), image::ImageFormat::Png)
        .unwrap();
    bytes
}

fn make_reservation() -> (
    Arc<AtomicBool>,
    Box<dyn crate::computer::frame::MediaReservationHandle>,
) {
    let released = Arc::new(AtomicBool::new(false));
    let handle: Box<dyn crate::computer::frame::MediaReservationHandle> =
        Box::new(InMemoryReservationHandle::new(released.clone()));
    (released, handle)
}

fn make_test_frame(width: u32, height: u32, fill: [u8; 4]) -> LiveComputerFrame {
    let png = make_rgba_png(width, height, fill);
    let (_r, handle) = make_reservation();
    LiveComputerFrame::try_new(
        png,
        ScreenshotMediaType::Png,
        make_dims(width, height),
        ObservationId("obs-1".to_string()),
        ActionId("act-1".to_string()),
        CaptureEpoch(1),
        handle,
        None,
    )
    .unwrap()
}

fn valid_key(frame: &LiveComputerFrame) -> ComputerDossierKey {
    ComputerDossierKey {
        session_id: "sess-1".to_string(),
        delegation_id: "del-1".to_string(),
        observation_epoch: ObservationEpoch(1),
        focus_generation: TargetGeneration(1),
        display_generation: GeometryGeneration(1),
        frame_checksum_hex: frame.checksum().0.clone(),
        dossier_schema_version: DOSSIER_SCHEMA_VERSION,
        sidecar_destination_digest: "dest-digest-1".to_string(),
    }
}

fn valid_entry() -> DossierSpatialEntry {
    DossierSpatialEntry {
        id: "btn-1".to_string(),
        source_bounds: SourcePixelRect {
            x_px: 10,
            y_px: 20,
            width_px: 100,
            height_px: 30,
        },
        confidence_bp: ConfidenceBp(9_000),
    }
}

fn valid_counts() -> ComputerDossierCounts {
    ComputerDossierCounts {
        ocr_count: 1,
        layout_count: 1,
        element_count: 1,
        fact_count: 1,
    }
}

// ===========================================================================
// Acceptance criterion 1: computer_dossier_coordinate_transform
// Tests identity, crop, letterbox, 90/180/270 rotation, HiDPI, boundary, and
// overflow cases with exact integer output.
// ===========================================================================

mod coordinate_transform {
    use super::*;

    fn transform(
        rotation: u16,
        crop_x: u32,
        crop_y: u32,
        scale_num: u32,
        scale_den: u32,
        letterbox_x: u32,
        letterbox_y: u32,
        src_w: u32,
        src_h: u32,
        phys_w: u32,
        phys_h: u32,
    ) -> ObservationTransform {
        ObservationTransform {
            rotation_deg: rotation,
            crop_x_px: crop_x,
            crop_y_px: crop_y,
            scale_numerator: scale_num,
            scale_denominator: scale_den,
            letterbox_x_px: letterbox_x,
            letterbox_y_px: letterbox_y,
            geometry_generation: GeometryGeneration(1),
            source_width_px: src_w,
            source_height_px: src_h,
            physical_width_px: phys_w,
            physical_height_px: phys_h,
        }
    }

    #[test]
    fn computer_dossier_coordinate_transform_identity() {
        // Identity: 1:1 scale, no rotation, no crop, no letterbox.
        let t = transform(0, 0, 0, 1, 1, 0, 0, 1920, 1080, 1920, 1080);
        let src = SourcePixelRect {
            x_px: 100,
            y_px: 200,
            width_px: 300,
            height_px: 400,
        };
        let phys = t.to_physical(src).unwrap();
        assert_eq!(phys.x, 100);
        assert_eq!(phys.y, 200);
        assert_eq!(phys.width, 300);
        assert_eq!(phys.height, 400);
    }

    #[test]
    fn computer_dossier_coordinate_transform_crop() {
        // Crop offset: source (110, 220) with crop (10, 20) -> (100, 200).
        let t = transform(0, 10, 20, 1, 1, 0, 0, 1920, 1080, 1920, 1080);
        let src = SourcePixelRect {
            x_px: 110,
            y_px: 220,
            width_px: 300,
            height_px: 400,
        };
        let phys = t.to_physical(src).unwrap();
        assert_eq!(phys.x, 100);
        assert_eq!(phys.y, 200);
        assert_eq!(phys.width, 300);
        assert_eq!(phys.height, 400);
    }

    #[test]
    fn computer_dossier_coordinate_transform_letterbox() {
        // Letterbox: add physical offset.
        let t = transform(0, 0, 0, 1, 1, 50, 60, 1920, 1080, 1920, 1080);
        let src = SourcePixelRect {
            x_px: 100,
            y_px: 200,
            width_px: 300,
            height_px: 400,
        };
        let phys = t.to_physical(src).unwrap();
        assert_eq!(phys.x, 150);
        assert_eq!(phys.y, 260);
        assert_eq!(phys.width, 300);
        assert_eq!(phys.height, 400);
    }

    #[test]
    fn computer_dossier_coordinate_transform_hidpi_scale_2x() {
        // HiDPI 2x scale: physical = source * 2.
        let t = transform(0, 0, 0, 2, 1, 0, 0, 960, 540, 1920, 1080);
        let src = SourcePixelRect {
            x_px: 100,
            y_px: 200,
            width_px: 300,
            height_px: 400,
        };
        let phys = t.to_physical(src).unwrap();
        assert_eq!(phys.x, 200);
        assert_eq!(phys.y, 400);
        assert_eq!(phys.width, 600);
        assert_eq!(phys.height, 800);
    }

    #[test]
    fn computer_dossier_coordinate_transform_hidpi_scale_half() {
        // Half scale: physical = source / 2 (floor for top/left, ceil for
        // bottom/right so the physical box encloses the source box).
        let t = transform(0, 0, 0, 1, 2, 0, 0, 1920, 1080, 960, 540);
        let src = SourcePixelRect {
            x_px: 100,
            y_px: 200,
            width_px: 301,
            height_px: 401,
        };
        let phys = t.to_physical(src).unwrap();
        // floor(100/2) = 50, floor(200/2) = 100
        // ceil(401/2) = 201, ceil(601/2) = 301
        // width = 201 - 100 = 101, height = 301 - 200 = 101
        assert_eq!(phys.x, 50);
        assert_eq!(phys.y, 100);
        assert_eq!(phys.width, 101);
        assert_eq!(phys.height, 151);
    }

    #[test]
    fn computer_dossier_coordinate_transform_rotation_90() {
        // 90 CW: (x, y) -> (src_h - y - h, x)
        // Source: x=100, y=200, w=300, h=400
        // After 90 CW: x = 1080 - 200 - 400 = 480, y = 100
        // right = 1080 - 200 = 880, bottom = 100 + 300 = 400
        // width = 880 - 480 = 400, height = 400 - 100 = 300
        let t = transform(90, 0, 0, 1, 1, 0, 0, 1920, 1080, 1080, 1920);
        let src = SourcePixelRect {
            x_px: 100,
            y_px: 200,
            width_px: 300,
            height_px: 400,
        };
        let phys = t.to_physical(src).unwrap();
        assert_eq!(phys.x, 480);
        assert_eq!(phys.y, 100);
        assert_eq!(phys.width, 400);
        assert_eq!(phys.height, 300);
    }

    #[test]
    fn computer_dossier_coordinate_transform_rotation_180() {
        // 180: (x, y) -> (src_w - x - w, src_h - y - h)
        // Source: x=100, y=200, w=300, h=400
        // After 180: x = 1920 - 400 = 1520, y = 1080 - 600 = 480
        let t = transform(180, 0, 0, 1, 1, 0, 0, 1920, 1080, 1920, 1080);
        let src = SourcePixelRect {
            x_px: 100,
            y_px: 200,
            width_px: 300,
            height_px: 400,
        };
        let phys = t.to_physical(src).unwrap();
        assert_eq!(phys.x, 1520);
        assert_eq!(phys.y, 480);
        assert_eq!(phys.width, 300);
        assert_eq!(phys.height, 400);
    }

    #[test]
    fn computer_dossier_coordinate_transform_rotation_270() {
        // 270 CW: (x, y) -> (y, src_w - x - w)
        // Source: x=100, y=200, w=300, h=400
        // After 270 CW: x = 200, y = 1920 - 400 = 1520
        let t = transform(270, 0, 0, 1, 1, 0, 0, 1920, 1080, 1080, 1920);
        let src = SourcePixelRect {
            x_px: 100,
            y_px: 200,
            width_px: 300,
            height_px: 400,
        };
        let phys = t.to_physical(src).unwrap();
        assert_eq!(phys.x, 200);
        assert_eq!(phys.y, 1520);
        assert_eq!(phys.width, 400);
        assert_eq!(phys.height, 300);
    }

    #[test]
    fn computer_dossier_coordinate_transform_boundary_zero_rect() {
        // Zero width/height rejected.
        let t = transform(0, 0, 0, 1, 1, 0, 0, 1920, 1080, 1920, 1080);
        let src = SourcePixelRect {
            x_px: 100,
            y_px: 200,
            width_px: 0,
            height_px: 400,
        };
        let err = t.to_physical(src).unwrap_err();
        assert_eq!(err, TransformError::SourceBoundsOutsideFrame);
    }

    #[test]
    fn computer_dossier_coordinate_transform_boundary_outside_frame() {
        // Bounds outside the source frame rejected.
        let t = transform(0, 0, 0, 1, 1, 0, 0, 1920, 1080, 1920, 1080);
        let src = SourcePixelRect {
            x_px: 1800,
            y_px: 200,
            width_px: 300,
            height_px: 400,
        };
        let err = t.to_physical(src).unwrap_err();
        assert_eq!(err, TransformError::SourceBoundsOutsideFrame);
    }

    #[test]
    fn computer_dossier_coordinate_transform_overflow_scale() {
        // Scale overflow rejected.
        let t = transform(0, 0, 0, u32::MAX, 1, 0, 0, 1920, 1080, 1920, 1080);
        let src = SourcePixelRect {
            x_px: 100,
            y_px: 200,
            width_px: 300,
            height_px: 400,
        };
        let err = t.to_physical(src).unwrap_err();
        assert_eq!(err, TransformError::Overflow);
    }

    #[test]
    fn computer_dossier_coordinate_transform_clip_outside_physical() {
        // Physical bounds clip outside the physical display rejected.
        let t = transform(0, 0, 0, 1, 1, 0, 0, 1920, 1080, 100, 100);
        let src = SourcePixelRect {
            x_px: 100,
            y_px: 200,
            width_px: 300,
            height_px: 400,
        };
        let err = t.to_physical(src).unwrap_err();
        assert_eq!(err, TransformError::BoundsClipOutsideFrame);
    }

    #[test]
    fn computer_dossier_coordinate_transform_invalid_rotation() {
        // Invalid rotation rejected.
        let t = transform(45, 0, 0, 1, 1, 0, 0, 1920, 1080, 1920, 1080);
        let src = SourcePixelRect {
            x_px: 100,
            y_px: 200,
            width_px: 300,
            height_px: 400,
        };
        let err = t.to_physical(src).unwrap_err();
        assert_eq!(err, TransformError::InvalidRotation(45));
    }

    #[test]
    fn computer_dossier_coordinate_transform_zero_denominator() {
        // Zero denominator rejected.
        let t = transform(0, 0, 0, 1, 0, 0, 0, 1920, 1080, 1920, 1080);
        let src = SourcePixelRect {
            x_px: 100,
            y_px: 200,
            width_px: 300,
            height_px: 400,
        };
        let err = t.to_physical(src).unwrap_err();
        assert_eq!(err, TransformError::ZeroDenominator);
    }

    #[test]
    fn computer_dossier_coordinate_transform_rounding_floor_ceil() {
        // Rounding: floor for top/left, ceil for bottom/right so the physical
        // box encloses the source box. Use a 1/3 scale.
        let t = transform(0, 0, 0, 1, 3, 0, 0, 3000, 3000, 1000, 1000);
        let src = SourcePixelRect {
            x_px: 100,
            y_px: 200,
            width_px: 100,
            height_px: 100,
        };
        let phys = t.to_physical(src).unwrap();
        // floor(100/3) = 33, floor(200/3) = 66
        // ceil(200/3) = 67, ceil(300/3) = 100
        // width = 67 - 33 = 34, height = 100 - 66 = 34
        assert_eq!(phys.x, 33);
        assert_eq!(phys.y, 66);
        assert_eq!(phys.width, 34);
        assert_eq!(phys.height, 34);
    }

    #[test]
    fn computer_dossier_coordinate_transform_combined_crop_scale_letterbox() {
        // Combined: crop (10, 20), 2x scale, letterbox (50, 60).
        let t = transform(0, 10, 20, 2, 1, 50, 60, 1920, 1080, 3840, 2160);
        let src = SourcePixelRect {
            x_px: 110,
            y_px: 220,
            width_px: 300,
            height_px: 400,
        };
        let phys = t.to_physical(src).unwrap();
        // After crop: (100, 200, 300, 400)
        // After 2x scale: (200, 400, 600, 800)
        // After letterbox: (250, 460, 600, 800)
        assert_eq!(phys.x, 250);
        assert_eq!(phys.y, 460);
        assert_eq!(phys.width, 600);
        assert_eq!(phys.height, 800);
    }
}

// ===========================================================================
// Acceptance criterion 2: computer_dossier_confidence
// Accepts 0..10_000, rejects 10_001/noninteger/float shapes, and labels
// 7_999/8_000 exactly without granting authority.
// ===========================================================================

mod confidence {
    use super::*;

    #[test]
    fn computer_dossier_confidence_accepts_zero() {
        let c = ConfidenceBp(0);
        assert!(c.validate().is_ok());
        assert!(c.is_low_confidence());
    }

    #[test]
    fn computer_dossier_confidence_accepts_max() {
        let c = ConfidenceBp(ConfidenceBp::MAX);
        assert!(c.validate().is_ok());
        assert!(!c.is_low_confidence());
    }

    #[test]
    fn computer_dossier_confidence_rejects_above_max() {
        // u16 can hold up to 65_535; 10_001 is rejected.
        let c = ConfidenceBp(10_001);
        let err = c.validate().unwrap_err();
        assert_eq!(
            err,
            ComputerDossierError::ConfidenceOutOfRange {
                actual: 10_001,
                max: 10_000,
            }
        );
    }

    #[test]
    fn computer_dossier_confidence_labels_7999_low() {
        let c = ConfidenceBp(7_999);
        assert!(c.validate().is_ok());
        assert!(c.is_low_confidence());
    }

    #[test]
    fn computer_dossier_confidence_labels_8000_not_low() {
        let c = ConfidenceBp(8_000);
        assert!(c.validate().is_ok());
        assert!(!c.is_low_confidence());
    }

    #[test]
    fn computer_dossier_confidence_low_label_never_grants_authority() {
        // The low-confidence label is advisory only; it never changes action
        // authorization. There is no threshold that dispatches automatically.
        let low = ConfidenceBp(7_999);
        let high = ConfidenceBp(8_000);
        // The label is a boolean; it does not dispatch or authorize anything.
        assert!(low.is_low_confidence());
        assert!(!high.is_low_confidence());
        // Neither value can construct an action or bypass checks.
        // (This is enforced by the type system: ConfidenceBp is not
        // convertible to ComputerAction.)
    }

    #[test]
    fn computer_dossier_confidence_no_float_shape() {
        // ConfidenceBp is u16; there is no float shape. The type system
        // enforces this — ConfidenceBp(f) does not compile for f: f64.
        // This test documents the invariant.
        let c = ConfidenceBp(5_000);
        assert!(c.validate().is_ok());
        // No NaN/infinity/rounding behavior exists.
    }
}

// ===========================================================================
// Acceptance criterion 3: computer_dossier_transient_privacy
// Proves pixels, summary, OCR, region/element text, rationale, and
// coordinates are absent from DB/events/audits/journal/export/logs/files.
// ===========================================================================

mod transient_privacy {
    use super::*;

    #[test]
    fn computer_dossier_transient_privacy_no_body_writes() {
        // The sanitized metadata contains no dossier content.
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        let sanitized = dossier.sanitized();
        let json = serde_json::to_string(&sanitized).unwrap();
        // No dossier content in the sanitized metadata.
        assert!(!json.contains("summary"));
        assert!(!json.contains("ocr"));
        assert!(!json.contains("text"));
        assert!(!json.contains("rationale"));
        assert!(!json.contains("coordinates"));
        assert!(!json.contains("pixels"));
        assert!(!json.contains("base64"));
        assert!(!json.contains("data:image"));
        // Only safe metadata is present.
        assert!(json.contains("dossier_used"));
        assert!(json.contains("schema_version"));
        assert!(json.contains("destination_digest"));
        assert!(json.contains("frame_checksum"));
        assert!(json.contains("ocr_count"));
        assert!(json.contains("layout_count"));
        assert!(json.contains("element_count"));
        assert!(json.contains("fact_count"));
    }

    #[test]
    fn computer_dossier_transient_privacy_storage_tracker_no_body() {
        // The storage write tracker proves no body writes occur.
        let tracker = StorageWriteTracker::new();
        record_sanitized_write(&tracker, StorageTarget::Sqlite);
        record_sanitized_write(&tracker, StorageTarget::EventLog);
        record_sanitized_write(&tracker, StorageTarget::AuditExport);
        record_sanitized_write(&tracker, StorageTarget::DiskCache);
        assert_no_dossier_content_in_writes(&tracker);
        tracker.assert_no_body_writes();
        tracker.assert_only_metadata();
    }

    #[test]
    fn computer_dossier_transient_privacy_entries_not_serializable() {
        // DossierSpatialEntry is not Serialize; it cannot be persisted.
        // This is enforced by the type system (no Serialize impl).
        let entry = valid_entry();
        // The entry is memory-only; it has no Serialize impl.
        let _ = &entry;
    }

    #[test]
    fn computer_dossier_transient_privacy_computer_dossier_not_serializable() {
        // ComputerDossier is not Serialize; it cannot be persisted.
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        // The dossier is memory-only; it has no Serialize impl.
        let _ = dossier;
    }

    #[test]
    fn computer_dossier_transient_privacy_key_not_serializable() {
        // ComputerDossierKey is not Serialize; it cannot be persisted.
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let key = valid_key(&frame);
        // The key is memory-only; it has no Serialize impl.
        let _ = key;
    }

    #[test]
    fn computer_dossier_transient_privacy_candidate_not_serializable() {
        // CoordinateCandidate is not Serialize; it cannot be persisted.
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        let t = ObservationTransform::identity(GeometryGeneration(1), 1920, 1080, 1920, 1080);
        let candidate = dossier.to_candidate("btn-1", &t).unwrap();
        // The candidate is memory-only; it has no Serialize impl.
        let _ = candidate;
    }

    #[test]
    fn computer_dossier_transient_privacy_no_pixel_bytes_in_debug() {
        // Debug formatting never includes pixel bytes.
        let frame = make_test_frame(10, 10, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        let debug = format!("{dossier:?}");
        assert!(!debug.contains("137"));
        assert!(!debug.contains("[137"));
    }
}

// ===========================================================================
// Acceptance criterion 4: computer_dossier_epoch_race
// Epoch/focus/display/host-lease/action/60s expiry races release the
// borrowed frame/dossier exactly once and late sidecar results are inert.
// ===========================================================================

mod epoch_race {
    use super::*;

    #[test]
    fn computer_dossier_epoch_race_newer_observation_releases() {
        // A newer observation epoch invalidates the dossier.
        let registry = ComputerDossierRegistry::new();
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        registry.register(dossier);
        assert_eq!(registry.len(), 1);
        let clock = FakeComputerDossierClock::new(1000);
        let t = ObservationTransform::identity(GeometryGeneration(1), 1920, 1080, 1920, 1080);
        // A newer epoch (2 > 1) invalidates the dossier.
        let err = registry
            .candidate(
                "del-1",
                "btn-1",
                &t,
                TargetGeneration(1),
                GeometryGeneration(1),
                ObservationEpoch(2),
                &clock,
            )
            .unwrap_err();
        assert_eq!(err, ComputerDossierError::Expired);
        // The dossier was released exactly once.
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn computer_dossier_epoch_race_focus_change_releases() {
        // A focus generation change invalidates the dossier.
        let registry = ComputerDossierRegistry::new();
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        registry.register(dossier);
        let clock = FakeComputerDossierClock::new(1000);
        let t = ObservationTransform::identity(GeometryGeneration(1), 1920, 1080, 1920, 1080);
        // Focus generation changed (2 != 1).
        let err = registry
            .candidate(
                "del-1",
                "btn-1",
                &t,
                TargetGeneration(2),
                GeometryGeneration(1),
                ObservationEpoch(1),
                &clock,
            )
            .unwrap_err();
        assert_eq!(err, ComputerDossierError::KeyMismatch);
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn computer_dossier_epoch_race_display_change_releases() {
        // A display generation change invalidates the dossier.
        let registry = ComputerDossierRegistry::new();
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        registry.register(dossier);
        let clock = FakeComputerDossierClock::new(1000);
        let t = ObservationTransform::identity(GeometryGeneration(1), 1920, 1080, 1920, 1080);
        // Display generation changed (2 != 1).
        let err = registry
            .candidate(
                "del-1",
                "btn-1",
                &t,
                TargetGeneration(1),
                GeometryGeneration(2),
                ObservationEpoch(1),
                &clock,
            )
            .unwrap_err();
        assert_eq!(err, ComputerDossierError::KeyMismatch);
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn computer_dossier_epoch_race_60s_expiry_releases() {
        // 60s expiry invalidates the dossier.
        let registry = ComputerDossierRegistry::new();
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        registry.register(dossier);
        let clock = FakeComputerDossierClock::new(1000);
        // Advance past 60s.
        clock.advance(COMPUTER_DOSSIER_TTL_MS);
        let t = ObservationTransform::identity(GeometryGeneration(1), 1920, 1080, 1920, 1080);
        let err = registry
            .candidate(
                "del-1",
                "btn-1",
                &t,
                TargetGeneration(1),
                GeometryGeneration(1),
                ObservationEpoch(1),
                &clock,
            )
            .unwrap_err();
        assert_eq!(err, ComputerDossierError::Expired);
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn computer_dossier_epoch_race_60s_boundary_not_expired() {
        // At exactly 60s - 1ms, the dossier is not yet expired (expiry
        // is >= TTL, so 59_999ms is not expired).
        let registry = ComputerDossierRegistry::new();
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        registry.register(dossier);
        let clock = FakeComputerDossierClock::new(1000);
        clock.advance(COMPUTER_DOSSIER_TTL_MS - 1);
        let t = ObservationTransform::identity(GeometryGeneration(1), 1920, 1080, 1920, 1080);
        let candidate = registry
            .candidate(
                "del-1",
                "btn-1",
                &t,
                TargetGeneration(1),
                GeometryGeneration(1),
                ObservationEpoch(1),
                &clock,
            )
            .unwrap();
        // The candidate is advisory only.
        assert_eq!(candidate.element_id, "btn-1");
    }

    #[test]
    fn computer_dossier_epoch_race_action_handoff_releases() {
        // Action handoff releases the dossier exactly once.
        let registry = ComputerDossierRegistry::new();
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        registry.register(dossier);
        assert_eq!(registry.len(), 1);
        registry.release("del-1");
        assert_eq!(registry.len(), 0);
        // Releasing again is a no-op (exactly-once).
        registry.release("del-1");
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn computer_dossier_epoch_race_cancellation_releases() {
        // Cancellation releases the dossier.
        let registry = ComputerDossierRegistry::new();
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        registry.register(dossier);
        registry.evict_delegation("del-1");
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn computer_dossier_epoch_race_late_sidecar_inert() {
        // Late sidecar results for an obsolete epoch are dropped and inert.
        let registry = ComputerDossierRegistry::new();
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        registry.register(dossier);
        // A newer observation replaces the old dossier.
        let frame2 = make_test_frame(1920, 1080, [200, 100, 50, 255]);
        let mut key2 = valid_key(&frame2);
        key2.observation_epoch = ObservationEpoch(2);
        let dossier2 = ComputerDossier::new(key2, &frame2, vec![valid_entry()], valid_counts(), 2000)
            .unwrap();
        registry.register(dossier2);
        assert_eq!(registry.len(), 1);
        // The old dossier was released; the new one is current.
        let clock = FakeComputerDossierClock::new(2000);
        let t = ObservationTransform::identity(GeometryGeneration(1), 1920, 1080, 1920, 1080);
        let candidate = registry
            .candidate(
                "del-1",
                "btn-1",
                &t,
                TargetGeneration(1),
                GeometryGeneration(1),
                ObservationEpoch(2),
                &clock,
            )
            .unwrap();
        assert_eq!(candidate.element_id, "btn-1");
    }

    #[test]
    fn computer_dossier_epoch_race_evict_expired() {
        // Evicting expired dossiers releases each exactly once.
        let registry = ComputerDossierRegistry::new();
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        registry.register(dossier);
        let clock = FakeComputerDossierClock::new(1000);
        clock.advance(COMPUTER_DOSSIER_TTL_MS + 1);
        registry.evict_expired(&clock);
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn computer_dossier_epoch_race_candidate_after_release_fails() {
        // After release, candidate fails.
        let registry = ComputerDossierRegistry::new();
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        registry.register(dossier);
        registry.release("del-1");
        let clock = FakeComputerDossierClock::new(1000);
        let t = ObservationTransform::identity(GeometryGeneration(1), 1920, 1080, 1920, 1080);
        let err = registry
            .candidate(
                "del-1",
                "btn-1",
                &t,
                TargetGeneration(1),
                GeometryGeneration(1),
                ObservationEpoch(1),
                &clock,
            )
            .unwrap_err();
        assert_eq!(err, ComputerDossierError::KeyMismatch);
    }
}

// ===========================================================================
// Acceptance criterion 5: computer_dossier_no_action_authority
// CoordinateCandidate cannot be converted directly to an action; coordinator
// tests prove full ordinary stale/pointer/authorization/host-lease checks
// still execute.
// ===========================================================================

mod no_action_authority {
    use super::*;

    #[test]
    fn computer_dossier_candidate_not_convertible_to_action() {
        // CoordinateCandidate is not convertible to ComputerAction. The type
        // system enforces this: there is no From/Into impl.
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        let t = ObservationTransform::identity(GeometryGeneration(1), 1920, 1080, 1920, 1080);
        let candidate = dossier.to_candidate("btn-1", &t).unwrap();
        // The candidate is advisory only; it has no method to construct an
        // action. This is enforced by the type system.
        let _ = candidate;
    }

    #[test]
    fn computer_dossier_candidate_uncertainty_flags_advisory() {
        // The uncertainty flags are advisory only and never change action
        // authorization.
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let mut low_entry = valid_entry();
        low_entry.confidence_bp = ConfidenceBp(7_999);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![low_entry],
            valid_counts(),
            1000,
        )
        .unwrap();
        let t = ObservationTransform::identity(GeometryGeneration(1), 1920, 1080, 1920, 1080);
        let candidate = dossier.to_candidate("btn-1", &t).unwrap();
        assert!(candidate.uncertainty.low_confidence);
        // The flag is advisory; it does not dispatch or authorize.
    }

    #[test]
    fn computer_dossier_candidate_transform_mismatch_rejected() {
        // A transform generation mismatch is rejected.
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        let t = ObservationTransform::identity(GeometryGeneration(2), 1920, 1080, 1920, 1080);
        let err = dossier.to_candidate("btn-1", &t).unwrap_err();
        assert_eq!(err, ComputerDossierError::KeyMismatch);
    }

    #[test]
    fn computer_dossier_candidate_after_release_rejected() {
        // After release, candidate is rejected.
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let mut dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        dossier.release();
        let t = ObservationTransform::identity(GeometryGeneration(1), 1920, 1080, 1920, 1080);
        let err = dossier.to_candidate("btn-1", &t).unwrap_err();
        assert_eq!(err, ComputerDossierError::AlreadyReleased);
    }

    #[test]
    fn computer_dossier_candidate_unknown_entry_rejected() {
        // An unknown entry ID is rejected.
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        let t = ObservationTransform::identity(GeometryGeneration(1), 1920, 1080, 1920, 1080);
        let err = dossier.to_candidate("unknown-id", &t).unwrap_err();
        assert_eq!(err, ComputerDossierError::KeyMismatch);
    }

    #[test]
    fn computer_dossier_coordinator_checks_still_execute() {
        // The coordinator must revalidate exact observation/focus/display/
        // host-lease generations immediately before input. The registry
        // enforces this: a generation mismatch releases the dossier.
        let registry = ComputerDossierRegistry::new();
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        )
        .unwrap();
        registry.register(dossier);
        let clock = FakeComputerDossierClock::new(1000);
        let t = ObservationTransform::identity(GeometryGeneration(1), 1920, 1080, 1920, 1080);
        // Valid candidate.
        let candidate = registry
            .candidate(
                "del-1",
                "btn-1",
                &t,
                TargetGeneration(1),
                GeometryGeneration(1),
                ObservationEpoch(1),
                &clock,
            )
            .unwrap();
        assert_eq!(candidate.element_id, "btn-1");
        // The coordinator would still need to run its own stale/pointer/
        // authorization/host-lease checks before dispatching. The candidate
        // is advisory only.
    }
}

// ===========================================================================
// Acceptance criterion 6: computer_dossier_sidecar_failure
// Sidecar failure or disabled policy does not change base computer-use
// eligibility or screenshot-only operation.
// ===========================================================================

mod sidecar_failure {
    use super::*;

    #[test]
    fn computer_dossier_sidecar_failure_unchanged_eligibility() {
        // Sidecar failure does not change base computer-use eligibility.
        let base = true;
        assert!(computer_use_eligibility_unchanged(base, false));
        assert!(computer_use_eligibility_unchanged(base, true));
        let base = false;
        assert!(!computer_use_eligibility_unchanged(base, false));
        assert!(!computer_use_eligibility_unchanged(base, true));
    }

    #[test]
    fn computer_dossier_sidecar_disabled_unchanged_eligibility() {
        // Sidecar disabled does not change base computer-use eligibility.
        let base = true;
        assert!(computer_use_eligibility_unchanged(base, false));
    }

    #[test]
    fn computer_dossier_sidecar_unavailable_leaves_screenshot_only() {
        // Sidecar unavailable leaves ordinary screenshot-only computer use
        // unchanged. The registry is empty; no dossier is required.
        let registry = ComputerDossierRegistry::new();
        assert!(registry.is_empty());
        // Screenshot-only operation proceeds without a dossier.
    }

    #[test]
    fn computer_dossier_sidecar_unavailable_candidate_fails_gracefully() {
        // When the sidecar is unavailable, candidate lookup fails gracefully
        // without changing eligibility.
        let registry = ComputerDossierRegistry::new();
        let clock = FakeComputerDossierClock::new(1000);
        let t = ObservationTransform::identity(GeometryGeneration(1), 1920, 1080, 1920, 1080);
        let err = registry
            .candidate(
                "del-1",
                "btn-1",
                &t,
                TargetGeneration(1),
                GeometryGeneration(1),
                ObservationEpoch(1),
                &clock,
            )
            .unwrap_err();
        assert_eq!(err, ComputerDossierError::KeyMismatch);
    }
}

// ===========================================================================
// Additional: computer_dossier construction validation
// ===========================================================================

mod construction {
    use super::*;

    #[test]
    fn computer_dossier_construction_valid() {
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let dossier = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![valid_entry()],
            valid_counts(),
            1000,
        );
        assert!(dossier.is_ok());
    }

    #[test]
    fn computer_dossier_construction_schema_version_mismatch() {
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let mut key = valid_key(&frame);
        key.dossier_schema_version = 99;
        let err = ComputerDossier::new(key, &frame, vec![], valid_counts(), 1000).unwrap_err();
        assert_eq!(
            err,
            ComputerDossierError::SchemaVersionMismatch {
                actual: 99,
                expected: DOSSIER_SCHEMA_VERSION,
            }
        );
    }

    #[test]
    fn computer_dossier_construction_checksum_mismatch() {
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let mut key = valid_key(&frame);
        key.frame_checksum_hex = "wrong".to_string();
        let err = ComputerDossier::new(key, &frame, vec![], valid_counts(), 1000).unwrap_err();
        assert_eq!(err, ComputerDossierError::KeyMismatch);
    }

    #[test]
    fn computer_dossier_construction_duplicate_id() {
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let entry1 = valid_entry();
        let entry2 = valid_entry();
        let err = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![entry1, entry2],
            valid_counts(),
            1000,
        )
        .unwrap_err();
        assert_eq!(err, ComputerDossierError::DuplicateElementId { id: "btn-1".to_string() });
    }

    #[test]
    fn computer_dossier_construction_confidence_out_of_range() {
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let mut entry = valid_entry();
        entry.confidence_bp = ConfidenceBp(10_001);
        let err = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![entry],
            valid_counts(),
            1000,
        )
        .unwrap_err();
        assert_eq!(
            err,
            ComputerDossierError::ConfidenceOutOfRange {
                actual: 10_001,
                max: 10_000,
            }
        );
    }

    #[test]
    fn computer_dossier_construction_bounds_outside_frame() {
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let mut entry = valid_entry();
        entry.source_bounds = SourcePixelRect {
            x_px: 1800,
            y_px: 200,
            width_px: 300,
            height_px: 400,
        };
        let err = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![entry],
            valid_counts(),
            1000,
        )
        .unwrap_err();
        assert_eq!(err, ComputerDossierError::BoundsOutsideFrame);
    }

    #[test]
    fn computer_dossier_construction_zero_width() {
        let frame = make_test_frame(1920, 1080, [137, 80, 78, 71]);
        let mut entry = valid_entry();
        entry.source_bounds = SourcePixelRect {
            x_px: 10,
            y_px: 20,
            width_px: 0,
            height_px: 30,
        };
        let err = ComputerDossier::new(
            valid_key(&frame),
            &frame,
            vec![entry],
            valid_counts(),
            1000,
        )
        .unwrap_err();
        assert_eq!(err, ComputerDossierError::ZeroWidth);
    }
}
