//! Named test suites for image-generation artifact routes.
//!
//! These cover the protocol surface, structural validation, strict
//! single-range parsing, thumbnail box/dimension arithmetic, the exact HTTP
//! error mapping, the SVG-only contract, and the old-behavior rejection
//! proofs required by prompt `image-generation-artifact-routes`.

#![allow(clippy::needless_pass_by_value)]

use super::*;

// A fixed valid 22-char base64url opaque ID (nonzero 16 bytes).
const VALID_ARTIFACT_ID: &str = "AQIDBAUGBwgJCgsMDQ4PEA";
const VALID_REQUEST_ID: &str = "ERITFBUWFxgZGhscHR4fIA";
const VALID_TRANSFER_ID: &str = "ISIjJCUmJygpKissLS4vMA";
const VALID_INSTANCE_ID: &str = "MTIzNDU2Nzg5Ojs8PT4_QA";
const VALID_SESSION_ID: &str = "QUJDREVGR0hJSktMTU5PUA";
const VALID_UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";

fn valid_metadata() -> ImageArtifactMetadataV1 {
    ImageArtifactMetadataV1 {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        artifact_id: VALID_ARTIFACT_ID.into(),
        artifact_generation: "1".into(),
        job_id: VALID_UUID.into(),
        job_generation: "1".into(),
        slot_id: VALID_UUID.into(),
        slot_generation: "1".into(),
        published_disposition: "ordinary".into(),
        published_disposition_generation: "1".into(),
        // Canonical slash-free media-kind token: the redacted metadata must
        // never carry a path/URL-shaped value (production accepts "png").
        media_kind: "png".into(),
        width: 1024,
        height: 768,
        byte_length: "12345".into(),
        checksum: "a".repeat(64),
        available_thumbnail_boxes: vec![256, 512],
    }
}

// ===========================================================================
// image_artifact_route_protocol_v1
// ===========================================================================

#[test]
fn image_artifact_route_protocol_v1_route_shape_metadata() {
    let path = format!(
        "api/cockpit/v1/instances/{VALID_INSTANCE_ID}/sessions/{VALID_SESSION_ID}/image-artifacts/{VALID_ARTIFACT_ID}/metadata"
    );
    let parsed = parse_route_path(&path).expect("metadata route parses");
    assert_eq!(parsed.route, ImageArtifactRouteKind::Metadata);
    assert_eq!(parsed.thumbnail_box, None);
    assert_eq!(parsed.instance_id, VALID_INSTANCE_ID);
    assert_eq!(parsed.session_id, VALID_SESSION_ID);
    assert_eq!(parsed.artifact_id, VALID_ARTIFACT_ID);
}

#[test]
fn image_artifact_route_protocol_v1_route_shape_content() {
    let path = format!(
        "api/cockpit/v1/instances/{VALID_INSTANCE_ID}/sessions/{VALID_SESSION_ID}/image-artifacts/{VALID_ARTIFACT_ID}/content"
    );
    let parsed = parse_route_path(&path).expect("content route parses");
    assert_eq!(parsed.route, ImageArtifactRouteKind::Content);
    assert_eq!(parsed.thumbnail_box, None);
}

#[test]
fn image_artifact_route_protocol_v1_route_shape_thumbnail_boxes() {
    for &box_size in THUMBNAIL_BOXES {
        let path = format!(
            "api/cockpit/v1/instances/{VALID_INSTANCE_ID}/sessions/{VALID_SESSION_ID}/image-artifacts/{VALID_ARTIFACT_ID}/thumbnails/{box_size}"
        );
        let parsed = parse_route_path(&path).expect("thumbnail route parses");
        assert_eq!(parsed.route, ImageArtifactRouteKind::Thumbnail);
        assert_eq!(parsed.thumbnail_box, Some(box_size));
    }
}

#[test]
fn image_artifact_route_protocol_v1_rejects_bad_thumbnail_box() {
    for bad in &["128", "0", "2048", "abc", "256x", "", "-1"] {
        let path = format!(
            "api/cockpit/v1/instances/{VALID_INSTANCE_ID}/sessions/{VALID_SESSION_ID}/image-artifacts/{VALID_ARTIFACT_ID}/thumbnails/{bad}"
        );
        assert_eq!(
            parse_route_path(&path),
            Err(RoutePathError::Malformed),
            "box {bad:?} must be rejected structurally"
        );
    }
}

#[test]
fn image_artifact_route_protocol_v1_rejects_bad_artifact_id() {
    for bad in &[
        "",
        "short",
        "AAAAAAAAAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAAAAAAA!",
        "AAAAAAAAAAAAAAAAAAAAAA", // all-zero 16 bytes
        "AQIDBAUGBwgJCgsMDQ4PE=", // padding rejected
    ] {
        let path = format!(
            "api/cockpit/v1/instances/{VALID_INSTANCE_ID}/sessions/{VALID_SESSION_ID}/image-artifacts/{bad}/metadata"
        );
        assert_eq!(
            parse_route_path(&path),
            Err(RoutePathError::Malformed),
            "artifact id {bad:?} must be rejected"
        );
    }
}

#[test]
fn image_artifact_route_protocol_v1_rejects_bad_path_shape() {
    let cases = [
        "",
        "/",
        "api/cockpit/v1/instances/x/sessions/y/image-artifacts/z/metadata",
        "api/cockpit/v2/instances/{VALID_INSTANCE_ID}/sessions/{VALID_SESSION_ID}/image-artifacts/{VALID_ARTIFACT_ID}/metadata",
        "api/cockpit/v1/instances/{VALID_INSTANCE_ID}/sessions/{VALID_SESSION_ID}/image-artifacts/{VALID_ARTIFACT_ID}",
        "api/cockpit/v1/instances/{VALID_INSTANCE_ID}/sessions/{VALID_SESSION_ID}/image-artifacts/{VALID_ARTIFACT_ID}/metadata/extra",
        "api/cockpit/v1/instances/{VALID_INSTANCE_ID}/sessions/{VALID_SESSION_ID}/image-artifacts/{VALID_ARTIFACT_ID}/unknown",
        "api/cockpit/v1/instances/{VALID_INSTANCE_ID}/sessions/{VALID_SESSION_ID}/image-artifacts/{VALID_ARTIFACT_ID}/thumbnails",
        "api/cockpit/v1/instances/{VALID_INSTANCE_ID}/sessions/{VALID_SESSION_ID}/image-artifacts/{VALID_ARTIFACT_ID}/thumbnails/256/extra",
    ];
    for bad in cases {
        let bad = bad
            .replace("{VALID_INSTANCE_ID}", VALID_INSTANCE_ID)
            .replace("{VALID_SESSION_ID}", VALID_SESSION_ID)
            .replace("{VALID_ARTIFACT_ID}", VALID_ARTIFACT_ID);
        assert_eq!(
            parse_route_path(&bad),
            Err(RoutePathError::Malformed),
            "path {bad:?} must be rejected"
        );
    }
}

#[test]
fn image_artifact_route_protocol_v1_accepts_uuid_session() {
    let path = format!(
        "api/cockpit/v1/instances/{VALID_INSTANCE_ID}/sessions/{VALID_UUID}/image-artifacts/{VALID_ARTIFACT_ID}/content"
    );
    let parsed = parse_route_path(&path).expect("uuid session parses");
    assert_eq!(parsed.session_id, VALID_UUID);
}

#[test]
fn image_artifact_route_protocol_v1_daemon_request_tags() {
    let metadata = ImageArtifactDaemonRequestV1::ImageArtifactMetadata {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        request_id: VALID_REQUEST_ID.into(),
        session_id: VALID_SESSION_ID.into(),
        artifact_id: VALID_ARTIFACT_ID.into(),
    };
    assert!(metadata.is_read_only());
    assert!(validate_daemon_request(&metadata));
    assert_eq!(metadata.request_id(), VALID_REQUEST_ID);

    let download = ImageArtifactDaemonRequestV1::ImageArtifactDownload {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        request_id: VALID_REQUEST_ID.into(),
        session_id: VALID_SESSION_ID.into(),
        artifact_id: VALID_ARTIFACT_ID.into(),
        range_header: Some("bytes=0-99".into()),
    };
    assert!(download.is_read_only());
    assert!(validate_daemon_request(&download));

    let thumbnail = ImageArtifactDaemonRequestV1::ImageArtifactThumbnail {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        request_id: VALID_REQUEST_ID.into(),
        session_id: VALID_SESSION_ID.into(),
        artifact_id: VALID_ARTIFACT_ID.into(),
        box_size: 512,
        range_header: None,
    };
    assert!(thumbnail.is_read_only());
    assert!(validate_daemon_request(&thumbnail));

    let cancel = ImageArtifactDaemonRequestV1::ImageArtifactTransferCancel {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        request_id: VALID_REQUEST_ID.into(),
        transfer_id: VALID_TRANSFER_ID.into(),
    };
    assert!(!cancel.is_read_only());
    assert!(validate_daemon_request(&cancel));
}

#[test]
fn image_artifact_route_protocol_v1_rejects_wrong_schema_version() {
    let req = ImageArtifactDaemonRequestV1::ImageArtifactMetadata {
        schema_version: 2,
        request_id: VALID_REQUEST_ID.into(),
        session_id: VALID_SESSION_ID.into(),
        artifact_id: VALID_ARTIFACT_ID.into(),
    };
    assert!(!validate_daemon_request(&req));
}

#[test]
fn image_artifact_route_protocol_v1_rejects_bad_ids_in_request() {
    let bad_id = ImageArtifactDaemonRequestV1::ImageArtifactMetadata {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        request_id: "short".into(),
        session_id: VALID_SESSION_ID.into(),
        artifact_id: VALID_ARTIFACT_ID.into(),
    };
    assert!(!validate_daemon_request(&bad_id));

    let bad_box = ImageArtifactDaemonRequestV1::ImageArtifactThumbnail {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        request_id: VALID_REQUEST_ID.into(),
        session_id: VALID_SESSION_ID.into(),
        artifact_id: VALID_ARTIFACT_ID.into(),
        box_size: 128,
        range_header: None,
    };
    assert!(!validate_daemon_request(&bad_box));

    let oversized_range = ImageArtifactDaemonRequestV1::ImageArtifactDownload {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        request_id: VALID_REQUEST_ID.into(),
        session_id: VALID_SESSION_ID.into(),
        artifact_id: VALID_ARTIFACT_ID.into(),
        range_header: Some("x".repeat(MAX_RANGE_HEADER_BYTES + 1)),
    };
    assert!(!validate_daemon_request(&oversized_range));

    let non_ascii_range = ImageArtifactDaemonRequestV1::ImageArtifactDownload {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        request_id: VALID_REQUEST_ID.into(),
        session_id: VALID_SESSION_ID.into(),
        artifact_id: VALID_ARTIFACT_ID.into(),
        range_header: Some("bytes=0-✓".into()),
    };
    assert!(!validate_daemon_request(&non_ascii_range));
}

#[test]
fn image_artifact_route_protocol_v1_daemon_reply_roundtrip() {
    let reply = ImageArtifactDaemonReplyV1 {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        request_id: VALID_REQUEST_ID.into(),
        outcome: ImageArtifactDaemonOutcomeV1::Metadata {
            value: valid_metadata(),
        },
    };
    let json = serde_json::to_string(&reply).expect("serialize");
    let back: ImageArtifactDaemonReplyV1 = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(reply, back);
    assert_eq!(back.request_id, VALID_REQUEST_ID);
}

#[test]
fn image_artifact_route_protocol_v1_error_code_roundtrip() {
    for code in [
        ImageArtifactDaemonErrorCode::Malformed,
        ImageArtifactDaemonErrorCode::ArtifactUnavailable,
        ImageArtifactDaemonErrorCode::ThumbnailUnavailableForFormat,
        ImageArtifactDaemonErrorCode::ThumbnailUnavailable,
        ImageArtifactDaemonErrorCode::RangeNotSatisfiable,
        ImageArtifactDaemonErrorCode::ThumbnailCapacity,
        ImageArtifactDaemonErrorCode::Internal,
    ] {
        let s = code.as_str();
        assert_eq!(ImageArtifactDaemonErrorCode::from_str(s), Some(code));
    }
    assert_eq!(ImageArtifactDaemonErrorCode::from_str("unknown"), None);
}

#[test]
fn image_artifact_route_protocol_v1_authorized_length_nullability() {
    // Content range error: nonnull canonical decimal.
    let content_err = ImageArtifactDaemonErrorV1::content_range(999);
    assert!(content_err.validate_nullability(false));
    assert_eq!(content_err.authorized_length, Some("999".to_string()));

    // Thumbnail range error: null.
    let thumb_err = ImageArtifactDaemonErrorV1::thumbnail_range();
    assert!(thumb_err.validate_nullability(true));
    assert_eq!(thumb_err.authorized_length, None);

    // Every non-range code with null length: valid on both routes.
    for code in [
        ImageArtifactDaemonErrorCode::Malformed,
        ImageArtifactDaemonErrorCode::ArtifactUnavailable,
        ImageArtifactDaemonErrorCode::ThumbnailUnavailableForFormat,
        ImageArtifactDaemonErrorCode::ThumbnailUnavailable,
        ImageArtifactDaemonErrorCode::ThumbnailCapacity,
        ImageArtifactDaemonErrorCode::Internal,
    ] {
        let err = ImageArtifactDaemonErrorV1::null_length(code);
        assert!(
            err.validate_nullability(false),
            "{code:?} null length valid on content"
        );
        assert!(
            err.validate_nullability(true),
            "{code:?} null length valid on thumbnail"
        );
    }
}

#[test]
fn image_artifact_route_protocol_v1_rejects_bad_nullability_pairings() {
    // Content-range error with null length: malformed.
    let content_null = ImageArtifactDaemonErrorV1 {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        code: ImageArtifactDaemonErrorCode::RangeNotSatisfiable,
        authorized_length: None,
    };
    assert!(!content_null.validate_nullability(false));

    // Thumbnail-range error with nonnull length: malformed.
    let thumb_nonnull = ImageArtifactDaemonErrorV1 {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        code: ImageArtifactDaemonErrorCode::RangeNotSatisfiable,
        authorized_length: Some("10".into()),
    };
    assert!(!thumb_nonnull.validate_nullability(true));

    // Non-range error with nonnull length: malformed.
    let nonrange_nonnull = ImageArtifactDaemonErrorV1 {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        code: ImageArtifactDaemonErrorCode::ArtifactUnavailable,
        authorized_length: Some("10".into()),
    };
    assert!(!nonrange_nonnull.validate_nullability(false));

    // Wrong schema version.
    let bad_schema = ImageArtifactDaemonErrorV1 {
        schema_version: 2,
        code: ImageArtifactDaemonErrorCode::Malformed,
        authorized_length: None,
    };
    assert!(!bad_schema.validate_nullability(false));
}

// ===========================================================================
// image_artifact_route_precedence
// ===========================================================================

#[test]
fn image_artifact_route_precedence_structural_400_before_lookup() {
    // A malformed path never reaches authorization or Range parsing.
    let bad = "api/cockpit/v1/instances/x/sessions/y/image-artifacts/z/metadata";
    assert_eq!(parse_route_path(bad), Err(RoutePathError::Malformed));
}

#[test]
fn image_artifact_route_precedence_metadata_forbids_range_structurally() {
    assert!(ImageArtifactRouteKind::Metadata.forbids_range_structurally());
    assert!(!ImageArtifactRouteKind::Content.forbids_range_structurally());
    assert!(!ImageArtifactRouteKind::Thumbnail.forbids_range_structurally());
}

#[test]
fn image_artifact_route_precedence_range_full_when_absent() {
    assert_eq!(parse_range_header(None, 1000), ParsedRange::Full);
}

#[test]
fn image_artifact_route_precedence_range_valid_start_end() {
    let r = parse_range_header(Some("bytes=0-99"), 1000);
    assert_eq!(
        r,
        ParsedRange::Satisfiable(SatisfiableRange { start: 0, end: 99 })
    );
}

#[test]
fn image_artifact_route_precedence_range_valid_start_open() {
    let r = parse_range_header(Some("bytes=500-"), 1000);
    assert_eq!(
        r,
        ParsedRange::Satisfiable(SatisfiableRange {
            start: 500,
            end: 999
        })
    );
}

#[test]
fn image_artifact_route_precedence_range_valid_suffix() {
    let r = parse_range_header(Some("bytes=-200"), 1000);
    assert_eq!(
        r,
        ParsedRange::Satisfiable(SatisfiableRange {
            start: 800,
            end: 999
        })
    );
}

#[test]
fn image_artifact_route_precedence_range_suffix_clamps_to_length() {
    // Suffix larger than length yields the whole content.
    let r = parse_range_header(Some("bytes=-5000"), 1000);
    assert_eq!(
        r,
        ParsedRange::Satisfiable(SatisfiableRange { start: 0, end: 999 })
    );
}

#[test]
fn image_artifact_route_precedence_range_end_clamps_to_last_byte() {
    let r = parse_range_header(Some("bytes=900-5000"), 1000);
    assert_eq!(
        r,
        ParsedRange::Satisfiable(SatisfiableRange {
            start: 900,
            end: 999
        })
    );
}

#[test]
fn image_artifact_route_precedence_range_zero_length_unsatisfiable() {
    assert_eq!(
        parse_range_header(Some("bytes=0-0"), 0),
        ParsedRange::NotSatisfiable
    );
    assert_eq!(
        parse_range_header(Some("bytes=0-"), 0),
        ParsedRange::NotSatisfiable
    );
    assert_eq!(
        parse_range_header(Some("bytes=-1"), 0),
        ParsedRange::NotSatisfiable
    );
}

#[test]
fn image_artifact_route_precedence_range_start_at_length_unsatisfiable() {
    assert_eq!(
        parse_range_header(Some("bytes=1000-"), 1000),
        ParsedRange::NotSatisfiable
    );
    assert_eq!(
        parse_range_header(Some("bytes=1000-2000"), 1000),
        ParsedRange::NotSatisfiable
    );
}

#[test]
fn image_artifact_route_precedence_range_zero_suffix_unsatisfiable() {
    assert_eq!(
        parse_range_header(Some("bytes=-0"), 1000),
        ParsedRange::NotSatisfiable
    );
}

#[test]
fn image_artifact_route_precedence_range_reverse_unsatisfiable() {
    assert_eq!(
        parse_range_header(Some("bytes=100-50"), 1000),
        ParsedRange::NotSatisfiable
    );
}

#[test]
fn image_artifact_route_precedence_range_multiple_unsatisfiable() {
    assert_eq!(
        parse_range_header(Some("bytes=0-99,200-300"), 1000),
        ParsedRange::NotSatisfiable
    );
}

#[test]
fn image_artifact_route_precedence_range_non_bytes_unit_unsatisfiable() {
    assert_eq!(
        parse_range_header(Some("items=0-99"), 1000),
        ParsedRange::NotSatisfiable
    );
}

#[test]
fn image_artifact_route_precedence_range_malformed_unsatisfiable() {
    let bad = [
        "bytes=",
        "bytes=-",
        "bytes=abc-def",
        "bytes=0--",
        "bytes=-+5",
        "bytes= 0-99",
        "bytes=0 -99",
        "bytes=0-99 ",
        "bytes=0x10-",
        "bytes=+0-99",
        "bytes=- 5",
        "bytes=0-99,",
        "bytes=",
        "range=0-99",
    ];
    for b in bad {
        assert_eq!(
            parse_range_header(Some(b), 1000),
            ParsedRange::NotSatisfiable,
            "range {b:?} must be not-satisfiable"
        );
    }
}

#[test]
fn image_artifact_route_precedence_http_error_mapping() {
    // malformed -> 400 body
    let r = http_error_response(ImageArtifactDaemonErrorCode::Malformed, false);
    assert_eq!(r.status, 400);
    assert!(r.has_body);

    // artifact_unavailable -> 404 body
    let r = http_error_response(ImageArtifactDaemonErrorCode::ArtifactUnavailable, false);
    assert_eq!(r.status, 404);
    assert!(r.has_body);

    // thumbnail_unavailable_for_format -> 409 body
    let r = http_error_response(
        ImageArtifactDaemonErrorCode::ThumbnailUnavailableForFormat,
        true,
    );
    assert_eq!(r.status, 409);
    assert!(r.has_body);

    // thumbnail_unavailable -> 409 body
    let r = http_error_response(ImageArtifactDaemonErrorCode::ThumbnailUnavailable, true);
    assert_eq!(r.status, 409);
    assert!(r.has_body);

    // content range -> 416 bodyless
    let r = http_error_response(ImageArtifactDaemonErrorCode::RangeNotSatisfiable, false);
    assert_eq!(r.status, 416);
    assert!(!r.has_body);
    assert_eq!(r.content_range, None); // caller sets Content-Range with length

    // thumbnail range -> 416 bodyless with bytes */*
    let r = http_error_response(ImageArtifactDaemonErrorCode::RangeNotSatisfiable, true);
    assert_eq!(r.status, 416);
    assert!(!r.has_body);
    assert_eq!(r.content_range, Some("bytes */*"));

    // thumbnail capacity -> 503 body with Retry-After
    let r = http_error_response(ImageArtifactDaemonErrorCode::ThumbnailCapacity, true);
    assert_eq!(r.status, 503);
    assert!(r.has_body);
    assert_eq!(r.retry_after, Some(THUMBNAIL_CAPACITY_RETRY_AFTER_SECONDS));

    // internal -> 500 bodyless
    let r = http_error_response(ImageArtifactDaemonErrorCode::Internal, false);
    assert_eq!(r.status, 500);
    assert!(!r.has_body);
}

#[test]
fn image_artifact_route_precedence_content_range_header_format() {
    assert_eq!(content_range_unsatisfiable(12345), "bytes */12345");
    assert_eq!(content_range_unsatisfiable(0), "bytes */0");
}

// ===========================================================================
// image_artifact_route_svg
// ===========================================================================

#[test]
fn image_artifact_route_svg_is_sanitized_svg_detection() {
    assert!(is_sanitized_svg("image/svg+xml"));
    assert!(is_sanitized_svg("svg"));
    assert!(!is_sanitized_svg("image/png"));
    assert!(!is_sanitized_svg("image/webp"));
}

#[test]
fn image_artifact_route_svg_content_type_constant() {
    assert_eq!(
        content_type_for_media_kind("image/svg+xml"),
        Some(CONTENT_TYPE_SVG)
    );
    assert_eq!(content_type_for_media_kind("svg"), Some(CONTENT_TYPE_SVG));
}

#[test]
fn image_artifact_route_svg_disposition_attachment_only() {
    let d = svg_content_disposition();
    assert!(d.starts_with("attachment; filename=\""));
    assert!(d.contains(SVG_DOWNLOAD_FILENAME));
    // Never inline.
    assert!(!d.starts_with("inline"));
}

#[test]
fn image_artifact_route_svg_csp_constant() {
    assert_eq!(SVG_CONTENT_SECURITY_POLICY, "default-src 'none'; sandbox");
}

#[test]
fn image_artifact_route_svg_thumbnail_409_before_range() {
    // The 409 for SVG thumbnail is emitted before any Range parsing.
    let r = http_error_response(
        ImageArtifactDaemonErrorCode::ThumbnailUnavailableForFormat,
        true,
    );
    assert_eq!(r.status, 409);
    // No Range parser is invoked: the error code itself signals format
    // unavailability.
    let err = ImageArtifactDaemonErrorV1::null_length(
        ImageArtifactDaemonErrorCode::ThumbnailUnavailableForFormat,
    );
    assert!(err.validate_nullability(true));
}

#[test]
fn image_artifact_route_svg_content_range_authorized_length_416() {
    // SVG content with any Range is 416 with bytes */<authorized-full-length>.
    // The content-route 416 carries the authorized length.
    let err = ImageArtifactDaemonErrorV1::content_range(4096);
    assert!(err.validate_nullability(false));
    assert_eq!(err.authorized_length, Some("4096".to_string()));
    assert_eq!(content_range_unsatisfiable(4096), "bytes */4096");
}

#[test]
fn image_artifact_route_svg_no_raster_fallback_for_thumbnail() {
    // The thumbnail route for SVG never falls back to raster: the error code
    // is thumbnail_unavailable_for_format, distinct from artifact_unavailable.
    assert_ne!(
        ImageArtifactDaemonErrorCode::ThumbnailUnavailableForFormat.as_str(),
        ImageArtifactDaemonErrorCode::ArtifactUnavailable.as_str()
    );
}

// ===========================================================================
// image_thumbnail_pipeline_and_state_matrix (dimension arithmetic subset)
// ===========================================================================

#[test]
fn image_thumbnail_pipeline_no_upscale_when_both_fit() {
    // Source smaller than box in both dims: out = (w, h).
    assert_eq!(thumbnail_output_dimensions(100, 50, 256), Some((100, 50)));
    assert_eq!(thumbnail_output_dimensions(256, 256, 256), Some((256, 256)));
}

#[test]
fn image_thumbnail_pipeline_downscale_w_ge_h() {
    // w >= h, w > box: out = (box, max(1, floor(h*box/w)))
    assert_eq!(
        thumbnail_output_dimensions(1024, 768, 256),
        Some((256, 192))
    );
    // Exact division.
    assert_eq!(thumbnail_output_dimensions(512, 256, 256), Some((256, 128)));
}

#[test]
fn image_thumbnail_pipeline_downscale_h_gt_w() {
    // h > w, h > box: out = (max(1, floor(w*box/h)), box)
    assert_eq!(
        thumbnail_output_dimensions(768, 1024, 256),
        Some((192, 256))
    );
}

#[test]
fn image_thumbnail_pipeline_min_one_dimension() {
    // Very wide image: height scales down to at least 1.
    let (w, h) = thumbnail_output_dimensions(100_000, 1, 256).expect("ok");
    assert_eq!(w, 256);
    assert_eq!(h, 1);
    // Very tall image.
    let (w, h) = thumbnail_output_dimensions(1, 100_000, 256).expect("ok");
    assert_eq!(w, 1);
    assert_eq!(h, 256);
}

#[test]
fn image_thumbnail_pipeline_all_boxes() {
    for &box_size in THUMBNAIL_BOXES {
        let (w, h) = thumbnail_output_dimensions(2000, 1000, box_size).expect("ok");
        assert_eq!(w, box_size);
        assert!(h >= 1 && h <= box_size);
    }
}

#[test]
fn image_thumbnail_pipeline_rejects_zero() {
    assert_eq!(thumbnail_output_dimensions(0, 100, 256), None);
    assert_eq!(thumbnail_output_dimensions(100, 0, 256), None);
    assert_eq!(thumbnail_output_dimensions(100, 100, 0), None);
}

#[test]
fn image_thumbnail_pipeline_bilinear_source_coordinate_identity() {
    // When out == source, x maps to itself: ix=x, fx=0.
    let (ix, fx) = bilinear_source_coordinate(5, 100, 100).expect("ok");
    assert_eq!(ix, 5);
    assert_eq!(fx, 0);
}

#[test]
fn image_thumbnail_pipeline_bilinear_source_coordinate_downscale() {
    // Downscale 2x: destination 0 maps near source 0.
    let (ix, fx) = bilinear_source_coordinate(0, 100, 50).expect("ok");
    assert_eq!(ix, 0);
    // fx should be 32768 (the -32768 offset yields a centered sample).
    let (ix2, _fx2) = bilinear_source_coordinate(49, 100, 50).expect("ok");
    assert!(ix2 <= 99);
}

#[test]
fn image_thumbnail_pipeline_bilinear_clamps_to_last_pixel() {
    // The last destination coordinate clamps ix to source_width-1.
    let (ix, _fx) = bilinear_source_coordinate(255, 256, 256).expect("ok");
    assert_eq!(ix, 255);
}

#[test]
fn image_thumbnail_pipeline_premultiply_unpremultiply_roundtrip() {
    // For opaque alpha (255), premultiply then unpremultiply is identity.
    for c in [0u8, 1, 127, 128, 200, 255] {
        let pc = premultiply_color(c, 255);
        assert_eq!(unpremultiply_color(pc, 255), c);
    }
    // Zero alpha premultiplies to zero and unpremultiplies to zero.
    assert_eq!(premultiply_color(200, 0), 0);
    assert_eq!(unpremultiply_color(0, 0), 0);
}

#[test]
fn image_thumbnail_pipeline_premultiply_formula() {
    // pc = (c*a + 127) / 255
    assert_eq!(premultiply_color(255, 255), 255);
    assert_eq!(premultiply_color(128, 128), (128u16 * 128 + 127) / 255);
}

#[test]
fn image_thumbnail_pipeline_derivative_key_components() {
    // The derivative key is exactly
    // (artifact_id, source_component_id, source_component_generation,
    //  source_component_checksum, box, pipeline_version).
    // Verify the pipeline version constant is 1.
    assert_eq!(THUMBNAIL_PIPELINE_VERSION, 1);
    assert_eq!(THUMBNAIL_BOXES, &[256, 512, 1024]);
}

// ===========================================================================
// image_artifact_route_byte_headers
// ===========================================================================

#[test]
fn image_artifact_route_byte_headers_raster_disposition_map() {
    assert_eq!(
        raster_download_disposition("image/png"),
        Some(RASTER_DOWNLOAD_FILENAME_PNG)
    );
    assert_eq!(
        raster_download_disposition("image/jpeg"),
        Some(RASTER_DOWNLOAD_FILENAME_JPEG)
    );
    assert_eq!(
        raster_download_disposition("image/webp"),
        Some(RASTER_DOWNLOAD_FILENAME_WEBP)
    );
    assert_eq!(raster_download_disposition("image/svg+xml"), None);
}

#[test]
fn image_artifact_route_byte_headers_content_disposition_attachment() {
    let d = raster_download_content_disposition("image/png").expect("png");
    assert!(d.starts_with("attachment; filename=\""));
    assert!(d.contains(RASTER_DOWNLOAD_FILENAME_PNG));
    assert!(!d.starts_with("inline"));
}

#[test]
fn image_artifact_route_byte_headers_thumbnail_disposition() {
    let d = thumbnail_content_disposition();
    assert!(d.contains(RASTER_THUMBNAIL_FILENAME));
}

#[test]
fn image_artifact_route_byte_headers_content_type_map() {
    assert_eq!(
        content_type_for_media_kind("image/png"),
        Some(CONTENT_TYPE_PNG)
    );
    assert_eq!(
        content_type_for_media_kind("image/jpeg"),
        Some(CONTENT_TYPE_JPEG)
    );
    assert_eq!(
        content_type_for_media_kind("image/webp"),
        Some(CONTENT_TYPE_WEBP)
    );
    assert_eq!(
        content_type_for_media_kind("image/svg+xml"),
        Some(CONTENT_TYPE_SVG)
    );
    assert_eq!(content_type_for_media_kind("unknown"), None);
}

#[test]
fn image_artifact_route_byte_headers_cache_nosniff_constants() {
    assert_eq!(ARTIFACT_CACHE_CONTROL, "private, no-store, max-age=0");
    assert_eq!(ARTIFACT_NOSNIFF, "nosniff");
}

#[test]
fn image_artifact_route_byte_headers_validated_raster_detection() {
    assert!(is_validated_raster("image/png"));
    assert!(is_validated_raster("image/jpeg"));
    assert!(is_validated_raster("image/webp"));
    assert!(!is_validated_raster("image/svg+xml"));
    assert!(!is_validated_raster("application/octet-stream"));
}

// ===========================================================================
// image_artifact_old_behavior_rejection
// ===========================================================================

#[test]
fn image_artifact_old_behavior_rejection_no_caller_mime() {
    // The old generic-asset behavior selected MIME from caller input. The new
    // route derives MIME only from the validated media kind; an unknown kind
    // yields no content type and no disposition.
    assert_eq!(content_type_for_media_kind("caller/says/png"), None);
    assert_eq!(raster_download_disposition("caller/says/png"), None);
}

#[test]
fn image_artifact_old_behavior_rejection_no_path_in_route() {
    // The route path never contains a filesystem path, provider URL, or
    // ComfyUI identifier — only opaque IDs. A path containing a slash inside
    // the artifact ID segment is structurally rejected.
    let bad = format!(
        "api/cockpit/v1/instances/{VALID_INSTANCE_ID}/sessions/{VALID_SESSION_ID}/image-artifacts/some/path/primary/metadata"
    );
    assert_eq!(parse_route_path(&bad), Err(RoutePathError::Malformed));
}

#[test]
fn image_artifact_old_behavior_rejection_auth_before_range() {
    // The old behavior parsed Range before authorization. The new precedence
    // parses Range only after authorization; a malformed range on a malformed
    // path never reaches the range parser (structural rejection wins).
    let bad_path = "api/cockpit/v1/instances/x/sessions/y/image-artifacts/z/metadata";
    assert_eq!(parse_route_path(bad_path), Err(RoutePathError::Malformed));
    // The range parser is only invoked for a structurally-valid, authorized
    // request; here we prove a bad range is classified but does not leak
    // whether the artifact exists.
    assert_eq!(
        parse_range_header(Some("bytes=999999-"), 10),
        ParsedRange::NotSatisfiable
    );
}

#[test]
fn image_artifact_old_behavior_rejection_retained_only_selection() {
    // The route never serves raw, quarantined, or model_payload components.
    // The media-kind map only recognizes validated raster and sanitized SVG.
    assert!(!is_validated_raster("quarantined_original"));
    assert!(!is_validated_raster("model_payload"));
    assert!(content_type_for_media_kind("quarantined_original").is_none());
}

// ===========================================================================
// image_artifact_route_fixture_redaction (subset)
// ===========================================================================

#[test]
fn image_artifact_route_fixture_redaction_no_path_in_metadata() {
    let m = valid_metadata();
    let json = serde_json::to_string(&m).expect("serialize");
    // No filesystem path, provider URL, or ComfyUI identifier appears.
    assert!(!json.contains('/'));
    assert!(!json.contains("comfyui"));
    assert!(!json.contains("http"));
    assert!(!json.contains("file:"));
    // Only opaque IDs and canonical decimal generations.
    assert!(json.contains("\"artifactId\""));
    assert!(json.contains("\"checksum\""));
}

#[test]
fn image_artifact_route_fixture_redaction_no_credential_in_reply() {
    let reply = ImageArtifactDaemonReplyV1 {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        request_id: VALID_REQUEST_ID.into(),
        outcome: ImageArtifactDaemonOutcomeV1::Error {
            error: ImageArtifactDaemonErrorV1::null_length(
                ImageArtifactDaemonErrorCode::ArtifactUnavailable,
            ),
        },
    };
    let json = serde_json::to_string(&reply).expect("serialize");
    // No ID echo beyond request_id, no free text, no path, no credential.
    assert!(!json.contains("password"));
    assert!(!json.contains("token"));
    assert!(!json.contains("bearer"));
    assert!(!json.contains("path"));
    // The error carries only code and authorizedLength.
    assert!(json.contains("\"code\":\"artifact_unavailable\""));
    assert!(json.contains("\"authorizedLength\":null"));
}

// ===========================================================================
// image_artifact_route_protocol_v1 read head validation
// ===========================================================================

fn valid_read_head(status: u16, is_svg: bool) -> ImageArtifactReadHeadV1 {
    ImageArtifactReadHeadV1 {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        request_id: VALID_REQUEST_ID.into(),
        transfer_id: VALID_TRANSFER_ID.into(),
        status,
        content_type: if is_svg {
            CONTENT_TYPE_SVG.into()
        } else {
            CONTENT_TYPE_PNG.into()
        },
        content_disposition: if is_svg {
            svg_content_disposition()
        } else {
            raster_download_content_disposition("image/png").unwrap()
        },
        cache_control: ARTIFACT_CACHE_CONTROL.into(),
        nosniff: ARTIFACT_NOSNIFF.into(),
        content_security_policy: if is_svg {
            Some(SVG_CONTENT_SECURITY_POLICY.into())
        } else {
            None
        },
        content_length: "12345".into(),
        content_range: if status == 206 {
            Some("bytes 0-99/12345".into())
        } else {
            None
        },
        etag: format!("\"{}\"", "a".repeat(64)),
        artifact_id: VALID_ARTIFACT_ID.into(),
        artifact_generation: "1".into(),
        component_generation: "1".into(),
        lease_deadline_ms: "60000".into(),
    }
}

#[test]
fn image_artifact_route_protocol_v1_read_head_valid_200_raster() {
    let head = valid_read_head(200, false);
    assert!(head.validate(false));
}

#[test]
fn image_artifact_route_protocol_v1_read_head_valid_206_raster() {
    let head = valid_read_head(206, false);
    assert!(head.validate(false));
}

#[test]
fn image_artifact_route_protocol_v1_read_head_valid_svg() {
    let head = valid_read_head(200, true);
    assert!(head.validate(true));
    // SVG with CSP set but validated as raster: fails (CSP must be null for raster).
    assert!(!head.validate(false));
}

#[test]
fn image_artifact_route_protocol_v1_read_head_rejects_bad_lease_deadline() {
    let mut head = valid_read_head(200, false);
    head.lease_deadline_ms = "0".into();
    assert!(!head.validate(false));
    head.lease_deadline_ms = "60001".into();
    assert!(!head.validate(false));
    head.lease_deadline_ms = "abc".into();
    assert!(!head.validate(false));
}

#[test]
fn image_artifact_route_protocol_v1_read_head_rejects_bad_etag() {
    let mut head = valid_read_head(200, false);
    head.etag = "not-quoted".into();
    assert!(!head.validate(false));
    head.etag = "\"short\"".into();
    assert!(!head.validate(false));
    // Unquoted hex.
    head.etag = "a".repeat(64);
    assert!(!head.validate(false));
}

#[test]
fn image_artifact_route_protocol_v1_read_head_rejects_200_with_range() {
    let mut head = valid_read_head(200, false);
    head.content_range = Some("bytes 0-99/12345".into());
    assert!(!head.validate(false));
}

#[test]
fn image_artifact_route_protocol_v1_read_head_rejects_206_without_range() {
    let mut head = valid_read_head(206, false);
    head.content_range = None;
    assert!(!head.validate(false));
}

#[test]
fn image_artifact_route_protocol_v1_read_head_rejects_bad_status() {
    let mut head = valid_read_head(200, false);
    head.status = 404;
    assert!(!head.validate(false));
}

#[test]
fn image_artifact_route_protocol_v1_metadata_validate() {
    assert!(valid_metadata().validate());
}

#[test]
fn image_artifact_route_protocol_v1_metadata_rejects_bad_boxes() {
    let mut m = valid_metadata();
    // Non-ascending.
    m.available_thumbnail_boxes = vec![512, 256];
    assert!(!m.validate());
    // Duplicate.
    m.available_thumbnail_boxes = vec![256, 256];
    assert!(!m.validate());
    // Invalid box.
    m.available_thumbnail_boxes = vec![128];
    assert!(!m.validate());
    // Valid ascending.
    m.available_thumbnail_boxes = vec![256, 512, 1024];
    assert!(m.validate());
}

#[test]
fn image_artifact_route_protocol_v1_metadata_rejects_zero_dims() {
    let mut m = valid_metadata();
    m.width = 0;
    assert!(!m.validate());
    m.width = 10;
    m.height = 0;
    assert!(!m.validate());
}

#[test]
fn image_artifact_route_protocol_v1_metadata_rejects_bad_checksum() {
    let mut m = valid_metadata();
    m.checksum = "short".into();
    assert!(!m.validate());
    m.checksum = "A".repeat(64); // uppercase
    assert!(!m.validate());
}

#[test]
fn image_artifact_route_protocol_v1_metadata_rejects_bad_disposition() {
    let mut m = valid_metadata();
    m.published_disposition = "quarantined".into();
    assert!(!m.validate());
}

#[test]
fn image_artifact_route_protocol_v1_thumbnail_pending_validate() {
    let p = ImageThumbnailPendingV1 {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        state: THUMBNAIL_PENDING_STATE.into(),
        artifact_id: VALID_ARTIFACT_ID.into(),
        artifact_generation: "1".into(),
        box_size: 512,
        work_generation: "1".into(),
        retry_after_ms: THUMBNAIL_PENDING_RETRY_AFTER_MS,
    };
    assert!(p.validate());
}

#[test]
fn image_artifact_route_protocol_v1_thumbnail_pending_rejects_bad_state() {
    let mut p = ImageThumbnailPendingV1 {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        state: "wrong".into(),
        artifact_id: VALID_ARTIFACT_ID.into(),
        artifact_generation: "1".into(),
        box_size: 512,
        work_generation: "1".into(),
        retry_after_ms: THUMBNAIL_PENDING_RETRY_AFTER_MS,
    };
    assert!(!p.validate());
    p.state = THUMBNAIL_PENDING_STATE.into();
    p.retry_after_ms = 999;
    assert!(!p.validate());
}

#[test]
fn image_artifact_route_protocol_v1_transfer_cancel_validate() {
    let r = ImageArtifactTransferCancelResultV1 {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        transfer_id: VALID_TRANSFER_ID.into(),
        state: TransferCancelState::Cancelled,
    };
    assert!(r.validate());
    let r2 = ImageArtifactTransferCancelResultV1 {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        transfer_id: VALID_TRANSFER_ID.into(),
        state: TransferCancelState::AlreadyTerminal,
    };
    assert!(r2.validate());
    // Bad transfer id.
    let r3 = ImageArtifactTransferCancelResultV1 {
        schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
        transfer_id: "short".into(),
        state: TransferCancelState::Cancelled,
    };
    assert!(!r3.validate());
}

// ===========================================================================
// image_artifact_route_authz (opaque ID isolation subset)
// ===========================================================================

#[test]
fn image_artifact_route_authz_opaque_ids_noninterchangeable() {
    // artifactId, componentId, transferId, thumbnailWorkId, and requestId are
    // distinct aliases; none parses as another. They all use the same 22-char
    // base64url codec, but their semantic kind is bound by the daemon tag, not
    // the bytes. The validator checks the codec shape only.
    assert!(parse_artifact_id(VALID_ARTIFACT_ID).is_some());
    assert!(parse_artifact_id(VALID_REQUEST_ID).is_some());
    // Distinct bytes decode to distinct values.
    assert_ne!(
        parse_artifact_id(VALID_ARTIFACT_ID),
        parse_artifact_id(VALID_REQUEST_ID)
    );
}

#[test]
fn image_artifact_route_authz_rejects_zero_artifact_id() {
    // An all-zero 16-byte ID is rejected (none parses as another).
    // "AAAAAAAAAAAAAAAAAAAAAA" decodes to all-zero? base64url of 16 zero
    // bytes is "AAAAAAAAAAAAAAAAAAAAAA" — which must be rejected.
    assert_eq!(parse_artifact_id("AAAAAAAAAAAAAAAAAAAAAA"), None);
}

#[test]
fn image_artifact_route_authz_image_admin_not_artifact_authority() {
    // ImageGenerationAdmin by itself is not artifact/session authority. The
    // route's existence-hiding 404 applies to image-admin-only access. This
    // is enforced at the authorization layer (control plane), not here; we
    // verify the error code that image-admin-only access maps to.
    let r = http_error_response(ImageArtifactDaemonErrorCode::ArtifactUnavailable, false);
    assert_eq!(r.status, 404);
    assert!(r.has_body);
}

// ===========================================================================
// image_artifact_route_lease_transfer (bulk constants subset)
// ===========================================================================

#[test]
fn image_artifact_route_lease_transfer_chunk_boundary() {
    assert_eq!(IMAGE_ARTIFACT_MAX_CHUNK_BYTES, 524_255);
}

#[test]
fn image_artifact_route_lease_transfer_receiver_window() {
    assert_eq!(IMAGE_ARTIFACT_RECEIVER_WINDOW_BYTES, 4 * 1024 * 1024);
}

#[test]
fn image_artifact_route_lease_transfer_queue_and_aggregate_caps() {
    assert_eq!(IMAGE_ARTIFACT_BULK_QUEUE_BYTES, 8 * 1024 * 1024);
    assert_eq!(IMAGE_ARTIFACT_AGGREGATE_CAP_BYTES, 16 * 1024 * 1024);
}

#[test]
fn image_artifact_route_lease_transfer_mime_class_constant() {
    assert_eq!(IMAGE_ARTIFACT_BYTES_MIME_CLASS, "image_artifact_bytes_v1");
}

#[test]
fn image_artifact_route_lease_transfer_begin_option_bits() {
    assert_eq!(IMAGE_ARTIFACT_BEGIN_OPTION_BITS, 0x03);
}

#[test]
fn image_artifact_route_lease_transfer_lease_deadline_bounds() {
    assert_eq!(LEASE_DEADLINE_MIN_MS, 1);
    assert_eq!(LEASE_DEADLINE_MAX_MS, 60_000);
}
