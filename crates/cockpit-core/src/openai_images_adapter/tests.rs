//! Tests for the OpenAI Images adapter.
//!
//! Covers: golden wire (generation JSON + edit multipart for every catalog
//! model and both moderation values), capability/preflight table, boundary
//! tests for both `gpt-image-2` identities, response parsing (bounded base64,
//! no URL branch), transport semantics (safe pre-handoff retry, ambiguous
//! post-handoff `submission_unknown`, stable request identity, no duplicate
//! paid submission), and multipart/reference/output-count/invalid-base64/
//! decode-bomb/MIME-mismatch/secret-redaction fixtures.

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use serde_json::Value;

use super::catalog::{
    Background, ImageModelIdentity, InputFidelity, Moderation, OpenaiImagesCatalog, OutputFormat,
    Quality,
};
use super::dto::NormalizedPrompt;
use super::preflight::{PreflightInput, PreflightReference, preflight};
use super::response::{DecodeLimit, parse_response};
use super::test_support::UnresolvablePlanSource;
use super::wire::{encode_generation, encode_multipart};
use super::{
    OpenaiImagesAdapter, OpenaiImagesAttemptInput, OpenaiImagesRoute, OpenaiImagesTransport,
    openai_images_adapter_sealed,
};
use crate::image_generation::transport::{ProviderTransportError, ProviderTransportOutcome};
use crate::image_generation_job::ImageGenerationHandoffResult;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_input(model: &str) -> PreflightInput {
    PreflightInput {
        model: model.into(),
        prompt: "a serene mountain lake at dawn".into(),
        n: 1,
        width: 1024,
        height: 1024,
        quality: "auto".into(),
        background: "auto".into(),
        output_format: "png".into(),
        moderation: "auto".into(),
        compression: None,
        input_fidelity: None,
    }
}

fn gpt_image_2_input() -> PreflightInput {
    let mut input = default_input("gpt-image-2");
    // 1024x1024 = 1,048,576 pixels, within 655,360..=8,294,400; aligned to 16.
    input.width = 1024;
    input.height = 1024;
    input
}

fn gpt_image_15_input() -> PreflightInput {
    let mut input = default_input("gpt-image-1.5");
    input.input_fidelity = Some("high".into());
    input
}

fn reference(filename: &str, mime: &str, byte_length: u64) -> PreflightReference {
    PreflightReference {
        filename: filename.into(),
        mime: mime.into(),
        byte_length,
    }
}

fn attempt_input(
    plan: super::preflight::PreflightPlan,
    idempotency: &str,
) -> OpenaiImagesAttemptInput {
    OpenaiImagesAttemptInput {
        plan,
        external_operation_id: uuid::Uuid::nil(),
        provider_request_identity: format!("req-{idempotency}"),
        provider_idempotency_identity: idempotency.into(),
    }
}

fn validated(
    input: &PreflightInput,
    refs: &[PreflightReference],
) -> super::preflight::PreflightPlan {
    preflight(input, refs).expect("preflight should succeed")
}

// ---------------------------------------------------------------------------
// Catalog tests
// ---------------------------------------------------------------------------

#[test]
fn catalog_has_exactly_four_entries() {
    assert_eq!(OpenaiImagesCatalog::descriptors().len(), 4);
}

#[test]
fn catalog_known_models_exclude_gpt_image_1() {
    let known = OpenaiImagesCatalog::known_models();
    assert!(known.contains("gpt-image-2"));
    assert!(known.contains("gpt-image-2-2026-04-21"));
    assert!(known.contains("gpt-image-1.5"));
    assert!(known.contains("gpt-image-1-mini"));
    assert!(!known.contains("gpt-image-1"));
    assert!(!known.contains("dall-e-3"));
}

#[test]
fn catalog_lookup_returns_none_for_unknown_model() {
    assert!(OpenaiImagesCatalog::lookup("gpt-image-1").is_none());
    assert!(OpenaiImagesCatalog::lookup("dall-e-3").is_none());
    assert!(OpenaiImagesCatalog::lookup("").is_none());
}

#[test]
fn catalog_dated_identity_is_distinct() {
    let a = OpenaiImagesCatalog::lookup("gpt-image-2").unwrap();
    let b = OpenaiImagesCatalog::lookup("gpt-image-2-2026-04-21").unwrap();
    assert_ne!(a.identity, b.identity);
    assert_eq!(a.identity, ImageModelIdentity::GptImage2);
    assert_eq!(b.identity, ImageModelIdentity::GptImage2Dated20260421);
}

#[test]
fn catalog_gpt_image_2_omits_input_fidelity_and_transparency() {
    let descriptor = OpenaiImagesCatalog::lookup("gpt-image-2").unwrap();
    assert!(descriptor.omit_input_fidelity);
    assert!(!descriptor.supports_background(Background::Transparent));
    assert!(descriptor.supports_background(Background::Auto));
    assert!(descriptor.supports_background(Background::Opaque));
}

#[test]
fn catalog_gpt_image_15_supports_transparency_and_fidelity() {
    let descriptor = OpenaiImagesCatalog::lookup("gpt-image-1.5").unwrap();
    assert!(!descriptor.omit_input_fidelity);
    assert!(descriptor.supports_background(Background::Transparent));
    assert!(descriptor.supports_input_fidelity(InputFidelity::Low));
    assert!(descriptor.supports_input_fidelity(InputFidelity::High));
}

#[test]
fn catalog_all_entries_support_all_qualities_formats_moderations() {
    for descriptor in OpenaiImagesCatalog::descriptors() {
        for quality in [Quality::Auto, Quality::Low, Quality::Medium, Quality::High] {
            assert!(
                descriptor.supports_quality(quality),
                "{:?} lacks quality {:?}",
                descriptor.identity.as_str(),
                quality.as_str()
            );
        }
        for format in [OutputFormat::Png, OutputFormat::Jpeg, OutputFormat::Webp] {
            assert!(
                descriptor.supports_format(format),
                "{:?} lacks format {:?}",
                descriptor.identity.as_str(),
                format.as_str()
            );
        }
        for moderation in [Moderation::Auto, Moderation::Low] {
            assert!(
                descriptor.supports_moderation(moderation),
                "{:?} lacks moderation {:?}",
                descriptor.identity.as_str(),
                moderation.as_str()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Preflight table tests
// ---------------------------------------------------------------------------

#[test]
fn preflight_rejects_unknown_model() {
    let mut input = gpt_image_15_input();
    input.model = "gpt-image-1".into();
    let failure = preflight(&input, &[]).unwrap_err();
    assert!(failure.reason.contains("unknown model"));
    assert!(failure.reason.contains("gpt-image-1"));
}

#[test]
fn preflight_rejects_unknown_moderation() {
    let mut input = gpt_image_15_input();
    input.moderation = "strict".into();
    let failure = preflight(&input, &[]).unwrap_err();
    assert!(failure.reason.contains("unknown moderation"));
}

#[test]
fn preflight_rejects_unknown_quality() {
    let mut input = gpt_image_15_input();
    input.quality = "ultra".into();
    let failure = preflight(&input, &[]).unwrap_err();
    assert!(failure.reason.contains("unknown quality"));
}

#[test]
fn preflight_rejects_transparent_jpeg() {
    let mut input = gpt_image_15_input();
    input.background = "transparent".into();
    input.output_format = "jpeg".into();
    let failure = preflight(&input, &[]).unwrap_err();
    assert!(
        failure
            .reason
            .contains("transparent background requires PNG or WebP")
    );
}

#[test]
fn preflight_rejects_png_compression() {
    let mut input = gpt_image_15_input();
    input.output_format = "png".into();
    input.compression = Some(80);
    let failure = preflight(&input, &[]).unwrap_err();
    assert!(failure.reason.contains("compression"));
    assert!(failure.reason.contains("must be omitted for PNG"));
}

#[test]
fn preflight_accepts_jpeg_compression_in_range() {
    let mut input = gpt_image_15_input();
    input.output_format = "jpeg".into();
    input.compression = Some(80);
    let result = preflight(&input, &[]).unwrap();
    assert_eq!(result.result.output_format, OutputFormat::Jpeg);
}

#[test]
fn preflight_rejects_compression_above_100() {
    let mut input = gpt_image_15_input();
    input.output_format = "webp".into();
    input.compression = Some(101);
    let failure = preflight(&input, &[]).unwrap_err();
    assert!(failure.reason.contains("compression 101 outside 0..=100"));
}

#[test]
fn preflight_rejects_input_fidelity_for_gpt_image_2() {
    let mut input = gpt_image_2_input();
    input.input_fidelity = Some("high".into());
    let failure = preflight(&input, &[]).unwrap_err();
    assert!(failure.reason.contains("input_fidelity"));
    assert!(failure.reason.contains("is not accepted"));
}

#[test]
fn preflight_requires_input_fidelity_for_gpt_image_15() {
    let mut input = gpt_image_15_input();
    input.input_fidelity = None;
    let failure = preflight(&input, &[]).unwrap_err();
    assert!(failure.reason.contains("input_fidelity is required"));
}

#[test]
fn preflight_rejects_transparent_for_gpt_image_2() {
    let mut input = gpt_image_2_input();
    input.background = "transparent".into();
    input.output_format = "png".into();
    let failure = preflight(&input, &[]).unwrap_err();
    assert!(
        failure
            .reason
            .contains("transparent background is rejected")
    );
}

#[test]
fn preflight_rejects_n_out_of_range() {
    let mut input = gpt_image_15_input();
    input.n = 0;
    assert!(preflight(&input, &[]).is_err());
    input.n = 11;
    assert!(preflight(&input, &[]).is_err());
}

#[test]
fn preflight_accepts_n_bounds() {
    let mut input = gpt_image_15_input();
    input.n = 1;
    assert!(preflight(&input, &[]).is_ok());
    input.n = 10;
    assert!(preflight(&input, &[]).is_ok());
}

#[test]
fn preflight_rejects_prompt_too_long_utf8() {
    let mut input = gpt_image_15_input();
    input.prompt = "x".repeat(128_001);
    let failure = preflight(&input, &[]).unwrap_err();
    assert!(failure.reason.contains("UTF-8 bytes"));
}

#[test]
fn preflight_rejects_prompt_too_many_scalars() {
    let mut input = gpt_image_15_input();
    // 2-byte chars: 64,001 scalars = 128,002 bytes, exceeds both. Use a
    // 3-byte char to exceed scalar limit before byte limit.
    input.prompt = "€".repeat(32_001);
    let failure = preflight(&input, &[]).unwrap_err();
    assert!(failure.reason.contains("Unicode scalar values"));
}

#[test]
fn preflight_rejects_too_many_references() {
    let input = gpt_image_15_input();
    let refs = (0..17)
        .map(|i| reference(&format!("ref-{i}.png"), "image/png", 1024))
        .collect::<Vec<_>>();
    let failure = preflight(&input, &refs).unwrap_err();
    assert!(failure.reason.contains("too many references"));
}

#[test]
fn preflight_generation_route_for_zero_references() {
    let input = gpt_image_15_input();
    let plan = preflight(&input, &[]).unwrap();
    assert_eq!(plan.route, OpenaiImagesRoute::Generations);
}

#[test]
fn preflight_edit_route_for_one_reference() {
    let input = gpt_image_15_input();
    let refs = vec![reference("ref-0.png", "image/png", 1024)];
    let plan = preflight(&input, &refs).unwrap();
    assert_eq!(plan.route, OpenaiImagesRoute::Edits);
}

#[test]
fn preflight_gpt_image_15_rejects_unsupported_size() {
    let mut input = gpt_image_15_input();
    input.width = 768;
    input.height = 768;
    let failure = preflight(&input, &[]).unwrap_err();
    assert!(failure.reason.contains("size 768x768 unsupported"));
}

#[test]
fn preflight_gpt_image_15_accepts_auto_size() {
    let mut input = gpt_image_15_input();
    input.width = 0;
    input.height = 0;
    // auto is represented as (0,0) in the candidate list.
    let plan = preflight(&input, &[]).unwrap();
    assert_eq!(plan.result.size_value(), "auto");
}

// ---------------------------------------------------------------------------
// gpt-image-2 boundary tests (both identities)
// ---------------------------------------------------------------------------

fn check_gpt_image_2_boundary(model: &str) {
    let base = || {
        let mut input = default_input(model);
        input.input_fidelity = None;
        input
    };

    // Inclusive lower pixel bound: 655,360 = 16*16 * 2560... actually
    // 655,360 = 16 * 16 * 2560? No: 655360 = 1024*640. Both aligned to 16,
    // ratio 1.6:1 <= 3:1. Accepted.
    let mut min_ok = base();
    min_ok.width = 1024;
    min_ok.height = 640;
    assert!(
        preflight(&min_ok, &[]).is_ok(),
        "{model}: min pixels accepted"
    );

    // Just below min: 655,344 = 1008*656? Let's use 16*16=256 pixels, below min.
    let mut below_min = base();
    below_min.width = 16;
    below_min.height = 16;
    let failure = preflight(&below_min, &[]).unwrap_err();
    assert!(
        failure.reason.contains("total pixels 256 outside"),
        "{model}: {failure}"
    );

    // Inclusive upper pixel bound: 8,294,400 = 3840*2160? 3840*2160=8,294,400.
    // But 2160 not aligned to 16? 2160/16=135, yes aligned. Ratio 3840:2160 =
    // 1.78:1 <= 3:1. Accepted at exactly 3840 edge.
    let mut max_ok = base();
    max_ok.width = 3840;
    max_ok.height = 2160;
    assert!(
        preflight(&max_ok, &[]).is_ok(),
        "{model}: max pixels accepted"
    );

    // 3856 edge: exceeds max edge 3840. Rejected.
    let mut over_edge = base();
    over_edge.width = 3856;
    over_edge.height = 1024;
    let failure = preflight(&over_edge, &[]).unwrap_err();
    assert!(
        failure.reason.contains("exceed max edge 3840"),
        "{model}: {failure}"
    );

    // 3840 edge accepted, 3856 rejected (per research notes).
    // 3840 edge at the maximum, paired with a height that keeps the aspect
    // ratio within 3:1 (3840:1280 == 3:1 exactly) and pixels in range.
    let mut at_3840 = base();
    at_3840.width = 3840;
    at_3840.height = 1280;
    assert!(
        preflight(&at_3840, &[]).is_ok(),
        "{model}: 3840 edge accepted"
    );

    // Non-16-aligned: 1025x1024. Rejected.
    let mut unaligned = base();
    unaligned.width = 1025;
    unaligned.height = 1024;
    let failure = preflight(&unaligned, &[]).unwrap_err();
    assert!(
        failure.reason.contains("not aligned to 16"),
        "{model}: {failure}"
    );

    // Ratio over 3:1: 3072x1024 = 3:1 exactly (accepted). 3072x1023 rejected
    // by alignment anyway. Use 4096x1024 = 4:1, but 4096 > 3840 edge. Use
    // 3072x1023 -> 1023 not aligned. Use 3024x1008 = 3:1 exactly (aligned).
    // 3072x1024 = 3:1 exactly, both aligned, pixels 3,145,728 within range.
    let mut ratio_ok = base();
    ratio_ok.width = 3072;
    ratio_ok.height = 1024;
    assert!(
        preflight(&ratio_ok, &[]).is_ok(),
        "{model}: 3:1 ratio accepted"
    );

    // Ratio over 3:1: 3328x1024 = 3.25:1, both aligned, pixels 3,407,872 in
    // range, edge 3328 <= 3840. Rejected by ratio.
    let mut ratio_over = base();
    ratio_over.width = 3328;
    ratio_over.height = 1024;
    let failure = preflight(&ratio_over, &[]).unwrap_err();
    assert!(
        failure.reason.contains("aspect ratio exceeds 3:1"),
        "{model}: {failure}"
    );

    // Transparency rejected for gpt-image-2.
    let mut transparent = base();
    transparent.background = "transparent".into();
    transparent.output_format = "png".into();
    let failure = preflight(&transparent, &[]).unwrap_err();
    assert!(
        failure
            .reason
            .contains("transparent background is rejected"),
        "{model}: {failure}"
    );

    // input_fidelity omitted (None) is accepted.
    let mut with_fidelity = base();
    with_fidelity.input_fidelity = Some("high".into());
    let failure = preflight(&with_fidelity, &[]).unwrap_err();
    assert!(
        failure.reason.contains("input_fidelity") && failure.reason.contains("is not accepted"),
        "{model}: {failure}"
    );
}

#[test]
fn preflight_gpt_image_2_boundaries() {
    check_gpt_image_2_boundary("gpt-image-2");
}

#[test]
fn preflight_gpt_image_2_dated_boundaries() {
    check_gpt_image_2_boundary("gpt-image-2-2026-04-21");
}

// ---------------------------------------------------------------------------
// Wire tests: golden generation JSON for every catalog model + moderation
// ---------------------------------------------------------------------------

fn assert_generation_json(model: &str, moderation: &str) {
    let mut input = match model {
        "gpt-image-2" | "gpt-image-2-2026-04-21" => gpt_image_2_input(),
        _ => gpt_image_15_input(),
    };
    input.model = model.into();
    input.moderation = moderation.into();
    input.n = 2;
    let plan = validated(&input, &[]);
    let attempt = attempt_input(plan, "idem-1");
    let body = encode_generation(&attempt).expect("generation encode");
    assert_eq!(body.content_type(), "application/json");
    let json: Value = serde_json::from_slice(&body.into_bytes()).expect("valid json");
    assert_eq!(json["model"], model);
    assert_eq!(json["prompt"], input.prompt);
    assert_eq!(json["n"], 2);
    assert_eq!(json["quality"], "auto");
    assert_eq!(json["background"], "auto");
    assert_eq!(json["output_format"], "png");
    assert_eq!(json["moderation"], moderation);
    assert_eq!(json["stream"], false);
    // No Responses/Chat/DALL-E route fields.
    assert!(json.get("messages").is_none());
    assert!(json.get("model_class").is_none());
    assert!(json.get("partial_images").is_none());
    assert!(json.get("url").is_none());
}

#[test]
fn wire_generation_json_all_models_moderation_auto() {
    for model in [
        "gpt-image-2",
        "gpt-image-2-2026-04-21",
        "gpt-image-1.5",
        "gpt-image-1-mini",
    ] {
        assert_generation_json(model, "auto");
    }
}

#[test]
fn wire_generation_json_all_models_moderation_low() {
    for model in [
        "gpt-image-2",
        "gpt-image-2-2026-04-21",
        "gpt-image-1.5",
        "gpt-image-1-mini",
    ] {
        assert_generation_json(model, "low");
    }
}

#[test]
fn wire_generation_json_gpt_image_2_size_is_width_x_height() {
    let mut input = gpt_image_2_input();
    input.width = 2048;
    input.height = 1024;
    let plan = validated(&input, &[]);
    let attempt = attempt_input(plan, "idem-2");
    let body = encode_generation(&attempt).unwrap();
    let json: Value = serde_json::from_slice(&body.into_bytes()).unwrap();
    assert_eq!(json["size"], "2048x1024");
}

#[test]
fn wire_generation_json_gpt_image_15_size_is_candidate_value() {
    let mut input = gpt_image_15_input();
    input.width = 1024;
    input.height = 1536;
    let plan = validated(&input, &[]);
    let attempt = attempt_input(plan, "idem-3");
    let body = encode_generation(&attempt).unwrap();
    let json: Value = serde_json::from_slice(&body.into_bytes()).unwrap();
    assert_eq!(json["size"], "1024x1536");
}

#[test]
fn wire_generation_serializes_stream_false_and_no_partial_images() {
    let input = gpt_image_15_input();
    let plan = validated(&input, &[]);
    let attempt = attempt_input(plan, "idem-4");
    let body = encode_generation(&attempt).unwrap();
    let json: Value = serde_json::from_slice(&body.into_bytes()).unwrap();
    assert_eq!(json["stream"], false);
    assert!(json.get("partial_images").is_none());
}

// ---------------------------------------------------------------------------
// Wire tests: golden edit multipart
// ---------------------------------------------------------------------------

#[test]
fn wire_edit_multipart_contains_all_fields_and_references() {
    let input = gpt_image_15_input();
    let refs = vec![
        reference("ref-0.png", "image/png", 4),
        reference("ref-1.png", "image/png", 4),
    ];
    let plan = validated(&input, &refs);
    let attempt = attempt_input(plan, "idem-edit-1");
    let body = encode_multipart(&attempt).expect("multipart encode");
    let content_type = body.content_type().to_string();
    assert!(content_type.starts_with("multipart/form-data; boundary="));
    let boundary = content_type
        .strip_prefix("multipart/form-data; boundary=")
        .unwrap()
        .to_string();
    let bytes = body.into_bytes();
    let text = String::from_utf8(bytes.clone()).unwrap();
    // Text fields present in deterministic order.
    assert!(text.contains("name=\"model\""));
    assert!(text.contains("gpt-image-1.5"));
    assert!(text.contains("name=\"prompt\""));
    assert!(text.contains("name=\"n\""));
    assert!(text.contains("name=\"size\""));
    assert!(text.contains("name=\"quality\""));
    assert!(text.contains("name=\"background\""));
    assert!(text.contains("name=\"output_format\""));
    assert!(text.contains("name=\"moderation\""));
    assert!(text.contains("name=\"stream\""));
    assert!(text.contains("false"));
    assert!(text.contains("name=\"input_fidelity\""));
    assert!(text.contains("high"));
    // Two image parts with provider field name image[].
    assert_eq!(text.matches("name=\"image[]\"").count(), 2);
    // Boundary terminus present.
    assert!(text.ends_with(&format!("--{boundary}--\r\n")));
}

#[test]
fn wire_edit_multipart_omits_input_fidelity_for_gpt_image_2() {
    let input = gpt_image_2_input();
    let refs = vec![reference("ref-0.png", "image/png", 4)];
    let plan = validated(&input, &refs);
    let attempt = attempt_input(plan, "idem-edit-2");
    let body = encode_multipart(&attempt).unwrap();
    let text = String::from_utf8(body.into_bytes()).unwrap();
    assert!(!text.contains("name=\"input_fidelity\""));
}

#[test]
fn wire_edit_multipart_boundary_is_deterministic() {
    let input = gpt_image_15_input();
    let refs = vec![reference("ref-0.png", "image/png", 4)];
    let plan = validated(&input, &refs);
    let attempt_a = attempt_input(plan.clone(), "idem-A");
    let attempt_b = attempt_input(plan, "idem-A");
    let body_a = encode_multipart(&attempt_a).unwrap();
    let body_b = encode_multipart(&attempt_b).unwrap();
    assert_eq!(body_a.content_type(), body_b.content_type());
    assert_eq!(body_a.into_bytes(), body_b.into_bytes());
}

#[test]
fn wire_edit_multipart_boundary_differs_for_different_idempotency() {
    let input = gpt_image_15_input();
    let refs = vec![reference("ref-0.png", "image/png", 4)];
    let plan = validated(&input, &refs);
    let attempt_a = attempt_input(plan.clone(), "idem-A");
    let attempt_b = attempt_input(plan, "idem-B");
    let body_a = encode_multipart(&attempt_a).unwrap();
    let body_b = encode_multipart(&attempt_b).unwrap();
    assert_ne!(body_a.content_type(), body_b.content_type());
}

#[test]
fn wire_edit_requires_at_least_one_reference() {
    let input = gpt_image_15_input();
    let plan = validated(&input, &[]);
    let attempt = attempt_input(plan, "idem-edit-3");
    assert!(encode_multipart(&attempt).is_err());
}

#[test]
fn wire_edit_rejects_reference_exceeding_per_reference_bound() {
    let input = gpt_image_15_input();
    let refs = vec![reference("big.png", "image/png", 65 * 1024 * 1024 + 1)];
    let plan = validated(&input, &refs);
    let attempt = attempt_input(plan, "idem-edit-4");
    assert!(encode_multipart(&attempt).is_err());
}

#[test]
fn wire_edit_rejects_references_exceeding_aggregate_bound() {
    let input = gpt_image_15_input();
    // 16 references * 16 MiB = 256 MiB = exactly aggregate bound; add one more
    // byte via a 17th... but max is 16 references. Use 4 * 64 MiB + 1.
    let refs = vec![
        reference("a.png", "image/png", 64 * 1024 * 1024),
        reference("b.png", "image/png", 64 * 1024 * 1024),
        reference("c.png", "image/png", 64 * 1024 * 1024),
        reference("d.png", "image/png", 64 * 1024 * 1024 + 1),
    ];
    let plan = validated(&input, &refs);
    let attempt = attempt_input(plan, "idem-edit-5");
    assert!(encode_multipart(&attempt).is_err());
}

// ---------------------------------------------------------------------------
// Response tests: bounded base64, no URL branch
// ---------------------------------------------------------------------------

fn one_pixel_png_base64() -> String {
    // A minimal valid 1x1 PNG.
    let bytes = [
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // signature
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, // IHDR
        0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x62, 0x00, 0x01, 0x00, 0x00,
        0x05, 0x00, 0x01, 0xC1, 0xA0, 0x2D, 0x2A, // IDAT
        0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82, // IEND
    ];
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn response_body(b64: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"data": [{"b64_json": b64}]})).unwrap()
}

#[test]
fn response_parses_bounded_b64_json() {
    let input = gpt_image_15_input();
    let plan = validated(&input, &[]);
    let body = response_body(&one_pixel_png_base64());
    let parsed = parse_response(&body, &plan, &DecodeLimit::canonical()).unwrap();
    assert_eq!(parsed.slots.len(), 1);
    assert!(parsed.slots[0].bytes.len() > 8); // PNG signature present
}

#[test]
fn response_rejects_url_output_field() {
    // The adapter must not parse a URL output. A response with only `url` and
    // no `b64_json` must fail (missing b64_json).
    let input = gpt_image_15_input();
    let plan = validated(&input, &[]);
    let body = serde_json::to_vec(&serde_json::json!({
        "data": [{"url": "https://example.com/image.png"}]
    }))
    .unwrap();
    let failure = parse_response(&body, &plan, &DecodeLimit::canonical()).unwrap_err();
    // b64_json is a required field; its absence fails deserialization.
    assert!(failure.reason.contains("not valid JSON") || failure.reason.contains("b64_json"));
}

#[test]
fn response_rejects_too_many_returned_items() {
    let input = gpt_image_15_input();
    let plan = validated(&input, &[]);
    let b64 = one_pixel_png_base64();
    let body = serde_json::to_vec(&serde_json::json!({
        "data": [{"b64_json": b64}, {"b64_json": b64}]
    }))
    .unwrap();
    let failure = parse_response(&body, &plan, &DecodeLimit::canonical()).unwrap_err();
    assert!(failure.reason.contains("extras rejected"));
}

#[test]
fn response_rejects_missing_items() {
    let input = gpt_image_15_input();
    let plan = validated(&input, &[]);
    let body = serde_json::to_vec(&serde_json::json!({"data": []})).unwrap();
    let failure = parse_response(&body, &plan, &DecodeLimit::canonical()).unwrap_err();
    assert!(failure.reason.contains("no items"));
}

#[test]
fn response_rejects_invalid_base64() {
    let input = gpt_image_15_input();
    let plan = validated(&input, &[]);
    let body = serde_json::to_vec(&serde_json::json!({
        "data": [{"b64_json": "!!!not-base64!!!"}]
    }))
    .unwrap();
    let failure = parse_response(&body, &plan, &DecodeLimit::canonical()).unwrap_err();
    assert!(failure.reason.contains("base64 decode failed"));
}

#[test]
fn response_rejects_decode_bomb_over_limit() {
    let input = gpt_image_15_input();
    let plan = validated(&input, &[]);
    // A valid base64 string whose decoded length exceeds a tiny limit.
    let big = "A".repeat(8);
    let limit = DecodeLimit {
        max_base64_bytes: 1024,
        max_decoded_bytes: 1,
    };
    let body = response_body(&big);
    let failure = parse_response(&body, &plan, &limit).unwrap_err();
    assert!(failure.reason.contains("decoded size"));
    assert!(failure.reason.contains("exceeds bound"));
}

#[test]
fn response_rejects_mime_mismatch() {
    let input = gpt_image_15_input();
    let plan = validated(&input, &[]);
    // bytes that are not a valid PNG despite the format claim.
    let bogus = base64::engine::general_purpose::STANDARD.encode(b"not a png");
    let body = response_body(&bogus);
    let failure = parse_response(&body, &plan, &DecodeLimit::canonical()).unwrap_err();
    assert!(failure.reason.contains("decode/mime validation failed"));
}

#[test]
fn response_fewer_than_planned_is_missing_slots() {
    let mut input = gpt_image_15_input();
    input.n = 3;
    let plan = validated(&input, &[]);
    let b64 = one_pixel_png_base64();
    let body = serde_json::to_vec(&serde_json::json!({
        "data": [{"b64_json": b64}]
    }))
    .unwrap();
    let failure = parse_response(&body, &plan, &DecodeLimit::canonical()).unwrap_err();
    assert!(failure.reason.contains("missing slots"));
}

// ---------------------------------------------------------------------------
// Transport tests: safe pre-handoff retry, ambiguous post-handoff, stable
// request identity, no duplicate paid submission
// ---------------------------------------------------------------------------

struct ScriptedTransport {
    outcomes: Mutex<Vec<Result<ProviderTransportOutcome, ProviderTransportError>>>,
    submissions: Mutex<Vec<(OpenaiImagesRoute, String, Vec<u8>)>>,
}

impl ScriptedTransport {
    fn new(outcomes: Vec<Result<ProviderTransportOutcome, ProviderTransportError>>) -> Self {
        Self {
            outcomes: Mutex::new(outcomes),
            submissions: Mutex::new(Vec::new()),
        }
    }
    fn submissions(&self) -> Vec<(OpenaiImagesRoute, String, Vec<u8>)> {
        self.submissions.lock().unwrap().clone()
    }
}

impl openai_images_adapter_sealed::Sealed for ScriptedTransport {}

#[async_trait::async_trait]
impl OpenaiImagesTransport for ScriptedTransport {
    async fn submit(
        &self,
        route: OpenaiImagesRoute,
        content_type: &str,
        body: &[u8],
    ) -> Result<ProviderTransportOutcome, ProviderTransportError> {
        self.submissions
            .lock()
            .unwrap()
            .push((route, content_type.to_string(), body.to_vec()));
        self.outcomes
            .lock()
            .unwrap()
            .pop()
            .expect("scripted transport exhausted")
    }
}

fn adapter(transport: ScriptedTransport) -> OpenaiImagesAdapter {
    // The `attempt`-based tests never call `handoff`, so the plan source is
    // unused; a never-resolving one keeps construction honest.
    OpenaiImagesAdapter::new(
        Arc::new(transport),
        Arc::new(UnresolvablePlanSource::new("attempt-only")),
        DecodeLimit::canonical(),
    )
}

fn generation_attempt_input(idem: &str) -> OpenaiImagesAttemptInput {
    let input = gpt_image_15_input();
    let plan = validated(&input, &[]);
    attempt_input(plan, idem)
}

#[tokio::test]
async fn transport_pre_handoff_connect_is_definitive_rejection() {
    // A pre-handoff Connect/Tls failure proves no byte was accepted, so the
    // adapter reports a definitive rejection (safe to resubmit).
    for pre_handoff in [ProviderTransportError::Connect, ProviderTransportError::Tls] {
        let transport = ScriptedTransport::new(vec![Err(pre_handoff)]);
        let adapter = adapter(transport);
        let input = generation_attempt_input("idem-pre");
        let (result, parsed) = adapter.attempt(&input).await;
        assert!(parsed.is_none());
        match result {
            ImageGenerationHandoffResult::DefinitivelyRejected { evidence } => {
                let text = String::from_utf8_lossy(&evidence);
                assert!(text.contains("pre_handoff_no_byte_accepted"));
            }
            other => panic!("expected DefinitivelyRejected, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn transport_post_handoff_ambiguous_is_submission_unknown() {
    // Both a post-handoff Timeout and an AmbiguousAcceptance map to
    // SubmissionUnknown: the request bytes were written, so the outcome must be
    // reconciled rather than assumed rejected.
    for ambiguous in [
        ProviderTransportError::Timeout,
        ProviderTransportError::AmbiguousAcceptance,
    ] {
        let transport = ScriptedTransport::new(vec![Err(ambiguous)]);
        let adapter = adapter(transport);
        let input = generation_attempt_input("idem-amb");
        let (result, _) = adapter.attempt(&input).await;
        match result {
            ImageGenerationHandoffResult::SubmissionUnknown { evidence } => {
                let text = String::from_utf8_lossy(&evidence);
                assert!(text.contains("post_handoff_ambiguous"));
            }
            other => panic!("expected SubmissionUnknown, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn transport_definitive_status_is_definitive_rejection() {
    let transport = ScriptedTransport::new(vec![Err(ProviderTransportError::Status {
        status: 401,
        body: Vec::new(),
    })]);
    let adapter = adapter(transport);
    let input = generation_attempt_input("idem-rej");
    let (result, _) = adapter.attempt(&input).await;
    assert!(matches!(
        result,
        ImageGenerationHandoffResult::DefinitivelyRejected { .. }
    ));
}

#[tokio::test]
async fn transport_body_limit_is_definitive_rejection() {
    let transport = ScriptedTransport::new(vec![Err(ProviderTransportError::BodyLimit)]);
    let adapter = adapter(transport);
    let input = generation_attempt_input("idem-body-limit");
    let (result, _) = adapter.attempt(&input).await;
    match result {
        ImageGenerationHandoffResult::DefinitivelyRejected { evidence } => {
            let text = String::from_utf8_lossy(&evidence);
            assert!(text.contains("body_limit"));
        }
        other => panic!("expected DefinitivelyRejected, got {other:?}"),
    }
}

#[tokio::test]
async fn transport_stable_request_identity_for_same_idempotency() {
    let b64 = one_pixel_png_base64();
    let body = response_body(&b64);
    let transport = ScriptedTransport::new(vec![
        Ok(ProviderTransportOutcome { status: 200, body }),
        Ok(ProviderTransportOutcome {
            status: 200,
            body: response_body(&b64),
        }),
    ]);
    let adapter = adapter(transport);
    let input_a = generation_attempt_input("same-idem");
    let input_b = generation_attempt_input("same-idem");
    let (result_a, _) = adapter.attempt(&input_a).await;
    let (result_b, _) = adapter.attempt(&input_b).await;
    // Both accepted; evidence encodes route + status (redacted, no secrets).
    assert!(matches!(
        result_a,
        ImageGenerationHandoffResult::Accepted { .. }
    ));
    assert!(matches!(
        result_b,
        ImageGenerationHandoffResult::Accepted { .. }
    ));
    assert_eq!(result_a, result_b);
}

#[tokio::test]
async fn transport_no_duplicate_paid_submission_on_post_handoff_ambiguous() {
    // On PostHandoffAmbiguous, the adapter reports SubmissionUnknown and does
    // NOT retry. The scripted transport has exactly one outcome; if the
    // adapter retried, the second pop would panic. The test passing (no panic)
    // proves a single submission.
    let transport = ScriptedTransport::new(vec![Err(ProviderTransportError::AmbiguousAcceptance)]);
    let adapter = adapter(transport);
    let input = generation_attempt_input("idem-no-dup");
    let (result, _) = adapter.attempt(&input).await;
    assert!(matches!(
        result,
        ImageGenerationHandoffResult::SubmissionUnknown { .. }
    ));
}

#[tokio::test]
async fn transport_records_exactly_one_submission_per_attempt() {
    let b64 = one_pixel_png_base64();
    let body = response_body(&b64);
    let transport =
        ScriptedTransport::new(vec![Ok(ProviderTransportOutcome { status: 200, body })]);
    let recorded = Arc::new(transport);
    let adapter = OpenaiImagesAdapter::new(
        recorded.clone(),
        Arc::new(UnresolvablePlanSource::new("attempt-only")),
        DecodeLimit::canonical(),
    );
    let input = generation_attempt_input("idem-count");
    let (_result, _) = adapter.attempt(&input).await;
    let submissions = recorded.submissions();
    assert_eq!(submissions.len(), 1);
    assert_eq!(submissions[0].0, OpenaiImagesRoute::Generations);
    assert_eq!(submissions[0].1, "application/json");
}

#[tokio::test]
async fn transport_accepted_with_valid_output_returns_parsed_response() {
    let b64 = one_pixel_png_base64();
    let body = response_body(&b64);
    let transport =
        ScriptedTransport::new(vec![Ok(ProviderTransportOutcome { status: 200, body })]);
    let adapter = adapter(transport);
    let input = generation_attempt_input("idem-ok");
    let (result, parsed) = adapter.attempt(&input).await;
    assert!(matches!(
        result,
        ImageGenerationHandoffResult::Accepted { .. }
    ));
    let parsed = parsed.expect("parsed response");
    assert_eq!(parsed.slots.len(), 1);
}

#[tokio::test]
async fn transport_accepted_with_invalid_output_is_accepted_handoff() {
    // The provider accepted (paid) but returned invalid output. The handoff
    // is Accepted (spend committed), with redacted evidence.
    let bogus = base64::engine::general_purpose::STANDARD.encode(b"not a png");
    let body = response_body(&bogus);
    let transport =
        ScriptedTransport::new(vec![Ok(ProviderTransportOutcome { status: 200, body })]);
    let adapter = adapter(transport);
    let input = generation_attempt_input("idem-invalid");
    let (result, parsed) = adapter.attempt(&input).await;
    assert!(parsed.is_none());
    assert!(matches!(
        result,
        ImageGenerationHandoffResult::Accepted { .. }
    ));
}

// ---------------------------------------------------------------------------
// Secret redaction: credential data and raw reference bytes absent from
// evidence and errors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn evidence_excludes_credentials_and_reference_bytes() {
    let b64 = one_pixel_png_base64();
    let body = response_body(&b64);
    let transport =
        ScriptedTransport::new(vec![Ok(ProviderTransportOutcome { status: 200, body })]);
    let adapter = adapter(transport);
    let mut input = gpt_image_15_input();
    input.prompt = "secret-prompt-do-not-leak".into();
    let refs = vec![reference("secret-ref.png", "image/png", 4)];
    let plan = validated(&input, &refs);
    let attempt = OpenaiImagesAttemptInput {
        plan,
        external_operation_id: uuid::Uuid::nil(),
        provider_request_identity: "req-secret".into(),
        provider_idempotency_identity: "idem-secret".into(),
    };
    let (result, _) = adapter.attempt(&attempt).await;
    if let ImageGenerationHandoffResult::Accepted { evidence } = result {
        let text = String::from_utf8_lossy(&evidence);
        assert!(!text.contains("secret-prompt-do-not-leak"));
        assert!(!text.contains("secret-ref.png"));
        assert!(!text.contains("Bearer"));
        assert!(!text.contains("sk-"));
    } else {
        panic!("expected Accepted, got {result:?}");
    }
}

#[test]
fn preflight_failure_reasons_redact_no_reference_bytes() {
    let input = gpt_image_15_input();
    let refs = vec![reference("leak.png", "image/png", 4)];
    // Force a failure (too many references).
    let mut many = refs.clone();
    many.resize(17, reference("x.png", "image/png", 4));
    let failure = preflight(&input, &many).unwrap_err();
    // The reason mentions counts, not byte contents.
    assert!(failure.reason.contains("too many references 17"));
    assert!(!failure.reason.contains("leak.png"));
}

// ---------------------------------------------------------------------------
// Normalized prompt sanity
// ---------------------------------------------------------------------------

#[test]
fn normalized_prompt_preserves_text() {
    let prompt = NormalizedPrompt("hello world".into());
    assert_eq!(prompt.as_str(), "hello world");
}
