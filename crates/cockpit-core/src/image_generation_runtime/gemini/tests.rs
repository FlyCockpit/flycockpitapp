//! Golden REST, catalog, raw-step, inline/URI, output-count, and absence
//! tests for the Gemini Interactions API image-generation adapter.

use super::*;
use crate::image_generation_runtime::{ImageRuntimeAdapter, ProbeRequest};
use cockpit_config::config::image_generation::{
    ImageAdapterKind, ImageEndpoint, ImageFormat, ImageLocationClass, ReferenceImageSupport,
};

// ── Helpers ─────────────────────────────────────────────────────────────────

fn reference(mime: &str, bytes: &[u8], order: u32) -> GeminiReferenceAttachment {
    GeminiReferenceAttachment {
        mime_type: mime.to_owned(),
        bytes: bytes.to_vec(),
        order,
    }
}

fn parse_response(json: &str) -> GeminiInteractionsResponse {
    serde_json::from_str(json).expect("response must parse")
}

// ── AC 1: Golden REST request tests ─────────────────────────────────────────

#[test]
fn gemini_text_only_request_is_exact_wire_contract() {
    let request = build_interactions_request(&GeminiInteractionsRequestInput {
        model: "gemini-3-pro-image".to_owned(),
        prompt: "a red panda painting watercolors".to_owned(),
        references: vec![],
        mime_type: Some("image/png".to_owned()),
        aspect_ratio: Some(GeminiAspectRatio::Square),
        image_size: Some(GeminiImageSize::Large),
        planned_outputs: 1,
    })
    .expect("text-only request must build");

    let json = serde_json::to_value(&request).unwrap();
    // Exact POST /v1beta/interactions body shape.
    assert_eq!(json["model"], "gemini-3-pro-image");
    assert!(json["input"].is_array());
    assert_eq!(json["input"].as_array().unwrap().len(), 1);
    assert_eq!(json["input"][0]["type"], "text");
    assert_eq!(json["input"][0]["text"], "a red panda painting watercolors");
    // Top-level image response_format.
    assert_eq!(json["response_format"]["type"], "image");
    assert_eq!(json["response_format"]["mime_type"], "image/png");
    assert_eq!(json["response_format"]["aspect_ratio"], "1:1");
    assert_eq!(json["response_format"]["image_size"], "large");
    // No legacy fields.
    assert!(json.get("generation_config").is_none());
    assert!(json.get("response_modalities").is_none());
    assert!(json.get("generation_config").is_none());
    // No generateContent / OpenAI facade fields.
    assert!(json.get("contents").is_none());
    assert!(json.get("messages").is_none());
}

#[test]
fn gemini_referenced_request_encodes_references_in_prompt_order() {
    let request = build_interactions_request(&GeminiInteractionsRequestInput {
        model: "gemini-3.1-flash-image".to_owned(),
        prompt: "edit this image to be sunset".to_owned(),
        references: vec![
            reference("image/jpeg", b"second-bytes", 1),
            reference("image/png", b"first-bytes", 0),
        ],
        mime_type: Some("image/png".to_owned()),
        aspect_ratio: Some(GeminiAspectRatio::Landscape),
        image_size: Some(GeminiImageSize::Medium),
        planned_outputs: 1,
    })
    .expect("referenced request must build");

    let json = serde_json::to_value(&request).unwrap();
    let input = json["input"].as_array().unwrap();
    // Deterministic: text first, then references in prompt order.
    assert_eq!(input.len(), 3);
    assert_eq!(input[0]["type"], "text");
    assert_eq!(input[1]["type"], "image");
    assert_eq!(input[1]["mime_type"], "image/png");
    assert_eq!(
        input[1]["data"],
        base64::engine::general_purpose::STANDARD.encode(b"first-bytes")
    );
    assert_eq!(input[2]["type"], "image");
    assert_eq!(input[2]["mime_type"], "image/jpeg");
    assert_eq!(
        input[2]["data"],
        base64::engine::general_purpose::STANDARD.encode(b"second-bytes")
    );
}

#[test]
fn gemini_request_omits_provider_default_fields() {
    // gemini-2.5-flash-image has image_size_policy = ProviderDefault.
    let request = build_interactions_request(&GeminiInteractionsRequestInput {
        model: "gemini-2.5-flash-image".to_owned(),
        prompt: "a sunset".to_owned(),
        references: vec![],
        mime_type: Some("image/png".to_owned()),
        aspect_ratio: Some(GeminiAspectRatio::Square),
        image_size: Some(GeminiImageSize::Small),
        planned_outputs: 1,
    })
    .expect("request must build");

    let json = serde_json::to_value(&request).unwrap();
    // aspect_ratio is explicit, image_size is provider-default (omitted).
    assert_eq!(json["response_format"]["aspect_ratio"], "1:1");
    assert!(
        json["response_format"].get("image_size").is_none()
            || json["response_format"]["image_size"].is_null()
    );
}

#[test]
fn gemini_request_x_goog_api_key_header_is_credential_boundary() {
    // The adapter does not set the header itself — the registry resolves it
    // from credential_ref into the ephemeral header map. We verify the header
    // name constant and that the route is the interactions endpoint.
    assert_eq!(API_KEY_HEADER, "x-goog-api-key");
    assert_eq!(INTERACTIONS_ROUTE, "/v1beta/interactions");
    // The route is registered in config for GeminiImages.
    assert_eq!(
        ImageAdapterKind::GeminiImages
            .route(cockpit_config::config::image_generation::ImageRoute::Generate),
        Some("/v1beta/interactions")
    );
}

// ── AC 2: Catalog tests ─────────────────────────────────────────────────────

#[test]
fn gemini_catalog_enumerates_exactly_four_models() {
    let names = catalog_model_names();
    assert_eq!(
        names,
        vec![
            "gemini-3.1-flash-lite-image",
            "gemini-3.1-flash-image",
            "gemini-3-pro-image",
            "gemini-2.5-flash-image",
        ]
    );
    assert_eq!(GEMINI_IMAGE_CATALOG.len(), 4);
}

#[test]
fn gemini_catalog_rejects_unknown_alias_preview_and_latest_names() {
    let rejected = [
        "gemini-3-pro-image-preview",
        "gemini-3-pro-image-latest",
        "gemini-3-pro-image-v2",
        "gemini-2.5-flash-image-preview",
        "gpt-4o",
        "",
        "gemini-3-pro-image ",
        "Gemini-3-Pro-Image",
        "gemini-4-flash-image",
        "gemini-3.1-flash-lite",
    ];
    for name in &rejected {
        assert!(!catalog_contains(name), "catalog must reject `{name}`");
        assert!(
            catalog_descriptor(name).is_none(),
            "descriptor must be absent for `{name}`"
        );
    }
}

#[test]
fn gemini_catalog_documents_aspect_ratios_tiers_formats_and_reference_rules() {
    let flash_lite = catalog_descriptor("gemini-3.1-flash-lite-image").unwrap();
    assert!(
        flash_lite
            .aspect_ratios
            .contains(&GeminiAspectRatio::Square)
    );
    assert!(
        flash_lite
            .aspect_ratios
            .contains(&GeminiAspectRatio::Portrait)
    );
    assert!(
        flash_lite
            .aspect_ratios
            .contains(&GeminiAspectRatio::Landscape)
    );
    assert!(!flash_lite.aspect_ratios.contains(&GeminiAspectRatio::Tall));
    assert!(flash_lite.image_sizes.contains(&GeminiImageSize::Small));
    assert!(flash_lite.image_sizes.contains(&GeminiImageSize::Medium));
    assert!(!flash_lite.image_sizes.contains(&GeminiImageSize::Large));
    assert!(flash_lite.formats.contains(&ImageFormat::Png));
    assert!(flash_lite.formats.contains(&ImageFormat::Jpeg));
    assert!(!flash_lite.formats.contains(&ImageFormat::Webp));
    assert_eq!(
        flash_lite.reference_support,
        ReferenceImageSupport::Optional
    );
    assert_eq!(flash_lite.max_reference_images, 1);

    let pro = catalog_descriptor("gemini-3-pro-image").unwrap();
    assert!(pro.formats.contains(&ImageFormat::Webp));
    assert!(pro.aspect_ratios.contains(&GeminiAspectRatio::Wide));
    assert!(pro.image_sizes.contains(&GeminiImageSize::Large));
    assert_eq!(pro.max_reference_images, MAX_REFERENCE_IMAGES as u32);

    let legacy = catalog_descriptor("gemini-2.5-flash-image").unwrap();
    // Legacy-but-supported remains explicit, not hidden.
    assert_eq!(
        legacy.image_size_policy,
        GeminiControlPolicy::ProviderDefault
    );
    assert_eq!(legacy.aspect_ratio_policy, GeminiControlPolicy::Explicit);
    assert_eq!(legacy.max_reference_images, 1);
    assert_eq!(legacy.source_date, CATALOG_SOURCE_DATE);
}

#[test]
fn gemini_catalog_resolution_functions_are_pure() {
    assert_eq!(
        resolve_aspect_ratio("gemini-3-pro-image", "1:1").unwrap(),
        GeminiAspectRatio::Square
    );
    assert!(resolve_aspect_ratio("gemini-3-pro-image", "2:3").is_err());
    assert!(resolve_aspect_ratio("unknown-model", "1:1").is_err());

    assert_eq!(
        resolve_image_size("gemini-3-pro-image", "large").unwrap(),
        GeminiImageSize::Large
    );
    assert!(resolve_image_size("gemini-3-pro-image", "xlarge").is_err());

    assert_eq!(
        resolve_format("gemini-3-pro-image", "image/png").unwrap(),
        ImageFormat::Png
    );
    assert!(resolve_format("gemini-3.1-flash-lite-image", "image/webp").is_err());
    assert!(resolve_format("unknown", "image/png").is_err());
}

// ── AC 3: Raw response fixture tests ────────────────────────────────────────

#[test]
fn gemini_extracts_images_only_from_model_output_steps() {
    let png_bytes = b"\x89PNG\r\n\x1a\nfake-png";
    let encoded = base64::engine::general_purpose::STANDARD.encode(png_bytes);
    let json = format!(
        r#" {{
            "id": "interaction-1",
            "status": "completed",
            "steps": [
                {{
                    "type": "user_input",
                    "content": [{{"type": "text", "text": "generate an image"}}]
                }},
                {{
                    "type": "model_output",
                    "step_id": "step-1",
                    "content": [
                        {{"type": "text", "text": "here is your image"}},
                        {{"type": "image", "data": "{encoded}", "mime_type": "image/png"}}
                    ]
                }}
            ]
        }} "#
    );
    let response = parse_response(&json);
    let result = extract_images(&response, 1).expect("must extract");
    assert_eq!(result.images.len(), 1);
    assert_eq!(result.images[0].data.as_deref(), Some(png_bytes.as_slice()));
    assert_eq!(result.images[0].mime_type, "image/png");
    assert_eq!(result.images[0].step_index, 1);
    assert_eq!(result.images[0].content_index, 1);
}

#[test]
fn gemini_rejects_image_content_outside_model_output() {
    let png_bytes = b"fake";
    let encoded = base64::engine::general_purpose::STANDARD.encode(png_bytes);
    let json = format!(
        r#" {{
            "status": "completed",
            "steps": [
                {{
                    "type": "user_input",
                    "content": [{{"type": "image", "data": "{encoded}", "mime_type": "image/png"}}]
                }}
            ]
        }} "#
    );
    let response = parse_response(&json);
    let err = extract_images(&response, 1).unwrap_err();
    assert_eq!(err, GeminiAdapterError::ImageContentOutsideModelOutput);
}

#[test]
fn gemini_no_sdk_output_image_parser_exists() {
    // The DTO must not have output_image or output_text fields. We verify by
    // deserializing a response that includes them and confirming they are
    // ignored (serde does not fail with unknown fields by default here, but
    // our GeminiInteractionsResponse does not declare them).
    let json = r#" {
        "status": "completed",
        "output_image": "should-be-ignored",
        "output_text": "should-be-ignored",
        "steps": []
    } "#;
    let response: GeminiInteractionsResponse = serde_json::from_str(json).unwrap();
    assert_eq!(response.status.as_deref(), Some("completed"));
    assert!(response.steps.is_empty());
    // No field on the struct for SDK conveniences.
    let serialized = serde_json::to_string(&response).unwrap();
    assert!(!serialized.contains("output_image"));
    assert!(!serialized.contains("output_text"));
}

// ── AC 4: Inline and URI response tests ─────────────────────────────────────

#[test]
fn gemini_inline_image_exactly_one_source_data() {
    let bytes = b"inline-png-bytes";
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let json = format!(
        r#" {{
            "status": "completed",
            "steps": [
                {{
                    "type": "model_output",
                    "content": [
                        {{"type": "image", "data": "{encoded}", "mime_type": "image/png"}}
                    ]
                }}
            ]
        }} "#
    );
    let response = parse_response(&json);
    let result = extract_images(&response, 1).unwrap();
    assert_eq!(result.images.len(), 1);
    assert!(result.images[0].data.is_some());
    assert!(result.images[0].uri.is_none());
}

#[test]
fn gemini_uri_image_exactly_one_source_uri() {
    let json = r#" {
        "status": "completed",
        "steps": [
            {
                "type": "model_output",
                "content": [
                    {"type": "image", "uri": "https://storage.googleapis.com/bucket/image.png", "mime_type": "image/png"}
                ]
            }
        ]
    } "#;
    let response = parse_response(&json);
    let result = extract_images(&response, 1).unwrap();
    assert_eq!(result.images.len(), 1);
    assert!(result.images[0].data.is_none());
    assert_eq!(
        result.images[0].uri.as_deref(),
        Some("https://storage.googleapis.com/bucket/image.png")
    );
}

#[test]
fn gemini_rejects_both_data_and_uri() {
    let encoded = base64::engine::general_purpose::STANDARD.encode(b"bytes");
    let json = format!(
        r#" {{
            "status": "completed",
            "steps": [
                {{
                    "type": "model_output",
                    "content": [
                        {{"type": "image", "data": "{encoded}", "uri": "https://example.com/img.png", "mime_type": "image/png"}}
                    ]
                }}
            ]
        }} "#
    );
    let response = parse_response(&json);
    let err = extract_images(&response, 1).unwrap_err();
    assert_eq!(err, GeminiAdapterError::ImageSourceAmbiguous);
}

#[test]
fn gemini_rejects_neither_data_nor_uri() {
    let json = r#" {
        "status": "completed",
        "steps": [
            {
                "type": "model_output",
                "content": [
                    {"type": "image", "mime_type": "image/png"}
                ]
            }
        ]
    } "#;
    let response = parse_response(&json);
    let err = extract_images(&response, 1).unwrap_err();
    assert_eq!(err, GeminiAdapterError::ImageSourceAbsent);
}

#[test]
fn gemini_rejects_invalid_base64() {
    let json = r#" {
        "status": "completed",
        "steps": [
            {
                "type": "model_output",
                "content": [
                    {"type": "image", "data": "!!!not-base64!!!", "mime_type": "image/png"}
                ]
            }
        ]
    } "#;
    let response = parse_response(&json);
    let err = extract_images(&response, 1).unwrap_err();
    assert_eq!(err, GeminiAdapterError::InvalidBase64);
}

#[test]
fn gemini_rejects_decode_mismatch() {
    // Valid base64 but with trailing data that doesn't re-encode identically.
    // We use padding corruption to trigger a decode mismatch.
    let json = r#" {
        "status": "completed",
        "steps": [
            {
                "type": "model_output",
                "content": [
                    {"type": "image", "data": "YWJj====", "mime_type": "image/png"}
                ]
            }
        ]
    } "#;
    let response = parse_response(&json);
    let result = extract_images(&response, 1);
    // Either InvalidBase64 or DecodeMismatch is acceptable here; both are
    // stable slot failures.
    assert!(matches!(
        result,
        Err(GeminiAdapterError::InvalidBase64) | Err(GeminiAdapterError::DecodeMismatch)
    ));
}

#[test]
fn gemini_rejects_absent_mime_type() {
    let encoded = base64::engine::general_purpose::STANDARD.encode(b"bytes");
    let json = format!(
        r#" {{
            "status": "completed",
            "steps": [
                {{
                    "type": "model_output",
                    "content": [
                        {{"type": "image", "data": "{encoded}"}}
                    ]
                }}
            ]
        }} "#
    );
    let response = parse_response(&json);
    let err = extract_images(&response, 1).unwrap_err();
    assert_eq!(err, GeminiAdapterError::InvalidMimeType);
}

#[test]
fn gemini_rejects_invalid_mime_type() {
    let encoded = base64::engine::general_purpose::STANDARD.encode(b"bytes");
    let json = format!(
        r#" {{
            "status": "completed",
            "steps": [
                {{
                    "type": "model_output",
                    "content": [
                        {{"type": "image", "data": "{encoded}", "mime_type": "application/json"}}
                    ]
                }}
            ]
        }} "#
    );
    let response = parse_response(&json);
    let err = extract_images(&response, 1).unwrap_err();
    assert_eq!(err, GeminiAdapterError::InvalidMimeType);
}

#[test]
fn gemini_output_order_is_step_then_content_order() {
    let b1 = base64::engine::general_purpose::STANDARD.encode(b"first");
    let b2 = base64::engine::general_purpose::STANDARD.encode(b"second");
    let b3 = base64::engine::general_purpose::STANDARD.encode(b"third");
    let json = format!(
        r#" {{
            "status": "completed",
            "steps": [
                {{
                    "type": "model_output",
                    "content": [
                        {{"type": "image", "data": "{b1}", "mime_type": "image/png"}}
                    ]
                }},
                {{
                    "type": "model_output",
                    "content": [
                        {{"type": "text", "text": "interstitial"}},
                        {{"type": "image", "data": "{b2}", "mime_type": "image/png"}},
                        {{"type": "image", "data": "{b3}", "mime_type": "image/png"}}
                    ]
                }}
            ]
        }} "#
    );
    let response = parse_response(&json);
    let result = extract_images(&response, 3).unwrap();
    assert_eq!(result.images.len(), 3);
    assert_eq!(result.images[0].data.as_deref(), Some(b"first".as_slice()));
    assert_eq!(result.images[1].data.as_deref(), Some(b"second".as_slice()));
    assert_eq!(result.images[2].data.as_deref(), Some(b"third".as_slice()));
    assert_eq!(result.images[0].step_index, 0);
    assert_eq!(result.images[1].step_index, 1);
    assert_eq!(result.images[1].content_index, 1);
    assert_eq!(result.images[2].content_index, 2);
}

// ── AC 5: Output-count tests ────────────────────────────────────────────────

#[test]
fn gemini_missing_outputs_do_not_fill_in_resubmit() {
    // Planned 3, but only 1 image part present. Missing outputs become missing
    // slot failures — the result returns 1 image (no fill-in resubmission).
    let encoded = base64::engine::general_purpose::STANDARD.encode(b"only");
    let json = format!(
        r#" {{
            "status": "completed",
            "steps": [
                {{
                    "type": "model_output",
                    "content": [
                        {{"type": "image", "data": "{encoded}", "mime_type": "image/png"}}
                    ]
                }}
            ]
        }} "#
    );
    let response = parse_response(&json);
    let result = extract_images(&response, 3).unwrap();
    // We get exactly the 1 image present; the caller records 2 missing slots.
    assert_eq!(result.images.len(), 1);
}

#[test]
fn gemini_extra_parts_beyond_planned_are_rejected() {
    let b1 = base64::engine::general_purpose::STANDARD.encode(b"first");
    let b2 = base64::engine::general_purpose::STANDARD.encode(b"second");
    let json = format!(
        r#" {{
            "status": "completed",
            "steps": [
                {{
                    "type": "model_output",
                    "content": [
                        {{"type": "image", "data": "{b1}", "mime_type": "image/png"}},
                        {{"type": "image", "data": "{b2}", "mime_type": "image/png"}}
                    ]
                }}
            ]
        }} "#
    );
    let response = parse_response(&json);
    let err = extract_images(&response, 1).unwrap_err();
    assert_eq!(
        err,
        GeminiAdapterError::OutputOverflow {
            planned: 1,
            actual: 2
        }
    );
}

#[test]
fn gemini_text_only_response_fails_planned_slots() {
    let json = r#" {
        "status": "completed",
        "steps": [
            {
                "type": "model_output",
                "content": [
                    {"type": "text", "text": "I cannot generate that image"}
                ]
            }
        ]
    } "#;
    let response = parse_response(&json);
    let result = extract_images(&response, 1).unwrap();
    // Valid text but no valid image — fails planned slots (0 images).
    assert_eq!(result.images.len(), 0);
    // Bounded non-sensitive text retained as provider metadata only.
    assert_eq!(result.provider_text.len(), 1);
    assert_eq!(result.provider_text[0], "I cannot generate that image");
}

// ── AC 6: Absence of legacy fields in production requests ───────────────────

#[test]
fn gemini_production_request_has_no_legacy_fields() {
    let request = build_interactions_request(&GeminiInteractionsRequestInput {
        model: "gemini-3-pro-image".to_owned(),
        prompt: "test".to_owned(),
        references: vec![],
        mime_type: None,
        aspect_ratio: None,
        image_size: None,
        planned_outputs: 1,
    })
    .unwrap();
    let json = serde_json::to_string(&request).unwrap();
    // No generateContent, generation_config.image_config, response_modalities,
    // tools, previous-interaction state, streaming, or arbitrary pixel size.
    assert!(!json.contains("generateContent"));
    assert!(!json.contains("generation_config"));
    assert!(!json.contains("image_config"));
    assert!(!json.contains("response_modalities"));
    assert!(!json.contains("tools"));
    assert!(!json.contains("previous_interaction_id"));
    assert!(!json.contains("stream"));
    assert!(!json.contains("width"));
    assert!(!json.contains("height"));
    assert!(!json.contains("contents"));
    assert!(!json.contains("messages"));
}

// ── AC 7: Ambiguous handoff, duplicate steps, late results, changed config ─

#[test]
fn gemini_non_completed_status_is_attempt_failure() {
    let json = r#" {"status": "running", "steps": []} "#;
    let response = parse_response(json);
    let err = extract_images(&response, 1).unwrap_err();
    assert!(matches!(
        err,
        GeminiAdapterError::InteractionNotCompleted { status } if status.as_deref() == Some("running")
    ));
}

#[test]
fn gemini_missing_status_is_attempt_failure() {
    let json = r#" {"steps": []} "#;
    let response = parse_response(json);
    let err = extract_images(&response, 1).unwrap_err();
    assert!(matches!(
        err,
        GeminiAdapterError::InteractionNotCompleted { status: None }
    ));
}

#[test]
fn gemini_duplicate_step_replay_is_idempotent() {
    let encoded = base64::engine::general_purpose::STANDARD.encode(b"image");
    let json = format!(
        r#" {{
            "status": "completed",
            "steps": [
                {{
                    "type": "model_output",
                    "step_id": "same-step",
                    "content": [
                        {{"type": "image", "data": "{encoded}", "mime_type": "image/png"}}
                    ]
                }},
                {{
                    "type": "model_output",
                    "step_id": "same-step",
                    "content": [
                        {{"type": "image", "data": "{encoded}", "mime_type": "image/png"}}
                    ]
                }}
            ]
        }} "#
    );
    let response = parse_response(&json);
    let result = extract_images(&response, 1).unwrap();
    // Duplicate step_id is replayed idempotently — only 1 image.
    assert_eq!(result.images.len(), 1);
}

#[test]
fn gemini_secret_redaction_does_not_expose_raw_data() {
    let bytes = b"sensitive-image-bytes";
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let json = format!(
        r#" {{
            "id": "interaction-secret",
            "status": "completed",
            "steps": [
                {{
                    "type": "model_output",
                    "content": [
                        {{"type": "image", "data": "{encoded}", "mime_type": "image/png"}}
                    ]
                }}
            ]
        }} "#
    );
    let response = parse_response(&json);
    let result = extract_images(&response, 1).unwrap();
    let summary = redact_response_summary(&response, &result);
    let serialized = serde_json::to_string(&summary).unwrap();
    // Raw response data and reference data are not logged.
    assert!(!serialized.contains("sensitive-image-bytes"));
    assert!(!serialized.contains(&encoded));
    assert!(serialized.contains("image_count"));
    assert_eq!(summary.image_count, 1);
    assert_eq!(
        summary.interaction_id.as_deref(),
        Some("interaction-secret")
    );
}

#[test]
fn gemini_reference_limit_exceeded_is_preflight_failure() {
    let refs: Vec<GeminiReferenceAttachment> = (0..2)
        .map(|i| reference("image/png", b"bytes", i))
        .collect();
    let err = build_interactions_request(&GeminiInteractionsRequestInput {
        model: "gemini-3.1-flash-lite-image".to_owned(), // max 1 reference
        prompt: "edit".to_owned(),
        references: refs,
        mime_type: None,
        aspect_ratio: None,
        image_size: None,
        planned_outputs: 1,
    })
    .unwrap_err();
    assert!(matches!(
        err,
        GeminiAdapterError::ReferenceLimitExceeded {
            requested: 2,
            max: 1,
            ..
        }
    ));
}

#[test]
fn gemini_unsupported_reference_mime_is_preflight_failure() {
    let err = build_interactions_request(&GeminiInteractionsRequestInput {
        model: "gemini-3-pro-image".to_owned(),
        prompt: "edit".to_owned(),
        references: vec![reference("application/pdf", b"bytes", 0)],
        mime_type: None,
        aspect_ratio: None,
        image_size: None,
        planned_outputs: 1,
    })
    .unwrap_err();
    assert_eq!(
        err,
        GeminiAdapterError::ReferenceMimeUnsupported("application/pdf".to_owned())
    );
}

#[test]
fn gemini_unknown_model_is_preflight_failure() {
    let err = build_interactions_request(&GeminiInteractionsRequestInput {
        model: "gemini-4-flash-image".to_owned(),
        prompt: "test".to_owned(),
        references: vec![],
        mime_type: None,
        aspect_ratio: None,
        image_size: None,
        planned_outputs: 1,
    })
    .unwrap_err();
    assert_eq!(
        err,
        GeminiAdapterError::UnknownModel("gemini-4-flash-image".to_owned())
    );
}

#[test]
fn gemini_inline_image_too_large_is_preflight_failure() {
    let big = vec![0u8; MAX_INLINE_IMAGE_BYTES + 1];
    let err = build_interactions_request(&GeminiInteractionsRequestInput {
        model: "gemini-3-pro-image".to_owned(),
        prompt: "test".to_owned(),
        references: vec![reference("image/png", &big, 0)],
        mime_type: None,
        aspect_ratio: None,
        image_size: None,
        planned_outputs: 1,
    })
    .unwrap_err();
    assert!(matches!(
        err,
        GeminiAdapterError::InlineImageTooLarge { decoded_bytes, max }
        if decoded_bytes == MAX_INLINE_IMAGE_BYTES + 1 && max == MAX_INLINE_IMAGE_BYTES
    ));
}

#[test]
fn gemini_build_request_for_target_returns_json_value() {
    let value = build_request_for_target(
        "gemini-3-pro-image",
        "a cat",
        vec![],
        Some("image/png"),
        Some(GeminiAspectRatio::Square),
        Some(GeminiImageSize::Large),
        1,
    )
    .unwrap();
    assert_eq!(value["model"], "gemini-3-pro-image");
    assert_eq!(value["response_format"]["type"], "image");
}

#[test]
fn gemini_standard_adapter_kind_is_gemini_images() {
    let adapter = standard_adapter();
    assert_eq!(adapter.kind(), ImageAdapterKind::GeminiImages);
}

#[test]
fn gemini_adapter_request_uses_interactions_route() {
    let endpoint = ImageEndpoint {
        id: "gemini-endpoint".into(),
        adapter: ImageAdapterKind::GeminiImages,
        origin: "https://generativelanguage.googleapis.com".into(),
        path_prefix: None,
        credential_ref: Some("google-api-key".into()),
        headers: vec![],
        allow_insecure_transport: false,
        location: ImageLocationClass::PublicCloud,
        enabled: true,
        route_profile_version: 1,
    };
    let resolved_headers = reqwest::header::HeaderMap::new();
    let probe = ProbeRequest {
        endpoint: endpoint.clone(),
        target_id: "gemini-target".into(),
        config_generation: 1,
        refresh_epoch: 1,
        request_id: 1,
        kind: crate::image_generation_runtime::RefreshKind::Health,
        credential_identity_digest: super::super::CredentialIdentityDigest::from_sha256([0u8; 32]),
        resolved_headers,
        limits: super::super::ProbeLimits::health(),
    };
    let adapter = GeminiImageRuntimeAdapter::new();
    let request = adapter.request(&probe).expect("probe request must build");
    assert_eq!(
        request.url.as_str(),
        "https://generativelanguage.googleapis.com/v1beta/interactions"
    );
}

#[test]
fn gemini_adapter_parse_rejects_auth_failure_status() {
    use crate::image_generation_runtime::{BoundProbeResponse, ConnectionHop, RefreshKind};
    use std::net::{IpAddr, Ipv4Addr};

    let endpoint = ImageEndpoint {
        id: "gemini-endpoint".into(),
        adapter: ImageAdapterKind::GeminiImages,
        origin: "https://generativelanguage.googleapis.com".into(),
        path_prefix: None,
        credential_ref: Some("google-api-key".into()),
        headers: vec![],
        allow_insecure_transport: false,
        location: ImageLocationClass::PublicCloud,
        enabled: true,
        route_profile_version: 1,
    };
    let probe = ProbeRequest {
        endpoint,
        target_id: "gemini-target".into(),
        config_generation: 1,
        refresh_epoch: 1,
        request_id: 1,
        kind: RefreshKind::Health,
        credential_identity_digest: super::super::CredentialIdentityDigest::from_sha256([0u8; 32]),
        resolved_headers: reqwest::header::HeaderMap::new(),
        limits: super::super::ProbeLimits::health(),
    };
    let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let response = BoundProbeResponse {
        status: reqwest::StatusCode::UNAUTHORIZED,
        body: Vec::new(),
        connection: super::super::ConnectionProof {
            authority: "generativelanguage.googleapis.com:443".into(),
            connected_ip: ip,
            location: super::super::AddressClass::PublicRemote,
            established_at: 0,
            hops: vec![ConnectionHop {
                authority: "generativelanguage.googleapis.com:443".into(),
                hostname: "generativelanguage.googleapis.com".into(),
                connected_ip: ip,
                location: super::super::AddressClass::PublicRemote,
            }],
        },
    };
    let adapter = GeminiImageRuntimeAdapter::new();
    let err = adapter.parse(&probe, &response).unwrap_err();
    assert_eq!(err.code, super::super::RuntimeErrorCode::Authentication);
}

#[test]
fn gemini_adapter_parse_success_returns_healthy() {
    use crate::image_generation_runtime::{BoundProbeResponse, ConnectionHop, RefreshKind};
    use std::net::{IpAddr, Ipv4Addr};

    let endpoint = ImageEndpoint {
        id: "gemini-endpoint".into(),
        adapter: ImageAdapterKind::GeminiImages,
        origin: "https://generativelanguage.googleapis.com".into(),
        path_prefix: None,
        credential_ref: Some("google-api-key".into()),
        headers: vec![],
        allow_insecure_transport: false,
        location: ImageLocationClass::PublicCloud,
        enabled: true,
        route_profile_version: 1,
    };
    let probe = ProbeRequest {
        endpoint,
        target_id: "gemini-target".into(),
        config_generation: 1,
        refresh_epoch: 1,
        request_id: 1,
        kind: RefreshKind::Health,
        credential_identity_digest: super::super::CredentialIdentityDigest::from_sha256([0u8; 32]),
        resolved_headers: reqwest::header::HeaderMap::new(),
        limits: super::super::ProbeLimits::health(),
    };
    let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let response = BoundProbeResponse {
        status: reqwest::StatusCode::OK,
        body: Vec::new(),
        connection: super::super::ConnectionProof {
            authority: "generativelanguage.googleapis.com:443".into(),
            connected_ip: ip,
            location: super::super::AddressClass::PublicRemote,
            established_at: 0,
            hops: vec![ConnectionHop {
                authority: "generativelanguage.googleapis.com:443".into(),
                hostname: "generativelanguage.googleapis.com".into(),
                connected_ip: ip,
                location: super::super::AddressClass::PublicRemote,
            }],
        },
    };
    let adapter = GeminiImageRuntimeAdapter::new();
    let result = adapter.parse(&probe, &response).unwrap();
    assert_eq!(result.state, super::super::ImageHealthState::Healthy);
}

#[test]
fn gemini_resolution_text_and_thought_parts_are_not_image_slots() {
    let encoded = base64::engine::general_purpose::STANDARD.encode(b"img");
    let json = format!(
        r#" {{
            "status": "completed",
            "steps": [
                {{
                    "type": "model_output",
                    "content": [
                        {{"type": "thought", "text": "thinking about the image"}},
                        {{"type": "text", "text": "here it is"}},
                        {{"type": "image", "data": "{encoded}", "mime_type": "image/png"}}
                    ]
                }}
            ]
        }} "#
    );
    let response = parse_response(&json);
    let result = extract_images(&response, 1).unwrap();
    assert_eq!(result.images.len(), 1);
    // Thought and text are retained as bounded provider metadata.
    assert!(result.provider_text.len() >= 1);
}

#[test]
fn gemini_malformed_steps_empty_content_is_not_failure() {
    let json = r#" {
        "status": "completed",
        "steps": [
            {"type": "model_output", "content": []}
        ]
    } "#;
    let response = parse_response(json);
    let result = extract_images(&response, 1).unwrap();
    assert_eq!(result.images.len(), 0);
}

#[test]
fn gemini_provider_text_is_bounded_and_control_stripped() {
    // Control characters are stripped; very long text is truncated.
    let long_text: String = "a".repeat(10_000);
    let json = format!(
        r#" {{
            "status": "completed",
            "steps": [
                {{
                    "type": "model_output",
                    "content": [
                        {{"type": "text", "text": "{long_text}\x00\x01"}}
                    ]
                }}
            ]
        }} "#
    );
    let response = parse_response(&json);
    let result = extract_images(&response, 1).unwrap();
    assert_eq!(result.provider_text.len(), 1);
    // Bounded to 4 KiB.
    assert!(result.provider_text[0].len() <= 4 * 1024);
    // No control characters.
    assert!(!result.provider_text[0].chars().any(|c| c.is_control()));
}
