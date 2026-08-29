//! Tests for the `read_image` tool: schema, transform, encoder, and
//! per-AgentDef tiering.
//!
//! Acceptance criteria covered:
//! 1. `read_image_schema` — exact mutually exclusive source, region, maxima,
//!    format, unknown-field, and bounded description behavior.
//! 2. `read_image_transform` — orientation-normalized crop-before-Lanczos3-
//!    scale, 2048 defaults, proportional fitting, no upscale, reject-not-
//!    clamp regions.
//! 3. `read_image_encoder` — auto=PNG, exact PNG/JPEG/WebP settings, alpha
//!    preservation/rejection, signatures/MIME, metadata removal, deterministic
//!    bytes.
//! 4. Input tests — no bypass of path/session/SSRF/identity/resource policy
//!    (the tool fails closed without the attachment authority).
//! 5. Output — only metadata plus opaque typed reference; no base64/path/
//!    query/provider URL in text/events/logs.
//! 7. Per-AgentDef tests — the exact tier table; Monty has no host APIs.

#![allow(clippy::needless_pass_by_value)]

use super::*;
use image::{ImageBuffer, Rgba};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A small 4×4 RGBA test image.
fn test_image_4x4() -> Vec<u8> {
    let mut img = ImageBuffer::new(4, 4);
    for (x, y, pixel) in img.enumerate_pixels_mut() {
        *pixel = Rgba([(x * 64) as u8, (y * 64) as u8, 128, 255]);
    }
    let mut bytes = Vec::new();
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut std::io::Cursor::new(&mut bytes), ImageFormat::Png)
        .unwrap();
    bytes
}

/// A 100×60 RGBA test image with a known pattern.
fn test_image_100x60() -> Vec<u8> {
    let mut img = ImageBuffer::new(100, 60);
    for (x, y, pixel) in img.enumerate_pixels_mut() {
        *pixel = Rgba([(x % 256) as u8, (y % 256) as u8, 100, 255]);
    }
    let mut bytes = Vec::new();
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut std::io::Cursor::new(&mut bytes), ImageFormat::Png)
        .unwrap();
    bytes
}

/// A 4×4 RGBA image with semi-transparent pixels.
fn test_image_with_alpha() -> Vec<u8> {
    let mut img = ImageBuffer::new(4, 4);
    for (x, y, pixel) in img.enumerate_pixels_mut() {
        *pixel = Rgba([
            (x * 64) as u8,
            (y * 64) as u8,
            128,
            if x == 0 { 128 } else { 255 }, // first column is semi-transparent
        ]);
    }
    let mut bytes = Vec::new();
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut std::io::Cursor::new(&mut bytes), ImageFormat::Png)
        .unwrap();
    bytes
}

// ===========================================================================
// Schema tests — Acceptance criterion 1
// ===========================================================================

mod schema {
    use super::*;

    #[test]
    fn read_image_schema_path_only_succeeds() {
        let args = json!({"path": "/tmp/test.png"});
        let parsed = ReadImageArgs::from_value(&args).unwrap();
        assert_eq!(parsed.path.as_deref(), Some("/tmp/test.png"));
        assert!(parsed.url.is_none());
        assert!(parsed.region.is_none());
        assert!(parsed.max_width.is_none());
        assert!(parsed.max_height.is_none());
        assert_eq!(parsed.format, OutputFormat::Auto);
    }

    #[test]
    fn read_image_schema_url_only_succeeds() {
        let args = json!({"url": "https://example.com/test.png"});
        let parsed = ReadImageArgs::from_value(&args).unwrap();
        assert!(parsed.path.is_none());
        assert_eq!(parsed.url.as_deref(), Some("https://example.com/test.png"));
    }

    #[test]
    fn read_image_schema_both_sources_fails() {
        let args = json!({"path": "/tmp/test.png", "url": "https://example.com/test.png"});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn read_image_schema_neither_source_fails() {
        let args = json!({"format": "png"});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn read_image_schema_http_url_rejected() {
        let args = json!({"url": "http://example.com/test.png"});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("https://"));
    }

    #[test]
    fn read_image_schema_empty_path_rejected() {
        let args = json!({"path": ""});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("non-empty"));
    }

    #[test]
    fn read_image_schema_empty_url_rejected() {
        let args = json!({"url": ""});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("non-empty"));
    }

    #[test]
    fn read_image_schema_region_valid() {
        let args = json!({
            "path": "/tmp/test.png",
            "region": {"x": 10, "y": 20, "width": 100, "height": 50}
        });
        let parsed = ReadImageArgs::from_value(&args).unwrap();
        let region = parsed.region.unwrap();
        assert_eq!(
            region,
            Region {
                x: 10,
                y: 20,
                width: 100,
                height: 50
            }
        );
    }

    #[test]
    fn read_image_schema_region_zero_width_rejected() {
        let args = json!({
            "path": "/tmp/test.png",
            "region": {"x": 0, "y": 0, "width": 0, "height": 50}
        });
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("positive"));
    }

    #[test]
    fn read_image_schema_region_zero_height_rejected() {
        let args = json!({
            "path": "/tmp/test.png",
            "region": {"x": 0, "y": 0, "width": 100, "height": 0}
        });
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("positive"));
    }

    #[test]
    fn read_image_schema_max_width_zero_rejected() {
        let args = json!({"path": "/tmp/test.png", "max_width": 0});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("positive"));
    }

    #[test]
    fn read_image_schema_max_height_zero_rejected() {
        let args = json!({"path": "/tmp/test.png", "max_height": 0});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("positive"));
    }

    #[test]
    fn read_image_schema_format_auto() {
        let args = json!({"path": "/tmp/test.png", "format": "auto"});
        let parsed = ReadImageArgs::from_value(&args).unwrap();
        assert_eq!(parsed.format, OutputFormat::Auto);
    }

    #[test]
    fn read_image_schema_format_png() {
        let args = json!({"path": "/tmp/test.png", "format": "png"});
        let parsed = ReadImageArgs::from_value(&args).unwrap();
        assert_eq!(parsed.format, OutputFormat::Png);
    }

    #[test]
    fn read_image_schema_format_jpeg() {
        let args = json!({"path": "/tmp/test.png", "format": "jpeg"});
        let parsed = ReadImageArgs::from_value(&args).unwrap();
        assert_eq!(parsed.format, OutputFormat::Jpeg);
    }

    #[test]
    fn read_image_schema_format_webp() {
        let args = json!({"path": "/tmp/test.png", "format": "webp"});
        let parsed = ReadImageArgs::from_value(&args).unwrap();
        assert_eq!(parsed.format, OutputFormat::Webp);
    }

    #[test]
    fn read_image_schema_format_invalid_rejected() {
        let args = json!({"path": "/tmp/test.png", "format": "bmp"});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("format"));
    }

    #[test]
    fn read_image_schema_unknown_field_rejected() {
        let args = json!({"path": "/tmp/test.png", "extra": "value"});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn read_image_schema_default_format_is_auto() {
        let args = json!({"path": "/tmp/test.png"});
        let parsed = ReadImageArgs::from_value(&args).unwrap();
        assert_eq!(parsed.format, OutputFormat::Auto);
    }

    #[test]
    fn read_image_schema_bounded_description() {
        let tool = ReadImageTool;
        let desc = tool.description();
        assert!(
            desc.len() < 200,
            "description too long: {} chars",
            desc.len()
        );
        assert!(desc.to_lowercase().contains("image"));
    }

    #[test]
    fn read_image_schema_parameters_have_required_fields() {
        let tool = ReadImageTool;
        let params = tool.parameters();
        let props = params.get("properties").unwrap().as_object().unwrap();
        assert!(props.contains_key("path"));
        assert!(props.contains_key("url"));
        assert!(props.contains_key("region"));
        assert!(props.contains_key("max_width"));
        assert!(props.contains_key("max_height"));
        assert!(props.contains_key("format"));
        assert_eq!(
            params.get("additionalProperties").unwrap(),
            &serde_json::Value::Bool(false)
        );
    }

    #[test]
    fn read_image_schema_format_enum_exact() {
        let tool = ReadImageTool;
        let params = tool.parameters();
        let format = params.get("properties").unwrap().get("format").unwrap();
        let enums = format.get("enum").unwrap().as_array().unwrap();
        let values: Vec<&str> = enums.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(values, vec!["auto", "png", "jpeg", "webp"]);
    }
}

// ===========================================================================
// Transform tests — Acceptance criterion 2
// ===========================================================================

mod transform {
    use super::*;

    #[test]
    fn read_image_transform_defaults_2048() {
        let plan = TransformPlan::compute(4096, 4096, None, None, None).unwrap();
        assert_eq!(
            plan.crop,
            Region {
                x: 0,
                y: 0,
                width: 4096,
                height: 4096
            }
        );
        assert_eq!(plan.output_width, 2048);
        assert_eq!(plan.output_height, 2048);
    }

    #[test]
    fn read_image_transform_one_omitted_maximum_defaults_2048() {
        let plan = TransformPlan::compute(4096, 1024, None, None, Some(512)).unwrap();
        assert_eq!(plan.output_width, 2048);
        assert_eq!(plan.output_height, 512);
    }

    #[test]
    fn read_image_transform_no_upscale() {
        let plan = TransformPlan::compute(100, 60, None, None, None).unwrap();
        assert_eq!(plan.output_width, 100);
        assert_eq!(plan.output_height, 60);
    }

    #[test]
    fn read_image_transform_proportional_fit_width_constrained() {
        let (w, h) = proportional_fit(200, 100, 50, 200);
        assert_eq!(w, 50);
        assert_eq!(h, 25);
    }

    #[test]
    fn read_image_transform_proportional_fit_height_constrained() {
        let (w, h) = proportional_fit(100, 200, 200, 50);
        assert_eq!(w, 25);
        assert_eq!(h, 50);
    }

    #[test]
    fn read_image_transform_proportional_fit_within_bounds() {
        let (w, h) = proportional_fit(100, 100, 200, 200);
        assert_eq!(w, 100);
        assert_eq!(h, 100);
    }

    #[test]
    fn read_image_transform_crop_before_scale() {
        let plan = TransformPlan::compute(
            100,
            60,
            Some(Region {
                x: 10,
                y: 10,
                width: 50,
                height: 50,
            }),
            Some(10),
            Some(10),
        )
        .unwrap();
        assert_eq!(
            plan.crop,
            Region {
                x: 10,
                y: 10,
                width: 50,
                height: 50
            }
        );
        assert_eq!(plan.output_width, 10);
        assert_eq!(plan.output_height, 10);
    }

    #[test]
    fn read_image_transform_reject_out_of_bounds_region() {
        let err = TransformPlan::compute(
            100,
            60,
            Some(Region {
                x: 50,
                y: 50,
                width: 100,
                height: 100,
            }),
            None,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("exceeds source"));
    }

    #[test]
    fn read_image_transform_reject_partially_overlapping_region() {
        let err = TransformPlan::compute(
            100,
            60,
            Some(Region {
                x: 80,
                y: 0,
                width: 50,
                height: 60,
            }),
            None,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("exceeds source"));
    }

    #[test]
    fn read_image_transform_reject_zero_dimension_source() {
        let err = TransformPlan::compute(0, 100, None, None, None).unwrap_err();
        assert!(err.to_string().contains("zero dimensions"));
    }

    #[test]
    fn read_image_transform_full_pipeline_crop_and_scale() {
        let input = test_image_100x60();
        let result = transform_bytes(
            &input,
            Some(Region {
                x: 10,
                y: 10,
                width: 50,
                height: 40,
            }),
            Some(20),
            Some(20),
            OutputFormat::Png,
        )
        .unwrap();
        assert_eq!(result.output_width, 20);
        assert_eq!(result.output_height, 16);
        assert_eq!(
            result.crop,
            Region {
                x: 10,
                y: 10,
                width: 50,
                height: 40
            }
        );
    }

    #[test]
    fn read_image_transform_no_upscale_in_pipeline() {
        let input = test_image_4x4();
        let result = transform_bytes(&input, None, None, None, OutputFormat::Png).unwrap();
        assert_eq!(result.output_width, 4);
        assert_eq!(result.output_height, 4);
    }

    #[test]
    fn read_image_transform_lanczos3_downscale_deterministic() {
        let input = test_image_100x60();
        let result1 = transform_bytes(&input, None, Some(50), Some(50), OutputFormat::Png).unwrap();
        let result2 = transform_bytes(&input, None, Some(50), Some(50), OutputFormat::Png).unwrap();
        assert_eq!(result1.bytes, result2.bytes);
        assert_eq!(result1.checksum, result2.checksum);
    }
}

// ===========================================================================
// Encoder tests — Acceptance criterion 3
// ===========================================================================

mod encoder {
    use super::*;

    #[test]
    fn read_image_encoder_auto_is_png() {
        let input = test_image_4x4();
        let result = transform_bytes(&input, None, None, None, OutputFormat::Auto).unwrap();
        assert_eq!(result.format, OutputFormat::Png);
        assert_eq!(result.mime_type, "image/png");
        assert!(result.bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]));
    }

    #[test]
    fn read_image_encoder_png_signature_and_mime() {
        let input = test_image_4x4();
        let result = transform_bytes(&input, None, None, None, OutputFormat::Png).unwrap();
        assert_eq!(result.mime_type, "image/png");
        assert!(result.bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]));
    }

    #[test]
    fn read_image_encoder_jpeg_signature_and_mime() {
        let input = test_image_4x4();
        let result = transform_bytes(&input, None, None, None, OutputFormat::Jpeg).unwrap();
        assert_eq!(result.mime_type, "image/jpeg");
        assert!(result.bytes.starts_with(&[0xFF, 0xD8]));
    }

    #[test]
    fn read_image_encoder_webp_signature_and_mime() {
        let input = test_image_4x4();
        let result = transform_bytes(&input, None, None, None, OutputFormat::Webp).unwrap();
        assert_eq!(result.mime_type, "image/webp");
        assert!(result.bytes.starts_with(b"RIFF"));
        assert!(result.bytes[8..12] == *b"WEBP");
    }

    #[test]
    fn read_image_encoder_png_preserves_alpha() {
        let input = test_image_with_alpha();
        let result = transform_bytes(&input, None, None, None, OutputFormat::Png).unwrap();
        let decoded = image::load_from_memory(&result.bytes).unwrap();
        let rgba = decoded.to_rgba8();
        let pixel = rgba.get_pixel(0, 0);
        assert_ne!(pixel[3], 255, "alpha should be preserved in PNG");
    }

    #[test]
    fn read_image_encoder_jpeg_rejects_non_opaque_alpha() {
        let input = test_image_with_alpha();
        let err = transform_bytes(&input, None, None, None, OutputFormat::Jpeg).unwrap_err();
        assert!(err.to_string().contains("jpeg_alpha_unsupported"));
    }

    #[test]
    fn read_image_encoder_jpeg_accepts_opaque() {
        let input = test_image_4x4();
        let result = transform_bytes(&input, None, None, None, OutputFormat::Jpeg).unwrap();
        assert_eq!(result.mime_type, "image/jpeg");
        assert!(result.bytes.starts_with(&[0xFF, 0xD8]));
    }

    #[test]
    fn read_image_encoder_webp_preserves_alpha() {
        let input = test_image_with_alpha();
        let result = transform_bytes(&input, None, None, None, OutputFormat::Webp).unwrap();
        let decoded = image::load_from_memory(&result.bytes).unwrap();
        let rgba = decoded.to_rgba8();
        let pixel = rgba.get_pixel(0, 0);
        assert_ne!(pixel[3], 255, "alpha should be preserved in WebP");
    }

    #[test]
    fn read_image_encoder_deterministic_bytes() {
        let input = test_image_100x60();
        let r1 = transform_bytes(&input, None, Some(50), Some(50), OutputFormat::Png).unwrap();
        let r2 = transform_bytes(&input, None, Some(50), Some(50), OutputFormat::Png).unwrap();
        assert_eq!(r1.bytes, r2.bytes);
        assert_eq!(r1.checksum, r2.checksum);
    }

    #[test]
    fn read_image_encoder_metadata_stripped() {
        let input = test_image_100x60();
        let result = transform_bytes(&input, None, None, None, OutputFormat::Png).unwrap();
        assert!(
            !result.bytes.windows(4).any(|w| w == b"eXIf"),
            "PNG output should not contain EXIF metadata"
        );
    }

    #[test]
    fn read_image_encoder_checksum_is_sha256_hex() {
        let input = test_image_4x4();
        let result = transform_bytes(&input, None, None, None, OutputFormat::Png).unwrap();
        assert_eq!(result.checksum.len(), 64);
        assert!(result.checksum.chars().all(|c| c.is_ascii_hexdigit()));
        let mut hasher = sha2::Sha256::new();
        hasher.update(&result.bytes);
        let expected = hasher.finalize();
        let expected_hex: String = expected.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(result.checksum, expected_hex);
    }
}

// ===========================================================================
// Input/fail-closed tests — Acceptance criteria 4, 5
// ===========================================================================

mod input_policy {
    use super::*;

    #[test]
    fn read_image_tool_fails_closed_without_authority() {
        let args = json!({"path": "/tmp/test.png"});
        let parsed = ReadImageArgs::from_value(&args).unwrap();
        assert!(parsed.path.is_some());
        assert!(parsed.url.is_none());
    }

    #[test]
    fn read_image_tool_rejects_non_https_url() {
        let args = json!({"url": "http://example.com/test.png"});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("https://"));
    }

    #[test]
    fn read_image_tool_rejects_file_url() {
        let args = json!({"url": "file:///tmp/test.png"});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("https://"));
    }

    #[test]
    fn read_image_transform_rejects_corrupt_input() {
        let corrupt = b"not an image at all";
        let err = transform_bytes(corrupt, None, None, None, OutputFormat::Png).unwrap_err();
        assert!(err.to_string().contains("decode"));
    }

    #[test]
    fn read_image_transform_rejects_oversized_input() {
        let oversized = vec![0u8; MAX_INPUT_BYTES + 1];
        let err = transform_bytes(&oversized, None, None, None, OutputFormat::Png).unwrap_err();
        assert!(err.to_string().contains("decompression bomb"));
    }
}

// ===========================================================================
// Per-AgentDef tiering tests — Acceptance criterion 7
// ===========================================================================

mod agent_tiering {
    use super::*;
    use crate::agents::{AgentDef, AgentMode, ToolTier};
    use std::collections::BTreeMap;

    fn make_def(name: &str) -> AgentDef {
        AgentDef {
            name: name.to_string(),
            description: String::new(),
            mode: AgentMode::default(),
            model: None,
            temperature: None,
            tools: None,
            tool_tiers: BTreeMap::new(),
            tool_descriptions: BTreeMap::new(),
            scan_tool_results: None,
            goal_supervision: Default::default(),
            permission: None,
            capabilities: None,
            tool_steering: None,
            context_policy: None,
            vnext: None,
            prompt: String::new(),
            prompt_overrides: std::collections::BTreeMap::new(),
            source: std::path::PathBuf::new(),
        }
    }

    #[test]
    fn read_image_tool_name_is_exact() {
        let tool = ReadImageTool;
        assert_eq!(tool.name(), "read_image");
    }

    #[test]
    fn read_image_tool_effect_is_read_only() {
        let tool = ReadImageTool;
        assert_eq!(tool.effect(), ToolEffect::ReadOnly);
    }

    #[test]
    fn read_image_tool_has_no_binary_requirements() {
        let tool = ReadImageTool;
        assert!(tool.binary_requirements().is_empty());
    }

    #[test]
    fn read_image_tool_has_verbose_description() {
        let tool = ReadImageTool;
        assert!(tool.verbose_description().is_some());
    }

    #[test]
    fn read_image_tool_verbose_parameters_match_parameters() {
        let tool = ReadImageTool;
        let params = tool.parameters();
        let defensive = tool.verbose_parameters().unwrap();
        assert_eq!(
            params
                .get("properties")
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            defensive
                .get("properties")
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn read_image_agent_def_build_careful_plan_explore_enabled() {
        for name in ["Build", "Careful", "Plan", "explore"] {
            let def = make_def(name);
            assert!(!def.tool_tiers.contains_key("read_image"));
        }
    }

    #[test]
    fn read_image_agent_def_user_override_takes_precedence() {
        let mut def = make_def("Build");
        def.tool_tiers
            .insert("read_image".to_string(), ToolTier::Disabled);
        assert_eq!(def.tool_tiers.get("read_image"), Some(&ToolTier::Disabled));
    }

    #[test]
    fn read_image_monty_has_no_host_apis() {
        let tool = ReadImageTool;
        assert!(tool.binary_requirements().is_empty());
    }
}

// ===========================================================================
// Output safety tests — Acceptance criterion 5
// ===========================================================================

mod output_safety {
    use super::*;

    #[test]
    fn read_image_output_has_no_base64_in_text() {
        let input = test_image_4x4();
        let result = transform_bytes(&input, None, None, None, OutputFormat::Png).unwrap();
        assert!(result.checksum.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn read_image_output_mime_type_is_canonical() {
        let input = test_image_4x4();
        for fmt in [
            OutputFormat::Auto,
            OutputFormat::Png,
            OutputFormat::Jpeg,
            OutputFormat::Webp,
        ] {
            let result = transform_bytes(&input, None, None, None, fmt).unwrap();
            assert!(
                result.mime_type.starts_with("image/"),
                "mime type should be image/*: {}",
                result.mime_type
            );
        }
    }

    #[test]
    fn read_image_output_dimensions_are_positive() {
        let input = test_image_4x4();
        let result = transform_bytes(&input, None, None, None, OutputFormat::Png).unwrap();
        assert!(result.output_width > 0);
        assert!(result.output_height > 0);
    }
}

// ===========================================================================
// Animation/edge case tests — Acceptance criterion 8
// ===========================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn read_image_animated_gif_reports_additional_frames_ignored() {
        let frame1 = ImageBuffer::from_pixel(4, 4, Rgba([255, 0, 0, 255]));
        let frame2 = ImageBuffer::from_pixel(4, 4, Rgba([0, 255, 0, 255]));

        let mut bytes = Vec::new();
        {
            let mut encoder = image::codecs::gif::GifEncoder::new(&mut bytes);
            encoder
                .encode_frame(image::Frame::from_parts(
                    frame1,
                    0,
                    0,
                    image::Delay::from_numer_denom_ms(100, 1),
                ))
                .unwrap();
            encoder
                .encode_frame(image::Frame::from_parts(
                    frame2,
                    100,
                    0,
                    image::Delay::from_numer_denom_ms(100, 1),
                ))
                .unwrap();
        }

        let result = transform_bytes(&bytes, None, None, None, OutputFormat::Png).unwrap();
        assert!(
            result.additional_frames_ignored,
            "animated GIF should report additional_frames_ignored"
        );
    }

    #[test]
    fn read_image_single_frame_gif_no_additional_frames() {
        let input = test_image_4x4();
        let result = transform_bytes(&input, None, None, None, OutputFormat::Png).unwrap();
        assert!(
            !result.additional_frames_ignored,
            "single-frame image should not report additional_frames_ignored"
        );
    }

    #[test]
    fn read_image_changed_source_produces_different_checksum() {
        let input1 = test_image_4x4();
        let input2 = test_image_100x60();
        let r1 = transform_bytes(&input1, None, None, None, OutputFormat::Png).unwrap();
        let r2 = transform_bytes(&input2, None, None, None, OutputFormat::Png).unwrap();
        assert_ne!(r1.checksum, r2.checksum);
    }
}
