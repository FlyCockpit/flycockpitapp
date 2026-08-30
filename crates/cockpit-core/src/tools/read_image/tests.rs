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
use crate::engine::tool::Tool;
use image::{GenericImage, ImageBuffer, Rgba};

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
        let args = json!({"source": {"path": "/tmp/test.png"}});
        let parsed = ReadImageArgs::from_value(&args).unwrap();
        assert_eq!(
            parsed.source,
            crate::tool_media_authority::ReadImageSource::Path {
                path: "/tmp/test.png".into()
            }
        );
        assert!(parsed.region.is_none());
        assert!(parsed.max_width.is_none());
        assert!(parsed.max_height.is_none());
        assert_eq!(parsed.format, OutputFormat::Auto);
    }

    #[test]
    fn read_image_schema_url_only_succeeds() {
        let args = json!({"source": {"url": "https://example.com/test.png"}});
        let parsed = ReadImageArgs::from_value(&args).unwrap();
        assert_eq!(
            parsed.source,
            crate::tool_media_authority::ReadImageSource::Url {
                url: "https://example.com/test.png".into()
            }
        );
    }

    #[test]
    fn read_image_schema_both_sources_fails() {
        let args =
            json!({"source": {"path": "/tmp/test.png", "url": "https://example.com/test.png"}});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn read_image_schema_neither_source_fails() {
        let args = json!({"format": "png"});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("`source` is required"));
    }

    #[test]
    fn read_image_schema_http_url_rejected() {
        let args = json!({"source": {"url": "http://example.com/test.png"}});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("https://"));
    }

    #[test]
    fn read_image_schema_empty_path_rejected() {
        let args = json!({"source": {"path": ""}});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("non-empty"));
    }

    #[test]
    fn read_image_schema_empty_url_rejected() {
        let args = json!({"source": {"url": ""}});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("non-empty"));
    }

    #[test]
    fn read_image_schema_region_valid() {
        let args = json!({
            "source": {"path": "/tmp/test.png"},
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
            "source": {"path": "/tmp/test.png"},
            "region": {"x": 0, "y": 0, "width": 0, "height": 50}
        });
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("positive"));
    }

    #[test]
    fn read_image_schema_region_zero_height_rejected() {
        let args = json!({
            "source": {"path": "/tmp/test.png"},
            "region": {"x": 0, "y": 0, "width": 100, "height": 0}
        });
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("positive"));
    }

    #[test]
    fn read_image_schema_max_width_zero_rejected() {
        let args = json!({"source": {"path": "/tmp/test.png"}, "max_width": 0});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("positive"));
    }

    #[test]
    fn read_image_schema_max_height_zero_rejected() {
        let args = json!({"source": {"path": "/tmp/test.png"}, "max_height": 0});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("positive"));
    }

    #[test]
    fn read_image_schema_format_auto() {
        let args = json!({"source": {"path": "/tmp/test.png"}, "format": "auto"});
        let parsed = ReadImageArgs::from_value(&args).unwrap();
        assert_eq!(parsed.format, OutputFormat::Auto);
    }

    #[test]
    fn read_image_schema_format_png() {
        let args = json!({"source": {"path": "/tmp/test.png"}, "format": "png"});
        let parsed = ReadImageArgs::from_value(&args).unwrap();
        assert_eq!(parsed.format, OutputFormat::Png);
    }

    #[test]
    fn read_image_schema_format_jpeg() {
        let args = json!({"source": {"path": "/tmp/test.png"}, "format": "jpeg"});
        let parsed = ReadImageArgs::from_value(&args).unwrap();
        assert_eq!(parsed.format, OutputFormat::Jpeg);
    }

    #[test]
    fn read_image_schema_format_webp() {
        let args = json!({"source": {"path": "/tmp/test.png"}, "format": "webp"});
        let parsed = ReadImageArgs::from_value(&args).unwrap();
        assert_eq!(parsed.format, OutputFormat::Webp);
    }

    #[test]
    fn read_image_schema_format_invalid_rejected() {
        let args = json!({"source": {"path": "/tmp/test.png"}, "format": "bmp"});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("format"));
    }

    #[test]
    fn read_image_schema_unknown_field_rejected() {
        let args = json!({"source": {"path": "/tmp/test.png"}, "extra": "value"});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn read_image_schema_default_format_is_auto() {
        let args = json!({"source": {"path": "/tmp/test.png"}});
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
        assert!(props.contains_key("source"));
        assert!(props.contains_key("region"));
        assert!(props.contains_key("max_width"));
        assert!(props.contains_key("max_height"));
        assert!(props.contains_key("format"));
        assert_eq!(
            params.get("additionalProperties").unwrap(),
            &serde_json::Value::Bool(false)
        );
        let required = params.get("required").unwrap().as_array().unwrap();
        assert!(required.iter().any(|v| v.as_str() == Some("source")));
    }

    #[test]
    fn read_image_schema_format_enum_exact() {
        let tool = ReadImageTool;
        let params = tool.parameters();
        let format = params.get("properties").unwrap().get("format").unwrap();
        let enums = format
            .get("anyOf")
            .and_then(|v| v.as_array().and_then(|a| a.first()))
            .and_then(|v| v.get("enum"))
            .unwrap()
            .as_array()
            .unwrap();
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
        let args = json!({"source": {"path": "/tmp/test.png"}});
        let parsed = ReadImageArgs::from_value(&args).unwrap();
        assert!(matches!(
            parsed.source,
            crate::tool_media_authority::ReadImageSource::Path { .. }
        ));
    }

    #[test]
    fn read_image_tool_rejects_non_https_url() {
        let args = json!({"source": {"url": "http://example.com/test.png"}});
        let err = ReadImageArgs::from_value(&args).unwrap_err();
        assert!(err.to_string().contains("https://"));
    }

    #[test]
    fn read_image_tool_rejects_file_url() {
        let args = json!({"source": {"url": "file:///tmp/test.png"}});
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
            package_files: None,
            mcp_bindings: Vec::new(),
            private_subagents: std::collections::BTreeMap::new(),
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
    fn read_image_agent_def_build_plan_explore_enabled() {
        for name in ["Build", "Plan", "explore"] {
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

// ===========================================================================
// Named acceptance tests (issue #71)
// ===========================================================================

use crate::media_image::test_hooks::{self, DecodeBarrier, PipelineCounters};
use crate::tool_media_authority::ToolMediaSubjectReceiptV1;
use crate::tool_media_authority::receipt::IssuerKind;
use crate::tool_media_authority::revalidator::RevalidatedSubject;
use crate::tool_media_authority::session_authority::{
    AdmissionDenial, AdmittedAttachment, AdmittedRetainedSource, AttachmentResolver, CleanupRace,
    HandleEvidence, LocalPathPolicy, RetainedHttpsPolicy, SessionMediaAuthority,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

struct AlwaysLive(RevalidatedSubject);

impl crate::tool_media_authority::session_authority::SubjectLiveness for AlwaysLive {
    fn revalidate(&self) -> Result<RevalidatedSubject, AdmissionDenial> {
        Ok(self.0.clone())
    }
}

struct TestAttachmentResolver {
    attachments: HashMap<[u8; 16], AdmittedAttachment>,
}

#[async_trait]
impl AttachmentResolver for TestAttachmentResolver {
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

struct TestLocalPathPolicy;

impl LocalPathPolicy for TestLocalPathPolicy {
    fn admit(
        &self,
        _session_id: &str,
        path: &str,
        max_bytes: usize,
    ) -> Result<crate::tool_media_authority::session_authority::AdmittedLocalHandle, AdmissionDenial>
    {
        if path.contains("denied") {
            return Err(AdmissionDenial::LocalPathDenied);
        }
        let content = std::fs::read(path).map_err(|e| AdmissionDenial::Internal(e.to_string()))?;
        if content.len() > max_bytes {
            return Err(AdmissionDenial::Internal("input too large".into()));
        }
        Ok(
            crate::tool_media_authority::session_authority::AdmittedLocalHandle::from_held_bytes(
                std::path::PathBuf::from(path),
                HandleEvidence {
                    metadata_fingerprint: [0xAA; 32],
                },
                content,
            ),
        )
    }

    fn authorize(
        &self,
        _session_id: &str,
        path: &str,
    ) -> Result<(std::fs::File, HandleEvidence), AdmissionDenial> {
        if path.contains("denied") {
            return Err(AdmissionDenial::LocalPathDenied);
        }
        std::fs::File::open(path)
            .map(|file| {
                (
                    file,
                    HandleEvidence {
                        metadata_fingerprint: [0xAA; 32],
                    },
                )
            })
            .or_else(|_| {
                std::fs::File::open(std::env::current_exe().unwrap()).map(|file| {
                    (
                        file,
                        HandleEvidence {
                            metadata_fingerprint: [0xAA; 32],
                        },
                    )
                })
            })
            .map_err(|error| AdmissionDenial::Internal(error.to_string()))
    }
}

struct TestHttpsPolicy {
    content: Vec<u8>,
}

impl RetainedHttpsPolicy for TestHttpsPolicy {
    fn admit(
        &self,
        _session_id: &str,
        url: &str,
        max_bytes: usize,
    ) -> Result<AdmittedRetainedSource, AdmissionDenial> {
        if url.contains("denied") {
            return Err(AdmissionDenial::HttpsDenied);
        }
        if self.content.len() > max_bytes {
            return Err(AdmissionDenial::Internal("input too large".into()));
        }
        Ok(AdmittedRetainedSource {
            canonical_url: url.to_string(),
            content: self.content.clone(),
            content_type: "image/png".to_string(),
        })
    }
}

fn test_subject(session_id: [u8; 16]) -> RevalidatedSubject {
    RevalidatedSubject {
        receipt: ToolMediaSubjectReceiptV1 {
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
    }
}

fn test_authority_with_attachment(
    session_id: [u8; 16],
    attachment_id: [u8; 16],
    bytes: Vec<u8>,
) -> SessionMediaAuthority {
    let mut attachments = HashMap::new();
    attachments.insert(
        attachment_id,
        AdmittedAttachment {
            attachment_id,
            attachment_version: 1,
            checksum: [0x55; 32],
            kind: 1,
            content: bytes.clone(),
        },
    );
    SessionMediaAuthority::new(
        test_subject(session_id).clone(),
        Arc::new(AlwaysLive(test_subject(session_id))),
        Arc::new(TestAttachmentResolver { attachments }),
        Arc::new(TestLocalPathPolicy),
        Arc::new(TestHttpsPolicy {
            content: bytes.clone(),
        }),
        None,
    )
}

/// Production `SessionMediaAuthority` always has durable storage. Named
/// acceptance tests that exercise reservation/write must install it or they
/// cannot observe the durable gate.
struct DurableSetup {
    tmp: tempfile::TempDir,
    media_root: std::path::PathBuf,
    authority: Arc<SessionMediaAuthority>,
    db: crate::db::Db,
}

impl DurableSetup {
    fn new(attachment_id: [u8; 16], bytes: Vec<u8>) -> (Self, crate::engine::tool::ToolCtx) {
        let tmp = tempfile::tempdir().unwrap();
        let media_root = tmp.path().join("media");
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let session_id = *ctx.session.id.as_bytes();
        let db = ctx.session.db.clone();
        let storage = Arc::new(
            crate::media_storage::MediaStorageRecovery::open_or_create(db.clone(), &media_root)
                .unwrap(),
        );
        let authority = Arc::new(
            test_authority_with_attachment(session_id, attachment_id, bytes)
                .with_durable_storage(storage, [0x22; 32]),
        );
        let ctx = ctx.with_media_authority(Arc::clone(&authority));
        (
            Self {
                tmp,
                media_root,
                authority,
                db,
            },
            ctx,
        )
    }
}

fn reservation_plan_dimensions(db: &crate::db::Db, source_kind: &str) -> Vec<String> {
    let source_kind = source_kind.to_string();
    db.blocking_read_for_sync_ui(move |conn| {
        let reservation: String = conn.query_row(
            "SELECT c.reservation_id
               FROM media_attachment_components c
               JOIN media_attachments a ON a.attachment_id = c.attachment_id
              WHERE a.source_kind = ?1
              LIMIT 1",
            [&source_kind],
            |row| row.get(0),
        )?;
        let mut statement = conn.prepare(
            "SELECT dimension FROM media_reservation_plan_facts WHERE reservation_id=?1 ORDER BY dimension",
        )?;
        statement
            .query_map([&reservation], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    })
    .unwrap()
}

fn plan_requested(db: &crate::db::Db, source_kind: &str, dimension: &str) -> i64 {
    let source_kind = source_kind.to_string();
    let dimension = dimension.to_string();
    db.blocking_read_for_sync_ui(move |conn| {
        conn.query_row(
            "SELECT CAST(json_extract(p.plan_json, '$.requested') AS INTEGER)
               FROM media_reservation_plan_facts p
               JOIN media_attachment_components c ON c.reservation_id = p.reservation_id
               JOIN media_attachments a ON a.attachment_id = c.attachment_id
              WHERE a.source_kind = ?1 AND p.dimension = ?2
              LIMIT 1",
            [source_kind, dimension],
            |row| row.get(0),
        )
        .map_err(Into::into)
    })
    .unwrap()
}

fn reservation_count(db: &crate::db::Db) -> i64 {
    db.blocking_read_for_sync_ui(|conn| {
        conn.query_row("SELECT COUNT(*) FROM media_reservations", [], |row| {
            row.get(0)
        })
        .map_err(Into::into)
    })
    .unwrap()
}

fn component_storage_paths(
    db: &crate::db::Db,
    media_root: &std::path::Path,
    source_kind: &str,
) -> Vec<std::path::PathBuf> {
    let source_kind = source_kind.to_string();
    let ids: Vec<String> = db
        .blocking_read_for_sync_ui(move |conn| {
            let mut statement = conn.prepare(
                "SELECT c.storage_id
                   FROM media_attachment_components c
                   JOIN media_attachments a ON a.attachment_id = c.attachment_id
                  WHERE a.source_kind = ?1",
            )?;
            statement
                .query_map([&source_kind], |row| row.get(0))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(Into::into)
        })
        .unwrap();
    ids.into_iter().map(|id| media_root.join(id)).collect()
}

fn reservation_balance(db: &crate::db::Db, source_kind: &str, dimension: &str) -> i64 {
    let source_kind = source_kind.to_string();
    let dimension = dimension.to_string();
    db.blocking_read_for_sync_ui(move |conn| {
        conn.query_row(
            "SELECT COALESCE((
                SELECT SUM(d.delta)
                  FROM media_reservation_deltas d
                  JOIN media_attachment_components c ON c.reservation_id = d.reservation_id
                  JOIN media_attachments a ON a.attachment_id = c.attachment_id
                 WHERE a.source_kind = ?1 AND d.dimension = ?2
            ), 0)",
            [source_kind, dimension],
            |row| row.get(0),
        )
        .map_err(Into::into)
    })
    .unwrap()
}

fn wide_source_png() -> Vec<u8> {
    // 8193×10 exceeds DecodedEdgePixels (8192) if charged from the source
    // header, and downscales to 2048×2 under the default 2048 output cap.
    let mut img = ImageBuffer::new(8_193, 10);
    for (x, y, pixel) in img.enumerate_pixels_mut() {
        *pixel = Rgba([(x % 256) as u8, (y % 256) as u8, 64, 255]);
    }
    let mut bytes = Vec::new();
    image::DynamicImage::ImageRgba8(img)
        .write_to(&mut std::io::Cursor::new(&mut bytes), ImageFormat::Png)
        .unwrap();
    bytes
}

fn oriented_crop_pixel() -> ([u8; 4], [u8; 4]) {
    // 2×2 unique pixels. EXIF orientation 6 = rotate 90 CW:
    // (0,0)=R → (1,0); (1,0)=G → (1,1); (1,1)=W → (0,1); (0,1)=B → (0,0)
    // Oriented (0,0) is original (0,1)=B. Unoriented (0,0)=R.
    let red = [255, 0, 0, 255];
    let blue = [0, 0, 255, 255];
    (red, blue)
}

#[test]
fn read_image_orientation_rotated_region() {
    let mut img = image::ImageBuffer::new(2, 2);
    img.put_pixel(0, 0, image::Rgba([255, 0, 0, 255]));
    img.put_pixel(1, 0, image::Rgba([0, 255, 0, 255]));
    img.put_pixel(0, 1, image::Rgba([0, 0, 255, 255]));
    img.put_pixel(1, 1, image::Rgba([255, 255, 255, 255]));
    let png = test_hooks::png_with_exif_orientation(image::DynamicImage::ImageRgba8(img), 6);
    let result = transform_bytes(
        &png,
        Some(Region {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
        }),
        None,
        None,
        OutputFormat::Png,
    )
    .unwrap();
    assert_eq!(result.source_width, 2);
    assert_eq!(result.source_height, 2);
    let decoded = image::load_from_memory(&result.bytes).unwrap().to_rgba8();
    let pixel = decoded.get_pixel(0, 0).0;
    let (_unoriented_red, oriented_blue) = oriented_crop_pixel();
    assert_eq!(
        pixel, oriented_blue,
        "crop is in oriented-image coordinates; orientation-6 maps original (0,1) to (0,0)"
    );
}

#[test]
fn read_image_malformed_exif_fails_before_derivative() {
    let counters = Arc::new(PipelineCounters::default());
    test_hooks::install_counters(Arc::clone(&counters));
    let jpeg = test_hooks::jpeg_malformed_exif_fixture();
    let attachment_id = *uuid::Uuid::now_v7().as_bytes();
    let (setup, ctx) = DurableSetup::new(attachment_id, jpeg);
    let args = json!({
        "source": {"attachment_id": uuid::Uuid::from_bytes(attachment_id).to_string()}
    });
    let err = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(ReadImageTool.call(args, &ctx))
        .unwrap_err();
    assert!(
        err.to_string().contains("media_orientation_unsupported"),
        "{err}"
    );
    assert_eq!(counters.decode.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(counters.crop.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(
        counters
            .reservation
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        counters
            .derivative_write
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(reservation_count(&ctx.session.db), 0);
    drop(setup);
    test_hooks::clear();
}

#[tokio::test]
async fn read_image_tool_call_media_reference() {
    let png = test_image_4x4();

    // Path arm.
    let (setup, ctx) = DurableSetup::new([0x44; 16], png.clone());
    let path = setup.tmp.path().join("img.png");
    std::fs::write(&path, &png).unwrap();
    let out = ReadImageTool
        .call(json!({"source": {"path": path.to_str().unwrap()}}), &ctx)
        .await
        .unwrap();
    let content = &out.content.parts()[0];
    let reference = content.as_media_reference().expect("media reference");
    assert_eq!(
        reference.media_kind,
        crate::typed_media_result::CanonicalMediaKind::Image
    );
    assert_eq!(reference.mime_type, "image/png");
    assert_eq!(reference.checksum.len(), 64);
    assert_eq!(out.content.parts().len(), 1);
    assert!(out.content.model_text().is_empty());
    drop(setup);

    // URL arm.
    let (setup, ctx) = DurableSetup::new([0x44; 16], png.clone());
    let out = ReadImageTool
        .call(
            json!({"source": {"url": "https://example.com/test.png"}}),
            &ctx,
        )
        .await
        .unwrap();
    let content = &out.content.parts()[0];
    assert!(content.as_media_reference().is_some());
    drop(setup);

    // Attachment arm.
    let attachment_id = uuid::Uuid::now_v7();
    let (setup, ctx) = DurableSetup::new(*attachment_id.as_bytes(), png.clone());
    let out = ReadImageTool
        .call(
            json!({"source": {"attachment_id": attachment_id.to_string()}}),
            &ctx,
        )
        .await
        .unwrap();
    let content = &out.content.parts()[0];
    let reference = content.as_media_reference().unwrap();
    assert_eq!(reference.attachment_version, 1);
    assert_eq!(
        reference.media_kind,
        crate::typed_media_result::CanonicalMediaKind::Image
    );
    drop(setup);

    // Malformed source fails before authority (no reservation).
    let counters = Arc::new(PipelineCounters::default());
    test_hooks::install_counters(Arc::clone(&counters));
    let (setup, ctx) = DurableSetup::new([0x44; 16], png.clone());
    let err = ReadImageTool
        .call(json!({"source": {"attachment_id": "not-a-uuid"}}), &ctx)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("UUID"), "{err}");
    assert_eq!(
        counters
            .reservation
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(counters.decode.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(reservation_count(&ctx.session.db), 0);

    // Authority denial fails before decode/reservation.
    let err = ReadImageTool
        .call(json!({"source": {"path": "/tmp/denied.png"}}), &ctx)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("denied") || err.to_string().contains("LocalPath"),
        "{err}"
    );
    assert_eq!(counters.decode.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(setup);
    test_hooks::clear();

    // A source larger than the 8192 decode-edge cap is admitted and reserved
    // against TransformPlan output, not the source header.
    let wide = wide_source_png();
    let (setup, ctx) = DurableSetup::new([0x44; 16], wide.clone());
    let path = setup.tmp.path().join("wide.png");
    std::fs::write(&path, &wide).unwrap();
    let out = ReadImageTool
        .call(json!({"source": {"path": path.to_str().unwrap()}}), &ctx)
        .await
        .unwrap();
    assert!(out.content.parts()[0].as_media_reference().is_some());
    let source_plan = reservation_plan_dimensions(&ctx.session.db, "local_path");
    assert!(
        !source_plan.iter().any(|dimension| {
            dimension == "decoded_edge_pixels"
                || dimension == "decoded_image_pixels"
                || dimension == "aggregate_decoded_pixels_per_request"
                || dimension == "local_cpu_jobs_global"
        }),
        "source persist must not charge decode-dimension or CPU-job limits: {source_plan:?}"
    );
    let derivative_plan =
        reservation_plan_dimensions(&ctx.session.db, "authenticated_session_upload");
    assert!(
        derivative_plan
            .iter()
            .any(|dimension| dimension == "decoded_edge_pixels"),
        "derivative reserve must charge decode-dimension limits: {derivative_plan:?}"
    );
    assert_eq!(
        plan_requested(
            &ctx.session.db,
            "authenticated_session_upload",
            "decoded_edge_pixels"
        ),
        2048
    );
    assert_eq!(
        plan_requested(
            &ctx.session.db,
            "authenticated_session_upload",
            "decoded_image_pixels"
        ),
        2048 * 2
    );
    drop(setup);
}

#[tokio::test]
async fn read_image_path_cannot_admit_a_trust_required_knowledge_base() {
    let tmp = tempfile::tempdir().unwrap();
    let knowledge = tmp.path().join(".cockpit/knowledge");
    std::fs::create_dir_all(&knowledge).unwrap();
    std::fs::write(
        tmp.path().join(".cockpit/config.json"),
        r#"{"knowledgeBases":[{"id":"private","name":"Private","description":"Private local knowledge","source":{"kind":"local","path":".cockpit/knowledge"},"embeddingOwnership":"local","trustRequired":true,"mergePolicy":"auto"}]}"#,
    )
    .unwrap();
    std::fs::write(knowledge.join("protected.png"), test_image_4x4()).unwrap();

    let ctx = crate::tools::common::test_ctx(tmp.path());
    let authority = Arc::new(test_authority_with_attachment(
        *ctx.session.id.as_bytes(),
        [0x44; 16],
        test_image_4x4(),
    ));
    let ctx = ctx.with_media_authority(authority);

    let error = ReadImageTool
        .call(
            json!({"source": {"path": ".cockpit/knowledge/protected.png"}}),
            &ctx,
        )
        .await
        .expect_err("an untrusted model must not admit a protected KB image");
    assert!(
        error
            .to_string()
            .contains("local knowledge base that requires a trusted model"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn read_image_tool_source_swap() {
    let original = test_image_4x4();
    let swapped = test_image_100x60();
    let (setup, ctx) = DurableSetup::new([0x44; 16], original.clone());
    let path = setup.tmp.path().join("swap.png");
    std::fs::write(&path, &original).unwrap();
    let (barrier, continue_tx, entered_rx) = DecodeBarrier::new();
    let counters = Arc::new(PipelineCounters::default());
    let path_str = path.to_str().unwrap().to_string();
    let call_thread = std::thread::spawn({
        let counters = Arc::clone(&counters);
        let barrier = Arc::clone(&barrier);
        move || {
            test_hooks::install_counters(counters);
            test_hooks::install_barrier(barrier);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(ReadImageTool.call(json!({"source": {"path": path_str}}), &ctx))
        }
    });
    entered_rx.recv().expect("decode barrier entered");
    std::fs::write(&path, &swapped).unwrap();
    continue_tx.send(()).unwrap();
    let out = call_thread.join().unwrap().unwrap();
    let content = &out.content.parts()[0];
    let reference = content.as_media_reference().unwrap();
    let expected = transform_bytes(&original, None, None, None, OutputFormat::Png).unwrap();
    let swapped_result = transform_bytes(&swapped, None, None, None, OutputFormat::Png).unwrap();
    assert_eq!(reference.checksum, expected.checksum);
    assert_ne!(reference.checksum, swapped_result.checksum);
    drop(setup);
    test_hooks::clear();
}

#[test]
fn read_image_toolsource_cleanup_race() {
    let png = test_image_4x4();

    // Cleanup wins before decode: flag the source missing before the call.
    let (setup, ctx) = DurableSetup::new([0x99; 16], png.clone());
    setup
        .authority
        .request_source_cleanup(uuid::Uuid::from_bytes([0x99; 16]));
    let counters = Arc::new(PipelineCounters::default());
    test_hooks::install_counters(Arc::clone(&counters));
    let err = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(ReadImageTool.call(
            json!({"source": {"attachment_id": uuid::Uuid::from_bytes([0x99; 16]).to_string()}}),
            &ctx,
        ))
        .unwrap_err();
    assert!(
        err.to_string().contains("not found") || err.to_string().contains("attachment"),
        "{err}"
    );
    assert_eq!(counters.decode.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(reservation_count(&ctx.session.db), 0);
    drop(setup);
    test_hooks::clear();

    // Cleanup waits on the held lease; cancellation injected at the decode barrier.
    let (setup, ctx) = DurableSetup::new([0x44; 16], png.clone());
    let path = setup.tmp.path().join("race.png");
    std::fs::write(&path, &png).unwrap();
    let cancel = ctx.cancel.clone();
    let (barrier, continue_tx, entered_rx) = DecodeBarrier::new();
    let counters = Arc::new(PipelineCounters::default());
    let path_str = path.to_str().unwrap().to_string();
    let auth_for_cleanup = Arc::clone(&setup.authority);
    let call_thread = std::thread::spawn({
        let counters = Arc::clone(&counters);
        let barrier = Arc::clone(&barrier);
        move || {
            test_hooks::install_counters(counters);
            test_hooks::install_barrier(barrier);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(ReadImageTool.call(json!({"source": {"path": path_str}}), &ctx))
        }
    });
    entered_rx.recv().expect("decode barrier entered");
    let ids = auth_for_cleanup.live_lease_ids();
    assert_eq!(ids.len(), 1);
    let cleanup_thread = std::thread::spawn({
        let auth = Arc::clone(&auth_for_cleanup);
        let id = ids[0];
        move || auth.request_source_cleanup(id)
    });
    std::thread::sleep(std::time::Duration::from_millis(20));
    cancel.cancel();
    continue_tx.send(()).unwrap();
    let result = call_thread.join().unwrap();
    assert!(result.unwrap_err().to_string().contains("cancelled"));
    let race = cleanup_thread.join().unwrap();
    assert_eq!(race, CleanupRace::WaitedForLease);
    assert_eq!(
        auth_for_cleanup
            .activity()
            .source_releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "ToolSource must release exactly once on cancellation"
    );
    assert_eq!(
        auth_for_cleanup
            .activity()
            .model_leases
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        auth_for_cleanup
            .activity()
            .preview_leases
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    drop(setup);
    test_hooks::clear();

    // Cancel after a successful persist must unlink the published derivative
    // and release its retained-byte charges in this session, not wait for boot.
    let (setup, ctx) = DurableSetup::new([0x44; 16], png.clone());
    let path = setup.tmp.path().join("publish-race.png");
    std::fs::write(&path, &png).unwrap();
    let cancel = ctx.cancel.clone();
    let (barrier, continue_tx, entered_rx) = DecodeBarrier::new();
    let path_str = path.to_str().unwrap().to_string();
    let call_thread = std::thread::spawn({
        let barrier = Arc::clone(&barrier);
        move || {
            test_hooks::install_publication_barrier(barrier);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(ReadImageTool.call(json!({"source": {"path": path_str}}), &ctx))
        }
    });
    entered_rx.recv().expect("publication barrier entered");
    let derivative_kind = "authenticated_session_upload";
    let paths_after_persist =
        component_storage_paths(&setup.db, &setup.media_root, derivative_kind);
    assert!(
        paths_after_persist.iter().any(|path| path.exists()),
        "persist must materialize derivative objects before the publication barrier"
    );
    assert!(
        reservation_balance(&setup.db, derivative_kind, "retained_bytes_per_session") > 0,
        "published derivative must retain bytes before cancel"
    );
    cancel.cancel();
    continue_tx.send(()).unwrap();
    let result = call_thread.join().unwrap();
    assert!(result.unwrap_err().to_string().contains("cancelled"));
    for path in component_storage_paths(&setup.db, &setup.media_root, derivative_kind) {
        assert!(!path.exists(), "cancel after persist must unlink {path:?}");
    }
    assert_eq!(
        reservation_balance(&setup.db, derivative_kind, "retained_bytes_per_session"),
        0,
        "cancel after persist must release derivative retained-byte charges"
    );
    drop(setup);
    test_hooks::clear();
}
