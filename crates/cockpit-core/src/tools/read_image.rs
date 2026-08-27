//! `read_image` — bounded lossless-default image transformation tool.
//!
//! Ingests through [`SessionMediaAuthority::admit_read_image_source`], performs
//! deterministic EXIF orientation → crop → proportional Lanczos3 downscale →
//! exact encoding, and returns an opaque [`MediaReference`] without claiming
//! lossy JPEG is lossless.
//!
//! ## Schema
//!
//! `read_image({source, region?, max_width?, max_height?, format?})` with
//! required closed `source` of exactly one of `{attachment_id}`, `{path}`,
//! or `{url}`. Optional fields are present-and-nullable. Region is
//! oriented-image pixel `{x,y,width,height}`. Omitted maxima default to
//! 2,048×2,048; one omitted maximum defaults to 2,048 for that axis. Crop
//! first, proportional Lanczos3 downscale second, never upscale.
//!
//! `format` is `auto|png|jpeg|webp`, default `auto`. `auto` always produces
//! lossless PNG. Encoders are exact:
//!
//! - PNG: RGB8/RGBA8, preserves alpha, `CompressionType::Default`,
//!   `FilterType::Adaptive` (via [`crate::media_image`]).
//! - JPEG: RGB8, quality 90, rejects any non-opaque alpha with
//!   `jpeg_alpha_unsupported` rather than flattening against an implicit
//!   color.
//! - WebP: lossless RGB8/RGBA8 using the existing image-crate encoder.
//!
//! ## Security
//!
//! Path/URL/attachment resolution is delegated to the shared session media
//! authority; this tool never opens an arbitrary model-supplied path or URL
//! itself. It never emits base64, data URL, host path, or provider URL in text.
//! EXIF orientation is preflighted before decode/crop/reservation; malformed
//! EXIF fails closed with `media_orientation_unsupported`.

use anyhow::{Result, bail};
use async_trait::async_trait;
use image::{ColorType, ExtendedColorType, ImageEncoder, ImageFormat};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};
use crate::media_image::{self, CropRect, ImageProfile};
use crate::tool_media_authority::ReadImageSource;
use crate::typed_media_result::{
    CanonicalMediaKind, CanonicalToolResultContent, MediaProvenance, MediaReference,
    MediaReferenceAvailability, MediaReferencePurpose,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The default maximum width/height when omitted.
pub const DEFAULT_MAX_DIMENSION: u32 = 2_048;

/// JPEG encoding quality (0..=100).
pub const JPEG_QUALITY: u8 = 90;

/// The schema version for the read-image tool result metadata.
pub const READ_IMAGE_SCHEMA_VERSION: u8 = 1;

/// Maximum input image bytes accepted (decompression bomb guard).
pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// Maximum output image bytes before the result is rejected (central limit).
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Schema (argument validation)
// ---------------------------------------------------------------------------

/// The output format selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Auto,
    Png,
    Jpeg,
    Webp,
}

impl OutputFormat {
    /// The effective output format, resolving `auto` to PNG (lossless).
    pub fn effective(self) -> OutputFormat {
        match self {
            OutputFormat::Auto => OutputFormat::Png,
            other => other,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            OutputFormat::Auto => "auto",
            OutputFormat::Png => "png",
            OutputFormat::Jpeg => "jpeg",
            OutputFormat::Webp => "webp",
        }
    }

    pub fn mime_type(self) -> &'static str {
        match self.effective() {
            OutputFormat::Png => "image/png",
            OutputFormat::Jpeg => "image/jpeg",
            OutputFormat::Webp => "image/webp",
            OutputFormat::Auto => unreachable!("effective() resolves auto"),
        }
    }

    pub fn image_format(self) -> ImageFormat {
        match self.effective() {
            OutputFormat::Png => ImageFormat::Png,
            OutputFormat::Jpeg => ImageFormat::Jpeg,
            OutputFormat::Webp => ImageFormat::WebP,
            OutputFormat::Auto => unreachable!("effective() resolves auto"),
        }
    }
}

/// Integer pixel region `{x, y, width, height}` in original-orientation-
/// normalized coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Region {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Region {
    /// Validate that width/height are positive and the region is wholly inside
    /// the decoded source. Rejects (does not clamp) out-of-bounds and
    /// partially-overlapping regions.
    pub fn validate(&self, source_width: u32, source_height: u32) -> Result<()> {
        if self.width == 0 {
            return Err(invalid_input("region width must be positive"));
        }
        if self.height == 0 {
            return Err(invalid_input("region height must be positive"));
        }
        let right = self
            .x
            .checked_add(self.width)
            .ok_or_else(|| invalid_input("region x+width overflows u32"))?;
        if right > source_width {
            return Err(invalid_input("region x+width exceeds source width"));
        }
        let bottom = self
            .y
            .checked_add(self.height)
            .ok_or_else(|| invalid_input("region y+height overflows u32"))?;
        if bottom > source_height {
            return Err(invalid_input("region y+height exceeds source height"));
        }
        Ok(())
    }
}

/// Parsed and validated tool arguments (before source resolution).
#[derive(Debug, Clone)]
pub struct ReadImageArgs {
    pub source: ReadImageSource,
    pub region: Option<Region>,
    pub max_width: Option<u32>,
    pub max_height: Option<u32>,
    pub format: OutputFormat,
}

impl ReadImageArgs {
    /// Parse and validate the raw JSON arguments. Schema failure occurs
    /// before any authority call.
    pub fn from_value(value: &Value) -> Result<Self> {
        let obj = value
            .as_object()
            .ok_or_else(|| invalid_input("read_image arguments must be an object"))?;

        let allowed = ["source", "region", "max_width", "max_height", "format"];
        for key in obj.keys() {
            if !allowed.contains(&key.as_str()) {
                return Err(invalid_input(format!(
                    "unknown field `{key}`; allowed: source, region, max_width, max_height, format"
                )));
            }
        }

        let source =
            parse_source(obj.get("source").ok_or_else(|| {
                invalid_input("`source` is required (attachment_id, path, or url)")
            })?)?;

        let region = match obj.get("region") {
            None | Some(Value::Null) => None,
            Some(v) => {
                let r = serde_json::from_value::<Region>(v.clone()).map_err(|e| {
                    invalid_input(format!(
                        "`region` must be an object with x, y, width, height: {e}"
                    ))
                })?;
                if r.width == 0 {
                    return Err(invalid_input("`region.width` must be positive"));
                }
                if r.height == 0 {
                    return Err(invalid_input("`region.height` must be positive"));
                }
                Some(r)
            }
        };

        let max_width = parse_optional_positive_u32(obj.get("max_width"), "max_width")?;
        let max_height = parse_optional_positive_u32(obj.get("max_height"), "max_height")?;

        let format = match obj.get("format") {
            None | Some(Value::Null) => OutputFormat::Auto,
            Some(v) => {
                let s = v
                    .as_str()
                    .ok_or_else(|| invalid_input("`format` must be a string"))?;
                match s {
                    "auto" => OutputFormat::Auto,
                    "png" => OutputFormat::Png,
                    "jpeg" => OutputFormat::Jpeg,
                    "webp" => OutputFormat::Webp,
                    _ => {
                        return Err(invalid_input(
                            "`format` must be one of: auto, png, jpeg, webp",
                        ));
                    }
                }
            }
        };

        Ok(Self {
            source,
            region,
            max_width,
            max_height,
            format,
        })
    }
}

fn parse_source(value: &Value) -> Result<ReadImageSource> {
    let obj = value
        .as_object()
        .ok_or_else(|| invalid_input("`source` must be an object"))?;
    for key in obj.keys() {
        if !matches!(key.as_str(), "attachment_id" | "path" | "url") {
            return Err(invalid_input(format!(
                "unknown source field `{key}`; allowed: attachment_id, path, url"
            )));
        }
    }
    let attachment_id = obj.get("attachment_id");
    let path = obj.get("path");
    let url = obj.get("url");
    let present = [attachment_id.is_some(), path.is_some(), url.is_some()]
        .iter()
        .filter(|b| **b)
        .count();
    if present != 1 {
        return Err(invalid_input(
            "`source` must contain exactly one of `attachment_id`, `path`, or `url`",
        ));
    }
    if let Some(v) = attachment_id {
        let s = v
            .as_str()
            .ok_or_else(|| invalid_input("`attachment_id` must be a string"))?;
        let uuid = Uuid::parse_str(s).map_err(|_| {
            invalid_input("`attachment_id` must be a canonical lowercase RFC-4122 UUID")
        })?;
        if uuid.to_string() != s {
            return Err(invalid_input(
                "`attachment_id` must be a canonical lowercase RFC-4122 UUID",
            ));
        }
        return Ok(ReadImageSource::Attachment {
            attachment_id: uuid,
        });
    }
    if let Some(v) = path {
        let s = v
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_input("`path` must be a non-empty string"))?;
        return Ok(ReadImageSource::Path {
            path: s.to_string(),
        });
    }
    let s = url
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid_input("`url` must be a non-empty string"))?;
    if !s.starts_with("https://") {
        return Err(invalid_input("`url` must use the https:// scheme"));
    }
    Ok(ReadImageSource::Url { url: s.to_string() })
}

fn parse_optional_positive_u32(value: Option<&Value>, name: &str) -> Result<Option<u32>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| invalid_input(format!("`{name}` must be a non-negative integer")))?;
            if n == 0 {
                return Err(invalid_input(format!(
                    "`{name}` must be positive or omitted"
                )));
            }
            u32::try_from(n)
                .map(Some)
                .map_err(|_| invalid_input(format!("`{name}` exceeds u32")))
        }
    }
}

// ---------------------------------------------------------------------------
// Transform: crop → proportional Lanczos3 downscale → never upscale
// ---------------------------------------------------------------------------

/// The effective crop and scale plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransformPlan {
    pub crop: Region,
    pub output_width: u32,
    pub output_height: u32,
}

impl TransformPlan {
    pub fn compute(
        source_width: u32,
        source_height: u32,
        region: Option<Region>,
        max_width: Option<u32>,
        max_height: Option<u32>,
    ) -> Result<Self> {
        if source_width == 0 || source_height == 0 {
            return Err(invalid_input("decoded source has zero dimensions"));
        }

        let crop = match region {
            Some(r) => {
                r.validate(source_width, source_height)?;
                r
            }
            None => Region {
                x: 0,
                y: 0,
                width: source_width,
                height: source_height,
            },
        };

        let max_w = max_width.unwrap_or(DEFAULT_MAX_DIMENSION);
        let max_h = max_height.unwrap_or(DEFAULT_MAX_DIMENSION);

        if max_w == 0 || max_h == 0 {
            return Err(invalid_input("max_width and max_height must be positive"));
        }

        let (out_w, out_h) = proportional_fit(crop.width, crop.height, max_w, max_h);

        Ok(Self {
            crop,
            output_width: out_w,
            output_height: out_h,
        })
    }
}

/// Fit `(width, height)` proportionally within `(max_w, max_h)`, never
/// upscaling.
pub fn proportional_fit(width: u32, height: u32, max_w: u32, max_h: u32) -> (u32, u32) {
    if width <= max_w && height <= max_h {
        return (width, height);
    }
    let scale_w = max_w as u64 * height as u64;
    let scale_h = max_h as u64 * width as u64;
    if scale_w <= scale_h {
        let out_w = max_w;
        let out_h = (max_w as u64 * height as u64 / width as u64) as u32;
        (out_w, out_h.max(1))
    } else {
        let out_h = max_h;
        let out_w = (max_h as u64 * width as u64 / height as u64) as u32;
        (out_w.max(1), out_h)
    }
}

// ---------------------------------------------------------------------------
// Encoder: exact PNG/JPEG/WebP settings
// ---------------------------------------------------------------------------

pub fn encode_image(img: &image::DynamicImage, format: OutputFormat) -> Result<Vec<u8>> {
    let format = format.effective();
    let mut bytes = Vec::new();
    match format {
        OutputFormat::Png => media_image::encode_png(img, &ImageProfile::read_image()),
        OutputFormat::Jpeg => {
            let rgba = img.to_rgba8();
            for pixel in rgba.pixels() {
                if pixel[3] != 255 {
                    return Err(invalid_input(
                        "jpeg_alpha_unsupported: JPEG cannot encode non-opaque alpha; use png or webp",
                    ));
                }
            }
            let rgb = image::DynamicImage::ImageRgb8(img.to_rgb8());
            let mut encoder =
                image::codecs::jpeg::JpegEncoder::new_with_quality(&mut bytes, JPEG_QUALITY);
            encoder.encode_image(&rgb)?;
            Ok(bytes)
        }
        OutputFormat::Webp => {
            let encoder = image::codecs::webp::WebPEncoder::new_lossless(&mut bytes);
            let has_alpha = matches!(img.color(), ColorType::Rgba8 | ColorType::La8);
            // Encode within each color branch: `Rgba8` and `Rgb8` buffers are
            // distinct `ImageBuffer<_>` types and cannot share one binding.
            if has_alpha {
                let webp_img = img.to_rgba8();
                encoder.write_image(
                    webp_img.as_raw(),
                    webp_img.width(),
                    webp_img.height(),
                    ExtendedColorType::Rgba8,
                )?;
            } else {
                let webp_img = img.to_rgb8();
                encoder.write_image(
                    webp_img.as_raw(),
                    webp_img.width(),
                    webp_img.height(),
                    ExtendedColorType::Rgb8,
                )?;
            }
            Ok(bytes)
        }
        OutputFormat::Auto => unreachable!("effective() resolves auto"),
    }
}

// ---------------------------------------------------------------------------
// Transform pipeline: decode → orient → crop → scale → encode
// ---------------------------------------------------------------------------

/// The result of a successful transform.
#[derive(Debug, Clone)]
pub struct TransformResult {
    pub bytes: Vec<u8>,
    pub mime_type: &'static str,
    pub output_width: u32,
    pub output_height: u32,
    pub source_width: u32,
    pub source_height: u32,
    pub crop: Region,
    pub format: OutputFormat,
    pub checksum: String,
    pub additional_frames_ignored: bool,
}

/// Decode raw image bytes, apply EXIF orientation, crop, proportional
/// Lanczos3 downscale (never upscale), and encode with exact settings.
pub fn transform_bytes(
    input: &[u8],
    region: Option<Region>,
    max_width: Option<u32>,
    max_height: Option<u32>,
    format: OutputFormat,
) -> Result<TransformResult> {
    let profile = ImageProfile::read_image();
    let additional_frames_ignored = media_image::is_animated_gif(input);
    let oriented = media_image::decode_and_orient(input, &profile)
        .map_err(|e| invalid_input(e.to_string()))?;

    let source_width = oriented.width();
    let source_height = oriented.height();

    let plan = TransformPlan::compute(source_width, source_height, region, max_width, max_height)?;

    let cropped = media_image::crop(
        oriented,
        CropRect {
            x: plan.crop.x,
            y: plan.crop.y,
            width: plan.crop.width,
            height: plan.crop.height,
        },
    )
    .map_err(|e| invalid_input(e.to_string()))?;

    let scaled = media_image::scale(cropped, plan.output_width, plan.output_height, &profile);

    let bytes = encode_image(&scaled, format)?;
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(invalid_input(format!(
            "output image exceeds {MAX_OUTPUT_BYTES} bytes (central limit)"
        )));
    }

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let checksum = hex_lower(&hasher.finalize());

    Ok(TransformResult {
        bytes,
        mime_type: format.effective().mime_type(),
        output_width: plan.output_width,
        output_height: plan.output_height,
        source_width,
        source_height,
        crop: plan.crop,
        format: format.effective(),
        checksum,
        additional_frames_ignored,
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Tool trait implementation
// ---------------------------------------------------------------------------

pub struct ReadImageTool;

#[async_trait]
impl Tool for ReadImageTool {
    fn name(&self) -> &str {
        "read_image"
    }

    fn description(&self) -> &str {
        "Read, crop, and downscale one image into a typed media reference with lossless-default PNG output"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Read one image from a session attachment, path, or https URL, optionally crop \
             and downscale it, and return an opaque typed media reference. Use `source` \
             (`attachment_id` / `path` / `url`), `region` to crop (oriented-image pixel \
             coordinates), `max_width`/`max_height` to downscale (defaults 2048, never \
             upscales), and `format` to select png/jpeg/webp (default `auto` = lossless \
             PNG). The result is a media reference — never base64, a data URL, or a host path."
                .to_string(),
        )
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "source": {
                    "anyOf": [
                        {
                            "type": "object",
                            "properties": {
                                "attachment_id": {
                                    "type": "string",
                                    "format": "uuid",
                                    "description": "Canonical lowercase RFC-4122 UUID of a session image attachment"
                                }
                            },
                            "required": ["attachment_id"],
                            "additionalProperties": false
                        },
                        {
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "minLength": 1,
                                    "description": "Path to the image file"
                                }
                            },
                            "required": ["path"],
                            "additionalProperties": false
                        },
                        {
                            "type": "object",
                            "properties": {
                                "url": {
                                    "type": "string",
                                    "minLength": 1,
                                    "description": "Retained HTTPS URL of the image"
                                }
                            },
                            "required": ["url"],
                            "additionalProperties": false
                        }
                    ]
                },
                "region": {
                    "anyOf": [
                        {
                            "type": "object",
                            "properties": {
                                "x":      {"type": "integer", "minimum": 0, "maximum": 4294967295u64},
                                "y":      {"type": "integer", "minimum": 0, "maximum": 4294967295u64},
                                "width":  {"type": "integer", "minimum": 1, "maximum": 4294967295u64},
                                "height": {"type": "integer", "minimum": 1, "maximum": 4294967295u64}
                            },
                            "required": ["x", "y", "width", "height"],
                            "additionalProperties": false
                        },
                        {"type": "null"}
                    ],
                    "description": "Crop region in oriented-image pixels"
                },
                "max_width": {
                    "anyOf": [
                        {"type": "integer", "minimum": 1, "maximum": 4294967295u64},
                        {"type": "null"}
                    ],
                    "description": "Maximum output width (default 2048; never upscales)"
                },
                "max_height": {
                    "anyOf": [
                        {"type": "integer", "minimum": 1, "maximum": 4294967295u64},
                        {"type": "null"}
                    ],
                    "description": "Maximum output height (default 2048; never upscales)"
                },
                "format": {
                    "anyOf": [
                        {"type": "string", "enum": ["auto", "png", "jpeg", "webp"]},
                        {"type": "null"}
                    ],
                    "description": "Output format (default auto = lossless PNG)"
                }
            },
            "required": ["source"],
            "additionalProperties": false,
            "description": "Read one image with optional crop and downscale; returns a typed media reference"
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(self.parameters())
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let parsed = ReadImageArgs::from_value(&args)?;

        let Some(authority) = ctx.media_authority() else {
            bail!(
                "media_attachment_authority_unavailable: this repository does not yet expose the typed session attachment authority required for safe media execution"
            );
        };

        let mut admitted = authority
            .admit_read_image_source(authority.subject(), parsed.source)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let source_bytes = match admitted.tool_source.bytes() {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => {
                admitted.tool_source.release();
                return Err(anyhow::anyhow!("{e}"));
            }
        };

        if let Err(e) = media_image::preflight_exif_orientation(&source_bytes) {
            admitted.tool_source.release();
            return Err(e);
        }

        let reservation = match authority.reserve_read_image_derivative(&admitted.identity) {
            Ok(reservation) => reservation,
            Err(e) => {
                admitted.tool_source.release();
                return Err(anyhow::anyhow!("{e}"));
            }
        };

        #[cfg(test)]
        crate::media_image::test_hooks::wait_decode_barrier();
        if ctx.cancel.is_cancelled() {
            authority.cancel_derivative(&reservation);
            admitted.tool_source.release();
            bail!("cancelled");
        }

        let transformed = match transform_bytes(
            &source_bytes,
            parsed.region,
            parsed.max_width,
            parsed.max_height,
            parsed.format,
        ) {
            Ok(result) => result,
            Err(e) => {
                authority.cancel_derivative(&reservation);
                admitted.tool_source.release();
                return Err(e);
            }
        };

        let derivative = match authority.register_read_image_derivative(
            reservation,
            &transformed.bytes,
            transformed.mime_type,
            transformed.output_width,
            transformed.output_height,
            &transformed.checksum,
        ) {
            Ok(identity) => identity,
            Err(e) => {
                admitted.tool_source.release();
                return Err(anyhow::anyhow!("{e}"));
            }
        };

        admitted.tool_source.release();

        let reference = MediaReference::new(
            derivative.attachment_id,
            derivative.attachment_version,
            CanonicalMediaKind::Image,
            transformed.mime_type,
            0,
            MediaReferencePurpose::Primary,
            transformed.checksum,
            transformed.bytes.len() as u64,
            MediaReferenceAvailability::Ready,
            MediaProvenance {
                tool_name: "read_image".to_string(),
                source_label: Some("read_image".to_string()),
            },
        )
        .with_dimensions(transformed.output_width, transformed.output_height);

        let content = CanonicalToolResultContent::media_reference(reference);
        Ok(ToolOutput::text(serde_json::to_string(&content)?))
    }
}

#[cfg(test)]
mod tests;
