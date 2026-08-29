//! `read_image` — bounded lossless-default image transformation tool.
//!
//! Ingests through typed media (path/URL resolved by the shared typed
//! attachment/path/HTTPS authority), performs deterministic crop →
//! proportional Lanczos3 downscale → exact encoding, and returns an opaque
//! [`MediaReference`] without claiming lossy JPEG is lossless.
//!
//! ## Schema
//!
//! `read_image({path?,url?,region?,max_width?,max_height?,format?})` with
//! exactly one source (`path` or `url`). Region is original-orientation-
//! normalized pixel `{x,y,width,height}`. Omitted maxima default to 2,048×
//! 2,048; one omitted maximum defaults to 2,048 for that axis. Crop first,
//! proportional Lanczos3 downscale second, never upscale.
//!
//! `format` is `auto|png|jpeg|webp`, default `auto`. `auto` always produces
//! lossless PNG. Encoders are exact:
//!
//! - PNG: RGB8/RGBA8, preserves alpha, `CompressionType::Default`,
//!   `FilterType::Adaptive`.
//! - JPEG: RGB8, quality 90, rejects any non-opaque alpha with
//!   `jpeg_alpha_unsupported` rather than flattening against an implicit
//!   color.
//! - WebP: lossless RGB8/RGBA8 using the existing image-crate encoder.
//!
//! ## Security
//!
//! Path/URL resolution is delegated to the shared typed attachment/path/HTTPS
//! authority; this tool never opens an arbitrary model-supplied path or URL
//! itself. It never emits base64, data URL, host path, or provider URL in text.
//! EXIF orientation is applied before coordinates and all metadata/GPS is
//! stripped (the image crate strips metadata on re-encode; no EXIF library is
//! available and none is authorized, so orientation is identity until an EXIF
//! reader is added).

use anyhow::{Result, bail};
use async_trait::async_trait;
use image::codecs::png::{CompressionType, FilterType};
use image::imageops::FilterType as ResizeFilter;
use image::{AnimationDecoder, ColorType, ExtendedColorType, ImageEncoder, ImageFormat};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};

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
    pub path: Option<String>,
    pub url: Option<String>,
    pub region: Option<Region>,
    pub max_width: Option<u32>,
    pub max_height: Option<u32>,
    pub format: OutputFormat,
}

impl ReadImageArgs {
    /// Parse and validate the raw JSON arguments.
    pub fn from_value(value: &Value) -> Result<Self> {
        let obj = value
            .as_object()
            .ok_or_else(|| invalid_input("read_image arguments must be an object"))?;

        let allowed = ["path", "url", "region", "max_width", "max_height", "format"];
        for key in obj.keys() {
            if !allowed.contains(&key.as_str()) {
                return Err(invalid_input(format!(
                    "unknown field `{key}`; allowed: path, url, region, max_width, max_height, format"
                )));
            }
        }

        let path = obj
            .get("path")
            .map(|v| {
                v.as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| invalid_input("`path` must be a non-empty string"))
            })
            .transpose()?
            .map(String::from);
        let url = obj
            .get("url")
            .map(|v| {
                v.as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| invalid_input("`url` must be a non-empty string"))
            })
            .transpose()?
            .map(String::from);

        match (path.is_some(), url.is_some()) {
            (false, false) => {
                return Err(invalid_input("exactly one of `path` or `url` is required"));
            }
            (true, true) => {
                return Err(invalid_input(
                    "exactly one of `path` or `url` is required; both were provided",
                ));
            }
            _ => {}
        }

        if let Some(ref u) = url
            && !u.starts_with("https://")
        {
            return Err(invalid_input("`url` must use the https:// scheme"));
        }

        let region = obj
            .get("region")
            .map(|v| {
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
                Ok(r)
            })
            .transpose()?;

        let max_width = obj
            .get("max_width")
            .map(|v| {
                let n = v
                    .as_u64()
                    .ok_or_else(|| invalid_input("`max_width` must be a non-negative integer"))?;
                if n == 0 {
                    return Err(invalid_input("`max_width` must be positive or omitted"));
                }
                u32::try_from(n).map_err(|_| invalid_input("`max_width` exceeds u32"))
            })
            .transpose()?;
        let max_height = obj
            .get("max_height")
            .map(|v| {
                let n = v
                    .as_u64()
                    .ok_or_else(|| invalid_input("`max_height` must be a non-negative integer"))?;
                if n == 0 {
                    return Err(invalid_input("`max_height` must be positive or omitted"));
                }
                u32::try_from(n).map_err(|_| invalid_input("`max_height` exceeds u32"))
            })
            .transpose()?;

        let format = obj
            .get("format")
            .map(|v| {
                let s = v
                    .as_str()
                    .ok_or_else(|| invalid_input("`format` must be a string"))?;
                match s {
                    "auto" => Ok(OutputFormat::Auto),
                    "png" => Ok(OutputFormat::Png),
                    "jpeg" => Ok(OutputFormat::Jpeg),
                    "webp" => Ok(OutputFormat::Webp),
                    _ => Err(invalid_input(
                        "`format` must be one of: auto, png, jpeg, webp",
                    )),
                }
            })
            .transpose()?
            .unwrap_or(OutputFormat::Auto);

        Ok(Self {
            path,
            url,
            region,
            max_width,
            max_height,
            format,
        })
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
        OutputFormat::Png => {
            let has_alpha = matches!(img.color(), ColorType::Rgba8 | ColorType::La8);
            let encoder = image::codecs::png::PngEncoder::new_with_quality(
                &mut bytes,
                CompressionType::Default,
                FilterType::Adaptive,
            );
            // Encode within each color branch: `Rgba8` and `Rgb8` buffers are
            // distinct `ImageBuffer<_>` types and cannot share one binding.
            if has_alpha {
                let png_img = img.to_rgba8();
                encoder.write_image(
                    png_img.as_raw(),
                    png_img.width(),
                    png_img.height(),
                    ExtendedColorType::Rgba8,
                )?;
            } else {
                let png_img = img.to_rgb8();
                encoder.write_image(
                    png_img.as_raw(),
                    png_img.width(),
                    png_img.height(),
                    ExtendedColorType::Rgb8,
                )?;
            }
            Ok(bytes)
        }
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

/// Decode raw image bytes, apply EXIF orientation (identity until an EXIF
/// reader is available), crop, proportional Lanczos3 downscale (never
/// upscale), and encode with exact settings.
pub fn transform_bytes(
    input: &[u8],
    region: Option<Region>,
    max_width: Option<u32>,
    max_height: Option<u32>,
    format: OutputFormat,
) -> Result<TransformResult> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(invalid_input(format!(
            "input image exceeds {MAX_INPUT_BYTES} bytes (decompression bomb guard)"
        )));
    }

    let img = image::load_from_memory(input)
        .map_err(|e| invalid_input(format!("failed to decode image: {e}")))?;

    let additional_frames_ignored = is_animated_gif(input);

    let oriented = apply_orientation(img);

    let source_width = oriented.width();
    let source_height = oriented.height();

    let plan = TransformPlan::compute(source_width, source_height, region, max_width, max_height)?;

    let cropped = if plan.crop.x == 0
        && plan.crop.y == 0
        && plan.crop.width == source_width
        && plan.crop.height == source_height
    {
        oriented
    } else {
        oriented.crop_imm(plan.crop.x, plan.crop.y, plan.crop.width, plan.crop.height)
    };

    let scaled = if plan.output_width == plan.crop.width && plan.output_height == plan.crop.height {
        cropped
    } else {
        cropped.resize_exact(
            plan.output_width,
            plan.output_height,
            ResizeFilter::Lanczos3,
        )
    };

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

fn apply_orientation(img: image::DynamicImage) -> image::DynamicImage {
    img
}

fn is_animated_gif(input: &[u8]) -> bool {
    if let Ok(decoder) = image::codecs::gif::GifDecoder::new(std::io::Cursor::new(input)) {
        let frames = decoder.into_frames();
        let count = frames.collect_frames().map(|f| f.len()).unwrap_or(0);
        return count > 1;
    }
    false
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

    fn verbose_description(&self) -> Option<String> {
        Some(
            "Read one image from a path or https URL, optionally crop and downscale it, \
             and return an opaque typed media reference. Use `region` to crop \
             (original-orientation pixel coordinates), `max_width`/`max_height` to \
             downscale (defaults 2048, never upscales), and `format` to select \
             png/jpeg/webp (default `auto` = lossless PNG). The result is a media \
             reference — never base64, a data URL, or a host path."
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
                "path": {
                    "type": "string",
                    "minLength": 1,
                    "description": "Path to the image file (mutually exclusive with url)"
                },
                "url": {
                    "type": "string",
                    "pattern": "^https://",
                    "description": "HTTPS URL of the image (mutually exclusive with path)"
                },
                "region": {
                    "type": "object",
                    "properties": {
                        "x":      {"type": "integer", "minimum": 0},
                        "y":      {"type": "integer", "minimum": 0},
                        "width":  {"type": "integer", "exclusiveMinimum": 0},
                        "height": {"type": "integer", "exclusiveMinimum": 0}
                    },
                    "required": ["x", "y", "width", "height"],
                    "additionalProperties": false,
                    "description": "Crop region in original-orientation-normalized pixels"
                },
                "max_width": {
                    "type": "integer",
                    "exclusiveMinimum": 0,
                    "description": "Maximum output width (default 2048; never upscales)"
                },
                "max_height": {
                    "type": "integer",
                    "exclusiveMinimum": 0,
                    "description": "Maximum output height (default 2048; never upscales)"
                },
                "format": {
                    "type": "string",
                    "enum": ["auto", "png", "jpeg", "webp"],
                    "description": "Output format (default auto = lossless PNG)"
                }
            },
            "additionalProperties": false,
            "description": "Read one image with optional crop and downscale; returns a typed media reference"
        })
    }

    fn verbose_parameters(&self) -> Option<Value> {
        Some(self.parameters())
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let parsed = ReadImageArgs::from_value(&args)?;

        let source_count = [parsed.path.is_some(), parsed.url.is_some()]
            .iter()
            .filter(|b| **b)
            .count();
        if source_count != 1 {
            return Err(invalid_input("exactly one of `path` or `url` is required"));
        }

        // Consumer behavior is intentionally out of scope for this change.
        // Do not ask the authority to admit a path/URL until a consumer can
        // use its held handle or immutable retained object: admission itself
        // may open or fetch a source.  Returning here preserves the no-I/O
        // denial contract for both stripped and direct-native contexts.
        let _ = (ctx, parsed);
        bail!(
            "media_attachment_authority_unavailable: image processing is not wired in this build"
        );
    }
}

#[cfg(test)]
mod tests;
