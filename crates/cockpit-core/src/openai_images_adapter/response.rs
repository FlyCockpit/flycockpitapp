//! Response parsing: bounded base64 decode + canonical media validation.
//!
//! Only `data[].b64_json` is parsed into bounded bytes. There is no
//! URL-output branch. Base64 length is checked before decode, decoded bytes
//! are capped by canonical output limits, and every byte sequence is
//! MIME/decode validated. Invalid base64, too many returned items, missing
//! items, decoded-size overflow, MIME mismatch, corrupt pixels, and provider
//! text-only errors become stable per-slot failures. Fewer returned images
//! than planned produces missing slot failures; extras beyond planned slots
//! are rejected and retained nowhere.

use anyhow::Result;
use base64::Engine as _;

use crate::image_generation_job::MAX_IMAGE_GENERATION_DIMENSION;

use super::dto::{
    ImagesResponseBody, ImagesResponseItem, ParsedImageSlot, ParsedImagesResponse,
    ResponseOutputFormat,
};
use super::preflight::PreflightPlanValidated;

/// Bounded decode limits. The base64 length is checked before decode; decoded
/// bytes are capped by canonical output limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeLimit {
    pub max_base64_bytes: usize,
    pub max_decoded_bytes: usize,
}

impl DecodeLimit {
    pub const fn canonical() -> Self {
        Self {
            max_base64_bytes: super::MAX_BASE64_LENGTH_BYTES,
            max_decoded_bytes: 64 * 1024 * 1024,
        }
    }
}

/// A response parse failure with a stable, redacted reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseParseFailure {
    pub reason: String,
}

impl std::fmt::Display for ResponseParseFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "openai images response parse failed: {}", self.reason)
    }
}
impl std::error::Error for ResponseParseFailure {}

/// Parses the bounded final JSON response. Streaming previews require a
/// separate reviewed job/artifact contract and are not implemented here.
pub fn parse_response(
    body: &[u8],
    plan: &PreflightPlanValidated,
    limit: &DecodeLimit,
) -> Result<ParsedImagesResponse, ResponseParseFailure> {
    let parsed: ImagesResponseBody =
        serde_json::from_slice(body).map_err(|error| ResponseParseFailure {
            reason: format!("response is not valid JSON: {error}"),
        })?;
    let expected = plan.n as usize;
    let returned = parsed.data.len();
    if returned > expected {
        return Err(ResponseParseFailure {
            reason: format!(
                "provider returned {returned} items; expected at most {expected}; extras rejected"
            ),
        });
    }
    if returned < 1 {
        return Err(ResponseParseFailure {
            reason: "provider returned no items".into(),
        });
    }
    let mut slots = Vec::with_capacity(returned);
    let format = ResponseOutputFormat::from_catalog(plan.result.output_format);
    for (index, item) in parsed.data.iter().enumerate() {
        let slot = parse_item(item, format, limit, index)?;
        slots.push(slot);
    }
    // Fewer returned images than planned produces missing slot failures.
    if returned < expected {
        return Err(ResponseParseFailure {
            reason: format!(
                "provider returned {returned} items; expected {expected}; missing slots"
            ),
        });
    }
    Ok(ParsedImagesResponse {
        slots,
        provider_request_id: None,
        revised_prompt: None,
    })
}

fn parse_item(
    item: &ImagesResponseItem,
    format: ResponseOutputFormat,
    limit: &DecodeLimit,
    index: usize,
) -> Result<ParsedImageSlot, ResponseParseFailure> {
    let b64 = &item.b64_json;
    if b64.len() > limit.max_base64_bytes {
        return Err(ResponseParseFailure {
            reason: format!("slot {index} base64 length {} exceeds bound", b64.len()),
        });
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|error| ResponseParseFailure {
            reason: format!("slot {index} base64 decode failed: {error}"),
        })?;
    if decoded.len() > limit.max_decoded_bytes {
        return Err(ResponseParseFailure {
            reason: format!("slot {index} decoded size {} exceeds bound", decoded.len()),
        });
    }
    validate_mime_and_pixels(&decoded, format, index)?;
    Ok(ParsedImageSlot {
        format,
        bytes: decoded,
    })
}

fn validate_mime_and_pixels(
    bytes: &[u8],
    format: ResponseOutputFormat,
    index: usize,
) -> Result<(), ResponseParseFailure> {
    use image::{ImageFormat, ImageReader, Limits};
    let image_format = match format {
        ResponseOutputFormat::Png => ImageFormat::Png,
        ResponseOutputFormat::Jpeg => ImageFormat::Jpeg,
        ResponseOutputFormat::Webp => ImageFormat::WebP,
    };
    let mut reader = ImageReader::with_format(std::io::Cursor::new(bytes), image_format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_GENERATION_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_GENERATION_DIMENSION);
    limits.max_alloc = Some(160_000_000);
    reader.limits(limits);
    let decoder = reader
        .into_decoder()
        .map_err(|error| ResponseParseFailure {
            reason: format!("slot {index} decode/mime validation failed: {error}"),
        })?;
    let _ = image::DynamicImage::from_decoder(decoder).map_err(|error| ResponseParseFailure {
        reason: format!("slot {index} pixel validation failed: {error}"),
    })?;
    Ok(())
}
