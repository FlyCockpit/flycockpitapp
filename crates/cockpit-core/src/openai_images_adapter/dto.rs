//! Generated request/response DTOs, kept separate from inference DTOs.
//!
//! These types model only the OpenAI Images API fields this adapter
//! serializes. Unsupported negative prompts, arbitrary provider JSON, or
//! fidelity/background/moderation combinations are rejected at preflight and
//! never reach these DTOs. The adapter serializes `stream=false`, never sends
//! `partial_images`, and parses only the final JSON response.

use serde::{Deserialize, Serialize};

use super::catalog::{Background, OutputFormat, Quality};

/// A normalized prompt is at most 32,000 Unicode scalar values and 128,000
/// UTF-8 bytes. Preflight enforces this before construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPrompt(pub String);

impl NormalizedPrompt {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Request body for `POST /v1/images/generations`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GenerationRequest {
    pub model: String,
    pub prompt: String,
    pub n: u32,
    pub size: String,
    pub quality: String,
    pub background: String,
    pub output_format: String,
    pub moderation: String,
    /// Always serialized as `false`. Streaming previews require a separate
    /// reviewed job/artifact contract.
    pub stream: bool,
}

/// One reference part for an edit multipart body. Multipart parts are 1–16
/// bounded typed media values with deterministic order and provider field
/// names covered by wire fixtures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditMultipartPart {
    /// Provider field name: `image[]` for typed references.
    pub field_name: &'static str,
    /// Deterministic filename derived from the reference identity.
    pub filename: String,
    /// Canonical MIME type for the reference bytes.
    pub mime: String,
    /// Bounded reference bytes. Aggregate and per-reference bounds are
    /// enforced by the wire encoder.
    pub bytes: Vec<u8>,
}

/// Request body for `POST /v1/images/edits` (multipart). The wire encoder
/// owns the boundary; this struct carries only the field values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditRequest {
    pub model: String,
    pub prompt: String,
    pub n: u32,
    pub size: String,
    pub quality: String,
    pub background: String,
    pub output_format: String,
    pub moderation: String,
    pub stream: bool,
    pub input_fidelity: Option<String>,
    pub image_parts: Vec<EditMultipartPart>,
}

/// Parsed quality from a plan parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseQuality {
    Auto,
    Low,
    Medium,
    High,
}

impl ResponseQuality {
    pub fn from_catalog(value: Quality) -> Self {
        match value {
            Quality::Auto => Self::Auto,
            Quality::Low => Self::Low,
            Quality::Medium => Self::Medium,
            Quality::High => Self::High,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseBackground {
    Auto,
    Opaque,
    Transparent,
}

impl ResponseBackground {
    pub fn from_catalog(value: Background) -> Self {
        match value {
            Background::Auto => Self::Auto,
            Background::Opaque => Self::Opaque,
            Background::Transparent => Self::Transparent,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Opaque => "opaque",
            Self::Transparent => "transparent",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseOutputFormat {
    Png,
    Jpeg,
    Webp,
}

impl ResponseOutputFormat {
    pub fn from_catalog(value: OutputFormat) -> Self {
        match value {
            OutputFormat::Png => Self::Png,
            OutputFormat::Jpeg => Self::Jpeg,
            OutputFormat::Webp => Self::Webp,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpeg",
            Self::Webp => "webp",
        }
    }
    pub fn mime(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Webp => "image/webp",
        }
    }
}

/// One item in the Images API response. Only `b64_json` is parsed; there is
/// no URL-output branch. Unknown additive metadata is ignored where safety
/// does not depend on it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ImagesResponseItem {
    #[serde(rename = "b64_json")]
    pub b64_json: String,
}

/// The bounded Images API response. `data` is required; `usage` and other
/// additive metadata are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ImagesResponseBody {
    pub data: Vec<ImagesResponseItem>,
}

/// The fully parsed response with bounded decoded bytes per slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedImagesResponse {
    pub slots: Vec<ParsedImageSlot>,
    pub provider_request_id: Option<String>,
    pub revised_prompt: Option<String>,
}

/// One decoded image slot. Bytes are MIME/decode validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedImageSlot {
    pub format: ResponseOutputFormat,
    pub bytes: Vec<u8>,
}
