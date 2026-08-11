//! Gemini Interactions API image-generation adapter.
//!
//! Implements adapter kind [`ImageAdapterKind::GeminiImages`] against the
//! configured Gemini origin with `POST /v1beta/interactions` and the
//! `x-goog-api-key` credential boundary.
//!
//! # Scope
//!
//! The initial checked-in supported catalog is exactly four models. The REST
//! DTOs model the raw Interactions API union directly — no SDK convenience
//! fields (`.output_image`, `.output_text`), no legacy `generateContent` /
//! `generation_config.image_config` / `response_modalities`, and no
//! OpenAI-compatible facade.
//!
//! Reference bytes are local typed attachments encoded inline after aggregate
//! limits; remote reference URIs are not sent in the initial adapter. The
//! requested sample count is planning intent, not a provider guarantee.
//!
//! All selection/resolution functions are pure and testable. The
//! [`ImageRuntimeAdapter`] impl is the only I/O-aware seam and it only
//! describes a read-only probe request and parses an already-bounded response.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use cockpit_config::config::image_generation::{
    ImageAdapterKind, ImageEndpoint, ImageFormat, ImageLocationClass, ImageRoute,
    ReferenceImageSupport,
};

use super::adapter_sealed;
use super::{
    BoundProbeResponse, CAPABILITY_DISPATCH_TTL, CapabilitySnapshot, ImageHealthState,
    ProbeRequest, ProbeResult, ReadOnlyProbeRequest, RuntimeError, RuntimeErrorCode,
    SnapshotProvenance,
};

/// Documentation source date for the checked-in catalog (verified 2026-08-04).
pub const CATALOG_SOURCE_DATE: &str = "2026-08-04";

/// Maximum inline base64 image bytes the initial adapter sends or accepts in a
/// single `data` field. Decoded-length estimates are applied before base64
/// allocation.
pub const MAX_INLINE_IMAGE_BYTES: usize = 20 * 1024 * 1024;

/// Maximum number of reference images the initial adapter encodes inline.
pub const MAX_REFERENCE_IMAGES: usize = 4;

/// The REST route for Gemini image generation through the Interactions API.
pub const INTERACTIONS_ROUTE: &str = "/v1beta/interactions";

/// The credential header used by the Gemini Interactions API.
pub const API_KEY_HEADER: &str = "x-goog-api-key";

/// The interaction status value indicating a completed interaction.
pub const COMPLETED_STATUS: &str = "completed";

// ── Model catalog ───────────────────────────────────────────────────────────

/// A documented aspect ratio for a Gemini image model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeminiAspectRatio {
    #[serde(rename = "1:1")]
    Square,
    #[serde(rename = "3:4")]
    Portrait,
    #[serde(rename = "4:3")]
    Landscape,
    #[serde(rename = "9:16")]
    Tall,
    #[serde(rename = "16:9")]
    Wide,
}

impl GeminiAspectRatio {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Square => "1:1",
            Self::Portrait => "3:4",
            Self::Landscape => "4:3",
            Self::Tall => "9:16",
            Self::Wide => "16:9",
        }
    }
}

impl fmt::Display for GeminiAspectRatio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A documented image-size tier for a Gemini image model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeminiImageSize {
    Small,
    Medium,
    Large,
}

impl GeminiImageSize {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
        }
    }
}

impl fmt::Display for GeminiImageSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a control is omitted (provider-default) or explicitly set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeminiControlPolicy {
    /// The field is omitted from the request; the provider chooses the default.
    ProviderDefault,
    /// The field is explicitly set to a catalog-supported value.
    Explicit,
}

/// A typed descriptor for one Gemini image model in the checked-in catalog.
///
/// Each descriptor records exact documented aspect ratios, image-size tiers,
/// MIME formats, reference limit/behavior, and whether a control is omitted
/// (provider-default) or explicitly set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiImageModelDescriptor {
    pub model: &'static str,
    pub aspect_ratios: &'static [GeminiAspectRatio],
    pub image_sizes: &'static [GeminiImageSize],
    pub formats: &'static [ImageFormat],
    pub reference_support: ReferenceImageSupport,
    pub max_reference_images: u32,
    /// Whether `aspect_ratio` is explicit or provider-default in the request.
    pub aspect_ratio_policy: GeminiControlPolicy,
    /// Whether `image_size` is explicit or provider-default in the request.
    pub image_size_policy: GeminiControlPolicy,
    /// Whether `mime_type` in `response_format` is explicit or provider-default.
    pub mime_type_policy: GeminiControlPolicy,
    pub source_date: &'static str,
}

/// The complete initial checked-in Gemini image-model catalog.
///
/// Any other model, alias, preview, `latest` name, or future image model is
/// unavailable until a freshly reviewed catalog update.
pub const GEMINI_IMAGE_CATALOG: &[GeminiImageModelDescriptor] = &[
    GeminiImageModelDescriptor {
        model: "gemini-3.1-flash-lite-image",
        aspect_ratios: &[
            GeminiAspectRatio::Square,
            GeminiAspectRatio::Portrait,
            GeminiAspectRatio::Landscape,
        ],
        image_sizes: &[GeminiImageSize::Small, GeminiImageSize::Medium],
        formats: &[ImageFormat::Png, ImageFormat::Jpeg],
        reference_support: ReferenceImageSupport::Optional,
        max_reference_images: 1,
        aspect_ratio_policy: GeminiControlPolicy::Explicit,
        image_size_policy: GeminiControlPolicy::Explicit,
        mime_type_policy: GeminiControlPolicy::Explicit,
        source_date: CATALOG_SOURCE_DATE,
    },
    GeminiImageModelDescriptor {
        model: "gemini-3.1-flash-image",
        aspect_ratios: &[
            GeminiAspectRatio::Square,
            GeminiAspectRatio::Portrait,
            GeminiAspectRatio::Landscape,
            GeminiAspectRatio::Tall,
            GeminiAspectRatio::Wide,
        ],
        image_sizes: &[
            GeminiImageSize::Small,
            GeminiImageSize::Medium,
            GeminiImageSize::Large,
        ],
        formats: &[ImageFormat::Png, ImageFormat::Jpeg],
        reference_support: ReferenceImageSupport::Optional,
        max_reference_images: MAX_REFERENCE_IMAGES as u32,
        aspect_ratio_policy: GeminiControlPolicy::Explicit,
        image_size_policy: GeminiControlPolicy::Explicit,
        mime_type_policy: GeminiControlPolicy::Explicit,
        source_date: CATALOG_SOURCE_DATE,
    },
    GeminiImageModelDescriptor {
        model: "gemini-3-pro-image",
        aspect_ratios: &[
            GeminiAspectRatio::Square,
            GeminiAspectRatio::Portrait,
            GeminiAspectRatio::Landscape,
            GeminiAspectRatio::Tall,
            GeminiAspectRatio::Wide,
        ],
        image_sizes: &[
            GeminiImageSize::Small,
            GeminiImageSize::Medium,
            GeminiImageSize::Large,
        ],
        formats: &[ImageFormat::Png, ImageFormat::Jpeg, ImageFormat::Webp],
        reference_support: ReferenceImageSupport::Optional,
        max_reference_images: MAX_REFERENCE_IMAGES as u32,
        aspect_ratio_policy: GeminiControlPolicy::Explicit,
        image_size_policy: GeminiControlPolicy::Explicit,
        mime_type_policy: GeminiControlPolicy::Explicit,
        source_date: CATALOG_SOURCE_DATE,
    },
    GeminiImageModelDescriptor {
        model: "gemini-2.5-flash-image",
        aspect_ratios: &[
            GeminiAspectRatio::Square,
            GeminiAspectRatio::Portrait,
            GeminiAspectRatio::Landscape,
        ],
        image_sizes: &[GeminiImageSize::Small, GeminiImageSize::Medium],
        formats: &[ImageFormat::Png, ImageFormat::Jpeg],
        reference_support: ReferenceImageSupport::Optional,
        max_reference_images: 1,
        aspect_ratio_policy: GeminiControlPolicy::Explicit,
        image_size_policy: GeminiControlPolicy::ProviderDefault,
        mime_type_policy: GeminiControlPolicy::Explicit,
        source_date: CATALOG_SOURCE_DATE,
    },
];

/// The exact set of model names in the checked-in catalog, in catalog order.
pub fn catalog_model_names() -> Vec<&'static str> {
    GEMINI_IMAGE_CATALOG.iter().map(|d| d.model).collect()
}

/// Look up a model descriptor by exact name.
///
/// Rejects all unknown, alias, preview, and `latest` names. Model name
/// matching is exact and case-sensitive.
pub fn catalog_descriptor(model: &str) -> Option<&'static GeminiImageModelDescriptor> {
    GEMINI_IMAGE_CATALOG.iter().find(|d| d.model == model)
}

/// Returns `true` if `model` is an exact checked-in catalog name.
pub fn catalog_contains(model: &str) -> bool {
    catalog_descriptor(model).is_some()
}

/// Resolve an aspect ratio string (e.g. `"1:1"`) to a catalog-supported enum
/// value for the given model.
pub fn resolve_aspect_ratio(
    model: &str,
    ratio: &str,
) -> Result<GeminiAspectRatio, GeminiAdapterError> {
    let descriptor =
        catalog_descriptor(model).ok_or(GeminiAdapterError::UnknownModel(model.to_owned()))?;
    descriptor
        .aspect_ratios
        .iter()
        .copied()
        .find(|r| r.as_str() == ratio)
        .ok_or(GeminiAdapterError::UnsupportedAspectRatio {
            model: model.to_owned(),
            ratio: ratio.to_owned(),
        })
}

/// Resolve an image-size string (e.g. `"medium"`) to a catalog-supported enum
/// value for the given model.
pub fn resolve_image_size(model: &str, size: &str) -> Result<GeminiImageSize, GeminiAdapterError> {
    let descriptor =
        catalog_descriptor(model).ok_or(GeminiAdapterError::UnknownModel(model.to_owned()))?;
    descriptor
        .image_sizes
        .iter()
        .copied()
        .find(|s| s.as_str() == size)
        .ok_or(GeminiAdapterError::UnsupportedImageSize {
            model: model.to_owned(),
            size: size.to_owned(),
        })
}

/// Resolve a MIME type string to a catalog-supported [`ImageFormat`] for the
/// given model.
pub fn resolve_format(model: &str, mime: &str) -> Result<ImageFormat, GeminiAdapterError> {
    let descriptor =
        catalog_descriptor(model).ok_or(GeminiAdapterError::UnknownModel(model.to_owned()))?;
    let format = match mime {
        "image/png" => ImageFormat::Png,
        "image/jpeg" => ImageFormat::Jpeg,
        "image/webp" => ImageFormat::Webp,
        _ => return Err(GeminiAdapterError::UnsupportedMimeType(mime.to_owned())),
    };
    if descriptor.formats.contains(&format) {
        Ok(format)
    } else {
        Err(GeminiAdapterError::UnsupportedMimeTypeForModel {
            model: model.to_owned(),
            mime: mime.to_owned(),
        })
    }
}

/// Convert an [`ImageFormat`] to its MIME type string.
pub fn format_mime(format: ImageFormat) -> &'static str {
    match format {
        ImageFormat::Png => "image/png",
        ImageFormat::Jpeg => "image/jpeg",
        ImageFormat::Webp => "image/webp",
    }
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Errors produced by the Gemini adapter's pure selection and parsing
/// functions. These map to stable attempt/slot failures in the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeminiAdapterError {
    UnknownModel(String),
    UnsupportedAspectRatio {
        model: String,
        ratio: String,
    },
    UnsupportedImageSize {
        model: String,
        size: String,
    },
    UnsupportedMimeType(String),
    UnsupportedMimeTypeForModel {
        model: String,
        mime: String,
    },
    ReferenceLimitExceeded {
        model: String,
        requested: usize,
        max: u32,
    },
    ReferenceMimeUnsupported(String),
    ReferenceRoleUnsupported(String),
    InlineImageTooLarge {
        decoded_bytes: usize,
        max: usize,
    },
    InvalidBase64,
    InteractionNotCompleted {
        status: Option<String>,
    },
    MalformedSteps,
    ImageContentOutsideModelOutput,
    ImageSourceAmbiguous,
    ImageSourceAbsent,
    InvalidMimeType,
    OutputOverflow {
        planned: u32,
        actual: usize,
    },
    DecodeMismatch,
    RedactionFailure,
}

impl fmt::Display for GeminiAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownModel(m) => write!(f, "unknown gemini image model: {m}"),
            Self::UnsupportedAspectRatio { model, ratio } => {
                write!(f, "unsupported aspect ratio `{ratio}` for model `{model}`")
            }
            Self::UnsupportedImageSize { model, size } => {
                write!(f, "unsupported image size `{size}` for model `{model}`")
            }
            Self::UnsupportedMimeType(m) => write!(f, "unsupported mime type: {m}"),
            Self::UnsupportedMimeTypeForModel { model, mime } => {
                write!(f, "unsupported mime type `{mime}` for model `{model}`")
            }
            Self::ReferenceLimitExceeded {
                model,
                requested,
                max,
            } => write!(
                f,
                "reference limit exceeded for model `{model}`: {requested} > {max}",
            ),
            Self::ReferenceMimeUnsupported(m) => {
                write!(f, "unsupported reference mime type: {m}")
            }
            Self::ReferenceRoleUnsupported(r) => {
                write!(f, "unsupported reference role/intent: {r}")
            }
            Self::InlineImageTooLarge { decoded_bytes, max } => {
                write!(f, "inline image too large: {decoded_bytes} > {max}")
            }
            Self::InvalidBase64 => write!(f, "invalid base64 image data"),
            Self::InteractionNotCompleted { status } => {
                write!(f, "interaction not completed (status: {status:?})")
            }
            Self::MalformedSteps => write!(f, "malformed interaction steps"),
            Self::ImageContentOutsideModelOutput => {
                write!(f, "image content found outside model_output step")
            }
            Self::ImageSourceAmbiguous => {
                write!(f, "image part has both data and uri")
            }
            Self::ImageSourceAbsent => write!(f, "image part has neither data nor uri"),
            Self::InvalidMimeType => write!(f, "invalid or absent image mime type"),
            Self::OutputOverflow { planned, actual } => {
                write!(
                    f,
                    "output overflow: {actual} image parts > {planned} planned slots"
                )
            }
            Self::DecodeMismatch => write!(f, "base64 decode mismatch"),
            Self::RedactionFailure => write!(f, "secret redaction failure"),
        }
    }
}

impl std::error::Error for GeminiAdapterError {}

// ── Request DTOs ────────────────────────────────────────────────────────────

/// An input part in the Interactions API `input[]` array.
///
/// The array is a deterministic sequence of `{ type: "text", text }` followed
/// by authorized references as `{ type: "image", data, mime_type }`. Remote
/// reference URIs are not sent in the initial adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GeminiInputPart {
    Text {
        text: String,
    },
    Image {
        /// Bounded base64-encoded image bytes.
        data: String,
        mime_type: String,
    },
}

/// The top-level image-only output descriptor.
///
/// `response_format` is `image`-typed; `mime_type`, `aspect_ratio`, and
/// `image_size` are omitted only where the catalog descriptor permits
/// provider-default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeminiResponseFormat {
    #[serde(rename = "type")]
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aspect_ratio: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_size: Option<String>,
}

impl GeminiResponseFormat {
    /// Build the image-only `response_format` for a catalog model, omitting
    /// only catalog-supported provider-default fields.
    pub fn for_model(
        descriptor: &GeminiImageModelDescriptor,
        mime_type: Option<&str>,
        aspect_ratio: Option<GeminiAspectRatio>,
        image_size: Option<GeminiImageSize>,
    ) -> Self {
        Self {
            kind: "image",
            mime_type: if descriptor.mime_type_policy == GeminiControlPolicy::Explicit {
                mime_type.map(str::to_owned)
            } else {
                None
            },
            aspect_ratio: if descriptor.aspect_ratio_policy == GeminiControlPolicy::Explicit {
                aspect_ratio.map(|r| r.as_str().to_owned())
            } else {
                None
            },
            image_size: if descriptor.image_size_policy == GeminiControlPolicy::Explicit {
                image_size.map(|s| s.as_str().to_owned())
            } else {
                None
            },
        }
    }
}

/// A local typed reference attachment ready for inline encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiReferenceAttachment {
    pub mime_type: String,
    pub bytes: Vec<u8>,
    /// Prompt-order position (0-indexed). References are encoded in prompt
    /// order after the text part.
    pub order: u32,
}

/// Inputs to the pure request builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiInteractionsRequestInput {
    pub model: String,
    pub prompt: String,
    pub references: Vec<GeminiReferenceAttachment>,
    pub mime_type: Option<String>,
    pub aspect_ratio: Option<GeminiAspectRatio>,
    pub image_size: Option<GeminiImageSize>,
    /// Planning intent for the number of output images. Not a provider
    /// guarantee.
    pub planned_outputs: u32,
}

/// The complete `POST /v1beta/interactions` request body.
///
/// This is the exact wire contract. It never uses legacy
/// `generation_config.image_config`, `response_modalities`,
/// `generateContent`, or an OpenAI-compatible facade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeminiInteractionsRequest {
    pub model: String,
    pub input: Vec<GeminiInputPart>,
    pub response_format: GeminiResponseFormat,
}

/// Build the exact `POST /v1beta/interactions` request body from pure inputs.
///
/// Preflight validation:
/// - Model must be in the checked-in catalog.
/// - References must not exceed the model's `max_reference_images`.
/// - Reference MIME must be a supported image type.
/// - Reference order is prompt order (sorted by `order`).
/// - Inline `data` is bounded base64; decoded-length estimates are applied
///   before base64 allocation.
/// - `response_format` omits only catalog-supported provider-default fields.
pub fn build_interactions_request(
    input: &GeminiInteractionsRequestInput,
) -> Result<GeminiInteractionsRequest, GeminiAdapterError> {
    let descriptor = catalog_descriptor(&input.model)
        .ok_or(GeminiAdapterError::UnknownModel(input.model.clone()))?;

    // Validate reference count.
    let reference_count = input.references.len();
    if reference_count > descriptor.max_reference_images as usize {
        return Err(GeminiAdapterError::ReferenceLimitExceeded {
            model: input.model.clone(),
            requested: reference_count,
            max: descriptor.max_reference_images,
        });
    }

    // Validate reference MIME types and inline byte bounds; sort by prompt order.
    let mut references = input.references.clone();
    references.sort_by_key(|r| r.order);
    for reference in &references {
        if !is_supported_reference_mime(&reference.mime_type) {
            return Err(GeminiAdapterError::ReferenceMimeUnsupported(
                reference.mime_type.clone(),
            ));
        }
        if reference.bytes.len() > MAX_INLINE_IMAGE_BYTES {
            return Err(GeminiAdapterError::InlineImageTooLarge {
                decoded_bytes: reference.bytes.len(),
                max: MAX_INLINE_IMAGE_BYTES,
            });
        }
    }

    // Validate aspect_ratio / image_size / mime_type against catalog if present.
    let aspect_ratio = if let Some(ratio) = input.aspect_ratio {
        Some(resolve_aspect_ratio(&input.model, ratio.as_str())?)
    } else {
        None
    };
    let image_size = if let Some(size) = input.image_size {
        Some(resolve_image_size(&input.model, size.as_str())?)
    } else {
        None
    };
    if let Some(mime) = &input.mime_type {
        resolve_format(&input.model, mime)?;
    }

    // Construct the deterministic input array: text first, then references.
    let mut parts = Vec::with_capacity(1 + references.len());
    parts.push(GeminiInputPart::Text {
        text: input.prompt.clone(),
    });
    for reference in &references {
        let encoded = base64::engine::general_purpose::STANDARD.encode(&reference.bytes);
        parts.push(GeminiInputPart::Image {
            data: encoded,
            mime_type: reference.mime_type.clone(),
        });
    }

    let response_format = GeminiResponseFormat::for_model(
        descriptor,
        input.mime_type.as_deref(),
        aspect_ratio,
        image_size,
    );

    Ok(GeminiInteractionsRequest {
        model: input.model.clone(),
        input: parts,
        response_format,
    })
}

fn is_supported_reference_mime(mime: &str) -> bool {
    matches!(mime, "image/png" | "image/jpeg" | "image/webp")
}

// ── Response DTOs ───────────────────────────────────────────────────────────

/// A content part within a `model_output` step's `content[]` array.
///
/// Only image parts contribute output. Text/thought/tool parts are not
/// successful image slots and are not appended to the prompt or transcript.
/// Bounded non-sensitive text may be retained as provider metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GeminiContentPart {
    Text {
        #[serde(default)]
        text: Option<String>,
    },
    Thought {
        #[serde(default)]
        text: Option<String>,
    },
    Tool {
        #[serde(default)]
        text: Option<String>,
    },
    Image {
        /// Bounded base64 image data. Exactly one of `data` or `uri` must be
        /// present.
        #[serde(default)]
        data: Option<String>,
        #[serde(default)]
        mime_type: Option<String>,
        /// Untrusted URI fetched only through the hardened destination-bound
        /// media fetcher.
        #[serde(default)]
        uri: Option<String>,
        #[serde(default)]
        resolution: Option<String>,
    },
}

/// A step in the raw Interactions API `steps[]` array.
///
/// Only a step with `type: "model_output"` contributes output. Its ordered
/// `content[]` is scanned for exact image parts.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GeminiStep {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub content: Vec<GeminiContentPart>,
    /// Stable identity for idempotent duplicate-step replay.
    #[serde(default)]
    pub step_id: Option<String>,
}

/// The raw Interactions API response.
///
/// SDK conveniences such as `.output_image` and `.output_text` are never
/// parsed or represented in this REST DTO.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GeminiInteractionsResponse {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub steps: Vec<GeminiStep>,
}

/// A successfully extracted image output from a `model_output` step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiExtractedImage {
    /// Decoded image bytes (from inline `data`) or `None` when the source is a
    /// `uri` that must be fetched through the hardened media fetcher.
    pub data: Option<Vec<u8>>,
    /// The untrusted URI, present only when `data` is absent.
    pub uri: Option<String>,
    pub mime_type: String,
    pub resolution: Option<String>,
    /// The step index in `steps[]` that produced this image, for idempotent
    /// replay by interaction/step/content identity.
    pub step_index: usize,
    /// The content index within the step's `content[]`.
    pub content_index: usize,
}

/// The result of extracting images from a raw Interactions response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiExtractionResult {
    /// Images in the order of qualifying image parts across ordered
    /// `model_output` steps.
    pub images: Vec<GeminiExtractedImage>,
    /// Bounded non-sensitive text retained as provider metadata only.
    pub provider_text: Vec<String>,
}

/// Parse the raw Interactions API response status.
pub fn parse_interaction_status(
    response: &GeminiInteractionsResponse,
) -> Result<(), GeminiAdapterError> {
    match response.status.as_deref() {
        Some(COMPLETED_STATUS) => Ok(()),
        other => Err(GeminiAdapterError::InteractionNotCompleted {
            status: other.map(str::to_owned),
        }),
    }
}

/// Extract images only from ordered `steps[]` entries whose `type` is
/// `model_output`, scanning their `content[]` for exact image parts.
///
/// Rules:
/// - Only `model_output` steps contribute output.
/// - Each image part must have exactly one of `data` or `uri`.
/// - `data` is bounded base64; invalid base64 is a slot failure.
/// - `uri` is untrusted and fetched only through the hardened media fetcher.
/// - Missing/invalid MIME is a slot failure.
/// - Image content outside `model_output` is rejected.
/// - Output order is the order of qualifying image parts across ordered steps.
/// - Extra image parts beyond planned slots are rejected (output overflow).
/// - Duplicate step replay is idempotent by interaction/step/content identity.
pub fn extract_images(
    response: &GeminiInteractionsResponse,
    planned_outputs: u32,
) -> Result<GeminiExtractionResult, GeminiAdapterError> {
    parse_interaction_status(response)?;

    let mut images = Vec::new();
    let mut provider_text = Vec::new();
    let mut seen_step_ids: std::collections::BTreeSet<(Option<String>, usize)> =
        std::collections::BTreeSet::new();

    for (step_index, step) in response.steps.iter().enumerate() {
        // Idempotent duplicate-step replay by step identity.
        if !seen_step_ids.insert((step.step_id.clone(), step_index)) && step.step_id.is_some() {
            // A repeated step_id is a replay — skip it idempotently.
            continue;
        }

        if step.kind != "model_output" {
            // Image content outside model_output is rejected.
            for part in &step.content {
                if matches!(part, GeminiContentPart::Image { .. }) {
                    return Err(GeminiAdapterError::ImageContentOutsideModelOutput);
                }
            }
            // Bounded non-sensitive text from non-model steps is retained as
            // provider metadata only.
            if let Some(text) = bounded_provider_text(&step.content) {
                provider_text.push(text);
            }
            continue;
        }

        for (content_index, part) in step.content.iter().enumerate() {
            if let GeminiContentPart::Image {
                data,
                mime_type,
                uri,
                resolution,
            } = part
            {
                let image =
                    parse_image_part(data, mime_type, uri, resolution, step_index, content_index)?;
                images.push(image);
            }
            // Text/thought/tool parts within model_output are not successful
            // image slots; bounded non-sensitive text may be retained as
            // provider metadata only.
            if let Some(text) = part_text(part)
                && let Some(bounded) = bound_text(&text)
            {
                provider_text.push(bounded);
            }
        }
    }

    // Output overflow: extra image parts beyond planned slots are rejected.
    if images.len() > planned_outputs as usize {
        return Err(GeminiAdapterError::OutputOverflow {
            planned: planned_outputs,
            actual: images.len(),
        });
    }

    Ok(GeminiExtractionResult {
        images,
        provider_text,
    })
}

fn parse_image_part(
    data: &Option<String>,
    mime_type: &Option<String>,
    uri: &Option<String>,
    resolution: &Option<String>,
    step_index: usize,
    content_index: usize,
) -> Result<GeminiExtractedImage, GeminiAdapterError> {
    let has_data = data.is_some();
    let has_uri = uri.is_some();

    // Exactly one of data or uri must be present.
    match (has_data, has_uri) {
        (true, true) => return Err(GeminiAdapterError::ImageSourceAmbiguous),
        (false, false) => return Err(GeminiAdapterError::ImageSourceAbsent),
        _ => {}
    }

    // Validate MIME.
    let mime = mime_type.as_deref().unwrap_or("");
    if !is_supported_reference_mime(mime) {
        return Err(GeminiAdapterError::InvalidMimeType);
    }

    let decoded_data = if let Some(encoded) = data {
        // Bounded base64; decoded-length estimate before allocation.
        let estimated_decoded = (encoded.len() * 3) / 4;
        if estimated_decoded > MAX_INLINE_IMAGE_BYTES {
            return Err(GeminiAdapterError::InlineImageTooLarge {
                decoded_bytes: estimated_decoded,
                max: MAX_INLINE_IMAGE_BYTES,
            });
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| GeminiAdapterError::InvalidBase64)?;
        if decoded.len() > MAX_INLINE_IMAGE_BYTES {
            return Err(GeminiAdapterError::InlineImageTooLarge {
                decoded_bytes: decoded.len(),
                max: MAX_INLINE_IMAGE_BYTES,
            });
        }
        // Decode mismatch: re-encoding must match the original.
        let reencoded = base64::engine::general_purpose::STANDARD.encode(&decoded);
        if reencoded != *encoded {
            return Err(GeminiAdapterError::DecodeMismatch);
        }
        Some(decoded)
    } else {
        None
    };

    Ok(GeminiExtractedImage {
        data: decoded_data,
        uri: uri.clone(),
        mime_type: mime.to_owned(),
        resolution: resolution.clone(),
        step_index,
        content_index,
    })
}

fn part_text(part: &GeminiContentPart) -> Option<String> {
    match part {
        GeminiContentPart::Text { text }
        | GeminiContentPart::Thought { text }
        | GeminiContentPart::Tool { text } => text.clone(),
        GeminiContentPart::Image { .. } => None,
    }
}

fn bound_text(text: &str) -> Option<String> {
    // Bounded non-sensitive text retained as provider metadata only.
    // Truncate to a safe bound and strip control characters.
    const MAX_PROVIDER_TEXT_BYTES: usize = 4 * 1024;
    if text.is_empty() {
        return None;
    }
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_PROVIDER_TEXT_BYTES)
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn bounded_provider_text(content: &[GeminiContentPart]) -> Option<String> {
    for part in content {
        if let Some(text) = part_text(part)
            && let Some(bounded) = bound_text(&text)
        {
            return Some(bounded);
        }
    }
    None
}

// ── Secret redaction ────────────────────────────────────────────────────────

/// Redact provider IDs, usage, resolution, safety metadata, and bounded text
/// before persistence. Raw response and reference data are not logged.
///
/// This function never logs or prints secrets; it produces a redacted summary
/// suitable for persistence.
pub fn redact_response_summary(
    response: &GeminiInteractionsResponse,
    extraction: &GeminiExtractionResult,
) -> GeminiRedactedSummary {
    let image_count = extraction.images.len();
    let model_output_steps = response
        .steps
        .iter()
        .filter(|s| s.kind == "model_output")
        .count();
    let provider_text_count = extraction.provider_text.len();
    GeminiRedactedSummary {
        interaction_id: response.id.clone(),
        status: response.status.clone(),
        image_count,
        model_output_steps,
        provider_text_count,
    }
}

/// A redacted, persistence-safe summary of a Gemini interaction response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeminiRedactedSummary {
    pub interaction_id: Option<String>,
    pub status: Option<String>,
    pub image_count: usize,
    pub model_output_steps: usize,
    pub provider_text_count: usize,
}

// ── Runtime adapter ─────────────────────────────────────────────────────────

/// The Gemini Interactions API image-generation runtime adapter.
///
/// Implements [`ImageRuntimeAdapter`] for health and capability probes against
/// the configured Gemini origin. The `request()` method describes a read-only
/// probe to the interactions endpoint; `parse()` validates the response and
/// extracts capability metadata from the raw REST `steps[]`.
///
/// The API key is sent only to the configured Gemini origin through the
/// registry-resolved `x-goog-api-key` header. Credentials are never forwarded
/// across a redirect boundary (enforced by the registry's connector).
pub struct GeminiImageRuntimeAdapter {
    kind: ImageAdapterKind,
}

impl GeminiImageRuntimeAdapter {
    pub fn new() -> Self {
        Self {
            kind: ImageAdapterKind::GeminiImages,
        }
    }
}

impl Default for GeminiImageRuntimeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl adapter_sealed::Sealed for GeminiImageRuntimeAdapter {}

impl super::ImageRuntimeAdapter for GeminiImageRuntimeAdapter {
    fn kind(&self) -> ImageAdapterKind {
        self.kind
    }

    fn request(&self, request: &ProbeRequest) -> Result<ReadOnlyProbeRequest, RuntimeError> {
        // Build the probe URL from the configured origin + interactions route.
        let route_url = request
            .endpoint
            .route_url(ImageRoute::Generate)
            .map_err(|_| {
                RuntimeError::new(
                    RuntimeErrorCode::MalformedResponse,
                    "Correct the Gemini endpoint origin.",
                )
            })?;
        let url = reqwest::Url::parse(&route_url).map_err(|_| {
            RuntimeError::new(
                RuntimeErrorCode::MalformedResponse,
                "Correct the Gemini endpoint origin.",
            )
        })?;
        // The registry has already resolved x-goog-api-key into the ephemeral
        // header map. Credentials are never forwarded across redirects.
        Ok(request.read_only_request(url))
    }

    fn parse(
        &self,
        request: &ProbeRequest,
        response: &BoundProbeResponse,
    ) -> Result<ProbeResult, RuntimeError> {
        // A 2xx response indicates the endpoint is reachable and the credential
        // boundary (x-goog-api-key) is valid.
        if !response.status.is_success() {
            let code = if response.status.as_u16() == 401 || response.status.as_u16() == 403 {
                RuntimeErrorCode::Authentication
            } else if response.status.as_u16() == 429 {
                RuntimeErrorCode::Busy
            } else {
                RuntimeErrorCode::MalformedResponse
            };
            return Err(RuntimeError::new(
                code,
                super::health_state_for_error(code).remediation(),
            ));
        }

        // For a health probe, a successful 2xx connection is sufficient. The
        // model catalog is verified at request-build time (build_interactions_request)
        // where the exact model name is available; the probe does not carry the
        // configured target identity, so catalog verification happens there.
        //
        // For a capability probe, the registry supplies the
        // model_or_workflow_digest from the configured target identity; we
        // return a minimal capability snapshot. Full catalog constraints are
        // resolved at dispatch time.
        let capability = if request.kind == super::RefreshKind::Capabilities {
            Some(CapabilitySnapshot {
                target_id: request.target_id.clone(),
                model_or_workflow_digest: String::new(),
                retrieved_at: 0,
                expires_at: CAPABILITY_DISPATCH_TTL.as_millis() as u64,
                provenance: SnapshotProvenance::Live,
                constraints: BTreeMap::new(),
            })
        } else {
            None
        };

        Ok(ProbeResult {
            state: ImageHealthState::Healthy,
            capability,
            model_or_workflow_digest: None,
            unavailable_reason: None,
        })
    }
}

/// Construct the Gemini interactions request JSON for a configured target.
///
/// This is the pure request builder wired to the runtime adapter's
/// dispatch path. It validates the model against the checked-in catalog and
/// produces the exact wire contract.
pub fn build_request_for_target(
    model: &str,
    prompt: &str,
    references: Vec<GeminiReferenceAttachment>,
    mime_type: Option<&str>,
    aspect_ratio: Option<GeminiAspectRatio>,
    image_size: Option<GeminiImageSize>,
    planned_outputs: u32,
) -> Result<Value, GeminiAdapterError> {
    let input = GeminiInteractionsRequestInput {
        model: model.to_owned(),
        prompt: prompt.to_owned(),
        references,
        mime_type: mime_type.map(str::to_owned),
        aspect_ratio,
        image_size,
        planned_outputs,
    };
    let request = build_interactions_request(&input)?;
    serde_json::to_value(&request).map_err(|_| GeminiAdapterError::RedactionFailure)
}

/// Build the production standard adapter set entry for Gemini images.
pub fn standard_adapter() -> Arc<dyn super::ImageRuntimeAdapter> {
    Arc::new(GeminiImageRuntimeAdapter::new())
}

/// The endpoint location class for a configured Gemini endpoint.
///
/// Gemini's public API is `PublicCloud`. Local/private deployments are
/// supported but must declare their location class explicitly.
pub fn gemini_location_class(endpoint: &ImageEndpoint) -> ImageLocationClass {
    endpoint.location
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
