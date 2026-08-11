//! Authenticated generated-artifact thumbnail and download routes.
//!
//! This module owns the V1 protocol surface for session-authorized metadata,
//! thumbnail, and download routes over validated generated artifacts. It is
//! UI-free and transport-free: it centralizes route authorization, structural
//! validation, strict single-range parsing, thumbnail box parsing, the exact
//! HTTP/daemon error mapping, and the redaction constants.
//!
//! Design invariants (prompt `image-generation-artifact-routes`):
//!
//! - Routes are keyed only by opaque artifact IDs. The server never accepts a
//!   filesystem path, redirects to a provider URL, or serves the user-owned
//!   published copy.
//! - Every authentication/existence/authorization/security-state failure is
//!   the byte-identical `404 artifact_unavailable` response and invokes no
//!   Range parser, format lookup, or thumbnail work.
//! - `ImageGenerationAdmin` by itself is not artifact/session authority.
//! - Range applies only to a full validated PNG/JPEG/WebP download. SVG
//!   content and any thumbnail route reject Range after authorization.
//! - SVG thumbnails return `409 thumbnail_unavailable_for_format` before any
//!   Range parser, source lookup, or worker.
//! - No error redirects, caches, includes an ID echo/free text, or falls
//!   through to another source.

use serde::{Deserialize, Serialize};

use crate::image_generation_control_plane::{
    validate_base64url_id_22, validate_canonical_decimal, validate_sha256_hex,
    validate_uuid_lowercase_hyphenated,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for all image-artifact route V1 structures.
pub const IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION: u8 = 1;

/// Maximum byte length of a forwarded `Range` header value.
pub const MAX_RANGE_HEADER_BYTES: usize = 256;

/// The exact allowlist of thumbnail bounding boxes.
pub const THUMBNAIL_BOXES: &[u32] = &[256, 512, 1024];

/// The thumbnail pipeline version.
pub const THUMBNAIL_PIPELINE_VERSION: u8 = 1;

/// Maximum thumbnail metadata payload size.
pub const MAX_IMAGE_ARTIFACT_METADATA_BYTES: usize = 64 * 1024;

/// The exact `Cache-Control` value for every artifact response.
pub const ARTIFACT_CACHE_CONTROL: &str = "private, no-store, max-age=0";

/// The exact `X-Content-Type-Options` value.
pub const ARTIFACT_NOSNIFF: &str = "nosniff";

/// The exact SVG `Content-Security-Policy` value.
pub const SVG_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; sandbox";

/// The exact `Retry-After` value for thumbnail capacity responses.
pub const THUMBNAIL_CAPACITY_RETRY_AFTER_SECONDS: u32 = 1;

/// The exact `retryAfterMs` for pending thumbnails.
pub const THUMBNAIL_PENDING_RETRY_AFTER_MS: u32 = 250;

/// The minimum leasable remaining duration in milliseconds.
pub const LEASE_DEADLINE_MIN_MS: u64 = 1;

/// The maximum leasable remaining duration in milliseconds.
pub const LEASE_DEADLINE_MAX_MS: u64 = 60_000;

/// The exact thumbnail pending state string.
pub const THUMBNAIL_PENDING_STATE: &str = "thumbnail_pending";

/// The MIME class for image-artifact byte bulk transfers.
pub const IMAGE_ARTIFACT_BYTES_MIME_CLASS: &str = "image_artifact_bytes_v1";

/// Maximum chunk bytes for image-artifact bulk transfers.
pub const IMAGE_ARTIFACT_MAX_CHUNK_BYTES: usize = 524_255;

/// The receiver window credit boundary.
pub const IMAGE_ARTIFACT_RECEIVER_WINDOW_BYTES: u64 = 4 * 1024 * 1024;

/// The bulk lane queue ceiling.
pub const IMAGE_ARTIFACT_BULK_QUEUE_BYTES: u64 = 8 * 1024 * 1024;

/// The aggregate transfer cap.
pub const IMAGE_ARTIFACT_AGGREGATE_CAP_BYTES: u64 = 16 * 1024 * 1024;

/// The closed filename map for validated raster downloads.
pub const RASTER_DOWNLOAD_FILENAME_PNG: &str = "flycockpit-generated-image.png";
pub const RASTER_DOWNLOAD_FILENAME_JPEG: &str = "flycockpit-generated-image.jpg";
pub const RASTER_DOWNLOAD_FILENAME_WEBP: &str = "flycockpit-generated-image.webp";
pub const RASTER_THUMBNAIL_FILENAME: &str = "flycockpit-generated-thumbnail.png";
pub const SVG_DOWNLOAD_FILENAME: &str = "flycockpit-generated-image.svg";

/// The exact `Content-Type` values for validated formats.
pub const CONTENT_TYPE_PNG: &str = "image/png";
pub const CONTENT_TYPE_JPEG: &str = "image/jpeg";
pub const CONTENT_TYPE_WEBP: &str = "image/webp";
pub const CONTENT_TYPE_SVG: &str = "image/svg+xml";
pub const CONTENT_TYPE_THUMBNAIL_PNG: &str = "image/png";

/// The bulk-lane begin `optionBits` for image-artifact transfers.
pub const IMAGE_ARTIFACT_BEGIN_OPTION_BITS: u32 = 0x03;

// ---------------------------------------------------------------------------
// Opaque ID codecs
// ---------------------------------------------------------------------------

/// Decode and validate a 22-character unpadded base64url opaque artifact ID.
/// Rejects zero bytes, noncanonical spelling, padding, and the wrong length.
pub fn parse_artifact_id(text: &str) -> Option<[u8; 16]> {
    if !validate_base64url_id_22(text) {
        return None;
    }
    let bytes = decode_base64url_16(text)?;
    if bytes.iter().all(|&b| b == 0) {
        return None;
    }
    Some(bytes)
}

/// Parse a thumbnail box path segment. Only `256`, `512`, `1024` are valid.
pub fn parse_thumbnail_box(text: &str) -> Option<u32> {
    match text {
        "256" => Some(256),
        "512" => Some(512),
        "1024" => Some(1024),
        _ => None,
    }
}

fn decode_base64url_16(text: &str) -> Option<[u8; 16]> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text.as_bytes())
        .ok()?;
    if decoded.len() != 16 {
        return None;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&decoded);
    // Re-encode to detect noncanonical spelling.
    if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out) != text {
        return None;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Route shape
// ---------------------------------------------------------------------------

/// The three application routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageArtifactRouteKind {
    Metadata,
    Content,
    Thumbnail,
}

impl ImageArtifactRouteKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Content => "content",
            Self::Thumbnail => "thumbnail",
        }
    }

    /// Whether this route forbids a `Range` header structurally (before any
    /// authorization or lookup).
    pub const fn forbids_range_structurally(self) -> bool {
        matches!(self, Self::Metadata)
    }
}

/// The parsed path segments for one of the three artifact routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageArtifactRoutePath {
    pub instance_id: String,
    pub session_id: String,
    pub artifact_id: String,
    pub route: ImageArtifactRouteKind,
    pub thumbnail_box: Option<u32>,
}

/// Structural path-shape validation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutePathError {
    /// Path does not match any of the three route shapes.
    Malformed,
}

/// Strict path codec validation. Returns the parsed path only when every
/// segment is structurally valid: `instanceId`/`sessionId` use their
/// dependency-owned 22-char alias / lowercase hyphenated UUID codecs,
/// `artifactId` is a 22-char base64url opaque ID, `box` is exactly
/// `256|512|1024`. Any other shape, codec, or extra/missing segment is
/// `Malformed` without lookup.
pub fn parse_route_path(path: &str) -> Result<ImageArtifactRoutePath, RoutePathError> {
    let trimmed = path.trim_start_matches('/').trim_end_matches('/');
    let segments: Vec<&str> = trimmed.split('/').collect();
    // Metadata/content: 10 segments. Thumbnail: 11 segments.
    if segments.len() != 10 && segments.len() != 11 {
        return Err(RoutePathError::Malformed);
    }
    if segments[0] != "api"
        || segments[1] != "cockpit"
        || segments[2] != "v1"
        || segments[3] != "instances"
        || segments[5] != "sessions"
        || segments[7] != "image-artifacts"
    {
        return Err(RoutePathError::Malformed);
    }
    let instance_id = segments[4];
    let session_id = segments[6];
    let artifact_id = segments[8];
    // instanceId/sessionId accept either the 22-char alias or lowercase
    // hyphenated UUID codec (dependency-owned).
    if !validate_base64url_id_22(instance_id) && !validate_uuid_lowercase_hyphenated(instance_id) {
        return Err(RoutePathError::Malformed);
    }
    if !validate_base64url_id_22(session_id) && !validate_uuid_lowercase_hyphenated(session_id) {
        return Err(RoutePathError::Malformed);
    }
    if parse_artifact_id(artifact_id).is_none() {
        return Err(RoutePathError::Malformed);
    }
    if segments.len() == 10 {
        let route = match segments[9] {
            "metadata" => ImageArtifactRouteKind::Metadata,
            "content" => ImageArtifactRouteKind::Content,
            _ => return Err(RoutePathError::Malformed),
        };
        return Ok(ImageArtifactRoutePath {
            instance_id: instance_id.to_string(),
            session_id: session_id.to_string(),
            artifact_id: artifact_id.to_string(),
            route,
            thumbnail_box: None,
        });
    }
    // len == 11: thumbnails/{box}
    if segments[9] != "thumbnails" {
        return Err(RoutePathError::Malformed);
    }
    let box_size = match parse_thumbnail_box(segments[10]) {
        Some(b) => b,
        None => return Err(RoutePathError::Malformed),
    };
    Ok(ImageArtifactRoutePath {
        instance_id: instance_id.to_string(),
        session_id: session_id.to_string(),
        artifact_id: artifact_id.to_string(),
        route: ImageArtifactRouteKind::Thumbnail,
        thumbnail_box: Some(box_size),
    })
}

// ---------------------------------------------------------------------------
// Range header parsing (strict single-range grammar)
// ---------------------------------------------------------------------------

/// A satisfiable single byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SatisfiableRange {
    pub start: u64,
    pub end: u64,
}

/// Parsed range request against a known authorized length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedRange {
    /// No Range header: full content.
    Full,
    /// One satisfiable range.
    Satisfiable(SatisfiableRange),
    /// Malformed, multiple, non-bytes, overflow, or unsatisfiable.
    NotSatisfiable,
}

/// Parse a `Range` header value against an authorized full length using the
/// strict single-range grammar: `bytes=start-end`, `bytes=start-`, or
/// `bytes=-suffix_length`.
///
/// Rejects: comma/multiple ranges, whitespace outside the fixed grammar,
/// non-`bytes` unit, signs, leading plus, empty digits, overflow, zero
/// suffix, reverse (end before start), start at/after length, or any
/// unsatisfiable form.
pub fn parse_range_header(value: Option<&str>, authorized_length: u64) -> ParsedRange {
    let Some(value) = value else {
        return ParsedRange::Full;
    };
    parse_range_text(value, authorized_length)
}

fn parse_range_text(text: &str, authorized_length: u64) -> ParsedRange {
    // Reject any comma (multiple ranges).
    if text.contains(',') {
        return ParsedRange::NotSatisfiable;
    }
    let bytes = text.as_bytes();
    // Must start with exactly "bytes=".
    if bytes.len() < 6 || &bytes[..6] != b"bytes=" {
        return ParsedRange::NotSatisfiable;
    }
    let spec = &text[6..];
    // No leading/trailing whitespace inside the spec, no internal whitespace.
    if spec != spec.trim() || spec.contains(char::is_whitespace) {
        return ParsedRange::NotSatisfiable;
    }
    // Must contain exactly one '-'.
    let dash_count = spec.bytes().filter(|&b| b == b'-').count();
    if dash_count != 1 {
        return ParsedRange::NotSatisfiable;
    }
    let (start_part, end_part) = spec.split_once('-').unwrap();
    // No signs, no leading plus, no empty-both.
    if start_part.is_empty() && end_part.is_empty() {
        return ParsedRange::NotSatisfiable;
    }
    if start_part.starts_with('+')
        || start_part.starts_with('-')
        || end_part.starts_with('+')
        || end_part.starts_with('-')
    {
        return ParsedRange::NotSatisfiable;
    }
    // Only ASCII digits allowed.
    if !start_part.is_empty() && !start_part.bytes().all(|b| b.is_ascii_digit()) {
        return ParsedRange::NotSatisfiable;
    }
    if !end_part.is_empty() && !end_part.bytes().all(|b| b.is_ascii_digit()) {
        return ParsedRange::NotSatisfiable;
    }
    // Suffix form: bytes=-suffix
    if start_part.is_empty() {
        let suffix = match end_part.parse::<u64>() {
            Ok(v) => v,
            Err(_) => return ParsedRange::NotSatisfiable,
        };
        if suffix == 0 {
            return ParsedRange::NotSatisfiable;
        }
        if authorized_length == 0 {
            return ParsedRange::NotSatisfiable;
        }
        let start = authorized_length.saturating_sub(suffix);
        let end = authorized_length - 1;
        return ParsedRange::Satisfiable(SatisfiableRange { start, end });
    }
    // Open-ended: bytes=start-
    let start = match start_part.parse::<u64>() {
        Ok(v) => v,
        Err(_) => return ParsedRange::NotSatisfiable,
    };
    if start >= authorized_length && authorized_length > 0 {
        return ParsedRange::NotSatisfiable;
    }
    if authorized_length == 0 {
        return ParsedRange::NotSatisfiable;
    }
    let end = if end_part.is_empty() {
        authorized_length - 1
    } else {
        let end = match end_part.parse::<u64>() {
            Ok(v) => v,
            Err(_) => return ParsedRange::NotSatisfiable,
        };
        if end < start {
            return ParsedRange::NotSatisfiable;
        }
        // Clamp end to last byte.
        end.min(authorized_length - 1)
    };
    ParsedRange::Satisfiable(SatisfiableRange { start, end })
}

// ---------------------------------------------------------------------------
// Daemon protocol types
// ---------------------------------------------------------------------------

/// The four exhaustive daemon request tags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tag", rename_all = "snake_case")]
pub enum ImageArtifactDaemonRequestV1 {
    ImageArtifactMetadata {
        #[serde(rename = "schemaVersion")]
        schema_version: u8,
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "sessionId")]
        session_id: String,
        #[serde(rename = "artifactId")]
        artifact_id: String,
    },
    ImageArtifactDownload {
        #[serde(rename = "schemaVersion")]
        schema_version: u8,
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "sessionId")]
        session_id: String,
        #[serde(rename = "artifactId")]
        artifact_id: String,
        #[serde(
            rename = "rangeHeader",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        range_header: Option<String>,
    },
    ImageArtifactThumbnail {
        #[serde(rename = "schemaVersion")]
        schema_version: u8,
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "sessionId")]
        session_id: String,
        #[serde(rename = "artifactId")]
        artifact_id: String,
        box_size: u32,
        #[serde(
            rename = "rangeHeader",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        range_header: Option<String>,
    },
    ImageArtifactTransferCancel {
        #[serde(rename = "schemaVersion")]
        schema_version: u8,
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "transferId")]
        transfer_id: String,
    },
}

impl ImageArtifactDaemonRequestV1 {
    /// Whether this tag is a read-only operation (the first three tags).
    pub fn is_read_only(&self) -> bool {
        !matches!(self, Self::ImageArtifactTransferCancel { .. })
    }

    /// The request ID of this tag.
    pub fn request_id(&self) -> &str {
        match self {
            Self::ImageArtifactMetadata { request_id, .. }
            | Self::ImageArtifactDownload { request_id, .. }
            | Self::ImageArtifactThumbnail { request_id, .. }
            | Self::ImageArtifactTransferCancel { request_id, .. } => request_id,
        }
    }

    /// The schema version.
    pub fn schema_version(&self) -> u8 {
        match self {
            Self::ImageArtifactMetadata { schema_version, .. }
            | Self::ImageArtifactDownload { schema_version, .. }
            | Self::ImageArtifactThumbnail { schema_version, .. }
            | Self::ImageArtifactTransferCancel { schema_version, .. } => *schema_version,
        }
    }
}

/// Validate a daemon request's opaque IDs and schema version. Returns `false`
/// for unknown fields, wrong schema version, non-22-char IDs, zero IDs, or an
/// invalid thumbnail box.
pub fn validate_daemon_request(request: &ImageArtifactDaemonRequestV1) -> bool {
    if request.schema_version() != IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION {
        return false;
    }
    match request {
        ImageArtifactDaemonRequestV1::ImageArtifactMetadata {
            request_id,
            session_id,
            artifact_id,
            ..
        } => {
            validate_base64url_id_22(request_id)
                && parse_artifact_id(artifact_id).is_some()
                && (validate_base64url_id_22(session_id)
                    || validate_uuid_lowercase_hyphenated(session_id))
        }
        ImageArtifactDaemonRequestV1::ImageArtifactDownload {
            request_id,
            session_id,
            artifact_id,
            range_header,
            ..
        } => {
            validate_base64url_id_22(request_id)
                && parse_artifact_id(artifact_id).is_some()
                && (validate_base64url_id_22(session_id)
                    || validate_uuid_lowercase_hyphenated(session_id))
                && range_header.as_ref().map_or(true, |r| {
                    r.len() <= MAX_RANGE_HEADER_BYTES && r.bytes().all(|b| b.is_ascii())
                })
        }
        ImageArtifactDaemonRequestV1::ImageArtifactThumbnail {
            request_id,
            session_id,
            artifact_id,
            box_size,
            range_header,
            ..
        } => {
            validate_base64url_id_22(request_id)
                && parse_artifact_id(artifact_id).is_some()
                && (validate_base64url_id_22(session_id)
                    || validate_uuid_lowercase_hyphenated(session_id))
                && THUMBNAIL_BOXES.contains(box_size)
                && range_header.as_ref().map_or(true, |r| {
                    r.len() <= MAX_RANGE_HEADER_BYTES && r.bytes().all(|b| b.is_ascii())
                })
        }
        ImageArtifactDaemonRequestV1::ImageArtifactTransferCancel {
            request_id,
            transfer_id,
            ..
        } => validate_base64url_id_22(request_id) && validate_base64url_id_22(transfer_id),
    }
}

// ---------------------------------------------------------------------------
// Daemon reply types
// ---------------------------------------------------------------------------

/// The exact daemon error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageArtifactDaemonErrorCode {
    Malformed,
    ArtifactUnavailable,
    ThumbnailUnavailableForFormat,
    ThumbnailUnavailable,
    RangeNotSatisfiable,
    ThumbnailCapacity,
    Internal,
}

impl ImageArtifactDaemonErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::ArtifactUnavailable => "artifact_unavailable",
            Self::ThumbnailUnavailableForFormat => "thumbnail_unavailable_for_format",
            Self::ThumbnailUnavailable => "thumbnail_unavailable",
            Self::RangeNotSatisfiable => "range_not_satisfiable",
            Self::ThumbnailCapacity => "thumbnail_capacity",
            Self::Internal => "internal",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "malformed" => Some(Self::Malformed),
            "artifact_unavailable" => Some(Self::ArtifactUnavailable),
            "thumbnail_unavailable_for_format" => Some(Self::ThumbnailUnavailableForFormat),
            "thumbnail_unavailable" => Some(Self::ThumbnailUnavailable),
            "range_not_satisfiable" => Some(Self::RangeNotSatisfiable),
            "thumbnail_capacity" => Some(Self::ThumbnailCapacity),
            "internal" => Some(Self::Internal),
            _ => None,
        }
    }
}

/// The daemon error projection with strict `authorizedLength` nullability.
///
/// `authorizedLength` is a canonical decimal `u64` string exactly for
/// `range_not_satisfiable` returned by the authorized full-content route, is
/// exactly null for `range_not_satisfiable` on the authorized thumbnail route,
/// and is exactly null for every other code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageArtifactDaemonErrorV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,
    pub code: ImageArtifactDaemonErrorCode,
    /// Canonical decimal u64 string or null per the strict nullability rules.
    #[serde(rename = "authorizedLength")]
    pub authorized_length: Option<String>,
}

impl ImageArtifactDaemonErrorV1 {
    /// Create an error with null `authorizedLength` (every non-range code, or
    /// thumbnail range).
    pub fn null_length(code: ImageArtifactDaemonErrorCode) -> Self {
        Self {
            schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
            code,
            authorized_length: None,
        }
    }

    /// Create an authorized content range error with the exact authorized
    /// full length.
    pub fn content_range(authorized_length: u64) -> Self {
        Self {
            schema_version: IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION,
            code: ImageArtifactDaemonErrorCode::RangeNotSatisfiable,
            authorized_length: Some(authorized_length.to_string()),
        }
    }

    /// Create an authorized thumbnail range error with null length.
    pub fn thumbnail_range() -> Self {
        Self::null_length(ImageArtifactDaemonErrorCode::RangeNotSatisfiable)
    }

    /// Validate the strict `authorizedLength` nullability pairing.
    ///
    /// A content-range error with null length, a thumbnail-range error with
    /// nonnull length, or any non-range error with nonnull length is malformed.
    pub fn validate_nullability(&self, is_thumbnail: bool) -> bool {
        if self.schema_version != IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION {
            return false;
        }
        match self.code {
            ImageArtifactDaemonErrorCode::RangeNotSatisfiable => {
                if is_thumbnail {
                    self.authorized_length.is_none()
                } else {
                    self.authorized_length
                        .as_ref()
                        .map_or(false, |s| validate_canonical_decimal(s))
                }
            }
            _ => self.authorized_length.is_none(),
        }
    }
}

/// The metadata reply value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageArtifactMetadataV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,
    #[serde(rename = "artifactId")]
    pub artifact_id: String,
    #[serde(rename = "artifactGeneration")]
    pub artifact_generation: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "jobGeneration")]
    pub job_generation: String,
    #[serde(rename = "slotId")]
    pub slot_id: String,
    #[serde(rename = "slotGeneration")]
    pub slot_generation: String,
    #[serde(rename = "publishedDisposition")]
    pub published_disposition: String,
    #[serde(rename = "publishedDispositionGeneration")]
    pub published_disposition_generation: String,
    #[serde(rename = "mediaKind")]
    pub media_kind: String,
    pub width: u32,
    pub height: u32,
    #[serde(rename = "byteLength")]
    pub byte_length: String,
    pub checksum: String,
    #[serde(rename = "availableThumbnailBoxes")]
    pub available_thumbnail_boxes: Vec<u32>,
}

impl ImageArtifactMetadataV1 {
    /// Validate the metadata value's field codecs and bounds.
    pub fn validate(&self) -> bool {
        if self.schema_version != IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION {
            return false;
        }
        if parse_artifact_id(&self.artifact_id).is_none() {
            return false;
        }
        if !validate_canonical_decimal(&self.artifact_generation)
            || !validate_canonical_decimal(&self.job_generation)
            || !validate_canonical_decimal(&self.slot_generation)
            || !validate_canonical_decimal(&self.published_disposition_generation)
            || !validate_canonical_decimal(&self.byte_length)
        {
            return false;
        }
        if !(validate_base64url_id_22(&self.job_id)
            || validate_uuid_lowercase_hyphenated(&self.job_id))
        {
            return false;
        }
        if !(validate_base64url_id_22(&self.slot_id)
            || validate_uuid_lowercase_hyphenated(&self.slot_id))
        {
            return false;
        }
        if self.published_disposition != "ordinary"
            && self.published_disposition != "late_authorized"
        {
            return false;
        }
        if self.width == 0 || self.height == 0 {
            return false;
        }
        if !validate_sha256_hex(&self.checksum) {
            return false;
        }
        // Boxes ascending and unique.
        if self.available_thumbnail_boxes.len() > THUMBNAIL_BOXES.len() {
            return false;
        }
        let mut prev = 0u32;
        for &b in &self.available_thumbnail_boxes {
            if !THUMBNAIL_BOXES.contains(&b) || b <= prev {
                return false;
            }
            prev = b;
        }
        true
    }
}

/// The pending-thumbnail reply value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageThumbnailPendingV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,
    pub state: String,
    #[serde(rename = "artifactId")]
    pub artifact_id: String,
    #[serde(rename = "artifactGeneration")]
    pub artifact_generation: String,
    pub box_size: u32,
    #[serde(rename = "workGeneration")]
    pub work_generation: String,
    #[serde(rename = "retryAfterMs")]
    pub retry_after_ms: u32,
}

impl ImageThumbnailPendingV1 {
    pub fn validate(&self) -> bool {
        self.schema_version == IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION
            && self.state == THUMBNAIL_PENDING_STATE
            && parse_artifact_id(&self.artifact_id).is_some()
            && validate_canonical_decimal(&self.artifact_generation)
            && validate_canonical_decimal(&self.work_generation)
            && THUMBNAIL_BOXES.contains(&self.box_size)
            && self.retry_after_ms == THUMBNAIL_PENDING_RETRY_AFTER_MS
    }
}

/// The transfer-cancel reply value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageArtifactTransferCancelResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,
    #[serde(rename = "transferId")]
    pub transfer_id: String,
    pub state: TransferCancelState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferCancelState {
    Cancelled,
    AlreadyTerminal,
}

impl ImageArtifactTransferCancelResultV1 {
    pub fn validate(&self) -> bool {
        self.schema_version == IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION
            && validate_base64url_id_22(&self.transfer_id)
    }
}

/// The read head emitted only after authorization, held-handle proof, full
/// checksum, and lease commit all succeed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageArtifactReadHeadV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "transferId")]
    pub transfer_id: String,
    pub status: u16,
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(rename = "contentDisposition")]
    pub content_disposition: String,
    #[serde(rename = "cacheControl")]
    pub cache_control: String,
    pub nosniff: String,
    #[serde(
        rename = "contentSecurityPolicy",
        skip_serializing_if = "Option::is_none"
    )]
    pub content_security_policy: Option<String>,
    #[serde(rename = "contentLength")]
    pub content_length: String,
    #[serde(rename = "contentRange", skip_serializing_if = "Option::is_none")]
    pub content_range: Option<String>,
    pub etag: String,
    #[serde(rename = "artifactId")]
    pub artifact_id: String,
    #[serde(rename = "artifactGeneration")]
    pub artifact_generation: String,
    #[serde(rename = "componentGeneration")]
    pub component_generation: String,
    #[serde(rename = "leaseDeadlineMs")]
    pub lease_deadline_ms: String,
}

impl ImageArtifactReadHeadV1 {
    /// Validate the read head's constant values and field codecs.
    pub fn validate(&self, is_svg: bool) -> bool {
        if self.schema_version != IMAGE_ARTIFACT_ROUTE_SCHEMA_VERSION {
            return false;
        }
        if !validate_base64url_id_22(&self.request_id)
            || !validate_base64url_id_22(&self.transfer_id)
        {
            return false;
        }
        if self.status != 200 && self.status != 206 {
            return false;
        }
        if self.cache_control != ARTIFACT_CACHE_CONTROL || self.nosniff != ARTIFACT_NOSNIFF {
            return false;
        }
        if !validate_canonical_decimal(&self.content_length)
            || !validate_canonical_decimal(&self.artifact_generation)
            || !validate_canonical_decimal(&self.component_generation)
            || !validate_canonical_decimal(&self.lease_deadline_ms)
        {
            return false;
        }
        // leaseDeadlineMs is 1..=60000.
        let lease = self.lease_deadline_ms.parse::<u64>().unwrap_or(0);
        if !(LEASE_DEADLINE_MIN_MS..=LEASE_DEADLINE_MAX_MS).contains(&lease) {
            return false;
        }
        if parse_artifact_id(&self.artifact_id).is_none() {
            return false;
        }
        // ETag is the quoted lowercase full SHA-256.
        if !self.etag.starts_with('"') || !self.etag.ends_with('"') || self.etag.len() != 66 {
            return false;
        }
        let inner = &self.etag[1..self.etag.len() - 1];
        if !validate_sha256_hex(inner) {
            return false;
        }
        // CSP is the exact SVG policy and otherwise null.
        if is_svg {
            if self.content_security_policy.as_deref() != Some(SVG_CONTENT_SECURITY_POLICY) {
                return false;
            }
            if self.content_type != CONTENT_TYPE_SVG {
                return false;
            }
        } else if self.content_security_policy.is_some() {
            return false;
        }
        // contentRange present exactly for 206.
        if self.status == 206 && self.content_range.is_none() {
            return false;
        }
        if self.status == 200 && self.content_range.is_some() {
            return false;
        }
        true
    }
}

/// The daemon reply outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImageArtifactDaemonOutcomeV1 {
    Metadata {
        value: ImageArtifactMetadataV1,
    },
    Read {
        head: ImageArtifactReadHeadV1,
    },
    ThumbnailPending {
        value: ImageThumbnailPendingV1,
    },
    Cancelled {
        value: ImageArtifactTransferCancelResultV1,
    },
    Error {
        error: ImageArtifactDaemonErrorV1,
    },
}

/// The daemon reply envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageArtifactDaemonReplyV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u8,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub outcome: ImageArtifactDaemonOutcomeV1,
}

// ---------------------------------------------------------------------------
// HTTP error mapping
// ---------------------------------------------------------------------------

/// The HTTP status code for a daemon error code under the precedence table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpErrorResponse {
    pub status: u16,
    /// Whether the response has a JSON body.
    pub has_body: bool,
    /// The `Content-Range` header value, if any (for 416).
    pub content_range: Option<&'static str>,
    /// The `Retry-After` header value, if any.
    pub retry_after: Option<u32>,
}

/// The exact HTTP status mapping for a daemon error code. The
/// `is_thumbnail_route` flag selects between the content-range and
/// thumbnail-range 416 `Content-Range` shapes.
pub fn http_error_response(
    code: ImageArtifactDaemonErrorCode,
    is_thumbnail_route: bool,
) -> HttpErrorResponse {
    match code {
        ImageArtifactDaemonErrorCode::Malformed => HttpErrorResponse {
            status: 400,
            has_body: true,
            content_range: None,
            retry_after: None,
        },
        ImageArtifactDaemonErrorCode::ArtifactUnavailable => HttpErrorResponse {
            status: 404,
            has_body: true,
            content_range: None,
            retry_after: None,
        },
        ImageArtifactDaemonErrorCode::ThumbnailUnavailableForFormat
        | ImageArtifactDaemonErrorCode::ThumbnailUnavailable => HttpErrorResponse {
            status: 409,
            has_body: true,
            content_range: None,
            retry_after: None,
        },
        ImageArtifactDaemonErrorCode::RangeNotSatisfiable => {
            if is_thumbnail_route {
                HttpErrorResponse {
                    status: 416,
                    has_body: false,
                    content_range: Some("bytes */*"),
                    retry_after: None,
                }
            } else {
                // Content-range 416 carries the authorized length in the
                // Content-Range header, set by the caller.
                HttpErrorResponse {
                    status: 416,
                    has_body: false,
                    content_range: None,
                    retry_after: None,
                }
            }
        }
        ImageArtifactDaemonErrorCode::ThumbnailCapacity => HttpErrorResponse {
            status: 503,
            has_body: true,
            content_range: None,
            retry_after: Some(THUMBNAIL_CAPACITY_RETRY_AFTER_SECONDS),
        },
        ImageArtifactDaemonErrorCode::Internal => HttpErrorResponse {
            status: 500,
            has_body: false,
            content_range: None,
            retry_after: None,
        },
    }
}

/// Build the `Content-Range` header for a content-range 416 with the exact
/// authorized full length.
pub fn content_range_unsatisfiable(authorized_length: u64) -> String {
    format!("bytes */{authorized_length}")
}

// ---------------------------------------------------------------------------
// Redaction / filename map
// ---------------------------------------------------------------------------

/// The exact `Content-Disposition` for a validated raster download format.
pub fn raster_download_disposition(media_kind: &str) -> Option<&'static str> {
    match media_kind {
        "image/png" | "png" => Some(RASTER_DOWNLOAD_FILENAME_PNG),
        "image/jpeg" | "jpeg" | "jpg" => Some(RASTER_DOWNLOAD_FILENAME_JPEG),
        "image/webp" | "webp" => Some(RASTER_DOWNLOAD_FILENAME_WEBP),
        _ => None,
    }
}

/// The exact `Content-Disposition` attachment header for a validated raster
/// download.
pub fn raster_download_content_disposition(media_kind: &str) -> Option<String> {
    raster_download_disposition(media_kind).map(|name| format!("attachment; filename=\"{name}\""))
}

/// The exact `Content-Disposition` inline header for a raster thumbnail.
pub fn thumbnail_content_disposition() -> String {
    format!("attachment; filename=\"{RASTER_THUMBNAIL_FILENAME}\"")
}

/// The exact `Content-Disposition` attachment header for sanitized SVG.
pub fn svg_content_disposition() -> String {
    format!("attachment; filename=\"{SVG_DOWNLOAD_FILENAME}\"")
}

/// The exact `Content-Type` for a validated media kind.
pub fn content_type_for_media_kind(media_kind: &str) -> Option<&'static str> {
    match media_kind {
        "image/png" | "png" => Some(CONTENT_TYPE_PNG),
        "image/jpeg" | "jpeg" | "jpg" => Some(CONTENT_TYPE_JPEG),
        "image/webp" | "webp" => Some(CONTENT_TYPE_WEBP),
        "image/svg+xml" | "svg" => Some(CONTENT_TYPE_SVG),
        _ => None,
    }
}

/// Whether a media kind is a validated raster format eligible for full
/// download with Range support.
pub fn is_validated_raster(media_kind: &str) -> bool {
    matches!(
        media_kind,
        "image/png" | "png" | "image/jpeg" | "jpeg" | "jpg" | "image/webp" | "webp"
    )
}

/// Whether a media kind is sanitized SVG.
pub fn is_sanitized_svg(media_kind: &str) -> bool {
    matches!(media_kind, "image/svg+xml" | "svg")
}

// ---------------------------------------------------------------------------
// Thumbnail dimension arithmetic (no upscale)
// ---------------------------------------------------------------------------

/// Compute the thumbnail output dimensions for source `w,h` and box `b`.
/// No upscale: `out=(w,h)` when both fit; otherwise
/// `w>=h -> (b,max(1,floor(h*b/w)))` and `h>w -> (max(1,floor(w*b/h)),b)`.
/// All products are checked.
pub fn thumbnail_output_dimensions(width: u32, height: u32, box_size: u32) -> Option<(u32, u32)> {
    if width == 0 || height == 0 || box_size == 0 {
        return None;
    }
    if width <= box_size && height <= box_size {
        return Some((width, height));
    }
    if width >= height {
        let out_w = box_size;
        let scaled = (u64::from(height))
            .checked_mul(u64::from(box_size))?
            .checked_div(u64::from(width))?;
        let out_h = scaled.max(1) as u32;
        Some((out_w, out_h))
    } else {
        let out_h = box_size;
        let scaled = (u64::from(width))
            .checked_mul(u64::from(box_size))?
            .checked_div(u64::from(height))?;
        let out_w = scaled.max(1) as u32;
        Some((out_w, out_h))
    }
}

/// Compute the fixed-point source coordinate for destination coordinate `x`.
/// `sx=floor(((2*x+1)*source_width*65536)/(2*out_width))-32768`, clamped to
/// `[0,(source_width-1)*65536]`.
pub fn bilinear_source_coordinate(x: u32, source_width: u32, out_width: u32) -> Option<(u32, u32)> {
    if out_width == 0 || source_width == 0 {
        return None;
    }
    let numerator = (u64::from(2u32)
        .checked_mul(u64::from(x))?
        .checked_add(1u64)?
        .checked_mul(u64::from(source_width))?
        .checked_mul(65536u64)?)
    .checked_div(u64::from(2u32).checked_mul(u64::from(out_width))?)?;
    let sx_raw = numerator.saturating_sub(32768u64);
    let max_sx = u64::from(source_width.saturating_sub(1)).saturating_mul(65536u64);
    let sx = sx_raw.clamp(0, max_sx);
    let ix = u32::try_from(sx / 65536).ok()?;
    let fx = u32::try_from(sx % 65536).ok()?;
    Some((ix, fx))
}

/// Premultiply a color channel: `pc=(c*a+127)/255`.
pub fn premultiply_color(c: u8, a: u8) -> u16 {
    (u16::from(c) * u16::from(a) + 127) / 255
}

/// Unpremultiply a color channel: `min(255,(pc*255+alpha/2)/alpha)`.
pub fn unpremultiply_color(pc: u16, alpha: u16) -> u8 {
    if alpha == 0 {
        return 0;
    }
    let v = (u32::from(pc) * 255 + u32::from(alpha) / 2) / u32::from(alpha);
    v.min(255) as u8
}

#[cfg(test)]
mod tests;
