//! Typed media tool-result transport: canonical schema, resolver, and Rig mappings.
//!
//! This module defines the one canonical media-bearing tool-result union that
//! sits above Rig's provider-specific `ToolResultContent` / `UserContent`. Tools
//! return opaque session references durably; provider adapters receive bytes
//! only after final authority/capability checks.
//!
//! ## Architecture
//!
//! ```text
//!  Tool output
//!      │
//!      ▼
//!  CanonicalToolResultContent  (Text | Json | MediaReference)   ← durable, persisted, protocol
//!      │
//!      ▼
//!  MediaReferenceResolver  ← checks session/project authority,
//!      │                     attachment identity/availability,
//!      │                     normalized-derivative status, lease,
//!      │                     model capability, primary/sidecar route
//!      │
//!      ▼
//!  ProviderRigMapping  ← builds transient Rig messages (bytes only here)
//!      │
//!      ▼
//!  rig::message::{ToolResult, UserContent}  ← transient, excluded from durable recording
//! ```
//!
//! Raw base64/data URLs/signed URLs/host paths are invalid `Text`/`Json`
//! result content. Missing/unavailable/changed/cross-session references fail
//! `media_reference_unavailable` before any provider request.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Canonical schema
// ---------------------------------------------------------------------------

/// Schema version tag for the canonical tool-result content union. Bumped only
/// on a wire-incompatible change to [`CanonicalToolResultContent`].
pub const CANONICAL_TOOL_RESULT_SCHEMA_VERSION: u8 = 1;

/// The one canonical media-bearing tool-result content union.
///
/// Persist/daemon/protocol/TypeScript always carry this union and never
/// bytes/paths/provider URLs. Immediately before provider dispatch, a
/// [`MediaReferenceResolver`] checks authority, availability, capability, and
/// route, then maps to transient Rig/provider messages.
///
/// `Text` and `Json` variants preserve the existing text/JSON tool-result
/// behavior. `MediaReference` is the new opaque-reference variant.
///
/// # Serialization
///
/// Serialized as a tagged union with a `kind` discriminator and `camelCase`
/// field names. Unknown variants are rejected (`deny_unknown_fields`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CanonicalToolResultContent {
    /// Literal text. Providers must not reinterpret it as structured JSON.
    Text {
        /// The text body.
        text: String,
    },
    /// Structured JSON supplied explicitly by the tool runtime.
    Json {
        /// The structured value.
        value: serde_json::Value,
    },
    /// An opaque reference to a retained media attachment. Contains no bytes,
    /// paths, provider URLs, or data URLs — only an attachment ID plus safe
    /// metadata. Session/project binding is authorization metadata carried
    /// alongside the reference at resolution time; it is never client-selectable
    /// from within the reference itself.
    MediaReference {
        #[serde(flatten)]
        reference: MediaReference,
    },
}

impl CanonicalToolResultContent {
    /// Construct a text variant.
    pub fn text(body: impl Into<String>) -> Self {
        Self::Text { text: body.into() }
    }

    /// Construct a JSON variant.
    pub fn json(value: serde_json::Value) -> Self {
        Self::Json { value }
    }

    /// Construct a media-reference variant.
    pub fn media_reference(reference: MediaReference) -> Self {
        Self::MediaReference { reference }
    }

    /// Borrow the text body if this is a `Text` variant.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text { text } => Some(text),
            _ => None,
        }
    }

    /// Borrow the JSON value if this is a `Json` variant.
    pub fn as_json(&self) -> Option<&serde_json::Value> {
        match self {
            Self::Json { value } => Some(value),
            _ => None,
        }
    }

    /// Borrow the media reference if this is a `MediaReference` variant.
    pub fn as_media_reference(&self) -> Option<&MediaReference> {
        match self {
            Self::MediaReference { reference } => Some(reference),
            _ => None,
        }
    }

    /// The ordinal position used for stable ordering. `(tool result content
    /// ordinal)` is the stable order; adjacent provider media preserves that
    /// order and tool-call ID.
    pub fn ordinal(&self) -> u32 {
        match self {
            Self::Text { .. } => 0,
            Self::Json { .. } => 1,
            Self::MediaReference { reference } => reference.ordinal,
        }
    }

    /// Returns `true` if this variant carries a media reference (not text/JSON).
    pub fn is_media_reference(&self) -> bool {
        matches!(self, Self::MediaReference { .. })
    }

    /// Validate that text/JSON content does not contain forbidden inline media
    /// sentinels (base64 data URLs, signed URLs, host paths, raw media bytes).
    ///
    /// Raw base64/data URLs/signed URLs/host paths are invalid `Text`/`Json`
    /// result content.
    pub fn validate_no_inline_media(&self) -> Result<(), MediaReferenceError> {
        match self {
            Self::Text { text } => {
                reject_inline_media_text(text)?;
                Ok(())
            }
            Self::Json { value } => {
                reject_inline_media_json(value)?;
                Ok(())
            }
            Self::MediaReference { .. } => Ok(()),
        }
    }
}

/// The media kind (image, audio, video). This is the sole canonical
/// [`cockpit_db::media_attachments::MediaKind`] discriminant; the
/// `CanonicalMediaKind` alias is retained for path stability and carries the
/// same `snake_case` serde form and FCM2 wire codes as storage/FCM2.
pub use cockpit_db::media_attachments::MediaKind as CanonicalMediaKind;

/// The availability state of a media reference at the time it was recorded.
/// This is a snapshot — the resolver re-checks live availability before
/// dispatch. A reference whose live availability no longer matches (or has
/// degraded) fails `media_reference_unavailable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaReferenceAvailability {
    /// The attachment was ready at recording time.
    Ready,
    /// The attachment was in a processing pipeline at recording time.
    Processing,
    /// The attachment was unavailable at recording time (kept for replay
    /// fidelity; the resolver will reject before dispatch).
    Unavailable,
}

/// The purpose of a media reference within a tool result. Drives routing
/// decisions (e.g. sidecar vs primary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaReferencePurpose {
    /// Primary content for the model.
    Primary,
    /// Sidecar content resolved by the sidecar service in an isolated
    /// media-only request.
    Sidecar,
    /// Reference content for context (not dispatched as bytes).
    Contextual,
}

/// Known image dimensions, when available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaDimensions {
    pub width: u32,
    pub height: u32,
}

/// Known media duration in milliseconds, when available (audio/video).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaDurationMs(pub u64);

/// Sanitized provenance metadata. Contains no raw paths, URLs, or credentials.
/// `tool_name` is the tool that produced the reference; `source_label` is a
/// sanitized, human-readable label (e.g. "screenshot", "generated image").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaProvenance {
    pub tool_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_label: Option<String>,
}

/// An opaque reference to a retained media attachment.
///
/// Contains the attachment ID, media kind/MIME, ordinal, purpose, checksum,
/// byte count, dimensions/duration when known, availability snapshot, and
/// sanitized provenance. Session/project binding is authorization metadata
/// supplied at resolution time (via [`MediaReferenceAuthContext`]); it is
/// never client-selectable from within the reference.
///
/// This type is serializable (persisted, protocol, TypeScript). Resolved
/// bytes and leases are a separate non-serializable type
/// ([`ResolvedMediaBytes`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaReference {
    /// Opaque attachment ID (UUIDv7). Never a path, URL, or data URL.
    #[serde(with = "strict_uuid_v7")]
    pub attachment_id: Uuid,
    /// Attachment version at recording time. The resolver verifies this
    /// matches the live version; a mismatch means the source changed.
    pub attachment_version: u64,
    /// Media kind (image, audio, video).
    pub media_kind: CanonicalMediaKind,
    /// Canonical MIME type (e.g. "image/png", "audio/wav", "video/mp4").
    pub mime_type: String,
    /// Stable ordinal position within the tool result content list. Used for
    /// deterministic ordering of adjacent provider media.
    pub ordinal: u32,
    /// Purpose (primary, sidecar, contextual).
    pub purpose: MediaReferencePurpose,
    /// SHA-256 checksum (hex lowercase) of the canonical/normalized derivative.
    pub checksum: String,
    /// Byte count of the canonical/normalized derivative.
    pub byte_count: u64,
    /// Image dimensions, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dimensions: Option<MediaDimensions>,
    /// Audio/video duration in milliseconds, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<MediaDurationMs>,
    /// Availability snapshot at recording time. The resolver re-checks live
    /// availability before dispatch.
    pub availability: MediaReferenceAvailability,
    /// Sanitized provenance (no raw paths/URLs/credentials).
    pub provenance: MediaProvenance,
}

impl MediaReference {
    /// Construct a new media reference with the required fields. Optional
    /// fields (dimensions, duration) default to `None`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        attachment_id: Uuid,
        attachment_version: u64,
        media_kind: CanonicalMediaKind,
        mime_type: impl Into<String>,
        ordinal: u32,
        purpose: MediaReferencePurpose,
        checksum: impl Into<String>,
        byte_count: u64,
        availability: MediaReferenceAvailability,
        provenance: MediaProvenance,
    ) -> Self {
        Self {
            attachment_id,
            attachment_version,
            media_kind,
            mime_type: mime_type.into(),
            ordinal,
            purpose,
            checksum: checksum.into(),
            byte_count,
            dimensions: None,
            duration_ms: None,
            availability,
            provenance,
        }
    }

    /// Attach image dimensions.
    pub fn with_dimensions(mut self, width: u32, height: u32) -> Self {
        self.dimensions = Some(MediaDimensions { width, height });
        self
    }

    /// Attach audio/video duration.
    pub fn with_duration_ms(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(MediaDurationMs(duration_ms));
        self
    }
}

// ---------------------------------------------------------------------------
// Authorization context (non-serializable, supplied at resolution time)
// ---------------------------------------------------------------------------

/// Authorization context for resolving a media reference. Session/project
/// binding is authorization metadata — it is never client-selectable from
/// within the reference itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaReferenceAuthContext {
    pub session_id: Uuid,
    pub canonical_project_digest: String,
}

/// The route selected for a media reference: primary (model receives bytes) or
/// sidecar (the canonical result remains a reference; the sidecar service
/// resolves it separately).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaRoute {
    Primary,
    Sidecar,
}

/// Model capability for media in tool results. The resolver uses this to
/// determine the correct Rig mapping. Unknown capability fails before dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelMediaCapability {
    /// Provider supports embedded image in tool results (e.g. Anthropic).
    ImageInToolResult,
    /// Provider does not support embedded image in tool results but supports
    /// image in user content (e.g. OpenAI Chat). Adjacent-content mapping.
    ImageInUserContent,
    /// Provider supports audio in user content (adjacent-content mapping).
    AudioInUserContent,
    /// Provider supports video in user content (adjacent-content mapping).
    VideoInUserContent,
    /// Provider capability is unknown — fail before dispatch.
    Unknown,
}

/// The capability profile for a model/provider at dispatch time. The resolver
/// checks each required capability; unknown capability fails.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ModelCapabilityProfile {
    pub image_in_tool_result: bool,
    pub image_in_user_content: bool,
    pub audio_in_user_content: bool,
    pub video_in_user_content: bool,
}

impl ModelCapabilityProfile {
    /// Resolve the capability for a given media kind and route.
    pub fn capability_for(
        &self,
        kind: CanonicalMediaKind,
        route: MediaRoute,
    ) -> ModelMediaCapability {
        match (kind, route) {
            (CanonicalMediaKind::Image, MediaRoute::Primary) => {
                if self.image_in_tool_result {
                    ModelMediaCapability::ImageInToolResult
                } else if self.image_in_user_content {
                    ModelMediaCapability::ImageInUserContent
                } else {
                    ModelMediaCapability::Unknown
                }
            }
            (CanonicalMediaKind::Image, MediaRoute::Sidecar) => {
                // Sidecar never sends bytes to the model; capability is not
                // constrained, but we still require the sidecar route to be
                // explicitly known.
                if self.image_in_tool_result || self.image_in_user_content {
                    ModelMediaCapability::ImageInToolResult
                } else {
                    ModelMediaCapability::Unknown
                }
            }
            (CanonicalMediaKind::Audio, MediaRoute::Primary) => {
                if self.audio_in_user_content {
                    ModelMediaCapability::AudioInUserContent
                } else {
                    ModelMediaCapability::Unknown
                }
            }
            (CanonicalMediaKind::Video, MediaRoute::Primary) => {
                if self.video_in_user_content {
                    ModelMediaCapability::VideoInUserContent
                } else {
                    ModelMediaCapability::Unknown
                }
            }
            (CanonicalMediaKind::Audio | CanonicalMediaKind::Video, MediaRoute::Sidecar) => {
                // Audio/video sidecar is not a supported route.
                ModelMediaCapability::Unknown
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Live attachment snapshot (supplied by the attachment resolver/lease layer)
// ---------------------------------------------------------------------------

/// Live availability states the resolver accepts as "dispatchable." Anything
/// else fails `media_reference_unavailable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveAttachmentAvailability {
    Ready,
    Processing,
    Deleted,
    SecurityBlocked,
    CleanupPending,
    SourceChanged,
    Failed,
}

impl LiveAttachmentAvailability {
    pub fn is_dispatchable(self) -> bool {
        self == Self::Ready
    }
}

/// A snapshot of the live attachment state at resolution time. Supplied by the
/// attachment resolver/lease layer; the canonical reference itself never
/// carries live state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveAttachmentSnapshot {
    pub attachment_id: Uuid,
    pub session_id: Uuid,
    pub canonical_project_digest: String,
    pub attachment_version: u64,
    pub availability: LiveAttachmentAvailability,
    /// Whether a normalized derivative exists (required for audio/video and
    /// for image adjacent-content mapping).
    pub has_normalized_derivative: bool,
    /// Whether a valid lease is currently held.
    pub lease_held: bool,
    pub media_kind: CanonicalMediaKind,
    pub mime_type: String,
}

/// The resolved bytes for a media reference. This is a non-serializable type —
/// it exists only transiently between the resolver and the provider adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMediaBytes {
    pub attachment_id: Uuid,
    pub media_kind: CanonicalMediaKind,
    pub mime_type: String,
    pub bytes: Vec<u8>,
    pub checksum: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// All errors from the media reference resolver. Every wrong-session/deleted/
/// changed/unavailable/unnormalized/capability-unknown branch fails before
/// provider transport with a typed error. They are never converted to a prose
/// placeholder and dispatched.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MediaReferenceError {
    #[error("media_reference_unavailable: attachment {attachment_id} not found")]
    NotFound { attachment_id: Uuid },

    #[error(
        "media_reference_unavailable: attachment {attachment_id} belongs to session {expected_session_id}, not {requested_session_id}"
    )]
    WrongSession {
        attachment_id: Uuid,
        requested_session_id: Uuid,
        expected_session_id: Uuid,
    },

    #[error(
        "media_reference_unavailable: attachment {attachment_id} belongs to project {expected_project_digest}, not {requested_project_digest}"
    )]
    WrongProject {
        attachment_id: Uuid,
        requested_project_digest: String,
        expected_project_digest: String,
    },

    #[error(
        "media_reference_unavailable: attachment {attachment_id} version changed (reference: {reference_version}, live: {live_version})"
    )]
    SourceChanged {
        attachment_id: Uuid,
        reference_version: u64,
        live_version: u64,
    },

    #[error("media_reference_unavailable: attachment {attachment_id} is deleted")]
    Deleted { attachment_id: Uuid },

    #[error("media_reference_unavailable: attachment {attachment_id} is security blocked")]
    SecurityBlocked { attachment_id: Uuid },

    #[error("media_reference_unavailable: attachment {attachment_id} is in cleanup pending state")]
    CleanupPending { attachment_id: Uuid },

    #[error("media_reference_unavailable: attachment {attachment_id} has failed processing")]
    Failed { attachment_id: Uuid },

    #[error(
        "media_reference_unavailable: attachment {attachment_id} is not ready (state: {live_state:?})"
    )]
    NotReady {
        attachment_id: Uuid,
        live_state: LiveAttachmentAvailability,
    },

    #[error("media_reference_unavailable: attachment {attachment_id} has no normalized derivative")]
    NotNormalized { attachment_id: Uuid },

    #[error("media_reference_unavailable: attachment {attachment_id} has no valid lease")]
    NoLease { attachment_id: Uuid },

    #[error(
        "media_reference_unavailable: capability unknown for media kind {media_kind:?} on route {route:?}"
    )]
    CapabilityUnknown {
        attachment_id: Uuid,
        media_kind: CanonicalMediaKind,
        route: MediaRoute,
    },

    #[error("media_reference_unavailable: inline media detected in text content")]
    InlineMediaInText,

    #[error("media_reference_unavailable: inline media detected in json content")]
    InlineMediaInJson,

    #[error("media_reference_unavailable: audio/video sidecar route is not supported")]
    AudioVideoSidecarUnsupported { attachment_id: Uuid },

    #[error("media_reference_unavailable: unknown provider mapping for capability {capability:?}")]
    UnknownProviderMapping {
        attachment_id: Uuid,
        capability: ModelMediaCapability,
    },
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

/// The result of resolving a [`CanonicalToolResultContent::MediaReference`].
/// Tells the provider adapter exactly which Rig mapping to use, with the
/// correlated tool-call ID and ordinal for stable ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMediaMapping {
    /// The tool-call ID this result answers (for correlation in adjacent
    /// content mapping).
    pub tool_call_id: String,
    /// The provider-specific call ID, when distinct.
    pub call_id: Option<String>,
    /// The ordinal position for stable ordering.
    pub ordinal: u32,
    /// The route (primary or sidecar).
    pub route: MediaRoute,
    /// The capability mapping to use.
    pub capability: ModelMediaCapability,
    /// The resolved bytes (present only for primary route; absent for sidecar).
    pub bytes: Option<ResolvedMediaBytes>,
}

/// The resolver checks session/project authority, attachment identity/
/// availability, normalized-derivative status, media lease, current model
/// capability, and selected primary/sidecar route. It must be called
/// immediately before provider dispatch.
pub struct MediaReferenceResolver<'a> {
    auth: &'a MediaReferenceAuthContext,
    capabilities: &'a ModelCapabilityProfile,
}

impl<'a> MediaReferenceResolver<'a> {
    pub fn new(
        auth: &'a MediaReferenceAuthContext,
        capabilities: &'a ModelCapabilityProfile,
    ) -> Self {
        Self { auth, capabilities }
    }

    /// Resolve a single media reference against a live attachment snapshot.
    /// Returns the mapping to use, or a typed error if any check fails.
    ///
    /// Every wrong-session/deleted/changed/unavailable/unnormalized/
    /// capability-unknown branch fails before provider transport.
    pub fn resolve(
        &self,
        reference: &MediaReference,
        live: &LiveAttachmentSnapshot,
        route: MediaRoute,
        tool_call_id: &str,
        call_id: Option<&str>,
    ) -> Result<ResolvedMediaMapping, MediaReferenceError> {
        // 1. Session/project authority check
        if live.session_id != self.auth.session_id {
            return Err(MediaReferenceError::WrongSession {
                attachment_id: reference.attachment_id,
                requested_session_id: self.auth.session_id,
                expected_session_id: live.session_id,
            });
        }
        if live.canonical_project_digest != self.auth.canonical_project_digest {
            return Err(MediaReferenceError::WrongProject {
                attachment_id: reference.attachment_id,
                requested_project_digest: self.auth.canonical_project_digest.clone(),
                expected_project_digest: live.canonical_project_digest.clone(),
            });
        }

        // 2. Attachment identity check (source changed)
        if live.attachment_id != reference.attachment_id {
            return Err(MediaReferenceError::NotFound {
                attachment_id: reference.attachment_id,
            });
        }
        if live.attachment_version != reference.attachment_version {
            return Err(MediaReferenceError::SourceChanged {
                attachment_id: reference.attachment_id,
                reference_version: reference.attachment_version,
                live_version: live.attachment_version,
            });
        }

        // 3. Availability check
        match live.availability {
            LiveAttachmentAvailability::Ready => {}
            LiveAttachmentAvailability::Deleted => {
                return Err(MediaReferenceError::Deleted {
                    attachment_id: reference.attachment_id,
                });
            }
            LiveAttachmentAvailability::SecurityBlocked => {
                return Err(MediaReferenceError::SecurityBlocked {
                    attachment_id: reference.attachment_id,
                });
            }
            LiveAttachmentAvailability::CleanupPending => {
                return Err(MediaReferenceError::CleanupPending {
                    attachment_id: reference.attachment_id,
                });
            }
            LiveAttachmentAvailability::SourceChanged => {
                return Err(MediaReferenceError::SourceChanged {
                    attachment_id: reference.attachment_id,
                    reference_version: reference.attachment_version,
                    live_version: live.attachment_version,
                });
            }
            LiveAttachmentAvailability::Failed => {
                return Err(MediaReferenceError::Failed {
                    attachment_id: reference.attachment_id,
                });
            }
            LiveAttachmentAvailability::Processing => {
                return Err(MediaReferenceError::NotReady {
                    attachment_id: reference.attachment_id,
                    live_state: live.availability,
                });
            }
        }

        // 4. Normalized-derivative check (required for audio/video, and for
        //    image adjacent-content mapping)
        if !live.has_normalized_derivative {
            // Audio/video always require normalized derivatives.
            if matches!(
                reference.media_kind,
                CanonicalMediaKind::Audio | CanonicalMediaKind::Video
            ) {
                return Err(MediaReferenceError::NotNormalized {
                    attachment_id: reference.attachment_id,
                });
            }
            // Image adjacent-content also requires a normalized derivative
            // (the sidecar/adjacent path uses only normalized derivatives).
            if route == MediaRoute::Primary
                && !self.capabilities.image_in_tool_result
                && self.capabilities.image_in_user_content
            {
                return Err(MediaReferenceError::NotNormalized {
                    attachment_id: reference.attachment_id,
                });
            }
        }

        // 5. Lease check (valid lease held until provider body handoff)
        if route == MediaRoute::Primary && !live.lease_held {
            return Err(MediaReferenceError::NoLease {
                attachment_id: reference.attachment_id,
            });
        }

        // 6. Audio/video sidecar route is not supported
        if route == MediaRoute::Sidecar
            && matches!(
                reference.media_kind,
                CanonicalMediaKind::Audio | CanonicalMediaKind::Video
            )
        {
            return Err(MediaReferenceError::AudioVideoSidecarUnsupported {
                attachment_id: reference.attachment_id,
            });
        }

        // 7. Capability check
        let capability = self
            .capabilities
            .capability_for(reference.media_kind, route);
        if capability == ModelMediaCapability::Unknown {
            return Err(MediaReferenceError::CapabilityUnknown {
                attachment_id: reference.attachment_id,
                media_kind: reference.media_kind,
                route,
            });
        }

        // 8. Build the mapping. For sidecar, no bytes are resolved (the sidecar
        //    service resolves it in its isolated media-only request).
        let bytes = if route == MediaRoute::Primary {
            Some(ResolvedMediaBytes {
                attachment_id: reference.attachment_id,
                media_kind: reference.media_kind,
                mime_type: reference.mime_type.clone(),
                bytes: Vec::new(), // bytes filled by the lease/derivative layer
                checksum: reference.checksum.clone(),
            })
        } else {
            None
        };

        Ok(ResolvedMediaMapping {
            tool_call_id: tool_call_id.to_string(),
            call_id: call_id.map(|s| s.to_string()),
            ordinal: reference.ordinal,
            route,
            capability,
            bytes,
        })
    }
}

// ---------------------------------------------------------------------------
// Rig mapping — transient provider messages
// ---------------------------------------------------------------------------

/// The provider mapping decision for a resolved media reference. Tells the
/// adapter exactly which Rig messages to build. Transient — excluded from
/// durable recording; rebuilt from the reference on each authorized dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderRigMapping {
    /// Anthropic image-capable tool result: correlated Rig
    /// `ToolResultContent::Image` and native base64 image block, transient
    /// only.
    AnthropicEmbeddedImage {
        tool_call_id: String,
        call_id: Option<String>,
        ordinal: u32,
        mime_type: String,
        base64_bytes: String,
    },
    /// Provider/Rig contracts that cannot embed image in a tool result
    /// (including current OpenAI Chat): correlated text/JSON `ToolResult`
    /// followed in the same user turn by `UserContent::Image`; the adapter
    /// fixture preserves call correlation/order.
    OpenAiAdjacentImage {
        tool_call_id: String,
        call_id: Option<String>,
        ordinal: u32,
        result_body: String,
        image_mime_type: String,
        image_base64_bytes: String,
    },
    /// Audio: correlated text/JSON `ToolResult` followed in the same user
    /// turn by `UserContent::Audio`, using only normalized derivatives.
    AdjacentAudio {
        tool_call_id: String,
        call_id: Option<String>,
        ordinal: u32,
        result_body: String,
        audio_mime_type: String,
        audio_base64_bytes: String,
    },
    /// Video: correlated text/JSON `ToolResult` followed in the same user
    /// turn by `UserContent::Video`, using only normalized derivatives.
    AdjacentVideo {
        tool_call_id: String,
        call_id: Option<String>,
        ordinal: u32,
        result_body: String,
        video_mime_type: String,
        video_base64_bytes: String,
    },
    /// Image sidecar: the canonical result remains a reference; the sidecar
    /// service resolves it in its isolated media-only request and returns
    /// typed dossier/text separately. No bytes are dispatched to the model.
    ImageSidecar {
        tool_call_id: String,
        call_id: Option<String>,
        ordinal: u32,
        reference_body: String,
    },
}

impl ProviderRigMapping {
    /// The tool-call ID this mapping is correlated with.
    pub fn tool_call_id(&self) -> &str {
        match self {
            Self::AnthropicEmbeddedImage { tool_call_id, .. }
            | Self::OpenAiAdjacentImage { tool_call_id, .. }
            | Self::AdjacentAudio { tool_call_id, .. }
            | Self::AdjacentVideo { tool_call_id, .. }
            | Self::ImageSidecar { tool_call_id, .. } => tool_call_id,
        }
    }

    /// The ordinal position for stable ordering.
    pub fn ordinal(&self) -> u32 {
        match self {
            Self::AnthropicEmbeddedImage { ordinal, .. }
            | Self::OpenAiAdjacentImage { ordinal, .. }
            | Self::AdjacentAudio { ordinal, .. }
            | Self::AdjacentVideo { ordinal, .. }
            | Self::ImageSidecar { ordinal, .. } => *ordinal,
        }
    }

    /// Whether this mapping produces adjacent user content (OpenAI image,
    /// audio, video).
    pub fn is_adjacent_content(&self) -> bool {
        matches!(
            self,
            Self::OpenAiAdjacentImage { .. }
                | Self::AdjacentAudio { .. }
                | Self::AdjacentVideo { .. }
        )
    }

    /// Whether this mapping embeds bytes in the tool result (Anthropic image).
    pub fn is_embedded(&self) -> bool {
        matches!(self, Self::AnthropicEmbeddedImage { .. })
    }

    /// Whether this mapping is a sidecar (no bytes dispatched to model).
    pub fn is_sidecar(&self) -> bool {
        matches!(self, Self::ImageSidecar { .. })
    }
}

/// Map a resolved media reference to a provider Rig mapping. This is the
/// exact dispatch mapping: Anthropic embedded-image, OpenAI adjacent-image,
/// audio/video adjacent-content, and sidecar. Unknown provider mapping/
/// capability fails before dispatch.
pub fn map_to_provider_rig(
    resolved: &ResolvedMediaMapping,
    reference: &MediaReference,
    base64_bytes: &str,
) -> Result<ProviderRigMapping, MediaReferenceError> {
    let tool_call_id = resolved.tool_call_id.clone();
    let call_id = resolved.call_id.clone();
    let ordinal = resolved.ordinal;

    match (reference.media_kind, resolved.capability, resolved.route) {
        // Anthropic embedded image
        (
            CanonicalMediaKind::Image,
            ModelMediaCapability::ImageInToolResult,
            MediaRoute::Primary,
        ) => Ok(ProviderRigMapping::AnthropicEmbeddedImage {
            tool_call_id,
            call_id,
            ordinal,
            mime_type: reference.mime_type.clone(),
            base64_bytes: base64_bytes.to_string(),
        }),
        // OpenAI adjacent image
        (
            CanonicalMediaKind::Image,
            ModelMediaCapability::ImageInUserContent,
            MediaRoute::Primary,
        ) => Ok(ProviderRigMapping::OpenAiAdjacentImage {
            tool_call_id,
            call_id,
            ordinal,
            result_body: format!(
                "[media: image {} ({} bytes, checksum {})]",
                reference.attachment_id, reference.byte_count, reference.checksum
            ),
            image_mime_type: reference.mime_type.clone(),
            image_base64_bytes: base64_bytes.to_string(),
        }),
        // Adjacent audio
        (
            CanonicalMediaKind::Audio,
            ModelMediaCapability::AudioInUserContent,
            MediaRoute::Primary,
        ) => Ok(ProviderRigMapping::AdjacentAudio {
            tool_call_id,
            call_id,
            ordinal,
            result_body: format!(
                "[media: audio {} ({} bytes, checksum {})]",
                reference.attachment_id, reference.byte_count, reference.checksum
            ),
            audio_mime_type: reference.mime_type.clone(),
            audio_base64_bytes: base64_bytes.to_string(),
        }),
        // Adjacent video
        (
            CanonicalMediaKind::Video,
            ModelMediaCapability::VideoInUserContent,
            MediaRoute::Primary,
        ) => Ok(ProviderRigMapping::AdjacentVideo {
            tool_call_id,
            call_id,
            ordinal,
            result_body: format!(
                "[media: video {} ({} bytes, checksum {})]",
                reference.attachment_id, reference.byte_count, reference.checksum
            ),
            video_mime_type: reference.mime_type.clone(),
            video_base64_bytes: base64_bytes.to_string(),
        }),
        // Image sidecar
        (CanonicalMediaKind::Image, _, MediaRoute::Sidecar) => {
            Ok(ProviderRigMapping::ImageSidecar {
                tool_call_id,
                call_id,
                ordinal,
                reference_body: format!(
                    "[media reference: image {} ({} bytes, checksum {})]",
                    reference.attachment_id, reference.byte_count, reference.checksum
                ),
            })
        }
        // Unknown mapping — should not reach here because the resolver already
        // rejected unknown capability, but fail closed if it does.
        _ => Err(MediaReferenceError::UnknownProviderMapping {
            attachment_id: reference.attachment_id,
            capability: resolved.capability,
        }),
    }
}

// ---------------------------------------------------------------------------
// Sentinel / inline-media rejection
// ---------------------------------------------------------------------------

/// Patterns that indicate forbidden inline media in text/JSON content.
const INLINE_MEDIA_PREFIXES: &[&str] = &[
    "data:image/",
    "data:audio/",
    "data:video/",
    "data:application/octet-stream;base64,",
];

/// Check whether a text string contains forbidden inline media sentinels.
/// Raw base64/data URLs/signed URLs/host paths are invalid text result content.
fn reject_inline_media_text(text: &str) -> Result<(), MediaReferenceError> {
    for prefix in INLINE_MEDIA_PREFIXES {
        if text.contains(prefix) {
            return Err(MediaReferenceError::InlineMediaInText);
        }
    }
    // Reject long base64-looking blobs (heuristic: >256 chars of base64 alphabet
    // with no spaces, likely an embedded data URL or raw base64).
    if text.len() > 256 && looks_like_base64_blob(text) {
        return Err(MediaReferenceError::InlineMediaInText);
    }
    Ok(())
}

/// Recursively check JSON for forbidden inline media sentinels in string values.
fn reject_inline_media_json(value: &serde_json::Value) -> Result<(), MediaReferenceError> {
    match value {
        serde_json::Value::String(s) => {
            // Check for inline media sentinels directly, returning the JSON
            // error variant (not the text variant) since this is JSON content.
            for prefix in INLINE_MEDIA_PREFIXES {
                if s.contains(prefix) {
                    return Err(MediaReferenceError::InlineMediaInJson);
                }
            }
            if s.len() > 256 && looks_like_base64_blob(s) {
                return Err(MediaReferenceError::InlineMediaInJson);
            }
            Ok(())
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                reject_inline_media_json(v)?;
            }
            Ok(())
        }
        serde_json::Value::Object(obj) => {
            for v in obj.values() {
                reject_inline_media_json(v)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Heuristic: does this string look like a base64 blob?
fn looks_like_base64_blob(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.len() <= 256 {
        return false;
    }
    // Check if it's mostly base64 alphabet characters with no spaces
    let base64_chars = trimmed
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();
    let total = trimmed.chars().count();
    total > 0 && base64_chars == total
}

/// Collect all safe metadata from a canonical tool result content list for
/// daemon/TUI/web/native rendering. Safe metadata plus authenticated artifact
/// handle only — no eager byte fetch or path assumptions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SafeMediaMetadata {
    pub attachment_id: Uuid,
    pub media_kind: CanonicalMediaKind,
    pub mime_type: String,
    pub byte_count: u64,
    pub ordinal: u32,
    pub purpose: MediaReferencePurpose,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dimensions: Option<MediaDimensions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<MediaDurationMs>,
    pub provenance: MediaProvenance,
    /// Authenticated artifact handle (opaque token the client uses to fetch
    /// the artifact through the authenticated route). Never a raw path or URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_handle: Option<String>,
}

/// Project a canonical tool result content to safe metadata for client rendering.
/// Web/native/TUI render safe metadata/authenticated handles without eager byte
/// fetch or path assumptions.
pub fn project_safe_metadata(
    content: &CanonicalToolResultContent,
    artifact_handle: Option<&str>,
) -> Option<SafeMediaMetadata> {
    let reference = content.as_media_reference()?;
    Some(SafeMediaMetadata {
        attachment_id: reference.attachment_id,
        media_kind: reference.media_kind,
        mime_type: reference.mime_type.clone(),
        byte_count: reference.byte_count,
        ordinal: reference.ordinal,
        purpose: reference.purpose,
        dimensions: reference.dimensions,
        duration_ms: reference.duration_ms,
        provenance: reference.provenance.clone(),
        artifact_handle: artifact_handle.map(|s| s.to_string()),
    })
}

// ---------------------------------------------------------------------------
// Strict UUIDv7 (mirrors cockpit_db::media_attachments)
// ---------------------------------------------------------------------------

mod strict_uuid_v7 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};
    use uuid::Uuid;

    pub fn serialize<S>(value: &Uuid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Uuid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        let value = Uuid::parse_str(&text).map_err(D::Error::custom)?;
        if value.is_nil()
            || value.get_version_num() != 7
            || value.get_variant() != uuid::Variant::RFC4122
            || value.to_string() != text
        {
            return Err(D::Error::custom(
                "UUID must be nonnil RFC 9562 UUIDv7 in canonical lowercase hyphenated form",
            ));
        }
        Ok(value)
    }
}

// ---------------------------------------------------------------------------
// Helper: stable ordering of canonical content
// ---------------------------------------------------------------------------

/// Sort canonical tool result content by ordinal position. Stable order is
/// `(tool result content ordinal)`; adjacent provider media preserves that
/// order and tool-call ID.
pub fn sort_by_ordinal(contents: &mut [CanonicalToolResultContent]) {
    contents.sort_by_key(|c| c.ordinal());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
