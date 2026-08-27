//! `MediaToolAvailability` — data-free tool-presence snapshot.
//!
//! Created from the live authority before `ToolCtx`, via `SpawnArgs`. It can
//! only *omit* direct-native media tools. It has no principal, source,
//! attachment, grant, or bypass data; every actual admission revalidates live
//! authority.
//!
//! Presence is the host-issued authority bit crossed with an exact
//! ffprobe/ffmpeg runtime profile and the session model's audio/video
//! modality. A false authority bit or an unsupported profile makes the
//! corresponding tools absent from both direct and MCP/Monty surfaces.

use crate::config::providers::CapabilityStatus;

/// Exact ffprobe/ffmpeg capability profile used to gate A/V tool
/// materialization. Profiles are nested: each step adds capability and
/// never skips a prerequisite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum AvRuntimeProfile {
    /// (a) No compatible ffprobe — all four A/V tools absent.
    #[default]
    None,
    /// (b) Compatible ffprobe, no ffmpeg storyboard/decode — `inspect_audio` only.
    ProbeOnly,
    /// (c) ffprobe + storyboard/decode ffmpeg, no audio encoder —
    /// `inspect_audio` and `inspect_video`.
    Inspect,
    /// (d) Adds a compatible audio encoder — additionally `extract_audio`.
    ExtractAudio,
    /// (e) Adds compatible H.264/yuv420p/AAC MP4 clip encoders — all four.
    FullClip,
}

impl AvRuntimeProfile {
    pub fn supports_inspect_audio(self) -> bool {
        self >= Self::ProbeOnly
    }

    pub fn supports_inspect_video(self) -> bool {
        self >= Self::Inspect
    }

    pub fn supports_extract_audio(self) -> bool {
        self >= Self::ExtractAudio
    }

    pub fn supports_extract_clip(self) -> bool {
        self == Self::FullClip
    }

    /// The exact direct A/V tool names this runtime profile can expose,
    /// before modality overlay and AgentDef tiers.
    pub fn runtime_exposed_av_tools(self) -> &'static [&'static str] {
        match self {
            Self::None => &[],
            Self::ProbeOnly => &["inspect_audio"],
            Self::Inspect => &["inspect_audio", "inspect_video"],
            Self::ExtractAudio => &["inspect_audio", "inspect_video", "extract_audio"],
            Self::FullClip => &[
                "inspect_audio",
                "inspect_video",
                "extract_audio",
                "extract_video_clip",
            ],
        }
    }
}

/// Encoder/probe flags that collapse into one of the five exact profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AvRuntimeCapabilities {
    pub ffprobe_compatible: bool,
    pub ffmpeg_decode: bool,
    pub audio_encoder: bool,
    pub clip_encoders: bool,
}

impl AvRuntimeCapabilities {
    pub fn profile(self) -> AvRuntimeProfile {
        if !self.ffprobe_compatible {
            return AvRuntimeProfile::None;
        }
        if !self.ffmpeg_decode {
            return AvRuntimeProfile::ProbeOnly;
        }
        if !self.audio_encoder {
            return AvRuntimeProfile::Inspect;
        }
        if !self.clip_encoders {
            return AvRuntimeProfile::ExtractAudio;
        }
        AvRuntimeProfile::FullClip
    }
}

/// Why a media tool is present or absent. Consumed by doctor/TUI/headless
/// availability output. Never used to paper over an Enabled+always-error stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaToolAvailabilityReason {
    AuthorityUnavailable,
    RuntimeProfileUnsupported,
    ModelCapabilityRequiresEntitlement,
    ModelCapabilityUnsupported,
    ModelCapabilityUnknown,
    Present,
}

impl MediaToolAvailabilityReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthorityUnavailable => "authority_unavailable",
            Self::RuntimeProfileUnsupported => "runtime_profile_unsupported",
            Self::ModelCapabilityRequiresEntitlement => "model_capability_requires_entitlement",
            Self::ModelCapabilityUnsupported => "model_capability_unsupported",
            Self::ModelCapabilityUnknown => "model_capability_unknown",
            Self::Present => "present",
        }
    }
}

/// One row of doctor/TUI/headless media-tool availability output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaToolAvailabilityRow {
    pub tool: &'static str,
    pub present: bool,
    pub reason: MediaToolAvailabilityReason,
}

/// Data-free media tool availability snapshot.
///
/// Carries no principal, source, attachment, grant, or bypass data. It is the
/// spawn-time signal that controls whether direct-native media tools appear
/// in the toolbox at all. Every actual tool-call admission revalidates live
/// authority — this snapshot never authorizes anything by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaToolAvailability {
    available: bool,
    runtime: AvRuntimeProfile,
    audio_modality: CapabilityStatus,
    video_modality: CapabilityStatus,
}

impl Default for MediaToolAvailability {
    fn default() -> Self {
        Self::unavailable()
    }
}

impl MediaToolAvailability {
    /// Create an unavailable snapshot — no media tools registered.
    pub fn unavailable() -> Self {
        Self {
            available: false,
            runtime: AvRuntimeProfile::None,
            audio_modality: CapabilityStatus::Unknown,
            video_modality: CapabilityStatus::Unknown,
        }
    }

    /// Create an available snapshot with a full clip runtime and Supported
    /// modalities. Carries **no authority data**.
    ///
    /// Prefer [`Self::available_with`] when the host has a real runtime
    /// profile or model modality overlay.
    pub fn available() -> Self {
        Self::available_with(
            AvRuntimeProfile::FullClip,
            CapabilityStatus::Supported,
            CapabilityStatus::Supported,
        )
    }

    /// Authority-usable snapshot crossed with an exact runtime profile and
    /// audio/video modality overlay.
    pub fn available_with(
        runtime: AvRuntimeProfile,
        audio_modality: CapabilityStatus,
        video_modality: CapabilityStatus,
    ) -> Self {
        Self {
            available: true,
            runtime,
            audio_modality,
            video_modality,
        }
    }

    /// Whether the typed session authority is currently usable for the bound
    /// principal/session/project. Independent of runtime/modality overlay.
    pub fn is_available(self) -> bool {
        self.available
    }

    pub fn runtime(self) -> AvRuntimeProfile {
        self.runtime
    }

    pub fn audio_modality(self) -> CapabilityStatus {
        self.audio_modality
    }

    pub fn video_modality(self) -> CapabilityStatus {
        self.video_modality
    }

    /// The set of media tool names that should be omitted when the authority
    /// bit is false. When `is_available()`, returns empty — runtime/modality
    /// omission is applied separately via [`Self::exposes_direct_tool`].
    pub fn omitted_tool_names(self) -> &'static [&'static str] {
        if self.available {
            &[]
        } else {
            MEDIA_TOOL_NAMES
        }
    }

    /// Whether this snapshot permits registering `name` as a direct-native
    /// tool. Runtime profile and inspection-modality overlay are applied
    /// here; extraction stays registered by runtime profile even when the
    /// output modality is not Supported (call-time handoff fails closed).
    pub fn exposes_direct_tool(self, name: &str) -> bool {
        if !self.available {
            return false;
        }
        match name {
            "inspect_audio" => {
                self.runtime.supports_inspect_audio()
                    && self.audio_modality == CapabilityStatus::Supported
            }
            "inspect_video" => {
                self.runtime.supports_inspect_video()
                    && self.video_modality == CapabilityStatus::Supported
            }
            "extract_audio" => self.runtime.supports_extract_audio(),
            "extract_video_clip" => self.runtime.supports_extract_clip(),
            "read_image" | "transcribe_audio" => true,
            _ => false,
        }
    }

    /// Exact direct A/V tools this snapshot would expose before AgentDef
    /// tiers. Product-table placement may still omit them.
    pub fn runtime_and_modality_exposed_av_tools(self) -> Vec<&'static str> {
        if !self.available {
            return Vec::new();
        }
        AV_TOOL_NAMES
            .iter()
            .copied()
            .filter(|name| self.exposes_direct_tool(name))
            .collect()
    }

    /// Doctor/TUI/headless availability rows for the four A/V tools.
    pub fn av_availability_rows(self) -> Vec<MediaToolAvailabilityRow> {
        AV_TOOL_NAMES
            .iter()
            .copied()
            .map(|tool| {
                let reason = self.reason_for(tool);
                MediaToolAvailabilityRow {
                    tool,
                    present: reason == MediaToolAvailabilityReason::Present,
                    reason,
                }
            })
            .collect()
    }

    pub fn reason_for(self, tool: &str) -> MediaToolAvailabilityReason {
        if !self.available {
            return MediaToolAvailabilityReason::AuthorityUnavailable;
        }
        let runtime_ok = match tool {
            "inspect_audio" => self.runtime.supports_inspect_audio(),
            "inspect_video" => self.runtime.supports_inspect_video(),
            "extract_audio" => self.runtime.supports_extract_audio(),
            "extract_video_clip" => self.runtime.supports_extract_clip(),
            "read_image" | "transcribe_audio" => true,
            _ => return MediaToolAvailabilityReason::RuntimeProfileUnsupported,
        };
        if !runtime_ok {
            return MediaToolAvailabilityReason::RuntimeProfileUnsupported;
        }
        // Extraction remains registered by runtime profile; inspection is
        // removed when the corresponding modality is not Supported.
        let modality = match tool {
            "inspect_audio" => Some(self.audio_modality),
            "inspect_video" => Some(self.video_modality),
            _ => None,
        };
        match modality {
            Some(CapabilityStatus::Supported) | None => MediaToolAvailabilityReason::Present,
            Some(CapabilityStatus::RequiresEntitlement) => {
                MediaToolAvailabilityReason::ModelCapabilityRequiresEntitlement
            }
            Some(CapabilityStatus::Unsupported) => {
                MediaToolAvailabilityReason::ModelCapabilityUnsupported
            }
            Some(CapabilityStatus::Unknown) => MediaToolAvailabilityReason::ModelCapabilityUnknown,
        }
    }

    /// Call-time extraction output-modality failure. Returns `None` when the
    /// output modality is Supported (or the tool is not an extractor).
    pub fn extraction_handoff_error(self, tool: &str) -> Option<&'static str> {
        let status = match tool {
            "extract_audio" => self.audio_modality,
            "extract_video_clip" => self.video_modality,
            _ => return None,
        };
        match status {
            CapabilityStatus::Supported => None,
            CapabilityStatus::RequiresEntitlement => Some("model_capability_requires_entitlement"),
            CapabilityStatus::Unsupported => Some("model_capability_unsupported"),
            CapabilityStatus::Unknown => Some("model_capability_unknown"),
        }
    }
}

/// The canonical set of direct-native media tool names.
///
/// These are absent from MCP/Monty/external-MCP registries even when
/// direct-native tools are enabled.
pub const MEDIA_TOOL_NAMES: &[&str] = &[
    "read_image",
    "inspect_audio",
    "inspect_video",
    "extract_video_clip",
    "extract_audio",
    "transcribe_audio",
];

/// The four A/V tools owned by this execution batch.
pub const AV_TOOL_NAMES: &[&str] = &[
    "inspect_audio",
    "inspect_video",
    "extract_audio",
    "extract_video_clip",
];

pub fn is_av_tool_name(name: &str) -> bool {
    AV_TOOL_NAMES.contains(&name)
}

pub fn is_media_tool_name(name: &str) -> bool {
    MEDIA_TOOL_NAMES.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_omits_all() {
        let avail = MediaToolAvailability::unavailable();
        assert!(!avail.is_available());
        let omitted = avail.omitted_tool_names();
        assert!(omitted.contains(&"read_image"));
        assert!(omitted.contains(&"transcribe_audio"));
        assert!(omitted.contains(&"extract_audio"));
        assert!(omitted.contains(&"extract_video_clip"));
    }

    #[test]
    fn available_omits_none() {
        let avail = MediaToolAvailability::available();
        assert!(avail.is_available());
        assert!(avail.omitted_tool_names().is_empty());
    }

    #[test]
    fn default_is_unavailable() {
        let avail = MediaToolAvailability::default();
        assert!(!avail.is_available());
    }

    #[test]
    fn availability_carries_no_authority_data() {
        // Copy snapshot of booleans/enums only — no principal, source,
        // attachment, grant, or bypass data.
        let avail = MediaToolAvailability::available();
        let _copy = avail;
        let debug = format!("{avail:?}");
        assert!(!debug.to_lowercase().contains("principal"));
        assert!(!debug.to_lowercase().contains("attachment"));
        assert!(!debug.to_lowercase().contains("grant"));
        assert!(!debug.contains("source"));
    }

    #[test]
    fn inspect_requires_entitlement_records_reason() {
        let avail = MediaToolAvailability::available_with(
            AvRuntimeProfile::Inspect,
            CapabilityStatus::RequiresEntitlement,
            CapabilityStatus::RequiresEntitlement,
        );
        assert!(!avail.exposes_direct_tool("inspect_audio"));
        assert!(!avail.exposes_direct_tool("inspect_video"));
        assert_eq!(
            avail.reason_for("inspect_audio"),
            MediaToolAvailabilityReason::ModelCapabilityRequiresEntitlement
        );
        assert_eq!(
            avail.reason_for("inspect_video"),
            MediaToolAvailabilityReason::ModelCapabilityRequiresEntitlement
        );
        let rows = avail.av_availability_rows();
        assert!(rows.iter().any(|row| {
            row.tool == "inspect_audio"
                && row.reason == MediaToolAvailabilityReason::ModelCapabilityRequiresEntitlement
                && !row.present
        }));
    }
}
