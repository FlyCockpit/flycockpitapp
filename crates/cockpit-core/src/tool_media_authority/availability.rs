//! `MediaToolAvailability` — data-free tool-presence snapshot.
//!
//! Created from the live authority before `ToolCtx`, via `SpawnArgs`. It can
//! only *omit* direct-native media tools. It has no principal, source,
//! attachment, grant, or bypass data; every actual admission revalidates live
//! authority.
//!
//! The snapshot is intentionally a bare boolean: `true` means direct-native
//! media tools may be registered on the toolbox; `false` means they are
//! omitted entirely. The snapshot carries zero authority data — the real
//! `SessionMediaAuthority` is constructed fresh on each tool call from the
//! persisted binding and live revalidator.

/// Data-free media tool availability snapshot.
///
/// Carries no principal, source, attachment, grant, or bypass data. It is the
/// spawn-time signal that controls whether direct-native media tools appear
/// in the toolbox at all. Every actual tool-call admission revalidates live
/// authority — this snapshot never authorizes anything by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MediaToolAvailability {
    available: bool,
}

impl MediaToolAvailability {
    /// Create an unavailable snapshot — no media tools registered.
    pub fn unavailable() -> Self {
        Self { available: false }
    }

    /// Create an available snapshot — media tools may be registered.
    ///
    /// This carries **no authority data**. The live `SessionMediaAuthority`
    /// is constructed fresh on each tool call from the persisted binding and
    /// revalidator. Revocation after registration denies before content I/O.
    pub fn available() -> Self {
        Self { available: true }
    }

    /// Whether direct-native media tools should be registered.
    pub fn is_available(self) -> bool {
        self.available
    }

    /// The set of media tool names that should be omitted when unavailable.
    ///
    /// Returns the full set of direct-native media tool names so callers can
    /// subtract them from a toolbox. When `is_available()`, returns empty.
    pub fn omitted_tool_names(self) -> &'static [&'static str] {
        if self.available {
            &[]
        } else {
            MEDIA_TOOL_NAMES
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
    "extract_audio_clip",
    "transcribe_audio",
];

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
        // The snapshot is Copy + has only a bool field — there is no
        // principal, source, attachment, grant, or bypass data to leak.
        let avail = MediaToolAvailability::available();
        let size = std::mem::size_of_val(&avail);
        assert_eq!(size, 1); // just the bool
    }
}
