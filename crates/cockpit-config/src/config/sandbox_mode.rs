use serde::{Deserialize, Serialize};

/// Persistable/selectable sandbox intent.
///
/// [`SandboxMode::Refuse`] is a runtime fail-closed effective state and is
/// intentionally absent here: configuration, settings writes, wizard answers,
/// and per-node override labels can only express a real intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SandboxIntent {
    Off,
    #[default]
    Sandbox,
    Container,
    ContainerReadonly,
}

impl SandboxIntent {
    pub const ALL: [Self; 4] = [
        Self::Off,
        Self::Sandbox,
        Self::Container,
        Self::ContainerReadonly,
    ];

    pub fn enabled(self) -> bool {
        !matches!(self, Self::Off)
    }

    pub fn is_container(self) -> bool {
        matches!(self, Self::Container | Self::ContainerReadonly)
    }

    pub fn project_read_only(self) -> bool {
        matches!(self, Self::ContainerReadonly)
    }

    pub fn as_mode(self) -> SandboxMode {
        self.into()
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Sandbox => "sandbox",
            Self::Container => "container",
            Self::ContainerReadonly => "container_readonly",
        }
    }

    /// Parse a stored/config label. `"refuse"` is not an intent.
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "off" => Some(Self::Off),
            "sandbox" => Some(Self::Sandbox),
            "container" => Some(Self::Container),
            "container_readonly" => Some(Self::ContainerReadonly),
            _ => None,
        }
    }
}

impl From<SandboxIntent> for SandboxMode {
    fn from(intent: SandboxIntent) -> Self {
        match intent {
            SandboxIntent::Off => Self::Off,
            SandboxIntent::Sandbox => Self::Sandbox,
            SandboxIntent::Container => Self::Container,
            SandboxIntent::ContainerReadonly => Self::ContainerReadonly,
        }
    }
}

/// [`SandboxMode::Refuse`] is not a persistable intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotASandboxIntent;

impl std::fmt::Display for NotASandboxIntent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "refuse is a runtime fail-closed state, not a persistable sandbox intent"
        )
    }
}

impl std::error::Error for NotASandboxIntent {}

impl TryFrom<SandboxMode> for SandboxIntent {
    type Error = NotASandboxIntent;

    fn try_from(mode: SandboxMode) -> Result<Self, Self::Error> {
        match mode {
            SandboxMode::Off => Ok(Self::Off),
            SandboxMode::Sandbox => Ok(Self::Sandbox),
            SandboxMode::Container => Ok(Self::Container),
            SandboxMode::ContainerReadonly => Ok(Self::ContainerReadonly),
            SandboxMode::Refuse => Err(NotASandboxIntent),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMode {
    Off,
    #[default]
    Sandbox,
    Container,
    ContainerReadonly,
    /// Runtime fail-closed effective state. Not a persistable config intent:
    /// configured sandbox/container with an unavailable host capability maps
    /// here so bash never silently runs unconfined.
    Refuse,
}

impl SandboxMode {
    /// Whether sandboxing is still required. [`Self::Refuse`] stays enabled so
    /// callers never take the unconfined [`Self::Off`] path.
    pub fn enabled(self) -> bool {
        !matches!(self, Self::Off)
    }

    /// Runtime fail-closed: configured sandbox cannot be honored.
    pub fn refuses(self) -> bool {
        matches!(self, Self::Refuse)
    }

    /// Persistable intents only. [`Self::Refuse`] is runtime-only.
    pub fn is_persistable_intent(self) -> bool {
        SandboxIntent::try_from(self).is_ok()
    }

    /// Persistable intent for this mode, if any. [`Self::Refuse`] yields
    /// [`None`].
    pub fn persistable_intent(self) -> Option<SandboxIntent> {
        SandboxIntent::try_from(self).ok()
    }

    pub fn is_container(self) -> bool {
        matches!(self, Self::Container | Self::ContainerReadonly)
    }

    pub fn project_read_only(self) -> bool {
        matches!(self, Self::ContainerReadonly)
    }

    pub fn from_enabled(enabled: bool) -> Self {
        if enabled { Self::Sandbox } else { Self::Off }
    }

    pub fn toggled_legacy(self) -> Self {
        if self.enabled() {
            Self::Off
        } else {
            Self::Sandbox
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistable_intent_serde_rejects_refuse() {
        assert!(serde_json::from_str::<SandboxIntent>(r#""refuse""#).is_err());
        assert_eq!(
            serde_json::from_str::<SandboxIntent>(r#""sandbox""#).unwrap(),
            SandboxIntent::Sandbox
        );
        assert_eq!(
            serde_json::from_str::<SandboxIntent>(r#""off""#).unwrap(),
            SandboxIntent::Off
        );
        assert!(SandboxIntent::from_label("refuse").is_none());
        assert_eq!(
            SandboxIntent::from_label("container_readonly"),
            Some(SandboxIntent::ContainerReadonly)
        );
        assert!(SandboxIntent::try_from(SandboxMode::Refuse).is_err());
        assert!(!SandboxMode::Refuse.is_persistable_intent());
        assert_eq!(
            SandboxIntent::try_from(SandboxMode::Sandbox).unwrap(),
            SandboxIntent::Sandbox
        );
    }

    #[test]
    fn runtime_mode_serde_still_roundtrips_refuse() {
        let mode = SandboxMode::Refuse;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, r#""refuse""#);
        assert_eq!(
            serde_json::from_str::<SandboxMode>(&json).unwrap(),
            SandboxMode::Refuse
        );
    }

    #[test]
    fn sandbox_config_rejects_refuse_default_mode() {
        let err = serde_json::from_str::<crate::config::extended::SandboxConfig>(
            r#"{"defaultMode":"refuse"}"#,
        )
        .expect_err("refuse is not a config intent");
        let message = err.to_string();
        assert!(
            message.contains("refuse") || message.contains("unknown variant"),
            "unexpected serde error: {message}"
        );
        let parsed: crate::config::extended::SandboxConfig =
            serde_json::from_str(r#"{"defaultMode":"sandbox"}"#).unwrap();
        assert_eq!(parsed.default_mode, SandboxIntent::Sandbox);
        let json = serde_json::to_value(&parsed).unwrap();
        assert_eq!(json["defaultMode"], "sandbox");
        assert_ne!(json["defaultMode"], "refuse");
    }
}
