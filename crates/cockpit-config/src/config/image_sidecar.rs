//! Local-trusted image-sidecar selection settings.
//!
//! This module deliberately contains only static selection configuration.  A
//! destination grant or invocation record is runtime authority and belongs to
//! the daemon ledger, never in a layered config document.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SidecarMode {
    #[default]
    Automatic,
    Always,
    Never,
}

impl SidecarMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::Always => "always",
            Self::Never => "never",
        }
    }
}

/// An explicitly configured provider/model pair.  Capability and credential
/// freshness are evaluated by the daemon at use time; this value never grants
/// egress on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SidecarProviderModel {
    pub provider: String,
    pub model: String,
}

/// The complete sidecar selection configuration.  The central invocation cap
/// remains in `mediaResources`; keeping it out of this type prevents a second
/// sidecar-local ceiling from being serialized.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SidecarSelectionConfig {
    pub mode: SidecarMode,
    pub trusted_primary_default: Option<SidecarProviderModel>,
    pub untrusted_primary_default: Option<SidecarProviderModel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_primary_override: Option<SidecarProviderModel>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_selection_config_round_trips_without_an_invocation_cap() {
        let config = SidecarSelectionConfig {
            mode: SidecarMode::Always,
            trusted_primary_default: Some(SidecarProviderModel {
                provider: "trusted".into(),
                model: "vision".into(),
            }),
            untrusted_primary_default: Some(SidecarProviderModel {
                provider: "untrusted".into(),
                model: "vision".into(),
            }),
            per_primary_override: None,
        };

        let value = serde_json::to_value(&config).expect("selection config serializes");
        assert!(value.get("sidecar_invocations_per_session").is_none());
        assert_eq!(
            serde_json::from_value::<SidecarSelectionConfig>(value)
                .expect("selection config deserializes"),
            config
        );
    }
}
