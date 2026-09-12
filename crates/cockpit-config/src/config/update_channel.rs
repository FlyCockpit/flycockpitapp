//! Closed update-channel vocabulary for the TUF updater boundary.
//!
//! Production activation is deferred; this module only defines parsing and the
//! CI/container override convention.

use std::fmt;

use serde::{Deserialize, Serialize};

/// User-facing update policy selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    /// Apply authorized targets when the installation channel permits it.
    #[default]
    Auto,
    /// Surface upgrade guidance without replacing the installed binary.
    Notify,
    /// Disable every update request.
    Off,
}

/// Environment override that forces [`UpdateChannel::Off`] in CI/containers.
pub const COCKPIT_UPDATES_ENV: &str = "COCKPIT_UPDATES";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateChannelParseError {
    pub value: String,
}

impl fmt::Display for UpdateChannelParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid update channel `{}` (expected auto, notify, or off)",
            self.value
        )
    }
}

impl std::error::Error for UpdateChannelParseError {}

impl UpdateChannel {
    pub const ALL: [Self; 3] = [Self::Auto, Self::Notify, Self::Off];

    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Notify => "notify",
            Self::Off => "off",
        }
    }

    /// Parse a closed channel label. Unknown values are rejected.
    pub fn from_label(label: &str) -> Result<Self, UpdateChannelParseError> {
        match label.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "notify" => Ok(Self::Notify),
            "off" => Ok(Self::Off),
            other => Err(UpdateChannelParseError {
                value: other.to_string(),
            }),
        }
    }

    /// Apply the installation config channel after the process-wide override.
    ///
    /// `COCKPIT_UPDATES` accepts only the closed channel labels. Unknown or
    /// malformed values are rejected instead of silently retaining the
    /// configured channel.
    pub fn resolve_effective(configured: Self) -> Result<Self, UpdateChannelParseError> {
        match std::env::var(COCKPIT_UPDATES_ENV) {
            Ok(value) => Self::from_label(&value),
            Err(std::env::VarError::NotPresent) => Ok(configured),
            Err(std::env::VarError::NotUnicode(_)) => Err(UpdateChannelParseError {
                value: format!("non-unicode {COCKPIT_UPDATES_ENV} value"),
            }),
        }
    }
}
