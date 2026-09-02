use serde::{Deserialize, Serialize};

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
