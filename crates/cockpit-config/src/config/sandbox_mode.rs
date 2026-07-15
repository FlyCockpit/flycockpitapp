use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMode {
    Off,
    #[default]
    Sandbox,
    Container,
    ContainerReadonly,
}

impl SandboxMode {
    pub fn enabled(self) -> bool {
        !matches!(self, Self::Off)
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
