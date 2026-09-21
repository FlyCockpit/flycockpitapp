//! Closed updater domain types shared by production composition and fakes.

use std::fmt;
use std::path::PathBuf;

use cockpit_config::config::update_channel::UpdateChannel;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use cockpit_updater_evidence::{
    FakeFixtureEvidence, ProductionTrustRootEvidence, UpdateTargetDescriptor,
    production_trust_root_evidence, validate_fake_fixture_evidence,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedMetadataVersions {
    pub root: u64,
    pub timestamp: u64,
    pub snapshot: u64,
    pub targets: u64,
    pub checked_at_unix_ms: i64,
}

/// Untrusted bytes returned by a metadata repository. Only [`super::TrustRoot`]
/// may turn these bytes into authorized targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedRepositoryMetadata {
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRepositoryMetadata {
    pub versions: TrustedMetadataVersions,
    pub targets: Vec<UpdateTargetDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateApplyReceipt {
    pub update_id: Uuid,
    pub state: UpdateApplyReceiptState,
    pub target: Option<UpdateTargetDescriptor>,
    pub updated_at_unix_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateApplyReceiptState {
    Checking,
    Selected,
    VerifiedStaged,
    Swapped,
    MaintenanceRequested,
    TerminalFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateLockRecord {
    pub update_id: Uuid,
    pub owner_pid: u32,
    pub owner_start_id: String,
    pub installed_path_digest: String,
    pub state: UpdateLockState,
    pub revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateLockState {
    Held,
    Released,
    Conflicted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorMaintenanceRequest {
    pub update_id: Uuid,
    pub target_version: String,
    pub installed_path_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallationAuthorization {
    SelfUpdate,
    Homebrew { command: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManualUpdateOutcome {
    Updated { version: String },
    Homebrew { command: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateCheckResult {
    Off,
    Available { version: String },
    Current,
    Failed(UpdaterError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateStatusSnapshot {
    Off,
    Ready {
        channel: UpdateChannel,
    },
    Unavailable {
        channel: UpdateChannel,
        reason: UpdaterError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateNotice {
    Available { version: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdaterError {
    Off,
    NoProductionTrustRoot,
    PackageManager,
    Io(String),
    Metadata(String),
    TargetNotFound(String),
    TargetLength { expected: u64, actual: u64 },
    TargetHash,
    Replacement(String),
    Supervisor(String),
    Lock(String),
}

impl UpdaterError {
    pub fn io(context: &str, error: impl fmt::Display) -> Self {
        Self::Io(format!("{context}: {error}"))
    }
}

impl fmt::Display for UpdaterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => f.write_str("updates are disabled"),
            Self::NoProductionTrustRoot => f.write_str("no production trust root"),
            Self::PackageManager => f.write_str(
                "self-update refused: this cockpit binary was installed by a package manager; use that package manager to upgrade",
            ),
            Self::Io(message)
            | Self::Metadata(message)
            | Self::Replacement(message)
            | Self::Supervisor(message)
            | Self::Lock(message) => f.write_str(message),
            Self::TargetNotFound(version) => {
                write!(f, "no trusted update target matched version `{version}`")
            }
            Self::TargetLength { expected, actual } => write!(
                f,
                "downloaded update target length mismatch: expected {expected}, got {actual}"
            ),
            Self::TargetHash => f.write_str("downloaded update target hash verification failed"),
        }
    }
}

impl std::error::Error for UpdaterError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationPaths {
    pub current_exe: PathBuf,
    pub receipt: PathBuf,
    pub brew_prefix: Option<PathBuf>,
}
