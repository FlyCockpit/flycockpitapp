//! Closed updater domain types for disabled preparation and future activation.

use std::fmt;

use cockpit_config::config::update_channel::UpdateChannel;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Production updater activation is blocked until verified root ceremony evidence exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisabledNoProductionRoot;

impl fmt::Display for DisabledNoProductionRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "production TUF updater is disabled until verified root ceremony evidence is accepted",
        )
    }
}

impl std::error::Error for DisabledNoProductionRoot {}

/// Cached trusted metadata role versions persisted after verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedMetadataVersions {
    pub root: u64,
    pub timestamp: u64,
    pub snapshot: u64,
    pub targets: u64,
    pub checked_at_unix_ms: i64,
}

/// Authorized target descriptor selected from current trusted targets metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateTargetDescriptor {
    pub version: String,
    pub platform: String,
    pub path: String,
    pub length: u64,
    pub sha256: String,
}

/// Durable apply receipt for manual and daemon-owned updates.
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

/// Private OS-exclusive update lock record.
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

/// Supervisor-owned maintenance request issued after a durable swap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorMaintenanceRequest {
    pub update_id: Uuid,
    pub target_version: String,
    pub installed_path_digest: String,
}

/// Installation channel classification derived from the cargo-dist receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallChannel {
    ShellInstaller,
    Homebrew,
    Cargo,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateCheckResult {
    Off,
    Disabled(DisabledNoProductionRoot),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateStatusSnapshot {
    Off,
    Disabled {
        channel: UpdateChannel,
        reason: DisabledNoProductionRoot,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateNotice {
    Disabled(DisabledNoProductionRoot),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdaterApplyError {
    Off,
    Disabled(DisabledNoProductionRoot),
}

impl fmt::Display for UpdaterApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => f.write_str("updates are disabled"),
            Self::Disabled(reason) => fmt::Display::fmt(reason, f),
        }
    }
}

impl std::error::Error for UpdaterApplyError {}
