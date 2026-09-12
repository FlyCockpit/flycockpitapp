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

/// Canonical fake-fixture evidence validated by private release tooling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FakeFixtureEvidence {
    pub release_tag: String,
    pub commit: String,
    pub targets: Vec<UpdateTargetDescriptor>,
}

/// Validate canonical fake-fixture evidence before offline signing or publication.
pub fn validate_fake_fixture_evidence(evidence: &FakeFixtureEvidence) -> Result<(), String> {
    use std::collections::{BTreeSet, HashSet};

    if evidence.release_tag.trim().is_empty() {
        return Err("release_tag must be non-empty".to_string());
    }
    if evidence.commit.trim().is_empty() {
        return Err("commit must be non-empty".to_string());
    }
    if evidence.targets.is_empty() {
        return Err("targets must not be empty".to_string());
    }

    let mut identities = HashSet::new();
    let mut paths = HashSet::new();
    let mut canonical = evidence.targets.clone();
    canonical.sort_by(|left, right| {
        left.version
            .cmp(&right.version)
            .then_with(|| left.platform.cmp(&right.platform))
            .then_with(|| left.path.cmp(&right.path))
    });
    if canonical != evidence.targets {
        return Err("targets must be listed in canonical version/platform/path order".to_string());
    }

    for target in &evidence.targets {
        if target.version.trim().is_empty()
            || target.platform.trim().is_empty()
            || target.path.trim().is_empty()
        {
            return Err("target entries must include version, platform, and path".to_string());
        }
        if target.length == 0 {
            return Err("target length must be non-zero".to_string());
        }
        if target.sha256.len() != 64 || !target.sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err("target sha256 must be a 64-character hex digest".to_string());
        }
        if target.sha256.chars().any(|ch| ch.is_ascii_uppercase()) {
            return Err("target sha256 must use lowercase hex digits".to_string());
        }
        if !identities.insert((target.version.clone(), target.platform.clone())) {
            return Err(format!(
                "duplicate target identity for version `{}` on platform `{}`",
                target.version, target.platform
            ));
        }
        if !paths.insert(target.path.clone()) {
            return Err(format!("duplicate target path `{}`", target.path));
        }
    }

    let inventory: BTreeSet<(String, String, String)> = evidence
        .targets
        .iter()
        .map(|target| {
            (
                target.version.clone(),
                target.platform.clone(),
                target.path.clone(),
            )
        })
        .collect();
    if inventory.len() != evidence.targets.len() {
        return Err(
            "target inventory must contain unique version/platform/path tuples".to_string(),
        );
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::{FakeFixtureEvidence, UpdateTargetDescriptor, validate_fake_fixture_evidence};

    #[test]
    fn fake_fixture_evidence_roundtrips_through_json() {
        let evidence = FakeFixtureEvidence {
            release_tag: "v0.1.0".to_string(),
            commit: "abc123".to_string(),
            targets: vec![UpdateTargetDescriptor {
                version: "0.1.0".to_string(),
                platform: "x86_64-unknown-linux-gnu".to_string(),
                path: "cockpit-x86_64-unknown-linux-gnu.tar.gz".to_string(),
                length: 42,
                sha256: "a".repeat(64),
            }],
        };
        let json = serde_json::to_string(&evidence).expect("serialize fake fixture evidence");
        let decoded: FakeFixtureEvidence =
            serde_json::from_str(&json).expect("deserialize fake fixture evidence");
        assert_eq!(decoded, evidence);
        validate_fake_fixture_evidence(&decoded).expect("canonical evidence validates");
    }
}
