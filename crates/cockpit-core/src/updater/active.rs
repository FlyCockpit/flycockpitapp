//! Receipt-gated updater orchestration. Trust, repository, placement, locking,
//! and supervisor maintenance are injected so owner-only release artifacts are
//! never simulated by production code.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use async_trait::async_trait;
use cockpit_config::config::update_channel::UpdateChannel;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::traits::{
    BinaryReplacer, MetadataRepository, SupervisorMaintenanceClient, TargetFetcher, TrustRoot,
    UpdateLockStore, Updater,
};
use super::types::{
    InstallationAuthorization, InstallationPaths, ManualUpdateOutcome,
    SupervisorMaintenanceRequest, UpdateApplyReceipt, UpdateApplyReceiptState, UpdateCheckResult,
    UpdateLockRecord, UpdateLockState, UpdateStatusSnapshot, UpdateTargetDescriptor, UpdaterError,
    VerifiedRepositoryMetadata,
};

pub const HOMEBREW_UPGRADE_COMMAND: &str = "brew upgrade cockpit";

#[derive(Debug, Clone)]
pub struct InstallationPolicy {
    paths: InstallationPaths,
}

impl InstallationPolicy {
    pub fn new(paths: InstallationPaths) -> Self {
        Self { paths }
    }

    pub fn production() -> Result<Self, UpdaterError> {
        let current_exe = std::env::current_exe()
            .map_err(|error| UpdaterError::io("resolving current executable", error))?;
        let receipt = cargo_dist_receipt_path()?;
        let brew_prefix = resolve_brew_prefix();
        Ok(Self::new(InstallationPaths {
            current_exe,
            receipt,
            brew_prefix,
        }))
    }

    pub fn authorize(&self) -> Result<InstallationAuthorization, UpdaterError> {
        if self.paths.receipt.is_file() {
            return Ok(InstallationAuthorization::SelfUpdate);
        }
        if self
            .paths
            .brew_prefix
            .as_ref()
            .is_some_and(|prefix| self.paths.current_exe.starts_with(prefix))
        {
            return Ok(InstallationAuthorization::Homebrew {
                command: HOMEBREW_UPGRADE_COMMAND,
            });
        }
        Err(UpdaterError::PackageManager)
    }

    pub fn current_exe(&self) -> &Path {
        &self.paths.current_exe
    }
}

fn cargo_dist_receipt_path() -> Result<PathBuf, UpdaterError> {
    #[cfg(windows)]
    let config_home = cargo_dist_config_home(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("LOCALAPPDATA"),
    );
    #[cfg(not(windows))]
    let config_home = cargo_dist_config_home(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    );
    config_home
        .map(|path| path.join("cockpit").join("cockpit-receipt.json"))
        .ok_or_else(|| UpdaterError::Io("could not resolve cargo-dist receipt directory".into()))
}

#[cfg(windows)]
fn cargo_dist_config_home(
    xdg_config_home: Option<std::ffi::OsString>,
    local_app_data: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    xdg_config_home.or(local_app_data).map(PathBuf::from)
}

#[cfg(not(windows))]
fn cargo_dist_config_home(
    xdg_config_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    xdg_config_home
        .map(PathBuf::from)
        .or_else(|| home.map(PathBuf::from).map(|path| path.join(".config")))
}

fn resolve_brew_prefix() -> Option<PathBuf> {
    if let Some(prefix) = std::env::var_os("HOMEBREW_PREFIX").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(prefix));
    }
    let output = Command::new("brew").arg("--prefix").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let prefix = String::from_utf8(output.stdout).ok()?;
    let prefix = prefix.trim();
    (!prefix.is_empty()).then(|| PathBuf::from(prefix))
}

pub struct ActiveUpdater {
    policy: InstallationPolicy,
    platform: String,
    trust_root: Option<Arc<dyn TrustRoot>>,
    repository: Arc<dyn MetadataRepository>,
    fetcher: Arc<dyn TargetFetcher>,
    replacer: Arc<dyn BinaryReplacer>,
    supervisor: Arc<dyn SupervisorMaintenanceClient>,
    lock_store: Arc<dyn UpdateLockStore>,
}

impl ActiveUpdater {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy: InstallationPolicy,
        platform: impl Into<String>,
        trust_root: Option<Arc<dyn TrustRoot>>,
        repository: Arc<dyn MetadataRepository>,
        fetcher: Arc<dyn TargetFetcher>,
        replacer: Arc<dyn BinaryReplacer>,
        supervisor: Arc<dyn SupervisorMaintenanceClient>,
        lock_store: Arc<dyn UpdateLockStore>,
    ) -> Self {
        Self {
            policy,
            platform: platform.into(),
            trust_root,
            repository,
            fetcher,
            replacer,
            supervisor,
            lock_store,
        }
    }

    fn root(&self) -> Result<&dyn TrustRoot, UpdaterError> {
        self.trust_root
            .as_deref()
            .ok_or(UpdaterError::NoProductionTrustRoot)
    }

    async fn verified_metadata(
        &self,
        channel: UpdateChannel,
    ) -> Result<VerifiedRepositoryMetadata, UpdaterError> {
        let root = self.root()?;
        let untrusted = self.repository.fetch_metadata(channel).await?;
        root.verify_metadata(&untrusted)
    }

    fn select_target<'a>(
        &'a self,
        metadata: &'a VerifiedRepositoryMetadata,
        requested: Option<&str>,
    ) -> Result<&'a UpdateTargetDescriptor, UpdaterError> {
        metadata
            .targets
            .iter()
            .filter(|target| target.platform == self.platform)
            .filter(|target| requested.is_none_or(|version| target.version == version))
            .max_by(|left, right| left.version.cmp(&right.version))
            .ok_or_else(|| UpdaterError::TargetNotFound(requested.unwrap_or("latest").to_string()))
    }

    async fn apply_authorized(
        &self,
        channel: UpdateChannel,
        version: Option<&str>,
    ) -> Result<ManualUpdateOutcome, UpdaterError> {
        let update_id = Uuid::now_v7();
        let installed_path_digest =
            hex_sha256(self.policy.current_exe().as_os_str().as_encoded_bytes());
        let lock = UpdateLockRecord {
            update_id,
            owner_pid: std::process::id(),
            owner_start_id: std::process::id().to_string(),
            installed_path_digest: installed_path_digest.clone(),
            state: UpdateLockState::Held,
            revision: 1,
        };
        self.lock_store.acquire_exclusive(&lock).await?;
        let result = self
            .apply_while_locked(channel, version, update_id, installed_path_digest)
            .await;
        let release = self.lock_store.release(update_id).await;
        match (result, release) {
            (Ok(outcome), Ok(())) => Ok(outcome),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    async fn apply_while_locked(
        &self,
        channel: UpdateChannel,
        version: Option<&str>,
        update_id: Uuid,
        installed_path_digest: String,
    ) -> Result<ManualUpdateOutcome, UpdaterError> {
        let metadata = self.verified_metadata(channel).await?;
        let target = self.select_target(&metadata, version)?.clone();
        let mut receipt = UpdateApplyReceipt {
            update_id,
            state: UpdateApplyReceiptState::Selected,
            target: Some(target.clone()),
            updated_at_unix_ms: now_unix_ms(),
        };
        let staged = self.fetcher.download_target(&target).await?;
        verify_target(&staged, &target)?;
        receipt.state = UpdateApplyReceiptState::VerifiedStaged;
        receipt.updated_at_unix_ms = now_unix_ms();
        self.replacer.stage_and_swap(&staged, &mut receipt).await?;
        receipt.state = UpdateApplyReceiptState::Swapped;
        receipt.updated_at_unix_ms = now_unix_ms();
        self.supervisor
            .request_maintenance(SupervisorMaintenanceRequest {
                update_id,
                target_version: target.version.clone(),
                installed_path_digest,
            })
            .await?;
        receipt.state = UpdateApplyReceiptState::MaintenanceRequested;
        Ok(ManualUpdateOutcome::Updated {
            version: target.version,
        })
    }
}

#[async_trait]
impl Updater for ActiveUpdater {
    async fn check(&self, channel: UpdateChannel) -> UpdateCheckResult {
        if channel == UpdateChannel::Off {
            return UpdateCheckResult::Off;
        }
        match self.policy.authorize() {
            Ok(InstallationAuthorization::Homebrew { .. }) => return UpdateCheckResult::Current,
            Err(error) => return UpdateCheckResult::Failed(error),
            Ok(InstallationAuthorization::SelfUpdate) => {}
        }
        let result = async {
            let metadata = self.verified_metadata(channel).await?;
            let target = self.select_target(&metadata, None)?;
            Ok::<_, UpdaterError>(target.version.clone())
        }
        .await;
        match result {
            Ok(version) if version == env!("CARGO_PKG_VERSION") => UpdateCheckResult::Current,
            Ok(version) => UpdateCheckResult::Available { version },
            Err(error) => UpdateCheckResult::Failed(error),
        }
    }

    async fn apply_manual(
        &self,
        channel: UpdateChannel,
        version: Option<&str>,
    ) -> Result<ManualUpdateOutcome, UpdaterError> {
        if channel == UpdateChannel::Off {
            return Err(UpdaterError::Off);
        }
        match self.policy.authorize()? {
            InstallationAuthorization::SelfUpdate => self.apply_authorized(channel, version).await,
            InstallationAuthorization::Homebrew { command } => {
                Ok(ManualUpdateOutcome::Homebrew { command })
            }
        }
    }

    fn status(&self, channel: UpdateChannel) -> UpdateStatusSnapshot {
        if channel == UpdateChannel::Off {
            return UpdateStatusSnapshot::Off;
        }
        let result = self
            .policy
            .authorize()
            .and_then(|authorization| match authorization {
                InstallationAuthorization::SelfUpdate => self.root().map(|_| ()),
                InstallationAuthorization::Homebrew { .. } => Err(UpdaterError::PackageManager),
            });
        match result {
            Ok(()) => UpdateStatusSnapshot::Ready { channel },
            Err(reason) => UpdateStatusSnapshot::Unavailable { channel, reason },
        }
    }
}

fn verify_target(path: &Path, target: &UpdateTargetDescriptor) -> Result<(), UpdaterError> {
    let bytes = std::fs::read(path)
        .map_err(|error| UpdaterError::io("reading downloaded update target", error))?;
    let actual = u64::try_from(bytes.len())
        .map_err(|_| UpdaterError::Io("downloaded update target length overflow".into()))?;
    if actual != target.length {
        return Err(UpdaterError::TargetLength {
            expected: target.length,
            actual,
        });
    }
    if hex_sha256(&bytes) != target.sha256 {
        return Err(UpdaterError::TargetHash);
    }
    Ok(())
}

pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

pub fn current_platform() -> String {
    format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_ladder_is_receipt_then_brew_then_generic() {
        let temp = tempfile::tempdir().unwrap();
        let prefix = temp.path().join("brew");
        let binary = prefix.join("bin/cockpit");
        let receipt = temp.path().join("cockpit-receipt.json");
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, b"binary").unwrap();
        std::fs::write(&receipt, b"{}").unwrap();

        let with_receipt = InstallationPolicy::new(InstallationPaths {
            current_exe: binary.clone(),
            receipt: receipt.clone(),
            brew_prefix: Some(prefix.clone()),
        });
        assert_eq!(
            with_receipt.authorize().unwrap(),
            InstallationAuthorization::SelfUpdate
        );

        std::fs::remove_file(receipt).unwrap();
        assert_eq!(
            with_receipt.authorize().unwrap(),
            InstallationAuthorization::Homebrew {
                command: HOMEBREW_UPGRADE_COMMAND
            }
        );

        let generic = InstallationPolicy::new(InstallationPaths {
            current_exe: temp.path().join("usr/bin/cockpit"),
            receipt: temp.path().join("missing.json"),
            brew_prefix: Some(prefix),
        });
        assert_eq!(generic.authorize(), Err(UpdaterError::PackageManager));
    }

    #[cfg(not(windows))]
    #[test]
    fn cargo_dist_receipt_home_matches_the_unix_installer_contract() {
        assert_eq!(
            cargo_dist_config_home(Some("/xdg".into()), Some("/home/user".into())),
            Some(PathBuf::from("/xdg"))
        );
        assert_eq!(
            cargo_dist_config_home(None, Some("/home/user".into())),
            Some(PathBuf::from("/home/user/.config"))
        );
    }

    #[test]
    fn target_bytes_must_match_root_authorized_length_and_hash() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("target");
        std::fs::write(&path, b"verified").unwrap();
        let mut target = UpdateTargetDescriptor {
            version: "9.9.9".into(),
            platform: "test".into(),
            path: "target".into(),
            length: 8,
            sha256: hex_sha256(b"verified"),
        };
        verify_target(&path, &target).unwrap();
        target.length = 7;
        assert_eq!(
            verify_target(&path, &target),
            Err(UpdaterError::TargetLength {
                expected: 7,
                actual: 8,
            })
        );
        target.length = 8;
        target.sha256 = "0".repeat(64);
        assert_eq!(verify_target(&path, &target), Err(UpdaterError::TargetHash));
    }
}
