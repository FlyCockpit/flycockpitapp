//! Package-manager build updater. The active module is not compiled when the
//! `no-self-update` feature is selected.

use std::path::PathBuf;
use std::process::Command;

use async_trait::async_trait;
use cockpit_config::config::update_channel::UpdateChannel;

use super::traits::Updater;
use super::types::{ManualUpdateOutcome, UpdateCheckResult, UpdateStatusSnapshot, UpdaterError};

pub const HOMEBREW_UPGRADE_COMMAND: &str = "brew upgrade cockpit";

pub(super) fn resolve_brew_prefix() -> Option<PathBuf> {
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

fn current_executable_is_homebrew_managed() -> bool {
    let Some(prefix) = resolve_brew_prefix() else {
        return false;
    };
    std::env::current_exe().is_ok_and(|current_exe| current_exe.starts_with(prefix))
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PackageManagerUpdater;

#[async_trait]
impl Updater for PackageManagerUpdater {
    async fn check(&self, channel: UpdateChannel) -> UpdateCheckResult {
        if channel == UpdateChannel::Off {
            UpdateCheckResult::Off
        } else {
            UpdateCheckResult::Failed(UpdaterError::PackageManager)
        }
    }

    async fn apply_manual(
        &self,
        channel: UpdateChannel,
        _version: Option<&str>,
    ) -> Result<ManualUpdateOutcome, UpdaterError> {
        if channel == UpdateChannel::Off {
            return Err(UpdaterError::Off);
        }
        if current_executable_is_homebrew_managed() {
            return Ok(ManualUpdateOutcome::Homebrew {
                command: HOMEBREW_UPGRADE_COMMAND,
            });
        }
        Err(UpdaterError::PackageManager)
    }

    fn status(&self, channel: UpdateChannel) -> UpdateStatusSnapshot {
        if channel == UpdateChannel::Off {
            UpdateStatusSnapshot::Off
        } else {
            UpdateStatusSnapshot::Unavailable {
                channel,
                reason: UpdaterError::PackageManager,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn package_manager_build_refuses_manual_self_update() {
        assert_eq!(
            PackageManagerUpdater
                .apply_manual(UpdateChannel::Auto, None)
                .await,
            Err(UpdaterError::PackageManager)
        );
    }
}
