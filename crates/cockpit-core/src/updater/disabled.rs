//! Package-manager build updater. The active module is not compiled when the
//! `no-self-update` feature is selected.

use async_trait::async_trait;
use cockpit_config::config::update_channel::UpdateChannel;

use super::traits::Updater;
use super::types::{ManualUpdateOutcome, UpdateCheckResult, UpdateStatusSnapshot, UpdaterError};

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
            Err(UpdaterError::Off)
        } else {
            Err(UpdaterError::PackageManager)
        }
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
