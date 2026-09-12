//! Installed production updater composition. Every entrypoint fails closed
//! before any transport, persistence, replacement, or maintenance seam runs.

use async_trait::async_trait;
use cockpit_config::config::update_channel::UpdateChannel;

use super::traits::Updater;
use super::types::{
    DisabledNoProductionRoot, UpdateCheckResult, UpdateStatusSnapshot, UpdaterApplyError,
};

/// Sole shipped updater implementation until ceremony-gated activation lands.
#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledUpdater;

impl DisabledUpdater {
    pub const fn new() -> Self {
        Self
    }

    fn disabled_reason() -> DisabledNoProductionRoot {
        DisabledNoProductionRoot
    }
}

#[async_trait]
impl Updater for DisabledUpdater {
    async fn check(&self, channel: UpdateChannel) -> UpdateCheckResult {
        if channel == UpdateChannel::Off {
            return UpdateCheckResult::Off;
        }
        UpdateCheckResult::Disabled(Self::disabled_reason())
    }

    async fn apply_manual(
        &self,
        channel: UpdateChannel,
        _version: Option<&str>,
    ) -> Result<(), UpdaterApplyError> {
        if channel == UpdateChannel::Off {
            return Err(UpdaterApplyError::Off);
        }
        Err(UpdaterApplyError::Disabled(Self::disabled_reason()))
    }

    fn status(&self, channel: UpdateChannel) -> UpdateStatusSnapshot {
        if channel == UpdateChannel::Off {
            UpdateStatusSnapshot::Off
        } else {
            UpdateStatusSnapshot::Disabled {
                channel,
                reason: Self::disabled_reason(),
            }
        }
    }
}
