//! Disabled updater boundaries and future TUF activation seams.
//!
//! Installed production code uses only [`composition::installed_composition`].
//! Fixture adapters live behind `cfg(test)` / `test-support` and must never
//! link into the shipped binary.

mod background;
mod composition;
mod disabled;
#[cfg(any(test, feature = "test-support"))]
pub mod fake;
mod traits;
mod types;

pub use background::spawn_background;
pub use composition::{InstalledUpdaterComposition, installed_composition, installed_updater};
pub use disabled::DisabledUpdater;
pub use traits::{
    BinaryReplacer, MetadataRepository, SupervisorMaintenanceClient, TargetFetcher,
    UpdateLockStore, Updater,
};
pub use types::{
    DisabledNoProductionRoot, FakeFixtureEvidence, InstallChannel, SupervisorMaintenanceRequest,
    TrustedMetadataVersions, UpdateApplyReceipt, UpdateApplyReceiptState, UpdateCheckResult,
    UpdateLockRecord, UpdateLockState, UpdateNotice, UpdateStatusSnapshot, UpdateTargetDescriptor,
    UpdaterApplyError, validate_fake_fixture_evidence,
};

use std::sync::Arc;

use cockpit_config::config::update_channel::UpdateChannel;

use crate::daemon::server::DaemonContext;

/// Resolve the effective update channel for the current installation.
pub fn effective_update_channel() -> anyhow::Result<UpdateChannel> {
    let configured = cockpit_config::extended::load_installation_update_channel()?;
    UpdateChannel::resolve_effective(configured).map_err(|error| anyhow::anyhow!("{error}"))
}

/// Returns whether startup and periodic update checks should run.
pub fn update_checks_enabled(channel: UpdateChannel) -> bool {
    channel != UpdateChannel::Off
}

/// Spawn periodic update checks only when the effective channel permits them.
pub fn maybe_spawn_background(ctx: Arc<DaemonContext>) -> Option<tokio::task::JoinHandle<()>> {
    match effective_update_channel() {
        Ok(channel) if update_checks_enabled(channel) => Some(spawn_background(ctx)),
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "skipping background update checker due to invalid channel configuration"
            );
            None
        }
    }
}

/// Startup and background check entrypoint. Never performs network, filesystem
/// update, replacement, or supervisor maintenance work in disabled preparation.
pub async fn run_startup_check(channel: UpdateChannel) -> UpdateCheckResult {
    installed_updater().check(channel).await
}

/// Manual/background status projection for CLI and TUI surfaces.
pub fn update_status(channel: UpdateChannel) -> UpdateStatusSnapshot {
    installed_updater().status(channel)
}

/// TUI notice entrypoint. Disabled preparation never emits a notify banner.
pub fn update_notice(channel: UpdateChannel) -> Option<UpdateNotice> {
    match installed_updater().status(channel) {
        UpdateStatusSnapshot::Off => None,
        UpdateStatusSnapshot::Disabled { reason, .. } => Some(UpdateNotice::Disabled(reason)),
    }
}
