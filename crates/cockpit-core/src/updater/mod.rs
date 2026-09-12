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
    DisabledNoProductionRoot, InstallChannel, SupervisorMaintenanceRequest,
    TrustedMetadataVersions, UpdateApplyReceipt, UpdateApplyReceiptState, UpdateCheckResult,
    UpdateLockRecord, UpdateLockState, UpdateNotice, UpdateStatusSnapshot, UpdateTargetDescriptor,
    UpdaterApplyError,
};

use cockpit_config::config::update_channel::UpdateChannel;

/// Resolve the effective update channel for the current installation.
pub fn effective_update_channel() -> anyhow::Result<UpdateChannel> {
    let configured = cockpit_config::extended::load_installation_update_channel()?;
    UpdateChannel::resolve_effective(configured).map_err(|error| anyhow::anyhow!("{error}"))
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
