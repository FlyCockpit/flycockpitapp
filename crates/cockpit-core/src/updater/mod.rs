//! Receipt-gated updater with an owner-supplied TUF trust-root seam.

#[cfg(not(feature = "no-self-update"))]
mod active;
mod background;
mod composition;
mod disabled;
#[cfg(any(test, feature = "test-support"))]
pub mod fake;
#[cfg(not(feature = "no-self-update"))]
mod platform;
mod traits;
mod types;

#[cfg(not(feature = "no-self-update"))]
pub use active::{ActiveUpdater, HOMEBREW_UPGRADE_COMMAND, InstallationPolicy, current_platform};
pub use background::spawn_background;
pub use composition::{InstalledUpdaterComposition, installed_composition, installed_updater};
pub use disabled::PackageManagerUpdater;
#[cfg(not(feature = "no-self-update"))]
pub use platform::{
    FileUpdateLockStore, LiveSupervisorMaintenanceClient, PlatformBinaryReplacer,
    cleanup_previous_binary_after_successful_start,
};
#[cfg(feature = "no-self-update")]
pub fn cleanup_previous_binary_after_successful_start() -> Result<(), UpdaterError> {
    Ok(())
}
pub use traits::{
    BinaryReplacer, MetadataRepository, SupervisorMaintenanceClient, TargetFetcher, TrustRoot,
    UpdateLockStore, Updater,
};
pub use types::{
    FakeFixtureEvidence, InstallationAuthorization, InstallationPaths, ManualUpdateOutcome,
    ProductionTrustRootEvidence, SupervisorMaintenanceRequest, TrustedMetadataVersions,
    UntrustedRepositoryMetadata, UpdateApplyReceipt, UpdateApplyReceiptState, UpdateCheckResult,
    UpdateLockRecord, UpdateLockState, UpdateNotice, UpdateStatusSnapshot, UpdateTargetDescriptor,
    UpdaterError, VerifiedRepositoryMetadata, production_trust_root_evidence,
    validate_fake_fixture_evidence,
};

use std::sync::{Arc, OnceLock, RwLock};

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

/// Startup and background check entrypoint. Checks never place a binary or
/// request supervisor maintenance; they only refresh the process-local notice.
pub async fn run_startup_check(channel: UpdateChannel) -> UpdateCheckResult {
    let result = installed_updater().check(channel).await;
    let notice = notice_for_result(&result);
    if let Ok(mut slot) = update_notice_slot().write() {
        *slot = notice;
    }
    result
}

fn notice_for_result(result: &UpdateCheckResult) -> Option<UpdateNotice> {
    match result {
        UpdateCheckResult::Available { version } => Some(UpdateNotice::Available {
            version: version.clone(),
        }),
        UpdateCheckResult::Off | UpdateCheckResult::Current | UpdateCheckResult::Failed(_) => None,
    }
}

/// Manual/background status projection for CLI and TUI surfaces.
pub fn update_status(channel: UpdateChannel) -> UpdateStatusSnapshot {
    installed_updater().status(channel)
}

/// Process-local TUI projection of the latest completed updater check.
pub fn update_notice(channel: UpdateChannel) -> Option<UpdateNotice> {
    if channel == UpdateChannel::Off {
        return None;
    }
    update_notice_slot()
        .read()
        .ok()
        .and_then(|notice| notice.clone())
}

fn update_notice_slot() -> &'static RwLock<Option<UpdateNotice>> {
    static NOTICE: OnceLock<RwLock<Option<UpdateNotice>>> = OnceLock::new();
    NOTICE.get_or_init(|| RwLock::new(None))
}

#[cfg(test)]
mod notice_tests {
    use super::*;

    #[test]
    fn available_check_projects_to_a_tui_notice_and_non_available_results_clear_it() {
        assert_eq!(
            notice_for_result(&UpdateCheckResult::Available {
                version: "9.9.9".into(),
            }),
            Some(UpdateNotice::Available {
                version: "9.9.9".into(),
            })
        );
        assert_eq!(notice_for_result(&UpdateCheckResult::Current), None);
        assert_eq!(notice_for_result(&UpdateCheckResult::Off), None);
    }
}
