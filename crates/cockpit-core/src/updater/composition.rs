//! Installed updater composition. Production callers use this single funnel.

#[cfg(not(feature = "no-self-update"))]
use std::path::PathBuf;
#[cfg(not(feature = "no-self-update"))]
use std::sync::Arc;

use cockpit_config::config::update_channel::UpdateChannel;

#[cfg(not(feature = "no-self-update"))]
use super::active::{ActiveUpdater, InstallationPolicy, current_platform};
use super::disabled::PackageManagerUpdater;
#[cfg(not(feature = "no-self-update"))]
use super::platform::{
    FileUpdateLockStore, LiveSupervisorMaintenanceClient, PlatformBinaryReplacer,
};
#[cfg(not(feature = "no-self-update"))]
use super::traits::TrustRoot;
use super::traits::Updater;
#[cfg(not(feature = "no-self-update"))]
use super::traits::{MetadataRepository, TargetFetcher};
#[cfg(not(feature = "no-self-update"))]
use super::types::{UntrustedRepositoryMetadata, UpdateTargetDescriptor, UpdaterError};

pub struct InstalledUpdaterComposition {
    updater: Box<dyn Updater>,
}

impl InstalledUpdaterComposition {
    pub fn updater(&self) -> &dyn Updater {
        self.updater.as_ref()
    }
}

#[async_trait::async_trait]
impl Updater for InstalledUpdaterComposition {
    async fn check(&self, channel: UpdateChannel) -> super::types::UpdateCheckResult {
        self.updater.check(channel).await
    }

    async fn apply_manual(
        &self,
        channel: UpdateChannel,
        version: Option<&str>,
    ) -> Result<super::types::ManualUpdateOutcome, super::types::UpdaterError> {
        self.updater.apply_manual(channel, version).await
    }

    fn status(&self, channel: UpdateChannel) -> super::types::UpdateStatusSnapshot {
        self.updater.status(channel)
    }
}

#[cfg(not(feature = "no-self-update"))]
#[derive(Debug)]
struct ProductionMetadataRepository;

#[cfg(not(feature = "no-self-update"))]
#[async_trait::async_trait]
impl MetadataRepository for ProductionMetadataRepository {
    async fn fetch_metadata(
        &self,
        _channel: UpdateChannel,
    ) -> Result<UntrustedRepositoryMetadata, UpdaterError> {
        Err(UpdaterError::NoProductionTrustRoot)
    }
}

#[cfg(not(feature = "no-self-update"))]
#[derive(Debug)]
struct ProductionTargetFetcher;

#[cfg(not(feature = "no-self-update"))]
#[async_trait::async_trait]
impl TargetFetcher for ProductionTargetFetcher {
    async fn download_target(
        &self,
        _target: &UpdateTargetDescriptor,
    ) -> Result<PathBuf, UpdaterError> {
        Err(UpdaterError::NoProductionTrustRoot)
    }
}

pub fn installed_composition() -> InstalledUpdaterComposition {
    #[cfg(feature = "no-self-update")]
    {
        InstalledUpdaterComposition {
            updater: Box::new(PackageManagerUpdater),
        }
    }
    #[cfg(not(feature = "no-self-update"))]
    {
        let policy = match InstallationPolicy::production() {
            Ok(policy) => policy,
            Err(_) => {
                return InstalledUpdaterComposition {
                    updater: Box::new(PackageManagerUpdater),
                };
            }
        };
        let installed = policy.current_exe().to_path_buf();
        let lock = installed.with_file_name(".cockpit-update.lock");
        // Owner-only ceremony evidence is deliberately `None`; no adapter may
        // infer or synthesize a production root.
        let _ceremony_evidence = super::types::production_trust_root_evidence();
        let trust_root: Option<Arc<dyn TrustRoot>> = None;
        InstalledUpdaterComposition {
            updater: Box::new(ActiveUpdater::new_for_platform_result(
                policy,
                current_platform(),
                trust_root,
                Arc::new(ProductionMetadataRepository),
                Arc::new(ProductionTargetFetcher),
                Arc::new(PlatformBinaryReplacer::new(installed.clone())),
                Arc::new(LiveSupervisorMaintenanceClient::new(installed)),
                Arc::new(FileUpdateLockStore::new(lock)),
            )),
        }
    }
}

pub fn installed_updater() -> InstalledUpdaterComposition {
    installed_composition()
}
