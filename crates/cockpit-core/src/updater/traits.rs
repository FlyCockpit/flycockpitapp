//! Injected updater seams. Production composition deliberately has no trust
//! root until owner ceremony evidence is embedded.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use cockpit_config::config::update_channel::UpdateChannel;

use super::types::{
    ManualUpdateOutcome, SupervisorMaintenanceRequest, UntrustedRepositoryMetadata,
    UpdateApplyReceipt, UpdateCheckResult, UpdateLockRecord, UpdateStatusSnapshot,
    UpdateTargetDescriptor, UpdaterError, VerifiedRepositoryMetadata,
};

#[async_trait]
pub trait Updater: Send + Sync {
    async fn check(&self, channel: UpdateChannel) -> UpdateCheckResult;
    async fn apply_manual(
        &self,
        channel: UpdateChannel,
        version: Option<&str>,
    ) -> Result<ManualUpdateOutcome, UpdaterError>;
    fn status(&self, channel: UpdateChannel) -> UpdateStatusSnapshot;
}

pub trait TrustRoot: Send + Sync {
    fn verify_metadata(
        &self,
        metadata: &UntrustedRepositoryMetadata,
    ) -> Result<VerifiedRepositoryMetadata, UpdaterError>;
}

#[async_trait]
pub trait MetadataRepository: Send + Sync {
    async fn fetch_metadata(
        &self,
        channel: UpdateChannel,
    ) -> Result<UntrustedRepositoryMetadata, UpdaterError>;
}

#[async_trait]
pub trait TargetFetcher: Send + Sync {
    async fn download_target(
        &self,
        target: &UpdateTargetDescriptor,
    ) -> Result<PathBuf, UpdaterError>;
}

#[async_trait]
pub trait BinaryReplacer: Send + Sync {
    async fn stage_and_swap(
        &self,
        staged: &Path,
        receipt: &mut UpdateApplyReceipt,
    ) -> Result<(), UpdaterError>;
}

#[async_trait]
pub trait SupervisorMaintenanceClient: Send + Sync {
    async fn request_maintenance(
        &self,
        request: SupervisorMaintenanceRequest,
    ) -> Result<(), UpdaterError>;
}

#[async_trait]
pub trait UpdateLockStore: Send + Sync {
    async fn acquire_exclusive(&self, record: &UpdateLockRecord) -> Result<(), UpdaterError>;
    async fn release(&self, update_id: uuid::Uuid) -> Result<(), UpdaterError>;
}
