//! Injected updater seams. Installed production composition wires only
//! [`super::disabled::DisabledUpdater`]; future activation supplies real adapters.

use std::path::PathBuf;

use async_trait::async_trait;
use cockpit_config::config::update_channel::UpdateChannel;

use super::types::{
    DisabledNoProductionRoot, SupervisorMaintenanceRequest, TrustedMetadataVersions,
    UpdateApplyReceipt, UpdateCheckResult, UpdateLockRecord, UpdateStatusSnapshot,
    UpdateTargetDescriptor, UpdaterApplyError,
};

#[async_trait]
pub trait Updater: Send + Sync {
    async fn check(&self, channel: UpdateChannel) -> UpdateCheckResult;
    async fn apply_manual(
        &self,
        channel: UpdateChannel,
        version: Option<&str>,
    ) -> Result<(), UpdaterApplyError>;
    fn status(&self, channel: UpdateChannel) -> UpdateStatusSnapshot;
}

#[async_trait]
pub trait MetadataRepository: Send + Sync {
    async fn refresh_trusted_metadata(
        &self,
    ) -> Result<TrustedMetadataVersions, DisabledNoProductionRoot>;
    async fn cached_versions(
        &self,
    ) -> Result<Option<TrustedMetadataVersions>, DisabledNoProductionRoot>;
}

#[async_trait]
pub trait TargetFetcher: Send + Sync {
    async fn download_verified_target(
        &self,
        target: &UpdateTargetDescriptor,
    ) -> Result<PathBuf, DisabledNoProductionRoot>;
}

#[async_trait]
pub trait BinaryReplacer: Send + Sync {
    async fn stage_and_swap(
        &self,
        staged: &PathBuf,
        receipt: &mut UpdateApplyReceipt,
    ) -> Result<(), DisabledNoProductionRoot>;
}

#[async_trait]
pub trait SupervisorMaintenanceClient: Send + Sync {
    async fn request_maintenance(
        &self,
        request: SupervisorMaintenanceRequest,
    ) -> Result<(), DisabledNoProductionRoot>;
}

#[async_trait]
pub trait UpdateLockStore: Send + Sync {
    async fn acquire_exclusive(
        &self,
        record: &UpdateLockRecord,
    ) -> Result<(), DisabledNoProductionRoot>;
    async fn release(&self, update_id: uuid::Uuid) -> Result<(), DisabledNoProductionRoot>;
}
