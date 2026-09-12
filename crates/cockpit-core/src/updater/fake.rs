//! Test-only fake fixture adapters. Never linked into the installed binary.
#![cfg(any(test, feature = "test-support"))]

use async_trait::async_trait;

use super::traits::{
    BinaryReplacer, MetadataRepository, SupervisorMaintenanceClient, TargetFetcher, UpdateLockStore,
};
use super::types::{
    DisabledNoProductionRoot, SupervisorMaintenanceRequest, TrustedMetadataVersions,
    UpdateApplyReceipt, UpdateLockRecord, UpdateTargetDescriptor,
};

pub use super::types::FakeFixtureEvidence;

/// Injectable metadata repository for error-path tests only.
#[derive(Debug, Default, Clone)]
pub struct FakeFixtureMetadataRepository {
    pub fail_with: Option<DisabledNoProductionRoot>,
}

#[async_trait]
impl MetadataRepository for FakeFixtureMetadataRepository {
    async fn refresh_trusted_metadata(
        &self,
    ) -> Result<TrustedMetadataVersions, DisabledNoProductionRoot> {
        if let Some(error) = self.fail_with {
            return Err(error);
        }
        Ok(TrustedMetadataVersions {
            root: 1,
            timestamp: 1,
            snapshot: 1,
            targets: 1,
            checked_at_unix_ms: 1,
        })
    }

    async fn cached_versions(
        &self,
    ) -> Result<Option<TrustedMetadataVersions>, DisabledNoProductionRoot> {
        if let Some(error) = self.fail_with {
            return Err(error);
        }
        Ok(None)
    }
}

/// Injectable target fetcher for serialization tests only.
#[derive(Debug, Default, Clone)]
pub struct FakeFixtureTargetFetcher;

#[async_trait]
impl TargetFetcher for FakeFixtureTargetFetcher {
    async fn download_verified_target(
        &self,
        _target: &UpdateTargetDescriptor,
    ) -> Result<std::path::PathBuf, DisabledNoProductionRoot> {
        Err(DisabledNoProductionRoot)
    }
}

/// Injectable binary replacer for serialization tests only.
#[derive(Debug, Default, Clone)]
pub struct FakeFixtureBinaryReplacer;

#[async_trait]
impl BinaryReplacer for FakeFixtureBinaryReplacer {
    async fn stage_and_swap(
        &self,
        _staged: &std::path::PathBuf,
        _receipt: &mut UpdateApplyReceipt,
    ) -> Result<(), DisabledNoProductionRoot> {
        Err(DisabledNoProductionRoot)
    }
}

/// Injectable maintenance client for serialization tests only.
#[derive(Debug, Default, Clone)]
pub struct FakeFixtureMaintenanceClient;

#[async_trait]
impl SupervisorMaintenanceClient for FakeFixtureMaintenanceClient {
    async fn request_maintenance(
        &self,
        _request: SupervisorMaintenanceRequest,
    ) -> Result<(), DisabledNoProductionRoot> {
        Err(DisabledNoProductionRoot)
    }
}

/// Injectable lock store for serialization tests only.
#[derive(Debug, Default, Clone)]
pub struct FakeFixtureUpdateLockStore;

#[async_trait]
impl UpdateLockStore for FakeFixtureUpdateLockStore {
    async fn acquire_exclusive(
        &self,
        _record: &UpdateLockRecord,
    ) -> Result<(), DisabledNoProductionRoot> {
        Err(DisabledNoProductionRoot)
    }

    async fn release(&self, _update_id: uuid::Uuid) -> Result<(), DisabledNoProductionRoot> {
        Err(DisabledNoProductionRoot)
    }
}
