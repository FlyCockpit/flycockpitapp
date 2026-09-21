//! Test-only fake fixture adapters. Never linked into the installed binary.
#![cfg(any(test, feature = "test-support"))]

use std::path::PathBuf;

use async_trait::async_trait;

use super::traits::{MetadataRepository, TargetFetcher, TrustRoot};
use super::types::{
    FakeFixtureEvidence, TrustedMetadataVersions, UntrustedRepositoryMetadata,
    UpdateTargetDescriptor, UpdaterError, VerifiedRepositoryMetadata,
    validate_fake_fixture_evidence,
};

#[derive(Debug, Clone)]
pub struct FakeFixtureTrustRoot {
    evidence: FakeFixtureEvidence,
    exact_metadata: Vec<u8>,
}

impl FakeFixtureTrustRoot {
    pub fn new(evidence: FakeFixtureEvidence) -> Self {
        let exact_metadata = serde_json::to_vec(&evidence).expect("fixture evidence serializes");
        Self {
            evidence,
            exact_metadata,
        }
    }

    pub fn metadata(&self) -> UntrustedRepositoryMetadata {
        UntrustedRepositoryMetadata {
            bytes: self.exact_metadata.clone(),
        }
    }
}

impl TrustRoot for FakeFixtureTrustRoot {
    fn verify_metadata(
        &self,
        metadata: &UntrustedRepositoryMetadata,
    ) -> Result<VerifiedRepositoryMetadata, UpdaterError> {
        if metadata.bytes != self.exact_metadata {
            return Err(UpdaterError::Metadata(
                "fixture metadata was not authorized by the injected trust root".into(),
            ));
        }
        validate_fake_fixture_evidence(&self.evidence).map_err(UpdaterError::Metadata)?;
        Ok(VerifiedRepositoryMetadata {
            versions: TrustedMetadataVersions {
                root: 1,
                timestamp: 1,
                snapshot: 1,
                targets: 1,
                checked_at_unix_ms: 1,
            },
            targets: self.evidence.targets.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct FakeFixtureMetadataRepository {
    pub metadata: UntrustedRepositoryMetadata,
}

#[async_trait]
impl MetadataRepository for FakeFixtureMetadataRepository {
    async fn fetch_metadata(
        &self,
        _channel: cockpit_config::config::update_channel::UpdateChannel,
    ) -> Result<UntrustedRepositoryMetadata, UpdaterError> {
        Ok(self.metadata.clone())
    }
}

#[derive(Debug, Clone)]
pub struct FakeFixtureTargetFetcher {
    pub path: PathBuf,
}

#[async_trait]
impl TargetFetcher for FakeFixtureTargetFetcher {
    async fn download_target(
        &self,
        _target: &UpdateTargetDescriptor,
    ) -> Result<PathBuf, UpdaterError> {
        Ok(self.path.clone())
    }
}
