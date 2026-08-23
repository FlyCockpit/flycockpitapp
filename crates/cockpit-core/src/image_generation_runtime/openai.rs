//! OpenAI Images runtime health/capability probe adapter.
//!
//! Implements adapter kind [`ImageAdapterKind::OpenaiImages`] as a read-only
//! health/capability probe against the configured OpenAI Images origin.
//!
//! Like every runtime adapter, the I/O-aware seam is purely descriptive:
//! [`request()`](super::ImageRuntimeAdapter::request) only names a read-only
//! probe URL derived from the configured origin + the `Generate` route, and
//! [`parse()`](super::ImageRuntimeAdapter::parse) only inspects an already
//! bounded response. The registry owns the pinned/vetted connector
//! ([`super::ReqwestPinnedConnector`] over [`super::BoundConnector`]): whole
//! DNS-set vetting, `redirect(none)`, no-proxy, body-limit-while-reading, and
//! ephemeral credential headers that are never forwarded across a redirect
//! boundary. This adapter never constructs an HTTP client and never handles
//! credentials directly.

use std::collections::BTreeMap;
use std::sync::Arc;

use cockpit_config::config::image_generation::{ImageAdapterKind, ImageRoute};

use super::adapter_sealed;
use super::{
    BoundProbeResponse, CAPABILITY_DISPATCH_TTL, CapabilitySnapshot, ImageHealthState,
    ProbeRequest, ProbeResult, ReadOnlyProbeRequest, RuntimeError, RuntimeErrorCode,
    SnapshotProvenance,
};

/// The OpenAI Images runtime health/capability probe adapter.
///
/// The credential boundary (the `Authorization: Bearer` header or configured
/// header set) is resolved by the registry into the ephemeral header map and is
/// never forwarded across a redirect boundary (enforced by the registry's
/// connector).
pub struct OpenaiImagesRuntimeAdapter {
    kind: ImageAdapterKind,
}

impl OpenaiImagesRuntimeAdapter {
    pub fn new() -> Self {
        Self {
            kind: ImageAdapterKind::OpenaiImages,
        }
    }
}

impl Default for OpenaiImagesRuntimeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl adapter_sealed::Sealed for OpenaiImagesRuntimeAdapter {}

impl super::ImageRuntimeAdapter for OpenaiImagesRuntimeAdapter {
    fn kind(&self) -> ImageAdapterKind {
        self.kind
    }

    fn request(&self, request: &ProbeRequest) -> Result<ReadOnlyProbeRequest, RuntimeError> {
        // Build the probe URL from the configured origin + images route.
        let route_url = request
            .endpoint
            .route_url(ImageRoute::Generate)
            .map_err(|_| {
                RuntimeError::new(
                    RuntimeErrorCode::MalformedResponse,
                    "Correct the OpenAI Images endpoint origin.",
                )
            })?;
        let url = reqwest::Url::parse(&route_url).map_err(|_| {
            RuntimeError::new(
                RuntimeErrorCode::MalformedResponse,
                "Correct the OpenAI Images endpoint origin.",
            )
        })?;
        // The registry has already resolved the credential header into the
        // ephemeral header map. Credentials are never forwarded across
        // redirects.
        Ok(request.read_only_request(url))
    }

    fn parse(
        &self,
        request: &ProbeRequest,
        response: &BoundProbeResponse,
    ) -> Result<ProbeResult, RuntimeError> {
        // A 2xx response indicates the endpoint is reachable and the credential
        // boundary is valid.
        if !response.status.is_success() {
            let code = if response.status.as_u16() == 401 || response.status.as_u16() == 403 {
                RuntimeErrorCode::Authentication
            } else if response.status.as_u16() == 429 {
                RuntimeErrorCode::Busy
            } else {
                RuntimeErrorCode::MalformedResponse
            };
            return Err(RuntimeError::new(
                code,
                super::health_state_for_error(code).remediation(),
            ));
        }

        // For a health probe, a successful 2xx connection is sufficient. For a
        // capability probe, the registry supplies the model_or_workflow_digest
        // from the configured target identity; we return a minimal capability
        // snapshot. Full model-catalog constraints are resolved at dispatch
        // time by the generation adapter.
        let capability = if request.kind == super::RefreshKind::Capabilities {
            Some(CapabilitySnapshot {
                target_id: request.target_id.clone(),
                model_or_workflow_digest: String::new(),
                retrieved_at: 0,
                expires_at: CAPABILITY_DISPATCH_TTL.as_millis() as u64,
                provenance: SnapshotProvenance::Live,
                constraints: BTreeMap::new(),
            })
        } else {
            None
        };

        Ok(ProbeResult {
            state: ImageHealthState::Healthy,
            capability,
            model_or_workflow_digest: None,
            unavailable_reason: None,
        })
    }
}

/// Build the production standard adapter set entry for OpenAI images.
pub fn standard_adapter() -> Arc<dyn super::ImageRuntimeAdapter> {
    Arc::new(OpenaiImagesRuntimeAdapter::new())
}

#[cfg(test)]
mod tests;
