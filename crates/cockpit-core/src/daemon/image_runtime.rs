//! Production install seam for the image-generation runtime registry.
//!
//! Session workers construct their registries from their effective project
//! configuration, while the daemon-lifecycle worker reaches those registries
//! through the owner-session directory below. This module is the documented
//! non-test construction point for the standard runtime adapters: it constructs
//! the four standard production adapters
//! ([`crate::image_generation_runtime::production_standard_image_runtime_adapters`]),
//! builds the registry over the pinned/vetted connector
//! ([`ImageRuntimeRegistry::production_standard`]), attaches the credential
//! store, and applies the loaded image-generation configuration.
//!
//! Keeping this seam here (rather than test-only construction) keeps
//! [`ImageRuntimeRegistry::standard`]/[`ImageRuntimeRegistry::production_standard`]
//! as real production factories.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::time::Instant;

use cockpit_config::config::image_generation::ImageGenerationConfig;

use crate::credentials::CredentialStore;
use crate::image_generation_job::{
    ImageGenerationAdapter, ImageGenerationAdapterMap, ImageGenerationCancelRequest,
    ImageGenerationCancelResult, ImageGenerationHandoffRequest, ImageGenerationHandoffResult,
    ImageGenerationReconcileRequest, ImageGenerationReconcileResult,
    image_generation_adapter_sealed,
};
use crate::image_generation_runtime::{ImageRuntimeRegistry, RuntimeClock, RuntimeError};
use cockpit_config::config::image_generation::ImageAdapterKind;

/// Routes worker revalidation to the live runtime authority that owns the
/// queued plan's session. The weak entries are intentionally not durable: a
/// terminated worker/session cannot keep its credentials or configuration alive
/// merely because a job row remains queued.
#[derive(Clone, Default)]
pub struct DaemonImageDispatchRegistry {
    services: Arc<
        Mutex<
            HashMap<uuid::Uuid, Weak<crate::image_generation_job::ImageGenerationDispatchService>>,
        >,
    >,
}

impl DaemonImageDispatchRegistry {
    pub fn install(
        &self,
        session_id: uuid::Uuid,
        service: &Arc<crate::image_generation_job::ImageGenerationDispatchService>,
    ) {
        self.services
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(session_id, Arc::downgrade(service));
    }

    pub fn remove(&self, session_id: uuid::Uuid) {
        self.services
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&session_id);
    }

    /// The daemon worker's fixed four-kind map. Each entry is only a router:
    /// it resolves the request owner at handoff time and delegates to that
    /// session's target-specific configured map. Credentials therefore never
    /// become daemon-global state.
    pub fn adapter_map(&self) -> ImageGenerationAdapterMap {
        let mut adapters = ImageGenerationAdapterMap::new();
        for kind in [
            ImageAdapterKind::OpenaiImages,
            ImageAdapterKind::OpenrouterImages,
            ImageAdapterKind::GeminiImages,
            ImageAdapterKind::Comfyui,
        ] {
            adapters.insert(
                kind,
                Arc::new(DaemonSessionAdapter {
                    kind,
                    services: self.clone(),
                }),
            );
        }
        adapters
    }
}

struct DaemonSessionAdapter {
    kind: ImageAdapterKind,
    services: DaemonImageDispatchRegistry,
}

impl image_generation_adapter_sealed::Sealed for DaemonSessionAdapter {}

#[async_trait::async_trait]
impl ImageGenerationAdapter for DaemonSessionAdapter {
    async fn handoff(
        &self,
        request: &ImageGenerationHandoffRequest,
    ) -> ImageGenerationHandoffResult {
        let service = self
            .services
            .services
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&request.owner_session_id)
            .and_then(Weak::upgrade);
        match service {
            Some(service) => {
                service
                    .handoff_to_configured_adapter(self.kind, request)
                    .await
            }
            None => ImageGenerationHandoffResult::DefinitivelyRejected {
                evidence: b"owner_session_image_adapter_unavailable".to_vec(),
            },
        }
    }

    async fn reconcile(
        &self,
        _: &ImageGenerationReconcileRequest,
    ) -> ImageGenerationReconcileResult {
        ImageGenerationReconcileResult::OutcomeUnknown {
            evidence: b"provider_reconciliation_requires_owner_session".to_vec(),
        }
    }

    async fn cancel(&self, _: &ImageGenerationCancelRequest) -> ImageGenerationCancelResult {
        ImageGenerationCancelResult::OutcomeUnknown {
            evidence: b"provider_cancellation_requires_owner_session".to_vec(),
        }
    }
}

impl crate::image_generation_job::ImageDispatchProofSource for DaemonImageDispatchRegistry {
    fn revalidate<'a>(
        &'a self,
        request: crate::image_generation_job::DispatchRevalidationRequest<'a>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        crate::image_generation_runtime::DispatchProofBinding,
                        RuntimeError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let service = self
                .services
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(&request.owner_session_id)
                .and_then(Weak::upgrade)
                .ok_or_else(|| {
                    RuntimeError::new(
                        crate::image_generation_runtime::RuntimeErrorCode::Obsolete,
                        "Refresh after the image generation session changes.",
                    )
                })?;
            service.revalidate_dispatch(request).await
        })
    }
}

/// Daemon-wide monotonic origin used for both image runtime health TTLs and
/// image-job deadlines. It carries no wall-clock data and cannot move backward.
pub struct DaemonImageRuntimeClock {
    started_at: Instant,
}

impl DaemonImageRuntimeClock {
    pub const fn new(started_at: Instant) -> Self {
        Self { started_at }
    }
}

impl RuntimeClock for DaemonImageRuntimeClock {
    fn now_millis(&self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Build the production image runtime registry with the four standard adapters,
/// attach the credential store used to resolve endpoint credentials, and apply
/// the loaded image-generation configuration at the given config generation and
/// refresh epoch.
///
/// This is the daemon-facing install point for the image runtime registry. The
/// image-generation reconciliation worker calls it once at startup (and again on
/// a configuration reload with a bumped `generation`/`epoch`) before any target
/// health refresh or dispatch.
pub fn install_standard_image_runtime_registry(
    config: &ImageGenerationConfig,
    generation: u64,
    epoch: u64,
    store: Option<CredentialStore>,
    clock: Arc<dyn RuntimeClock>,
) -> Result<ImageRuntimeRegistry, RuntimeError> {
    let mut registry = ImageRuntimeRegistry::production_standard_with_clock(clock)?;
    if let Some(store) = store {
        registry = registry.with_store(store);
    }
    registry.apply_config(config, generation, epoch)?;
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_config::config::image_generation::ImageAdapterKind;

    #[test]
    fn install_standard_image_runtime_registry_resolves_all_four_adapter_kinds() {
        // The production install seam constructs the registry from the standard
        // production adapters and applies an (empty) configuration. All four
        // adapter kinds must resolve — proving the standard factory is a real,
        // non-test production path.
        let config = ImageGenerationConfig::default();
        let registry = install_standard_image_runtime_registry(
            &config,
            1,
            1,
            None,
            Arc::new(DaemonImageRuntimeClock::new(Instant::now())),
        )
        .expect("production install seam must build the standard registry");
        for kind in [
            ImageAdapterKind::OpenaiImages,
            ImageAdapterKind::OpenrouterImages,
            ImageAdapterKind::GeminiImages,
            ImageAdapterKind::Comfyui,
        ] {
            assert_eq!(registry.adapter(kind).unwrap().kind(), kind);
        }
    }
}
