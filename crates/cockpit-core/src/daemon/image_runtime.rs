//! Production install seam for the image-generation runtime registry.
//!
//! There is no live daemon construction of the image runtime registry yet — the
//! reconciliation worker that drives health refresh and dispatch is owned by the
//! deferred `image-generation-job-daemon-integration` prompt. This module is the
//! single, documented non-test entry point that worker will call at startup: it
//! constructs the four standard production adapters
//! ([`crate::image_generation_runtime::production_standard_image_runtime_adapters`]),
//! builds the registry over the pinned/vetted connector
//! ([`ImageRuntimeRegistry::production_standard`]), attaches the credential
//! store, and applies the loaded image-generation configuration.
//!
//! Keeping this seam here (rather than test-only construction) is what makes
//! [`ImageRuntimeRegistry::standard`]/[`ImageRuntimeRegistry::production_standard`]
//! a real production factory and not dead code.

use cockpit_config::config::image_generation::ImageGenerationConfig;

use crate::credentials::CredentialStore;
use crate::image_generation_runtime::{ImageRuntimeRegistry, RuntimeError};

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
) -> Result<ImageRuntimeRegistry, RuntimeError> {
    let mut registry = ImageRuntimeRegistry::production_standard()?;
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
        let registry = install_standard_image_runtime_registry(&config, 1, 1, None)
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
