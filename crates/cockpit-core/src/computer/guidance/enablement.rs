//! Production resolver that feeds the four `allow_computer_guidance_proposals`
//! config layers into the pure [`resolve_enablement`] algebra.
//!
//! The pure four-layer resolver lives in [`super`]; this module owns the
//! impure half: reading the layered config values (global + canonical
//! machine-local project doc layers, plus the provider and model catalog
//! layers) and mapping each `absent | enabled | disabled` value into
//! [`EnablementLayers`].
//!
//! Default-off: with every layer absent the result is disabled; any explicit
//! disable at any layer is a sticky safety veto that no narrower enable can
//! lift. cockpit-config cannot depend on cockpit-core, so the config crate
//! exposes the raw per-layer `Option<bool>` values and this resolver performs
//! the mapping.

use std::path::Path;

use crate::config::providers::ProvidersConfig;

use super::{EnablementLayers, EnablementResolution, EnablementValue, resolve_enablement};

/// Read the provider-layer `allow_computer_guidance_proposals` value.
fn provider_layer_value(providers: &ProvidersConfig, provider_id: &str) -> Option<bool> {
    providers
        .providers
        .get(provider_id)
        .and_then(|entry| entry.allow_computer_guidance_proposals)
}

/// Read the model-layer `allow_computer_guidance_proposals` value.
fn model_layer_value(
    providers: &ProvidersConfig,
    provider_id: &str,
    model_id: &str,
) -> Option<bool> {
    providers
        .model_entry(provider_id, model_id)
        .and_then(|model| model.allow_computer_guidance_proposals)
}

/// Resolve the effective `allow_computer_guidance_proposals` enablement for
/// `(cwd, provider_id, model_id)` across all four layers.
///
/// - **global** and **project** come from the document config layers for
///   `cwd` (home-scoped vs canonical machine-local project), read separately
///   — never combined most-restrictively.
/// - **provider** comes from the provider catalog entry.
/// - **model** comes from the model catalog entry keyed by
///   `(provider_id, model_id)`.
///
/// Returns the full [`EnablementResolution`] (effective boolean, the four
/// contributing layer values, and whether a sticky disable veto is present)
/// so a caller can surface the enablement trace. With every layer absent the
/// result is disabled.
pub fn resolve_guidance_enablement(
    providers: &ProvidersConfig,
    cwd: &Path,
    provider_id: &str,
    model_id: &str,
) -> EnablementResolution {
    let doc_layers = crate::config::extended::resolve_guidance_proposal_doc_layers_for_cwd(cwd);

    let layers = EnablementLayers {
        global: EnablementValue::from_bool(doc_layers.global),
        project: EnablementValue::from_bool(doc_layers.project),
        provider: EnablementValue::from_bool(provider_layer_value(providers, provider_id)),
        model: EnablementValue::from_bool(model_layer_value(providers, provider_id, model_id)),
    };

    resolve_enablement(&layers)
}

/// Resolve from an already captured, generation-pinned document projection.
/// Unlike [`resolve_guidance_enablement`], this performs no filesystem I/O.
pub fn resolve_guidance_enablement_pinned(
    providers: &ProvidersConfig,
    global: Option<bool>,
    project: Option<bool>,
    provider_id: &str,
    model_id: &str,
) -> EnablementResolution {
    resolve_enablement(&EnablementLayers {
        global: EnablementValue::from_bool(global),
        project: EnablementValue::from_bool(project),
        provider: EnablementValue::from_bool(provider_layer_value(providers, provider_id)),
        model: EnablementValue::from_bool(model_layer_value(providers, provider_id, model_id)),
    })
}
