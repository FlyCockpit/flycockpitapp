//! Template-scoped model policy defaults.

use crate::config::extended::LlmMode;
use crate::config::providers::{CacheConfig, CacheMode, ModelEntry};

pub const KNOWN_FRONTIER_MODEL_IDS: &[&str] = &[
    "claude-fable-5",
    "claude-opus-4-6",
    "claude-opus-4-7",
    "claude-opus-4-8",
    "glm-5.2",
    "gpt-5.4",
    "gpt-5.5",
    "gpt-5.6",
    "grok-4.5",
];

pub const COPILOT_MODEL_MODE_DEFAULTS: &[(&str, LlmMode)] = &[
    ("gpt-5.5", LlmMode::Frontier),
    ("gpt-5.4", LlmMode::Frontier),
    ("gpt-5.6-sol", LlmMode::Frontier),
    ("claude-opus-4.6", LlmMode::Frontier),
    ("claude-opus-4.7", LlmMode::Frontier),
    ("claude-opus-4.8", LlmMode::Frontier),
    ("claude-fable-5", LlmMode::Frontier),
    ("claude-sonnet-4.6", LlmMode::Normal),
    ("claude-sonnet-4.7", LlmMode::Normal),
    ("claude-sonnet-4.8", LlmMode::Normal),
    ("gpt-5.6-terra", LlmMode::Normal),
    ("kimi-k2.7-code", LlmMode::Normal),
    ("gpt-3.5-turbo", LlmMode::Defensive),
    ("gpt-3.5-turbo-0613", LlmMode::Defensive),
    ("gpt-4", LlmMode::Defensive),
    ("gpt-4-0613", LlmMode::Defensive),
    ("gpt-4.1", LlmMode::Defensive),
    ("gpt-4.1-2025-04-14", LlmMode::Defensive),
    ("gpt-4o", LlmMode::Defensive),
    ("gpt-4-o-preview", LlmMode::Defensive),
    ("gpt-4o-preview", LlmMode::Defensive),
    ("gpt-4o-mini", LlmMode::Defensive),
    ("gpt-4o-mini-2024-07-18", LlmMode::Defensive),
    ("gpt-4o-2024-11-20", LlmMode::Defensive),
    ("gpt-4o-2024-08-06", LlmMode::Defensive),
    ("gpt-4o-2024-05-13", LlmMode::Defensive),
    ("claude-haiku-4.5", LlmMode::Defensive),
    ("gemini-2.5-pro", LlmMode::Defensive),
    ("gemini-3.1-pro-preview", LlmMode::Defensive),
    ("gemini-3.5-flash", LlmMode::Defensive),
];

/// The standard first-party provider **templates** whose models receive the
/// known-frontier defaults ([`apply_known_frontier_model_defaults`]). These
/// endpoints are known to serve the frontier ids verbatim and to prompt-cache,
/// so the defaults are correct there; the same id served through an
/// aggregator such as OpenRouter is left alone. GitHub Copilot has its own
/// template-scoped mode table ([`COPILOT_MODEL_MODE_DEFAULTS`]). Matched
/// against a provider's persisted [`ProviderEntry::template`] identity (with a
/// map-key fallback via [`ProviderEntry::effective_template`]), **not** its
/// config-map key — so a renamed connection like `anthropic-work` still gets
/// the defaults.
pub const FRONTIER_DEFAULT_PROVIDER_IDS: &[&str] =
    &["anthropic", "codex-oauth", "grok-oauth", "openai", "z-ai"];

pub fn is_known_frontier_model_id(model_id: &str) -> bool {
    KNOWN_FRONTIER_MODEL_IDS.contains(&model_id)
}

/// Whether a provider `template` id gates the known-frontier defaults
/// ([`FRONTIER_DEFAULT_PROVIDER_IDS`]). Callers pass the provider's effective
/// template identity ([`ProviderEntry::effective_template`]), not the config-map
/// key, so renaming e.g. `anthropic` to `anthropic-work` keeps the defaults.
pub fn is_frontier_default_provider_template(template: &str) -> bool {
    FRONTIER_DEFAULT_PROVIDER_IDS.contains(&template)
}

pub fn copilot_default_mode_for_model_id(model_id: &str) -> Option<LlmMode> {
    COPILOT_MODEL_MODE_DEFAULTS
        .iter()
        .find_map(|(id, mode)| (*id == model_id).then_some(*mode))
}

/// Apply model defaults for a provider template. Known frontier models on a
/// standard first-party provider receive product-approved frontier settings.
pub fn apply_template_model_defaults(template: Option<&str>, model: &mut ModelEntry) {
    apply_known_frontier_model_defaults(template, model);
    apply_copilot_model_mode_defaults(template, model);
}

/// Default a known frontier model on a standard first-party provider.
pub fn apply_known_frontier_model_defaults(template: Option<&str>, model: &mut ModelEntry) {
    let Some(template) = template else {
        return;
    };
    if !is_frontier_default_provider_template(template) || !is_known_frontier_model_id(&model.id) {
        return;
    }
    if model.mode.is_none() {
        model.mode = Some(LlmMode::Frontier);
    }
    if model.auto_prune.is_none() {
        model.auto_prune = Some(false);
    }
    if model.cache.is_none() {
        model.cache = Some(CacheConfig {
            mode: CacheMode::Ephemeral,
            ttl_secs: CacheConfig::default().ttl_secs,
        });
    }
}

/// Default known Copilot-served model ids on a provider created from the
/// `copilot` template. Frontier-tier ids get the full frontier defaults.
pub fn apply_copilot_model_mode_defaults(template: Option<&str>, model: &mut ModelEntry) {
    if template != Some("copilot") {
        return;
    }
    let Some(mode) = copilot_default_mode_for_model_id(&model.id) else {
        return;
    };
    if model.mode.is_none() {
        model.mode = Some(mode);
    }
    if mode == LlmMode::Frontier {
        if model.auto_prune.is_none() {
            model.auto_prune = Some(false);
        }
        if model.cache.is_none() {
            model.cache = Some(CacheConfig {
                mode: CacheMode::Ephemeral,
                ttl_secs: CacheConfig::default().ttl_secs,
            });
        }
    }
}
