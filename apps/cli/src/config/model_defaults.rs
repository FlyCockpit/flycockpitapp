//! Template-scoped model policy defaults.

use crate::config::extended::LlmMode;
use crate::config::providers::{CacheConfig, CacheMode, CapabilityStatus, ModelEntry};

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
    apply_template_capability_defaults(template, model);
}

/// Apply conservative capability defaults only for known first-class provider
/// templates. Generic OpenAI-compatible providers and Copilot are deliberately
/// excluded because the same model ids may be proxied with different features.
pub fn apply_template_capability_defaults(template: Option<&str>, model: &mut ModelEntry) {
    let Some(template) = template else {
        return;
    };
    match template {
        "openai" | "codex-oauth" => apply_openai_capability_defaults(model),
        "anthropic" => apply_anthropic_capability_defaults(model),
        "deepseek" => apply_deepseek_capability_defaults(model),
        "minimax" => apply_minimax_capability_defaults(model),
        "grok" | "grok-oauth" => apply_grok_capability_defaults(model),
        "z-ai" => apply_zai_capability_defaults(model),
        "xiaomi-mimo" => apply_mimo_capability_defaults(model),
        "opencode-zen" => apply_opencode_zen_capability_defaults(model),
        _ => {}
    }
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

fn apply_openai_capability_defaults(model: &mut ModelEntry) {
    // Source: https://platform.openai.com/docs/models
    let id = model.id.to_ascii_lowercase();
    if id.starts_with("gpt-5") {
        fill_chat_core(model, 400_000, Some(128_000));
        fill_images(model, true);
        fill_reasoning(model, CapabilityStatus::Supported);
    } else if id.starts_with("gpt-4.1") {
        fill_chat_core(model, 1_000_000, Some(32_768));
        fill_images(model, true);
    } else if id.starts_with("gpt-4o") {
        fill_chat_core(model, 128_000, Some(16_384));
        fill_images(model, true);
    } else if id.starts_with("o3") || id.starts_with("o4") {
        fill_chat_core(model, 200_000, Some(100_000));
        fill_images(model, true);
        fill_reasoning(model, CapabilityStatus::Supported);
    }
}

fn apply_anthropic_capability_defaults(model: &mut ModelEntry) {
    // Source: https://docs.anthropic.com/en/api/models-list
    let id = model.id.to_ascii_lowercase();
    if !id.starts_with("claude-") {
        return;
    }
    fill_chat_core(model, 200_000, Some(64_000));
    fill_images(model, true);
    if id.contains("opus") || id.contains("sonnet") || id.contains("fable") {
        fill_reasoning(model, CapabilityStatus::Supported);
    }
}

fn apply_deepseek_capability_defaults(model: &mut ModelEntry) {
    // Sources: https://api-docs.deepseek.com/api/list-models and
    // https://api-docs.deepseek.com/guides/reasoning_model
    let id = model.id.to_ascii_lowercase();
    if id == "deepseek-reasoner" || id.contains("deepseek-r1") {
        fill_u32(&mut model.capabilities.context_tokens, 64_000);
        fill_u32(&mut model.capabilities.max_output_tokens, 8_000);
        fill_reasoning(model, CapabilityStatus::Supported);
        fill_status(
            &mut model.capabilities.tool_calling,
            CapabilityStatus::Unsupported,
        );
    } else if id == "deepseek-chat" || id.starts_with("deepseek-v") {
        fill_chat_core(model, 64_000, Some(8_000));
    }
}

fn apply_minimax_capability_defaults(model: &mut ModelEntry) {
    // Source: https://www.minimax.io/platform/document
    let id = model.id.to_ascii_lowercase();
    if id.contains("m3") {
        fill_chat_core(model, 1_000_000, Some(64_000));
        fill_images(model, true);
        fill_reasoning(model, CapabilityStatus::Supported);
    } else if id.contains("m2") {
        fill_chat_core(model, 204_800, Some(16_384));
        fill_reasoning(model, CapabilityStatus::Supported);
    }
}

fn apply_grok_capability_defaults(model: &mut ModelEntry) {
    // Source: https://docs.x.ai/docs/models
    let id = model.id.to_ascii_lowercase();
    if id.contains("imagine") || id.contains("voice") || id.contains("image-generation") {
        return;
    }
    if id.starts_with("grok-4") {
        fill_chat_core(model, 500_000, Some(128_000));
        fill_reasoning(model, CapabilityStatus::Supported);
    }
}

fn apply_zai_capability_defaults(model: &mut ModelEntry) {
    // Source: https://docs.z.ai/guides/llm/glm-5.2
    let id = model.id.to_ascii_lowercase();
    if id.starts_with("glm-5.2") {
        fill_chat_core(model, 1_000_000, Some(128_000));
        fill_reasoning(model, CapabilityStatus::Supported);
    }
}

fn apply_mimo_capability_defaults(model: &mut ModelEntry) {
    // Source: https://platform.moonshot.ai/docs/guide/mimo
    let id = model.id.to_ascii_lowercase();
    if id.contains("mimo-v2.5") || id.contains("mimo-v2-5") {
        fill_chat_core(model, 1_000_000, Some(64_000));
        fill_reasoning(model, CapabilityStatus::Supported);
        if !id.contains("pro") {
            fill_images(model, true);
        }
    } else if id.contains("mimo-v2-flash") {
        fill_chat_core(model, 256_000, Some(32_000));
    }
}

fn apply_opencode_zen_capability_defaults(model: &mut ModelEntry) {
    // Source: https://opencode.ai/docs/zen
    let id = model.id.to_ascii_lowercase();
    if id.contains("zen") || id.starts_with("kimi-") || id.starts_with("qwen") {
        fill_chat_core(model, 256_000, Some(32_000));
        fill_reasoning(model, CapabilityStatus::Supported);
    }
}

fn fill_chat_core(model: &mut ModelEntry, context_tokens: u32, max_output_tokens: Option<u32>) {
    fill_u32(&mut model.capabilities.context_tokens, context_tokens);
    if let Some(max_output_tokens) = max_output_tokens {
        fill_u32(&mut model.capabilities.max_output_tokens, max_output_tokens);
    }
    fill_status(
        &mut model.capabilities.tool_calling,
        CapabilityStatus::Supported,
    );
    fill_status(
        &mut model.capabilities.structured_outputs,
        CapabilityStatus::Supported,
    );
}

fn fill_images(model: &mut ModelEntry, images: bool) {
    if model.capabilities.images.is_none() {
        model.capabilities.images = Some(images);
    }
}

fn fill_reasoning(model: &mut ModelEntry, status: CapabilityStatus) {
    fill_status(&mut model.capabilities.reasoning, status);
}

fn fill_status(field: &mut CapabilityStatus, status: CapabilityStatus) {
    if field.is_unknown() {
        *field = status;
    }
}

fn fill_u32(field: &mut Option<u32>, value: u32) {
    if field.is_none() {
        *field = Some(value);
    }
}
