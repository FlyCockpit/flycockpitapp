//! Template-scoped model policy defaults.

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

/// Copilot-served model ids that receive product-approved frontier riders
/// (`auto_prune = false` + ephemeral prompt cache) when discovered on a
/// provider created from the `copilot` template. Frontier-tier ids on the
/// standard first-party providers are handled by
/// [`apply_known_frontier_model_defaults`] instead.
pub const COPILOT_FRONTIER_MODEL_IDS: &[&str] = &[
    "gpt-5.5",
    "gpt-5.4",
    "gpt-5.6-sol",
    "claude-opus-4.6",
    "claude-opus-4.7",
    "claude-opus-4.8",
    "claude-fable-5",
];

/// The standard first-party provider **templates** whose models receive the
/// known-frontier defaults ([`apply_known_frontier_model_defaults`]). These
/// endpoints are known to serve the frontier ids verbatim and to prompt-cache,
/// so the defaults are correct there; the same id served through an
/// aggregator such as OpenRouter is left alone. GitHub Copilot has its own
/// template-scoped rider table ([`COPILOT_FRONTIER_MODEL_IDS`]). Matched
/// against a provider's persisted [`ProviderEntry::template`] identity as
/// exposed by [`ProviderEntry::effective_template`], **not** its config-map
/// key — so a renamed connection like `anthropic-work` still gets the defaults.
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

fn is_copilot_frontier_model_id(model_id: &str) -> bool {
    COPILOT_FRONTIER_MODEL_IDS.contains(&model_id)
}

/// Apply the frontier riders directly on `model`: `auto_prune = false` and an
/// ephemeral prompt-cache config. Each is set only when the model has not
/// already pinned its own value, so a user override survives.
fn apply_frontier_riders(model: &mut ModelEntry) {
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

/// Apply model defaults for a provider template. Known frontier models on a
/// standard first-party provider receive product-approved frontier settings.
pub fn apply_template_model_defaults(template: Option<&str>, model: &mut ModelEntry) {
    apply_known_frontier_model_defaults(template, model);
    apply_copilot_model_defaults(template, model);
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
        "openai" => {
            apply_openai_capability_defaults(model);
            // The first-party API-key OpenAI endpoint exposes the shared
            // `/v1/audio/transcriptions` route independently of chat-model
            // modality. Do not extend this to generic compatible or OAuth
            // templates without equally authoritative endpoint evidence.
            fill_status(
                &mut model.capabilities.transcription,
                CapabilityStatus::Supported,
            );
        }
        "codex-oauth" => apply_openai_capability_defaults(model),
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

/// Default a known frontier model on a standard first-party provider. Sets the
/// frontier riders (`auto_prune = false` + ephemeral cache) directly on the
/// matched [`ModelEntry`]; posture is no longer derived from a mode.
pub fn apply_known_frontier_model_defaults(template: Option<&str>, model: &mut ModelEntry) {
    let Some(template) = template else {
        return;
    };
    if !is_frontier_default_provider_template(template) || !is_known_frontier_model_id(&model.id) {
        return;
    }
    apply_frontier_riders(model);
}

/// Default known Copilot-served frontier model ids on a provider created from
/// the `copilot` template. Frontier-tier ids get the full frontier riders
/// (`auto_prune = false` + ephemeral cache) directly on the matched
/// [`ModelEntry`]; posture is no longer derived from a mode.
pub fn apply_copilot_model_defaults(template: Option<&str>, model: &mut ModelEntry) {
    if template != Some("copilot") || !is_copilot_frontier_model_id(&model.id) {
        return;
    }
    apply_frontier_riders(model);
}

fn apply_openai_capability_defaults(model: &mut ModelEntry) {
    // Source: OpenAI/Azure prompt-caching docs, rechecked 2026-07-24.
    let id = model.id.to_ascii_lowercase();
    if id.starts_with("gpt-5") {
        fill_chat_core(model, 400_000, Some(128_000));
        fill_images(model, true);
        fill_reasoning(model, CapabilityStatus::Supported);
        fill_prompt_cache_retention(model, openai_prompt_cache_retention_status(&id));
    } else if id.starts_with("gpt-4.1") {
        fill_chat_core(model, 1_000_000, Some(32_768));
        fill_images(model, true);
        fill_prompt_cache_retention(model, CapabilityStatus::Supported);
    } else if id.starts_with("gpt-4o") {
        fill_chat_core(model, 128_000, Some(16_384));
        fill_images(model, true);
    } else if id.starts_with("o3") || id.starts_with("o4") {
        fill_chat_core(model, 200_000, Some(100_000));
        fill_images(model, true);
        fill_reasoning(model, CapabilityStatus::Supported);
    }
}

fn openai_prompt_cache_retention_status(id: &str) -> CapabilityStatus {
    if id == "gpt-5" || id.starts_with("gpt-5-codex") {
        return CapabilityStatus::Supported;
    }
    let Some(rest) = id.strip_prefix("gpt-5.") else {
        return CapabilityStatus::Unknown;
    };
    let minor = rest
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    let Ok(minor) = minor.parse::<u32>() else {
        return CapabilityStatus::Unknown;
    };
    if (1..=5).contains(&minor) {
        CapabilityStatus::Supported
    } else if minor >= 6 {
        CapabilityStatus::Unsupported
    } else {
        CapabilityStatus::Unknown
    }
}

fn apply_anthropic_capability_defaults(model: &mut ModelEntry) {
    // Source: https://docs.anthropic.com/en/api/models-list
    let id = model.id.to_ascii_lowercase();
    if !id.starts_with("claude-") {
        return;
    }
    // Model output limits change across Claude families and must come from
    // catalog metadata or explicit user/provider configuration. Guessing here
    // would make native requests appear available with an unauthoritative
    // `max_tokens` value.
    fill_chat_core(model, 200_000, None);
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
    fill_status(
        &mut model.capabilities.image_input,
        if images {
            CapabilityStatus::Supported
        } else {
            CapabilityStatus::Unsupported
        },
    );
}

fn fill_reasoning(model: &mut ModelEntry, status: CapabilityStatus) {
    fill_status(&mut model.capabilities.reasoning, status);
}

fn fill_prompt_cache_retention(model: &mut ModelEntry, status: CapabilityStatus) {
    fill_status(&mut model.capabilities.prompt_cache_retention, status);
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
