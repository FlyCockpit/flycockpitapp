use super::*;

#[test]
fn deepseek_builtin_default_maps_all_four_modes() {
    let cfg = ProvidersConfig::default();
    // Nothing configured for `deepseek` — the bottom tier (built-in
    // default keyed by provider id) supplies the fragment.
    assert_eq!(
        cfg.resolve_thinking_params("deepseek", "deepseek-reasoner", ThinkingMode::Off),
        Some(serde_json::json!({ "thinking": { "type": "disabled" } })),
    );
    assert_eq!(
        cfg.resolve_thinking_params("deepseek", "deepseek-reasoner", ThinkingMode::Low),
        Some(serde_json::json!({
            "thinking": { "type": "enabled" }, "reasoning_effort": "low"
        })),
    );
    assert_eq!(
        cfg.resolve_thinking_params("deepseek", "deepseek-reasoner", ThinkingMode::Medium),
        Some(serde_json::json!({
            "thinking": { "type": "enabled" }, "reasoning_effort": "medium"
        })),
    );
    assert_eq!(
        cfg.resolve_thinking_params("deepseek", "deepseek-reasoner", ThinkingMode::High),
        Some(serde_json::json!({
            "thinking": { "type": "enabled" }, "reasoning_effort": "high"
        })),
    );
}

/// A provider with no built-in mapping and no configured override sends
/// no extra keys for any mode — every existing provider's request is
/// byte-for-byte unchanged.
#[test]
fn provider_without_mapping_sends_no_extra_params() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers
        .insert("z-ai".into(), ProviderEntry::default());
    for mode in [
        ThinkingMode::Off,
        ThinkingMode::Low,
        ThinkingMode::Medium,
        ThinkingMode::High,
    ] {
        assert_eq!(cfg.resolve_thinking_params("z-ai", "glm-4.6", mode), None);
    }
    // An entirely unknown provider also resolves to nothing.
    assert_eq!(
        cfg.resolve_thinking_params("nope", "whatever", ThinkingMode::High),
        None
    );
}

#[test]
fn resolve_reasoning_effort_params_uses_native_mapping_and_default() {
    let mut cfg = ProvidersConfig::default();
    let mut mapping = BTreeMap::new();
    mapping.insert("minimal".to_string(), serde_json::json!("minimal"));
    mapping.insert("xhigh".to_string(), serde_json::json!("xhigh"));
    cfg.providers.insert(
        "codex".into(),
        ProviderEntry {
            models: vec![ModelEntry {
                id: "gpt-5-codex".into(),
                capabilities: ModelCapabilities {
                    reasoning_effort: Some(ReasoningEffortCapability {
                        values: vec![
                            CapabilityValue {
                                value: "minimal".into(),
                                label: Some("Minimal".into()),
                                description: None,
                            },
                            CapabilityValue {
                                value: "xhigh".into(),
                                label: Some("Extra high".into()),
                                description: None,
                            },
                        ],
                        default: Some("minimal".into()),
                        request_mapping: Some(ReasoningEffortRequestMapping::JsonField {
                            field: "reasoning_effort".into(),
                            values: mapping,
                        }),
                        source: Some(CapabilitySource::Live),
                    }),
                    ..ModelCapabilities::default()
                },
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );

    assert_eq!(
        cfg.resolve_reasoning_effort_params("codex", "gpt-5-codex", None),
        Some(serde_json::json!({ "reasoning_effort": "minimal" }))
    );
    assert_eq!(
        cfg.resolve_reasoning_effort_params("codex", "gpt-5-codex", Some("xhigh")),
        Some(serde_json::json!({ "reasoning_effort": "xhigh" }))
    );
    assert_eq!(
        cfg.resolve_reasoning_effort_params("codex", "gpt-5-codex", Some("stale")),
        None,
        "an explicit stale selection must not silently fall back to the default"
    );

    cfg.active_model = Some(ActiveModelRef {
        provider: "codex".into(),
        model: "gpt-5-codex".into(),
        reasoning_effort: Some(ActiveReasoningEffort {
            value: "xhigh".into(),
        }),
        thinking_mode: Some(ThinkingMode::High),
    });
    assert_eq!(
        cfg.resolve_active_model_reasoning_params(),
        Some(serde_json::json!({ "reasoning_effort": "xhigh" }))
    );
}

#[test]
fn resolve_capabilities_applies_model_overrides_after_detection() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "p".into(),
        ProviderEntry {
            capabilities: ProviderCapabilities {
                images: Some(false),
                context_tokens: Some(100_000),
                max_output_tokens: Some(8_000),
                tool_calling: CapabilityStatus::Unsupported,
                structured_outputs: CapabilityStatus::Unsupported,
                ..ProviderCapabilities::default()
            },
            models: vec![ModelEntry {
                id: "m".into(),
                capabilities: ModelCapabilities {
                    images: Some(false),
                    context_tokens: Some(200_000),
                    max_output_tokens: Some(16_000),
                    tool_calling: CapabilityStatus::Unsupported,
                    structured_outputs: CapabilityStatus::Unsupported,
                    ..ModelCapabilities::default()
                },
                capability_overrides: ModelCapabilityOverrides {
                    images: Some(true),
                    context_tokens: Some(300_000),
                    max_output_tokens: Some(32_000),
                    tool_calling: Some(CapabilityStatus::Supported),
                    structured_outputs: Some(CapabilityStatus::Supported),
                    ..ModelCapabilityOverrides::default()
                },
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );

    let caps = cfg.resolve_capabilities("p", "m");
    assert_eq!(caps.images, Some(true));
    assert_eq!(caps.context_tokens, Some(300_000));
    assert_eq!(caps.max_output_tokens, Some(32_000));
    assert_eq!(caps.tool_calling, CapabilityStatus::Supported);
    assert_eq!(caps.structured_outputs, CapabilityStatus::Supported);
}

#[test]
fn resolve_capabilities_selects_computer_contract_from_metadata() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "p".into(),
        ProviderEntry {
            capabilities: ProviderCapabilities {
                computer_use: ComputerUseCapability {
                    contract: Some(ComputerUseContract::Anthropic20250124),
                    source: Some(CapabilitySource::Manual),
                },
                ..ProviderCapabilities::default()
            },
            models: vec![ModelEntry {
                id: "m".into(),
                capabilities: ModelCapabilities {
                    computer_use: ComputerUseCapability {
                        contract: Some(ComputerUseContract::Anthropic20251124),
                        source: Some(CapabilitySource::Manual),
                    },
                    ..ModelCapabilities::default()
                },
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );

    let caps = cfg.resolve_capabilities("p", "m");
    assert_eq!(
        caps.computer_use.as_ref().and_then(|cap| cap.contract),
        Some(ComputerUseContract::Anthropic20251124)
    );
    let caps = cfg.resolve_capabilities("p", "unknown-model");
    assert_eq!(
        caps.computer_use.as_ref().and_then(|cap| cap.contract),
        Some(ComputerUseContract::Anthropic20250124)
    );
}

#[test]
fn probed_capability_precedence_order() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "entry".into(),
        ProviderEntry {
            models: vec![ModelEntry {
                id: "entry-only".into(),
                context_length: Some(32_000),
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );
    cfg.providers.insert(
        "p".into(),
        ProviderEntry {
            capabilities: ProviderCapabilities {
                context_tokens: Some(64_000),
                ..ProviderCapabilities::default()
            },
            models: vec![
                ModelEntry {
                    id: "detected".into(),
                    context_length: Some(32_000),
                    capabilities: ModelCapabilities {
                        context_tokens: Some(96_000),
                        context_tokens_source: Some(CapabilitySource::Live),
                        ..ModelCapabilities::default()
                    },
                    ..ModelEntry::default()
                },
                ModelEntry {
                    id: "probed".into(),
                    context_length: Some(32_000),
                    capabilities: ModelCapabilities {
                        context_tokens: Some(128_000),
                        context_tokens_source: Some(CapabilitySource::Probed),
                        ..ModelCapabilities::default()
                    },
                    ..ModelEntry::default()
                },
                ModelEntry {
                    id: "manual".into(),
                    context_length: Some(32_000),
                    capabilities: ModelCapabilities {
                        context_tokens: Some(128_000),
                        context_tokens_source: Some(CapabilitySource::Probed),
                        ..ModelCapabilities::default()
                    },
                    capability_overrides: ModelCapabilityOverrides {
                        context_tokens: Some(256_000),
                        ..ModelCapabilityOverrides::default()
                    },
                    ..ModelEntry::default()
                },
            ],
            ..ProviderEntry::default()
        },
    );

    assert_eq!(
        cfg.resolve_capabilities("entry", "entry-only")
            .context_tokens,
        Some(32_000)
    );
    assert_eq!(
        cfg.resolve_capabilities("p", "detected").context_tokens,
        Some(96_000)
    );
    assert_eq!(
        cfg.resolve_capabilities("p", "probed").context_tokens,
        Some(128_000)
    );
    assert_eq!(
        cfg.resolve_capabilities("p", "manual").context_tokens,
        Some(256_000)
    );
}

#[test]
fn manual_override_beats_probed_value() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "p".into(),
        ProviderEntry {
            models: vec![ModelEntry {
                id: "m".into(),
                capabilities: ModelCapabilities {
                    context_tokens: Some(128_000),
                    context_tokens_source: Some(CapabilitySource::Probed),
                    ..ModelCapabilities::default()
                },
                capability_overrides: ModelCapabilityOverrides {
                    context_tokens: Some(256_000),
                    ..ModelCapabilityOverrides::default()
                },
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );

    let caps = cfg.resolve_capabilities("p", "m");
    assert_eq!(caps.context_tokens, Some(256_000));
}

#[test]
fn probed_context_survives_refetch_on_non_manual_entry() {
    let mut existing = model("gpt-5-mini", false);
    existing.capabilities.context_tokens = Some(128_000);
    existing.capabilities.context_tokens_source = Some(CapabilitySource::Probed);

    let mut fetched = model("gpt-5-mini", false);
    fetched.capabilities.context_tokens = Some(32_000);
    fetched.capabilities.context_tokens_source = Some(CapabilitySource::Live);

    let merged = merge_fetched_models_with_policy(
        Some("openai"),
        &[existing],
        vec![fetched],
        ModelMergePolicy::KeepUnlisted,
    );
    let model = &merged[0];
    assert!(!model.manual);
    assert_eq!(model.capabilities.context_tokens, Some(128_000));
    assert_eq!(
        model.capabilities.context_tokens_source,
        Some(CapabilitySource::Probed)
    );
}

#[test]
fn probed_entry_is_not_manual() {
    let mut model = model("m", false);
    model.capabilities.context_tokens = Some(128_000);
    model.capabilities.context_tokens_source = Some(CapabilitySource::Probed);

    assert!(!model.manual);
}

#[test]
fn merge_refresh_preserves_overrides_but_not_stale_detected_capabilities() {
    let mut existing = model("mimo-v2.5", false);
    existing.capabilities.images = Some(false);
    existing.capability_overrides.images = Some(true);

    let mut fetched = model("mimo-v2.5", false);
    fetched.capabilities.images = Some(false);
    fetched.capabilities.context_tokens = Some(1_000_000);

    let merged = merge_fetched_models_with_policy(
        Some("xiaomi-mimo"),
        &[existing],
        vec![fetched],
        ModelMergePolicy::KeepUnlisted,
    );

    assert_eq!(merged[0].capabilities.images, Some(false));
    assert_eq!(merged[0].capabilities.context_tokens, Some(1_000_000));
    assert_eq!(merged[0].capability_overrides.images, Some(true));
}

#[test]
fn first_class_defaults_apply_only_to_matching_templates() {
    let mut deepseek = model("deepseek-reasoner", false);
    apply_template_model_defaults(Some("deepseek"), &mut deepseek);
    assert_eq!(deepseek.capabilities.reasoning, CapabilityStatus::Supported);
    assert_eq!(deepseek.capabilities.context_tokens, Some(64_000));

    let mut minimax_m3 = model("minimax-m3", false);
    apply_template_model_defaults(Some("minimax"), &mut minimax_m3);
    assert_eq!(minimax_m3.capabilities.images, Some(true));
    assert_eq!(minimax_m3.capabilities.context_tokens, Some(1_000_000));

    let mut minimax_m2 = model("MiniMax-M2", false);
    apply_template_model_defaults(Some("minimax"), &mut minimax_m2);
    assert_eq!(minimax_m2.capabilities.context_tokens, Some(204_800));
    assert_eq!(
        minimax_m2.capabilities.reasoning,
        CapabilityStatus::Supported
    );

    let mut grok = model("grok-4.5", false);
    apply_template_model_defaults(Some("grok"), &mut grok);
    assert_eq!(grok.capabilities.context_tokens, Some(500_000));
    assert_eq!(grok.capabilities.tool_calling, CapabilityStatus::Supported);

    let mut grok_imagine = model("grok-4-imagine", false);
    apply_template_model_defaults(Some("grok"), &mut grok_imagine);
    assert!(grok_imagine.capabilities.is_empty());

    let mut zai = model("glm-5.2", false);
    apply_template_model_defaults(Some("z-ai"), &mut zai);
    assert_eq!(zai.capabilities.context_tokens, Some(1_000_000));
    assert_eq!(zai.capabilities.max_output_tokens, Some(128_000));

    let mut mimo = model("mimo-v2.5", false);
    apply_template_model_defaults(Some("xiaomi-mimo"), &mut mimo);
    assert_eq!(mimo.capabilities.images, Some(true));
    assert_eq!(mimo.capabilities.context_tokens, Some(1_000_000));
    assert_eq!(mimo.capabilities.reasoning, CapabilityStatus::Supported);

    let mut pro = model("mimo-v2.5-pro", false);
    apply_template_model_defaults(Some("xiaomi-mimo"), &mut pro);
    assert_eq!(pro.capabilities.images, None);
    assert_eq!(pro.capabilities.context_tokens, Some(1_000_000));

    let mut zen = model("kimi-k2.7-code", false);
    apply_template_model_defaults(Some("opencode-zen"), &mut zen);
    assert_eq!(zen.capabilities.context_tokens, Some(256_000));
    assert_eq!(zen.capabilities.tool_calling, CapabilityStatus::Supported);

    let mut openai = model("gpt-4o", false);
    apply_template_model_defaults(Some("openai"), &mut openai);
    assert_eq!(openai.capabilities.images, Some(true));
    assert_eq!(
        openai.capabilities.structured_outputs,
        CapabilityStatus::Supported
    );

    let mut generic = model("mimo-v2.5", false);
    apply_template_model_defaults(Some("openai-compatible"), &mut generic);
    assert!(generic.capabilities.is_empty());

    let mut copilot = model("gpt-4o", false);
    apply_template_model_defaults(Some("copilot"), &mut copilot);
    assert!(copilot.capabilities.is_empty());
}

#[test]
fn fallback_models_without_effort_values_do_not_resolve_reasoning_params() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "codex".into(),
        ProviderEntry {
            models: vec![ModelEntry {
                id: "fallback".into(),
                capabilities: ModelCapabilities {
                    reasoning_effort: Some(ReasoningEffortCapability {
                        source: Some(CapabilitySource::Fallback),
                        ..ReasoningEffortCapability::default()
                    }),
                    ..ModelCapabilities::default()
                },
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );

    assert!(!cfg.has_reasoning_effort_capability("codex", "fallback"));
    assert_eq!(
        cfg.resolve_reasoning_effort_params("codex", "fallback", Some("high")),
        None
    );
}

/// A configured layer that maps only some modes shadows the lower tiers
/// for EVERY mode: a mode the winning layer doesn't list resolves to
/// `None` (send nothing) rather than falling through. This is the
/// "explicit override is total" rule.
#[test]
fn configured_layer_with_partial_modes_does_not_fall_through() {
    let mut cfg = ProvidersConfig::default();
    let mut deepseek = ProviderEntry::default();
    deepseek.thinking_params.0.insert(
        ThinkingMode::High,
        serde_json::json!({ "reasoning_effort": "max" }),
    );
    cfg.providers.insert("deepseek".into(), deepseek);

    // High uses the configured provider fragment...
    assert_eq!(
        cfg.resolve_thinking_params("deepseek", "deepseek-reasoner", ThinkingMode::High),
        Some(serde_json::json!({ "reasoning_effort": "max" })),
    );
    // ...but Off does NOT fall through to the built-in disabled form,
    // because the provider layer is the winner and lists no Off entry.
    assert_eq!(
        cfg.resolve_thinking_params("deepseek", "deepseek-reasoner", ThinkingMode::Off),
        None,
    );
}

/// Three-tier precedence (per-model → per-provider → built-in default),
/// mirroring `resolve_inline_think_three_tier_precedence`.
#[test]
fn resolve_thinking_params_three_tier_precedence() {
    let mut cfg = ProvidersConfig::default();

    // A `deepseek` provider that pins its own provider-level fragment
    // for High, plus a model that pins its own model-level fragment.
    let mut deepseek = ProviderEntry::default();
    deepseek.thinking_params.0.insert(
        ThinkingMode::High,
        serde_json::json!({ "provider_level": true }),
    );
    let mut pinned = model("pinned", true);
    pinned.thinking_params.0.insert(
        ThinkingMode::High,
        serde_json::json!({ "model_level": true }),
    );
    deepseek.models.push(pinned);
    deepseek.models.push(model("inherit", false));
    cfg.providers.insert("deepseek".into(), deepseek);

    // Top tier: the per-model fragment wins over the provider fragment
    // AND over the built-in DeepSeek default.
    assert_eq!(
        cfg.resolve_thinking_params("deepseek", "pinned", ThinkingMode::High),
        Some(serde_json::json!({ "model_level": true })),
    );
    // Middle tier: a model with no map of its own falls to the provider
    // fragment (not the built-in default).
    assert_eq!(
        cfg.resolve_thinking_params("deepseek", "inherit", ThinkingMode::High),
        Some(serde_json::json!({ "provider_level": true })),
    );

    // Bottom tier: a provider with no configured map at all falls to the
    // built-in default keyed by provider id.
    let mut cfg2 = ProvidersConfig::default();
    cfg2.providers
        .insert("deepseek".into(), ProviderEntry::default());
    assert_eq!(
        cfg2.resolve_thinking_params("deepseek", "any", ThinkingMode::High),
        Some(serde_json::json!({
            "thinking": { "type": "enabled" }, "reasoning_effort": "high"
        })),
    );
}

/// An unset `thinking_params` map is skipped on serialize at both the
/// provider and model scope (so configs that never pin it stay clean),
/// and a configured one round-trips.
#[test]
fn thinking_params_skipped_on_serialize_when_empty() {
    let unset = ProviderEntry::default();
    let json = serde_json::to_string(&unset).unwrap();
    assert!(!json.contains("thinking_params"));

    let unset_model = model("m", true);
    let json = serde_json::to_string(&unset_model).unwrap();
    assert!(!json.contains("thinking_params"));

    let mut set = ProviderEntry::default();
    set.thinking_params.0.insert(
        ThinkingMode::Off,
        serde_json::json!({ "thinking": { "type": "disabled" } }),
    );
    let json = serde_json::to_string(&set).unwrap();
    assert!(json.contains("thinking_params"));
    // Round-trips back to the same map.
    let back: ProviderEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.thinking_params, set.thinking_params);
}

#[test]
fn provider_inline_think_skipped_on_serialize_when_unset() {
    let unset = ProviderEntry::default();
    let json = serde_json::to_string(&unset).unwrap();
    assert!(!json.contains("inline_think"));
    let set = ProviderEntry {
        inline_think: Some(false),
        ..Default::default()
    };
    let json = serde_json::to_string(&set).unwrap();
    assert!(json.contains("\"inline_think\":false"));
}

#[test]
fn provider_model_catalog_defaults_live_and_serializes_only_for_fallback() {
    let provider = ProviderEntry {
        url: "https://example.test/v1".into(),
        ..ProviderEntry::default()
    };
    let json = serde_json::to_string(&provider).unwrap();
    assert!(
        !json.contains("model_catalog"),
        "live catalog should stay implicit: {json}"
    );

    let provider = ProviderEntry {
        model_catalog: ProviderModelCatalog::CodexFallback,
        ..provider
    };
    let json = serde_json::to_string(&provider).unwrap();
    assert!(
        json.contains("\"model_catalog\":\"codex-fallback\""),
        "{json}"
    );
    let back: ProviderEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.model_catalog, ProviderModelCatalog::CodexFallback);
}

#[test]
fn merge_retains_manual_entry_across_refetch() {
    let existing = vec![model("fetched-old", false), model("hand-added", true)];
    // A refetch returns a fresh fetched list that no longer includes
    // the old fetched id and never knew about the manual one.
    let fetched = vec![model("fetched-new", false)];
    let merged = merge_fetched_models_with_policy(
        Some("p"),
        &existing,
        fetched,
        ModelMergePolicy::KeepUnlisted,
    );

    let ids: Vec<&str> = merged.iter().map(|m| m.id.as_str()).collect();
    // The default safe merge keeps unlisted configured entries and adds
    // the fetched entry.
    assert!(ids.contains(&"hand-added"));
    assert!(ids.contains(&"fetched-old"));
    assert!(ids.contains(&"fetched-new"));
    // The manual entry keeps its manual flag.
    assert!(merged.iter().find(|m| m.id == "hand-added").unwrap().manual);
}

#[test]
fn merge_manual_wins_on_id_collision_no_duplicate() {
    let existing = vec![model("shared", true)];
    // The refetch returns an id that collides with the manual entry.
    let fetched = vec![model("shared", false), model("other", false)];
    let merged = merge_fetched_models_with_policy(
        Some("p"),
        &existing,
        fetched,
        ModelMergePolicy::KeepUnlisted,
    );

    // Exactly one `shared` row, and it's the manual one.
    let shared: Vec<&ModelEntry> = merged.iter().filter(|m| m.id == "shared").collect();
    assert_eq!(shared.len(), 1, "manual entry must dedupe the fetched dup");
    assert!(shared[0].manual);
    // The non-colliding fetched entry is still added.
    assert!(merged.iter().any(|m| m.id == "other" && !m.manual));
}

#[test]
fn merge_policy_remove_drops_unlisted_fetched_entries_but_retains_manual() {
    let existing = vec![model("fetched-old", false), model("hand-added", true)];
    let fetched = vec![model("fetched-new", false)];
    let merged = merge_fetched_models_with_policy(
        Some("p"),
        &existing,
        fetched,
        ModelMergePolicy::RemoveUnlisted,
    );

    let ids: Vec<&str> = merged.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(ids, vec!["fetched-new", "hand-added"]);
    assert!(merged.iter().find(|m| m.id == "hand-added").unwrap().manual);
}

#[test]
fn known_frontier_model_ids_are_exact_matches() {
    assert!(is_known_frontier_model_id("gpt-5.4"));
    assert!(is_known_frontier_model_id("gpt-5.5"));
    assert!(is_known_frontier_model_id("gpt-5.6"));
    assert!(is_known_frontier_model_id("glm-5.2"));
    assert!(is_known_frontier_model_id("claude-opus-4-6"));
    assert!(is_known_frontier_model_id("claude-opus-4-7"));
    assert!(is_known_frontier_model_id("claude-opus-4-8"));
    assert!(is_known_frontier_model_id("claude-fable-5"));
    assert!(is_known_frontier_model_id("grok-4.5"));
    assert!(!is_known_frontier_model_id("gpt-5.5-mini"));
    assert!(!is_known_frontier_model_id("grok-4.5-fast"));
    assert!(!is_known_frontier_model_id("openai/gpt-5.5"));
    assert!(!is_known_frontier_model_id("claude-opus-4-5-20251101"));
    assert!(!is_known_frontier_model_id("kimi-for-coding"));
}

/// The frontier-defaults gate is an exact-**template** match. A renamed
/// connection keeps its template identity (so the gate stays keyed to the
/// vendor, not the config-map key), but an unrelated template id is not a
/// member.
#[test]
fn frontier_default_provider_ids_are_exact_matches() {
    assert!(is_frontier_default_provider_template("anthropic"));
    assert!(is_frontier_default_provider_template("codex-oauth"));
    assert!(is_frontier_default_provider_template("openai"));
    assert!(is_frontier_default_provider_template("grok-oauth"));
    assert!(is_frontier_default_provider_template("z-ai"));
    // A config-map key rename is not a template, so it is not a member —
    // the caller resolves the template identity before consulting the gate.
    assert!(!is_frontier_default_provider_template("anthropic-work"));
    assert!(!is_frontier_default_provider_template("openrouter"));
}

#[test]
fn copilot_model_mode_defaults_are_exact_matches_by_tier() {
    assert_eq!(
        COPILOT_MODEL_MODE_DEFAULTS.len(),
        30,
        "the product table should remain exact"
    );
    for (id, mode) in [
        ("gpt-5.5", LlmMode::Frontier),
        ("claude-opus-4.8", LlmMode::Frontier),
        ("claude-sonnet-4.7", LlmMode::Normal),
        ("kimi-k2.7-code", LlmMode::Normal),
        ("gpt-4-o-preview", LlmMode::Defensive),
        ("gpt-4o-preview", LlmMode::Defensive),
        ("gemini-3.5-flash", LlmMode::Defensive),
    ] {
        assert_eq!(copilot_default_mode_for_model_id(id), Some(mode), "{id}");
    }
    assert_eq!(copilot_default_mode_for_model_id("gpt-5.5-mini"), None);
    assert_eq!(copilot_default_mode_for_model_id("openai/gpt-5.5"), None);
    assert_eq!(copilot_default_mode_for_model_id("claude-opus-4-8"), None);
}

#[test]
fn copilot_defaults_apply_only_to_newly_discovered_copilot_models() {
    let mut pinned = model("claude-sonnet-4.7", false);
    pinned.mode = Some(LlmMode::Defensive);
    let cleared = model("gpt-4o", false);

    let merged = merge_fetched_models_with_policy(
        Some("copilot"),
        &[pinned, cleared],
        vec![
            model("gpt-5.5", false),
            model("claude-sonnet-4.7", false),
            model("gpt-4o", false),
            model("ordinary", false),
        ],
        ModelMergePolicy::KeepUnlisted,
    );
    let by_id = |id: &str| merged.iter().find(|m| m.id == id).unwrap();

    let frontier = by_id("gpt-5.5");
    assert_eq!(frontier.mode, Some(LlmMode::Frontier));
    assert_eq!(frontier.auto_prune, Some(false));
    assert_eq!(
        frontier.cache,
        Some(CacheConfig {
            mode: CacheMode::Ephemeral,
            ttl_secs: 300,
        })
    );

    let preserved_pinned = by_id("claude-sonnet-4.7");
    assert_eq!(preserved_pinned.mode, Some(LlmMode::Defensive));
    assert_eq!(preserved_pinned.auto_prune, None);
    assert_eq!(preserved_pinned.cache, None);

    let preserved_cleared = by_id("gpt-4o");
    assert_eq!(preserved_cleared.mode, None);
    assert_eq!(preserved_cleared.auto_prune, None);
    assert_eq!(preserved_cleared.cache, None);

    let ordinary = by_id("ordinary");
    assert_eq!(ordinary.mode, None);
    assert_eq!(ordinary.auto_prune, None);
    assert_eq!(ordinary.cache, None);
}

#[test]
fn copilot_normal_and_defensive_defaults_set_mode_only() {
    let merged = merge_fetched_models_with_policy(
        Some("copilot"),
        &[],
        vec![
            model("claude-sonnet-4.6", false),
            model("gpt-4o-mini", false),
        ],
        ModelMergePolicy::KeepUnlisted,
    );
    let by_id = |id: &str| merged.iter().find(|m| m.id == id).unwrap();

    let normal = by_id("claude-sonnet-4.6");
    assert_eq!(normal.mode, Some(LlmMode::Normal));
    assert_eq!(normal.auto_prune, None);
    assert_eq!(normal.cache, None);

    let defensive = by_id("gpt-4o-mini");
    assert_eq!(defensive.mode, Some(LlmMode::Defensive));
    assert_eq!(defensive.auto_prune, None);
    assert_eq!(defensive.cache, None);
}

#[test]
fn copilot_defaults_do_not_apply_to_other_aggregators() {
    let merged = merge_fetched_models_with_policy(
        Some("openrouter"),
        &[],
        vec![
            model("gpt-5.5", false),
            model("claude-sonnet-4.6", false),
            model("gpt-4o-mini", false),
        ],
        ModelMergePolicy::KeepUnlisted,
    );
    for m in &merged {
        assert_eq!(m.mode, None, "{}", m.id);
        assert_eq!(m.auto_prune, None, "{}", m.id);
        assert_eq!(m.cache, None, "{}", m.id);
    }
}

#[test]
fn copilot_defaults_apply_on_manual_model_add_helper() {
    let mut frontier = model("claude-fable-5", true);
    apply_template_model_defaults(Some("copilot"), &mut frontier);
    assert_eq!(frontier.mode, Some(LlmMode::Frontier));
    assert_eq!(frontier.auto_prune, Some(false));
    assert_eq!(
        frontier.cache.as_ref().map(|c| c.mode),
        Some(CacheMode::Ephemeral)
    );

    let mut normal = model("gpt-5.6-terra", true);
    apply_template_model_defaults(Some("copilot"), &mut normal);
    assert_eq!(normal.mode, Some(LlmMode::Normal));
    assert_eq!(normal.auto_prune, None);
    assert_eq!(normal.cache, None);
}

#[test]
fn renamed_copilot_template_connection_gets_copilot_defaults() {
    let entry = ProviderEntry {
        template: Some("copilot".into()),
        ..ProviderEntry::default()
    };
    let merged = merge_fetched_models_with_policy(
        entry.effective_template("copilot-work"),
        &[],
        vec![model("gpt-4o-mini", false)],
        ModelMergePolicy::KeepUnlisted,
    );
    let m = merged.iter().find(|m| m.id == "gpt-4o-mini").unwrap();
    assert_eq!(m.mode, Some(LlmMode::Defensive));
    assert_eq!(m.auto_prune, None);
    assert_eq!(m.cache, None);
}

/// Frontier defaults are applied only to ids this fetch newly discovers.
/// Pre-existing ids keep whatever mode they had (here both are pinned);
/// only the genuinely-new known id (`glm-5.2`) is defaulted to frontier,
/// and non-known new ids are left alone.
#[test]
fn merge_defaults_known_fetched_models_to_frontier_only_when_newly_discovered() {
    let mut existing_normal = model("gpt-5.5", false);
    existing_normal.mode = Some(LlmMode::Normal);
    let mut existing_defensive = model("claude-opus-4-7", false);
    existing_defensive.mode = Some(LlmMode::Defensive);

    let fetched = vec![
        model("glm-5.2", false),
        model("gpt-5.5", false),
        model("claude-opus-4-7", false),
        model("gpt-5.5-mini", false),
        model("ordinary", false),
    ];
    let merged = merge_fetched_models_with_policy(
        Some("codex-oauth"),
        &[existing_normal, existing_defensive],
        fetched,
        ModelMergePolicy::RemoveUnlisted,
    );
    let mode_for = |id: &str| merged.iter().find(|m| m.id == id).and_then(|m| m.mode);

    // Newly-discovered known id → frontier default.
    assert_eq!(mode_for("glm-5.2"), Some(LlmMode::Frontier));
    // Pre-existing ids keep their pinned modes (no re-default).
    assert_eq!(mode_for("gpt-5.5"), Some(LlmMode::Normal));
    assert_eq!(mode_for("claude-opus-4-7"), Some(LlmMode::Defensive));
    // New but non-known ids are untouched.
    assert_eq!(mode_for("gpt-5.5-mini"), None);
    assert_eq!(mode_for("ordinary"), None);
}

/// An existing known-frontier id whose `mode` the user cleared back to
/// inherit stays `None` after a `/models` re-merge — the frontier default
/// is not re-applied to already-configured ids.
#[test]
fn merge_does_not_repin_cleared_mode_on_existing_known_frontier_id() {
    // gpt-5.5 already configured with mode explicitly cleared to inherit.
    let existing = model("gpt-5.5", false);
    assert_eq!(existing.mode, None);

    let merged = merge_fetched_models_with_policy(
        Some("codex-oauth"),
        &[existing],
        vec![model("gpt-5.5", false)],
        ModelMergePolicy::KeepUnlisted,
    );

    let out = merged.iter().find(|m| m.id == "gpt-5.5").unwrap();
    assert_eq!(out.mode, None, "cleared mode must survive a refresh");
}

/// A manual entry's hand-set display name and context window survive an
/// upstream `/models` collision, while a non-manual entry in the same merge
/// takes the fresh upstream name/context_length.
#[test]
fn merge_preserves_manual_name_and_context_length_across_refresh() {
    let mut manual = model("hand", true);
    manual.name = Some("My Handle".to_string());
    manual.context_length = Some(8_192);
    let non_manual = model("auto", false);

    let mut fetched_manual = model("hand", false);
    fetched_manual.name = Some("Upstream Hand".to_string());
    fetched_manual.context_length = Some(200_000);
    let mut fetched_non_manual = model("auto", false);
    fetched_non_manual.name = Some("Upstream Auto".to_string());
    fetched_non_manual.context_length = Some(128_000);

    let merged = merge_fetched_models_with_policy(
        Some("p"),
        &[manual, non_manual],
        vec![fetched_manual, fetched_non_manual],
        ModelMergePolicy::KeepUnlisted,
    );
    let by_id = |id: &str| merged.iter().find(|m| m.id == id).unwrap();

    // Manual entry keeps its hand-set name + context window.
    let hand = by_id("hand");
    assert!(hand.manual);
    assert_eq!(hand.name.as_deref(), Some("My Handle"));
    assert_eq!(hand.context_length, Some(8_192));

    // Non-manual entry takes the fresh upstream metadata.
    let auto = by_id("auto");
    assert!(!auto.manual);
    assert_eq!(auto.name.as_deref(), Some("Upstream Auto"));
    assert_eq!(auto.context_length, Some(128_000));
}

/// The frontier defaults are provider-scoped: the same known id fetched
/// from an aggregator (OpenRouter etc.) is left completely alone.
#[test]
fn frontier_defaults_do_not_apply_outside_the_standard_providers() {
    let merged = merge_fetched_models_with_policy(
        Some("openrouter"),
        &[],
        vec![model("gpt-5.5", false), model("claude-fable-5", false)],
        ModelMergePolicy::KeepUnlisted,
    );
    for m in &merged {
        assert_eq!(m.mode, None, "{}", m.id);
        assert_eq!(m.auto_prune, None, "{}", m.id);
        assert_eq!(m.cache, None, "{}", m.id);
    }
}

/// Discovered known-frontier models on the standard providers get the
/// full default set: frontier mode, auto-prune off, ephemeral cache —
/// each only when the field is still unset.
#[test]
fn frontier_defaults_set_auto_prune_off_and_ephemeral_cache() {
    let mut pinned = model("claude-fable-5", false);
    pinned.auto_prune = Some(true);
    pinned.cache = Some(CacheConfig {
        mode: CacheMode::None,
        ttl_secs: 60,
    });

    let merged = merge_fetched_models_with_policy(
        Some("anthropic"),
        &[pinned.clone()],
        vec![
            model("claude-fable-5", false),
            model("claude-opus-4-8", false),
            model("claude-haiku-4-5-20251001", false),
        ],
        ModelMergePolicy::KeepUnlisted,
    );
    let by_id = |id: &str| merged.iter().find(|m| m.id == id).unwrap();

    // Fresh known id → all three defaults.
    let opus = by_id("claude-opus-4-8");
    assert_eq!(opus.mode, Some(LlmMode::Frontier));
    assert_eq!(opus.auto_prune, Some(false));
    assert_eq!(
        opus.cache,
        Some(CacheConfig {
            mode: CacheMode::Ephemeral,
            ttl_secs: 300,
        })
    );

    // A pre-existing known id is never re-defaulted: its pinned values
    // survive and its unset `mode` stays `None` (no re-pin to frontier).
    let fable = by_id("claude-fable-5");
    assert_eq!(fable.auto_prune, Some(true));
    assert_eq!(fable.cache, pinned.cache);
    assert_eq!(fable.mode, None);

    // Non-frontier ids on the same provider stay untouched.
    let haiku = by_id("claude-haiku-4-5-20251001");
    assert_eq!(haiku.mode, None);
    assert_eq!(haiku.auto_prune, None);
    assert_eq!(haiku.cache, None);
}

/// The plain OpenAI API-key template and the SuperGrok OAuth template both
/// serve their frontier ids verbatim and prompt-cache, so a fresh known id
/// discovered on either gets the frontier defaults.
#[test]
fn merge_applies_frontier_defaults_for_openai_and_grok_templates() {
    for (template, id) in [("openai", "gpt-5.6"), ("grok-oauth", "grok-4.5")] {
        let merged = merge_fetched_models_with_policy(
            Some(template),
            &[],
            vec![model(id, false)],
            ModelMergePolicy::KeepUnlisted,
        );
        let m = merged.iter().find(|m| m.id == id).unwrap();
        assert_eq!(m.mode, Some(LlmMode::Frontier), "{template}/{id} mode");
        assert_eq!(m.auto_prune, Some(false), "{template}/{id} auto_prune");
        assert_eq!(
            m.cache.as_ref().map(|c| c.mode),
            Some(CacheMode::Ephemeral),
            "{template}/{id} cache"
        );
    }
}

/// `effective_template` prefers the stored `template`, otherwise falls back
/// to the config-map key when that key itself names a known template — and
/// resolves to `None` for a renamed/custom provider with no stored template.
#[test]
fn effective_template_prefers_stored_then_falls_back_to_known_key() {
    // Stored template wins even under a renamed key.
    let renamed = ProviderEntry {
        template: Some("anthropic".into()),
        url: "https://x".into(),
        ..ProviderEntry::default()
    };
    assert_eq!(
        renamed.effective_template("anthropic-work"),
        Some("anthropic")
    );

    // Pre-`template` config whose key still names a known template.
    let legacy = ProviderEntry {
        url: "https://x".into(),
        ..ProviderEntry::default()
    };
    assert_eq!(legacy.effective_template("anthropic"), Some("anthropic"));

    // Custom provider with no stored template and a non-template key.
    let custom = ProviderEntry {
        url: "https://x".into(),
        ..ProviderEntry::default()
    };
    assert_eq!(custom.effective_template("my-endpoint"), None);
}

/// A renamed first-party connection (custom key, stored `template`) still
/// gets the frontier defaults, while a genuinely custom provider (no
/// template, non-template key) does not.
#[test]
fn frontier_defaults_follow_template_identity_not_the_config_key() {
    // Second Anthropic connection under a custom key.
    let work = ProviderEntry {
        template: Some("anthropic".into()),
        url: "https://api.anthropic.com".into(),
        ..ProviderEntry::default()
    };
    let merged = merge_fetched_models_with_policy(
        work.effective_template("anthropic-work"),
        &[],
        vec![model("claude-opus-4-8", false)],
        ModelMergePolicy::KeepUnlisted,
    );
    assert_eq!(
        merged
            .iter()
            .find(|m| m.id == "claude-opus-4-8")
            .unwrap()
            .mode,
        Some(LlmMode::Frontier),
    );

    // Custom provider that merely serves a known id gets nothing.
    let custom = ProviderEntry {
        url: "https://example.com".into(),
        ..ProviderEntry::default()
    };
    let merged = merge_fetched_models_with_policy(
        custom.effective_template("my-endpoint"),
        &[],
        vec![model("claude-opus-4-8", false)],
        ModelMergePolicy::KeepUnlisted,
    );
    let m = merged.iter().find(|m| m.id == "claude-opus-4-8").unwrap();
    assert_eq!(m.mode, None);
    assert_eq!(m.auto_prune, None);
    assert_eq!(m.cache, None);
}

#[test]
fn resolve_auto_prune_prefers_model_then_provider_then_on() {
    let mut cfg = ProvidersConfig::default();
    let mut off_model = model("frontier-ish", false);
    off_model.auto_prune = Some(false);
    cfg.providers.insert(
        "p".into(),
        ProviderEntry {
            url: "https://x".into(),
            auto_prune: Some(true),
            models: vec![off_model, model("bare", false)],
            ..ProviderEntry::default()
        },
    );

    // Model override wins over the provider value.
    assert!(!cfg.resolve_auto_prune("p", "frontier-ish"));
    // Bare model inherits the provider override.
    assert!(cfg.resolve_auto_prune("p", "bare"));
    // Unknown provider/model resolves to on.
    assert!(cfg.resolve_auto_prune("nope", "x"));

    // Provider-level off applies to models without their own pin.
    cfg.providers.get_mut("p").unwrap().auto_prune = Some(false);
    assert!(!cfg.resolve_auto_prune("p", "bare"));
}

#[test]
fn fetched_known_frontier_model_gets_model_mode_even_with_provider_mode() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "codex-oauth".into(),
        ProviderEntry {
            url: "https://x".into(),
            mode: Some(LlmMode::Defensive),
            models: merge_fetched_models_with_policy(
                Some("codex-oauth"),
                &[],
                vec![model("gpt-5.5", false)],
                ModelMergePolicy::KeepUnlisted,
            ),
            ..ProviderEntry::default()
        },
    );

    let row = &cfg.providers["codex-oauth"].models[0];
    assert_eq!(row.mode, Some(LlmMode::Frontier));
    assert_eq!(
        cfg.resolve_mode("codex-oauth", "gpt-5.5", LlmMode::Normal),
        LlmMode::Frontier
    );
}

#[test]
fn merge_preserves_model_override_fields_on_matching_fetched_id() {
    let mut existing = model("shared", true);
    existing.favorite = true;
    existing.cache = Some(CacheConfig {
        mode: CacheMode::Ephemeral,
        ttl_secs: 3600,
    });
    existing.context = Some(ContextConfig {
        auto_compact_pct: 70,
        compact_keep_recent_turns: 3,
        compact_shadow: true,
        compact_shadow_margin_pct: 10,
        auto_prune_pct: 45,
        auto_prune_prunable_pct: 20,
    });
    existing.timeout = Some(TimeoutConfig {
        ttft_secs: 77,
        idle_secs: 55,
    });
    existing.backup = Some(BackupConfig {
        provider: "paid".to_string(),
        model: "backup".to_string(),
    });
    existing.trust = Some(ModelTrust::Trusted);
    existing.location = Some(ModelLocation::Local);
    existing.quality_rank = Some(12);
    existing.cost_rank = Some(-2);
    existing.subagent_invokable = Some(true);
    existing.availability.categories = vec!["reasoning".to_string()];
    existing.inline_think = Some(false);
    existing.hint_tool_call_corrections = Some(false);
    existing.wire_api = WireApi::Responses;
    existing.auto_prune = Some(false);

    let mut fetched = model("shared", false);
    fetched.name = Some("Fresh remote name".to_string());
    fetched.context_length = Some(123_456);

    let merged = merge_fetched_models_with_policy(
        Some("p"),
        &[existing.clone()],
        vec![fetched],
        ModelMergePolicy::RemoveUnlisted,
    );

    assert_eq!(merged.len(), 1);
    let out = &merged[0];
    assert_eq!(out.name.as_deref(), Some("Fresh remote name"));
    assert_eq!(out.context_length, Some(123_456));
    assert!(out.manual);
    assert!(out.favorite);
    assert_eq!(out.cache, existing.cache);
    assert_eq!(out.context, existing.context);
    assert_eq!(out.timeout, existing.timeout);
    assert_eq!(out.backup, existing.backup);
    assert_eq!(out.trust, Some(ModelTrust::Trusted));
    assert_eq!(out.location, Some(ModelLocation::Local));
    assert_eq!(out.quality_rank, Some(12));
    assert_eq!(out.cost_rank, Some(-2));
    assert_eq!(out.subagent_invokable, Some(true));
    assert_eq!(out.availability.categories, vec!["reasoning"]);
    assert_eq!(out.inline_think, Some(false));
    assert_eq!(out.hint_tool_call_corrections, Some(false));
    assert_eq!(out.wire_api, WireApi::Responses);
    assert_eq!(out.auto_prune, Some(false));
}

// --- wire-API endpoint routing (implementation note)

/// Layer 2 name auto-detect: `gpt-5*` (case-insensitive) is responses-only;
/// everything else (including `gpt-4o`, `gpt-50`, a too-short id) is
/// completions — today's default for every existing model.
#[test]
fn wire_api_detect_heuristic_is_gpt5_prefix_case_insensitive() {
    use WireApi::{Completions, Responses};
    assert_eq!(WireApi::detect("gpt-5"), Responses);
    assert_eq!(WireApi::detect("gpt-5.4-mini"), Responses);
    assert_eq!(WireApi::detect("gpt-5o"), Responses);
    // Case-insensitive on the prefix.
    assert_eq!(WireApi::detect("GPT-5.4-mini"), Responses);
    assert_eq!(WireApi::detect("Gpt-5"), Responses);
    // Everything else → completions.
    assert_eq!(WireApi::detect("gpt-4o-mini"), Completions);
    assert_eq!(WireApi::detect("claude-opus-4-7"), Completions);
    assert_eq!(WireApi::detect("glm-4.6"), Completions);
    // A non-`gpt-5` id that merely shares a shorter prefix is completions.
    assert_eq!(WireApi::detect("gpt-4"), Completions);
    // Too-short ids never panic and default to completions.
    assert_eq!(WireApi::detect("gpt"), Completions);
    assert_eq!(WireApi::detect(""), Completions);
}

#[test]
fn grok_providers_default_to_responses_wire_api() {
    assert_eq!(
        WireApi::detect_for_provider("grok", "grok-4.3"),
        WireApi::Responses
    );
    assert_eq!(
        WireApi::detect_for_provider("grok-oauth", "grok-4.3"),
        WireApi::Responses
    );
}

#[test]
fn codex_oauth_defaults_to_responses_wire_api() {
    assert_eq!(
        WireApi::detect_for_provider("codex-oauth", "gpt-5.5"),
        WireApi::Responses
    );
}

/// `opposite` is the bidirectional swap target the fallback retries.
#[test]
fn wire_api_opposite_is_bidirectional() {
    assert_eq!(WireApi::Responses.opposite(), WireApi::Completions);
    assert_eq!(WireApi::Completions.opposite(), WireApi::Responses);
    // `Auto` is never the resolved value; defensively → Responses.
    assert_eq!(WireApi::Auto.opposite(), WireApi::Responses);
}

/// Layer 1 (explicit config) wins over layer 2 (auto-detect): a pinned
/// `completions`/`responses` is returned verbatim; an `auto` (or unknown
/// provider/model) returns `Auto` so the build path falls through to
/// `detect`.
#[test]
fn resolve_wire_api_explicit_config_wins() {
    let mut cfg = ProvidersConfig::default();
    let mut entry = ProviderEntry {
        url: "https://x".into(),
        ..ProviderEntry::default()
    };
    // A `gpt-5` model that the heuristic would route to responses, but is
    // explicitly pinned to completions: the pin must win.
    let mut pinned = model("gpt-5.4-mini", false);
    pinned.wire_api = WireApi::Completions;
    entry.models.push(pinned);
    // A model left on `auto`.
    entry.models.push(model("gpt-4o", false));
    cfg.providers.insert("p".into(), entry);

    // Explicit pin returned verbatim (caller will NOT auto-detect).
    assert_eq!(
        cfg.resolve_wire_api("p", "gpt-5.4-mini"),
        WireApi::Completions
    );
    // `auto` model → Auto (caller auto-detects).
    assert_eq!(cfg.resolve_wire_api("p", "gpt-4o"), WireApi::Auto);
    // Unknown model / provider → Auto.
    assert_eq!(cfg.resolve_wire_api("p", "missing"), WireApi::Auto);
    assert_eq!(cfg.resolve_wire_api("nope", "x"), WireApi::Auto);
    assert!(!cfg.is_wire_api_explicit("p", "gpt-4o"));
    assert!(cfg.is_wire_api_explicit("p", "gpt-5.4-mini"));
}

#[test]
fn resolve_wire_api_provider_default_between_model_and_auto() {
    let mut cfg = ProvidersConfig::default();
    let mut entry = ProviderEntry {
        url: "https://x".into(),
        wire_api: WireApi::Completions,
        ..ProviderEntry::default()
    };
    entry.models.push(model("inherits", false));
    let mut pinned = model("pins-responses", false);
    pinned.wire_api = WireApi::Responses;
    entry.models.push(pinned);
    cfg.providers.insert("p".into(), entry);

    assert_eq!(cfg.resolve_wire_api("p", "inherits"), WireApi::Completions);
    assert_eq!(
        cfg.resolve_wire_api("p", "pins-responses"),
        WireApi::Responses
    );
    assert_eq!(cfg.resolve_wire_api("p", "missing"), WireApi::Completions);
    assert!(cfg.is_wire_api_explicit("p", "inherits"));
}

/// `auto` is the serde default and is skipped on serialize, so configs that
/// never pin it stay clean and load unchanged; a pinned value round-trips.
#[test]
fn wire_api_defaults_auto_and_skips_serialize() {
    // Default + skip.
    let m = model("x", false);
    assert_eq!(m.wire_api, WireApi::Auto);
    let json = serde_json::to_string(&m).unwrap();
    assert!(
        !json.contains("wire_api"),
        "auto must not serialize: {json}"
    );
    // Legacy row without the field loads as auto.
    let legacy: ModelEntry = serde_json::from_str(r#"{"id":"legacy"}"#).unwrap();
    assert_eq!(legacy.wire_api, WireApi::Auto);
    // A pin serializes its lowercase spelling and round-trips.
    let mut pinned = model("y", false);
    pinned.wire_api = WireApi::Responses;
    let json = serde_json::to_string(&pinned).unwrap();
    assert!(json.contains("\"wire_api\":\"responses\""), "{json}");
    let back: ModelEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.wire_api, WireApi::Responses);

    let provider = ProviderEntry {
        url: "https://example.test/v1".into(),
        ..ProviderEntry::default()
    };
    let json = serde_json::to_string(&provider).unwrap();
    assert!(
        !json.contains("wire_api"),
        "provider auto must not serialize: {json}"
    );
    let legacy: ProviderEntry =
        serde_json::from_str(r#"{"url":"https://example.test/v1"}"#).unwrap();
    assert_eq!(legacy.wire_api, WireApi::Auto);
}

#[test]
fn allow_insecure_http_defaults_false_skips_false_and_persists_true() {
    let legacy: ProviderEntry =
        serde_json::from_str(r#"{"url":"https://example.test/v1"}"#).unwrap();
    assert!(!legacy.allow_insecure_http);

    let provider = ProviderEntry {
        url: "https://example.test/v1".into(),
        ..ProviderEntry::default()
    };
    let json = serde_json::to_string(&provider).unwrap();
    assert!(
        !json.contains("allow_insecure_http"),
        "false opt-in must not serialize: {json}"
    );

    let provider = ProviderEntry {
        allow_insecure_http: true,
        ..provider
    };
    let json = serde_json::to_string(&provider).unwrap();
    assert!(
        json.contains("\"allow_insecure_http\":true"),
        "true opt-in must serialize: {json}"
    );
    let back: ProviderEntry = serde_json::from_str(&json).unwrap();
    assert!(back.allow_insecure_http);
    assert_eq!(back.url, "https://example.test/v1");
}

/// A user-or-fallback-pinned `wire_api` survives a `/models` refresh: the
/// refetched (always-`auto`) entry inherits the prior pin instead of
/// resetting it.
#[test]
fn merge_preserves_pinned_wire_api_across_refetch() {
    let mut prev = model("gpt-5.4-mini", false);
    prev.wire_api = WireApi::Responses; // self-healed last session
    let existing = vec![prev];
    // The refetch returns the same id, freshly `auto` (upstream never
    // carries wire_api), plus a new unrelated model.
    let fetched = vec![model("gpt-5.4-mini", false), model("gpt-4o", false)];
    let merged = merge_fetched_models_with_policy(
        Some("p"),
        &existing,
        fetched,
        ModelMergePolicy::KeepUnlisted,
    );

    let healed = merged.iter().find(|m| m.id == "gpt-5.4-mini").unwrap();
    assert_eq!(
        healed.wire_api,
        WireApi::Responses,
        "a pinned endpoint must survive a /models refresh"
    );
    // An unpinned new model stays auto.
    let fresh = merged.iter().find(|m| m.id == "gpt-4o").unwrap();
    assert_eq!(fresh.wire_api, WireApi::Auto);
}

#[test]
fn capability_enum_serde_names_are_stable() {
    assert_eq!(
        serde_json::to_value(CapabilitySource::ProviderRule).unwrap(),
        serde_json::json!("provider_rule")
    );
    assert_eq!(
        serde_json::to_value(CapabilitySource::Probed).unwrap(),
        serde_json::json!("probed")
    );
    assert_eq!(
        serde_json::to_value(CapabilitySource::LegacySynthesized).unwrap(),
        serde_json::json!("legacy_synthesized")
    );
    assert_eq!(
        serde_json::to_value(CapabilityStatus::RequiresEntitlement).unwrap(),
        serde_json::json!("requires_entitlement")
    );
    assert_eq!(
        serde_json::to_value(ModelFetchStatusKind::FailedKeptExisting).unwrap(),
        serde_json::json!("failed_kept_existing")
    );
}

#[test]
fn provider_and_model_capability_schema_round_trips() {
    let raw = r#"{
            "url": "https://example.test/v1",
            "provider_metadata": { "organization": "xai" },
            "capabilities": {
              "client_side_tools": {
                "status": "requires_entitlement",
                "entitlement": "supergrok",
                "source": "provider_rule"
              }
            },
            "last_model_fetch": {
              "status": "failed_kept_existing",
              "at": "2026-06-18T00:00:00Z",
              "source": "live",
              "reason": "http 503"
            },
            "models": [{
              "id": "gpt-5-mini",
              "capabilities": {
                "reasoning_effort": {
                  "values": [
                    { "value": "minimal", "label": "Minimal" },
                    { "value": "xhigh", "description": "extra high" }
                  ],
                  "default": "minimal",
                  "request_mapping": {
                    "type": "json_field",
                    "field": "reasoning_effort",
                    "values": { "minimal": "minimal", "xhigh": "xhigh" }
                  },
                  "source": "live"
                },
                "client_side_tools": { "status": "supported", "source": "live" }
              },
              "provider_metadata": { "owned_by": "openai" },
              "extra": { "legacy": true }
            }]
        }"#;
    let entry: ProviderEntry = serde_json::from_str(raw).unwrap();
    assert_eq!(
        entry.capabilities.client_side_tools.status,
        CapabilityStatus::RequiresEntitlement
    );
    assert_eq!(
        entry.last_model_fetch.as_ref().unwrap().status,
        ModelFetchStatusKind::FailedKeptExisting
    );
    let model = &entry.models[0];
    assert_eq!(
        model
            .capabilities
            .reasoning_effort
            .as_ref()
            .unwrap()
            .default
            .as_deref(),
        Some("minimal")
    );
    assert_eq!(
        model
            .provider_metadata
            .get("owned_by")
            .and_then(Value::as_str),
        Some("openai")
    );
    let json = serde_json::to_string(&entry).unwrap();
    let back: ProviderEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.models[0].capabilities, model.capabilities);
    assert_eq!(back.provider_metadata, entry.provider_metadata);
}

#[test]
fn legacy_configs_load_with_unknown_default_capability_state() {
    let model: ModelEntry = serde_json::from_str(
        r#"{"id":"legacy","thinking_modes":["off","high"],"inputs":{"images":true}}"#,
    )
    .unwrap();
    assert_eq!(
        model.thinking_modes,
        vec![ThinkingMode::Off, ThinkingMode::High]
    );
    assert!(model.capabilities.is_empty());
    assert!(model.provider_metadata.is_empty());

    let provider: ProviderEntry =
        serde_json::from_str(r#"{"url":"https://example.test/v1"}"#).unwrap();
    assert!(provider.capabilities.is_empty());
    assert!(provider.last_model_fetch.is_none());
    assert!(provider.provider_metadata.is_empty());
}

#[test]
fn reasoning_effort_projection_is_documented_compatibility_only() {
    let capability = ReasoningEffortCapability {
        values: vec![
            CapabilityValue {
                value: "off".into(),
                ..Default::default()
            },
            CapabilityValue {
                value: "minimal".into(),
                ..Default::default()
            },
            CapabilityValue {
                value: "low".into(),
                ..Default::default()
            },
            CapabilityValue {
                value: "xhigh".into(),
                ..Default::default()
            },
            CapabilityValue {
                value: "high".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    assert_eq!(
        project_reasoning_effort_to_thinking_modes(&capability),
        vec![ThinkingMode::Off, ThinkingMode::Low, ThinkingMode::High]
    );
}

#[test]
fn client_side_tools_resolution_precedence() {
    let mut cfg = ProvidersConfig::default();
    let mut provider = ProviderEntry {
        url: "https://example.test/v1".into(),
        capabilities: ProviderCapabilities {
            client_side_tools: ClientSideToolsCapability {
                status: CapabilityStatus::RequiresEntitlement,
                entitlement: Some("provider-plan".into()),
                source: Some(CapabilitySource::ProviderRule),
            },
            ..ProviderCapabilities::default()
        },
        ..ProviderEntry::default()
    };
    let mut model_override = model("model-override", false);
    model_override.capabilities.client_side_tools = ClientSideToolsCapability {
        status: CapabilityStatus::Supported,
        entitlement: None,
        source: Some(CapabilitySource::Manual),
    };
    provider.models.push(model_override);
    provider.models.push(model("provider-override", false));
    cfg.providers.insert("p".into(), provider);

    let rule = ClientSideToolsCapability {
        status: CapabilityStatus::Unsupported,
        entitlement: None,
        source: Some(CapabilitySource::ProviderRule),
    };
    assert_eq!(
        cfg.resolve_client_side_tools("p", "model-override", Some(rule.clone()))
            .status,
        CapabilityStatus::Supported
    );
    let inherited = cfg.resolve_client_side_tools("p", "provider-override", Some(rule.clone()));
    assert_eq!(inherited.status, CapabilityStatus::RequiresEntitlement);
    assert_eq!(inherited.entitlement.as_deref(), Some("provider-plan"));
    assert_eq!(
        cfg.resolve_client_side_tools("missing", "x", Some(rule))
            .status,
        CapabilityStatus::Unsupported
    );
    assert!(
        cfg.resolve_client_side_tools("missing", "x", None)
            .is_empty()
    );
}

#[test]
fn xai_multi_agent_provider_rule_requires_entitlement() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "grok-oauth".into(),
        ProviderEntry {
            url: "https://api.x.ai/v1".into(),
            ..ProviderEntry::default()
        },
    );

    let capability =
        cfg.resolve_effective_client_side_tools("grok-oauth", "grok-4.20-multi-agent-0309");
    assert_eq!(capability.status, CapabilityStatus::RequiresEntitlement);
    assert_eq!(
        capability.entitlement.as_deref(),
        Some(XAI_MULTI_AGENT_TOOLS_ENTITLEMENT)
    );
    assert_eq!(capability.source, Some(CapabilitySource::ProviderRule));

    assert!(
        cfg.resolve_effective_client_side_tools("grok-oauth", "grok-4.3")
            .is_empty()
    );
}

#[test]
fn xai_multi_agent_detection_uses_layered_provider_evidence() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "custom-url".into(),
        ProviderEntry {
            url: "https://api.x.ai/v1".into(),
            ..ProviderEntry::default()
        },
    );
    cfg.providers.insert(
        "custom-credential".into(),
        ProviderEntry {
            url: "https://example.test/v1".into(),
            credential_ref: Some("grok-oauth".into()),
            ..ProviderEntry::default()
        },
    );
    cfg.providers.insert(
        "custom-metadata".into(),
        ProviderEntry {
            url: "https://example.test/v1".into(),
            provider_metadata: serde_json::json!({ "provider": "xAI" })
                .as_object()
                .unwrap()
                .clone(),
            ..ProviderEntry::default()
        },
    );

    for provider_id in ["custom-url", "custom-credential", "custom-metadata"] {
        assert_eq!(
            cfg.resolve_effective_client_side_tools(provider_id, "grok-build-multi-agent")
                .status,
            CapabilityStatus::RequiresEntitlement,
            "{provider_id} should be recognized as xAI/Grok"
        );
    }
}

#[test]
fn xai_multi_agent_manual_capabilities_override_provider_rule() {
    let mut cfg = ProvidersConfig::default();
    let mut provider = ProviderEntry {
        url: "https://api.x.ai/v1".into(),
        capabilities: ProviderCapabilities {
            client_side_tools: ClientSideToolsCapability {
                status: CapabilityStatus::Supported,
                entitlement: Some(XAI_MULTI_AGENT_TOOLS_ENTITLEMENT.into()),
                source: Some(CapabilitySource::Manual),
            },
            ..ProviderCapabilities::default()
        },
        ..ProviderEntry::default()
    };
    let mut model_override = model("grok-4.20-multi-agent-0309", false);
    model_override.capabilities.client_side_tools = ClientSideToolsCapability {
        status: CapabilityStatus::RequiresEntitlement,
        entitlement: Some(XAI_MULTI_AGENT_TOOLS_ENTITLEMENT.into()),
        source: Some(CapabilitySource::Manual),
    };
    provider.models.push(model_override);
    provider.models.push(model("grok-build-multi-agent", false));
    cfg.providers.insert("grok".into(), provider);

    assert_eq!(
        cfg.resolve_effective_client_side_tools("grok", "grok-build-multi-agent")
            .status,
        CapabilityStatus::Supported
    );
    assert_eq!(
        cfg.resolve_effective_client_side_tools("grok", "grok-4.20-multi-agent-0309")
            .status,
        CapabilityStatus::RequiresEntitlement
    );
}

#[test]
fn model_fetch_failure_status_classifies_auth_and_redacts_reason() {
    let mut provider = ProviderEntry::default();
    provider.mark_model_fetch_failed_kept_existing(
            "https://api.example.test/v1/models returned 401 — credentials rejected. Bearer sk-test-token-abcdefghijklmnopqrstuvwxyz123456",
        );

    let status = provider.last_model_fetch.unwrap();
    assert_eq!(status.status, ModelFetchStatusKind::AuthFailed);
    let reason = status.reason.unwrap();
    assert!(reason.contains("credentials rejected"));
    assert!(reason.contains("[redacted]"));
    assert!(!reason.contains("sk-test-token"));

    let mut provider = ProviderEntry::default();
    provider
        .mark_model_fetch_failed_kept_existing("https://api.example.test/v1/models returned 503");
    assert_eq!(
        provider.last_model_fetch.unwrap().status,
        ModelFetchStatusKind::FailedKeptExisting
    );
}

#[test]
fn model_fetch_fallback_status_records_redacted_reason() {
    let mut provider = ProviderEntry::default();
    provider.mark_model_fetch_fallback(
            "https://api.example.test/v1/models returned 503. Authorization: sk-test-token-abcdefghijklmnopqrstuvwxyz123456",
        );

    let status = provider.last_model_fetch.unwrap();
    assert_eq!(status.status, ModelFetchStatusKind::Fallback);
    assert_eq!(status.source, ModelFetchSource::Fallback);
    let reason = status.reason.unwrap();
    assert!(reason.contains("returned 503"));
    assert!(reason.contains("[redacted]"));
    assert!(!reason.contains("sk-test-token"));
}

#[test]
fn merge_preserves_existing_capabilities_and_provider_metadata() {
    let mut existing = model("gpt-5", false);
    existing.capabilities.client_side_tools = ClientSideToolsCapability {
        status: CapabilityStatus::Supported,
        entitlement: None,
        source: Some(CapabilitySource::Manual),
    };
    existing
        .provider_metadata
        .insert("existing".into(), serde_json::json!(true));
    existing
        .extra
        .insert("legacy_only".into(), serde_json::json!("kept"));
    let mut fetched = model("gpt-5", false);
    fetched
        .provider_metadata
        .insert("upstream".into(), serde_json::json!(true));
    fetched
        .extra
        .insert("upstream".into(), serde_json::json!(true));

    let merged = merge_fetched_models_with_policy(
        Some("p"),
        &[existing],
        vec![fetched],
        ModelMergePolicy::KeepUnlisted,
    );
    let model = &merged[0];
    assert_eq!(
        model.capabilities.client_side_tools.status,
        CapabilityStatus::Supported
    );
    assert_eq!(
        model.provider_metadata.get("existing"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(
        model.provider_metadata.get("upstream"),
        Some(&serde_json::json!(true))
    );
    assert_eq!(
        model.provider_metadata.get("legacy_only"),
        Some(&serde_json::json!("kept"))
    );
    assert_eq!(model.extra.get("existing"), Some(&serde_json::json!(true)));
    assert_eq!(
        model.extra.get("legacy_only"),
        Some(&serde_json::json!("kept"))
    );
    assert_eq!(model.extra.get("upstream"), Some(&serde_json::json!(true)));
}

#[test]
fn embeddings_capability_roundtrip() {
    let entry: ModelEntry = serde_json::from_value(serde_json::json!({
        "id": "embed-small",
        "embeddings": true,
        "embedding_dimensions": 1536,
        "capabilities": { "embeddings": true, "embedding_dimensions": 1536 }
    }))
    .unwrap();
    assert_eq!(entry.embeddings, Some(true));
    assert_eq!(entry.embedding_dimensions, Some(1536));
    assert_eq!(entry.capabilities.embeddings, Some(true));
    assert_eq!(entry.capabilities.embedding_dimensions, Some(1536));

    let encoded = serde_json::to_value(&entry).unwrap();
    assert_eq!(encoded["embeddings"], true);
    assert_eq!(encoded["embedding_dimensions"], 1536);
}

#[test]
fn fetch_merge_preserves_embeddings() {
    let mut existing = model("embed-small", false);
    existing.embeddings = Some(true);
    existing.embedding_dimensions = Some(1536);
    existing.capability_overrides.embeddings = Some(true);
    existing.capability_overrides.embedding_dimensions = Some(1536);

    let fetched = model("embed-small", false);
    let merged = merge_fetched_models_with_policy(
        Some("openai"),
        &[existing],
        vec![fetched],
        ModelMergePolicy::KeepUnlisted,
    );

    assert_eq!(merged[0].embeddings, Some(true));
    assert_eq!(merged[0].embedding_dimensions, Some(1536));
    assert_eq!(merged[0].capability_overrides.embeddings, Some(true));
    assert_eq!(
        merged[0].capability_overrides.embedding_dimensions,
        Some(1536)
    );
}

#[test]
fn resolve_embedding_model_two_level() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "openai".into(),
        ProviderEntry {
            embeddings: Some(false),
            models: vec![
                ModelEntry {
                    id: "chat".into(),
                    embeddings: Some(false),
                    ..ModelEntry::default()
                },
                ModelEntry {
                    id: "embed".into(),
                    embeddings: Some(true),
                    embedding_dimensions: Some(1536),
                    quality_rank: Some(7),
                    ..ModelEntry::default()
                },
            ],
            ..ProviderEntry::default()
        },
    );
    let extended = crate::config::extended::ExtendedConfig {
        embedding_model: Some("openai/embed".into()),
        ..Default::default()
    };

    let resolved = cfg.resolve_embedding_model(&extended).unwrap();
    assert_eq!(resolved.provider, "openai");
    assert_eq!(resolved.model, "embed");
    assert_eq!(resolved.embedding_dimensions, Some(1536));
}

#[test]
fn embedding_model_unresolvable_is_loud() {
    let cfg = ProvidersConfig::default();
    let extended = crate::config::extended::ExtendedConfig {
        embedding_model: Some("missing/embed".into()),
        ..Default::default()
    };

    let err = cfg.resolve_embedding_model(&extended).unwrap_err();
    assert!(err.to_string().contains("unknown provider `missing`"));
}

fn anthropic_reasoning_capability(
    mapping: ReasoningEffortRequestMapping,
) -> ReasoningEffortCapability {
    ReasoningEffortCapability {
        values: ["low", "medium", "high", "xhigh"]
            .into_iter()
            .map(|value| CapabilityValue {
                value: value.to_string(),
                ..CapabilityValue::default()
            })
            .collect(),
        default: Some("high".into()),
        request_mapping: Some(mapping),
        source: Some(CapabilitySource::Live),
    }
}

#[test]
fn manual_thinking_budget_matrix() {
    assert_eq!(manual_thinking_budget(10_001, "low").unwrap(), 2_500);
    assert_eq!(manual_thinking_budget(10_001, "medium").unwrap(), 5_000);
    assert_eq!(manual_thinking_budget(10_001, "high").unwrap(), 7_500);
    assert_eq!(manual_thinking_budget(10_001, "xhigh").unwrap(), 8_000);
    assert_eq!(manual_thinking_budget(3_000, "low").unwrap(), 1_024);
    assert_eq!(manual_thinking_budget(5_000, "xhigh").unwrap(), 3_976);
    assert_eq!(manual_thinking_budget(2_048, "low").unwrap(), 1_024);
    assert!(manual_thinking_budget(2_047, "low").is_err());
    assert!(manual_thinking_budget(8_192, "unknown").is_err());
}

#[test]
fn adaptive_thinking_has_no_budget() {
    let mut cfg = ProvidersConfig::default();
    cfg.providers.insert(
        "anthropic".into(),
        ProviderEntry {
            models: vec![ModelEntry {
                id: "claude-adaptive".into(),
                capabilities: ModelCapabilities {
                    max_output_tokens: Some(16_384),
                    reasoning_effort: Some(anthropic_reasoning_capability(
                        ReasoningEffortRequestMapping::AnthropicAdaptive {
                            values: BTreeMap::from([("xhigh".into(), "max".into())]),
                        },
                    )),
                    ..ModelCapabilities::default()
                },
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );
    let params = cfg
        .resolve_reasoning_effort_params_for_wire(
            "anthropic",
            "claude-adaptive",
            Some("xhigh"),
            ReasoningEffortWire::AnthropicNative,
            Some(16_384),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        params["thinking"],
        serde_json::json!({ "type": "adaptive" })
    );
    assert_eq!(params["output_config"]["effort"], "max");
    assert!(params.get("budget_tokens").is_none());
    assert!(params["thinking"].get("budget_tokens").is_none());
    let error = cfg
        .resolve_reasoning_effort_params_for_wire(
            "anthropic",
            "claude-adaptive",
            Some("stale"),
            ReasoningEffortWire::AnthropicNative,
            Some(16_384),
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("not advertised"), "{error}");
}

#[test]
fn anthropic_max_tokens_always_resolved() {
    let mut entry = ProviderEntry {
        capabilities: ProviderCapabilities {
            max_output_tokens: Some(4_096),
            ..ProviderCapabilities::default()
        },
        models: vec![ModelEntry {
            id: "claude".into(),
            capabilities: ModelCapabilities {
                max_output_tokens: Some(16_384),
                ..ModelCapabilities::default()
            },
            capability_overrides: ModelCapabilityOverrides {
                max_output_tokens: Some(8_192),
                ..ModelCapabilityOverrides::default()
            },
            ..ModelEntry::default()
        }],
        ..ProviderEntry::default()
    };
    assert_eq!(resolve_anthropic_max_tokens(&entry, "claude"), Some(16_384));
    entry.models[0].capabilities.max_output_tokens = None;
    assert_eq!(resolve_anthropic_max_tokens(&entry, "claude"), Some(8_192));
    entry.models[0].capability_overrides.max_output_tokens = None;
    assert_eq!(resolve_anthropic_max_tokens(&entry, "claude"), Some(4_096));
}

#[test]
fn catalog_max_output_tokens_consumed() {
    let entry = ProviderEntry {
        models: vec![ModelEntry {
            id: "claude".into(),
            capabilities: ModelCapabilities {
                max_output_tokens: Some(64_000),
                ..ModelCapabilities::default()
            },
            ..ModelEntry::default()
        }],
        ..ProviderEntry::default()
    };
    assert_eq!(
        validate_anthropic_model_configuration(&entry, "claude").unwrap(),
        64_000
    );
}

#[test]
fn missing_output_limit_fails_closed() {
    let models = merge_fetched_models_with_policy(
        Some("anthropic"),
        &[],
        vec![ModelEntry {
            id: "claude-sonnet-new".into(),
            ..ModelEntry::default()
        }],
        ModelMergePolicy::KeepUnlisted,
    );
    assert_eq!(models[0].capabilities.max_output_tokens, None);
    let entry = ProviderEntry {
        models,
        ..ProviderEntry::default()
    };
    let error = validate_anthropic_model_configuration(&entry, "claude-sonnet-new")
        .unwrap_err()
        .to_string();
    assert!(error.contains("no output limit"), "{error}");
    assert!(error.contains("max_output_tokens"), "{error}");
}
