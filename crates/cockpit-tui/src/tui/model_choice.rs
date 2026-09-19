//! Shared model-list ordering and favorite cycling used by the composer pill
//! picker, quick dialog, multireview, and inventory paths.

use std::collections::HashMap;
use std::path::Path;

use cockpit_config::dirs::{COCKPIT_CONFIG_ENV, config_file_paths_for_load};
use cockpit_config::providers::{
    ActiveModelRef, ModelEntry, ProviderEntry, ReasoningEffortCapability, ThinkingMode,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelDrift {
    pub session_label: String,
    pub config_label: String,
    pub config_model: Option<ActiveModelRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelChoice {
    pub provider_id: String,
    pub model_id: String,
    pub label: String,
    pub is_favorite: bool,
    pub trust: cockpit_config::providers::ModelTrust,
}

#[derive(Clone)]
pub(crate) struct Entry {
    provider_id: String,
    model_id: String,
    is_favorite: bool,
    reasoning_effort: Option<ReasoningEffortCapability>,
    thinking_modes: Vec<ThinkingMode>,
    trust: cockpit_config::providers::ModelTrust,
}

impl Entry {
    fn label(&self) -> String {
        format!("{}/{}", self.provider_id, self.model_id)
    }
}

pub(crate) fn picker_entry(
    provider_id: &str,
    provider: &ProviderEntry,
    model: &ModelEntry,
) -> Entry {
    let wire_api = if !model.wire_api.is_auto() && model.wire_api_provenance.is_user_configured() {
        model.wire_api
    } else if !provider.wire_api.is_auto() {
        provider.wire_api
    } else {
        cockpit_config::providers::default_wire_api_for_template(
            provider.effective_template(provider_id),
        )
    };
    let native_anthropic = wire_api == cockpit_config::providers::WireApi::Anthropic;
    let reasoning_effort = if native_anthropic
        && cockpit_config::providers::validate_anthropic_model_configuration(provider, &model.id)
            .is_err()
    {
        None
    } else {
        model
            .capabilities
            .reasoning_effort
            .clone()
            .filter(|capability| native_anthropic || capability.supports_wire_api(wire_api))
    };
    Entry {
        provider_id: provider_id.to_string(),
        model_id: model.id.clone(),
        is_favorite: model.favorite,
        reasoning_effort,
        thinking_modes: if native_anthropic {
            Vec::new()
        } else {
            model.thinking_modes.clone()
        },
        trust: cockpit_config::providers::ModelTrust::Untrusted,
    }
}

/// Build ordered model choices from a daemon inventory-bundle model list.
/// Does not read credentials or the local provider config tree.
pub fn ordered_model_choices_from_inventory(
    models: &[cockpit_proto::ModelSummary],
    counts: &HashMap<String, u64>,
) -> Vec<ModelChoice> {
    let mut entries: Vec<Entry> = models
        .iter()
        .map(|m| Entry {
            provider_id: m.provider.clone(),
            model_id: m.id.clone(),
            is_favorite: m.favorite,
            reasoning_effort: m.reasoning_effort.clone(),
            thinking_modes: m.thinking_modes.clone(),
            trust: m.trust,
        })
        .collect();
    sort_entries(&mut entries, counts, &[]);
    entries
        .into_iter()
        .map(|e| {
            let label = e.label();
            ModelChoice {
                label,
                provider_id: e.provider_id,
                model_id: e.model_id,
                is_favorite: e.is_favorite,
                trust: e.trust,
            }
        })
        .collect()
}

pub(crate) fn sort_entries(
    entries: &mut [Entry],
    counts: &HashMap<String, u64>,
    slot_first: &[(String, String)],
) {
    entries.sort_by(|a, b| {
        let a_slot = slot_first
            .iter()
            .position(|(provider, model)| provider == &a.provider_id && model == &a.model_id);
        let b_slot = slot_first
            .iter()
            .position(|(provider, model)| provider == &b.provider_id && model == &b.model_id);
        a_slot
            .unwrap_or(usize::MAX)
            .cmp(&b_slot.unwrap_or(usize::MAX))
            .then_with(|| b.is_favorite.cmp(&a.is_favorite))
            .then_with(|| {
                let ca = counts.get(&a.label()).copied().unwrap_or(0);
                let cb = counts.get(&b.label()).copied().unwrap_or(0);
                cb.cmp(&ca)
            })
            .then_with(|| a.label().cmp(&b.label()))
    });
}

pub fn cycle_active_favorite(
    cfg: &cockpit_config::providers::ProvidersConfig,
    active: Option<&ActiveModelRef>,
    counts: &HashMap<String, u64>,
    forward: bool,
) -> Result<Option<ActiveModelRef>, String> {
    let active_key = active.map(|active| (active.provider.clone(), active.model.clone()));
    let mut entries: Vec<Entry> = Vec::new();
    for (pid, entry) in &cfg.providers {
        for model in &entry.models {
            if model.favorite {
                let mut picker = picker_entry(pid, entry, model);
                picker.trust = cfg.resolve_trust(pid, &model.id);
                entries.push(picker);
            }
        }
    }
    sort_entries(&mut entries, counts, &[]);
    if entries.is_empty() {
        return Ok(None);
    }
    if entries.len() == 1
        && active_key.as_ref().is_some_and(|(provider, model)| {
            entries[0].provider_id == *provider && entries[0].model_id == *model
        })
    {
        return Ok(None);
    }
    let current = active_key.as_ref().and_then(|(p, m)| {
        entries
            .iter()
            .position(|e| &e.provider_id == p && &e.model_id == m)
    });
    let target_idx = match (current, forward) {
        (Some(idx), true) => (idx + 1) % entries.len(),
        (Some(0), false) => entries.len() - 1,
        (Some(idx), false) => idx - 1,
        (None, _) => 0,
    };
    let target = &entries[target_idx];
    let mut selection = ActiveModelRef {
        provider: target.provider_id.clone(),
        model: target.model_id.clone(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    };
    if let Some(current) = active {
        selection.reasoning_effort = current.reasoning_effort.clone().filter(|effort| {
            target.reasoning_effort.as_ref().is_some_and(|capability| {
                capability
                    .values
                    .iter()
                    .any(|candidate| candidate.value == effort.value)
            })
        });
        selection.thinking_mode = current
            .thinking_mode
            .filter(|mode| target.thinking_modes.contains(mode));
        selection.prompt_cache_retention = current.prompt_cache_retention.filter(|retention| {
            retention.is_default()
                || cfg
                    .resolve_prompt_cache_retention(
                        &target.provider_id,
                        &target.model_id,
                        Some(*retention),
                    )
                    .is_some()
        });
    }
    Ok(Some(selection))
}

pub fn ensure_config_reachable(cwd: &Path) -> Result<(), String> {
    if std::env::var_os(COCKPIT_CONFIG_ENV).is_some() {
        return Ok(());
    }
    if config_file_paths_for_load(cwd)
        .into_iter()
        .any(|path| path.exists())
    {
        Ok(())
    } else {
        Err("no cockpit config found — run `/settings` to create one".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_config::providers::{
        ActiveReasoningEffort, CapabilityValue, ConfigDoc, EndpointReasoningEffortRequestMapping,
        ModelCapabilities, ProvidersConfig, ReasoningEffortRequestMapping, WireApi,
    };
    use std::collections::BTreeMap;
    use std::fs;

    fn providers_at(cwd: &std::path::Path) -> ProvidersConfig {
        let paths = cockpit_config::dirs::config_file_paths_for_load(cwd);
        let mut cfg = ConfigDoc::providers_from_paths(&paths);
        if cfg.providers.is_empty() {
            let providers_dir = cwd.join(".cockpit").join("providers");
            if let Ok(entries) = fs::read_dir(providers_dir) {
                for entry in entries.flatten() {
                    let Ok(contents) = fs::read_to_string(entry.path()) else {
                        continue;
                    };
                    let Ok(provider) = serde_json::from_str::<ProviderEntry>(&contents) else {
                        continue;
                    };
                    let path = entry.path();
                    let Some(id) = path.file_stem().and_then(|name| name.to_str()) else {
                        continue;
                    };
                    cfg.providers.insert(id.to_string(), provider);
                }
            }
        }
        cfg
    }

    fn seed_active_model(config_path: &std::path::Path, provider: &str, model: &str) {
        let mut raw: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(config_path).unwrap()).unwrap();
        raw["active_model"] = serde_json::json!({ "provider": provider, "model": model });
        fs::write(
            config_path,
            format!("{}\n", serde_json::to_string_pretty(&raw).unwrap()),
        )
        .unwrap();
    }

    fn reasoning_capability() -> ReasoningEffortCapability {
        ReasoningEffortCapability {
            values: vec![
                CapabilityValue {
                    value: "minimal".into(),
                    label: None,
                    description: None,
                },
                CapabilityValue {
                    value: "xhigh".into(),
                    label: Some("Extra high".into()),
                    description: Some("deepest reasoning".into()),
                },
            ],
            default: Some("xhigh".into()),
            request_mapping: Some(ReasoningEffortRequestMapping::JsonField {
                field: "reasoning_effort".into(),
                values: BTreeMap::from([
                    ("minimal".into(), serde_json::json!("minimal")),
                    ("xhigh".into(), serde_json::json!("xhigh")),
                ]),
            }),
            endpoint_request_mappings: Vec::new(),
            source: Some(cockpit_config::providers::CapabilitySource::Live),
        }
    }

    #[test]
    fn ensure_config_unreachable_without_config_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let error = ensure_config_reachable(tmp.path()).unwrap_err();
        assert!(
            error.contains("/settings"),
            "missing config must direct the user to settings: {error}"
        );
    }

    #[test]
    fn native_anthropic_picker_hides_legacy_and_invalid_reasoning_controls() {
        let model = ModelEntry {
            id: "claude-test".into(),
            thinking_modes: vec![ThinkingMode::High],
            capabilities: ModelCapabilities {
                max_output_tokens: Some(8_192),
                reasoning_effort: Some(reasoning_capability()),
                ..ModelCapabilities::default()
            },
            ..ModelEntry::default()
        };
        let provider = ProviderEntry {
            wire_api: WireApi::Anthropic,
            models: vec![model.clone()],
            ..ProviderEntry::default()
        };
        let entry = picker_entry("anthropic", &provider, &model);
        assert!(entry.thinking_modes.is_empty());
        assert!(entry.reasoning_effort.is_none());
    }

    #[test]
    fn configured_copilot_responses_favorite_offers_effort_picker() {
        let responses_only_effort = ReasoningEffortCapability {
            values: vec![CapabilityValue {
                value: "ultra".into(),
                label: None,
                description: None,
            }],
            default: Some("ultra".into()),
            request_mapping: None,
            endpoint_request_mappings: vec![EndpointReasoningEffortRequestMapping {
                wire_api: WireApi::Responses,
                request_mapping: ReasoningEffortRequestMapping::JsonPath {
                    path: vec!["reasoning".into(), "effort".into()],
                    values: BTreeMap::from([("ultra".into(), serde_json::json!("ultra"))]),
                },
            }],
            source: Some(cockpit_config::providers::CapabilitySource::Live),
        };
        let model = ModelEntry {
            id: "gpt-5.6-terra".into(),
            favorite: true,
            capabilities: ModelCapabilities {
                reasoning_effort: Some(responses_only_effort),
                supported_wire_apis: Vec::new(),
                ..ModelCapabilities::default()
            },
            ..ModelEntry::default()
        };
        let provider = ProviderEntry {
            template: Some("copilot".into()),
            wire_api: WireApi::Responses,
            ..ProviderEntry::default()
        };

        let entry = picker_entry("copilot", &provider, &model);

        assert!(entry.is_favorite);
        assert!(
            entry.reasoning_effort.is_some(),
            "an explicitly Responses-routed favorite must expose its effort picker"
        );
    }

    #[test]
    fn renamed_copilot_responses_provider_offers_effort_picker() {
        let responses_only_effort = ReasoningEffortCapability {
            values: vec![CapabilityValue {
                value: "ultra".into(),
                label: None,
                description: None,
            }],
            default: Some("ultra".into()),
            request_mapping: None,
            endpoint_request_mappings: vec![EndpointReasoningEffortRequestMapping {
                wire_api: WireApi::Responses,
                request_mapping: ReasoningEffortRequestMapping::JsonPath {
                    path: vec!["reasoning".into(), "effort".into()],
                    values: BTreeMap::from([("ultra".into(), serde_json::json!("ultra"))]),
                },
            }],
            source: Some(cockpit_config::providers::CapabilitySource::Live),
        };
        let model = ModelEntry {
            id: "gpt-5.6-terra".into(),
            capabilities: ModelCapabilities {
                reasoning_effort: Some(responses_only_effort),
                supported_wire_apis: Vec::new(),
                ..ModelCapabilities::default()
            },
            ..ModelEntry::default()
        };
        let provider = ProviderEntry {
            template: Some("copilot".into()),
            wire_api: WireApi::Responses,
            ..ProviderEntry::default()
        };

        assert!(
            picker_entry("team-github", &provider, &model)
                .reasoning_effort
                .is_some()
        );
    }

    #[test]
    fn cycle_active_favorite_skips_nonfavorites_and_wraps() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        fs::create_dir(&cockpit).unwrap();
        let config_path = cockpit.join("config.json");
        fs::write(&config_path, r#"{"providers":{"p":{"url":"https://example.test","models":[{"id":"a","favorite":true},{"id":"b"},{"id":"c","favorite":true}]}}}"#).unwrap();
        let provider_path =
            cockpit_config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
        fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
        fs::write(
            &provider_path,
            r#"{"url":"https://example.test","models":[{"id":"a","favorite":true},{"id":"b"},{"id":"c","favorite":true}]}"#,
        )
        .unwrap();
        seed_active_model(&config_path, "p", "a");

        let mut cfg = providers_at(tmp.path());
        cfg.active_model = Some(ActiveModelRef {
            provider: "p".into(),
            model: "a".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        });
        let next = cycle_active_favorite(&cfg, cfg.active_model.as_ref(), &HashMap::new(), true)
            .unwrap()
            .expect("next favorite");
        assert_eq!(next.provider, "p");
        assert_eq!(next.model, "c");
        seed_active_model(&config_path, &next.provider, &next.model);

        cfg.active_model = Some(next.clone());
        let prev = cycle_active_favorite(&cfg, cfg.active_model.as_ref(), &HashMap::new(), false)
            .unwrap()
            .expect("previous favorite");
        assert_eq!(prev.provider, "p");
        assert_eq!(prev.model, "a");
    }

    #[test]
    fn cycle_active_favorite_selects_sole_favorite_when_active_model_differs() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "p".into(),
            ProviderEntry {
                models: vec![
                    ModelEntry {
                        id: "active".into(),
                        ..Default::default()
                    },
                    ModelEntry {
                        id: "favorite".into(),
                        favorite: true,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        );
        let active = ActiveModelRef {
            provider: "p".into(),
            model: "active".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        };

        let next = cycle_active_favorite(&cfg, Some(&active), &HashMap::new(), true)
            .unwrap()
            .expect("the different sole favorite is a valid target");
        assert_eq!(next.provider, "p");
        assert_eq!(next.model, "favorite");
    }

    #[test]
    fn cycle_active_favorite_filters_responses_only_effort_on_completions_pin() {
        let responses_only_effort = ReasoningEffortCapability {
            values: vec![CapabilityValue {
                value: "ultra".into(),
                label: None,
                description: None,
            }],
            default: Some("ultra".into()),
            request_mapping: None,
            endpoint_request_mappings: vec![EndpointReasoningEffortRequestMapping {
                wire_api: WireApi::Responses,
                request_mapping: ReasoningEffortRequestMapping::JsonPath {
                    path: vec!["reasoning".into(), "effort".into()],
                    values: BTreeMap::from([("ultra".into(), serde_json::json!("ultra"))]),
                },
            }],
            source: Some(cockpit_config::providers::CapabilitySource::Live),
        };
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "p".into(),
            ProviderEntry {
                models: vec![
                    ModelEntry {
                        id: "active".into(),
                        ..ModelEntry::default()
                    },
                    ModelEntry {
                        id: "favorite".into(),
                        favorite: true,
                        wire_api: WireApi::Completions,
                        capabilities: ModelCapabilities {
                            reasoning_effort: Some(responses_only_effort),
                            ..ModelCapabilities::default()
                        },
                        ..ModelEntry::default()
                    },
                ],
                ..ProviderEntry::default()
            },
        );
        let active = ActiveModelRef {
            provider: "p".into(),
            model: "active".into(),
            reasoning_effort: Some(ActiveReasoningEffort {
                value: "ultra".into(),
            }),
            thinking_mode: None,
            prompt_cache_retention: None,
        };

        let next = cycle_active_favorite(&cfg, Some(&active), &HashMap::new(), true)
            .unwrap()
            .expect("favorite target");
        assert_eq!(next.model, "favorite");
        assert_eq!(
            next.reasoning_effort, None,
            "Responses-only effort must not survive onto a Completions-pinned favorite"
        );
    }
}
