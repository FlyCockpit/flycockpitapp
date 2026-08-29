use super::*;

fn set_prompt_cache_retention_capability(
    cfg: &mut crate::config::providers::ProvidersConfig,
    provider: &str,
    model: &str,
    status: crate::config::providers::CapabilityStatus,
) {
    use crate::config::providers::{ModelCapabilities, ModelEntry};

    let entry = cfg
        .providers
        .get_mut(provider)
        .expect("provider exists in model-switch harness");
    if let Some(model_entry) = entry.models.iter_mut().find(|entry| entry.id == model) {
        model_entry.capabilities.prompt_cache_retention = status;
    } else {
        entry.models.push(ModelEntry {
            id: model.to_string(),
            capabilities: ModelCapabilities {
                prompt_cache_retention: status,
                ..ModelCapabilities::default()
            },
            ..ModelEntry::default()
        });
    }
}

#[test]
fn ordinary_vnext_root_rebuild_pins_its_authorized_running_model() {
    let (driver, _tmp) = model_switch_driver();
    let running = driver.stack[0].agent.model.clone();
    let root_args = driver.spawn_args(true);
    assert!(
        root_args
            .model_override
            .as_ref()
            .is_some_and(|model| Arc::ptr_eq(model, &running)),
        "vNext root reconstruction must carry the running selection"
    );
    let selection = driver.active_selection_for_model(&running);
    let args = driver.rebuild_frame_args(0, running.clone(), &selection, None);

    assert!(
        args.model_override
            .as_ref()
            .is_some_and(|model| Arc::ptr_eq(model, &running)),
        "ordinary root refresh must not replace a resumed/selected vNext model with the slot default"
    );
}

fn install_slot_compatible_model_switch_config(driver: &mut Driver) {
    use crate::config::providers::{ModelCapabilities, ModelEntry};

    let (mut cfg, provider, model) = driver
        .test_providers_override
        .clone()
        .expect("model switch harness installs provider override");
    for (provider_id, model_id) in [("provider-a", "model-a"), ("provider-b", "model-b")] {
        let entry = cfg
            .providers
            .get_mut(provider_id)
            .expect("model-switch provider exists");
        if !entry.models.iter().any(|item| item.id == model_id) {
            entry.models.push(ModelEntry {
                id: model_id.to_string(),
                capabilities: ModelCapabilities {
                    context_tokens: Some(128_000),
                    ..ModelCapabilities::default()
                },
                ..ModelEntry::default()
            });
        }
    }
    driver.test_providers_override = Some((cfg.clone(), provider, model));
    driver.set_config_handle(
        crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                1,
                cfg,
                crate::config::extended::ExtendedConfig::default(),
            ),
        ),
    );
}

fn prepared_rebuild_host_policy(driver: &Driver) -> std::sync::Arc<crate::agents::VnextHostPolicy> {
    std::sync::Arc::new(
        driver.stack[0]
            .agent
            .vnext_grant
            .as_ref()
            .expect("model-switch Build is vNext")
            .host_policy
            .clone(),
    )
}

#[tokio::test]
async fn rebuild_prepared_primary_uses_adopted_default_not_outgoing_running_model() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    install_slot_compatible_model_switch_config(&mut driver);
    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-a");
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-a");

    driver
        .session
        .set_active_model("provider-b", "model-b")
        .unwrap();
    prepare_root_primary_slot_routes(
        &mut driver,
        &[
            ("provider-a", "model-a", false),
            ("provider-b", "model-b", true),
        ],
    );

    let host_policy = prepared_rebuild_host_policy(&driver);
    assert!(
        driver
            .rebuild_prepared_primary("Build", host_policy, &tx)
            .await,
        "prepared primary rebuild must succeed"
    );
    assert_eq!(
        driver.stack[0].agent.model.provider_id(),
        "provider-b",
        "first-time SetAgent rebuild must not keep the outgoing running model"
    );
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-b");
}

#[tokio::test]
async fn rebuild_prepared_primary_keeps_session_matching_in_set_selection() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    install_slot_compatible_model_switch_config(&mut driver);
    assert_eq!(
        driver
            .session
            .active_model_ref()
            .map(|selection| (selection.provider, selection.model)),
        Some(("provider-a".into(), "model-a".into()))
    );
    prepare_root_primary_slot_routes(
        &mut driver,
        &[
            ("provider-a", "model-a", false),
            ("provider-b", "model-b", true),
        ],
    );

    let host_policy = prepared_rebuild_host_policy(&driver);
    assert!(
        driver
            .rebuild_prepared_primary("Build", host_policy, &tx)
            .await,
        "prepared primary rebuild must succeed"
    );
    assert_eq!(
        driver.stack[0].agent.model.provider_id(),
        "provider-a",
        "re-applying a prepared root must keep a session-matching in-set selection"
    );
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-a");
}

#[test]
fn ordinary_vnext_child_rebuild_pins_its_parent_named_running_model() {
    let (mut driver, _tmp) = model_switch_driver();
    push_test_child(&mut driver, Vec::new());
    let cfg = driver
        .test_providers_override
        .as_ref()
        .expect("model switch harness installs provider override")
        .0
        .clone();
    let parent_named = Arc::new(
        crate::engine::model::Model::for_provider(
            &cfg,
            "provider-b",
            "model-b",
            Arc::new(crate::redact::RedactionTable::empty()),
        )
        .unwrap(),
    );
    Arc::make_mut(&mut driver.stack[1].agent).model = parent_named.clone();
    let selection = driver.active_selection_for_model(&parent_named);
    let args = driver.rebuild_frame_args(1, parent_named.clone(), &selection, None);

    assert!(
        !args.delegated && args.delegation_model.is_none(),
        "interactive child rebuild still starts from undeclared-root spawn args"
    );
    assert!(
        args.model_override
            .as_ref()
            .is_some_and(|model| Arc::ptr_eq(model, &parent_named)),
        "ordinary child refresh must not replace a parent-named vNext model with the slot default"
    );
}

#[test]
fn ordinary_vnext_child_rebuild_keeps_parent_mcp_intersection() {
    let (mut driver, _tmp) = model_switch_driver();
    push_test_child(&mut driver, Vec::new());
    let parent_reachable = std::collections::BTreeSet::from([(
        "reachable".to_string(),
        crate::mcp::config::DEFAULT_PROFILE.to_string(),
    )]);
    {
        let child = Arc::make_mut(&mut driver.stack[1].agent);
        child.mcp_resolver = child
            .mcp_resolver
            .with_parent_reachable(parent_reachable.clone());
    }
    let running = driver.stack[1].agent.model.clone();
    let selection = driver.active_selection_for_model(&running);
    let args = driver.rebuild_frame_args(1, running, &selection, None);

    assert_eq!(
        args.mcp_parent_reachable.as_ref(),
        Some(&parent_reachable),
        "interactive child rebuild must keep the admission parent MCP intersection"
    );
    let root_running = driver.stack[0].agent.model.clone();
    let root_selection = driver.active_selection_for_model(&root_running);
    let root_args = driver.rebuild_frame_args(0, root_running, &root_selection, None);
    assert!(
        root_args.mcp_parent_reachable.is_none(),
        "root rebuild must not invent a parent MCP intersection"
    );
}

fn set_reasoning_effort_capability(
    cfg: &mut crate::config::providers::ProvidersConfig,
    provider: &str,
    model: &str,
) {
    use crate::config::providers::{
        CapabilitySource, CapabilityValue, ModelCapabilities, ModelEntry,
        ReasoningEffortCapability, ReasoningEffortRequestMapping,
    };

    let capability = ReasoningEffortCapability {
        values: vec![CapabilityValue {
            value: "xhigh".to_string(),
            label: None,
            description: None,
        }],
        default: None,
        request_mapping: Some(ReasoningEffortRequestMapping::JsonField {
            field: "reasoning_effort".to_string(),
            values: std::collections::BTreeMap::from([(
                "xhigh".to_string(),
                serde_json::json!("xhigh"),
            )]),
        }),
        endpoint_request_mappings: Vec::new(),
        source: Some(CapabilitySource::Live),
    };
    let entry = cfg
        .providers
        .get_mut(provider)
        .expect("provider exists in model-switch harness");
    if let Some(model_entry) = entry.models.iter_mut().find(|entry| entry.id == model) {
        model_entry.capabilities.reasoning_effort = Some(capability);
    } else {
        entry.models.push(ModelEntry {
            id: model.to_string(),
            capabilities: ModelCapabilities {
                reasoning_effort: Some(capability),
                ..ModelCapabilities::default()
            },
            ..ModelEntry::default()
        });
    }
}

fn set_responses_reasoning_effort_capability(
    cfg: &mut crate::config::providers::ProvidersConfig,
    provider: &str,
    model: &str,
) {
    use crate::config::providers::{
        CapabilitySource, CapabilityValue, EndpointReasoningEffortRequestMapping,
        ModelCapabilities, ModelEntry, ReasoningEffortCapability, ReasoningEffortRequestMapping,
        WireApi,
    };

    let capability = ReasoningEffortCapability {
        values: vec![CapabilityValue {
            value: "ultra".to_string(),
            label: None,
            description: None,
        }],
        default: Some("ultra".to_string()),
        request_mapping: None,
        endpoint_request_mappings: vec![EndpointReasoningEffortRequestMapping {
            wire_api: WireApi::Responses,
            request_mapping: ReasoningEffortRequestMapping::JsonPath {
                path: vec!["reasoning".to_string(), "effort".to_string()],
                values: std::collections::BTreeMap::from([(
                    "ultra".to_string(),
                    serde_json::json!("ultra"),
                )]),
            },
        }],
        source: Some(CapabilitySource::Live),
    };
    let entry = cfg
        .providers
        .get_mut(provider)
        .expect("provider exists in model-switch harness");
    if let Some(model_entry) = entry.models.iter_mut().find(|entry| entry.id == model) {
        model_entry.capabilities.reasoning_effort = Some(capability);
        model_entry.capabilities.supported_wire_apis =
            vec![WireApi::Responses, WireApi::Completions];
    } else {
        entry.models.push(ModelEntry {
            id: model.to_string(),
            capabilities: ModelCapabilities {
                reasoning_effort: Some(capability),
                supported_wire_apis: vec![WireApi::Responses, WireApi::Completions],
                ..ModelCapabilities::default()
            },
            ..ModelEntry::default()
        });
    }
}

fn edit_model_switch_config(
    driver: &mut Driver,
    edit: impl FnOnce(&mut crate::config::providers::ProvidersConfig),
) {
    let (cfg, _, _) = driver
        .test_providers_override
        .as_mut()
        .expect("model switch harness installs provider override");
    edit(cfg);
}

#[test]
fn retention_extended_maps_to_24h_only_when_capability_supported() {
    use crate::config::providers::{
        CapabilityStatus, PromptCacheRetention, ProviderEntry, ProvidersConfig,
    };
    use std::collections::BTreeMap;

    let mut cfg = ProvidersConfig {
        providers: BTreeMap::from([("openai".to_string(), ProviderEntry::default())]),
        ..ProvidersConfig::default()
    };
    set_prompt_cache_retention_capability(
        &mut cfg,
        "openai",
        "supported",
        CapabilityStatus::Supported,
    );
    set_prompt_cache_retention_capability(
        &mut cfg,
        "openai",
        "unsupported",
        CapabilityStatus::Unsupported,
    );

    assert_eq!(
        cfg.resolve_prompt_cache_retention(
            "openai",
            "supported",
            Some(PromptCacheRetention::Extended),
        ),
        Some(PromptCacheRetention::EXTENDED_WIRE_VALUE)
    );
    assert_eq!(
        cfg.resolve_prompt_cache_retention(
            "openai",
            "supported",
            Some(PromptCacheRetention::Default),
        ),
        None
    );
    assert_eq!(
        cfg.resolve_prompt_cache_retention(
            "openai",
            "unsupported",
            Some(PromptCacheRetention::Extended),
        ),
        None
    );
    assert_eq!(
        cfg.resolve_prompt_cache_retention(
            "openai",
            "unknown",
            Some(PromptCacheRetention::Extended),
        ),
        None
    );
}

#[tokio::test]
async fn session_selection_wins_over_config_default_retention() {
    use crate::config::providers::{ActiveModelRef, CapabilityStatus, PromptCacheRetention};

    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    edit_model_switch_config(&mut driver, |cfg| {
        set_prompt_cache_retention_capability(
            cfg,
            "provider-a",
            "model-a",
            CapabilityStatus::Supported,
        );
        cfg.active_model
            .as_mut()
            .expect("active model exists")
            .prompt_cache_retention = Some(PromptCacheRetention::Extended);
    });
    driver
        .session
        .set_active_model_ref(ActiveModelRef {
            provider: "provider-a".into(),
            model: "model-a".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: Some(PromptCacheRetention::Default),
        })
        .unwrap();
    driver
        .run_control(
            DriverControl::RefreshConfigDerivedState {
                applied: tokio::sync::oneshot::channel().0,
            },
            &tx,
        )
        .await;
    drain_until_active_model_state(&mut rx);
    assert_eq!(
        driver.stack[0].agent.params.prompt_cache_retention, None,
        "the session's explicit default-retention choice wins over the configured default"
    );
    let background = driver.spawn_args(false);
    assert_eq!(
        background.params.prompt_cache_retention, None,
        "background/utility spawns must not inherit prompt cache retention"
    );
    assert_eq!(
        background.params.prompt_cache_key, None,
        "background/utility spawns must not inherit the foreground cache key"
    );

    driver
        .run_control(
            DriverControl::SetLongcache {
                enabled: Some(true),
            },
            &tx,
        )
        .await;

    assert_eq!(
        driver.stack[0]
            .agent
            .params
            .prompt_cache_retention
            .as_deref(),
        Some(PromptCacheRetention::EXTENDED_WIRE_VALUE)
    );
    match rx.try_recv().expect("longcache emits state") {
        TurnEvent::LongcacheState { enabled, supported } => {
            assert!(enabled);
            assert!(supported);
        }
        other => panic!("expected LongcacheState, got {other:?}"),
    }

    driver
        .run_control(
            DriverControl::SetLongcache {
                enabled: Some(false),
            },
            &tx,
        )
        .await;
    assert_eq!(
        driver.stack[0].agent.params.prompt_cache_retention, None,
        "clearing /longcache returns to the durable session preference"
    );
    match rx.try_recv().expect("longcache emits off state") {
        TurnEvent::LongcacheState { enabled, supported } => {
            assert!(!enabled);
            assert!(supported);
        }
        other => panic!("expected LongcacheState, got {other:?}"),
    }

    driver
        .session
        .set_active_model_ref(ActiveModelRef {
            provider: "provider-a".into(),
            model: "model-a".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: Some(PromptCacheRetention::Extended),
        })
        .unwrap();
    edit_model_switch_config(&mut driver, |cfg| {
        cfg.active_model
            .as_mut()
            .expect("active model exists")
            .prompt_cache_retention = None;
    });
    driver
        .run_control(
            DriverControl::RefreshConfigDerivedState {
                applied: tokio::sync::oneshot::channel().0,
            },
            &tx,
        )
        .await;
    drain_until_active_model_state(&mut rx);
    assert_eq!(
        driver.prompt_cache_retention_preference,
        Some(PromptCacheRetention::Extended),
        "config refresh retains the durable session preference"
    );
    assert_eq!(
        driver.stack[0]
            .agent
            .params
            .prompt_cache_retention
            .as_deref(),
        Some(PromptCacheRetention::EXTENDED_WIRE_VALUE),
        "session extended retention remains active when the configured default differs"
    );

    edit_model_switch_config(&mut driver, |cfg| {
        set_prompt_cache_retention_capability(
            cfg,
            "provider-a",
            "model-a",
            CapabilityStatus::Unknown,
        );
    });
    driver
        .run_control(
            DriverControl::RefreshConfigDerivedState {
                applied: tokio::sync::oneshot::channel().0,
            },
            &tx,
        )
        .await;
    drain_until_active_model_state(&mut rx);
    assert_eq!(
        driver.stack[0].agent.params.prompt_cache_retention, None,
        "unknown capability suppresses the session's extended retention"
    );

    edit_model_switch_config(&mut driver, |cfg| {
        set_prompt_cache_retention_capability(
            cfg,
            "provider-a",
            "model-a",
            CapabilityStatus::Unsupported,
        );
    });
    driver
        .run_control(
            DriverControl::RefreshConfigDerivedState {
                applied: tokio::sync::oneshot::channel().0,
            },
            &tx,
        )
        .await;
    drain_until_active_model_state(&mut rx);
    assert_eq!(
        driver.stack[0].agent.params.prompt_cache_retention, None,
        "unsupported capability suppresses the session's extended retention"
    );
}

#[tokio::test]
async fn config_refresh_emits_same_generation_full_default_and_divergence_correction() {
    use crate::config::providers::{
        ActiveModelRef, ActiveReasoningEffort, PromptCacheRetention, ThinkingMode,
    };

    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let corrected_default = ActiveModelRef {
        provider: "provider-b".into(),
        model: "model-b".into(),
        reasoning_effort: Some(ActiveReasoningEffort {
            value: "high".into(),
        }),
        thinking_mode: Some(ThinkingMode::High),
        prompt_cache_retention: Some(PromptCacheRetention::Extended),
    };
    edit_model_switch_config(&mut driver, |cfg| {
        cfg.active_model = Some(corrected_default.clone());
    });

    driver
        .run_control(
            DriverControl::RefreshConfigDerivedState {
                applied: tokio::sync::oneshot::channel().0,
            },
            &tx,
        )
        .await;

    match rx
        .try_recv()
        .expect("config refresh emits model correction")
    {
        TurnEvent::ActiveModelState {
            selection,
            default_selection,
            diverged,
            generation,
        } => {
            assert_eq!(selection.provider, "provider-a");
            assert_eq!(selection.model, "model-a");
            assert_eq!(default_selection, Some(corrected_default));
            assert!(diverged);
            assert_eq!(generation, 0, "config correction is not a model selection");
        }
        other => panic!("expected ActiveModelState, got {other:?}"),
    }
}

#[tokio::test]
async fn config_refresh_gates_retention_on_loaded_foreground_model() {
    use crate::config::providers::{CapabilityStatus, PromptCacheRetention};

    let (mut driver, _tmp) = model_switch_driver();
    edit_model_switch_config(&mut driver, |cfg| {
        set_prompt_cache_retention_capability(
            cfg,
            "provider-a",
            "model-a",
            CapabilityStatus::Supported,
        );
        set_prompt_cache_retention_capability(
            cfg,
            "provider-b",
            "model-b",
            CapabilityStatus::Unsupported,
        );
        cfg.active_model
            .as_mut()
            .expect("active model exists")
            .prompt_cache_retention = Some(PromptCacheRetention::Extended);
    });
    let cfg = driver
        .test_providers_override
        .as_ref()
        .expect("model switch harness installs provider override")
        .0
        .clone();
    let model_b = Arc::new(
        crate::engine::model::Model::for_provider(
            &cfg,
            "provider-b",
            "model-b",
            Arc::new(crate::redact::RedactionTable::empty()),
        )
        .unwrap(),
    );
    let mut args = driver.spawn_args(true);
    args.model = model_b;
    args.params.prompt_cache_retention = Some(PromptCacheRetention::EXTENDED_WIRE_VALUE.into());
    driver.stack[0].agent = Arc::new(crate::engine::builtin::load("Build", &args).unwrap());

    driver.set_config_handle(
        crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(
                1,
                cfg,
                crate::config::extended::ExtendedConfig::default(),
            ),
        ),
    );

    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-b");
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-b");
    assert_eq!(
        driver.stack[0].agent.params.prompt_cache_retention, None,
        "config refresh must re-resolve retention against the loaded foreground model"
    );
}

#[tokio::test]
async fn longcache_unsupported_model_surfaces_notice_and_stays_off() {
    use crate::config::providers::{CapabilityStatus, PromptCacheRetention};

    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let (cfg, _, _) = driver
        .test_providers_override
        .as_mut()
        .expect("model switch harness installs provider override");
    set_prompt_cache_retention_capability(
        cfg,
        "provider-a",
        "model-a",
        CapabilityStatus::Unsupported,
    );
    driver.prompt_cache_retention_preference = Some(PromptCacheRetention::Extended);

    driver
        .run_control(
            DriverControl::SetLongcache {
                enabled: Some(true),
            },
            &tx,
        )
        .await;

    assert!(
        driver.prompt_cache_retention_override.is_none(),
        "unsupported model must not arm the session override"
    );
    assert_eq!(driver.stack[0].agent.params.prompt_cache_retention, None);
    match rx.try_recv().expect("unsupported toggle emits notice") {
        TurnEvent::Notice { text } => assert!(
            text.contains("/longcache") && text.contains("not verified for the active model"),
            "unexpected notice: {text}"
        ),
        other => panic!("expected Notice, got {other:?}"),
    }
    match rx.try_recv().expect("unsupported toggle emits off state") {
        TurnEvent::LongcacheState { enabled, supported } => {
            assert!(!enabled);
            assert!(!supported);
        }
        other => panic!("expected LongcacheState, got {other:?}"),
    }
}

#[tokio::test]
async fn reasoning_params_prefer_native_capability_over_legacy_thinking_mode() {
    use crate::config::providers::{
        ActiveModelRef, ActiveReasoningEffort, CapabilitySource, CapabilityValue, ModelEntry,
        ProviderEntry, ProvidersConfig, ReasoningEffortCapability, ReasoningEffortRequestMapping,
        ThinkingMode,
    };
    use std::collections::BTreeMap;

    let (mut driver, _tmp) = test_driver(1);
    let mut mapping = BTreeMap::new();
    mapping.insert("minimal".to_string(), serde_json::json!("minimal"));
    mapping.insert("xhigh".to_string(), serde_json::json!("xhigh"));
    let mut providers = BTreeMap::new();
    providers.insert(
        "provider-a".to_string(),
        ProviderEntry {
            url: "http://localhost:1/v1".into(),
            models: vec![ModelEntry {
                id: "model-a".into(),
                capabilities: crate::config::providers::ModelCapabilities {
                    reasoning_effort: Some(ReasoningEffortCapability {
                        values: vec![
                            CapabilityValue {
                                value: "minimal".into(),
                                label: None,
                                description: None,
                            },
                            CapabilityValue {
                                value: "xhigh".into(),
                                label: None,
                                description: None,
                            },
                        ],
                        default: Some("minimal".into()),
                        request_mapping: Some(ReasoningEffortRequestMapping::JsonField {
                            field: "reasoning_effort".into(),
                            values: mapping,
                        }),
                        endpoint_request_mappings: Vec::new(),
                        source: Some(CapabilitySource::Live),
                    }),
                    ..crate::config::providers::ModelCapabilities::default()
                },
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        },
    );
    let cfg = ProvidersConfig {
        providers,
        active_model: Some(ActiveModelRef {
            provider: "provider-a".into(),
            model: "model-a".into(),
            reasoning_effort: Some(ActiveReasoningEffort {
                value: "xhigh".into(),
            }),
            thinking_mode: Some(ThinkingMode::High),
            prompt_cache_retention: None,
        }),
        ..ProvidersConfig::default()
    };
    let model = crate::engine::model::Model::for_provider(
        &cfg,
        "provider-a",
        "model-a",
        Arc::new(crate::redact::RedactionTable::empty()),
    )
    .unwrap();
    driver.test_providers_override = Some((cfg, "provider-a".into(), "model-a".into()));

    assert_eq!(
        driver.resolve_thinking_params_for(&model),
        Some(serde_json::json!({ "reasoning_effort": "xhigh" }))
    );
}

/// Regression: a session driving on model A routes the next request to model
/// B after a mid-session `SetActiveModel`, with no restart — the root
/// primary's bound model is rebuilt to B's id + provider.
#[tokio::test]
async fn live_model_switch_routes_next_request_to_new_model() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    prepare_root_primary_slot_routes(
        &mut driver,
        &[
            ("provider-a", "model-a", true),
            ("provider-b", "model-b", false),
        ],
    );

    // The dispatched request's model == A's id before the switch.
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-a");
    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-a");

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-b".into(),
                model: "model-b".into(),
                persist_as_default: true,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;

    // The next outbound request now routes to B's id + provider, same
    // session, same root history (no restart).
    assert_eq!(
        driver.stack[0].agent.model.model_id_ref(),
        "model-b",
        "next request's model is B after the switch"
    );
    assert_eq!(
        driver.stack[0].agent.model.provider_id(),
        "provider-b",
        "next request's provider is B after the switch"
    );
    // The primary identity is unchanged — only the bound model swapped.
    assert_eq!(driver.stack[0].agent.name, "Build");
    let names = driver.stack[0].agent.tools.names();
    assert!(
        names.contains(&"todo"),
        "rebuilt foreground Build must preserve interactive direct `todo` tool: {names:?}"
    );
    let discoverable = driver.stack[0].agent.tools.discoverable_mcp_tool_names();
    for tool in ["session_read", "session_search"] {
        assert!(
            discoverable.iter().any(|name| name == tool),
            "rebuilt foreground Build must preserve interactive discoverable `{tool}` tool: {discoverable:?}"
        );
    }
    // The session's persisted active-model row is committed to B.
    assert_eq!(driver.session.active_model().as_deref(), Some("model-b"));
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-b")
    );
    assert_config_active_model(&driver, "provider-b", "model-b");
}

#[tokio::test]
async fn prepared_root_out_of_slot_switch_uses_derived_definition_and_persists_runtime_model() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    prepare_root_primary_slot_routes(&mut driver, &[("provider-a", "model-a", true)]);

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-b".into(),
                model: "model-b".into(),
                persist_as_default: false,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;

    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-b");
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-b");
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-b")
    );
    assert_eq!(driver.session.active_model().as_deref(), Some("model-b"));
}

#[tokio::test]
async fn model_switch_carries_prompt_cache_retention() {
    use crate::config::providers::{CapabilityStatus, PromptCacheRetention};

    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    let (cfg, _, _) = driver
        .test_providers_override
        .as_mut()
        .expect("model switch harness installs provider override");
    set_prompt_cache_retention_capability(
        cfg,
        "provider-b",
        "model-b",
        CapabilityStatus::Supported,
    );

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-b".into(),
                model: "model-b".into(),
                persist_as_default: true,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: Some(PromptCacheRetention::Extended),
            },
            &tx,
        )
        .await;

    assert_eq!(
        driver.stack[0]
            .agent
            .params
            .prompt_cache_retention
            .as_deref(),
        Some(PromptCacheRetention::EXTENDED_WIRE_VALUE)
    );
    assert_eq!(
        driver
            .session
            .active_model_ref()
            .and_then(|active| active.prompt_cache_retention),
        Some(PromptCacheRetention::Extended)
    );
    let (cfg, _, _) = driver
        .test_providers_override
        .as_ref()
        .expect("model switch harness installs provider override");
    assert_eq!(
        cfg.active_model
            .as_ref()
            .and_then(|active| active.prompt_cache_retention),
        Some(PromptCacheRetention::Extended)
    );
}

/// A successful switch commits both durable authorities and routes the next
/// inference through the newly selected root model.
#[tokio::test]
async fn live_model_switch_commits_config_and_session_together() {
    let (mut driver, tmp) = model_switch_driver_with_disk_config();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    run_control_with_trusted_project_config(
        &mut driver,
        tmp.path(),
        DriverControl::SetActiveModel {
            selection_id: uuid::Uuid::nil(),
            provider: "provider-b".into(),
            model: "model-b".into(),
            persist_as_default: true,
            trigger: crate::session::ModelSwitchTrigger::Daemon,
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        },
        &tx,
    )
    .await;

    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-b");
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-b");
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-b")
    );
    assert_eq!(driver.session.active_model().as_deref(), Some("model-b"));
    assert_disk_config_active_model(tmp.path(), "provider-b", "model-b");
    assert_one_model_switch_event(&driver, "ok", false).await;
    drain_until_active_model_state(&mut rx);
    match rx.try_recv().expect("terminal selection result") {
        TurnEvent::ModelSelectionResult {
            outcome:
                crate::daemon::proto::ModelSelectionOutcome::Applied {
                    active_state,
                    default_update: crate::daemon::proto::DefaultModelUpdateOutcome::Verified { .. },
                },
            ..
        } => {
            let default = active_state
                .default_selection
                .as_ref()
                .expect("saved default reflected immediately");
            assert_eq!(default.provider, "provider-b");
            assert_eq!(default.model, "model-b");
            assert!(!active_state.diverged);
        }
        other => panic!("expected successful default save, got {other:?}"),
    }
}

/// **Rejected behavior.** Plain Enter must not touch the default at all. The
/// prompt states it "sends a session-only request and never invokes the
/// effective-default mutation API" and "cannot alter `active_model` in any
/// layer" (AC7), that it "stays session-only and never performs the
/// effective-default operation" (Desired behavior, line 124), and that it
/// "remains the consciously separate session-only action" (decision 3). This
/// test previously tolerated a first-default write; it now fails
/// deterministically if that behavior returns.
#[tokio::test]
async fn plain_enter_leaves_an_existing_default_untouched() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-b".into(),
                model: "model-b".into(),
                persist_as_default: false,
                trigger: crate::session::ModelSwitchTrigger::Picker,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;

    assert_config_active_model(&driver, "provider-a", "model-a");
    drain_until_active_model_state(&mut rx);
    match rx.try_recv().expect("terminal selection result") {
        TurnEvent::ModelSelectionResult {
            outcome:
                crate::daemon::proto::ModelSelectionOutcome::Applied {
                    active_state,
                    default_update: crate::daemon::proto::DefaultModelUpdateOutcome::NotRequested,
                },
            ..
        } => {
            assert_eq!(active_state.selection.provider, "provider-b");
            assert_eq!(
                active_state
                    .default_selection
                    .as_ref()
                    .map(|value| value.provider.as_str()),
                Some("provider-a")
            );
            assert!(active_state.diverged);
        }
        other => panic!("expected a session-only switch, got {other:?}"),
    }
}

/// **Rejected behavior.** This previously asserted the opposite — that the
/// first plain-Enter selection saves itself as the default. The prompt forbids
/// it outright: plain Enter "sends a session-only request and never invokes the
/// effective-default mutation API" and "cannot alter `active_model` in any
/// layer" (AC7), "stays session-only and never performs the effective-default
/// operation", and remains "the consciously separate session-only action"
/// (decision 3). Establishing a first default is an explicit act — Ctrl+Enter,
/// `/settings`, or `/setup model`. The old assertion is inverted here so the
/// removed behavior fails deterministically if it ever returns.
#[tokio::test]
async fn plain_enter_never_establishes_a_first_default() {
    let (mut driver, _tmp) = model_switch_driver();
    edit_model_switch_config(&mut driver, |cfg| cfg.active_model = None);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-b".into(),
                model: "model-b".into(),
                persist_as_default: false,
                trigger: crate::session::ModelSwitchTrigger::Picker,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;

    assert!(
        driver
            .live_providers_config()
            .unwrap()
            .active_model
            .is_none(),
        "plain Enter must not write a default into any layer"
    );
    drain_until_active_model_state(&mut rx);
    match rx.try_recv().expect("terminal selection result") {
        TurnEvent::ModelSelectionResult {
            outcome:
                crate::daemon::proto::ModelSelectionOutcome::Applied {
                    active_state,
                    default_update: crate::daemon::proto::DefaultModelUpdateOutcome::NotRequested,
                },
            ..
        } => {
            assert_eq!(active_state.selection.provider, "provider-b");
            assert_eq!(
                active_state.default_selection, None,
                "no default may be reported, because none was written"
            );
        }
        other => panic!("expected a session-only switch with no default write, got {other:?}"),
    }
}

/// **Rejected behavior.** Plain Enter must not touch the default at all. The
/// prompt states it "sends a session-only request and never invokes the
/// effective-default mutation API" and "cannot alter `active_model` in any
/// layer" (AC7), that it "stays session-only and never performs the
/// effective-default operation" (Desired behavior, line 124), and that it
/// "remains the consciously separate session-only action" (decision 3). This
/// test previously tolerated a first-default write; it now fails
/// deterministically if that behavior returns.
///
/// Formerly `concurrent_stale_workers_initialize_exactly_one_default`: plain
/// Enter no longer initializes anything, so the correct invariant is that
/// *neither* concurrent session-only switch writes a default.
#[tokio::test]
async fn concurrent_plain_enter_switches_write_no_default_at_all() {
    let (mut driver_a, mut driver_b, shared, _driver_b_tmp) =
        model_switch_drivers_with_shared_disk_config_without_default();
    let (tx_a, mut rx_a) = mpsc::channel::<TurnEvent>(64);
    let (tx_b, mut rx_b) = mpsc::channel::<TurnEvent>(64);
    let root = shared.path();

    let a = run_control_with_trusted_project_config(
        &mut driver_a,
        root,
        DriverControl::SetActiveModel {
            selection_id: uuid::Uuid::new_v4(),
            provider: "provider-a".into(),
            model: "model-a".into(),
            persist_as_default: false,
            trigger: crate::session::ModelSwitchTrigger::Picker,
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        },
        &tx_a,
    );
    let b = run_control_with_trusted_project_config(
        &mut driver_b,
        root,
        DriverControl::SetActiveModel {
            selection_id: uuid::Uuid::new_v4(),
            provider: "provider-b".into(),
            model: "model-b".into(),
            persist_as_default: false,
            trigger: crate::session::ModelSwitchTrigger::Picker,
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        },
        &tx_b,
    );
    tokio::join!(a, b);

    let outcomes = [
        terminal_default_update(&mut rx_a),
        terminal_default_update(&mut rx_b),
    ];
    assert!(
        outcomes.iter().all(|outcome| matches!(
            outcome,
            crate::daemon::proto::DefaultModelUpdateOutcome::NotRequested
        )),
        "a session-only switch may never report a default update; outcomes={outcomes:?}"
    );
    assert_eq!(
        crate::config::providers::ConfigDoc::load(&root.join(".cockpit/config.json"))
            .unwrap()
            .providers()
            .active_model,
        None,
        "no plain-Enter switch may establish a default"
    );
}

/// **Rejected behavior.** Plain Enter must not touch the default at all. The
/// prompt states it "sends a session-only request and never invokes the
/// effective-default mutation API" and "cannot alter `active_model` in any
/// layer" (AC7), that it "stays session-only and never performs the
/// effective-default operation" (Desired behavior, line 124), and that it
/// "remains the consciously separate session-only action" (decision 3). This
/// test previously tolerated a first-default write; it now fails
/// deterministically if that behavior returns.
///
/// Formerly `concurrent_explicit_replace_always_wins_over_stale_initializer`:
/// the "initializer" is now an ordinary session-only switch, so the explicit
/// replacement is the *only* writer.
#[tokio::test]
async fn a_concurrent_plain_enter_cannot_disturb_an_explicit_replace() {
    let (mut explicit_driver, mut session_only_driver, shared, _session_only_tmp) =
        model_switch_drivers_with_shared_disk_config_without_default();
    let (explicit_tx, _explicit_rx) = mpsc::channel::<TurnEvent>(64);
    let (session_only_tx, _session_only_rx) = mpsc::channel::<TurnEvent>(64);
    let root = shared.path();

    let explicit = run_control_with_trusted_project_config(
        &mut explicit_driver,
        root,
        DriverControl::SetActiveModel {
            selection_id: uuid::Uuid::new_v4(),
            provider: "provider-a".into(),
            model: "model-a".into(),
            persist_as_default: true,
            trigger: crate::session::ModelSwitchTrigger::Picker,
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        },
        &explicit_tx,
    );
    let session_only = run_control_with_trusted_project_config(
        &mut session_only_driver,
        root,
        DriverControl::SetActiveModel {
            selection_id: uuid::Uuid::new_v4(),
            provider: "provider-b".into(),
            model: "model-b".into(),
            persist_as_default: false,
            trigger: crate::session::ModelSwitchTrigger::Picker,
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        },
        &session_only_tx,
    );
    tokio::join!(explicit, session_only);

    assert_disk_config_active_model(root, "provider-a", "model-a");
}

#[tokio::test]
async fn expired_model_selection_deadline_rejects_without_mutating_session() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let selection_id = uuid::Uuid::new_v4();
    let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
    driver
        .run_control(
            DriverControl::SetActiveModelWithDeadline {
                selection_id,
                deadline: std::time::Instant::now() - std::time::Duration::from_secs(1),
                terminal_claimed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                completion: completion_tx,
                provider: "provider-b".into(),
                model: "model-b".into(),
                persist_as_default: false,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;
    completion_rx.await.expect("driver completion signal");
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-a")
    );
    assert_eq!(driver.session.active_model().as_deref(), Some("model-a"));
    match rx.try_recv().expect("deadline rejection") {
        TurnEvent::ModelSelectionResult {
            selection_id: actual,
            outcome:
                crate::daemon::proto::ModelSelectionOutcome::Rejected {
                    diagnostic_code, ..
                },
            ..
        } => {
            assert_eq!(actual, selection_id);
            assert_eq!(diagnostic_code, "model_selection_deadline_exceeded");
        }
        other => panic!("expected deadline rejection, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "deadline emits exactly one terminal result"
    );
}

#[tokio::test]
async fn held_config_lock_times_out_before_terminal_claim_without_late_mutation() {
    let (mut driver, tmp) = model_switch_driver_with_disk_config();
    let root = tmp.path();
    let config_path = root.join(".cockpit/config.json");
    let policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(root).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };
    // Hold the shared cross-process mutation lock so the driver's journaled
    // transaction cannot even reach its durable commit boundary.
    let held = crate::config::hold_config_mutation_lock(&config_path)
        .expect("hold the shared config mutation lock");
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let selection_id = uuid::Uuid::new_v4();
    let terminal_claimed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();

    crate::config::trust::scope_workspace_trust_policy(
        policy,
        driver.run_control(
            DriverControl::SetActiveModelWithDeadline {
                selection_id,
                deadline: std::time::Instant::now() + std::time::Duration::from_millis(150),
                terminal_claimed: terminal_claimed.clone(),
                completion: completion_tx,
                provider: "provider-b".into(),
                model: "model-b".into(),
                persist_as_default: true,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        ),
    )
    .await;
    completion_rx.await.expect("driver completion signal");

    assert!(terminal_claimed.load(std::sync::atomic::Ordering::Acquire));
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-a")
    );
    assert_eq!(driver.session.active_model().as_deref(), Some("model-a"));
    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-a");
    assert_disk_config_active_model(root, "provider-a", "model-a");
    // The deadline is now enforced at commit time, so it reports like any
    // other commit-time failure: a Notice and a refreshed active-model state
    // precede the terminal result. Collect everything and assert on the
    // terminal result specifically, and that there is exactly one.
    let mut terminals = Vec::new();
    while let Ok(event) = rx.try_recv() {
        if let TurnEvent::ModelSelectionResult {
            selection_id: actual,
            outcome,
            ..
        } = event
        {
            terminals.push((actual, outcome));
        }
    }
    assert_eq!(
        terminals.len(),
        1,
        "deadline must emit exactly one terminal result, got {terminals:?}"
    );
    let (actual, outcome) = terminals.remove(0);
    assert_eq!(actual, selection_id);
    match outcome {
        crate::daemon::proto::ModelSelectionOutcome::Rejected {
            diagnostic_code, ..
        } => assert_eq!(diagnostic_code, "model_selection_deadline_exceeded"),
        other => panic!("expected deadline rejection, got {other:?}"),
    }

    drop(held);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-a")
    );
    assert_disk_config_active_model(root, "provider-a", "model-a");
}

#[tokio::test]
async fn worker_terminal_claim_before_commit_prevents_late_model_mutation() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
    let terminal_claimed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));

    driver
        .run_control(
            DriverControl::SetActiveModelWithDeadline {
                selection_id: uuid::Uuid::new_v4(),
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(60),
                terminal_claimed,
                completion: completion_tx,
                provider: "provider-b".into(),
                model: "model-b".into(),
                persist_as_default: false,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;

    completion_rx.await.expect("driver completion signal");
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-a")
    );
    assert_eq!(driver.session.active_model().as_deref(), Some("model-a"));
    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-a");
    assert!(
        rx.try_recv().is_err(),
        "the worker-owned terminal outcome remains the only result"
    );
}

/// A session model switch always updates the durable root while a foreground
/// child retains its pinned model until it returns.
#[tokio::test]
async fn live_model_switch_from_subagent_frame_converges_session_and_parked_root() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    push_test_child(&mut driver, Vec::new());

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-b".into(),
                model: "model-b".into(),
                persist_as_default: true,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;

    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-b");
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-b");
    assert_eq!(driver.stack[1].agent.model.provider_id(), "provider-a");
    assert_eq!(driver.stack[1].agent.model.model_id_ref(), "model-a");
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-b")
    );
    assert_eq!(driver.session.active_model().as_deref(), Some("model-b"));
    assert_config_active_model(&driver, "provider-b", "model-b");

    driver.stack.pop().expect("interactive child returns");
    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-b");
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-b");
    assert_eq!(driver.session.active_model().as_deref(), Some("model-b"));
}

/// Reasoning effort and thinking mode selected by the client survive the
/// daemon-side config write.
#[tokio::test]
async fn live_model_switch_persists_requested_reasoning_options() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    edit_model_switch_config(&mut driver, |cfg| {
        set_reasoning_effort_capability(cfg, "provider-b", "model-b");
    });

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-b".into(),
                model: "model-b".into(),
                persist_as_default: true,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: Some("xhigh".into()),
                thinking_mode: Some(crate::config::providers::ThinkingMode::High),
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;
    let persisted = driver
        .session
        .active_model_ref()
        .expect("full selection persisted in the session");
    assert_eq!(persisted.provider, "provider-b");
    assert_eq!(persisted.model, "model-b");
    assert_eq!(
        persisted
            .reasoning_effort
            .as_ref()
            .map(|effort| effort.value.as_str()),
        Some("xhigh")
    );
    assert_eq!(
        persisted.thinking_mode,
        Some(crate::config::providers::ThinkingMode::High)
    );
    assert_eq!(
        driver.stack[0].agent.params.additional_params,
        Some(serde_json::json!({ "reasoning_effort": "xhigh" })),
        "the committed default selection is applied to the live inference frame"
    );

    let (cfg, _, _) = driver
        .test_providers_override
        .as_ref()
        .expect("model switch harness installs provider override");
    let active = cfg.active_model.as_ref().expect("active model written");
    assert_eq!(active.provider, "provider-b");
    assert_eq!(active.model, "model-b");
    assert_eq!(
        active
            .reasoning_effort
            .as_ref()
            .map(|effort| effort.value.as_str()),
        Some("xhigh")
    );
    assert_eq!(
        active.thinking_mode,
        Some(crate::config::providers::ThinkingMode::High)
    );
    driver.refresh_active_frame_for_turn(&tx).await;
    assert_eq!(
        driver.stack[0].agent.params.additional_params,
        Some(serde_json::json!({ "reasoning_effort": "xhigh" })),
        "the first turn-boundary rebuild retains the committed rich selection"
    );
}

/// A catalog-derived Responses reasoning shape is rebuilt with its alternate
/// endpoint payload on a live switch. The generic fallback route must not
/// replay `reasoning.effort` to Chat Completions.
#[tokio::test]
async fn live_model_switch_keeps_endpoint_specific_reasoning_recovery_params() {
    use crate::config::providers::{ActiveReasoningEffort, WireApi};

    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    edit_model_switch_config(&mut driver, |cfg| {
        set_responses_reasoning_effort_capability(cfg, "provider-b", "model-b");
    });

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-b".into(),
                model: "model-b".into(),
                persist_as_default: true,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: Some("ultra".into()),
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;

    let params = &driver.stack[0].agent.params;
    assert_eq!(
        driver.stack[0].agent.model.current_wire_api(),
        WireApi::Responses,
        "the advertised Responses endpoint is selected for the new model"
    );
    assert_eq!(
        params.additional_params,
        // The model was selected at the advertised `ultra` tier, but rig's typed
        // ReasoningEffort cannot express it, so the resolver clamps the wire
        // value to the ceiling `max` on this recovery/switch dispatch too.
        Some(serde_json::json!({ "reasoning": { "effort": "max" } })),
        "the switched frame uses the catalog's Responses payload (ultra clamped to max)"
    );
    assert_eq!(
        params
            .endpoint_recovery_additional_params
            .as_ref()
            .map(|recovery| recovery.primary_wire_api),
        Some(WireApi::Responses),
        "the switched frame carries endpoint recovery metadata for its own model"
    );
    assert_eq!(
        params.additional_params_for_wire(WireApi::Completions),
        None,
        "a fallback to Chat Completions omits Responses-only reasoning fields"
    );
    assert_eq!(
        driver
            .session
            .active_model_ref()
            .and_then(|selection| selection.reasoning_effort)
            .map(|ActiveReasoningEffort { value }| value),
        Some("ultra".to_string())
    );
}

#[tokio::test]
async fn same_identity_preference_change_is_applied_and_persisted() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let before = Arc::as_ptr(&driver.stack[0].agent);
    edit_model_switch_config(&mut driver, |cfg| {
        set_reasoning_effort_capability(cfg, "provider-a", "model-a");
        set_prompt_cache_retention_capability(
            cfg,
            "provider-a",
            "model-a",
            crate::config::providers::CapabilityStatus::Supported,
        );
    });

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-a".into(),
                model: "model-a".into(),
                persist_as_default: false,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: Some("xhigh".into()),
                thinking_mode: Some(crate::config::providers::ThinkingMode::High),
                prompt_cache_retention: Some(
                    crate::config::providers::PromptCacheRetention::Extended,
                ),
            },
            &tx,
        )
        .await;

    assert_ne!(
        Arc::as_ptr(&driver.stack[0].agent),
        before,
        "changing preferences on the same provider/model is not a no-op"
    );
    let persisted = driver
        .session
        .active_model_ref()
        .expect("full selection persisted in the session");
    assert_eq!(
        persisted
            .reasoning_effort
            .as_ref()
            .map(|effort| effort.value.as_str()),
        Some("xhigh")
    );
    assert_eq!(
        persisted.thinking_mode,
        Some(crate::config::providers::ThinkingMode::High)
    );
    assert_eq!(
        persisted.prompt_cache_retention,
        Some(crate::config::providers::PromptCacheRetention::Extended)
    );
    assert_eq!(
        driver.stack[0].agent.params.additional_params,
        Some(serde_json::json!({ "reasoning_effort": "xhigh" }))
    );
    assert_eq!(
        driver.stack[0]
            .agent
            .params
            .prompt_cache_retention
            .as_deref(),
        Some(crate::config::providers::PromptCacheRetention::EXTENDED_WIRE_VALUE)
    );
    let state = drain_until_active_model_state(&mut rx);
    match state {
        TurnEvent::ActiveModelState {
            selection,
            default_selection,
            diverged,
            ..
        } => {
            assert_eq!(selection, persisted);
            assert!(default_selection.is_some());
            assert!(diverged);
        }
        other => panic!("expected ActiveModelState, got {other:?}"),
    }
    assert_terminal_model_selection(&mut rx, None);
    driver.refresh_active_frame_for_turn(&tx).await;
    assert_eq!(
        driver.stack[0].agent.params.additional_params,
        Some(serde_json::json!({ "reasoning_effort": "xhigh" })),
        "session-only reasoning survives the first queued-turn rebuild"
    );
    assert_eq!(
        driver.stack[0]
            .agent
            .params
            .prompt_cache_retention
            .as_deref(),
        Some(crate::config::providers::PromptCacheRetention::EXTENDED_WIRE_VALUE),
        "session-only cache retention survives the first queued-turn rebuild"
    );
}

/// Switching to an unconfigured model surfaces a loud `Notice` error and
/// leaves the prior model active in live routing, session storage, and config.
#[tokio::test]
async fn live_model_switch_failure_leaves_config_and_session_on_old_model() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-c".into(), // never configured
                model: "model-c".into(),
                persist_as_default: true,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;

    // A loud notice surfaced (never a silent no-op).
    let notice = rx
        .try_recv()
        .expect("a Notice must surface on an unconfigured switch");
    match notice {
        TurnEvent::Notice { text } => {
            assert!(
                text.contains("provider-c") && text.contains("failed"),
                "the notice names the failed target: {text}"
            );
        }
        other => panic!("expected a Notice, got {other:?}"),
    }

    // The prior model A is still active — both the live routing and the
    // persisted row are untouched.
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-a");
    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-a");
    assert_eq!(driver.session.active_model().as_deref(), Some("model-a"));
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-a")
    );
    assert_config_active_model(&driver, "provider-a", "model-a");
    assert_one_model_switch_event(&driver, "build_failed", true).await;
    drain_until_active_model_state(&mut rx);
    assert_terminal_model_selection(&mut rx, Some("model_selection_build_failed"));
}

#[tokio::test]
async fn live_model_switch_fails_closed_without_pinned_root_definition() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    Arc::make_mut(&mut driver.stack[0].agent).definition = None;

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-b".into(),
                model: "model-b".into(),
                persist_as_default: true,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;

    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-a");
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-a");
    assert_eq!(driver.session.active_model().as_deref(), Some("model-a"));
    assert_notice_contains(&mut rx, "no pinned definition");
    drain_until_active_model_state(&mut rx);
    assert_terminal_model_selection(&mut rx, Some("model_selection_rebuild_failed"));
}

/// A session-row persistence failure aborts before config commit and restores
/// the live root model and in-memory session state.
#[tokio::test]
async fn live_model_switch_session_persist_failure_rolls_back() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.test_fail_next_active_model_session_persist = true;

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-b".into(),
                model: "model-b".into(),
                persist_as_default: true,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;

    assert_notice_contains(&mut rx, "session persist failure");
    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-a");
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-a");
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-a")
    );
    assert_eq!(driver.session.active_model().as_deref(), Some("model-a"));
    assert_config_active_model(&driver, "provider-a", "model-a");
    assert_one_model_switch_event(&driver, "send_failed", true).await;
    drain_until_active_model_state(&mut rx);
    assert_terminal_model_selection(&mut rx, Some("model_selection_session_persist_failed"));
}

/// Ctrl+Enter is all-or-nothing: a config write failure rejects the whole
/// session+default transaction and preserves both authorities.
#[tokio::test]
async fn live_model_switch_config_write_failure_rejects_session_and_default() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.test_fail_next_active_model_config_write = true;

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-b".into(),
                model: "model-b".into(),
                persist_as_default: true,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;

    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-a");
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-a");
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-a")
    );
    assert_eq!(driver.session.active_model().as_deref(), Some("model-a"));
    assert_config_active_model(&driver, "provider-a", "model-a");
    assert_one_model_switch_event(&driver, "send_failed", true).await;
    drain_until_active_model_state(&mut rx);
    assert_terminal_model_selection(&mut rx, Some("default_model_write_failed"));
    assert!(rx.try_recv().is_err(), "failure is reported exactly once");
}

/// The legacy unconfigured-target regression remains: the active model is
/// unchanged and the user sees an explicit failure notice.
#[tokio::test]
async fn live_model_switch_to_unconfigured_keeps_current_model() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-c".into(),
                model: "model-c".into(),
                persist_as_default: true,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;

    assert_notice_contains(&mut rx, "provider-c");
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-a");
    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-a");
    assert_eq!(driver.session.active_model().as_deref(), Some("model-a"));
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-a")
    );
    assert_config_active_model(&driver, "provider-a", "model-a");
    drain_until_active_model_state(&mut rx);
}

/// Re-selecting the already-active model is a no-op — no rebuild, no
/// cache-busting churn, no error.
#[tokio::test]
async fn live_model_switch_same_model_emits_state_without_rebuild() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let before = Arc::as_ptr(&driver.stack[0].agent);
    if let Some((cfg, _, _)) = driver.test_providers_override.as_mut() {
        cfg.active_model = Some(crate::config::providers::ActiveModelRef {
            provider: "provider-b".into(),
            model: "model-b".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        });
    }

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-a".into(),
                model: "model-a".into(),
                persist_as_default: true,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;

    // Same Arc — the agent was not rebuilt.
    assert_eq!(
        Arc::as_ptr(&driver.stack[0].agent),
        before,
        "re-selecting the active model must not rebuild the primary"
    );
    match rx
        .try_recv()
        .expect("same-model re-select emits authoritative state")
    {
        TurnEvent::ActiveModelState {
            selection,
            default_selection,
            diverged,
            generation,
        } => {
            assert_eq!(selection.provider, "provider-a");
            assert_eq!(selection.model, "model-a");
            let default_selection = default_selection.expect("default selection");
            assert_eq!(default_selection.provider, "provider-a");
            assert_eq!(default_selection.model, "model-a");
            assert!(!diverged);
            assert_eq!(generation, 1);
        }
        other => panic!("expected ActiveModelState, got {other:?}"),
    }
    match rx
        .try_recv()
        .expect("same-model re-select emits a correlated terminal result")
    {
        TurnEvent::ModelSelectionResult {
            selection_id,
            provider,
            model,
            outcome: crate::daemon::proto::ModelSelectionOutcome::Applied { active_state, .. },
            ..
        } => {
            assert_eq!(selection_id, uuid::Uuid::nil());
            assert_eq!(provider, "provider-a");
            assert_eq!(model, "model-a");
            assert_eq!(active_state.selection.provider, "provider-a");
            assert_eq!(active_state.selection.model, "model-a");
        }
        other => panic!("expected ModelSelectionResult, got {other:?}"),
    }
    assert!(rx.try_recv().is_err(), "one terminal result is emitted");
}

/// Same-model selection preserves the historical no-op invariant.
#[tokio::test]
async fn live_model_switch_same_model_is_noop() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let before = Arc::as_ptr(&driver.stack[0].agent);

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-a".into(),
                model: "model-a".into(),
                persist_as_default: true,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;

    assert_eq!(Arc::as_ptr(&driver.stack[0].agent), before);
    assert_one_model_switch_event(&driver, "noop", false).await;
    drain_until_active_model_state(&mut rx);
}

/// A successful switch emits the authoritative daemon-to-client state event.
#[tokio::test]
async fn live_model_switch_emits_active_model_state_event() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-b".into(),
                model: "model-b".into(),
                persist_as_default: true,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;

    let event = drain_until_active_model_state(&mut rx);
    match event {
        TurnEvent::ActiveModelState {
            selection,
            default_selection,
            diverged,
            generation,
        } => {
            assert_eq!(selection.provider, "provider-b");
            assert_eq!(selection.model, "model-b");
            let default_selection = default_selection.expect("default selection");
            assert_eq!(default_selection.provider, "provider-b");
            assert_eq!(default_selection.model, "model-b");
            assert!(!diverged);
            assert_eq!(generation, 1);
        }
        other => panic!("expected ActiveModelState, got {other:?}"),
    }
}

/// Audit-row write failure is diagnostic-only: an otherwise-successful live
/// model switch still commits the session row, config file, and root model.
#[tokio::test]
async fn live_model_switch_audit_record_failure_does_not_roll_back() {
    let (mut driver, tmp) = model_switch_driver_with_disk_config();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.test_fail_next_model_switch_audit_record = true;

    run_control_with_trusted_project_config(
        &mut driver,
        tmp.path(),
        DriverControl::SetActiveModel {
            selection_id: uuid::Uuid::nil(),
            provider: "provider-b".into(),
            model: "model-b".into(),
            persist_as_default: true,
            trigger: crate::session::ModelSwitchTrigger::Daemon,
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        },
        &tx,
    )
    .await;

    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-b");
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-b");
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-b")
    );
    assert_eq!(driver.session.active_model().as_deref(), Some("model-b"));
    assert_disk_config_active_model(tmp.path(), "provider-b", "model-b");
    drain_until_active_model_state(&mut rx);
}

fn assert_config_active_model(driver: &Driver, provider: &str, model: &str) {
    let (cfg, _, _) = driver
        .test_providers_override
        .as_ref()
        .expect("model switch harness installs provider override");
    let active = cfg.active_model.as_ref().expect("active model written");
    assert_eq!(active.provider, provider);
    assert_eq!(active.model, model);
}

async fn assert_one_model_switch_event(driver: &Driver, outcome: &str, error_present: bool) {
    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == "model_switch")
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1, "one model_switch event must be recorded");
    assert_eq!(events[0].data["from_provider"], "provider-a");
    assert_eq!(events[0].data["from_model"], "model-a");
    assert_eq!(events[0].data["trigger"], "daemon");
    assert_eq!(events[0].data["outcome"], outcome);
    assert_eq!(
        events[0].data["error"].is_string(),
        error_present,
        "error presence should match outcome"
    );
}

fn assert_notice_contains(rx: &mut mpsc::Receiver<TurnEvent>, expected: &str) {
    match rx.try_recv().expect("expected user-visible failure notice") {
        TurnEvent::Notice { text } => {
            assert!(
                text.contains(expected) && text.contains("failed"),
                "notice should contain `{expected}` and `failed`: {text}"
            );
        }
        other => panic!("expected Notice, got {other:?}"),
    }
}

fn assert_terminal_model_selection(
    rx: &mut mpsc::Receiver<TurnEvent>,
    rejection_code: Option<&str>,
) {
    match rx
        .try_recv()
        .expect("a dispatch-accepted selection emits one terminal result")
    {
        TurnEvent::ModelSelectionResult {
            selection_id,
            outcome,
            ..
        } => {
            assert_eq!(selection_id, uuid::Uuid::nil());
            match (rejection_code, outcome) {
                (
                    None,
                    crate::daemon::proto::ModelSelectionOutcome::Applied { active_state, .. },
                ) => {
                    assert_eq!(active_state.generation, 1);
                }
                (
                    Some(expected_code),
                    crate::daemon::proto::ModelSelectionOutcome::Rejected {
                        diagnostic_code, ..
                    },
                ) => {
                    assert_eq!(diagnostic_code, expected_code);
                }
                (expected, actual) => {
                    panic!("expected rejection code {expected:?}, got {actual:?}")
                }
            }
        }
        other => panic!("expected ModelSelectionResult, got {other:?}"),
    }
}

fn drain_until_active_model_state(rx: &mut mpsc::Receiver<TurnEvent>) -> TurnEvent {
    loop {
        let event = rx.try_recv().expect("expected ActiveModelState event");
        if matches!(event, TurnEvent::ActiveModelState { .. }) {
            return event;
        }
    }
}

fn terminal_default_update(
    rx: &mut mpsc::Receiver<TurnEvent>,
) -> crate::daemon::proto::DefaultModelUpdateOutcome {
    drain_until_active_model_state(rx);
    match rx.try_recv().expect("terminal model-selection result") {
        TurnEvent::ModelSelectionResult {
            outcome: crate::daemon::proto::ModelSelectionOutcome::Applied { default_update, .. },
            ..
        } => default_update,
        other => panic!("expected applied ModelSelectionResult, got {other:?}"),
    }
}

fn model_switch_driver_with_disk_config() -> (Driver, tempfile::TempDir) {
    let (mut driver, tmp) = model_switch_driver();
    write_two_model_config(tmp.path(), "provider-a", "model-a");
    driver.test_providers_override = None;
    let policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };
    crate::config::trust::with_workspace_trust_policy(policy, || {
        driver.refresh_config_from_disk_for_tests();
    });
    (driver, tmp)
}

fn model_switch_drivers_with_shared_disk_config_without_default()
-> (Driver, Driver, tempfile::TempDir, tempfile::TempDir) {
    let (mut driver_a, shared) = model_switch_driver();
    write_two_model_config(shared.path(), "provider-a", "model-a");
    // An explicit null at the project layer masks any developer-global
    // default, keeping this concurrent mutation test hermetic.
    std::fs::write(
        shared.path().join(".cockpit/config.json"),
        r#"{"active_model":null}"#,
    )
    .unwrap();
    driver_a.test_providers_override = None;
    driver_a.refresh_config_from_disk_for_tests();

    let (mut driver_b, driver_b_tmp) = model_switch_driver();
    driver_b.cwd = shared.path().to_path_buf();
    driver_b.test_providers_override = None;
    driver_b.refresh_config_from_disk_for_tests();
    (driver_a, driver_b, shared, driver_b_tmp)
}

async fn run_control_with_trusted_project_config(
    driver: &mut Driver,
    project_root: &std::path::Path,
    control: DriverControl,
    tx: &mpsc::Sender<TurnEvent>,
) {
    let root = crate::config::trust::resolve_trust_root(project_root).unwrap();
    let policy = crate::config::trust::WorkspaceTrustPolicy {
        root,
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };
    crate::config::trust::scope_workspace_trust_policy(policy, driver.run_control(control, tx))
        .await;
}

fn write_two_model_config(root: &std::path::Path, provider: &str, model: &str) {
    let cockpit = root.join(".cockpit");
    std::fs::create_dir_all(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    std::fs::write(&config_path, "{}").unwrap();
    for (id, model_id, url) in [
        ("provider-a", "model-a", "http://localhost:1/v1"),
        ("provider-b", "model-b", "http://localhost:2/v1"),
    ] {
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, id).unwrap();
        std::fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
        std::fs::write(
            provider_path,
            format!(r#"{{"url":"{url}","models":[{{"id":"{model_id}"}}]}}"#),
        )
        .unwrap();
    }
    // Seed the layer directly: the only runtime writer of `active_model` is
    // the authoritative effective-default operation, which is under test here.
    let mut raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    raw["active_model"] = serde_json::json!({ "provider": provider, "model": model });
    std::fs::write(
        &config_path,
        format!("{}\n", serde_json::to_string_pretty(&raw).unwrap()),
    )
    .unwrap();
}

fn assert_disk_config_active_model(root: &std::path::Path, provider: &str, model: &str) {
    let active = crate::config::providers::ConfigDoc::load(&root.join(".cockpit/config.json"))
        .unwrap()
        .providers()
        .active_model
        .expect("active model written");
    assert_eq!(active.provider, provider);
    assert_eq!(active.model, model);
}

fn write_custom_agent(root: &std::path::Path, name: &str) {
    let agents = root.join(".cockpit/agents");
    std::fs::create_dir_all(&agents).unwrap();
    std::fs::write(
        agents.join(format!("{name}.md")),
        format!(
            "---\ndescription: test agent\nschemaVersion: 2\nagentId: authored/{name}\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: Test model refresh\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\n\n{name} body\n"
        ),
    )
    .unwrap();
}

fn write_malformed_agent_override(root: &std::path::Path, name: &str) {
    let agents = root.join(".cockpit/agents");
    std::fs::create_dir_all(&agents).unwrap();
    std::fs::write(
        agents.join(format!("{name}.md")),
        "---\nmode: subagent\n---\nmissing description\n",
    )
    .unwrap();
}

fn remove_agent_override(root: &std::path::Path, name: &str) {
    let path = root.join(".cockpit/agents").join(format!("{name}.md"));
    if path.exists() {
        std::fs::remove_file(path).unwrap();
    }
}

fn tool_definitions_value(agent: &crate::engine::agent::Agent) -> serde_json::Value {
    serde_json::to_value(agent.tools.definitions(agent.tool_steering)).unwrap()
}

fn task_definition_mentions_agent(agent: &crate::engine::agent::Agent, name: &str) -> bool {
    agent
        .tools
        .definitions(agent.tool_steering)
        .into_iter()
        .find(|definition| definition.name == "task")
        .map(|definition| serde_json::to_string(&definition).unwrap().contains(name))
        .unwrap_or(false)
}

fn push_named_test_child(driver: &mut Driver, name: &str) {
    let mut args = driver.spawn_args(true);
    args.model = driver.stack[0].agent.model.clone();
    let agent = Arc::new(crate::engine::builtin::load(name, &args).unwrap());
    push_test_child(driver, Vec::new());
    let depth = driver.stack.len() - 1;
    let child = driver.stack.last_mut().unwrap();
    child.queue_target =
        crate::engine::message::QueueTarget::child(name.to_string(), depth, "test", "default");
    child.agent = agent;
}

fn drain_notices(rx: &mut mpsc::Receiver<TurnEvent>) -> Vec<String> {
    let mut notices = Vec::new();
    while let Ok(event) = rx.try_recv() {
        if let TurnEvent::Notice { text } = event {
            notices.push(text);
        }
    }
    notices
}

fn prepare_root_primary_slot_routes(driver: &mut Driver, routes: &[(&str, &str, bool)]) {
    let definition = driver.stack[0]
        .agent
        .definition
        .as_ref()
        .expect("model-switch root has a pinned definition")
        .as_ref()
        .clone();
    let installation_id = uuid::Uuid::from_u128(0x78);
    driver.vnext_local_installation_resolver =
        crate::agents::LocalInstallationResolver::from_bound_definitions(
            std::collections::BTreeMap::from([(installation_id, definition)]),
        )
        .unwrap()
        .with_primary_slot_routes(std::collections::BTreeMap::from([(
            installation_id,
            routes
                .iter()
                .map(
                    |(provider, model, is_default)| crate::agents::PreparedPrimarySlotRoute {
                        provider_profile_handle: (*provider).to_string(),
                        provider_id: (*provider).to_string(),
                        model_id: (*model).to_string(),
                        is_default: *is_default,
                        hard_capability_verified: true,
                    },
                )
                .collect(),
        )]))
        .unwrap();
}

#[tokio::test]
async fn active_frame_refresh_rebuilds_top_frame_not_root() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    push_test_child(&mut driver, Vec::new());
    let root_before = Arc::as_ptr(&driver.stack[0].agent);
    let child_before = Arc::as_ptr(&driver.stack.last().unwrap().agent);

    driver.refresh_active_frame_for_turn(&tx).await;

    assert_eq!(
        Arc::as_ptr(&driver.stack[0].agent),
        root_before,
        "root frame must not be rebuilt while a child frame is active"
    );
    assert_ne!(
        Arc::as_ptr(&driver.stack.last().unwrap().agent),
        child_before,
        "active child frame must be rebuilt"
    );
}

#[tokio::test]
async fn active_frame_refresh_root_only_stack_is_unchanged_behavior() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    let before = driver.stack[0].agent.clone();

    driver.refresh_active_frame_for_turn(&tx).await;

    let after = &driver.stack[0].agent;
    assert_eq!(after.name, before.name);
    assert_eq!(after.model.provider_id(), before.model.provider_id());
    assert_eq!(after.model.model_id_ref(), before.model.model_id_ref());
    assert_eq!(
        after.params.prompt_cache_key,
        before.params.prompt_cache_key
    );
}

#[tokio::test]
async fn active_frame_refresh_picks_up_new_custom_agent_in_subagent_frame() {
    let (mut driver, tmp) = model_switch_driver_with_disk_config();
    let policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };
    crate::config::trust::scope_workspace_trust_policy(policy, async {
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        push_test_child(&mut driver, Vec::new());
        let custom = "active-frame-helper";
        assert!(
            !task_definition_mentions_agent(driver.stack.last().unwrap().agent.as_ref(), custom),
            "custom agent should not be present before its file exists"
        );

        write_custom_agent(tmp.path(), custom);
        admit_authored_child_to_test_grants(&mut driver, &format!("authored/{custom}"));
        driver.refresh_active_frame_for_turn(&tx).await;

        assert!(
            task_definition_mentions_agent(driver.stack.last().unwrap().agent.as_ref(), custom),
            "active child task schema should include the new custom agent after refresh"
        );
        assert!(
            !task_definition_mentions_agent(driver.stack[0].agent.as_ref(), custom),
            "parked root task schema should not be rebuilt while the child is active"
        );
    })
    .await;
}

#[tokio::test]
async fn active_frame_refresh_is_byte_identical_when_config_unchanged() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    push_test_child(&mut driver, Vec::new());
    let before = tool_definitions_value(driver.stack.last().unwrap().agent.as_ref());

    driver.refresh_active_frame_for_turn(&tx).await;
    let after = tool_definitions_value(driver.stack.last().unwrap().agent.as_ref());

    assert_eq!(
        after, before,
        "deterministic active-frame refresh must leave the serialized tool surface unchanged"
    );
}

#[tokio::test]
async fn foreground_definition_is_pinned_while_new_children_see_fresh_definition() {
    let (mut driver, tmp) = model_switch_driver_with_disk_config();
    let policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };
    crate::config::trust::scope_workspace_trust_policy(policy, async {
        let agents = tmp.path().join(".cockpit/agents");
        std::fs::create_dir_all(&agents).unwrap();
        let definition = |body: &str| {
            format!(
                "---\ndescription: pinned builder\nschemaVersion: 2\nagentId: cockpit/builder\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: Test definition pinning\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\n\n{body}\n"
            )
        };
        let path = agents.join("builder.md");
        std::fs::write(&path, definition("PINNED GENERATION")).unwrap();
        push_named_test_child(&mut driver, "builder");
        assert_eq!(
            driver.stack.last().unwrap().agent.role_prompt,
            "PINNED GENERATION"
        );

        std::fs::write(&path, definition("FRESH GENERATION")).unwrap();
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        driver.refresh_active_frame_for_turn(&tx).await;
        assert_eq!(
            driver.stack.last().unwrap().agent.role_prompt,
            "PINNED GENERATION",
            "the running foreground frame keeps its definition snapshot"
        );

        let mut args = driver.spawn_args(true);
        args.model = driver.stack[0].agent.model.clone();
        let fresh = crate::engine::builtin::load("builder", &args).unwrap();
        assert_eq!(
            fresh.role_prompt, "FRESH GENERATION",
            "a newly constructed child resolves the fresh definition"
        );
    })
    .await;
}

#[tokio::test]
async fn active_frame_tool_surface_refresh_survives_model_build_failure() {
    let (mut driver, tmp) = model_switch_driver_with_disk_config();
    let policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };
    crate::config::trust::scope_workspace_trust_policy(policy, async {
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        push_test_child(&mut driver, Vec::new());
        let custom = "model-failure-helper";
        write_custom_agent(tmp.path(), custom);
        admit_authored_child_to_test_grants(&mut driver, &format!("authored/{custom}"));
        driver.test_providers_override = Some((
            crate::config::providers::ProvidersConfig::default(),
            "provider-a".into(),
            "model-a".into(),
        ));

        driver.refresh_active_frame_for_turn(&tx).await;

        let notices = drain_notices(&mut rx);
        assert!(
            notices
                .iter()
                .any(|text| text.contains("Refreshing the active model from config failed")),
            "model refresh failure must emit its existing notice: {notices:?}"
        );
        assert!(
            task_definition_mentions_agent(driver.stack.last().unwrap().agent.as_ref(), custom),
            "tool surface should still pick up the custom agent when model rebuild fails"
        );
    })
    .await;
}

#[tokio::test]
async fn active_frame_refresh_ignores_malformed_newer_definition() {
    let (mut driver, tmp) = model_switch_driver_with_disk_config();
    let policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };
    crate::config::trust::scope_workspace_trust_policy(policy, async {
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        push_named_test_child(&mut driver, "builder");
        let active_idx = driver.stack.len() - 1;
        let before = Arc::as_ptr(&driver.stack[active_idx].agent);
        write_malformed_agent_override(tmp.path(), "builder");

        driver
            .refresh_active_tool_surface_for_turn(active_idx, None, &tx)
            .await;

        assert_ne!(Arc::as_ptr(&driver.stack[active_idx].agent), before);
        let notices = drain_notices(&mut rx);
        assert!(notices.is_empty(), "pinned definition reload: {notices:?}");
        assert_eq!(
            driver.stack[active_idx].agent.name, "builder",
            "the pinned child definition remains active"
        );
    })
    .await;
}

#[tokio::test]
async fn active_tool_surface_refresh_retains_root_without_pinned_definition() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let root = Arc::make_mut(&mut driver.stack[0].agent);
    root.name = "pinned-root-marker".to_string();
    root.definition = None;
    let before = driver.stack[0].agent.clone();

    driver
        .refresh_active_tool_surface_for_turn(0, None, &tx)
        .await;

    assert!(Arc::ptr_eq(&driver.stack[0].agent, &before));
    assert_eq!(driver.stack[0].agent.name, "pinned-root-marker");
    let notices = drain_notices(&mut rx);
    assert!(
        notices
            .iter()
            .any(|notice| notice.contains("no pinned definition")),
        "root reconstruction failure must be surfaced: {notices:?}"
    );
}

#[tokio::test]
async fn active_frame_refresh_notices_dedupe_independently() {
    let (mut driver, tmp) = model_switch_driver_with_disk_config();
    let policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };
    crate::config::trust::scope_workspace_trust_policy(policy, async {
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        push_named_test_child(&mut driver, "builder");
        write_malformed_agent_override(tmp.path(), "builder");
        driver.test_providers_override = Some((
            crate::config::providers::ProvidersConfig::default(),
            "provider-a".into(),
            "model-a".into(),
        ));

        driver.refresh_active_frame_for_turn(&tx).await;
        let notices = drain_notices(&mut rx);
        assert_eq!(notices.len(), 1, "only the model refresh should fail");
        assert!(notices.iter().any(|text| text.contains("active model")));

        driver.refresh_active_frame_for_turn(&tx).await;
        assert!(
            drain_notices(&mut rx).is_empty(),
            "identical recurring failures should dedupe independently"
        );

        remove_agent_override(tmp.path(), "builder");
        driver.test_providers_override = Some((
            two_model_providers_config(),
            "provider-a".into(),
            "model-a".into(),
        ));
        driver.refresh_active_frame_for_turn(&tx).await;
        assert!(
            drain_notices(&mut rx).is_empty(),
            "successful refresh clears both dedupe slots without a notice"
        );

        write_malformed_agent_override(tmp.path(), "builder");
        driver.refresh_active_frame_for_turn(&tx).await;
        assert!(drain_notices(&mut rx).is_empty());
    })
    .await;
}

#[tokio::test]
async fn active_frame_refresh_updates_schedule_agent() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    push_named_test_child(&mut driver, "builder");

    driver.refresh_active_frame_for_turn(&tx).await;

    assert_eq!(driver.schedule.agent_name_for_tests(), "builder");
}

#[tokio::test]
async fn active_frame_refresh_updates_schedule_with_malformed_newer_definition() {
    let (mut driver, tmp) = model_switch_driver_with_disk_config();
    let policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };
    crate::config::trust::scope_workspace_trust_policy(policy, async {
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        push_named_test_child(&mut driver, "builder");
        write_malformed_agent_override(tmp.path(), "builder");

        driver.refresh_active_frame_for_turn(&tx).await;

        assert_eq!(driver.schedule.agent_name_for_tests(), "builder");
        assert!(drain_notices(&mut rx).is_empty());
    })
    .await;
}

#[tokio::test]
async fn active_frame_refresh_updates_schedule_when_model_refresh_fails() {
    let (mut driver, tmp) = model_switch_driver_with_disk_config();
    let policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };
    crate::config::trust::scope_workspace_trust_policy(policy, async {
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        push_named_test_child(&mut driver, "builder");
        write_malformed_agent_override(tmp.path(), "builder");
        driver.test_providers_override = Some((
            crate::config::providers::ProvidersConfig::default(),
            "provider-a".into(),
            "model-a".into(),
        ));

        driver.refresh_active_frame_for_turn(&tx).await;

        assert_eq!(driver.schedule.agent_name_for_tests(), "builder");
        let notices = drain_notices(&mut rx);
        assert!(
            notices.iter().any(|notice| notice.contains("active model")),
            "model refresh failure should be surfaced: {notices:?}"
        );
        assert!(!notices.iter().any(|notice| notice.contains("tool surface")));
    })
    .await;
}

#[tokio::test]
async fn model_switch_inside_subagent_frame_rebuilds_session_root_only() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    push_named_test_child(&mut driver, "builder");
    let root_before = Arc::as_ptr(&driver.stack[0].agent);
    let child_before = Arc::as_ptr(&driver.stack.last().unwrap().agent);

    driver
        .run_control(
            DriverControl::SetActiveModel {
                selection_id: uuid::Uuid::nil(),
                provider: "provider-b".into(),
                model: "model-b".into(),
                persist_as_default: true,
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            &tx,
        )
        .await;

    assert_ne!(
        Arc::as_ptr(&driver.stack[0].agent),
        root_before,
        "session model selection must rebuild the durable root"
    );
    assert_eq!(
        Arc::as_ptr(&driver.stack.last().unwrap().agent),
        child_before,
        "the foreground child must retain its pinned model until it returns"
    );
    let child = driver.stack.last().unwrap();
    assert_eq!(child.agent.name, "builder");
    assert_eq!(child.agent.model.provider_id(), "provider-a");
    assert_eq!(child.agent.model.model_id_ref(), "model-a");
    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-b");
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-b");
    assert_eq!(driver.session.active_model().as_deref(), Some("model-b"));
}

#[tokio::test]
async fn live_root_model_rebuild_never_inherits_foreground_child_config_path() {
    let (mut driver, tmp) = model_switch_driver();
    let root_config = tmp.path().join("root-config.toml");
    let child_config = tmp.path().join("child-config.toml");
    let mut root_agent = (*driver.stack[0].agent).clone();
    root_agent.model = Arc::new(
        (*root_agent.model)
            .clone()
            .with_config_path(root_config.clone()),
    );
    driver.stack[0].agent = Arc::new(root_agent);

    push_named_test_child(&mut driver, "builder");
    let child_index = driver.stack.len() - 1;
    let mut child_agent = (*driver.stack[child_index].agent).clone();
    child_agent.model = Arc::new(
        (*child_agent.model)
            .clone()
            .with_config_path(child_config.clone()),
    );
    driver.stack[child_index].agent = Arc::new(child_agent);

    let rebuilt = driver
        .build_live_model(&crate::config::providers::ActiveModelRef {
            provider: "provider-b".to_string(),
            model: "model-b".to_string(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        })
        .expect("root model rebuild succeeds");

    assert_eq!(rebuilt.config_path(), Some(root_config.as_path()));
    assert_ne!(rebuilt.config_path(), Some(child_config.as_path()));
}

#[tokio::test]
async fn malformed_foreground_child_override_does_not_block_session_root_switch() {
    let (mut driver, tmp) = model_switch_driver_with_disk_config();
    let policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    };
    crate::config::trust::scope_workspace_trust_policy(policy, async {
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        push_named_test_child(&mut driver, "builder");
        let root_before = Arc::as_ptr(&driver.stack[0].agent);
        let child_before = Arc::as_ptr(&driver.stack.last().unwrap().agent);
        let child_provider_before = driver
            .stack
            .last()
            .unwrap()
            .agent
            .model
            .provider_id()
            .to_string();
        let child_model_before = driver
            .stack
            .last()
            .unwrap()
            .agent
            .model
            .model_id_ref()
            .to_string();
        write_malformed_agent_override(tmp.path(), "builder");

        driver
            .run_control(
                DriverControl::SetActiveModel {
                    selection_id: uuid::Uuid::nil(),
                    provider: "provider-b".into(),
                    model: "model-b".into(),
                    persist_as_default: true,
                    trigger: crate::session::ModelSwitchTrigger::Daemon,
                    reasoning_effort: None,
                    thinking_mode: None,
                    prompt_cache_retention: None,
                },
                &tx,
            )
            .await;

        assert_ne!(Arc::as_ptr(&driver.stack[0].agent), root_before);
        assert_eq!(
            Arc::as_ptr(&driver.stack.last().unwrap().agent),
            child_before
        );
        assert_eq!(driver.stack.last().unwrap().agent.name, "builder");
        assert_eq!(
            driver.stack.last().unwrap().agent.model.provider_id(),
            child_provider_before
        );
        assert_eq!(
            driver.stack.last().unwrap().agent.model.model_id_ref(),
            child_model_before
        );
        assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-b");
        assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-b");
        assert_eq!(driver.session.active_model().as_deref(), Some("model-b"));
        let notices = drain_notices(&mut rx);
        assert!(
            notices
                .iter()
                .all(|notice| !notice.contains("Model switch to `provider-b/model-b` failed")),
            "a malformed parked child override must not reject the root switch: {notices:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn refresh_rebuild_inherits_wire_state_only_for_same_identity() {
    use crate::config::providers::WireApi;

    let (driver, _tmp) = model_switch_driver();
    let running = driver.stack[0].agent.model.clone();
    running.confirm_wire_api_for_base_url("http://localhost:1/v1", WireApi::Responses);

    let same = driver
        .build_live_model_for_running(&running, "provider-a", "model-a")
        .expect("same model rebuild succeeds");
    assert_eq!(
        same.confirmed_wire_api_for_base_url("http://localhost:1/v1"),
        Some(WireApi::Responses),
        "same-identity refresh must inherit the session-confirmed endpoint"
    );

    let switched = driver
        .build_live_model_for_running(&running, "provider-b", "model-b")
        .expect("different model build succeeds");
    assert_eq!(
        switched.confirmed_wire_api_for_base_url("http://localhost:1/v1"),
        None,
        "a genuine model switch must not inherit endpoint confirmations"
    );
}

#[tokio::test]
async fn refresh_preserves_confirmed_endpoint_without_probe_cache() {
    use crate::config::providers::WireApi;

    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.stack[0]
        .agent
        .model
        .confirm_wire_api_for_base_url("http://localhost:1/v1", WireApi::Responses);

    driver.refresh_active_frame_for_turn(&tx).await;

    let refreshed = &driver.stack[0].agent.model;
    assert_eq!(
        refreshed.confirmed_wire_api_for_base_url("http://localhost:1/v1"),
        Some(WireApi::Responses)
    );
    assert_eq!(
        refreshed.resolve_live_wire_api_for_base_url("http://localhost:1/v1"),
        WireApi::Responses,
        "the preserved session confirmation must route the refreshed model"
    );
    assert!(
        rx.try_recv().is_err(),
        "successful refresh must not emit a notice"
    );
}

#[tokio::test]
async fn explicit_config_endpoint_beats_stale_confirmation_after_refresh() {
    use crate::config::providers::WireApi;

    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    driver.stack[0]
        .agent
        .model
        .confirm_wire_api_for_base_url("http://localhost:1/v1", WireApi::Responses);
    let (cfg, _, _) = driver
        .test_providers_override
        .as_mut()
        .expect("model switch harness installs provider override");
    cfg.providers
        .get_mut("provider-a")
        .expect("provider-a exists")
        .wire_api = WireApi::Completions;

    driver.refresh_active_frame_for_turn(&tx).await;

    let refreshed = &driver.stack[0].agent.model;
    assert_eq!(
        refreshed.confirmed_wire_api_for_base_url("http://localhost:1/v1"),
        Some(WireApi::Responses),
        "the stale confirmation is preserved for the session"
    );
    assert_eq!(
        refreshed.resolve_live_wire_api_for_base_url("http://localhost:1/v1"),
        WireApi::Completions,
        "but the fresh explicit config pin wins over it"
    );
}

#[tokio::test]
async fn refresh_failure_is_loud_and_deduped() {
    use crate::config::providers::WireApi;

    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let before = Arc::as_ptr(&driver.stack[0].agent.model);
    driver.stack[0]
        .agent
        .model
        .confirm_wire_api_for_base_url("http://localhost:1/v1", WireApi::Responses);
    driver.test_providers_override = Some((
        crate::config::providers::ProvidersConfig::default(),
        "provider-a".into(),
        "model-a".into(),
    ));

    driver.refresh_active_frame_for_turn(&tx).await;
    assert_eq!(
        Arc::as_ptr(&driver.stack[0].agent.model),
        before,
        "failed refresh must keep the previous model active"
    );
    assert_eq!(
        driver.stack[0]
            .agent
            .model
            .confirmed_wire_api_for_base_url("http://localhost:1/v1"),
        Some(WireApi::Responses),
        "failed refresh must preserve the current model's confirmed endpoint state"
    );
    match rx.try_recv().expect("first failure emits a notice") {
        TurnEvent::Notice { text } => assert!(
            text.contains("Refreshing the active model from config failed")
                && text.contains("Keeping the previous model active"),
            "unexpected notice text: {text}"
        ),
        other => panic!("expected a Notice, got {other:?}"),
    }

    driver.refresh_active_frame_for_turn(&tx).await;
    assert!(
        rx.try_recv().is_err(),
        "identical consecutive refresh failures should dedupe notices"
    );

    driver.test_providers_override = Some((
        two_model_providers_config(),
        "provider-a".into(),
        "model-a".into(),
    ));
    driver.refresh_active_frame_for_turn(&tx).await;
    assert!(
        rx.try_recv().is_err(),
        "successful refresh should not emit a notice"
    );

    driver.test_providers_override = Some((
        crate::config::providers::ProvidersConfig::default(),
        "provider-a".into(),
        "model-a".into(),
    ));
    driver.refresh_active_frame_for_turn(&tx).await;
    rx.try_recv()
        .expect("success clears the dedupe key so the next failure re-notifies");
}

/// A recovery pass cannot know the driver's active-model-state generation, and
/// a client's terminal gate compares against exactly that. Routing the
/// recovered terminal through the driver must therefore stamp a generation
/// strictly newer than anything the client has already seen — otherwise the
/// gate silently drops the one terminal event the client is waiting for.
#[tokio::test]
async fn recovered_terminals_carry_a_generation_the_client_gate_accepts() {
    use crate::config::providers::{
        ActiveModelRef, RecoveredOutcome, RecoveredTransaction, SessionCompensation,
        TransactionCorrelation,
    };

    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let session_id = driver.session.id;
    // Whatever the client last observed.
    driver.active_model_state_generation = 7;
    let baseline = driver.active_model_state_generation;

    let requested = ActiveModelRef {
        provider: "provider-b".into(),
        model: "model-b".into(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    };
    let selection_id = uuid::Uuid::new_v4();
    let default_update_id = uuid::Uuid::new_v4();
    let (receipt_ready, receipt_result) = tokio::sync::oneshot::channel();
    driver
        .run_control(
            DriverControl::EmitRecoveredDefaultTerminals {
                transactions: vec![
                    RecoveredTransaction {
                        correlation: TransactionCorrelation::ModelSelection {
                            selection_id,
                            session_id,
                        },
                        outcome: RecoveredOutcome::Applied {
                            // A recovery pass's own stamp; the driver replaces it.
                            selection: Some(requested.clone()),
                            generation: 0,
                        },
                        scope_label: "user".into(),
                        requested: Some(requested.clone()),
                    },
                    RecoveredTransaction {
                        correlation: TransactionCorrelation::RetainedDefaultUpdate {
                            default_update_id,
                            session_id,
                            authority: Some(
                                crate::config::providers::DefaultUpdateAuthorityBinding::new(
                                    "4d8d4cd5bbf18d6ae07e52adf7f0b6a9e5e8f91a9e72d8cb69c6a129e84e400c"
                                        .to_string(),
                                    3,
                                )
                                .unwrap(),
                            ),
                        },
                        outcome: RecoveredOutcome::Restored {
                            restored: None,
                            session: SessionCompensation::Untouched,
                        },
                        scope_label: "user".into(),
                        requested: Some(requested.clone()),
                    },
                    // A transaction for a different session must be ignored.
                    RecoveredTransaction {
                        correlation: TransactionCorrelation::RetainedDefaultUpdate {
                            default_update_id: uuid::Uuid::new_v4(),
                            session_id: uuid::Uuid::new_v4(),
                            authority: None,
                        },
                        outcome: RecoveredOutcome::Restored {
                            restored: None,
                            session: SessionCompensation::Untouched,
                        },
                        scope_label: "user".into(),
                        requested: Some(requested.clone()),
                    },
                ],
                respond_to: Some(receipt_ready),
            },
            &tx,
        )
        .await;
    receipt_result
        .await
        .expect("recovered terminal driver acknowledges its durable receipt")
        .expect("recovered terminal receipt is persisted before event fan-out");
    let stored_receipt = driver
        .session
        .db
        .default_model_update_receipt(session_id, default_update_id)
        .await
        .expect("read durable recovered default receipt")
        .expect("default update terminal receipt is present");
    assert!(
        stored_receipt
            .outcome_json
            .contains("effective_default_restored_after_boundary"),
        "the durable receipt carries the exact safe terminal outcome"
    );
    assert_eq!(
        stored_receipt.authority_revision.as_deref(),
        Some("4d8d4cd5bbf18d6ae07e52adf7f0b6a9e5e8f91a9e72d8cb69c6a129e84e400c"),
        "even a recovered rejection remains tied to its retained authority"
    );
    assert_eq!(stored_receipt.config_generation, Some(3));

    match rx.try_recv().expect("recovered model-selection terminal") {
        TurnEvent::ModelSelectionResult {
            selection_id: got,
            outcome:
                crate::daemon::proto::ModelSelectionOutcome::Applied {
                    active_state,
                    default_update,
                },
            ..
        } => {
            assert_eq!(got, selection_id);
            assert!(
                active_state.generation > baseline,
                "a recovered Applied must be newer than the client's baseline: {} vs {baseline}",
                active_state.generation
            );
            match default_update {
                crate::daemon::proto::DefaultModelUpdateOutcome::Verified {
                    generation,
                    scope_label,
                    ..
                } => {
                    assert!(generation > baseline);
                    assert_eq!(scope_label, "user");
                }
                other => panic!("expected a verified default update, got {other:?}"),
            }
        }
        other => panic!("expected a recovered ModelSelectionResult, got {other:?}"),
    }

    match rx.try_recv().expect("recovered default-update terminal") {
        TurnEvent::DefaultModelUpdateResult {
            default_update_id: got,
            outcome:
                crate::daemon::proto::DefaultModelStandaloneOutcome::Rejected {
                    user_message,
                    diagnostic_code,
                },
        } => {
            assert_eq!(got, default_update_id);
            assert_eq!(diagnostic_code, "effective_default_restored_after_boundary");
            assert!(
                user_message.contains("the session model was never changed"),
                "a restoration must describe the session half truthfully: {user_message}"
            );
        }
        other => panic!("expected a recovered DefaultModelUpdateResult, got {other:?}"),
    }

    assert!(
        rx.try_recv().is_err(),
        "a transaction for another session must not be emitted here"
    );
}

/// A recovered `SetDefaultModel` is config-only by contract: `/settings`
/// changes the default for *new* sessions and must never switch the running
/// one (AC6/AC9). Only a `ModelSelection` correlation — the Ctrl+Enter
/// session+default transaction — may adopt the recovered model into the live
/// root agent.
#[tokio::test]
async fn a_recovered_default_update_never_switches_the_live_session() {
    use crate::config::providers::{
        ActiveModelRef, RecoveredOutcome, RecoveredTransaction, TransactionCorrelation,
    };

    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let session_id = driver.session.id;
    let running_before = driver.stack[0].agent.model.provider_id().to_string();
    let session_model_before = driver.session.active_model_ref();
    assert_eq!(running_before, "provider-a");

    let recovered = ActiveModelRef {
        provider: "provider-b".into(),
        model: "model-b".into(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    };
    let default_update_id = uuid::Uuid::new_v4();
    driver
        .run_control(
            DriverControl::EmitRecoveredDefaultTerminals {
                transactions: vec![RecoveredTransaction {
                    correlation: TransactionCorrelation::RetainedDefaultUpdate {
                        default_update_id,
                        session_id,
                        authority: Some(
                            crate::config::providers::DefaultUpdateAuthorityBinding::new(
                                "4d8d4cd5bbf18d6ae07e52adf7f0b6a9e5e8f91a9e72d8cb69c6a129e84e400c"
                                    .to_string(),
                                3,
                            )
                            .unwrap(),
                        ),
                    },
                    outcome: RecoveredOutcome::Applied {
                        selection: Some(recovered.clone()),
                        generation: 3,
                    },
                    scope_label: "user".into(),
                    requested: Some(recovered.clone()),
                }],
                respond_to: None,
            },
            &tx,
        )
        .await;

    assert_eq!(
        driver.stack[0].agent.model.provider_id(),
        "provider-a",
        "a config-only default recovery must not rebuild the live root agent"
    );
    assert_eq!(
        driver.session.active_model_ref(),
        session_model_before,
        "a config-only default recovery must not touch the session model"
    );

    match rx.try_recv().expect("recovered default-update terminal") {
        TurnEvent::DefaultModelUpdateResult {
            default_update_id: got,
            outcome:
                crate::daemon::proto::DefaultModelStandaloneOutcome::Applied {
                    selection,
                    scope_label,
                    generation,
                    ..
                },
        } => {
            assert_eq!(got, default_update_id);
            assert_eq!(selection.as_ref(), Some(&recovered));
            assert_eq!(scope_label, "user");
            assert_eq!(
                generation, 3,
                "recovered config-only terminal preserves its sealed config generation"
            );
        }
        other => panic!("expected a recovered DefaultModelUpdateResult, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "a config-only default recovery emits exactly one event and no state change"
    );
}
