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
async fn session_override_wins_over_persisted_retention_preference() {
    use crate::config::providers::{CapabilityStatus, PromptCacheRetention};

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
        .run_control(DriverControl::RefreshPromptCacheRetention, &tx)
        .await;
    assert_eq!(
        driver.stack[0]
            .agent
            .params
            .prompt_cache_retention
            .as_deref(),
        Some(PromptCacheRetention::EXTENDED_WIRE_VALUE),
        "persisted extended preference applies when no session override is set"
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

    edit_model_switch_config(&mut driver, |cfg| {
        cfg.active_model
            .as_mut()
            .expect("active model exists")
            .prompt_cache_retention = Some(PromptCacheRetention::Default);
    });
    driver
        .run_control(DriverControl::RefreshPromptCacheRetention, &tx)
        .await;
    assert_eq!(
        driver.stack[0].agent.params.prompt_cache_retention, None,
        "persisted default omits the wire key"
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
        "clearing the session override returns to the persisted default"
    );
    match rx.try_recv().expect("longcache emits off state") {
        TurnEvent::LongcacheState { enabled, supported } => {
            assert!(!enabled);
            assert!(supported);
        }
        other => panic!("expected LongcacheState, got {other:?}"),
    }

    edit_model_switch_config(&mut driver, |cfg| {
        cfg.active_model
            .as_mut()
            .expect("active model exists")
            .prompt_cache_retention = None;
    });
    driver
        .run_control(DriverControl::RefreshPromptCacheRetention, &tx)
        .await;
    assert_eq!(
        driver.prompt_cache_retention_preference, None,
        "absent persisted preference is inherited as provider default"
    );
    assert_eq!(
        driver.stack[0].agent.params.prompt_cache_retention, None,
        "neither override nor persisted preference omits retention"
    );

    edit_model_switch_config(&mut driver, |cfg| {
        cfg.active_model
            .as_mut()
            .expect("active model exists")
            .prompt_cache_retention = Some(PromptCacheRetention::Extended);
        set_prompt_cache_retention_capability(
            cfg,
            "provider-a",
            "model-a",
            CapabilityStatus::Unknown,
        );
    });
    driver
        .run_control(DriverControl::RefreshPromptCacheRetention, &tx)
        .await;
    assert_eq!(
        driver.stack[0].agent.params.prompt_cache_retention, None,
        "unknown capability suppresses persisted extended retention"
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
        .run_control(DriverControl::RefreshPromptCacheRetention, &tx)
        .await;
    assert_eq!(
        driver.stack[0].agent.params.prompt_cache_retention, None,
        "unsupported capability suppresses persisted extended retention"
    );
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
    for tool in ["goal", "session_read", "session_search"] {
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

#[tokio::test]
async fn llm_mode_reresolved_on_model_switch() {
    use crate::config::extended::LlmMode;
    use crate::config::providers::ModelEntry;

    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    assert_eq!(driver.stack[0].agent.llm_mode, LlmMode::Defensive);
    driver
        .test_providers_override
        .as_mut()
        .unwrap()
        .0
        .providers
        .get_mut("provider-b")
        .unwrap()
        .models
        .push(ModelEntry {
            id: "model-b".into(),
            mode: Some(LlmMode::Normal),
            ..ModelEntry::default()
        });

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

    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-b");
    assert_eq!(driver.stack[0].agent.llm_mode, LlmMode::Normal);
    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    assert!(events.iter().any(
        |event| matches!(event, TurnEvent::LlmModeChanged { mode } if *mode == LlmMode::Normal)
    ));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TurnEvent::Pruned { .. })),
        "model-pin re-resolution is prune-free; only explicit /llm-mode warns and prunes"
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
                    default_update: crate::daemon::proto::DefaultModelUpdateOutcome::Saved,
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
            assert_eq!(diagnostic_code, "model_switch_rejected");
        }
        other => panic!("expected deadline rejection, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "deadline emits exactly one terminal result"
    );
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

/// A switch requested while a child frame is foregrounded is applied to that
/// active frame and never to the parked root frame.
#[tokio::test]
async fn live_model_switch_from_subagent_frame_applies_to_active_child() {
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

    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-a");
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-a");
    assert_eq!(driver.stack[1].agent.model.provider_id(), "provider-b");
    assert_eq!(driver.stack[1].agent.model.model_id_ref(), "model-b");
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-b")
    );
    assert_eq!(driver.session.active_model().as_deref(), Some("model-b"));
    assert_config_active_model(&driver, "provider-b", "model-b");
}

/// Reasoning effort and thinking mode selected by the client survive the
/// daemon-side config write.
#[tokio::test]
async fn live_model_switch_persists_requested_reasoning_options() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);

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
}

#[tokio::test]
async fn same_identity_preference_change_is_applied_and_persisted() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let before = Arc::as_ptr(&driver.stack[0].agent);

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
                prompt_cache_retention: None,
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
    assert_terminal_model_selection(&mut rx, true);
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
    assert_terminal_model_selection(&mut rx, false);
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
    assert_terminal_model_selection(&mut rx, false);
}

/// Saving the future default is a secondary outcome: a config write failure
/// must not undo a successfully-built and durably-persisted session switch.
#[tokio::test]
async fn live_model_switch_config_write_failure_keeps_session_switch() {
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

    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-b");
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-b");
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-b")
    );
    assert_eq!(driver.session.active_model().as_deref(), Some("model-b"));
    assert_config_active_model(&driver, "provider-a", "model-a");
    assert_one_model_switch_event(&driver, "ok", false).await;
    drain_until_active_model_state(&mut rx);
    match rx.try_recv().expect("terminal selection result") {
        TurnEvent::ModelSelectionResult {
            outcome:
                crate::daemon::proto::ModelSelectionOutcome::Applied {
                    active_state,
                    default_update:
                        crate::daemon::proto::DefaultModelUpdateOutcome::Failed {
                            diagnostic_code,
                            user_message,
                        },
                },
            ..
        } => {
            assert!(active_state.diverged);
            assert_eq!(diagnostic_code, "default_model_write_failed");
            assert!(user_message.contains("could not save it as the default"));
        }
        other => panic!("expected applied selection with default-save failure, got {other:?}"),
    }
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

fn assert_terminal_model_selection(rx: &mut mpsc::Receiver<TurnEvent>, applied: bool) {
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
            match (applied, outcome) {
                (
                    true,
                    crate::daemon::proto::ModelSelectionOutcome::Applied { active_state, .. },
                ) => {
                    assert_eq!(active_state.generation, 1);
                }
                (
                    false,
                    crate::daemon::proto::ModelSelectionOutcome::Rejected {
                        diagnostic_code, ..
                    },
                ) => {
                    assert_eq!(diagnostic_code, "model_switch_rejected");
                }
                (expected, actual) => panic!("expected applied={expected}, got {actual:?}"),
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
    crate::config::providers::ConfigDoc::load(&config_path)
        .unwrap()
        .write_active_model(Some(&crate::config::providers::ActiveModelRef {
            provider: provider.into(),
            model: model.into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        }))
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
            "---\ndescription: test agent\nmode: subagent\ntools: [read]\n---\n\n{name} body\n"
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
    serde_json::to_value(agent.tools.definitions(agent.llm_mode)).unwrap()
}

fn task_definition_mentions_agent(agent: &crate::engine::agent::Agent, name: &str) -> bool {
    agent
        .tools
        .definitions(agent.llm_mode)
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
async fn active_frame_tool_surface_refresh_failure_emits_its_own_notice() {
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
            .refresh_active_tool_surface_for_turn(active_idx, &tx)
            .await;

        assert_eq!(
            Arc::as_ptr(&driver.stack[active_idx].agent),
            before,
            "non-root tool-surface failure must retain the previous agent"
        );
        let notices = drain_notices(&mut rx);
        assert_eq!(notices.len(), 1, "expected one tool-surface notice");
        assert!(
            notices[0].contains("tool surface")
                && notices[0].contains("Keeping the previous tool surface"),
            "unexpected notice: {}",
            notices[0]
        );
        assert_eq!(
            driver.stack[active_idx].agent.name, "builder",
            "non-root failure must not fall back to the default Build primary"
        );
    })
    .await;
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
        assert_eq!(
            notices.len(),
            2,
            "both independent failures should report once"
        );
        assert!(notices.iter().any(|text| text.contains("active model")));
        assert!(notices.iter().any(|text| text.contains("tool surface")));

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
        let notices = drain_notices(&mut rx);
        assert_eq!(
            notices.len(),
            1,
            "only the reintroduced failure should notify"
        );
        assert!(
            notices[0].contains("tool surface"),
            "unexpected notice: {}",
            notices[0]
        );
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
async fn active_frame_refresh_updates_schedule_when_tool_surface_fails() {
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
        assert!(
            drain_notices(&mut rx)
                .iter()
                .any(|notice| notice.contains("tool surface")),
            "tool-surface failure should still be surfaced"
        );
    })
    .await;
}

#[tokio::test]
async fn active_frame_refresh_updates_schedule_when_both_refreshes_fail() {
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
        assert!(
            notices.iter().any(|notice| notice.contains("tool surface")),
            "tool-surface failure should be surfaced: {notices:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn model_switch_inside_subagent_frame_rebuilds_that_frame() {
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

    assert_eq!(
        Arc::as_ptr(&driver.stack[0].agent),
        root_before,
        "explicit switch inside a subagent must leave the root frame untouched"
    );
    assert_ne!(
        Arc::as_ptr(&driver.stack.last().unwrap().agent),
        child_before,
        "explicit switch inside a subagent must rebuild the child frame"
    );
    let child = driver.stack.last().unwrap();
    assert_eq!(child.agent.name, "builder");
    assert_eq!(child.agent.model.provider_id(), "provider-b");
    assert_eq!(child.agent.model.model_id_ref(), "model-b");
    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-a");
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-a");
}

#[tokio::test]
async fn model_switch_inside_subagent_frame_rebuild_failure_keeps_child() {
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

        assert_eq!(Arc::as_ptr(&driver.stack[0].agent), root_before);
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
        let notices = drain_notices(&mut rx);
        assert!(
            notices.iter().any(|notice| {
                notice.contains("Model switch to `provider-b/model-b` failed")
                    && notice.contains("Keeping the current model active")
            }),
            "model switch rebuild failure should be surfaced: {notices:?}"
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
