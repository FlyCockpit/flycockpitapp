use super::*;

#[test]
fn reasoning_params_prefer_native_capability_over_legacy_thinking_mode() {
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
                provider: "provider-b".into(),
                model: "model-b".into(),
                reasoning_effort: None,
                thinking_mode: None,
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
    for tool in [
        "create_goal",
        "get_goal",
        "update_goal",
        "todo",
        "todo_read",
        "session_read",
        "session_search",
    ] {
        assert!(
            names.contains(&tool),
            "rebuilt foreground Build must preserve interactive `{tool}` tool: {names:?}"
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

/// A successful switch commits both durable authorities and routes the next
/// inference through the newly selected root model.
#[tokio::test]
async fn live_model_switch_commits_config_and_session_together() {
    let (mut driver, tmp) = model_switch_driver_with_disk_config();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .run_control(
            DriverControl::SetActiveModel {
                provider: "provider-b".into(),
                model: "model-b".into(),
                reasoning_effort: None,
                thinking_mode: None,
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

/// A switch requested while a child frame is foregrounded is applied to the
/// root primary and never to the transient child frame.
#[tokio::test]
async fn live_model_switch_from_subagent_frame_applies_to_root() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    push_test_child(&mut driver, Vec::new());

    driver
        .run_control(
            DriverControl::SetActiveModel {
                provider: "provider-b".into(),
                model: "model-b".into(),
                reasoning_effort: None,
                thinking_mode: None,
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
                provider: "provider-b".into(),
                model: "model-b".into(),
                reasoning_effort: Some("xhigh".into()),
                thinking_mode: Some("high".into()),
            },
            &tx,
        )
        .await;

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

/// Switching to an unconfigured model surfaces a loud `Notice` error and
/// leaves the prior model active in live routing, session storage, and config.
#[tokio::test]
async fn live_model_switch_failure_leaves_config_and_session_on_old_model() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .run_control(
            DriverControl::SetActiveModel {
                provider: "provider-c".into(), // never configured
                model: "model-c".into(),
                reasoning_effort: None,
                thinking_mode: None,
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
    drain_until_active_model_state(&mut rx);
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
                provider: "provider-b".into(),
                model: "model-b".into(),
                reasoning_effort: None,
                thinking_mode: None,
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
    drain_until_active_model_state(&mut rx);
}

/// A config write failure rolls the session row back and keeps the live root
/// model on the previous provider/model pair.
#[tokio::test]
async fn live_model_switch_config_write_failure_rolls_back() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.test_fail_next_active_model_config_write = true;

    driver
        .run_control(
            DriverControl::SetActiveModel {
                provider: "provider-b".into(),
                model: "model-b".into(),
                reasoning_effort: None,
                thinking_mode: None,
            },
            &tx,
        )
        .await;

    assert_notice_contains(&mut rx, "config write failure");
    assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-a");
    assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-a");
    assert_eq!(
        driver.session.active_provider().as_deref(),
        Some("provider-a")
    );
    assert_eq!(driver.session.active_model().as_deref(), Some("model-a"));
    assert_config_active_model(&driver, "provider-a", "model-a");
    drain_until_active_model_state(&mut rx);
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
                provider: "provider-c".into(),
                model: "model-c".into(),
                reasoning_effort: None,
                thinking_mode: None,
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
        });
    }

    driver
        .run_control(
            DriverControl::SetActiveModel {
                provider: "provider-a".into(),
                model: "model-a".into(),
                reasoning_effort: None,
                thinking_mode: None,
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
            provider,
            model,
            config_provider,
            config_model,
            diverged,
            generation,
        } => {
            assert_eq!(provider, "provider-a");
            assert_eq!(model, "model-a");
            assert_eq!(config_provider.as_deref(), Some("provider-b"));
            assert_eq!(config_model.as_deref(), Some("model-b"));
            assert!(diverged);
            assert_eq!(generation, 1);
        }
        other => panic!("expected ActiveModelState, got {other:?}"),
    }
    assert!(
        rx.try_recv().is_err(),
        "same-model re-select emits no notice or projection"
    );
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
                provider: "provider-a".into(),
                model: "model-a".into(),
                reasoning_effort: None,
                thinking_mode: None,
            },
            &tx,
        )
        .await;

    assert_eq!(Arc::as_ptr(&driver.stack[0].agent), before);
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
                provider: "provider-b".into(),
                model: "model-b".into(),
                reasoning_effort: None,
                thinking_mode: None,
            },
            &tx,
        )
        .await;

    let event = drain_until_active_model_state(&mut rx);
    match event {
        TurnEvent::ActiveModelState {
            provider,
            model,
            config_provider,
            config_model,
            diverged,
            generation,
        } => {
            assert_eq!(provider, "provider-b");
            assert_eq!(model, "model-b");
            assert_eq!(config_provider.as_deref(), Some("provider-b"));
            assert_eq!(config_model.as_deref(), Some("model-b"));
            assert!(!diverged);
            assert_eq!(generation, 1);
        }
        other => panic!("expected ActiveModelState, got {other:?}"),
    }
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
    (driver, tmp)
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

#[test]
fn refresh_rebuild_inherits_wire_state_only_for_same_identity() {
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

    driver.refresh_active_model_for_turn(&tx).await;

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

    driver.refresh_active_model_for_turn(&tx).await;

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

    driver.refresh_active_model_for_turn(&tx).await;
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

    driver.refresh_active_model_for_turn(&tx).await;
    assert!(
        rx.try_recv().is_err(),
        "identical consecutive refresh failures should dedupe notices"
    );

    driver.test_providers_override = Some((
        two_model_providers_config(),
        "provider-a".into(),
        "model-a".into(),
    ));
    driver.refresh_active_model_for_turn(&tx).await;
    assert!(
        rx.try_recv().is_err(),
        "successful refresh should not emit a notice"
    );

    driver.test_providers_override = Some((
        crate::config::providers::ProvidersConfig::default(),
        "provider-a".into(),
        "model-a".into(),
    ));
    driver.refresh_active_model_for_turn(&tx).await;
    rx.try_recv()
        .expect("success clears the dedupe key so the next failure re-notifies");
}
