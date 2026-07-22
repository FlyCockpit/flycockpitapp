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
                trigger: crate::session::ModelSwitchTrigger::Daemon,
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
    for tool in ["todo", "todo_read"] {
        assert!(
            names.contains(&tool),
            "rebuilt foreground Build must preserve interactive direct `{tool}` tool: {names:?}"
        );
    }
    let discoverable = driver.stack[0].agent.tools.discoverable_mcp_tool_names();
    for tool in [
        "create_goal",
        "get_goal",
        "update_goal",
        "session_read",
        "session_search",
    ] {
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
                provider: "provider-b".into(),
                model: "model-b".into(),
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
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

    driver
        .run_control(
            DriverControl::SetActiveModel {
                provider: "provider-b".into(),
                model: "model-b".into(),
                trigger: crate::session::ModelSwitchTrigger::Daemon,
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
    assert_one_model_switch_event(&driver, "ok", false);
    drain_until_active_model_state(&mut rx);
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
                provider: "provider-b".into(),
                model: "model-b".into(),
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
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
                provider: "provider-b".into(),
                model: "model-b".into(),
                trigger: crate::session::ModelSwitchTrigger::Daemon,
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
                trigger: crate::session::ModelSwitchTrigger::Daemon,
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
    assert_one_model_switch_event(&driver, "build_failed", true);
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
                trigger: crate::session::ModelSwitchTrigger::Daemon,
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
    assert_one_model_switch_event(&driver, "send_failed", true);
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
                trigger: crate::session::ModelSwitchTrigger::Daemon,
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
    assert_one_model_switch_event(&driver, "send_failed", true);
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
                trigger: crate::session::ModelSwitchTrigger::Daemon,
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
                trigger: crate::session::ModelSwitchTrigger::Daemon,
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
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
            },
            &tx,
        )
        .await;

    assert_eq!(Arc::as_ptr(&driver.stack[0].agent), before);
    assert_one_model_switch_event(&driver, "noop", false);
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
                trigger: crate::session::ModelSwitchTrigger::Daemon,
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

/// Audit-row write failure is diagnostic-only: an otherwise-successful live
/// model switch still commits the session row, config file, and root model.
#[tokio::test]
async fn live_model_switch_audit_record_failure_does_not_roll_back() {
    let (mut driver, tmp) = model_switch_driver_with_disk_config();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.test_fail_next_model_switch_audit_record = true;

    driver
        .run_control(
            DriverControl::SetActiveModel {
                provider: "provider-b".into(),
                model: "model-b".into(),
                trigger: crate::session::ModelSwitchTrigger::Daemon,
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

fn assert_config_active_model(driver: &Driver, provider: &str, model: &str) {
    let (cfg, _, _) = driver
        .test_providers_override
        .as_ref()
        .expect("model switch harness installs provider override");
    let active = cfg.active_model.as_ref().expect("active model written");
    assert_eq!(active.provider, provider);
    assert_eq!(active.model, model);
}

fn assert_one_model_switch_event(driver: &Driver, outcome: &str, error_present: bool) {
    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
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
    driver.refresh_config_from_disk_for_tests();
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
}

#[tokio::test]
async fn active_frame_tool_surface_refresh_failure_emits_its_own_notice() {
    let (mut driver, tmp) = model_switch_driver_with_disk_config();
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
}

#[tokio::test]
async fn active_frame_refresh_notices_dedupe_independently() {
    let (mut driver, tmp) = model_switch_driver_with_disk_config();
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
}

#[tokio::test]
async fn active_frame_refresh_updates_schedule_when_both_refreshes_fail() {
    let (mut driver, tmp) = model_switch_driver_with_disk_config();
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
                provider: "provider-b".into(),
                model: "model-b".into(),
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
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
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    push_named_test_child(&mut driver, "builder");
    let root_before = Arc::as_ptr(&driver.stack[0].agent);
    let child_before = Arc::as_ptr(&driver.stack.last().unwrap().agent);
    write_malformed_agent_override(tmp.path(), "builder");

    driver
        .run_control(
            DriverControl::SetActiveModel {
                provider: "provider-b".into(),
                model: "model-b".into(),
                trigger: crate::session::ModelSwitchTrigger::Daemon,
                reasoning_effort: None,
                thinking_mode: None,
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
        "provider-a"
    );
    assert_eq!(
        driver.stack.last().unwrap().agent.model.model_id_ref(),
        "model-a"
    );
    let notices = drain_notices(&mut rx);
    assert!(
        notices.iter().any(|notice| {
            notice.contains("Model switch to `provider-b/model-b` failed")
                && notice.contains("Keeping the current model active")
        }),
        "model switch rebuild failure should be surfaced: {notices:?}"
    );
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
