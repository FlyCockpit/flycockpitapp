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
}

/// Switching to an unconfigured model surfaces a loud `Notice` error and
/// leaves the prior model (and the persisted active-model row) active.
#[tokio::test]
async fn live_model_switch_to_unconfigured_keeps_current_model() {
    let (mut driver, _tmp) = model_switch_driver();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .run_control(
            DriverControl::SetActiveModel {
                provider: "provider-c".into(), // never configured
                model: "model-c".into(),
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
}

/// Re-selecting the already-active model is a no-op — no rebuild, no
/// cache-busting churn, no error.
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
    // No notice, no projection event.
    assert!(
        rx.try_recv().is_err(),
        "a same-model re-select emits nothing"
    );
}
