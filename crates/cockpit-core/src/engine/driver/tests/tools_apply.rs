use super::*;

fn drain_ready(rx: &mut mpsc::Receiver<TurnEvent>) -> Vec<TurnEvent> {
    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    events
}

fn install_pinned_build_definition(driver: &mut Driver) {
    let def = crate::agents::embedded_default("Build").expect("embedded Build definition");
    let args = driver.spawn_args(true);
    driver.stack[0].agent = Arc::new(
        crate::engine::builtin::agent_from_def(&def, &args)
            .expect("Build constructs from its embedded definition"),
    );
}

#[test]
fn native_tool_surface_change_checks_reentry_fence_before_installing_surface() {
    let driver = include_str!("../mod.rs");
    let set_tool_surface_override = driver
        .split("async fn set_tool_surface_override")
        .nth(1)
        .expect("set_tool_surface_override must exist")
        .split("/// Decide the cache-aware reuse-vs-fresh path")
        .next()
        .expect("set_tool_surface_override must end before follow-up cache logic");
    let native_schema_changed = set_tool_surface_override
        .find("let native_schema_changed")
        .expect("tool surface override must classify native schema changes");
    let reentry_fence = set_tool_surface_override
        .find("native_schema_changed\n                && self.persist_on_reentry_owns_started_unsettled_siblings()")
        .expect("native changes must be fenced while required pruning is unsafe");
    let install = set_tool_surface_override
        .find("self.stack[0].agent = Arc::new(updated)")
        .expect("tool surface override must install its rebuilt root agent");
    assert!(
        native_schema_changed < reentry_fence && reentry_fence < install,
        "the re-entry fence must reject a native change before it can become live without its mandatory prune"
    );
}

#[tokio::test]
async fn tool_surface_validation_does_not_mutate_live_state() {
    let (mut driver, _tmp) = test_driver_without_network(1);
    install_pinned_build_definition(&mut driver);
    driver.stack[0].history = dup_read_history_big();
    let before = driver.stack[0].agent.clone();
    let mut base = crate::agents::embedded_default("Build").unwrap();
    let mut tools = base.tools.take().unwrap();
    tools.retain(|tool| tool != "read");
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let (respond_to, result) = tokio::sync::oneshot::channel();

    driver
        .run_control(
            DriverControl::ValidateToolSurfaceOverride {
                selection: crate::agents::ToolSurfaceSelection {
                    tools,
                    tool_tiers: base.tool_tiers,
                },
                cache_break_acknowledged: true,
                respond_to,
            },
            &tx,
        )
        .await;

    assert_eq!(result.await.unwrap(), Ok(()));
    assert!(
        Arc::ptr_eq(&driver.stack[0].agent, &before),
        "pre-persistence validation must not install a live-only tool surface"
    );
    assert!(
        !prune::dedup_plan(&driver.stack[0].history).is_empty(),
        "pre-persistence validation must not prune cached history"
    );
    assert!(
        drain_ready(&mut rx).is_empty(),
        "pre-persistence validation must not emit an applied transition"
    );
}

#[tokio::test]
async fn tools_apply_rebuilds_root_and_prunes() {
    let (mut driver, tmp) = test_driver_without_network(1);
    install_pinned_build_definition(&mut driver);
    let pinned_role = driver.stack[0].agent.role_prompt.clone();
    let pinned_model = driver.stack[0].agent.model.clone();
    let pinned_posture = driver.stack[0].agent.posture.clone();
    let pinned_context_policy = driver.stack[0].agent.context_policy.clone();
    let agents = tmp.path().join(".cockpit/agents");
    std::fs::create_dir_all(&agents).unwrap();
    std::fs::write(agents.join("Build.md"), "---\ninvalid: [\n").unwrap();
    driver.stack[0].history = dup_read_history_big();
    assert!(
        !prune::dedup_plan(&driver.stack[0].history).is_empty(),
        "fixture must start prunable"
    );
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let mut base = crate::agents::embedded_default("Build").unwrap();
    let mut tools = base.tools.take().unwrap();
    if !tools.iter().any(|tool| tool == "skill") {
        tools.push("skill".to_string());
        tools.sort();
    }
    let (respond_to, result) = tokio::sync::oneshot::channel();

    driver
        .run_control(
            DriverControl::SetToolSurfaceOverride {
                selection: crate::agents::ToolSurfaceSelection {
                    tools,
                    tool_tiers: base.tool_tiers,
                },
                cache_break_acknowledged: true,
                monty_nudge: Some("monty tools disabled: code".to_string()),
                respond_to,
            },
            &tx,
        )
        .await;
    assert_eq!(result.await.unwrap(), Ok(()));

    let names = driver.stack[0].agent.tools.names();
    assert!(names.contains(&"skill"), "{names:?}");
    assert!(names.contains(&"read"), "{names:?}");
    assert_eq!(driver.stack[0].agent.role_prompt, pinned_role);
    assert!(Arc::ptr_eq(&driver.stack[0].agent.model, &pinned_model));
    assert_eq!(driver.stack[0].agent.posture, pinned_posture);
    assert_eq!(driver.stack[0].agent.context_policy, pinned_context_policy);
    assert_eq!(
        driver.pending_monty_tool_nudge.as_deref(),
        Some("monty tools disabled: code")
    );
    assert!(
        prune::dedup_plan(&driver.stack[0].history).is_empty(),
        "forced prune should remove duplicate snapshot bodies"
    );
    let events = drain_ready(&mut rx);
    assert!(events.iter().any(|event| matches!(
        event,
        TurnEvent::Notice { text } if text.contains("Tool surface updated")
    )));
    assert!(
        events
            .iter()
            .any(|event| matches!(event, TurnEvent::Pruned { .. })),
        "an acknowledged native tool-surface change must use the prune path"
    );
}

#[tokio::test]
async fn tools_apply_refuses_unacknowledged_native_schema_change_before_mutation() {
    let (mut driver, _tmp) = test_driver_without_network(1);
    install_pinned_build_definition(&mut driver);
    let before = driver.stack[0].agent.clone();
    let mut base = crate::agents::embedded_default("Build").unwrap();
    let mut tools = base.tools.take().unwrap();
    assert!(
        tools.iter().any(|tool| tool == "read"),
        "fixture must start with a native read tool"
    );
    tools.retain(|tool| tool != "read");
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let (respond_to, result) = tokio::sync::oneshot::channel();

    driver
        .run_control(
            DriverControl::SetToolSurfaceOverride {
                selection: crate::agents::ToolSurfaceSelection {
                    tools,
                    tool_tiers: base.tool_tiers,
                },
                cache_break_acknowledged: false,
                monty_nudge: Some("must not be staged".to_string()),
                respond_to,
            },
            &tx,
        )
        .await;

    let error = result
        .await
        .unwrap()
        .expect_err("native schema changes require acknowledgement");
    assert!(error.contains("cache-break acknowledgement"), "{error}");
    assert!(
        Arc::ptr_eq(&driver.stack[0].agent, &before),
        "refusal must leave the active tool surface untouched"
    );
    assert!(driver.pending_monty_tool_nudge.is_none());
    let events = drain_ready(&mut rx);
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TurnEvent::Pruned { .. })),
        "an unacknowledged change must not mutate cached context"
    );
}

#[tokio::test]
async fn tools_apply_refused_when_subagent_foreground() {
    let (mut driver, _tmp) = test_driver_without_network(1);
    install_pinned_build_definition(&mut driver);
    push_test_child(&mut driver, dup_read_history_big());
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let (respond_to, result) = tokio::sync::oneshot::channel();

    driver
        .run_control(
            DriverControl::SetToolSurfaceOverride {
                selection: crate::agents::ToolSurfaceSelection {
                    tools: vec!["read".to_string()],
                    tool_tiers: std::collections::BTreeMap::new(),
                },
                cache_break_acknowledged: true,
                monty_nudge: None,
                respond_to,
            },
            &tx,
        )
        .await;
    assert!(result.await.unwrap().is_err());

    assert_eq!(driver.stack.len(), 2);
    assert!(
        !prune::dedup_plan(&driver.stack[1].history).is_empty(),
        "refusal must not prune the foreground subagent"
    );
    let events = drain_ready(&mut rx);
    assert!(events.iter().any(|event| matches!(
        event,
        TurnEvent::Notice { text }
            if text.contains("refused") && text.contains("interactive subagent")
    )));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TurnEvent::Pruned { .. }))
    );
}
