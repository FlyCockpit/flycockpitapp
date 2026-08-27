use super::*;

fn drain_ready(rx: &mut mpsc::Receiver<TurnEvent>) -> Vec<TurnEvent> {
    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    events
}

#[tokio::test]
async fn tools_apply_rebuilds_root_and_prunes() {
    let (mut driver, _tmp) = test_driver_without_network(1);
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

    driver
        .run_control(
            DriverControl::SetToolSurfaceOverride {
                selection: crate::agents::ToolSurfaceSelection {
                    tools,
                    tool_tiers: base.tool_tiers,
                },
                prune_after_switch: true,
                monty_nudge: Some("monty tools disabled: code".to_string()),
            },
            &tx,
        )
        .await;

    let names = driver.stack[0].agent.tools.names();
    assert!(names.contains(&"skill"), "{names:?}");
    assert!(names.contains(&"read"), "{names:?}");
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
        "tool-surface apply with prune_after_switch should use prune path"
    );
}

#[tokio::test]
async fn tools_apply_refused_when_subagent_foreground() {
    let (mut driver, _tmp) = test_driver_without_network(1);
    push_test_child(&mut driver, dup_read_history_big());
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .run_control(
            DriverControl::SetToolSurfaceOverride {
                selection: crate::agents::ToolSurfaceSelection {
                    tools: vec!["read".to_string()],
                    tool_tiers: std::collections::BTreeMap::new(),
                },
                prune_after_switch: true,
                monty_nudge: None,
            },
            &tx,
        )
        .await;

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
