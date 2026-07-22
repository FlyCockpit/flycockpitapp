use super::*;

fn drain_ready(rx: &mut mpsc::Receiver<TurnEvent>) -> Vec<TurnEvent> {
    let mut events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }
    events
}

#[tokio::test]
async fn llm_mode_switch_rebuilds_and_triggers_prune() {
    use crate::config::extended::LlmMode;

    let (mut driver, _tmp) = test_driver(1);
    driver.stack[0].history = dup_read_history_big();
    assert!(
        !prune::dedup_plan(&driver.stack[0].history).is_empty(),
        "fixture must start prunable"
    );
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .run_control(
            DriverControl::SetLlmMode {
                mode: Some(LlmMode::Frontier),
                prune_after_switch: true,
            },
            &tx,
        )
        .await;

    assert_eq!(driver.stack[0].agent.llm_mode, LlmMode::Frontier);
    assert!(
        prune::dedup_plan(&driver.stack[0].history).is_empty(),
        "forced prune should remove duplicate snapshot bodies"
    );
    let events = drain_ready(&mut rx);
    assert!(events.iter().any(
        |event| matches!(event, TurnEvent::LlmModeChanged { mode } if *mode == LlmMode::Frontier)
    ));
    assert!(events.iter().any(|event| matches!(
        event,
        TurnEvent::Pruned {
            auto: false,
            bodies,
            cache_break: false,
            ..
        } if *bodies > 0
    )));
}

#[tokio::test]
async fn llm_mode_noop_does_not_rebuild_or_prune() {
    use crate::config::extended::LlmMode;

    let (mut driver, _tmp) = test_driver(1);
    driver.stack[0].history = dup_read_history_big();
    let original_agent = driver.stack[0].agent.clone();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .run_control(
            DriverControl::SetLlmMode {
                mode: Some(LlmMode::Defensive),
                prune_after_switch: true,
            },
            &tx,
        )
        .await;

    assert!(Arc::ptr_eq(&driver.stack[0].agent, &original_agent));
    assert!(
        !prune::dedup_plan(&driver.stack[0].history).is_empty(),
        "no-op must not prune"
    );
    assert!(drain_ready(&mut rx).is_empty());
}

#[tokio::test]
async fn llm_mode_switch_refused_with_message_when_subagent_foreground() {
    use crate::config::extended::LlmMode;

    let (mut driver, _tmp) = test_driver(1);
    push_test_child(&mut driver, dup_read_history_big());
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .run_control(
            DriverControl::SetLlmMode {
                mode: Some(LlmMode::Frontier),
                prune_after_switch: true,
            },
            &tx,
        )
        .await;

    assert_eq!(driver.stack[0].agent.llm_mode, LlmMode::Defensive);
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

#[tokio::test]
async fn llm_mode_switch_load_failure_leaves_mode_unchanged() {
    use crate::config::extended::LlmMode;

    let (mut driver, _tmp) = test_driver(1);
    let mut agent = driver.stack[0].agent.as_ref().clone();
    agent.name = "missing-agent".to_string();
    driver.stack[0].agent = Arc::new(agent);
    driver.stack[0].history = dup_read_history_big();
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver
        .run_control(
            DriverControl::SetLlmMode {
                mode: Some(LlmMode::Frontier),
                prune_after_switch: true,
            },
            &tx,
        )
        .await;

    assert_eq!(driver.stack[0].agent.llm_mode, LlmMode::Defensive);
    assert!(
        !prune::dedup_plan(&driver.stack[0].history).is_empty(),
        "failed reload must not prune"
    );
    let events = drain_ready(&mut rx);
    assert!(events.iter().any(|event| matches!(
        event,
        TurnEvent::Notice { text }
            if text.contains("failed") && text.contains("Keeping the current mode active")
    )));
    assert!(!events.iter().any(|event| matches!(
        event,
        TurnEvent::LlmModeChanged { .. } | TurnEvent::Pruned { .. }
    )));
}

#[tokio::test]
async fn llm_mode_switch_prune_failure_keeps_new_mode() {
    use crate::config::extended::LlmMode;

    let (mut driver, _tmp) = test_driver(1);
    driver.stack[0].history = dup_read_history_big();
    let (tx, rx) = mpsc::channel::<TurnEvent>(1);
    drop(rx);

    driver
        .run_control(
            DriverControl::SetLlmMode {
                mode: Some(LlmMode::Normal),
                prune_after_switch: true,
            },
            &tx,
        )
        .await;

    assert_eq!(
        driver.stack[0].agent.llm_mode,
        LlmMode::Normal,
        "event delivery/prune notification failure must not roll back the switched mode"
    );
}
