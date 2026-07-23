use super::*;

#[tokio::test]
async fn turn_boundary_refresh_picks_up_new_dotenv_secret_for_driver_model_and_schedule() {
    let (mut driver, tmp) = test_driver(1);
    std::fs::write(tmp.path().join(".env"), "NEW_SECRET=turn-boundary-secret\n").unwrap();
    let (tx, _rx) = mpsc::channel(8);

    driver.refresh_redaction_table_for_turn(&tx).await;

    for scrubbed in [
        driver.redact.scrub("turn-boundary-secret"),
        driver.stack[0]
            .agent
            .model
            .redact_table()
            .scrub("turn-boundary-secret"),
        driver
            .schedule
            .redaction_table()
            .scrub("turn-boundary-secret"),
    ] {
        assert!(!scrubbed.contains("turn-boundary-secret"));
        assert!(scrubbed.contains("REDACTED"));
    }
}

#[tokio::test]
async fn stale_child_watermark_does_not_suppress_sibling_auto_prune() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    push_test_child(&mut driver, dup_read_history_big());

    assert!(driver.maybe_auto_prune(&tx).await, "child A prunes");
    let stale_len = driver
        .prune_watermark
        .get(&2)
        .copied()
        .expect("child A depth-2 watermark");
    let _ = driver.pop_child_with_envelope(None, &tx).await;

    let sibling_history = dup_read_history_big();
    assert_eq!(
        sibling_history.len(),
        stale_len,
        "regression setup requires sibling history length to match stale watermark"
    );
    push_test_child(&mut driver, sibling_history);

    assert!(
        driver.maybe_auto_prune(&tx).await,
        "fresh sibling must evaluate and prune instead of matching stale depth watermark"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

#[tokio::test]
async fn stale_shadow_discarded() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    append_complete_test_turns(&mut driver, 1);
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 100);
    record_test_context_tokens(&driver, 55).await;
    assert!(driver.maybe_shadow_brief(&tx).await);
    wait_for_shadow_brief(&mut driver).await;
    append_complete_test_turns(&mut driver, 9);

    driver.do_compact(&tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}
    let purposes = compact_inference_purposes(&driver).await;
    assert!(purposes.iter().any(|p| p == "compact_shadow_brief"));
    assert!(purposes.iter().any(|p| p == "compact_brief"));
    assert!(!purposes.iter().any(|p| p == "compact_brief_delta"));
}

/// Config resolution: with no `config.json` on disk, the
/// delegation-shrink strategy defaults to `prune` (lowest quality
/// loss, priority #1) and a 30s margin.
#[test]
fn resolve_shrink_config_defaults_to_prune() {
    use crate::config::providers::ShrinkStrategy;
    let (driver, _tmp) = test_driver(8);
    let shrink = driver.resolve_shrink_config();
    assert_eq!(shrink.strategy, ShrinkStrategy::Prune);
    assert_eq!(shrink.margin_secs, 30);
}

#[test]
fn steer_queue_drains_fifo_at_child_turn_boundary() {
    let mut registry = NoninteractiveDelegationRegistry::default();
    registry.register_running(
        "task-1",
        "default",
        "explore".to_string(),
        NoninteractiveDelegationSnapshot::empty(),
    );

    registry.push_steer("task-1", "default", "first".to_string());
    registry.push_steer("task-1", "default", "second".to_string());
    registry.push_steer("task-1", "default", "third".to_string());
    let drained: Vec<_> = registry
        .drain_steer_queue("task-1", "default")
        .into_iter()
        .map(|steer| steer.body)
        .collect();
    assert_eq!(
        drained,
        vec![
            "first".to_string(),
            "second".to_string(),
            "third".to_string()
        ]
    );
    assert!(
        registry.drain_steer_queue("task-1", "default").is_empty(),
        "turn-boundary drain consumes queued steers"
    );
}
