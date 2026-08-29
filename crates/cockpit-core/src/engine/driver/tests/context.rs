use super::*;

/// `/prune` (and auto-prune) target the **foreground** agent only —
/// the top of the interactive-agent stack. A suspended parent frame's
/// history is never touched (GOALS §3b scope).
#[tokio::test]
async fn prune_targets_foreground_subagent_only() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    // Parent (root) frame carries elidable duplicate reads.
    driver.stack[0].history = dup_read_history_big();

    // Push an interactive subagent frame with its OWN duplicate reads.
    let child = driver.stack[0].agent.clone();
    driver.stack.push(AgentSession {
        queue_target: crate::engine::message::QueueTarget::child(
            child.name.clone(),
            driver.stack.len(),
            "test",
            "default",
        ),
        agent: child,
        agent_instance_id: None,
        endpoint_generation: None,
        history: dup_read_history(),
        answering: None,
        deferred_log: crate::engine::deferred::DeferredLog::new(),
        fallback_decision: None,
        recovery_activation: None,
        late_user_steer_permit: None,
        _vnext_child_admission: None,
        stop_gate: crate::engine::agent::hooks::StopGateState::default(),
    });

    // Prune the foreground (the subagent on top).
    driver.do_prune(false, &tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}

    // Foreground (top) was pruned: older body became a marker.
    let top = driver.stack.last().unwrap();
    let plan_top = prune::dedup_plan(&top.history);
    assert!(plan_top.is_empty(), "foreground should be fully pruned");

    // Parent (suspended) is untouched: still has an elidable dup.
    let parent = &driver.stack[0];
    let plan_parent = prune::dedup_plan(&parent.history);
    assert!(
        !plan_parent.is_empty(),
        "suspended parent frame must NOT be pruned"
    );
}

/// The watermark short-circuits auto-prune: after a prune, with no
/// history growth, `maybe_auto_prune` is a no-op even when cold.
#[tokio::test]
async fn auto_prune_watermark_short_circuits() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.stack[0].history = dup_read_history_big();

    // Cache is cold (no send yet) and there's something prunable →
    // first auto-prune fires.
    assert!(driver.maybe_auto_prune(&tx).await, "first auto-prune fires");
    // History length unchanged since → watermark short-circuits.
    assert!(
        !driver.maybe_auto_prune(&tx).await,
        "watermark short-circuits with no growth"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

/// The auto-prune master switch: `auto_prune: off` on the provider
/// suppresses the automatic prune entirely — even with a cold/no-cache
/// provider and a material prunable plan, which would otherwise always
/// fire. Flipping it back on lets the same state prune.
#[tokio::test]
async fn auto_prune_master_switch_off_suppresses_auto_prune() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        100_000,
    );
    driver
        .test_providers_override
        .as_mut()
        .unwrap()
        .0
        .providers
        .get_mut("lmstudio")
        .unwrap()
        .auto_prune = Some(false);
    driver.stack[0].history = dup_read_history_big();
    let plan = prune::dedup_plan(&driver.stack[0].history);
    assert!(!plan.is_empty(), "test requires a prunable plan");
    let history_len = driver.stack[0].history.len();

    assert!(
        !driver.maybe_auto_prune(&tx).await,
        "auto-prune off must suppress the automatic prune"
    );
    assert!(rx.try_recv().is_err(), "no Pruned event is emitted");
    // The master-switch-off branch advances the watermark like the sibling
    // no-op branches, so the next boundary short-circuits the config load.
    assert_eq!(
        driver.prune_watermark.get(&1).copied(),
        Some(history_len),
        "switch-off must advance the watermark to history_len"
    );

    driver
        .test_providers_override
        .as_mut()
        .unwrap()
        .0
        .providers
        .get_mut("lmstudio")
        .unwrap()
        .auto_prune = Some(true);
    // Flipping back on with no growth stays short-circuited by the
    // watermark — matching sibling-branch semantics.
    assert!(
        !driver.maybe_auto_prune(&tx).await,
        "auto-prune on with no history growth stays watermark-short-circuited"
    );
    // Growing history past the watermark re-evaluates and fires.
    driver.stack[0].history.extend(dup_read_history_big());
    assert!(
        driver.maybe_auto_prune(&tx).await,
        "auto-prune on fires once history grows past the watermark"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

#[tokio::test]
async fn auto_prune_skips_zero_savings_plan_without_pruned_event() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    install_test_providers(
        &mut driver,
        CacheMode::Ephemeral,
        ContextConfig::default(),
        100_000,
    );
    driver.stack[0].history = dup_read_history_zero_savings();
    let plan = prune::dedup_plan(&driver.stack[0].history);
    assert!(!plan.is_empty(), "test requires a non-empty plan");
    assert_eq!(plan.tokens_saved(), 0, "test requires zero savings");
    let history_len = driver.stack[0].history.len();

    assert!(!driver.maybe_auto_prune(&tx).await);
    assert_eq!(driver.prune_watermark.get(&1).copied(), Some(history_len));
    assert!(rx.try_recv().is_err(), "no visible Pruned event is emitted");

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap();
    assert!(
        events.iter().all(|ev| ev.kind != "context_pruned"),
        "zero-savings auto-prune must not write context_pruned"
    );
    let diagnostic = events
        .iter()
        .find(|ev| ev.kind == "auto_prune_diagnostic")
        .expect("skip diagnostic is exported");
    assert_eq!(diagnostic.data["skip_reason"], "zero_savings");
    assert_eq!(diagnostic.data["trigger_reason"], "cache_already_cold");
    assert_eq!(diagnostic.data["tokens_saved"], serde_json::json!(0));
    assert_eq!(
        diagnostic.data["watermark_advanced"],
        serde_json::json!(true)
    );
}

#[tokio::test]
async fn auto_prune_skips_trivial_cache_cold_plan_with_diagnostic() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    install_test_providers(
        &mut driver,
        CacheMode::Ephemeral,
        ContextConfig::default(),
        100_000,
    );
    driver.stack[0].history = dup_read_history_tiny_savings();
    let plan = prune::dedup_plan(&driver.stack[0].history);
    let projected = plan.tokens_saved();
    assert!(
        projected > 0 && projected < AUTO_PRUNE_MIN_COLD_SAVINGS_TOKENS,
        "test requires a tiny nonzero saving, got {projected}"
    );

    assert!(!driver.maybe_auto_prune(&tx).await);
    assert!(rx.try_recv().is_err(), "no visible Pruned event is emitted");

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap();
    assert!(
        events.iter().all(|ev| ev.kind != "context_pruned"),
        "trivial cold-cache auto-prune must not write context_pruned"
    );
    let diagnostic = events
        .iter()
        .find(|ev| ev.kind == "auto_prune_diagnostic")
        .expect("skip diagnostic is exported");
    assert_eq!(diagnostic.data["skip_reason"], "below_min_cold_savings");
    assert_eq!(diagnostic.data["trigger_reason"], "cache_already_cold");
    assert_eq!(
        diagnostic.data["min_cold_savings_tokens"],
        serde_json::json!(AUTO_PRUNE_MIN_COLD_SAVINGS_TOKENS)
    );
    assert_eq!(
        diagnostic.data["tokens_saved"],
        serde_json::json!(projected)
    );
}

#[tokio::test]
async fn auto_prune_material_cache_cold_plan_records_trigger_reason() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    install_test_providers(
        &mut driver,
        CacheMode::Ephemeral,
        ContextConfig::default(),
        100_000,
    );
    driver.stack[0].history = dup_read_history_big();
    let projected = prune::dedup_plan(&driver.stack[0].history).tokens_saved();
    assert!(projected >= AUTO_PRUNE_MIN_COLD_SAVINGS_TOKENS);

    assert!(driver.maybe_auto_prune(&tx).await);
    let mut saw_pruned = false;
    drop(tx);
    while let Some(ev) = rx.recv().await {
        if let TurnEvent::Pruned {
            cache_break,
            trigger_reason,
            tokens_saved,
            ..
        } = ev
        {
            saw_pruned = true;
            assert!(!cache_break);
            assert_eq!(trigger_reason.as_deref(), Some("cache_already_cold"));
            assert_eq!(tokens_saved, projected as u64);
        }
    }
    assert!(saw_pruned, "material cache-cold auto-prune emits Pruned");

    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap();
    let pruned = events
        .iter()
        .find(|ev| ev.kind == "context_pruned")
        .expect("applied auto-prune is exported");
    assert_eq!(pruned.data["trigger"], "auto");
    assert_eq!(pruned.data["trigger_reason"], "cache_already_cold");
    assert_eq!(
        pruned.data["tokens_saved"],
        serde_json::json!(projected as u64)
    );
}

#[tokio::test]
async fn prune_watermark_cleared_for_popped_child_depth() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.prune_watermark.insert(1, 99);
    push_test_child(&mut driver, dup_read_history_big());

    assert!(
        driver.maybe_auto_prune(&tx).await,
        "child auto-prune establishes depth-2 watermark"
    );
    assert!(driver.prune_watermark.contains_key(&2));

    let _ = driver.pop_child_with_envelope(None, None, &[], &tx).await;

    assert_eq!(
        driver.prune_watermark.get(&1).copied(),
        Some(99),
        "root watermark must not be cleared when the child pops"
    );
    assert!(
        !driver.prune_watermark.contains_key(&2),
        "popped child depth watermark must be cleared"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

/// Nothing prunable → auto-prune is a no-op and emits no Pruned event.
#[tokio::test]
async fn auto_prune_noop_when_nothing_prunable() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    // Empty foreground history: nothing to prune.
    assert!(!driver.maybe_auto_prune(&tx).await);
}

/// `context_metrics` (the ctx%/prunable% figure the auto-compact +
/// ctx%-threshold auto-prune triggers consume): computed from the last
/// request's prompt size against the model's context window, inert when
/// the window is unknown or no usage has been reported
/// (implementation note).
#[tokio::test]
async fn context_metrics_compute_and_inert_cases() {
    // 60k of a 100k window → 60% ctx; 30k prunable → 30% prunable.
    let m = context_metrics(Some(100_000), Some(60_000), 30_000).unwrap();
    assert!((m.ctx_pct - 60.0).abs() < 1e-9);
    assert!((m.prunable_pct - 30.0).abs() < 1e-9);

    // No context_length known → None (ctx%-gated triggers inert): the
    // exact edge case the spec requires the ctx% paths to skip.
    assert!(context_metrics(None, Some(60_000), 30_000).is_none());
    // A zero/garbage window is treated as unknown.
    assert!(context_metrics(Some(0), Some(60_000), 30_000).is_none());
    // No usage reported yet → None (no last send).
    assert!(context_metrics(Some(100_000), None, 30_000).is_none());

    // Threshold composition mirrors `maybe_auto_prune`: above the prune
    // ctx% (50) AND above prunable% (30) fires.
    let warm = context_metrics(Some(100_000), Some(55_000), 31_000).unwrap();
    assert!(warm.ctx_pct > 50.0 && warm.prunable_pct > 30.0);
    // Below either gate → no threshold fire.
    let low_prunable = context_metrics(Some(100_000), Some(55_000), 10_000).unwrap();
    assert!(!(low_prunable.ctx_pct > 50.0 && low_prunable.prunable_pct > 30.0));

    // The auto-compact line (60%): at/above fires, below doesn't.
    let hot = context_metrics(Some(100_000), Some(65_000), 0).unwrap();
    assert!(hot.ctx_pct >= 60.0);
    let mid = context_metrics(Some(100_000), Some(55_000), 0).unwrap();
    assert!(mid.ctx_pct < 60.0);
}

#[tokio::test]
async fn active_context_length_uses_probed_capability() {
    use crate::config::providers::{
        ActiveModelRef, CapabilitySource, ModelCapabilities, ModelEntry, ProviderEntry,
        ProvidersConfig, WireApi,
    };

    let (mut driver, _tmp) = test_driver(8);
    let mut entry = ProviderEntry {
        url: "http://127.0.0.1:1/v1".to_string(),
        wire_api: WireApi::Completions,
        ..ProviderEntry::default()
    };
    entry.models.push(ModelEntry {
        id: "local".into(),
        context_length: None,
        capabilities: ModelCapabilities {
            context_tokens: Some(128_000),
            context_tokens_source: Some(CapabilitySource::Probed),
            ..ModelCapabilities::default()
        },
        wire_api: WireApi::Completions,
        ..ModelEntry::default()
    });
    let mut providers = std::collections::BTreeMap::new();
    providers.insert("lmstudio".to_string(), entry);
    driver.test_providers_override = Some((
        ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "lmstudio".into(),
                model: "local".into(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            }),
            ..ProvidersConfig::default()
        },
        "lmstudio".into(),
        "local".into(),
    ));

    assert_eq!(driver.active_model_context_length(), Some(128_000));
}

#[tokio::test]
async fn shadow_brief_predrafts() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    append_complete_test_turns(&mut driver, 2);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        10_000,
    );
    record_test_context_tokens(&driver, 5_500).await;

    assert!(driver.maybe_shadow_brief(&tx).await);
    assert!(matches!(
        driver.shadow_brief,
        Some(ShadowBriefState::InFlight(_))
    ));
    wait_for_shadow_brief(&mut driver).await;
    assert_eq!(
        compact_inference_purposes(&driver).await,
        ["compact_shadow_brief"]
    );
    assert!(
        driver
            .session
            .db
            .compaction_shadow(driver.session.id)
            .await
            .unwrap()
            .is_some(),
        "ready shadow brief is persisted eagerly"
    );
}

#[tokio::test]
async fn compact_uses_shadow_delta() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    append_complete_test_turns(&mut driver, 2);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        10_000,
    );
    record_test_context_tokens(&driver, 5_500).await;
    assert!(driver.maybe_shadow_brief(&tx).await);
    wait_for_shadow_brief(&mut driver).await;
    append_complete_test_turns(&mut driver, 1);

    driver.do_compact(&tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}
    let purposes = compact_inference_purposes(&driver).await;
    assert_eq!(
        purposes
            .iter()
            .filter(|p| p.as_str() == "compact_shadow_brief")
            .count(),
        1,
        "the shadow/full draft runs exactly once"
    );
    assert_eq!(
        purposes
            .iter()
            .filter(|p| p.as_str() == "compact_brief_delta")
            .count(),
        1,
        "compaction performs one section-wise delta revision"
    );
    assert!(!purposes.iter().any(|p| p == "compact_brief"));
    let calls = crate::sync::lock_or_recover(
        driver
            .test_compact_brief_calls
            .as_ref()
            .expect("fake compact seam"),
    );
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].purpose, "compact_shadow_brief");
    assert_eq!(calls[1].purpose, "compact_brief_delta");
    assert!(calls[1].prompt.contains("<existing_shadow_brief>"));
    assert_eq!(
        crate::engine::compact::complete_exchange_count(&calls[1].history),
        3,
        "delta sees the shadow's omitted tail plus the new exchange"
    );
}

#[tokio::test]
async fn ready_brief_survives_driver_drop() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    append_complete_test_turns(&mut driver, 2);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        10_000,
    );
    record_test_context_tokens(&driver, 5_500).await;
    assert!(driver.maybe_shadow_brief(&tx).await);
    wait_for_shadow_brief(&mut driver).await;

    let session = driver.session.clone();
    let locks = driver.locks.clone();
    let redact = driver.redact.clone();
    let cwd = driver.cwd.clone();
    let root = driver.stack[0].agent.clone();
    assert!(
        session
            .db
            .compaction_shadow(session.id)
            .await
            .unwrap()
            .is_some()
    );
    drop(driver);

    let mut restored = Driver::new(session.clone(), locks, redact, cwd, root);
    restored.load_compaction_shadow_from_store().await;
    append_complete_test_turns(&mut restored, 3);
    install_test_providers(
        &mut restored,
        CacheMode::None,
        ContextConfig::default(),
        10_000,
    );
    restored.do_compact(&tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}

    let purposes = compact_inference_purposes(&restored).await;
    assert_eq!(
        purposes
            .iter()
            .filter(|purpose| purpose.as_str() == "compact_shadow_brief")
            .count(),
        1
    );
    assert_eq!(
        purposes
            .iter()
            .filter(|purpose| purpose.as_str() == "compact_brief_delta")
            .count(),
        1,
        "restored ready brief is used for delta compaction"
    );
    assert!(!purposes.iter().any(|purpose| purpose == "compact_brief"));
}

#[tokio::test]
async fn consumed_brief_is_deleted() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    append_complete_test_turns(&mut driver, 2);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        10_000,
    );
    record_test_context_tokens(&driver, 5_500).await;
    assert!(driver.maybe_shadow_brief(&tx).await);
    wait_for_shadow_brief(&mut driver).await;
    assert!(
        driver
            .session
            .db
            .compaction_shadow(driver.session.id)
            .await
            .unwrap()
            .is_some()
    );

    let ready = driver
        .take_fresh_shadow_brief(ContextConfig::default().compact_keep_recent_turns)
        .await;

    assert!(ready.is_some());
    assert!(
        driver
            .session
            .db
            .compaction_shadow(driver.session.id)
            .await
            .unwrap()
            .is_none(),
        "consuming a ready shadow deletes its durable row"
    );
}

#[tokio::test]
async fn load_without_row_clears_memory_view() {
    let (mut driver, _tmp) = test_driver_without_network(8);
    driver.shadow_brief_generation = 2;
    driver.shadow_brief = Some(ShadowBriefState::Ready(ShadowBriefReady {
        generation: 2,
        snapshot_history: vec![Message::user("memory only")],
        snapshot_turns: 0,
        snapshot_tail_turns: 0,
        brief: "memory only".to_string(),
        fit_rung: crate::engine::compact_draft::CompactFitRung::Verbatim,
        input_coverage: crate::engine::compact_draft::CompactInputCoverage::Full,
    }));

    driver.load_compaction_shadow_from_store().await;

    assert!(
        driver.shadow_brief.is_none(),
        "missing durable row clears the in-memory view"
    );
}

#[tokio::test]
async fn loaded_brief_generation_is_persisted_and_compared() {
    let (driver, _tmp) = test_driver_without_network(8);
    let payload = DurableCompactionShadow::ReadyBrief(DurableShadowBrief {
        generation: 7,
        snapshot_history: vec![Message::user("snapshot"), Message::assistant("briefed")],
        snapshot_turns: 1,
        snapshot_tail_turns: 1,
        brief: "stored brief".to_string(),
        fit_rung: crate::engine::compact_draft::CompactFitRung::Verbatim,
        input_coverage: crate::engine::compact_draft::CompactInputCoverage::Full,
    });
    driver
        .session
        .db
        .upsert_compaction_shadow(driver.session.id, &serde_json::to_string(&payload).unwrap())
        .await
        .unwrap();

    let mut restored = Driver::new(
        driver.session.clone(),
        driver.locks.clone(),
        driver.redact.clone(),
        driver.cwd.clone(),
        driver.stack[0].agent.clone(),
    );
    restored.load_compaction_shadow_from_store().await;

    assert_eq!(restored.shadow_brief_generation, 7);
    assert!(matches!(
        &restored.shadow_brief,
        Some(ShadowBriefState::Ready(ready)) if ready.brief == "stored brief"
    ));

    let older = DurableCompactionShadow::ReadyBrief(DurableShadowBrief {
        generation: 6,
        snapshot_history: vec![Message::user("older")],
        snapshot_turns: 0,
        snapshot_tail_turns: 0,
        brief: "older brief".to_string(),
        fit_rung: crate::engine::compact_draft::CompactFitRung::Verbatim,
        input_coverage: crate::engine::compact_draft::CompactInputCoverage::Full,
    });
    restored
        .session
        .db
        .upsert_compaction_shadow(restored.session.id, &serde_json::to_string(&older).unwrap())
        .await
        .unwrap();
    restored.shadow_brief_generation = 8;
    restored.load_compaction_shadow_from_store().await;

    assert!(restored.shadow_brief.is_none());
    assert!(
        restored
            .session
            .db
            .compaction_shadow(restored.session.id)
            .await
            .unwrap()
            .is_none(),
        "stored generation behind the live driver is discarded"
    );
}

#[tokio::test]
async fn durable_shadow_missing_fit_metadata_is_discarded() {
    let (mut driver, _tmp) = test_driver_without_network(8);
    let legacy_payload = serde_json::json!({
        "kind": "ready_brief",
        "generation": 1,
        "snapshot_history": [],
        "snapshot_turns": 0,
        "snapshot_tail_turns": 0,
        "brief": "legacy metadata-free brief"
    });
    driver
        .session
        .db
        .upsert_compaction_shadow(driver.session.id, &legacy_payload.to_string())
        .await
        .unwrap();

    driver.load_compaction_shadow_from_store().await;

    assert!(driver.shadow_brief.is_none());
    assert!(
        driver
            .session
            .db
            .compaction_shadow(driver.session.id)
            .await
            .unwrap()
            .is_none(),
        "metadata-free shadows must be deleted rather than assumed full"
    );
}

#[tokio::test]
async fn stale_loaded_brief_is_discarded() {
    let (mut driver, _tmp) = test_driver_without_network(8);
    let payload = DurableCompactionShadow::ReadyBrief(DurableShadowBrief {
        generation: 3,
        snapshot_history: vec![Message::user("old")],
        snapshot_turns: 0,
        snapshot_tail_turns: 0,
        brief: "too old".to_string(),
        fit_rung: crate::engine::compact_draft::CompactFitRung::Verbatim,
        input_coverage: crate::engine::compact_draft::CompactInputCoverage::Full,
    });
    driver
        .session
        .db
        .upsert_compaction_shadow(driver.session.id, &serde_json::to_string(&payload).unwrap())
        .await
        .unwrap();
    append_complete_test_turns(&mut driver, 9);

    driver.load_compaction_shadow_from_store().await;

    assert!(driver.shadow_brief.is_none());
    assert!(
        driver
            .session
            .db
            .compaction_shadow(driver.session.id)
            .await
            .unwrap()
            .is_none(),
        "stale loaded shadow row is deleted"
    );
}

#[tokio::test]
async fn killswitch_writes_no_rows() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    let payload = DurableCompactionShadow::ReadyBrief(DurableShadowBrief {
        generation: 1,
        snapshot_history: vec![Message::user("delete me")],
        snapshot_turns: 0,
        snapshot_tail_turns: 0,
        brief: "delete me".to_string(),
        fit_rung: crate::engine::compact_draft::CompactFitRung::Verbatim,
        input_coverage: crate::engine::compact_draft::CompactInputCoverage::Full,
    });
    driver
        .session
        .db
        .upsert_compaction_shadow(driver.session.id, &serde_json::to_string(&payload).unwrap())
        .await
        .unwrap();
    append_complete_test_turns(&mut driver, 2);
    let cfg = ContextConfig {
        compact_shadow: false,
        ..ContextConfig::default()
    };
    install_test_providers(&mut driver, CacheMode::None, cfg, 10_000);
    record_test_context_tokens(&driver, 5_500).await;

    assert!(!driver.maybe_shadow_brief(&tx).await);

    assert!(driver.shadow_brief.is_none());
    assert!(
        driver
            .session
            .db
            .compaction_shadow(driver.session.id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn ephemeral_session_writes_no_rows() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (parent, _tmp) = test_driver_without_network(8);
    let row = parent
        .session
        .db
        .create_ephemeral_fork(parent.session.id, None)
        .await
        .unwrap();
    let session = Arc::new(
        Session::resume_for_test(
            parent.session.db.clone(),
            row.session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .unwrap(),
    );
    let mut driver = Driver::new(
        session.clone(),
        parent.locks.clone(),
        parent.redact.clone(),
        parent.cwd.clone(),
        parent.stack[0].agent.clone(),
    );
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    append_complete_test_turns(&mut driver, 2);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        10_000,
    );
    record_test_context_tokens(&driver, 5_500).await;

    assert!(driver.maybe_shadow_brief(&tx).await);
    wait_for_shadow_brief(&mut driver).await;

    assert!(
        driver
            .session
            .db
            .compaction_shadow(driver.session.id)
            .await
            .unwrap()
            .is_none(),
        "ephemeral session shadows are not persisted"
    );
}

#[tokio::test]
async fn durable_shadow_payload_round_trips_with_prepared_compaction() {
    let (mut driver, _tmp) = prepare_apply_fixture().await;
    let (tx, _rx) = mpsc::channel::<TurnEvent>(16);
    let prepared = driver
        .prepare_compaction_with_source(&tx, "manual")
        .await
        .expect("prepare succeeds");
    let payload = DurableCompactionShadow::PreparedCompaction(Box::new(prepared));
    let encoded = serde_json::to_string(&payload).unwrap();
    let decoded: DurableCompactionShadow = serde_json::from_str(&encoded).unwrap();

    assert_eq!(decoded, payload);
}

#[tokio::test]
async fn staleness_rule_has_one_implementation() {
    assert_eq!(shadow_stale_after_turns(0), 8);
    assert_eq!(shadow_stale_after_turns(3), 8);
    assert_eq!(shadow_stale_after_turns(8), 12);
}

#[tokio::test]
async fn compact_draft_retries_only_transient_or_degenerate() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let _cancel_fixture = TestCompactSample::Cancelled;
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        10_000,
    );
    append_complete_test_turns(&mut driver, 1);
    let script = driver.test_compact_brief_script.as_ref().unwrap();
    crate::sync::lock_or_recover(script).extend([
        TestCompactSample::Error {
            message: "temporary network failure".to_string(),
            status: None,
            typed_timeout: false,
        },
        TestCompactSample::Success("usable compact synthesis ".repeat(40)),
    ]);
    let history = driver.stack.last().unwrap().history.clone();
    let draft = driver
        .compact_brief_draft(
            &tx,
            history,
            Arc::new(std::sync::Mutex::new(CompactPreparationQuota::default())),
        )
        .await;
    let outcome = execute_compact_brief(
        draft,
        "summarize".to_string(),
        "compact_script_test",
        &tokio_util::sync::CancellationToken::new(),
    )
    .await;
    let crate::engine::compact_draft::CompactDraftOutcome::Success(success) = outcome else {
        panic!("scripted retry should recover")
    };
    assert_eq!(success.attempts, 2);
    {
        let calls = crate::sync::lock_or_recover(driver.test_compact_brief_calls.as_ref().unwrap());
        let scripted = calls
            .iter()
            .filter(|call| call.purpose == "compact_script_test")
            .collect::<Vec<_>>();
        assert_eq!(scripted.len(), 2);
        assert_eq!(scripted[0].attempt, 1);
        assert_eq!(scripted[1].attempt, 2);
        assert_eq!(scripted[0].fit_rung, scripted[1].fit_rung);
    }
    assert_eq!(
        compact_inference_purposes(&driver)
            .await
            .into_iter()
            .filter(|purpose| purpose == "compact_script_test")
            .count(),
        2,
        "each scripted wire sample has its own observable classification event"
    );
}

#[tokio::test]
async fn compact_override_uses_selected_models_context_window() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(16);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        100_000,
    );
    let (providers, _, _) = driver.test_providers_override.as_mut().unwrap();
    let provider = providers.providers.get_mut("lmstudio").unwrap();
    let mut compact = provider.models[0].clone();
    compact.id = "compact".to_string();
    compact.context_length = Some(4_096);
    provider.models.push(compact);
    driver.test_compact_model_ref = Some("lmstudio:compact".to_string());
    let draft = driver
        .compact_brief_draft(
            &tx,
            vec![Message::user("history")],
            Arc::new(std::sync::Mutex::new(CompactPreparationQuota::default())),
        )
        .await;
    assert_eq!(draft.model.model_id_ref(), "compact");
    assert_eq!(draft.context_window, Some(4_096));
}

#[tokio::test]
async fn compact_preparation_quota_is_shared_across_draft_calls() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(16);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        10_000,
    );
    let quota = Arc::new(std::sync::Mutex::new(CompactPreparationQuota {
        draft_nodes: crate::engine::compact_draft::MAX_DRAFT_NODES - 1,
        wire_samples: crate::engine::compact_draft::MAX_COMPACTION_WIRE_SAMPLES - 1,
    }));
    let first = driver
        .compact_brief_draft(&tx, vec![Message::user("first")], quota.clone())
        .await;
    assert!(matches!(
        execute_compact_brief(
            first,
            "summarize".to_string(),
            "quota_first",
            &tokio_util::sync::CancellationToken::new(),
        )
        .await,
        crate::engine::compact_draft::CompactDraftOutcome::Success(_)
    ));
    let second = driver
        .compact_brief_draft(&tx, vec![Message::user("second")], quota.clone())
        .await;
    let outcome = execute_compact_brief(
        second,
        "summarize".to_string(),
        "quota_second",
        &tokio_util::sync::CancellationToken::new(),
    )
    .await;
    assert!(matches!(
        outcome,
        crate::engine::compact_draft::CompactDraftOutcome::ContextOverflow { .. }
    ));
    let quota = crate::sync::lock_or_recover(&quota);
    assert_eq!(
        quota.draft_nodes,
        crate::engine::compact_draft::MAX_DRAFT_NODES
    );
    assert_eq!(
        quota.wire_samples,
        crate::engine::compact_draft::MAX_COMPACTION_WIRE_SAMPLES
    );
}

#[tokio::test]
async fn full_shadow_delta_overflow_fallback_covers_complete_current_history() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        10_000,
    );
    let full_history = (0..8)
        .flat_map(|turn| {
            [
                Message::user(format!("full-source-user-{turn}-{}", "u".repeat(5_000))),
                Message::assistant(format!(
                    "full-source-assistant-{turn}-{}",
                    "a".repeat(5_000)
                )),
            ]
        })
        .collect::<Vec<_>>();
    let revision_history = full_history[full_history.len() - 2..].to_vec();
    let script = driver.test_compact_brief_script.as_ref().unwrap();
    crate::sync::lock_or_recover(script).extend(
        std::iter::once(TestCompactSample::Error {
            message: "maximum context length".to_string(),
            status: Some(400),
            typed_timeout: false,
        })
        .chain(
            std::iter::repeat_with(|| {
                TestCompactSample::Success("complete trustworthy synthesis ".repeat(40))
            })
            .take(40),
        ),
    );

    let result = driver
        .draft_brief_delta(
            &tx,
            &[],
            &"existing full shadow brief ".repeat(40),
            revision_history.clone(),
            full_history.clone(),
            Arc::new(std::sync::Mutex::new(CompactPreparationQuota::default())),
        )
        .await;
    assert!(result.is_ok(), "full-coverage fallback should synthesize");

    let calls = crate::sync::lock_or_recover(driver.test_compact_brief_calls.as_ref().unwrap());
    let delta = calls
        .iter()
        .find(|call| call.purpose == "compact_brief_delta")
        .expect("delta attempt is captured");
    assert_eq!(
        delta.history, revision_history,
        "delta keeps the reduced revision"
    );
    let chunk_source = calls
        .iter()
        .filter(|call| call.purpose == "compact_chunk_brief")
        .flat_map(|call| call.history.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        chunk_source, full_history,
        "overflow fallback chunks must cover the snapshot prefix as well as the revision tail"
    );
}

#[test]
fn compact_synthesis_quota_accounts_for_the_direct_node_before_execution() {
    let mut quota = CompactPreparationQuota::default();
    quota.claim_node().expect("direct node fits");
    assert!(
        quota
            .ensure_nodes_available(crate::engine::compact_draft::MAX_DRAFT_NODES - 1)
            .is_ok()
    );
    assert!(
        quota
            .ensure_nodes_available(crate::engine::compact_draft::MAX_DRAFT_NODES)
            .is_err()
    );
    assert_eq!(quota.draft_nodes, 1, "preflight does not consume nodes");
}

#[tokio::test]
async fn compact_unknown_window_overflow_never_advances_to_smaller_rung() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(16);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        10_000,
    );
    let history = vec![
        Message::user("older request"),
        Message::assistant("older response"),
        Message::user("newest request"),
        Message::assistant("newest response"),
    ];
    crate::sync::lock_or_recover(driver.test_compact_brief_script.as_ref().unwrap()).extend([
        TestCompactSample::Error {
            message: "maximum context length exceeded".to_string(),
            status: Some(400),
            typed_timeout: false,
        },
        TestCompactSample::Success("must never be sampled ".repeat(40)),
    ]);
    let mut draft = driver
        .compact_brief_draft(
            &tx,
            history.clone(),
            Arc::new(std::sync::Mutex::new(CompactPreparationQuota::default())),
        )
        .await;
    draft.context_window = None;
    let outcome = execute_compact_brief(
        draft,
        "summarize".to_string(),
        "unknown_window_overflow",
        &tokio_util::sync::CancellationToken::new(),
    )
    .await;
    assert!(matches!(
        outcome,
        crate::engine::compact_draft::CompactDraftOutcome::ContextOverflow { .. }
    ));
    let calls = crate::sync::lock_or_recover(driver.test_compact_brief_calls.as_ref().unwrap());
    let calls = calls
        .iter()
        .filter(|call| call.purpose == "unknown_window_overflow")
        .collect::<Vec<_>>();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].attempt, 1);
    assert_eq!(
        calls[0].fit_rung,
        crate::engine::compact_draft::CompactFitRung::Verbatim
    );
    assert_eq!(calls[0].history, history);
}

#[test]
fn compact_auto_gate_has_exact_boundary_activity_origin_and_ingress_transitions() {
    use crate::engine::compact_draft::CompactDraftOutcome as DraftO;
    use crate::engine::message::{SubmissionOrigin, UserSubmission};

    // ── Restart begins Eligible ───────────────────────────────────────
    // The gate is driver-only and not serialized, so a restart starts fresh.
    let fresh = AutoCompactGate::default();
    let coverage = prepared_compaction_coverage(&[Message::user("one")]);
    assert!(!fresh.suppresses(&coverage), "restart must begin Eligible");

    // ── Ingress inventory completeness bound (AC11) ────────────────────
    //
    // Origin classification is assigned at construction. The gate moves only
    // when a consumption site calls `observe_accepted_user_submission` (or
    // the FCM2 delayed `external_activity`). Message-only rebuilds
    // (`build_user_message`) keep origin as inventory metadata and cannot
    // move the gate.
    //
    // Production observe/advance sites (the remaining class is empty when
    // a new consumer either goes through one of these or is added here):
    //   - `run_user_input_with_leading_history_inner` (turn start)
    //   - `record_queued_user_fold` after a successful fold (backgroundable
    //     interrupt via `take_backgroundable_user_interrupt`, Continue/Done
    //     intercepts, leading-history batch folds)
    //   - FCM2 phase-two materialization (`external_activity` after an
    //     oversized lease is accepted)
    //
    // Production constructors (exhaustive non-test search). "observe via"
    // is the consumption site, not the constructor:
    //
    // Site                                              Origin            observe via
    // ------------------------------------------------  ----------------  -----------------------------
    // UserSubmission::text default                      Internal          run_user_input / fold origin
    // UserSubmission::compact_notice()                  CompactNotice     run_user_input (Compact RPC)
    // dispatch.rs handle_send_user_message              ExternalRoot      run_user_input
    //   (reject-non-root; bulk sibling delegates here)
    // session_worker FCM2 oversized replay              ExternalRoot      run_user_input + FCM2 delay
    // daemon/scheduler RegistryPromptRunner             ScheduledJob      run_user_input
    // schedule_dispatch::scheduled_job_submission       ScheduledJob      run_user_input
    // retry_recovery / auto_continue / goal helpers     named internal    run_user_input
    // driver tool-result recoveries                     ToolResult        run_user_input
    // DeliverLateUserDecisionSteer (UserSubmission::text) Internal        run_user_input
    // stop_continuation_prompt                          Internal          next_prompt (no observe)
    // prepare_queued_user_submission                    copied            caller (run_user_input/fold)
    // folded leading history rebuild                    copied            record_queued_user_fold
    // RetryRequired requeue                             Internal          already observed at turn start
    // history rebuild after observe                     Internal          already observed at turn start
    // take_backgroundable_user_interrupt                copied            record_queued_user_fold
    // noninteractive AsyncUser (UserSubmission::text)   Internal          run_user_input
    // TUI /init /learn /skill, composer, btw,           ExternalRoot      run_user_input
    //   /multireview
    // TUI resume.rs + agent_runner Request::Compact     CompactNotice     Compact RPC, not SendUserMessage
    // CLI cockpit run Default::default()                proto ExternalRoot dispatch → run_user_input
    //
    // UserSubmission::text(...) defaults to Internal (the blanket origin for
    // driver-generated submissions that are not externally authored).
    assert_eq!(
        UserSubmission::text("driver-generated").origin,
        SubmissionOrigin::Internal,
        "UserSubmission::text defaults to Internal"
    );
    assert_eq!(
        UserSubmission::compact_notice().origin,
        SubmissionOrigin::CompactNotice,
        "compact_notice() uses CompactNotice"
    );

    // Only ExternalRoot advances activity_epoch and surfaces as a
    // user_prompt_submit source.  Every other origin preserves UntilActivity
    // and does not fire the UserPromptSubmit hook.
    assert!(SubmissionOrigin::ExternalRoot.advances_activity_epoch());
    assert_eq!(
        SubmissionOrigin::ExternalRoot.user_prompt_submit_source(),
        Some("user")
    );
    for origin in [
        SubmissionOrigin::GoalContinuation,
        SubmissionOrigin::ScheduledJob,
        SubmissionOrigin::AutoContinue,
        SubmissionOrigin::RetryRecovery,
        SubmissionOrigin::ToolResult,
        SubmissionOrigin::CompactNotice,
        SubmissionOrigin::Internal,
    ] {
        assert!(!origin.advances_activity_epoch(), "{origin:?}");
        assert_eq!(origin.user_prompt_submit_source(), None, "{origin:?}");
    }

    // ── Deterministic failure → UntilActivity (blocks until external
    //    user activity) ──────────────────────────────────────────────────
    let mut gate = AutoCompactGate::default();
    let deterministic = PrepareCompactionError::Draft(DraftO::Deterministic {
        diagnostic: "rejected".to_string(),
    });
    gate.record_failure(&deterministic, coverage.clone());
    assert!(gate.suppresses(&coverage));

    // Internal origins do not advance the epoch, so UntilActivity persists
    // even when observe_submission is actually invoked.
    for origin in [
        SubmissionOrigin::GoalContinuation,
        SubmissionOrigin::ScheduledJob,
        SubmissionOrigin::AutoContinue,
        SubmissionOrigin::RetryRecovery,
        SubmissionOrigin::ToolResult,
        SubmissionOrigin::CompactNotice,
        SubmissionOrigin::Internal,
    ] {
        gate.observe_submission(origin, false);
        assert!(
            matches!(
                gate,
                AutoCompactGate::UntilActivity {
                    activity_epoch: 0,
                    ..
                }
            ),
            "{origin:?} must not clear UntilActivity"
        );
        assert!(
            gate.suppresses(&coverage),
            "{origin:?} must not clear UntilActivity"
        );
    }

    // ExternalRoot advances the epoch through observe_submission, clearing
    // UntilActivity. Calling external_activity() directly would not prove
    // the origin coupling.
    gate.observe_submission(SubmissionOrigin::ExternalRoot, false);
    assert!(
        !gate.suppresses(&coverage),
        "external user activity must clear UntilActivity"
    );

    // ── Transient failure → BoundarySuppressed (same key only) ─────────
    gate.record_failure(
        &PrepareCompactionError::Draft(DraftO::TransientExhausted {
            diagnostic: "network".to_string(),
        }),
        coverage.clone(),
    );
    assert!(
        gate.suppresses(&coverage),
        "transient failure suppresses the same BoundaryKey"
    );
    let changed = prepared_compaction_coverage(&[Message::user("one"), Message::assistant("two")]);
    assert!(
        !gate.suppresses(&changed),
        "transient failure does not suppress a different coverage"
    );

    // ── Cancellation → Eligible (never suppresses) ─────────────────────
    let mut cancel_gate = AutoCompactGate::default();
    cancel_gate.record_failure(
        &PrepareCompactionError::Draft(DraftO::Cancelled),
        coverage.clone(),
    );
    assert!(
        !cancel_gate.suppresses(&coverage),
        "cancellation leaves the gate Eligible — never suppresses"
    );

    // ── Committed-on-apply suppresses until external activity ──────────
    let mut committed_gate = AutoCompactGate::Committed { activity_epoch: 0 };
    assert!(
        committed_gate.suppresses(&coverage),
        "Committed-on-apply suppresses further auto-compaction"
    );
    committed_gate.external_activity();
    assert!(
        !committed_gate.suppresses(&coverage),
        "external activity clears Committed"
    );

    // ── ContextOverflow failure → UntilActivity (deterministic-class) ──
    let mut overflow_gate = AutoCompactGate::default();
    overflow_gate.record_failure(
        &PrepareCompactionError::Draft(DraftO::ContextOverflow {
            diagnostic: "too long".to_string(),
        }),
        coverage.clone(),
    );
    assert!(
        overflow_gate.suppresses(&coverage),
        "context-overflow failure blocks until external activity"
    );

    // ── Degenerate failure → BoundarySuppressed (same key only) ────────
    let mut degen_gate = AutoCompactGate::default();
    degen_gate.record_failure(
        &PrepareCompactionError::Draft(DraftO::Degenerate {
            non_whitespace_chars: 42,
        }),
        coverage.clone(),
    );
    assert!(
        degen_gate.suppresses(&coverage),
        "degenerate failure suppresses the same BoundaryKey"
    );
    assert!(
        !degen_gate.suppresses(&changed),
        "degenerate failure does not suppress a different coverage"
    );
}

#[test]
fn production_host_ingress_constructors_preserve_until_activity() {
    use crate::engine::message::SubmissionOrigin;

    // Named host helpers (the ratchet for driver-owned origin constructors).
    // Direct field assignments at other production sites are inventoried in
    // `compact_auto_gate_has_exact_boundary_activity_origin_and_ingress_transitions`
    // and cannot move the gate except through the observe-site bound there.
    let routed = [
        retry_recovery_submission("retry".to_string()),
        auto_continue_submission("auto".to_string(), Vec::new()),
        goal_continuation_submission("goal".to_string(), Vec::new(), None),
        crate::engine::driver::schedule_dispatch::scheduled_job_submission(
            "scheduled root delivery".to_string(),
            None,
        ),
        crate::engine::driver::schedule_dispatch::scheduled_job_submission(
            "scheduled subagent result delivery".to_string(),
            Some("job-child".to_string()),
        ),
    ];
    assert_eq!(routed[0].origin, SubmissionOrigin::RetryRecovery);
    assert_eq!(routed[1].origin, SubmissionOrigin::AutoContinue);
    assert_eq!(routed[2].origin, SubmissionOrigin::GoalContinuation);
    assert_eq!(routed[3].origin, SubmissionOrigin::ScheduledJob);
    assert_eq!(routed[4].origin, SubmissionOrigin::ScheduledJob);

    for submission in routed {
        let mut gate = AutoCompactGate::UntilActivity {
            activity_epoch: 7,
            reason: "deterministic compaction failure".to_string(),
        };
        gate.observe_submission(submission.origin, false);
        assert!(
            matches!(
                gate,
                AutoCompactGate::UntilActivity {
                    activity_epoch: 7,
                    ..
                }
            ),
            "production {origin:?} ingress must preserve UntilActivity",
            origin = submission.origin
        );
    }

    let mut gate = AutoCompactGate::UntilActivity {
        activity_epoch: 7,
        reason: "deterministic compaction failure".to_string(),
    };
    gate.observe_submission(SubmissionOrigin::ExternalRoot, false);
    assert!(matches!(
        gate,
        AutoCompactGate::Eligible { activity_epoch: 8 }
    ));
}

#[tokio::test]
async fn queued_user_fold_observes_auto_compact_gate_from_origin() {
    use crate::engine::message::SubmissionOrigin;

    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let target = driver.active_queue_target();

    let mut external = UserSubmission::text("user interrupt");
    external.origin = SubmissionOrigin::ExternalRoot;
    let internal = UserSubmission::text("host continuation");
    let (external_id, _) = queue.push(external, target.clone()).await;
    let (_internal_id, _) = queue.push(internal, target.clone()).await;

    let mut drained = Vec::new();
    queue
        .drain_into_for(&mut drained, 2, Some(&target.id))
        .await;
    assert_eq!(drained.len(), 2);
    assert_eq!(drained[0].queue_item_ids, vec![external_id]);
    assert_eq!(drained[0].origin, SubmissionOrigin::ExternalRoot);
    assert_eq!(drained[1].origin, SubmissionOrigin::Internal);

    driver.auto_compact_gate = AutoCompactGate::UntilActivity {
        activity_epoch: 7,
        reason: "deterministic compaction failure".to_string(),
    };
    driver
        .record_queued_user_fold(&drained[1], &tx)
        .await
        .expect("internal fold should persist");
    assert!(
        matches!(
            driver.auto_compact_gate,
            AutoCompactGate::UntilActivity {
                activity_epoch: 7,
                ..
            }
        ),
        "Internal fold must preserve UntilActivity"
    );

    driver
        .record_queued_user_fold(&drained[0], &tx)
        .await
        .expect("external fold should persist");
    assert!(
        matches!(
            driver.auto_compact_gate,
            AutoCompactGate::Eligible { activity_epoch: 8 }
        ),
        "ExternalRoot fold must advance activity_epoch"
    );

    drop(tx);
    while rx.recv().await.is_some() {}
}

#[tokio::test]
async fn backgroundable_user_interrupt_observes_auto_compact_gate() {
    use crate::engine::message::SubmissionOrigin;

    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let mut submission = UserSubmission::text("interrupt the background task");
    submission.origin = SubmissionOrigin::ExternalRoot;
    let _ = queue.push(submission, driver.active_queue_target()).await;
    let first = queue
        .recv()
        .await
        .expect("queued interrupt must be receivable");

    driver.auto_compact_gate = AutoCompactGate::UntilActivity {
        activity_epoch: 7,
        reason: "deterministic compaction failure".to_string(),
    };
    let prompt = driver
        .take_backgroundable_user_interrupt(first, &queue, &tx)
        .await;
    assert!(
        matches!(
            driver.auto_compact_gate,
            AutoCompactGate::Eligible { activity_epoch: 8 }
        ),
        "queued user interrupt of a backgroundable task must clear UntilActivity"
    );
    match prompt {
        Message::User { .. } => {}
        other => panic!("expected user interrupt prompt, got {other:?}"),
    }

    drop(tx);
    while rx.recv().await.is_some() {}
}

#[tokio::test]
async fn manual_compact_cancels_shadow() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    // This test owns shadow pre-emption, not the known-oversized-request
    // branch. Give the compact request enough framing space so the asserted
    // fallback sample is real; a 100-token window correctly skips sampling.
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        10_000,
    );
    let cancel = tokio_util::sync::CancellationToken::new();
    let observed_cancel = cancel.clone();
    driver.shadow_brief_generation = 1;
    driver.shadow_brief = Some(ShadowBriefState::InFlight(ShadowBriefInFlight {
        generation: 1,
        snapshot_history: Vec::new(),
        snapshot_turns: 0,
        snapshot_tail_turns: 0,
        cancel,
        handle: tokio::spawn(std::future::pending::<
            crate::engine::compact_draft::CompactDraftOutcome,
        >()),
    }));

    driver.do_compact(&tx).await;
    assert!(observed_cancel.is_cancelled());
    drop(tx);
    while rx.recv().await.is_some() {}
    assert_eq!(compact_inference_purposes(&driver).await, ["compact_brief"]);

    let (mut ending_driver, _tmp2) = test_driver_without_network(8);
    let ending_cancel = tokio_util::sync::CancellationToken::new();
    let ending_observer = ending_cancel.clone();
    ending_driver.shadow_brief = Some(ShadowBriefState::InFlight(ShadowBriefInFlight {
        generation: 1,
        snapshot_history: Vec::new(),
        snapshot_turns: 0,
        snapshot_tail_turns: 0,
        cancel: ending_cancel,
        handle: tokio::spawn(std::future::pending::<
            crate::engine::compact_draft::CompactDraftOutcome,
        >()),
    }));
    drop(ending_driver);
    assert!(
        ending_observer.is_cancelled(),
        "session teardown cancels shadow work"
    );
}

#[tokio::test]
async fn shadow_brief_foreground_preparation_preempts_before_preflight() {
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
    let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
    let cancel = tokio_util::sync::CancellationToken::new();
    let observed_cancel = cancel.clone();
    driver.shadow_brief_generation = 1;
    driver.shadow_brief = Some(ShadowBriefState::InFlight(ShadowBriefInFlight {
        generation: 1,
        snapshot_history: Vec::new(),
        snapshot_turns: 0,
        snapshot_tail_turns: 0,
        cancel,
        handle: tokio::spawn(std::future::pending::<
            crate::engine::compact_draft::CompactDraftOutcome,
        >()),
    }));

    let prepared = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        driver.prepare_queued_user_submission(UserSubmission::text("hello"), &queue, &tx),
    )
    .await
    .expect("foreground preparation should not wait for the delayed shadow");
    assert!(prepared.is_some());
    assert!(
        observed_cancel.is_cancelled(),
        "the first preparation action cancels shadow utility work before preflight"
    );

    driver.shadow_brief_generation = 2;
    driver.shadow_brief = Some(ShadowBriefState::Ready(ShadowBriefReady {
        generation: 2,
        snapshot_history: Vec::new(),
        snapshot_turns: 0,
        snapshot_tail_turns: 0,
        brief: "ready".to_string(),
        fit_rung: crate::engine::compact_draft::CompactFitRung::Verbatim,
        input_coverage: crate::engine::compact_draft::CompactInputCoverage::Full,
    }));
    let _ = driver
        .prepare_queued_user_submission(UserSubmission::text("hello again"), &queue, &tx)
        .await;
    assert!(
        matches!(
            &driver.shadow_brief,
            Some(ShadowBriefState::Ready(ready)) if ready.brief == "ready"
        ),
        "a shadow completed before dequeue remains available"
    );
}

#[tokio::test]
async fn shadow_gated_on_prune_effectiveness() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 100);
    record_test_context_tokens(&driver, 50).await;
    assert!(
        !driver.maybe_shadow_brief(&tx).await,
        "effective pruning gates early band"
    );
    for ctx_pct in [35.0, 42.0, 50.0] {
        driver.note_prune_effectiveness(PruneEffectiveness {
            ctx_pct,
            saved_pct: 0.5,
        });
    }
    assert!(
        driver.maybe_shadow_brief(&tx).await,
        "ineffective pruning opens early band"
    );
    assert!(
        !driver.maybe_shadow_brief(&tx).await,
        "only one draft may be in flight"
    );
}

#[tokio::test]
async fn shadow_killswitch_restores_sync() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    let cfg = ContextConfig {
        compact_shadow: false,
        ..ContextConfig::default()
    };
    install_test_providers(&mut driver, CacheMode::None, cfg, 10_000);
    record_test_context_tokens(&driver, 5_500).await;
    assert!(!driver.maybe_shadow_brief(&tx).await);
    driver.do_compact(&tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}
    assert_eq!(compact_inference_purposes(&driver).await, ["compact_brief"]);
}

async fn prepare_apply_fixture() -> (Driver, tempfile::TempDir) {
    use crate::engine::message::AssistantContent;
    use rig::message::{ToolCall, ToolFunction};

    let (mut driver, tmp) = test_driver_without_network(8);
    let old = driver.stack[0].agent.clone();
    let tools =
        crate::engine::tool::ToolBox::new().with(std::sync::Arc::new(crate::tools::read::ReadTool));
    driver.stack[0].agent = std::sync::Arc::new(Agent {
        name: old.name.clone(),
        system: old.system.clone(),
        role_prompt: old.role_prompt.clone(),
        tools,
        model: old.model.clone(),
        params: old.params.clone(),
        scan_tool_results: old.scan_tool_results,
        tool_steering: old.tool_steering,
        posture: old.posture.clone(),
        context_policy: None,
        lock_identity: "Build".to_string(),
        write_scope: None,
        workspace_lease: None,
        delegated: false,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        vnext_grant: None,
        env_overlay: old.env_overlay.clone(),
        definition: old.definition.clone(),
        assistant_identity_prefix: None,
    });
    install_test_providers(
        &mut driver,
        crate::config::providers::CacheMode::None,
        crate::config::providers::ContextConfig::default(),
        100_000,
    );
    std::fs::write(driver.cwd.join("seed.txt"), "seed body").unwrap();
    driver
        .session
        .record_tool_call(crate::session::ToolCallRow {
            event_id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".into(),
            call_id: "seed-source".into(),
            parent_call_id: None,
            parent_child_index: None,
            identity: crate::session::ToolCallProviderIdentity::default(),
            tool: "read".into(),
            path: Some("seed.txt".into()),
            mcp_server: None,
            original_input_json: serde_json::json!({ "path": "seed.txt" }),
            wire_input_json: serde_json::json!({ "path": "seed.txt" }),
            recovery: crate::db::tool_calls::Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            output: "seed body".into(),
            truncated: false,
            duration_ms: 1,
            shape_fingerprint: None,
            hint: None,
        })
        .await
        .unwrap();

    let original = (0..700)
        .map(|index| format!("noise line {index}"))
        .collect::<Vec<_>>()
        .join("\n");
    driver.stack[0].history = vec![
        Message::user("run the suite"),
        Message::Assistant {
            id: None,
            content: vec![AssistantContent::ToolCall(ToolCall {
                id: rig::message::ToolCallId::new_or_mint("bash-condense"),
                provider: None,
                function: ToolFunction {
                    name: "bash".into(),
                    arguments: serde_json::json!({"command": "cargo test"}),
                },
                signature: None,
                additional_params: None,
            })],
        },
        crate::engine::message::synthetic_tool_result_message_with_provider_identity(
            "bash-condense".to_string(),
            None,
            None,
            "bash",
            original,
        ),
        Message::assistant("suite complete"),
        Message::user("next step"),
        Message::assistant("continue"),
    ];
    (driver, tmp)
}

fn compact_ready_without_session_id(event: &TurnEvent) -> serde_json::Value {
    match event {
        TurnEvent::CompactReady {
            handoff,
            brief,
            source,
            trigger_ctx_pct,
            tokens_before,
            tokens_after,
            turns_summarized,
            tail_kept,
            tail_trimmed,
            seed_tool_count,
            seed_tool_tokens,
            ..
        } => serde_json::json!({
            "handoff": handoff,
            "brief": brief,
            "source": source,
            "trigger_ctx_pct": trigger_ctx_pct,
            "tokens_before": tokens_before,
            "tokens_after": tokens_after,
            "turns_summarized": turns_summarized,
            "tail_kept": tail_kept,
            "tail_trimmed": tail_trimmed,
            "seed_tool_count": seed_tool_count,
            "seed_tool_tokens": seed_tool_tokens,
        }),
        other => panic!("expected CompactReady, got {other:?}"),
    }
}

async fn compact_record_without_session_ids(driver: &Driver) -> serde_json::Value {
    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap();
    let mut data = events
        .iter()
        .find(|event| event.kind == "session_compacted")
        .expect("session_compacted event")
        .data
        .clone();
    for key in [
        "predecessor_session_id",
        "predecessor_short_id",
        "successor_session_id",
        "successor_short_id",
    ] {
        data.as_object_mut().unwrap().remove(key);
    }
    data
}

#[tokio::test]
async fn prepare_commits_nothing() {
    let (mut driver, _tmp) = prepare_apply_fixture().await;
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(16);
    let before_history = serde_json::to_value(&driver.stack[0].history).unwrap();
    let events_before = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap();

    let prepared = driver
        .prepare_compaction_with_source(&tx, "manual")
        .await
        .expect("prepare succeeds");

    assert_eq!(
        serde_json::to_value(&driver.stack[0].history).unwrap(),
        before_history
    );
    assert_eq!(prepared.seed_tags.len(), 1);
    assert!(
        driver
            .session
            .db
            .list_text_artifacts(driver.session.id)
            .await
            .unwrap()
            .is_empty(),
        "prepare must not persist text artifacts"
    );
    let events_after = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap();
    assert_eq!(
        events_before
            .iter()
            .filter(|event| event.kind == "session_compacted")
            .count(),
        events_after
            .iter()
            .filter(|event| event.kind == "session_compacted")
            .count(),
        "prepare must not record a compaction boundary"
    );
    assert!(rx.try_recv().is_err(), "prepare emits no UI events");
}

#[tokio::test]
async fn prepared_compaction_round_trips_serde() {
    let (mut driver, _tmp) = prepare_apply_fixture().await;
    let (tx, _rx) = mpsc::channel::<TurnEvent>(16);

    let prepared = driver
        .prepare_compaction_with_source(&tx, "manual")
        .await
        .expect("prepare succeeds");
    let encoded = serde_json::to_string(&prepared).unwrap();
    let decoded: PreparedCompaction = serde_json::from_str(&encoded).unwrap();

    assert_eq!(decoded, prepared);
}

#[tokio::test]
async fn apply_runs_no_inference() {
    let (mut driver, _tmp) = prepare_apply_fixture().await;
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let prepared = driver
        .prepare_compaction_with_source(&tx, "manual")
        .await
        .expect("prepare succeeds");
    let before = compact_inference_purposes(&driver).await;

    driver
        .apply_prepared_compaction(prepared, &tx)
        .await
        .expect("apply succeeds");

    assert_eq!(compact_inference_purposes(&driver).await, before);
    assert!(matches!(
        driver.auto_compact_gate,
        AutoCompactGate::Committed { activity_epoch: 0 }
    ));
    drop(tx);
    while rx.recv().await.is_some() {}
}

#[tokio::test]
async fn apply_rejects_stale_prepared_compaction() {
    let (mut driver, _tmp) = prepare_apply_fixture().await;
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(16);
    let prepared = driver
        .prepare_compaction_with_source(&tx, "manual")
        .await
        .expect("prepare succeeds");
    driver.stack[0].history.push(Message::user("late turn"));
    let before_apply = serde_json::to_value(&driver.stack[0].history).unwrap();

    let error = driver
        .apply_prepared_compaction(prepared, &tx)
        .await
        .expect_err("stale prepared compaction is rejected");

    assert!(matches!(error, PreparedCompactionApplyError::Stale { .. }));
    assert_eq!(
        serde_json::to_value(&driver.stack[0].history).unwrap(),
        before_apply
    );
    assert!(
        driver
            .session
            .db
            .list_text_artifacts(driver.session.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        driver
            .session
            .db
            .list_session_events(driver.session.id)
            .await
            .unwrap()
            .iter()
            .all(|event| event.kind != "session_compacted")
    );
    assert!(rx.try_recv().is_err(), "stale apply emits no events");
}

#[tokio::test]
async fn apply_of_prepared_matches_synchronous_path() {
    let (mut split_driver, _tmp_a) = prepare_apply_fixture().await;
    let (mut sync_driver, _tmp_b) = prepare_apply_fixture().await;
    let (split_tx, mut split_rx) = mpsc::channel::<TurnEvent>(64);
    let (sync_tx, mut sync_rx) = mpsc::channel::<TurnEvent>(64);

    let prepared = split_driver
        .prepare_compaction_with_source(&split_tx, "manual")
        .await
        .expect("prepare succeeds");
    split_driver
        .apply_prepared_compaction(prepared, &split_tx)
        .await
        .expect("apply succeeds");
    sync_driver.do_compact_with_source(&sync_tx, "manual").await;
    drop(split_tx);
    drop(sync_tx);

    let mut split_events = Vec::new();
    while let Some(event) = split_rx.recv().await {
        split_events.push(event);
    }
    let mut sync_events = Vec::new();
    while let Some(event) = sync_rx.recv().await {
        sync_events.push(event);
    }
    let split_ready = split_events
        .iter()
        .find(|event| matches!(event, TurnEvent::CompactReady { .. }))
        .expect("split CompactReady");
    let sync_ready = sync_events
        .iter()
        .find(|event| matches!(event, TurnEvent::CompactReady { .. }))
        .expect("sync CompactReady");

    assert_eq!(
        serde_json::to_value(&split_driver.stack[0].history).unwrap(),
        serde_json::to_value(&sync_driver.stack[0].history).unwrap()
    );
    assert_eq!(
        compact_ready_without_session_id(split_ready),
        compact_ready_without_session_id(sync_ready)
    );
    assert_eq!(
        compact_record_without_session_ids(&split_driver).await,
        compact_record_without_session_ids(&sync_driver).await
    );
}

#[tokio::test]
async fn compact_end_to_end_preserves_private_draft_contract() {
    let (mut driver, _tmp) = prepare_apply_fixture().await;
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    driver.do_compact_with_source(&tx, "manual").await;
    drop(tx);

    let mut events = Vec::new();
    while let Some(event) = rx.recv().await {
        events.push(event);
    }
    let ready = events
        .iter()
        .find(|event| matches!(event, TurnEvent::CompactReady { .. }))
        .expect("CompactReady emitted");
    let expected_handoff = format!(
        "test compact brief\n\n---\n## State appendix (deterministic — runtime ledger)\n\n\n**Files read:**\n- `seed.txt`\n\n\n## Context tags\nUse these @file, @file:XX-YY, @dir/, and /skill tags to resolve the working set through the shared tag policy:\n- @seed.txt\n\n\n{}",
        crate::engine::compact::HISTORY_AGENT_NUDGE
    );
    // A private compaction draft has no owning `context_pruned` event, so it
    // must not invent a text-artifact projection. Its prompt therefore retains
    // the original body; the old byte-level golden encoded an invalid private
    // condensation and is intentionally not stable across that contract change.
    assert_eq!(
        compact_ready_without_session_id(ready),
        serde_json::json!({
            "brief": "test compact brief",
            "handoff": expected_handoff,
            "seed_tool_count": 1,
            "seed_tool_tokens": 3,
            "source": "manual",
            "tail_kept": 2,
            "tail_trimmed": 0,
            "tokens_after": crate::engine::compact_draft::wire_token_total(&driver.stack[0].history),
            "tokens_before": 3654,
            "trigger_ctx_pct": null,
            "turns_summarized": 0,
        })
    );
    let compact_record = compact_record_without_session_ids(&driver).await;
    assert_eq!(compact_record["brief_text"], "test compact brief");
    assert_eq!(compact_record["handoff_text"], expected_handoff);
    assert_eq!(compact_record["tokens_before"], 3654);
    assert_eq!(
        compact_record["tokens_after"],
        crate::engine::compact_draft::wire_token_total(&driver.stack[0].history)
    );
    assert!(
        driver
            .session
            .db
            .list_text_artifacts(driver.session.id)
            .await
            .unwrap()
            .is_empty(),
        "a private compaction draft must not create an artifact without a context_pruned owner event"
    );
    assert!(
        matches!(events.last(), Some(TurnEvent::CompactReady { brief, .. }) if brief == "test compact brief"),
        "synchronous entry point still emits CompactReady last"
    );
    assert!(
        driver.stack[0]
            .history
            .first()
            .is_some_and(|message| matches!(message, Message::User { .. })),
        "compacted history still starts with the handoff"
    );
    assert_eq!(
        driver
            .session
            .db
            .list_session_events(driver.session.id)
            .await
            .unwrap()
            .iter()
            .filter(|event| event.kind == "session_compacted")
            .count(),
        1
    );
}

#[tokio::test]
async fn apply_ordering_persists_then_runs_seeds_then_emits_ready() {
    let (mut driver, _tmp) = prepare_apply_fixture().await;
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let apply_trace = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    driver.test_compaction_apply_trace = Some(apply_trace.clone());
    let prepared = driver
        .prepare_compaction_with_source(&tx, "manual")
        .await
        .expect("prepare succeeds");

    driver
        .apply_prepared_compaction(prepared, &tx)
        .await
        .expect("apply succeeds");
    drop(tx);

    let mut emitted = Vec::new();
    while let Some(event) = rx.recv().await {
        emitted.push(event);
    }
    let ready = emitted
        .iter()
        .position(|event| matches!(event, TurnEvent::CompactReady { .. }))
        .expect("CompactReady emitted");
    assert_eq!(ready, emitted.len() - 1, "CompactReady is last");

    let db_events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap();
    assert!(
        db_events
            .iter()
            .find(|event| event.kind == "session_compacted")
            .is_some(),
        "timeline boundary is recorded during apply"
    );
    assert_eq!(
        *apply_trace.lock().unwrap(),
        [
            "live_history_swapped",
            "timeline_recorded",
            "compact_ready_emitted",
        ]
    );
}

#[tokio::test]
async fn rollback_paths_are_gone_because_prepare_is_pure() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(16);
    driver.stack[0].history = vec![Message::user("keep me"), Message::assistant("kept")];
    let before = serde_json::to_value(&driver.stack[0].history).unwrap();
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 0);

    assert!(
        driver
            .prepare_compaction_with_source(&tx, "manual")
            .await
            .is_err(),
        "zero-window prepare fails before any apply-phase side effect"
    );

    assert_eq!(
        serde_json::to_value(&driver.stack[0].history).unwrap(),
        before
    );
    assert!(
        driver
            .session
            .db
            .list_text_artifacts(driver.session.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        driver
            .session
            .db
            .list_session_events(driver.session.id)
            .await
            .unwrap()
            .iter()
            .all(|event| event.kind != "session_compacted")
    );
    assert!(rx.try_recv().is_err(), "failed prepare emits no events");
}

/// Threshold-branch auto-prune: a WARM cache (ephemeral, just sent) with
/// ctx% > the prune ctx% (50) AND prunable% > the prunable% (30) prunes
/// anyway, accepting the cache bust — and the `Pruned` event carries
/// `cache_break = true` so the client surfaces the warning.
#[tokio::test]
async fn auto_prune_threshold_branch_prunes_warm_cache_with_cache_break() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    // A big duplicated body so the prune actually reclaims many tokens
    // (the elision marker is small relative to the body).
    driver.stack[0].history = dup_read_history_big();
    let prunable = prune::dedup_plan(&driver.stack[0].history).tokens_saved();
    assert!(prunable > 0, "the big-body history must be prunable");
    // Pick a window so prunable% > 30 and ctx% > 50: window = prunable*2
    // makes prunable% = 50, and input = 60% of the window keeps ctx% > 50.
    let window = (prunable as u32) * 2;
    install_test_providers(
        &mut driver,
        CacheMode::Ephemeral,
        ContextConfig::default(),
        window,
    );
    // Warm cache: a send just happened.
    driver.session.note_send();
    let input = (f64::from(window) * 0.6) as u64; // ctx% = 60 (> 50)
    driver
        .session
        .record_usage(
            uuid::Uuid::new_v4(),
            crate::tokens::TokenUsage {
                input_tokens: input,
                output_tokens: 0,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
        )
        .await
        .unwrap();

    assert!(
        driver.maybe_auto_prune(&tx).await,
        "threshold branch prunes on a warm cache"
    );
    // The emitted Pruned event flags the cache break.
    let mut saw_cache_break = false;
    let mut saw_warm_threshold = false;
    drop(tx);
    while let Some(ev) = rx.recv().await {
        if let TurnEvent::Pruned {
            cache_break,
            trigger_reason,
            ..
        } = ev
        {
            saw_cache_break = saw_cache_break || cache_break;
            saw_warm_threshold =
                saw_warm_threshold || trigger_reason.as_deref() == Some("warm_threshold");
        }
    }
    assert!(
        saw_cache_break,
        "warm-cache threshold prune flags cache_break"
    );
    assert!(
        saw_warm_threshold,
        "warm-cache threshold prune records trigger reason"
    );
}

/// Auto-compact fires at/above the configured ctx% (default 60) and is a
/// one-shot (the second call no-ops because the session is being handed
/// off). Below the line it doesn't fire.
#[tokio::test]
async fn auto_compact_fires_at_threshold_once() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        5_000,
    );
    let fixture_model = driver.stack[0].agent.model.clone();
    let mut build = crate::engine::builtin::load("Build", &driver.spawn_args(true)).unwrap();
    build.model = fixture_model;
    driver.stack[0].agent = Arc::new(build);
    std::fs::write(driver.cwd.join("seed.txt"), "seed body").unwrap();
    driver
        .session
        .record_tool_call(crate::session::ToolCallRow {
            event_id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".into(),
            call_id: "seed-source".into(),
            parent_call_id: None,
            parent_child_index: None,
            identity: crate::session::ToolCallProviderIdentity::default(),
            tool: "read".into(),
            path: Some("seed.txt".into()),
            mcp_server: None,
            original_input_json: serde_json::json!({ "path": "seed.txt" }),
            wire_input_json: serde_json::json!({ "path": "seed.txt" }),
            recovery: crate::db::tool_calls::Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            output: "seed body".into(),
            truncated: false,
            duration_ms: 1,
            shape_fingerprint: None,
            hint: None,
        })
        .await
        .unwrap();

    // 50% < 60 → no compact.
    driver
        .session
        .record_usage(
            uuid::Uuid::new_v4(),
            crate::tokens::TokenUsage {
                input_tokens: 2_500,
                output_tokens: 0,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
        )
        .await
        .unwrap();
    assert!(
        !driver.maybe_auto_compact(&tx).await,
        "below 60% no compact"
    );

    // The cumulative usage is now above 60%, so compact fires once.
    driver
        .session
        .record_usage(
            uuid::Uuid::new_v4(),
            crate::tokens::TokenUsage {
                input_tokens: 3_100,
                output_tokens: 0,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
        )
        .await
        .unwrap();
    assert!(driver.maybe_auto_compact(&tx).await, "at/over 60% compacts");
    // One-shot: a second call no-ops even while still hot.
    assert!(
        !driver.maybe_auto_compact(&tx).await,
        "auto-compact is one-shot per session"
    );
    drop(tx);
    let mut events = Vec::new();
    while let Some(ev) = rx.recv().await {
        events.push(ev);
    }
    let compact_ready = events
        .iter()
        .position(
            |ev| matches!(ev, TurnEvent::CompactReady { brief, .. } if !brief.trim().is_empty()),
        )
        .expect("compact ready event emitted");
    assert_eq!(
        compact_ready,
        events.len() - 1,
        "CompactReady remains last: {events:?}"
    );
    assert!(
        !events.iter().any(|ev| matches!(ev, TurnEvent::ToolStart { tool, .. } | TurnEvent::ToolEnd { tool, .. } if tool == "read")),
        "tag-based compaction does not re-run seed read tools: {events:?}"
    );
}

#[tokio::test]
async fn effective_auto_compact_pct_defaults_when_unset() {
    use crate::config::providers::ContextConfig;
    let (driver, _tmp) = test_driver_without_network(8);
    let cfg = ContextConfig::default();

    assert_eq!(driver.effective_auto_compact_pct(&cfg, None), 80);
    let conservative = crate::agents::ContextPolicy {
        auto_compact_pct: Some(60),
        inline_caps: Some(crate::agents::InlineCapsProfile::Conservative),
    };
    assert_eq!(
        driver.effective_auto_compact_pct(&cfg, Some(&conservative)),
        60
    );
}

#[tokio::test]
async fn effective_auto_compact_pct_is_80_without_mcp() {
    use crate::config::providers::ContextConfig;
    let (driver, _tmp) = test_driver_without_network(8);
    let cfg = ContextConfig::default();

    assert_eq!(driver.effective_auto_compact_pct(&cfg, None), 80);
}

#[tokio::test]
async fn effective_auto_compact_pct_explicit_override_wins() {
    use crate::config::providers::ContextConfig;
    let (driver, _tmp) = test_driver_without_network(8);
    let cfg = ContextConfig {
        auto_compact_pct: Some(50),
        ..ContextConfig::default()
    };
    let policy = crate::agents::ContextPolicy {
        auto_compact_pct: Some(60),
        inline_caps: None,
    };

    assert_eq!(driver.effective_auto_compact_pct(&cfg, None), 50);
    assert_eq!(driver.effective_auto_compact_pct(&cfg, Some(&policy)), 50);
}

#[tokio::test]
async fn auto_compact_fires_at_resolved_line() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut capable, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    install_test_providers(
        &mut capable,
        CacheMode::None,
        ContextConfig::default(),
        100_000,
    );
    capable.session.set_active_tool_names(["mcp"], false);

    record_test_context_tokens(&capable, 70_000).await;
    assert!(
        !capable.maybe_auto_compact(&tx).await,
        "mcp-capable stays below the resolved 80% line at 70%"
    );
    record_test_context_tokens(&capable, 82_000).await;
    assert!(
        capable.maybe_auto_compact(&tx).await,
        "mcp-capable compacts at the resolved 80% line"
    );
    drop(tx);
    while rx.recv().await.is_some() {}

    let (mut no_mcp, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    install_test_providers(
        &mut no_mcp,
        CacheMode::None,
        ContextConfig::default(),
        100_000,
    );
    no_mcp.session.set_active_tool_names([], false);
    record_test_context_tokens(&no_mcp, 65_000).await;
    assert!(
        no_mcp.maybe_auto_compact(&tx).await,
        "without mcp keeps the 60% forced line"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

#[tokio::test]
async fn auto_compact_defers_equal_line_until_compact_nudge_fires() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        100_000,
    );
    let mut agent = (*driver.stack[0].agent).clone();
    agent.context_policy = Some(crate::agents::ContextPolicy {
        auto_compact_pct: Some(60),
        inline_caps: Some(crate::agents::InlineCapsProfile::Conservative),
    });
    driver.stack[0].agent = Arc::new(agent);
    driver.session.set_active_tool_names(["mcp"], false);
    record_test_context_tokens(&driver, 65_000).await;

    assert!(
        !driver.maybe_auto_compact(&tx).await,
        "a 60% context policy gives the equal-line compact nudge one turn to reach the model"
    );
    assert!(
        driver
            .session
            .compact_self_nudge(Some(65.0), 60, 60, true, true)
            .is_some(),
        "turn-start injection records that the model received the warning"
    );
    assert!(
        driver.maybe_auto_compact(&tx).await,
        "after the warning has fired, the 60% forced line compacts"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

#[tokio::test]
async fn context_usage_reports_nudge_and_resolved_forced_pct() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut driver, _tmp) = test_driver_without_network(8);
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        100_000,
    );
    driver.session.set_active_tool_names(["mcp"], false);
    record_test_context_tokens(&driver, 62_000).await;

    let snapshot = driver.context_usage_snapshot();

    assert_eq!(snapshot.ctx_pct, Some(62.0));
    assert_eq!(snapshot.used_tokens, Some(62_000));
    assert_eq!(snapshot.total_tokens, Some(100_000));
    assert_eq!(snapshot.compact_nudge_pct, 60);
    assert_eq!(snapshot.auto_compact_pct, 80);
}

#[tokio::test]
async fn oversized_compact_handoff_leaves_history_unchanged() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.stack[0].history = vec![
        Message::user("retain this exact user turn"),
        Message::assistant("retain this exact assistant turn"),
    ];
    let before = serde_json::to_value(&driver.stack[0].history).unwrap();
    // The empty planning placeholder fits, while the assembled five-section
    // handoff plus deterministic appendix cannot land below 60% of this tiny
    // window. This exercises the pure prepare failure path after the private
    // prune-first derivation.
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 40);

    driver.do_compact(&tx).await;

    assert_eq!(
        serde_json::to_value(&driver.stack[0].history).unwrap(),
        before
    );
    assert!(
        driver
            .session
            .db
            .list_session_events(driver.session.id)
            .await
            .unwrap()
            .iter()
            .all(|event| event.kind != "session_compacted"),
        "a failed compaction must not record a successful boundary"
    );
    drop(tx);
    let mut saw_unchanged_notice = false;
    while let Some(event) = rx.recv().await {
        if matches!(event, TurnEvent::Notice { text } if text.contains("history was left unchanged"))
        {
            saw_unchanged_notice = true;
        }
    }
    assert!(
        saw_unchanged_notice,
        "the explicit failure should be surfaced"
    );
}

/// Compaction is an in-place history reset: sealed injection availability and
/// the union-only redaction table must survive a completed boundary.
#[tokio::test]
async fn sealed_value_survives_completed_compaction() {
    let (mut driver, _tmp) = prepare_apply_fixture().await;
    let literal = "compact-survives-sealed-value-3a8c";
    // Mirror the worker path: seal against the live driver table, then install
    // the unioned table into both persisted session state and the live driver.
    driver
        .session
        .set_sealed_value(
            crate::sealed::OwnerAuthority::for_test("owner"),
            driver.redact.as_ref(),
            "compact_keep",
            literal,
            "compaction survival",
            "user",
        )
        .await
        .unwrap();
    let persisted = driver
        .session
        .persisted_redaction_table()
        .unwrap()
        .expect("persisted redaction after seal");
    // Production installation path: driver + agent models + scheduler tables.
    driver.set_redaction_table(std::sync::Arc::new(persisted));
    assert!(
        !driver.redact.scrub(literal).contains(literal),
        "live driver redaction table must scrub the sealed literal before compaction"
    );

    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.do_compact_with_source(&tx, "manual").await;
    drop(tx);
    let mut saw_ready = false;
    while let Some(event) = rx.recv().await {
        if matches!(event, TurnEvent::CompactReady { .. }) {
            saw_ready = true;
        }
    }
    assert!(saw_ready, "completed compaction must emit CompactReady");

    assert!(
        driver
            .session
            .sealed_value_exists(
                crate::sealed::OwnerAuthority::for_test("owner"),
                "compact_keep"
            )
            .await
            .unwrap(),
        "sealed value must remain injectable after completed compaction"
    );
    let table = driver
        .session
        .persisted_redaction_table()
        .unwrap()
        .expect("redaction table must persist across compaction");
    assert!(
        !table.scrub(literal).contains(literal),
        "persisted redaction table must still scrub the sealed literal"
    );
    assert!(
        !driver.redact.scrub(literal).contains(literal),
        "live driver redaction table must still scrub the sealed literal after compaction"
    );
}

/// Resume after a completed compaction reloads the same injection and
/// redaction guarantees from durable session state.
#[tokio::test]
async fn sealed_value_survives_compaction_and_resume() {
    let (mut driver, _tmp) = prepare_apply_fixture().await;
    let literal = "compact-resume-sealed-value-6b1e";
    let session_id = driver.session.id;
    let db = driver.session.db.clone();
    driver
        .session
        .set_sealed_value(
            crate::sealed::OwnerAuthority::for_test("owner"),
            driver.redact.as_ref(),
            "resume_keep",
            literal,
            "compaction resume",
            "user",
        )
        .await
        .unwrap();
    driver.set_redaction_table(std::sync::Arc::new(
        driver
            .session
            .persisted_redaction_table()
            .unwrap()
            .expect("persisted after seal"),
    ));
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.do_compact_with_source(&tx, "manual").await;
    drop(tx);
    while rx.recv().await.is_some() {}

    let resumed = Session::resume_for_test(
        db,
        session_id,
        crate::session::test_redaction_key_resolver(),
    )
    .unwrap()
    .expect("session must resume after compaction");
    assert!(
        resumed
            .sealed_value_exists(
                crate::sealed::OwnerAuthority::for_test("owner"),
                "resume_keep"
            )
            .await
            .unwrap(),
        "resumed session must inject the pre-compaction sealed value"
    );
    let scrubbed = resumed
        .persisted_redaction_table()
        .unwrap()
        .expect("resumed redaction table")
        .scrub(literal);
    assert!(
        !scrubbed.contains(literal),
        "resumed redaction table must still scrub the sealed literal"
    );
}

/// A deterministic prepare failure must leave sealed injection and redaction
/// state exactly as they were before the attempt.
#[tokio::test]
async fn failed_compaction_does_not_change_sealed_state() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut driver, _tmp) = test_driver_without_network(8);
    let literal = "failed-compact-sealed-value-2d9f";
    driver
        .session
        .set_sealed_value(
            crate::sealed::OwnerAuthority::for_test("owner"),
            &crate::redact::RedactionTable::empty(),
            "fail_keep",
            literal,
            "failed compaction",
            "user",
        )
        .await
        .unwrap();
    let before_meta = driver
        .session
        .list_sealed_value_metadata(crate::sealed::OwnerAuthority::for_test("owner"))
        .await
        .unwrap();
    let before_table_json = driver
        .session
        .persisted_redaction_table()
        .unwrap()
        .expect("pre-attempt redaction table")
        .to_persisted_json()
        .unwrap();
    let before_scrub = driver
        .session
        .persisted_redaction_table()
        .unwrap()
        .unwrap()
        .scrub(literal);
    driver.stack[0].history = vec![
        Message::user("retain this exact user turn"),
        Message::assistant("retain this exact assistant turn"),
    ];
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 40);

    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.do_compact(&tx).await;
    drop(tx);
    let mut saw_unchanged_notice = false;
    while let Some(event) = rx.recv().await {
        if matches!(event, TurnEvent::Notice { text } if text.contains("history was left unchanged"))
        {
            saw_unchanged_notice = true;
        }
    }
    assert!(
        saw_unchanged_notice,
        "failed compaction must surface the unchanged-history notice"
    );

    assert!(
        driver
            .session
            .sealed_value_exists(
                crate::sealed::OwnerAuthority::for_test("owner"),
                "fail_keep"
            )
            .await
            .unwrap(),
        "failed compaction must keep the pre-attempt sealed value injectable"
    );
    let after_meta = driver
        .session
        .list_sealed_value_metadata(crate::sealed::OwnerAuthority::for_test("owner"))
        .await
        .unwrap();
    assert_eq!(
        after_meta.len(),
        before_meta.len(),
        "failed compaction must not alter sealed metadata cardinality"
    );
    assert_eq!(
        after_meta
            .iter()
            .map(|row| row.value_id.as_str())
            .collect::<Vec<_>>(),
        before_meta
            .iter()
            .map(|row| row.value_id.as_str())
            .collect::<Vec<_>>(),
    );
    let after_table = driver
        .session
        .persisted_redaction_table()
        .unwrap()
        .expect("redaction table after failed compaction");
    // Compare without assert_eq so a mismatch cannot dump the literal-bearing JSON.
    assert!(
        after_table.to_persisted_json().unwrap() == before_table_json,
        "failed compaction must not mutate the persisted redaction table"
    );
    let after_scrub = after_table.scrub(literal);
    assert!(
        after_scrub == before_scrub,
        "failed compaction must leave scrub coverage unchanged"
    );
    assert!(
        !after_scrub.contains(literal),
        "failed compaction must leave the sealed literal in the redaction table"
    );
}

#[tokio::test]
async fn zero_window_compact_fails_explicitly_without_mutation() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(16);
    driver.stack[0].history = vec![Message::user("keep me"), Message::assistant("kept")];
    let before = serde_json::to_value(&driver.stack[0].history).unwrap();
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 0);

    driver.do_compact(&tx).await;

    assert_eq!(
        serde_json::to_value(&driver.stack[0].history).unwrap(),
        before
    );
    drop(tx);
    assert!(
        matches!(rx.recv().await, Some(TurnEvent::Notice { text }) if text.contains("history was left unchanged"))
    );
}

#[tokio::test]
async fn compact_prune_stage_does_not_mutate_live_history() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(16);
    driver.stack[0].history = dup_read_history_big();
    let before = serde_json::to_value(&driver.stack[0].history).unwrap();
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 0);

    driver.do_compact(&tx).await;

    assert_eq!(
        serde_json::to_value(&driver.stack[0].history).unwrap(),
        before,
        "the private prune-first stage must not mutate the live frame before the final compact write"
    );
    drop(tx);
    assert!(
        matches!(rx.recv().await, Some(TurnEvent::Notice { text }) if text.contains("history was left unchanged"))
    );
}

#[tokio::test]
async fn compact_private_prune_does_not_invent_an_artifact_owner() {
    use crate::config::providers::{CacheMode, ContextConfig};
    use crate::engine::message::AssistantContent;
    use rig::message::{ToolCall, ToolFunction};

    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    let original = (0..700)
        .map(|index| format!("noise line {index}"))
        .collect::<Vec<_>>()
        .join("\n");
    driver.stack[0].history = vec![
        Message::user("run the suite"),
        Message::Assistant {
            id: None,
            content: vec![AssistantContent::ToolCall(ToolCall {
                id: rig::message::ToolCallId::new_or_mint("bash-condense"),
                provider: None,
                function: ToolFunction {
                    name: "bash".into(),
                    arguments: serde_json::json!({"command": "cargo test"}),
                },
                signature: None,
                additional_params: None,
            })],
        },
        crate::engine::message::synthetic_tool_result_message_with_provider_identity(
            "bash-condense".to_string(),
            None,
            None,
            "bash",
            original.clone(),
        ),
        Message::assistant("suite complete"),
    ];
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        100_000,
    );

    driver.do_compact(&tx).await;

    let wire = serde_json::to_string(&driver.stack[0].history).unwrap();
    assert!(!wire.contains("cockpit_artifact_v1"), "{wire}");
    let stored = driver
        .session
        .db
        .list_text_artifacts(driver.session.id)
        .await
        .unwrap();
    assert!(stored.is_empty());
}

#[tokio::test]
async fn compact_tail_prompt_uses_durable_session_event_seqs() {
    let (mut driver, _tmp) = test_driver_without_network(8);
    let agent = driver.active_agent().to_string();
    let mut recorded = Vec::new();
    let mut excluded_skill_seq = None;
    for index in 0..2 {
        recorded.push(
            driver
                .session
                .record_event(
                    crate::db::session_log::SessionEventKind::UserMessage,
                    None,
                    None,
                    &serde_json::json!({"text": format!("user {index}")}),
                )
                .await
                .unwrap(),
        );
        if index == 1 {
            excluded_skill_seq = Some(
                driver
                    .session
                    .record_event(
                        crate::db::session_log::SessionEventKind::ToolCall,
                        Some(&agent),
                        Some("skill-nonsteering"),
                        &serde_json::json!({
                            "tool": "skill",
                            "wire_input": {"name": "reference"},
                            "output": "injected body",
                        }),
                    )
                    .await
                    .unwrap(),
            );
            driver.skill_pairs.push(SkillPair {
                call_id: "skill-nonsteering".into(),
                owner: agent.clone(),
                intentional_steer: false,
            });
        }
        recorded.push(
            driver
                .session
                .record_event(
                    crate::db::session_log::SessionEventKind::AssistantMessage,
                    Some(&agent),
                    None,
                    &serde_json::json!({"text": format!("assistant {index}")}),
                )
                .await
                .unwrap(),
        );
    }

    assert_eq!(driver.compact_tail_message_seqs(1).await, recorded[2..]);
    assert!(
        !driver
            .compact_tail_message_seqs(1)
            .await
            .contains(&excluded_skill_seq.unwrap())
    );
}

#[tokio::test]
async fn request_compact_honored_at_safe_boundary() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    driver.auto_compact_gate = AutoCompactGate::Committed { activity_epoch: 0 };
    driver.session.request_agent_compact();

    assert!(
        driver.maybe_auto_compact(&tx).await,
        "agent-requested compaction bypasses the auto latch"
    );
    assert!(!driver.session.agent_compact_requested());
    assert!(
        matches!(driver.stack[0].history.first(), Some(Message::User { .. })),
        "post-compact history starts with the handoff; a configured tail may follow"
    );
    drop(tx);
    let mut saw_compact_ready = false;
    while let Some(ev) = rx.recv().await {
        if matches!(ev, TurnEvent::CompactReady { .. }) {
            saw_compact_ready = true;
        }
    }
    assert!(saw_compact_ready, "compaction emits CompactReady");
    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap();
    let compact_events: Vec<_> = events
        .iter()
        .filter(|event| event.kind == "session_compacted")
        .collect();
    assert_eq!(compact_events.len(), 1);
    assert_eq!(compact_events[0].data["source"], "agent_requested");
}

#[tokio::test]
async fn request_compact_coalesces() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    driver.session.request_agent_compact();
    driver.session.request_agent_compact();

    assert!(driver.maybe_auto_compact(&tx).await);
    assert!(!driver.maybe_auto_compact(&tx).await);
    drop(tx);
    while rx.recv().await.is_some() {}
    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap();
    let compact_count = events
        .iter()
        .filter(|event| event.kind == "session_compacted")
        .count();
    assert_eq!(compact_count, 1);
}

/// `classify_prune_reason` reports the telemetry reason from a plan's
/// targets (Part D).
#[tokio::test]
async fn classify_prune_reason_buckets() {
    use crate::engine::prune::{DedupPlan, Elision, ElisionTarget, OVERLAP_REASON};
    let mk = |reason: &'static str| ElisionTarget {
        history_index: 0,
        current_body: String::new(),
        elision: Elision {
            original_event_id: "x".into(),
            reason,
        },
        partial_body: None,
        tokens_saved: 0,
        target_call_id: "x".into(),
    };
    let exact = DedupPlan {
        targets: vec![mk("snapshot superseded")],
    };
    assert_eq!(classify_prune_reason(&exact), "exact-identity");
    let overlap = DedupPlan {
        targets: vec![mk(OVERLAP_REASON)],
    };
    assert_eq!(classify_prune_reason(&overlap), "overlap-merge");
    let mixed = DedupPlan {
        targets: vec![mk("snapshot superseded"), mk(OVERLAP_REASON)],
    };
    assert_eq!(classify_prune_reason(&mixed), "mixed");
}

/// The escalation predicate: N consecutive small-saving prunes while ctx%
/// climbs is ineffective; a single big save, a non-climbing run, or too
/// few prunes is not (implementation note Part B).
#[tokio::test]
async fn prune_ineffective_predicate() {
    let (mut driver, _tmp) = test_driver(8);
    // Fewer than the run length → not ineffective yet.
    driver.note_prune_effectiveness(PruneEffectiveness {
        ctx_pct: 50.0,
        saved_pct: 0.5,
    });
    driver.note_prune_effectiveness(PruneEffectiveness {
        ctx_pct: 55.0,
        saved_pct: 0.5,
    });
    assert!(!driver.prune_is_ineffective(), "two prunes is too few");

    // A third small-and-climbing prune trips it.
    driver.note_prune_effectiveness(PruneEffectiveness {
        ctx_pct: 60.0,
        saved_pct: 0.5,
    });
    assert!(
        driver.prune_is_ineffective(),
        "three small saves while ctx% climbs is ineffective"
    );

    // A large recent save breaks the run.
    driver.note_prune_effectiveness(PruneEffectiveness {
        ctx_pct: 65.0,
        saved_pct: 20.0,
    });
    assert!(
        !driver.prune_is_ineffective(),
        "a big save means pruning is working"
    );

    // Small saves but ctx% NOT climbing (flat/falling) → not ineffective
    // (pruning is holding the line).
    let mut d2 = test_driver(8).0;
    for ctx in [60.0, 55.0, 50.0] {
        d2.note_prune_effectiveness(PruneEffectiveness {
            ctx_pct: ctx,
            saved_pct: 0.5,
        });
    }
    assert!(
        !d2.prune_is_ineffective(),
        "ctx% not climbing → not an escalation case"
    );
}

/// End-to-end escalation: when auto-prunes keep saving little while ctx%
/// climbs (below the hard auto-compact line), the next idle boundary
/// escalates to `/compact` (implementation note Part B).
#[tokio::test]
async fn ineffective_prunes_escalate_to_compaction_below_compact_line() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    // ctx 55% is below the 60% auto-compact line, so only escalation can
    // trigger a compact here.
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 100);
    driver
        .session
        .record_usage(
            uuid::Uuid::new_v4(),
            crate::tokens::TokenUsage {
                input_tokens: 55,
                output_tokens: 0,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
        )
        .await
        .unwrap();
    // No ineffective history yet → below the line, no compact.
    assert!(
        !driver.maybe_auto_compact(&tx).await,
        "below the compact line with no ineffective run → no compact"
    );
    // Seed an ineffective run (three small saves, climbing ctx%).
    for ctx in [35.0, 45.0, 55.0] {
        driver.note_prune_effectiveness(PruneEffectiveness {
            ctx_pct: ctx,
            saved_pct: 0.5,
        });
    }
    assert!(
        driver.maybe_auto_compact(&tx).await,
        "ineffective prunes escalate to compaction below the hard line"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

/// No `context_length` known → the ctx%-gated paths are inert: the
/// threshold auto-prune branch and auto-compact both skip, but the
/// cache-cold auto-prune branch still fires.
#[tokio::test]
async fn no_context_length_makes_ctx_gated_paths_inert() {
    use crate::config::providers::{
        ActiveModelRef, CacheConfig, CacheMode, ModelEntry, ProviderEntry, ProvidersConfig,
    };
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

    // Provider config WITHOUT a context_length on the model, ephemeral
    // (so cache could be warm), warm send.
    let mut entry = ProviderEntry {
        url: "http://localhost:1/v1".into(),
        cache: CacheConfig {
            mode: CacheMode::Ephemeral,
            ttl_secs: 300,
        },
        ..ProviderEntry::default()
    };
    entry.models.push(ModelEntry {
        id: "local".into(),
        name: None,
        thinking_modes: vec![],
        inputs: None,
        context_length: None, // unknown window
        favorite: false,
        manual: false,
        trust: None,
        location: None,
        quality_rank: None,
        cost_rank: None,
        subagent_invokable: None,
        can_delegate: None,
        computer_use: None,
        allow_computer_guidance_proposals: None,
        default_thinking_mode: None,
        embeddings: None,
        embedding_dimensions: None,
        availability: Default::default(),
        cache: None,
        shrink: None,
        context: None,
        auto_prune: None,
        timeout: None,
        backup: None,
        inline_think: None,
        hint_tool_call_corrections: None,
        text_embedded_recovery: None,
        thinking_params: Default::default(),
        system_prompt: None,
        wire_api: Default::default(),
        wire_api_provenance: Default::default(),
        extra: Default::default(),
        capabilities: Default::default(),
        capability_overrides: Default::default(),
        provider_metadata: Default::default(),
    });
    let mut providers = std::collections::BTreeMap::new();
    providers.insert("lmstudio".to_string(), entry);
    driver.test_providers_override = Some((
        ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "lmstudio".into(),
                model: "local".into(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            }),
            ..ProvidersConfig::default()
        },
        "lmstudio".into(),
        "local".into(),
    ));

    // Auto-compact inert (no ctx%).
    driver
        .session
        .record_usage(
            uuid::Uuid::new_v4(),
            crate::tokens::TokenUsage {
                input_tokens: 999_999,
                output_tokens: 0,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
        )
        .await
        .unwrap();
    assert!(
        !driver.maybe_auto_compact(&tx).await,
        "no context_length → auto-compact inert"
    );

    // Threshold auto-prune branch inert on a WARM cache (no ctx%), so the
    // only thing that could fire it is the cache-cold branch. Make it
    // cold (no send → cold) and confirm the cache-cold branch still works.
    driver.stack[0].history = dup_read_history_big();
    assert!(
        driver.maybe_auto_prune(&tx).await,
        "cache-cold auto-prune still fires without context_length"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

/// A registry with BOTH `preCompact` and `postCompact` hooks matched on the
/// `manual` compact source. Commands are unresolvable (fail-open) so no real
/// process spawns; each firing still records one `hook_run` row.
fn compact_manual_registry() -> crate::config::extended::hooks::HookRegistry {
    use crate::config::extended::hooks::{HookEvent, HookOrigin, HookRegistry, ResolvedHook};
    let hook = |event: HookEvent| ResolvedHook {
        event,
        matcher: Some(["manual".to_string()].into_iter().collect()),
        command: vec!["cockpit-compact-hook-does-not-exist".to_string()],
        timeout_secs: 5,
        env: std::collections::BTreeMap::new(),
        origin: HookOrigin::for_test("project:abcdef0123456789:0"),
        source_config_path: std::path::PathBuf::from("/tmp/test/config.json"),
        source_directory: std::path::PathBuf::from("/tmp/test"),
        execution: crate::config::extended::hooks::HookExecutionProvenance::Ambient,
    };
    HookRegistry {
        hooks: vec![hook(HookEvent::PreCompact), hook(HookEvent::PostCompact)],
        warnings: Vec::new(),
    }
}

/// The ordered event keys of the `preCompact` / `postCompact` `hook_run` rows.
async fn compact_hook_event_order(driver: &Driver) -> Vec<String> {
    driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "hook_run")
        .filter_map(|e| e.data["event"].as_str().map(str::to_string))
        .filter(|event| event == "preCompact" || event == "postCompact")
        .collect()
}

#[tokio::test]
async fn compact_hooks_fire_pre_before_post_only_on_success() {
    // Pin the asymmetric (BY DESIGN) preCompact/postCompact contract over the
    // real `do_compact_with_source` boundary:
    //   prepare-fail → 0 pre + 0 post (no compaction attempted)
    //   apply-fail   → 1 pre + 0 post (preCompact fired before the destructive
    //                  apply and cannot be retroactively un-fired)
    //   success      → 1 pre + 1 post, preCompact strictly before postCompact
    // Source is "manual" so the auto-compact-gate failure branch is never taken.

    // prepare-fail → neither fires.
    let (mut driver, _tmp) = prepare_apply_fixture().await;
    inject_hooks(&mut driver, compact_manual_registry());
    driver.test_compact_force_failure = Some(crate::engine::driver::CompactForceFailure::Prepare);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.do_compact_with_source(&tx, "manual").await;
    drop(tx);
    while rx.recv().await.is_some() {}
    assert!(
        observe_hook_events(&driver, "preCompact").await.is_empty(),
        "prepare failure must not fire preCompact"
    );
    assert!(
        observe_hook_events(&driver, "postCompact").await.is_empty(),
        "prepare failure must not fire postCompact"
    );

    // apply-fail → preCompact only.
    let (mut driver, _tmp) = prepare_apply_fixture().await;
    inject_hooks(&mut driver, compact_manual_registry());
    driver.test_compact_force_failure = Some(crate::engine::driver::CompactForceFailure::Apply);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.do_compact_with_source(&tx, "manual").await;
    drop(tx);
    while rx.recv().await.is_some() {}
    assert_eq!(
        observe_hook_events(&driver, "preCompact").await,
        vec!["failed".to_string()],
        "apply failure must still fire preCompact (fired before the destructive apply)"
    );
    assert!(
        observe_hook_events(&driver, "postCompact").await.is_empty(),
        "apply failure must NOT fire postCompact (no durable successor)"
    );

    // success → both, pre strictly before post.
    let (mut driver, _tmp) = prepare_apply_fixture().await;
    inject_hooks(&mut driver, compact_manual_registry());
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.do_compact_with_source(&tx, "manual").await;
    drop(tx);
    while rx.recv().await.is_some() {}
    assert_eq!(
        observe_hook_events(&driver, "preCompact").await,
        vec!["failed".to_string()],
        "success must fire exactly one preCompact"
    );
    assert_eq!(
        observe_hook_events(&driver, "postCompact").await,
        vec!["failed".to_string()],
        "success must fire exactly one postCompact"
    );
    assert_eq!(
        compact_hook_event_order(&driver).await,
        vec!["preCompact".to_string(), "postCompact".to_string()],
        "preCompact must be recorded strictly before postCompact"
    );
}

/// AC9: a fitted initial shadow with `input_coverage=Partial` persists
/// `fit_rung` and `input_coverage=Partial` through the durable shadow
/// payload and is restored across a driver restart as partial.  A partial
/// shadow is never a final handoff — it is an accelerator only.
#[tokio::test]
async fn fitted_initial_shadow_persists_partial_coverage_across_restart() {
    use crate::engine::compact_draft::{CompactFitRung, CompactInputCoverage};

    let (mut driver, _tmp) = test_driver_without_network(8);
    let snapshot_history = vec![
        Message::user("first request"),
        Message::assistant("first response"),
        Message::user("second request"),
        Message::assistant("second response"),
    ];
    driver.shadow_brief_generation = 5;
    driver.shadow_brief = Some(ShadowBriefState::InFlight(ShadowBriefInFlight {
        generation: 5,
        snapshot_history: snapshot_history.clone(),
        snapshot_turns: 2,
        snapshot_tail_turns: 1,
        cancel: tokio_util::sync::CancellationToken::new(),
        handle: tokio::spawn(async {
            crate::engine::compact_draft::CompactDraftOutcome::Success(
                crate::engine::compact_draft::CompactDraftSuccess {
                    brief: "partial shadow brief derived from fitted history".to_string(),
                    fit_rung: CompactFitRung::HistorySelected,
                    input_coverage: CompactInputCoverage::Partial,
                    attempts: 1,
                },
            )
        }),
    }));
    tokio::task::yield_now().await;
    driver.settle_shadow_brief().await;

    let stored = driver
        .session
        .db
        .compaction_shadow(driver.session.id)
        .await
        .unwrap()
        .expect("settling a fitted shadow must persist it");
    let payload_json = stored.payload_json;
    let persisted: DurableCompactionShadow = serde_json::from_str(&payload_json).unwrap();
    let DurableCompactionShadow::ReadyBrief(persisted) = persisted else {
        panic!("settled shadow must persist a ready brief");
    };
    assert_eq!(persisted.fit_rung, CompactFitRung::HistorySelected);
    assert_eq!(persisted.input_coverage, CompactInputCoverage::Partial);
    assert_eq!(persisted.snapshot_history, snapshot_history);

    // Simulate a restart: create a fresh driver on the same session DB.
    let mut restored = Driver::new(
        driver.session.clone(),
        driver.locks.clone(),
        driver.redact.clone(),
        driver.cwd.clone(),
        driver.stack[0].agent.clone(),
    );
    restored.load_compaction_shadow_from_store().await;

    // The shadow is restored as Ready, not discarded.
    let ready = match &restored.shadow_brief {
        Some(ShadowBriefState::Ready(ready)) => ready,
        _ => panic!("expected Ready shadow after restart"),
    };
    assert_eq!(restored.shadow_brief_generation, 5);
    assert_eq!(
        ready.brief,
        "partial shadow brief derived from fitted history"
    );
    // The fit metadata survives the round-trip.
    assert_eq!(ready.fit_rung, CompactFitRung::HistorySelected);
    assert_eq!(ready.input_coverage, CompactInputCoverage::Partial);
    // The original snapshot history/coverage is retained for staleness.
    assert_eq!(ready.snapshot_history, snapshot_history);
    assert_eq!(ready.snapshot_turns, 2);

    // A partial shadow is never a final handoff.  The durable payload
    // itself is a `ReadyBrief` (shadow), not a `PreparedCompaction` (the
    // final handoff).  Verify this structurally.
    let decoded: DurableCompactionShadow = serde_json::from_str(&payload_json).unwrap();
    assert!(
        matches!(decoded, DurableCompactionShadow::ReadyBrief(_)),
        "a partial shadow must be a ReadyBrief, not a PreparedCompaction handoff"
    );

    // A restart must not turn the partial ready brief into a complete
    // handoff. The foreground delta receives the current complete history,
    // including the snapshot prefix omitted by the initial fitted shadow.
    restored.stack[0].history = snapshot_history.clone();
    install_test_providers(
        &mut restored,
        crate::config::providers::CacheMode::None,
        crate::config::providers::ContextConfig::default(),
        10_000,
    );
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(128);
    restored.do_compact(&tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}
    let calls = crate::sync::lock_or_recover(
        restored
            .test_compact_brief_calls
            .as_ref()
            .expect("fake compact seam"),
    );
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].purpose, "compact_brief_delta");
    assert_eq!(
        calls[0].history, snapshot_history,
        "a partial shadow delta must include every source exchange, not only the old tail"
    );
}

/// Manual `/compact` bypasses the auto-compaction gate: even when the gate
/// is in a suppressing state (`UntilActivity`), `do_compact` proceeds
/// because it never calls `suppresses()`.  Only `maybe_auto_compact`
/// consults the gate.
#[tokio::test]
async fn manual_compact_bypasses_auto_compact_gate() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    driver.stack[0].history = vec![
        Message::user("retain this turn"),
        Message::assistant("retain this response"),
    ];
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        10_000,
    );

    // Set the gate to a suppressing state that would block auto-compaction.
    let coverage = prepared_compaction_coverage(&driver.stack[0].history);
    driver.auto_compact_gate = AutoCompactGate::UntilActivity {
        activity_epoch: 0,
        reason: "deterministic failure".to_string(),
    };
    assert!(
        driver.auto_compact_gate.suppresses(&coverage),
        "precondition: gate must suppress auto-compaction"
    );

    // Manual compact must proceed despite the suppressing gate.
    driver.do_compact(&tx).await;
    drop(tx);

    let mut saw_compact_event = false;
    while let Some(event) = rx.recv().await {
        if matches!(
            event,
            TurnEvent::CompactReady { .. } | TurnEvent::Notice { .. }
        ) {
            saw_compact_event = true;
        }
    }
    assert!(
        saw_compact_event,
        "manual /compact must bypass the gate and emit a result event"
    );

    // Verify a session_compacted event was recorded (success path).
    let events = driver
        .session
        .db
        .list_session_events(driver.session.id)
        .await
        .unwrap();
    let compact_count = events
        .iter()
        .filter(|event| event.kind == "session_compacted")
        .count();
    assert_eq!(
        compact_count, 1,
        "manual compact must succeed despite the suppressing gate"
    );
}

/// AC11: restart begins `Eligible` — the gate is driver-only and not
/// serialized, so a fresh driver's gate does not suppress auto-compaction
/// even if a prior run left the gate in a blocking state.
#[tokio::test]
async fn auto_compact_gate_restart_begins_eligible() {
    let (mut driver, _tmp) = test_driver_without_network(8);
    let coverage = prepared_compaction_coverage(&[Message::user("one")]);

    // Leave the prior in-memory driver in a blocking state.
    driver.auto_compact_gate = AutoCompactGate::UntilActivity {
        activity_epoch: 0,
        reason: "deterministic failure".to_string(),
    };
    assert!(
        driver.auto_compact_gate.suppresses(&coverage),
        "precondition: the prior driver must be blocked"
    );

    // Simulate a restart by creating a new driver on the same session.
    let restored = Driver::new(
        driver.session.clone(),
        driver.locks.clone(),
        driver.redact.clone(),
        driver.cwd.clone(),
        driver.stack[0].agent.clone(),
    );
    assert!(
        !restored.auto_compact_gate.suppresses(&coverage),
        "restart must begin Eligible — the gate is not serialized"
    );
}
