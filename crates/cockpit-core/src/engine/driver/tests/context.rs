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
        history: dup_read_history(),
        answering: None,
        deferred_log: crate::engine::deferred::DeferredLog::new(),
        fallback_decision: None,
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
    assert!(driver.prune_watermark.get(&2).is_some());

    let _ = driver.pop_child_with_envelope(None, &tx).await;

    assert_eq!(
        driver.prune_watermark.get(&1).copied(),
        Some(99),
        "root watermark must not be cleared when the child pops"
    );
    assert!(
        driver.prune_watermark.get(&2).is_none(),
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
#[test]
fn context_metrics_compute_and_inert_cases() {
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

#[test]
fn active_context_length_uses_probed_capability() {
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
    record_test_context_tokens(&driver, 5_500);

    assert!(driver.maybe_shadow_brief(&tx).await);
    assert!(matches!(
        driver.shadow_brief,
        Some(ShadowBriefState::InFlight(_))
    ));
    wait_for_shadow_brief(&mut driver).await;
    assert_eq!(
        compact_inference_purposes(&driver),
        ["compact_shadow_brief"]
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
    record_test_context_tokens(&driver, 5_500);
    assert!(driver.maybe_shadow_brief(&tx).await);
    wait_for_shadow_brief(&mut driver).await;
    append_complete_test_turns(&mut driver, 1);

    driver.do_compact(&tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}
    let purposes = compact_inference_purposes(&driver);
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
async fn manual_compact_cancels_shadow() {
    use crate::config::providers::{CacheMode, ContextConfig};
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 100);
    let cancel = tokio_util::sync::CancellationToken::new();
    let observed_cancel = cancel.clone();
    driver.shadow_brief_generation = 1;
    driver.shadow_brief = Some(ShadowBriefState::InFlight(ShadowBriefInFlight {
        generation: 1,
        snapshot_history: Vec::new(),
        snapshot_turns: 0,
        snapshot_tail_turns: 0,
        cancel,
        handle: tokio::spawn(std::future::pending::<Option<String>>()),
    }));

    driver.do_compact(&tx).await;
    assert!(observed_cancel.is_cancelled());
    drop(tx);
    while rx.recv().await.is_some() {}
    assert_eq!(compact_inference_purposes(&driver), ["compact_brief"]);

    let (mut ending_driver, _tmp2) = test_driver_without_network(8);
    let ending_cancel = tokio_util::sync::CancellationToken::new();
    let ending_observer = ending_cancel.clone();
    ending_driver.shadow_brief = Some(ShadowBriefState::InFlight(ShadowBriefInFlight {
        generation: 1,
        snapshot_history: Vec::new(),
        snapshot_turns: 0,
        snapshot_tail_turns: 0,
        cancel: ending_cancel,
        handle: tokio::spawn(std::future::pending::<Option<String>>()),
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
    let cancel = tokio_util::sync::CancellationToken::new();
    let observed_cancel = cancel.clone();
    driver.shadow_brief_generation = 1;
    driver.shadow_brief = Some(ShadowBriefState::InFlight(ShadowBriefInFlight {
        generation: 1,
        snapshot_history: Vec::new(),
        snapshot_turns: 0,
        snapshot_tail_turns: 0,
        cancel,
        handle: tokio::spawn(std::future::pending::<Option<String>>()),
    }));

    let prepared = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        driver.prepare_queued_user_submission(UserSubmission::text("hello"), &tx),
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
    }));
    let _ = driver
        .prepare_queued_user_submission(UserSubmission::text("hello again"), &tx)
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
    record_test_context_tokens(&driver, 50);
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
    install_test_providers(&mut driver, CacheMode::None, cfg, 100);
    record_test_context_tokens(&driver, 55);
    assert!(!driver.maybe_shadow_brief(&tx).await);
    driver.do_compact(&tx).await;
    drop(tx);
    while rx.recv().await.is_some() {}
    assert_eq!(compact_inference_purposes(&driver), ["compact_brief"]);
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
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 100);
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
            llm_mode: crate::config::extended::LlmMode::default(),
            shape_fingerprint: None,
            hint: None,
        })
        .unwrap();

    // 50% < 60 → no compact.
    driver
        .session
        .record_usage(
            uuid::Uuid::new_v4(),
            crate::tokens::TokenUsage {
                input_tokens: 50,
                output_tokens: 0,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
        )
        .unwrap();
    assert!(
        !driver.maybe_auto_compact(&tx).await,
        "below 60% no compact"
    );

    // 65% ≥ 60 → compact fires once.
    driver
        .session
        .record_usage(
            uuid::Uuid::new_v4(),
            crate::tokens::TokenUsage {
                input_tokens: 65,
                output_tokens: 0,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
            },
        )
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
    let seed_start = events
        .iter()
        .position(|ev| matches!(ev, TurnEvent::ToolStart { tool, .. } if tool == "read"))
        .expect("seed read starts without a user follow-up");
    let seed_end = events
        .iter()
        .position(|ev| matches!(ev, TurnEvent::ToolEnd { tool, output, .. } if tool == "read" && output.contains("seed body")))
        .expect("seed read completes without a user follow-up");
    let compact_ready = events
        .iter()
        .position(
            |ev| matches!(ev, TurnEvent::CompactReady { brief, .. } if !brief.trim().is_empty()),
        )
        .expect("compact ready event emitted");
    assert!(
        seed_start < seed_end && seed_end < compact_ready,
        "seed tools should run before CompactReady: {events:?}"
    );
}

#[tokio::test]
async fn oversized_compact_handoff_leaves_history_unchanged() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    driver.stack[0].history = vec![
        Message::user("retain this exact user turn"),
        Message::assistant("retain this exact assistant turn"),
    ];
    let before = serde_json::to_value(&driver.stack[0].history).unwrap();
    // The empty planning placeholder fits, while the assembled five-section
    // handoff plus deterministic appendix cannot land below 60% of this tiny
    // window. This exercises the driver's rollback after prune-first.
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

#[tokio::test]
async fn zero_window_compact_fails_explicitly_without_mutation() {
    use crate::config::providers::{CacheMode, ContextConfig};

    let (mut driver, _tmp) = test_driver(8);
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

    let (mut driver, _tmp) = test_driver(8);
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
async fn compact_private_prune_preserves_shell_condensation() {
    use crate::config::providers::{CacheMode, ContextConfig};
    use crate::engine::message::{AssistantContent, OneOrMany};
    use rig::message::{ToolCall, ToolFunction};

    let (mut driver, _tmp) = test_driver(8);
    let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
    let original = (0..700)
        .map(|index| format!("noise line {index}"))
        .collect::<Vec<_>>()
        .join("\n");
    driver.stack[0].history = vec![
        Message::user("run the suite"),
        Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
                id: "bash-condense".into(),
                call_id: None,
                function: ToolFunction {
                    name: "bash".into(),
                    arguments: serde_json::json!({"command": "cargo test"}),
                },
                signature: None,
                additional_params: None,
            })),
        },
        Message::tool_result_with_call_id("bash-condense".to_string(), None, original.clone()),
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
    assert!(wire.contains("compressed tool result"), "{wire}");
    let stored = driver
        .session
        .db
        .list_compressed_tool_results(driver.session.id)
        .unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].content, original);
}

#[test]
fn compact_tail_prompt_uses_durable_session_event_seqs() {
    let (mut driver, _tmp) = test_driver(8);
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
                .unwrap(),
        );
    }

    assert_eq!(driver.compact_tail_message_seqs(1), recorded[2..]);
    assert!(
        !driver
            .compact_tail_message_seqs(1)
            .contains(&excluded_skill_seq.unwrap())
    );
}

#[tokio::test]
async fn request_compact_honored_at_safe_boundary() {
    let (mut driver, _tmp) = test_driver(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
    driver.auto_compacted = true;
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
        .unwrap();
    let compact_count = events
        .iter()
        .filter(|event| event.kind == "session_compacted")
        .count();
    assert_eq!(compact_count, 1);
}

/// `classify_prune_reason` reports the telemetry reason from a plan's
/// targets (Part D).
#[test]
fn classify_prune_reason_buckets() {
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
        mode: None,
        inline_think: None,
        hint_tool_call_corrections: None,
        text_embedded_recovery: None,
        thinking_params: Default::default(),
        system_prompt: None,
        wire_api: Default::default(),
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
