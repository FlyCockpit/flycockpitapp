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

// J2 regression: a driver's per-turn redaction refresh must never overwrite the
// durable table with its own stale `self.redact` copy and thereby drop a sealed
// literal that was adopted mid-session into the HUB's shared table (decision
// 10.1 adopted-table invariant). The refresh now routes through the hub's
// serialized read→union→persist→swap, so it unions the disk scan onto the LATEST
// shared table (which holds the committed sealed literal) instead of the stale
// copy.
#[tokio::test]
async fn driver_refresh_does_not_drop_a_committed_sealed_adoption() {
    use crate::engine::interrupt::InterruptHub;
    use crate::sealed::compartment::SealedLiteral;
    use crate::sealed::identity::{
        SealedName, SealedRecordId, SealedRedactionIdentity, SealedScopeKind,
    };
    use crate::sealed::runtime::{SealedRedactionSink, SessionRedactionSink};

    let (mut driver, tmp) = test_driver(1);
    let session = driver.session.clone();

    // A real (non-detached) hub sharing the driver's session + db, with a live
    // shared table starting empty — the same shape the daemon wires onto the
    // driver and the tool context's `SessionRedactionSink`.
    let redaction: crate::daemon::SharedRedactionTable = std::sync::Arc::new(
        std::sync::RwLock::new(std::sync::Arc::new(RedactionTable::empty())),
    );
    let (events, _events_rx) = tokio::sync::broadcast::channel(16);
    let hub = std::sync::Arc::new(InterruptHub::new(
        events,
        redaction.clone(),
        std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(1)),
        session.db.clone(),
        session.id,
    ));

    // Adopt a sealed literal into the hub's shared table + durable store. The
    // driver's own `self.redact` is never told about this adoption.
    const SEALED_LIT: &str = "driver-refresh-sealed-literal-do-not-drop-000";
    let sink = SessionRedactionSink::new(hub.clone(), session.clone());
    sink.register_before_use(
        &SealedLiteral::new(SEALED_LIT),
        &SealedRedactionIdentity {
            scope: SealedScopeKind::Project,
            record_id: Some(SealedRecordId::generate()),
            name: SealedName::canonical("deploy_token").unwrap(),
            version: 1,
        },
    )
    .await
    .unwrap();

    // The adoption is durable, but the driver's stale copy does not scrub it.
    assert!(
        !session
            .persisted_redaction_table()
            .unwrap()
            .unwrap()
            .scrub(SEALED_LIT)
            .contains(SEALED_LIT),
        "sealed literal is durable immediately after adoption"
    );
    assert!(
        driver.redact.scrub(SEALED_LIT).contains(SEALED_LIT),
        "driver's own copy is stale and does not yet scrub the sealed literal"
    );

    // Wire the same hub onto the driver and add a fresh on-disk secret so the
    // refresh has a real disk delta to union + persist.
    driver.set_interrupt_hub(hub);
    std::fs::write(
        tmp.path().join(".env"),
        "DISK_SECRET=driver-refresh-disk-secret\n",
    )
    .unwrap();

    let (tx, _turn_rx) = mpsc::channel(8);
    driver.refresh_redaction_table_for_turn(&tx).await;

    // Core J2 property: the refresh unioned onto the LATEST shared table under
    // the write lock, so the DURABLE table still scrubs the committed sealed
    // literal. Under the pre-fix code the driver persisted its stale `self.redact`
    // copy (which never saw the mid-session adoption), clobbering the sealed
    // literal out of the durable table — this assertion is what catches that.
    let durable = session.persisted_redaction_table().unwrap().unwrap();
    assert!(
        !durable.scrub(SEALED_LIT).contains(SEALED_LIT),
        "the driver refresh must not clobber the durable sealed adoption"
    );

    // The refresh genuinely unioned the disk delta onto the committed table
    // (it is not a no-op). Disk-derived (dotenv) VALUES are intentionally
    // excluded from the persisted table — `RedactionTable::to_persisted_json`
    // keeps only their origin marker and they are re-scanned on resume — so the
    // disk secret lands in the LIVE egress tables, not the durable one. Both the
    // driver's live copy AND the hub's shared table must now carry BOTH the
    // preserved sealed literal and the freshly discovered disk secret, proving
    // the driver merged the disk scan onto the committed adoption rather than
    // replacing it and that it now participates in the shared-table path.
    let shared = redaction.read().unwrap().clone();
    for live in [&driver.redact, &shared] {
        assert!(
            !live.scrub(SEALED_LIT).contains(SEALED_LIT),
            "live table keeps the sealed literal"
        );
        assert!(
            !live
                .scrub("driver-refresh-disk-secret")
                .contains("driver-refresh-disk-secret"),
            "live table gains the freshly discovered disk secret"
        );
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
    install_test_providers(
        &mut driver,
        CacheMode::None,
        ContextConfig::default(),
        10_000,
    );
    record_test_context_tokens(&driver, 5_500).await;
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

// ---------------------------------------------------------------------------
// Lifecycle observe-hook boundary wiring (userPromptSubmit / stopFailure)
//
// These drive the real driver production entry points at their named
// boundaries. The hook command is unresolvable so it fails open
// (executable-not-found) without spawning a process; a `hook_run` row is still
// recorded, which is the wiring signal. On dead-code HEAD (no wiring) no such
// row exists, so each fails there. Shared helpers
// (`observe_boundary_registry` / `inject_hooks` / `observe_hook_events`) live
// in `tests/mod.rs`.
// ---------------------------------------------------------------------------

#[test]
fn submission_origin_user_prompt_source_only_fires_for_external_user() {
    // The single explicit discriminator (carried on the submission, not ambient
    // state): only a genuine external user submission is a `userPromptSubmit`;
    // every host / goal / scheduled / system-driven origin suppresses it. This
    // is the classification the `run_user_input` path keys off, so it can never
    // fire as `"user"` for a goal or scheduled auto-turn.
    use crate::engine::message::SubmissionOrigin as O;
    assert_eq!(O::ExternalRoot.user_prompt_submit_source(), Some("user"));
    for host in [
        O::GoalContinuation,
        O::ScheduledJob,
        O::AutoContinue,
        O::RetryRecovery,
        O::ToolResult,
        O::CompactNotice,
        O::Internal,
    ] {
        assert_eq!(
            host.user_prompt_submit_source(),
            None,
            "{host:?} must not fire userPromptSubmit"
        );
    }
}

#[tokio::test]
async fn user_prompt_submit_hook_fires_only_for_external_user_source() {
    // Drive the record boundary directly with each resolved source. `user`
    // fires one row; a `queued`-only hook does not fire for `user` (exact
    // matcher); and `None` (a host/goal/scheduled origin) fires ZERO rows even
    // with a `user`-matched hook registered — the regression the reviewer
    // flagged (goal/scheduled auto-turns hitting the hardcoded `"user"`).
    let (tx, _rx) = mpsc::channel(8);
    let data = serde_json::json!({ "text": "hello" });

    // `Some("user")` → one row.
    let (mut driver, _tmp) = test_driver_without_network(1);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::UserPromptSubmit,
            "user",
        ),
    );
    let _ = driver
        .record_user_message_event(Some("Build"), None, &data, &[], &tx, Some("user"))
        .await;
    assert_eq!(
        observe_hook_events(&driver, "userPromptSubmit").await,
        vec!["failed".to_string()],
        "a genuine user submission must fire exactly one userPromptSubmit hook"
    );

    // A queued-only hook must NOT fire for a `user` submission.
    let (mut driver, _tmp) = test_driver_without_network(1);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::UserPromptSubmit,
            "queued",
        ),
    );
    let _ = driver
        .record_user_message_event(Some("Build"), None, &data, &[], &tx, Some("user"))
        .await;
    assert!(
        observe_hook_events(&driver, "userPromptSubmit")
            .await
            .is_empty(),
        "a queued-only hook must not fire on a user submission"
    );

    // `None` (host / goal / scheduled auto-turn) → ZERO rows even with a
    // `user`-matched hook registered.
    let (mut driver, _tmp) = test_driver_without_network(1);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::UserPromptSubmit,
            "user",
        ),
    );
    let _ = driver
        .record_user_message_event(Some("Build"), None, &data, &[], &tx, None)
        .await;
    assert!(
        observe_hook_events(&driver, "userPromptSubmit")
            .await
            .is_empty(),
        "a host/goal/scheduled auto-turn must fire NO userPromptSubmit hook"
    );
}

#[tokio::test]
async fn stop_failure_hook_fires_on_inference_error_class() {
    // The production `run_stop_failure_hooks` helper (the exact call the two
    // inference-failure arms make before unwinding) fires a `stopFailure` hook
    // matched on the error-class token, and does not fire on a lookalike class.
    let (mut driver, _tmp) = test_driver_without_network(1);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::StopFailure,
            "network",
        ),
    );
    driver
        .run_stop_failure_hooks(&crate::engine::model::InferenceErrorClass::Network)
        .await;
    assert_eq!(
        observe_hook_events(&driver, "stopFailure").await,
        vec!["failed".to_string()],
        "a network inference failure must fire exactly one stopFailure hook"
    );

    // A `timeout_ttft`-only hook must not fire on a network failure.
    let (mut driver, _tmp) = test_driver_without_network(1);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::StopFailure,
            "timeout_ttft",
        ),
    );
    driver
        .run_stop_failure_hooks(&crate::engine::model::InferenceErrorClass::Network)
        .await;
    assert!(
        observe_hook_events(&driver, "stopFailure").await.is_empty(),
        "a timeout_ttft-only hook must not fire on a network failure"
    );
}

// ---------------------------------------------------------------------------
// Interactive subagent lifecycle observe-hook boundary wiring
// (subagentStart / subagentStop). These drive the REAL driver production
// boundaries: `pop_child_with_envelope` (success child stop) and
// `unwind_stack_to_root` (abort child stop). The hook command is unresolvable
// so it fails open (executable-not-found) WITHOUT spawning a process; a
// `hook_run` row is still recorded — the wiring signal. On dead-code HEAD (no
// wiring) no such row exists, so each fails there. `push_answering_child`
// pushes a child whose agent name is `builder`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn subagent_stop_hook_fires_on_interactive_child_success_pop() {
    // Drive the real success-pop boundary: a `subagentStop` hook matched on the
    // child agent type fires exactly once when the child frame is popped.
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStop,
            "builder",
        ),
    );
    push_answering_child(&mut driver, "task-pop-1", "fn-pop-1");
    let _ = driver.pop_child_with_envelope(None, &tx).await;
    assert_eq!(
        observe_hook_events(&driver, "subagentStop").await,
        vec!["failed".to_string()],
        "popping an interactive child must fire exactly one subagentStop hook"
    );
    drop(tx);
    while rx.recv().await.is_some() {}

    // A different-agent-type hook must NOT fire on a builder child pop.
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStop,
            "explore",
        ),
    );
    push_answering_child(&mut driver, "task-pop-2", "fn-pop-2");
    let _ = driver.pop_child_with_envelope(None, &tx).await;
    assert!(
        observe_hook_events(&driver, "subagentStop")
            .await
            .is_empty(),
        "an explore-only hook must not fire on a builder child pop"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

#[tokio::test]
async fn subagent_stop_hook_fires_on_interactive_child_abort_unwind() {
    // Drive the real abort/teardown boundary: a cancelled parent turn unwinds
    // the child stack, which must STILL fire `subagentStop` so every started
    // child is paired with a stop. Without this, an aborted interactive child
    // would leave a `subagentStart` with no matching `subagentStop`.
    let (mut driver, _tmp) = test_driver_without_network(8);
    let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
    let call_id = "task-abort-hook-1";
    let function_call_id = "fn-abort-hook-1";
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStop,
            "builder",
        ),
    );
    driver.stack[0].history = vec![task_tool_call(call_id, function_call_id)];
    push_answering_child(&mut driver, call_id, function_call_id);
    driver
        .unwind_stack_to_root(StackUnwindReason::Cancelled, &tx)
        .await;
    assert_eq!(driver.stack.len(), 1, "unwind returns to the root frame");
    assert_eq!(
        observe_hook_events(&driver, "subagentStop").await,
        vec!["failed".to_string()],
        "aborting an interactive child must fire exactly one subagentStop hook"
    );
    drop(tx);
    while rx.recv().await.is_some() {}
}

#[tokio::test]
async fn subagent_start_hook_fires_for_child_agent_type_matcher() {
    // The production `fire_subagent_hook` helper (the exact call the interactive
    // spawn boundary makes) fires a `subagentStart` hook matched on the child
    // agent type, and does not fire on a different-agent-type lookalike.
    let (mut driver, _tmp) = test_driver_without_network(1);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStart,
            "builder",
        ),
    );
    driver
        .fire_subagent_hook(
            crate::config::extended::hooks::HookEvent::SubagentStart,
            "builder",
            Some("task-start-1"),
            None,
        )
        .await;
    assert_eq!(
        observe_hook_events(&driver, "subagentStart").await,
        vec!["failed".to_string()],
        "a builder child spawn must fire exactly one subagentStart hook"
    );

    let (mut driver, _tmp) = test_driver_without_network(1);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStart,
            "explore",
        ),
    );
    driver
        .fire_subagent_hook(
            crate::config::extended::hooks::HookEvent::SubagentStart,
            "builder",
            Some("task-start-2"),
            None,
        )
        .await;
    assert!(
        observe_hook_events(&driver, "subagentStart")
            .await
            .is_empty(),
        "an explore-only hook must not fire on a builder child spawn"
    );
}

#[tokio::test]
async fn orphaned_child_teardown_fires_paired_subagent_stop() {
    // The pairing-teardown escape hatch: a driver-loop exit that abandons a
    // still-active interactive child (only reachable via a fatal error, which
    // does NOT unwind) must still fire exactly one `subagentStop` per orphaned
    // child so no `subagentStart` is left unpaired. Drive the real teardown
    // helper (`drain_orphaned_child_stop_hooks`, called unconditionally when
    // the driver loop resolves in the session worker) with a child on the
    // stack.
    let (mut driver, _tmp) = test_driver_without_network(8);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStop,
            "builder",
        ),
    );
    push_answering_child(&mut driver, "task-orphan-1", "fn-orphan-1");
    // Child is still on the stack (not popped / unwound) — simulating a fatal
    // driver-loop exit that abandoned it.
    assert_eq!(driver.stack.len(), 2, "child frame is present pre-teardown");
    driver.drain_orphaned_child_stop_hooks().await;
    assert_eq!(
        observe_hook_events(&driver, "subagentStop").await,
        vec!["failed".to_string()],
        "an orphaned child at driver teardown must fire exactly one subagentStop"
    );

    // At the root frame (the normal exit state) the teardown fires nothing —
    // no double-stop for children already popped / unwound.
    let (mut driver, _tmp) = test_driver_without_network(8);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStop,
            "builder",
        ),
    );
    assert_eq!(driver.stack.len(), 1, "root-only stack");
    driver.drain_orphaned_child_stop_hooks().await;
    assert!(
        observe_hook_events(&driver, "subagentStop")
            .await
            .is_empty(),
        "teardown at the root frame must fire no subagentStop"
    );
}
