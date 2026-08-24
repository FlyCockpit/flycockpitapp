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

// ---------------------------------------------------------------------------
// Detached-`Swarm` subagent lifecycle observe-hook boundary wiring
// (subagentStart / subagentStop, spawn mode 3 of 3). These drive the REAL
// driver production helpers the `ScheduleEvent` drain calls
// (`fire_swarm_subagent_start` on `SwarmChildStarted`,
// `fire_swarm_subagent_stop_if_tracked` on `Completed`, and the teardown
// backstop `drain_orphaned_swarm_stop_hooks`). The hook command is
// unresolvable so it fails open (executable-not-found) WITHOUT spawning a
// process; a `hook_run` row is still recorded — the wiring signal. On unwired
// HEAD no such row exists, so each fails there.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn swarm_subagent_start_and_stop_pair_for_child_agent_type_matcher() {
    // A genuine swarm child (`bee`) that starts then completes fires exactly one
    // `subagentStart` and exactly one paired `subagentStop`, both matched on the
    // child agent type. A different-agent-type hook fires neither.
    let (mut driver, _tmp) = test_driver_without_network(1);
    let mut reg = observe_boundary_registry(
        crate::config::extended::hooks::HookEvent::SubagentStart,
        "bee",
    );
    reg.hooks.extend(
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStop,
            "bee",
        )
        .hooks,
    );
    inject_hooks(&mut driver, reg);

    driver.fire_swarm_subagent_start("sched-bee-1", "bee").await;
    assert_eq!(
        observe_hook_events(&driver, "subagentStart").await,
        vec!["failed".to_string()],
        "a bee swarm child start must fire exactly one subagentStart hook"
    );
    // Its terminal `Completed` (failed = false → success) fires the paired stop.
    driver
        .fire_swarm_subagent_stop_if_tracked("sched-bee-1", false)
        .await;
    assert_eq!(
        observe_hook_events(&driver, "subagentStop").await,
        vec!["failed".to_string()],
        "the same bee child's completion must fire exactly one paired subagentStop"
    );

    // A `scout`-only hook fires nothing for a `bee` child — proving the matcher
    // is the child agent type, not an unconditional fire.
    let (mut driver, _tmp) = test_driver_without_network(1);
    let mut reg = observe_boundary_registry(
        crate::config::extended::hooks::HookEvent::SubagentStart,
        "scout",
    );
    reg.hooks.extend(
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStop,
            "scout",
        )
        .hooks,
    );
    inject_hooks(&mut driver, reg);
    driver.fire_swarm_subagent_start("sched-bee-2", "bee").await;
    driver
        .fire_swarm_subagent_stop_if_tracked("sched-bee-2", false)
        .await;
    assert!(
        observe_hook_events(&driver, "subagentStart")
            .await
            .is_empty(),
        "a scout-only hook must not fire on a bee child start"
    );
    assert!(
        observe_hook_events(&driver, "subagentStop")
            .await
            .is_empty(),
        "a scout-only hook must not fire on a bee child stop"
    );
}

#[tokio::test]
async fn swarm_subagent_stop_only_fires_for_a_tracked_started_child() {
    // A `Completed` whose `job_id` never fired a `subagentStart` — a
    // goal-supervision control worker (never tracked; guidance L22), a
    // loop/timer/background job, or a stray/double completion — fires NO
    // `subagentStop`. Only a child recorded by a prior start is paired.
    let (mut driver, _tmp) = test_driver_without_network(1);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStop,
            "bee",
        ),
    );
    // Never started (not in the map): stop is a no-op even though a matching
    // hook is configured.
    driver
        .fire_swarm_subagent_stop_if_tracked("sched-untracked", false)
        .await;
    assert!(
        observe_hook_events(&driver, "subagentStop")
            .await
            .is_empty(),
        "a completion for an untracked job must fire no subagentStop"
    );

    // Start then stop fires exactly once; a SECOND stop for the same job fires
    // nothing (the map removal makes the pairing exactly-once — no double-fire
    // on a duplicate/late completion).
    driver.fire_swarm_subagent_start("sched-bee-3", "bee").await;
    driver
        .fire_swarm_subagent_stop_if_tracked("sched-bee-3", false)
        .await;
    driver
        .fire_swarm_subagent_stop_if_tracked("sched-bee-3", false)
        .await;
    assert_eq!(
        observe_hook_events(&driver, "subagentStop").await,
        vec!["failed".to_string()],
        "a started child fires exactly one subagentStop even if Completed twice"
    );
}

#[tokio::test]
async fn orphaned_swarm_child_teardown_fires_paired_subagent_stop() {
    // A driver-loop exit that abandons a live swarm child (its terminal
    // `Completed` is never drained — detach loss / shutdown) must still fire
    // exactly one paired `subagentStop` (`aborted`) so no `subagentStart` is
    // left unpaired. Drive the real teardown helper.
    let (mut driver, _tmp) = test_driver_without_network(1);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStop,
            "bee",
        ),
    );
    driver.fire_swarm_subagent_start("sched-bee-4", "bee").await;
    // `fire_swarm_subagent_start` also fires a subagentStart; clear the ledger
    // expectation by only inspecting subagentStop below.
    driver.drain_orphaned_swarm_stop_hooks().await;
    assert_eq!(
        observe_hook_events(&driver, "subagentStop").await,
        vec!["failed".to_string()],
        "an orphaned swarm child at teardown must fire exactly one subagentStop"
    );

    // A child that already completed (removed from the map) is NOT re-fired at
    // teardown — no double-stop.
    let (mut driver, _tmp) = test_driver_without_network(1);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(
            crate::config::extended::hooks::HookEvent::SubagentStop,
            "bee",
        ),
    );
    driver.fire_swarm_subagent_start("sched-bee-5", "bee").await;
    driver
        .fire_swarm_subagent_stop_if_tracked("sched-bee-5", false)
        .await;
    driver.drain_orphaned_swarm_stop_hooks().await;
    assert_eq!(
        observe_hook_events(&driver, "subagentStop").await,
        vec!["failed".to_string()],
        "a completed swarm child must not be re-fired at teardown (no double-stop)"
    );
}

// ---------------------------------------------------------------------------
// Root stop-gate continuation machine (increment 2B-ii-a).
//
// These drive the REAL driver stop-gate: `consult_root_stop_gate` threads a
// caller-owned per-turn `StopGateState` latch (a turn-scoped LOCAL in
// `run_user_input`, one per `(session, root frame, originating user turn)`)
// through the production `run_stop_hooks`. The runner / process-env seams are
// injected so a `block` / `continue:false` decision can be exercised without
// spawning a real process, no sleeps, and no `std::env` mutation. The full-loop
// wiring (that the `Done` arm calls this, and that cancel / interrupt /
// inference-error never do) is covered in `turn_loop.rs`.
// ---------------------------------------------------------------------------

/// A fake stop-hook runner that returns fixed stdout and counts invocations.
struct StopScriptRunner {
    stdout: String,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl StopScriptRunner {
    fn new(stdout: &str) -> Self {
        Self {
            stdout: stdout.to_string(),
            calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

#[async_trait::async_trait]
impl crate::engine::agent::hooks::CommandRunner for StopScriptRunner {
    async fn run(
        &self,
        _executable: &std::path::Path,
        _args: &[String],
        _env: &std::collections::BTreeMap<String, String>,
        _cwd: &std::path::Path,
        _stdin: &str,
        _timeout: std::time::Duration,
    ) -> crate::engine::agent::hooks::HookRawOutput {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        crate::engine::agent::hooks::HookRawOutput {
            stdout: self.stdout.clone(),
            exit_code: Some(0),
            duration_ms: 1,
            spawn_failed: false,
            timeout: false,
        }
    }
}

/// A runner that must never be invoked: proves a capped latch does not reconsult.
struct PanicRunner;

#[async_trait::async_trait]
impl crate::engine::agent::hooks::CommandRunner for PanicRunner {
    async fn run(
        &self,
        _executable: &std::path::Path,
        _args: &[String],
        _env: &std::collections::BTreeMap<String, String>,
        _cwd: &std::path::Path,
        _stdin: &str,
        _timeout: std::time::Duration,
    ) -> crate::engine::agent::hooks::HookRawOutput {
        panic!("a capped stop gate must not reconsult its stop hooks");
    }
}

/// A process-env that resolves any bare executable so the injected runner runs.
struct ResolveEnv;

impl crate::engine::agent::hooks::ProcessEnv for ResolveEnv {
    fn resolve_executable(&self, name: &str) -> Option<std::path::PathBuf> {
        Some(std::path::PathBuf::from("/fake/bin").join(name))
    }
    fn system_root(&self) -> Option<String> {
        None
    }
}

#[tokio::test]
async fn root_stop_gate_per_turn_latch_caps_and_is_independent() {
    use crate::engine::agent::hooks::{StopGateState, StopHookOutcome};
    let (mut driver, _tmp) = test_driver_without_network(1);
    inject_hooks(
        &mut driver,
        observe_boundary_registry(crate::config::extended::hooks::HookEvent::Stop, "end_turn"),
    );

    let env = ResolveEnv;
    let block = StopScriptRunner::new(r#"{"decision":"block","reason":"keep going"}"#);
    // Independently pinned expectation (not re-derived from the constant).
    let expected_grants: usize = 8;
    assert_eq!(
        crate::engine::agent::hooks::STOP_HOOK_MAX_CONTINUATIONS as usize,
        expected_grants
    );

    // Turn A owns its own latch (a turn-scoped local, exactly as the driver's
    // `run_user_input` does): exactly `expected_grants` continuations, each
    // running the hook once.
    let mut turn_a = StopGateState::default();
    for round in 1..=expected_grants {
        let outcome = driver
            .consult_root_stop_gate(&block, &env, &mut turn_a)
            .await;
        assert_eq!(
            outcome,
            StopHookOutcome::Continue {
                reason: "keep going".to_string(),
                additional_context: None,
            },
            "round {round} still open"
        );
        assert_eq!(turn_a.continuation_count as usize, round);
        assert_eq!(
            block.calls.load(std::sync::atomic::Ordering::SeqCst),
            round,
            "each granted round consults the hook once"
        );
    }

    // The next consultation on turn A is capped: force-end WITHOUT reconsulting.
    // A `PanicRunner` proves the hook is never run at the cap.
    let outcome = driver
        .consult_root_stop_gate(&PanicRunner, &env, &mut turn_a)
        .await;
    assert_eq!(outcome, StopHookOutcome::ForcedEnd);

    // A DIFFERENT user turn owns a SEPARATE latch: turn B starts fresh and is
    // granted a continuation even though turn A is capped (independence — the
    // cap is not a process-global counter).
    let block_b = StopScriptRunner::new(r#"{"decision":"block","reason":"more"}"#);
    let mut turn_b = StopGateState::default();
    let outcome = driver
        .consult_root_stop_gate(&block_b, &env, &mut turn_b)
        .await;
    assert_eq!(
        outcome,
        StopHookOutcome::Continue {
            reason: "more".to_string(),
            additional_context: None,
        },
        "a fresh user turn is not affected by another turn's cap"
    );
    assert_eq!(turn_b.continuation_count, 1);

    // `{"continue":false}` wins over block aggregation → ForcedEnd.
    let stop = StopScriptRunner::new(r#"{"continue":false,"stopReason":"all done"}"#);
    let mut turn_c = StopGateState::default();
    let outcome = driver
        .consult_root_stop_gate(&stop, &env, &mut turn_c)
        .await;
    assert_eq!(outcome, StopHookOutcome::ForcedEnd);
    assert_eq!(
        turn_c.continuation_count, 0,
        "continue:false ends the turn without counting a continuation"
    );
}

#[test]
fn stop_continuation_prompt_is_host_internal_and_carries_feedback() {
    // The injected feedback is a host-generated message: it carries the
    // aggregated block reason + additionalContext, and it uses
    // `SubmissionOrigin::Internal`, whose `user_prompt_submit_source()` is `None`
    // — so the continuation can never re-fire `userPromptSubmit` (which fires
    // only from `record_user_message_event`, a path this prompt never touches).
    let msg =
        Driver::stop_continuation_prompt("keep going".to_string(), Some("more ctx".to_string()));
    let Message::User { content } = &msg else {
        panic!("stop continuation must be a user-role message");
    };
    assert_eq!(
        crate::engine::message::extract_user_text(content),
        "keep going\nmore ctx"
    );
    assert_eq!(
        crate::engine::message::SubmissionOrigin::Internal.user_prompt_submit_source(),
        None,
        "the host-generated continuation origin must not fire userPromptSubmit"
    );

    // With no additionalContext the reason stands alone (no trailing newline).
    let msg = Driver::stop_continuation_prompt("just the reason".to_string(), None);
    let Message::User { content } = &msg else {
        panic!("stop continuation must be a user-role message");
    };
    assert_eq!(
        crate::engine::message::extract_user_text(content),
        "just the reason"
    );
}
