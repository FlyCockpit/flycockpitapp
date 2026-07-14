const INTERRUPT_REDACTION_FAILED: &str = "[redaction failed]";

fn redaction_failed_interrupt_decision_payload(
    interrupt_id: uuid::Uuid,
    decision: &crate::daemon::proto::InterruptDecision,
) -> serde_json::Value {
    let lines = decision
        .lines
        .iter()
        .map(|_| {
            serde_json::json!({
                "prompt": INTERRUPT_REDACTION_FAILED,
                "answer": INTERRUPT_REDACTION_FAILED,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "interrupt_id": interrupt_id,
        "decision": {
            "permission": decision.permission,
            "cancelled": decision.cancelled,
            "lines": lines,
        },
    })
}

#[cfg(test)]
mod interrupt_redaction_tests {
    use super::*;

    #[test]
    fn redaction_failure_payload_preserves_shape_without_raw_interrupt_text() {
        let interrupt_id = uuid::Uuid::new_v4();
        let decision = crate::daemon::proto::InterruptDecision {
            permission: true,
            cancelled: false,
            lines: vec![crate::daemon::proto::InterruptDecisionLine {
                prompt: "Run `cat /tmp/secret`?".to_string(),
                answer: "Allow once".to_string(),
            }],
        };

        let payload = redaction_failed_interrupt_decision_payload(interrupt_id, &decision);
        let serialized = payload.to_string();

        assert_eq!(payload["interrupt_id"], interrupt_id.to_string());
        assert_eq!(payload["decision"]["permission"], true);
        assert_eq!(payload["decision"]["cancelled"], false);
        assert_eq!(
            payload["decision"]["lines"][0]["prompt"],
            INTERRUPT_REDACTION_FAILED
        );
        assert_eq!(
            payload["decision"]["lines"][0]["answer"],
            INTERRUPT_REDACTION_FAILED
        );
        assert!(!serialized.contains("/tmp/secret"));
        assert!(!serialized.contains("Allow once"));
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_worker(
    session: Arc<Session>,
    locks: Arc<LockManager>,
    redact: Arc<RedactionTable>,
    model: Arc<Model>,
    model_override: Option<Arc<Model>>,
    thinking_params: Option<serde_json::Value>,
    project_root: PathBuf,
    mut work_rx: mpsc::Receiver<SessionWork>,
    event_tx: EventSender,
    redaction: SharedRedactionTable,
    live: Arc<LiveState>,
    interactive_clients: Arc<std::sync::atomic::AtomicUsize>,
    sandbox_notice_armed: Arc<AtomicBool>,
    env_overlay: Arc<RwLock<HashMap<String, String>>>,
    repair_required: Arc<RwLock<Option<proto::ResumeRepairState>>>,
    foreground: Arc<Mutex<LiveForegroundState>>,
    lsp: Arc<crate::daemon::lsp::LspManager>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    _global_bus: Option<EventSender>,
) {
    let session_id = session.id;

    // The layered `config.json` resolved once at session start.
    // The active LLM mode (implementation note) and the
    // default primary agent (the auto-router feature) both read it; the live
    // `/llm-mode` switch overrides the mode in place via `DriverControl`.
    let extended_cfg = crate::config::extended::load_for_cwd(&project_root);
    // Effective LLM mode = active model `mode` override → active provider
    // `mode` override → the persisted global `llm_mode`
    // (implementation note). Re-resolved here so a
    // model/provider that pins a mode takes effect at session start (and on a
    // `/model` change, which restarts the worker on the new active model). A
    // live `/llm-mode` toggle still overrides this for the running session via
    // `DriverControl::SetLlmMode`.
    let llm_mode = resolve_effective_llm_mode(&session, &project_root, extended_cfg.llm_mode);
    // Root primary: the session's stored active agent (so a resume restarts
    // on `Plan` after a `/plan` swap or whichever primary `Auto` handed off
    // to, `plan.md §4.6.d`), falling back to the configured default
    // (`Auto` unless the user pinned another) when it's unset/unknown.
    let root_agent_name = resolve_root_agent(session_id, &session.db, &extended_cfg);
    // The daemon's shared shutdown gate, captured before `model` is moved into
    // `spawn_args`. Reused when building model-comparison tandem (shadow)
    // models so a tandem request — itself a new provider round-trip — refuses
    // to dispatch once a drain begins (`model-comparison-tandem-
    // inference.md`).
    let shutdown_gate = model.shutdown_gate();
    let spawn_args = SpawnArgs {
        model,
        env_overlay: env_overlay.clone(),
        // The active model's resolved extra-request-body fragment
        // (implementation note) rides on every outbound
        // request via `ModelParams`; the rest are defaults as before.
        params: ModelParams {
            additional_params: thinking_params,
            // Top-level `prompt_cache_key` = session id for OpenAI-compatible
            // backends (prompt `prompt-caching-strategy.md`, decision 3),
            // held constant across the session so per-key prefix caching keeps
            // hitting. Only the main session worker's foreground model sets
            // it; background/utility models leave it `None`. The native
            // Anthropic arm ignores it (it caches per-block instead).
            prompt_cache_key: Some(session_id.to_string()),
            ..ModelParams::default()
        },
        cwd: project_root.clone(),
        session_short_id: session.short_id.clone(),
        model_system_prompt_snapshot: session.model_system_prompt_snapshot(),
        // The daemon root is always the user-facing interactive agent —
        // it gets the cross-session recall tools.
        interactive: true,
        llm_mode,
        // Plan-level model override (`plan-duplication-and-model-override.md`):
        // when set, the root and every spawned subagent run under it.
        model_override: model_override.clone(),
        delegation_model: None,
        delegated: false,
        delegation_recursion: builtin::configured_recursion_context(
            &extended_cfg.delegation,
            &root_agent_name,
            None,
        ),
        // Recursive-`Swarm` depth (GOALS §24): the `Swarm` root is depth 0;
        // each `bee` fan-out spawn advances it. The ceiling rides along so
        // the `spawn` description shows the remaining budget.
        swarm_depth: 0,
        swarm_max_depth: extended_cfg.swarm.max_depth,
        // The root primary carries no per-delegation grants — grants attach to
        // an individual `task` delegation, never to the root spawn.
        granted_tools: Vec::new(),
    };
    let root = Arc::new(
        builtin::load(&root_agent_name, &spawn_args)
            .unwrap_or_else(|_| builtin::build(&spawn_args)),
    );

    // Snapshot the resolved agent-guidance file body that just went into
    // the frozen system block (live instructions-file diff injection,
    // prompt `instructions-file-live-diff.md`). This is the start-of-
    // session baseline a later in-place edit is diffed against; the driver
    // checks it on every outbound request. Recomputed on each worker spawn
    // (fresh or resumed) because `builtin::build` re-composes the system
    // block from the current file each time.
    session.snapshot_guidance_baseline(&project_root);

    let (queue_update_tx, mut queue_update_rx) =
        mpsc::unbounded_channel::<Vec<crate::engine::message::QueuedUserMessage>>();
    let driver_input_queue = crate::engine::message::UserSubmissionQueue::new(queue_update_tx);
    let foreground_input_target = Arc::new(Mutex::new(crate::engine::message::QueueTarget::root(
        root.name.clone(),
    )));
    let (driver_control_tx, driver_control_rx) =
        mpsc::channel::<crate::engine::driver::DriverControl>(WORK_QUEUE_CAPACITY);
    let (engine_event_tx, mut engine_event_rx) = mpsc::channel::<TurnEvent>(WORK_QUEUE_CAPACITY);

    // Forward engine events → broadcast channel as proto::Event, and
    // maintain the live job/turn status (GOALS §17f) off the same
    // authoritative stream. These signals originate from the driver turn
    // loop (`ThinkingStarted` / `AgentIdle`) and the single `ScheduleAuthority`
    // (`ScheduleStarted` / `ScheduleCompleted`); the forwarder is the one seam they
    // all pass through, so updating here never duplicates the authority.
    let event_tx_for_forward = event_tx.clone();
    let event_tx_for_queue = event_tx.clone();
    let redaction_for_forward = redaction.clone();
    let redaction_for_queue = redaction.clone();
    let foreground_input_target_for_forward = foreground_input_target.clone();
    let foreground_for_forward = foreground.clone();
    let live_for_forward = live.clone();
    let sandbox_notice_armed_for_forward = sandbox_notice_armed.clone();
    // The lock authority + the interactive-client count, for the
    // `AgentIdle`-with-zero-clients release edge
    // (implementation note). When a turn finishes and no
    // interactive client is attached, the session's locks are released here —
    // the second of the two edges (the first is the last-detach drop above).
    let locks_for_forward = locks.clone();
    let interactive_clients_for_forward = interactive_clients.clone();
    let forward = tokio::spawn(async move {
        let send_event = |ev: proto::Event| {
            // Per-session de-dupe (§6.5): the engine emits `SandboxUnavailable`
            // on every refused `bash` (the verdict is process-lifetime-cached,
            // so it recurs), but the user needs only one persistent notice.
            // Forward the first; drop the recurring duplicates. `set_sandbox`
            // re-arms the latch when the user toggles `/sandbox`.
            if matches!(ev, proto::Event::SandboxUnavailable { .. })
                && !forward_sandbox_unavailable(&sandbox_notice_armed_for_forward)
            {
                return;
            }
            match &ev {
                proto::Event::ThinkingStarted { .. } => {
                    live_for_forward.processing.store(true, Ordering::Relaxed);
                }
                proto::Event::AgentIdle { .. } => {
                    live_for_forward.processing.store(false, Ordering::Relaxed);
                    live_for_forward
                        .tool_running
                        .store(0, Ordering::Relaxed);
                    // Last-detach-while-idle edge, idle side
                    // (implementation note): the turn just finished, so if no
                    // interactive client is attached, release this session's locks now.
                    if interactive_clients_for_forward.load(Ordering::SeqCst) == 0 {
                        schedule_session_locks_unattended(
                            locks_for_forward.clone(),
                            interactive_clients_for_forward.clone(),
                            live_for_forward.clone(),
                            session_id,
                            "idle with no attached clients",
                        );
                        schedule_session_container_release(
                            interactive_clients_for_forward.clone(),
                            live_for_forward.clone(),
                            session_id,
                            "idle with no attached clients",
                        );
                    }
                }
                proto::Event::ScheduleStarted { .. } => {
                    live_for_forward
                        .active_schedules
                        .fetch_add(1, Ordering::Relaxed);
                }
                proto::Event::ScheduleCompleted { .. } => {
                    // Saturating: never underflow if a completion is ever seen without its start.
                    let _ = live_for_forward.active_schedules.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |n| Some(n.saturating_sub(1)),
                    );
                }
                proto::Event::ToolStart { .. } => {
                    live_for_forward
                        .tool_running
                        .fetch_add(1, Ordering::Relaxed);
                }
                proto::Event::ToolEnd { .. } | proto::Event::ToolError { .. } => {
                    let _ = live_for_forward.tool_running.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |n| Some(n.saturating_sub(1)),
                    );
                }
                _ => {}
            }
            // `send` returns `Err` only when there are no subscribers — that's fine.
            send_current_event(&event_tx_for_forward, &redaction_for_forward, ev);
        };

        let mut coalescer = StreamDeltaCoalescer::default();
        loop {
            if let Some(deadline) = coalescer.deadline() {
                tokio::select! {
                    maybe_event = engine_event_rx.recv() => {
                        let Some(event) = maybe_event else {
                            for ev in coalescer.flush() {
                                send_event(ev);
                            }
                            break;
                        };
                        update_live_foreground(
                            &foreground_for_forward,
                            &foreground_input_target_for_forward,
                            &event,
                        );
                        for ev in proto::turn_event_to_proto(event, session_id) {
                            for ready in coalescer.push(ev) {
                                send_event(ready);
                            }
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        for ev in coalescer.flush() {
                            send_event(ev);
                        }
                    }
                }
            } else {
                let Some(event) = engine_event_rx.recv().await else {
                    break;
                };
                update_live_foreground(
                    &foreground_for_forward,
                    &foreground_input_target_for_forward,
                    &event,
                );
                for ev in proto::turn_event_to_proto(event, session_id) {
                    for ready in coalescer.push(ev) {
                        send_event(ready);
                    }
                }
            }
        }
    });
    let queue_forward = tokio::spawn(async move {
        while let Some(queue) = queue_update_rx.recv().await {
            send_current_event(
                &event_tx_for_queue,
                &redaction_for_queue,
                proto::Event::QueueUpdated {
                    session_id,
                    queue: queue.into_iter().map(queue_item_to_proto).collect(),
                },
            );
        }
    });

    // Build the driver, then capture its async-job command sender (GOALS
    // §22) so a human-initiated `/schedule cancel` reaches the single
    // authority before moving the driver into its task.
    let max_concurrent_schedules = max_concurrent_schedules_for(&project_root);
    let mut driver = Driver::with_max_schedules(
        session.clone(),
        locks.clone(),
        redact.clone(),
        project_root.clone(),
        root,
        max_concurrent_schedules,
    );
    // Propagate any plan-level model override to the whole delegation tree
    // (`plan-duplication-and-model-override.md`): the root already runs under
    // it (loaded with the override `SpawnArgs`); this carries it down to
    // delegated subagents whose frontmatter would otherwise win.
    driver.set_model_override(model_override);
    // Recursive-`Swarm` knobs (GOALS §24): the depth ceiling + the global
    // concurrency cap on simultaneously-running `bee` workers, enforced
    // centrally by the single async-job authority.
    driver.set_swarm_config(
        extended_cfg.swarm.max_depth,
        extended_cfg.swarm.max_concurrency,
    );
    driver.set_lsp_manager(lsp);
    if let Some(scheduler) = resource_scheduler {
        driver.set_resource_scheduler(scheduler);
    }
    let job_cmd_tx = driver.job_command_sender();
    // Capture the driver's cancel handle (GOALS §3a) before moving it into
    // its task, so a user ctrl+c (`SessionWork::Cancel`) can abort the
    // in-flight user-message run — aborting the streaming inference and
    // killing any running `bash` subprocess.
    let cancel_handle = driver.cancel_handle();

    // Interrupt wakeup hub (GOALS §3b): wire the driver's tool calls to
    // the client event fan-out so the `question` tool can raise an
    // interrupt and block on the answer. We keep the same `Arc` so the
    // `ResolveInterrupt` handler below can wake the blocked tool. The
    // hub must be installed before the driver loop starts.
    let interrupts = Arc::new(crate::engine::interrupt::InterruptHub::new(
        event_tx.clone(),
        redaction.clone(),
        interactive_clients,
        session.db.clone(),
        session_id,
    ));
    driver.set_interrupt_hub(interrupts.clone());

    // Command/path approval driver (sandboxing part 2). Built on the
    // session's grant store + the client-wired interrupt hub above, so a
    // `bash` run-fail-escalate or a native out-of-boundary path access
    // raises a prompt that fans out to the attached client exactly like a
    // `question`. The driver threads it into every `ToolCtx`. Installed
    // after the hub (the approver captures the same `Arc`). The active
    // agent for the prompt is the foreground primary agent at spawn time;
    // a delegated builder shares the same approver via the `ToolCtx`
    // `Arc`, so grants persist across the delegation tree.
    let grant_store = crate::approval::store::GrantStore::new(
        session.db.clone(),
        session_id,
        project_root.clone(),
    );
    let approver = Arc::new(crate::approval::Approver::new(
        grant_store,
        session.db.clone(),
        session_id,
        initial_active_agent(&extended_cfg),
        interrupts.clone(),
    ));
    driver.set_approver(approver);

    // Loop-guard threshold (GOALS §1/§12) from the layered config, same
    // discovery the jobs cap uses. Clamped to ≥ 2 by the setter.
    driver.set_loop_guard_threshold(loop_guard_threshold_for(&project_root));
    driver.set_max_primary_rounds(max_primary_rounds_for(&project_root));
    driver.set_allow_unbounded_schedule_loops(extended_cfg.schedule.allow_unbounded_loops);

    // Resume rehydration (implementation note): on a
    // fresh worker for a session that has prior recorded turns (a daemon
    // restart, an `/exit` + `/resume`, or resuming a `/compact` successor
    // that already had turns), rebuild the root agent's model-bound history
    // from the durable transcript + prune ledger so the next message
    // continues the conversation in its PRUNED form rather than starting
    // fresh. Automatic — only when the root frame has no live in-memory
    // history (which a freshly-built driver never does). A hard rebuild
    // failure (corrupt/unpairable rows) is surfaced as a clear error rather
    // than sending a malformed or silently-fresh context (priority #1).
    let (_, _, active_wire_api) = active_wire_api_for_session(&session, &project_root);
    let responses_strict_replay = matches!(
        active_wire_api,
        crate::config::providers::WireApi::Responses
    );
    let rehydrate_policy = if responses_strict_replay {
        crate::engine::rehydrate::RehydratePolicy::strict()
    } else {
        crate::engine::rehydrate::RehydratePolicy::heal()
    };
    let rehydrated = match driver
        .rehydrate_root_if_empty_with_policy(&root_agent_name, rehydrate_policy)
    {
        Ok(r) => r,
        Err(e) => {
            if responses_strict_replay
                && let Some(repair) =
                    e.downcast_ref::<crate::engine::rehydrate::RehydrateRepairRequired>()
            {
                let state = build_resume_repair_state(&session, &project_root, repair);
                tracing::error!(
                    session_id = %session_id,
                    failure_kind = %state.failure_kind,
                    failing_tool_call_ids = ?state.failing_tool_call_ids,
                    "resume rehydration requires explicit Responses repair before provider replay"
                );
                {
                    let mut slot = repair_required
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    *slot = Some(state.clone());
                }
                let label = if state.short_id.is_empty() {
                    state.session_id.to_string()
                } else {
                    state.short_id.clone()
                };
                send_current_event(
                    &event_tx,
                    &redaction,
                    proto::Event::Notice {
                        session_id,
                        text: format!(
                            "Resume repair required for {label}: {}. The transcript is open read-only; fork from the last valid turn, export a debug bundle, or explicitly repair before continuing.",
                            state.detail
                        ),
                    },
                );
            } else {
                tracing::error!(error = %e, session_id = %session_id,
                    "resume rehydration failed; the transcript could not be rebuilt into a \
                     provider-valid conversation");
                send_current_event(
                    &event_tx,
                    &redaction,
                    proto::Event::Notice {
                        session_id,
                        text: format!(
                            "Resume failed: the prior conversation could not be rebuilt ({e}). \
                         Start a new session to continue."
                        ),
                    },
                );
            }
            None
        }
    };
    if let Some(r) = &rehydrated
        && r.ledger_fallback
    {
        // Continuity preserved, just less pruned — surface a non-fatal
        // warning (never a silent drop to a fresh context).
        send_current_event(
            &event_tx,
            &redaction,
            proto::Event::Notice {
                session_id,
                text: "Resume: the prune ledger was inconsistent; restored the full \
                   (unpruned) prior context instead."
                    .to_string(),
            },
        );
    }
    if let Some(r) = &rehydrated
        && !r.heals.is_empty()
    {
        // The heal pass stubbed/dropped unpairable rows so the prior
        // conversation could be rebuilt instead of dead-ending — degrade
        // visibly (alongside any ledger-fallback notice above), never a
        // silent alteration of the resumed context.
        let n = r.heals.len();
        send_current_event(
            &event_tx,
            &redaction,
            proto::Event::Notice {
                session_id,
                text: format!(
                    "Resume: {n} incomplete tool call(s) were stubbed to rebuild the conversation."
                ),
            },
        );
    }

    match session.db.list_open_interrupts(session_id) {
        Ok(rows) => {
            for row in rows {
                match (row.state, row.parked.is_some()) {
                    (crate::db::needs_attention::InterruptState::Open, true) => {
                        if let Err(error) = session.db.park_interrupt(row.interrupt_id) {
                            tracing::warn!(
                                %error,
                                interrupt_id = %row.interrupt_id,
                                "parking crash-surviving interrupt failed"
                            );
                        }
                    }
                    (crate::db::needs_attention::InterruptState::Open, false)
                    | (crate::db::needs_attention::InterruptState::Parked, false) => {
                        if let Err(error) = session.db.mark_interrupt_interrupted(row.interrupt_id)
                        {
                            tracing::warn!(
                                %error,
                                interrupt_id = %row.interrupt_id,
                                "marking unrecoverable interrupt failed"
                            );
                        }
                        send_current_event(
                            &event_tx,
                            &redaction,
                            proto::Event::Notice {
                                session_id,
                                text: format!(
                                    "Interrupted request {}: missing replay payload.",
                                    row.interrupt_id
                                ),
                            },
                        );
                    }
                    _ => {}
                }
            }
        }
        Err(error) => {
            tracing::warn!(%error, "interrupt reconciliation failed");
        }
    }

    // Seed-tool re-execution (`/compact` handoff, T6.e): if this session
    // was created by `/compact`, its derived seed-tool plan was persisted
    // keyed by this session id. Drain it and dispatch the calls (read-only
    // / idempotent only) into the fresh agent's initial context *before*
    // the first inference — re-executed, never replayed from a stale
    // transcript. Done synchronously before the driver loop starts so it
    // can never race the first user message. Best-effort.
    //
    // MUTUALLY EXCLUSIVE with rehydration: seed re-execution is for a
    // *fresh* successor's first inference. When this worker rehydrated a
    // successor that has ALREADY had turns, the full pruned context is
    // rebuilt from its transcript — re-running seed tools too would
    // double-seed. So skip seeds when rehydration produced a history; the
    // seed rows are taken (drained) regardless so they never re-fire on a
    // later resume (idempotent).
    match session.db.take_seed_tools(session_id) {
        Ok(seeds)
            if !seeds.is_empty()
                && rehydrated.is_none()
                && repair_required
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .is_none() =>
        {
            driver.run_seed_tools(&seeds, &engine_event_tx).await;
        }
        Ok(_) => {}
        Err(error) => {
            log_seed_tool_drain_failed(session_id, &error);
        }
    }

    // Session-only redaction source overrides (`/toggle-redaction`). The
    // base config is reloaded at every turn boundary so dotenv/settings/SSH
    // changes made after session start are picked up before the next provider
    // request; these overrides preserve any live toggles without writing them
    // to disk.
    let mut redaction_overrides = RedactionSourceOverrides::default();
    let mut unsupported_redaction_notified: HashSet<PathBuf> = HashSet::new();

    // Spawn the driver loop.
    let driver_queue_for_loop = driver_input_queue.clone();
    let mut driver_handle = tokio::spawn(async move {
        match driver
            .run_main_loop(driver_queue_for_loop, driver_control_rx, &engine_event_tx)
            .await
        {
            Ok(()) => DriverOutcome::Ok,
            Err(e) => {
                let error = format!("{e:#}");
                tracing::error!(error = %error, "driver loop terminated with error");
                DriverOutcome::Err(error)
            }
        }
    });

    // Main work loop.
    let mut driver_failed = false;
    let mut driver_joined = false;
    let stop = loop {
        let work = tokio::select! {
            biased;
            work = work_rx.recv() => work,
            outcome = &mut driver_handle => {
                driver_joined = true;
                let outcome = driver_join_outcome(outcome);
                if let Some(error) = outcome.failure_error() {
                    emit_session_driver_failed_once(
                        &event_tx,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                        error.to_string(),
                    );
                    break WorkerStop::DriverFailed;
                }
                break WorkerStop::DriverExited;
            }
        };
        let Some(work) = work else {
            break WorkerStop::WorkerStopped;
        };
        match work {
            SessionWork::UserMessage {
                submission,
                respond_to,
            } => {
                if let Some(state) = repair_required
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone()
                {
                    let ids = if state.failing_tool_call_ids.is_empty() {
                        "unknown tool id".to_string()
                    } else {
                        state.failing_tool_call_ids.join(", ")
                    };
                    send_current_event(
                        &event_tx,
                        &redaction,
                        proto::Event::Notice {
                            session_id,
                            text: format!(
                                "Read-only resume: refusing to send model context until Responses repair is resolved ({}: {}). Use the resume repair dialog, fork, or export a debug bundle.",
                                state.failure_kind, ids
                            ),
                        },
                    );
                    let _ = respond_to.send((
                        proto::QueueItem {
                            id: Uuid::nil(),
                            status: proto::QueueItemStatus::Folding,
                            text: String::new(),
                            target: proto::QueueTarget::default(),
                        },
                        Vec::new(),
                    ));
                    continue;
                }
                // Lazy persistence (session-id-display-and-lazy-persist): the
                // first user message is what commits the `sessions` row.
                // Flush it *before* `touch()` and before the driver runs, so
                // the row exists ahead of any dependent write (tool_calls,
                // inference_calls, locks). A persist failure aborts the
                // message rather than letting dependents reference a missing
                // row.
                match session.persist_if_needed() {
                    Ok(_) => {}
                    Err(e) => {
                        let error = format!("{e:#}");
                        tracing::error!(error = %error, session_id = %session_id,
                            "persisting session on first message failed; dropping message");
                        send_current_event(
                            &event_tx,
                            &redaction,
                            proto::Event::SessionPersistFailed { session_id, error },
                        );
                        let _ = respond_to.send((
                            proto::QueueItem {
                                id: Uuid::nil(),
                                status: proto::QueueItemStatus::Folding,
                                text: String::new(),
                                target: proto::QueueTarget::default(),
                            },
                            Vec::new(),
                        ));
                        continue;
                    }
                }
                if let Err(e) = session.touch() {
                    tracing::warn!(error = %e, "session touch failed");
                }
                let session_env = env_overlay
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                if !refresh_redaction_for_turn(
                    &session,
                    session_id,
                    &project_root,
                    &redaction_overrides,
                    &mut unsupported_redaction_notified,
                    &redaction,
                    &event_tx,
                    &driver_control_tx,
                    &session_env,
                )
                .await
                {
                    emit_session_driver_failed_once(
                        &event_tx,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                        "driver control channel closed".to_string(),
                    );
                    let _ = respond_to.send((
                        proto::QueueItem {
                            id: Uuid::nil(),
                            status: proto::QueueItemStatus::Folding,
                            text: String::new(),
                            target: proto::QueueTarget::default(),
                        },
                        Vec::new(),
                    ));
                    break WorkerStop::DriverFailed;
                }
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::RefreshActiveModel,
                    &event_tx,
                    &redaction,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    let _ = respond_to.send((
                        proto::QueueItem {
                            id: Uuid::nil(),
                            status: proto::QueueItemStatus::Folding,
                            text: String::new(),
                            target: proto::QueueTarget::default(),
                        },
                        Vec::new(),
                    ));
                    break WorkerStop::DriverFailed;
                }
                let max_rounds = max_primary_rounds_for(&project_root);
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::SetMaxPrimaryRounds { max_rounds },
                    &event_tx,
                    &redaction,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    let _ = respond_to.send((
                        proto::QueueItem {
                            id: Uuid::nil(),
                            status: proto::QueueItemStatus::Folding,
                            text: String::new(),
                            target: proto::QueueTarget::default(),
                        },
                        Vec::new(),
                    ));
                    break WorkerStop::DriverFailed;
                }
                let target = foreground_input_target
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                let (id, snapshot) = driver_input_queue.push(*submission, target).await;
                let queue: Vec<proto::QueueItem> =
                    snapshot.into_iter().map(queue_item_to_proto).collect();
                let item =
                    queue
                        .iter()
                        .find(|item| item.id == id)
                        .cloned()
                        .unwrap_or(proto::QueueItem {
                            id,
                            status: proto::QueueItemStatus::Folding,
                            text: String::new(),
                            target: proto::QueueTarget::default(),
                        });
                let _ = respond_to.send((item, queue));
            }
            SessionWork::SteerDelegation {
                task_call_id,
                label,
                message,
                origin_principal,
                respond_to,
            } => {
                let result = steer_delegation_side_channel(
                    &session,
                    &redact,
                    task_call_id,
                    label,
                    message,
                    origin_principal,
                );
                let _ = respond_to.send(result);
            }
            SessionWork::RemoveQueuedUserMessage {
                queue_item_id,
                respond_to,
            } => {
                let (result, snapshot) = driver_input_queue.remove(queue_item_id).await;
                let reason = remove_reason_to_proto(result);
                let _ = respond_to.send(proto::RemoveQueuedUserMessageResult {
                    applied: matches!(reason, proto::RemoveQueuedUserMessageReason::Removed),
                    reason,
                    removed_item: None,
                    queue: snapshot.into_iter().map(queue_item_to_proto).collect(),
                });
            }
            SessionWork::RemoveNewestQueuedUserMessage {
                target_id,
                respond_to,
            } => {
                let target_id = target_id.unwrap_or_else(|| {
                    foreground_input_target
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .id
                        .clone()
                });
                let (result, removed_item, snapshot) =
                    driver_input_queue.remove_newest_for(&target_id).await;
                let reason = remove_reason_to_proto(result);
                let _ = respond_to.send(proto::RemoveQueuedUserMessageResult {
                    applied: matches!(reason, proto::RemoveQueuedUserMessageReason::Removed),
                    reason,
                    removed_item: removed_item.map(queue_item_to_proto),
                    queue: snapshot.into_iter().map(queue_item_to_proto).collect(),
                });
            }
            SessionWork::RemoveEditableQueuedUserMessages {
                target_id,
                respond_to,
            } => {
                let target_id = target_id.unwrap_or_else(|| {
                    foreground_input_target
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .id
                        .clone()
                });
                let (result, removed_items, snapshot) =
                    driver_input_queue.remove_editable_for(&target_id).await;
                let reason = remove_reason_to_proto(result);
                let _ = respond_to.send(proto::RemoveQueuedUserMessagesResult {
                    applied: !removed_items.is_empty(),
                    reason,
                    removed_items: removed_items.into_iter().map(queue_item_to_proto).collect(),
                    queue: snapshot.into_iter().map(queue_item_to_proto).collect(),
                });
            }
            SessionWork::Cancel => {
                // User ctrl+c (`CancelTurn`). Fire the in-flight run's
                // cancellation token: the driver's `turn` aborts the
                // streaming inference (returning an `InferenceCancelled`
                // sentinel that unwinds the run cleanly), and any running
                // `bash` subprocess is killed via its process group. Safe
                // and idempotent at idle / mid-cancel — `CancelHandle::cancel`
                // is a no-op when no run is in flight. The driver then emits
                // `AgentIdle`, clearing the TUI's busy state.
                tracing::info!(session_id = %session_id, "cancel requested");
                cancel_handle.cancel();
            }
            SessionWork::ResolveInterrupt {
                interrupt_id,
                response,
            } => {
                let row = session.db.get_interrupt(interrupt_id).ok().flatten();
                let was_active = session
                    .db
                    .list_open_interrupts(session_id)
                    .ok()
                    .and_then(|open| open.first().map(|row| row.interrupt_id))
                    == Some(interrupt_id);
                let decision = row.as_ref().map(|row| {
                    crate::db::needs_attention::summarize_interrupt_decision(row, &response)
                });
                if let Some(row) = row.as_ref()
                    && row.state == crate::db::needs_attention::InterruptState::Parked
                {
                    let claimed = match session
                        .db
                        .begin_parked_interrupt_execution(interrupt_id, &response)
                    {
                        Ok(claimed) => claimed,
                        Err(error) => {
                            tracing::warn!(%error, %interrupt_id, "claiming parked interrupt failed");
                            false
                        }
                    };
                    if !claimed {
                        interrupts.emit_queue_state();
                        continue;
                    }
                    let Some(payload) = row.parked.clone() else {
                        let _ = session.db.mark_interrupt_interrupted(interrupt_id);
                        send_current_event(
                            &event_tx,
                            &redaction,
                            proto::Event::Notice {
                                session_id,
                                text: format!(
                                    "Interrupted parked request {interrupt_id}: missing replay payload."
                                ),
                            },
                        );
                        interrupts.emit_queue_state();
                        continue;
                    };
                    let (respond_to, replay_result_rx) = tokio::sync::oneshot::channel();
                    let replay_result = if driver_control_tx
                        .send(crate::engine::driver::DriverControl::ReplayParkedInterrupt {
                            interrupt_id,
                            payload,
                            response: response.clone(),
                            respond_to,
                        })
                        .await
                        .is_ok()
                    {
                        replay_result_rx
                            .await
                            .unwrap_or_else(|error| Err(format!("driver replay response dropped: {error}")))
                    } else {
                        Err("driver is not available for parked interrupt replay".to_string())
                    };
                    if let Err(error) = replay_result {
                        let _ = session.db.mark_interrupt_interrupted(interrupt_id);
                        tracing::warn!(%error, %interrupt_id, "parked interrupt replay failed");
                        send_current_event(
                            &event_tx,
                            &redaction,
                            proto::Event::Notice {
                                session_id,
                                text: format!(
                                    "Interrupted parked request {interrupt_id}: {error}"
                                ),
                            },
                        );
                        interrupts.emit_queue_state();
                        continue;
                    }
                    if let Err(error) = session.db.complete_executing_interrupt(interrupt_id) {
                        tracing::warn!(%error, %interrupt_id, "completing parked interrupt failed");
                    }
                    let seq = decision.as_ref().and_then(|decision| {
                        let data = serde_json::json!({
                            "interrupt_id": interrupt_id,
                            "decision": decision,
                        });
                        let scrubbed =
                            crate::daemon::current_redaction(&redaction).scrub(&data.to_string());
                        let redacted_data =
                            serde_json::from_str(&scrubbed).unwrap_or_else(|error| {
                                tracing::warn!(
                                    %error,
                                    %interrupt_id,
                                    "interrupt decision redaction produced invalid JSON; persisting fail-closed placeholder"
                                );
                                redaction_failed_interrupt_decision_payload(interrupt_id, decision)
                            });
                        session
                            .record_event(
                                crate::db::session_log::SessionEventKind::InterruptDecision,
                                None,
                                None,
                                &redacted_data,
                            )
                            .map_err(|error| {
                                tracing::warn!(%error, %interrupt_id, "recording interrupt decision failed");
                                error
                            })
                            .ok()
                    });
                    send_current_event(
                        &event_tx,
                        &redaction,
                        proto::Event::InterruptResolved {
                            session_id,
                            interrupt_id,
                            decision,
                            seq,
                        },
                    );
                    if was_active {
                        interrupts.emit_active_from_db();
                    } else {
                        interrupts.emit_queue_state();
                    }
                    continue;
                }
                if let Err(e) = session.db.resolve_interrupt(interrupt_id, &response) {
                    tracing::warn!(error = %e, %interrupt_id, "resolve_interrupt failed");
                }
                let seq = decision.as_ref().and_then(|decision| {
                    let data = serde_json::json!({
                        "interrupt_id": interrupt_id,
                        "decision": decision,
                    });
                    let scrubbed =
                        crate::daemon::current_redaction(&redaction).scrub(&data.to_string());
                    let redacted_data = serde_json::from_str(&scrubbed).unwrap_or_else(|error| {
                        tracing::warn!(
                            %error,
                            %interrupt_id,
                            "interrupt decision redaction produced invalid JSON; persisting fail-closed placeholder"
                        );
                        redaction_failed_interrupt_decision_payload(interrupt_id, decision)
                    });
                    session
                        .record_event(
                            crate::db::session_log::SessionEventKind::InterruptDecision,
                            None,
                            None,
                            &redacted_data,
                        )
                        .map_err(|error| {
                            tracing::warn!(%error, %interrupt_id, "recording interrupt decision failed");
                            error
                        })
                        .ok()
                });
                send_current_event(
                    &event_tx,
                    &redaction,
                    proto::Event::InterruptResolved {
                        session_id,
                        interrupt_id,
                        decision,
                        seq,
                    },
                );
                // Engine-side wakeup (GOALS §3b): hand the resolution to
                // whatever tool call is blocked on this interrupt id (the
                // `question` tool). `false` just means nobody was blocked
                // locally — e.g. a `schedule` needs-attention nudge — and the
                // DB row update above is the only effect.
                interrupts.resolve(interrupt_id, response);
                if was_active {
                    interrupts.emit_active_from_db();
                } else {
                    interrupts.emit_queue_state();
                }
            }
            SessionWork::RepairResume { respond_to } => {
                let Some(state) = repair_required
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone()
                else {
                    let _ = respond_to.send(Err(
                        "no Responses resume repair is pending for this session".to_string(),
                    ));
                    continue;
                };
                let (driver_respond_to, driver_response_rx) = oneshot::channel();
                if driver_control_tx
                    .send(crate::engine::driver::DriverControl::RepairResume {
                        root_agent: root_agent_name.clone(),
                        respond_to: driver_respond_to,
                    })
                    .await
                    .is_err()
                {
                    let message = "driver control channel closed".to_string();
                    emit_session_driver_failed_once(
                        &event_tx,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                        message.clone(),
                    );
                    let _ = respond_to.send(Err(message));
                    break WorkerStop::DriverFailed;
                }
                match driver_response_rx.await {
                    Ok(Ok(heal_count)) => {
                        {
                            let mut slot = repair_required
                                .write()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            *slot = None;
                        }
                        let text = format!(
                            "Responses resume repair approved: synthetic resume heal applied to {heal_count} tool call(s)."
                        );
                        if let Err(error) = session.record_event(
                            crate::db::session_log::SessionEventKind::UserNote,
                            Some(&root_agent_name),
                            None,
                            &serde_json::json!({
                                "text": text,
                                "resume_repair": {
                                    "approved": true,
                                    "failure_kind": state.failure_kind,
                                    "failing_tool_call_ids": state.failing_tool_call_ids,
                                    "provider": state.provider,
                                    "model": state.model,
                                    "wire_api": state.wire_api,
                                    "synthetic_heal_count": heal_count,
                                    "detail": state.detail,
                                }
                            }),
                        ) {
                            tracing::warn!(%error, %session_id, "record resume repair provenance failed");
                        }
                        send_current_event(
                            &event_tx,
                            &redaction,
                            proto::Event::Notice { session_id, text },
                        );
                        let _ = respond_to.send(Ok(()));
                    }
                    Ok(Err(message)) => {
                        let _ = respond_to
                            .send(Err(format!("explicit Responses repair failed: {message}")));
                    }
                    Err(error) => {
                        let _ = respond_to
                            .send(Err(format!("explicit Responses repair failed: {error}")));
                    }
                }
            }
            SessionWork::SetActiveModel { provider, model } => {
                // Mid-session model switch (implementation note):
                // route the new `(provider, model)` to the running driver, which
                // rebuilds the active primary under the new model at the idle
                // boundary so the next request routes there. The driver persists
                // the session's active-model row only on a successful build (and
                // surfaces a loud `Notice` on an unconfigured/bad target, keeping
                // the current model active), so config + live routing never
                // diverge — the worker no longer pre-commits it here.
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::SetActiveModel { provider, model },
                    &event_tx,
                    &redaction,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::SetAgent { name } => {
                // Persist the active-agent choice so a resume restarts on it,
                // then swap the live primary in place at the idle boundary
                // (`/plan` → `Plan`, `/build` → `Build`, `plan.md §4.6.d`).
                if let Err(e) = session.set_active_agent(&name) {
                    tracing::warn!(error = %e, "set_active_agent failed");
                }
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::SwapPrimary { name },
                    &event_tx,
                    &redaction,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::SetLlmMode { mode } => {
                // Resolve toggle against the current config value (the
                // single source of truth shared with `/settings` + the
                // config file), persist the resolved value so a resume keeps
                // it, then route the explicit mode to the driver to rebuild
                // the root agent in place.
                let current = crate::config::extended::load_for_cwd(&project_root).llm_mode;
                let resolved = mode.unwrap_or_else(|| current.cycled());
                if let Err(e) = persist_llm_mode(&project_root, resolved) {
                    tracing::warn!(error = %e, "persisting llm_mode failed");
                }
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::SetLlmMode {
                        mode: Some(resolved),
                    },
                    &event_tx,
                    &redaction,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::SetSessionLlmMode { mode } => {
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::SetLlmMode { mode: Some(mode) },
                    &event_tx,
                    &redaction,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::SetDelegationRecursion {
                enabled,
                default_depth,
            } => {
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::SetDelegationRecursion {
                        enabled,
                        default_depth,
                    },
                    &event_tx,
                    &redaction,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::SetRedaction {
                scan_environment,
                scan_dotenv,
                scan_ssh_keys,
            } => {
                // `/toggle-redaction`: mutate the session's in-memory
                // effective `RedactConfig`, rebuild the newly discoverable
                // redaction table, then union it into the session's
                // accumulated egress table. Session-only — never persisted.
                // Turning a source off stops future discovery; it never
                // removes values already known in this session.
                //
                // Prompt-cache note (`prompt-caching-strategy.md`): changing
                // what's redacted can change the scrubbed bytes of the cached
                // prefix, so the *next* outbound request after a toggle is a
                // one-time cache re-warm. This is accepted — the toggle is a
                // deliberate, rare user action; `scrub()` output is otherwise
                // deterministic/byte-stable turn-to-turn (see
                // `redact::tests::scrub_is_deterministic_within_a_session`),
                // so it never silently varies the prefix between turns.
                let mut effective_redact =
                    crate::config::extended::load_for_cwd(&project_root).redact;
                redaction_overrides.apply_to(&mut effective_redact);
                if let Some(v) = scan_environment {
                    redaction_overrides.scan_environment = Some(v);
                    effective_redact.scan_environment = v;
                }
                if let Some(v) = scan_dotenv {
                    redaction_overrides.scan_dotenv = Some(v);
                    effective_redact.scan_dotenv = v;
                }
                if let Some(v) = scan_ssh_keys {
                    redaction_overrides.scan_ssh_keys = Some(v);
                    effective_redact.scan_ssh_keys = v;
                }
                let session_env = env_overlay
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                match crate::redact::RedactionTable::build_with_env(
                    &effective_redact,
                    &project_root,
                    &session_env,
                ) {
                    Ok(new_table) => {
                        let table = match current_redaction(&redaction).union(&new_table) {
                            Ok(table) => Arc::new(table),
                            Err(error) => {
                                tracing::warn!(error = %error, "unioning redaction table failed");
                                Arc::new(new_table)
                            }
                        };
                        set_current_redaction(&redaction, table.clone());
                        if let Err(error) = session.persist_redaction_table(&table) {
                            tracing::warn!(error = %error, %session_id, "persisting redaction table failed");
                        }
                        for path in table.unsupported_files() {
                            if unsupported_redaction_notified.insert(path.clone()) {
                                send_current_event(
                                    &event_tx,
                                    &redaction,
                                    proto::Event::Notice {
                                        session_id,
                                        text: format!(
                                            "`{}` is an unsupported format; redaction for this file will not work",
                                            path.display()
                                        ),
                                    },
                                );
                            }
                        }
                        if !send_driver_control_or_fail(
                            &driver_control_tx,
                            crate::engine::driver::DriverControl::SetRedaction {
                                table,
                                scan_environment,
                                scan_dotenv,
                                scan_ssh_keys,
                            },
                            &event_tx,
                            &redaction,
                            session_id,
                            &mut driver_failed,
                        )
                        .await
                        {
                            break WorkerStop::DriverFailed;
                        }
                        send_current_event(
                            &event_tx,
                            &redaction,
                            proto::Event::RedactionState {
                                session_id,
                                scan_environment: effective_redact.scan_environment,
                                scan_dotenv: effective_redact.scan_dotenv,
                                scan_ssh_keys: effective_redact.scan_ssh_keys,
                            },
                        );
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "rebuilding redaction table failed");
                    }
                }
            }
            SessionWork::SetPreflight { enabled } => {
                // `/preflight`: route the override to the driver, which holds
                // it (precedence over config), resolves the toggle against its
                // authoritative current value, and broadcasts the resulting
                // state via `TurnEvent::PreflightState`. Session-only — never
                // persisted (mirrors `/toggle-redaction`).
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::SetPreflight { enabled },
                    &event_tx,
                    &redaction,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::SetTrustedOnly { enabled } => {
                let target = enabled.unwrap_or_else(|| session.toggle_trusted_only());
                if enabled.is_some() {
                    session.set_trusted_only(target);
                }
                send_current_event(
                    &event_tx,
                    &redaction,
                    proto::Event::TrustedOnlyState {
                        session_id,
                        enabled: target,
                    },
                );
            }
            SessionWork::SetTandemModels { models } => {
                // `/model-comparison`: build a completion model for each
                // selected `(provider, model)` from the already-configured
                // providers, route them to the driver's in-memory tandem set,
                // and broadcast the resulting state (+ a one-line token-burn
                // warning when non-empty). Empty disables the feature.
                // Session-only — never persisted (mirrors `/toggle-redaction`).
                let (_, providers_cfg) = crate::auto_title::load_configs_for(&project_root);
                // Reuse the session redaction table the registry already
                // built successfully. Tandem models must never install an
                // empty fail-open table after a redaction rebuild error.
                let tandem_redact = redact.clone();
                let active = (session.active_provider(), session.active_model());
                let mut targets: Vec<crate::engine::schedule::TandemTarget> = Vec::new();
                for (provider, model_id) in &models {
                    // Defensive: never shadow the active model itself (the
                    // client already excludes it; no self-shadowing).
                    if active.0.as_deref() == Some(provider.as_str())
                        && active.1.as_deref() == Some(model_id.as_str())
                    {
                        continue;
                    }
                    let session_env = env_overlay
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    match crate::engine::model::Model::for_provider_with_env_trusted_only(
                        &providers_cfg,
                        provider,
                        model_id,
                        tandem_redact.clone(),
                        session.trusted_only_flag(),
                        |name| session_env.get(name).cloned(),
                    ) {
                        Ok(m) => {
                            let m = m.with_shutdown_gate(shutdown_gate.clone());
                            targets.push(crate::engine::schedule::TandemTarget {
                                provider: provider.clone(),
                                model: model_id.clone(),
                                handle: Arc::new(m),
                            });
                        }
                        Err(e) => {
                            // A misconfigured tandem provider/model is skipped
                            // with a notice rather than failing the toggle.
                            send_current_event(
                                &event_tx,
                                &redaction,
                                proto::Event::Notice {
                                    session_id,
                                    text: format!(
                                        "model-comparison: skipping `{provider}/{model_id}` — {e:#}"
                                    ),
                                },
                            );
                        }
                    }
                }
                let labels: Vec<String> = targets
                    .iter()
                    .map(crate::engine::schedule::TandemTarget::label)
                    .collect();
                // Token-burn warning on a non-empty set (warning only — no cap,
                // no meter), in the spirit of the `/swarm` entry warning.
                let warning = (!labels.is_empty()).then(|| {
                    format!(
                        "model-comparison ON: every substantive request is ALSO sent to {} tandem model(s) ({}). This multiplies token spend — it is off by default and reverts on restart.",
                        labels.len(),
                        labels.join(", ")
                    )
                });
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::SetTandemModels { targets },
                    &event_tx,
                    &redaction,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
                send_current_event(
                    &event_tx,
                    &redaction,
                    proto::Event::TandemState {
                        session_id,
                        models: labels,
                        warning,
                    },
                );
            }
            SessionWork::CancelSchedule { job_id } => {
                if job_cmd_tx
                    .send(crate::engine::schedule::ScheduleCommand::Cancel { job_id })
                    .await
                    .is_err()
                {
                    tracing::warn!(session_id = %session_id, "job command channel closed");
                }
            }
            SessionWork::Prune => {
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::Prune,
                    &event_tx,
                    &redaction,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::Compact => {
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::Compact,
                    &event_tx,
                    &redaction,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::Pin { text } => {
                if !send_driver_control_or_fail(
                    &driver_control_tx,
                    crate::engine::driver::DriverControl::Pin { text },
                    &event_tx,
                    &redaction,
                    session_id,
                    &mut driver_failed,
                )
                .await
                {
                    break WorkerStop::DriverFailed;
                }
            }
            SessionWork::Shutdown { pause_for_resume } => {
                let parked_count = interrupts.park_all_registered();
                let pending_tool_count = session
                    .db
                    .list_open_interrupts(session_id)
                    .map(|rows| rows.len() as i64)
                    .unwrap_or(parked_count as i64);
                let active = {
                    let (has_schedules, processing) =
                        (live.has_active_schedules(), live.processing());
                    has_schedules || processing || pending_tool_count > 0
                };
                break WorkerStop::Shutdown {
                    pause_for_resume,
                    active,
                    pending_tool_count,
                };
            }
        }
    };

    // Drain: close the driver input → the driver finishes its current
    // turn (if any) and exits. Then the engine event channel closes
    // and the forwarder task exits.
    driver_input_queue.close().await;
    if !driver_joined {
        let outcome = driver_join_outcome(driver_handle.await);
        if let Some(error) = outcome.failure_error() {
            tracing::warn!(session_id = %session_id, error = %error, "driver ended during worker drain");
        }
    }
    drop(driver_input_queue);
    let _ = forward.await;
    let _ = queue_forward.await;

    if let WorkerStop::Shutdown {
        pause_for_resume: true,
        active,
        pending_tool_count,
    } = stop
    {
        if active
            && let Err(e) = session.db.upsert_paused_session_work(
                session_id,
                &root_agent_name,
                &project_root.display().to_string(),
                "daemon shutdown paused active work",
                pending_tool_count,
                proto::DAEMON_VERSION,
            )
        {
            tracing::warn!(error = %e, "persisting paused session work failed");
        }
    } else {
        // Mark session ended in DB for destructive/explicit worker stops. A
        // graceful daemon drain keeps the session resumable instead.
        if let Err(e) = locks.end_session(session_id) {
            tracing::warn!(error = %e, "lock cleanup failed during terminal session shutdown");
        }
        if let Err(e) = session.end() {
            tracing::warn!(error = %e, "session.end() failed during shutdown");
        }
    }
    send_current_event(
        &event_tx,
        &redaction,
        proto::Event::SessionEnded {
            session_id,
            reason: stop.session_ended_reason().into(),
        },
    );
    tracing::info!(session_id = %session_id, "session worker exited");
}

// Decide whether a just-landed user write/edit in this session earns the
// one-time concurrent-write-during-plan warning, and word it mode-aware
// (`plan-concurrent-build-and-merge.md`). Returns `Some(text)` to fire the
// toast (and stamps `warned_plan` so the same plan episode warns only once),
// or `None` when there's no active plan or this plan episode was already
// warned. A *different* active plan re-arms the warning (the stamp differs).
