//! Ephemeral-fork loop execution (`keep_in_context = false`, GOALS §22).
//!
//! The whole loop runs inside one spawned task. Each iteration is a turn
//! loop on an **ephemeral fork** branched from the live main context at its
//! execution boundary. A compaction/successor handoff therefore changes the
//! parent for a not-yet-run wake without recreating the timer:
//!
//! - `independent = false` (default): iterations accumulate in the fork's
//!   own history (iteration 3 sees 1–2).
//! - `independent = true`: each iteration is a fresh fork from the
//!   snapshot, no prior-iteration history.
//!
//! Ordinary loops promote their accumulated notes and terminal result only at
//! termination. Idle loops instead classify each wake independently: a pure
//! read-only wake is discarded, while that wake's notes, spawn requests, or
//! terminal assistant report are promoted immediately.
//!
//! Forks **cannot** spawn async work: `loop.start`/`background.start`
//! called inside a fork do not execute — they record a
//! [`SpawnRequest`] that rides back to main with the terminal return.

use std::sync::Arc;

use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::engine::agent::{Agent, TurnEvent, TurnOutcome, turn};
use crate::engine::message::{Message, extract_text};
use crate::engine::schedule::authority::{LiveScheduleContext, ScheduleContext, ScheduleEvent};
use crate::engine::schedule::spec::{LoopStartArgs, ScheduleKind};
use crate::engine::tool::ToolBox;
use crate::intel::budget::BudgetedWriter;
use crate::tools::schedule::{
    ActiveIdleWake, ForkScheduleState, ForkScheduleTool, IdleWakeActionTool, NoteTool,
    begin_active_idle_wake_publication, finish_active_idle_wake_publication,
    finish_active_idle_wake_without_publication, install_active_idle_wake,
};

use super::{ASYNC_RESULT_TOKEN_CAP, FORK_HISTORY_BYTE_CAP, FORK_HISTORY_MESSAGE_CAP};

/// Everything the spawned ephemeral-loop task needs.
pub struct LoopRunCtx {
    pub job_id: String,
    pub label: String,
    pub args: LoopStartArgs,
    /// The authority's live context. It is deliberately shared rather than
    /// cloned at task spawn so a successor handoff reaches a timer that is
    /// already waiting for its next wake.
    pub ctx: LiveScheduleContext,
    /// Engine event channel — UI-only signals (notes, progress).
    pub turn_tx: mpsc::Sender<TurnEvent>,
    /// Authority→driver channel — the terminal completion.
    pub event_tx: mpsc::Sender<ScheduleEvent>,
    /// An accepted parent-thread user message publishes its instant here and
    /// restarts an idle timer's countdown from the actual activity time.
    pub idle_activity_rx: Option<watch::Receiver<Instant>>,
    /// The authority owns this handoff while a wake runs. It can promote an
    /// already-recorded action if external cancellation aborts the runner.
    pub active_idle_wake: Option<ActiveIdleWake>,
}

/// Max turns one fork iteration may take before we cut it off (bounds a
/// runaway iteration; same spirit as the noninteractive per-role turn
/// caps in `run_noninteractive`).
const MAX_ITERATION_TURNS: usize = 8;

/// Drive an ephemeral-fork loop to termination. Normal loops send one
/// [`ScheduleEvent::Completed`]; successful idle loops emit one
/// [`ScheduleEvent::IdleWakeCompleted`] for every acting wake, then one
/// [`ScheduleEvent::EphemeralCompleted`] to reconcile the registry entry.
pub async fn run_forked_loop(run: LoopRunCtx) {
    let LoopRunCtx {
        job_id,
        label,
        args,
        ctx,
        turn_tx,
        event_tx,
        mut idle_activity_rx,
        active_idle_wake,
    } = run;

    // Ordinary forked loops retain their state until terminal promotion. Idle
    // loops instead get a fresh state and toolbox for every wake, so their
    // action accounting is local to that one wake.
    let persistent_state = (!args.idle).then(|| Arc::new(ForkScheduleState::new(job_id.clone())));
    let limit = args.limit.unwrap_or(u64::MAX);
    let mut delay = args.interval_secs;
    let mut migration_rx = ctx.subscribe_migrations();
    let initial_generation = *migration_rx.borrow();
    let initial_ctx = ctx.snapshot();
    let mut watch_digest = (!args.watch_paths.is_empty()).then(|| {
        (
            initial_generation,
            local_change_digest(&initial_ctx.cwd, &args.watch_paths),
        )
    });
    // A fork persists across wakes exactly as before, but a handoff replaces
    // it so no later wake remains rooted in the retired context.
    let mut fork_session: Option<(u64, Arc<crate::session::Session>)> = None;

    // Accumulated history for `independent = false`. Reset each iteration
    // for `independent = true`.
    let mut fork_history: Vec<Message> = Vec::new();
    let mut last_result = String::new();
    let mut iteration: u64 = 0;
    let mut errored = false;
    let mut cancelled = false;
    let mut failed_idle_notes = Vec::new();
    let mut failed_idle_requests = Vec::new();
    let mut failed_idle_actions = Vec::new();
    let wake_prompt = args.idle.then(|| {
        format!(
            "[idle wake] Do not invent work. Inspect only what is needed to determine whether a real change requires action. If nothing changed, take no action and send no message.\n\n{}",
            args.prompt
        )
    });

    while iteration < limit {
        // Wait the interval before each iteration (a timer with limit=1
        // therefore fires after one interval — matching "one-shot delayed
        // prompt").
        match wait_for_next_wake(delay, args.interval_secs, idle_activity_rx.as_mut()).await {
            WakeWait::Elapsed { activity_seen } => {
                // Activity restarts both this countdown and any backoff. The
                // next wake therefore fires after the configured interval from
                // the last accepted user message, never an old deadline.
                if activity_seen {
                    delay = args.interval_secs;
                }
            }
            WakeWait::ActivityChannelClosed => {
                // An idle timer without its authority must never degrade into
                // an immediate loop. It cannot observe a future reset, so end
                // visibly and let the driver's normal failed-completion path
                // reconcile the bounded registry entry.
                last_result = "idle activity authority closed".to_string();
                errored = true;
                break;
            }
        }

        if cancelled {
            break;
        }

        // A timer may have spent its whole countdown while the foreground
        // thread compacted or moved to a successor. Snapshot only after the
        // wait so this iteration cannot fork from the retired context.
        // Mark all migrations observed before this execution boundary as
        // incorporated, then snapshot. Once this wake starts, it must run to
        // its normal completion: a tool may already have crossed an external
        // effect boundary, so retrying the wake after a handoff could duplicate
        // that effect. A replacement racing this snapshot is adopted at the
        // following wake instead.
        let live_generation = *migration_rx.borrow_and_update();
        let live_ctx = ctx.snapshot();

        if args.independent {
            fork_history.clear();
        }

        if let Some((watch_generation, previous_digest)) = watch_digest.as_mut() {
            let current_digest = local_change_digest(&live_ctx.cwd, &args.watch_paths);
            if *watch_generation != live_generation {
                // A successor has its own working context. Establish its watch
                // baseline without treating predecessor metadata as a change.
                *watch_generation = live_generation;
                *previous_digest = current_digest;
                delay = args.interval_secs;
                continue;
            }
            if current_digest == *previous_digest {
                iteration += 1;
                if args.backoff {
                    delay = (delay.saturating_mul(2)).min(super::spec::BACKOFF_CEILING_SECS);
                }
                continue;
            }
            *previous_digest = current_digest;
            delay = args.interval_secs;
        }

        let source_changed = fork_session
            .as_ref()
            .map_or(true, |(source_generation, _)| {
                *source_generation != live_generation
            });
        if source_changed {
            if fork_session.is_some() {
                // The old fork was rooted in the retired thread. Its local
                // transcript must not be carried into the successor context.
                fork_history.clear();
            }
            let session = match fork_from_live_context(&live_ctx) {
                Ok(session) => session,
                Err(e) => {
                    let _ = event_tx
                        .send(ScheduleEvent::Completed {
                            job_id,
                            label,
                            kind: args.kind(),
                            result: format!("loop fork failed: {e:#}"),
                            failed: true,
                            requests: Vec::new(),
                        })
                        .await;
                    return;
                }
            };
            fork_session = Some((live_generation, session));
        }

        let state = persistent_state
            .clone()
            .unwrap_or_else(|| Arc::new(ForkScheduleState::new(job_id.clone())));
        if let Some(active_idle_wake) = active_idle_wake.as_ref() {
            if !install_active_idle_wake(active_idle_wake, state.clone()) {
                return;
            }
        }
        let fork_agent = Arc::new(build_fork_agent(
            &live_ctx.agent,
            state.clone(),
            turn_tx.clone(),
            args.idle,
        ));

        // A handoff is deliberately not selected against a running wake. The
        // running fork owns one concrete iteration and its active-idle-wake
        // state until it publishes or releases that wake. Cancelling it here
        // would both leave that state in `Running` and make any external tool
        // effect indeterminate; replaying the same due wake could execute the
        // effect twice while consuming only one bounded iteration.
        let iteration_result = run_iteration(
            &fork_agent,
            &mut fork_history,
            wake_prompt.as_deref().unwrap_or(&args.prompt),
            fork_session
                .as_ref()
                .expect("a fork is created before every iteration")
                .1
                .clone(),
            &live_ctx,
            &turn_tx,
        )
        .await;

        match iteration_result {
            Ok(text) => last_result = text,
            Err(e) => {
                last_result = format!("loop iteration error: {e:#}");
                errored = true;
                // A failed idle wake still fails closed. Preserve any action
                // it recorded before the failure in the terminal completion
                // rather than silently dropping it with this wake's fork.
                if args.idle {
                    if !active_idle_wake
                        .as_ref()
                        .is_some_and(|active| begin_active_idle_wake_publication(active, &state))
                    {
                        return;
                    }
                    failed_idle_notes = state.take_notes();
                    failed_idle_requests = state.take_requests();
                    failed_idle_actions = state.take_actions();
                }
                break;
            }
        }

        cap_fork_history(&mut fork_history);
        iteration += 1;

        if args.idle {
            let acted = wake_has_durable_dispatch(&state);
            // Only explicit effect channels make a wake durable: `note`
            // sends to the user, create-requests raise inbox work, and wrapped
            // non-read-only tools record mutation. A model conclusion after a
            // read-only inspection is deliberately discarded.
            if acted {
                // Claim publication before draining action records. If
                // cancellation wins first, it owns the terminal promotion; if
                // it arrives later, this runner owns exactly this event.
                if !active_idle_wake
                    .as_ref()
                    .is_some_and(|active| begin_active_idle_wake_publication(active, &state))
                {
                    return;
                }
                let notes = state.take_notes();
                let requests = state.take_requests();
                let actions = state.take_actions();
                let result = bundle_terminal(
                    &label,
                    args.kind(),
                    iteration,
                    &last_result,
                    &notes,
                    &actions,
                );
                let _ = event_tx
                    .send(ScheduleEvent::IdleWakeCompleted {
                        job_id: job_id.clone(),
                        kind: args.kind(),
                        result,
                        requests,
                    })
                    .await;
                if active_idle_wake
                    .as_ref()
                    .is_some_and(finish_active_idle_wake_publication)
                {
                    let _ = event_tx
                        .send(ScheduleEvent::IdleWakePublicationCancelled {
                            job_id,
                            label,
                            kind: args.kind(),
                        })
                        .await;
                    return;
                }
            } else if !active_idle_wake
                .as_ref()
                .is_some_and(|active| finish_active_idle_wake_without_publication(active, &state))
            {
                // Cancellation claimed the no-op before it was released. It
                // owns the terminal marker; this runner must remain silent.
                return;
            }
        }

        // The fork may have asked to cancel its own loop mid-iteration.
        if state.is_cancelled() {
            cancelled = true;
            break;
        }

        if args.backoff {
            delay = (delay.saturating_mul(2)).min(super::spec::BACKOFF_CEILING_SECS);
        }
    }

    // An idle loop's successful terminal state is only a registry lifecycle
    // event: every acting wake already emitted its own durable result above.
    if args.idle && !errored {
        let _ = event_tx
            .send(ScheduleEvent::EphemeralCompleted { job_id })
            .await;
        return;
    }

    // Promote the terminal iteration's result + accumulated notes to main.
    let (notes, requests, actions) = if args.idle {
        (failed_idle_notes, failed_idle_requests, failed_idle_actions)
    } else {
        let state = persistent_state.expect("non-idle loops retain one fork state");
        (
            state.take_notes(),
            state.take_requests(),
            state.take_actions(),
        )
    };
    let result = bundle_terminal(
        &label,
        args.kind(),
        iteration,
        &last_result,
        &notes,
        &actions,
    );

    let _ = event_tx
        .send(ScheduleEvent::Completed {
            job_id,
            label,
            kind: args.kind(),
            result,
            failed: errored,
            requests,
        })
        .await;
}

fn fork_from_live_context(ctx: &ScheduleContext) -> anyhow::Result<Arc<crate::session::Session>> {
    let session = crate::session::Session::create_fork(
        ctx.session.db.clone(),
        ctx.session.id,
        None,
        ctx.session.redaction_key_resolver().clone(),
        ctx.session.secret_vault().clone(),
    )?;
    session.set_external_journal(ctx.session.external_journal());
    session.set_message_media_authority(ctx.session.message_media_authority());
    // Inherit the parent's command-secret cache so the scheduled loop fork's
    // store funnel injects resolved command outputs.
    session.set_command_secret_cache(ctx.session.command_secret_cache());
    // Inherit the parent's descendant containment handle so the scheduled loop
    // fork's lifecycle hooks run under a proven lease instead of failing open.
    session.set_process_containment(ctx.session.process_containment());
    Ok(Arc::new(session))
}

fn wake_has_durable_dispatch(state: &ForkScheduleState) -> bool {
    state.has_persistent_action()
}

enum WakeWait {
    /// The timer elapsed. `activity_seen` means the deadline was rebuilt from
    /// an accepted user message at least once while we waited.
    Elapsed { activity_seen: bool },
    /// The authority that owns the activity epoch went away. This is terminal
    /// for an idle job; returning it prevents a closed watch channel from
    /// making the outer loop spin.
    ActivityChannelClosed,
}

async fn wait_for_next_wake(
    delay_secs: u64,
    reset_delay_secs: u64,
    activity_rx: Option<&mut watch::Receiver<Instant>>,
) -> WakeWait {
    let Some(activity_rx) = activity_rx else {
        tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
        return WakeWait::Elapsed {
            activity_seen: false,
        };
    };
    let mut activity_seen = false;
    let mut deadline = Instant::now() + std::time::Duration::from_secs(delay_secs);
    match activity_rx.has_changed() {
        Ok(true) => {
            deadline =
                *activity_rx.borrow_and_update() + std::time::Duration::from_secs(reset_delay_secs);
            activity_seen = true;
        }
        Ok(false) => {}
        Err(_) => return WakeWait::ActivityChannelClosed,
    }
    loop {
        let sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep);
        tokio::select! {
            biased;
            changed = activity_rx.changed() => {
                if changed.is_err() {
                    return WakeWait::ActivityChannelClosed;
                }
                // The timestamp also covers activity that arrived while an
                // inference was running: the next sleep is measured from the
                // actual user activity, not from when this function noticed it.
                deadline = *activity_rx.borrow_and_update()
                    + std::time::Duration::from_secs(reset_delay_secs);
                activity_seen = true;
            }
            _ = &mut sleep => return WakeWait::Elapsed { activity_seen },
        }
    }
}

/// Cheap local metadata digest. A file appearing, disappearing, or changing
/// metadata counts as a change without an inference request. Directory watch
/// roots include every descendant so ordinary in-place file edits do not rely
/// on the platform's directory mtime behaviour.
fn local_change_digest(root: &std::path::Path, paths: &[String]) -> String {
    let mut entries = Vec::new();
    for path in paths {
        let absolute = root.join(path);
        match std::fs::symlink_metadata(&absolute) {
            Ok(metadata) if metadata.is_dir() => {
                for entry in walkdir::WalkDir::new(&absolute)
                    .follow_links(false)
                    .sort_by_file_name()
                {
                    match entry {
                        Ok(entry) => {
                            let relative = entry.path().strip_prefix(root).unwrap_or(entry.path());
                            match entry.metadata() {
                                Ok(metadata) => entries
                                    .push(metadata_digest(&relative.to_string_lossy(), &metadata)),
                                Err(error) => entries.push(format!(
                                    "{path}:metadata-error:{}:{}",
                                    relative.to_string_lossy(),
                                    error
                                )),
                            }
                        }
                        Err(error) => entries.push(format!(
                            "{path}:walk-error:{}:{}",
                            error.path().map_or_else(
                                || "unknown".to_string(),
                                |path| path.to_string_lossy().into_owned()
                            ),
                            error
                        )),
                    }
                }
            }
            Ok(metadata) => entries.push(metadata_digest(path, &metadata)),
            Err(error) => entries.push(format!("{path}:missing:{}", error.kind())),
        }
    }
    entries.sort();
    entries.join("|")
}

fn metadata_digest(path: &str, metadata: &std::fs::Metadata) -> String {
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let kind = if metadata.is_dir() {
        "dir"
    } else if metadata.file_type().is_symlink() {
        "symlink"
    } else {
        "file"
    };
    format!("{path}:{}:{kind}:{modified}", metadata.len())
}

/// Run one iteration's turn loop in the fork. Returns the iteration's
/// final assistant text.
async fn run_iteration(
    agent: &Arc<Agent>,
    history: &mut Vec<Message>,
    prompt: &str,
    session: Arc<crate::session::Session>,
    ctx: &ScheduleContext,
    turn_tx: &mpsc::Sender<TurnEvent>,
) -> anyhow::Result<String> {
    let mut next_prompt = Message::user(prompt.to_string());
    // A loop fork is a leaf with no human on the other end. Its toolbox
    // removes `question`, so it cannot raise an answerable interrupt (single
    // async-job authority, GOALS §22); a detached hub satisfies the shared
    // `turn` signature. Same for cancellation: a fork isn't tied to the
    // foreground run's ctrl+c slot (it's cancelled via `jobs(loop.cancel)`),
    // so a fresh never-cancelled token keeps the signature uniform.
    let interrupts = Arc::new(crate::engine::interrupt::InterruptHub::detached());
    let cancel = tokio_util::sync::CancellationToken::new();
    let mut scheduled_lane_driver = crate::engine::driver::Driver::for_nested_turn_plans(
        session.clone(),
        ctx.locks.clone(),
        ctx.redact.clone(),
        ctx.cwd.clone(),
        agent.clone(),
        ctx.config.clone(),
        None,
        interrupts.clone(),
        None,
        None,
        ctx.local_installations.clone(),
        None,
    );
    if let Some(write_scope) = ctx.write_scope.clone() {
        scheduled_lane_driver.set_write_scope_source(write_scope);
    }
    for _ in 0..MAX_ITERATION_TURNS {
        let mut outcome = turn(
            agent,
            // A loop/job fork runs on the session-root agent's own model. It is
            // outside the per-turn backup-fallback scope (interactive turns +
            // delegated subagents; implementation note), so
            // it dispatches on its primary model and emits its own failure UI.
            &agent.model,
            history,
            next_prompt,
            session.clone(),
            ctx.locks.clone(),
            ctx.redact.clone(),
            ctx.cwd.clone(),
            ctx.config.clone(),
            interrupts.clone(),
            cancel.clone(),
            // A loop fork is a leaf with no human on the other end, so it
            // can't raise an answerable approval prompt either (same
            // reason it gets a detached interrupt hub). No approver →
            // native tools skip the boundary prompt (never deny) and the
            // sandboxed shell can't escalate. The fork still runs
            // confined when sandboxing is on. The loop guard is gated on
            // an approver, so it's inert here; the threshold is irrelevant.
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            // A loop/job fork runs on the session-root agent's frozen
            // system block (GOALS §22), so it benefits from the live
            // instructions-file diff injection the same as the interactive
            // root conversation (`instructions-file-live-diff.md`).
            true,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            // A loop fork is a leaf with no parent to defer to; it carries a
            // fresh empty deferred-log that nobody reads (`plan.md §3d`).
            crate::engine::deferred::DeferredLog::new(),
            // Outside the backup-fallback scope: emit the failure UI directly.
            true,
            // A loop-fork iteration isn't a tandem-shadowed substantive turn; a
            // fresh per-round id satisfies the shared `turn` contract.
            uuid::Uuid::new_v4(),
            // A loop fork bypasses the backup wrapper: it is always the primary
            // (and only) attempt, so ordinal 0.
            0,
            // Loop-fork iterations are out of the tandem-shadow scope.
            None,
            None,
            None,
            turn_tx,
            None,
        )
        .await?;
        while let TurnOutcome::ScheduledCalls { mut plan } = outcome {
            outcome = scheduled_lane_driver
                .advance_driver_owned_turn_plan_in_history(
                    &mut plan,
                    agent,
                    history,
                    turn_tx,
                    cancel.clone(),
                )
                .await?;
            if !plan.is_finished() && !matches!(&outcome, TurnOutcome::Continue | TurnOutcome::Done)
            {
                // Leaf fork: structural outcomes cannot persist-on-re-entry, so
                // remainder owns every still-unsettled claimed source plus the
                // unstarted suffix.
                plan.settle_unreachable_remainder(history).await?;
            }
        }
        let outcome = crate::engine::agent::collapse_continue_without_injection(outcome, history);
        match outcome {
            TurnOutcome::Continue => {
                next_prompt = history
                    .pop()
                    .expect("Continue with empty history is unreachable");
            }
            TurnOutcome::Done => return Ok(collect_final_text(history)),
            // A fork is a leaf — it cannot delegate via `task`, and its
            // `schedule` tool is the in-process `ForkScheduleTool` (never routed as
            // `ScheduleAction`). If a weak model somehow lands here, end the
            // iteration rather than spin.
            TurnOutcome::SpawnSubagent { .. }
            | TurnOutcome::SpawnNoninteractive { .. }
            | TurnOutcome::SpawnNoninteractiveBatch { .. }
            | TurnOutcome::TaskControl { .. }
            | TurnOutcome::ToolResult { .. }
            | TurnOutcome::ScheduleAction { .. }
            | TurnOutcome::Spawn { .. }
            // A fork runs a primary's surface; it never holds the delegated-
            // subagent `return` tool, but be exhaustive and end the iteration.
            | TurnOutcome::Return { .. } => {
                return Ok(collect_final_text(history));
            }
            TurnOutcome::ScheduledCalls { .. }
            | TurnOutcome::ScheduledParallelLane { .. } => {
                unreachable!("scheduled calls are normalized before loop-fork dispatch")
            }
        }
    }
    Ok(collect_final_text(history))
}

/// Build the ephemeral-fork agent: the parent agent's system + tools, plus
/// the `note` tool and a fork-scoped `schedule` tool that only cancels its own
/// loop and re-routes create-actions to requests.
fn build_fork_agent(
    parent: &Arc<Agent>,
    state: Arc<ForkScheduleState>,
    turn_tx: mpsc::Sender<TurnEvent>,
    idle: bool,
) -> Agent {
    // Idle no-op classification is sound only if every possible side effect
    // crosses state owned below. Retain the parent's ordinary mutation surface
    // and wrap every non-read-only operation so its invocation is durably
    // recorded before external cancellation can abort the wake.
    let mut tools: ToolBox = parent
        .tools
        .clone()
        .without("question")
        .without_direct_native_media();
    if idle {
        tools = tools.map_non_read_only_operations(|tool| {
            Arc::new(IdleWakeActionTool::new(tool, state.clone()))
        });
    }
    tools = tools.with(Arc::new(NoteTool::new(state.clone(), turn_tx)));
    tools = tools.with(Arc::new(ForkScheduleTool::new(state)));
    let mut params = parent.params.clone();
    // A loop fork does not own the parent's opened coordinator and has no
    // live-loop injection path (`turn()` is not `turn_with_backup`). Inheriting
    // advertised geometry would re-declare the tool and drop every native
    // computer item — the advertised-but-inert failure open-before-advertise
    // exists to prevent.
    params.detach_inherited_native_computer();
    Agent {
        name: parent.name.clone(),
        system: parent.system.clone(),
        role_prompt: parent.role_prompt.clone(),
        tools,
        model: parent.model.clone(),
        params,
        scan_tool_results: parent.scan_tool_results,
        env_overlay: parent.env_overlay.clone(),
        // The fork inherits the parent's complete definition-scoped posture.
        tool_steering: parent.tool_steering,
        posture: parent.posture.clone(),
        context_policy: parent.context_policy.clone(),
        lock_identity: parent.lock_identity.clone(),
        assistant_identity_prefix: parent.assistant_identity_prefix.clone(),
        mcp_resolver: parent.mcp_resolver.clone(),
        write_scope: parent.write_scope.clone(),
        workspace_lease: parent.workspace_lease.clone(),
        delegated: parent.delegated,
        delegation_recursion: parent.delegation_recursion.clone(),
        vnext_grant: parent.vnext_grant.clone(),
        definition: parent.definition.clone(),
    }
}

/// Bundle the terminal result + notes into the budget-capped text injected
/// into main context.
fn bundle_terminal(
    label: &str,
    kind: ScheduleKind,
    iterations: u64,
    last_result: &str,
    notes: &[String],
    actions: &[String],
) -> String {
    let mut writer = BudgetedWriter::new(ASYNC_RESULT_TOKEN_CAP);
    let _ = writer.writeln(&format!(
        "{} `{label}` ended after {iterations} iteration(s).",
        kind.as_str()
    ));
    if !notes.is_empty() {
        let _ = writer.writeln("Notes:");
        for n in notes {
            let _ = writer.writeln(&format!("- {n}"));
        }
    }
    if !actions.is_empty() {
        let _ = writer.writeln("Actions:");
        for action in actions {
            let _ = writer.writeln(&format!("- {action}"));
        }
    }
    let trimmed = last_result.trim();
    if !trimmed.is_empty() {
        let _ = writer.writeln("Final iteration:");
        let _ = writer.writeln(trimmed);
    }
    writer.into_string()
}

fn collect_final_text(history: &[Message]) -> String {
    for msg in history.iter().rev() {
        if let Message::Assistant { content, .. } = msg {
            let text = extract_text(content);
            if !text.trim().is_empty() {
                return text;
            }
        }
    }
    String::new()
}
fn cap_fork_history(history: &mut Vec<Message>) {
    while history.len() > FORK_HISTORY_MESSAGE_CAP {
        history.remove(0);
    }
    while fork_history_bytes(history) > FORK_HISTORY_BYTE_CAP && !history.is_empty() {
        history.remove(0);
    }
}

fn fork_history_bytes(history: &[Message]) -> usize {
    history
        .iter()
        .map(|m| serde_json::to_vec(m).map(|v| v.len()).unwrap_or(0))
        .sum()
}

#[cfg(test)]
mod idle_dispatch_tests {
    use super::*;

    #[test]
    fn read_only_conclusion_has_no_durable_dispatch() {
        let state = ForkScheduleState::new("idle-read-only".into());
        assert!(!wake_has_durable_dispatch(&state));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_model() -> Arc<crate::engine::model::Model> {
        let mut providers = std::collections::BTreeMap::new();
        providers.insert(
            "local".to_string(),
            crate::config::providers::ProviderEntry {
                url: "http://localhost:1/v1".into(),
                headers: vec![],
                ..Default::default()
            },
        );
        let config = crate::config::providers::ProvidersConfig {
            providers,
            active_model: Some(crate::config::providers::ActiveModelRef {
                provider: "local".into(),
                model: "model".into(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            }),
            ..Default::default()
        };
        Arc::new(
            crate::engine::model::Model::from_config(
                &config,
                Arc::new(crate::redact::RedactionTable::empty()),
            )
            .unwrap(),
        )
    }

    fn parent_agent_with_question() -> Arc<Agent> {
        Arc::new(Agent {
            name: "Build".into(),
            system: "system".into(),
            role_prompt: "role".into(),
            tools: ToolBox::new()
                .with(Arc::new(crate::tools::question::QuestionTool))
                .with(Arc::new(crate::tools::write::WriteTool))
                .with(Arc::new(crate::tools::read::ReadTool)),
            model: test_model(),
            params: crate::engine::model::ModelParams::default(),
            scan_tool_results: false,
            tool_steering: crate::agents::ToolSteering::Terse,
            posture: crate::agents::PostureResolution::standard(),
            context_policy: Some(crate::agents::ContextPolicy {
                auto_compact_pct: Some(65),
                inline_caps: Some(crate::agents::InlineCapsProfile::Conservative),
                artifact_spill_bytes: None,
                artifact_preview_lines: None,
            }),
            lock_identity: "Build".to_string(),
            write_scope: None,
            workspace_lease: None,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            vnext_grant: None,
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            definition: None,
            assistant_identity_prefix: None,
            mcp_resolver: crate::mcp::resolver::EffectiveCatalogResolver::empty(),
        })
    }

    #[test]
    fn idle_fork_keeps_mutation_tools_but_not_question() {
        let parent = parent_agent_with_question();
        assert!(parent.tools.names().contains(&"question"));
        assert!(parent.tools.names().contains(&"write"));
        let state = Arc::new(ForkScheduleState::new("job-1".into()));
        let (turn_tx, _turn_rx) = mpsc::channel(8);

        let fork = build_fork_agent(&parent, state, turn_tx, true);
        let names = fork.tools.names();

        assert!(!names.contains(&"question"), "{names:?}");
        assert!(names.contains(&"write"), "{names:?}");
        assert!(names.contains(&"note"), "{names:?}");
        assert!(names.contains(&"schedule"), "{names:?}");
        assert!(names.contains(&"read"), "{names:?}");
        assert_eq!(fork.context_policy, parent.context_policy);
    }

    #[test]
    fn directory_watch_digest_observes_descendant_file_modification() {
        let tmp = tempfile::tempdir().unwrap();
        let watched = tmp.path().join("watched");
        std::fs::create_dir(&watched).unwrap();
        let child = watched.join("status.txt");
        std::fs::write(&child, "old").unwrap();
        let before = local_change_digest(tmp.path(), &["watched".to_string()]);

        // Rewriting an existing child does not reliably update the watched
        // directory's own metadata; the recursive digest must still change.
        std::fs::write(child, "updated").unwrap();
        let after = local_change_digest(tmp.path(), &["watched".to_string()]);

        assert_ne!(before, after);
    }

    #[tokio::test(start_paused = true)]
    async fn user_activity_restarts_a_backed_off_idle_deadline() {
        let (activity_tx, activity_rx) = watch::channel(Instant::now());
        let wait = tokio::spawn(async move {
            let mut activity_rx = activity_rx;
            wait_for_next_wake(300, 60, Some(&mut activity_rx)).await
        });

        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(59)).await;
        tokio::task::yield_now().await;
        assert!(!wait.is_finished());

        activity_tx.send(Instant::now()).unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(59)).await;
        tokio::task::yield_now().await;
        assert!(!wait.is_finished());

        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        assert!(matches!(
            wait.await.unwrap(),
            WakeWait::Elapsed {
                activity_seen: true
            }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn closed_idle_activity_channel_is_terminal() {
        let (activity_tx, mut activity_rx) = watch::channel(Instant::now());
        drop(activity_tx);

        assert!(matches!(
            wait_for_next_wake(60, 60, Some(&mut activity_rx)).await,
            WakeWait::ActivityChannelClosed
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn activity_seen_after_inference_uses_its_original_timestamp() {
        let (activity_tx, mut activity_rx) = watch::channel(Instant::now());

        // This send models activity accepted while a model iteration is still
        // executing, before the runner gets back to its next wait.
        tokio::time::advance(std::time::Duration::from_secs(30)).await;
        activity_tx.send(Instant::now()).unwrap();
        tokio::time::advance(std::time::Duration::from_secs(45)).await;

        let wait =
            tokio::spawn(async move { wait_for_next_wake(300, 60, Some(&mut activity_rx)).await });
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(14)).await;
        tokio::task::yield_now().await;
        assert!(!wait.is_finished());

        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        assert!(matches!(
            wait.await.unwrap(),
            WakeWait::Elapsed {
                activity_seen: true
            }
        ));
    }

    #[test]
    fn fork_history_message_cap_keeps_freshest_messages() {
        let mut history: Vec<Message> = (0..(FORK_HISTORY_MESSAGE_CAP + 10))
            .map(|i| Message::user(format!("msg-{i}")))
            .collect();
        cap_fork_history(&mut history);
        assert_eq!(history.len(), FORK_HISTORY_MESSAGE_CAP);
        assert!(format!("{:?}", history[0]).contains("msg-10"));
    }

    #[test]
    fn fork_history_byte_cap_keeps_serialized_size_bounded() {
        let mut history: Vec<Message> = (0..80)
            .map(|i| Message::user(format!("msg-{i}-{}", "x".repeat(8192))))
            .collect();
        cap_fork_history(&mut history);
        assert!(fork_history_bytes(&history) <= FORK_HISTORY_BYTE_CAP);
        assert!(history.len() < 80);
    }
}
