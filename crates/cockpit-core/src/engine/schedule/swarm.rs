//! Recursive `Swarm` subagent execution (GOALS §24).
//!
//! A `Swarm` agent (root or background subagent) fans out work by calling
//! `spawn`. The driver routes the root's calls to the single
//! async-job authority, which schedules each child here as a parallel
//! background job under the global concurrency cap. This module runs one such
//! child's agent loop to completion and reports a budget-capped terminal
//! result back to main (GOALS §10).
//!
//! ## Recursion squares with single-async-job authority
//!
//! A child that *itself* calls `spawn` does **not** spawn async work
//! directly. Its runner posts a [`ScheduleCommand::Spawn`] back to main
//! (the single authority), which owns the queue + the global concurrency cap
//! and decides whether to schedule it (GOALS §22). The child receives a
//! synchronous "scheduled/queued" tool result and continues; the grandchild's
//! own findings bubble up the same way (the encouraged pattern: each leaf
//! persists to its dedicated `write_scope`/DB and returns a compact pointer).
//!
//! ## Depth ceiling (clamp, don't crash)
//!
//! Each child knows its own `depth` and the ceiling. A `spawn` that
//! would exceed the ceiling is **refused** in the runner: the tool returns a
//! refusal and the branch does that slice's work itself as a leaf. No panic,
//! no runaway.

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::engine::agent::{Agent, TurnEvent, TurnOutcome};
use crate::engine::builtin::SpawnArgs;
use crate::engine::message::{Message, extract_text};
use crate::engine::schedule::authority::{
    MAX_SWARM_PROMPT_BYTES, ScheduleCommand, ScheduleContext, ScheduleEvent, SpawnModelOrigin,
    SpawnSpec, SpawnWorkerKind,
};
use crate::engine::schedule::spec::ScheduleKind;
use crate::intel::budget::BudgetedWriter;

use super::ASYNC_RESULT_TOKEN_CAP;

/// Everything the spawned recursive-`Swarm` task needs.
pub struct SwarmRunCtx {
    pub job_id: String,
    pub label: String,
    pub spec: SpawnSpec,
    pub ctx: ScheduleContext,
    /// Engine event channel — UI-only signals (started/progress).
    pub turn_tx: mpsc::Sender<TurnEvent>,
    /// Authority→driver channel — the terminal completion.
    pub event_tx: mpsc::Sender<ScheduleEvent>,
    /// Driver command channel — the runner posts a child's own
    /// `spawn` back to main (the single authority) here.
    pub cmd_tx: mpsc::Sender<ScheduleCommand>,
}

/// Turn cap on one recursive-`Swarm` child's loop. Wide enough for real
/// fan-out + leaf work, bounded so a stuck child can't spin forever (same
/// spirit as the noninteractive per-role caps).
const SWARM_MAX_TURNS: usize = 64;

/// A live delegation: the coordinator that owns it, and the transfer to drain.
type ActiveDelegation = (
    std::sync::Arc<crate::write_scope::WriteScopeCoordinator>,
    uuid::Uuid,
);

/// Begin the durable write-scope transfer for a write-capable child.
///
/// Returns `Ok(None)` when no coordinator is installed (unit-test drivers), and
/// `Err(refusal)` — a model-facing message — when the transfer is refused. A
/// refusal here means the child never runs, which is the point: without a
/// Proven backend the child cannot be given exclusive authority.
async fn begin_write_scope_transfer(
    spec: &SpawnSpec,
    ctx: &ScheduleContext,
) -> std::result::Result<Option<ActiveDelegation>, String> {
    let Some(coordinator) = ctx.write_scope() else {
        // No durable authority installed (unit-test driver). The dispatch gate
        // already refused write-capable children on an unsupported backend.
        return Ok(None);
    };
    let scope = match crate::write_scope::CanonicalScope::resolve_under(&ctx.cwd, &spec.write_scope)
    {
        Ok(scope) => scope,
        Err(err) => {
            return Err(format!(
                "refused: `write_scope` is not a usable subtree of this workspace — {err}."
            ));
        }
    };
    // The parent's root lease for this session. Absent one there is no
    // authority to transfer from, so the child cannot start.
    let parent_lease_id = match coordinator.session_root_lease(ctx.session.id).await {
        Ok(Some(lease_id)) => lease_id,
        Ok(None) => {
            return Err(
                "refused: this session holds no durable write authority to delegate from."
                    .to_string(),
            );
        }
        Err(err) => return Err(format!("refused: write authority lookup failed — {err}")),
    };

    // ------------------------------------------------------------------
    // The containment ticket must own the work it authorizes, and at THIS
    // layer it cannot.
    //
    // A `bee` is not an OS process: `run_swarm_loop` below executes it as a
    // task inside the daemon. `ProcessContainmentBarrier` contains processes,
    // so containing "the child" here would mean containing some *other*
    // process while the real writes happen in the uncontained daemon. An
    // earlier revision papered over that by launching `current_exe()` as a
    // placeholder — which both spawned a stray `cockpit` process per
    // delegation and made `ProvenEmpty` a statement about the placeholder
    // rather than about the child. The return barrier and parent restoration
    // are built on that proof, so a false proof makes the whole lifecycle
    // decorative.
    //
    // The spec places the execution-wide permit and containment at "shell/tool
    // execution ... before the containment actor spawns native user code or
    // creates/execs container/zerobox work" — i.e. at `tools/bash` and
    // container exec, where user code genuinely becomes a process. Wiring it
    // there (and threading the child's scope + generation token into
    // `ToolCtx`) is a separate, sizeable integration.
    //
    // Until then this fails closed. Nothing is fabricated, no stray process is
    // spawned, and no child ever runs behind a containment proof that does not
    // cover it. Today this is unreachable anyway: the dispatch gate already
    // refuses write-capable children on the direct workspace.
    let _ = (&scope, &parent_lease_id, &coordinator, spec);
    Err(
        "refused: scoped writes are unsupported for swarm children on this build — a `bee` runs \
         inside the daemon rather than as a contained process, so its descendants cannot be \
         proven drained and exclusive authority over the scope cannot be honored. Do this \
         slice's work yourself, or delegate a reviewer that needs no write tools (note that \
         such a child can still write via `bash` within the session cwd)."
            .to_string(),
    )
}

/// Mark the child terminal and drain the return barrier.
async fn finish_write_scope_transfer(
    coordinator: &std::sync::Arc<crate::write_scope::WriteScopeCoordinator>,
    transfer_id: uuid::Uuid,
) -> std::result::Result<(), crate::write_scope::WriteScopeError> {
    coordinator.child_terminal(transfer_id).await?;
    coordinator.complete_return(transfer_id).await?;
    Ok(())
}

/// Drive one recursive `Swarm` subagent to completion. Always sends
/// exactly one [`ScheduleEvent::Completed`] so the authority reconciles its
/// registry entry + the running-swarm count.
pub async fn run_swarm(run: SwarmRunCtx) {
    let SwarmRunCtx {
        job_id,
        label,
        spec,
        ctx,
        turn_tx,
        event_tx,
        cmd_tx,
    } = run;

    // Announce the child START to the driver as this task's FIRST action, on the
    // same channel and by the same task that sends its terminal `Completed`
    // below — so the driver drains the start before the paired completion (FIFO
    // by program order) even under channel backpressure. The driver fires
    // `subagentStart` and records the child so the paired `subagentStop` fires
    // on completion. GENUINE swarm children (`bee` / `scout`) only: goal-
    // supervision control workers (Planner/Evaluator/Gatekeeper/ColdSkeptic)
    // share this runner but are never user-facing subagents (guidance L22), so
    // the `is_goal_control` check is the single closed exclusion predicate and
    // they emit neither lifecycle event.
    if !spec.worker.is_goal_control() {
        let _ = event_tx
            .send(ScheduleEvent::SwarmChildStarted {
                job_id: job_id.clone(),
                subagent_type: spec.worker.agent_name().to_string(),
            })
            .await;
    }

    // AC7: capability + execution-wide permit + containment are acquired here,
    // immediately BEFORE the child's first turn — i.e. before any native spawn
    // or container create/exec. A write-capable child receives exclusive
    // authority over its sub-scope, so the durable transfer must succeed first
    // or the child must not run at all.
    //
    // A worker without Cockpit write tools receives no transferred authority
    // and takes no lease. It is not mechanically prevented from writing via
    // `bash`; see `SpawnWorkerKind::is_write_capable`.
    let delegation = if spec.worker.is_write_capable() {
        match begin_write_scope_transfer(&spec, &ctx).await {
            Ok(handle) => handle,
            Err(refusal) => {
                let _ = event_tx
                    .send(ScheduleEvent::Completed {
                        job_id,
                        label,
                        kind: ScheduleKind::Swarm,
                        result: refusal,
                        failed: true,
                        requests: Vec::new(),
                    })
                    .await;
                return;
            }
        }
    } else {
        None
    };

    let loop_outcome = run_swarm_loop(&job_id, &spec, &ctx, &turn_tx, &cmd_tx).await;

    // The child is terminal either way. Invalidate its token and drain the
    // return barrier before the parent is told anything, so the parent can
    // never observe completion while the child still holds authority.
    if let Some((coordinator, transfer_id)) = delegation.as_ref()
        && let Err(error) = finish_write_scope_transfer(coordinator, *transfer_id).await
    {
        // Authority is retained, not restored: the rows stay for recovery.
        tracing::warn!(
            error = %error,
            transfer_id = %transfer_id,
            "swarm child return barrier did not complete; write authority retained"
        );
    }

    let result = match loop_outcome {
        Ok(text) => {
            // The child ran its controlling `subagentStop` gate inside
            // `run_swarm_loop` on EVERY normal-return path (Done / structural
            // finish / primary-turn ceiling), firing exactly one gated stop.
            // Announce that (FIFO, before `Completed`) so the driver skips the
            // terminal `subagentStop` at the `Completed` drain for a normally
            // gated success — no double. Goal-supervision workers never gate and
            // never track a subagent, so they never announce it (guidance L22).
            if !spec.worker.is_goal_control() {
                let _ = event_tx
                    .send(ScheduleEvent::SwarmChildStopGateCompleted {
                        job_id: job_id.clone(),
                    })
                    .await;
            }
            text
        }
        Err(e) => {
            // A failure bypasses the loop gate; the driver fires the terminal
            // `subagentStop` (`failed`) at the `Completed` drain instead.
            let _ = event_tx
                .send(ScheduleEvent::Completed {
                    job_id,
                    label,
                    kind: ScheduleKind::Swarm,
                    result: format!("swarm subagent error: {e:#}"),
                    failed: true,
                    requests: Vec::new(),
                })
                .await;
            return;
        }
    };

    let body = if spec.worker.is_goal_control() {
        result.trim().to_string()
    } else {
        budget_result(&label, &spec, &result)
    };
    let _ = event_tx
        .send(ScheduleEvent::Completed {
            job_id,
            label,
            kind: ScheduleKind::Swarm,
            result: body,
            failed: false,
            requests: Vec::new(),
        })
        .await;
}

/// Run the child's `Swarm` agent loop, intercepting its own
/// `spawn` calls and routing them back to main.
async fn run_swarm_loop(
    job_id: &str,
    spec: &SpawnSpec,
    ctx: &ScheduleContext,
    turn_tx: &mpsc::Sender<TurnEvent>,
    cmd_tx: &mpsc::Sender<ScheduleCommand>,
) -> anyhow::Result<String> {
    let SwarmChild {
        agent,
        custody,
        pinned,
    } = build_swarm_child(spec, ctx)?;
    let agent = Arc::new(agent);
    let mut history: Vec<Message> = Vec::new();
    let brief = swarm_child_brief(spec, &custody);
    tracing::debug!(
        custody = ?custody.custody(),
        routing = %custody.routing_diagnostics_json(),
        "swarm child custody"
    );
    let mut next_prompt = Message::user(brief);

    // A background swarm child is a leaf with no human on the other end:
    // a detached interrupt hub + a fresh cancel token satisfy `turn`'s
    // signature (same rationale as the loop-fork runner). No approver →
    // native tools skip the boundary prompt (never deny); the loop guard is
    // inert without one.
    let interrupts = Arc::new(crate::engine::interrupt::InterruptHub::detached());
    let cancel = tokio_util::sync::CancellationToken::new();
    let deferred_log = crate::engine::deferred::DeferredLog::new();

    // This detached child owns its `subagentStop` continuation budget for its
    // whole job lifetime (a LOOP-LOCAL latch). It is dropped when this function
    // returns on ANY path, and a nested job receives its OWN `run_swarm_loop`
    // invocation with a fresh latch — so it can never leak, be reconsulted after
    // the loop returns, or be reopened (never-reopen airtight by construction).
    let mut stop_gate = crate::engine::agent::hooks::StopGateState::default();

    // Per-turn backup-model fallback for the background `Swarm` child
    // (implementation note): `Swarm` is in scope, so the
    // child inherits the same mechanism, resolved against the model it runs on.
    // Resolve backup/failover under the child's PINNED config (never live
    // `ctx.config`), so failover/reposture/dispatch share the same generation the
    // child's identity/posture were built under.
    // Owner-scoped under the child's PINNED config: backup/failover are built
    // from the store scoped to (provider, this workspace), so a swarm child's
    // fallback can never resolve a foreign workspace's `$secret:`.
    let backup_model = crate::engine::driver::resolve_backup_model_for_session(
        &pinned,
        &agent.model,
        &ctx.session,
    );
    let fallback_models = crate::engine::driver::resolve_failover_models_for_session(
        &pinned,
        &agent.model,
        &ctx.session,
    );

    for _ in 0..SWARM_MAX_TURNS {
        let outcome = crate::engine::agent::turn_with_backup(
            &agent,
            backup_model.as_ref(),
            &fallback_models,
            &mut history,
            next_prompt,
            ctx.session.clone(),
            ctx.locks.clone(),
            ctx.redact.clone(),
            ctx.cwd.clone(),
            pinned.clone(),
            interrupts.clone(),
            cancel.clone(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            // A noninteractive child recomposes its own fresh system block on
            // spawn; it never needs the live instructions-file diff injection.
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            deferred_log.clone(),
            // Swarm subagents run in detached job tasks, not the driver
            // stack, and are not tandem-shadowed; a fresh per-round id satisfies
            // the shared `turn` contract.
            uuid::Uuid::new_v4(),
            // Swarm subagents are not tandem-shadowed (out of the §26 fan-out
            // scope; the spec shadows primary + builder/explore/docs only).
            None,
            spec.goal_provenance,
            None,
            turn_tx,
            None,
        )
        .await?;
        match outcome {
            TurnOutcome::Continue => {
                next_prompt = history
                    .pop()
                    .expect("Continue with empty history is unreachable");
            }
            TurnOutcome::Done => {
                // Genuine detached-`Swarm` child completion: consult its
                // loop-local `subagentStop` gate (the single gated firing for
                // this stop). Goal-supervision workers never gate — enforced
                // inside `swarm_child_stop_continuation` (guidance L22). A
                // blocking stop hook re-runs the child with host feedback.
                if let Some(prompt) = swarm_child_stop_continuation(
                    job_id,
                    spec,
                    ctx,
                    &pinned,
                    &cancel,
                    &mut stop_gate,
                )
                .await
                {
                    next_prompt = prompt;
                    continue;
                }
                return Ok(collect_final_text(&history));
            }
            // The child fanned out further. Route the spawn back to main (the
            // single authority) — or refuse it at the ceiling (clamp, don't
            // crash) — and feed the resulting pointer back as this call's
            // tool result so the child can keep going.
            TurnOutcome::Spawn {
                prompt,
                write_scope,
                model,
                task_call_id,
                task_provider_item_id,
                task_function_call_id,
            } => {
                let pointer = route_child_spawn(
                    spec,
                    &prompt,
                    &write_scope,
                    &ctx.cwd,
                    model,
                    cmd_tx,
                    turn_tx,
                )
                .await;
                next_prompt =
                    crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        "spawn",
                        pointer,
                    );
            }
            // A `bee` child is leaf-terminated for every edge *except*
            // bee→bee (handled above via `spawn`): it holds `task` only to
            // reach `docs`, which the noninteractive child path does not run
            // recursively here, and never holds done/jobs-as-spawn.
            // `return` is its structured finish tool — treat it (and any stray
            // structural outcome from a weak model) as end-of-run, returning
            // what the child has (clamp, don't crash).
            TurnOutcome::SpawnSubagent { .. }
            | TurnOutcome::SpawnNoninteractive { .. }
            | TurnOutcome::SpawnNoninteractiveBatch { .. }
            | TurnOutcome::TaskControl { .. }
            | TurnOutcome::ToolResult { .. }
            | TurnOutcome::ScheduleAction { .. }
            | TurnOutcome::Return { .. } => {
                // A structural end-of-run for a genuine swarm child: gate its
                // `subagentStop` exactly like the `Done` arm (single gated
                // firing; goal-supervision excluded inside the funnel per L22).
                if let Some(prompt) = swarm_child_stop_continuation(
                    job_id,
                    spec,
                    ctx,
                    &pinned,
                    &cancel,
                    &mut stop_gate,
                )
                .await
                {
                    next_prompt = prompt;
                    continue;
                }
                return Ok(collect_final_text(&history));
            }
        }
    }
    // Primary-turn ceiling reached without a normal stop boundary. The child
    // cannot re-run, so the continuation is not honored — but the single gated
    // `subagentStop` must still fire (else the success marker sent by `run_swarm`
    // would skip the stop at the drain, dropping it). Goal-supervision workers
    // never gate (enforced inside the funnel per L22).
    let _ =
        swarm_child_stop_continuation(job_id, spec, ctx, &pinned, &cancel, &mut stop_gate).await;
    Ok(collect_final_text(&history))
}

/// Consult a genuine detached-`Swarm` child's controlling `subagentStop` gate on
/// a normal completion, through the unified [`crate::engine::agent::hooks::run_stop_hooks`]
/// G::Stop dispatcher (`endReason = completed`). Returns `Some(prompt)` when a
/// blocking stop hook grants a continuation the caller should re-run the child
/// with (host feedback via `SubmissionOrigin::Internal`, so it never re-fires
/// `userPromptSubmit`), and the run is not cancelled; otherwise `None` (end).
///
/// The L22 goal-supervision exclusion is enforced at THIS single funnel (not at
/// each of the three `run_swarm_loop` call sites): a goal-control worker
/// (Planner/Evaluator/Gatekeeper/ColdSkeptic) returns `None` immediately WITHOUT
/// dispatching any hook, so it can never fire `subagentStop`. Enforcing it here
/// once means no call site can drift into firing it, and one test
/// (`swarm_stop_gate_never_fires_for_goal_control_workers`) covers every gate
/// site. The `stop_gate` latch is loop-local and dropped when `run_swarm_loop`
/// returns, so it is never-reopen airtight.
async fn swarm_child_stop_continuation(
    job_id: &str,
    spec: &SpawnSpec,
    ctx: &ScheduleContext,
    pinned: &crate::daemon::session_worker::SessionConfigHandle,
    cancel: &tokio_util::sync::CancellationToken,
    stop_gate: &mut crate::engine::agent::hooks::StopGateState,
) -> Option<Message> {
    // L22: goal-supervision control workers are never user-facing subagents and
    // fire NEITHER lifecycle event. Fail closed at the funnel.
    if spec.worker.is_goal_control() {
        return None;
    }
    let snapshot = pinned.snapshot();
    let outcome = crate::engine::agent::hooks::run_stop_hooks(
        &crate::engine::agent::hooks::TokioCommandRunner::with_optional_containment(
            ctx.session.process_containment(),
        ),
        &crate::engine::agent::hooks::DefaultProcessEnv,
        snapshot.hooks(),
        crate::config::extended::hooks::HookEvent::SubagentStop,
        spec.worker.agent_name(),
        ctx.session.id,
        &ctx.cwd,
        &ctx.session.db,
        Some(spec.worker.agent_name()),
        Some(job_id),
        Some("completed"),
        stop_gate,
    )
    .await;
    if let crate::engine::agent::hooks::StopHookOutcome::Continue {
        reason,
        additional_context,
    } = outcome
        && !cancel.is_cancelled()
    {
        return Some(crate::engine::driver::Driver::stop_continuation_prompt(
            reason,
            additional_context,
        ));
    }
    None
}

/// Route a running child's own `spawn` to main, or refuse it at the
/// ceiling. The child's depth is `spec.depth`; a grandchild would be
/// `spec.depth + 1`. When that would exceed the ceiling the spawn is refused
/// and the branch must do the work inline (the tool result says so).
#[allow(clippy::too_many_arguments)]
async fn route_child_spawn(
    spec: &SpawnSpec,
    prompt: &str,
    write_scope: &str,
    workspace_root: &std::path::Path,
    model: Option<String>,
    cmd_tx: &mpsc::Sender<ScheduleCommand>,
    turn_tx: &mpsc::Sender<TurnEvent>,
) -> String {
    let child_depth = spec.depth + 1;
    if child_depth > spec.max_depth {
        return format!(
            "refused: depth ceiling {} reached (you are at depth {}). Do this slice's work \
             yourself as a leaf instead of delegating.",
            spec.max_depth, spec.depth
        );
    }
    // A running child fanning out further takes the same fail-closed barrier as
    // the foreground path: a write-capable grandchild is a strict writable
    // delegation and needs a backend that can isolate arbitrary child syscalls.
    if let Some(refusal) = crate::engine::driver::scoped_write_refusal(
        spec.worker,
        workspace_root,
        write_scope,
        &crate::write_scope::DirectWorkspaceBackend,
    ) {
        return refusal;
    }
    if prompt.len() > MAX_SWARM_PROMPT_BYTES {
        return format!(
            "refused: spawn prompt is {} bytes; maximum is {} bytes",
            prompt.len(),
            MAX_SWARM_PROMPT_BYTES
        );
    }
    // Provenance never launders through a nested fan-out. `model` here is the
    // grandchild's `spawn` **tool argument** — model-authored — so it is always
    // `ModelDirected`, even when the parent spec was host config. Only an
    // unchanged inherited selector (the child supplied none, or repeated the
    // parent's host-config value verbatim) keeps `HostConfig`. Without this a
    // host-config skeptic holding `spawn` could name any trusted model and
    // obtain raw custody plus a real grant.
    let model_origin = match (&model, &spec.model) {
        (None, _) => spec.model_origin,
        (Some(child_model), Some(parent_model))
            if child_model == parent_model && spec.model_origin == SpawnModelOrigin::HostConfig =>
        {
            SpawnModelOrigin::HostConfig
        }
        _ => SpawnModelOrigin::ModelDirected,
    };
    let child = SpawnSpec {
        job_id: None,
        goal_provenance: spec.goal_provenance,
        worker: spec.worker,
        prompt: prompt.to_string(),
        write_scope: write_scope.to_string(),
        model,
        model_origin,
        depth: child_depth,
        max_depth: spec.max_depth,
    };
    // Surface the fan-out as a UI note on the parent job, then route the
    // request to main (the single authority schedules/queues it).
    let _ = turn_tx.try_send(TurnEvent::ScheduleProgress {
        job_id: spec_label(spec),
    });
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    match cmd_tx
        .send(ScheduleCommand::Spawn {
            spec: child,
            result_tx: Some(result_tx),
        })
        .await
    {
        Ok(()) => match result_rx.await {
            Ok(result) => result,
            Err(_) => "could not schedule the deeper subagent (the scheduler dropped the result); \
                 do this slice's work yourself."
                .to_string(),
        },
        Err(_) => "could not schedule the deeper subagent (the session is shutting down); do this \
             slice's work yourself."
            .to_string(),
    }
}

/// Build the recursive `Swarm` child agent at the spec's depth, so its own
/// `spawn` description carries the remaining-budget hint (GOALS §24).
fn build_swarm_child(spec: &SpawnSpec, ctx: &ScheduleContext) -> anyhow::Result<SwarmChild> {
    if ctx.agent.vnext_grant.is_some() {
        anyhow::bail!(
            "vNext definitions cannot enter the legacy Swarm fork path; use the effective-grant task delegation route"
        );
    }
    let worker_agent = spec.worker.agent_name();
    // Pin the config to a held snapshot for THIS swarm child's build: model
    // selection AND the agent build below both read the same frozen generation,
    // so a concurrent refresh can never split the child's identity from its
    // posture (it affects only the next spawn).
    let pinned = ctx.config.repin();
    let (extended, providers) = crate::engine::model_roles::load_model_role_config(&pinned);
    // Owner-scoped store for this swarm child's model selection AND its delegated
    // model construction, derived from the SAME pinned providers config: a
    // model-authored `spawn.model` `$secret:` selector (or a header ref) can only
    // resolve a secret owned by (provider, this workspace), never a foreign one.
    // See `named-secret-ownership-boundary`.
    let scoped_store = ctx.session.provider_credential_store(&providers).ok();
    // `spawn.model` is a model-authored selector exactly like
    // `task.payload.model`, so it takes the same custody-typed, forced
    // redacted-untrusted route with subagent-invokable and capability checks.
    // Naming a trusted-custody model here is a custody error, not an escalation.
    let (model, custody) = match spec.model.as_deref() {
        Some(selector) => match spec.model_origin {
            // Host config named this target (e.g. `goalSupervision.coldSkepticModel`):
            // it keeps its own configured custody class.
            SpawnModelOrigin::HostConfig => {
                crate::engine::model_roles::resolve_host_config_spawn_selector_with_store(
                    selector,
                    worker_agent,
                    &extended,
                    &providers,
                    &ctx.agent.model,
                    scoped_store.clone(),
                )
            }
            // A model wrote this selector: forced redacted-untrusted custody.
            SpawnModelOrigin::ModelDirected => {
                crate::engine::model_roles::resolve_spawn_selector_with_store(
                    selector,
                    worker_agent,
                    &extended,
                    &providers,
                    &ctx.agent.model,
                    scoped_store.clone(),
                )
            }
        }
        .map_err(|error| {
            anyhow::anyhow!(
                "invalid explicit spawn model selector `{selector}`: {}",
                match error {
                    crate::engine::model_roles::SelectorResolution::Unset =>
                        "selector unset".to_string(),
                    crate::engine::model_roles::SelectorResolution::InvalidLiteral(message) =>
                        message,
                }
            )
        })?,
        None => {
            // No selector: the child inherits the parent's host-chosen model,
            // so custody is that model's own configured class.
            let custody = crate::engine::model_roles::inherited_custody_for_model(
                &providers,
                &ctx.agent.model,
                &extended,
            );
            (ctx.agent.model.clone(), custody)
        }
    };
    let args = SpawnArgs {
        model,
        params: ctx.agent.params.clone(),
        env_overlay: ctx.agent.env_overlay.clone(),
        cwd: ctx.cwd.clone(),
        config: pinned.clone(),
        session_short_id: ctx.session.short_id(),
        // Inherit the parent agent's identity prefix so a `spawn` → bee/scout/goal
        // worker in an assistant session keeps the SOUL/USER identity.
        assistant_identity_prefix: ctx.agent.assistant_identity_prefix.clone(),
        model_system_prompt_snapshot: ctx.session.model_system_prompt_snapshot(),
        // A background swarm child is noninteractive (no human attached).
        interactive: false,
        mcp_parent_reachable: Some(
            ctx.agent
                .mcp_resolver
                .catalog()
                .servers
                .keys()
                .cloned()
                .collect(),
        ),
        // Plan-level overrides don't apply to ad-hoc swarm fan-out.
        model_override: None,
        delegation_model: None,
        delegated: true,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        vnext_grant: None,
        vnext_host_policy: None,
        vnext_local_installation_resolver:
            crate::agents::LocalInstallationResolver::no_installations(),
        parent_vnext_grant: None,
        parent_posture: Some(ctx.agent.posture.clone()),
        swarm_depth: spec.depth,
        swarm_max_depth: spec.max_depth,
        // Background swarm children carry no per-delegation grants.
        granted_tools: Vec::new(),
        lock_identity: None,
        write_scope: None,
        credential_store: scoped_store,
    };
    // The recursive worker unit is `bee` (GOALS §24/§26): a noninteractive,
    // write-capable, parallel worker that may itself fan out deeper `bee`
    // workers via `spawn`. The interactive `Swarm` primary holds `spawn`; each
    // background child it fans out is a `bee`.
    Ok(SwarmChild {
        agent: match spec.worker {
            SpawnWorkerKind::Bee => crate::engine::builtin::load("bee", &args)?,
            SpawnWorkerKind::Scout => crate::engine::builtin::load("scout", &args)?,
            SpawnWorkerKind::GoalPlanner
            | SpawnWorkerKind::GoalEvaluator
            | SpawnWorkerKind::GoalGatekeeper
            | SpawnWorkerKind::GoalColdSkeptic => {
                crate::engine::builtin::goal_control(spec.worker, &args)
            }
        },
        custody,
        pinned,
    })
}

/// A built swarm child plus the custody decision its route was resolved under.
/// The brief is rendered through `custody` before it reaches the child, so the
/// typed payload is on the real dispatch path.
struct SwarmChild {
    agent: Agent,
    custody: crate::engine::model_roles::DelegationCustody,
    /// The pinned config snapshot the child's model selection + build resolved
    /// under. Carried out so the WHOLE attempt — backup/failover resolution and
    /// every `turn_with_backup` dispatch — reads this SAME frozen generation, so a
    /// concurrent refresh can never split the child's pinned identity/posture from
    /// a newer-generation failover/reposture/dispatch (it applies to the next
    /// spawn only).
    pinned: crate::daemon::session_worker::SessionConfigHandle,
}

/// The brief the child actually receives.
///
/// Composed, then rendered for the resolved destination's custody class before
/// it reaches the child or its history: an untrusted (cloud) child gets the
/// session redaction-table rendering, a trusted (self-hosted / no-log) child
/// gets it unchanged. This is the production use of the typed payload, and it
/// is a named function so the test that pins it exercises the line
/// [`run_swarm_loop`] runs rather than a copy of it.
fn swarm_child_brief(
    spec: &SpawnSpec,
    custody: &crate::engine::model_roles::DelegationCustody,
) -> String {
    custody.render_brief(&compose_child_brief(spec))
}

/// Compose the child's brief: its slice question plus a standing instruction
/// to persist findings to its dedicated write scope and return a compact
/// pointer + summary (the §10 aggregation pattern).
fn compose_child_brief(spec: &SpawnSpec) -> String {
    if spec.worker.is_goal_control() {
        return spec.prompt.clone();
    }
    format!(
        "{}\n\nSave your findings under `{}` (your dedicated output location — do not write \
         elsewhere). Return a compact summary plus a pointer to what you saved; do not dump the \
         full dataset back through your reply.",
        spec.prompt, spec.write_scope
    )
}

/// Budget-cap the child's terminal result for injection into main context
/// (GOALS §10). Leads with a pointer to the write scope so the aggregating
/// parent knows where the detail lives.
fn budget_result(label: &str, spec: &SpawnSpec, result: &str) -> String {
    let mut writer = BudgetedWriter::new(ASYNC_RESULT_TOKEN_CAP);
    let _ = writer.writeln(&format!("swarm `{label}` finished."));
    let _ = writer.writeln(&format!("output saved under: {}", spec.write_scope));
    let trimmed = result.trim();
    if !trimmed.is_empty() {
        let _ = writer.writeln("summary:");
        let _ = writer.writeln(trimmed);
    }
    writer.into_string()
}

/// A stable-ish progress key for the parent swarm job (the depth + brief
/// head); only used for the UI `ScheduleProgress` ping.
fn spec_label(spec: &SpawnSpec) -> String {
    let head: String = spec
        .prompt
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(16)
        .collect();
    format!("swarm[d{}] {head}", spec.depth)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_swarm_spawn_responses_result_keeps_dual_identity_and_name() {
        let result = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
            "call_spawn_background",
            Some("fc_spawn_background".to_string()),
            Some("call_spawn_background".to_string()),
            "spawn",
            "queued",
        );
        let Message::User { content } = result else {
            panic!("spawn result must be a user tool-result message");
        };
        let Some(rig::message::UserContent::ToolResult(result)) = content.first() else {
            panic!("spawn result must contain a tool result");
        };
        assert_eq!(result.call.as_str(), "call_spawn_background");
        assert_eq!(result.name, "spawn");
        assert_eq!(
            result
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("call_spawn_background")
        );
        assert_eq!(
            result
                .provider
                .as_ref()
                .and_then(|provider| provider.item_id.as_deref()),
            Some("fc_spawn_background")
        );
    }

    fn spec(depth: u32, max_depth: u32) -> SpawnSpec {
        SpawnSpec {
            job_id: None,
            goal_provenance: None,
            worker: SpawnWorkerKind::Bee,
            prompt: "find every firm in this state".into(),
            write_scope: "/tmp/state-ca".into(),
            model: None,
            model_origin: Default::default(),
            depth,
            max_depth,
        }
    }

    /// The brief-rendering step of swarm dispatch, exercised through
    /// [`swarm_child_brief`] — the exact call [`run_swarm_loop`] makes, not a
    /// re-implementation of it. Deleting or weakening the render inside that
    /// function fails this test.
    ///
    /// This test covers the rendering step only; it does not run the dispatch
    /// loop. [`swarm_dispatch_never_sends_a_secret_to_an_untrusted_child`]
    /// covers the loop end to end.
    ///
    /// A self-hosted (trusted) parent must not silently lose raw briefs — its
    /// inherited-custody children carry the parent's own class, so the brief
    /// arrives unchanged. An untrusted (cloud) child gets the session
    /// redaction-table rendering.
    #[test]
    fn swarm_child_brief_is_rendered_for_the_childs_custody_class() {
        use crate::config::providers::{ModelEntry, ModelTrust, ProviderEntry, ProvidersConfig};

        const SECRET: &str = "sk-live-swarm-secret";

        let mut cfg = ProvidersConfig::default();
        let entry = |trust: ModelTrust| ProviderEntry {
            url: "http://localhost:1/v1".into(),
            trust: Some(trust),
            models: vec![ModelEntry {
                id: "worker".into(),
                subagent_invokable: Some(true),
                ..ModelEntry::default()
            }],
            ..ProviderEntry::default()
        };
        cfg.providers
            .insert("selfhosted".into(), entry(ModelTrust::Trusted));
        cfg.providers
            .insert("cloud".into(), entry(ModelTrust::Untrusted));

        let table = Arc::new(
            crate::redact::RedactionTable::empty()
                .with_forced_literal(SECRET.to_string(), "TEST".to_string())
                .expect("forced literal"),
        );
        let extended = crate::config::extended::ExtendedConfig::default();

        let mut spec = spec(1, 3);
        spec.prompt = format!("use {SECRET} against the staging box");
        let composed = compose_child_brief(&spec);
        assert!(composed.contains(SECRET), "the composed brief carries it");

        // Trusted (self-hosted / no-log) parent → raw brief reaches the child.
        let trusted_parent = Arc::new(
            crate::engine::model::Model::for_provider(&cfg, "selfhosted", "worker", table.clone())
                .unwrap(),
        );
        let trusted_custody = crate::engine::model_roles::inherited_custody_for_model(
            &cfg,
            &trusted_parent,
            &extended,
        );
        assert_eq!(
            trusted_custody.custody(),
            crate::config::providers::ModelCustody::Trusted
        );
        let rendered = swarm_child_brief(&spec, &trusted_custody);
        assert_eq!(
            rendered, composed,
            "a self-hosted swarm must not silently lose raw briefs"
        );

        // Untrusted (cloud) child → session redaction-table rendering.
        let untrusted_child = Arc::new(
            crate::engine::model::Model::for_provider(&cfg, "cloud", "worker", table.clone())
                .unwrap(),
        );
        let untrusted_custody = crate::engine::model_roles::inherited_custody_for_model(
            &cfg,
            &untrusted_child,
            &extended,
        );
        assert_eq!(
            untrusted_custody.custody(),
            crate::config::providers::ModelCustody::Untrusted
        );
        let rendered = swarm_child_brief(&spec, &untrusted_custody);
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert_eq!(rendered, table.scrub(&composed));
    }

    /// Swarm dispatch, actually dispatched. This drives [`run_swarm_loop`]
    /// itself — child build, brief render, and a real provider request — and
    /// asserts on what came off the wire.
    ///
    /// The property under test is the one that matters for an untrusted
    /// (cloud, may-retain-logs) child: a secret in the parent's brief must
    /// never reach it. Two independent mechanisms stand behind that — the
    /// custody rendering in [`swarm_child_brief`] and the model's own outbound
    /// redaction guard — and this test fails if *either* is removed, because
    /// the assertion is made on the bytes the provider received rather than on
    /// an intermediate value.
    ///
    /// It also pins that dispatch happened at all: the captured body must
    /// carry the brief's non-secret text and the child's output-dir
    /// instruction, so the test cannot pass by never reaching the provider.
    #[tokio::test]
    async fn swarm_dispatch_never_sends_a_secret_to_an_untrusted_child() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        const SECRET: &str = "sk-live-swarm-dispatch-secret";

        // A provider that captures the request body and answers with a
        // one-token, finish_reason=stop completion so the loop ends after one
        // turn.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, capture_rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let mut tx = Some(tx);
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while let Ok(n) = tokio::io::AsyncReadExt::read(&mut stream, &mut tmp).await {
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
                    let content_len = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let body_start = header_end + 4;
                    if buf.len() >= body_start + content_len {
                        if let Some(tx) = tx.take() {
                            let _ = tx.send(
                                String::from_utf8_lossy(&buf[body_start..body_start + content_len])
                                    .into_owned(),
                            );
                        }
                        break;
                    }
                }
                let payload = "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"done\"},\"finish_reason\":null}],\"usage\":null}\n\n\
                               data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"total_tokens\":2}}\n\n\
                               data: [DONE]\n\n";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.flush().await;
            }
        });
        let base_url = format!("http://{addr}/v1");

        // A cloud (untrusted) provider on that endpoint, written where the
        // session config handle will read it.
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".cockpit")).unwrap();
        let config_path = tmp.path().join(".cockpit/config.json");
        std::fs::write(&config_path, r#"{}"#).unwrap();
        let mut providers = crate::config::providers::ProvidersConfig::default();
        providers.providers.insert(
            "cloud".into(),
            crate::config::providers::ProviderEntry {
                url: base_url.clone(),
                trust: Some(crate::config::providers::ModelTrust::Untrusted),
                timeout: crate::config::providers::TimeoutConfig {
                    ttft_secs: 10,
                    idle_secs: 10,
                },
                models: vec![crate::config::providers::ModelEntry {
                    id: "worker".into(),
                    subagent_invokable: Some(true),
                    can_delegate: Some(true),
                    ..crate::config::providers::ModelEntry::default()
                }],
                ..crate::config::providers::ProviderEntry::default()
            },
        );
        let mut doc = crate::config::providers::ConfigDoc::load(&config_path).unwrap();
        doc.write(&providers).unwrap();

        let table = Arc::new(
            crate::redact::RedactionTable::empty()
                .with_forced_literal(SECRET.to_string(), "[REDACTED]".to_string())
                .expect("forced literal"),
        );
        let config =
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path());
        let (_extended, effective_providers) =
            crate::engine::model_roles::load_model_role_config(&config);
        let parent_model = Arc::new(
            crate::engine::model::Model::for_provider(
                &effective_providers,
                "cloud",
                "worker",
                table.clone(),
            )
            .unwrap(),
        );

        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Arc::new(
            crate::session::Session::create_for_test(
                db,
                tmp.path().to_path_buf(),
                "Swarm",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        // The durable-before-handoff barrier is non-optional; install a
        // production-shaped journal so swarm-child inference is exercised.
        session.install_test_external_journal();
        let locks = Arc::new(crate::locks::LockManager::in_memory(
            crate::db::Db::open_in_memory().unwrap(),
        ));
        let parent = Agent {
            name: "Swarm".to_string(),
            system: "s".to_string(),
            role_prompt: "s".to_string(),
            tools: crate::engine::tool::ToolBox::new(),
            model: parent_model,
            params: crate::engine::model::ModelParams::default(),
            scan_tool_results: true,
            tool_steering: crate::agents::ToolSteering::Terse,
            posture: crate::agents::PostureResolution::standard(),
            context_policy: None,
            lock_identity: "Swarm".to_string(),
            write_scope: None,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            vnext_grant: None,
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            definition: None,
            assistant_identity_prefix: None,
            mcp_resolver: crate::mcp::resolver::EffectiveCatalogResolver::empty(),
        };
        let ctx = ScheduleContext {
            session,
            locks,
            redact: table.clone(),
            cwd: tmp.path().to_path_buf(),
            config,
            agent: Arc::new(parent),
            // This test drives `run_swarm_loop` directly to check brief
            // redaction; it never delegates write authority, so no coordinator
            // is installed. `None` is "no durable write-scope lifecycle", which
            // is the same value the sibling authority test uses.
            write_scope: None,
        };

        let mut spec = spec(1, 3);
        spec.prompt = format!("use {SECRET} against the staging box");
        let composed = compose_child_brief(&spec);
        assert!(composed.contains(SECRET), "the composed brief carries it");

        let (turn_tx, mut turn_rx) = mpsc::channel(256);
        let (cmd_tx, _cmd_rx) = mpsc::channel(8);
        tokio::spawn(async move { while turn_rx.recv().await.is_some() {} });

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            run_swarm_loop("job-test", &spec, &ctx, &turn_tx, &cmd_tx),
        )
        .await
        .expect("the swarm loop must finish against the local endpoint");
        outcome.expect("the swarm child must complete");

        let body = tokio::time::timeout(std::time::Duration::from_secs(10), capture_rx)
            .await
            .expect("the child must have reached the provider")
            .expect("captured request body");

        assert!(
            !body.contains(SECRET),
            "an untrusted swarm child must never receive the parent's secret: {body}"
        );
        assert!(
            body.contains("against the staging box"),
            "the brief must actually have been dispatched: {body}"
        );
        assert!(
            body.contains("/tmp/state-ca"),
            "the child's output-dir instruction must be on the wire: {body}"
        );
    }

    /// Fix-2: `run_swarm` EMITS the ordered `SwarmChildStopGateCompleted` marker
    /// on a genuine (non-goal-control) child's `Ok` success, FIFO after
    /// `SwarmChildStarted` and before the terminal `Completed`. This drives a real
    /// `run_swarm` for a `scout` (read-only → no write-scope transfer) against a
    /// local one-token endpoint so the child reaches `Done`/`Ok`. If the
    /// `event_tx.send(SwarmChildStopGateCompleted)` were dropped, a gated success
    /// would double at the driver drain (completed + aborted) — this test fails
    /// (the marker would be absent from the event order).
    #[tokio::test]
    async fn run_swarm_emits_stop_gate_marker_before_completed_on_success() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        // A provider that answers with a one-token, finish_reason=stop completion
        // so the child loop ends after one turn.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while let Ok(n) = tokio::io::AsyncReadExt::read(&mut stream, &mut tmp).await {
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
                    let content_len = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let body_start = header_end + 4;
                    if buf.len() >= body_start + content_len {
                        break;
                    }
                }
                let payload = "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"done\"},\"finish_reason\":null}],\"usage\":null}\n\n\
                               data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"total_tokens\":2}}\n\n\
                               data: [DONE]\n\n";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.flush().await;
            }
        });
        let base_url = format!("http://{addr}/v1");

        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".cockpit")).unwrap();
        let config_path = tmp.path().join(".cockpit/config.json");
        std::fs::write(&config_path, r#"{}"#).unwrap();
        let mut providers = crate::config::providers::ProvidersConfig::default();
        providers.providers.insert(
            "cloud".into(),
            crate::config::providers::ProviderEntry {
                url: base_url.clone(),
                trust: Some(crate::config::providers::ModelTrust::Untrusted),
                timeout: crate::config::providers::TimeoutConfig {
                    ttft_secs: 10,
                    idle_secs: 10,
                },
                models: vec![crate::config::providers::ModelEntry {
                    id: "worker".into(),
                    subagent_invokable: Some(true),
                    can_delegate: Some(true),
                    ..crate::config::providers::ModelEntry::default()
                }],
                ..crate::config::providers::ProviderEntry::default()
            },
        );
        let mut doc = crate::config::providers::ConfigDoc::load(&config_path).unwrap();
        doc.write(&providers).unwrap();

        let table = Arc::new(crate::redact::RedactionTable::empty());
        let config =
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path());
        let (_extended, effective_providers) =
            crate::engine::model_roles::load_model_role_config(&config);
        let parent_model = Arc::new(
            crate::engine::model::Model::for_provider(
                &effective_providers,
                "cloud",
                "worker",
                table.clone(),
            )
            .unwrap(),
        );

        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Arc::new(
            crate::session::Session::create_for_test(
                db,
                tmp.path().to_path_buf(),
                "Swarm",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        session.install_test_external_journal();
        let locks = Arc::new(crate::locks::LockManager::in_memory(
            crate::db::Db::open_in_memory().unwrap(),
        ));
        let parent = Agent {
            name: "Swarm".to_string(),
            system: "s".to_string(),
            role_prompt: "s".to_string(),
            tools: crate::engine::tool::ToolBox::new(),
            model: parent_model,
            params: crate::engine::model::ModelParams::default(),
            scan_tool_results: true,
            tool_steering: crate::agents::ToolSteering::Terse,
            posture: crate::agents::PostureResolution::standard(),
            context_policy: None,
            lock_identity: "Swarm".to_string(),
            write_scope: None,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            vnext_grant: None,
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            definition: None,
            assistant_identity_prefix: None,
            mcp_resolver: crate::mcp::resolver::EffectiveCatalogResolver::empty(),
        };
        let ctx = ScheduleContext {
            session,
            locks,
            redact: table.clone(),
            cwd: tmp.path().to_path_buf(),
            config,
            agent: Arc::new(parent),
            write_scope: None,
        };

        let mut spec = spec(1, 3);
        // A read-only `scout` takes NO write-scope transfer, so `run_swarm`
        // proceeds straight into the loop against the local endpoint.
        spec.worker = SpawnWorkerKind::Scout;

        let (turn_tx, mut turn_rx) = mpsc::channel(256);
        tokio::spawn(async move { while turn_rx.recv().await.is_some() {} });
        let (event_tx, mut event_rx) = mpsc::channel::<ScheduleEvent>(64);
        let (cmd_tx, _cmd_rx) = mpsc::channel(8);

        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            run_swarm(SwarmRunCtx {
                job_id: "job-marker".to_string(),
                label: "scout".to_string(),
                spec,
                ctx,
                turn_tx,
                event_tx,
                cmd_tx,
            }),
        )
        .await
        .expect("run_swarm must finish against the local endpoint");

        // The ordered event stream for a genuine gated success.
        let mut order = Vec::new();
        let mut saw_completed = false;
        while let Ok(Some(ev)) =
            tokio::time::timeout(std::time::Duration::from_secs(5), event_rx.recv()).await
        {
            match ev {
                ScheduleEvent::SwarmChildStarted { .. } => order.push("started"),
                ScheduleEvent::SwarmChildStopGateCompleted { .. } => order.push("gate"),
                ScheduleEvent::Completed { failed, .. } => {
                    assert!(!failed, "a scout success must be a non-failed Completed");
                    saw_completed = true;
                    break;
                }
                other => panic!("unexpected event {other:?}"),
            }
        }
        assert!(saw_completed, "run_swarm must emit a terminal Completed");
        assert_eq!(
            order,
            vec!["started", "gate"],
            "run_swarm must emit SwarmChildStopGateCompleted (FIFO) after the start \
             and before Completed; a dropped marker fails here"
        );
    }

    /// Fix-3: L22 at the SINGLE swarm gate funnel. Every gate site in
    /// `run_swarm_loop` routes through `swarm_child_stop_continuation`, which fails
    /// closed for a goal-supervision worker BEFORE dispatching any hook. Driving
    /// that funnel directly for each goal-control worker (with a MATCHING
    /// `subagentStop` hook configured) fires nothing; a genuine `scout` fires
    /// exactly one through the same funnel. Removing the `is_goal_control` guard
    /// inside the funnel makes the goal-control assertion fail (a `hook_run` row
    /// would appear) — covering all three gate sites via the one funnel.
    #[tokio::test]
    async fn swarm_stop_gate_never_fires_for_goal_control_workers() {
        use crate::config::extended::ExtendedConfig;
        use crate::config::extended::hooks::{HookEvent, HookOrigin, HookRegistry, ResolvedHook};
        use crate::config::providers::{ActiveModelRef, ProviderEntry, ProvidersConfig};
        use crate::daemon::session_worker::{SessionConfigHandle, SessionConfigSnapshot};

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Arc::new(
            crate::session::Session::create_for_test(
                db.clone(),
                root.clone(),
                "Swarm",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        let locks = Arc::new(crate::locks::LockManager::in_memory(db));
        let redact = Arc::new(crate::redact::RedactionTable::empty());

        let mut providers = std::collections::BTreeMap::new();
        providers.insert(
            "lmstudio".to_string(),
            ProviderEntry {
                url: "http://localhost:1/v1".into(),
                ..ProviderEntry::default()
            },
        );
        let pcfg = ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "lmstudio".into(),
                model: "local".into(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            }),
            ..ProvidersConfig::default()
        };
        let model = Arc::new(
            crate::engine::model::Model::from_config(
                &pcfg,
                Arc::new(crate::redact::RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = Arc::new(Agent {
            name: "Swarm".to_string(),
            system: "s".to_string(),
            role_prompt: "s".to_string(),
            tools: crate::engine::tool::ToolBox::new(),
            model,
            params: crate::engine::model::ModelParams::default(),
            scan_tool_results: true,
            tool_steering: crate::agents::ToolSteering::Terse,
            posture: crate::agents::PostureResolution::standard(),
            context_policy: None,
            lock_identity: "Swarm".to_string(),
            write_scope: None,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            vnext_grant: None,
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            definition: None,
            assistant_identity_prefix: None,
            mcp_resolver: crate::mcp::resolver::EffectiveCatalogResolver::empty(),
        });
        let ctx = ScheduleContext {
            session,
            locks,
            redact,
            cwd: root,
            config: SessionConfigHandle::detached_default(),
            agent,
            write_scope: None,
        };

        let pinned_with_stop_hook = |matcher: &str| -> SessionConfigHandle {
            let reg = HookRegistry {
                hooks: vec![ResolvedHook {
                    event: HookEvent::SubagentStop,
                    matcher: Some([matcher.to_string()].into_iter().collect()),
                    command: vec!["cockpit-swarm-hook-does-not-exist".to_string()],
                    timeout_secs: 5,
                    env: std::collections::BTreeMap::new(),
                    origin: HookOrigin::for_test("project:abcdef0123456789:0"),
                    source_config_path: std::path::PathBuf::from("/tmp/test/config.json"),
                    source_directory: std::path::PathBuf::from("/tmp/test"),
                    execution: crate::config::extended::hooks::HookExecutionProvenance::Ambient,
                }],
                warnings: Vec::new(),
            };
            SessionConfigHandle::detached(SessionConfigSnapshot::with_hooks(
                1,
                ProvidersConfig::default(),
                ExtendedConfig::default(),
                reg,
            ))
        };

        async fn subagent_stop_rows(db: &crate::db::Db, sid: uuid::Uuid) -> usize {
            db.list_session_events(sid)
                .await
                .unwrap()
                .into_iter()
                .filter(|e| e.kind == "hook_run" && e.data["event"] == "subagentStop")
                .count()
        }

        // Every goal-supervision worker: the funnel returns None and fires
        // nothing, even with a matching subagentStop hook configured.
        for worker in [
            SpawnWorkerKind::GoalPlanner,
            SpawnWorkerKind::GoalEvaluator,
            SpawnWorkerKind::GoalGatekeeper,
            SpawnWorkerKind::GoalColdSkeptic,
        ] {
            let mut s = spec(0, 3);
            s.worker = worker;
            let pinned = pinned_with_stop_hook(worker.agent_name());
            let mut state = crate::engine::agent::hooks::StopGateState::default();
            let cancel = tokio_util::sync::CancellationToken::new();
            let out =
                swarm_child_stop_continuation("job-gc", &s, &ctx, &pinned, &cancel, &mut state)
                    .await;
            assert!(out.is_none(), "{worker:?} must not gate (L22)");
        }
        assert_eq!(
            subagent_stop_rows(&ctx.session.db, ctx.session.id).await,
            0,
            "L22: no goal-supervision worker fires subagentStop at the gate funnel"
        );

        // Positive control: a genuine `scout` DOES fire exactly one subagentStop
        // through the SAME funnel — so the zero above is a real guard, not a
        // config where the hook could never match.
        let mut scout = spec(0, 3);
        scout.worker = SpawnWorkerKind::Scout;
        let pinned = pinned_with_stop_hook("scout");
        let mut state = crate::engine::agent::hooks::StopGateState::default();
        let cancel = tokio_util::sync::CancellationToken::new();
        let _ =
            swarm_child_stop_continuation("job-scout", &scout, &ctx, &pinned, &cancel, &mut state)
                .await;
        assert_eq!(
            subagent_stop_rows(&ctx.session.db, ctx.session.id).await,
            1,
            "a non-goal worker fires exactly one subagentStop through the same funnel"
        );
    }

    /// A spawn spec defaults to model-directed provenance: anything that forgets
    /// to say where its selector came from gets the conservative filter.
    #[test]
    fn spawn_spec_model_origin_defaults_to_model_directed() {
        assert_eq!(spec(0, 3).model_origin, SpawnModelOrigin::ModelDirected);
        assert_eq!(SpawnModelOrigin::default(), SpawnModelOrigin::ModelDirected);
    }

    /// Regression: host provenance must not launder through a nested spawn.
    ///
    /// A host-config goal-verification skeptic holding `spawn` used to hand its
    /// `HostConfig` origin to a grandchild whose selector came from the **tool
    /// argument** — letting the model name any trusted endpoint and obtain raw
    /// custody plus a real grant. A tool-supplied selector is always
    /// `ModelDirected`; only an unchanged inherited selector keeps `HostConfig`.
    #[tokio::test]
    async fn nested_spawn_cannot_launder_host_provenance() {
        async fn child_origin(parent: &SpawnSpec, child_model: Option<&str>) -> SpawnModelOrigin {
            // The scenario this test describes is a goal-verification skeptic,
            // which is dispatched as a `Scout` (see the
            // `goalSupervision.coldSkepticModel` spawn in `driver`). Use that
            // worker kind here: a write-capable grandchild is refused by the
            // scoped-write barrier *before* dispatch, so it would never reach
            // the provenance computation this test exists to pin. Provenance
            // itself is worker-independent.
            let mut parent = parent.clone();
            parent.worker = SpawnWorkerKind::Scout;
            let parent = &parent;

            // `write_scope` is validated for every worker, so it must name a
            // real subtree of the workspace.
            let ws = workspace();

            let (cmd_tx, mut cmd_rx) = mpsc::channel::<ScheduleCommand>(8);
            let (turn_tx, _turn_rx) = mpsc::channel::<TurnEvent>(8);
            let handle = tokio::spawn(async move {
                match cmd_rx.recv().await {
                    Some(ScheduleCommand::Spawn { spec, result_tx }) => {
                        if let Some(result_tx) = result_tx {
                            let _ = result_tx.send("scheduled".to_string());
                        }
                        spec.model_origin
                    }
                    _ => panic!("expected a spawn command"),
                }
            });
            let _ = route_child_spawn(
                parent,
                "deeper slice",
                "slice",
                ws.path(),
                child_model.map(str::to_string),
                &cmd_tx,
                &turn_tx,
            )
            .await;
            handle.await.expect("spawn command observed")
        }

        let mut host_parent = spec(0, 3);
        host_parent.model = Some("selfhosted:skeptic".into());
        host_parent.model_origin = SpawnModelOrigin::HostConfig;

        // The laundering attempt: a *different*, model-authored selector.
        assert_eq!(
            child_origin(&host_parent, Some("selfhosted:llama")).await,
            SpawnModelOrigin::ModelDirected,
            "a tool-supplied selector can never inherit host provenance"
        );

        // No selector at all: the child inherits the parent's model, so the
        // parent's provenance is still the honest answer.
        assert_eq!(
            child_origin(&host_parent, None).await,
            SpawnModelOrigin::HostConfig
        );

        // Repeating the host-config value verbatim is not an escalation.
        assert_eq!(
            child_origin(&host_parent, Some("selfhosted:skeptic")).await,
            SpawnModelOrigin::HostConfig
        );

        // A model-directed parent can never produce host provenance.
        let mut model_parent = spec(0, 3);
        model_parent.model = Some("selfhosted:skeptic".into());
        model_parent.model_origin = SpawnModelOrigin::ModelDirected;
        assert_eq!(
            child_origin(&model_parent, Some("selfhosted:skeptic")).await,
            SpawnModelOrigin::ModelDirected
        );
        assert_eq!(
            child_origin(&model_parent, None).await,
            SpawnModelOrigin::ModelDirected
        );
    }

    /// A workspace with one child subtree, so `write_scope` resolution is
    /// exercised against a real directory rather than a synthetic path.
    fn workspace() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("slice")).unwrap();
        tmp
    }

    /// A child at the ceiling that calls `spawn` is refused — the
    /// branch degrades to a leaf (clamp, don't crash, GOALS §24). No request
    /// is sent to main.
    #[tokio::test]
    async fn route_child_spawn_refuses_over_ceiling() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ScheduleCommand>(8);
        let (turn_tx, _turn_rx) = mpsc::channel::<TurnEvent>(8);
        // depth 3, ceiling 3 → a child would be depth 4 > 3: refused.
        let s = spec(3, 3);
        let ws = workspace();
        let out = route_child_spawn(
            &s,
            "deeper",
            "/tmp/deeper",
            ws.path(),
            None,
            &cmd_tx,
            &turn_tx,
        )
        .await;
        assert!(out.contains("refused"), "got {out}");
        assert!(out.contains("yourself"), "got {out}");
        assert!(
            cmd_rx.try_recv().is_err(),
            "no spawn request should be routed"
        );
    }

    /// A child below the ceiling routes the spawn back to main (the single
    /// authority) at depth+1.
    #[tokio::test]
    async fn route_child_spawn_routes_under_ceiling() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ScheduleCommand>(8);
        let (turn_tx, _turn_rx) = mpsc::channel::<TurnEvent>(8);
        let mut s = spec(1, 3);
        // No Cockpit write tools: a write-capable child is refused by the
        // barrier (see `route_child_spawn_refuses_writable_delegation`).
        s.worker = SpawnWorkerKind::Scout;
        let ws = workspace();
        let routed = route_child_spawn(
            &s,
            "city slice",
            "slice",
            ws.path(),
            None,
            &cmd_tx,
            &turn_tx,
        );
        tokio::pin!(routed);
        let result_tx = tokio::select! {
            maybe = cmd_rx.recv() => match maybe {
                Some(ScheduleCommand::Spawn { spec, result_tx }) => {
                    assert_eq!(spec.depth, 2, "depth advances by one per edge");
                    assert_eq!(spec.write_scope, "slice");
                    assert_eq!(spec.max_depth, 3);
                    result_tx
                }
                other => panic!("expected a routed Spawn, got {other:?}"),
            },
            out = &mut routed => panic!("route_child_spawn returned before routing: {out}"),
        };
        result_tx.unwrap().send("scheduled".to_string()).unwrap();
        let out = routed.await;
        assert!(out.contains("scheduled"), "got {out}");
    }

    #[tokio::test]
    async fn route_child_spawn_preserves_scout_worker_and_model() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ScheduleCommand>(8);
        let (turn_tx, _turn_rx) = mpsc::channel::<TurnEvent>(8);
        let mut s = spec(1, 3);
        s.worker = SpawnWorkerKind::Scout;
        let ws = workspace();
        let routed = route_child_spawn(
            &s,
            "adjudicate claim",
            "slice",
            ws.path(),
            Some("openrouter/reviewer".into()),
            &cmd_tx,
            &turn_tx,
        );
        tokio::pin!(routed);
        let result_tx = tokio::select! {
            maybe = cmd_rx.recv() => match maybe {
                Some(ScheduleCommand::Spawn { spec, result_tx }) => {
                    assert_eq!(spec.worker, SpawnWorkerKind::Scout);
                    assert_eq!(spec.model.as_deref(), Some("openrouter/reviewer"));
                    assert_eq!(spec.depth, 2);
                    result_tx
                }
                other => panic!("expected a routed Spawn, got {other:?}"),
            },
            out = &mut routed => panic!("route_child_spawn returned before routing: {out}"),
        };
        result_tx.unwrap().send("scheduled".to_string()).unwrap();
        let out = routed.await;
        assert!(out.contains("scheduled"), "got {out}");
    }

    /// A `bee` fanning out to a deeper `bee` is a strict writable delegation:
    /// the grandchild would get exclusive authority over a subtree. The direct
    /// workspace cannot isolate arbitrary child syscalls, so the request is
    /// refused before anything is routed to main.
    #[tokio::test]
    async fn route_child_spawn_refuses_writable_delegation() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ScheduleCommand>(8);
        let (turn_tx, _turn_rx) = mpsc::channel::<TurnEvent>(8);
        let s = spec(1, 3);
        assert_eq!(s.worker, SpawnWorkerKind::Bee);
        let ws = workspace();
        let out = route_child_spawn(
            &s,
            "deeper slice",
            "slice",
            ws.path(),
            None,
            &cmd_tx,
            &turn_tx,
        )
        .await;
        assert!(out.contains("refused"), "got {out}");
        assert!(out.contains("hard link"), "the refusal explains why: {out}");
        assert!(
            cmd_rx.try_recv().is_err(),
            "a refused writable delegation must route nothing to main"
        );
    }

    /// The child brief pins the dedicated write scope + the compact-pointer
    /// return convention (GOALS §10 aggregation pattern).
    #[test]
    fn child_brief_pins_write_scope_and_compact_return() {
        let brief = compose_child_brief(&spec(1, 3));
        assert!(brief.contains("/tmp/state-ca"), "{brief}");
        assert!(brief.contains("dedicated output location"), "{brief}");
        assert!(brief.contains("compact summary"), "{brief}");
    }
}
