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
//! persists to its dedicated `output_dir`/DB and returns a compact pointer).
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
    MAX_SWARM_PROMPT_BYTES, ScheduleCommand, ScheduleContext, ScheduleEvent, SpawnSpec,
    SpawnWorkerKind,
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

    let result = match run_swarm_loop(&spec, &ctx, &turn_tx, &cmd_tx).await {
        Ok(text) => text,
        Err(e) => {
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

    let body = budget_result(&label, &spec, &result);
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
    spec: &SpawnSpec,
    ctx: &ScheduleContext,
    turn_tx: &mpsc::Sender<TurnEvent>,
    cmd_tx: &mpsc::Sender<ScheduleCommand>,
) -> anyhow::Result<String> {
    let agent = Arc::new(build_swarm_child(spec, ctx)?);
    let mut history: Vec<Message> = Vec::new();
    let brief = compose_child_brief(spec);
    let mut next_prompt = Message::user(brief);

    // A background swarm child is a leaf with no human on the other end:
    // a detached interrupt hub + a fresh cancel token satisfy `turn`'s
    // signature (same rationale as the loop-fork runner). No approver →
    // native tools skip the boundary prompt (never deny); the loop guard is
    // inert without one.
    let interrupts = Arc::new(crate::engine::interrupt::InterruptHub::detached());
    let cancel = tokio_util::sync::CancellationToken::new();
    let deferred_log = crate::engine::deferred::DeferredLog::new();
    let seeds = crate::engine::seed_collector::SeedCollector::new();

    // Per-turn backup-model fallback for the background `Swarm` child
    // (implementation note): `Swarm` is in scope, so the
    // child inherits the same mechanism, resolved against the model it runs on.
    let backup_model = crate::engine::driver::resolve_backup_model_for(&ctx.cwd, &agent.model);

    for _ in 0..SWARM_MAX_TURNS {
        let outcome = crate::engine::agent::turn_with_backup(
            &agent,
            backup_model.as_ref(),
            &mut history,
            next_prompt,
            ctx.session.clone(),
            ctx.locks.clone(),
            ctx.redact.clone(),
            ctx.cwd.clone(),
            interrupts.clone(),
            cancel.clone(),
            None,
            None,
            None,
            crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            // A noninteractive child recomposes its own fresh system block on
            // spawn; it never needs the live instructions-file diff injection.
            false,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            deferred_log.clone(),
            seeds.clone(),
            // Swarm subagents run in detached job tasks, not the driver
            // stack, and are not tandem-shadowed; a fresh per-round id satisfies
            // the shared `turn` contract.
            uuid::Uuid::new_v4(),
            // Swarm subagents are not tandem-shadowed (out of the §26 fan-out
            // scope; the spec shadows primary + builder/explore/docs only).
            None,
            None,
            turn_tx,
        )
        .await?;
        match outcome {
            TurnOutcome::Continue => {
                next_prompt = history
                    .pop()
                    .expect("Continue with empty history is unreachable");
            }
            TurnOutcome::Done => return Ok(collect_final_text(&history)),
            // The child fanned out further. Route the spawn back to main (the
            // single authority) — or refuse it at the ceiling (clamp, don't
            // crash) — and feed the resulting pointer back as this call's
            // tool result so the child can keep going.
            TurnOutcome::Spawn {
                prompt,
                output_dir,
                model,
                task_call_id,
                task_function_call_id,
            } => {
                let pointer =
                    route_child_spawn(spec, &prompt, &output_dir, model, cmd_tx, turn_tx).await;
                next_prompt =
                    Message::tool_result_with_call_id(task_call_id, task_function_call_id, pointer);
            }
            // A `bee` child is leaf-terminated for every edge *except*
            // bee→bee (handled above via `spawn`): it holds `task` only to
            // reach `docs`, which the noninteractive child path does not run
            // recursively here, and never holds handoff/done/jobs-as-spawn.
            // `return` is its structured finish tool — treat it (and any stray
            // structural outcome from a weak model) as end-of-run, returning
            // what the child has (clamp, don't crash).
            TurnOutcome::SpawnSubagent { .. }
            | TurnOutcome::SpawnNoninteractive { .. }
            | TurnOutcome::SpawnNoninteractiveBatch { .. }
            | TurnOutcome::TaskControl { .. }
            | TurnOutcome::ToolResult { .. }
            | TurnOutcome::ScheduleAction { .. }
            | TurnOutcome::Handoff { .. }
            | TurnOutcome::Return { .. } => {
                return Ok(collect_final_text(&history));
            }
        }
    }
    Ok(collect_final_text(&history))
}

/// Route a running child's own `spawn` to main, or refuse it at the
/// ceiling. The child's depth is `spec.depth`; a grandchild would be
/// `spec.depth + 1`. When that would exceed the ceiling the spawn is refused
/// and the branch must do the work inline (the tool result says so).
async fn route_child_spawn(
    spec: &SpawnSpec,
    prompt: &str,
    output_dir: &str,
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
    if prompt.len() > MAX_SWARM_PROMPT_BYTES {
        return format!(
            "refused: spawn prompt is {} bytes; maximum is {} bytes",
            prompt.len(),
            MAX_SWARM_PROMPT_BYTES
        );
    }
    let child = SpawnSpec {
        worker: spec.worker,
        prompt: prompt.to_string(),
        output_dir: output_dir.to_string(),
        model,
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
fn build_swarm_child(spec: &SpawnSpec, ctx: &ScheduleContext) -> anyhow::Result<Agent> {
    let model = match spec.model.as_deref() {
        Some(selector) => {
            let (extended, providers) =
                crate::engine::model_roles::load_model_role_config(&ctx.cwd);
            crate::engine::model_roles::resolve_selector(
                selector,
                &extended,
                &providers,
                &ctx.agent.model,
            )
            .map_err(|_| anyhow::anyhow!("invalid explicit spawn model selector `{selector}`"))?
        }
        None => ctx.agent.model.clone(),
    };
    let args = SpawnArgs {
        model,
        params: ctx.agent.params.clone(),
        env_overlay: ctx.agent.env_overlay.clone(),
        cwd: ctx.cwd.clone(),
        session_short_id: ctx.session.short_id.clone(),
        model_system_prompt_snapshot: ctx.session.model_system_prompt_snapshot(),
        // A background swarm child is noninteractive (no human attached).
        interactive: false,
        llm_mode: ctx.agent.llm_mode,
        // Plan-level overrides don't apply to ad-hoc swarm fan-out.
        model_override: None,
        delegation_model: None,
        delegated: true,
        delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
        swarm_depth: spec.depth,
        swarm_max_depth: spec.max_depth,
        // Background swarm children carry no per-delegation grants.
        granted_tools: Vec::new(),
    };
    // The recursive worker unit is `bee` (GOALS §24/§26): a noninteractive,
    // write-capable, parallel worker that may itself fan out deeper `bee`
    // workers via `spawn`. The interactive `Swarm` primary holds `spawn`; each
    // background child it fans out is a `bee`.
    Ok(match spec.worker {
        SpawnWorkerKind::Bee => crate::engine::builtin::bee(&args),
        SpawnWorkerKind::Scout => crate::engine::builtin::scout(&args),
    })
}

/// Compose the child's brief: its slice question plus a standing instruction
/// to persist findings to its dedicated output dir and return a compact
/// pointer + summary (the §10 aggregation pattern).
fn compose_child_brief(spec: &SpawnSpec) -> String {
    format!(
        "{}\n\nSave your findings under `{}` (your dedicated output location — do not write \
         elsewhere). Return a compact summary plus a pointer to what you saved; do not dump the \
         full dataset back through your reply.",
        spec.prompt, spec.output_dir
    )
}

/// Budget-cap the child's terminal result for injection into main context
/// (GOALS §10). Leads with a pointer to the output dir so the aggregating
/// parent knows where the detail lives.
fn budget_result(label: &str, spec: &SpawnSpec, result: &str) -> String {
    let mut writer = BudgetedWriter::new(ASYNC_RESULT_TOKEN_CAP);
    let _ = writer.writeln(&format!("swarm `{label}` finished."));
    let _ = writer.writeln(&format!("output saved under: {}", spec.output_dir));
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

    fn spec(depth: u32, max_depth: u32) -> SpawnSpec {
        SpawnSpec {
            worker: SpawnWorkerKind::Bee,
            prompt: "find every firm in this state".into(),
            output_dir: "/tmp/state-ca".into(),
            model: None,
            depth,
            max_depth,
        }
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
        let out = route_child_spawn(&s, "deeper", "/tmp/deeper", None, &cmd_tx, &turn_tx).await;
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
        let s = spec(1, 3);
        let routed = route_child_spawn(&s, "city slice", "/tmp/city", None, &cmd_tx, &turn_tx);
        tokio::pin!(routed);
        let result_tx = tokio::select! {
            maybe = cmd_rx.recv() => match maybe {
                Some(ScheduleCommand::Spawn { spec, result_tx }) => {
                    assert_eq!(spec.depth, 2, "depth advances by one per edge");
                    assert_eq!(spec.output_dir, "/tmp/city");
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
        let routed = route_child_spawn(
            &s,
            "adjudicate claim",
            "/tmp/review-claim",
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

    /// The child brief pins the dedicated output dir + the compact-pointer
    /// return convention (GOALS §10 aggregation pattern).
    #[test]
    fn child_brief_pins_output_dir_and_compact_return() {
        let brief = compose_child_brief(&spec(1, 3));
        assert!(brief.contains("/tmp/state-ca"), "{brief}");
        assert!(brief.contains("dedicated output location"), "{brief}");
        assert!(brief.contains("compact summary"), "{brief}");
    }
}
