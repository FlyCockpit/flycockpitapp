//! The single async-job authority + registry (GOALS §22).
//!
//! The authority lives on the driver. It owns the registry of live jobs
//! and the per-job spawned tasks. Two channels connect it to the rest of
//! the engine:
//!
//! - **commands** ([`ScheduleCommand`]): driver → authority. A `schedule` tool call
//!   in the main context turns into a command. The driver calls
//!   [`ScheduleAuthority::handle_command`] inline (it's cheap; no `.await` on
//!   network).
//! - **events** ([`ScheduleEvent`]): authority → driver. Drained by the driver
//!   at the **same turn boundary** as the user-input queue. Carries the
//!   things that must enter *main context*: a keep-in-context loop
//!   iteration's prompt, and any job's terminal result.
//!
//! UI-only signals (job started, per-iteration progress, fork notes, job
//! failed) are emitted by the authority straight onto the engine
//! [`TurnEvent`] channel — they reach the TUI but never the model's main
//! context until termination (token economy, §22 "UI visibility and
//! context injection are deliberately separated").
//!
//! ## Loop execution split
//!
//! - `keep_in_context = true`: the authority schedules a ticking timer
//!   that sends [`ScheduleEvent::LoopIterationDue`] to the driver; the driver
//!   runs the prompt as a real turn in **main history**, then tells the
//!   authority the iteration finished ([`ScheduleCommand::IterationFinished`])
//!   so it can schedule the next tick or terminate.
//! - `keep_in_context = false`: the whole loop runs inside the spawned
//!   task on an **ephemeral fork** ([`super::loop_runner`]); only `note`s
//!   (live UI) and the terminal result (via [`ScheduleEvent::Completed`]) cross
//!   to main.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;
use uuid::Uuid;

use crate::engine::agent::{Agent, TurnEvent};
use crate::engine::schedule::loop_runner::{self, LoopRunCtx};
use crate::engine::schedule::spec::{
    BackgroundStartArgs, LoopStartArgs, ScheduleKind, SpawnRequest,
};
use crate::redact::RedactionTable;
use crate::session::Session;

use super::{background, swarm};

/// A command from the driver to the authority over the async command
/// channel. The driver mutates the authority directly for everything it
/// originates (start / iteration-finished); this channel exists for
/// commands that arrive from **outside** the turn loop — today, a
/// human-initiated cancel routed through the session worker (GOALS §22).
#[derive(Debug)]
pub enum ScheduleCommand {
    /// Cancel a job (loop / timer / background) by id. From the human
    /// ("stop checking the deploy", `/schedule cancel <id>`).
    Cancel { job_id: String },
    /// A running recursive `Swarm` child called `spawn` (GOALS
    /// §24). Per single-async-job authority a child does **not** spawn async
    /// work directly — it posts this request and main (the authority) decides:
    /// schedule it (depth + concurrency permitting) or queue it. The child's
    /// own depth-ceiling check already ran in its runner; this carries the
    /// pre-advanced spec.
    Spawn {
        spec: SpawnSpec,
        result_tx: Option<oneshot::Sender<String>>,
    },
}

/// Maximum number of recursive `Swarm` spawn requests waiting for a free
/// concurrency slot.
pub const MAX_SWARM_QUEUE_LEN: usize = 256;

/// Maximum UTF-8 byte length accepted for a recursive `Swarm` spawn prompt.
pub const MAX_SWARM_PROMPT_BYTES: usize = 256 * 1024;

/// An event from the authority to the driver, drained at the turn
/// boundary. These are the only signals that affect **main context**.
#[derive(Debug)]
pub enum ScheduleEvent {
    /// A keep-in-context loop iteration is due: run `prompt` as a turn in
    /// main history. After the turn the driver posts
    /// [`ScheduleCommand::IterationFinished`].
    LoopIterationDue { job_id: String, prompt: String },
    /// A job reached a terminal state and its result must be injected into
    /// main context as a late-arriving turn. `notes` are the fork's
    /// accumulated notes (ephemeral loops); empty otherwise.
    Completed {
        job_id: String,
        label: String,
        kind: ScheduleKind,
        /// Budget-capped result text.
        result: String,
        /// `true` when the job failed (non-zero exit, error). Drives the
        /// `needs_attention` flag wording.
        failed: bool,
        /// Create-action requests a fork emitted (anti-runaway): main
        /// decides whether to honour them. Empty for non-fork jobs.
        requests: Vec<SpawnRequest>,
    },
}

/// One row in the live-jobs registry. Cloned cheaply into the
/// [`ScheduleSnapshot`] the TUI strip / `/schedule` read.
struct ScheduleEntry {
    job_id: String,
    label: String,
    kind: ScheduleKind,
    /// `Some(n)` = iteration cap; `None` = unlimited.
    limit: Option<u64>,
    /// Completed iterations so far (loops only).
    iteration: u64,
    /// Abort handle for the spawned task (background, ephemeral loop) or
    /// `None` for an in-context loop (driven by the driver, no task).
    abort: Option<AbortHandle>,
    /// For in-context loops: the scheduler state needed to re-arm.
    in_context: Option<InContextLoop>,
    /// Handle the authority uses to talk to a background job (tail / kill).
    background: Option<Arc<background::BackgroundHandle>>,
}

/// Per-iteration scheduling state for a keep-in-context loop. The
/// authority arms a timer task that fires [`ScheduleEvent::LoopIterationDue`].
struct InContextLoop {
    args: LoopStartArgs,
    /// The next tick's delay, doubled each iteration when `backoff`.
    next_delay_secs: u64,
    /// Abort handle for the currently-armed tick timer (if any).
    timer_abort: Option<AbortHandle>,
}

/// A read-only snapshot of one live job, for the TUI strip and `/schedule`.
#[derive(Debug, Clone)]
pub struct ScheduleSnapshot {
    pub job_id: String,
    pub label: String,
    pub kind: ScheduleKind,
    pub limit: Option<u64>,
    pub iteration: u64,
    pub status: ScheduleStatus,
}

/// Live registry status for a job. Terminal jobs are removed from the live
/// registry after their completion event is emitted, so snapshots currently
/// expose only non-terminal states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleStatus {
    Pending,
    Running,
}

impl ScheduleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ScheduleStatus::Pending => "pending",
            ScheduleStatus::Running => "running",
        }
    }
}

/// Shared context the authority threads into spawned job tasks.
#[derive(Clone)]
pub struct ScheduleContext {
    pub session: Arc<Session>,
    pub locks: Arc<crate::locks::LockManager>,
    pub redact: Arc<RedactionTable>,
    pub cwd: std::path::PathBuf,
    /// Session config reader for the async-job's turns, captured from the
    /// driver so loop/swarm iterations read the same snapshot as the
    /// foreground turn (`engine-config-snapshot-adoption`).
    pub config: crate::daemon::session_worker::SessionConfigHandle,
    /// The main agent — ephemeral-fork loop iterations run on the same
    /// agent/model/provider config (GOALS §22).
    pub agent: Arc<Agent>,
}

/// The worker kind scheduled through the recursive `Swarm` authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnWorkerKind {
    Bee,
    Scout,
}

/// A scheduled-or-queued recursive `Swarm` subagent (GOALS §24). Built by
/// the driver from a `spawn` call (depth pre-advanced + ceiling
/// checked), or posted back by a running `Swarm` child that itself called
/// `spawn` (routed through main, the single authority). The
/// authority owns the queue + the running-count, enforcing the global
/// concurrency cap centrally.
#[derive(Debug, Clone)]
pub struct SpawnSpec {
    /// Which worker factory to use. Both route through this same authority:
    /// write-capable `bee` for Swarm, read-only `scout` for Multireview.
    pub worker: SpawnWorkerKind,
    /// The child's self-contained brief.
    pub prompt: String,
    /// The dedicated output folder/DB the child writes results into.
    pub output_dir: String,
    /// Optional caller-supplied model selector for this worker.
    pub model: Option<String>,
    /// This child's recursive depth (root = 0; advanced by one per
    /// Swarm→Swarm edge). Already clamped ≤ ceiling by the caller.
    pub depth: u32,
    /// The depth ceiling, threaded onto the child's `SpawnArgs` so its own
    /// `spawn` description shows the remaining budget.
    pub max_depth: u32,
}

/// The single async-job authority. Owned by the driver; never cloned.
pub struct ScheduleAuthority {
    registry: BTreeMap<String, ScheduleEntry>,
    /// Cap on concurrently-running jobs.
    pub max_concurrent: usize,
    /// Sender the authority hands to spawned tasks + timers so they post
    /// [`ScheduleEvent`]s back to the driver.
    event_tx: mpsc::Sender<ScheduleEvent>,
    /// Self-command channel: spawned timers post `IterationFinished`-style
    /// re-arm requests here. Actually the driver owns command delivery;
    /// the authority also holds a clone so in-task timers can re-arm.
    cmd_tx: mpsc::Sender<ScheduleCommand>,
    /// Engine event channel for UI-only signals (started / progress /
    /// note / failed). Cloned into spawned tasks.
    turn_tx: mpsc::Sender<TurnEvent>,
    /// Shared per-session context for spawning ephemeral-fork loops +
    /// background jobs.
    ctx: ScheduleContext,
    /// Global cap on simultaneously-running recursive `Swarm` subagents
    /// across the whole tree (GOALS §24, `swarm.max_concurrency`). `0` =
    /// unlimited. This is a **separate** budget from [`Self::max_concurrent`]
    /// (the loop/timer/background cap): swarm fan-out has its own cap so
    /// it neither starves nor is starved by the §22 job set.
    swarm_max_concurrency: usize,
    /// Count of currently-running recursive `Swarm` subagents. Bumped on
    /// dispatch, decremented on the swarm job's terminal completion.
    running_swarm: usize,
    /// Recursive `Swarm` spawns that arrived while at the concurrency cap
    /// (GOALS §24). Drained FIFO as running jobs complete and slots free.
    swarm_queue: std::collections::VecDeque<SpawnSpec>,
}

impl ScheduleAuthority {
    /// Build an authority. `event_tx` is drained by the driver at the turn
    /// boundary; `cmd_tx` lets in-task timers re-arm; `turn_tx` is the
    /// engine event channel for UI-only signals.
    pub fn new(
        event_tx: mpsc::Sender<ScheduleEvent>,
        cmd_tx: mpsc::Sender<ScheduleCommand>,
        turn_tx: mpsc::Sender<TurnEvent>,
        ctx: ScheduleContext,
        max_concurrent: usize,
    ) -> Self {
        Self {
            registry: BTreeMap::new(),
            max_concurrent: max_concurrent.max(1),
            event_tx,
            cmd_tx,
            turn_tx,
            ctx,
            swarm_max_concurrency: crate::config::extended::DEFAULT_SWARM_MAX_CONCURRENCY,
            running_swarm: 0,
            swarm_queue: std::collections::VecDeque::new(),
        }
    }

    /// Set the global recursive-`Swarm` concurrency cap (GOALS §24). `0`
    /// means unlimited. Installed by the driver from `swarm.max_concurrency`
    /// before the loop starts.
    pub fn set_swarm_max_concurrency(&mut self, cap: usize) {
        self.swarm_max_concurrency = cap;
    }

    /// Whether one more recursive `Swarm` subagent would exceed the global
    /// cap (GOALS §24). Always `false` when the cap is `0` (unlimited).
    fn swarm_at_capacity(&self) -> bool {
        self.swarm_max_concurrency != 0 && self.running_swarm >= self.swarm_max_concurrency
    }

    /// Number of currently-running recursive `Swarm` subagents (test +
    /// `/schedule`-strip visibility).
    pub fn running_swarm(&self) -> usize {
        self.running_swarm
    }

    /// Refresh the redaction table cloned into newly spawned scheduled work.
    /// Existing in-flight tasks keep the table they started with; every
    /// schedule/loop/background task started after this boundary inherits the
    /// new one.
    pub fn set_redaction_table(&mut self, table: Arc<RedactionTable>) {
        self.ctx.redact = table;
    }

    /// Refresh the session config reader handed to async-job turns. In-flight
    /// tasks keep the handle they started with; jobs spawned after this
    /// boundary read the new (re-pinned) snapshot — the same turn-boundary
    /// semantics as [`Self::set_redaction_table`]
    /// (`engine-config-snapshot-adoption`).
    pub fn set_config_handle(
        &mut self,
        config: crate::daemon::session_worker::SessionConfigHandle,
    ) {
        self.ctx.config = config;
    }

    #[cfg(test)]
    pub fn redaction_table(&self) -> Arc<RedactionTable> {
        self.ctx.redact.clone()
    }

    /// Number of recursive `Swarm` spawns waiting on a free slot.
    pub fn queued_swarm(&self) -> usize {
        self.swarm_queue.len()
    }

    /// Schedule a recursive `Swarm` subagent, or queue it when at the
    /// global concurrency cap (GOALS §24). Returns a human pointer the caller
    /// surfaces as the `spawn` tool result: the started job id, or a
    /// queued-position note. Depth is already advanced + ceiling-checked by
    /// the caller (the driver / the child runner) — this method only enforces
    /// the concurrency cap and FIFO queueing.
    pub fn spawn_swarm(&mut self, spec: SpawnSpec) -> String {
        if spec.prompt.len() > MAX_SWARM_PROMPT_BYTES {
            return format!(
                "refused: spawn prompt is {} bytes; maximum is {} bytes",
                spec.prompt.len(),
                MAX_SWARM_PROMPT_BYTES
            );
        }
        if self.swarm_at_capacity() {
            if self.swarm_queue.len() >= MAX_SWARM_QUEUE_LEN {
                return format!(
                    "refused: swarm queue is full ({} waiting; max {})",
                    self.swarm_queue.len(),
                    MAX_SWARM_QUEUE_LEN
                );
            }
            self.swarm_queue.push_back(spec);
            return format!(
                "queued (swarm concurrency cap {} reached; {} waiting) — starts when a slot frees",
                self.swarm_max_concurrency,
                self.swarm_queue.len()
            );
        }
        let job_id = self.start_swarm_now(spec);
        format!("scheduled swarm subagent `{job_id}` (running in the background)")
    }

    /// Start a recursive `Swarm` subagent task immediately (slot already
    /// reserved by the caller's cap check). Registers the job, bumps the
    /// running count, and spawns the runner. Returns the job id.
    fn start_swarm_now(&mut self, spec: SpawnSpec) -> String {
        let job_id = new_job_id();
        let label = swarm_label(&spec);
        self.running_swarm += 1;
        self.emit_started(&job_id, &label, ScheduleKind::Swarm);

        let run_ctx = swarm::SwarmRunCtx {
            job_id: job_id.clone(),
            label: label.clone(),
            spec,
            ctx: self.ctx.clone(),
            turn_tx: self.turn_tx.clone(),
            event_tx: self.event_tx.clone(),
            cmd_tx: self.cmd_tx.clone(),
        };
        let handle = tokio::spawn(swarm::run_swarm(run_ctx));
        let entry = ScheduleEntry {
            job_id: job_id.clone(),
            label,
            kind: ScheduleKind::Swarm,
            limit: None,
            iteration: 0,
            abort: Some(handle.abort_handle()),
            in_context: None,
            background: None,
        };
        self.registry.insert(job_id.clone(), entry);
        job_id
    }

    /// A recursive `Swarm` subagent finished (GOALS §24): decrement the
    /// running count and start the next queued spawn if one is waiting and a
    /// slot is now free. Called by the driver when it drains a swarm job's
    /// terminal [`ScheduleEvent::Completed`].
    pub fn swarm_completed(&mut self) {
        self.running_swarm = self.running_swarm.saturating_sub(1);
        while !self.swarm_at_capacity() {
            let Some(spec) = self.swarm_queue.pop_front() else {
                break;
            };
            self.start_swarm_now(spec);
        }
    }

    /// `true` when at least one loop is live — gates `loop.cancel` enabling.
    pub fn has_loop(&self) -> bool {
        self.registry
            .values()
            .any(|e| matches!(e.kind, ScheduleKind::Loop | ScheduleKind::Timer))
    }

    /// `true` when at least one background job exists — gates
    /// `background.tail` / `background.cancel` enabling.
    pub fn has_background(&self) -> bool {
        self.registry
            .values()
            .any(|e| matches!(e.kind, ScheduleKind::Background))
    }

    /// Snapshot for the TUI strip / `/schedule`, sorted by job id.
    pub fn snapshot(&self) -> Vec<ScheduleSnapshot> {
        self.registry
            .values()
            .map(|e| ScheduleSnapshot {
                job_id: e.job_id.clone(),
                label: e.label.clone(),
                kind: e.kind,
                limit: e.limit,
                iteration: e.iteration,
                status: if e.iteration == 0 {
                    ScheduleStatus::Pending
                } else {
                    ScheduleStatus::Running
                },
            })
            .collect()
    }

    /// Look up a background handle for `tail`.
    pub fn background_handle(&self, job_id: &str) -> Option<Arc<background::BackgroundHandle>> {
        self.registry.get(job_id).and_then(|e| e.background.clone())
    }

    /// Drop a job that reported terminal completion from its own spawned
    /// task. In-context loops remove themselves before emitting completion;
    /// this is primarily for background, forked-loop, and swarm tasks.
    pub fn mark_completed(&mut self, job_id: &str) {
        if let Some(mut entry) = self.registry.remove(job_id) {
            if let Some(ic) = &mut entry.in_context
                && let Some(t) = ic.timer_abort.take()
            {
                t.abort();
            }
            entry.abort.take();
        }
    }

    /// `true` when the concurrency cap would be exceeded by one more job.
    pub fn at_capacity(&self) -> bool {
        self.registry.len() >= self.max_concurrent
    }

    /// Start a loop/timer that accumulates in the main context. Returns
    /// the registered job id (echoed back to the model so it can cancel).
    pub fn start_loop_in_context(&mut self, args: LoopStartArgs) -> String {
        let job_id = new_job_id();
        let kind = args.kind();
        let label = loop_label(&args);
        let entry = ScheduleEntry {
            job_id: job_id.clone(),
            label: label.clone(),
            kind,
            limit: args.limit,
            iteration: 0,
            abort: None,
            in_context: Some(InContextLoop {
                next_delay_secs: args.interval_secs,
                args,
                timer_abort: None,
            }),
            background: None,
        };
        self.registry.insert(job_id.clone(), entry);
        self.emit_started(&job_id, &label, kind);
        // Arm the first tick.
        self.arm_in_context_tick(&job_id);
        job_id
    }

    /// Start an ephemeral-fork loop (`keep_in_context = false`). The whole
    /// loop runs inside the spawned task; only notes (live UI) + the
    /// terminal result cross to main.
    pub fn start_loop_forked(&mut self, args: LoopStartArgs) -> String {
        let job_id = new_job_id();
        let kind = args.kind();
        let label = loop_label(&args);
        self.emit_started(&job_id, &label, kind);

        let run_ctx = LoopRunCtx {
            job_id: job_id.clone(),
            label: label.clone(),
            args: args.clone(),
            ctx: self.ctx.clone(),
            turn_tx: self.turn_tx.clone(),
            event_tx: self.event_tx.clone(),
        };
        let handle = tokio::spawn(loop_runner::run_forked_loop(run_ctx));
        let entry = ScheduleEntry {
            job_id: job_id.clone(),
            label,
            kind,
            limit: args.limit,
            iteration: 0,
            abort: Some(handle.abort_handle()),
            in_context: None,
            background: None,
        };
        self.registry.insert(job_id.clone(), entry);
        job_id
    }

    /// Start a background shell job. Returns the job id.
    pub fn start_background(&mut self, args: BackgroundStartArgs) -> String {
        let job_id = new_job_id();
        let label = background_label(&args);
        self.emit_started(&job_id, &label, ScheduleKind::Background);

        let cwd = args
            .cwd
            .as_deref()
            .map(|s| crate::tools::common::resolve(s, &self.ctx.cwd))
            .unwrap_or_else(|| self.ctx.cwd.clone());

        let (handle, task) = background::spawn(
            job_id.clone(),
            label.clone(),
            args.command.clone(),
            cwd,
            self.ctx.redact.clone(),
            self.turn_tx.clone(),
            self.event_tx.clone(),
        );
        let abort = task.abort_handle();
        let entry = ScheduleEntry {
            job_id: job_id.clone(),
            label,
            kind: ScheduleKind::Background,
            limit: None,
            iteration: 0,
            abort: Some(abort),
            in_context: None,
            background: Some(Arc::new(handle)),
        };
        self.registry.insert(job_id.clone(), entry);
        job_id
    }

    /// Cancel a job by id. Returns `true` if it existed. For an
    /// in-context loop, this also promotes its current state as the
    /// terminal result (the model called `loop.cancel`, so the loop is
    /// done — the spec promotes the terminal iteration's result; here the
    /// in-context iterations already accumulated in main, so we just
    /// drop the schedule and emit a terminal marker for the strip).
    pub fn cancel(&mut self, job_id: &str) -> bool {
        let Some(mut entry) = self.registry.remove(job_id) else {
            return false;
        };
        // Stop any armed tick timer + spawned task.
        if let Some(ic) = &mut entry.in_context
            && let Some(t) = ic.timer_abort.take()
        {
            t.abort();
        }
        if let Some(a) = entry.abort.take() {
            a.abort();
        }
        if let Some(bg) = &entry.background {
            bg.kill();
        }
        // In-context loops: the iterations already reached main; emit a
        // terminal completion so the strip clears and a marker shows.
        if entry.in_context.is_some() {
            self.send_terminal_event(ScheduleEvent::Completed {
                job_id: entry.job_id.clone(),
                label: entry.label.clone(),
                kind: entry.kind,
                result: format!(
                    "{} cancelled after {} iteration(s)",
                    entry.kind.as_str(),
                    entry.iteration
                ),
                failed: false,
                requests: Vec::new(),
            });
        }
        // Ephemeral loops + background: the spawned task is aborted; we
        // synthesize the terminal completion here since the task won't get
        // to send its own.
        else {
            self.send_terminal_event(ScheduleEvent::Completed {
                job_id: entry.job_id.clone(),
                label: entry.label.clone(),
                kind: entry.kind,
                result: format!("{} `{}` cancelled", entry.kind.as_str(), entry.label),
                failed: false,
                requests: Vec::new(),
            });
        }
        true
    }

    /// A keep-in-context iteration finished. Advance the count; arm the
    /// next tick or terminate (limit reached).
    pub fn iteration_finished(&mut self, job_id: &str) {
        let terminal = {
            let Some(entry) = self.registry.get_mut(job_id) else {
                return;
            };
            entry.iteration = entry.iteration.saturating_add(1);
            let Some(ic) = &mut entry.in_context else {
                return;
            };
            // Backoff: double the next delay up to the ceiling.
            if ic.args.backoff {
                ic.next_delay_secs =
                    (ic.next_delay_secs.saturating_mul(2)).min(super::spec::BACKOFF_CEILING_SECS);
            }
            matches!(entry.limit, Some(limit) if entry.iteration >= limit)
        };
        if terminal {
            // Limit reached: emit terminal completion, drop the entry.
            if let Some(entry) = self.registry.remove(job_id) {
                self.send_terminal_event(ScheduleEvent::Completed {
                    job_id: entry.job_id.clone(),
                    label: entry.label.clone(),
                    kind: entry.kind,
                    result: format!(
                        "{} `{}` completed after {} iteration(s)",
                        entry.kind.as_str(),
                        entry.label,
                        entry.iteration
                    ),
                    failed: false,
                    requests: Vec::new(),
                });
            }
        } else {
            self.arm_in_context_tick(job_id);
        }
    }

    /// Handle a [`ScheduleCommand`] that arrived over the async command channel
    /// (a human-initiated cancel). Everything the driver originates it
    /// calls directly via the dedicated `start_*` / `iteration_finished`
    /// methods.
    pub fn handle_command(&mut self, cmd: ScheduleCommand) {
        match cmd {
            ScheduleCommand::Cancel { job_id } => {
                self.cancel(&job_id);
            }
            // A running `Swarm` child requested a deeper spawn (GOALS §24).
            // Main is the single authority: schedule it or queue it under the
            // global cap. The pointer return is dropped here — the child
            // already received its synchronous "scheduled/queued" tool result
            // from its own runner; this path only does the actual scheduling.
            ScheduleCommand::Spawn { spec, result_tx } => {
                let result = self.spawn_swarm(spec);
                if let Some(result_tx) = result_tx {
                    let _ = result_tx.send(result);
                }
            }
        }
    }

    /// Arm a timer task that, after the next delay, posts
    /// [`ScheduleEvent::LoopIterationDue`] for `job_id`.
    fn arm_in_context_tick(&mut self, job_id: &str) {
        let (delay, prompt) = {
            let Some(entry) = self.registry.get(job_id) else {
                return;
            };
            let Some(ic) = &entry.in_context else {
                return;
            };
            (ic.next_delay_secs, ic.args.prompt.clone())
        };
        let event_tx = self.event_tx.clone();
        let jid = job_id.to_string();
        let task = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            let _ = event_tx
                .send(ScheduleEvent::LoopIterationDue {
                    job_id: jid,
                    prompt,
                })
                .await;
        });
        if let Some(entry) = self.registry.get_mut(job_id)
            && let Some(ic) = &mut entry.in_context
            && let Some(old) = ic.timer_abort.replace(task.abort_handle())
        {
            old.abort();
        }
    }

    /// Deliver terminal schedule events without losing them to a temporarily
    /// full channel. Progress/UI events stay best-effort, but completion is
    /// the authority's reconciliation signal.
    fn send_terminal_event(&self, event: ScheduleEvent) {
        match self.event_tx.try_send(event) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(event)) => {
                let tx = self.event_tx.clone();
                tokio::spawn(async move {
                    let _ = tx.send(event).await;
                });
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    /// Emit the UI-only `started` signal.
    fn emit_started(&self, job_id: &str, label: &str, kind: ScheduleKind) {
        let _ = self.turn_tx.try_send(TurnEvent::ScheduleStarted {
            session_id: self.ctx.session.id,
            job_id: job_id.to_string(),
            label: label.to_string(),
            kind: kind.as_str().to_string(),
        });
    }

    /// Re-derive the command sender so the session worker can post
    /// driver-side commands (used by tests + the driver wiring).
    pub fn command_sender(&self) -> mpsc::Sender<ScheduleCommand> {
        self.cmd_tx.clone()
    }

    /// Rebind the engine [`TurnEvent`] channel used for UI-only signals.
    /// The driver builds the authority before it has the per-turn event
    /// sender (`tx`), then rebinds it once `run_main_loop` starts — before
    /// any job can be created, so no UI signal is ever lost.
    pub fn set_turn_tx(&mut self, tx: mpsc::Sender<TurnEvent>) {
        self.turn_tx = tx;
    }

    /// Rebind the fork context's agent after a primary swap (`/plan` ↔
    /// `/build`, `plan.md §4.6.d`) so future ephemeral-fork loop iterations
    /// run on the new primary's model/tool surface. Existing live jobs keep
    /// the agent they were spawned with.
    pub fn set_agent(&mut self, agent: Arc<Agent>) {
        self.ctx.agent = agent;
    }

    #[cfg(test)]
    pub(crate) fn agent_name_for_tests(&self) -> &str {
        &self.ctx.agent.name
    }
}

/// Short random scheduled-task id (`sched-xxxxxxxx`). Human-typable in
/// `/schedule cancel` and short enough for the strip. The `sched-` prefix is
/// generated here only (implementation note); it is opaque on
/// the read path, so pre-rename `job-…` ids in existing session-log rows still
/// round-trip untouched (no `strip_prefix("job-")` anywhere — back-compat read).
fn new_job_id() -> String {
    let u = Uuid::new_v4();
    let short = &u.simple().to_string()[..8];
    format!("sched-{short}")
}

/// One-line label for a loop/timer (the command-ish summary shown in the
/// strip and completion marker).
fn loop_label(args: &LoopStartArgs) -> String {
    let first = args.prompt.lines().next().unwrap_or("").trim();
    let snippet: String = first.chars().take(32).collect();
    if first.chars().count() > 32 {
        format!("{snippet}…")
    } else {
        snippet
    }
}

/// One-line label for a recursive `Swarm` subagent (its output dir +
/// the first line of the brief), shown in the strip + completion marker.
fn swarm_label(spec: &SpawnSpec) -> String {
    let first = spec.prompt.lines().next().unwrap_or("").trim();
    let snippet: String = first.chars().take(28).collect();
    let head = if first.chars().count() > 28 {
        format!("{snippet}…")
    } else {
        snippet
    };
    format!("swarm[d{}] {head}", spec.depth)
}

/// One-line label for a background job (first line of the command).
fn background_label(args: &BackgroundStartArgs) -> String {
    let first = args.command.lines().next().unwrap_or("").trim();
    let snippet: String = first.chars().take(40).collect();
    if first.chars().count() > 40 {
        format!("{snippet}…")
    } else {
        snippet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::schedule::spec::parse_loop_start;
    use std::time::Duration;

    /// Build a test authority with a keyless localhost model (never
    /// called by the in-context / background paths under test). Returns
    /// the authority + the job-event receiver + the UI-event receiver.
    fn test_authority(
        max: usize,
    ) -> (
        ScheduleAuthority,
        mpsc::Receiver<ScheduleEvent>,
        mpsc::Receiver<TurnEvent>,
        tempfile::TempDir,
    ) {
        use crate::config::providers::{ActiveModelRef, ProviderEntry, ProvidersConfig};
        use std::collections::BTreeMap;

        // A real on-disk cwd so background jobs (real subprocesses) can
        // spawn. Returned so it outlives the authority.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session =
            Arc::new(crate::session::Session::create(db.clone(), root.clone(), "builder").unwrap());
        let locks = Arc::new(crate::locks::LockManager::from_db(db).unwrap());
        let cfg = crate::config::extended::RedactConfig::default();
        let redact = Arc::new(RedactionTable::build(&cfg, &root).unwrap());

        let mut providers = BTreeMap::new();
        providers.insert(
            "lmstudio".to_string(),
            ProviderEntry {
                url: "http://localhost:1/v1".into(),
                headers: vec![],
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
            }),
            ..ProvidersConfig::default()
        };
        let model = Arc::new(
            crate::engine::model::Model::from_config(
                &pcfg,
                std::sync::Arc::new(crate::redact::RedactionTable::empty()),
            )
            .unwrap(),
        );
        let agent = Arc::new(crate::engine::agent::Agent {
            name: "builder".into(),
            system: String::new(),
            role_prompt: String::new(),
            tools: crate::engine::tool::ToolBox::new(),
            model,
            params: crate::engine::model::ModelParams::default(),
            scan_tool_results: true,
            llm_mode: crate::config::extended::LlmMode::default(),
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        });

        let (event_tx, event_rx) = mpsc::channel(64);
        let (cmd_tx, _cmd_rx) = mpsc::channel(64);
        let (turn_tx, turn_rx) = mpsc::channel(64);
        let ctx = ScheduleContext {
            session,
            locks,
            redact,
            cwd: root,
            config: crate::daemon::session_worker::SessionConfigHandle::detached_default(),
            agent,
        };
        let authority = ScheduleAuthority::new(event_tx, cmd_tx, turn_tx, ctx, max);
        (authority, event_rx, turn_rx, tmp)
    }

    /// An in-context loop fires a `LoopIterationDue` each interval and,
    /// once its limit is reached, emits a terminal `Completed`. The driver
    /// drives the turns; here we simulate that by calling
    /// `iteration_finished` after each due event.
    #[tokio::test(start_paused = true)]
    async fn in_context_loop_ticks_then_terminates_at_limit() {
        let (mut auth, mut events, mut ui, _tmp) = test_authority(8);
        let args = parse_loop_start(&serde_json::json!({
            "interval": 10, "prompt": "poll", "limit": 2
        }))
        .unwrap();
        let job_id = auth.start_loop_in_context(args);
        assert!(auth.has_loop());
        // started UI signal.
        assert!(matches!(
            ui.try_recv(),
            Ok(TurnEvent::ScheduleStarted { .. })
        ));

        // Tick 1.
        tokio::time::advance(Duration::from_secs(10)).await;
        match events.recv().await.unwrap() {
            ScheduleEvent::LoopIterationDue { job_id: j, prompt } => {
                assert_eq!(j, job_id);
                assert_eq!(prompt, "poll");
            }
            other => panic!("expected LoopIterationDue, got {other:?}"),
        }
        auth.iteration_finished(&job_id);

        // Tick 2 (the last).
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(matches!(
            events.recv().await.unwrap(),
            ScheduleEvent::LoopIterationDue { .. }
        ));
        auth.iteration_finished(&job_id);

        // Limit reached → terminal Completed, registry emptied.
        match events.recv().await.unwrap() {
            ScheduleEvent::Completed { kind, failed, .. } => {
                assert_eq!(kind, ScheduleKind::Loop);
                assert!(!failed);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert!(!auth.has_loop());
    }

    /// A timer (`limit = 1`) fires exactly one iteration then completes.
    #[tokio::test(start_paused = true)]
    async fn timer_fires_once() {
        let (mut auth, mut events, _ui, _tmp) = test_authority(8);
        let args = parse_loop_start(&serde_json::json!({
            "interval": 5, "prompt": "fire", "limit": 1
        }))
        .unwrap();
        assert!(args.is_timer());
        let job_id = auth.start_loop_in_context(args);

        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(matches!(
            events.recv().await.unwrap(),
            ScheduleEvent::LoopIterationDue { .. }
        ));
        auth.iteration_finished(&job_id);
        match events.recv().await.unwrap() {
            ScheduleEvent::Completed { kind, .. } => assert_eq!(kind, ScheduleKind::Timer),
            other => panic!("expected timer Completed, got {other:?}"),
        }
        assert!(!auth.has_loop());
    }

    /// `loop.cancel` ends a live in-context loop early and emits a
    /// terminal Completed.
    #[tokio::test(start_paused = true)]
    async fn cancel_ends_loop_early() {
        let (mut auth, mut events, _ui, _tmp) = test_authority(8);
        let args = parse_loop_start(&serde_json::json!({
            "interval": 60, "prompt": "poll", "limit": 0
        }))
        .unwrap();
        let job_id = auth.start_loop_in_context(args);
        assert!(auth.has_loop());
        assert!(auth.cancel(&job_id));
        match events.recv().await.unwrap() {
            ScheduleEvent::Completed { failed, .. } => assert!(!failed),
            other => panic!("expected Completed, got {other:?}"),
        }
        assert!(!auth.has_loop());
        assert!(!auth.cancel(&job_id), "double-cancel is a no-op");
    }

    #[tokio::test(start_paused = true)]
    async fn terminal_completion_survives_full_event_channel() {
        let (mut auth, mut events, _ui, _tmp) = test_authority(8);
        let args = parse_loop_start(&serde_json::json!({
            "interval": 60, "prompt": "poll", "limit": 0
        }))
        .unwrap();
        let job_id = auth.start_loop_in_context(args);

        for i in 0..64 {
            auth.event_tx
                .try_send(ScheduleEvent::LoopIterationDue {
                    job_id: format!("dummy-{i}"),
                    prompt: "blocked".to_string(),
                })
                .unwrap();
        }
        assert!(auth.cancel(&job_id));

        for _ in 0..64 {
            assert!(matches!(
                events.recv().await.unwrap(),
                ScheduleEvent::LoopIterationDue { .. }
            ));
        }
        tokio::task::yield_now().await;
        match events.recv().await.unwrap() {
            ScheduleEvent::Completed {
                job_id: j, failed, ..
            } => {
                assert_eq!(j, job_id);
                assert!(!failed);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn swarm_budget_is_separate_from_schedule_capacity() {
        let (mut auth, _events, _ui, _tmp) = test_authority(1);
        let args = parse_loop_start(&serde_json::json!({
            "interval": 60, "prompt": "poll", "limit": 0
        }))
        .unwrap();
        auth.start_loop_in_context(args);
        assert!(
            auth.at_capacity(),
            "ordinary schedule capacity should be full"
        );
        auth.set_swarm_max_concurrency(2);

        let msg = auth.spawn_swarm(swarm_spec(1));
        assert!(msg.contains("scheduled"), "got {msg}");
        assert_eq!(auth.running_swarm(), 1);
        assert_eq!(auth.queued_swarm(), 0);
    }

    /// A background `echo` job runs, retains output for `tail`, and injects
    /// a budget-capped completion. Uses real wall-clock time (the child is
    /// a real subprocess) so this test does not pause time.
    #[tokio::test]
    async fn background_runs_tails_and_completes() {
        let (mut auth, mut events, mut ui, _tmp) = test_authority(8);
        let args = crate::engine::schedule::spec::parse_background_start(&serde_json::json!({
            "command": "printf 'hello\\nworld\\n'"
        }))
        .unwrap();
        let job_id = auth.start_background(args);
        assert!(auth.has_background());
        match ui.try_recv() {
            Ok(TurnEvent::ScheduleStarted {
                job_id: j, kind, ..
            }) => {
                assert_eq!(j, job_id);
                assert_eq!(kind, "background");
            }
            other => panic!("expected ScheduleStarted, got {other:?}"),
        }

        // Wait for completion.
        let completed = tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("background should complete")
            .unwrap();
        match completed {
            ScheduleEvent::Completed {
                kind,
                failed,
                result,
                ..
            } => {
                assert_eq!(kind, ScheduleKind::Background);
                assert!(!failed, "echo exits 0 — got result: {result}");
                assert!(
                    result.contains("world"),
                    "output should be captured: {result}"
                );
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    /// A [`SpawnSpec`] for the recursive-`Swarm` cap/queue tests.
    fn swarm_spec(depth: u32) -> SpawnSpec {
        SpawnSpec {
            worker: SpawnWorkerKind::Bee,
            prompt: "slice".into(),
            output_dir: "/tmp/out".into(),
            model: None,
            depth,
            max_depth: 3,
        }
    }

    /// The global recursive-`Swarm` concurrency cap (GOALS §24) starts
    /// jobs up to the cap and queues the rest; a completion frees a slot and
    /// drains one queued spawn. Asserted synchronously right after each call
    /// (the spawned child tasks error out against the keyless model later,
    /// which doesn't affect the synchronous accounting under test).
    #[tokio::test(start_paused = true)]
    async fn swarm_concurrency_cap_queues_then_drains() {
        let (mut auth, _events, _ui, _tmp) = test_authority(8);
        auth.set_swarm_max_concurrency(2);

        // Two start immediately (running == cap), the third queues.
        assert!(auth.spawn_swarm(swarm_spec(1)).contains("scheduled"));
        assert!(auth.spawn_swarm(swarm_spec(1)).contains("scheduled"));
        assert_eq!(auth.running_swarm(), 2);
        let queued_msg = auth.spawn_swarm(swarm_spec(1));
        assert!(queued_msg.contains("queued"), "got {queued_msg}");
        assert_eq!(auth.running_swarm(), 2);
        assert_eq!(auth.queued_swarm(), 1);

        // A completion frees a slot → the queued spawn starts.
        auth.swarm_completed();
        assert_eq!(auth.running_swarm(), 2);
        assert_eq!(auth.queued_swarm(), 0);

        // Two more completions empty the running set.
        auth.swarm_completed();
        auth.swarm_completed();
        assert_eq!(auth.running_swarm(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn swarm_queue_rejects_when_full() {
        let (mut auth, _events, _ui, _tmp) = test_authority(8);
        auth.set_swarm_max_concurrency(1);
        assert!(auth.spawn_swarm(swarm_spec(1)).contains("scheduled"));
        for _ in 0..MAX_SWARM_QUEUE_LEN {
            assert!(auth.spawn_swarm(swarm_spec(1)).contains("queued"));
        }
        assert_eq!(auth.queued_swarm(), MAX_SWARM_QUEUE_LEN);
        let refused = auth.spawn_swarm(swarm_spec(1));
        assert!(refused.contains("refused"), "got {refused}");
        assert!(refused.contains("queue is full"), "got {refused}");
        assert_eq!(auth.queued_swarm(), MAX_SWARM_QUEUE_LEN);
    }

    #[tokio::test(start_paused = true)]
    async fn swarm_spawn_rejects_oversized_prompt() {
        let (mut auth, _events, _ui, _tmp) = test_authority(8);
        let mut spec = swarm_spec(1);
        spec.prompt = "x".repeat(MAX_SWARM_PROMPT_BYTES + 1);
        let refused = auth.spawn_swarm(spec);
        assert!(refused.contains("refused"), "got {refused}");
        assert!(refused.contains("maximum"), "got {refused}");
        assert_eq!(auth.running_swarm(), 0);
        assert_eq!(auth.queued_swarm(), 0);
    }

    /// `swarm.max_concurrency = 0` means unlimited (GOALS §24): every
    /// spawn starts immediately, nothing queues.
    #[tokio::test(start_paused = true)]
    async fn swarm_concurrency_zero_is_unlimited() {
        let (mut auth, _events, _ui, _tmp) = test_authority(8);
        auth.set_swarm_max_concurrency(0);
        for _ in 0..20 {
            assert!(auth.spawn_swarm(swarm_spec(1)).contains("scheduled"));
        }
        assert_eq!(auth.running_swarm(), 20);
        assert_eq!(auth.queued_swarm(), 0);
    }

    /// The concurrency cap is observable via `at_capacity` once the
    /// registry is full.
    #[tokio::test(start_paused = true)]
    async fn capacity_cap_observed() {
        let (mut auth, _events, _ui, _tmp) = test_authority(1);
        assert!(!auth.at_capacity());
        let args =
            parse_loop_start(&serde_json::json!({ "interval": 60, "prompt": "p", "limit": 0 }))
                .unwrap();
        auth.start_loop_in_context(args);
        assert!(auth.at_capacity());
    }
}
