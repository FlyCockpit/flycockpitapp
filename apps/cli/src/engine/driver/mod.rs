//! Multi-agent conversation driver.
//!
//! Holds a stack of `AgentSession`s — one per active agent in the
//! current invocation tree. The user always talks to the agent on top
//! of the stack. On a `task` tool call, the driver pushes a new
//! subagent; when that subagent finishes (final text + no tool calls
//! and the parent has an outstanding task call), the driver pops it
//! and delivers the subagent's text as the parent's tool result.
//!
//! This is the v0 implementation of GOALS §3b's *interactive subagent*:
//! the primary-agent identity swaps every time the stack height
//! changes, and the user's messages route to whoever's on top.

mod context_reduction;
mod inbound;
mod noninteractive;
mod schedule_dispatch;
mod skills_seed;
mod swap;

#[cfg(test)]
use context_reduction::*;
use context_reduction::{PruneEffectiveness, wire_token_total};
use inbound::injection_check_prompt_target;
#[cfg(test)]
use noninteractive::*;
use noninteractive::{
    BackgroundNoninteractiveCompletion, BackgroundNoninteractiveJob, BatchNoninteractiveTask,
    DelegationPartialProgress, NoninteractiveDelegationRegistry, PartialProgressCommand,
    PartialProgressFileEdit, SingleNoninteractiveTask, handle_footer, stale_handle_error,
};
pub(crate) use noninteractive::{NoninteractiveSteerTarget, run_noninteractive};
use skills_seed::SkillPair;

use std::{collections::HashSet, path::PathBuf, pin::Pin, sync::Arc};

use anyhow::{Context, Result, bail};
use tokio::sync::mpsc;
use tokio::time::{Duration, Sleep};

use crate::engine::agent::{Agent, TaskControlAction, TurnEvent, TurnOutcome, turn_with_backup};
use crate::engine::message::{
    Message, UserSubmission, UserSubmissionKind, extract_text, extract_user_text,
};
use crate::engine::prune;
use crate::engine::schedule::{ScheduleAuthority, ScheduleCommand, ScheduleEvent};
use crate::redact::RedactionTable;
use crate::session::Session;

/// Out-of-band control requests routed to the driver from the daemon
/// worker — `/prune`, `/compact`, `/pin`. Drained on the same boundary
/// as user input and job events so they never interleave with a
/// mid-turn state (the safe-boundary rule, `plan.md` T6.e).
#[derive(Debug)]
pub enum DriverControl {
    #[cfg(test)]
    #[allow(dead_code)]
    AbortForTest,
    /// Run snapshot dedup on the foreground agent now. `confirmed` is
    /// always true here — the confirm UX lives in the TUI; by the time a
    /// `Prune` reaches the driver the user has already accepted the
    /// before→after numbers.
    Prune,
    /// Assemble a `/compact` handoff for the foreground agent: prune
    /// first (fixed ordering), draft the model brief, append the
    /// deterministic appendix, derive seed-tools, create a fresh session,
    /// and emit `CompactReady`.
    Compact,
    /// Pin a user message verbatim for the next `/compact` (`/pin`).
    Pin { text: String },
    /// Explicitly opt into synthetic resume repair for a Responses session
    /// that strict replay opened read-only. The original transcript is not
    /// mutated; only the live root history is populated with the healed replay.
    RepairResume {
        root_agent: String,
        respond_to: tokio::sync::oneshot::Sender<std::result::Result<usize, String>>,
    },
    /// Swap the **primary** (root-frame) agent in place (`/plan` → `Plan`,
    /// `/build` → `Build`, `plan.md §4.6.d`). Handled at the idle boundary
    /// like other control requests; the root history is preserved so the
    /// new primary continues the same conversation with its own tool
    /// surface + system prompt. A no-op when an interactive subagent holds
    /// the foreground (stack depth > 1) or the name is already active.
    SwapPrimary { name: String },
    /// Switch the active `llm_mode` live (`/llm-mode`,
    /// implementation note). Rebuilds the root-frame
    /// agent so its tool-description verbosity + per-mode prompt re-render;
    /// busts the cached system prefix (the TUI shows the cache-break warning
    /// via the shared helper, suppressed on a no-cache provider). Root
    /// history is preserved — same conversation, new steering. A no-op when
    /// an interactive subagent holds the foreground or the mode is unchanged.
    /// `mode = None` toggles against the driver's authoritative current value
    /// (the `/llm-mode` / `toggle` default action); `Some(_)` sets it
    /// explicitly.
    SetLlmMode {
        mode: Option<crate::config::extended::LlmMode>,
    },
    /// Swap the session's redaction table live (`/toggle-redaction`). The
    /// session worker rebuilds the table from the in-memory effective
    /// `RedactConfig` and hands it here; the driver replaces `self.redact`
    /// so subsequent outbound prompts (and newly-cloned tool contexts /
    /// subagents) scrub against it. Session-only — no config write.
    /// `scrub()` stays non-bypassable; only the table contents change.
    SetRedaction {
        table: Arc<RedactionTable>,
        scan_environment: Option<bool>,
        scan_dotenv: Option<bool>,
        scan_ssh_keys: Option<bool>,
    },
    /// Set (or toggle) the session-only request-preflight override
    /// (`/preflight`, implementation note). `None` toggles against
    /// the driver's authoritative current effective state; `Some(_)` sets it
    /// explicitly. The driver records the override (precedence over config) and
    /// emits [`TurnEvent::PreflightState`] with the resulting state. Session-
    /// only — no config write; reverts on restart (mirrors [`Self::SetRedaction`]).
    SetPreflight { enabled: Option<bool> },
    /// Set a session-only root delegation recursion override (`/quick`).
    /// Root delegation still obeys existing allowed-target and per-agent
    /// max-depth policy; this only overrides the default enabled/depth values.
    SetDelegationRecursion { enabled: bool, default_depth: u32 },
    /// Update the per-user-message primary round ceiling from the latest
    /// layered settings. Applied at the next idle/control boundary so a
    /// `/settings` edit affects subsequent user messages in this session.
    SetMaxPrimaryRounds { max_rounds: u32 },
    /// Switch the active model+provider live mid-session (`/model` picker,
    /// implementation note). The driver builds the new
    /// [`Model`](crate::engine::model::Model) for `(provider, model)` from the
    /// layered config — threading the session's effective redaction table
    /// ([`Self::redact`]) and inheriting the current model's shutdown gate +
    /// wire-API self-heal target — then rebuilds the **root primary** under it
    /// at the idle boundary, so the next outbound request routes to the new
    /// model. Breaking the prompt cache is expected (new model = new cache
    /// key). On an unconfigured/bad target it **fails loudly** via
    /// [`TurnEvent::Notice`] and keeps the current model active (never a silent
    /// no-op). The session's persisted active-model row is updated only on a
    /// successful build, so config + live routing never diverge.
    SetActiveModel { provider: String, model: String },
    /// Rebuild the current root model from config + the session env overlay at
    /// the next safe boundary. Used after attach-time `RefreshEnv` so exported
    /// provider keys affect the next inference without daemon-global `setenv`.
    RefreshActiveModel,
    /// Set the session's model-comparison tandem (shadow) set
    /// (`/model-comparison`, implementation note).
    /// The session worker builds a [`Model`](crate::engine::model::Model) for
    /// each selected `(provider, model)` (excluding the active model) from the
    /// already-configured providers and hands them here; the driver replaces
    /// its in-memory tandem set. **Empty = feature off.** Session-only — no
    /// config write; reverts on restart (mirrors [`Self::SetRedaction`]).
    SetTandemModels {
        targets: Vec<crate::engine::schedule::TandemTarget>,
    },
}

/// Maximum number of queued user messages to fold into a single
/// follow-up prompt. Generous because the worst case is a user
/// hammering Enter — concat-joining a dozen short messages is fine;
/// concat-joining a hundred would bloat the next inference. If we
/// hit this cap, extras stay in the channel for the *next* fold.
const MAX_FOLD: usize = 16;
const GOAL_IDLE_CONTINUATION: &str = "An active goal is still in progress. Your previous response did not call a tool and did not mark the goal complete or blocked.\n\nRead the current goal, decide the next concrete action, and continue working. This turn must produce visible progress: call a tool, update the goal status, or provide a concrete blocker that is shown to the user. If the goal is complete, call update_goal with status \"complete\" and evidence. If truly blocked, call update_goal with status \"blocked\" and explain the blocker. Otherwise use tools to make progress.";
const GOAL_IDLE_CONTINUATION_STRONG: &str = "An active goal is still in progress and this is the second consecutive prose-only idle turn. You must choose one exit: call a tool to make progress, call get_goal then update_goal(status=\"complete\", evidence=...), or call update_goal(status=\"blocked\", blocker=...) only for a true blocker. Do not finish this turn silently; it must leave a visible assistant message, tool call, or goal-status event.";
const GOAL_WATCHDOG_CONTINUATION: &str = "An active goal is still in progress, and background work has been pending for 10 minutes.\n\nCheck the status of the pending background task(s). If one is hung, decide whether to cancel, retry, inspect logs, or continue with other work. If the goal is complete, call update_goal(status=\"complete\"). If blocked, call update_goal(status=\"blocked\").";
const GOAL_WATCHDOG_DELAY: Duration = Duration::from_secs(600);

const ID_PRIMARY_ROUNDS_CONTINUE: &str = "primary_rounds_continue";
const ID_PRIMARY_ROUNDS_STOP: &str = "primary_rounds_stop";

/// Trigger string for an `Auto`→primary `handoff` swap (the `handoff` tool).
const SWAP_TRIGGER_HANDOFF: &str = "handoff";
/// Trigger string for a `/plan`/`/build`/`/swarm` (and `/agent`/`Shift+Tab`)
/// slash-command swap routed through `DriverControl::SwapPrimary` at idle.
const SWAP_TRIGGER_COMMAND: &str = "swap_command";

/// The export-audit context for a primary swap (`primary_swap` event). Carries
/// the trigger and — for the `handoff` path only — both halves of the
/// wire-vs-user split (GOALS §14): the user-facing `display` row and the
/// model-facing wire `kickoff`. The slash-command swaps inject no kickoff, so
/// both are absent there (never fabricated).
struct PrimarySwapContext<'a> {
    trigger: &'a str,
    display: Option<&'a str>,
    kickoff: Option<&'a str>,
}

/// Result of dispatching a `schedule` meta-tool action through the per-action
/// validate-then-repair contract (§12). Carries the model-facing result
/// text plus the §14 wire-vs-user surface: `recovery` is what the audit row
/// records, `wire_args` is the repaired `{action, args}` payload (so
/// `wire_input` shows the canonical form the parser consumed, while
/// `original_input` keeps what the model emitted).
struct ScheduleDispatch {
    output: String,
    recovery: crate::engine::repair::Recovery,
    wire_args: serde_json::Value,
}

struct ScheduleToolCallRecord {
    agent: String,
    llm_mode: crate::config::extended::LlmMode,
    call_id: String,
    original_input_json: serde_json::Value,
    wire_input_json: serde_json::Value,
    recovery: crate::engine::repair::Recovery,
    hard_fail: bool,
    output: String,
    duration_ms: u64,
}

impl<'a> PrimarySwapContext<'a> {
    /// A `/plan`/`/build`/`/swarm` slash-command swap: trigger only, no
    /// kickoff (the new primary's first turn is the user's next message).
    fn swap_command() -> Self {
        Self {
            trigger: SWAP_TRIGGER_COMMAND,
            display: None,
            kickoff: None,
        }
    }

    /// An `Auto`→primary `handoff` swap: trigger plus both halves of the
    /// wire-vs-user split.
    fn handoff(display: &'a str, kickoff: &'a str) -> Self {
        Self {
            trigger: SWAP_TRIGGER_HANDOFF,
            display: Some(display),
            kickoff: Some(kickoff),
        }
    }
}

/// Option ids for the prompt-injection false-positive override prompt
/// (GOALS §4i). Stable strings the resolved interrupt response maps back
/// to in [`Driver::injection_override`].
const ID_INJECTION_SEND_ONCE: &str = "inj_send_once";
const ID_INJECTION_LOWER: &str = "inj_lower";
const ID_INJECTION_EDIT: &str = "inj_edit";

use crate::engine::interrupt::{freetext_of, selected_id_of};

/// Path to the global `config.json` to write override settings
/// into: the first existing home-scoped config dir, else the first
/// creatable one (scaffolded). Errors only when no home dir is locatable.
fn global_extended_config_path() -> Result<std::path::PathBuf> {
    use crate::config::dirs::{
        CONFIG_FILE, ConfigDirKind, creatable_config_dirs, discover_config_dirs,
    };
    // Prefer an existing home-scoped layer.
    if let Some(dir) = discover_config_dirs(std::path::Path::new("."))
        .into_iter()
        .find(|d| matches!(d.kind, ConfigDirKind::HomeXdg | ConfigDirKind::HomeDot))
    {
        return Ok(dir.path.join(CONFIG_FILE));
    }
    // Otherwise scaffold the first creatable home location.
    let dir = creatable_config_dirs()
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no home directory to write global config into"))?;
    std::fs::create_dir_all(&dir.path)?;
    Ok(dir.path.join(CONFIG_FILE))
}

/// Handle the session worker keeps to cancel the in-flight user-message
/// run on a ctrl+c (`SessionWork::Cancel`). Shares the driver's
/// `cancel_current` slot; cancelling the live token aborts the in-flight
/// inference and signals any running `bash` subprocess to die. Idempotent
/// and safe at idle — when no run is in flight the slot is `None` and
/// [`Self::cancel`] is a no-op.
#[derive(Clone)]
pub struct CancelHandle {
    current: Arc<std::sync::Mutex<Option<tokio_util::sync::CancellationToken>>>,
}

impl CancelHandle {
    /// Cancel the in-flight run, if any. Safe to call when idle (no-op),
    /// when already cancelling (cancelling a cancelled token is a no-op),
    /// and concurrently from multiple callers.
    pub fn cancel(&self) {
        if let Some(token) = crate::sync::lock_or_recover(&self.current).as_ref() {
            token.cancel();
        }
    }
}

/// RAII guard that clears the driver's `cancel_current` slot when a
/// user-message run ends (any exit path). Ensures a finished run's token
/// can never be cancelled by a late ctrl+c that should instead arm a
/// fresh first press.
struct CancelSlotGuard {
    slot: Arc<std::sync::Mutex<Option<tokio_util::sync::CancellationToken>>>,
}

impl Drop for CancelSlotGuard {
    fn drop(&mut self) {
        *crate::sync::lock_or_recover(&self.slot) = None;
    }
}

/// One agent's slice of state on the driver stack.
pub struct AgentSession {
    pub agent: Arc<Agent>,
    pub history: Vec<Message>,
    pub queue_target: crate::engine::message::QueueTarget,
    /// When this session was pushed by a parent's `task` tool, the
    /// parent's outstanding tool-call id (we have to answer it when we
    /// pop). `None` for the root session.
    pub answering: Option<PendingTaskCall>,
    /// This frame's deferred-log buffer (`plan.md §3d`). A subagent's
    /// `defer_to_orchestrator` calls append here; on pop the driver drains
    /// it and folds it into the report the parent ingests. The root frame's
    /// buffer is never read (the root has no parent to defer to).
    pub deferred_log: crate::engine::deferred::DeferredLog,
}

#[derive(Debug, Clone)]
pub struct PendingTaskCall {
    pub call_id: String,
    pub function_call_id: Option<String>,
    pub repair_notes: Vec<String>,
}

#[derive(Debug, Clone)]
enum StackUnwindReason {
    Cancelled,
    Gated,
    InferenceFailed {
        provider: String,
        model: String,
        class: String,
        phase: String,
    },
}

impl StackUnwindReason {
    fn abort_report(&self) -> String {
        match self {
            Self::Cancelled => {
                "Delegation aborted: parent turn cancelled by user before this subagent reported."
                    .to_string()
            }
            Self::Gated => "Delegation aborted: daemon draining for shutdown.".to_string(),
            Self::InferenceFailed {
                provider,
                model,
                class,
                phase,
            } => format!(
                "Delegation aborted: parent inference failed (provider={provider}, model={model}, class={class}, phase={phase})."
            ),
        }
    }
}

pub struct Driver {
    pub session: Arc<Session>,
    pub locks: Arc<crate::locks::LockManager>,
    pub redact: Arc<RedactionTable>,
    pub cwd: std::path::PathBuf,
    pub stack: Vec<AgentSession>,
    /// Minutes between `[time: ...]` preludes injected on user
    /// messages (GOALS §17g). Loaded from
    /// `extended.system_prompt.time_injection_interval_minutes`;
    /// defaults to 5 if unset.
    pub time_injection_interval_minutes: u32,
    /// Back-to-back identical tool-call threshold for the loop guard
    /// (GOALS §1/§12): the number of consecutive identical calls before
    /// the approval prompt fires. Loaded from
    /// `extended.loop_guard.repeat_threshold` (default 2 = fire on the
    /// first exact repeat); set via [`Self::set_loop_guard_threshold`]
    /// before the loop starts.
    pub loop_guard_threshold: u32,
    /// Maximum root-agent `Continue` cycles allowed per user message
    /// before the driver pauses for confirmation. `0` means unlimited.
    pub max_primary_rounds: u32,
    /// Config opt-in for schedule `limit=0` loops. Even when true, an
    /// interactive session approval is still required once per session.
    pub allow_unbounded_schedule_loops: bool,
    unbounded_schedule_loops_approved: bool,
    /// The single async-job authority (GOALS §22). Owns the live-schedule
    /// registry + per-job tasks; the driver is the one place that mutates
    /// it (single-authority rule).
    pub schedule: ScheduleAuthority,
    /// In-memory authority for noninteractive `task` delegations that can
    /// later be moved off the foreground turn. The current path still waits
    /// inline; this registry is the foundation for background completion,
    /// query snapshots, and turn-boundary steering.
    noninteractive_delegations: NoninteractiveDelegationRegistry,
    /// Job events drained at the turn boundary (loop-iteration-due,
    /// terminal completions). Same boundary as the user-input queue.
    job_event_rx: mpsc::Receiver<ScheduleEvent>,
    /// Self-command channel for in-task timers to re-arm. The driver
    /// drains it alongside job events.
    job_cmd_rx: mpsc::Receiver<ScheduleCommand>,
    /// Completion channel for noninteractive delegations detached from the
    /// foreground turn after user input arrives.
    noninteractive_complete_tx: mpsc::Sender<BackgroundNoninteractiveCompletion>,
    noninteractive_complete_rx: mpsc::Receiver<BackgroundNoninteractiveCompletion>,
    /// Completions received while another task is waiting inline. Keyed by
    /// task id so task A can never satisfy task B's select.
    pending_noninteractive_completions:
        std::collections::VecDeque<BackgroundNoninteractiveCompletion>,
    /// Backgrounded noninteractive delegation jobs keyed by task call id.
    noninteractive_jobs: std::collections::HashMap<String, BackgroundNoninteractiveJob>,
    /// Which cache-safe capability hints have already been appended to the
    /// active history (GOALS §22). A branch is enabled by two cache-safe
    /// moves: the dispatcher starts accepting the action (always, here),
    /// and a hint message is appended **once** announcing it — appended
    /// messages extend the cached prefix without reserializing the
    /// byte-stable tools array. We append the hint the first time the
    /// gating job kind appears.
    appended_hints: std::collections::HashSet<&'static str>,
    /// Per-foreground-agent "last prune watermark" (GOALS §10): the
    /// foreground history length at the last auto-prune. The cache-aware
    /// auto-prune short-circuits when the foreground history hasn't grown
    /// since — nothing new can be prunable. Keyed by stack depth so an
    /// interactive subagent's watermark doesn't bleed into the parent's.
    prune_watermark: std::collections::HashMap<usize, usize>,
    /// One-shot latch for auto-compact (implementation note):
    /// once the ctx%-threshold auto-compact has fired for this session it is
    /// not fired again — `/compact` hands the conversation off to a fresh
    /// session (the client re-attaches), so re-firing on the abandoned old
    /// session would loop. Reset would only matter across sessions, and each
    /// session gets its own driver.
    auto_compacted: bool,
    /// Rolling effectiveness ledger of recent **auto** prunes at the root
    /// frame, for the escalate-to-compaction policy
    /// (implementation note). Each entry is one auto-prune
    /// boundary's `(ctx_pct_before, saved_pct_of_window)`. When the last
    /// [`PRUNE_INEFFECTIVE_RUN`] consecutive prunes each saved less than
    /// [`PRUNE_INEFFECTIVE_SAVING_PCT`] of the window **while** ctx% rose
    /// across them, the next boundary escalates to `/compact` instead of
    /// another tiny snapshot prune. Bounded to the last few entries.
    prune_effectiveness: std::collections::VecDeque<PruneEffectiveness>,
    /// Re-executed seed-tool context for a `/compact` fresh session
    /// (T6.e). Set by [`Self::run_seed_tools`] before the loop starts;
    /// prepended to the **first** user message so the fresh agent's first
    /// inference carries the live working set, then cleared. Avoids two
    /// consecutive user messages on the wire.
    pending_seed_context: Option<String>,
    goal_no_tool_idle_count: u8,
    /// Latches after the active-goal no-tool idle guard stops automatic
    /// continuation. Cleared when a real user turn or a non-prose/toolful state
    /// gives the agent a fresh chance to progress.
    goal_idle_intervention_pending: bool,
    /// Interrupt wakeup hub (GOALS §3b) threaded into every tool call so
    /// the `question` tool can block on a human answer. Defaults to a
    /// [`detached`](crate::engine::interrupt::InterruptHub::detached) hub
    /// (no client fan-out); the session worker swaps in the client-wired
    /// one via [`Self::set_interrupt_hub`] before the loop starts, and
    /// keeps the same `Arc` so its `ResolveInterrupt` handler can wake
    /// the blocked tool.
    interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    /// One-shot guard for the "skills auto-selection skipped: no
    /// utility_model" notice (GOALS §5). Logged at most once per driver
    /// so an unconfigured utility model doesn't spam the log every turn.
    skills_no_utility_model_logged: bool,
    /// One-shot guard for the prompt-injection "scan could not run" warn
    /// chip (GOALS §4i). Surfaced at most once per driver so a missing /
    /// broken utility model doesn't append a chip to every turn.
    injection_no_scan_logged: bool,
    /// Session-only request-preflight override (`/preflight`,
    /// implementation note). `None` defers to the layered
    /// `preflight.enabled` config; `Some(v)` forces it on/off for this
    /// session. Never persisted — reverts on restart (mirrors the
    /// `SetRedaction` session-only override shape).
    preflight_override: Option<bool>,
    /// Session-only root delegation recursion override (`/quick`). `None`
    /// defers to layered config; `Some` replaces only the root default
    /// enabled/depth values while preserving allowed-target and max-depth
    /// policy checks.
    delegation_recursion_override: Option<DelegationRecursionOverride>,
    /// One-shot guard for the request-preflight "determinism guard skipped
    /// the rewrite" notice. Surfaced at most once per driver so a model
    /// that keeps mangling control tokens doesn't spam the transcript.
    preflight_guard_logged: bool,
    current_lifecycle_turn_id: Option<String>,
    /// Cancellation handle for the in-flight user-message run (ctrl+c →
    /// `CancelTurn`, GOALS §3a). `run_user_input` installs a fresh
    /// [`CancellationToken`] here at the start of each run and clears it on
    /// exit; the session worker holds a clone of the `Arc` so a
    /// `SessionWork::Cancel` can read the live token and fire it. `None`
    /// when idle — cancelling then is a safe no-op. Threaded into every
    /// `turn()` (to abort the in-flight inference) and `ToolCtx` (to kill a
    /// long-running `bash` subprocess) within the run.
    cancel_current: Arc<std::sync::Mutex<Option<tokio_util::sync::CancellationToken>>>,
    /// Command/path approval driver (sandboxing part 2). Threaded into
    /// every [`ToolCtx`] so `bash`'s run-fail-escalate and the native
    /// tools' out-of-boundary path checks can prompt + remember. `None`
    /// until the session worker installs it via
    /// [`Self::set_approver`] before the loop starts (same shape as the
    /// interrupt hub); seed-tool re-execution before that runs with no
    /// approver (skips the prompt, never denies).
    approver: Option<Arc<crate::approval::Approver>>,
    /// Daemon-owned LSP manager, installed by the session worker. Optional so
    /// in-process tests and replay paths can skip advisory LSP cleanly.
    lsp: Option<Arc<crate::daemon::lsp::LspManager>>,
    /// Daemon-owned runtime resource scheduler. Persistent daemons install a
    /// shared handle; ephemeral/test/replay contexts may leave it absent.
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    /// Compact-after-delegation trackers for **interactive** subagent
    /// delegations (`SpawnSubagent`), keyed by the paused parent frame's
    /// stack depth (its index in `self.stack`). The lazy shrink for the
    /// parent runs in a background task whose handle rides alongside the
    /// tracker; on the child's `Done` pop we resolve full-vs-shrunk for the
    /// now-top parent frame (implementation note). A
    /// `Vec` indexed by depth would also work, but the map makes the
    /// "no tracker at this depth" case explicit.
    deleg_shrinks: std::collections::HashMap<usize, PendingDelegationShrink>,
    /// Plan-level model override (prompt
    /// `plan-duplication-and-model-override.md`): when a plan run pins a
    /// `model`, it overrides every spawned agent's frontmatter model. Carried
    /// here so child [`SpawnArgs`] (built in [`Self::spawn_args`]) propagate it
    /// to the whole delegation tree — builder, merge-resolver, any subagent.
    /// `None` outside a plan run.
    model_override: Option<Arc<crate::engine::model::Model>>,
    /// Recursive-`Swarm` depth ceiling (GOALS §24, `swarm.max_depth`).
    /// Hard ceiling on Swarm-spawning-Swarm; a `spawn` that
    /// would exceed it is refused (the branch degrades to a leaf). Baked into
    /// the `spawn` description so the model can self-limit.
    swarm_max_depth: u32,
    /// Global cap on simultaneously-running `Swarm` subagents across the
    /// whole tree (GOALS §24, `swarm.max_concurrency`). `0` = unlimited.
    /// Enforced centrally by the single async-job authority: spawns beyond it
    /// queue and start as slots free.
    swarm_max_concurrency: usize,
    /// One-shot context estimate (input tokens) for a session rehydrated on
    /// resume (implementation note). Set by
    /// [`Self::rehydrate_root_if_empty`] to the cl100k_base estimate of the
    /// rebuilt **pruned** root history, emitted once as a `Usage` event at
    /// the top of [`Self::run_main_loop`] so the TUI context gauge is
    /// accurate on the first post-resume turn (before the provider reports a
    /// real count). `None` for a fresh session or a live worker.
    rehydrated_ctx_estimate: Option<u64>,
    /// Ownership ledger for user-invoked skill pairs folded into the root
    /// history by [`Self::seed_forced_skill`] (`handoff-kickoff-and-
    /// skill-leak.md`). Each entry records the synthesized `skill` call's id
    /// and the primary that was active when it was injected. On a primary
    /// swap ([`Self::swap_primary`]) the outgoing primary's **non-steering**
    /// pairs are stripped from history (call + result, together) so an
    /// abandoned skill the previous primary declined to follow does not
    /// masquerade as the new primary's instructions. The `intentional_steer`
    /// flag is the opt-out seam for a future user-invoked skill that should
    /// deliberately survive a swap and direct the new primary — today nothing
    /// sets it, so every user-invoked pair is owned-and-stripped on swap.
    skill_pairs: Vec<SkillPair>,
    /// Seedable-set ledger for parent→child skill seeding
    /// (implementation note). Records every skill genuinely
    /// **active in this primary's context** — user-invoked (folded by
    /// [`Self::seed_forced_skill`]) OR auto-injected (folded by
    /// [`Self::maybe_inject_skill`]) — keyed by skill name to its rendered
    /// (`!`-processed, scrubbed) body. When the primary delegates via `task`
    /// and names a skill in `task.skill_seed`, the host seeds that skill's
    /// instructions + framing into the child's brief **only if the name is in
    /// this set** (validate, don't trust the model); a named skill absent here
    /// is deterministically stripped with a model-visible note. The latest body
    /// for a given name wins (a re-invoked / re-injected skill refreshes it).
    active_skills: Vec<(String, String)>,
    /// Per-session set of skill names already **auto-injected** this session
    /// (implementation note, change 4). A skill
    /// auto-injected once stays out of every later auto-selection pass in this
    /// session: it is removed before the utility-model catalog is built, so it
    /// can be neither re-voted nor re-passed by the backstop — never re-paying
    /// its body for a skill the agent already has in context. Distinct from
    /// [`Self::active_skills`] (the *seedable* set, which also holds
    /// user-`/skill`-invoked and `task.skill_seed` bodies — a different intent
    /// this exclusion must not cover): scope is strictly the auto-injection
    /// path. Populated on actual injection (in [`Self::maybe_inject_skill`]'s
    /// `Selection::Skills` arm), not on a vote/match. In-memory and
    /// session-scoped only — never persisted to config or DB (a resumed
    /// session reconstructs nothing here; at worst one skill re-injects once).
    auto_injected_skills: std::collections::HashSet<String>,
    /// Deferred agent-swap identity marker, pending injection on the user's
    /// next message (implementation note). After a
    /// `swap_command` swap (`/build`/`/plan`/`/swarm`/`/build`) the wire
    /// history carries no boundary entry, so a weak model anchors on its own
    /// prior turns' identity claims. This records the **previously-effective**
    /// agent — the one whose turns are actually in history — captured at the
    /// **first** swap since the last message and never overwritten by
    /// intermediate hops, so a `Build`→`Swarm`→`Plan`→`Build` run coalesces to
    /// a single marker naming the previously-effective → final agent. Consumed
    /// (and cleared) in [`Self::run_user_input`] at send time: one concise
    /// wire-only `[Primary agent changed: …]` entry is injected immediately
    /// ahead of the user message — unless the final agent equals the
    /// previously-effective agent (net no-op), in which case nothing is
    /// injected. Deferred to send time so the cached prefix stays byte-stable
    /// until the message is actually sent. `None` outside a swap window. The
    /// `handoff` path injects its own kickoff and never sets this.
    pending_swap_marker_from: Option<String>,
    /// Per-call ownership of historical tool calls, keyed by the tool call's
    /// `id` → the primary that **actually made it**
    /// (implementation note). Captured at each swap
    /// boundary: before re-rooting, every not-yet-attributed tool call in the
    /// root history is attributed to the **outgoing** agent (the one in
    /// `stack[0]` right now). Because primary swaps only fire at idle, by swap
    /// time the just-finished run's calls are all in history — so attribution
    /// is exact even across several swaps ("the previous agent" is not enough).
    /// Read at the user's next message in [`Self::annotate_absent_tool_calls`]:
    /// any call whose tool the **final** agent lacks gets a wire-only note
    /// naming this owner, so the swapped-in agent doesn't read a foreign call
    /// as its own capability and re-issue a tool it lacks (priority #1). A
    /// re-swap restoring a tool never strips earlier notes (they stay
    /// historically accurate); the ledger is monotonic per call_id.
    tool_call_owner: std::collections::HashMap<String, String>,
    /// Session-only model-comparison tandem (shadow) set
    /// (implementation note). **Empty = feature
    /// off** — there is no separate enable flag. In-memory only: mutated via
    /// [`DriverControl::SetTandemModels`], never written to config, reverts on
    /// restart (mirrors `/toggle-redaction`). When non-empty, every
    /// substantive turn also shadows its assembled request to each tandem
    /// model via the single job authority ([`Self::run_user_input`]).
    tandem_set: crate::engine::schedule::TandemSet,
    /// Test-only injected (providers config, provider, model). Lets the
    /// auto-prune/auto-compact trigger tests exercise the real
    /// resolution + trigger paths deterministically without depending on the
    /// test machine's on-disk config layers. Never set in production.
    #[cfg(test)]
    test_providers_override: Option<(crate::config::providers::ProvidersConfig, String, String)>,
    redaction_scan_environment_override: Option<bool>,
    redaction_scan_dotenv_override: Option<bool>,
    redaction_scan_ssh_keys_override: Option<bool>,
    redaction_unsupported_notified: HashSet<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DelegationRecursionOverride {
    enabled: bool,
    default_depth: u32,
}

/// An in-flight compact-after-delegation: the decision tracker plus the
/// background shrink task's join handle (`None` once joined, or when the
/// shrink was synchronous). Held per delegation so the parent can resolve
/// full-vs-shrunk on the sub-agent's return.
struct PendingDelegationShrink {
    tracker: crate::engine::deleg_shrink::DelegationShrink,
    handle: Option<tokio::task::JoinHandle<Vec<Message>>>,
}

pub(crate) fn is_host_failure_sentinel(report: &str) -> bool {
    report.trim_start().starts_with("Error: ")
}

fn model_selector_display(
    model: &Option<crate::engine::model_roles::DelegationModelSelector>,
) -> Option<String> {
    model.as_ref().map(|selector| selector.display_selector())
}

fn model_selector_json(
    model: &Option<crate::engine::model_roles::DelegationModelSelector>,
) -> serde_json::Value {
    model
        .as_ref()
        .map(|selector| selector.to_json())
        .unwrap_or(serde_json::Value::Null)
}

fn recursion_policy<'a>(
    cfg: &'a crate::config::extended::DelegationConfig,
    agent: &str,
) -> Option<&'a crate::config::extended::DelegationRecursionPolicy> {
    cfg.recursion.get(agent).or_else(|| cfg.recursion.get("*"))
}

fn apply_root_recursion_override(
    mut ctx: crate::engine::builtin::DelegationRecursionContext,
    override_state: Option<DelegationRecursionOverride>,
) -> crate::engine::builtin::DelegationRecursionContext {
    if let Some(override_state) = override_state {
        ctx.enabled = override_state.enabled;
        ctx.remaining_depth = if override_state.enabled {
            override_state.default_depth
        } else {
            0
        };
    }
    ctx
}

#[derive(Debug, Clone)]
struct ChildCwd {
    requested: Option<String>,
    resolved: std::path::PathBuf,
}

impl ChildCwd {
    fn requested_json(&self) -> Option<&str> {
        self.requested.as_deref()
    }

    fn resolved_display(&self) -> String {
        self.resolved.display().to_string()
    }
}

struct InteractiveChildLoadRequest<'a> {
    child_agent: &'a str,
    granted_tools: Vec<String>,
    model: Option<crate::engine::model_roles::DelegationModelSelector>,
    child_recursion: crate::engine::builtin::DelegationRecursionContext,
    task_call_id: &'a str,
    task_function_call_id: Option<String>,
    repair_notes: &'a [String],
}

const DELEGATION_PAYLOAD_DIRECT_LIMIT_BYTES: usize = 32 * 1024;
const DELEGATION_PAYLOAD_REFUSAL: &str = "delegation payload was too large to deliver exactly; save the payload to a file or retry with smaller slices";

fn prepend_task_repair_notes(report: String, notes: &[String]) -> String {
    if notes.is_empty() {
        report
    } else {
        format!("{}\n\n{}", notes.join("\n"), report)
    }
}

fn subagent_report_event_data(
    child_agent: &str,
    task_call_id: Option<&str>,
    task_function_call_id: Option<&str>,
    label: &str,
    report: &str,
    partial_progress: Option<&DelegationPartialProgress>,
) -> serde_json::Value {
    let task_identity = task_call_id.map(|call_id| {
        crate::engine::task_identity::TaskProviderIdentity::for_task_call(
            call_id,
            task_function_call_id,
        )
    });
    let mut data = serde_json::json!({
        "child_agent": child_agent,
        "task_call_id": task_call_id,
        "label": label,
        "report": report,
        "provider_call_id": task_identity
            .as_ref()
            .map(|identity| identity.provider_call_id.clone()),
        "provider_call_id_source": task_identity
            .as_ref()
            .map(|identity| identity.provider_call_id_source),
        "provider_identity": task_call_id.zip(task_identity.as_ref()).map(
            |(call_id, identity)| identity.event_identity_json(call_id),
        ),
    });
    if let Some(partial_progress) = partial_progress
        && !partial_progress.is_empty()
    {
        data["partial_progress"] = serde_json::to_value(partial_progress)
            .unwrap_or_else(|_| serde_json::json!({ "serialization_error": true }));
    }
    data
}

fn with_model_routing_metadata(
    mut data: serde_json::Value,
    model: &crate::engine::model::Model,
) -> serde_json::Value {
    data["trusted_only"] = serde_json::json!(model.trusted_only_enabled());
    data["model_trusted"] = serde_json::json!(model.is_trusted());
    data["routing"] = model.routing_metadata_json(None);
    data
}

/// Inbound channel capacity for job events / commands. Generous; job
/// lifecycle traffic is tiny.
const JOB_CHANNEL_CAPACITY: usize = 256;

impl Driver {
    // Public default-cap constructor; retained for callers that don't
    // need the explicit-capacity `with_*` variants.
    #[allow(dead_code)]
    pub fn new(
        session: Arc<Session>,
        locks: Arc<crate::locks::LockManager>,
        redact: Arc<RedactionTable>,
        cwd: std::path::PathBuf,
        root: Arc<Agent>,
    ) -> Self {
        Self::with_max_schedules(
            session,
            locks,
            redact,
            cwd,
            root,
            crate::engine::schedule::DEFAULT_MAX_CONCURRENT_SCHEDULES,
        )
    }

    fn clone_for_background_noninteractive(&self, tx: &mpsc::Sender<TurnEvent>) -> Self {
        let (job_event_tx, job_event_rx) = mpsc::channel::<ScheduleEvent>(JOB_CHANNEL_CAPACITY);
        let (job_cmd_tx, job_cmd_rx) = mpsc::channel::<ScheduleCommand>(JOB_CHANNEL_CAPACITY);
        let (_complete_tx, noninteractive_complete_rx) =
            mpsc::channel::<BackgroundNoninteractiveCompletion>(JOB_CHANNEL_CAPACITY);
        let ctx = crate::engine::schedule::authority::ScheduleContext {
            session: self.session.clone(),
            locks: self.locks.clone(),
            redact: self.redact.clone(),
            cwd: self.cwd.clone(),
            agent: self.stack[0].agent.clone(),
        };
        let schedule = ScheduleAuthority::new(
            job_event_tx,
            job_cmd_tx,
            tx.clone(),
            ctx,
            crate::engine::schedule::DEFAULT_MAX_CONCURRENT_SCHEDULES,
        );
        Self {
            session: self.session.clone(),
            locks: self.locks.clone(),
            redact: self.redact.clone(),
            cwd: self.cwd.clone(),
            stack: self
                .stack
                .iter()
                .map(|frame| AgentSession {
                    agent: frame.agent.clone(),
                    history: frame.history.clone(),
                    queue_target: frame.queue_target.clone(),
                    answering: frame.answering.clone(),
                    deferred_log: crate::engine::deferred::DeferredLog::new(),
                })
                .collect(),
            time_injection_interval_minutes: self.time_injection_interval_minutes,
            loop_guard_threshold: self.loop_guard_threshold,
            max_primary_rounds: self.max_primary_rounds,
            allow_unbounded_schedule_loops: self.allow_unbounded_schedule_loops,
            unbounded_schedule_loops_approved: self.unbounded_schedule_loops_approved,
            schedule,
            noninteractive_delegations: NoninteractiveDelegationRegistry::default(),
            job_event_rx,
            job_cmd_rx,
            noninteractive_complete_tx: self.noninteractive_complete_tx.clone(),
            noninteractive_complete_rx,
            pending_noninteractive_completions: std::collections::VecDeque::new(),
            noninteractive_jobs: std::collections::HashMap::new(),
            appended_hints: self.appended_hints.clone(),
            prune_watermark: self.prune_watermark.clone(),
            auto_compacted: self.auto_compacted,
            prune_effectiveness: self.prune_effectiveness.clone(),
            pending_seed_context: None,
            goal_no_tool_idle_count: 0,
            goal_idle_intervention_pending: false,
            interrupts: self.interrupts.clone(),
            skills_no_utility_model_logged: self.skills_no_utility_model_logged,
            injection_no_scan_logged: self.injection_no_scan_logged,
            preflight_override: self.preflight_override,
            delegation_recursion_override: self.delegation_recursion_override,
            preflight_guard_logged: self.preflight_guard_logged,
            current_lifecycle_turn_id: self.current_lifecycle_turn_id.clone(),
            cancel_current: self.cancel_current.clone(),
            approver: self.approver.clone(),
            lsp: self.lsp.clone(),
            resource_scheduler: self.resource_scheduler.clone(),
            deleg_shrinks: std::collections::HashMap::new(),
            model_override: self.model_override.clone(),
            swarm_max_depth: self.swarm_max_depth,
            swarm_max_concurrency: self.swarm_max_concurrency,
            rehydrated_ctx_estimate: None,
            skill_pairs: Vec::new(),
            active_skills: self.active_skills.clone(),
            auto_injected_skills: self.auto_injected_skills.clone(),
            pending_swap_marker_from: None,
            tool_call_owner: self.tool_call_owner.clone(),
            tandem_set: self.tandem_set.clone(),
            #[cfg(test)]
            test_providers_override: self.test_providers_override.clone(),
            redaction_scan_environment_override: self.redaction_scan_environment_override,
            redaction_scan_dotenv_override: self.redaction_scan_dotenv_override,
            redaction_scan_ssh_keys_override: self.redaction_scan_ssh_keys_override,
            redaction_unsupported_notified: self.redaction_unsupported_notified.clone(),
        }
    }

    fn assign_todos_to_task(
        &self,
        brief: String,
        todo_ids: &[uuid::Uuid],
        task_call_id: &str,
        label: &str,
        child_agent: &str,
    ) -> String {
        if todo_ids.is_empty() {
            return brief;
        }
        let assigned = match self.session.db.assign_task_todos(
            self.session.id,
            todo_ids,
            task_call_id,
            label,
            child_agent,
        ) {
            Ok(todos) => todos,
            Err(e) => {
                return format!(
                    "{brief}\n\n[assigned todo lookup failed: {e:#}; continue with the task brief and report the blocker]"
                );
            }
        };
        let mut block = String::from("\n\nAssigned todos (durable state):\n");
        for todo in &assigned {
            block.push_str(&format!(
                "- `{}` [{} p{} #{}] {}\n",
                todo.id,
                todo.status.as_str(),
                todo.priority,
                todo.position,
                todo.content
            ));
            if let Some(summary) = &todo.outcome_summary {
                block.push_str(&format!("  summary: {summary}\n"));
            }
        }
        block.push_str(
            "\nAppend notes while working with `todo(action=\"append_note\")` when available. End your final report with a fenced `todo_delta` JSON object: {\"todos\":[{\"id\":\"...\",\"status\":\"completed|in_progress|pending|cancelled\",\"summary\":\"one line\",\"notes\":[{\"kind\":\"summary|finding|decision|artifact|blocker|handoff\",\"body\":\"...\"}],\"suggested_edits\":[\"...\"]}]}.\n",
        );
        format!("{brief}{block}")
    }

    fn reconcile_todo_delta(
        &self,
        task_call_id: &str,
        label: &str,
        child_agent: &str,
        report: &str,
        failed: bool,
    ) -> String {
        let state = if failed { "error" } else { "completed" };
        if let Err(e) = self.session.db.finish_task_assignment(
            self.session.id,
            task_call_id,
            label,
            state,
            None,
        ) {
            tracing::warn!(error = %e, task_call_id, "finish task todo assignment failed");
        }
        let Some(delta) = extract_todo_delta(report) else {
            return report.to_string();
        };
        let mut applied = 0usize;
        if let Some(todos) = delta.get("todos").and_then(serde_json::Value::as_array) {
            for item in todos {
                let Some(id) = item
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|s| uuid::Uuid::parse_str(s).ok())
                else {
                    continue;
                };
                let status = item
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .map(crate::db::task_todos::TodoStatus::parse)
                    .transpose()
                    .ok()
                    .flatten();
                let summary = item.get("summary").and_then(serde_json::Value::as_str);
                if status.is_some() || summary.is_some() {
                    if let Err(e) = self.session.db.update_task_todo(
                        self.session.id,
                        id,
                        status,
                        None,
                        None,
                        summary,
                    ) {
                        tracing::warn!(error = %e, todo_id = %id, "todo delta status update failed");
                    } else {
                        applied += 1;
                    }
                }
                if let Some(notes) = item.get("notes").and_then(serde_json::Value::as_array) {
                    for note in notes {
                        let Some(body) = note.get("body").and_then(serde_json::Value::as_str)
                        else {
                            continue;
                        };
                        let kind = note
                            .get("kind")
                            .and_then(serde_json::Value::as_str)
                            .map(crate::db::task_todos::TodoNoteKind::parse)
                            .transpose()
                            .ok()
                            .flatten()
                            .unwrap_or(crate::db::task_todos::TodoNoteKind::Finding);
                        if self
                            .session
                            .db
                            .append_task_todo_note(
                                self.session.id,
                                id,
                                kind,
                                body,
                                child_agent,
                                None,
                            )
                            .is_ok()
                        {
                            applied += 1;
                        }
                    }
                }
                if let Some(edits) = item
                    .get("suggested_edits")
                    .and_then(serde_json::Value::as_array)
                {
                    for edit in edits.iter().filter_map(serde_json::Value::as_str) {
                        let body = format!("Suggested later-todo edit: {edit}");
                        if self
                            .session
                            .db
                            .append_task_todo_note(
                                self.session.id,
                                id,
                                crate::db::task_todos::TodoNoteKind::Handoff,
                                &body,
                                child_agent,
                                None,
                            )
                            .is_ok()
                        {
                            applied += 1;
                        }
                    }
                }
            }
        }
        if applied == 0 {
            report.to_string()
        } else {
            format!("{report}\n\n[todo_delta applied: {applied} update(s)]")
        }
    }

    /// Build a driver with a configurable max-concurrent-schedules cap (GOALS
    /// §22). The authority's [`ScheduleContext`] is rooted on `root` — the
    /// agent ephemeral-fork loops run on (same model/provider config).
    pub fn with_max_schedules(
        session: Arc<Session>,
        locks: Arc<crate::locks::LockManager>,
        redact: Arc<RedactionTable>,
        cwd: std::path::PathBuf,
        root: Arc<Agent>,
        max_concurrent_schedules: usize,
    ) -> Self {
        let (job_event_tx, job_event_rx) = mpsc::channel::<ScheduleEvent>(JOB_CHANNEL_CAPACITY);
        let (job_cmd_tx, job_cmd_rx) = mpsc::channel::<ScheduleCommand>(JOB_CHANNEL_CAPACITY);
        let (noninteractive_complete_tx, noninteractive_complete_rx) =
            mpsc::channel::<BackgroundNoninteractiveCompletion>(JOB_CHANNEL_CAPACITY);
        let ctx = crate::engine::schedule::authority::ScheduleContext {
            session: session.clone(),
            locks: locks.clone(),
            redact: redact.clone(),
            cwd: cwd.clone(),
            agent: root.clone(),
        };
        // The authority needs the engine UI-event channel (`tx`) to emit
        // started/progress/note signals, but `tx` isn't known until
        // `run_main_loop`. Build with a dummy sender now; `run_main_loop`
        // rebinds it via [`ScheduleAuthority::set_turn_tx`] before any job can
        // start, so no UI signal is ever lost.
        let (dummy_tx, _dummy_rx) = mpsc::channel::<TurnEvent>(1);
        let schedule = ScheduleAuthority::new(
            job_event_tx,
            job_cmd_tx,
            dummy_tx,
            ctx,
            max_concurrent_schedules,
        );
        Self {
            session,
            locks,
            redact,
            cwd,
            stack: vec![AgentSession {
                queue_target: crate::engine::message::QueueTarget::root(root.name.clone()),
                agent: root,
                history: Vec::new(),
                answering: None,
                deferred_log: crate::engine::deferred::DeferredLog::new(),
            }],
            time_injection_interval_minutes: 5,
            loop_guard_threshold: crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            max_primary_rounds: 0,
            allow_unbounded_schedule_loops: false,
            unbounded_schedule_loops_approved: false,
            schedule,
            noninteractive_delegations: NoninteractiveDelegationRegistry::default(),
            job_event_rx,
            job_cmd_rx,
            noninteractive_complete_tx,
            noninteractive_complete_rx,
            pending_noninteractive_completions: std::collections::VecDeque::new(),
            noninteractive_jobs: std::collections::HashMap::new(),
            appended_hints: std::collections::HashSet::new(),
            prune_watermark: std::collections::HashMap::new(),
            auto_compacted: false,
            prune_effectiveness: std::collections::VecDeque::new(),
            pending_seed_context: None,
            goal_no_tool_idle_count: 0,
            goal_idle_intervention_pending: false,
            interrupts: Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            skills_no_utility_model_logged: false,
            injection_no_scan_logged: false,
            preflight_override: None,
            delegation_recursion_override: None,
            preflight_guard_logged: false,
            current_lifecycle_turn_id: None,
            cancel_current: Arc::new(std::sync::Mutex::new(None)),
            approver: None,
            lsp: None,
            resource_scheduler: None,
            deleg_shrinks: std::collections::HashMap::new(),
            model_override: None,
            swarm_max_depth: crate::config::extended::DEFAULT_SWARM_MAX_DEPTH,
            swarm_max_concurrency: crate::config::extended::DEFAULT_SWARM_MAX_CONCURRENCY,
            rehydrated_ctx_estimate: None,
            skill_pairs: Vec::new(),
            active_skills: Vec::new(),
            auto_injected_skills: std::collections::HashSet::new(),
            pending_swap_marker_from: None,
            tool_call_owner: std::collections::HashMap::new(),
            tandem_set: crate::engine::schedule::TandemSet::default(),
            #[cfg(test)]
            test_providers_override: None,
            redaction_scan_environment_override: None,
            redaction_scan_dotenv_override: None,
            redaction_scan_ssh_keys_override: None,
            redaction_unsupported_notified: HashSet::new(),
        }
    }

    /// Install the plan-level model override (prompt
    /// `plan-duplication-and-model-override.md`) before the main loop starts,
    /// so every child spawn propagates it. The root agent already runs under
    /// the override (the session worker loads it with the override
    /// [`SpawnArgs`]); this is what carries the override down to delegated
    /// subagents whose frontmatter would otherwise win.
    pub fn set_model_override(&mut self, model: Option<Arc<crate::engine::model::Model>>) {
        self.model_override = model;
    }

    fn refresh_agent_model_redaction(
        agent: &Arc<Agent>,
        providers: &crate::config::providers::ProvidersConfig,
        table: Arc<RedactionTable>,
    ) -> Arc<Agent> {
        let mut refreshed = (**agent).clone();
        let mut model = (*refreshed.model).clone();
        model.set_redact_table_for_config(providers, table);
        refreshed.model = Arc::new(model);
        Arc::new(refreshed)
    }

    fn set_redaction_table(&mut self, table: Arc<RedactionTable>) {
        self.redact = table.clone();
        let providers = self.live_providers_config().ok();
        let Some(providers) = providers.as_ref() else {
            tracing::warn!("providers config unavailable while refreshing redaction table");
            self.schedule.set_redaction_table(table);
            return;
        };
        for frame in &mut self.stack {
            frame.agent =
                Self::refresh_agent_model_redaction(&frame.agent, providers, table.clone());
        }
        if let Some(model) = &mut self.model_override {
            let mut refreshed = (**model).clone();
            refreshed.set_redact_table_for_config(providers, table.clone());
            *model = Arc::new(refreshed);
        }
        self.schedule.set_redaction_table(table);
    }

    async fn load_max_primary_rounds_for_turn(&self) -> u32 {
        let cwd = self.cwd.clone();
        tokio::task::spawn_blocking(move || {
            crate::config::extended::load_for_cwd(&cwd).max_primary_rounds
        })
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "loading max_primary_rounds task join failed");
            crate::config::extended::ExtendedConfig::default().max_primary_rounds
        })
    }

    async fn refresh_redaction_table_for_turn(&mut self, tx: &mpsc::Sender<TurnEvent>) {
        let cwd = self.cwd.clone();
        let scan_environment_override = self.redaction_scan_environment_override;
        let scan_dotenv_override = self.redaction_scan_dotenv_override;
        let scan_ssh_keys_override = self.redaction_scan_ssh_keys_override;
        let session_env = self.stack[0]
            .agent
            .env_overlay
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        match tokio::task::spawn_blocking(move || {
            let mut cfg = crate::config::extended::load_for_cwd(&cwd).redact;
            if let Some(v) = scan_environment_override {
                cfg.scan_environment = v;
            }
            if let Some(v) = scan_dotenv_override {
                cfg.scan_dotenv = v;
            }
            if let Some(v) = scan_ssh_keys_override {
                cfg.scan_ssh_keys = v;
            }
            RedactionTable::build_with_env(&cfg, &cwd, &session_env)
        })
        .await
        {
            Ok(Ok(new_table)) => {
                let table = match self.redact.union(&new_table) {
                    Ok(table) => Arc::new(table),
                    Err(error) => {
                        tracing::warn!(error = %error, "unioning redaction table failed");
                        Arc::new(new_table)
                    }
                };
                if let Err(error) = self.session.persist_redaction_table(&table) {
                    tracing::warn!(error = %error, "persisting redaction table failed");
                }
                for path in table.unsupported_files() {
                    if self.redaction_unsupported_notified.insert(path.clone()) {
                        let _ = tx
                            .send(TurnEvent::Notice {
                                text: format!(
                                    "`{}` is an unsupported format; redaction for this file will not work",
                                    path.display()
                                ),
                            })
                            .await;
                    }
                }
                self.set_redaction_table(table);
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "refreshing redaction table failed");
            }
            Err(e) => {
                tracing::warn!(error = %e, "refreshing redaction table task join failed");
            }
        }
    }

    /// Install the recursive-`Swarm` knobs (GOALS §24) before the main
    /// loop starts: the hard depth ceiling and the global concurrency cap on
    /// simultaneously-running `Swarm` subagents. The cap is handed to the
    /// single async-job authority's dedicated `Swarm` slot accounting so it
    /// can queue spawns beyond the cap and start them as slots free.
    pub fn set_swarm_config(&mut self, max_depth: u32, max_concurrency: usize) {
        self.swarm_max_depth = max_depth;
        self.swarm_max_concurrency = max_concurrency;
        self.schedule.set_swarm_max_concurrency(max_concurrency);
    }

    /// Swap in the session worker's client-wired interrupt hub (GOALS
    /// §3b) before the main loop starts. The worker keeps the same
    /// `Arc` so its `ResolveInterrupt` handler wakes whatever tool call
    /// is blocked on the answer. Same shape as [`ScheduleAuthority`]'s
    /// `set_turn_tx`: the channel-bearing dependency isn't known at
    /// construction.
    pub fn set_interrupt_hub(&mut self, hub: Arc<crate::engine::interrupt::InterruptHub>) {
        self.interrupts = hub;
    }

    /// Install the command/path approval driver (sandboxing part 2)
    /// before the main loop starts. The session worker builds it with the
    /// session's grant store + the client-wired interrupt hub, so the
    /// approval prompt fans out to the attached client exactly like a
    /// `question`. Must be set after [`Self::set_interrupt_hub`] (the
    /// approver captures the same hub).
    pub fn set_approver(&mut self, approver: Arc<crate::approval::Approver>) {
        self.approver = Some(approver);
    }

    pub fn set_lsp_manager(&mut self, lsp: Arc<crate::daemon::lsp::LspManager>) {
        self.lsp = Some(lsp);
    }

    pub fn set_resource_scheduler(
        &mut self,
        scheduler: Arc<crate::engine::resource_scheduler::ResourceScheduler>,
    ) {
        self.resource_scheduler = Some(scheduler);
    }

    /// Rehydrate the root foreground agent's model history from the durable
    /// transcript + prune ledger on a fresh worker spin-up
    /// (implementation note). This is the session-level
    /// counterpart of the subagent `resume_handle` persist-and-rehydrate:
    /// after a daemon stop+restart the in-memory `Vec<Message>` is gone, so
    /// the next message would otherwise start the model fresh even though
    /// the full transcript is on disk.
    ///
    /// **Automatic + idempotent.** Rehydration applies only when the root
    /// frame has **no live in-memory history** — a worker that is already
    /// alive with a live context (the daemon never died) is left untouched
    /// (never rebuild over a live context). Returns the rehydration outcome
    /// for the caller to surface (e.g. a ledger-fallback warning), or `None`
    /// when nothing was rehydrated (live history present, or a brand-new
    /// session with no recorded turns).
    ///
    /// On a hard rebuild failure (corrupt/unpairable rows) returns `Err` so
    /// the worker surfaces a clear error rather than sending a malformed or
    /// silently-fresh context (priority #1).
    #[allow(dead_code)]
    pub fn rehydrate_root_if_empty(
        &mut self,
        root_agent: &str,
    ) -> Result<Option<crate::engine::rehydrate::Rehydrated>> {
        self.rehydrate_root_if_empty_with_policy(
            root_agent,
            crate::engine::rehydrate::RehydratePolicy::heal(),
        )
    }

    pub fn rehydrate_root_if_empty_with_policy(
        &mut self,
        root_agent: &str,
        policy: crate::engine::rehydrate::RehydratePolicy,
    ) -> Result<Option<crate::engine::rehydrate::Rehydrated>> {
        // Only rehydrate the root frame, and only when it is empty (no live
        // context). A non-root stack or a non-empty root means a live
        // worker — leave it as-is.
        if self.stack.len() != 1 || !self.stack[0].history.is_empty() {
            return Ok(None);
        }
        let Some(rehydrated) = crate::engine::rehydrate::rehydrate_session_with_policy(
            &self.session.db,
            self.session.id,
            root_agent,
            policy,
        )?
        else {
            return Ok(None);
        };
        // Restore the rebuilt (pruned) history + the depth-1 prune
        // watermark so auto-prune's short-circuit stays consistent.
        self.stack[0].history = rehydrated.history.clone();
        self.restore_skill_pairs_after_rehydrate(root_agent);
        if rehydrated.watermark > 0 {
            self.prune_watermark.insert(1, rehydrated.watermark);
        }
        // Token/context accounting: recompute the context-fill estimate from
        // the reconstructed PRUNED history so the TUI gauge is accurate on
        // the first post-resume turn (the provider hasn't reported a real
        // count yet after a restart). Emitted once at `run_main_loop` start.
        let estimate = wire_token_total(&self.stack[0].history);
        self.rehydrated_ctx_estimate = Some(estimate);
        // Seed the session's in-memory usage so the ctx%-gated auto-prune /
        // auto-compact triggers have a basis on the first post-resume turn
        // too (they read `session.last_usage`). Input-only estimate; an
        // in-memory seed (no `inference_calls` row, so `/stats` is clean).
        self.session
            .set_last_usage_estimate(crate::tokens::TokenUsage {
                input_tokens: estimate,
                output_tokens: 0,
                cached_input_tokens: 0,
                cache_creation_input_tokens: 0,
            });
        Ok(Some(rehydrated))
    }

    /// Persist the foreground root agent's current prune state to the
    /// durable ledger (implementation note). Called at
    /// every inference boundary (after each turn) and on every `/prune`, so
    /// a resumed session can re-derive the exact pruned form even after an
    /// unclean daemon kill. Best-effort: a DB failure is logged, never
    /// propagated — auditing/continuity must not break a live turn.
    ///
    /// Reuses [`prune::PruneLedger::capture`], which derives the elided-id
    /// set from the live wire history the same way [`prune::current_elided_ids`]
    /// does (single marker format), so the ledger is always in lockstep
    /// with what the model last saw.
    fn persist_prune_ledger(&self) {
        // Only the root frame's history is the resumable context.
        let history = &self.stack[0].history;
        let watermark = self.prune_watermark.get(&1).copied().unwrap_or(0);
        let ledger = prune::PruneLedger::capture(history, watermark);
        if let Err(e) = self.session.db.save_prune_ledger(self.session.id, &ledger) {
            tracing::warn!(error = %e, "persisting prune ledger failed");
        }
    }

    /// Set the loop-guard threshold (GOALS §1/§12) from the layered
    /// config before the loop starts. Clamped to a minimum of 2 — the
    /// guard only fires on a *repeat*, so a smaller value is meaningless.
    pub fn set_loop_guard_threshold(&mut self, threshold: u32) {
        self.loop_guard_threshold =
            threshold.max(crate::config::extended::MIN_LOOP_GUARD_THRESHOLD);
    }

    /// Set the per-user-message primary round ceiling. `0` disables the
    /// guard; positive values are applied exactly as configured.
    pub fn set_max_primary_rounds(&mut self, max_rounds: u32) {
        self.max_primary_rounds = max_rounds;
    }

    pub fn set_allow_unbounded_schedule_loops(&mut self, allowed: bool) {
        self.allow_unbounded_schedule_loops = allowed;
        if !allowed {
            self.unbounded_schedule_loops_approved = false;
        }
    }

    /// Build the wire text the model receives when one or more skills were
    /// auto-injected: each body, in relevance order, folded ahead of the
    /// user's message (implementation note).
    /// Pure — the user-facing `SkillAutoInjected` rows and the seedable-set
    /// recording are the caller's side effects; this is just the format.
    fn fold_injected_skills(
        skills: &[crate::skills::auto_select::InjectedSkill],
        user_text: &str,
    ) -> String {
        let mut out = String::new();
        for skill in skills {
            out.push_str(&format!(
                "Skill `{}` (auto-selected):\n\n{}\n\n---\n\n",
                skill.name, skill.body
            ));
        }
        out.push_str(user_text);
        out
    }

    /// Run the request-preflight rewrite on the raw user text, resolving
    /// config + the preflight model ref (override → utility model). Returns
    /// [`PreflightOutcome::Skipped`] when disabled / a skip rule fires /
    /// fail-open; the caller never blocks the turn on it.
    async fn run_preflight(&self, raw_text: &str) -> crate::engine::preflight::PreflightOutcome {
        let enabled = self.preflight_enabled();
        if !enabled {
            return crate::engine::preflight::PreflightOutcome::Skipped;
        }
        let (extended, providers) = crate::auto_title::load_configs_for(&self.cwd);
        let resolved = crate::config::extended::resolve_preflight(&self.cwd);
        let model_ref = extended.preflight_model_ref();
        // Resolve the strip-`<think>` toggle for the *preflight* model
        // (`provider:model` from `model_ref`, falling back to the global
        // `inlineThink` default) — same classification semantics the active
        // model uses (implementation note). When
        // ON, an inline `<think>` block in the rewrite is reasoning and is
        // scrubbed from the single `cleaned`; an unparseable ref falls through
        // to the global.
        let strip_think = match model_ref.and_then(|r| r.split_once(':')) {
            Some((provider, model)) => {
                providers.resolve_inline_think(provider, model, extended.inline_think)
            }
            None => extended.inline_think,
        };
        // Assemble the disambiguation context from the root session
        // (implementation note): the last few
        // user/assistant turns (with tool activity), the active agent's
        // role/identity prompt only (not its composed system block — no
        // sysinfo, no duplicated guidance), and the project instructions-file
        // body. Each source is budget-capped inside `assemble_context`; the
        // whole block is scrubbed by the Model send chokepoint before dispatch
        // (no manual scrub here). The current message is not yet in `history`,
        // so the "last three" window reaches the right messages.
        let root = &self.stack[0];
        let instructions = crate::engine::builtin::load_agent_guidance(&self.cwd);
        let context = crate::engine::preflight::assemble_context(
            &root.history,
            &root.agent.role_prompt,
            instructions.as_ref().map(|(_, body)| body.as_str()),
        );
        crate::engine::preflight::run(
            enabled,
            model_ref,
            &providers,
            self.redact.clone(),
            self.session.trusted_only_flag(),
            &resolved.preflight_prompt,
            raw_text,
            &context,
            strip_think,
        )
        .await
    }

    /// Resolve a [`PreflightOutcome`] into the model-facing text, the
    /// optional cleaned-text-for-display (drives the `⚙ preflighted` chip;
    /// `None` when preflight didn't run / no-op / fell back), and the
    /// effective `forced_skill`. A guard trip emits the one-time skip notice.
    /// A mid-text `/skill` parsed out of the prose becomes the `forced_skill`
    /// so it loads deterministically; an existing leading `forced_skill`
    /// (the TUI's `/skill <name>` path) always wins and is left untouched.
    async fn resolve_preflight_outcome(
        &mut self,
        outcome: crate::engine::preflight::PreflightOutcome,
        raw_text: &str,
        existing_forced_skill: Option<String>,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> (String, Option<String>, Option<String>) {
        use crate::engine::preflight::PreflightOutcome;
        match outcome {
            PreflightOutcome::Rewritten { cleaned, skill } => {
                // Mid-text skill loads after the body; a leading forced skill
                // (set by the TUI) takes precedence and is preserved.
                let forced_skill = existing_forced_skill.or(skill);
                let display = Some(cleaned.clone());
                (cleaned, display, forced_skill)
            }
            PreflightOutcome::GuardTripped { original } => {
                if !self.preflight_guard_logged {
                    self.preflight_guard_logged = true;
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: "request preflight was skipped: the rewrite altered a \
                                   `/`-command or `@`-tag, so the original prompt was sent"
                                .to_string(),
                        })
                        .await;
                }
                (original, None, existing_forced_skill)
            }
            // Send the original untouched, no chip — byte-for-byte unchanged.
            PreflightOutcome::Skipped => (raw_text.to_string(), None, existing_forced_skill),
        }
    }

    /// Apply a precomputed [`CheckOutcome`] (the self-mutating half of the
    /// injection guard): fail-open notice, below-threshold flag, or the
    /// at/above-threshold block + false-positive override UX. Returns
    /// whether the prompt may proceed.
    async fn apply_injection_outcome(
        &mut self,
        threshold: crate::config::extended::InjectionThreshold,
        outcome: crate::engine::injection_check::CheckOutcome,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> bool {
        use crate::engine::injection_check::CheckOutcome;
        let guard_threshold = threshold;
        match outcome {
            CheckOutcome::Unavailable => {
                // Fail open: proceed, but tell the user the scan didn't run
                // (logged at most once per driver so a missing/broken
                // utility model doesn't spam the transcript every turn).
                if !self.injection_no_scan_logged {
                    self.injection_no_scan_logged = true;
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: "prompt-injection scan could not run (utility model unset or \
                                   unavailable); proceeding unscanned"
                                .to_string(),
                        })
                        .await;
                }
                true
            }
            CheckOutcome::Rated(rating) => {
                if guard_threshold.blocks(rating) {
                    // At/above threshold → block + offer the override.
                    self.injection_override(rating, tx).await
                } else {
                    // Below threshold → surface the flag, proceed.
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: format!(
                                "prompt-injection guard rated this prompt `{}` (below the `{}` \
                                 block threshold) — proceeding",
                                rating.as_str(),
                                guard_threshold.as_str()
                            ),
                        })
                        .await;
                    true
                }
            }
        }
    }

    /// Raise an interrupt with the given question set and block until the
    /// user answers (or dismisses). Mirrors the persist → register → emit
    /// → wait ordering the `question` tool and `Approver` rely on. On a DB
    /// failure (can't persist the interrupt) returns `Cancel` so the
    /// caller treats it as a dismissal rather than hanging.
    async fn raise_and_wait(
        &self,
        agent: &str,
        description: &str,
        set: crate::daemon::proto::InterruptQuestionSet,
    ) -> crate::daemon::proto::ResolveResponse {
        crate::engine::interrupt::raise_and_wait(
            &self.session.db,
            &self.interrupts,
            self.session.id,
            agent,
            description,
            set,
            "injection override",
        )
        .await
    }

    async fn primary_round_ceiling_allows_more(
        &self,
        rounds: u32,
        limit: u32,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> bool {
        if limit == 0 || rounds < limit {
            return true;
        }

        let message =
            format!("Reached the configured limit of {limit} tool round(s) for this message.");

        if !self.interrupts.is_interactive_attached() {
            let _ = tx
                .send(TurnEvent::Notice {
                    text: format!(
                        "{message} Stopping because no interactive client can approve more rounds."
                    ),
                })
                .await;
            return false;
        }

        use crate::daemon::proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};

        let question = InterruptQuestion::Single {
            prompt: format!("{message} Allow another {limit} round(s)?"),
            options: vec![
                InterruptOption {
                    id: ID_PRIMARY_ROUNDS_CONTINUE.to_string(),
                    label: "Continue".to_string(),
                    description: Some("allow another chunk for this message".to_string()),
                },
                InterruptOption {
                    id: ID_PRIMARY_ROUNDS_STOP.to_string(),
                    label: "Stop".to_string(),
                    description: Some("end this turn now".to_string()),
                },
            ],
            allow_freetext: false,
            command_detail: None,
            permission: false,
            sandbox_escalation: None,
        };
        let set = InterruptQuestionSet {
            questions: vec![question],
        };
        let response = self
            .raise_and_wait(self.active_agent(), "Primary tool-round limit reached", set)
            .await;
        if selected_id_of(&response).as_deref() == Some(ID_PRIMARY_ROUNDS_CONTINUE) {
            let _ = tx
                .send(TurnEvent::Notice {
                    text: format!("Continuing for up to {limit} more tool round(s)."),
                })
                .await;
            true
        } else {
            let _ = tx
                .send(TurnEvent::Notice {
                    text: "Stopped at the configured tool-round limit for this message."
                        .to_string(),
                })
                .await;
            false
        }
    }

    /// Lower the global injection-block threshold by one level (toward
    /// `off`) and persist it to a global config dir. Returns the new
    /// threshold. The write target is the first existing/home global
    /// config dir, scaffolded if needed.
    fn lower_injection_threshold(&self) -> Result<crate::config::extended::InjectionThreshold> {
        use crate::config::extended::{InjectionThreshold, resolve_injection_guard};
        let current = resolve_injection_guard(&self.cwd).threshold;
        // One notch toward `off`: high→medium→low→off.
        let next = match current {
            InjectionThreshold::High => InjectionThreshold::Medium,
            InjectionThreshold::Medium => InjectionThreshold::Low,
            InjectionThreshold::Low => InjectionThreshold::Off,
            InjectionThreshold::Off => InjectionThreshold::Off,
        };
        let path = global_extended_config_path()?;
        let mut doc = crate::config::extended::ExtendedConfigDoc::load(&path)?;
        let mut cfg = doc.config();
        cfg.prompt_injection_guard.threshold = next;
        doc.write(&cfg)?;
        Ok(next)
    }

    /// Persist a new injection check-prompt. Writes to the project
    /// `.cockpit/` layer when one exists for this cwd (so the override is
    /// project-scoped where the project already overrides config),
    /// otherwise the global config dir. Returns a human label for the
    /// scope it wrote to.
    fn write_injection_check_prompt(&self, text: &str) -> Result<&'static str> {
        let (path, scope) = injection_check_prompt_target(&self.cwd)?;
        let mut doc = crate::config::extended::ExtendedConfigDoc::load(&path)?;
        let mut cfg = doc.config();
        cfg.prompt_injection_guard.check_prompt = Some(text.to_string());
        doc.write(&cfg)?;
        Ok(scope)
    }

    /// Name of the agent currently holding the user's conversation.
    /// Used by the TUI for the active-agent slot.
    pub fn active_agent(&self) -> &str {
        self.stack
            .last()
            .map(|a| a.agent.name.as_str())
            .unwrap_or("")
    }

    fn active_queue_target(&self) -> crate::engine::message::QueueTarget {
        self.stack
            .last()
            .map(|frame| frame.queue_target.clone())
            .unwrap_or_else(|| crate::engine::message::QueueTarget::root(""))
    }

    fn active_queue_target_id(&self) -> String {
        self.active_queue_target().id
    }

    /// A sender into the async-job command channel (GOALS §22). The
    /// session worker keeps a clone so a **human** cancel (`/schedule cancel
    /// <id>`, "stop checking the deploy") reaches the single async-job
    /// authority on the same boundary as model-issued commands. Drained
    /// in [`Self::run_main_loop`].
    pub fn job_command_sender(&self) -> mpsc::Sender<ScheduleCommand> {
        self.schedule.command_sender()
    }

    /// A handle the session worker keeps so a user ctrl+c
    /// (`SessionWork::Cancel`) can abort the in-flight user-message run.
    /// Cheap to clone — it shares the driver's `cancel_current` slot. See
    /// [`CancelHandle::cancel`].
    pub fn cancel_handle(&self) -> CancelHandle {
        CancelHandle {
            current: self.cancel_current.clone(),
        }
    }

    /// Long-running main loop: pulls user input from `input_rx` and
    /// drives it through the agent stack, draining queued user messages
    /// (GOALS §1c) at inference boundaries. A drained batch preserves one
    /// user turn per queued submission in FIFO order; compact markers split
    /// batches instead of synthesizing dummy user turns.
    ///
    /// Per GOALS §1c, the queue is delivered at the *next inference
    /// call* — not the next user turn. Mid-tool-loop: the next
    /// tool-result → inference round-trip carries the queue alongside
    /// the tool result. End-of-turn: the queue is delivered as the
    /// first content of the next request. Empty queue: standard
    /// behavior.
    pub async fn run_main_loop(
        &mut self,
        input_queue: crate::engine::message::UserSubmissionQueue,
        mut control_rx: mpsc::Receiver<DriverControl>,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<()> {
        // Rebind the async-job authority's UI-event channel now that we
        // have `tx`. Done before the first message so no job can start
        // (and thus emit a started/progress signal) beforehand.
        self.schedule.set_turn_tx(tx.clone());

        // Resume rehydration (implementation note): if a
        // prior conversation was rebuilt for this worker, emit its context
        // estimate once so the TUI gauge reflects the rehydrated PRUNED
        // history on the first post-resume turn (before the provider reports
        // a real count). One-shot; cleared after emit.
        if let Some(estimate) = self.rehydrated_ctx_estimate.take() {
            let agent = self.active_agent().to_string();
            let _ = tx
                .send(TurnEvent::Usage {
                    agent,
                    usage: crate::tokens::TokenUsage {
                        input_tokens: estimate,
                        output_tokens: 0,
                        cached_input_tokens: 0,
                        cache_creation_input_tokens: 0,
                    },
                })
                .await;
            self.emit_context_projection(tx).await;
        }

        let mut goal_watchdog: Option<Pin<Box<Sleep>>> = None;
        loop {
            let active_target_id = self.active_queue_target_id();
            if !self.pending_noninteractive_completions.is_empty()
                && !input_queue.has_pending_for(Some(&active_target_id)).await
                && self
                    .run_next_pending_noninteractive_completion(&input_queue, tx)
                    .await?
            {
                self.goal_no_tool_idle_count = 0;
                self.goal_idle_intervention_pending = false;
                self.maybe_continue_active_goal(&input_queue, tx).await?;
                self.refresh_goal_watchdog(&mut goal_watchdog);
                continue;
            }
            // Wait for the next thing to do: a user message, a control
            // request (/prune /compact /pin), a job event (loop iteration
            // due / job completed), or a job command (an in-task timer
            // re-arm). Async results inject "as a late-arriving turn at
            // the next turn boundary" — at idle, the next boundary is
            // right here.
            tokio::select! {
                biased;
                msg = input_queue.recv_for(Some(&active_target_id)) => {
                    goal_watchdog = None;
                    let Some(first) = msg else { break };
                    // Fold anything else that's already queued behind the
                    // first message (rare but harmless).
                    let mut batch = vec![first];
                    drain_queue(&input_queue, &mut batch, &active_target_id).await;
                    let items = fold_submission_commands(batch);
                    if items.iter().any(|item| matches!(item, FoldedSubmission::User(_))) {
                        self.goal_no_tool_idle_count = 0;
                        self.goal_idle_intervention_pending = false;
                    }
                    self.run_folded_submission_commands(items, &input_queue, tx).await?;
                    self.maybe_continue_active_goal(&input_queue, tx).await?;
                    self.refresh_goal_watchdog(&mut goal_watchdog);
                }
                ctl = control_rx.recv() => {
                    goal_watchdog = None;
                    match ctl {
                        // Control requests arrive at idle (the stack is at
                        // the foreground agent and no turn is in flight) —
                        // a safe compaction boundary by construction.
                        #[cfg(test)]
                        Some(DriverControl::AbortForTest) => {
                            anyhow::bail!("driver abort requested for test");
                        }
                        Some(control) => self.run_control(control, tx).await,
                        None => break,
                    }
                }
                ev = self.job_event_rx.recv() => {
                    goal_watchdog = None;
                    match ev {
                        Some(event) => {
                            self.goal_no_tool_idle_count = 0;
                            self.goal_idle_intervention_pending = false;
                            self.run_job_event(event, &input_queue, tx).await?;
                            self.maybe_continue_active_goal(&input_queue, tx).await?;
                            self.refresh_goal_watchdog(&mut goal_watchdog);
                        }
                        None => break,
                    }
                }
                completion = self.noninteractive_complete_rx.recv() => {
                    goal_watchdog = None;
                    let delivered = self
                        .deliver_background_noninteractive_completion(completion, &input_queue, tx)
                        .await?;
                    if delivered {
                        self.goal_no_tool_idle_count = 0;
                        self.goal_idle_intervention_pending = false;
                        self.maybe_continue_active_goal(&input_queue, tx).await?;
                        self.refresh_goal_watchdog(&mut goal_watchdog);
                    }
                }
                cmd = self.job_cmd_rx.recv() => {
                    goal_watchdog = None;
                    if let Some(cmd) = cmd {
                        self.schedule.handle_command(cmd);
                        continue;
                    } else {
                        break;
                    }
                }
                _ = async {
                    match goal_watchdog.as_mut() {
                        Some(timer) => timer.as_mut().await,
                        None => std::future::pending().await,
                    }
                } => {
                    goal_watchdog = None;
                    self.run_user_input(UserSubmission::text(GOAL_WATCHDOG_CONTINUATION), &input_queue, tx).await?;
                    self.maybe_continue_active_goal(&input_queue, tx).await?;
                    self.refresh_goal_watchdog(&mut goal_watchdog);
                }
            }
            // Stack has unwound to the root and the queue is drained — the
            // agent is idle until the next message: the same safe inference
            // boundary auto-prune uses. Auto-compact fires here when the last
            // turn pushed ctx% over the configured auto-compact line
            // (implementation note); it emits `CompactReady`
            // and the client re-attaches to the fresh session. Guarded by the
            // one-shot latch + `at_safe_boundary` so it can't loop.
            self.maybe_auto_compact(tx).await;
            // Emit the falling edge so the TUI can stop its working-indicator
            // clock, and refresh the "% prunable" projection from the
            // now-settled foreground history.
            self.emit_context_projection(tx).await;
            let turn_id = self.current_lifecycle_turn_id.take();
            let _ = tx.send(TurnEvent::AgentIdle { turn_id }).await;
        }
        Ok(())
    }

    /// Whether the conversation is at a safe boundary for context
    /// reduction (`plan.md` T6.e). The driver evaluates control requests
    /// and auto-prune only at the inference boundary (between tool loops
    /// / at idle), where by construction no tool call is mid-dispatch and
    /// the foreground agent is the one being targeted. The remaining
    /// concern is an interactive subagent: pruning/compacting always
    /// targets the **top** of the stack (the foreground agent), so a
    /// deeper frame is never touched — the predicate is consulted to keep
    /// the contract explicit and to gate the auto-fire.
    fn at_safe_boundary(&self) -> bool {
        // No tool call is in flight at the call sites that consult this
        // (idle / inference boundary); no pending user interaction model
        // exists in v1. The only live concern is captured by always
        // operating on `stack.last_mut()`.
        crate::engine::is_at_safe_compaction_boundary(false, false, false)
    }

    /// Run an out-of-band control request against the **foreground**
    /// agent (top of stack) — never a hardcoded root. Scope == current
    /// conversational agent (GOALS §3b).
    async fn run_control(&mut self, control: DriverControl, tx: &mpsc::Sender<TurnEvent>) {
        if !self.at_safe_boundary() {
            // Not safe — drop rather than corrupt the transcript split.
            // The TUI re-issues on the next idle (control requests are
            // user-initiated, so a retry is a keystroke away). v1 reaches
            // here only at idle, so this is defensive.
            tracing::warn!("control request at unsafe boundary; ignoring");
            return;
        }
        match control {
            #[cfg(test)]
            DriverControl::AbortForTest => unreachable!("handled before run_control"),
            DriverControl::Prune => {
                self.do_prune(false, tx).await;
            }
            DriverControl::Compact => {
                self.do_compact(tx).await;
            }
            DriverControl::Pin { text } => {
                self.session.pin_message(&text);
            }
            DriverControl::RepairResume {
                root_agent,
                respond_to,
            } => {
                let result = match self.rehydrate_root_if_empty_with_policy(
                    &root_agent,
                    crate::engine::rehydrate::RehydratePolicy::heal(),
                ) {
                    Ok(Some(rehydrated)) => Ok(rehydrated.heals.len()),
                    Ok(None) => Ok(0),
                    Err(error) => Err(format!("{error:#}")),
                };
                let _ = respond_to.send(result);
            }
            DriverControl::SwapPrimary { name } => {
                self.swap_primary(&name, tx).await;
            }
            DriverControl::SetLlmMode { mode } => {
                self.set_llm_mode(mode, tx).await;
            }
            DriverControl::SetRedaction {
                table,
                scan_environment,
                scan_dotenv,
                scan_ssh_keys,
            } => {
                // Swap the redaction table in place. Future driver/model/
                // schedule clones (next outbound prompt, new tool contexts,
                // freshly spawned subagents) pick up the new table; in-flight
                // clones keep the old one until they finish.
                if scan_environment.is_some() {
                    self.redaction_scan_environment_override = scan_environment;
                }
                if scan_dotenv.is_some() {
                    self.redaction_scan_dotenv_override = scan_dotenv;
                }
                if scan_ssh_keys.is_some() {
                    self.redaction_scan_ssh_keys_override = scan_ssh_keys;
                }
                self.set_redaction_table(table);
            }
            DriverControl::SetTandemModels { targets } => {
                // Replace the in-memory tandem (shadow) set. Empty disables the
                // feature; non-empty shadows every subsequent substantive turn.
                // Session-only — never persisted (mirrors `SetRedaction`).
                self.tandem_set.set(targets);
            }
            DriverControl::SetPreflight { enabled } => {
                // `/preflight`: set the session-only override (precedence over
                // config). `None` toggles against the current effective state
                // (config overlaid by any existing override). Broadcast the
                // resulting state so the client mirror + toast stay current.
                // Session-only — never persisted (mirrors `SetRedaction`).
                let target = enabled.unwrap_or(!self.preflight_enabled());
                self.preflight_override = Some(target);
                let _ = tx.send(TurnEvent::PreflightState { enabled: target }).await;
            }
            DriverControl::SetDelegationRecursion {
                enabled,
                default_depth,
            } => {
                self.delegation_recursion_override = Some(DelegationRecursionOverride {
                    enabled,
                    default_depth,
                });
                let _ = tx
                    .send(TurnEvent::DelegationRecursionState {
                        enabled,
                        default_depth,
                    })
                    .await;
            }
            DriverControl::SetMaxPrimaryRounds { max_rounds } => {
                self.set_max_primary_rounds(max_rounds);
            }
            DriverControl::SetActiveModel { provider, model } => {
                self.set_active_model_live(&provider, &model, tx).await;
            }
            DriverControl::RefreshActiveModel => {
                let provider = self.stack[0].agent.model.provider_id().to_string();
                let model = self.stack[0].agent.model.model_id_ref().to_string();
                let Ok(new_model) = self.build_live_model(&provider, &model) else {
                    return;
                };
                let rebuilt = self.rebuild_frame_with_model(0, Arc::new(new_model));
                self.stack[0].agent = Arc::new(rebuilt);
                self.schedule.set_agent(self.stack[0].agent.clone());
            }
        }
    }

    async fn maybe_continue_active_goal(
        &mut self,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<()> {
        loop {
            let Some(goal) = self
                .session
                .db
                .current_session_goal(self.session.id, false)?
            else {
                self.goal_no_tool_idle_count = 0;
                self.goal_idle_intervention_pending = false;
                return Ok(());
            };
            if goal.status != crate::db::session_goals::GoalStatus::Active {
                self.goal_no_tool_idle_count = 0;
                self.goal_idle_intervention_pending = false;
                return Ok(());
            }
            if goal
                .token_budget
                .is_some_and(|budget| goal.tokens_used >= budget)
            {
                let _ = self.session.db.update_session_goal(
                    self.session.id,
                    crate::db::session_goals::GoalStatus::BudgetLimited,
                    None,
                    None,
                    Some("token budget exhausted"),
                );
                self.goal_no_tool_idle_count = 0;
                self.goal_idle_intervention_pending = false;
                return Ok(());
            }
            if self.goal_idle_intervention_pending {
                if self
                    .root_last_user_text()
                    .is_some_and(|text| !is_continue_command(&text))
                {
                    self.goal_no_tool_idle_count = 0;
                    self.goal_idle_intervention_pending = false;
                }
                return Ok(());
            }
            if !self.root_last_assistant_was_prose_without_tools() {
                self.goal_no_tool_idle_count = 0;
                self.goal_idle_intervention_pending = false;
                return Ok(());
            }
            if !self.schedule.snapshot().is_empty() {
                return Ok(());
            }
            self.goal_no_tool_idle_count = self.goal_no_tool_idle_count.saturating_add(1);
            if self.goal_no_tool_idle_count >= 3 {
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: "goal: needs intervention — agent_failed_to_progress".to_string(),
                    })
                    .await;
                self.goal_no_tool_idle_count = 0;
                self.goal_idle_intervention_pending = true;
                return Ok(());
            }
            let prompt = if self.goal_no_tool_idle_count == 1 {
                GOAL_IDLE_CONTINUATION
            } else {
                GOAL_IDLE_CONTINUATION_STRONG
            };
            self.run_user_input(UserSubmission::text(prompt), input_rx, tx)
                .await?;
        }
    }

    fn root_last_assistant_was_prose_without_tools(&self) -> bool {
        use crate::engine::message::{AssistantContent, Message, extract_text};
        let Some(root) = self.stack.first() else {
            return false;
        };
        let Some(Message::Assistant { content, .. }) = root.history.last() else {
            return false;
        };
        for part in content.iter() {
            if matches!(part, AssistantContent::ToolCall(_)) {
                return false;
            }
        }
        !extract_text(content).trim().is_empty()
    }

    fn root_last_user_text(&self) -> Option<String> {
        use crate::engine::message::{Message, extract_user_text};
        let root = self.stack.first()?;
        let Message::User { content } = root.history.last()? else {
            return None;
        };
        Some(extract_user_text(content))
    }

    fn is_goal_intervention_continue(&self, text: &str) -> bool {
        if !self.goal_idle_intervention_pending {
            return false;
        }
        if !is_continue_command(text) {
            return false;
        }
        self.session
            .db
            .current_session_goal(self.session.id, false)
            .ok()
            .flatten()
            .is_some_and(|goal| goal.status == crate::db::session_goals::GoalStatus::Active)
    }

    fn latest_session_event_seq(&self) -> i64 {
        self.session
            .db
            .list_session_events(self.session.id)
            .ok()
            .and_then(|events| events.last().map(|event| event.seq))
            .unwrap_or(0)
    }

    fn failed_turn_retry_prompt_for(&self, text: &str) -> Option<(String, String)> {
        if !is_continue_command(text) {
            return None;
        }
        let events = self.session.db.list_session_events(self.session.id).ok()?;
        for event in events.iter().rev() {
            if event.kind != "failed_turn_recovery" {
                continue;
            }
            if event.data["status"] != "needs_retry" {
                return None;
            }
            let recovery_id = event
                .data
                .get("recovery_id")
                .and_then(serde_json::Value::as_str)
                .or(event.call_id.as_deref())?
                .to_string();
            let text = event
                .data
                .get("active_prompt")
                .and_then(|prompt| prompt.get("text"))
                .and_then(serde_json::Value::as_str)?
                .to_string();
            if text.trim().is_empty() {
                return None;
            }
            return Some((recovery_id, text));
        }
        None
    }

    async fn record_failed_turn_retry_started(
        &self,
        recovery_id: &str,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        if let Err(e) = self.session.record_event(
            crate::db::session_log::SessionEventKind::FailedTurnRecovery,
            Some(self.active_agent()),
            Some(recovery_id),
            &serde_json::json!({
                "status": "retry_started",
                "recovery_id": recovery_id,
                "trigger": "continue",
                "recommended_action": {
                    "kind": "retry_same_turn",
                    "consumed": true,
                },
            }),
        ) {
            tracing::warn!(error = %e, "record failed_turn_recovery retry_started event failed");
        }
        let _ = tx
            .send(TurnEvent::Notice {
                text: "retrying failed turn from stored recovery record".to_string(),
            })
            .await;
    }

    async fn record_failed_turn_recovery(
        &self,
        agent: &Agent,
        attempted_prompt: &Message,
        call_id: uuid::Uuid,
        failure: &crate::engine::model::InferenceFailure,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        let prompt = prompt_summary(attempted_prompt, 8_000);
        let progress = self
            .stack
            .last()
            .map(|top| partial_progress_from_history(&top.history))
            .unwrap_or_default();
        let active_goal = self
            .session
            .db
            .current_session_goal(self.session.id, false)
            .ok()
            .flatten()
            .map(|goal| {
                serde_json::json!({
                    "id": goal.id.to_string(),
                    "objective": goal.objective,
                    "status": goal.status.as_str(),
                    "token_budget": goal.token_budget,
                    "tokens_used": goal.tokens_used,
                    "blocked_attempts": goal.blocked_attempts,
                })
            });
        let provider_status = failure
            .class
            .strip_prefix("http_")
            .and_then(|s| s.parse::<u16>().ok());
        let (retry_final_decision, classification_rationale) =
            crate::engine::retry::failure_retry_decision_and_rationale(
                &failure.class,
                provider_status,
            );
        let provider_body_snippet =
            redacted_bounded_snippet(&failure.detail, self.redact.as_ref(), 800);
        let recovery_id = call_id.to_string();
        let data = serde_json::json!({
            "kind": "terminal_inference_failure",
            "status": "needs_retry",
            "recovery_id": recovery_id,
            "active_agent": agent.name,
            "active_prompt": prompt,
            "active_goal": active_goal,
            "provider": failure.provider,
            "model": failure.model,
            "wire_api": agent.model.wire_api_label(),
            "phase_reached": failure.phase,
            "error_class": failure.class,
            "elapsed_ms": failure.elapsed_ms,
            "provider_status": provider_status,
            "provider_body_snippet": provider_body_snippet,
            "retry_attempts": {
                "known": false,
                "reason": "retry layer currently reports only terminal outcome"
            },
            "retry_final_decision": retry_final_decision,
            "classification_rationale": classification_rationale,
            "recommended_action": {
                "kind": "retry_same_turn",
                "command": "continue",
                "requires_explicit_user_action": true,
                "reuses_recovery_id": recovery_id,
            },
            "last_action": progress.last_action,
            "files_read": progress.files_read,
            "files_edited": progress.files_edited,
            "commands": progress.commands,
            "verification_state": progress.verification_state,
            "review_state": progress.review_state,
            "worktree": {
                "dirty_files_known": true,
                "dirty_files_source": "host_tool_history",
                "dirty_files": progress.dirty_owned_changes,
            },
        });
        if let Err(e) = self.session.record_event(
            crate::db::session_log::SessionEventKind::FailedTurnRecovery,
            Some(&agent.name),
            Some(&recovery_id),
            &data,
        ) {
            tracing::warn!(error = %e, "record failed_turn_recovery event failed");
        }
        let _ = tx
            .send(TurnEvent::Notice {
                text: "inference failed; type `continue` to retry the same turn from the stored recovery record".to_string(),
            })
            .await;
    }

    fn goal_continue_progress_since(&self, anchor_seq: i64) -> bool {
        let Ok(events) = self.session.db.list_session_events(self.session.id) else {
            return false;
        };
        events
            .iter()
            .filter(|event| event.seq > anchor_seq)
            .any(|event| {
                matches!(
                    event.kind.as_str(),
                    "assistant_message"
                        | "tool_call"
                        | "tool_call_started"
                        | "tool_call_completed"
                        | "subagent_spawned"
                        | "subagent_report"
                        | "session_compacted"
                        | "inference_failure"
                        | "failed_turn_recovery"
                        | "primary_swap"
                )
            })
            || self
                .session
                .db
                .current_session_goal(self.session.id, false)
                .ok()
                .flatten()
                .is_none_or(|goal| goal.status != crate::db::session_goals::GoalStatus::Active)
    }

    async fn emit_goal_continue_no_progress(
        &mut self,
        anchor_seq: i64,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        let text =
            "goal: continue produced no visible progress — agent_failed_to_progress_after_continue"
                .to_string();
        let data = serde_json::json!({
            "kind": "goal_continue_no_progress",
            "anchor_seq": anchor_seq,
            "reason": "completed_inference_without_visible_progress",
        });
        if let Err(e) = self.session.record_event(
            crate::db::session_log::SessionEventKind::GoalProgressDiagnostic,
            Some(self.active_agent()),
            None,
            &data,
        ) {
            tracing::warn!(error = %e, "recording goal progress diagnostic failed");
        }
        let _ = tx.send(TurnEvent::Notice { text }).await;
        self.goal_no_tool_idle_count = 0;
        self.goal_idle_intervention_pending = true;
    }

    async fn record_queued_user_fold(
        &self,
        folded: &UserSubmission,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Option<i64> {
        if folded.queue_item_ids.is_empty() {
            return None;
        }
        let target = folded
            .queue_target
            .clone()
            .unwrap_or_else(|| self.active_queue_target());
        let data = user_message_event_data(
            &folded.text,
            folded.job_id.as_deref(),
            &folded.queue_item_ids,
            Some(&target),
            folded.preflight_cleaned.as_deref(),
        );
        let seq = match self.session.record_event_with_origin(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some(target.agent.as_str()),
            None,
            folded.origin_principal.as_deref(),
            &data,
        ) {
            Ok(seq) => Some(seq),
            Err(e) => {
                tracing::warn!(error = %e, "record queued user fold event failed");
                None
            }
        };
        let _ = tx
            .send(TurnEvent::QueuedUserMessagesFolded {
                text: folded.text.clone(),
                queue_item_ids: folded.queue_item_ids.clone(),
                target,
                seq,
                preflight_cleaned: folded.preflight_cleaned.clone(),
            })
            .await;
        seq
    }

    async fn prepare_queued_user_submission(
        &mut self,
        submission: UserSubmission,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Option<UserSubmission> {
        if self.preflight_will_run(&submission.text) {
            let _ = tx.send(TurnEvent::PreflightStarted).await;
        }
        let (injection, preflight) = tokio::join!(
            self.injection_check_only(&submission.text),
            self.run_preflight(&submission.text),
        );
        if let Some((threshold, outcome)) = injection
            && !self.apply_injection_outcome(threshold, outcome, tx).await
        {
            let _ = tx.send(TurnEvent::UserMessageRetracted).await;
            self.emit_context_projection(tx).await;
            let turn_id = self.current_lifecycle_turn_id.take();
            let _ = tx.send(TurnEvent::AgentIdle { turn_id }).await;
            return None;
        }
        let (raw_text, cleaned_for_display, forced_skill) = self
            .resolve_preflight_outcome(preflight, &submission.text, submission.forced_skill, tx)
            .await;
        let inbound_text = self.translate_inbound(&raw_text).await;
        Some(UserSubmission {
            kind: UserSubmissionKind::User,
            text: inbound_text,
            images: submission.images,
            forced_skill,
            origin_principal: submission.origin_principal,
            job_id: submission.job_id,
            preflight_cleaned: cleaned_for_display,
            queue_item_ids: submission.queue_item_ids,
            queue_target: submission.queue_target,
        })
    }

    async fn requeue_command_submission_for_boundary(
        &self,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        submission: UserSubmission,
    ) -> bool {
        if !matches!(submission.kind, UserSubmissionKind::Compact) {
            return false;
        }
        input_rx
            .requeue_front(submission, self.active_queue_target())
            .await;
        true
    }

    async fn run_prepared_queued_user_batch(
        &mut self,
        submissions: Vec<UserSubmission>,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<()> {
        if submissions.is_empty() {
            return Ok(());
        }
        if submissions.len() == 1
            || submissions
                .iter()
                .take(submissions.len().saturating_sub(1))
                .any(|submission| submission.forced_skill.is_some())
        {
            for submission in submissions {
                self.run_user_input(submission, input_rx, tx).await?;
            }
            return Ok(());
        }

        let last_index = submissions.len() - 1;
        let mut leading_history = Vec::with_capacity(last_index);
        let mut leading_queue_item_ids = Vec::new();
        let mut last = None;
        for (idx, submission) in submissions.into_iter().enumerate() {
            if idx == last_index {
                last = Some(submission);
                break;
            }
            leading_queue_item_ids.extend(submission.queue_item_ids.iter().copied());
            self.record_queued_user_fold(&submission, tx).await;
            leading_history.push(crate::engine::message::build_user_message(UserSubmission {
                kind: UserSubmissionKind::User,
                text: submission.text,
                images: submission.images,
                forced_skill: None,
                origin_principal: None,
                job_id: None,
                preflight_cleaned: None,
                queue_item_ids: Vec::new(),
                queue_target: None,
            }));
        }
        let last = last.expect("non-empty queued batch has a final user turn");
        let result = self
            .run_user_input_with_leading_history(last, leading_history, true, input_rx, tx)
            .await;
        input_rx.finish(&leading_queue_item_ids).await;
        result
    }

    async fn run_folded_submission_commands(
        &mut self,
        items: Vec<FoldedSubmission>,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<()> {
        let mut pending_users = Vec::new();
        for item in items {
            match item {
                FoldedSubmission::Compact(queue_item_ids) => {
                    self.run_prepared_queued_user_batch(
                        std::mem::take(&mut pending_users),
                        input_rx,
                        tx,
                    )
                    .await?;
                    self.do_compact(tx).await;
                    input_rx.finish(&queue_item_ids).await;
                }
                FoldedSubmission::User(submission) => {
                    let queue_item_ids = submission.queue_item_ids.clone();
                    let Some(prepared) = self.prepare_queued_user_submission(*submission, tx).await
                    else {
                        input_rx.finish(&queue_item_ids).await;
                        self.run_prepared_queued_user_batch(
                            std::mem::take(&mut pending_users),
                            input_rx,
                            tx,
                        )
                        .await?;
                        return Ok(());
                    };
                    pending_users.push(prepared);
                }
            }
        }
        self.run_prepared_queued_user_batch(pending_users, input_rx, tx)
            .await
    }

    fn refresh_goal_watchdog(&self, watchdog: &mut Option<Pin<Box<Sleep>>>) {
        let active = self
            .session
            .db
            .current_session_goal(self.session.id, false)
            .ok()
            .flatten()
            .is_some_and(|g| g.status == crate::db::session_goals::GoalStatus::Active);
        let should_arm = active
            && self.root_last_assistant_was_prose_without_tools()
            && !self.schedule.snapshot().is_empty();
        if should_arm {
            if watchdog.is_none() {
                *watchdog = Some(Box::pin(tokio::time::sleep(GOAL_WATCHDOG_DELAY)));
            }
        } else {
            *watchdog = None;
        }
    }

    /// Load the layered providers config for the live model switch, honoring a
    /// test-injected config when present (mirrors [`Self::active_providers_config`])
    /// and otherwise reading the top discovered `.cockpit/config.json` — the same
    /// file the `/model` picker just wrote the new active model into.
    fn live_providers_config(&self) -> Result<crate::config::providers::ProvidersConfig> {
        #[cfg(test)]
        if let Some((providers, _, _)) = &self.test_providers_override {
            return Ok(providers.clone());
        }
        use crate::config::providers::ConfigDoc;
        Ok(ConfigDoc::load_effective(&self.cwd))
    }

    /// Re-load a foreground frame under `new_model` (live model switch),
    /// preserving its name + LLM mode. The new model's reasoning params are
    /// re-resolved from the config's active-model thinking mode so a switch to a
    /// model with different reasoning controls sends the right vendor params (and
    /// drops a prior model's params that the new one would reject — priority #1),
    /// while the session-scoped `prompt_cache_key` is carried across unchanged.
    fn rebuild_frame_with_model(
        &self,
        frame_idx: usize,
        new_model: Arc<crate::engine::model::Model>,
    ) -> Agent {
        let name = self.stack[frame_idx].agent.name.clone();
        // Re-resolve the new model's reasoning params from the (freshly-written)
        // config's active-model thinking mode; fall back to none when the config
        // can't be read or no mode is selected.
        let additional_params = self.resolve_thinking_params_for(&new_model);
        // Every frame on `self.stack` is foreground/user-facing: index 0 is the
        // root primary, and deeper frames are interactive subagents. One-shot
        // noninteractive delegations run off-stack, so rebuilding a stack frame
        // must preserve the interactive recall/todo/goal tool surface.
        let mut args = self.spawn_args(true);
        args.model = new_model;
        args.model_override = None;
        args.delegation_model = None;
        args.params = crate::engine::model::ModelParams {
            additional_params,
            // The cache key is the session id — model-agnostic, carried across.
            prompt_cache_key: self.stack[frame_idx].agent.params.prompt_cache_key.clone(),
            ..crate::engine::model::ModelParams::default()
        };
        // `builtin::load` honors a user override of a bundled primary; fall back
        // to the same agent name's default build on a load failure so the swap
        // never strands the session without a primary.
        crate::engine::builtin::load(&name, &args)
            .unwrap_or_else(|_| crate::engine::builtin::build(&args))
    }

    /// Re-resolve the reasoning-param fragment for `model` from the config's
    /// rich reasoning-effort capability first, falling back to the legacy
    /// active-model thinking mode (implementation note) only
    /// when the model has no typed capability.
    fn resolve_thinking_params_for(
        &self,
        model: &crate::engine::model::Model,
    ) -> Option<serde_json::Value> {
        let providers = self.live_providers_config().ok()?;
        let active = providers.active_model.as_ref()?;
        if providers.has_reasoning_effort_capability(model.provider_id(), model.model_id_ref()) {
            let selected = active
                .reasoning_effort
                .as_ref()
                .filter(|_| {
                    active.provider == model.provider_id() && active.model == model.model_id_ref()
                })
                .map(|effort| effort.value.as_str());
            return providers.resolve_reasoning_effort_params(
                model.provider_id(),
                model.model_id_ref(),
                selected,
            );
        }
        let mode = active.thinking_mode?;
        providers.resolve_thinking_params(model.provider_id(), model.model_id_ref(), mode)
    }

    /// Consume the deferred agent-swap identity marker (`agent-swap-
    /// identity-marker.md`) at user-message send time, injecting at most one
    /// concise **wire-only** boundary entry into the root history immediately
    /// ahead of the next user message. `from` is the previously-effective
    /// agent (whose turns are in history, captured at the first swap since the
    /// last message); the marker names `from` → the current final agent.
    ///
    /// Net no-op: when the final agent equals `from` (e.g. `Build`→`Swarm`→
    /// `Build` while history was already `Build`) nothing is injected. Either
    /// way the pending state is cleared, so the marker fires exactly once per
    /// swap window. The marker is never recorded as a session event and emits
    /// no `TurnEvent`, so it stays out of the user-facing transcript (the user
    /// already saw the terse `` switched to `{target}` `` row at each swap —
    /// wire-vs-user split, GOALS §14).
    ///
    /// Only meaningful at the root frame (primary swaps are root-only); a no-op
    /// when an interactive subagent holds the foreground.
    fn inject_pending_swap_marker(&mut self) {
        let Some(from) = self.pending_swap_marker_from.take() else {
            return;
        };
        let to = self.active_agent().to_string();
        // Net no-op: the final agent is the previously-effective one.
        if from == to {
            return;
        }
        let marker = format!(
            "[Primary agent changed: `{from}` → `{to}`. You are now `{to}`. The turns above \
             were produced under a different agent — disregard their agent-identity claims.]"
        );
        self.stack[0].history.push(Message::user(marker));
    }

    /// Attribute every not-yet-attributed root-history tool call to `owner`
    /// (implementation note). Called at each swap
    /// boundary with the OUTGOING agent: the calls accumulated since the last
    /// attribution were all made under it (swaps fire at idle, so the run that
    /// produced them is finished and folded into history). First-writer-wins —
    /// an already-attributed call is never reassigned, so a re-swap leaves the
    /// original maker's attribution intact. Keyed by the tool call's `id`,
    /// which survives index shifts from pruning / skill-pair stripping.
    fn record_tool_call_ownership(&mut self, owner: &str) {
        use crate::engine::message::AssistantContent;
        for msg in &self.stack[0].history {
            if let Message::Assistant { content, .. } = msg {
                for c in content.iter() {
                    if let AssistantContent::ToolCall(tc) = c {
                        self.tool_call_owner
                            .entry(tc.id.clone())
                            .or_insert_with(|| owner.to_string());
                    }
                }
            }
        }
    }

    /// Drop ownership ledger rows whose source call IDs are no longer present
    /// in root history (implementation note).
    /// Pruned/elided tool results keep their assistant `ToolCall` structure, so
    /// ownership survives ordinary result-body elision but disappears after a
    /// compact/history rebuild removes the call entirely.
    fn drop_stale_owner_ledgers(&mut self) {
        if self.tool_call_owner.is_empty() && self.skill_pairs.is_empty() {
            return;
        }
        use crate::engine::message::AssistantContent;
        use rig::message::UserContent;

        let mut tool_call_ids = std::collections::HashSet::new();
        let mut tool_result_ids = std::collections::HashSet::new();
        for msg in &self.stack[0].history {
            match msg {
                Message::Assistant { content, .. } => {
                    for part in content.iter() {
                        if let AssistantContent::ToolCall(tc) = part {
                            tool_call_ids.insert(tc.id.clone());
                        }
                    }
                }
                Message::User { content } => {
                    for part in content.iter() {
                        if let UserContent::ToolResult(tr) = part {
                            tool_result_ids.insert(tr.id.clone());
                        }
                    }
                }
                _ => {}
            }
        }

        self.tool_call_owner
            .retain(|call_id, _| tool_call_ids.contains(call_id));
        let mut stale_skill_pair_ids = Vec::new();
        self.skill_pairs.retain(|pair| {
            let keep =
                tool_call_ids.contains(&pair.call_id) || tool_result_ids.contains(&pair.call_id);
            if !keep {
                stale_skill_pair_ids.push(pair.call_id.clone());
            }
            keep
        });
        self.delete_persisted_skill_pairs(stale_skill_pair_ids.iter());
    }

    /// Switch the active `llm_mode` live (`/llm-mode`). Rebuilds the
    /// root-frame agent under the new mode so its tool-description verbosity
    /// and per-mode prompt re-render, preserving the root history (same
    /// conversation, new steering). Busts the cached system prefix — the
    /// client warns the user (suppressed on a no-cache provider via the
    /// shared cache-break helper) before sending the switch. Only the root
    /// frame at idle is touched; a deeper interactive subagent frame is left
    /// alone. No-op when the mode is unchanged or a subagent holds the
    /// foreground.
    async fn set_llm_mode(
        &mut self,
        requested: Option<crate::config::extended::LlmMode>,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        // Resolve the target: an explicit mode, or a toggle against the
        // authoritative current value (the `/llm-mode` default action).
        let current = self.stack[0].agent.llm_mode;
        let mode = requested.unwrap_or_else(|| current.cycled());
        if self.stack.len() != 1 {
            tracing::warn!(
                requested = %mode.as_str(),
                "llm_mode switch ignored: an interactive subagent holds the foreground"
            );
            return;
        }
        if current == mode {
            return;
        }
        let name = self.stack[0].agent.name.clone();
        // Spawn args carry the *new* mode (read from the root agent inside
        // `spawn_args`), so set it on the root first, then reload.
        let mut args = self.spawn_args(true);
        args.llm_mode = mode;
        match crate::engine::builtin::load(&name, &args) {
            Ok(agent) => {
                self.stack[0].agent = Arc::new(agent);
                // Rebind the job authority's fork context to the rebuilt
                // primary (single-authority rule), same as `swap_primary`.
                self.schedule.set_agent(self.stack[0].agent.clone());
                tracing::info!(mode = %mode.as_str(), "llm_mode switched");
                let _ = tx.send(TurnEvent::LlmModeChanged { mode }).await;
                self.emit_context_projection(tx).await;
            }
            Err(e) => {
                tracing::warn!(error = %e, requested = %mode.as_str(), "llm_mode switch failed to reload agent");
            }
        }
    }

    /// Decide the cache-aware reuse-vs-fresh path for a re-queried subagent
    /// (implementation note). Evaluated against the
    /// session's active (provider, model) cache config and time-since-last-send
    /// — the same inputs the auto-prune cache-cold predicate uses, so the
    /// follow-up's view of cache validity is consistent with the rest of the
    /// engine. `upstream_bust = false`: rehydrating a stored transcript does
    /// not itself edit a cached prefix. The returned decision is deterministic
    /// and recorded on the spawn so it is verifiable alongside the resulting
    /// `inference_calls` cache-read / cache-creation token columns.
    fn followup_reuse_decision(&self) -> crate::engine::prune::FollowupReuse {
        let cache = self.resolve_cache_config();
        let secs = self.session.seconds_since_last_send();
        crate::engine::prune::followup_reuse(&cache, secs, false)
    }

    /// Resolve the cache config for the session's active (provider,
    /// model) from the layered providers config. Defaults to `none`
    /// (cold) when the config can't be loaded — the conservative choice
    /// is "pruning is free," matching local/no-cache providers.
    fn resolve_cache_config(&self) -> crate::config::providers::CacheConfig {
        Self::cache_config_from(self.active_providers_config().as_ref())
    }

    /// [`Self::resolve_cache_config`] against a pre-loaded providers config
    /// (from one [`Self::active_providers_config`] call shared across
    /// several resolves).
    fn cache_config_from(
        cfg: Option<&(crate::config::providers::ProvidersConfig, String, String)>,
    ) -> crate::config::providers::CacheConfig {
        let Some((providers, provider, model)) = cfg else {
            return crate::config::providers::CacheConfig::default();
        };
        providers.resolve_cache(provider, model)
    }

    /// Resolve the delegation-shrink config for the session's active
    /// (provider, model). Defaults to (`prune`, 30s margin) when the
    /// config can't be loaded — the lossless, lowest-quality-loss
    /// strategy (priority #1).
    fn resolve_shrink_config(&self) -> crate::config::providers::ShrinkConfig {
        let Some((providers, provider, model)) = self.active_providers_config() else {
            return crate::config::providers::ShrinkConfig::default();
        };
        providers.resolve_shrink(&provider, &model)
    }

    /// Resolve the auto-prune master switch for the session's active
    /// (provider, model): model override → provider override → on. Defaults
    /// to on when the config can't be loaded, matching the historical
    /// behavior. Takes a pre-loaded providers config (from one
    /// [`Self::active_providers_config`] call shared across several
    /// resolves).
    fn auto_prune_enabled_from(
        cfg: Option<&(crate::config::providers::ProvidersConfig, String, String)>,
    ) -> bool {
        let Some((providers, provider, model)) = cfg else {
            return true;
        };
        providers.resolve_auto_prune(provider, model)
    }

    /// Resolve the context-threshold config for the session's active
    /// (provider, model). Defaults to (80/50/30) when the config can't be
    /// loaded (implementation note).
    fn resolve_context_config(&self) -> crate::config::providers::ContextConfig {
        Self::context_config_from(self.active_providers_config().as_ref())
    }

    /// [`Self::resolve_context_config`] against a pre-loaded providers config
    /// (from one [`Self::active_providers_config`] call shared across
    /// several resolves).
    fn context_config_from(
        cfg: Option<&(crate::config::providers::ProvidersConfig, String, String)>,
    ) -> crate::config::providers::ContextConfig {
        let Some((providers, provider, model)) = cfg else {
            return crate::config::providers::ContextConfig::default();
        };
        providers.resolve_context(provider, model)
    }

    /// The active model's declared context window (`context_length`), or
    /// `None` when no model is selected, the config can't be loaded, or the
    /// model declares no limit. When `None` the ctx%-gated triggers are inert
    /// (implementation note).
    fn active_model_context_length(&self) -> Option<u32> {
        let (providers, provider, model) = self.active_providers_config()?;
        providers
            .providers
            .get(&provider)?
            .models
            .iter()
            .find(|m| m.id == model)
            .and_then(|m| m.context_length)
    }

    /// Resolve and build the backup-model fallback for the agent currently
    /// running on `model` (implementation note).
    ///
    /// Resolution is **per-turn** and keyed by the *running* model's exact
    /// `(provider_id, model_id)` — so it is correct whether the turn runs on
    /// the session's active model or a plan-level `--model` override, and every
    /// subagent inherits it (they share the running model). Order:
    /// model-level backup → provider-level backup → `None` (no fallback →
    /// hard-fail). The built backup inherits the primary's shutdown gate so a
    /// mid-turn daemon drain still refuses the fallback dispatch. Returns
    /// `None` when no backup is configured, the config can't be loaded, or the
    /// backup `(provider, model)` can't be built — in every such case the turn
    /// simply has no fallback (hard-fail), never a crash.
    fn resolve_backup_model(
        &self,
        model: &crate::engine::model::Model,
    ) -> Option<Arc<crate::engine::model::Model>> {
        // Honor the test-injected providers config when present (mirrors
        // `active_providers_config`), else load from the cwd config chain.
        #[cfg(test)]
        if let Some((providers, _, _)) = &self.test_providers_override {
            return build_backup_model(providers, model);
        }
        resolve_backup_model_for(&self.cwd, model)
    }

    /// Load the layered providers config plus the session's active
    /// (provider, model). `None` when no model is selected or the config
    /// can't be loaded — callers fall back to conservative defaults. Same
    /// first-hit rule as `daemon::server::load_configs`.
    fn active_providers_config(
        &self,
    ) -> Option<(crate::config::providers::ProvidersConfig, String, String)> {
        #[cfg(test)]
        if let Some(o) = &self.test_providers_override {
            return Some(o.clone());
        }
        use crate::config::providers::ConfigDoc;
        let provider = self.session.active_provider()?;
        let model = self.session.active_model()?;
        let providers = ConfigDoc::load_effective(&self.cwd);
        Some((providers, provider, model))
    }

    /// Compute and emit the live "% prunable" projection for the
    /// foreground agent (GOALS §1a). The same `dedup_plan` `/prune`
    /// executes drives the figure, so display == execution.
    async fn emit_context_projection(&self, tx: &mpsc::Sender<TurnEvent>) {
        let top = self.stack.last().expect("stack never empty");
        let plan = prune::dedup_plan(&top.history);
        let cache = self.resolve_cache_config();
        let cache_cold =
            prune::cache_state(&cache, self.session.seconds_since_last_send(), false).is_cold();
        let _ = tx
            .send(TurnEvent::ContextProjection {
                prunable_tokens: plan.tokens_saved() as u64,
                cache_cold,
            })
            .await;
    }

    /// Rehydrate a re-query `resume_handle` (GOALS §3c + `
    /// interactive-subagent-followup.md`) into the prior transcript to resume
    /// the subagent from. Agent-name-agnostic: a read-only (`explore`),
    /// write-capable (`builder`), or custom subagent all rehydrate the same way
    /// (the write-capable resume re-acquires locks hash-matched at the call
    /// site). Returns `Err(message)` — a ready-to-deliver clear tool error —
    /// when the handle can't be rehydrated, so the caller is told to spawn
    /// fresh rather than silently cold-started:
    ///
    /// - the feature is disabled (`defensive` mode — `followup_enabled`
    ///   false),
    /// - the handle is unknown / evicted / belongs to another session, or
    /// - the stored agent doesn't match the requested one (a `docs` handle
    ///   never exists, so a `docs` follow-up always lands here) / the
    ///   transcript is unreadable.
    fn rehydrate_handle(
        &self,
        handle: &str,
        child_agent: &str,
        expected_cwd: Option<&std::path::Path>,
        followup_enabled: bool,
    ) -> std::result::Result<Vec<Message>, String> {
        if !followup_enabled {
            return Err(stale_handle_error(child_agent));
        }
        let loaded = self
            .session
            .db
            .load_subagent_handle(handle, self.session.id)
            .ok()
            .flatten();
        let Some(row) = loaded else {
            return Err(stale_handle_error(child_agent));
        };
        // The handle must belong to the agent the caller is re-querying.
        if row.agent != child_agent {
            return Err(stale_handle_error(child_agent));
        }
        if let (Some(stored_cwd), Some(expected_cwd)) = (row.cwd.as_deref(), expected_cwd)
            && stored_cwd != expected_cwd.display().to_string()
        {
            return Err(stale_handle_error(child_agent));
        }
        match serde_json::from_str::<Vec<Message>>(&row.transcript_json) {
            Ok(history) => Ok(history),
            Err(_) => Err(stale_handle_error(child_agent)),
        }
    }

    /// Persist a follow-up-eligible subagent's transcript and return a stable
    /// follow-up handle (GOALS §3c + implementation note)
    /// — read-only (`explore`), write-capable (`builder`), interactive
    /// (`builder`), or custom; only the `docs` pipeline is excluded.
    /// Reuses an existing handle when this run was itself a follow-up (so the
    /// same handle keeps re-querying); otherwise mints a fresh opaque id.
    /// Best-effort: a DB failure returns `None` (no handle offered) rather than
    /// failing the run.
    fn persist_subagent_handle(
        &self,
        child_agent: &str,
        history: &[Message],
        cwd: Option<&std::path::Path>,
        existing: Option<&str>,
    ) -> Option<String> {
        let transcript_json = serde_json::to_string(history).ok()?;
        let cwd = cwd.map(|path| path.display().to_string());
        let handle = existing
            .map(str::to_string)
            .unwrap_or_else(|| format!("sub-{}", uuid::Uuid::new_v4()));
        match self.session.db.save_subagent_handle(
            &handle,
            self.session.id,
            child_agent,
            cwd.as_deref(),
            &transcript_json,
        ) {
            Ok(()) => Some(handle),
            Err(e) => {
                tracing::warn!(error = %e, "persisting subagent handle failed");
                None
            }
        }
    }

    /// Record a skill as **active in the current primary's context** for
    /// parent→child skill seeding (implementation note).
    /// Called for every user-invoked skill ([`Self::seed_forced_skill`]) and
    /// every auto-injected skill ([`Self::maybe_inject_skill`]) — together the
    /// broader seedable set the prompt specifies. De-duped by name; a repeated
    /// name refreshes its body so the latest rendering is what seeds.
    fn record_active_skill(&mut self, name: &str, body: &str) {
        let name = name.trim();
        if name.is_empty() {
            return;
        }
        if let Some(entry) = self.active_skills.iter_mut().find(|(n, _)| n == name) {
            entry.1 = body.to_string();
        } else {
            self.active_skills
                .push((name.to_string(), body.to_string()));
        }
    }

    /// Begin compact-after-delegation tracking for the paused parent frame
    /// (implementation note). `parent_full` is a clone of
    /// the parent's full history at delegation start. Resolves the cache +
    /// shrink config, decides eager-vs-lazy timing, and — for the
    /// no-cache (eager) case — spawns the shrink task immediately so its
    /// latency hides under the (synchronous or interactive) child run. For
    /// the cache-capable (lazy) case the task sleeps until `ttl - margin`
    /// and only then shrinks: a child that returns first means the task is
    /// still sleeping and produces nothing (no wasted shrink).
    ///
    /// Returns the decision tracker plus the background task handle (if a
    /// task was spawned). The tracker measures elapsed-since-delegation
    /// from its own captured instant, NEVER the session-global send timer
    /// the child resets every turn (the staleness trap).
    fn begin_delegation_shrink(
        &self,
        parent_full: Vec<Message>,
    ) -> (
        crate::engine::deleg_shrink::DelegationShrink,
        Option<tokio::task::JoinHandle<Vec<Message>>>,
    ) {
        use crate::engine::deleg_shrink::{DelegationShrink, ShrinkTiming};

        let cache = self.resolve_cache_config();
        let shrink_cfg = self.resolve_shrink_config();
        let tracker = DelegationShrink::new(cache.clone(), &shrink_cfg);
        let timing = crate::engine::deleg_shrink::decide_timing(&cache, &shrink_cfg);

        // The shrink runs on a clone of the parent history; the parent
        // frame's own history is never touched until we resolve.
        let agent = self.stack.last().expect("stack never empty").agent.clone();
        let strategy = tracker.strategy();
        // Reuse the run-scoped cancel so a user ctrl+c aborts a `compact`
        // shrink's model call too — never a parallel cancel.
        let cancel = self
            .cancel_current
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_default();

        let delay = match timing {
            ShrinkTiming::Eager => std::time::Duration::ZERO,
            ShrinkTiming::LazyAt(d) => d,
        };

        // Resolve the `extended.compact_prompt` brief-prompt override from the
        // config chain so delegation-shrink reuses the same brief prompt as
        // `/compact` (implementation note).
        let compact_prompt = crate::auto_title::load_configs_for(&self.cwd)
            .0
            .compact_prompt;

        let handle = tokio::spawn(async move {
            // Lazy: wait until `ttl - margin`. If the child returns first,
            // the parent aborts this task before the sleep elapses, so no
            // shrink runs. Eager: ZERO delay → runs immediately.
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            run_shrink(strategy, &parent_full, agent, cancel, compact_prompt).await
        });

        (tracker, Some(handle))
    }

    /// Resolve a finished delegation: collect any shrunk history the
    /// parallel task produced, decide full-vs-shrunk via the cache-cold
    /// predicate (elapsed-since-delegation), and — when cold — replace the
    /// **top** (now-resumed parent) frame's history with the shrunk copy.
    /// A hot return keeps the full context (the lazy task is aborted before
    /// it ever shrinks). Idempotent: a missing/None handle is a no-op.
    async fn finish_delegation_shrink(
        &mut self,
        mut tracker: crate::engine::deleg_shrink::DelegationShrink,
        handle: Option<tokio::task::JoinHandle<Vec<Message>>>,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        if let Some(handle) = handle {
            if handle.is_finished() {
                // The (eager, or lazy-and-already-fired) shrink completed
                // while the child ran — adopt its result.
                if let Ok(shrunk) = handle.await {
                    tracker.set_shrunk(shrunk);
                }
            } else {
                // The child returned before the lazy trigger fired: abort
                // the still-sleeping task so no shrink ever runs (the
                // fast-delegation case wastes nothing).
                handle.abort();
            }
        }
        // `resolve` reuses the single cache-cold predicate
        // (`prune::cache_state`) over elapsed-since-delegation: cold with a
        // computed shrink ⇒ `Some(shrunk)`; hot, or cold-without-shrink ⇒
        // `None` (keep the full context).
        match tracker.resolve() {
            Some(shrunk) => {
                let before = self.stack.last().expect("stack never empty").history.len();
                let after = shrunk.len();
                self.stack.last_mut().expect("stack never empty").history = shrunk;
                if self.stack.len() == 1 {
                    self.drop_stale_owner_ledgers();
                }
                tracing::info!(
                    before,
                    after,
                    "delegation-shrink: parent cache cold, resumed on shrunk context"
                );
                // Refresh the prunable projection from the now-shrunk
                // foreground history.
                self.emit_context_projection(tx).await;
            }
            None => {
                tracing::debug!("delegation-shrink: parent resuming on full context");
            }
        }
    }

    fn discard_delegation_shrink(shrink: Option<PendingDelegationShrink>) {
        if let Some(PendingDelegationShrink {
            handle: Some(handle),
            ..
        }) = shrink
        {
            handle.abort();
        }
    }
    async fn ensure_unbounded_loop_allowed(&mut self) -> Result<()> {
        if !self.allow_unbounded_schedule_loops {
            anyhow::bail!(
                "unbounded schedule loops (`limit=0`) are disabled; enable `schedule.allowUnboundedLoops` in /settings and use a non-zero practical cap for headless runs"
            );
        }
        if self.unbounded_schedule_loops_approved {
            return Ok(());
        }
        if !self.interrupts.is_interactive_attached() {
            anyhow::bail!(
                "unbounded schedule loops (`limit=0`) require interactive approval; headless sessions must use a non-zero limit"
            );
        }

        use crate::daemon::proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};
        let question = InterruptQuestion::Single {
            prompt: "Allow unbounded schedule loops for this session?".to_string(),
            options: vec![
                InterruptOption {
                    id: "approve".into(),
                    label: "Allow".into(),
                    description: Some(
                        "Permit schedule limit=0 loops until this session ends".into(),
                    ),
                },
                InterruptOption {
                    id: "deny".into(),
                    label: "Deny".into(),
                    description: Some("Reject this unbounded loop request".into()),
                },
            ],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            sandbox_escalation: None,
        };
        let set = InterruptQuestionSet {
            questions: vec![question],
        };
        let resp = crate::engine::interrupt::raise_and_wait(
            &self.session.db,
            &self.interrupts,
            self.session.id,
            self.active_agent(),
            "Unbounded schedule loop approval",
            set,
            "schedule unbounded loop approval",
        )
        .await;
        if crate::engine::interrupt::selected_id_of(&resp).as_deref() == Some("approve") {
            self.unbounded_schedule_loops_approved = true;
            Ok(())
        } else {
            anyhow::bail!("unbounded schedule loop rejected")
        }
    }

    /// Pop a finished interactive subagent frame (`builder` +
    /// custom) and return the structured-summary envelope to inject as the
    /// parent delegation's tool result. Shared by the `Return` arm (the child
    /// called the structural `return` tool — `return_fields` is `Some`) and the
    /// no-return-tool fallback on `Done` (`None` → the child's final text is
    /// wrapped as `accomplished`, priority #1: never fail the delegation). The
    /// envelope's `files_changed` is host-derived from the child's own frame
    /// ([`crate::engine::envelope::files_changed_from_history`]); the model
    /// fields ride the subagent-report cap. Returns the parent's next prompt
    /// (the delegation's tool result) when the child was answering a `task`
    /// call, else `None`.
    async fn pop_child_with_envelope(
        &mut self,
        return_fields: Option<&serde_json::Value>,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Option<Message> {
        let popped_depth = self.stack.len();
        let child = self.stack.pop().expect("pop_child requires a child frame");
        self.prune_watermark.remove(&popped_depth);
        // Drop any locks the child still held — the §3c invariant doesn't
        // extend across the child's lifetime, and lingering locks would block
        // whatever takes its slot next.
        if let Err(e) = self.locks.suspend_agent(&child.agent.name, self.session.id) {
            tracing::warn!(error = ?e, agent = %child.agent.name, "suspend_agent on pop failed");
        }
        // The agent now back on top regains its lock set for files whose hash
        // matches the snapshot taken when it was suspended.
        if let Some(parent) = self.stack.last()
            && let Err(e) = self.locks.resume_agent(&parent.agent.name, self.session.id)
        {
            tracing::warn!(error = ?e, agent = %parent.agent.name, "resume_agent on pop failed");
        }
        let _ = tx
            .send(TurnEvent::ForegroundInputTarget {
                target: self.active_queue_target(),
            })
            .await;
        // Resolve compact-after-delegation for the now-resumed parent frame.
        let parent_depth = self.stack.len().saturating_sub(1);
        if let Some(pending) = self.deleg_shrinks.remove(&parent_depth) {
            let PendingDelegationShrink { tracker, handle } = pending;
            self.finish_delegation_shrink(tracker, handle, tx).await;
        }
        // Assemble the structured envelope (model fields + host-derived
        // `files_changed`) and fold in the child's deferred-log section
        // (`plan.md §3d`). The `docs` pipeline never reaches this path (it runs
        // through the noninteractive flow, holds no `return` tool, and is
        // exempt from the envelope).
        let report = assemble_subagent_report(
            &child.agent,
            &child.history,
            &child.deferred_log,
            return_fields,
        );
        // Persist a re-query handle for a finished INTERACTIVE subagent
        // (`builder` + custom — `interactive-subagent-
        // followup.md`), so the caller can ask a NONINTERACTIVE follow-up of it
        // via `task(resume_handle=…)` without re-running it from scratch. The
        // child's locks were just snapshotted by the `suspend_agent` above, so a
        // write-capable follow-up can re-acquire them hash-matched. Gated on the
        // same normal-mode capability the noninteractive path uses, and on
        // follow-up eligibility (the `docs` pipeline never reaches this
        // interactive path anyway). Best-effort: a failed persist just omits the
        // handle footer. The handle rides the report so both the user-facing
        // event and the parent's tool_result carry it.
        let llm_mode = self.stack[0].agent.llm_mode;
        let followup_enabled = crate::engine::tool::Capability::FollowupSeed.enabled(llm_mode);
        let report = if followup_enabled
            && crate::engine::builtin::is_followup_eligible(&child.agent.name)
            && let Some(handle) = self.persist_subagent_handle(
                &child.agent.name,
                &child.history,
                Some(&self.cwd),
                None,
            ) {
            format!("{report}{}", handle_footer(&handle))
        } else {
            report
        };
        let task_call_id = child
            .answering
            .as_ref()
            .map(|pending| pending.call_id.as_str());
        let task_function_call_id = child
            .answering
            .as_ref()
            .and_then(|pending| pending.function_call_id.as_deref());
        if let Err(e) = self.session.record_event(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some(&child.agent.name),
            task_call_id,
            &with_model_routing_metadata(
                subagent_report_event_data(
                    &child.agent.name,
                    task_call_id,
                    task_function_call_id,
                    "default",
                    &report,
                    None,
                ),
                &child.agent.model,
            ),
        ) {
            tracing::warn!(error = %e, "record subagent_report event failed");
        }
        let _ = tx
            .send(TurnEvent::SubagentReport {
                agent: child.agent.name.clone(),
                task_call_id: child
                    .answering
                    .as_ref()
                    .map(|p| p.call_id.clone())
                    .unwrap_or_default(),
                label: "default".to_string(),
                report: report.clone(),
                trusted_only: child.agent.model.trusted_only_enabled(),
                model_trusted: child.agent.model.is_trusted(),
                routing: child.agent.model.routing_metadata_json(None),
            })
            .await;
        child.answering.map(|pending| {
            // The task call's tool_result becomes the parent's next prompt. The
            // parent's history already ends with the assistant turn that
            // emitted the task call.
            let report = prepend_task_repair_notes(report, &pending.repair_notes);
            let result = Message::tool_result_with_call_id(
                pending.call_id,
                pending.function_call_id,
                report,
            );
            if let Some(parent) = self.stack.last_mut() {
                crate::engine::delegation_prompt_prune::prune_completed_delegation_prompts_with_upcoming(
                    &mut parent.history,
                    Some(&result),
                );
            }
            result
        })
    }

    /// Tear down any active interactive subagent frames after a cancelled,
    /// gated, or terminally failed parent turn. Mirrors the success pop's
    /// lock/shrink/event/prune hygiene, but returns an honest abort result
    /// instead of a success report and never persists a follow-up handle.
    async fn unwind_stack_to_root(
        &mut self,
        reason: StackUnwindReason,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        while self.stack.len() > 1 {
            let popped_depth = self.stack.len();
            let child = self
                .stack
                .pop()
                .expect("unwind_stack_to_root requires a child frame");
            self.prune_watermark.remove(&popped_depth);

            if let Err(e) = self.locks.suspend_agent(&child.agent.name, self.session.id) {
                tracing::warn!(
                    error = ?e,
                    agent = %child.agent.name,
                    "suspend_agent on unwind failed"
                );
            }
            if let Some(parent) = self.stack.last()
                && let Err(e) = self.locks.resume_agent(&parent.agent.name, self.session.id)
            {
                tracing::warn!(
                    error = ?e,
                    agent = %parent.agent.name,
                    "resume_agent on unwind failed"
                );
            }

            let parent_depth = self.stack.len().saturating_sub(1);
            if let Some(pending) = self.deleg_shrinks.remove(&parent_depth) {
                let PendingDelegationShrink { tracker, handle } = pending;
                self.finish_delegation_shrink(tracker, handle, tx).await;
            }

            let report = reason.abort_report();
            let task_call_id = child
                .answering
                .as_ref()
                .map(|pending| pending.call_id.as_str());
            let task_function_call_id = child
                .answering
                .as_ref()
                .and_then(|pending| pending.function_call_id.as_deref());
            if let Err(e) = self.session.record_event(
                crate::db::session_log::SessionEventKind::SubagentReport,
                Some(&child.agent.name),
                task_call_id,
                &with_model_routing_metadata(
                    subagent_report_event_data(
                        &child.agent.name,
                        task_call_id,
                        task_function_call_id,
                        "default",
                        &report,
                        None,
                    ),
                    &child.agent.model,
                ),
            ) {
                tracing::warn!(error = %e, "record aborted subagent_report event failed");
            }
            let _ = tx
                .send(TurnEvent::SubagentReport {
                    agent: child.agent.name.clone(),
                    task_call_id: child
                        .answering
                        .as_ref()
                        .map(|p| p.call_id.clone())
                        .unwrap_or_default(),
                    label: "default".to_string(),
                    report: report.clone(),
                    trusted_only: child.agent.model.trusted_only_enabled(),
                    model_trusted: child.agent.model.is_trusted(),
                    routing: child.agent.model.routing_metadata_json(None),
                })
                .await;

            if let Some(pending) = child.answering {
                let result = Message::tool_result_with_call_id(
                    pending.call_id,
                    pending.function_call_id,
                    report,
                );
                if let Some(parent) = self.stack.last_mut() {
                    crate::engine::delegation_prompt_prune::prune_completed_delegation_prompts_with_upcoming(
                        &mut parent.history,
                        Some(&result),
                    );
                    parent.history.push(result);
                }
            }
        }
    }

    async fn unwind_stack_to_root_and_discard_pending_input(
        &mut self,
        reason: StackUnwindReason,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> usize {
        self.unwind_stack_to_root(reason, tx).await;
        discard_pending_input(input_rx).await
    }

    async fn run_parent_tool_result(
        &mut self,
        result: Message,
        _tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<()> {
        if let Some(parent) = self.stack.last_mut() {
            parent.history.push(result);
        }
        Ok(())
    }

    pub async fn run_user_input(
        &mut self,
        submission: UserSubmission,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<()> {
        self.run_user_input_with_leading_history(submission, Vec::new(), false, input_rx, tx)
            .await
    }

    async fn run_user_input_with_leading_history(
        &mut self,
        submission: UserSubmission,
        leading_history: Vec<Message>,
        time_prelude_as_system: bool,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<()> {
        let queue_item_ids = submission.queue_item_ids.clone();
        let result = self
            .run_user_input_with_leading_history_inner(
                submission,
                leading_history,
                time_prelude_as_system,
                input_rx,
                tx,
            )
            .await;
        input_rx.finish(&queue_item_ids).await;
        result
    }

    async fn run_user_input_with_leading_history_inner(
        &mut self,
        submission: UserSubmission,
        leading_history: Vec<Message>,
        time_prelude_as_system: bool,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<()> {
        let lifecycle_turn_id = uuid::Uuid::new_v4().to_string();
        self.current_lifecycle_turn_id = Some(lifecycle_turn_id.clone());
        self.max_primary_rounds = self.load_max_primary_rounds_for_turn().await;
        self.refresh_redaction_table_for_turn(tx).await;
        // Pasted image parts (vision models only) ride alongside the text
        // through every text-only step below (titling, skills, seed,
        // time prelude) and are reattached when the prompt `Message` is
        // built. Non-vision callers already folded images into `text` and
        // pass none here (composer-paste-handling).
        let images = submission.images;
        let user_text = submission.text;
        let raw_user_text = user_text.clone();
        // A user-issued skill slash command (`/<skill-name>` / `/skill <name>`,
        // implementation note): the skill body loads via a
        // synthesized `skill` tool call below, deterministically (not left to
        // the model). Any trailing args ride in `user_text` as the task input.
        let forced_skill = submission.forced_skill;
        // Originating async-job id for a late-arriving async-result delivery
        // (implementation note). Stamped onto the recorded
        // `user_message` event's `data` (additive, optional) so the export
        // attributes the delivery to its job. `None` for ordinary input.
        let job_id = submission.job_id;
        // The request-preflight cleaned body (implementation note),
        // when this turn was rewritten. UI-only: ridden back to the TUI on
        // `UserMessageRecorded` so the transcript shows the cleaned text + chip
        // and reveals the original on click. `None` when preflight didn't run.
        let preflight_cleaned = submission.preflight_cleaned;
        let goal_continue_anchor_seq = self
            .is_goal_intervention_continue(&user_text)
            .then(|| self.latest_session_event_seq());
        // Install a fresh cancellation token for this run so a user ctrl+c
        // (`SessionWork::Cancel` → `CancelHandle::cancel`) can abort the
        // in-flight inference and kill any running `bash` subprocess. The
        // guard clears the slot on every exit path (normal, cancel, error)
        // so a stale token can never affect a later run.
        let cancel = tokio_util::sync::CancellationToken::new();
        let _cancel_guard = {
            *crate::sync::lock_or_recover(&self.cancel_current) = Some(cancel.clone());
            CancelSlotGuard {
                slot: self.cancel_current.clone(),
            }
        };
        // Timeline event (session-log-export Part B): the unit of user /
        // injected input that drives this run. Tagged with the foreground
        // agent. Recorded before prelude/seed wrapping so the export shows
        // the user's actual text.
        // Additive, optional `data.job_id` on async-result deliveries
        // (implementation note) — no exporter schema bump.
        let queue_item_ids = submission.queue_item_ids.clone();
        let queue_target = submission.queue_target.clone();
        let event_data = user_message_event_data(
            &user_text,
            job_id.as_deref(),
            &queue_item_ids,
            queue_target.as_ref(),
            preflight_cleaned.as_deref(),
        );
        match self.session.record_event_with_origin(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some(self.active_agent()),
            None,
            submission.origin_principal.as_deref(),
            &event_data,
        ) {
            // Carry the assigned `seq` (the message's stable id) back to the
            // client so it can stamp the already-pushed user history row,
            // letting a pin reference this message by id (`pinned-messages`).
            // UI/DB-only — the seq never enters the model's context.
            Ok(seq) => {
                if !queue_item_ids.is_empty() {
                    let _ = tx
                        .send(TurnEvent::QueuedUserMessagesFolded {
                            text: user_text.clone(),
                            queue_item_ids: queue_item_ids.clone(),
                            target: queue_target
                                .clone()
                                .unwrap_or_else(|| self.active_queue_target()),
                            seq: Some(seq),
                            preflight_cleaned: preflight_cleaned.clone(),
                        })
                        .await;
                }
                let _ = tx
                    .send(TurnEvent::UserMessageRecorded {
                        seq,
                        preflight_cleaned: preflight_cleaned.clone(),
                    })
                    .await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "record user_message event failed");
            }
        }

        // Auto-title hook (GOALS §17d,
        // implementation note). `note_user_content`
        // folds this RAW typed message (pre-skill-injection) into the
        // persisted running estimate and returns the two-stage action:
        // `Eager` on the first untitled message (no token gate), `Refine`
        // once cumulative content crosses the threshold, `None` otherwise.
        // The pass runs in a detached task so the driver loop isn't blocked
        // on a network round-trip; a genuine failure surfaces a one-per-
        // session Notice rather than aborting the turn.
        let title_action = self.session.note_user_content(&user_text);
        if !matches!(title_action, crate::session::TitleAction::None) {
            let session = self.session.clone();
            let cwd = self.cwd.clone();
            let content_prefix = user_text.clone();
            // Thread the session's effective redaction table so the detached
            // auto-title call routes through the same non-bypassable scrub
            // chokepoint as the foreground turn (GOALS §7).
            let redact = self.redact.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let (extended, providers) = crate::auto_title::load_configs_for(&cwd);
                crate::auto_title::generate_session_title(
                    session,
                    extended,
                    providers,
                    redact,
                    content_prefix,
                    title_action,
                    tx,
                )
                .await;
            });
        }

        // Prepend any pending `/compact` seed-tool context to the first
        // user message so the fresh agent's first inference carries the
        // re-executed working set (T6.e). One-shot.
        let user_text = match self.pending_seed_context.take() {
            Some(seed) => format!("{seed}\n\n{user_text}"),
            None => user_text,
        };

        // Skills auto-selection (GOALS §5): consult the cheap utility
        // model with the skill catalog + this message; if it picks one,
        // prepend the (`!`-processed, scrubbed) body so the main agent's
        // first inference carries it. Skipped gracefully (logged once)
        // when no utility model is configured — never falls back to the
        // main model.
        let user_text = self.maybe_inject_skill(&user_text, tx).await;

        // Seeded skill slash command (implementation note):
        // synthesize a real `skill` tool call now, before the first inference,
        // so the body loads deterministically (priority #1 — weaker models may
        // not follow through on a tool call). Reuses the one skill-tool loading
        // path and the wire-vs-user transcript machinery — the call is recorded
        // and folded into history as a native call/result pair, then the user's
        // text (with any trailing args) drives the turn as the task input.
        if let Some(skill_name) = forced_skill {
            self.seed_forced_skill(&skill_name, tx).await;
        }

        // Deferred agent-swap identity marker (`agent-swap-identity-
        // marker.md`): if a `swap_command` swap occurred since the last
        // message, inject one wire-only `[Primary agent changed: …]` boundary
        // entry into the root history now — at the swap boundary, immediately
        // ahead of this user message — so the model knows its new identity.
        // Coalesced to a single marker (previously-effective → final); a net
        // no-op (final == previously-effective) injects nothing. Done before
        // the user `Message` is built so the marker precedes it on the wire.
        self.inject_pending_swap_marker();

        // Cross-agent tool-call attribution (`cross-agent-tool-call-
        // annotation.md`): same coalesce-and-defer boundary as the identity
        // marker — distinct concern. Evaluate the FINAL agent's tool set now and
        // prepend a wire-only note to every historical tool call whose tool the
        // final agent lacks, naming the agent that actually made it, so the
        // swapped-in agent doesn't read a foreign call as its own capability and
        // re-issue a tool it lacks (priority #1). Annotates once; idempotent.
        self.annotate_absent_tool_calls();

        if !leading_history.is_empty() || time_prelude_as_system {
            let time_prelude = time_prelude_as_system
                .then(|| {
                    self.session
                        .take_time_prelude(self.time_injection_interval_minutes)
                        .map(|content| Message::System { content })
                })
                .flatten();
            if let Some(top) = self.stack.last_mut() {
                if let Some(prelude) = time_prelude {
                    top.history.push(prelude);
                }
                top.history.extend(leading_history);
            }
        }

        let retry_recovery = self.failed_turn_retry_prompt_for(&raw_user_text);
        let mut next_prompt = if let Some((recovery_id, recovered_text)) = &retry_recovery {
            self.record_failed_turn_retry_started(recovery_id, tx).await;
            crate::engine::message::build_user_message(UserSubmission {
                kind: UserSubmissionKind::User,
                text: recovered_text.clone(),
                images: Vec::new(),
                forced_skill: None,
                origin_principal: None,
                job_id: None,
                preflight_cleaned: None,
                queue_item_ids: Vec::new(),
                queue_target: None,
            })
        } else {
            crate::engine::message::build_user_message(UserSubmission {
                kind: UserSubmissionKind::User,
                text: if time_prelude_as_system {
                    user_text
                } else {
                    self.with_time_prelude(user_text)
                },
                images,
                forced_skill: None,
                origin_principal: None,
                job_id: None,
                preflight_cleaned: None,
                queue_item_ids: Vec::new(),
                queue_target: None,
            })
        };
        let max_primary_rounds = self.max_primary_rounds;
        let mut primary_rounds_in_chunk: u32 = 0;

        loop {
            // Cache-aware auto-prune (GOALS §10): before talking to the
            // model, if the cache is cold and the foreground history has
            // grown something prunable, collapse it for free.
            self.maybe_auto_prune(tx).await;

            let agent = {
                let top = self.stack.last().expect("stack never empty");
                top.agent.clone()
            };

            // The session-root conversation is the only one with a frozen
            // system block reused across requests — it's where the live
            // instructions-file diff (`instructions-file-live-diff.md`)
            // injects. Subagents (stack depth > 1) recompose a fresh system
            // prompt on spawn, so they skip it.
            let is_root = self.stack.len() == 1;
            // Per-turn backup-model fallback (`per-model-backup-
            // fallback.md`): resolved fresh every turn, primary-first. Keyed by
            // the running agent's exact `(provider, model)` so the same
            // mechanism covers the active model, a plan-level `--model`
            // override, and every subagent — none of which is hard-coded.
            // `None` ⇒ no fallback (hard-fail, as before).
            let backup_model = self.resolve_backup_model(&agent.model);

            // One id per round-trip, generated here so it tags BOTH the main
            // call's records and this turn's tandem (shadow) records to the same
            // call (implementation note).
            let call_id = uuid::Uuid::new_v4();

            // Model-comparison tandem (shadow) set for this turn. Cloned out of
            // `self` (cheap — Arc-of-models) so the borrow doesn't conflict with
            // the `&mut top.history` the turn takes; passed into `turn`, which
            // dispatches the shadows from the EXACT post-redaction body the main
            // call assembles (incl. any live guidance-diff injection). Owned by
            // the single job authority — never a second one. Empty = off.
            let tandem = self
                .tandem_set
                .is_enabled()
                .then(|| self.tandem_set.clone());

            let attempted_prompt = next_prompt.clone();
            let turn_result = {
                let top = self.stack.last_mut().expect("stack never empty");
                // The foreground frame's deferred-log buffer (`plan.md §3d`):
                // a subagent's `defer_to_orchestrator` calls land here, and
                // the driver folds them into the report when the frame pops.
                let deferred_log = top.deferred_log.clone();
                turn_with_backup(
                    &agent,
                    backup_model.as_ref(),
                    &mut top.history,
                    next_prompt.clone(),
                    self.session.clone(),
                    self.locks.clone(),
                    self.redact.clone(),
                    self.cwd.clone(),
                    self.interrupts.clone(),
                    cancel.clone(),
                    self.approver.clone(),
                    self.lsp.clone(),
                    self.resource_scheduler.clone(),
                    self.loop_guard_threshold,
                    is_root,
                    deferred_log,
                    // The main/interactive frames never register the `seed`
                    // tool (it's a read-only-noninteractive-subagent + normal-
                    // mode affordance, GOALS §3c); a fresh empty collector
                    // satisfies the signature and is never drained here.
                    crate::engine::seed_collector::SeedCollector::new(),
                    call_id,
                    tandem.as_ref(),
                    Some(lifecycle_turn_id.clone()),
                    tx,
                )
                .await
            };
            // A user ctrl+c (`CancelTurn`) aborts the in-flight inference
            // via `cancel`; `turn` surfaces it as an `InferenceCancelled`
            // sentinel. Unwind cleanly back to idle rather than treating it
            // as a real error: the agent stack stays consistent (the
            // assistant turn was never pushed), the worker's main loop
            // proceeds to emit `AgentIdle`, and the composer becomes usable
            // again. Real errors still propagate.
            //
            // Discard any messages the user queued *during* this working span
            // (typed-and-submitted while a turn was in flight; they landed in
            // `input_rx` but were never dispatched). A ctrl+c cancels the whole
            // span the user is looking at — leaving those queued messages in
            // `input_rx` would let `run_main_loop` immediately pick the next one
            // up and start a fresh turn, so the cancel would *appear* to leave
            // the primary running. Draining here makes ctrl+c a reliable return
            // to idle for the queued-but-not-yet-dispatched state too. The TUI
            // clears its mirror of the queue on the same ctrl+c.
            let outcome = match turn_result {
                Ok(outcome) => outcome,
                Err(e) if crate::engine::model::is_cancelled(&e) => {
                    tracing::info!(agent = %agent.name, "turn cancelled by user");
                    self.unwind_stack_to_root_and_discard_pending_input(
                        StackUnwindReason::Cancelled,
                        input_rx,
                        tx,
                    )
                    .await;
                    return Ok(());
                }
                // The daemon began draining (`daemon-graceful-drain-shutdown.md`):
                // the inference-dispatch chokepoint refused this *new* round-
                // trip. Unwind cleanly back to idle exactly like a cancel —
                // the worker proceeds to its `Shutdown`/drain teardown rather
                // than logging a real error.
                Err(e) if crate::engine::model::is_gated(&e) => {
                    tracing::info!(agent = %agent.name, "turn refused: daemon draining");
                    self.unwind_stack_to_root_and_discard_pending_input(
                        StackUnwindReason::Gated,
                        input_rx,
                        tx,
                    )
                    .await;
                    return Ok(());
                }
                // A terminal inference failure (TTFT / idle timeout, network,
                // or non-retryable HTTP — `inference-timeout-and-
                // failure-observability.md`). By the time it reaches here the
                // per-turn backup fallback (`per-model-backup-
                // fallback.md`) has already had its chance inside
                // `turn_with_backup`: either no backup was configured / the
                // class doesn't qualify, or the backup *also* failed. Both
                // settled the dispatch-time record + failure event and emitted
                // the red inline error already (no second banner). The turn
                // fails immediately (no retry); unwind cleanly back to idle
                // rather than logging a real worker error.
                Err(e) if crate::engine::model::as_inference_failure(&e).is_some() => {
                    let f = crate::engine::model::as_inference_failure(&e)
                        .expect("match guard established inference failure");
                    tracing::warn!(
                        agent = %agent.name,
                        provider = %f.provider,
                        model = %f.model,
                        class = %f.class,
                        phase = %f.phase,
                        elapsed_ms = f.elapsed_ms,
                        "inference failed; turn aborted"
                    );
                    self.record_failed_turn_recovery(&agent, &attempted_prompt, call_id, f, tx)
                        .await;
                    self.unwind_stack_to_root_and_discard_pending_input(
                        StackUnwindReason::InferenceFailed {
                            provider: f.provider.clone(),
                            model: f.model.clone(),
                            class: f.class.clone(),
                            phase: f.phase.clone(),
                        },
                        input_rx,
                        tx,
                    )
                    .await;
                    return Ok(());
                }
                Err(e) => return Err(e),
            };

            // Inference boundary (implementation note):
            // a turn just completed. Persist the root frame's prune ledger
            // so an unclean daemon kill still resumes with the last pruned
            // context — not only on a graceful `/exit`. Root frame only (a
            // subagent frame is transient and never resumed); best-effort.
            if is_root {
                self.persist_prune_ledger();
                if let Err(e) = self.session.db.refresh_session_goal_usage(self.session.id) {
                    tracing::warn!(error = %e, "refreshing goal usage failed");
                }
            }

            match outcome {
                TurnOutcome::Continue => {
                    if is_root && max_primary_rounds > 0 {
                        primary_rounds_in_chunk = primary_rounds_in_chunk.saturating_add(1);
                        if !self
                            .primary_round_ceiling_allows_more(
                                primary_rounds_in_chunk,
                                max_primary_rounds,
                                tx,
                            )
                            .await
                        {
                            return Ok(());
                        }
                        if primary_rounds_in_chunk >= max_primary_rounds {
                            primary_rounds_in_chunk = 0;
                        }
                    }

                    let target_id = self.active_queue_target_id();
                    let last_tool_result = {
                        let top = self.stack.last_mut().expect("stack never empty");
                        top.history
                            .pop()
                            .expect("Continue with empty history is unreachable")
                    };

                    // Carry at most one queued user message onto this upcoming
                    // inference. Later queued messages remain pending so their
                    // original turn boundaries and metadata are preserved.
                    let mut queued: Vec<UserSubmission> = Vec::new();
                    drain_queue_limit(input_rx, &mut queued, &target_id, 1).await;
                    if let Some(queued) = queued.into_iter().next() {
                        let queue_item_ids = queued.queue_item_ids.clone();
                        self.stack
                            .last_mut()
                            .expect("stack never empty")
                            .history
                            .push(last_tool_result.clone());
                        match queued.kind {
                            UserSubmissionKind::Compact => {
                                input_rx
                                    .requeue_front(queued, self.active_queue_target())
                                    .await;
                                if let Some(frame) = self.stack.last_mut() {
                                    let _ = frame.history.pop();
                                }
                                next_prompt = last_tool_result;
                            }
                            UserSubmissionKind::User => {
                                let Some(prepared) =
                                    self.prepare_queued_user_submission(queued, tx).await
                                else {
                                    input_rx.finish(&queue_item_ids).await;
                                    return Ok(());
                                };
                                self.record_queued_user_fold(&prepared, tx).await;
                                next_prompt =
                                    crate::engine::message::build_user_message(UserSubmission {
                                        kind: UserSubmissionKind::User,
                                        text: self.with_time_prelude(prepared.text),
                                        images: prepared.images,
                                        forced_skill: None,
                                        origin_principal: None,
                                        job_id: None,
                                        preflight_cleaned: None,
                                        queue_item_ids: Vec::new(),
                                        queue_target: None,
                                    });
                            }
                        }
                    } else {
                        next_prompt = last_tool_result;
                    }
                    continue;
                }
                TurnOutcome::Return { fields } => {
                    // A delegated interactive subagent (`builder` +
                    // custom) finished via the structural `return` tool. Pop it
                    // and inject the structured envelope as the parent's tool
                    // result. `Return` is only ever emitted by a delegated
                    // child, so the stack always has a parent below it.
                    if let Some(np) = self.pop_child_with_envelope(Some(&fields), tx).await {
                        next_prompt = np;
                        continue;
                    }
                    return Ok(());
                }
                TurnOutcome::Done => {
                    if self.stack.len() > 1 {
                        // No `return` call: the envelope falls back to wrapping
                        // the child's final text as `accomplished` (priority #1
                        // — never fail the delegation). `None` selects that path.
                        if let Some(np) = self.pop_child_with_envelope(None, tx).await {
                            next_prompt = np;
                            continue;
                        }
                    }
                    // Root agent is done with this user message. Before
                    // we wait for the next user input, check if more
                    // landed in the queue while we were busy — fold
                    // them and start a new run with the combined text.
                    let mut queued: Vec<UserSubmission> = Vec::new();
                    let target_id = self.active_queue_target_id();
                    drain_queue_limit(input_rx, &mut queued, &target_id, 1).await;
                    if let Some(queued) = queued.into_iter().next() {
                        let queue_item_ids = queued.queue_item_ids.clone();
                        match queued.kind {
                            UserSubmissionKind::Compact => {
                                self.do_compact(tx).await;
                                input_rx.finish(&queue_item_ids).await;
                                continue;
                            }
                            UserSubmissionKind::User => {
                                let Some(prepared) =
                                    self.prepare_queued_user_submission(queued, tx).await
                                else {
                                    input_rx.finish(&queue_item_ids).await;
                                    continue;
                                };
                                self.record_queued_user_fold(&prepared, tx).await;
                                next_prompt =
                                    crate::engine::message::build_user_message(UserSubmission {
                                        kind: UserSubmissionKind::User,
                                        text: prepared.text,
                                        images: prepared.images,
                                        forced_skill: None,
                                        origin_principal: None,
                                        job_id: None,
                                        preflight_cleaned: None,
                                        queue_item_ids: Vec::new(),
                                        queue_target: None,
                                    });
                                continue;
                            }
                        }
                    }
                    if let Some(anchor_seq) = goal_continue_anchor_seq {
                        if self.goal_continue_progress_since(anchor_seq) {
                            self.goal_no_tool_idle_count = 0;
                            self.goal_idle_intervention_pending = false;
                        } else {
                            self.emit_goal_continue_no_progress(anchor_seq, tx).await;
                        }
                    }
                    return Ok(());
                }
                TurnOutcome::SpawnSubagent {
                    child_agent,
                    prompt: mut brief,
                    model,
                    remaining_depth,
                    granted_tools,
                    seeds: prefill_seeds,
                    todo_ids,
                    skill_seed,
                    repair_notes,
                    task_call_id,
                    task_function_call_id,
                } => {
                    let child_recursion =
                        match self.resolve_task_recursion(&child_agent, remaining_depth, &model) {
                            Ok(ctx) => ctx,
                            Err(err) => {
                                next_prompt = Message::tool_result_with_call_id(
                                    task_call_id,
                                    task_function_call_id,
                                    prepend_task_repair_notes(err, &repair_notes),
                                );
                                continue;
                            }
                        };
                    // Per-delegation tool grants (prompt `parent-granted-tools.md`):
                    // validate against the target's role invariants before the
                    // handoff. An invalid grant is rejected as this `task`
                    // call's result — the conversation stays with the parent.
                    if let Some(err) = grant_rejection(&self.cwd, &child_agent, &granted_tools) {
                        next_prompt = Message::tool_result_with_call_id(
                            task_call_id,
                            task_function_call_id,
                            prepend_task_repair_notes(err, &repair_notes),
                        );
                        continue;
                    }
                    let parent_agent = self.stack.last().unwrap().agent.name.clone();
                    let task_args_json = serde_json::to_string(&serde_json::json!({
                        "child_agent": &child_agent,
                        "model": model_selector_json(&model),
                        "remaining_depth": remaining_depth,
                        "todo_ids": &todo_ids,
                        "skill_seed": &skill_seed,
                        "interactive": true,
                    }))
                    .ok();
                    if let Err(e) = self.session.db.upsert_task_delegation_job(
                        self.session.id,
                        &task_call_id,
                        task_function_call_id.as_deref(),
                        &parent_agent,
                        task_args_json.as_deref(),
                        &[crate::db::task_delegations::DelegationChildInit {
                            label: "default",
                            child_agent: &child_agent,
                            model: model_selector_display(&model).as_deref(),
                            output_dir: None,
                            requested_cwd: None,
                            resolved_cwd: None,
                            todo_ids_json: None,
                        }],
                    ) {
                        tracing::warn!(error = %e, task_call_id, "persist interactive task delegation job failed");
                        next_prompt = Message::tool_result_with_call_id(
                            task_call_id,
                            task_function_call_id,
                            prepend_task_repair_notes(
                                DELEGATION_PAYLOAD_REFUSAL.to_string(),
                                &repair_notes,
                            ),
                        );
                        continue;
                    }
                    match self.persist_delegation_payload(
                        &task_call_id,
                        task_function_call_id.as_deref(),
                        &parent_agent,
                        "default",
                        &child_agent,
                        &brief,
                    ) {
                        Ok(loaded) => brief = loaded,
                        Err(e) => {
                            tracing::warn!(error = %e, task_call_id, "persist interactive task delegation payload failed");
                            next_prompt = Message::tool_result_with_call_id(
                                task_call_id,
                                task_function_call_id,
                                prepend_task_repair_notes(
                                    DELEGATION_PAYLOAD_REFUSAL.to_string(),
                                    &repair_notes,
                                ),
                            );
                            continue;
                        }
                    }
                    let (mut delegation_payload_history, brief) = match self
                        .delegation_payload_delivery(&task_call_id, "default", &brief, true)
                    {
                        Ok(delivery) => delivery,
                        Err(e) => {
                            tracing::warn!(error = %e, task_call_id, "interactive task delegation payload delivery failed");
                            next_prompt = Message::tool_result_with_call_id(
                                task_call_id,
                                task_function_call_id,
                                prepend_task_repair_notes(
                                    DELEGATION_PAYLOAD_REFUSAL.to_string(),
                                    &repair_notes,
                                ),
                            );
                            continue;
                        }
                    };
                    let child = match self.load_interactive_child_or_tool_error(
                        InteractiveChildLoadRequest {
                            child_agent: &child_agent,
                            granted_tools,
                            model,
                            child_recursion,
                            task_call_id: &task_call_id,
                            task_function_call_id: task_function_call_id.clone(),
                            repair_notes: &repair_notes,
                        },
                    ) {
                        Ok(child) => child,
                        Err(message) => {
                            next_prompt = *message;
                            continue;
                        }
                    };

                    // Snapshot the outgoing primary's locks before the
                    // child takes over. If the parent ever resumes (the
                    // child pops via TurnOutcome::Done above), the
                    // matching-hash files can come back without a re-
                    // readlock round-trip.
                    if let Some(parent) = self.stack.last()
                        && let Err(e) = self
                            .locks
                            .suspend_agent(&parent.agent.name, self.session.id)
                    {
                        tracing::warn!(error = ?e, agent = %parent.agent.name, "suspend_agent on push failed");
                    }
                    // Begin compact-after-delegation tracking for the
                    // parent frame about to be paused below the interactive
                    // child (implementation note). Keyed
                    // by the parent's depth (its index, = pre-push height
                    // minus one). Captured here so elapsed-since-delegation
                    // measures from the parent's last inference — the turn
                    // that emitted this `task` call — not the session-global
                    // send timer the child resets every turn (the trap).
                    let parent_depth = self.stack.len() - 1;
                    let parent_full = self
                        .stack
                        .last()
                        .expect("stack never empty")
                        .history
                        .clone();
                    let (tracker, handle) = self.begin_delegation_shrink(parent_full);
                    self.deleg_shrinks
                        .insert(parent_depth, PendingDelegationShrink { tracker, handle });
                    // Caller→child read-only pre-seeds (`task.seed`,
                    // implementation note): re-execute each
                    // in the CHILD's cwd against the child's own toolbox and
                    // prepend the native tool-call/result pairs to its initial
                    // history, so the child starts grounded before its first
                    // turn. Budget-capped (whole entries dropped past the cap);
                    // a dropped-seed note is appended to the brief so the child
                    // knows context was trimmed.
                    let (seed_prefix, seeds_truncated) = self
                        .prefill_child_seeds(&prefill_seeds, &child, &self.cwd, Some(tx))
                        .await;
                    let mut seed_prefix = seed_prefix;
                    if !seed_prefix.is_empty() {
                        delegation_payload_history.append(&mut seed_prefix);
                    }
                    self.stack.push(AgentSession {
                        queue_target: crate::engine::message::QueueTarget::child(
                            child.name.clone(),
                            self.stack.len(),
                            task_call_id.clone(),
                            "default",
                        ),
                        agent: Arc::new(child),
                        history: delegation_payload_history,
                        answering: Some(PendingTaskCall {
                            call_id: task_call_id.clone(),
                            function_call_id: task_function_call_id,
                            repair_notes,
                        }),
                        deferred_log: crate::engine::deferred::DeferredLog::new(),
                    });
                    let _ = tx
                        .send(TurnEvent::ForegroundInputTarget {
                            target: self.active_queue_target(),
                        })
                        .await;
                    let brief = if seeds_truncated {
                        format!("{brief}{SEED_PREFILL_TRUNCATION_NOTE}")
                    } else {
                        brief
                    };
                    let brief = self.assign_todos_to_task(
                        brief,
                        &todo_ids,
                        &task_call_id,
                        "default",
                        &child_agent,
                    );
                    // Parent→child skill seeding (`task.skill_seed`,
                    // implementation note): validate the
                    // requested skill names against this primary's active-skill
                    // set and prepend the seeded instructions + framing (or a
                    // model-visible strip note) to the child's brief. Woven into
                    // the brief only — scoped to this child's run, never folded
                    // into the parent's active-skill set or the root history.
                    let skill_block = self.seed_skills_block(&skill_seed, &child_agent);
                    let brief = if skill_block.is_empty() {
                        brief
                    } else {
                        format!("{skill_block}{brief}")
                    };
                    next_prompt = Message::user(brief);
                    continue;
                }
                TurnOutcome::SpawnNoninteractive {
                    child_agent,
                    prompt: brief,
                    model,
                    remaining_depth,
                    why,
                    resume_handle,
                    cwd,
                    granted_tools,
                    seeds: prefill_seeds,
                    todo_ids,
                    skill_seed,
                    repair_notes,
                    task_call_id,
                    task_function_call_id,
                } => {
                    let child_recursion =
                        match self.resolve_task_recursion(&child_agent, remaining_depth, &model) {
                            Ok(ctx) => ctx,
                            Err(err) => {
                                next_prompt = Message::tool_result_with_call_id(
                                    task_call_id,
                                    task_function_call_id,
                                    prepend_task_repair_notes(err, &repair_notes),
                                );
                                continue;
                            }
                        };
                    let child_cwd = match self.resolve_child_cwd(cwd.as_deref()) {
                        Ok(child_cwd) => child_cwd,
                        Err(err) => {
                            next_prompt = Message::tool_result_with_call_id(
                                task_call_id,
                                task_function_call_id,
                                prepend_task_repair_notes(err, &repair_notes),
                            );
                            continue;
                        }
                    };
                    next_prompt = self
                        .run_single_noninteractive_task_backgroundable(
                            SingleNoninteractiveTask {
                                child_agent,
                                brief,
                                model,
                                remaining_depth,
                                why,
                                resume_handle,
                                child_cwd,
                                granted_tools,
                                prefill_seeds,
                                todo_ids,
                                skill_seed,
                                child_recursion,
                                repair_notes,
                                task_call_id,
                                task_function_call_id,
                            },
                            input_rx,
                            tx,
                            cancel.clone(),
                        )
                        .await?;
                    continue;
                }
                TurnOutcome::SpawnNoninteractiveBatch {
                    entries,
                    why,
                    repair_notes,
                    task_call_id,
                    task_function_call_id,
                } => {
                    let mut child_cwds = Vec::with_capacity(entries.len());
                    let mut cwd_error = None;
                    for entry in &entries {
                        match self.resolve_child_cwd(entry.cwd.as_deref()) {
                            Ok(child_cwd) => child_cwds.push(child_cwd),
                            Err(err) => {
                                cwd_error = Some(format!(
                                    "Error: batch entry `{}` has invalid cwd. {err}",
                                    entry.label
                                ));
                                break;
                            }
                        }
                    }
                    if let Some(err) = cwd_error {
                        next_prompt = Message::tool_result_with_call_id(
                            task_call_id,
                            task_function_call_id,
                            prepend_task_repair_notes(err, &repair_notes),
                        );
                        continue;
                    }
                    next_prompt = self
                        .run_batch_noninteractive_task_backgroundable(
                            BatchNoninteractiveTask {
                                entries,
                                child_cwds,
                                why,
                                repair_notes,
                                task_call_id,
                                task_function_call_id,
                            },
                            input_rx,
                            tx,
                            cancel.clone(),
                        )
                        .await?;
                    continue;
                }
                TurnOutcome::TaskControl {
                    action,
                    target_task_call_id,
                    label,
                    message,
                    task_call_id,
                    task_function_call_id,
                } => {
                    let body =
                        self.dispatch_task_control(action, target_task_call_id, label, message);
                    next_prompt = Message::tool_result_with_call_id(
                        task_call_id,
                        task_function_call_id,
                        body,
                    );
                    continue;
                }
                TurnOutcome::ToolResult {
                    task_call_id,
                    task_function_call_id,
                    body,
                } => {
                    next_prompt = Message::tool_result_with_call_id(
                        task_call_id,
                        task_function_call_id,
                        body,
                    );
                    continue;
                }
                TurnOutcome::Spawn {
                    prompt,
                    output_dir,
                    model,
                    task_call_id,
                    task_function_call_id,
                } => {
                    // Recursive `Swarm` fan-out (GOALS §24). The foreground
                    // `Swarm` agent (root, depth 0) asked to delegate to a
                    // child `Swarm`. Enforce the depth ceiling here (clamp,
                    // don't crash), then route the spawn to the single async-job
                    // authority, which owns the queue + the global concurrency
                    // cap and schedules the parallel background child. The
                    // pointer (scheduled / queued / refused) comes back as this
                    // `spawn` call's tool result. The dedicated
                    // `output_dir` is the contention-avoidance mechanism: each
                    // child writes only there, so disjoint scopes coexist and
                    // the lock manager still serializes any same-path write.
                    let agent_name = self.stack.last().unwrap().agent.name.clone();
                    let _ = tx
                        .send(TurnEvent::ToolStart {
                            agent: agent_name.clone(),
                            call_id: task_call_id.clone(),
                            tool: "spawn".to_string(),
                            args: serde_json::json!({ "output_dir": output_dir }),
                        })
                        .await;
                    let parent_depth = self.foreground_swarm_depth();
                    let output = match spawn_gate(parent_depth, self.swarm_max_depth, &output_dir) {
                        Err(refusal) => refusal,
                        Ok(child_depth) => {
                            let worker = match agent_name.as_str() {
                                "Multireview" | "scout" => {
                                    crate::engine::schedule::authority::SpawnWorkerKind::Scout
                                }
                                _ => crate::engine::schedule::authority::SpawnWorkerKind::Bee,
                            };
                            self.schedule.spawn_swarm(
                                crate::engine::schedule::authority::SpawnSpec {
                                    worker,
                                    prompt,
                                    output_dir,
                                    model,
                                    depth: child_depth,
                                    max_depth: self.swarm_max_depth,
                                },
                            )
                        }
                    };
                    let _ = tx
                        .send(TurnEvent::ToolEnd {
                            agent: agent_name,
                            call_id: task_call_id.clone(),
                            tool: "spawn".to_string(),
                            output: output.clone(),
                            truncated: false,
                            // The hint layer is `bash`-only.
                            hint: None,
                        })
                        .await;
                    next_prompt = Message::tool_result_with_call_id(
                        task_call_id,
                        task_function_call_id,
                        output,
                    );
                    if let Some(parent) = self.stack.last_mut() {
                        crate::engine::delegation_prompt_prune::prune_completed_delegation_prompts_with_upcoming(
                            &mut parent.history,
                            Some(&next_prompt),
                        );
                    }
                    continue;
                }
                TurnOutcome::ScheduleAction {
                    original_args,
                    args,
                    recovery,
                    task_call_id,
                    task_function_call_id,
                } => {
                    // The single async-job authority lives on the driver
                    // (GOALS §22). Dispatch the action, emit one
                    // ToolStart/End pair so the user sees a single row,
                    // and deliver the result as this `schedule` call’s
                    // tool_result.
                    let active_agent = &self.stack.last().unwrap().agent;
                    let agent_name = active_agent.name.clone();
                    let llm_mode = active_agent.llm_mode;
                    let _ = tx
                        .send(TurnEvent::ToolStart {
                            agent: agent_name.clone(),
                            call_id: task_call_id.clone(),
                            tool: "schedule".to_string(),
                            args: args.clone(),
                        })
                        .await;
                    let start = std::time::Instant::now();
                    // Per-action validate→repair→parse (§12). The §14
                    // wire-vs-user split records the repaired sub-args as
                    // `wire_input` and the sub-arg repair as the row's
                    // recovery when the outer `{action,args}` repair was
                    // clean (single-Recovery invariant — the outer repair
                    // only flags a malformed `action`; the per-action repair
                    // is the substantive correction). On a hard dispatch
                    // failure (capacity, or args still invalid after repair)
                    // we keep the outer `args` + recovery and surface the
                    // error.
                    let (mut output, hard_fail, kind, wire_input, recovery) =
                        match self.dispatch_schedule_action_repaired(&args).await {
                            Ok(dispatch) => {
                                let ScheduleDispatch {
                                    output,
                                    recovery: sub_recovery,
                                    wire_args,
                                } = dispatch;
                                let recorded =
                                    if matches!(recovery, crate::engine::repair::Recovery::Clean) {
                                        sub_recovery
                                    } else {
                                        recovery
                                    };
                                (output, false, None, wire_args, recorded)
                            }
                            Err(e) => (
                                format!("Error: {e}"),
                                true,
                                Some(crate::engine::tool::classify_failure(&e)),
                                args.clone(),
                                recovery,
                            ),
                        };
                    // Cache-safe capability growth (GOALS §22): the first
                    // time a loop or background exists, append a hint to
                    // this tool result announcing the now-available
                    // branches. Appended text extends the prefix; the
                    // byte-stable tools array never changes.
                    if !hard_fail {
                        for hint in self.pending_capability_hints() {
                            output.push('\n');
                            output.push_str(hint);
                        }
                    }
                    if hard_fail {
                        let _ = tx
                            .send(TurnEvent::ToolError {
                                agent: agent_name.clone(),
                                call_id: task_call_id.clone(),
                                tool: "schedule".to_string(),
                                error: output.clone(),
                                kind: kind.unwrap_or(crate::engine::tool::ToolFailKind::Execution),
                            })
                            .await;
                    } else {
                        let _ = tx
                            .send(TurnEvent::ToolEnd {
                                agent: agent_name.clone(),
                                call_id: task_call_id.clone(),
                                tool: "schedule".to_string(),
                                output: output.clone(),
                                truncated: false,
                                // The hint layer is `bash`-only.
                                hint: None,
                            })
                            .await;
                    }
                    self.record_schedule_tool_call(ScheduleToolCallRecord {
                        agent: agent_name.clone(),
                        llm_mode,
                        call_id: task_call_id.clone(),
                        original_input_json: original_args,
                        wire_input_json: wire_input,
                        recovery,
                        hard_fail,
                        output: output.clone(),
                        duration_ms: start.elapsed().as_millis() as u64,
                    });
                    next_prompt = Message::tool_result_with_call_id(
                        task_call_id,
                        task_function_call_id,
                        output,
                    );
                    continue;
                }
                TurnOutcome::Handoff {
                    target,
                    task_call_id,
                    task_function_call_id,
                } => {
                    // The `Auto` front door hands the conversation to a
                    // primary agent. The shared application path confirms the
                    // call as `handoff`'s tool_result, persists the new active
                    // agent, and swaps the root-frame primary in place; the
                    // delivered tool_result then drives the swapped-in
                    // primary's next turn — `Auto` is no longer in the loop.
                    next_prompt = self
                        .apply_handoff(&target, task_call_id, task_function_call_id, tx)
                        .await;
                    continue;
                }
            }
        }
    }

    /// Return any capability-hint strings that should be appended now: the
    /// first time a loop exists, announce `loop.cancel`; the first time a
    /// background exists, announce `background.tail`/`background.cancel`.
    /// Each hint fires at most once per session (tracked in
    /// `appended_hints`).
    fn pending_capability_hints(&mut self) -> Vec<&'static str> {
        let mut hints = Vec::new();
        if self.schedule.has_loop() && self.appended_hints.insert("loop") {
            hints.push(
                "(schedule: loop.cancel is now available — args {\"job_id\": <id>} — to end a live loop)",
            );
        }
        if self.schedule.has_background() && self.appended_hints.insert("background") {
            hints.push(
                "(schedule: background.tail and background.cancel are now available — args {\"job_id\": <id>})",
            );
        }
        hints
    }

    /// Build [`SpawnArgs`] for a child agent. `interactive` distinguishes
    /// a user-facing handoff (an interactive subagent — e.g. `builder`,
    /// which gets the cross-session recall tools) from a one-shot leaf
    /// delegation run via [`run_noninteractive`] (explore / docs, which
    /// do not). This is the spawn-time analog of the runtime
    /// interactive-mode gate.
    fn load_interactive_child_or_tool_error(
        &self,
        req: InteractiveChildLoadRequest<'_>,
    ) -> std::result::Result<Agent, Box<Message>> {
        match crate::engine::builtin::load(
            req.child_agent,
            &self.spawn_args_delegated(true, req.granted_tools, req.model, req.child_recursion),
        ) {
            Ok(child) => Ok(child),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    child_agent = %req.child_agent,
                    task_call_id = req.task_call_id,
                    "interactive child load failed"
                );
                Err(Box::new(Message::tool_result_with_call_id(
                    req.task_call_id.to_string(),
                    req.task_function_call_id,
                    prepend_task_repair_notes(
                        format!(
                            "Error: failed to load subagent `{}`: {e:#}",
                            req.child_agent
                        ),
                        req.repair_notes,
                    ),
                )))
            }
        }
    }

    fn spawn_args(&self, interactive: bool) -> crate::engine::builtin::SpawnArgs {
        crate::engine::builtin::SpawnArgs {
            model: self.stack[0].agent.model.clone(),
            params: self.stack[0].agent.params.clone(),
            env_overlay: self.stack[0].agent.env_overlay.clone(),
            cwd: self.cwd.clone(),
            session_short_id: self.session.short_id.clone(),
            model_system_prompt_snapshot: self.session.model_system_prompt_snapshot(),
            interactive,
            // The active LLM mode rides on the root agent; child spawns
            // inherit it so the whole invocation tree renders one mode.
            llm_mode: self.stack[0].agent.llm_mode,
            // A plan-level model override propagates to the whole delegation
            // tree so every spawned agent runs under it.
            model_override: self.model_override.clone(),
            delegation_model: None,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            // The foreground frame's recursive-`Swarm` depth (GOALS §24).
            // Background `Swarm` children are spawned off-stack with an
            // explicit advanced depth (see `dispatch_spawn`); on-stack
            // frames inherit the root primary's depth (0) — `/swarm` swaps
            // the root in place, never deeper.
            swarm_depth: self.foreground_swarm_depth(),
            swarm_max_depth: self.swarm_max_depth,
            // No per-delegation grants by default. A `task` delegation that
            // carries grants overrides this via [`Self::spawn_args_granted`].
            granted_tools: Vec::new(),
        }
    }

    fn spawn_args_delegated(
        &self,
        interactive: bool,
        grant: Vec<String>,
        model: Option<crate::engine::model_roles::DelegationModelSelector>,
        recursion: crate::engine::builtin::DelegationRecursionContext,
    ) -> crate::engine::builtin::SpawnArgs {
        let model_override = if recursion.same_model_only {
            self.stack.last().map(|frame| frame.agent.model.clone())
        } else {
            self.model_override.clone()
        };
        crate::engine::builtin::SpawnArgs {
            granted_tools: grant,
            delegation_model: model,
            delegated: true,
            delegation_recursion: recursion,
            model_override,
            ..self.spawn_args(interactive)
        }
    }

    fn spawn_args_delegated_in_cwd(
        &self,
        child_cwd: &std::path::Path,
        interactive: bool,
        grant: Vec<String>,
        model: Option<crate::engine::model_roles::DelegationModelSelector>,
        recursion: crate::engine::builtin::DelegationRecursionContext,
    ) -> crate::engine::builtin::SpawnArgs {
        let model_override = if recursion.same_model_only {
            self.stack.last().map(|frame| frame.agent.model.clone())
        } else {
            self.model_override.clone()
        };
        crate::engine::builtin::SpawnArgs {
            granted_tools: grant,
            delegation_model: model,
            delegated: true,
            delegation_recursion: recursion,
            model_override,
            cwd: child_cwd.to_path_buf(),
            ..self.spawn_args(interactive)
        }
    }

    fn resolve_task_recursion(
        &self,
        child_agent: &str,
        requested_depth: Option<u32>,
        model: &Option<crate::engine::model_roles::DelegationModelSelector>,
    ) -> Result<crate::engine::builtin::DelegationRecursionContext, String> {
        let parent = self.stack.last().expect("stack never empty").agent.as_ref();
        let cfg = crate::config::extended::load_for_cwd(&self.cwd).delegation;
        let root_parent_ctx = if parent.delegated {
            None
        } else {
            Some(apply_root_recursion_override(
                crate::engine::builtin::configured_recursion_context(&cfg, &parent.name, None),
                self.delegation_recursion_override,
            ))
        };
        let requested_depth = match requested_depth {
            Some(depth) => depth,
            None if !parent.delegated => root_parent_ctx
                .as_ref()
                .map(|ctx| ctx.remaining_depth)
                .unwrap_or(0),
            None => 0,
        };

        if child_agent == "deepthink" && requested_depth > 0 {
            return Err(
                "Error: `deepthink` is a tool-free leaf and cannot receive recursive depth"
                    .to_string(),
            );
        }

        if parent.delegated {
            let parent_ctx = &parent.delegation_recursion;
            if !parent_ctx.enabled {
                return Err("Error: subagent recursion is disabled by configuration".to_string());
            }
            if !parent_ctx.can_delegate_to(child_agent) {
                return Err(format!(
                    "Error: `{}` is not allowed to recursively delegate to `{child_agent}` or has no remaining recursion depth",
                    parent.name
                ));
            }
            if parent_ctx.same_model_only && model.is_some() {
                return Err(format!(
                    "Error: `{}` recursive delegation must omit `model`; the child uses the same resolved model",
                    parent.name
                ));
            }
            let max_child_depth = parent_ctx.remaining_depth.saturating_sub(1);
            if requested_depth > max_child_depth {
                return Err(format!(
                    "Error: requested remaining_depth {requested_depth} exceeds `{}`'s remaining recursive budget {max_child_depth}",
                    parent.name
                ));
            }
        } else if requested_depth > 0 {
            let parent_ctx = root_parent_ctx
                .as_ref()
                .expect("root recursion context exists for non-delegated parent");
            if !parent_ctx.enabled {
                return Err("Error: subagent recursion is disabled by configuration".to_string());
            }
            if !parent_ctx
                .allowed_targets
                .iter()
                .any(|target| target == child_agent)
            {
                return Err(format!(
                    "Error: `{}` may not grant recursive depth to `{child_agent}`",
                    parent.name
                ));
            }
            if requested_depth > parent_ctx.remaining_depth {
                return Err(format!(
                    "Error: requested remaining_depth {requested_depth} exceeds `{}`'s configured recursive budget {}",
                    parent.name, parent_ctx.remaining_depth
                ));
            }
        }

        if (parent.delegated || requested_depth > 0)
            && (child_agent == "explore" || child_agent == "docs")
        {
            let enabled = if parent.delegated {
                cfg.recursion_enabled
            } else {
                root_parent_ctx
                    .as_ref()
                    .map(|ctx| ctx.enabled)
                    .unwrap_or(cfg.recursion_enabled)
            };
            return Ok(crate::engine::builtin::DelegationRecursionContext {
                enabled,
                remaining_depth: requested_depth.min(1),
                allowed_targets: vec!["explore".to_string()],
                same_model_only: true,
            });
        }

        if requested_depth == 0 {
            return Ok(crate::engine::builtin::DelegationRecursionContext {
                enabled: cfg.recursion_enabled,
                remaining_depth: 0,
                allowed_targets: Vec::new(),
                same_model_only: false,
            });
        }

        if let Some(policy) = recursion_policy(&cfg, child_agent)
            && let Some(max_depth) = policy.max_depth
            && requested_depth > max_depth
        {
            return Err(format!(
                "Error: requested remaining_depth {requested_depth} exceeds `{child_agent}` maxDepth {max_depth}"
            ));
        }

        let mut ctx = crate::engine::builtin::configured_recursion_context(
            &cfg,
            child_agent,
            Some(requested_depth),
        );
        if let Some(root_ctx) = root_parent_ctx.as_ref() {
            ctx.enabled = root_ctx.enabled;
        }
        Ok(ctx)
    }

    fn resolve_child_cwd(&self, requested: Option<&str>) -> Result<ChildCwd, String> {
        let root = self.cwd.canonicalize().map_err(|e| {
            format!(
                "Error: could not resolve session cwd `{}`: {e}",
                self.cwd.display()
            )
        })?;
        let Some(raw) = requested.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(ChildCwd {
                requested: None,
                resolved: root,
            });
        };
        let requested_path = std::path::Path::new(raw);
        let candidate = if requested_path.is_absolute() {
            requested_path.to_path_buf()
        } else {
            self.cwd.join(requested_path)
        };
        let resolved = candidate
            .canonicalize()
            .map_err(|_| format!("Error: cwd `{raw}` does not exist or is not a directory"))?;
        if !resolved.is_dir() {
            return Err(format!(
                "Error: cwd `{raw}` does not exist or is not a directory"
            ));
        }
        if !resolved.starts_with(&root) {
            return Err(format!(
                "Error: cwd `{raw}` resolves outside trusted workspace `{}`",
                root.display()
            ));
        }
        Ok(ChildCwd {
            requested: Some(raw.to_string()),
            resolved,
        })
    }

    /// The recursive-`Swarm` depth of the current foreground frame (GOALS
    /// §24). On-stack frames are reached by `/swarm` swap or interactive
    /// handoff, neither of which advances a Swarm edge, so they are depth 0.
    /// Background `Swarm` children (the recursion) carry their own advanced
    /// depth in the `SpawnArgs` the job machinery builds directly.
    fn foreground_swarm_depth(&self) -> u32 {
        0
    }
}

/// Drain queued user submissions from the channel without blocking.
/// Stops at the [`MAX_FOLD`] batch cap; anything beyond stays queued.
async fn drain_queue(
    rx: &crate::engine::message::UserSubmissionQueue,
    into: &mut Vec<UserSubmission>,
    target_id: &str,
) {
    drain_queue_limit(rx, into, target_id, MAX_FOLD).await;
}

async fn drain_queue_limit(
    rx: &crate::engine::message::UserSubmissionQueue,
    into: &mut Vec<UserSubmission>,
    target_id: &str,
    max: usize,
) {
    rx.drain_into_for(into, max, Some(target_id)).await;
}

/// Discard *all* currently-queued user submissions from the channel
/// (no [`MAX_FOLD`] cap, unlike [`drain_queue`]) and report how many were
/// dropped. Used on the ctrl+c cancel-unwind so messages the user queued
/// during the cancelled span never auto-start a fresh turn — the cancel
/// returns the session to idle rather than silently rolling into the next
/// queued message. Non-blocking: only what is already buffered is dropped.
async fn discard_pending_input(rx: &crate::engine::message::UserSubmissionQueue) -> usize {
    let dropped = rx.discard_pending().await;
    if dropped > 0 {
        tracing::info!(dropped, "discarded queued user messages on cancel");
    }
    dropped
}

/// Header line for a late-arriving async-result delivery
/// (implementation note). Names both the job `kind`
/// (`loop`/`timer`/`background`/`swarm`) and the originating `job_id` (the
/// same `job-…` string `loop.cancel` / `TurnEvent::ScheduleCompleted` use) so the
/// model has an unambiguous referent for a delivery that may land turns away
/// from its trigger. Identical across every job kind.
fn async_result_header(kind: &str, job_id: &str) -> String {
    format!("[async result · {kind} · {job_id}]")
}

/// Build the `data` object for a recorded `user_message` timeline event.
/// Always carries `text`; an async-result delivery additionally stamps an
/// optional `job_id` (implementation note) attributing it to
/// its originating job. Additive to the existing `data` shape — no exporter
/// schema bump; ordinary input omits the key entirely.
fn user_message_event_data(
    text: &str,
    job_id: Option<&str>,
    queue_item_ids: &[uuid::Uuid],
    queue_target: Option<&crate::engine::message::QueueTarget>,
    preflight_cleaned: Option<&str>,
) -> serde_json::Value {
    let mut data = serde_json::json!({ "text": text });
    if let Some(jid) = job_id {
        data["job_id"] = serde_json::Value::String(jid.to_string());
    }
    if !queue_item_ids.is_empty() {
        data["queued"] = serde_json::Value::Bool(true);
        data["queue_item_ids"] = serde_json::json!(queue_item_ids);
        if let Some(target) = queue_target {
            data["queue_target"] = serde_json::json!(target);
        }
        data["preflight_cleaned"] = preflight_cleaned
            .map(|text| serde_json::Value::String(text.to_string()))
            .unwrap_or(serde_json::Value::Null);
    }
    data
}

enum FoldedSubmission {
    User(Box<UserSubmission>),
    Compact(Vec<uuid::Uuid>),
}

fn fold_submission_commands(submissions: Vec<UserSubmission>) -> Vec<FoldedSubmission> {
    submissions
        .into_iter()
        .map(|submission| match submission.kind {
            UserSubmissionKind::User => FoldedSubmission::User(Box::new(submission)),
            UserSubmissionKind::Compact => FoldedSubmission::Compact(submission.queue_item_ids),
        })
        .collect()
}

/// How many consecutive auto-prunes must each save below
/// [`PRUNE_INEFFECTIVE_SAVING_PCT`] of the window — while ctx% climbs across
/// them — before the next boundary escalates to compaction. Three keeps a
/// single dense-read spike from over-triggering while still catching the
/// "two small prunes never escalated on a 145k climb" failure the spec cites.
const PRUNE_INEFFECTIVE_RUN: usize = 3;

/// The per-prune saving (as a % of the model window) at or below which an
/// auto-prune counts as *ineffective* for the escalation policy. A prune that
/// reclaims under ~2% of the window is not keeping context in budget.
const PRUNE_INEFFECTIVE_SAVING_PCT: f64 = 2.0;

/// Minimum projected wire-token saving for cache-cold auto-prune. This matches
/// the settled pruning floor from `subagent-delegation-prompt-pruning.md`: a
/// smaller automatic prune is maintenance churn, not useful context recovery.
const AUTO_PRUNE_MIN_COLD_SAVINGS_TOKENS: usize = 96;

const AUTO_PRUNE_TRIGGER_CACHE_ALREADY_COLD: &str = "cache_already_cold";
const AUTO_PRUNE_TRIGGER_NO_CACHE_PROVIDER: &str = "no_cache_provider";
const AUTO_PRUNE_TRIGGER_UPSTREAM_CACHE_BUST: &str = "upstream_cache_bust";
const AUTO_PRUNE_TRIGGER_WARM_THRESHOLD: &str = "warm_threshold";
fn is_continue_command(text: &str) -> bool {
    matches!(text.trim().to_ascii_lowercase().as_str(), "continue")
}

/// Turn cap for the explore subagent's noninteractive loop. Real
/// exploration work needs headroom; 64 turns bounds runaway loops
/// without cutting legitimate work short.
pub(crate) const EXPLORE_MAX_TURNS: usize = 64;

/// Token cap on the seeded read-only results a re-queryable subagent injects
/// into its caller's transcript (GOALS §3c). Seeds are real injected context,
/// so they ride the standard subagent-report budget (§10) — the same default
/// cap as an async job's injected result ([`crate::engine::schedule::ASYNC_RESULT_TOKEN_CAP`]).
/// Enforced via [`crate::intel::budget::BudgetedWriter`]: whole seeds are
/// dropped once the cap is reached, deterministically, with a truncation note.
const SEED_INJECTION_TOKEN_CAP: usize = crate::engine::schedule::ASYNC_RESULT_TOKEN_CAP;

/// Model-visible note appended to a child's brief when one or more
/// caller→child pre-seeds (`task.seed`,
/// implementation note) were dropped to stay within the
/// seed budget — so the child knows its pre-loaded context was trimmed and can
/// re-gather what it needs.
const SEED_PREFILL_TRUNCATION_NOTE: &str = "\n\n[note: some pre-seeded read-only context was omitted to stay within the context budget; re-read anything you need]";

/// Gate a `spawn` request (GOALS §24): enforce the dedicated-output
/// requirement and the hard depth ceiling (clamp, don't crash). Returns
/// `Ok(child_depth)` (= `parent_depth + 1`) when the spawn is admissible, or
/// `Err(refusal_text)` — the tool result telling the model to do the slice's
/// work itself as a leaf — when `output_dir` is missing or the child would
/// exceed the ceiling. Pure so the gate is unit-testable without a driver.
fn spawn_gate(
    parent_depth: u32,
    max_depth: u32,
    output_dir: &str,
) -> std::result::Result<u32, String> {
    if output_dir.trim().is_empty() {
        return Err(
            "refused: `output_dir` is required so concurrent branches don't collide on a file \
             — give this child a dedicated folder/DB path and retry."
                .to_string(),
        );
    }
    let child_depth = parent_depth + 1;
    if child_depth > max_depth {
        return Err(format!(
            "refused: depth ceiling {max_depth} reached (you are at depth {parent_depth}). Do \
             this slice's work yourself as a leaf instead of delegating."
        ));
    }
    Ok(child_depth)
}

/// Compose a noninteractive subagent's brief, injecting the caller's `why`
/// (motivation, GOALS §3c) as a terse leading line so the subagent can tailor
/// what it surfaces/seeds. An empty `why` adds nothing (token economy).
/// True when `msg` is one half of a tracked skill pair — an assistant
/// message whose sole content is a `skill` ToolCall in `ids`, or its matching
/// user tool_result. Used by [`Driver::strip_abandoned_skill_pairs`] to drop
/// both halves of an abandoned skill pair together (the seam pushes each pair
/// as a standalone assistant turn + its result, so this never strips an
/// unrelated message). Assistant turns carrying anything beyond the tracked
/// skill call are left intact — the call/result wouldn't be cleanly removable
/// without breaking pairing.
fn message_references_call_id(msg: &Message, ids: &std::collections::HashSet<String>) -> bool {
    use crate::engine::message::AssistantContent;
    use rig::message::UserContent;
    match msg {
        Message::Assistant { content, .. } => {
            let calls: Vec<&str> = content
                .iter()
                .filter_map(|c| match c {
                    AssistantContent::ToolCall(tc) => Some(tc.id.as_str()),
                    _ => None,
                })
                .collect();
            // Strip only when the turn is exactly the tracked skill call and
            // nothing else (the seam pushes it as a standalone assistant turn).
            content.iter().count() == 1
                && calls.iter().all(|id| ids.contains(*id))
                && !calls.is_empty()
        }
        Message::User { content } => content.iter().any(|c| match c {
            UserContent::ToolResult(tr) => ids.contains(&tr.id),
            _ => false,
        }),
        _ => false,
    }
}

fn skill_pair_call_ids_in_history(history: &[Message]) -> std::collections::HashSet<String> {
    use crate::engine::message::AssistantContent;
    use rig::message::UserContent;

    let mut skill_calls = std::collections::HashSet::new();
    let mut skill_results = std::collections::HashSet::new();
    for msg in history {
        match msg {
            Message::Assistant { content, .. } => {
                for part in content.iter() {
                    if let AssistantContent::ToolCall(tc) = part
                        && tc.id.starts_with("skillslash-")
                        && tc.function.name == "skill"
                    {
                        skill_calls.insert(tc.id.clone());
                    }
                }
            }
            Message::User { content } => {
                for part in content.iter() {
                    if let UserContent::ToolResult(tr) = part
                        && tr.id.starts_with("skillslash-")
                    {
                        skill_results.insert(tr.id.clone());
                    }
                }
            }
            _ => {}
        }
    }
    skill_calls.intersection(&skill_results).cloned().collect()
}

/// Opening of the cross-agent tool-call attribution note
/// (implementation note). Doubles as the idempotency
/// sentinel: a `tool_result` whose first text part already opens with this was
/// annotated on an earlier message and is left untouched, so re-evaluation on a
/// later send never double-stamps and a re-swap never re-annotates.
const CROSS_AGENT_NOTE: &str = "[Called by `";

/// Return a copy of `tr` with `note` prepended to its first text content part
/// (the model-facing call outcome). Idempotent: if the first text part already
/// opens with [`CROSS_AGENT_NOTE`] the result is returned unchanged. When the
/// result carries no text part (e.g. an image-only result) a fresh leading text
/// part holding the note is inserted, so the attribution is never lost.
fn prepend_tool_result_note(tr: &rig::message::ToolResult, note: &str) -> rig::message::ToolResult {
    use crate::engine::message::OneOrMany;
    use rig::message::ToolResultContent;
    let mut parts: Vec<ToolResultContent> = tr.content.iter().cloned().collect();
    if let Some(idx) = parts
        .iter()
        .position(|p| matches!(p, ToolResultContent::Text(_)))
    {
        if let ToolResultContent::Text(t) = &parts[idx] {
            if t.text.starts_with(CROSS_AGENT_NOTE) {
                return tr.clone();
            }
            let merged = format!("{note}{}", t.text);
            parts[idx] = ToolResultContent::text(merged);
        }
    } else {
        parts.insert(0, ToolResultContent::text(note.to_string()));
    }
    rig::message::ToolResult {
        id: tr.id.clone(),
        call_id: tr.call_id.clone(),
        content: OneOrMany::many(parts).unwrap_or_else(|_| tr.content.clone()),
    }
}

fn compose_subagent_brief(brief: &str, why: &str) -> String {
    let why = why.trim();
    if why.is_empty() {
        return brief.to_string();
    }
    format!("[why the caller is asking: {why}]\n\n{brief}")
}

fn delegation_payload_reference_prompt(
    row: &crate::db::task_delegation_payloads::TaskDelegationPayloadRow,
) -> String {
    format!(
        "[delegation payload retrieved]\n\
         The exact delegation brief for task `{}` label `{}` was delivered in the immediately \
         preceding `delegation_payload_retrieve` tool result. Treat that retrieved text as the \
         complete task brief and follow it exactly. Payload hash: `{}`.",
        row.task_call_id, row.label, row.payload_hash
    )
}

fn delegation_payload_retrieval_history(
    row: &crate::db::task_delegation_payloads::TaskDelegationPayloadRow,
    body: &str,
) -> Vec<Message> {
    use crate::engine::message::{AssistantContent, OneOrMany, ToolCall};
    use rig::message::{ToolFunction, ToolResult, ToolResultContent, UserContent};

    let call_id = format!(
        "delegation-payload-{}-{}",
        row.label,
        &row.payload_hash[..12]
    );
    vec![
        Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
                id: call_id.clone(),
                call_id: None,
                function: ToolFunction {
                    name: "delegation_payload_retrieve".to_string(),
                    arguments: serde_json::json!({ "hash": row.payload_hash }),
                },
                signature: None,
                additional_params: None,
            })),
        },
        Message::User {
            content: OneOrMany::one(UserContent::ToolResult(ToolResult {
                id: call_id,
                call_id: None,
                content: OneOrMany::one(ToolResultContent::text(body.to_string())),
            })),
        },
    ]
}

fn extract_todo_delta(report: &str) -> Option<serde_json::Value> {
    let marker = "```todo_delta";
    let start = report.find(marker)?;
    let after = &report[start + marker.len()..];
    let after = after.strip_prefix(" json").unwrap_or(after);
    let after = after.strip_prefix('\n').unwrap_or(after);
    let end = after.find("```")?;
    serde_json::from_str(after[..end].trim()).ok()
}

/// Validate a per-delegation tool grant (prompt `parent-granted-tools.md`)
/// against the delegation target's role invariants. Returns `Some(error)` — a
/// clear tool-result string — when the grant is inadmissible, else `None` so
/// the spawn proceeds with the child's surface = base + grants for this run.
///
/// An empty grant is always admissible (the common no-grant case). The `docs`
/// pipeline is a fixed two-stage internal flow whose tool surface is not
/// parent-extensible, so a non-empty grant on it is refused outright. For every
/// other target the grant is checked against the **same** role invariants a
/// user-authored `tools:` grant is ([`crate::agents::invariants::validate_grant`]),
/// resolving the target's own name + mode so the single-writer / spawn-only /
/// primary-only rules are evaluated for that agent. A resolution failure
/// (unknown agent) is itself a clear error — the grant is never silently honored.
fn grant_rejection(cwd: &std::path::Path, child_agent: &str, grant: &[String]) -> Option<String> {
    if grant.is_empty() {
        return None;
    }
    if matches!(child_agent, "docs" | "docs-resolver" | "docs-answerer") {
        return Some(format!(
            "Error: cannot grant tools to `{child_agent}` — the docs pipeline is a fixed \
             internal flow and its tool surface is not extensible."
        ));
    }
    let (target_name, target_mode) = match crate::agents::resolve(cwd, child_agent) {
        Ok(Some(def)) => (def.name, def.mode),
        Ok(None) => {
            return Some(format!(
                "Error: cannot grant tools to unknown agent `{child_agent}`."
            ));
        }
        Err(e) => {
            return Some(format!(
                "Error: cannot grant tools to `{child_agent}`: {e:#}"
            ));
        }
    };
    match crate::agents::invariants::validate_grant(&target_name, target_mode, grant) {
        Ok(()) => None,
        Err(e) => Some(format!("Error: {e:#}")),
    }
}

/// Produce the shrunk version of a parent history for a delegation
/// (implementation note). `prune` is lossless + sync
/// (snapshot-dedup on a clone); `compact` reuses `compact.rs`'s brief
/// machinery to summarize the (pre-pruned) parent context into a single
/// dense message, with a prune-only fallback on model failure. Runs on the
/// background shrink task, off the parent's frame.
async fn run_shrink(
    strategy: crate::config::providers::ShrinkStrategy,
    parent_full: &[Message],
    agent: Arc<Agent>,
    cancel: tokio_util::sync::CancellationToken,
    compact_prompt: Option<String>,
) -> Vec<Message> {
    use crate::config::providers::ShrinkStrategy;
    use crate::engine::deleg_shrink;
    match strategy {
        ShrinkStrategy::Prune => deleg_shrink::prune_shrink(parent_full),
        ShrinkStrategy::Compact => {
            let drafter = deleg_shrink::ModelBriefDrafter {
                agent,
                cancel,
                compact_prompt,
            };
            deleg_shrink::compact_shrink(parent_full, &drafter).await
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct FailedTurnPromptSummary {
    text: String,
    truncated: bool,
    has_non_text_parts: bool,
}

fn prompt_summary(msg: &Message, max_chars: usize) -> FailedTurnPromptSummary {
    let (text, has_non_text_parts) = match msg {
        Message::User { content } => {
            let has_non_text_parts = content
                .iter()
                .any(|part| !matches!(part, rig::message::UserContent::Text(_)));
            (extract_user_text(content), has_non_text_parts)
        }
        Message::Assistant { content, .. } => (extract_text(content), true),
        Message::System { content } => (content.clone(), false),
    };
    let (text, truncated) = crate::text::cap_chars(&text, max_chars);
    FailedTurnPromptSummary {
        text,
        truncated,
        has_non_text_parts,
    }
}

fn redacted_bounded_snippet(
    detail: &str,
    redact: &RedactionTable,
    max_chars: usize,
) -> Option<String> {
    let trimmed = detail.trim();
    if trimmed.is_empty() {
        return None;
    }
    crate::text::bounded_snippet(&redact.scrub(trimmed), max_chars)
}

/// Resolve and build the backup-model fallback for `model`, loading the
/// providers config from the `cwd` config chain
/// (implementation note). The shared seam every turn-runner
/// (the driver loop, noninteractive subagents, the `docs` pipeline) uses so
/// the fallback mechanism is identical everywhere — subagents inherit it, never
/// a hard-coded model. `None` when no backup is configured, the config can't be
/// loaded, or the backup `(provider, model)` can't be built (each ⇒ no
/// fallback / hard-fail, never a crash).
pub(crate) fn resolve_backup_model_for(
    cwd: &std::path::Path,
    model: &crate::engine::model::Model,
) -> Option<Arc<crate::engine::model::Model>> {
    use crate::config::providers::ConfigDoc;
    let providers = ConfigDoc::load_effective(cwd);
    build_backup_model(&providers, model)
}

/// Resolve the per-`(provider, model)` backup against an already-loaded
/// providers config and build it, inheriting `model`'s shutdown gate. Split
/// from [`resolve_backup_model_for`] so the test-injected config path can reuse
/// it without touching disk.
pub(crate) fn build_backup_model(
    providers: &crate::config::providers::ProvidersConfig,
    model: &crate::engine::model::Model,
) -> Option<Arc<crate::engine::model::Model>> {
    let backup = providers.resolve_backup(model.provider_id(), model.model_id_ref())?;
    let built = crate::engine::model::Model::for_provider_trusted_only(
        providers,
        &backup.provider,
        &backup.model,
        // Start from the primary's session redaction table, then let the
        // backup target resolve its own trust policy.
        model.session_redact_table(),
        model.trusted_only_flag(),
    )
    .ok()?;
    let built = built.with_shutdown_gate(model.shutdown_gate());
    // Inherit the primary's wire-API self-heal target so the backup model also
    // pins a corrected endpoint (implementation note).
    let built = match model.config_path() {
        Some(path) => built.with_config_path(path.to_path_buf()),
        None => built,
    };
    Some(Arc::new(built))
}

/// Assemble a finished delegated subagent's report. Every delegated subagent
/// (`builder`/`explore` + custom) holds the structural `return`
/// tool and returns a **structured summary envelope**
/// (implementation note): the model-authored
/// fields (from a `return` call, or — on the fallback path — its final text
/// wrapped as `accomplished`) plus the host-derived `files_changed` ledger from
/// the child's own frame. The `docs` Q&A pipeline is exempt: it holds no
/// `return` tool, so it keeps returning its plain answer unchanged. The
/// subagent's deferred-log section (`plan.md §3d`) is appended either way.
///
/// `return_fields` is `Some` when the subagent finished via the `return` tool;
/// `None` is the no-return-tool fallback (priority #1: a delegation must still
/// yield a valid envelope, never fail).
fn assemble_subagent_report(
    agent: &Agent,
    history: &[Message],
    deferred_log: &crate::engine::deferred::DeferredLog,
    return_fields: Option<&serde_json::Value>,
) -> String {
    // Drain the deferred-log once on pop; nothing-deferred is the common path
    // and adds no framing (`plan.md §3d`).
    let deferred_section = if deferred_log.is_empty() {
        String::new()
    } else {
        crate::engine::deferred::format_section(&deferred_log.drain())
    };

    // The `docs` pipeline (and any hypothetical agent without `return`) keeps
    // the legacy plain report. Everything delegated holds `return`.
    if agent.tools.get("return").is_none() {
        return format!("{}{}", collect_final_text(history), deferred_section);
    }

    let envelope = match return_fields {
        Some(fields) => crate::engine::envelope::Envelope::from_return_args(fields),
        None => crate::engine::envelope::Envelope::from_final_text(collect_final_text(history)),
    }
    .with_files_changed(crate::engine::envelope::files_changed_from_history(history));

    format!("{}{}", envelope.render(), deferred_section)
}

fn partial_progress_from_history(history: &[Message]) -> DelegationPartialProgress {
    use rig::message::AssistantContent;
    use std::collections::BTreeSet;

    let outputs = partial_progress_tool_outputs(history);
    let mut files_read = BTreeSet::new();
    let mut files_edited = Vec::new();
    let mut commands = Vec::new();
    let mut last_action = None;

    for msg in history {
        let Message::Assistant { content, .. } = msg else {
            continue;
        };
        for part in content.iter() {
            let AssistantContent::ToolCall(tc) = part else {
                continue;
            };
            let tool = tc.function.name.as_str();
            match tool {
                "read" | "readlock" => {
                    if let Some(path) = crate::engine::compact::arg_path(&tc.function.arguments) {
                        files_read.insert(path.clone());
                        last_action = Some(format!("{} `{}`", tool, path));
                    } else {
                        last_action = Some(tool.to_string());
                    }
                }
                "write" | "writeunlock" | "edit" | "editunlock" | "unlock" => {
                    if let Some(path) = crate::engine::compact::arg_path(&tc.function.arguments) {
                        let hash = crate::engine::compact::arg_hash(&tc.function.arguments)
                            .or_else(|| {
                                outputs
                                    .get(&tc.id)
                                    .and_then(|out| crate::engine::compact::hash_from_output(out))
                            });
                        crate::engine::compact::record_edit(&mut files_edited, path.clone(), hash);
                        last_action = Some(format!("{} `{}`", tool, path));
                    } else {
                        last_action = Some(tool.to_string());
                    }
                }
                "bash" => {
                    if let Some(command) = tc
                        .function
                        .arguments
                        .get("command")
                        .and_then(serde_json::Value::as_str)
                    {
                        let command = crate::text::first_line_capped(command, 100);
                        commands.push(PartialProgressCommand {
                            verification: is_verification_command(&command),
                            command: command.clone(),
                        });
                        last_action = Some(format!("bash `{command}`"));
                    } else {
                        last_action = Some("bash".to_string());
                    }
                }
                _ => {
                    last_action = Some(tool.to_string());
                }
            }
        }
    }

    let files_read: Vec<String> = files_read.into_iter().collect();
    let files_edited: Vec<PartialProgressFileEdit> = files_edited
        .into_iter()
        .map(|edit| PartialProgressFileEdit {
            path: edit.path,
            hash: edit.hash,
        })
        .collect();
    let dirty_owned_changes = files_edited
        .iter()
        .map(|edit| edit.path.clone())
        .collect::<Vec<_>>();
    let review_state = if files_edited.is_empty() {
        None
    } else {
        Some("needs_review".to_string())
    };
    let verification_state = if files_edited.is_empty() && commands.is_empty() {
        None
    } else {
        Some("not_completed".to_string())
    };

    DelegationPartialProgress {
        files_read,
        files_edited,
        commands,
        last_action,
        verification_state,
        review_state,
        dirty_owned_changes,
    }
}

fn partial_progress_tool_outputs(history: &[Message]) -> std::collections::HashMap<String, String> {
    use rig::message::{ToolResultContent, UserContent};

    let mut outputs = std::collections::HashMap::new();
    for msg in history {
        let Message::User { content } = msg else {
            continue;
        };
        for part in content.iter() {
            if let UserContent::ToolResult(result) = part {
                let text = result
                    .content
                    .iter()
                    .filter_map(|content| match content {
                        ToolResultContent::Text(text) => Some(text.text.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("");
                outputs.insert(result.id.clone(), text);
            }
        }
    }
    outputs
}

fn render_failed_subagent_report(
    error_report: &str,
    progress: &DelegationPartialProgress,
) -> String {
    if progress.is_empty() {
        return error_report.to_string();
    }

    let mut out = error_report.trim_end().to_string();
    out.push_str("\n\n## Partial progress (host-derived)\n");
    if let Some(review_state) = &progress.review_state {
        out.push_str(&format!("- Review state: `{review_state}`\n"));
    }
    if let Some(verification_state) = &progress.verification_state {
        if verification_state == "not_completed" {
            out.push_str("- Verification did not complete.\n");
        } else {
            out.push_str(&format!("- Verification state: `{verification_state}`\n"));
        }
    }
    if !progress.files_edited.is_empty() {
        out.push_str("- Files edited:\n");
        for file in &progress.files_edited {
            match &file.hash {
                Some(hash) => out.push_str(&format!("  - `{}` (hash {})\n", file.path, hash)),
                None => out.push_str(&format!("  - `{}`\n", file.path)),
            }
        }
    }
    if !progress.files_read.is_empty() {
        out.push_str("- Files read:\n");
        for file in &progress.files_read {
            out.push_str(&format!("  - `{file}`\n"));
        }
    }
    if !progress.commands.is_empty() {
        out.push_str("- Commands run:\n");
        for command in &progress.commands {
            let suffix = if command.verification {
                " (verification)"
            } else {
                ""
            };
            out.push_str(&format!("  - `{}`{suffix}\n", command.command));
        }
    }
    if let Some(last_action) = &progress.last_action {
        out.push_str(&format!("- Last action: {last_action}\n"));
    }
    if !progress.dirty_owned_changes.is_empty() {
        out.push_str("- Owned changes needing inspection:\n");
        for file in &progress.dirty_owned_changes {
            out.push_str(&format!("  - `{file}`\n"));
        }
    }
    out
}

fn is_verification_command(command: &str) -> bool {
    let command = command.to_ascii_lowercase();
    [
        " test",
        " cargo test",
        "cargo test",
        " check",
        " cargo check",
        "cargo check",
        " clippy",
        " cargo clippy",
        "cargo clippy",
        " fmt --check",
        "cargo fmt --check",
        " build",
        " cargo build",
        "cargo build",
        "pnpm test",
        "npm test",
        "yarn test",
        "pytest",
        "go test",
    ]
    .iter()
    .any(|needle| command.contains(needle))
}

fn collect_final_text(history: &[Message]) -> String {
    // The last assistant message in the history is the subagent's
    // final text. Walk back to find it.
    for msg in history.iter().rev() {
        if let Message::Assistant { content, .. } = msg {
            let text = crate::engine::message::extract_text(content);
            if !text.trim().is_empty() {
                return text;
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests;
