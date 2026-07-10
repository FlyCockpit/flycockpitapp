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

/// Resolve where to persist an edited injection check-prompt: the project
/// `.cockpit/` layer for `cwd` when one already exists (so the override is
/// project-scoped where the project already carries config), else the
/// global home config. Returns the target path plus a human scope label.
fn injection_check_prompt_target(
    cwd: &std::path::Path,
) -> Result<(std::path::PathBuf, &'static str)> {
    use crate::config::dirs::{ConfigDirKind, discover_config_dirs};
    if let Some(dir) = discover_config_dirs(cwd)
        .into_iter()
        .find(|d| matches!(d.kind, ConfigDirKind::Project))
    {
        return Ok((dir.path.join(crate::config::dirs::CONFIG_FILE), "project"));
    }
    Ok((global_extended_config_path()?, "global"))
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NoninteractiveDelegationKey {
    task_call_id: String,
    label: String,
}

impl NoninteractiveDelegationKey {
    pub(crate) fn new(task_call_id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            task_call_id: task_call_id.into(),
            label: label.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum NoninteractiveDelegationStatus {
    Running,
    Backgrounded,
    Completed,
    Failed,
    Cancelled,
    Lost,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct NoninteractiveDelegationSnapshot {
    history: Vec<Message>,
}

impl NoninteractiveDelegationSnapshot {
    fn empty() -> Self {
        Self {
            history: Vec::new(),
        }
    }

    fn from_history(history: Vec<Message>) -> Self {
        Self { history }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct NoninteractiveSteer {
    body: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct NoninteractiveCompletionPayload {
    report: String,
    failed: bool,
    result: Option<Message>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct PartialProgressFileEdit {
    path: String,
    hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct PartialProgressCommand {
    command: String,
    verification: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
struct DelegationPartialProgress {
    files_read: Vec<String>,
    files_edited: Vec<PartialProgressFileEdit>,
    commands: Vec<PartialProgressCommand>,
    last_action: Option<String>,
    verification_state: Option<String>,
    review_state: Option<String>,
    dirty_owned_changes: Vec<String>,
}

impl DelegationPartialProgress {
    fn is_empty(&self) -> bool {
        self.files_read.is_empty()
            && self.files_edited.is_empty()
            && self.commands.is_empty()
            && self.last_action.is_none()
            && self.verification_state.is_none()
            && self.review_state.is_none()
            && self.dirty_owned_changes.is_empty()
    }
}

#[derive(Debug, Clone)]
struct DelegationChildOutcome {
    report: String,
    failed: bool,
    partial_progress: DelegationPartialProgress,
}

impl DelegationChildOutcome {
    fn ok(report: impl Into<String>) -> Self {
        Self {
            report: report.into(),
            failed: false,
            partial_progress: DelegationPartialProgress::default(),
        }
    }

    fn failed(report: impl Into<String>) -> Self {
        Self {
            report: report.into(),
            failed: true,
            partial_progress: DelegationPartialProgress::default(),
        }
    }

    fn failed_with_progress(
        report: impl Into<String>,
        partial_progress: DelegationPartialProgress,
    ) -> Self {
        let report = report.into();
        let report = render_failed_subagent_report(&report, &partial_progress);
        Self {
            report,
            failed: true,
            partial_progress,
        }
    }
}

pub(crate) fn is_host_failure_sentinel(report: &str) -> bool {
    report.trim_start().starts_with("Error: ")
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct NoninteractiveDelegationEntry {
    child_agent: String,
    status: NoninteractiveDelegationStatus,
    delivered: bool,
    snapshot: NoninteractiveDelegationSnapshot,
    steer_queue: std::collections::VecDeque<NoninteractiveSteer>,
    completion: Option<NoninteractiveCompletionPayload>,
}

impl NoninteractiveDelegationEntry {
    fn running(child_agent: String, snapshot: NoninteractiveDelegationSnapshot) -> Self {
        Self {
            child_agent,
            status: NoninteractiveDelegationStatus::Running,
            delivered: false,
            snapshot,
            steer_queue: std::collections::VecDeque::new(),
            completion: None,
        }
    }
}

#[derive(Default)]
struct NoninteractiveDelegationRegistry {
    entries: std::collections::HashMap<NoninteractiveDelegationKey, NoninteractiveDelegationEntry>,
}

#[allow(dead_code)]
impl NoninteractiveDelegationRegistry {
    fn register_running(
        &mut self,
        task_call_id: &str,
        label: &str,
        child_agent: String,
        snapshot: NoninteractiveDelegationSnapshot,
    ) {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        self.entries.insert(
            key,
            NoninteractiveDelegationEntry::running(child_agent, snapshot),
        );
    }

    fn set_snapshot(
        &mut self,
        task_call_id: &str,
        label: &str,
        snapshot: NoninteractiveDelegationSnapshot,
    ) {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.snapshot = snapshot;
        }
    }

    fn push_steer(&mut self, task_call_id: &str, label: &str, body: String) {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.steer_queue.push_back(NoninteractiveSteer { body });
        }
    }

    fn is_live(&self, task_call_id: &str, label: &str) -> bool {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        self.entries.get(&key).is_some_and(|entry| {
            matches!(
                entry.status,
                NoninteractiveDelegationStatus::Running
                    | NoninteractiveDelegationStatus::Backgrounded
            )
        })
    }

    fn cancel(&mut self, task_call_id: &str, label: &str) -> bool {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        let Some(entry) = self.entries.get_mut(&key) else {
            return false;
        };
        if !matches!(
            entry.status,
            NoninteractiveDelegationStatus::Running | NoninteractiveDelegationStatus::Backgrounded
        ) {
            return false;
        }
        entry.status = NoninteractiveDelegationStatus::Cancelled;
        entry
            .completion
            .get_or_insert(NoninteractiveCompletionPayload {
                report: "cancelled".to_string(),
                failed: false,
                result: None,
            });
        true
    }

    fn live_rows(
        &self,
    ) -> Vec<(
        String,
        String,
        String,
        NoninteractiveDelegationStatus,
        usize,
    )> {
        let mut rows = self
            .entries
            .iter()
            .map(|(key, entry)| {
                (
                    key.task_call_id.clone(),
                    key.label.clone(),
                    entry.child_agent.clone(),
                    entry.status,
                    entry.steer_queue.len(),
                )
            })
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        rows
    }

    fn snapshot_report(&self, task_call_id: &str, label: &str) -> Option<String> {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        let entry = self.entries.get(&key)?;
        if let Some(completion) = &entry.completion {
            return Some(completion.report.clone());
        }
        if entry.snapshot.history.is_empty() {
            return None;
        }
        let start = entry.snapshot.history.len().saturating_sub(6);
        serde_json::to_string(&entry.snapshot.history[start..]).ok()
    }

    fn drain_steer_queue(
        &mut self,
        task_call_id: &str,
        label: &str,
    ) -> std::collections::VecDeque<NoninteractiveSteer> {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        self.entries
            .get_mut(&key)
            .map(|entry| std::mem::take(&mut entry.steer_queue))
            .unwrap_or_default()
    }

    fn background_on_user_input(&mut self, task_call_id: &str, label: &str) -> bool {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        let Some(entry) = self.entries.get_mut(&key) else {
            return false;
        };
        if entry.status != NoninteractiveDelegationStatus::Running {
            return false;
        }
        entry.status = NoninteractiveDelegationStatus::Backgrounded;
        true
    }

    fn complete(
        &mut self,
        task_call_id: &str,
        label: &str,
        report: String,
        failed: bool,
        result: Option<Message>,
    ) -> bool {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        let Some(entry) = self.entries.get_mut(&key) else {
            return false;
        };
        if entry.completion.is_some() {
            return false;
        }
        entry.status = if failed {
            NoninteractiveDelegationStatus::Failed
        } else {
            NoninteractiveDelegationStatus::Completed
        };
        entry.completion = Some(NoninteractiveCompletionPayload {
            report,
            failed,
            result,
        });
        true
    }

    fn completed_undelivered(&self, task_call_id: &str) -> Vec<(String, String)> {
        let mut rows = self
            .entries
            .iter()
            .filter(|(key, entry)| {
                key.task_call_id == task_call_id
                    && !entry.delivered
                    && matches!(
                        entry.status,
                        NoninteractiveDelegationStatus::Completed
                            | NoninteractiveDelegationStatus::Failed
                            | NoninteractiveDelegationStatus::Cancelled
                            | NoninteractiveDelegationStatus::Lost
                    )
            })
            .filter_map(|(key, entry)| {
                entry
                    .completion
                    .as_ref()
                    .map(|completion| (key.label.clone(), completion.report.clone()))
            })
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }

    fn running_labels(&self, task_call_id: &str) -> Vec<String> {
        let mut labels = self
            .entries
            .iter()
            .filter(|(key, entry)| {
                key.task_call_id == task_call_id
                    && matches!(
                        entry.status,
                        NoninteractiveDelegationStatus::Running
                            | NoninteractiveDelegationStatus::Backgrounded
                    )
            })
            .map(|(key, _)| key.label.clone())
            .collect::<Vec<_>>();
        labels.sort();
        labels
    }

    fn is_backgrounded_job(&self, task_call_id: &str) -> bool {
        self.entries.iter().any(|(key, entry)| {
            key.task_call_id == task_call_id
                && entry.status == NoninteractiveDelegationStatus::Backgrounded
        })
    }

    fn mark_delivered(&mut self, task_call_id: &str, label: &str) -> bool {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        let Some(entry) = self.entries.get_mut(&key) else {
            return false;
        };
        if entry.delivered {
            return false;
        }
        entry.delivered = true;
        true
    }

    fn take_late_result(&mut self, task_call_id: &str, label: &str) -> Option<Message> {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        let result = self
            .entries
            .get(&key)
            .and_then(|entry| entry.completion.as_ref())
            .and_then(|completion| completion.result.clone())?;
        if !self.mark_delivered(task_call_id, label) {
            return None;
        }
        Some(result)
    }

    #[cfg(test)]
    fn status(&self, task_call_id: &str, label: &str) -> Option<NoninteractiveDelegationStatus> {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        self.entries.get(&key).map(|entry| entry.status)
    }

    #[cfg(test)]
    fn child_agent(&self, task_call_id: &str, label: &str) -> Option<&str> {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        self.entries
            .get(&key)
            .map(|entry| entry.child_agent.as_str())
    }

    #[cfg(test)]
    fn snapshot_len(&self, task_call_id: &str, label: &str) -> Option<usize> {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        self.entries
            .get(&key)
            .map(|entry| entry.snapshot.history.len())
    }
}

struct SingleNoninteractiveTask {
    child_agent: String,
    brief: String,
    model: Option<crate::engine::model_roles::DelegationModelSelector>,
    remaining_depth: Option<u32>,
    why: String,
    resume_handle: Option<String>,
    child_cwd: ChildCwd,
    granted_tools: Vec<String>,
    prefill_seeds: Vec<crate::engine::compact::SeedTool>,
    todo_ids: Vec<uuid::Uuid>,
    skill_seed: Vec<String>,
    child_recursion: crate::engine::builtin::DelegationRecursionContext,
    repair_notes: Vec<String>,
    task_call_id: String,
    task_function_call_id: Option<String>,
}

struct SingleNoninteractiveCompletion {
    child_agent: String,
    task_call_id: String,
    task_function_call_id: Option<String>,
    report: String,
    failed: bool,
    partial_progress: DelegationPartialProgress,
    seeds: Vec<crate::engine::compact::SeedTool>,
    new_handle: Option<String>,
    snapshot: NoninteractiveDelegationSnapshot,
    shrink: Option<PendingDelegationShrink>,
    repair_notes: Vec<String>,
}

struct BatchNoninteractiveTask {
    entries: Vec<crate::engine::agent::BatchTaskEntry>,
    child_cwds: Vec<ChildCwd>,
    why: String,
    repair_notes: Vec<String>,
    task_call_id: String,
    task_function_call_id: Option<String>,
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

struct BatchChildCompletion {
    idx: usize,
    label: String,
    child_agent: String,
    report: String,
    failed: bool,
    partial_progress: DelegationPartialProgress,
    snapshot: NoninteractiveDelegationSnapshot,
}

struct BatchNoninteractiveCompletion {
    task_call_id: String,
    task_function_call_id: Option<String>,
    children: Vec<BatchChildCompletion>,
    repair_notes: Vec<String>,
}

enum BackgroundNoninteractiveCompletion {
    Single {
        task_call_id: String,
        task_function_call_id: Option<String>,
        result: Box<Result<SingleNoninteractiveCompletion>>,
    },
    Batch {
        task_call_id: String,
        task_function_call_id: Option<String>,
        result: Box<Result<BatchNoninteractiveCompletion>>,
    },
}

impl BackgroundNoninteractiveCompletion {
    fn task_call_id(&self) -> &str {
        match self {
            Self::Single { task_call_id, .. } | Self::Batch { task_call_id, .. } => task_call_id,
        }
    }
}

enum NoninteractiveCompletionDelivery {
    None,
    Inline(Message),
    AsyncUser(String),
}

impl NoninteractiveCompletionDelivery {
    fn into_inline_message(self) -> Message {
        match self {
            Self::Inline(message) => message,
            Self::AsyncUser(text) => Message::user(text),
            Self::None => Message::user(""),
        }
    }
}

struct BackgroundNoninteractiveJob {
    delivered: bool,
    handle: tokio::task::JoinHandle<()>,
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

impl Drop for BackgroundNoninteractiveJob {
    fn drop(&mut self) {
        if !self.handle.is_finished() {
            self.handle.abort();
        }
    }
}

/// One user-invoked skill pair folded into the root history, tracked so a
/// primary swap can strip an abandoned skill the outgoing primary declined
/// to follow (implementation note). The pair is the
/// contiguous assistant(`skill` ToolCall)+user(ToolResult) the seam pushes;
/// both messages carry `call_id` and are removed together so history stays
/// well-formed.
struct SkillPair {
    /// The synthesized `skill` call's id (the `skillslash-…` value shared by
    /// the assistant ToolCall and its tool_result).
    call_id: String,
    /// The primary that was active when the skill was invoked. Its swap-out
    /// is what strips the pair.
    owner: String,
    /// Opt-out seam for a future user-invoked skill that should deliberately
    /// survive a swap and steer the new primary. Always `false` today — no
    /// path sets it — so the scope-narrowly contract ("an *abandoned* skill
    /// must not masquerade as the new primary's instructions") holds without
    /// blocking that future behavior.
    intentional_steer: bool,
}

impl From<crate::db::skill_pairs::SkillPairRow> for SkillPair {
    fn from(row: crate::db::skill_pairs::SkillPairRow) -> Self {
        Self {
            call_id: row.call_id,
            owner: row.owner,
            intentional_steer: row.intentional_steer,
        }
    }
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

    /// Wrap `user_text` with the `[time: ...]` prelude when the
    /// session's interval has elapsed. Side-effect: stamps the
    /// session's last-prelude timestamp on success. No-op when the
    /// interval hasn't elapsed.
    fn with_time_prelude(&self, user_text: String) -> String {
        match self
            .session
            .take_time_prelude(self.time_injection_interval_minutes)
        {
            Some(prelude) => format!("{prelude}\n\n{user_text}"),
            None => user_text,
        }
    }

    /// Skills auto-selection seam (GOALS §5). Loads the layered config,
    /// consults the cheap utility model with the skill catalog + the recent
    /// conversation window (the same last-3-turn shape `predict` uses), and
    /// — if any skills are selected — returns `user_text` with each chosen
    /// skill's (`!`-processed, scrubbed) body prepended in relevance order
    /// so the main agent's first inference carries them. Selection is capped
    /// in count and total token budget. Returns `user_text` unchanged when
    /// no skill is chosen.
    ///
    /// Graceful degradation: an unset `utility_model` skips the pass
    /// (logged at most once) and returns `user_text` untouched — no
    /// error, no main-model fallback. The cheap model only ever sees the
    /// `(name, description)` catalog (token economy, GOALS §10).
    async fn maybe_inject_skill(
        &mut self,
        user_text: &str,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> String {
        let (extended, providers) = crate::auto_title::load_configs_for(&self.cwd);

        if extended.skill_injection_model_ref().is_none() {
            if !self.skills_no_utility_model_logged {
                self.skills_no_utility_model_logged = true;
                tracing::info!("skills auto-selection skipped: no `utility_model` configured");
            }
            return user_text.to_string();
        }

        // Feed the selector the same window `predict` uses: the recent
        // turns (user input + agent final response, no tool calls). The
        // current user message isn't in history yet (it's pushed inside
        // `turn()`), so append it as the latest open turn before windowing.
        let mut turns = crate::engine::predict::turns_from_messages(&self.stack[0].history);
        turns.push(crate::engine::predict::PredictionTurn {
            user: user_text.to_string(),
            agent: String::new(),
        });

        let (selection, diagnostics) = crate::skills::auto_select::select_with_diagnostics(
            &self.cwd,
            &extended,
            &providers,
            self.redact.clone(),
            self.session.trusted_only_flag(),
            &turns,
            &self.auto_injected_skills,
        )
        .await;
        if !diagnostics.is_empty() {
            let data = serde_json::json!({ "rejections": diagnostics.rejections });
            if let Err(e) = self.session.record_event(
                crate::db::session_log::SessionEventKind::SkillAutoSelect,
                Some(&self.stack[0].agent.name),
                None,
                &data,
            ) {
                tracing::warn!(error = %e, "recording skill auto-select diagnostics failed");
            }
        }

        match selection {
            crate::skills::auto_select::Selection::Skills(skills) => {
                let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
                tracing::debug!(skills = ?names, "skills auto-selection injected skill bodies");
                for skill in &skills {
                    // Record the auto-injected body in the seedable set so a
                    // later `task.skill_seed` naming this skill passes host
                    // validation (implementation note).
                    self.record_active_skill(&skill.name, &skill.body);
                    // Record it in the auto-injection suppression set so it is
                    // not re-injected later this session (once-per-session,
                    // implementation note change 4).
                    // Recorded only on actual injection, not on vote/match —
                    // a voted-then-dropped skill stays eligible for a later
                    // turn when it finally fits.
                    self.auto_injected_skills.insert(skill.name.clone());
                    // Surface the injection in the transcript as a distinct
                    // `/{name} · injected by agent` row, in injection order,
                    // ahead of the user's message (`auto-injected-skill-
                    // transcript-visibility.md`). UI-only — the wire still
                    // carries the body folded into the user message below
                    // (wire-vs-user split, GOALS §14).
                    let _ = tx
                        .send(TurnEvent::SkillAutoInjected {
                            name: skill.name.clone(),
                            // Display-only / off-wire (GOALS §14): the reason
                            // (model clause or keyword-overlap fallback) rides
                            // the user-facing row, never the folded body.
                            reason: skill.reason.clone(),
                        })
                        .await;
                }
                // Fold every surviving body in relevance order ahead of the
                // user's message — the wire half of the split (the model still
                // sees the bodies; the `SkillAutoInjected` rows above are the
                // user-facing half).
                Self::fold_injected_skills(&skills, user_text)
            }
            crate::skills::auto_select::Selection::None => user_text.to_string(),
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

    /// Inbound utility-model translation (implementation note):
    /// translate `text` from the user's language into the model's language.
    /// Returns the text unchanged when the feature is inactive (languages
    /// unset/equal) or the utility model is unset/unavailable/erroring —
    /// degrade, never block the turn. Called between the injection scan
    /// (which sees the raw text) and outbound redaction.
    async fn translate_inbound(&self, text: &str) -> String {
        match crate::engine::translate::load_if_active(&self.cwd) {
            Some((extended, providers)) => {
                crate::engine::translate::inbound(
                    text,
                    &extended,
                    &providers,
                    self.redact.clone(),
                    self.session.trusted_only_flag(),
                )
                .await
            }
            None => text.to_string(),
        }
    }

    /// Prompt-injection guard (GOALS §4i). Scans the **raw** user text
    /// (before redaction) through the history-free, nonce-wrapped
    /// injection check ([`crate::engine::injection_check`]) and returns
    /// whether the prompt may proceed. Two-part so the check can run
    /// concurrently with the request-preflight rewrite
    /// (implementation note): [`Self::injection_check_only`] runs
    /// the classification, [`Self::apply_injection_outcome`] applies the
    /// (self-mutating) verdict + override UX.
    ///
    /// Run **only** the prompt-injection classification on the raw text,
    /// without any self-mutating override UX. Returns `None` when scanning
    /// is disabled (`threshold == Off`), else the configured threshold +
    /// the [`CheckOutcome`]. Split out from [`Self::injection_guard_allows`]
    /// so the check can run **concurrently** with the request-preflight
    /// rewrite (both consume the same raw text — implementation note).
    async fn injection_check_only(
        &self,
        raw_text: &str,
    ) -> Option<(
        crate::config::extended::InjectionThreshold,
        crate::engine::injection_check::CheckOutcome,
    )> {
        use crate::config::extended::{InjectionThreshold, resolve_injection_guard};
        use crate::engine::injection_check::check;

        let (extended, providers) = crate::auto_title::load_configs_for(&self.cwd);
        let guard = resolve_injection_guard(&self.cwd);
        if guard.threshold == InjectionThreshold::Off {
            return None; // scanning disabled
        }
        // The guard's own model override falls back to the utility model.
        let model_ref = extended.guard_model_ref();
        let outcome = check(
            model_ref,
            &providers,
            self.redact.clone(),
            self.session.trusted_only_flag(),
            &guard.check_prompt,
            raw_text,
        )
        .await;
        Some((guard.threshold, outcome))
    }

    /// The effective request-preflight enabled state: the session-only
    /// `/preflight` override ([`Self::preflight_override`]) when set, else
    /// the layered `preflight.enabled` config (implementation note).
    fn preflight_enabled(&self) -> bool {
        self.preflight_override
            .unwrap_or_else(|| crate::config::extended::resolve_preflight(&self.cwd).enabled)
    }

    /// Whether request preflight will *actually run* for `text` — enabled AND
    /// not a `should_skip` no-op (trivial / bare ack / leading `/`). Drives the
    /// submit-time `PreflightStarted` in-progress signal: only an actually-
    /// running preflight adds the animated `Preflight…` indicator
    /// (implementation note).
    fn preflight_will_run(&self, text: &str) -> bool {
        self.preflight_enabled() && !crate::engine::preflight::should_skip(text)
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

    /// Raise the false-positive override prompt for a blocked prompt and
    /// act on the user's choice. Returns whether the prompt may proceed.
    ///
    /// Headless (no interactive client that can answer) → block stands
    /// (`false`): there is no human to override, and silently sending a
    /// high-risk prompt would defeat the guard. A dismissal reads the same.
    async fn injection_override(
        &mut self,
        rating: crate::config::extended::InjectionThreshold,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> bool {
        use crate::daemon::proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};

        if !self.interrupts.is_interactive_attached() {
            let _ = tx
                .send(TurnEvent::Notice {
                    text: format!(
                        "prompt-injection guard blocked this prompt (rated `{}`); no interactive \
                         client to confirm an override — dropped",
                        rating.as_str()
                    ),
                })
                .await;
            return false;
        }

        let agent = self.active_agent().to_string();
        let description = format!(
            "Prompt-injection guard rated this prompt `{}` (at or above your block threshold). \
             This may be a false positive. How do you want to proceed?",
            rating.as_str()
        );
        let question = InterruptQuestion::Single {
            prompt: "Allow this blocked prompt?".to_string(),
            options: vec![
                InterruptOption {
                    id: ID_INJECTION_SEND_ONCE.to_string(),
                    label: "Approve & send this prompt once".to_string(),
                    description: Some("does not change any setting".to_string()),
                },
                InterruptOption {
                    id: ID_INJECTION_LOWER.to_string(),
                    label: "Approve & lower the block threshold".to_string(),
                    description: Some("relaxes the global threshold one level".to_string()),
                },
                InterruptOption {
                    id: ID_INJECTION_EDIT.to_string(),
                    label: "Approve & edit the injection-check prompt".to_string(),
                    description: Some("you'll type a new check-prompt next".to_string()),
                },
            ],
            allow_freetext: false,
            command_detail: None,
            // A genuine decision prompt (distinct action choices), not a
            // tool-permission scope select — keep the question presentation.
            permission: false,
            sandbox_escalation: None,
        };
        let set = InterruptQuestionSet {
            questions: vec![question],
        };

        let choice = self.raise_and_wait(&agent, &description, set).await;
        let id = selected_id_of(&choice);
        match id.as_deref() {
            Some(ID_INJECTION_SEND_ONCE) => {
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: "prompt-injection block overridden (sent once)".to_string(),
                    })
                    .await;
                true
            }
            Some(ID_INJECTION_LOWER) => {
                let msg = match self.lower_injection_threshold() {
                    Ok(new) => format!(
                        "prompt-injection block overridden; threshold lowered to `{}`",
                        new.as_str()
                    ),
                    Err(e) => format!(
                        "prompt-injection block overridden (sent once); lowering threshold \
                         failed: {e}"
                    ),
                };
                let _ = tx.send(TurnEvent::Notice { text: msg }).await;
                true
            }
            Some(ID_INJECTION_EDIT) => {
                // Follow-up free-text interrupt for the new check-prompt.
                let edit_set = InterruptQuestionSet {
                    questions: vec![InterruptQuestion::Freetext {
                        prompt:
                            "Enter the new injection-check prompt (blank keeps the current one)"
                                .to_string(),
                        masked: false,
                    }],
                };
                let resp = self
                    .raise_and_wait(&agent, "Edit the injection-check prompt", edit_set)
                    .await;
                let new_prompt = freetext_of(&resp);
                let msg = match new_prompt {
                    Some(text) if !text.trim().is_empty() => {
                        match self.write_injection_check_prompt(&text) {
                            Ok(scope) => format!(
                                "prompt-injection block overridden; check-prompt updated ({scope})"
                            ),
                            Err(e) => format!(
                                "prompt-injection block overridden (sent once); saving the \
                                 check-prompt failed: {e}"
                            ),
                        }
                    }
                    _ => "prompt-injection block overridden (sent once); check-prompt unchanged"
                        .to_string(),
                };
                let _ = tx.send(TurnEvent::Notice { text: msg }).await;
                true
            }
            _ => {
                // Dismissed → the block stands.
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: "prompt-injection block kept — prompt dropped".to_string(),
                    })
                    .await;
                false
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
            failure_retry_decision_and_rationale(&failure.class, provider_status);
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

    /// Switch the active model+provider live (`mid-session-model-
    /// switch.md`), at the idle control boundary like every other primary swap.
    /// Builds the new [`Model`](crate::engine::model::Model) for
    /// `(provider, model)` from the layered config, threading the session's
    /// effective redaction table (`self.redact`) so the new model keeps the
    /// non-bypassable scrub chokepoint (GOALS §7), and inheriting the current
    /// model's shutdown gate + wire-API self-heal target. On success it rebuilds
    /// the **root primary** under the new model — preserving the root history so
    /// the same conversation continues — persists the session's active-model row,
    /// and refreshes the prunable projection. On any failure (provider not
    /// configured, bad id, missing credentials) it **fails loudly** via a
    /// [`TurnEvent::Notice`] and leaves the current model active (no silent
    /// no-op, no crash). The prompt-cache break is expected and accepted.
    async fn set_active_model_live(
        &mut self,
        provider: &str,
        model: &str,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        // A no-op when the requested model is already the active one — never
        // rebuild (and bust the cache) for a same-model re-select.
        let active_idx = self.stack.len().saturating_sub(1);
        let current = &self.stack[active_idx].agent.model;
        if current.provider_id() == provider && current.model_id_ref() == model {
            return;
        }
        // The new model inherits the running model's shutdown gate (so a daemon
        // drain still refuses its dispatch) and wire-API self-heal target.
        let new_model = match self.build_live_model(provider, model) {
            Ok(m) => Arc::new(m),
            Err(e) => {
                // Fail loudly, keep the current model active.
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: format!(
                            "Model switch to `{provider}/{model}` failed — {e:#}. \
                             Keeping the current model active."
                        ),
                    })
                    .await;
                return;
            }
        };
        let rebuilt = self.rebuild_frame_with_model(active_idx, new_model);
        self.stack[active_idx].agent = Arc::new(rebuilt);
        if active_idx == 0 {
            // The job authority's fork context is rooted on the root agent;
            // rebind it when the root model changes.
            self.schedule.set_agent(self.stack[0].agent.clone());
            if let Err(e) = self.session.set_active_model(provider, model) {
                tracing::warn!(error = %e, "persisting active model after live switch failed");
            }
        }
        tracing::info!(provider, model, "active model switched live");
        // The model changed, so the prefix cache key changes — refresh the
        // prunable projection the chrome shows (cache-cold reflects the bust).
        self.emit_context_projection(tx).await;
    }

    /// Build a fresh [`Model`](crate::engine::model::Model) for `(provider,
    /// model)` from the layered config (honoring the test-injected config in
    /// tests), threading the session's effective redaction table and inheriting
    /// the running model's shutdown gate + wire-API self-heal target. The new
    /// model's reasoning params are re-resolved from the config's active-model
    /// thinking mode and ride on the rebuilt root agent (see
    /// [`Self::rebuild_root_with_model`]). Errors propagate so the caller can
    /// surface them (unconfigured provider / bad id / missing key).
    fn build_live_model(&self, provider: &str, model: &str) -> Result<crate::engine::model::Model> {
        let providers = self.live_providers_config()?;
        let running = &self.stack.last().expect("stack never empty").agent.model;
        let env_overlay = self.stack[0].agent.env_overlay.clone();
        let built = crate::engine::model::Model::for_provider_with_env_trusted_only(
            &providers,
            provider,
            model,
            self.redact.clone(),
            running.trusted_only_flag(),
            move |name| {
                env_overlay
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(name)
                    .cloned()
            },
        )?
        .with_shutdown_gate(running.shutdown_gate());
        let built = match running.config_path() {
            Some(path) => built.with_config_path(path.to_path_buf()),
            None => built,
        };
        Ok(built)
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

    /// Swap the root-frame agent to `name` in place, preserving the root
    /// history so the new primary continues the same conversation. Only the
    /// root frame is swapped, and only at idle (the control boundary) — a
    /// deeper interactive subagent frame is never touched. No-op when an
    /// interactive subagent holds the foreground or the agent is already
    /// active. The new agent is built through [`crate::engine::builtin::load`]
    /// so a user override of `Plan`/`Build` takes effect.
    ///
    /// Before re-rooting, the outgoing primary's abandoned (non-steering)
    /// user-invoked skill pairs are stripped from history so a skill the
    /// previous primary declined to follow does not govern the new primary
    /// (implementation note).
    ///
    /// The imperative-kickoff contract (begin work on the first turn, tool
    /// call not narration) attaches only to the [`Self::apply_handoff`] path:
    /// a `handoff` fires **mid-turn**, so the swapped-in primary's first input
    /// is the synthesized `handoff` tool_result, which `apply_handoff` builds
    /// as the kickoff. The `/plan`/`/build`/`/swarm` (and `/agent`,
    /// `Shift+Tab`) swaps route here at **idle** and return to idle without a
    /// turn — the new primary's first turn is driven by the user's *next*
    /// message, which is already actionable, so there is no separate kickoff
    /// to inject for those paths.
    async fn swap_primary(&mut self, name: &str, tx: &mpsc::Sender<TurnEvent>) {
        self.swap_primary_with_context(name, PrimarySwapContext::swap_command(), tx)
            .await;
    }

    /// [`Self::swap_primary`] plus the export-audit `primary_swap` context: the
    /// trigger and (for the `handoff` path) the wire-vs-user `display`/`kickoff`
    /// pair (GOALS §14). The control-swap entry point passes
    /// [`PrimarySwapContext::swap_command`] (no kickoff); [`Self::apply_handoff`]
    /// passes the handoff display + kickoff. The `primary_swap` timeline event
    /// is recorded only on a successful re-root, so a failed agent load never
    /// records a phantom swap.
    async fn swap_primary_with_context(
        &mut self,
        name: &str,
        swap_ctx: PrimarySwapContext<'_>,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> bool {
        if self.stack.len() != 1 {
            tracing::warn!(
                requested = %name,
                "primary swap ignored: an interactive subagent holds the foreground"
            );
            return false;
        }
        if self.stack[0].agent.name == name {
            return true;
        }
        match crate::engine::builtin::load(name, &self.spawn_args(true)) {
            Ok(agent) => {
                // An abandoned skill the outgoing primary declined to follow
                // must not cross the swap as authoritative instructions for
                // the new primary (implementation note).
                // Strip the outgoing primary's non-steering skill pairs before
                // re-rooting; a future intentionally-steering skill opts out
                // via `intentional_steer` and survives.
                let outgoing = self.stack[0].agent.name.clone();
                self.strip_abandoned_skill_pairs(&outgoing);
                // Per-call tool-call ownership (`cross-agent-tool-call-
                // annotation.md`): attribute every not-yet-attributed tool call
                // now in the root history to the OUTGOING agent before re-
                // rooting. Runs AFTER the skill-pair strip so an abandoned skill
                // call (already removed) is never attributed. Swaps fire at idle,
                // so the just-finished run's calls are all present — attribution
                // is exact across any number of swaps. Existing entries are never
                // overwritten (a re-swap doesn't reattribute earlier calls).
                self.record_tool_call_ownership(&outgoing);
                let outgoing_write_capable =
                    crate::engine::builtin::is_write_capable(&self.stack[0].agent);
                let incoming_write_capable = crate::engine::builtin::is_write_capable(&agent);
                if outgoing_write_capable {
                    let lock_result = if incoming_write_capable {
                        self.locks
                            .transfer_agent_locks(&outgoing, &agent.name, self.session.id)
                            .map(|_| ())
                    } else {
                        self.locks
                            .suspend_agent(&outgoing, self.session.id)
                            .map(|_| ())
                    };
                    if let Err(e) = lock_result {
                        tracing::warn!(
                            error = ?e,
                            from = %outgoing,
                            to = %agent.name,
                            "primary swap failed during lock ownership update"
                        );
                        return false;
                    }
                }
                // Deferred agent-swap identity marker (`agent-swap-
                // identity-marker.md`): a `swap_command` swap leaves no boundary
                // entry on the wire, so record the previously-effective agent now
                // for injection on the user's next message. Capture the outgoing
                // agent only at the FIRST swap since the last message — never
                // overwrite it on an intermediate hop — so a multi-swap run
                // coalesces to one marker naming previously-effective → final.
                // The `handoff` path injects its own kickoff and sets nothing.
                if swap_ctx.trigger == SWAP_TRIGGER_COMMAND
                    && self.pending_swap_marker_from.is_none()
                {
                    self.pending_swap_marker_from = Some(outgoing.clone());
                }
                self.stack[0].agent = Arc::new(agent);
                self.stack[0].queue_target =
                    crate::engine::message::QueueTarget::root(name.to_string());
                // The job authority's fork context is rooted on the old
                // agent; rebind it so any future loop fork runs on the new
                // primary's model/tool surface (single-authority rule).
                self.schedule.set_agent(self.stack[0].agent.clone());
                tracing::info!(agent = %name, "primary agent swapped");
                // `primary_swap` timeline event (export-audit fidelity):
                // from/to + trigger + both halves of the wire-vs-user split.
                if let Err(e) = self.session.record_primary_swap(
                    &outgoing,
                    name,
                    swap_ctx.trigger,
                    swap_ctx.display,
                    swap_ctx.kickoff,
                ) {
                    tracing::warn!(error = %e, "record primary_swap event failed");
                }
                // Tell the client chrome's active-agent slot about the new
                // primary, then refresh the prunable projection.
                let _ = tx
                    .send(TurnEvent::PrimarySwapped {
                        name: name.to_string(),
                    })
                    .await;
                let _ = tx
                    .send(TurnEvent::ForegroundInputTarget {
                        target: self.active_queue_target(),
                    })
                    .await;
                self.emit_context_projection(tx).await;
                true
            }
            Err(e) => {
                tracing::warn!(error = %e, requested = %name, "primary swap failed to load agent");
                false
            }
        }
    }

    /// Remove from the root history the user-invoked skill pairs owned by the
    /// outgoing primary `owner` that are not flagged `intentional_steer`, so an
    /// abandoned skill the outgoing primary declined to follow does not cross a
    /// primary swap as authoritative instructions for the new primary
    /// (implementation note). Each pair is the
    /// contiguous assistant(`skill` ToolCall)+user(ToolResult) the
    /// [`Self::seed_forced_skill`] seam pushed; both messages share `call_id`
    /// and are removed together so the transcript stays well-formed (no
    /// orphaned tool call or unanswered result). The ledger entries for the
    /// stripped pairs are dropped; a steering pair (none today) is retained.
    fn strip_abandoned_skill_pairs(&mut self, owner: &str) {
        let ids: std::collections::HashSet<String> = self
            .skill_pairs
            .iter()
            .filter(|p| !p.intentional_steer && p.owner == owner)
            .map(|p| p.call_id.clone())
            .collect();
        if ids.is_empty() {
            return;
        }
        let history = &mut self.stack[0].history;
        history.retain(|msg| !message_references_call_id(msg, &ids));
        self.skill_pairs
            .retain(|p| p.intentional_steer || p.owner != owner);
        self.delete_persisted_skill_pairs(ids.iter());
    }

    /// Restore the persisted skill-pair ownership ledger after model-history
    /// rehydration. Newer sessions load direct `skill_pairs` rows; older
    /// post-migration resumes can reconstruct from the durable skill-slash
    /// tool-call audit rows because those rows carry both `call_id` and the
    /// agent active when the slash command ran.
    fn restore_skill_pairs_after_rehydrate(&mut self, root_agent: &str) {
        let present = skill_pair_call_ids_in_history(&self.stack[0].history);
        if present.is_empty() {
            self.skill_pairs.clear();
            return;
        }

        let mut restored: Vec<SkillPair> = self
            .session
            .db
            .list_skill_pairs(self.session.id)
            .map(|rows| rows.into_iter().map(SkillPair::from).collect())
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "loading skill-pair ownership failed");
                Vec::new()
            });
        restored.retain(|pair| present.contains(&pair.call_id));

        let known: std::collections::HashSet<String> =
            restored.iter().map(|pair| pair.call_id.clone()).collect();
        if known.len() < present.len() {
            let mut inferred = self.reconstruct_skill_pairs_from_tool_log(root_agent, &present);
            inferred.retain(|pair| !known.contains(&pair.call_id));
            for pair in &inferred {
                if let Err(e) = self.session.db.save_skill_pair(
                    self.session.id,
                    &pair.call_id,
                    &pair.owner,
                    pair.intentional_steer,
                ) {
                    tracing::warn!(error = %e, call_id = %pair.call_id, "persisting reconstructed skill-pair ownership failed");
                }
            }
            restored.extend(inferred);
        }

        self.skill_pairs = restored;
    }

    fn reconstruct_skill_pairs_from_tool_log(
        &self,
        root_agent: &str,
        present: &std::collections::HashSet<String>,
    ) -> Vec<SkillPair> {
        let calls = self
            .session
            .db
            .list_tool_calls_for_session(self.session.id)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "loading tool calls for skill-pair reconstruction failed");
                Vec::new()
            });

        let mut pairs = Vec::new();
        for call_id in present {
            let owner = calls
                .iter()
                .find(|call| call.call_id == *call_id && call.tool == "skill")
                .map(|call| call.agent.clone())
                .unwrap_or_else(|| root_agent.to_string());
            pairs.push(SkillPair {
                call_id: call_id.clone(),
                owner,
                intentional_steer: false,
            });
        }
        pairs
    }

    fn delete_persisted_skill_pairs<'a, I>(&self, call_ids: I)
    where
        I: IntoIterator<Item = &'a String>,
    {
        let ids: Vec<&str> = call_ids.into_iter().map(String::as_str).collect();
        if ids.is_empty() {
            return;
        }
        if let Err(e) = self.session.db.delete_skill_pairs(self.session.id, ids) {
            tracing::warn!(error = %e, "deleting persisted skill-pair ownership failed");
        }
    }

    /// `/compact` drafts a new-thread brief from a filtered view of history:
    /// non-steering user-invoked skill pairs are deliberately omitted because
    /// they would be stripped on any primary swap and must not survive inside
    /// the model-written handoff text. The live history is left unchanged until
    /// the normal compaction reset, where stale ledger rows are cleaned up.
    fn compact_brief_history(&self, history: &[Message]) -> Vec<Message> {
        let ids: std::collections::HashSet<String> = self
            .skill_pairs
            .iter()
            .filter(|pair| !pair.intentional_steer)
            .map(|pair| pair.call_id.clone())
            .collect();
        if ids.is_empty() {
            return history.to_vec();
        }
        history
            .iter()
            .filter(|msg| !message_references_call_id(msg, &ids))
            .cloned()
            .collect()
    }

    /// Build the imperative kickoff the swapped-in primary takes its first
    /// turn on after a `handoff` (implementation note).
    /// It restates the user's **salient originating request verbatim** (the
    /// most recent user turn in the shared root history — not the outgoing
    /// primary's paraphrase) and instructs the new primary to begin now with a
    /// tool call rather than a description of intent. This replaces the bare
    /// `` "Handed off to `{target}`." `` ack — a weaker model reads that ack as
    /// something to narrate and emits no tool call, terminating the loop.
    /// Token-efficient (§10): the restated request plus one imperative line,
    /// no boilerplate. Falls back to the imperative alone when no user turn is
    /// present (defensive — a handoff always follows a user request).
    fn handoff_kickoff(&self) -> String {
        let request = crate::engine::predict::turns_from_messages(&self.stack[0].history)
            .pop()
            .map(|t| t.user)
            .filter(|u| !u.trim().is_empty());
        let imperative = "Begin now. Act on this request directly — your first action must be a \
                          tool call, not a description of what you intend to do.";
        match request {
            Some(req) => format!("User's request:\n{}\n\n{imperative}", req.trim()),
            None => imperative.to_string(),
        }
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

    /// Annotate, in the wire history, every historical tool call whose tool the
    /// **final** (now-active) agent lacks
    /// (implementation note). Consumed at the user's
    /// next message — the same coalesce-and-defer boundary as
    /// [`Self::inject_pending_swap_marker`] — so the cached prefix stays
    /// byte-stable until the message is actually sent, and absence is evaluated
    /// once against the final agent's authoritative tool set
    /// ([`crate::engine::tool::ToolBox::get`], role-driven, not name-bound).
    ///
    /// For each matching call the note is prepended to its `tool_result`
    /// content (what the model reads as the call's outcome), e.g.
    /// `` [Called by `Build`, which had the `edit` tool. You (`Plan`) do not ``
    /// `` have this tool.] ``. Calls for tools the final agent still has are
    /// left unchanged; `task` (subagent) calls follow the same rule. Wire-only
    /// (GOALS §14) — the user transcript is untouched.
    ///
    /// Idempotent: an already-annotated result (carrying [`CROSS_AGENT_NOTE`])
    /// is skipped, so re-evaluation on a later message never double-stamps, and
    /// a re-swap that restores the tool never strips an earlier note (it stays
    /// historically accurate). Only meaningful at the root frame.
    fn annotate_absent_tool_calls(&mut self) {
        use crate::engine::message::{AssistantContent, OneOrMany};
        use rig::message::UserContent;
        if self.tool_call_owner.is_empty() {
            return;
        }
        let final_agent = self.active_agent().to_string();
        let root = &self.stack[0];
        // call_id → tool name, for every tool call in the root history, plus
        // the set of tool names absent from the final agent's authoritative
        // surface (`ToolBox::get`, role-driven). Built up front so the history
        // mutation below borrows nothing else from `self`.
        let mut absent_call: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for msg in &root.history {
            if let Message::Assistant { content, .. } = msg {
                for c in content.iter() {
                    if let AssistantContent::ToolCall(tc) = c
                        && root.agent.tools.get(&tc.function.name).is_none()
                    {
                        absent_call.insert(tc.id.clone(), tc.function.name.clone());
                    }
                }
            }
        }
        if absent_call.is_empty() {
            return;
        }
        let owners = &self.tool_call_owner;
        for msg in &mut self.stack[0].history {
            let Message::User { content } = msg else {
                continue;
            };
            // Skip well-formed messages with no annotatable tool_result fast.
            if !content.iter().any(
                |p| matches!(p, UserContent::ToolResult(tr) if absent_call.contains_key(&tr.id)),
            ) {
                continue;
            }
            let parts: Vec<UserContent> = content
                .iter()
                .map(|part| match part {
                    UserContent::ToolResult(tr) => {
                        let (Some(tool), Some(owner)) =
                            (absent_call.get(&tr.id), owners.get(&tr.id))
                        else {
                            return part.clone();
                        };
                        let note = format!(
                            "[Called by `{owner}`, which had the `{tool}` tool. You \
                             (`{final_agent}`) do not have this tool.] "
                        );
                        UserContent::ToolResult(prepend_tool_result_note(tr, &note))
                    }
                    other => other.clone(),
                })
                .collect();
            if let Ok(rebuilt) = OneOrMany::many(parts) {
                *content = rebuilt;
            }
        }
    }

    /// Apply an `Auto` → `Plan`/`Build` handoff at the idle boundary and
    /// return the `handoff` tool_result the swapped-in primary takes its next
    /// turn on. Emits the `handoff` tool_call timeline events, persists the
    /// new active agent (so a resume restarts on it), then swaps the
    /// root-frame primary in place through [`Self::swap_primary`] — the same
    /// machinery `/plan`/`/build` use, which preserves the root history so the
    /// chosen primary continues this same conversation. Sole owner of the
    /// handoff side effects so the live turn loop and the regression test
    /// drive byte-identical behavior. The tool_result is built **before** the
    /// swap so it lands in the shared root history `swap_primary` preserves.
    ///
    /// The tool_result the swapped-in primary takes its first turn on is the
    /// **imperative kickoff** ([`Self::handoff_kickoff`]) — the user's salient
    /// originating request restated verbatim plus a begin-now instruction —
    /// **not** a bare ack. A bare ack made weaker models narrate and emit no
    /// tool call, terminating the loop (`handoff-kickoff-and-skill-
    /// leak.md`). The **user-facing** timeline still shows the terse
    /// `` "Handed off to `{target}`." `` row (wire-vs-user split, GOALS §14):
    /// the model sees the kickoff (wire), the user sees the clean ack.
    async fn apply_handoff(
        &mut self,
        target: &str,
        task_call_id: String,
        task_function_call_id: Option<String>,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Message {
        let agent_name = self.stack.last().unwrap().agent.name.clone();
        let _ = tx
            .send(TurnEvent::ToolStart {
                agent: agent_name.clone(),
                call_id: task_call_id.clone(),
                tool: "handoff".to_string(),
                args: serde_json::json!({ "target": target }),
            })
            .await;
        // User-facing timeline row: terse ack. The model-facing tool_result is
        // the imperative kickoff (wire-vs-user split, GOALS §14).
        let display = format!("Handed off to `{target}`.");
        let _ = tx
            .send(TurnEvent::ToolEnd {
                agent: agent_name.clone(),
                call_id: task_call_id.clone(),
                tool: "handoff".to_string(),
                output: display.clone(),
                truncated: false,
                // The hint layer is `bash`-only.
                hint: None,
            })
            .await;
        // Build the kickoff from the user's originating request BEFORE the swap
        // strips any abandoned skill pair — `turns_from_messages` reads the
        // last plain user turn (the skill body is a tool-result round it skips),
        // so the restated request is the user's, not the skill's.
        let kickoff = self.handoff_kickoff();
        let next_prompt =
            Message::tool_result_with_call_id(task_call_id, task_function_call_id, kickoff.clone());
        // The `primary_swap` event records BOTH the user-facing `display` and
        // the model-facing wire `kickoff` (GOALS §14) with trigger `handoff`.
        let swapped = self
            .swap_primary_with_context(target, PrimarySwapContext::handoff(&display, &kickoff), tx)
            .await;
        if swapped && let Err(e) = self.session.set_active_agent(target) {
            tracing::warn!(error = %e, "set_active_agent on handoff failed");
        }
        next_prompt
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

    /// Snapshot-dedup the foreground agent's history. `auto` distinguishes
    /// the cache-aware auto-fire from a manual `/prune`. Emits `Pruned` +
    /// a refreshed `ContextProjection`. Never breaks a warm cache (the
    /// cache-cold or manual paths), so `cache_break = false`.
    async fn do_prune(&mut self, auto: bool, tx: &mpsc::Sender<TurnEvent>) {
        self.do_prune_inner(auto, false, None, None, tx).await;
    }

    /// Inner prune: `cache_break` flags a ctx%-threshold auto-prune that ran
    /// against a warm cache (implementation note), so the
    /// client surfaces the shared cache-break warning. Emits `Pruned` + a
    /// refreshed `ContextProjection`.
    async fn do_prune_inner(
        &mut self,
        auto: bool,
        cache_break: bool,
        trigger_reason: Option<&'static str>,
        precomputed_plan: Option<prune::DedupPlan>,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        // Capture the inputs the escalation telemetry needs before borrowing
        // `top` mutably (last reported usage + the model window).
        let window = self.active_model_context_length();
        let used_before = self.session.last_usage().map(|u| u.input_tokens);

        let depth = self.stack.len();
        let agent_name = self.active_agent().to_string();
        let top = self.stack.last_mut().expect("stack never empty");
        // Snapshot wire-token total + message count before the prune so
        // the timeline event (Part C) can record the before/after delta.
        let messages_before = top.history.len();
        let tokens_before = wire_token_total(&top.history);
        // This prune's targets (the bodies elided *this* call) — the
        // `original_event_id`s describing what was removed — and the
        // classifying reason (overlap-merge vs exact-identity vs mixed).
        let this_prune = precomputed_plan.unwrap_or_else(|| prune::dedup_plan(&top.history));
        let this_elided: Vec<String> = this_prune
            .targets
            .iter()
            .map(|t| t.elision.original_event_id.clone())
            .collect();
        let reason = classify_prune_reason(&this_prune).to_string();

        let applied = this_prune;
        prune::apply_plan(&mut top.history, &applied);
        for candidate in prune::condense_candidates(&top.history) {
            let hash =
                crate::db::compressed_results::compressed_result_hash(&candidate.original_body);
            match self.session.db.insert_compressed_tool_result(
                &hash,
                crate::db::compressed_results::NewCompressedToolResult {
                    session_id: self.session.id,
                    agent_id: &agent_name,
                    tool: &candidate.tool,
                    call_id: &candidate.call_id,
                    original_byte_len: candidate.original_body.len(),
                    compressed_byte_len: Some(candidate.condensed_body.len()),
                    created_at: chrono::Utc::now().timestamp(),
                    kind: "prune-boundary",
                    content: &candidate.original_body,
                },
            ) {
                Ok(()) => {
                    prune::apply_condensed_tool_result(&mut top.history, &candidate, &hash);
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        tool = %candidate.tool,
                        call_id = %candidate.call_id,
                        "prune-boundary compressed tool result store failed"
                    );
                }
            }
        }
        let bodies = applied.targets.len();
        let tokens_saved = applied.tokens_saved() as u64;
        let messages_after = top.history.len();
        let tokens_after = wire_token_total(&top.history);
        // The full live elided set (cumulative across prunes), so the TUI
        // dims every currently-elided body — not just this prune's targets.
        let elided = prune::current_elided_ids(&top.history);
        // Update the watermark so auto-prune short-circuits until the
        // foreground history grows again.
        self.prune_watermark.insert(depth, top.history.len());

        // Remaining context budget after this prune: model window − the
        // post-prune input-token estimate. The last reported usage is the
        // pre-prune prompt size; subtract this prune's wire saving to estimate
        // the post-prune prompt size. `None` when the window / usage is
        // unknown (ctx%-gated figures inert).
        let remaining_budget = match (window, used_before) {
            (Some(w), Some(used)) => {
                let after = used.saturating_sub(tokens_saved);
                Some(u64::from(w).saturating_sub(after))
            }
            _ => None,
        };

        // Record this auto-prune's effectiveness for the escalation policy
        // (root frame only — a subagent frame's prune is transient). Only when
        // the ctx%-gated figures are known.
        if auto
            && depth == 1
            && bodies > 0
            && let (Some(w), Some(used)) = (window, used_before)
        {
            let window_f = f64::from(w);
            self.note_prune_effectiveness(PruneEffectiveness {
                ctx_pct: used as f64 / window_f * 100.0,
                saved_pct: tokens_saved as f64 / window_f * 100.0,
            });
        }

        // Timeline event (Part C): record the prune so the export can
        // audit it. Only when something was actually elided — an empty
        // prune is not a meaningful timeline entry. Ordered immediately
        // before the next `inference_request` event by construction
        // (auto-prune fires right before a `turn`).
        if bodies > 0
            && let Err(e) = self.session.record_context_pruned(
                &agent_name,
                auto,
                messages_before,
                messages_after,
                tokens_before,
                tokens_after,
                &this_elided,
                &reason,
                tokens_saved,
                remaining_budget,
                trigger_reason,
            )
        {
            tracing::warn!(error = %e, "record context_pruned event failed");
        }

        // Persist the prune ledger so a later resume re-derives this exact
        // pruned form (implementation note). Only the
        // root frame's prune is resumable; an interactive subagent frame's
        // prune is transient (its frame is never resumed), so skip the
        // write there to avoid clobbering the root ledger.
        if depth == 1 {
            self.persist_prune_ledger();
            self.drop_stale_owner_ledgers();
        }

        let _ = tx
            .send(TurnEvent::Pruned {
                auto,
                bodies,
                tokens_saved,
                elided,
                trigger_reason: trigger_reason.map(str::to_string),
                cache_break,
            })
            .await;
        self.emit_context_projection(tx).await;
    }

    /// Record one auto-prune's effectiveness onto the rolling ledger, capped
    /// at the window the escalation predicate inspects
    /// (implementation note).
    fn note_prune_effectiveness(&mut self, e: PruneEffectiveness) {
        self.prune_effectiveness.push_back(e);
        while self.prune_effectiveness.len() > PRUNE_INEFFECTIVE_RUN {
            self.prune_effectiveness.pop_front();
        }
    }

    /// True when recent auto-prunes have been *ineffective* — the last
    /// [`PRUNE_INEFFECTIVE_RUN`] prunes each saved below
    /// [`PRUNE_INEFFECTIVE_SAVING_PCT`] of the window while ctx% rose strictly
    /// across them — so the next boundary should escalate to compaction rather
    /// than continue tiny snapshot prunes (implementation note
    /// Part B). Pure over the ledger so it is unit-testable.
    fn prune_is_ineffective(&self) -> bool {
        if self.prune_effectiveness.len() < PRUNE_INEFFECTIVE_RUN {
            return false;
        }
        let runs: Vec<&PruneEffectiveness> = self
            .prune_effectiveness
            .iter()
            .rev()
            .take(PRUNE_INEFFECTIVE_RUN)
            .collect();
        // Each of the last N prunes saved below the threshold.
        let all_small = runs
            .iter()
            .all(|e| e.saved_pct < PRUNE_INEFFECTIVE_SAVING_PCT);
        // ctx% climbed strictly across them (oldest → newest). `runs` is
        // newest-first, so compare adjacent pairs in reverse.
        let mut climbing = true;
        for pair in runs.windows(2) {
            // pair[0] is newer, pair[1] is older → newer must exceed older.
            if pair[0].ctx_pct <= pair[1].ctx_pct {
                climbing = false;
                break;
            }
        }
        all_small && climbing
    }

    fn record_auto_prune_skip(
        &self,
        agent_name: &str,
        trigger_reason: &str,
        plan: &prune::DedupPlan,
        tokens_saved: usize,
        skip_reason: &str,
        watermark_advanced: bool,
    ) {
        let data = serde_json::json!({
            "kind": "auto_prune_skipped",
            "skip_reason": skip_reason,
            "trigger_reason": trigger_reason,
            "tokens_saved": tokens_saved,
            "min_cold_savings_tokens": AUTO_PRUNE_MIN_COLD_SAVINGS_TOKENS,
            "targets": plan.targets.len(),
            "plan_reason": classify_prune_reason(plan),
            "watermark_advanced": watermark_advanced,
        });
        if let Err(e) = self.session.record_event(
            crate::db::session_log::SessionEventKind::AutoPruneDiagnostic,
            Some(agent_name),
            None,
            &data,
        ) {
            tracing::warn!(error = %e, "recording auto-prune diagnostic failed");
        }
    }

    /// Cache-aware auto-prune (GOALS §10 / implementation note):
    /// before an inference call, fire `/prune` with no user prompt when the
    /// foreground history has grown since the last prune, there is something
    /// prunable, and **either**
    ///
    /// - the cache-cold predicate holds (free pruning, unchanged), **or**
    /// - the ctx%-threshold branch holds (`ctx% > auto-prune ctx %` AND
    ///   `prunable% > auto-prune prunable %`), which may prune even on a warm
    ///   cache, accepting the cache bust to reclaim context.
    ///
    /// When the threshold branch fires against a warm cache the same
    /// cache-break warning the manual `/prune` surfaces is emitted via the
    /// `Pruned { cache_break }` flag. Returns `true` if a prune happened.
    async fn maybe_auto_prune(&mut self, tx: &mpsc::Sender<TurnEvent>) -> bool {
        if !self.at_safe_boundary() {
            return false;
        }
        let depth = self.stack.len();
        let history_len = self.stack.last().expect("stack never empty").history.len();
        // Short-circuit: nothing new since the last prune at this depth.
        // Checked before anything touching the layered config so the common
        // no-growth boundary stays a pure in-memory lookup.
        if self.prune_watermark.get(&depth).copied() == Some(history_len) {
            return false;
        }
        // One layered-config load feeds every resolve below (auto-prune
        // switch, cache config, context config) — `active_providers_config`
        // walks the on-disk config chain, so don't load it three times.
        let providers_cfg = self.active_providers_config();
        // Master switch: auto-prune off for this (provider, model) means no
        // automatic pruning at all — neither the cache-cold branch nor the
        // ctx%-threshold branch. Manual `/prune` is unaffected.
        if !Self::auto_prune_enabled_from(providers_cfg.as_ref()) {
            // Advance the watermark so we don't re-walk the config chain until
            // growth. Flipping auto-prune back on mid-session won't re-evaluate
            // until history grows past the watermark, matching the sibling
            // no-op branches (empty plan / below-min savings).
            self.prune_watermark.insert(depth, history_len);
            return false;
        }
        // Cache-cold? Resolve the active provider/model cache config and
        // evaluate the predicate. `upstream_bust = false` here: v1 has no
        // mid-prefix tool-result edit path that busts the anchor before a
        // send, so cases (a) and (b) carry the predicate.
        let cache = Self::cache_config_from(providers_cfg.as_ref());
        let secs = self.session.seconds_since_last_send();
        let cache_state = prune::cache_state(&cache, secs, false);

        // Is anything actually prunable? Avoid an empty Pruned event.
        let plan = {
            let top = self.stack.last().expect("stack never empty");
            prune::dedup_plan(&top.history)
        };
        if plan.is_empty() {
            // Advance the watermark so we don't re-walk until growth.
            self.prune_watermark.insert(depth, history_len);
            return false;
        }

        // The ctx%-threshold branch (inert when context_length is unknown):
        // prune above the configured ctx% AND prunable% even on a warm cache.
        let ctx_cfg = Self::context_config_from(providers_cfg.as_ref());
        let usage = self.session.last_usage();
        let metrics = context_metrics(
            self.active_model_context_length(),
            usage.map(|u| u.input_tokens),
            plan.tokens_saved() as u64,
        );
        let threshold_hit = metrics.is_some_and(|m| {
            m.ctx_pct > f64::from(ctx_cfg.auto_prune_pct)
                && m.prunable_pct > f64::from(ctx_cfg.auto_prune_prunable_pct)
        });

        let Some(trigger_reason) = auto_prune_trigger_reason(cache_state, threshold_hit) else {
            return false;
        };

        let tokens_saved = plan.tokens_saved();
        let cold_branch = !auto_prune_trigger_breaks_cache(trigger_reason);
        if tokens_saved == 0 || (cold_branch && tokens_saved < AUTO_PRUNE_MIN_COLD_SAVINGS_TOKENS) {
            self.prune_watermark.insert(depth, history_len);
            let skip_reason = if tokens_saved == 0 {
                "zero_savings"
            } else {
                "below_min_cold_savings"
            };
            let agent_name = self.active_agent().to_string();
            self.record_auto_prune_skip(
                &agent_name,
                trigger_reason,
                &plan,
                tokens_saved,
                skip_reason,
                true,
            );
            return false;
        }
        // Warm cache + threshold-driven prune → the cache anchor is broken;
        // surface the same warning the manual prune does.
        let cache_break = auto_prune_trigger_breaks_cache(trigger_reason);
        self.do_prune_inner(true, cache_break, Some(trigger_reason), Some(plan), tx)
            .await;
        true
    }

    /// Auto-compact trigger (implementation note): at or
    /// above the configured auto-compact ctx% the foreground context is
    /// compacted automatically via the existing `/compact` machinery — no
    /// prune-first step for the compact trigger (the prune threshold handles
    /// the cheaper reclaim below the compact line). Inert when
    /// `context_length` is unknown (ctx% uncomputable). Guarded by the same
    /// `at_safe_boundary` / watermark short-circuit as auto-prune so it can't
    /// loop. Returns `true` if a compaction was started.
    async fn maybe_auto_compact(&mut self, tx: &mpsc::Sender<TurnEvent>) -> bool {
        // One-shot: `/compact` hands off to a fresh session, so firing again
        // on this (now-abandoned) session would loop.
        if self.auto_compacted {
            return false;
        }
        if !self.at_safe_boundary() {
            return false;
        }
        // Only the foreground root frame is compactable at the boundary; a
        // deeper interactive subagent frame is never auto-compacted.
        if self.stack.len() != 1 {
            return false;
        }
        let ctx_cfg = self.resolve_context_config();
        let usage = self.session.last_usage();
        let Some(metrics) = context_metrics(
            self.active_model_context_length(),
            usage.map(|u| u.input_tokens),
            0,
        ) else {
            return false;
        };
        // Two triggers reach the same `/compact` machinery:
        //   1. ctx% at/above the configured auto-compact line (the existing
        //      hard ceiling), OR
        //   2. escalation: recent auto-prunes stayed ineffective while ctx%
        //      kept climbing (implementation note Part B) —
        //      tiny snapshot prunes aren't keeping context in budget, so stop
        //      churning them and compact now, below the hard line.
        let over_compact_line = metrics.ctx_pct >= f64::from(ctx_cfg.auto_compact_pct);
        let escalate = self.prune_is_ineffective();
        if !over_compact_line && !escalate {
            return false;
        }
        self.auto_compacted = true;
        self.do_compact(tx).await;
        true
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

    /// Assemble and apply a `/compact` handoff for the foreground agent.
    /// Prune-first (fixed ordering), draft the model brief, append the
    /// deterministic appendix, derive seed-tools, then reset the foreground
    /// context window in this same session.
    async fn do_compact(&mut self, tx: &mpsc::Sender<TurnEvent>) {
        use crate::engine::compact;

        // 0. Prune-first (lossless; denser transcript → tighter brief).
        self.do_prune(false, tx).await;

        // 1. Model brief from the foreground agent's current history.
        let brief = self.draft_brief(tx).await;

        // 2. Deterministic appendix from the runtime ledger.
        let calls = self
            .session
            .db
            .list_tool_calls_for_session(self.session.id)
            .unwrap_or_default();
        let pins = self.session.pinned_messages();
        let active_goal = self
            .session
            .db
            .current_session_goal(self.session.id, false)
            .ok()
            .flatten()
            .map(|g| {
                format!(
                    "- status: {}\n- objective: {}\n- tokens: {}/{}",
                    g.status.as_str(),
                    g.objective,
                    g.tokens_used,
                    g.token_budget
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "none".to_string())
                )
            });
        let mut appendix = compact::build_appendix(&calls, &self.cwd, &pins, &[], active_goal);
        if let Ok(overview) = self.session.db.task_todo_overview(self.session.id, 24) {
            appendix.task_overview = compact::render_task_todo_overview(&overview);
        }

        // 3. Seed-tools (read-only/idempotent; re-executed, not replayed).
        let seeds = compact::derive_seed_tools(&calls);
        let seed_tool_tokens: u64 = seeds
            .iter()
            .map(|s| crate::tokens::count(&s.args.to_string()) as u64)
            .sum();

        // 4. Assemble the review-ready handoff.
        let handoff = compact::assemble_handoff(&brief, &appendix);

        // 5. Reset the foreground model context in place.
        if let Some(top) = self.stack.last_mut() {
            top.history.clear();
            top.history.push(Message::user(handoff.clone()));
        }
        self.drop_stale_owner_ledgers();

        // Persist the seed-tool plan on this session for the follow-up
        // prompt's re-execution kickoff.
        if let Err(e) = self.session.db.set_seed_tools(self.session.id, &seeds) {
            tracing::warn!(error = %e, "compact: persisting seed tools failed");
        }

        // Timeline boundary: `/compact` reset this session in place.
        if let Err(e) = self.session.record_session_compacted(
            self.active_agent(),
            self.session.id,
            &self.session.short_id,
            seeds.len(),
            &brief,
        ) {
            tracing::warn!(error = %e, "record session_compacted event failed");
        }

        self.run_seed_tools(&seeds, tx).await;

        let _ = tx
            .send(TurnEvent::CompactReady {
                new_session_id: self.session.id,
                handoff,
                brief,
                seed_tool_count: seeds.len(),
                seed_tool_tokens,
            })
            .await;
    }

    /// Run one model round-trip asking the foreground agent to draft the
    /// self-contained handoff brief (T6.e step 1). Falls back to a terse
    /// placeholder if the model call fails so `/compact` always produces
    /// a usable handoff (the deterministic appendix is the real safety
    /// net).
    async fn draft_brief(&self, tx: &mpsc::Sender<TurnEvent>) -> String {
        let top = self.stack.last().expect("stack never empty");
        // Resolve the two `extended.*` compaction knobs from the config
        // chain (implementation note):
        // `compact_prompt` (the brief-prompt override) and `compact_model`
        // (the dedicated drafting model).
        let (extended, providers) = crate::auto_title::load_configs_for(&self.cwd);
        let prompt = Message::user(crate::engine::compact::brief_prompt(
            extended.compact_prompt.as_deref(),
        ));

        // Two-level model precedence: a configured `compact_model` (when it
        // resolves) drafts the brief; otherwise the active agent's own model.
        // A configured-but-unresolvable `compact_model` falls back to the
        // agent's model and surfaces a terse one-line notice — losing the
        // handoff is worse than using the wrong model (priority #1).
        let compact_model = match extended.compact_model_ref() {
            Some(model_ref) => match crate::engine::model::Model::from_ref_trusted_only(
                &providers,
                model_ref,
                self.redact.clone(),
                top.agent.model.trusted_only_flag(),
            ) {
                Ok(m) => Some(m),
                Err(e) => {
                    tracing::warn!(error = %e, model = %model_ref, "compact: compact_model failed to resolve; using active agent's model");
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: format!(
                                "compact_model `{model_ref}` unavailable; drafting the brief with the active agent's model."
                            ),
                        })
                        .await;
                    None
                }
            },
            None => None,
        };
        let model = compact_model.as_ref().unwrap_or(&top.agent.model);

        // Always-on capture (Part A): the `/compact` brief is an inference
        // call too, so persist its request body + a timeline event keyed by
        // a fresh round-trip id.
        let call_id = uuid::Uuid::new_v4();
        let brief_history = self.compact_brief_history(&top.history);
        match model
            .complete_captured(
                &top.agent.system,
                &brief_history,
                prompt,
                &[],
                top.agent.params.clone(),
                &top.agent.name,
                None,
                // The `/compact` brief is a short utility round-trip, not a
                // user-message turn; it isn't tied to the run's ctrl+c
                // cancel slot. A fresh never-cancelled token keeps the
                // signature uniform.
                &tokio_util::sync::CancellationToken::new(),
                None,
            )
            .await
        {
            Ok(((_, choice, usage), captured, _timing)) => {
                if let Err(e) = self.session.record_inference_request(
                    call_id,
                    &captured,
                    crate::db::session_log::InferenceRequestStatus::Completed,
                ) {
                    tracing::warn!(error = %e, "compact brief: record_inference_request failed");
                }
                // The `/compact` brief is background machinery, not a
                // foreground user turn: persist a utility-flagged
                // `inference_calls` row so the `/export debug` bundle routes
                // this request body into `inference_requests_utility/`.
                if let Some(u) = usage
                    && let Err(e) = self.session.record_usage_utility(call_id, u)
                {
                    tracing::warn!(error = %e, "compact brief: record_usage_utility failed");
                }
                let usage_json = usage.map(|u| {
                    serde_json::json!({
                        "input_tokens": u.input_tokens,
                        "output_tokens": u.output_tokens,
                        "cached_input_tokens": u.cached_input_tokens,
                    })
                });
                if let Err(e) = self.session.record_event(
                    crate::db::session_log::SessionEventKind::InferenceRequest,
                    Some(&top.agent.name),
                    Some(&call_id.to_string()),
                    &serde_json::json!({ "usage": usage_json, "purpose": "compact_brief" }),
                ) {
                    tracing::warn!(error = %e, "compact brief: record inference_request event failed");
                }
                let text = crate::engine::message::extract_text(&choice);
                if text.trim().is_empty() {
                    "(model produced no brief; rely on the state appendix below)".to_string()
                } else {
                    text
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "compact: brief generation failed");
                "(brief generation failed; rely on the state appendix below)".to_string()
            }
        }
    }

    /// Re-execute a `/compact` seed-tool plan into the foreground agent's
    /// initial context, *before* the first inference (T6.e). Each seed is
    /// a read-only / idempotent tool call (`read`, the read-only intel
    /// tools); we dispatch it fresh and fold the results into one
    /// synthetic user message prepended to history — so the fresh agent
    /// starts with the live working set without a round-trip, and never
    /// sees a stale snapshot. Tools the agent doesn't have, or that fail,
    /// are skipped (the brief/appendix still carry the context). A
    /// `ToolStart`/`ToolEnd` pair is emitted per seed so the cost is
    /// visible on the new agent's first turn.
    pub async fn run_seed_tools(
        &mut self,
        seeds: &[crate::engine::compact::SeedTool],
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        let agent = self.stack.last().expect("stack never empty").agent.clone();
        let ctx = crate::engine::tool::ToolCtx {
            agent_id: agent.name.clone(),
            llm_mode: agent.llm_mode,
            locks: self.locks.clone(),
            session: self.session.clone(),
            cwd: self.cwd.clone(),
            redact: self.redact.clone(),
            interrupts: self.interrupts.clone(),
            // Seed-tool re-execution runs before the first user turn; it
            // has no run-scoped cancel slot, so a fresh never-cancelled
            // token suffices.
            cancel: tokio_util::sync::CancellationToken::new(),
            // Seeds are read-only/idempotent and run before the approver
            // is consulted in earnest; a missing approver skips the
            // boundary prompt (never denies).
            approver: self.approver.clone(),
            // Seed re-exec runs read-only tools only; nothing defers or
            // re-seeds.
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            seeds: crate::engine::seed_collector::SeedCollector::new(),
            has_tree: agent.tools.get("tree").is_some(),
            has_bash: agent.tools.get("bash").is_some(),
            // Route a blocked `readlock`'s waiting indicator through this
            // run's turn-event stream (`readlock-wait-and-lock-expiry.md`).
            events: Some(tx.clone()),
            lsp: None,
            resource_scheduler: self.resource_scheduler.clone(),
            env_overlay: agent.env_overlay.clone(),
        };
        let mut blocks: Vec<String> = Vec::new();
        for seed in seeds {
            // Restrict defensively to read-only/idempotent tools and to
            // tools this agent actually has — never dispatch a write path.
            let Some(tool) = agent.tools.get(&seed.tool) else {
                continue;
            };
            let call_id = format!("seed-{}", uuid::Uuid::new_v4());
            let _ = tx
                .send(TurnEvent::ToolStart {
                    agent: agent.name.clone(),
                    call_id: call_id.clone(),
                    tool: seed.tool.clone(),
                    args: seed.args.clone(),
                })
                .await;
            let result = tool.call(seed.args.clone(), &ctx).await;
            let body = match result {
                Ok(out) => out.content,
                Err(e) => format!("Error: {e}"),
            };
            let _ = tx
                .send(TurnEvent::ToolEnd {
                    agent: agent.name.clone(),
                    call_id,
                    tool: seed.tool.clone(),
                    output: body.clone(),
                    truncated: false,
                    // The hint layer is `bash`-only.
                    hint: None,
                })
                .await;
            let label = crate::tui::agent_runner::short_args(&seed.args);
            blocks.push(format!(
                "<seed tool=\"{}\" {}>\n{}\n</seed>",
                seed.tool, label, body
            ));
        }
        if !blocks.is_empty() {
            let combined = format!(
                "[compaction handoff — re-executed working-set context; the live results follow]\n\n{}",
                blocks.join("\n\n")
            );
            // Prepend to the first user message rather than pushing a bare
            // user turn (which would put two user messages back-to-back).
            self.pending_seed_context = Some(combined);
        }
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

    /// Re-execute a list of read-only seeds against `agent`'s toolbox in
    /// `ctx`'s cwd and turn each into a native tool-call/result pair, sharing
    /// one `budget` so the combined output is capped deterministically (whole
    /// seeds dropped once the cap trips — never a half-written record). Both
    /// seed directions reuse this: child→parent ([`Self::inject_seeds`]) runs
    /// it against the **caller**'s agent/cwd and folds the pairs into the
    /// caller's transcript; parent→child ([`Self::prefill_child_seeds`]) runs
    /// it against the **child**'s agent/cwd and prepends the pairs to the
    /// child's initial history.
    ///
    /// Each pair is redaction-scrubbed and persisted as a tool-call audit row
    /// plus a timeline event (GOALS §14), exactly like a call the holder made
    /// itself (verbatim → `wire == original`, no recovery). Seeds naming a tool
    /// the holder doesn't actually hold are skipped (already filtered to
    /// read-only at parse time). A seed whose tool errors in `ctx`'s cwd is a
    /// **failed seed**: its `Error: …` body is injected as the result (so the
    /// holder sees the failure) and counted in the returned failure count —
    /// never a hard abort. When `tx` is `Some`, a `ToolStart`/`ToolEnd` pair is
    /// streamed per injected seed. Returns the native pairs split into the
    /// assistant tool calls and their matching `tool_result` user messages,
    /// plus how many seeds failed to execute.
    #[allow(clippy::type_complexity)]
    async fn execute_seeds_into_pairs(
        &self,
        seeds: &[crate::engine::compact::SeedTool],
        agent: &Agent,
        ctx: &crate::engine::tool::ToolCtx,
        budget: &mut crate::intel::budget::BudgetedWriter,
        tx: Option<&mpsc::Sender<TurnEvent>>,
    ) -> (
        Vec<crate::engine::message::ToolCall>,
        Vec<crate::engine::message::Message>,
        usize,
    ) {
        use crate::engine::message::{Message, OneOrMany, ToolCall};
        use rig::message::{ToolFunction, ToolResult, ToolResultContent, UserContent};

        let mut seed_calls: Vec<ToolCall> = Vec::new();
        let mut seed_results: Vec<Message> = Vec::new();
        let mut failed = 0usize;

        for seed in seeds {
            // Restrict to read-only tools the holder actually holds — never
            // dispatch a write path or a tool the holder can't see. (Parse-time
            // filtering already dropped non-read-only entries; this is the
            // hard gate.)
            if !crate::engine::compact::is_read_only_seed_tool(&seed.tool) {
                continue;
            }
            let Some(tool) = agent.tools.get(&seed.tool) else {
                continue;
            };
            let started = std::time::Instant::now();
            let result = tool.call(seed.args.clone(), ctx).await;
            let (body, hard_fail) = match result {
                Ok(out) => (out.content, false),
                // A seed that fails to execute (e.g. the path doesn't exist in
                // this cwd) is surfaced as a failed seed — the error body is
                // injected so the holder sees it — never a hard abort.
                Err(e) => (format!("Error: {e}"), true),
            };
            if hard_fail {
                failed += 1;
            }
            let duration_ms = started.elapsed().as_millis() as u64;
            // Reserve this seed's output against the shared budget. Drop the
            // whole seed (call + result) once the cap is reached.
            if !budget.write(&body) {
                break;
            }
            let call_id = format!("seed-{}", uuid::Uuid::new_v4());
            let provider_identity =
                crate::session::ToolCallProviderIdentity::synthetic_responses_call(&call_id);
            let provider_call_id = provider_identity.provider_call_id.clone();
            if let Some(tx) = tx {
                let _ = tx
                    .send(TurnEvent::ToolStart {
                        agent: agent.name.clone(),
                        call_id: call_id.clone(),
                        tool: seed.tool.clone(),
                        args: seed.args.clone(),
                    })
                    .await;
                let _ = tx
                    .send(TurnEvent::ToolEnd {
                        agent: agent.name.clone(),
                        call_id: call_id.clone(),
                        tool: seed.tool.clone(),
                        output: body.clone(),
                        truncated: false,
                        // The hint layer is `bash`-only.
                        hint: None,
                    })
                    .await;
            }
            // Persist the seed as a tool-call audit row + timeline event
            // (GOALS §14), exactly like a call the holder made itself: a seed
            // is emitted verbatim, so `wire == original` and there is no
            // recovery. Without this the injected pair would stream to the
            // live client but vanish from a session export.
            if let Err(e) = self.session.record_tool_call(crate::session::ToolCallRow {
                event_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                agent: agent.name.clone(),
                call_id: call_id.clone(),
                identity: provider_identity.clone(),
                tool: seed.tool.clone(),
                path: None,
                original_input_json: seed.args.clone(),
                wire_input_json: seed.args.clone(),
                recovery: crate::engine::repair::Recovery::Clean,
                hard_fail,
                output: body.clone(),
                truncated: false,
                duration_ms,
                llm_mode: agent.llm_mode,
                // Seed re-exec — not the §12 dispatch path; no repair fingerprint.
                shape_fingerprint: None,
                // The hint layer is `bash`-only; a seed re-exec never carries one.
                hint: None,
            }) {
                tracing::warn!(error = %e, tool = %seed.tool, "persisting seed tool_call failed");
            }
            if let Err(e) = self.session.record_event(
                crate::db::session_log::SessionEventKind::ToolCall,
                Some(&agent.name),
                Some(&call_id),
                &serde_json::json!({
                    "tool": seed.tool,
                    "original_input": seed.args,
                    "wire_input": seed.args,
                    "recovery_kind": Option::<&str>::None,
                    "recovery_stage": Option::<&str>::None,
                    "hard_fail": hard_fail,
                    "output": body,
                    "truncated": false,
                    "duration_ms": duration_ms,
                    "seed": true,
                    "provider_identity": {
                        "provider_item_id": provider_identity.provider_item_id,
                        "provider_call_id": provider_identity.provider_call_id,
                        "provider_call_id_source": provider_identity.provider_call_id_source,
                        "wire_api": provider_identity.wire_api,
                        "provider_family": provider_identity.provider_family,
                    },
                }),
            ) {
                tracing::warn!(error = %e, "recording seed timeline event failed");
            }
            seed_calls.push(ToolCall {
                id: call_id.clone(),
                call_id: provider_call_id.clone(),
                function: ToolFunction {
                    name: seed.tool.clone(),
                    arguments: seed.args.clone(),
                },
                signature: None,
                additional_params: None,
            });
            seed_results.push(Message::User {
                content: OneOrMany::one(UserContent::ToolResult(ToolResult {
                    id: call_id,
                    call_id: provider_call_id,
                    content: OneOrMany::one(ToolResultContent::text(body)),
                })),
            });
        }

        (seed_calls, seed_results, failed)
    }

    /// Re-execute caller→child read-only pre-seeds (`task.seed`,
    /// implementation note) in the **child**'s cwd and
    /// return native tool-call/result pairs to prepend to the child's initial
    /// history, *before* its first turn. The child therefore starts already
    /// holding the relevant reads instead of re-deriving them. Mirrors
    /// [`Self::inject_seeds`] (the child→parent direction), reusing
    /// [`Self::execute_seeds_into_pairs`]: same read-only gate, same
    /// re-execute-not-replay rule (the seed runs against the child's own
    /// toolbox in the child's cwd), same per-seed budget/drop, and the same
    /// failed-seed-not-abort surfacing.
    ///
    /// Returns the flattened `[assistant tool-calls][matching tool_results]`
    /// history prefix (empty when nothing seeded or nothing survived the
    /// budget) and whether the budget truncated (so the caller can append a
    /// model-visible note to the child's brief).
    async fn prefill_child_seeds(
        &self,
        seeds: &[crate::engine::compact::SeedTool],
        child: &Agent,
        child_cwd: &std::path::Path,
        tx: Option<&mpsc::Sender<TurnEvent>>,
    ) -> (Vec<crate::engine::message::Message>, bool) {
        use crate::engine::message::{AssistantContent, Message, OneOrMany};

        if seeds.is_empty() {
            return (Vec::new(), false);
        }
        // Re-execution against the child's own toolbox and cwd keeps the seed
        // honest (re-execute, never replay the caller's snapshot).
        let ctx = crate::engine::tool::ToolCtx {
            agent_id: child.name.clone(),
            llm_mode: child.llm_mode,
            locks: self.locks.clone(),
            session: self.session.clone(),
            cwd: child_cwd.to_path_buf(),
            redact: self.redact.clone(),
            interrupts: self.interrupts.clone(),
            cancel: tokio_util::sync::CancellationToken::new(),
            approver: self.approver.clone(),
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            seeds: crate::engine::seed_collector::SeedCollector::new(),
            has_tree: child.tools.get("tree").is_some(),
            has_bash: child.tools.get("bash").is_some(),
            // Route a blocked `readlock`'s waiting indicator through this
            // run's turn-event stream (`readlock-wait-and-lock-expiry.md`).
            events: tx.cloned(),
            lsp: None,
            resource_scheduler: self.resource_scheduler.clone(),
            env_overlay: child.env_overlay.clone(),
        };
        let mut budget = crate::intel::budget::BudgetedWriter::new(SEED_INJECTION_TOKEN_CAP);
        let (seed_calls, seed_results, _failed) = self
            .execute_seeds_into_pairs(seeds, child, &ctx, &mut budget, tx)
            .await;
        if seed_calls.is_empty() {
            return (Vec::new(), budget.is_truncated());
        }
        // One assistant turn carrying all surviving seed calls, followed by
        // their matching tool_results — a well-formed native prefix the child's
        // first inference sees as prior context it already gathered.
        let mut prefix: Vec<Message> = Vec::new();
        if let Ok(content) = OneOrMany::many(
            seed_calls
                .into_iter()
                .map(AssistantContent::ToolCall)
                .collect::<Vec<_>>(),
        ) {
            prefix.push(Message::Assistant { id: None, content });
            prefix.extend(seed_results);
        }
        (prefix, budget.is_truncated())
    }

    /// Inject a re-queryable subagent's seeded read-only results into the
    /// caller's transcript as native tool-call/result pairs (GOALS §3c). Each
    /// seed is **re-executed** in the caller's cwd (never replayed from the
    /// subagent's snapshot), capped under the subagent-report budget via
    /// [`crate::intel::budget::BudgetedWriter`] with a deterministic
    /// truncation note. The seed `ToolCall`s are folded into the SAME
    /// assistant turn that emitted the `task` call — so to the caller they
    /// look like calls it made itself, and the cached prefix is undisturbed —
    /// and their `tool_result`s are pushed before the task call's result.
    ///
    /// Reuses the seed-replay machinery shape from [`Self::run_seed_tools`]:
    /// restricted to tools the caller actually holds, read-only, and
    /// redaction-scrubbed before entering context.
    async fn inject_seeds(
        &mut self,
        seeds: &[crate::engine::compact::SeedTool],
        task_call_id: &str,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> bool {
        use crate::engine::message::{AssistantContent, Message, OneOrMany};

        let agent = self.stack.last().expect("stack never empty").agent.clone();
        let ctx = crate::engine::tool::ToolCtx {
            agent_id: agent.name.clone(),
            llm_mode: agent.llm_mode,
            locks: self.locks.clone(),
            session: self.session.clone(),
            cwd: self.cwd.clone(),
            redact: self.redact.clone(),
            interrupts: self.interrupts.clone(),
            cancel: tokio_util::sync::CancellationToken::new(),
            approver: self.approver.clone(),
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            seeds: crate::engine::seed_collector::SeedCollector::new(),
            has_tree: agent.tools.get("tree").is_some(),
            has_bash: agent.tools.get("bash").is_some(),
            // Route a blocked `readlock`'s waiting indicator through this
            // run's turn-event stream (`readlock-wait-and-lock-expiry.md`).
            events: Some(tx.clone()),
            lsp: None,
            resource_scheduler: self.resource_scheduler.clone(),
            env_overlay: agent.env_overlay.clone(),
        };

        // Token-budget the combined seed output deterministically: one
        // `BudgetedWriter` across all seeds, dropping whole seeds once the cap
        // is reached (atomic, sticky — never a half-written record).
        let mut budget = crate::intel::budget::BudgetedWriter::new(SEED_INJECTION_TOKEN_CAP);
        let (seed_calls, seed_results, _failed) = self
            .execute_seeds_into_pairs(seeds, &agent, &ctx, &mut budget, Some(tx))
            .await;

        if seed_calls.is_empty() {
            return budget.is_truncated();
        }

        // Fold the seed `ToolCall`s into the caller's most recent assistant
        // message (the turn that emitted the `task` call). This keeps them on
        // the same turn the model already produced — cache-safe and native —
        // rather than synthesizing a fresh assistant turn. The matching
        // `tool_result`s are pushed before the task call's result (delivered
        // as `next_prompt`), so every tool call in the turn is answered.
        let history = &mut self.stack.last_mut().expect("stack never empty").history;
        let mut folded = false;
        if let Some(Message::Assistant { content, .. }) = history.last_mut() {
            let has_task_call = content
                .iter()
                .any(|c| matches!(c, AssistantContent::ToolCall(tc) if tc.id == task_call_id));
            if has_task_call {
                let mut parts: Vec<AssistantContent> = content.iter().cloned().collect();
                for call in &seed_calls {
                    parts.push(AssistantContent::ToolCall(call.clone()));
                }
                if let Ok(merged) = OneOrMany::many(parts) {
                    *content = merged;
                    folded = true;
                }
            }
        }
        if !folded {
            // Defensive fallback (the assistant turn wasn't where we expected):
            // push a fresh assistant turn carrying just the seed calls so the
            // pairs are still well-formed.
            if let Ok(content) = OneOrMany::many(
                seed_calls
                    .iter()
                    .cloned()
                    .map(AssistantContent::ToolCall)
                    .collect::<Vec<_>>(),
            ) {
                history.push(Message::Assistant { id: None, content });
            }
        }
        for msg in seed_results {
            history.push(msg);
        }
        budget.is_truncated()
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

    /// Validate a parent's requested `task.skill_seed` names against the
    /// seedable set ([`Self::active_skills`]) and build the
    /// seeded-skill block to prepend to the child's brief
    /// (implementation note).
    ///
    /// Host-side validation (validate, don't trust the model): a requested name
    /// that is genuinely active (user-invoked OR auto-injected) contributes its
    /// instructions + delegation framing; a name that was never invoked is
    /// **deterministically stripped** and named in a model-visible note so the
    /// child knows the parent's claim of an active skill was dropped — not a
    /// hard error that aborts the delegation. Returns the text to prepend to
    /// the brief (empty when nothing was requested and nothing was stripped).
    ///
    /// The returned block is woven into the child's brief only — it never enters
    /// [`Self::active_skills`] or the root history, so the seeded skill is
    /// scoped to this child's run and does not masquerade as the child's own
    /// user instruction beyond it.
    fn seed_skills_block(&self, requested: &[String], child_agent: &str) -> String {
        // De-dup requested names (trim + first-seen order) so a model that
        // names a skill twice doesn't double-inject.
        let mut wanted: Vec<&str> = Vec::new();
        for name in requested {
            let name = name.trim();
            if !name.is_empty() && !wanted.contains(&name) {
                wanted.push(name);
            }
        }
        if wanted.is_empty() {
            return String::new();
        }

        let mut seeded: Vec<(&str, &str)> = Vec::new();
        let mut stripped: Vec<&str> = Vec::new();
        for name in wanted {
            match self.active_skills.iter().find(|(n, _)| n == name) {
                Some((n, body)) => seeded.push((n.as_str(), body.as_str())),
                None => stripped.push(name),
            }
        }

        let mut out = String::new();
        for (name, body) in &seeded {
            out.push_str(&format!(
                "We are working on skill `{name}`, and this delegation is part of \
                 resolving it. Its instructions and framing govern what `{child_agent}` \
                 should do for this task — they take precedence over your baked-in \
                 default behavior where they differ (your tool discipline still \
                 holds). Skill `{name}`:\n\n{body}\n\n---\n\n"
            ));
        }
        if !stripped.is_empty() {
            // Model-visible correction (not a hard error): the parent named
            // a skill that isn't active in its context, so the host dropped it.
            let names = stripped.join("`, `");
            out.push_str(&format!(
                "[note: the seeded skill(s) `{names}` were dropped because they are not \
                 active in the delegating agent's context; only a skill the parent \
                 actually invoked (or that was auto-injected) can be seeded into a \
                 child.]\n\n"
            ));
        }
        out
    }

    /// Synthesize a deterministic `skill` tool call for a user-issued skill
    /// slash command (`/<skill-name>` / `/skill <name>`,
    /// implementation note) and fold it into the foreground
    /// frame's history as a native call/result pair, *before* the first
    /// inference of this turn.
    ///
    /// This is the whole point of the feature (priority #1): a weaker model
    /// may not follow through on a tool call just because a message suggests
    /// one, so the harness invokes the skill itself. It reuses the single
    /// `skill`-tool loading path (`crate::tools::skill::SkillTool`) — body
    /// loading + the frontmatter `model:` override come for free — and the
    /// wire-vs-user transcript machinery: the call is recorded with
    /// `wire_input == original_input` and `Recovery::Clean` (a verbatim
    /// synthesized call, no repair), exactly like a seeded call the caller
    /// made itself. An unknown skill name surfaces the tool's own
    /// `invalid_input` error as the recorded result (never a silent no-op).
    async fn seed_forced_skill(&mut self, skill_name: &str, tx: &mpsc::Sender<TurnEvent>) {
        use crate::engine::message::{AssistantContent, Message, OneOrMany, ToolCall};
        use rig::message::{ToolFunction, ToolResult, ToolResultContent, UserContent};

        let agent = self.stack.last().expect("stack never empty").agent.clone();
        let Some(tool) = agent.tools.get("skill") else {
            // No `skill` tool on this agent (shouldn't happen for the
            // interactive front-door agents) — surface a notice rather than
            // silently dropping the user's explicit invocation.
            let _ = tx
                .send(TurnEvent::Notice {
                    text: format!(
                        "skill `{skill_name}` not invoked: this agent has no `skill` tool"
                    ),
                })
                .await;
            return;
        };

        let args = serde_json::json!({ "name": skill_name });
        let ctx = crate::engine::tool::ToolCtx {
            agent_id: agent.name.clone(),
            llm_mode: agent.llm_mode,
            locks: self.locks.clone(),
            session: self.session.clone(),
            cwd: self.cwd.clone(),
            redact: self.redact.clone(),
            interrupts: self.interrupts.clone(),
            cancel: tokio_util::sync::CancellationToken::new(),
            approver: self.approver.clone(),
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            seeds: crate::engine::seed_collector::SeedCollector::new(),
            has_tree: agent.tools.get("tree").is_some(),
            has_bash: agent.tools.get("bash").is_some(),
            // Route a blocked `readlock`'s waiting indicator through this
            // run's turn-event stream (`readlock-wait-and-lock-expiry.md`).
            events: Some(tx.clone()),
            lsp: None,
            resource_scheduler: self.resource_scheduler.clone(),
            env_overlay: agent.env_overlay.clone(),
        };

        let started = std::time::Instant::now();
        let result = tool.call(args.clone(), &ctx).await;
        let (body, hard_fail) = match result {
            Ok(out) => (out.content, false),
            // An unknown/ambiguous skill surfaces the tool's invalid-input
            // error as the recorded result — clear, never a silent no-op.
            Err(e) => (format!("Error: {e}"), true),
        };
        // Record a successfully-loaded user-invoked skill in the seedable set
        // so a later `task.skill_seed` naming it passes host validation
        // (implementation note). The skill tool's output is
        // `Skill \`name\`:\n\n<rendered body>`; strip that header so the seeded
        // payload carries the instructions, not the wrapper line.
        if !hard_fail {
            let seed_body = body
                .strip_prefix(&format!("Skill `{skill_name}`:\n\n"))
                .unwrap_or(&body);
            self.record_active_skill(skill_name, seed_body);
        }
        let duration_ms = started.elapsed().as_millis() as u64;

        let call_id = format!("skillslash-{}", uuid::Uuid::new_v4());
        let provider_identity =
            crate::session::ToolCallProviderIdentity::synthetic_responses_call(&call_id);
        let provider_call_id = provider_identity.provider_call_id.clone();
        let _ = tx
            .send(TurnEvent::ToolStart {
                agent: agent.name.clone(),
                call_id: call_id.clone(),
                tool: "skill".to_string(),
                args: args.clone(),
            })
            .await;
        let _ = tx
            .send(TurnEvent::ToolEnd {
                agent: agent.name.clone(),
                call_id: call_id.clone(),
                tool: "skill".to_string(),
                output: body.clone(),
                truncated: false,
                // The hint layer is `bash`-only.
                hint: None,
            })
            .await;

        // Persist the synthesized call as a tool-call audit row + timeline
        // event (GOALS §14), exactly like a call the agent made itself: it is
        // emitted verbatim, so `wire == original` and there is no recovery.
        if let Err(e) = self.session.record_tool_call(crate::session::ToolCallRow {
            event_id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: agent.name.clone(),
            call_id: call_id.clone(),
            identity: provider_identity.clone(),
            tool: "skill".to_string(),
            path: None,
            original_input_json: args.clone(),
            wire_input_json: args.clone(),
            recovery: crate::engine::repair::Recovery::Clean,
            hard_fail,
            output: body.clone(),
            truncated: false,
            duration_ms,
            llm_mode: agent.llm_mode,
            // Synthesized clean skill-slash call — never goes through §12 repair.
            shape_fingerprint: None,
            // The hint layer is `bash`-only; a skill-slash call never carries one.
            hint: None,
        }) {
            tracing::warn!(error = %e, "persisting skill-slash tool_call failed");
        }
        if let Err(e) = self.session.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some(&agent.name),
            Some(&call_id),
            &serde_json::json!({
                "tool": "skill",
                "original_input": args,
                "wire_input": args,
                "recovery_kind": Option::<&str>::None,
                "recovery_stage": Option::<&str>::None,
                "hard_fail": hard_fail,
                "output": body,
                "truncated": false,
                "duration_ms": duration_ms,
                "skill_slash": true,
                "provider_identity": {
                    "provider_item_id": provider_identity.provider_item_id,
                    "provider_call_id": provider_identity.provider_call_id,
                    "provider_call_id_source": provider_identity.provider_call_id_source,
                    "wire_api": provider_identity.wire_api,
                    "provider_family": provider_identity.provider_family,
                },
            }),
        ) {
            tracing::warn!(error = %e, "recording skill-slash timeline event failed");
        }

        // Fold the call/result into the foreground frame's history as a
        // native pair so the next inference carries the skill body. Pushed as
        // a fresh assistant turn (carrying just this call) followed by its
        // tool_result — well-formed regardless of what preceded it.
        let call = ToolCall {
            id: call_id.clone(),
            call_id: provider_call_id.clone(),
            function: ToolFunction {
                name: "skill".to_string(),
                arguments: args,
            },
            signature: None,
            additional_params: None,
        };
        let history = &mut self.stack.last_mut().expect("stack never empty").history;
        history.push(Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(call)),
        });
        history.push(Message::User {
            content: OneOrMany::one(UserContent::ToolResult(ToolResult {
                id: call_id.clone(),
                call_id: provider_call_id,
                content: OneOrMany::one(ToolResultContent::text(body)),
            })),
        });

        // Record ownership so a later primary swap can strip this pair if the
        // owning primary is swapped away without acting on it
        // (implementation note). Only the root frame's
        // primary owns user-invoked skills (slash commands arrive at idle on
        // the root); never set `intentional_steer` today.
        self.skill_pairs.push(SkillPair {
            call_id: call_id.clone(),
            owner: agent.name.clone(),
            intentional_steer: false,
        });
        if let Err(e) =
            self.session
                .db
                .save_skill_pair(self.session.id, &call_id, &agent.name, false)
        {
            tracing::warn!(error = %e, "persisting skill-pair ownership failed");
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

    /// Run a job event as a late-arriving turn in **main** context. A
    /// loop-iteration-due event runs the loop's prompt as a real turn (and
    /// reports back so the authority schedules the next tick); a terminal
    /// completion injects the budget-capped result, then surfaces any
    /// fork-emitted spawn requests for the model to decide on.
    async fn run_job_event(
        &mut self,
        event: ScheduleEvent,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<()> {
        match event {
            ScheduleEvent::LoopIterationDue { job_id, prompt } => {
                let framed = format!("[loop {job_id}] {prompt}");
                self.run_user_input(UserSubmission::text(framed), input_rx, tx)
                    .await?;
                // The iteration's turn finished — advance the schedule.
                self.schedule.iteration_finished(&job_id);
            }
            ScheduleEvent::Completed {
                job_id,
                label,
                kind,
                result,
                failed,
                requests,
            } => {
                self.schedule.mark_completed(&job_id);
                // A recursive `Swarm` subagent finished (GOALS §24): free
                // its concurrency slot and start the next queued spawn, before
                // anything else, so the global cap accounting stays tight even
                // if the injected turn below is long-running. Done here on the
                // main thread — the authority is the single scheduler.
                if matches!(kind, crate::engine::schedule::ScheduleKind::Swarm) {
                    self.schedule.swarm_completed();
                }
                // UI marker for the strip / transcript.
                let _ = tx
                    .send(TurnEvent::ScheduleCompleted {
                        job_id: job_id.clone(),
                        label: label.clone(),
                        kind: kind.as_str().to_string(),
                        failed,
                    })
                    .await;
                // Flag the needs-attention queue on every job end (GOALS
                // §22) so a detached client still sees it on reconnect.
                let note = if failed {
                    format!("async {} `{}` failed", kind.as_str(), label)
                } else {
                    format!("async {} `{}` completed", kind.as_str(), label)
                };
                if let Err(e) =
                    self.session
                        .db
                        .raise_interrupt(self.session.id, "schedule", &note, None)
                {
                    tracing::warn!(error = %e, "raising needs_attention on job end failed");
                }
                // Inject the budget-capped result as a late-arriving turn.
                // The header names the originating `job_id` (the same `job-…`
                // string `loop.cancel` / `TurnEvent::ScheduleCompleted` use) so the
                // model has an unambiguous referent — a late delivery may land
                // turns away from its trigger (implementation note).
                let mut injected =
                    format!("{}\n{result}", async_result_header(kind.as_str(), &job_id));
                // Surface any fork-emitted spawn requests (anti-runaway:
                // forks request, main decides). The model sees them and
                // can re-issue a `schedule` call to honour them.
                if !requests.is_empty() {
                    injected.push_str(
                        "\n\nThis loop requested new scheduled work (not started — you decide):",
                    );
                    for req in &requests {
                        injected.push_str(&format!("\n- {}", req.summary()));
                    }
                }
                // Carry the `job_id` on the submission so the recorded
                // `user_message` delivery event stamps `data.job_id`,
                // attributing the delivery to its originating job. The body
                // still flows through `scrub` — redaction stays non-bypassable.
                self.run_user_input(
                    UserSubmission {
                        kind: UserSubmissionKind::User,
                        text: injected,
                        images: Vec::new(),
                        forced_skill: None,
                        origin_principal: None,
                        job_id: Some(job_id.clone()),
                        preflight_cleaned: None,
                        queue_item_ids: Vec::new(),
                        queue_target: None,
                    },
                    input_rx,
                    tx,
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Dispatch a `schedule` meta-tool action against the authority and return
    /// the tool-result string the model sees. Thin wrapper over
    /// [`Self::dispatch_schedule_action_repaired`] that drops the §14 recovery
    /// surface — the production path ([`TurnOutcome::ScheduleAction`]) needs the
    /// full surface, so this convenience form is used only by tests.
    #[cfg(test)]
    async fn dispatch_schedule_action(&mut self, args: &serde_json::Value) -> Result<String> {
        Ok(self.dispatch_schedule_action_repaired(args).await?.output)
    }

    /// Dispatch a `schedule` meta-tool action, running the §12
    /// validate-then-repair contract on the per-action `args` first, and
    /// return the result text alongside the §14 recovery surface (the
    /// repaired wire `{action, args}` payload + the recovery the row should
    /// record). The single async-job authority lives here on the driver
    /// (GOALS §22), which is why the engine routes `schedule` calls back via
    /// [`TurnOutcome::ScheduleAction`] rather than dispatching them inline.
    ///
    /// The per-action schemas ([`crate::engine::schedule::schemas`]) are hidden
    /// from the model; the public `schedule` schema stays `{action, args}`. We
    /// validate the per-action `args` against its hidden schema, repair on
    /// failure through the same [`crate::engine::repair::repair`] machinery
    /// the top-level tool dispatcher uses, then hand the (possibly-repaired)
    /// `args` to the [`crate::engine::schedule::spec`] parser. A repair that
    /// can't validate falls through to the parser, which produces the same
    /// error wording it does today (out of scope to improve here).
    async fn dispatch_schedule_action_repaired(
        &mut self,
        args: &serde_json::Value,
    ) -> Result<ScheduleDispatch> {
        use crate::engine::repair::repair;
        use crate::engine::schedule::schemas::schema_for;
        use crate::tools::schedule::split_action;

        let (action, mut action_args) = split_action(args)?;

        // Per-action validate → repair → re-validate (§12), keyed by the
        // hidden per-action schema. A clean call is byte-identical; a
        // repairable malformation (e.g. `limit:"1"`) is coerced; an
        // unrecoverable call still flows to the parser below (same error).
        let schema = schema_for(action);
        let recovery = repair(&mut action_args, &schema, "schedule").recovery;

        // The §14 wire payload reflects the repaired sub-args so the audit
        // row's `wire_input` shows the canonical form the parser consumed.
        let wire_args = serde_json::json!({
            "action": action.as_str(),
            "args": action_args.clone(),
        });

        let output = self.run_job_action(action, &action_args).await?;
        Ok(ScheduleDispatch {
            output,
            recovery,
            wire_args,
        })
    }

    /// Execute a `schedule` action against the authority with already-validated,
    /// repaired per-action `action_args`, returning the model-facing result
    /// text. Split out of [`Self::dispatch_schedule_action_repaired`] so the
    /// repair pass owns the §14 surface and this method owns the dispatch.
    async fn run_job_action(
        &mut self,
        action: crate::engine::schedule::ScheduleAction,
        action_args: &serde_json::Value,
    ) -> Result<String> {
        use crate::engine::schedule::{ScheduleAction, ScheduleKind};

        match action {
            ScheduleAction::LoopStart => {
                if self.schedule.at_capacity() {
                    anyhow::bail!(
                        "max concurrent scheduled tasks reached ({}); cancel one before starting another",
                        self.schedule.max_concurrent
                    );
                }
                let parsed = crate::engine::schedule::parse_loop_start(action_args)?;
                let kind = parsed.kind();
                let limit = parsed.limit;
                let limit_defaulted = parsed.limit_defaulted;
                if limit.is_none() {
                    self.ensure_unbounded_loop_allowed().await?;
                }
                let job_id = if parsed.keep_in_context {
                    self.schedule.start_loop_in_context(parsed)
                } else {
                    self.schedule.start_loop_forked(parsed)
                };
                let noun = if kind == ScheduleKind::Timer {
                    "timer"
                } else {
                    "loop"
                };
                Ok(crate::engine::schedule::loop_start_message(
                    noun,
                    &job_id,
                    limit,
                    limit_defaulted,
                ))
            }
            ScheduleAction::LoopCancel => {
                let parsed = crate::engine::schedule::parse_loop_cancel(action_args)?;
                if self.schedule.cancel(&parsed.job_id) {
                    Ok(format!("cancelled `{}`", parsed.job_id))
                } else {
                    Ok(format!("no live job `{}`", parsed.job_id))
                }
            }
            ScheduleAction::BackgroundStart => {
                if self.schedule.at_capacity() {
                    anyhow::bail!(
                        "max concurrent scheduled tasks reached ({}); cancel one before starting another",
                        self.schedule.max_concurrent
                    );
                }
                let parsed = crate::engine::schedule::parse_background_start(action_args)?;
                let job_id = self.schedule.start_background(parsed);
                Ok(format!(
                    "started background `{job_id}` — tail with schedule(action=\"background.tail\", args={{\"job_id\":\"{job_id}\"}})"
                ))
            }
            ScheduleAction::BackgroundTail => {
                let parsed = crate::engine::schedule::parse_background_tail(action_args)?;
                match self.schedule.background_handle(&parsed.job_id) {
                    Some(handle) => Ok(handle.tail(parsed.lines, &self.redact)),
                    None => Ok(format!("no live background `{}`", parsed.job_id)),
                }
            }
            ScheduleAction::BackgroundCancel => {
                let parsed = crate::engine::schedule::parse_background_cancel(action_args)?;
                if self.schedule.cancel(&parsed.job_id) {
                    Ok(format!("cancelled background `{}`", parsed.job_id))
                } else {
                    Ok(format!("no live background `{}`", parsed.job_id))
                }
            }
            ScheduleAction::List => {
                let snap = self.schedule.snapshot();
                let running_swarm = self.schedule.running_swarm();
                let queued_swarm = self.schedule.queued_swarm();
                let scheduled: Vec<serde_json::Value> = snap
                    .into_iter()
                    .map(|j| {
                        serde_json::json!({
                            "job_id": j.job_id,
                            "kind": j.kind.as_str(),
                            "label": j.label,
                            "status": j.status.as_str(),
                            "executions_completed": j.iteration,
                            "execution_limit": j.limit,
                        })
                    })
                    .collect();
                Ok(serde_json::json!({
                    "scheduled": scheduled,
                    "swarm": {
                        "running": running_swarm,
                        "queued": queued_swarm,
                    }
                })
                .to_string())
            }
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

    fn record_schedule_tool_call(&self, row: ScheduleToolCallRecord) {
        // A `schedule` action is dispatched to the main-thread authority, not
        // through the ordinary tool-dispatch path, so — unlike every other tool
        // — it never wrote a `tool_call` row to the export timeline; the export
        // (which reads `session_events`) showed only failed bash/mcp detours,
        // never the successful native call (implementation note,
        // §5). Mirror the ordinary-tool pattern: persist BOTH the
        // `tool_call_events` row (`/stats`, history) AND a `tool_call`
        // `session_events` row (the export's dispatch record).
        let (recovery_kind, recovery_stage) = row.recovery.db_fields();
        if let Err(e) = self.session.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some(&row.agent),
            Some(&row.call_id),
            &serde_json::json!({
                "tool": "schedule",
                "original_input": row.original_input_json,
                "wire_input": row.wire_input_json,
                "recovery_kind": recovery_kind,
                "recovery_stage": recovery_stage,
                "hard_fail": row.hard_fail,
                "output": row.output,
                "truncated": false,
                "duration_ms": row.duration_ms,
            }),
        ) {
            tracing::warn!(error = %e, "recording schedule timeline event failed");
        }
        if let Err(e) = self.session.record_tool_call(crate::session::ToolCallRow {
            event_id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: row.agent,
            call_id: row.call_id,
            identity: crate::session::ToolCallProviderIdentity::default(),
            tool: "schedule".to_string(),
            path: None,
            original_input_json: row.original_input_json,
            wire_input_json: row.wire_input_json,
            recovery: row.recovery,
            hard_fail: row.hard_fail,
            output: row.output,
            truncated: false,
            duration_ms: row.duration_ms,
            llm_mode: row.llm_mode,
            // The schedule meta-tool's fixed minimal-schema repair fingerprint is not
            // threaded through `ScheduleToolCallRecord`; the §12 fingerprint telemetry
            // covers the per-tool dispatch path.
            shape_fingerprint: None,
            // The hint layer is `bash`-only; a `schedule` call never carries one.
            hint: None,
        }) {
            tracing::warn!(error = %e, "persisting schedule tool_call_event failed");
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

    fn persist_delegation_payload(
        &self,
        task_call_id: &str,
        task_function_call_id: Option<&str>,
        parent_agent: &str,
        label: &str,
        child_agent: &str,
        prompt: &str,
    ) -> Result<String> {
        let prompt = prompt.to_string();
        self.session
            .db
            .insert_task_delegation_payload(
                crate::db::task_delegation_payloads::NewTaskDelegationPayload {
                    task_call_id,
                    function_call_id: task_function_call_id,
                    parent_session_id: self.session.id,
                    parent_agent,
                    label,
                    child_agent,
                    prompt: &prompt,
                },
            )
            .with_context(|| {
                format!("persisting task delegation payload `{task_call_id}:{label}`")
            })?;
        let loaded = self
            .session
            .db
            .load_task_delegation_payload(task_call_id, label)
            .with_context(|| format!("loading task delegation payload `{task_call_id}:{label}`"))?;
        Ok(loaded.body)
    }

    fn delegation_payload_delivery(
        &self,
        task_call_id: &str,
        label: &str,
        prompt: &str,
        retrieval_allowed: bool,
    ) -> Result<(Vec<Message>, String)> {
        let row = self
            .session
            .db
            .task_delegation_payload(task_call_id, label)?
            .with_context(|| format!("task delegation payload `{task_call_id}:{label}` missing"))?;
        if row.prompt_byte_len <= DELEGATION_PAYLOAD_DIRECT_LIMIT_BYTES {
            self.session
                .db
                .mark_task_delegation_payload_delivered(task_call_id, label)?;
            return Ok((Vec::new(), prompt.to_string()));
        }
        if !retrieval_allowed {
            bail!(DELEGATION_PAYLOAD_REFUSAL);
        }
        let history = delegation_payload_retrieval_history(&row, prompt);
        self.session
            .db
            .mark_task_delegation_payload_delivered(task_call_id, label)?;
        Ok((history, delegation_payload_reference_prompt(&row)))
    }

    async fn run_single_noninteractive_task_backgroundable(
        &mut self,
        mut task: SingleNoninteractiveTask,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<Message> {
        let task_call_id = task.task_call_id.clone();
        let task_function_call_id = task.task_function_call_id.clone();
        let resolved_cwd_display = task.child_cwd.resolved_display();
        let task_args_json = serde_json::to_string(&serde_json::json!({
            "child_agent": &task.child_agent,
            "model": model_selector_json(&task.model),
            "why": &task.why,
            "resume_handle": &task.resume_handle,
            "requested_cwd": task.child_cwd.requested_json(),
            "resolved_cwd": &resolved_cwd_display,
            "todo_ids": &task.todo_ids,
            "skill_seed": &task.skill_seed,
        }))
        .ok();
        let parent_agent = self.stack.last().unwrap().agent.name.clone();
        if let Err(e) = self.session.db.upsert_task_delegation_job(
            self.session.id,
            &task_call_id,
            task_function_call_id.as_deref(),
            &parent_agent,
            task_args_json.as_deref(),
            &[crate::db::task_delegations::DelegationChildInit {
                label: "default",
                child_agent: &task.child_agent,
                model: model_selector_display(&task.model).as_deref(),
                output_dir: None,
                requested_cwd: task.child_cwd.requested_json(),
                resolved_cwd: Some(&resolved_cwd_display),
                todo_ids_json: None,
            }],
        ) {
            tracing::warn!(error = %e, task_call_id, "persist single task delegation job failed");
            return Ok(Message::tool_result_with_call_id(
                task_call_id,
                task_function_call_id,
                prepend_task_repair_notes(
                    DELEGATION_PAYLOAD_REFUSAL.to_string(),
                    &task.repair_notes,
                ),
            ));
        }
        match self.persist_delegation_payload(
            &task_call_id,
            task_function_call_id.as_deref(),
            &parent_agent,
            "default",
            &task.child_agent,
            &task.brief,
        ) {
            Ok(loaded) => task.brief = loaded,
            Err(e) => {
                tracing::warn!(error = %e, task_call_id, "persist single task delegation payload failed");
                return Ok(Message::tool_result_with_call_id(
                    task_call_id,
                    task_function_call_id,
                    prepend_task_repair_notes(
                        DELEGATION_PAYLOAD_REFUSAL.to_string(),
                        &task.repair_notes,
                    ),
                ));
            }
        }
        self.noninteractive_delegations.register_running(
            &task_call_id,
            "default",
            task.child_agent.clone(),
            NoninteractiveDelegationSnapshot::empty(),
        );
        let mut runner = self.clone_for_background_noninteractive(tx);
        let complete_tx = self.noninteractive_complete_tx.clone();
        let tx_for_task = tx.clone();
        let completion_task_call_id = task_call_id.clone();
        let completion_task_function_call_id = task_function_call_id.clone();
        let handle = tokio::spawn(async move {
            let result = runner
                .execute_single_noninteractive_task(task, &tx_for_task, cancel)
                .await;
            let _ = complete_tx
                .send(BackgroundNoninteractiveCompletion::Single {
                    task_call_id: completion_task_call_id,
                    task_function_call_id: completion_task_function_call_id,
                    result: Box::new(result),
                })
                .await;
        });
        self.noninteractive_jobs.insert(
            task_call_id.clone(),
            BackgroundNoninteractiveJob {
                delivered: false,
                handle,
            },
        );
        tokio::select! {
            biased;
            user = input_rx.recv() => {
                let Some(first) = user else {
                    return Ok(Message::user(""));
                };
                if self
                    .requeue_command_submission_for_boundary(input_rx, first.clone())
                    .await
                {
                    let completion = self.recv_noninteractive_completion_for(&task_call_id).await;
                    let delivery = self
                        .finalize_background_noninteractive_completion(completion, tx)
                        .await?;
                    self.reap_finished_noninteractive_jobs();
                    return Ok(delivery.into_inline_message());
                }
                self.noninteractive_delegations
                    .background_on_user_input(&task_call_id, "default");
                if let Err(e) = self
                    .session
                    .db
                    .background_task_delegation_child(&task_call_id, "default")
                {
                    tracing::warn!(error = %e, task_call_id, "background single task delegation failed");
                }
                let ack =
                    self.background_delegation_ack(&task_call_id, task_function_call_id.clone());
                if let Some(parent) = self.stack.last_mut() {
                    parent.history.push(ack);
                }
                let Some(prepared) = self.prepare_queued_user_submission(first, tx).await else {
                    return Ok(Message::user(""));
                };
                self.record_queued_user_fold(&prepared, tx).await;
                Ok(crate::engine::message::build_user_message(UserSubmission {
                    kind: UserSubmissionKind::User,
                    text: self.with_time_prelude(prepared.text),
                    images: prepared.images,
                    forced_skill: None,
                    origin_principal: None,
                    job_id: None,
                    preflight_cleaned: None,
                    queue_item_ids: Vec::new(),
                    queue_target: None,
                }))
            }
            completion = self.recv_noninteractive_completion_for(&task_call_id) => {
                let delivery = self
                    .finalize_background_noninteractive_completion(completion, tx)
                    .await?;
                self.reap_finished_noninteractive_jobs();
                Ok(delivery.into_inline_message())
            }
        }
    }

    async fn execute_single_noninteractive_task(
        &mut self,
        task: SingleNoninteractiveTask,
        tx: &mpsc::Sender<TurnEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<SingleNoninteractiveCompletion> {
        let SingleNoninteractiveTask {
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
        } = task;

        self.noninteractive_delegations.register_running(
            &task_call_id,
            "default",
            child_agent.clone(),
            NoninteractiveDelegationSnapshot::empty(),
        );

        if let Some(err) = grant_rejection(&child_cwd.resolved, &child_agent, &granted_tools) {
            return Ok(SingleNoninteractiveCompletion {
                child_agent,
                task_call_id,
                task_function_call_id,
                report: err,
                failed: true,
                partial_progress: DelegationPartialProgress::default(),
                seeds: Vec::new(),
                new_handle: None,
                snapshot: NoninteractiveDelegationSnapshot::empty(),
                shrink: None,
                repair_notes,
            });
        }

        let (delegation_payload_history, delivered_brief) = match self.delegation_payload_delivery(
            &task_call_id,
            "default",
            &brief,
            child_agent != "docs",
        ) {
            Ok(delivery) => delivery,
            Err(e) => {
                tracing::warn!(error = %e, task_call_id, "task delegation payload delivery failed");
                return Ok(SingleNoninteractiveCompletion {
                    child_agent,
                    task_call_id,
                    task_function_call_id,
                    report: DELEGATION_PAYLOAD_REFUSAL.to_string(),
                    failed: true,
                    partial_progress: DelegationPartialProgress::default(),
                    seeds: Vec::new(),
                    new_handle: None,
                    snapshot: NoninteractiveDelegationSnapshot::empty(),
                    shrink: None,
                    repair_notes,
                });
            }
        };

        let routing = self
            .stack
            .last()
            .unwrap()
            .agent
            .model
            .routing_metadata_json(None);
        let _ = tx
            .send(TurnEvent::SubagentSpawned {
                parent: self.stack.last().unwrap().agent.name.clone(),
                child: child_agent.clone(),
                task_call_id: task_call_id.clone(),
                label: "default".to_string(),
                prompt: delivered_brief.clone(),
                requested_cwd: child_cwd.requested.clone(),
                resolved_cwd: Some(child_cwd.resolved_display()),
                trusted_only: self
                    .stack
                    .last()
                    .unwrap()
                    .agent
                    .model
                    .trusted_only_enabled(),
                model_trusted: self.stack.last().unwrap().agent.model.is_trusted(),
                routing: routing.clone(),
            })
            .await;
        let task_identity = crate::engine::task_identity::TaskProviderIdentity::for_task_call(
            &task_call_id,
            task_function_call_id.as_deref(),
        );
        if let Err(e) = self.session.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some(&self.stack.last().unwrap().agent.name),
            Some(&task_call_id),
            &serde_json::json!({
                "child_agent": child_agent.clone(),
                "task_call_id": task_call_id,
                "provider_call_id": task_identity.provider_call_id,
                "provider_call_id_source": task_identity.provider_call_id_source,
                "provider_identity": task_identity.event_identity_json(&task_call_id),
                "label": "default",
                "noninteractive": true,
                "prompt": delivered_brief.clone(),
                "why": why.clone(),
                "model": model_selector_json(&model),
                "trusted_only": self.stack.last().unwrap().agent.model.trusted_only_enabled(),
                "model_trusted": self.stack.last().unwrap().agent.model.is_trusted(),
                "routing": routing,
                "remaining_depth": remaining_depth,
                "resume_handle": resume_handle.clone(),
                "requested_cwd": child_cwd.requested_json(),
                "resolved_cwd": child_cwd.resolved_display(),
                "grant_tools": granted_tools.clone(),
                "seed": prefill_seeds.clone(),
                "skill_seed": skill_seed.clone(),
                "todo_ids": todo_ids.clone(),
            }),
        ) {
            tracing::warn!(error = %e, "record single subagent_spawned event failed");
        }

        let parent_full = self
            .stack
            .last()
            .expect("stack never empty")
            .history
            .clone();
        let (tracker, shrink_handle) = self.begin_delegation_shrink(parent_full);

        let llm_mode = self.stack[0].agent.llm_mode;
        let followup_enabled = crate::engine::tool::Capability::FollowupSeed.enabled(llm_mode);
        let skill_block = self.seed_skills_block(&skill_seed, &child_agent);
        let composed_brief = compose_subagent_brief(&delivered_brief, &why);
        let composed_brief = if skill_block.is_empty() {
            composed_brief
        } else {
            format!("{skill_block}{composed_brief}")
        };
        let mut seeds: Vec<crate::engine::compact::SeedTool> = Vec::new();
        let mut new_handle: Option<String> = None;
        let mut snapshot = NoninteractiveDelegationSnapshot::empty();
        let composed_brief = self.assign_todos_to_task(
            composed_brief,
            &todo_ids,
            &task_call_id,
            "default",
            &child_agent,
        );

        let outcome = if child_agent == "docs" {
            if resume_handle.is_some() {
                DelegationChildOutcome::failed(stale_handle_error(&child_agent))
            } else {
                match crate::engine::docs_pipeline::run(
                    &delivered_brief,
                    &self.spawn_args_delegated_in_cwd(
                        &child_cwd.resolved,
                        false,
                        Vec::new(),
                        model.clone(),
                        child_recursion.clone(),
                    ),
                    self.session.clone(),
                    self.locks.clone(),
                    self.redact.clone(),
                    self.approver.clone(),
                    self.interrupts.clone(),
                    cancel.clone(),
                    Some(self.tandem_set.clone()),
                    Some(tx.clone()),
                    Some(NoninteractiveSteerTarget::new(
                        task_call_id.clone(),
                        "default",
                    )),
                )
                .await
                {
                    Ok(text) => DelegationChildOutcome::ok(text),
                    Err(e) => DelegationChildOutcome::failed(format!("Error: {e:#}")),
                }
            }
        } else {
            let rehydrated = match &resume_handle {
                None => Ok(Vec::new()),
                Some(handle) => self.rehydrate_handle(
                    handle,
                    &child_agent,
                    Some(&child_cwd.resolved),
                    followup_enabled,
                ),
            };
            match rehydrated {
                Err(msg) => DelegationChildOutcome::failed(msg),
                Ok(prior_history) => {
                    let child = match crate::engine::builtin::load(
                        &child_agent,
                        &self.spawn_args_delegated_in_cwd(
                            &child_cwd.resolved,
                            false,
                            granted_tools.clone(),
                            model.clone(),
                            child_recursion.clone(),
                        ),
                    ) {
                        Ok(child) => child,
                        Err(e) => {
                            return Ok(SingleNoninteractiveCompletion {
                                child_agent,
                                task_call_id,
                                task_function_call_id,
                                report: format!("Error: {e:#}"),
                                failed: true,
                                partial_progress: DelegationPartialProgress::default(),
                                seeds: Vec::new(),
                                new_handle: None,
                                snapshot: NoninteractiveDelegationSnapshot::empty(),
                                shrink: Some(PendingDelegationShrink {
                                    tracker,
                                    handle: shrink_handle,
                                }),
                                repair_notes,
                            });
                        }
                    };
                    let read_only = crate::engine::builtin::is_read_only_noninteractive(&child);
                    let write_capable = crate::engine::builtin::is_write_capable(&child);
                    if resume_handle.is_some() && write_capable {
                        match self.locks.resume_agent(&child_agent, self.session.id) {
                            Ok(reacquired) => {
                                tracing::debug!(
                                    agent = %child_agent,
                                    reacquired = reacquired.len(),
                                    "followup resume reacquired locks hash-matched"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(error = ?e, agent = %child_agent, "followup resume_agent failed");
                            }
                        }
                    }
                    if resume_handle.is_some() {
                        let reuse = self.followup_reuse_decision();
                        if let Err(e) = self.session.record_event(
                            crate::db::session_log::SessionEventKind::SubagentSpawned,
                            Some(&child_agent),
                            Some(&task_call_id),
                            &serde_json::json!({
                                "followup_resume": true,
                                "reuse_decision": format!("{reuse:?}"),
                                "write_capable": write_capable,
                            }),
                        ) {
                            tracing::warn!(error = %e, "record followup reuse event failed");
                        }
                    }
                    let (seed_prefix, seeds_truncated) = self
                        .prefill_child_seeds(&prefill_seeds, &child, &child_cwd.resolved, None)
                        .await;
                    let mut prior_history = prior_history;
                    let mut delivery_history = delegation_payload_history.clone();
                    let mut seed_prefix = seed_prefix;
                    if !delivery_history.is_empty() || !seed_prefix.is_empty() {
                        delivery_history.append(&mut seed_prefix);
                        delivery_history.append(&mut prior_history);
                        prior_history = delivery_history;
                    }
                    let composed_brief = if seeds_truncated {
                        format!("{composed_brief}{SEED_PREFILL_TRUNCATION_NOTE}")
                    } else {
                        composed_brief.clone()
                    };
                    let collector = crate::engine::seed_collector::SeedCollector::new();
                    match run_noninteractive_resumable(
                        child,
                        composed_brief,
                        prior_history,
                        collector.clone(),
                        self.session.clone(),
                        self.locks.clone(),
                        self.redact.clone(),
                        child_cwd.resolved.clone(),
                        self.interrupts.clone(),
                        cancel,
                        self.approver.clone(),
                        self.resource_scheduler.clone(),
                        self.loop_guard_threshold,
                        EXPLORE_MAX_TURNS,
                        Some(self.tandem_set.clone()),
                        Some(tx.clone()),
                        Some(NoninteractiveSteerTarget::new(
                            task_call_id.clone(),
                            "default",
                        )),
                    )
                    .await
                    {
                        Err(e) => {
                            let (message, history) = e.into_parts();
                            let partial_progress = partial_progress_from_history(&history);
                            snapshot = NoninteractiveDelegationSnapshot::from_history(history);
                            DelegationChildOutcome::failed_with_progress(
                                format!("Error: {message}"),
                                partial_progress,
                            )
                        }
                        Ok(outcome) => {
                            snapshot = NoninteractiveDelegationSnapshot::from_history(
                                outcome.history.clone(),
                            );
                            if followup_enabled
                                && crate::engine::builtin::is_followup_eligible(&child_agent)
                            {
                                new_handle = self.persist_subagent_handle(
                                    &child_agent,
                                    &outcome.history,
                                    Some(&child_cwd.resolved),
                                    resume_handle.as_deref(),
                                );
                                if read_only {
                                    seeds = collector.drain();
                                }
                                if write_capable
                                    && let Err(e) =
                                        self.locks.suspend_agent(&child_agent, self.session.id)
                                {
                                    tracing::warn!(error = ?e, agent = %child_agent, "followup suspend_agent at finish failed");
                                }
                            }
                            DelegationChildOutcome::ok(outcome.report)
                        }
                    }
                }
            }
        };

        Ok(SingleNoninteractiveCompletion {
            child_agent,
            task_call_id,
            task_function_call_id,
            report: outcome.report,
            failed: outcome.failed,
            partial_progress: outcome.partial_progress,
            seeds,
            new_handle,
            snapshot,
            shrink: Some(PendingDelegationShrink {
                tracker,
                handle: shrink_handle,
            }),
            repair_notes,
        })
    }

    async fn finalize_single_noninteractive_task(
        &mut self,
        completion: SingleNoninteractiveCompletion,
        tx: &mpsc::Sender<TurnEvent>,
        apply_shrink: bool,
    ) -> Message {
        let SingleNoninteractiveCompletion {
            child_agent,
            task_call_id,
            task_function_call_id,
            report,
            failed,
            partial_progress,
            seeds,
            new_handle,
            snapshot,
            shrink,
            repair_notes,
        } = completion;

        let emit_report_event = shrink.is_some();
        if !emit_report_event {
            let report = prepend_task_repair_notes(report, &repair_notes);
            let report = self.maybe_scan_task_report(&child_agent, report, tx).await;
            let result = Message::tool_result_with_call_id(
                task_call_id.clone(),
                task_function_call_id,
                report.clone(),
            );
            self.noninteractive_delegations
                .set_snapshot(&task_call_id, "default", snapshot);
            self.noninteractive_delegations.complete(
                &task_call_id,
                "default",
                report.clone(),
                failed,
                Some(result.clone()),
            );
            if let Err(e) = self.session.db.complete_task_delegation_child(
                &task_call_id,
                "default",
                &report,
                failed,
                None,
            ) {
                tracing::warn!(error = %e, task_call_id, "complete single delegation child failed");
            }
            let _ = self
                .noninteractive_delegations
                .mark_delivered(&task_call_id, "default");
            return result;
        }
        if apply_shrink {
            if let Some(PendingDelegationShrink { tracker, handle }) = shrink {
                self.finish_delegation_shrink(tracker, handle, tx).await;
            }
        } else {
            Self::discard_delegation_shrink(shrink);
        }

        let seeds_truncated = if seeds.is_empty() {
            false
        } else {
            self.inject_seeds(&seeds, &task_call_id, tx).await
        };

        let mut report = report;
        if seeds_truncated {
            report.push_str(
                "\n\n[note: some seeded results were omitted to stay within the report budget]",
            );
        }
        let report =
            self.reconcile_todo_delta(&task_call_id, "default", &child_agent, &report, failed);
        let report = match &new_handle {
            Some(handle) => format!("{report}{}", handle_footer(handle)),
            None => report,
        };
        let report = prepend_task_repair_notes(report, &repair_notes);
        let report = self.maybe_scan_task_report(&child_agent, report, tx).await;

        if let Err(e) = self.session.record_event(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some(&child_agent),
            Some(&task_call_id),
            &with_model_routing_metadata(
                subagent_report_event_data(
                    &child_agent,
                    Some(&task_call_id),
                    task_function_call_id.as_deref(),
                    "default",
                    &report,
                    Some(&partial_progress),
                ),
                &self.stack.last().unwrap().agent.model,
            ),
        ) {
            tracing::warn!(error = %e, "record subagent_report event failed");
        }
        let _ = tx
            .send(TurnEvent::SubagentReport {
                agent: child_agent.clone(),
                task_call_id: task_call_id.clone(),
                label: "default".to_string(),
                report: report.clone(),
                trusted_only: self
                    .stack
                    .last()
                    .unwrap()
                    .agent
                    .model
                    .trusted_only_enabled(),
                model_trusted: self.stack.last().unwrap().agent.model.is_trusted(),
                routing: self
                    .stack
                    .last()
                    .unwrap()
                    .agent
                    .model
                    .routing_metadata_json(None),
            })
            .await;

        let result = Message::tool_result_with_call_id(
            task_call_id.clone(),
            task_function_call_id,
            report.clone(),
        );
        self.noninteractive_delegations
            .set_snapshot(&task_call_id, "default", snapshot);
        self.noninteractive_delegations.complete(
            &task_call_id,
            "default",
            report.clone(),
            failed,
            Some(result.clone()),
        );
        if let Err(e) = self.session.db.complete_task_delegation_child(
            &task_call_id,
            "default",
            &report,
            failed,
            None,
        ) {
            tracing::warn!(error = %e, task_call_id, "complete single delegation child failed");
        }
        let _ = self
            .noninteractive_delegations
            .mark_delivered(&task_call_id, "default");
        if apply_shrink && let Some(parent) = self.stack.last_mut() {
            crate::engine::delegation_prompt_prune::prune_completed_delegation_prompts_with_upcoming(
                &mut parent.history,
                Some(&result),
            );
        }
        result
    }

    async fn maybe_scan_task_report(
        &self,
        child_agent: &str,
        report: String,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> String {
        let guard = crate::config::extended::resolve_injection_guard(&self.cwd);
        let scan = crate::agents::resolve(&self.cwd, child_agent)
            .ok()
            .flatten()
            .map(|def| {
                def.scan_tool_results.unwrap_or_else(|| {
                    crate::agents::default_scan_tool_results(&def.name, def.mode)
                })
            })
            .unwrap_or_else(|| !matches!(child_agent, "explore" | "scout" | "docs-answerer"));
        if !crate::engine::agent::should_scan_tool_result(
            "task",
            scan,
            self.session.approval_mode(),
            guard.threshold,
        ) {
            return report;
        }
        let ctx = crate::engine::agent::ResultRecheckCtx {
            agent_id: child_agent.to_string(),
            session: self.session.clone(),
            cwd: self.cwd.clone(),
            redact: self.redact.clone(),
            interrupts: self.interrupts.clone(),
        };
        crate::engine::agent::result_recheck(&report, &ctx, tx).await
    }

    fn take_pending_noninteractive_completion(
        &mut self,
        task_call_id: &str,
    ) -> Option<BackgroundNoninteractiveCompletion> {
        let pos = self
            .pending_noninteractive_completions
            .iter()
            .position(|completion| completion.task_call_id() == task_call_id)?;
        self.pending_noninteractive_completions.remove(pos)
    }

    async fn recv_noninteractive_completion_for(
        &mut self,
        task_call_id: &str,
    ) -> Option<BackgroundNoninteractiveCompletion> {
        if let Some(completion) = self.take_pending_noninteractive_completion(task_call_id) {
            return Some(completion);
        }
        loop {
            let completion = self.noninteractive_complete_rx.recv().await?;
            match completion.task_call_id() {
                id if id != task_call_id => {
                    self.pending_noninteractive_completions
                        .push_back(completion);
                }
                _ => return Some(completion),
            }
        }
    }

    async fn run_next_pending_noninteractive_completion(
        &mut self,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<bool> {
        let Some(completion) = self.pending_noninteractive_completions.pop_front() else {
            return Ok(false);
        };
        self.deliver_background_noninteractive_completion(Some(completion), input_rx, tx)
            .await
    }

    async fn deliver_background_noninteractive_completion(
        &mut self,
        completion: Option<BackgroundNoninteractiveCompletion>,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<bool> {
        let delivery = self
            .finalize_background_noninteractive_completion(completion, tx)
            .await?;
        self.reap_finished_noninteractive_jobs();
        match delivery {
            NoninteractiveCompletionDelivery::None => Ok(false),
            NoninteractiveCompletionDelivery::Inline(message) => {
                self.run_parent_tool_result(message, tx).await?;
                Ok(true)
            }
            NoninteractiveCompletionDelivery::AsyncUser(text) => {
                if text.trim().is_empty() {
                    return Ok(false);
                }
                self.run_user_input(UserSubmission::text(text), input_rx, tx)
                    .await?;
                Ok(true)
            }
        }
    }

    async fn finalize_background_noninteractive_completion(
        &mut self,
        completion: Option<BackgroundNoninteractiveCompletion>,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<NoninteractiveCompletionDelivery> {
        let Some(completion) = completion else {
            return Ok(NoninteractiveCompletionDelivery::None);
        };
        match completion {
            BackgroundNoninteractiveCompletion::Single {
                task_call_id,
                task_function_call_id,
                result,
            } => match *result {
                Ok(completion) => {
                    let was_backgrounded = self
                        .noninteractive_delegations
                        .is_backgrounded_job(&task_call_id);
                    if let Some(job) = self.noninteractive_jobs.get_mut(&task_call_id) {
                        if job.delivered {
                            return Ok(NoninteractiveCompletionDelivery::None);
                        }
                        job.delivered = true;
                    }
                    let result = self
                        .finalize_single_noninteractive_task(completion, tx, !was_backgrounded)
                        .await;
                    if was_backgrounded {
                        Ok(self
                            .async_delegation_result(&task_call_id)
                            .map(NoninteractiveCompletionDelivery::AsyncUser)
                            .unwrap_or(NoninteractiveCompletionDelivery::None))
                    } else {
                        if let Err(e) = self
                            .session
                            .db
                            .mark_task_delegation_child_delivered(&task_call_id, "default")
                        {
                            tracing::warn!(error = %e, task_call_id, "mark inline single delegation delivered failed");
                        }
                        Ok(NoninteractiveCompletionDelivery::Inline(result))
                    }
                }
                Err(e) => {
                    let body = format!("Error: {e:#}");
                    let was_backgrounded = self
                        .noninteractive_delegations
                        .is_backgrounded_job(&task_call_id);
                    if let Some(job) = self.noninteractive_jobs.get_mut(&task_call_id) {
                        if job.delivered {
                            return Ok(NoninteractiveCompletionDelivery::None);
                        }
                        job.delivered = true;
                    }
                    if was_backgrounded {
                        self.record_background_noninteractive_error(&task_call_id, &body);
                        Ok(self
                            .async_delegation_result(&task_call_id)
                            .map(NoninteractiveCompletionDelivery::AsyncUser)
                            .unwrap_or(NoninteractiveCompletionDelivery::None))
                    } else {
                        Ok(NoninteractiveCompletionDelivery::Inline(
                            Message::tool_result_with_call_id(
                                task_call_id,
                                task_function_call_id,
                                body,
                            ),
                        ))
                    }
                }
            },
            BackgroundNoninteractiveCompletion::Batch {
                task_call_id,
                task_function_call_id,
                result,
            } => match *result {
                Ok(completion) => {
                    let was_backgrounded = self
                        .noninteractive_delegations
                        .is_backgrounded_job(&task_call_id);
                    if let Some(job) = self.noninteractive_jobs.get_mut(&task_call_id) {
                        if job.delivered {
                            return Ok(NoninteractiveCompletionDelivery::None);
                        }
                        job.delivered = true;
                    }
                    let result = self
                        .finalize_batch_noninteractive_task(completion, tx)
                        .await;
                    if was_backgrounded {
                        Ok(self
                            .async_delegation_result(&task_call_id)
                            .map(NoninteractiveCompletionDelivery::AsyncUser)
                            .unwrap_or(NoninteractiveCompletionDelivery::None))
                    } else {
                        match self
                            .session
                            .db
                            .undelivered_task_delegation_children(&task_call_id)
                        {
                            Ok(rows) => {
                                for row in rows {
                                    if let Err(e) =
                                        self.session.db.mark_task_delegation_child_delivered(
                                            &task_call_id,
                                            &row.label,
                                        )
                                    {
                                        tracing::warn!(error = %e, task_call_id, label = %row.label, "mark inline batch delegation delivered failed");
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, task_call_id, "load inline batch delegation rows failed");
                            }
                        }
                        Ok(NoninteractiveCompletionDelivery::Inline(result))
                    }
                }
                Err(e) => {
                    let body = format!("Error: {e:#}");
                    let was_backgrounded = self
                        .noninteractive_delegations
                        .is_backgrounded_job(&task_call_id);
                    if let Some(job) = self.noninteractive_jobs.get_mut(&task_call_id) {
                        if job.delivered {
                            return Ok(NoninteractiveCompletionDelivery::None);
                        }
                        job.delivered = true;
                    }
                    if was_backgrounded {
                        self.record_background_noninteractive_error(&task_call_id, &body);
                        Ok(self
                            .async_delegation_result(&task_call_id)
                            .map(NoninteractiveCompletionDelivery::AsyncUser)
                            .unwrap_or(NoninteractiveCompletionDelivery::None))
                    } else {
                        Ok(NoninteractiveCompletionDelivery::Inline(
                            Message::tool_result_with_call_id(
                                task_call_id,
                                task_function_call_id,
                                body,
                            ),
                        ))
                    }
                }
            },
        }
    }

    fn reap_finished_noninteractive_jobs(&mut self) {
        self.noninteractive_jobs.retain(|task_call_id, job| {
            let reap = job.delivered && job.handle.is_finished();
            if reap {
                tracing::debug!(task_call_id, "reaped delivered noninteractive job handle");
            }
            !reap
        });
    }

    fn release_noninteractive_child_locks(
        &self,
        rows: &[crate::db::task_delegations::DelegationChildDetail],
    ) {
        let mut released = std::collections::HashSet::new();
        for row in rows {
            if !released.insert(row.child_agent.as_str()) {
                continue;
            }
            if let Err(e) = self.locks.suspend_agent(&row.child_agent, self.session.id) {
                tracing::warn!(
                    error = ?e,
                    agent = %row.child_agent,
                    task_call_id = %row.task_call_id,
                    "release noninteractive child locks after abort failed"
                );
            }
        }
    }

    fn record_background_noninteractive_error(&mut self, task_call_id: &str, body: &str) {
        let rows = match self
            .session
            .db
            .list_task_delegation_children(self.session.id)
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(error = %e, task_call_id, "load task delegation rows for background error failed");
                return;
            }
        };
        for row in rows
            .into_iter()
            .filter(|row| row.task_call_id == task_call_id && delegation_status_live(row.status))
        {
            if let Err(e) = self.session.db.complete_task_delegation_child(
                task_call_id,
                &row.label,
                body,
                true,
                None,
            ) {
                tracing::warn!(error = %e, task_call_id, label = %row.label, "complete errored background delegation child failed");
            }
            self.noninteractive_delegations.complete(
                task_call_id,
                &row.label,
                body.to_string(),
                true,
                None,
            );
        }
    }

    fn background_delegation_ack(
        &mut self,
        task_call_id: &str,
        task_function_call_id: Option<String>,
    ) -> Message {
        let completed = self
            .noninteractive_delegations
            .completed_undelivered(task_call_id);
        let running = self.noninteractive_delegations.running_labels(task_call_id);
        for (label, _) in &completed {
            let _ = self
                .noninteractive_delegations
                .mark_delivered(task_call_id, label);
            if let Err(e) = self
                .session
                .db
                .mark_task_delegation_child_delivered(task_call_id, label)
            {
                tracing::warn!(error = %e, task_call_id, label, "mark delegation ack child delivered failed");
            }
        }
        let body = format_delegation_background_ack(task_call_id, &completed, &running);
        Message::tool_result_with_call_id(task_call_id.to_string(), task_function_call_id, body)
    }

    fn async_delegation_result(&mut self, task_call_id: &str) -> Option<String> {
        let completed = match self
            .session
            .db
            .undelivered_task_delegation_children(task_call_id)
        {
            Ok(rows) => rows
                .into_iter()
                .map(|row| AsyncDelegationChildResult {
                    label: row.label,
                    status: row.status.as_str().to_string(),
                    report: row.report,
                })
                .collect::<Vec<_>>(),
            Err(e) => {
                tracing::warn!(error = %e, task_call_id, "load undelivered delegation children failed");
                self.noninteractive_delegations
                    .completed_undelivered(task_call_id)
                    .into_iter()
                    .map(|(label, report)| AsyncDelegationChildResult {
                        label,
                        status: "completed".to_string(),
                        report: Some(report),
                    })
                    .collect::<Vec<_>>()
            }
        };
        if completed.is_empty() {
            return None;
        }
        for child in &completed {
            let _ = self
                .noninteractive_delegations
                .mark_delivered(task_call_id, &child.label);
            if let Err(e) = self
                .session
                .db
                .mark_task_delegation_child_delivered(task_call_id, &child.label)
            {
                let label = child.label.as_str();
                tracing::warn!(error = %e, task_call_id, label, "mark async delegation child delivered failed");
            }
        }
        let running = self.noninteractive_delegations.running_labels(task_call_id);
        Some(format_async_delegation_result(
            task_call_id,
            &completed,
            &running,
        ))
    }

    fn enqueue_delegation_steer(
        &mut self,
        target_task_call_id: Option<String>,
        label: Option<String>,
        body: String,
        origin_principal: String,
        scrubbed: bool,
    ) -> std::result::Result<crate::daemon::proto::DelegationSteerResult, String> {
        let rows = self
            .session
            .db
            .list_task_delegation_children(self.session.id)
            .map_err(|e| format!("could not load task delegations: {e:#}"))?;
        let orphaned = orphaned_task_control_keys(&rows, &self.noninteractive_delegations);
        let selected =
            match resolve_task_control_targets(&rows, target_task_call_id.clone(), label, false) {
                Ok(selected) => selected,
                Err(reason) => {
                    return Ok(crate::daemon::proto::DelegationSteerResult::not_steerable(
                        target_task_call_id.unwrap_or_default(),
                        None,
                        reason,
                    ));
                }
            };
        if selected.len() != 1 {
            return Ok(crate::daemon::proto::DelegationSteerResult::not_steerable(
                target_task_call_id.unwrap_or_default(),
                None,
                "steer requires exactly one delegation child".to_string(),
            ));
        }
        let row = &selected[0];
        if !task_control_actionable_live(row, &orphaned, &self.noninteractive_delegations) {
            let reason = if orphaned.contains(&task_control_key(row)) {
                "lost (daemon restarted; no live worker)".to_string()
            } else {
                delegation_status_name(row.status).to_string()
            };
            return Ok(crate::daemon::proto::DelegationSteerResult::not_steerable(
                row.task_call_id.clone(),
                Some(row.label.clone()),
                reason,
            ));
        }
        if body.trim().is_empty() {
            return Ok(crate::daemon::proto::DelegationSteerResult::not_steerable(
                row.task_call_id.clone(),
                Some(row.label.clone()),
                "message is required for steer".to_string(),
            ));
        }
        self.session
            .db
            .enqueue_task_delegation_steer(&row.task_call_id, &row.label, &body, &origin_principal)
            .map_err(|e| format!("could not persist steer: {e:#}"))?;
        self.noninteractive_delegations
            .push_steer(&row.task_call_id, &row.label, body);
        Ok(crate::daemon::proto::DelegationSteerResult::queued(
            row.task_call_id.clone(),
            row.label.clone(),
            row.pending_steers + 1,
            origin_principal,
            scrubbed,
        ))
    }

    fn dispatch_task_control(
        &mut self,
        action: TaskControlAction,
        target_task_call_id: Option<String>,
        label: Option<String>,
        message: Option<String>,
    ) -> String {
        if matches!(action, TaskControlAction::Models) {
            return match self.live_providers_config() {
                Ok(providers) => crate::engine::model_roles::render_model_discovery(
                    self.active_agent(),
                    &providers,
                ),
                Err(e) => format!("Error: could not load provider model policy: {e:#}"),
            };
        }
        let rows = match self
            .session
            .db
            .list_task_delegation_children(self.session.id)
        {
            Ok(rows) => rows,
            Err(e) => return format!("Error: could not load task delegations: {e:#}"),
        };
        let orphaned = orphaned_task_control_keys(&rows, &self.noninteractive_delegations);
        match action {
            TaskControlAction::Models => unreachable!("handled before task delegation DB lookup"),
            TaskControlAction::List => format_task_control_list(&rows, &orphaned),
            TaskControlAction::Status => {
                let selected = match resolve_task_control_targets(
                    &rows,
                    target_task_call_id.clone(),
                    label,
                    false,
                ) {
                    Ok(selected) => selected,
                    Err(e) => return e,
                };
                format_task_control_status(&selected, &orphaned)
            }
            TaskControlAction::Cancel => {
                let selected = match resolve_task_control_targets(
                    &rows,
                    target_task_call_id.clone(),
                    label.clone(),
                    true,
                ) {
                    Ok(selected) => selected,
                    Err(e) => return e,
                };
                let cancel_whole_job = target_task_call_id.is_some() && label.is_none();
                if cancel_whole_job
                    && let Some(task_call_id) = selected.first().map(|row| row.task_call_id.clone())
                    && let Some(job) = self.noninteractive_jobs.remove(&task_call_id)
                {
                    job.handle.abort();
                    self.release_noninteractive_child_locks(&selected);
                }
                let mut changed = Vec::new();
                let mut unchanged = Vec::new();
                let mut orphaned_lost = Vec::new();
                for row in selected {
                    let key = task_control_key(&row);
                    if orphaned.contains(&key) {
                        match self
                            .session
                            .db
                            .mark_task_delegation_child_lost(&row.task_call_id, &row.label)
                        {
                            Ok(true) => {
                                let _ = self.session.db.finish_task_assignment(
                                    self.session.id,
                                    &row.task_call_id,
                                    &row.label,
                                    "lost",
                                    None,
                                );
                                orphaned_lost.push(format!("{}:{}", row.task_call_id, row.label))
                            }
                            Ok(false) => unchanged.push(format!(
                                "{}:{} ({})",
                                row.task_call_id,
                                row.label,
                                task_control_row_status_name(&row, &orphaned)
                            )),
                            Err(e) => {
                                return format!(
                                    "Error: could not mark orphaned `{}`/`{}` lost: {e:#}",
                                    row.task_call_id, row.label
                                );
                            }
                        }
                        continue;
                    }
                    let live_changed = self
                        .noninteractive_delegations
                        .cancel(&row.task_call_id, &row.label);
                    let db_changed = match self
                        .session
                        .db
                        .cancel_task_delegation_child(&row.task_call_id, &row.label)
                    {
                        Ok(changed) => changed,
                        Err(e) => {
                            return format!(
                                "Error: could not cancel `{}`/`{}`: {e:#}",
                                row.task_call_id, row.label
                            );
                        }
                    };
                    let _ = self.session.db.finish_task_assignment(
                        self.session.id,
                        &row.task_call_id,
                        &row.label,
                        "cancelled",
                        None,
                    );
                    if live_changed || db_changed {
                        changed.push(format!("{}:{}", row.task_call_id, row.label));
                    } else {
                        unchanged.push(format!(
                            "{}:{} ({})",
                            row.task_call_id,
                            row.label,
                            task_control_row_status_name(&row, &orphaned)
                        ));
                    }
                }
                let state = if changed.is_empty() && orphaned_lost.is_empty() {
                    "no_change"
                } else if !orphaned_lost.is_empty() && changed.is_empty() {
                    "lost"
                } else {
                    "cancelled"
                };
                task_envelope(serde_json::json!({
                    "state": state,
                    "task_call_id": target_task_call_id,
                    "blocking": false,
                    "tool_call_closed": true,
                    "result_pending": false,
                    "report_available": false,
                    "report_delivered": false,
                    "cancelled": changed,
                    "orphaned_lost": orphaned_lost,
                    "unchanged": unchanged,
                    "children": [],
                }))
            }
            TaskControlAction::Query => {
                let selected = match resolve_task_control_targets(
                    &rows,
                    target_task_call_id.clone(),
                    label,
                    false,
                ) {
                    Ok(selected) => selected,
                    Err(e) => return e,
                };
                if selected.len() != 1 {
                    return task_envelope(serde_json::json!({
                        "state": "refused",
                        "task_call_id": target_task_call_id,
                        "blocking": false,
                        "tool_call_closed": true,
                        "result_pending": false,
                        "report_available": false,
                        "report_delivered": false,
                        "actionable": false,
                        "reason": "query requires exactly one delegation child",
                        "children": [],
                    }));
                }
                let row = &selected[0];
                if !task_control_actionable_live(row, &orphaned, &self.noninteractive_delegations) {
                    let reason = if orphaned.contains(&task_control_key(row)) {
                        "lost (daemon restarted; no live worker)".to_string()
                    } else {
                        delegation_status_name(row.status).to_string()
                    };
                    let report_source = if row.report.is_some() { "db" } else { "none" };
                    let mut value = serde_json::json!({
                        "state": "refused",
                        "task_call_id": row.task_call_id,
                        "blocking": false,
                        "tool_call_closed": true,
                        "result_pending": false,
                        "report_available": row.report.is_some(),
                        "report_delivered": row.result_delivered,
                        "actionable": false,
                        "reason": reason,
                        "report_source": report_source,
                        "children": [task_child_detail_json(row, &orphaned)],
                    });
                    if let Some(report) = &row.report {
                        value["report"] = serde_json::json!(cap_text(report, 1200));
                    }
                    return task_envelope(value);
                }
                let db_report = row.report.clone();
                let live_report = self
                    .noninteractive_delegations
                    .snapshot_report(&row.task_call_id, &row.label);
                let (report_source, report) = if let Some(report) = db_report {
                    ("db", report)
                } else if let Some(report) = live_report {
                    ("live_snapshot", report)
                } else {
                    (
                        "none",
                        "No report yet; child is still running/backgrounded.".to_string(),
                    )
                };
                task_envelope(serde_json::json!({
                    "state": "query",
                    "task_call_id": row.task_call_id,
                    "blocking": false,
                    "tool_call_closed": row.status != crate::db::task_delegations::DelegationStatus::Running,
                    "result_pending": false,
                    "report_available": report_source != "none",
                    "report_delivered": row.result_delivered,
                    "actionable": true,
                    "read_only": true,
                    "child_state_unchanged": true,
                    "report_source": report_source,
                    "children": [task_child_detail_json(row, &orphaned)],
                    "report": cap_text(&report, 1200),
                }))
            }
            TaskControlAction::Steer => {
                let selected = match resolve_task_control_targets(
                    &rows,
                    target_task_call_id.clone(),
                    label,
                    false,
                ) {
                    Ok(selected) => selected,
                    Err(e) => return e,
                };
                if selected.len() != 1 {
                    return task_envelope(serde_json::json!({
                        "state": "refused",
                        "task_call_id": target_task_call_id,
                        "blocking": false,
                        "tool_call_closed": true,
                        "result_pending": false,
                        "report_available": false,
                        "report_delivered": false,
                        "actionable": false,
                        "reason": "steer requires exactly one delegation child",
                        "children": [],
                    }));
                }
                let row = &selected[0];
                if !task_control_actionable_live(row, &orphaned, &self.noninteractive_delegations) {
                    let reason = if orphaned.contains(&task_control_key(row)) {
                        "lost (daemon restarted; no live worker)".to_string()
                    } else {
                        delegation_status_name(row.status).to_string()
                    };
                    return task_envelope(serde_json::json!({
                        "state": "refused",
                        "task_call_id": row.task_call_id,
                        "blocking": false,
                        "tool_call_closed": true,
                        "result_pending": false,
                        "report_available": row.report.is_some(),
                        "report_delivered": row.result_delivered,
                        "actionable": false,
                        "reason": reason,
                        "children": [task_child_detail_json(row, &orphaned)],
                    }));
                }
                let Some(body) = message else {
                    return task_envelope(serde_json::json!({
                        "state": "refused",
                        "task_call_id": row.task_call_id,
                        "blocking": false,
                        "tool_call_closed": true,
                        "result_pending": false,
                        "report_available": row.report.is_some(),
                        "report_delivered": row.result_delivered,
                        "actionable": false,
                        "reason": "message is required for steer",
                        "children": [task_child_detail_json(row, &orphaned)],
                    }));
                };
                match self.enqueue_delegation_steer(
                    Some(row.task_call_id.clone()),
                    Some(row.label.clone()),
                    body,
                    format!("agent:{}", row.task_call_id),
                    false,
                ) {
                    Ok(result) => task_envelope(result.to_task_envelope_value()),
                    Err(message) => format!("Error: {message}"),
                }
            }
        }
    }

    async fn run_batch_noninteractive_task_backgroundable(
        &mut self,
        mut task: BatchNoninteractiveTask,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<Message> {
        let task_call_id = task.task_call_id.clone();
        let task_function_call_id = task.task_function_call_id.clone();
        let child_todo_json = task
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.label.clone(),
                    serde_json::to_string(&entry.todo_ids).ok(),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        let child_cwd_displays = task
            .child_cwds
            .iter()
            .map(ChildCwd::resolved_display)
            .collect::<Vec<_>>();
        let child_model_displays = task
            .entries
            .iter()
            .map(|entry| model_selector_display(&entry.model))
            .collect::<Vec<_>>();
        let child_inits = task
            .entries
            .iter()
            .zip(task.child_cwds.iter())
            .zip(child_cwd_displays.iter())
            .zip(child_model_displays.iter())
            .map(|(((entry, child_cwd), resolved_cwd), model)| {
                crate::db::task_delegations::DelegationChildInit {
                    label: entry.label.as_str(),
                    child_agent: entry.child_agent.as_str(),
                    model: model.as_deref(),
                    output_dir: entry.output_dir.as_deref(),
                    requested_cwd: child_cwd.requested_json(),
                    resolved_cwd: Some(resolved_cwd.as_str()),
                    todo_ids_json: child_todo_json
                        .get(&entry.label)
                        .and_then(|value| value.as_deref()),
                }
            })
            .collect::<Vec<_>>();
        let task_args_json = serde_json::to_string(&serde_json::json!({
            "entries": task.entries.iter().zip(task.child_cwds.iter()).map(|(entry, child_cwd)| serde_json::json!({
                "label": &entry.label,
                "child_agent": &entry.child_agent,
                "model": model_selector_json(&entry.model),
                "resume_handle": &entry.resume_handle,
                "requested_cwd": child_cwd.requested_json(),
                "resolved_cwd": child_cwd.resolved_display(),
                "output_dir": &entry.output_dir,
                "todo_ids": &entry.todo_ids,
                "skill_seed": &entry.skill_seed,
            })).collect::<Vec<_>>(),
            "why": &task.why,
        }))
        .ok();
        let parent_agent = self.stack.last().unwrap().agent.name.clone();
        if let Err(e) = self.session.db.upsert_task_delegation_job(
            self.session.id,
            &task_call_id,
            task_function_call_id.as_deref(),
            &parent_agent,
            task_args_json.as_deref(),
            &child_inits,
        ) {
            tracing::warn!(error = %e, task_call_id, "persist batch task delegation job failed");
            return Ok(Message::tool_result_with_call_id(
                task_call_id,
                task_function_call_id,
                prepend_task_repair_notes(
                    DELEGATION_PAYLOAD_REFUSAL.to_string(),
                    &task.repair_notes,
                ),
            ));
        }
        for entry in &mut task.entries {
            match self.persist_delegation_payload(
                &task_call_id,
                task_function_call_id.as_deref(),
                &parent_agent,
                &entry.label,
                &entry.child_agent,
                &entry.prompt,
            ) {
                Ok(loaded) => entry.prompt = loaded,
                Err(e) => {
                    let label = entry.label.clone();
                    tracing::warn!(error = %e, task_call_id, label, "persist batch task delegation payload failed");
                    return Ok(Message::tool_result_with_call_id(
                        task_call_id,
                        task_function_call_id,
                        prepend_task_repair_notes(
                            DELEGATION_PAYLOAD_REFUSAL.to_string(),
                            &task.repair_notes,
                        ),
                    ));
                }
            }
        }
        for entry in &task.entries {
            self.noninteractive_delegations.register_running(
                &task_call_id,
                &entry.label,
                entry.child_agent.clone(),
                NoninteractiveDelegationSnapshot::empty(),
            );
        }
        let mut runner = self.clone_for_background_noninteractive(tx);
        let complete_tx = self.noninteractive_complete_tx.clone();
        let tx_for_task = tx.clone();
        let completion_task_call_id = task_call_id.clone();
        let completion_task_function_call_id = task_function_call_id.clone();
        let handle = tokio::spawn(async move {
            let result = runner
                .execute_batch_noninteractive_task(task, &tx_for_task, cancel)
                .await;
            let _ = complete_tx
                .send(BackgroundNoninteractiveCompletion::Batch {
                    task_call_id: completion_task_call_id,
                    task_function_call_id: completion_task_function_call_id,
                    result: Box::new(result),
                })
                .await;
        });
        self.noninteractive_jobs.insert(
            task_call_id.clone(),
            BackgroundNoninteractiveJob {
                delivered: false,
                handle,
            },
        );
        tokio::select! {
            biased;
            user = input_rx.recv() => {
                let Some(first) = user else {
                    return Ok(Message::user(""));
                };
                if self
                    .requeue_command_submission_for_boundary(input_rx, first.clone())
                    .await
                {
                    let completion = self.recv_noninteractive_completion_for(&task_call_id).await;
                    let delivery = self
                        .finalize_background_noninteractive_completion(completion, tx)
                        .await?;
                    self.reap_finished_noninteractive_jobs();
                    return Ok(delivery.into_inline_message());
                }
                let labels = self
                    .noninteractive_delegations
                    .entries
                    .keys()
                    .filter(|key| key.task_call_id == task_call_id)
                    .map(|key| key.label.clone())
                    .collect::<Vec<_>>();
                for label in labels {
                    self.noninteractive_delegations
                        .background_on_user_input(&task_call_id, &label);
                    if let Err(e) = self
                        .session
                        .db
                        .background_task_delegation_child(&task_call_id, &label)
                    {
                        tracing::warn!(error = %e, task_call_id, label, "background batch task delegation failed");
                    }
                }
                let ack =
                    self.background_delegation_ack(&task_call_id, task_function_call_id.clone());
                if let Some(parent) = self.stack.last_mut() {
                    parent.history.push(ack);
                }
                let Some(prepared) = self.prepare_queued_user_submission(first, tx).await else {
                    return Ok(Message::user(""));
                };
                self.record_queued_user_fold(&prepared, tx).await;
                Ok(crate::engine::message::build_user_message(UserSubmission {
                    kind: UserSubmissionKind::User,
                    text: self.with_time_prelude(prepared.text),
                    images: prepared.images,
                    forced_skill: None,
                    origin_principal: None,
                    job_id: None,
                    preflight_cleaned: None,
                    queue_item_ids: Vec::new(),
                    queue_target: None,
                }))
            }
            completion = self.recv_noninteractive_completion_for(&task_call_id) => {
                let delivery = self
                    .finalize_background_noninteractive_completion(completion, tx)
                    .await?;
                self.reap_finished_noninteractive_jobs();
                Ok(delivery.into_inline_message())
            }
        }
    }

    async fn execute_batch_noninteractive_task(
        &mut self,
        task: BatchNoninteractiveTask,
        tx: &mpsc::Sender<TurnEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<BatchNoninteractiveCompletion> {
        let BatchNoninteractiveTask {
            entries,
            child_cwds,
            why,
            repair_notes,
            task_call_id,
            task_function_call_id,
        } = task;

        let mut batch_refusal: Option<String> = None;
        let mut child_recursions = Vec::with_capacity(entries.len());
        for (entry, child_cwd) in entries.iter().zip(child_cwds.iter()) {
            let child_recursion = match self.resolve_task_recursion(
                &entry.child_agent,
                entry.remaining_depth,
                &entry.model,
            ) {
                Ok(ctx) => ctx,
                Err(err) => {
                    batch_refusal = Some(format!("entry `{}`: {err}", entry.label));
                    break;
                }
            };
            let child = match crate::engine::builtin::load(
                &entry.child_agent,
                &self.spawn_args_delegated_in_cwd(
                    &child_cwd.resolved,
                    false,
                    entry.granted_tools.clone(),
                    entry.model.clone(),
                    child_recursion.clone(),
                ),
            ) {
                Ok(child) => child,
                Err(e) => {
                    batch_refusal = Some(format!("could not load `{}`: {e:#}", entry.child_agent));
                    break;
                }
            };
            if crate::engine::builtin::is_write_capable(&child) && entry.output_dir.is_none() {
                batch_refusal = Some(format!(
                    "parallel write-capable entry `{}` (`{}`) requires `output_dir`",
                    entry.label, entry.child_agent
                ));
                break;
            }
            child_recursions.push(child_recursion);
        }
        if let Some(msg) = batch_refusal {
            return Ok(BatchNoninteractiveCompletion {
                task_call_id,
                task_function_call_id,
                children: vec![BatchChildCompletion {
                    idx: 0,
                    label: String::new(),
                    child_agent: String::new(),
                    report: format!("Error: {msg}"),
                    failed: true,
                    partial_progress: DelegationPartialProgress::default(),
                    snapshot: NoninteractiveDelegationSnapshot::empty(),
                }],
                repair_notes,
            });
        }

        for entry in &entries {
            self.noninteractive_delegations.register_running(
                &task_call_id,
                &entry.label,
                entry.child_agent.clone(),
                NoninteractiveDelegationSnapshot::empty(),
            );
        }

        use futures::StreamExt as _;

        let mut runs = futures::stream::FuturesUnordered::new();
        let mut children = Vec::new();
        for (idx, ((mut entry, child_cwd), child_recursion)) in entries
            .into_iter()
            .zip(child_cwds)
            .zip(child_recursions)
            .enumerate()
        {
            let driver = &*self;
            let entry_why = why.clone();
            let entry_task_call_id = task_call_id.clone();
            let parent = self.stack.last().unwrap().agent.name.clone();
            let (delegation_payload_history, delivered_prompt) = match self
                .delegation_payload_delivery(
                    &task_call_id,
                    &entry.label,
                    &entry.prompt,
                    entry.child_agent != "docs",
                ) {
                Ok(delivery) => delivery,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        task_call_id,
                        label = %entry.label,
                        "batch task delegation payload delivery failed"
                    );
                    children.push(BatchChildCompletion {
                        idx,
                        label: entry.label,
                        child_agent: entry.child_agent,
                        report: DELEGATION_PAYLOAD_REFUSAL.to_string(),
                        failed: true,
                        partial_progress: DelegationPartialProgress::default(),
                        snapshot: NoninteractiveDelegationSnapshot::empty(),
                    });
                    continue;
                }
            };
            entry.prompt = delivered_prompt;
            let routing = self
                .stack
                .last()
                .unwrap()
                .agent
                .model
                .routing_metadata_json(None);
            let _ = tx
                .send(TurnEvent::SubagentSpawned {
                    parent,
                    child: entry.child_agent.clone(),
                    task_call_id: task_call_id.clone(),
                    label: entry.label.clone(),
                    prompt: entry.prompt.clone(),
                    requested_cwd: child_cwd.requested.clone(),
                    resolved_cwd: Some(child_cwd.resolved_display()),
                    trusted_only: self
                        .stack
                        .last()
                        .unwrap()
                        .agent
                        .model
                        .trusted_only_enabled(),
                    model_trusted: self.stack.last().unwrap().agent.model.is_trusted(),
                    routing: routing.clone(),
                })
                .await;
            let task_identity = crate::engine::task_identity::TaskProviderIdentity::for_task_call(
                &task_call_id,
                task_function_call_id.as_deref(),
            );
            if let Err(e) = self.session.record_event(
                crate::db::session_log::SessionEventKind::SubagentSpawned,
                Some(&self.stack.last().unwrap().agent.name),
                Some(&task_call_id),
                &serde_json::json!({
                    "child_agent": entry.child_agent.clone(),
                    "task_call_id": task_call_id,
                    "provider_call_id": task_identity.provider_call_id,
                    "provider_call_id_source": task_identity.provider_call_id_source,
                    "provider_identity": task_identity.event_identity_json(&task_call_id),
                    "label": entry.label.clone(),
                    "noninteractive": true,
                    "prompt": entry.prompt.clone(),
                    "why": why.clone(),
                    "model": model_selector_json(&entry.model),
                    "trusted_only": self.stack.last().unwrap().agent.model.trusted_only_enabled(),
                    "model_trusted": self.stack.last().unwrap().agent.model.is_trusted(),
                    "routing": routing,
                    "remaining_depth": entry.remaining_depth,
                    "resume_handle": entry.resume_handle.clone(),
                    "requested_cwd": child_cwd.requested_json(),
                    "resolved_cwd": child_cwd.resolved_display(),
                    "grant_tools": entry.granted_tools.clone(),
                    "seed": entry.seeds.clone(),
                    "skill_seed": entry.skill_seed.clone(),
                    "todo_ids": entry.todo_ids.clone(),
                    "output_dir": entry.output_dir.clone(),
                }),
            ) {
                tracing::warn!(error = %e, "record batch subagent_spawned event failed");
            }

            let child_cancel = cancel.clone();
            runs.push(async move {
                let mut snapshot = NoninteractiveDelegationSnapshot::empty();
                let outcome =
                    if let Some(err) =
                        grant_rejection(&child_cwd.resolved, &entry.child_agent, &entry.granted_tools)
                    {
                        DelegationChildOutcome::failed(err)
                    } else if entry.child_agent == "docs" {
                        if entry.resume_handle.is_some() {
                            DelegationChildOutcome::failed(stale_handle_error(&entry.child_agent))
                        } else {
                            match crate::engine::docs_pipeline::run(
                                &entry.prompt,
                                &driver.spawn_args_delegated_in_cwd(
                                    &child_cwd.resolved,
                                    false,
                                    Vec::new(),
                                    entry.model.clone(),
                                    child_recursion.clone(),
                                ),
                                driver.session.clone(),
                                driver.locks.clone(),
                                driver.redact.clone(),
                                driver.approver.clone(),
                                driver.interrupts.clone(),
                                child_cancel.clone(),
                                Some(driver.tandem_set.clone()),
                                Some(tx.clone()),
                                Some(NoninteractiveSteerTarget::new(
                                    entry_task_call_id.clone(),
                                    entry.label.clone(),
                                )),
                            )
                            .await
                            {
                                Ok(text) => DelegationChildOutcome::ok(text),
                                Err(e) => DelegationChildOutcome::failed(format!("Error: {e:#}")),
                            }
                        }
                    } else {
                        let child = match crate::engine::builtin::load(
                            &entry.child_agent,
                            &driver.spawn_args_delegated_in_cwd(
                                &child_cwd.resolved,
                                false,
                                entry.granted_tools.clone(),
                                entry.model.clone(),
                                child_recursion.clone(),
                            ),
                        ) {
                            Ok(child) => child,
                            Err(e) => {
                                return (
                                    idx,
                                    entry,
                                    DelegationChildOutcome::failed(format!("Error: {e:#}")),
                                    snapshot,
                                );
                            }
                        };
                        let skill_block =
                            driver.seed_skills_block(&entry.skill_seed, &entry.child_agent);
                        let mut brief = compose_subagent_brief(&entry.prompt, &entry_why);
                        if let Some(output_dir) = &entry.output_dir {
                            brief = format!(
                                "{brief}\n\nWrite constraint: keep all file writes under `{output_dir}`."
                            );
                        }
                        if !skill_block.is_empty() {
                            brief = format!("{skill_block}{brief}");
                        }
                        let brief = driver.assign_todos_to_task(
                            brief,
                            &entry.todo_ids,
                            &entry_task_call_id,
                            &entry.label,
                            &entry.child_agent,
                        );
                        let (seed_prefix, seeds_truncated) =
                            driver
                                .prefill_child_seeds(&entry.seeds, &child, &child_cwd.resolved, None)
                                .await;
                        let mut prior_history = delegation_payload_history;
                        let mut seed_prefix = seed_prefix;
                        if !seed_prefix.is_empty() {
                            prior_history.append(&mut seed_prefix);
                        }
                        let brief = if seeds_truncated {
                            format!("{brief}{SEED_PREFILL_TRUNCATION_NOTE}")
                        } else {
                            brief
                        };
                        let collector = crate::engine::seed_collector::SeedCollector::new();
                        match run_noninteractive_resumable(
                            child,
                            brief,
                            prior_history,
                            collector,
                            driver.session.clone(),
                            driver.locks.clone(),
                            driver.redact.clone(),
                            child_cwd.resolved.clone(),
                            driver.interrupts.clone(),
                            child_cancel.clone(),
                            driver.approver.clone(),
                            driver.resource_scheduler.clone(),
                            driver.loop_guard_threshold,
                            EXPLORE_MAX_TURNS,
                            Some(driver.tandem_set.clone()),
                            Some(tx.clone()),
                            Some(NoninteractiveSteerTarget::new(
                                entry_task_call_id.clone(),
                                entry.label.clone(),
                            )),
                        )
                        .await
                        {
                            Ok(outcome) => {
                                snapshot = NoninteractiveDelegationSnapshot::from_history(
                                    outcome.history.clone(),
                                );
                                DelegationChildOutcome::ok(outcome.report)
                            }
                            Err(e) => {
                                let (message, history) = e.into_parts();
                                let partial_progress = partial_progress_from_history(&history);
                                snapshot = NoninteractiveDelegationSnapshot::from_history(history);
                                DelegationChildOutcome::failed_with_progress(
                                    format!("Error: {message}"),
                                    partial_progress,
                                )
                            }
                        }
                    };
                (idx, entry, outcome, snapshot)
            });
        }

        while let Some((idx, entry, outcome, snapshot)) = runs.next().await {
            let report = self.reconcile_todo_delta(
                &task_call_id,
                &entry.label,
                &entry.child_agent,
                &outcome.report,
                outcome.failed,
            );
            if let Err(e) = self.session.record_event(
                crate::db::session_log::SessionEventKind::SubagentReport,
                Some(&entry.child_agent),
                Some(&task_call_id),
                &with_model_routing_metadata(
                    subagent_report_event_data(
                        &entry.child_agent,
                        Some(&task_call_id),
                        task_function_call_id.as_deref(),
                        &entry.label,
                        &report,
                        Some(&outcome.partial_progress),
                    ),
                    &self.stack.last().unwrap().agent.model,
                ),
            ) {
                tracing::warn!(error = %e, "record batch subagent_report event failed");
            }
            let _ = tx
                .send(TurnEvent::SubagentReport {
                    agent: entry.child_agent.clone(),
                    task_call_id: task_call_id.clone(),
                    label: entry.label.clone(),
                    report: report.clone(),
                    trusted_only: self
                        .stack
                        .last()
                        .unwrap()
                        .agent
                        .model
                        .trusted_only_enabled(),
                    model_trusted: self.stack.last().unwrap().agent.model.is_trusted(),
                    routing: self
                        .stack
                        .last()
                        .unwrap()
                        .agent
                        .model
                        .routing_metadata_json(None),
                })
                .await;
            children.push(BatchChildCompletion {
                idx,
                label: entry.label,
                child_agent: entry.child_agent,
                report,
                failed: outcome.failed,
                partial_progress: outcome.partial_progress,
                snapshot,
            });
        }

        Ok(BatchNoninteractiveCompletion {
            task_call_id,
            task_function_call_id,
            children,
            repair_notes,
        })
    }

    async fn finalize_batch_noninteractive_task(
        &mut self,
        completion: BatchNoninteractiveCompletion,
        _tx: &mpsc::Sender<TurnEvent>,
    ) -> Message {
        let BatchNoninteractiveCompletion {
            task_call_id,
            task_function_call_id,
            mut children,
            repair_notes,
        } = completion;

        if children.len() == 1
            && children[0].label.is_empty()
            && children[0].child_agent.is_empty()
            && children[0].failed
        {
            return Message::tool_result_with_call_id(
                task_call_id,
                task_function_call_id,
                prepend_task_repair_notes(children.remove(0).report, &repair_notes),
            );
        }

        children.sort_by_key(|child| child.idx);
        let registry_updates: Vec<_> = children
            .iter()
            .map(|child| {
                (
                    child.label.clone(),
                    child.report.clone(),
                    child.failed,
                    child.snapshot.clone(),
                )
            })
            .collect();
        let children: Vec<_> = children
            .into_iter()
            .map(|child| {
                let mut data = serde_json::json!({
                    "label": child.label,
                    "agent": child.child_agent,
                    "failed": child.failed,
                    "report": child.report,
                });
                if !child.partial_progress.is_empty() {
                    data["partial_progress"] = serde_json::to_value(child.partial_progress)
                        .unwrap_or_else(|_| serde_json::json!({ "serialization_error": true }));
                }
                data
            })
            .collect();
        let mut body = serde_json::json!({
            "status": "completed",
            "children": children,
        });
        if !repair_notes.is_empty() {
            body["repair_notes"] = serde_json::json!(repair_notes);
        }
        let body = body.to_string();
        let result =
            Message::tool_result_with_call_id(task_call_id.clone(), task_function_call_id, body);
        for (label, report, failed, snapshot) in registry_updates {
            self.noninteractive_delegations
                .set_snapshot(&task_call_id, &label, snapshot);
            self.noninteractive_delegations.complete(
                &task_call_id,
                &label,
                report.clone(),
                failed,
                Some(result.clone()),
            );
            if let Err(e) = self.session.db.complete_task_delegation_child(
                &task_call_id,
                &label,
                &report,
                failed,
                None,
            ) {
                tracing::warn!(error = %e, task_call_id, label, "complete batch delegation child failed");
            }
            let _ = self
                .noninteractive_delegations
                .mark_delivered(&task_call_id, &label);
        }
        if let Some(parent) = self.stack.last_mut() {
            crate::engine::delegation_prompt_prune::prune_completed_delegation_prompts_with_upcoming(
                &mut parent.history,
                Some(&result),
            );
        }
        result
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

fn delegation_status_name(status: crate::db::task_delegations::DelegationStatus) -> &'static str {
    status.as_str()
}

fn delegation_status_live(status: crate::db::task_delegations::DelegationStatus) -> bool {
    matches!(
        status,
        crate::db::task_delegations::DelegationStatus::Running
            | crate::db::task_delegations::DelegationStatus::Backgrounded
            | crate::db::task_delegations::DelegationStatus::PausedPendingTool
    )
}

fn task_control_key(row: &crate::db::task_delegations::DelegationChildDetail) -> (String, String) {
    (row.task_call_id.clone(), row.label.clone())
}

fn orphaned_task_control_keys(
    rows: &[crate::db::task_delegations::DelegationChildDetail],
    registry: &NoninteractiveDelegationRegistry,
) -> HashSet<(String, String)> {
    rows.iter()
        .filter(|row| {
            delegation_status_live(row.status) && !registry.is_live(&row.task_call_id, &row.label)
        })
        .map(task_control_key)
        .collect()
}

fn task_control_actionable_live(
    row: &crate::db::task_delegations::DelegationChildDetail,
    orphaned: &HashSet<(String, String)>,
    registry: &NoninteractiveDelegationRegistry,
) -> bool {
    delegation_status_live(row.status)
        && !orphaned.contains(&task_control_key(row))
        && registry.is_live(&row.task_call_id, &row.label)
}

fn task_control_row_status_name(
    row: &crate::db::task_delegations::DelegationChildDetail,
    orphaned: &HashSet<(String, String)>,
) -> String {
    if orphaned.contains(&task_control_key(row)) {
        "lost (orphaned)".to_string()
    } else {
        delegation_status_name(row.status).to_string()
    }
}

fn cap_text(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for ch in text.chars().take(max_chars) {
        out.push(ch);
    }
    if out.len() < text.len() {
        out.push_str("\n[truncated]");
    }
    out
}

fn resolve_task_control_targets(
    rows: &[crate::db::task_delegations::DelegationChildDetail],
    task_call_id: Option<String>,
    label: Option<String>,
    allow_whole_job: bool,
) -> std::result::Result<Vec<crate::db::task_delegations::DelegationChildDetail>, String> {
    let live_rows = rows
        .iter()
        .filter(|row| delegation_status_live(row.status))
        .collect::<Vec<_>>();
    let selected = match (task_call_id.as_deref(), label.as_deref()) {
        (Some(task), Some(label)) => rows
            .iter()
            .filter(|row| row.task_call_id == task && row.label == label)
            .cloned()
            .collect::<Vec<_>>(),
        (Some(task), None) if allow_whole_job => rows
            .iter()
            .filter(|row| row.task_call_id == task)
            .cloned()
            .collect::<Vec<_>>(),
        (Some(task), None) => rows
            .iter()
            .filter(|row| row.task_call_id == task)
            .cloned()
            .collect::<Vec<_>>(),
        (None, Some(label)) => {
            let matches = live_rows
                .iter()
                .filter(|row| row.label == label)
                .copied()
                .collect::<Vec<_>>();
            if matches.len() > 1 {
                return Err(format!(
                    "Error: label `{label}` is ambiguous across active delegations; pass `task_call_id`"
                ));
            }
            matches.into_iter().cloned().collect::<Vec<_>>()
        }
        (None, None) => {
            if live_rows.len() == 1 {
                vec![(*live_rows[0]).clone()]
            } else if live_rows.is_empty() {
                return Err("Error: no active task delegations".to_string());
            } else {
                return Err(
                    "Error: multiple active task delegations; pass `task_call_id` and/or `label`"
                        .to_string(),
                );
            }
        }
    };
    if selected.is_empty() {
        Err("Error: no matching task delegation".to_string())
    } else {
        Ok(selected)
    }
}

fn task_envelope(mut value: serde_json::Value) -> String {
    if let Some(obj) = value.as_object_mut() {
        obj.insert("type".to_string(), serde_json::json!("task_delegation"));
        obj.insert("version".to_string(), serde_json::json!(1));
    }
    serde_json::to_string(&value).unwrap_or_else(|_| {
        "{\"type\":\"task_delegation\",\"version\":1,\"state\":\"serialization_error\"}".to_string()
    })
}

fn task_child_detail_json(
    row: &crate::db::task_delegations::DelegationChildDetail,
    orphaned: &HashSet<(String, String)>,
) -> serde_json::Value {
    let is_orphaned = orphaned.contains(&task_control_key(row));
    let status = if is_orphaned {
        "lost"
    } else {
        delegation_status_name(row.status)
    };
    let report_available = row.report.is_some();
    let result_pending =
        !row.result_delivered && (!delegation_status_live(row.status) || is_orphaned);
    let actionable = delegation_status_live(row.status) && !is_orphaned;
    let mut child = serde_json::json!({
        "task_call_id": row.task_call_id,
        "label": row.label,
        "agent": row.child_agent,
        "model": row.model.as_deref().unwrap_or("default"),
        "status": status,
        "blocking": row.status == crate::db::task_delegations::DelegationStatus::Running && !is_orphaned,
        "tool_call_closed": row.status != crate::db::task_delegations::DelegationStatus::Running,
        "result_pending": result_pending,
        "report_available": report_available,
        "report_delivered": row.result_delivered,
        "pending_steers": row.pending_steers,
        "orphaned": is_orphaned,
        "actionable": actionable,
        "started_at": row.started_at,
        "finished_at": row.finished_at,
        "updated_at": row.updated_at,
    });
    if let Some(report) = &row.report {
        child["report"] = serde_json::json!(cap_text(report, 500));
    }
    child
}

fn format_task_control_list(
    rows: &[crate::db::task_delegations::DelegationChildDetail],
    orphaned: &HashSet<(String, String)>,
) -> String {
    let children = rows
        .iter()
        .take(12)
        .map(|row| task_child_detail_json(row, orphaned))
        .collect::<Vec<_>>();
    task_envelope(serde_json::json!({
        "state": "list",
        "task_call_id": serde_json::Value::Null,
        "blocking": children.iter().any(|child| child["blocking"].as_bool().unwrap_or(false)),
        "tool_call_closed": true,
        "result_pending": children.iter().any(|child| child["result_pending"].as_bool().unwrap_or(false)),
        "report_available": children.iter().any(|child| child["report_available"].as_bool().unwrap_or(false)),
        "report_delivered": children.iter().all(|child| child["report_delivered"].as_bool().unwrap_or(false)),
        "children": children,
        "omitted_children": rows.len().saturating_sub(12),
    }))
}

fn format_task_control_status(
    rows: &[crate::db::task_delegations::DelegationChildDetail],
    orphaned: &HashSet<(String, String)>,
) -> String {
    let children = rows
        .iter()
        .take(8)
        .map(|row| task_child_detail_json(row, orphaned))
        .collect::<Vec<_>>();
    task_envelope(serde_json::json!({
        "state": "status",
        "task_call_id": rows.first().map(|row| row.task_call_id.as_str()),
        "blocking": children.iter().any(|child| child["blocking"].as_bool().unwrap_or(false)),
        "tool_call_closed": children.iter().all(|child| child["tool_call_closed"].as_bool().unwrap_or(false)),
        "result_pending": children.iter().any(|child| child["result_pending"].as_bool().unwrap_or(false)),
        "report_available": children.iter().any(|child| child["report_available"].as_bool().unwrap_or(false)),
        "report_delivered": children.iter().all(|child| child["report_delivered"].as_bool().unwrap_or(false)),
        "children": children,
        "omitted_children": rows.len().saturating_sub(8),
    }))
}

fn format_delegation_background_ack(
    task_call_id: &str,
    completed: &[(String, String)],
    running: &[String],
) -> String {
    let mut children = Vec::new();
    for (label, report) in completed {
        children.push(serde_json::json!({
            "task_call_id": task_call_id,
            "label": label,
            "agent": serde_json::Value::Null,
            "model": serde_json::Value::Null,
            "status": "completed",
            "blocking": false,
            "tool_call_closed": true,
            "result_pending": false,
            "report_available": true,
            "report_delivered": true,
            "pending_steers": 0,
            "orphaned": false,
            "actionable": false,
            "newly_delivered": true,
            "report": report,
        }));
    }
    for label in running {
        children.push(serde_json::json!({
            "task_call_id": task_call_id,
            "label": label,
            "agent": serde_json::Value::Null,
            "model": serde_json::Value::Null,
            "status": "backgrounded",
            "blocking": false,
            "tool_call_closed": true,
            "result_pending": true,
            "report_available": false,
            "report_delivered": false,
            "pending_steers": 0,
            "orphaned": false,
            "actionable": true,
        }));
    }
    task_envelope(serde_json::json!({
        "state": "backgrounded",
        "task_call_id": task_call_id,
        "blocking": false,
        "tool_call_closed": true,
        "result_pending": !running.is_empty(),
        "report_available": !completed.is_empty(),
        "report_delivered": completed.iter().all(|_| true) && running.is_empty(),
        "children": children,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AsyncDelegationChildResult {
    label: String,
    status: String,
    report: Option<String>,
}

fn derive_async_delegation_status(children: &[AsyncDelegationChildResult]) -> &'static str {
    if children.iter().any(|child| child.status == "failed") {
        "failed"
    } else if children.iter().any(|child| child.status == "lost") {
        "lost"
    } else if children.iter().any(|child| child.status == "cancelled") {
        "cancelled"
    } else {
        "completed"
    }
}

fn format_async_delegation_result(
    task_call_id: &str,
    completed: &[AsyncDelegationChildResult],
    running: &[String],
) -> String {
    let status = derive_async_delegation_status(completed);
    let mut children = completed
        .iter()
        .map(|child| {
            let mut value = serde_json::json!({
                "task_call_id": task_call_id,
                "label": child.label,
                "agent": serde_json::Value::Null,
                "model": serde_json::Value::Null,
                "status": child.status,
                "blocking": false,
                "tool_call_closed": true,
                "result_pending": false,
                "report_available": child.report.is_some(),
                "report_delivered": true,
                "pending_steers": 0,
                "orphaned": child.status == "lost",
                "actionable": false,
                "newly_delivered": true,
            });
            if let Some(report) = &child.report {
                if matches!(child.status.as_str(), "failed" | "cancelled" | "lost") {
                    value["error"] = serde_json::json!(report);
                } else {
                    value["report"] = serde_json::json!(report);
                }
            }
            value
        })
        .collect::<Vec<_>>();
    for label in running {
        children.push(serde_json::json!({
            "task_call_id": task_call_id,
            "label": label,
            "agent": serde_json::Value::Null,
            "model": serde_json::Value::Null,
            "status": "backgrounded",
            "blocking": false,
            "tool_call_closed": true,
            "result_pending": true,
            "report_available": false,
            "report_delivered": false,
            "pending_steers": 0,
            "orphaned": false,
            "actionable": true,
        }));
    }
    task_envelope(serde_json::json!({
        "state": status,
        "task_call_id": task_call_id,
        "blocking": false,
        "tool_call_closed": true,
        "result_pending": false,
        "report_available": !completed.is_empty(),
        "report_delivered": true,
        "children": children,
    }))
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

/// Estimate the wire-side token total of a message history via the
/// cl100k_base fallback counter over each message's serialized form. Used
/// only for the `context_pruned` timeline event's before/after figures
/// (session-log-export Part C) — a faithful proxy, the same basis the
/// tokenizer-calibration sampler uses, not an exact provider count.
fn wire_token_total(history: &[Message]) -> u64 {
    history
        .iter()
        .map(|m| match serde_json::to_string(m) {
            Ok(s) => crate::tokens::count(&s) as u64,
            Err(_) => 0,
        })
        .sum()
}

/// Context-fill metrics for the auto-prune/auto-compact triggers
/// (implementation note). `ctx_pct` is the last request's
/// prompt size as a percentage of the model's context window; `prunable_pct`
/// is the prunable wire tokens as a percentage of the same window. Returns
/// `None` (ctx%-gated triggers inert) when the window size is unknown/zero or
/// no request has reported its usage yet — exactly the edge case the spec
/// requires the ctx%-gated paths to skip.
#[derive(Debug, Clone, Copy, PartialEq)]
struct ContextMetrics {
    ctx_pct: f64,
    prunable_pct: f64,
}

fn context_metrics(
    context_length: Option<u32>,
    input_tokens: Option<u64>,
    prunable_tokens: u64,
) -> Option<ContextMetrics> {
    let window = context_length.filter(|n| *n > 0)?;
    let used = input_tokens?;
    let window = f64::from(window);
    Some(ContextMetrics {
        ctx_pct: used as f64 / window * 100.0,
        prunable_pct: prunable_tokens as f64 / window * 100.0,
    })
}

/// One auto-prune boundary's effectiveness, for the escalate-to-compaction
/// policy (implementation note). Both figures are known
/// only when the model window + last usage are (ctx%-gated); a prune at an
/// unknown-window boundary records nothing (the escalation path stays inert,
/// exactly like the other ctx%-gated triggers).
#[derive(Debug, Clone, Copy, PartialEq)]
struct PruneEffectiveness {
    /// ctx% (input tokens / window) measured just before this prune.
    ctx_pct: f64,
    /// Tokens this prune saved, as a percentage of the model window.
    saved_pct: f64,
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

/// Classify a prune plan's targets into the telemetry reason string
/// (implementation note Part D): `overlap-merge` when
/// every elided body was an overlapping-read partial, `exact-identity` when
/// every body was a whole-body snapshot supersession, `mixed` when both
/// kinds fired in one prune. Empty plans never reach here (no event emitted).
fn classify_prune_reason(plan: &crate::engine::prune::DedupPlan) -> &'static str {
    let mut overlap = false;
    let mut exact = false;
    for t in &plan.targets {
        if t.elision.reason == crate::engine::prune::OVERLAP_REASON {
            overlap = true;
        } else {
            exact = true;
        }
    }
    match (overlap, exact) {
        (true, true) => "mixed",
        (true, false) => "overlap-merge",
        _ => "exact-identity",
    }
}

fn auto_prune_trigger_reason(
    cache_state: crate::engine::prune::CacheState,
    threshold_hit: bool,
) -> Option<&'static str> {
    match cache_state {
        crate::engine::prune::CacheState::Cold(
            crate::engine::prune::ColdReason::NoCacheProvider,
        ) => Some(AUTO_PRUNE_TRIGGER_NO_CACHE_PROVIDER),
        crate::engine::prune::CacheState::Cold(crate::engine::prune::ColdReason::TtlElapsed) => {
            Some(AUTO_PRUNE_TRIGGER_CACHE_ALREADY_COLD)
        }
        crate::engine::prune::CacheState::Cold(crate::engine::prune::ColdReason::UpstreamBust) => {
            Some(AUTO_PRUNE_TRIGGER_UPSTREAM_CACHE_BUST)
        }
        crate::engine::prune::CacheState::Hot if threshold_hit => {
            Some(AUTO_PRUNE_TRIGGER_WARM_THRESHOLD)
        }
        crate::engine::prune::CacheState::Hot => None,
    }
}

fn auto_prune_trigger_breaks_cache(trigger_reason: &str) -> bool {
    trigger_reason == AUTO_PRUNE_TRIGGER_WARM_THRESHOLD
}

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

/// The clear tool error returned when a `resume_handle` can't be rehydrated
/// (unknown, evicted, a `docs` run, or the feature is disabled). Tells the
/// caller to spawn a fresh subagent — never a silent cold start (GOALS §3c).
fn stale_handle_error(child_agent: &str) -> String {
    format!(
        "Error: no resumable subagent for that `resume_handle` (unknown, expired, \
         or not re-queryable). Spawn a fresh `{child_agent}` subagent instead (omit \
         `resume_handle`)."
    )
}

/// The footer appended to a re-queryable subagent's report carrying its
/// follow-up handle (GOALS §3c). Terse + machine-stable so the caller's model
/// can extract and re-use it.
fn handle_footer(handle: &str) -> String {
    format!("\n\n[follow-up handle: {handle} — pass as `resume_handle` to re-query this subagent]")
}

/// Run a child agent's loop to completion synchronously. Used for
/// noninteractive subagents — explore primarily. Drops the child's
/// per-turn events on the floor (the parent's history already has a
/// ToolStart/End representing this call); only the final text comes
/// back. The loop is bounded by the `max_turns` parameter (each role
/// passes its own named constant — explore/docs-answerer 64, docs
/// resolver 24) to bound runaway loops; the over-limit error reports
/// that limit.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_noninteractive(
    child: Agent,
    brief: String,
    session: Arc<Session>,
    locks: Arc<crate::locks::LockManager>,
    redact: Arc<RedactionTable>,
    cwd: std::path::PathBuf,
    interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    cancel: tokio_util::sync::CancellationToken,
    approver: Option<Arc<crate::approval::Approver>>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    loop_guard_threshold: u32,
    max_turns: usize,
    // Model-comparison tandem (shadow) set, forwarded so the `docs` pipeline's
    // resolver/answerer turns are shadowed when the feature is on.
    tandem: Option<crate::engine::schedule::TandemSet>,
    event_tx: Option<mpsc::Sender<TurnEvent>>,
    steer_target: Option<NoninteractiveSteerTarget>,
) -> Result<String> {
    // The docs pipeline (the only other caller) neither rehydrates nor
    // seeds: a fresh transcript, no prior history, and a throwaway seed
    // collector. It only needs the report text.
    let out = run_noninteractive_resumable(
        child,
        brief,
        Vec::new(),
        crate::engine::seed_collector::SeedCollector::new(),
        session,
        locks,
        redact,
        cwd,
        interrupts,
        cancel,
        approver,
        resource_scheduler,
        loop_guard_threshold,
        max_turns,
        tandem,
        event_tx,
        steer_target,
    )
    .await?;
    Ok(out.report)
}

#[derive(Debug, Clone)]
pub(crate) struct NoninteractiveSteerTarget {
    task_call_id: String,
    label: String,
}

impl NoninteractiveSteerTarget {
    pub(crate) fn new(task_call_id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            task_call_id: task_call_id.into(),
            label: label.into(),
        }
    }
}

impl NoninteractiveSteerTarget {
    fn lineage(&self) -> crate::session::SessionEventLineage {
        crate::session::SessionEventLineage {
            task_call_id: self.task_call_id.clone(),
            label: self.label.clone(),
        }
    }
}

#[derive(Default)]
struct PendingNestedDeltas {
    assistant: Option<(String, String)>,
    reasoning: Option<(String, String)>,
}

impl PendingNestedDeltas {
    fn push_assistant(&mut self, agent: String, delta: String) {
        match self.assistant.as_mut() {
            Some((current_agent, current_delta)) if current_agent == &agent => {
                current_delta.push_str(&delta);
            }
            _ => {
                self.assistant = Some((agent, delta));
            }
        }
    }

    fn push_reasoning(&mut self, agent: String, delta: String) {
        match self.reasoning.as_mut() {
            Some((current_agent, current_delta)) if current_agent == &agent => {
                current_delta.push_str(&delta);
            }
            _ => {
                self.reasoning = Some((agent, delta));
            }
        }
    }

    fn drain(&mut self) -> Vec<TurnEvent> {
        let mut out = Vec::new();
        if let Some((agent, delta)) = self.reasoning.take()
            && !delta.is_empty()
        {
            out.push(TurnEvent::ReasoningDelta { agent, delta });
        }
        if let Some((agent, delta)) = self.assistant.take()
            && !delta.is_empty()
        {
            out.push(TurnEvent::AssistantTextDelta { agent, delta });
        }
        out
    }
}

fn wrap_noninteractive_child_event(
    target: &NoninteractiveSteerTarget,
    inner: TurnEvent,
) -> TurnEvent {
    TurnEvent::NestedTurn {
        task_call_id: target.task_call_id.clone(),
        label: target.label.clone(),
        parent_task_call_id: None,
        inner: Box::new(inner),
    }
}

async fn send_wrapped_noninteractive_event(
    tx: &mpsc::Sender<TurnEvent>,
    target: &NoninteractiveSteerTarget,
    event: TurnEvent,
) -> bool {
    tx.send(wrap_noninteractive_child_event(target, event))
        .await
        .is_ok()
}

async fn flush_nested_deltas(
    tx: &mpsc::Sender<TurnEvent>,
    target: &NoninteractiveSteerTarget,
    pending: &mut PendingNestedDeltas,
) -> bool {
    for event in pending.drain() {
        if !send_wrapped_noninteractive_event(tx, target, event).await {
            return false;
        }
    }
    true
}

fn spawn_noninteractive_event_forwarder(
    mut rx: mpsc::Receiver<TurnEvent>,
    event_tx: Option<mpsc::Sender<TurnEvent>>,
    target: Option<NoninteractiveSteerTarget>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (Some(event_tx), Some(target)) = (event_tx, target) else {
            while rx.recv().await.is_some() {}
            return;
        };

        let mut pending = PendingNestedDeltas::default();
        let mut flush_interval = tokio::time::interval(Duration::from_millis(100));
        flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                maybe_event = rx.recv() => {
                    let Some(event) = maybe_event else {
                        let _ = flush_nested_deltas(&event_tx, &target, &mut pending).await;
                        break;
                    };
                    match event {
                        TurnEvent::AssistantTextDelta { agent, delta } => {
                            pending.push_assistant(agent, delta);
                        }
                        TurnEvent::ReasoningDelta { agent, delta } => {
                            pending.push_reasoning(agent, delta);
                        }
                        other => {
                            if !flush_nested_deltas(&event_tx, &target, &mut pending).await {
                                break;
                            }
                            if !send_wrapped_noninteractive_event(&event_tx, &target, other).await {
                                break;
                            }
                        }
                    }
                }
                _ = flush_interval.tick() => {
                    if !flush_nested_deltas(&event_tx, &target, &mut pending).await {
                        break;
                    }
                }
            }
        }
    })
}

fn render_noninteractive_steers(
    steers: &[crate::db::task_delegations::TaskDelegationSteerRow],
) -> String {
    let mut out = String::from("[queued delegation steer]\n");
    for (idx, steer) in steers.iter().enumerate() {
        out.push_str(&format!(
            "{}. from {}: {}\n",
            idx + 1,
            steer.origin_principal,
            steer.body.trim()
        ));
    }
    out.push_str("\nContinue the delegated task, incorporating the queued steer above.");
    out
}

/// A finished noninteractive run: the report text plus the full transcript
/// (so the driver can persist a re-query handle, GOALS §3c).
pub(crate) struct NoninteractiveOutcome {
    /// The subagent's final text + any deferred-log section.
    pub report: String,
    /// The complete `Vec<Message>` transcript (prior history + this run),
    /// persisted as a handle for read-only noninteractive subagents in
    /// normal mode.
    pub history: Vec<Message>,
}

#[derive(Debug)]
pub(crate) struct NoninteractiveRunError {
    source: anyhow::Error,
    history: Vec<Message>,
}

impl NoninteractiveRunError {
    fn new(source: anyhow::Error, history: Vec<Message>) -> Self {
        Self { source, history }
    }

    fn into_parts(self) -> (String, Vec<Message>) {
        (format!("{:#}", self.source), self.history)
    }
}

impl std::fmt::Display for NoninteractiveRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.source)
    }
}

impl std::error::Error for NoninteractiveRunError {}

/// Run a child agent's loop to completion, optionally **rehydrated** from a
/// prior transcript (`prior_history`) and collecting any `seed` calls into
/// `seeds`. Returns the report + the full transcript. [`run_noninteractive`]
/// is the no-rehydrate, no-seed wrapper used by the `docs` pipeline.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_noninteractive_resumable(
    child: Agent,
    brief: String,
    prior_history: Vec<Message>,
    seeds: crate::engine::seed_collector::SeedCollector,
    session: Arc<Session>,
    locks: Arc<crate::locks::LockManager>,
    redact: Arc<RedactionTable>,
    cwd: std::path::PathBuf,
    interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    cancel: tokio_util::sync::CancellationToken,
    approver: Option<Arc<crate::approval::Approver>>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    loop_guard_threshold: u32,
    max_turns: usize,
    // Model-comparison tandem (shadow) set (`model-comparison-tandem-
    // inference.md`). `Some(set)` when the session has model-comparison on, so
    // this leaf subagent's (`builder`/`explore`/`docs`) substantive turns are
    // shadowed too; `None`/empty disables it. Cheap clone per call.
    tandem: Option<crate::engine::schedule::TandemSet>,
    event_tx: Option<mpsc::Sender<TurnEvent>>,
    steer_target: Option<NoninteractiveSteerTarget>,
) -> std::result::Result<NoninteractiveOutcome, NoninteractiveRunError> {
    use crate::engine::agent::turn_with_backup;

    let (child_tx, child_rx) = mpsc::channel::<TurnEvent>(64);
    let forwarder = spawn_noninteractive_event_forwarder(child_rx, event_tx, steer_target.clone());

    let agent = Arc::new(child);
    // Per-turn backup-model fallback for the subagent (`per-model-
    // backup-fallback.md`): subagents inherit the *mechanism*, resolved by the
    // same model→provider→none order against the model the subagent runs on
    // (here, its own `agent.model`). Resolved once for the run — the model is
    // fixed for the subagent's lifetime, and resolution is per-turn-equivalent
    // (the subagent always tries its primary model first each turn).
    let backup_model = resolve_backup_model_for(&cwd, &agent.model);
    // Rehydration: a follow-up starts from the subagent's prior transcript,
    // so it answers with full knowledge of what it already did (GOALS §3c).
    let mut history: Vec<Message> = prior_history;
    let mut next_prompt = Message::user(brief);
    // A noninteractive subagent's own deferred-log (`plan.md §3d`). The
    // bundled leaves (explore/docs) lack `defer_to_orchestrator`, so this
    // stays empty for them; a custom subagent that holds the tool gets its
    // deferred items folded into the leaf report it returns up.
    let deferred_log = crate::engine::deferred::DeferredLog::new();

    for _ in 0..max_turns {
        if let Some(target) = &steer_target {
            match session
                .db
                .drain_task_delegation_steers(&target.task_call_id, &target.label)
            {
                Ok(steers) if !steers.is_empty() => {
                    history.push(next_prompt);
                    next_prompt = Message::user(render_noninteractive_steers(&steers));
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        task_call_id = %target.task_call_id,
                        label = %target.label,
                        "drain delegation steer failed"
                    );
                }
            }
        }
        // Per-round id, shared with this turn's tandem shadows.
        let call_id = uuid::Uuid::new_v4();
        // Model-comparison tandem (shadow) set for this leaf subagent turn
        // (`builder`/`explore`/`docs`, `model-comparison-tandem-
        // inference.md`). Passed into `turn`, which dispatches the shadows from
        // the exact post-redaction body; a pure DB-only observer that never
        // enters the child's history or affects its loop. `None`/empty = off.
        let turn_future = turn_with_backup(
            &agent,
            backup_model.as_ref(),
            &mut history,
            next_prompt,
            session.clone(),
            locks.clone(),
            redact.clone(),
            cwd.clone(),
            interrupts.clone(),
            cancel.clone(),
            approver.clone(),
            None,
            resource_scheduler.clone(),
            loop_guard_threshold,
            // A noninteractive child delegation recomposes its own fresh
            // system prompt on spawn, so it never needs the live
            // instructions-file diff injection.
            false,
            deferred_log.clone(),
            seeds.clone(),
            call_id,
            tandem.as_ref(),
            None,
            &child_tx,
        );
        let outcome_future = async {
            if let Some(target) = &steer_target {
                crate::session::with_session_event_lineage(Some(target.lineage()), turn_future)
                    .await
            } else {
                turn_future.await
            }
        };
        let outcome = match outcome_future.await {
            Ok(outcome) => outcome,
            Err(error) => {
                drop(child_tx);
                let _ = forwarder.await;
                return Err(NoninteractiveRunError::new(error, history));
            }
        };
        match outcome {
            TurnOutcome::Continue => {
                next_prompt = history
                    .pop()
                    .expect("Continue with empty history is unreachable");
            }
            TurnOutcome::Done => {
                drop(child_tx);
                let _ = forwarder.await;
                // No `return` tool call: fall back to wrapping the final text
                // (envelope-holding agents only — the `docs` pipeline keeps its
                // plain answer). `None` selects the fallback path.
                let report = assemble_subagent_report(&agent, &history, &deferred_log, None);
                return Ok(NoninteractiveOutcome { report, history });
            }
            TurnOutcome::Return { fields } => {
                drop(child_tx);
                let _ = forwarder.await;
                let report =
                    assemble_subagent_report(&agent, &history, &deferred_log, Some(&fields));
                return Ok(NoninteractiveOutcome { report, history });
            }
            TurnOutcome::SpawnSubagent { .. }
            | TurnOutcome::SpawnNoninteractive { .. }
            | TurnOutcome::SpawnNoninteractiveBatch { .. }
            | TurnOutcome::TaskControl { .. }
            | TurnOutcome::ToolResult { .. }
            | TurnOutcome::ScheduleAction { .. }
            | TurnOutcome::Spawn { .. }
            | TurnOutcome::Handoff { .. } => {
                // explore is a leaf without `task`/`schedule`/`handoff`; this
                // shouldn't happen, but if it does we bail rather than spin
                // (the single async-job + primary-swap authority is the main
                // driver, never a noninteractive subagent — §22 anti-runaway).
                drop(child_tx);
                let _ = forwarder.await;
                return Err(NoninteractiveRunError::new(
                    anyhow::anyhow!(
                        "noninteractive agent `{}` attempted to delegate or schedule a job",
                        agent.name
                    ),
                    history,
                ));
            }
        }
    }
    drop(child_tx);
    let _ = forwarder.await;
    Err(NoninteractiveRunError::new(
        anyhow::anyhow!(
            "noninteractive agent `{}` exceeded {max_turns} turns",
            agent.name
        ),
        history,
    ))
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
    let (text, truncated) = cap_chars(&text, max_chars);
    FailedTurnPromptSummary {
        text,
        truncated,
        has_non_text_parts,
    }
}

fn cap_chars(text: &str, max_chars: usize) -> (String, bool) {
    let mut out = String::new();
    let mut chars = text.chars();
    for _ in 0..max_chars {
        let Some(ch) = chars.next() else {
            return (out, false);
        };
        out.push(ch);
    }
    if chars.next().is_some() {
        out.push_str("...");
        (out, true)
    } else {
        (out, false)
    }
}

fn failure_retry_decision_and_rationale(
    class: &str,
    provider_status: Option<u16>,
) -> (&'static str, &'static str) {
    match class {
        "timeout_ttft" => ("fail_fast", "time_to_first_token_timeout"),
        "timeout_idle" => ("fail_fast", "stream_idle_timeout"),
        "network" => (
            "terminal_after_retry_layer",
            "transport_or_provider_failure_after_retry_layer",
        ),
        "missing_tool_entitlement" | "client_side_tools_unsupported" => {
            ("fail_fast", "client_side_capability_block")
        }
        _ if provider_status.is_some_and(|status| status == 429 || status == 503) => (
            "terminal_after_retry_layer",
            "retryable_http_status_terminal",
        ),
        _ if provider_status.is_some_and(|status| (500..=599).contains(&status)) => {
            ("terminal_after_retry_layer", "server_http_status_terminal")
        }
        _ if provider_status.is_some_and(|status| (400..=499).contains(&status)) => {
            ("fail_fast", "non_retryable_http_status")
        }
        _ => ("fail_fast", "non_retryable_or_unclassified_failure"),
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
    Some(cap_chars(&redact.scrub(trimmed), max_chars).0)
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
                        let command = first_line_capped_ascii(command, 100);
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

fn first_line_capped_ascii(s: &str, max: usize) -> String {
    let line = s.lines().next().unwrap_or("").trim();
    if line.chars().count() > max {
        let mut capped: String = line.chars().take(max).collect();
        capped.push_str("...");
        capped
    } else {
        line.to_string()
    }
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
mod tests {
    use super::*;

    #[tokio::test]
    async fn noninteractive_event_forwarder_wraps_child_events() {
        let (child_tx, child_rx) = mpsc::channel(8);
        let (parent_tx, mut parent_rx) = mpsc::channel(8);
        let target = NoninteractiveSteerTarget::new("task-1", "default");
        let forwarder =
            spawn_noninteractive_event_forwarder(child_rx, Some(parent_tx), Some(target));

        child_tx
            .send(TurnEvent::AssistantTextDelta {
                agent: "Explore".into(),
                delta: "hel".into(),
            })
            .await
            .unwrap();
        child_tx
            .send(TurnEvent::AssistantTextDelta {
                agent: "Explore".into(),
                delta: "lo".into(),
            })
            .await
            .unwrap();
        child_tx
            .send(TurnEvent::ToolStart {
                agent: "Explore".into(),
                call_id: "call-1".into(),
                tool: "read".into(),
                args: serde_json::json!({"path":"README.md"}),
            })
            .await
            .unwrap();
        drop(child_tx);
        forwarder.await.unwrap();

        match parent_rx.recv().await.unwrap() {
            TurnEvent::NestedTurn {
                task_call_id,
                label,
                parent_task_call_id,
                inner,
            } => {
                assert_eq!(task_call_id, "task-1");
                assert_eq!(label, "default");
                assert_eq!(parent_task_call_id, None);
                assert!(matches!(
                    inner.as_ref(),
                    TurnEvent::AssistantTextDelta { agent, delta }
                        if agent == "Explore" && delta == "hello"
                ));
            }
            other => panic!("expected nested assistant delta, got {other:?}"),
        }
        match parent_rx.recv().await.unwrap() {
            TurnEvent::NestedTurn { inner, .. } => assert!(matches!(
                inner.as_ref(),
                TurnEvent::ToolStart { agent, call_id, tool, .. }
                    if agent == "Explore" && call_id == "call-1" && tool == "read"
            )),
            other => panic!("expected nested tool start, got {other:?}"),
        }
        assert!(parent_rx.recv().await.is_none());
    }

    /// Build a driver rooted on a keyless localhost agent (the model is
    /// never called by the action-dispatch paths under test).
    fn test_driver(max_schedules: usize) -> (Driver, tempfile::TempDir) {
        use crate::config::providers::{ActiveModelRef, ProviderEntry, ProvidersConfig};
        use std::collections::BTreeMap;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Arc::new(Session::create(db.clone(), root.clone(), "Build").unwrap());
        let locks = Arc::new(crate::locks::LockManager::from_db(db).unwrap());
        let rcfg = crate::config::extended::RedactConfig::default();
        let redact = Arc::new(RedactionTable::build(&rcfg, &root).unwrap());

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
        let agent = Arc::new(Agent {
            name: "Build".into(),
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
        let driver = Driver::with_max_schedules(session, locks, redact, root, agent, max_schedules);
        (driver, tmp)
    }

    fn set_active_delegated_recursion(
        driver: &mut Driver,
        ctx: crate::engine::builtin::DelegationRecursionContext,
    ) {
        let mut agent = (*driver.stack[0].agent).clone();
        agent.delegated = true;
        agent.delegation_recursion = ctx;
        driver.stack[0].agent = Arc::new(agent);
    }

    fn write_recursion_policy(root: &std::path::Path) {
        let cockpit = root.join(".cockpit");
        std::fs::create_dir_all(&cockpit).unwrap();
        std::fs::write(
            cockpit.join("config.json"),
            r#"{
              "delegation": {
                "recursionEnabled": true,
                "defaultRecursionDepth": 0,
                "recursion": {
                  "Build": {
                    "allowedTargets": ["Build"],
                    "maxDepth": 6
                  }
                }
              }
            }"#,
        )
        .unwrap();
    }

    #[test]
    fn task_recursion_rejects_delegated_child_without_budget() {
        let (mut driver, _tmp) = test_driver(1);
        set_active_delegated_recursion(
            &mut driver,
            crate::engine::builtin::DelegationRecursionContext::default(),
        );

        let err = driver
            .resolve_task_recursion("explore", Some(0), &None)
            .expect_err("no recursive budget");
        assert!(
            err.contains("not allowed") || err.contains("no remaining"),
            "{err}"
        );
    }

    #[test]
    fn task_recursion_must_reduce_inherited_depth() {
        let (mut driver, _tmp) = test_driver(1);
        set_active_delegated_recursion(
            &mut driver,
            crate::engine::builtin::DelegationRecursionContext {
                enabled: true,
                remaining_depth: 1,
                allowed_targets: vec!["explore".to_string()],
                same_model_only: true,
            },
        );

        let err = driver
            .resolve_task_recursion("explore", Some(1), &None)
            .expect_err("child depth must be lower than parent depth");
        assert!(err.contains("exceeds"), "{err}");

        let child = driver
            .resolve_task_recursion("explore", Some(0), &None)
            .expect("leaf explore recursion allowed");
        assert_eq!(child.remaining_depth, 0);
        assert!(child.same_model_only);
        assert_eq!(child.allowed_targets, vec!["explore".to_string()]);
    }

    #[test]
    fn task_recursion_rejects_model_selector_for_same_model_special_case() {
        let (mut driver, _tmp) = test_driver(1);
        set_active_delegated_recursion(
            &mut driver,
            crate::engine::builtin::DelegationRecursionContext {
                enabled: true,
                remaining_depth: 1,
                allowed_targets: vec!["explore".to_string()],
                same_model_only: true,
            },
        );
        let model = crate::engine::model_roles::DelegationModelSelector::from_value(Some(
            &serde_json::json!({
                "kind": "category",
                "category": "cheap_code"
            }),
        ))
        .unwrap();

        let err = driver
            .resolve_task_recursion("explore", Some(0), &model)
            .expect_err("same-model recursion rejects model selector");
        assert!(err.contains("must omit `model`"), "{err}");
    }

    #[test]
    fn task_recursion_rejects_deepthink_depth() {
        let (driver, _tmp) = test_driver(1);
        let err = driver
            .resolve_task_recursion("deepthink", Some(1), &None)
            .expect_err("deepthink is always a leaf");
        assert!(err.contains("tool-free leaf"), "{err}");

        let leaf = driver
            .resolve_task_recursion("deepthink", Some(0), &None)
            .expect("leaf deepthink delegation is allowed");
        assert_eq!(leaf.remaining_depth, 0);
        assert!(leaf.allowed_targets.is_empty());
    }

    #[tokio::test]
    async fn quick_recursion_override_off_rejects_root_recursive_depth() {
        let (mut driver, tmp) = test_driver(1);
        write_recursion_policy(tmp.path());
        let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

        driver
            .run_control(
                DriverControl::SetDelegationRecursion {
                    enabled: false,
                    default_depth: 0,
                },
                &tx,
            )
            .await;

        let err = driver
            .resolve_task_recursion("Build", Some(1), &None)
            .expect_err("quick off disables root recursion");
        assert!(err.contains("disabled"), "{err}");
    }

    #[tokio::test]
    async fn quick_recursion_override_depths_apply_without_bypassing_policy() {
        for depth in 1..=6 {
            let (mut driver, tmp) = test_driver(1);
            write_recursion_policy(tmp.path());
            let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

            driver
                .run_control(
                    DriverControl::SetDelegationRecursion {
                        enabled: true,
                        default_depth: depth,
                    },
                    &tx,
                )
                .await;

            let ctx = driver
                .resolve_task_recursion("Build", None, &None)
                .expect("default depth grants allowed recursive child");
            assert_eq!(ctx.remaining_depth, depth);
            assert!(ctx.enabled);

            let err = driver
                .resolve_task_recursion("Plan", None, &None)
                .expect_err("override must not bypass allowed-target policy");
            assert!(err.contains("may not grant"), "{err}");
        }
    }

    #[tokio::test]
    async fn goal_idle_guard_needs_intervention_without_blocking_goal() {
        let (mut driver, _tmp) = test_driver(1);
        driver
            .session
            .db
            .create_session_goal(
                driver.session.id,
                &driver.session.project_id,
                "ship goal flow",
                None,
                None,
            )
            .unwrap();
        driver
            .stack
            .first_mut()
            .unwrap()
            .history
            .push(Message::assistant(
                "I will keep working without using a tool.",
            ));
        driver.goal_no_tool_idle_count = 2;

        let (queue_updates_tx, _queue_updates_rx) = mpsc::unbounded_channel();
        let input_queue = crate::engine::message::UserSubmissionQueue::new(queue_updates_tx);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);

        driver
            .maybe_continue_active_goal(&input_queue, &tx)
            .await
            .unwrap();

        let notice = rx.try_recv().expect("intervention notice should emit");
        match notice {
            TurnEvent::Notice { text } => {
                assert!(
                    text.contains("needs intervention")
                        && text.contains("agent_failed_to_progress")
                        && !text.contains("goal: blocked"),
                    "notice must describe runtime intervention, not terminal block: {text}"
                );
            }
            other => panic!("expected intervention Notice, got {other:?}"),
        }
        let goal = driver
            .session
            .db
            .current_session_goal(driver.session.id, false)
            .unwrap()
            .unwrap();
        assert_eq!(
            goal.status,
            crate::db::session_goals::GoalStatus::Active,
            "runtime non-progress must not terminally block the persisted goal"
        );
        assert_eq!(
            goal.blocked_attempts, 0,
            "driver intervention must not consume model-facing blocked attempts"
        );
        assert_eq!(driver.goal_no_tool_idle_count, 0);
        assert!(driver.goal_idle_intervention_pending);

        driver
            .maybe_continue_active_goal(&input_queue, &tx)
            .await
            .unwrap();
        assert!(
            rx.try_recv().is_err(),
            "latched intervention should not spin or emit duplicate notices"
        );

        driver
            .stack
            .first_mut()
            .unwrap()
            .history
            .push(Message::user("Try again with a concrete tool call."));
        driver
            .maybe_continue_active_goal(&input_queue, &tx)
            .await
            .unwrap();
        assert!(
            !driver.goal_idle_intervention_pending,
            "a real follow-up should clear the intervention latch"
        );
    }

    #[tokio::test]
    async fn goal_continue_only_maintenance_events_emits_diagnostic_and_keeps_latch() {
        let (mut driver, _tmp) = test_driver(1);
        driver
            .session
            .db
            .create_session_goal(
                driver.session.id,
                &driver.session.project_id,
                "ship goal flow",
                None,
                None,
            )
            .unwrap();
        driver.goal_idle_intervention_pending = true;
        let anchor = driver.latest_session_event_seq();
        driver
            .session
            .record_event(
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("Build"),
                None,
                &serde_json::json!({"text": "continue"}),
            )
            .unwrap();
        driver
            .session
            .record_event(
                crate::db::session_log::SessionEventKind::SkillAutoSelect,
                Some("Build"),
                None,
                &serde_json::json!({"rejections": []}),
            )
            .unwrap();
        driver
            .session
            .record_context_pruned(
                "Build",
                true,
                4,
                4,
                120,
                120,
                &[],
                "exact-identity",
                0,
                None,
                Some("cache_already_cold"),
            )
            .unwrap();
        let call_id = uuid::Uuid::new_v4().to_string();
        driver
            .session
            .record_event(
                crate::db::session_log::SessionEventKind::InferenceRequest,
                Some("Build"),
                Some(&call_id),
                &serde_json::json!({"usage": null}),
            )
            .unwrap();

        assert!(
            !driver.goal_continue_progress_since(anchor),
            "skill diagnostics, context_pruned, and inference_request are maintenance only"
        );

        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
        driver.emit_goal_continue_no_progress(anchor, &tx).await;
        let notice = rx.try_recv().expect("diagnostic notice should emit");
        match notice {
            TurnEvent::Notice { text } => {
                assert!(text.contains("agent_failed_to_progress_after_continue"));
            }
            other => panic!("expected diagnostic Notice, got {other:?}"),
        }
        assert!(
            driver.goal_idle_intervention_pending,
            "no-progress continue keeps the intervention latch active"
        );
        let events = driver
            .session
            .db
            .list_session_events(driver.session.id)
            .unwrap();
        let diagnostic = events
            .iter()
            .find(|event| event.kind == "goal_progress_diagnostic")
            .expect("goal progress diagnostic is durable");
        assert_eq!(diagnostic.data["kind"], "goal_continue_no_progress");
        assert_eq!(diagnostic.data["anchor_seq"], serde_json::json!(anchor));
    }

    #[tokio::test]
    async fn goal_continue_progress_accepts_goal_status_update() {
        let (driver, _tmp) = test_driver(1);
        driver
            .session
            .db
            .create_session_goal(
                driver.session.id,
                &driver.session.project_id,
                "ship goal flow",
                None,
                None,
            )
            .unwrap();
        let anchor = driver.latest_session_event_seq();
        driver
            .session
            .record_event(
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("Build"),
                None,
                &serde_json::json!({"text": "continue"}),
            )
            .unwrap();
        driver
            .session
            .db
            .current_session_goal(driver.session.id, true)
            .unwrap();
        driver
            .session
            .db
            .update_session_goal(
                driver.session.id,
                crate::db::session_goals::GoalStatus::Complete,
                Some("done"),
                None,
                None,
            )
            .unwrap();

        assert!(
            driver.goal_continue_progress_since(anchor),
            "terminal goal status is progress even if no further tool is needed"
        );
    }

    #[tokio::test]
    async fn failed_turn_recovery_records_retry_context_and_progress() {
        let (mut driver, _tmp) = test_driver(1);
        driver
            .session
            .db
            .create_session_goal(
                driver.session.id,
                &driver.session.project_id,
                "ship the recovery path",
                None,
                None,
            )
            .unwrap();
        driver.stack[0]
            .history
            .push(write_turn("edit-1", "src/lib.rs"));
        driver.stack[0]
            .history
            .push(bash_turn("bash-1", "cargo test"));
        let agent = driver.stack[0].agent.clone();
        let attempted = Message::user("continue implementing the retry contract");
        let call_id = uuid::Uuid::new_v4();
        let failure = crate::engine::model::InferenceFailure {
            provider: "codex-oauth".into(),
            model: "gpt-5.5".into(),
            phase: "first_token".into(),
            class: "network".into(),
            elapsed_ms: 42_000,
            detail: "HTTP 503 Service Unavailable".into(),
        };
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);

        driver
            .record_failed_turn_recovery(&agent, &attempted, call_id, &failure, &tx)
            .await;

        let notice = rx.try_recv().expect("retry notice emitted");
        match notice {
            TurnEvent::Notice { text } => {
                assert!(text.contains("continue"));
                assert!(text.contains("retry the same turn"));
            }
            other => panic!("expected Notice, got {other:?}"),
        }
        let events = driver
            .session
            .db
            .list_session_events(driver.session.id)
            .unwrap();
        let recovery = events
            .iter()
            .find(|event| event.kind == "failed_turn_recovery")
            .expect("failed_turn_recovery event recorded");
        let call_id_str = call_id.to_string();
        assert_eq!(recovery.call_id.as_deref(), Some(call_id_str.as_str()));
        assert_eq!(recovery.data["status"], "needs_retry");
        assert_eq!(
            recovery.data["active_prompt"]["text"],
            "continue implementing the retry contract"
        );
        assert_eq!(
            recovery.data["active_goal"]["objective"],
            "ship the recovery path"
        );
        assert_eq!(recovery.data["provider"], "codex-oauth");
        assert_eq!(recovery.data["model"], "gpt-5.5");
        assert_eq!(recovery.data["wire_api"], "completions");
        assert_eq!(recovery.data["phase_reached"], "first_token");
        assert_eq!(
            recovery.data["retry_final_decision"],
            "terminal_after_retry_layer"
        );
        assert_eq!(
            recovery.data["recommended_action"]["kind"],
            "retry_same_turn"
        );
        assert_eq!(recovery.data["last_action"], "bash `cargo test`");
        assert_eq!(recovery.data["files_edited"][0]["path"], "src/lib.rs");
        assert_eq!(recovery.data["commands"][0]["verification"], true);
        assert_eq!(
            recovery.data["worktree"]["dirty_files"][0],
            serde_json::json!("src/lib.rs")
        );
    }

    #[tokio::test]
    async fn failed_turn_continue_reuses_and_consumes_recovery_record() {
        let (driver, _tmp) = test_driver(1);
        let recovery_id = uuid::Uuid::new_v4().to_string();
        driver
            .session
            .record_event(
                crate::db::session_log::SessionEventKind::FailedTurnRecovery,
                Some("Build"),
                Some(&recovery_id),
                &serde_json::json!({
                    "status": "needs_retry",
                    "recovery_id": recovery_id.clone(),
                    "active_prompt": {
                        "text": "original failed prompt",
                        "truncated": false,
                        "has_non_text_parts": false
                    }
                }),
            )
            .unwrap();

        let (id, prompt) = driver
            .failed_turn_retry_prompt_for("continue")
            .expect("continue should recover prompt");
        assert_eq!(id, recovery_id);
        assert_eq!(prompt, "original failed prompt");

        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
        driver.record_failed_turn_retry_started(&id, &tx).await;
        assert!(matches!(
            rx.try_recv().unwrap(),
            TurnEvent::Notice { text } if text.contains("retrying failed turn")
        ));
        assert!(
            driver.failed_turn_retry_prompt_for("continue").is_none(),
            "retry_started should prevent stale repeated continue"
        );
    }

    /// Build a driver rooted on the real `Auto` front-door agent — the
    /// handoff scenario. The model is keyless localhost and never called:
    /// these tests drive [`Driver::apply_handoff`] (the engine side of a
    /// model-issued `handoff` call) directly, so no inference round-trips.
    fn auto_rooted_driver() -> (Driver, tempfile::TempDir) {
        let (mut driver, tmp) = test_driver(1);
        // Re-root on a genuine `Auto`, built through the same factory the
        // session worker uses, so its tool surface + name match production.
        let auto = crate::engine::builtin::load("Auto", &driver.spawn_args(true)).unwrap();
        driver.stack[0].agent = Arc::new(auto);
        driver.session.set_active_agent("Auto").unwrap();
        (driver, tmp)
    }

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

    /// An assistant turn carrying a single `writeunlock` tool call on `path`.
    fn write_turn(call_id: &str, path: &str) -> Message {
        use crate::engine::message::AssistantContent;
        use rig::OneOrMany;
        use rig::message::{ToolCall, ToolFunction};
        Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
                id: call_id.to_string(),
                call_id: None,
                function: ToolFunction {
                    name: "writeunlock".to_string(),
                    arguments: serde_json::json!({ "path": path }),
                },
                signature: None,
                additional_params: None,
            })),
        }
    }

    fn read_turn(call_id: &str, path: &str) -> Message {
        use crate::engine::message::AssistantContent;
        use rig::OneOrMany;
        use rig::message::{ToolCall, ToolFunction};
        Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
                id: call_id.to_string(),
                call_id: None,
                function: ToolFunction {
                    name: "read".to_string(),
                    arguments: serde_json::json!({ "path": path }),
                },
                signature: None,
                additional_params: None,
            })),
        }
    }

    fn bash_turn(call_id: &str, command: &str) -> Message {
        use crate::engine::message::AssistantContent;
        use rig::OneOrMany;
        use rig::message::{ToolCall, ToolFunction};
        Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
                id: call_id.to_string(),
                call_id: None,
                function: ToolFunction {
                    name: "bash".to_string(),
                    arguments: serde_json::json!({ "command": command }),
                },
                signature: None,
                additional_params: None,
            })),
        }
    }

    /// A `builder` delegation that wrote a file returns a structured envelope with
    /// `files_changed` derived deterministically from its edits — not prose.
    #[test]
    fn builder_report_is_structured_envelope_with_host_derived_files() {
        let (driver, _tmp) = test_driver(1);
        let builder = crate::engine::builtin::load("builder", &driver.spawn_args(true)).unwrap();
        let history = vec![
            write_turn("w1", "/src/a.rs"),
            Message::tool_result_with_call_id("w1".to_string(), None, "[hash=abc123 ok]"),
            Message::assistant("I changed the file."),
        ];
        let deferred = crate::engine::deferred::DeferredLog::new();
        // Via the structural `return` tool: the model fields plus the host
        // ledger render together.
        let fields = serde_json::json!({
            "accomplished": "added the flag",
            "decisions_made": "used a u32",
        });
        let report = assemble_subagent_report(&builder, &history, &deferred, Some(&fields));
        assert!(report.contains("## Accomplished"));
        assert!(report.contains("added the flag"));
        assert!(report.contains("## Decisions made"));
        assert!(report.contains("## Files changed"));
        assert!(report.contains("/src/a.rs"));
        assert!(report.contains("abc123"));
    }

    /// A read-only `explore` delegation returns the same envelope shape with an
    /// empty `files_changed` (it issued no write/edit/unlock calls), and the
    /// no-return-tool fallback wraps its final text as `accomplished`.
    #[test]
    fn explore_report_envelope_has_empty_files_and_fallback_wraps_final_text() {
        let (driver, _tmp) = test_driver(1);
        let explore = crate::engine::builtin::load("explore", &driver.spawn_args(false)).unwrap();
        let history = vec![Message::assistant("the bug is in foo.rs line 10")];
        let deferred = crate::engine::deferred::DeferredLog::new();
        // No `return` call (fallback): final text becomes `accomplished`; no
        // files section because nothing was written.
        let report = assemble_subagent_report(&explore, &history, &deferred, None);
        assert!(report.contains("## Accomplished"));
        assert!(report.contains("the bug is in foo.rs line 10"));
        assert!(
            !report.contains("## Files changed"),
            "read-only run must not list files: {report}"
        );
    }

    /// The `docs` pipeline is exempt: a `docs`-style agent holds no `return`
    /// tool, so `assemble_subagent_report` returns its plain answer unchanged
    /// (no envelope headers).
    #[test]
    fn docs_style_agent_without_return_tool_reports_plain_answer() {
        // A bare agent with an empty toolbox stands in for the `docs` answerer
        // (a pipeline stage, not an AgentDef) — it holds no `return` tool.
        let (driver, _tmp) = test_driver(1);
        let plain = Agent {
            name: "docs-answerer".into(),
            system: String::new(),
            role_prompt: String::new(),
            tools: crate::engine::tool::ToolBox::new(),
            model: driver.stack[0].agent.model.clone(),
            params: crate::engine::model::ModelParams::default(),
            scan_tool_results: false,
            llm_mode: crate::config::extended::LlmMode::default(),
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            env_overlay: driver.stack[0].agent.env_overlay.clone(),
        };
        let history = vec![Message::assistant("The answer is to call foo() with bar.")];
        let deferred = crate::engine::deferred::DeferredLog::new();
        let report = assemble_subagent_report(&plain, &history, &deferred, None);
        assert_eq!(report, "The answer is to call foo() with bar.");
        assert!(!report.contains("## Accomplished"));
    }

    #[test]
    fn failed_subagent_progress_lists_partial_edits_and_incomplete_verification() {
        let history = vec![
            read_turn("r1", "/src/a.rs"),
            Message::tool_result_with_call_id("r1".to_string(), None, "[hash=old ok]"),
            write_turn("w1", "/src/a.rs"),
            Message::tool_result_with_call_id("w1".to_string(), None, "[hash=abc123 ok]"),
            bash_turn("b1", "cargo test -p cockpit-cli"),
        ];

        let progress = partial_progress_from_history(&history);
        assert_eq!(progress.files_read, vec!["/src/a.rs"]);
        assert_eq!(progress.files_edited[0].path, "/src/a.rs");
        assert_eq!(progress.files_edited[0].hash.as_deref(), Some("abc123"));
        assert_eq!(
            progress.verification_state.as_deref(),
            Some("not_completed")
        );
        assert_eq!(progress.review_state.as_deref(), Some("needs_review"));
        assert_eq!(progress.dirty_owned_changes, vec!["/src/a.rs"]);

        let report = render_failed_subagent_report(
            "Error: noninteractive agent `builder` exceeded 16 turns",
            &progress,
        );
        assert!(report.contains("Partial progress"));
        assert!(report.contains("`/src/a.rs`"));
        assert!(report.contains("Verification did not complete"));
        assert!(report.contains("needs_review"));
        assert!(!report.contains("before starting"));
        assert!(!report.contains("no code changes"));
    }

    #[test]
    fn failed_subagent_before_first_tool_has_no_partial_progress() {
        let history = vec![Message::user("please edit a.rs")];
        let progress = partial_progress_from_history(&history);
        assert!(progress.is_empty());
        assert_eq!(
            render_failed_subagent_report("Error: model request failed", &progress),
            "Error: model request failed"
        );
    }

    #[test]
    fn spawn_gate_clamps_to_ceiling_and_requires_output_dir() {
        // Depth ceiling (GOALS §24): at the ceiling the spawn is refused and
        // the branch does its own work (clamp, don't crash). Below it, the
        // child depth advances by one.
        assert_eq!(spawn_gate(0, 3, "/tmp/out"), Ok(1));
        assert_eq!(spawn_gate(2, 3, "/tmp/out"), Ok(3));
        let refused = spawn_gate(3, 3, "/tmp/out").unwrap_err();
        assert!(refused.contains("depth ceiling 3"), "{refused}");
        assert!(refused.contains("yourself"), "{refused}");
        // A ceiling of 0 refuses even the root's first spawn.
        assert!(spawn_gate(0, 0, "/tmp/out").is_err());
        // Missing `output_dir` is refused with the dedicated-folder nudge.
        let no_dir = spawn_gate(0, 3, "   ").unwrap_err();
        assert!(no_dir.contains("output_dir"), "{no_dir}");
        assert!(no_dir.contains("dedicated"), "{no_dir}");
    }

    #[tokio::test]
    async fn set_swarm_config_threads_caps_to_authority() {
        let (mut driver, _tmp) = test_driver(8);
        driver.set_swarm_config(5, 0);
        assert_eq!(driver.swarm_max_depth, 5);
        assert_eq!(driver.swarm_max_concurrency, 0);
        // The authority received the (unlimited) cap: spawns never queue.
        for _ in 0..12 {
            assert!(
                driver
                    .schedule
                    .spawn_swarm(crate::engine::schedule::authority::SpawnSpec {
                        worker: crate::engine::schedule::authority::SpawnWorkerKind::Bee,
                        prompt: "s".into(),
                        output_dir: "/tmp/o".into(),
                        model: None,
                        depth: 1,
                        max_depth: 5,
                    })
                    .contains("scheduled")
            );
        }
        assert_eq!(driver.schedule.queued_swarm(), 0);
    }

    #[tokio::test]
    async fn unbounded_loop_without_config_opt_in_is_rejected() {
        let (mut driver, _tmp) = test_driver(8);
        let err = driver
            .dispatch_schedule_action(&serde_json::json!({
                "action": "loop.start",
                "args": { "interval": 60, "prompt": "poll", "limit": 0 }
            }))
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("allowUnboundedLoops"), "{msg}");
        assert!(!driver.schedule.has_loop());
    }

    #[tokio::test]
    async fn unbounded_loop_headless_is_rejected_even_with_config_opt_in() {
        let (mut driver, _tmp) = test_driver(8);
        driver.set_allow_unbounded_schedule_loops(true);
        let err = driver
            .dispatch_schedule_action(&serde_json::json!({
                "action": "loop.start",
                "args": { "interval": 60, "prompt": "poll", "limit": 0 }
            }))
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("headless"), "{msg}");
        assert!(!driver.schedule.has_loop());
    }

    #[tokio::test]
    async fn primary_round_ceiling_zero_is_disabled() {
        let (driver, _tmp) = test_driver(1);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);

        assert!(driver.primary_round_ceiling_allows_more(99, 0, &tx).await);
        assert!(rx.try_recv().is_err(), "disabled ceiling emits no notice");
    }

    #[tokio::test]
    async fn primary_round_ceiling_headless_stops_with_notice() {
        let (driver, _tmp) = test_driver(1);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);

        assert!(!driver.primary_round_ceiling_allows_more(3, 3, &tx).await);
        match rx.recv().await {
            Some(TurnEvent::Notice { text }) => {
                assert!(text.contains("configured limit of 3"), "{text}");
                assert!(text.contains("no interactive client"), "{text}");
            }
            other => panic!("expected notice, got {other:?}"),
        }
    }

    /// The active-agent name persisted in the session row — what a resume
    /// restarts on.
    fn persisted_active_agent(driver: &Driver) -> String {
        driver
            .session
            .db
            .get_session(driver.session.id)
            .unwrap()
            .unwrap()
            .active_agent
    }

    /// The text of a `tool_result`-carrying `Message::User`. Empty for any other shape.
    fn tool_result_text(msg: &Message) -> String {
        use rig::message::{ToolResultContent, UserContent};
        match msg {
            Message::User { content } => content
                .iter()
                .filter_map(|c| match c {
                    UserContent::ToolResult(tr) => Some(
                        tr.content
                            .iter()
                            .filter_map(|c| match c {
                                ToolResultContent::Text(t) => Some(t.text.clone()),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join(""),
                    ),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(""),
            _ => String::new(),
        }
    }

    fn push_user_turn(driver: &mut Driver, text: &str) {
        driver.stack[0].history.push(Message::user(text));
    }

    #[tokio::test]
    async fn auto_hands_off_to_build_on_clear_build_intent() {
        let (mut driver, _t) = auto_rooted_driver();
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        assert_eq!(driver.active_agent(), "Auto", "starts on the front door");

        let next = driver
            .apply_handoff("Build", "call-1".to_string(), Some("fc-1".to_string()), &tx)
            .await;

        assert_eq!(driver.active_agent(), "Build", "primary swapped to `Build`");
        assert_eq!(driver.stack.len(), 1, "swap stays on the root frame");
        // Persisted so a resume restarts on the handed-off primary.
        assert_eq!(persisted_active_agent(&driver), "Build");
        // The confirmation tool_result is what drives `Build`'s next turn.
        assert!(
            matches!(&next, Message::User { .. }),
            "tool_result delivered"
        );
    }

    #[tokio::test]
    async fn failed_handoff_does_not_persist_target_agent() {
        let (mut driver, _t) = auto_rooted_driver();
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);

        driver
            .apply_handoff(
                "DefinitelyNotAnAgent",
                "call-1".to_string(),
                Some("fc-1".to_string()),
                &tx,
            )
            .await;

        assert_eq!(driver.active_agent(), "Auto");
        assert_eq!(persisted_active_agent(&driver), "Auto");
    }

    /// Part 1 (implementation note): the swapped-in
    /// primary's first turn is driven by an IMPERATIVE kickoff — the user's
    /// originating request restated verbatim + a begin-now instruction — NOT
    /// the bare `` "Handed off to `Build`." `` ack a weak model would merely
    /// narrate.
    #[tokio::test]
    async fn handoff_kickoff_restates_user_request_and_commands_action() {
        let (mut driver, _t) = auto_rooted_driver();
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        // The originating user request that triggered the handoff.
        let request = "Add a confirm-on-quit toggle to /settings";
        push_user_turn(&mut driver, request);

        let next = driver
            .apply_handoff("Build", "call-1".to_string(), Some("fc-1".to_string()), &tx)
            .await;

        let kickoff = tool_result_text(&next);
        assert!(
            kickoff.contains(request),
            "kickoff restates the user's request verbatim: {kickoff:?}"
        );
        assert!(
            kickoff.to_lowercase().contains("begin now")
                && kickoff.to_lowercase().contains("tool call"),
            "kickoff commands a begin-now tool call, not narration: {kickoff:?}"
        );
        assert!(
            !kickoff.contains("Handed off to"),
            "the bare ack is NOT the model-facing kickoff: {kickoff:?}"
        );
    }

    /// The kickoff restates the SALIENT (most recent) user turn when several
    /// preceded the handoff — not the whole transcript.
    #[tokio::test]
    async fn handoff_kickoff_restates_only_the_salient_request() {
        let (mut driver, _t) = auto_rooted_driver();
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        push_user_turn(&mut driver, "What does the config loader do?");
        // An intervening agent reply closes that turn so the next user message
        // opens a fresh, salient one.
        driver.stack[0]
            .history
            .push(Message::assistant("It walks up .cockpit/."));
        let salient = "Now rename `loadConfig` to `load_config` everywhere";
        push_user_turn(&mut driver, salient);

        let next = driver
            .apply_handoff("Build", "c".to_string(), Some("fc".to_string()), &tx)
            .await;

        let kickoff = tool_result_text(&next);
        assert!(
            kickoff.contains(salient),
            "salient request restated: {kickoff:?}"
        );
        assert!(
            !kickoff.contains("config loader"),
            "the earlier turn is not dragged in: {kickoff:?}"
        );
    }

    /// Companion to the above: a clear planning request routes to `Plan`.
    #[tokio::test]
    async fn auto_hands_off_to_plan_on_clear_plan_intent() {
        let (mut driver, _t) = auto_rooted_driver();
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);

        driver
            .apply_handoff("Plan", "call-2".to_string(), Some("fc-2".to_string()), &tx)
            .await;

        assert_eq!(driver.active_agent(), "Plan", "primary swapped to `Plan`");
        assert_eq!(persisted_active_agent(&driver), "Plan");
    }

    /// Plain `UserContent::Text` of a `Message::User` (the synthetic swap
    /// marker is one such message). Empty for a tool-result-carrying user
    /// message (the handoff kickoff) or any non-user shape.
    fn plain_user_text(msg: &Message) -> String {
        match msg {
            Message::User { content } => crate::engine::message::extract_user_text(content),
            _ => String::new(),
        }
    }

    /// Count of injected agent-swap identity markers in the root history
    /// (implementation note) — `Message::User` entries
    /// whose plain text opens the `[Primary agent changed:` boundary.
    fn swap_markers(driver: &Driver) -> Vec<String> {
        driver.stack[0]
            .history
            .iter()
            .map(plain_user_text)
            .filter(|t| t.starts_with("[Primary agent changed:"))
            .collect()
    }

    /// Regression (implementation note): start as agent A,
    /// exchange a turn, swap to agent B via the `swap_command` path, then send
    /// a message — the wire history carries exactly ONE swap marker naming
    /// A→B, positioned at the swap boundary (immediately ahead of the user's
    /// next message, after the prior turns).
    #[tokio::test]
    async fn swap_command_injects_one_marker_at_boundary_on_next_message() {
        let (mut driver, _t) = test_driver(1); // rooted on `Build`
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        // Exchange ≥1 turn under `Build` (A).
        push_user_turn(&mut driver, "What does the lock manager do?");
        driver.stack[0]
            .history
            .push(Message::assistant("It arbitrates writers."));
        assert_eq!(driver.active_agent(), "Build");

        // Swap to `Swarm` (B) via the slash-command path. No marker yet —
        // injection is deferred to the next message.
        driver.swap_primary("Swarm", &tx).await;
        assert_eq!(driver.active_agent(), "Swarm");
        assert!(
            swap_markers(&driver).is_empty(),
            "marker is deferred, not written at swap time"
        );

        // The user's next message: the marker is injected at send time, at the
        // boundary, then the user message follows.
        driver.inject_pending_swap_marker();
        driver.stack[0].history.push(Message::user("now build it"));

        let markers = swap_markers(&driver);
        assert_eq!(markers.len(), 1, "exactly one marker: {markers:?}");
        assert!(
            markers[0].contains("`Build` → `Swarm`") && markers[0].contains("You are now `Swarm`"),
            "marker names A→B and the new identity: {:?}",
            markers[0]
        );
        // Positioned at the boundary: the marker sits immediately before the
        // new user message and after the prior turns.
        let texts: Vec<String> = driver.stack[0]
            .history
            .iter()
            .map(plain_user_text)
            .collect();
        let marker_idx = texts
            .iter()
            .position(|t| t.starts_with("[Primary agent changed:"))
            .unwrap();
        assert_eq!(
            texts[marker_idx + 1],
            "now build it",
            "marker sits immediately ahead of the next user message"
        );
        // Pending state is consumed — a later message injects no second marker.
        driver.inject_pending_swap_marker();
        assert_eq!(swap_markers(&driver).len(), 1, "fires once per swap window");
    }

    /// Coalesce (implementation note): several swaps before
    /// a message (`Build`→`Swarm`→`Plan`→`Build` … then `Plan`) emit exactly
    /// ONE marker naming previously-effective → final. The intermediate hops
    /// produce nothing; `from` stays the agent whose turns are in history.
    #[tokio::test]
    async fn multiple_swaps_before_message_coalesce_to_one_marker() {
        let (mut driver, _t) = test_driver(1); // rooted on `Build`
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        push_user_turn(&mut driver, "outline the change");
        driver.stack[0]
            .history
            .push(Message::assistant("here is an outline"));

        // Build → Swarm → Plan, all before a message.
        driver.swap_primary("Swarm", &tx).await;
        driver.swap_primary("Build", &tx).await;
        driver.swap_primary("Plan", &tx).await;
        assert_eq!(driver.active_agent(), "Plan");
        assert!(swap_markers(&driver).is_empty(), "no markers until send");

        driver.inject_pending_swap_marker();
        let markers = swap_markers(&driver);
        assert_eq!(markers.len(), 1, "intermediate hops coalesce: {markers:?}");
        assert!(
            markers[0].contains("`Build` → `Plan`"),
            "from = previously-effective (`Build`), to = final (`Plan`): {:?}",
            markers[0]
        );
    }

    /// Net no-op (implementation note): when the final
    /// agent equals the previously-effective one (`Build`→`Swarm`→`Build`
    /// while history was already `Build`), nothing is injected — and the
    /// pending state is still cleared.
    #[tokio::test]
    async fn swap_back_to_original_agent_injects_no_marker() {
        let (mut driver, _t) = test_driver(1); // rooted on `Build`
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        push_user_turn(&mut driver, "think about it");
        driver.stack[0].history.push(Message::assistant("thinking"));

        driver.swap_primary("Swarm", &tx).await;
        driver.swap_primary("Build", &tx).await; // back to the original
        assert_eq!(driver.active_agent(), "Build");

        driver.inject_pending_swap_marker();
        assert!(
            swap_markers(&driver).is_empty(),
            "final == previously-effective → no marker"
        );
        assert!(
            driver.pending_swap_marker_from.is_none(),
            "pending state cleared even on the net no-op"
        );
    }

    /// The synthetic marker is wire-only (`agent-swap-identity-
    /// marker.md`, wire-vs-user split GOALS §14): the swap path emits only the
    /// terse `PrimarySwapped` chrome event for the user-facing timeline, never
    /// a transcript row for the marker, and the marker is not recorded as a
    /// session event. The user sees the switched-to row; the marker stays on
    /// the wire.
    #[tokio::test]
    async fn swap_marker_does_not_leak_into_user_transcript() {
        let (mut driver, _t) = test_driver(1);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        push_user_turn(&mut driver, "do the thing");
        driver.stack[0].history.push(Message::assistant("ok"));

        driver.swap_primary("Swarm", &tx).await;
        driver.inject_pending_swap_marker();

        // The marker is on the wire.
        assert_eq!(swap_markers(&driver).len(), 1);
        // No user-message transcript row was recorded for the marker (the swap
        // records its own `primary_swap` event, but the marker is wire-only).
        let user_msg_rows = driver
            .session
            .db
            .list_session_events(driver.session.id)
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == "user_message")
            .count();
        assert_eq!(
            user_msg_rows, 0,
            "the marker is never recorded as a user-message transcript row"
        );
        // The only user-facing chrome signal from the swap is `PrimarySwapped`
        // (the terse switched-to row) — never a transcript entry carrying the
        // marker text.
        drop(tx);
        let mut saw_swapped = false;
        while let Ok(ev) = rx.try_recv() {
            if let TurnEvent::PrimarySwapped { name } = &ev {
                assert_eq!(name, "Swarm");
                saw_swapped = true;
            }
            // No event should ever carry the marker text.
            let dbg = format!("{ev:?}");
            assert!(
                !dbg.contains("[Primary agent changed:"),
                "marker text must not reach the client: {dbg}"
            );
        }
        assert!(saw_swapped, "the terse switched-to chrome event fired");
    }

    /// Re-root the driver on a real bundled primary built through the same
    /// factory the session worker uses, so its tool surface + name match
    /// production — the authority for "absent from the new agent"
    /// (implementation note).
    fn reroot_real(driver: &mut Driver, name: &str) {
        let agent = crate::engine::builtin::load(name, &driver.spawn_args(true)).unwrap();
        driver.stack[0].agent = Arc::new(agent);
        driver.session.set_active_agent(name).unwrap();
    }

    /// An assistant turn carrying one tool call: `tool` named `tool`, id
    /// `call_id`. Used to seed cross-agent attribution history.
    fn tool_call_turn(call_id: &str, tool: &str) -> Message {
        use crate::engine::message::{AssistantContent, OneOrMany};
        use rig::message::{ToolCall, ToolFunction};
        Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
                id: call_id.to_string(),
                call_id: None,
                function: ToolFunction {
                    name: tool.to_string(),
                    arguments: serde_json::json!({}),
                },
                signature: None,
                additional_params: None,
            })),
        }
    }

    /// The text of the `tool_result` answering `call_id` in the root history
    /// (empty if none). Used to read back the wire-only attribution note.
    fn tool_result_text_for(driver: &Driver, call_id: &str) -> String {
        use rig::message::{ToolResultContent, UserContent};
        for msg in &driver.stack[0].history {
            if let Message::User { content } = msg {
                for c in content.iter() {
                    if let UserContent::ToolResult(tr) = c
                        && tr.id == call_id
                    {
                        return tr
                            .content
                            .iter()
                            .filter_map(|p| match p {
                                ToolResultContent::Text(t) => Some(t.text.clone()),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join("");
                    }
                }
            }
        }
        String::new()
    }

    fn history_text(history: &[Message]) -> String {
        use crate::engine::message::AssistantContent;
        use rig::message::{ToolResultContent, UserContent};

        let mut out = String::new();
        for msg in history {
            match msg {
                Message::User { content } => {
                    for c in content.iter() {
                        match c {
                            UserContent::Text(text) => out.push_str(&text.text),
                            UserContent::ToolResult(tr) => {
                                for part in tr.content.iter() {
                                    if let ToolResultContent::Text(text) = part {
                                        out.push_str(&text.text);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Message::Assistant { content, .. } => {
                    for c in content.iter() {
                        match c {
                            AssistantContent::Text(text) => out.push_str(&text.text),
                            AssistantContent::ToolCall(tc) => out.push_str(&tc.id),
                            _ => {}
                        }
                    }
                }
                Message::System { .. } => {}
            }
            out.push('\n');
        }
        out
    }

    fn record_skill_tool_row(driver: &Driver, call_id: &str, agent: &str, output: &str) {
        driver
            .session
            .record_tool_call(crate::session::ToolCallRow {
                event_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                agent: agent.to_string(),
                call_id: call_id.to_string(),
                identity: crate::session::ToolCallProviderIdentity::default(),
                tool: "skill".to_string(),
                path: None,
                original_input_json: serde_json::json!({ "name": "x" }),
                wire_input_json: serde_json::json!({ "name": "x" }),
                recovery: crate::engine::repair::Recovery::Clean,
                hard_fail: false,
                output: output.to_string(),
                truncated: false,
                duration_ms: 1,
                llm_mode: crate::config::extended::LlmMode::Normal,
                shape_fingerprint: None,
                hint: None,
            })
            .unwrap();
    }

    #[test]
    fn stale_tool_owner_ledgers_drop_calls_absent_from_root_history() {
        let (mut driver, _t) = test_driver(1);
        driver.stack[0]
            .history
            .push(tool_call_turn("live", "editunlock"));
        driver.stack[0]
            .history
            .push(Message::tool_result_with_call_id(
                "live".to_string(),
                None,
                "[elided body]",
            ));
        driver
            .tool_call_owner
            .insert("live".to_string(), "Build".to_string());
        driver
            .tool_call_owner
            .insert("stale".to_string(), "Build".to_string());

        driver.drop_stale_owner_ledgers();

        assert_eq!(
            driver.tool_call_owner.get("live").map(String::as_str),
            Some("Build"),
            "structural tool calls stay owned even when their result body is elided"
        );
        assert!(
            !driver.tool_call_owner.contains_key("stale"),
            "calls absent from root history are dropped"
        );
    }

    #[test]
    fn stale_skill_pairs_drop_when_call_and_result_leave_root_history() {
        let (mut driver, _t) = test_driver(1);
        driver.stack[0]
            .history
            .push(tool_call_turn("skill-live", "skill"));
        driver.stack[0]
            .history
            .push(Message::tool_result_with_call_id(
                "skill-live".to_string(),
                None,
                "skill body",
            ));
        driver.skill_pairs.push(SkillPair {
            call_id: "skill-live".to_string(),
            owner: "Auto".to_string(),
            intentional_steer: false,
        });
        driver.skill_pairs.push(SkillPair {
            call_id: "skill-stale".to_string(),
            owner: "Auto".to_string(),
            intentional_steer: false,
        });

        driver.drop_stale_owner_ledgers();

        assert_eq!(driver.skill_pairs.len(), 1);
        assert_eq!(driver.skill_pairs[0].call_id, "skill-live");
    }

    #[tokio::test]
    async fn persisted_skill_pair_strips_after_resume_swap() {
        let (mut driver, _t) = test_driver(1);
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        reroot_real(&mut driver, "Build");
        driver.stack[0]
            .history
            .push(tool_call_turn("skillslash-resume", "skill"));
        driver.stack[0]
            .history
            .push(Message::tool_result_with_call_id(
                "skillslash-resume".to_string(),
                None,
                "Skill `x`:\n\nresume-only instructions",
            ));
        driver
            .session
            .db
            .save_skill_pair(driver.session.id, "skillslash-resume", "Build", false)
            .unwrap();

        driver.restore_skill_pairs_after_rehydrate("Build");
        assert_eq!(driver.skill_pairs.len(), 1);
        assert_eq!(driver.skill_pairs[0].owner, "Build");

        driver.swap_primary("Plan", &tx).await;

        assert!(
            !history_text(&driver.stack[0].history).contains("resume-only instructions"),
            "resume-restored abandoned skill body stripped on swap"
        );
        assert!(
            driver
                .session
                .db
                .list_skill_pairs(driver.session.id)
                .unwrap()
                .is_empty(),
            "stripped pair is removed from durable ledger"
        );
    }

    #[test]
    fn skill_pair_reconstructs_from_history_and_tool_log_when_db_empty() {
        let (mut driver, _t) = test_driver(1);
        driver.stack[0]
            .history
            .push(tool_call_turn("skillslash-rebuilt", "skill"));
        driver.stack[0]
            .history
            .push(Message::tool_result_with_call_id(
                "skillslash-rebuilt".to_string(),
                None,
                "Skill `x`:\n\npre-migration instructions",
            ));
        record_skill_tool_row(
            &driver,
            "skillslash-rebuilt",
            "Build",
            "pre-migration instructions",
        );

        driver.restore_skill_pairs_after_rehydrate("Plan");

        assert_eq!(driver.skill_pairs.len(), 1);
        assert_eq!(driver.skill_pairs[0].call_id, "skillslash-rebuilt");
        assert_eq!(driver.skill_pairs[0].owner, "Build");
        assert!(
            !driver.skill_pairs[0].intentional_steer,
            "fallback reconstruction defaults to non-steering"
        );
        let rows = driver
            .session
            .db
            .list_skill_pairs(driver.session.id)
            .unwrap();
        assert_eq!(rows.len(), 1, "reconstructed row is persisted");
        assert_eq!(rows[0].owner, "Build");
    }

    #[test]
    fn compact_brief_history_excludes_abandoned_skill_bodies() {
        let (mut driver, _t) = test_driver(1);
        driver.stack[0]
            .history
            .push(Message::user("please continue"));
        driver.stack[0]
            .history
            .push(tool_call_turn("skillslash-compact", "skill"));
        driver.stack[0]
            .history
            .push(Message::tool_result_with_call_id(
                "skillslash-compact".to_string(),
                None,
                "Skill `x`:\n\nCOMPACT_SENTINEL_DO_NOT_SUMMARIZE",
            ));
        driver.skill_pairs.push(SkillPair {
            call_id: "skillslash-compact".to_string(),
            owner: "Build".to_string(),
            intentional_steer: false,
        });

        let filtered = driver.compact_brief_history(&driver.stack[0].history);

        let text = history_text(&filtered);
        assert!(text.contains("please continue"));
        assert!(
            !text.contains("COMPACT_SENTINEL_DO_NOT_SUMMARIZE"),
            "abandoned skill body is omitted from compact brief input"
        );
    }

    #[test]
    fn stale_owner_cleanup_bounds_repeated_removed_calls() {
        let (mut driver, _t) = test_driver(1);
        driver.stack[0]
            .history
            .push(tool_call_turn("still-here", "read"));
        for i in 0..128 {
            driver
                .tool_call_owner
                .insert(format!("gone-{i}"), "Build".to_string());
            driver.skill_pairs.push(SkillPair {
                call_id: format!("skill-gone-{i}"),
                owner: "Auto".to_string(),
                intentional_steer: false,
            });
        }
        driver
            .tool_call_owner
            .insert("still-here".to_string(), "Build".to_string());

        driver.drop_stale_owner_ledgers();

        assert_eq!(driver.tool_call_owner.len(), 1);
        assert!(driver.tool_call_owner.contains_key("still-here"));
        assert!(
            driver.skill_pairs.is_empty(),
            "removed skill calls do not accumulate stale ledger rows"
        );
    }

    /// Regression (implementation note): agent A
    /// (`Build`, has the write tool) calls a write tool and a `read`; swap to
    /// agent B (`Plan`, read-only) and send a message — every historical
    /// write-tool call carries a wire-only note naming A and the tool, while
    /// the `read` call (a tool B still has) is left unannotated.
    #[tokio::test]
    async fn absent_tool_calls_annotated_naming_the_maker_present_tools_untouched() {
        let (mut driver, _t) = test_driver(1);
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        reroot_real(&mut driver, "Build");
        assert_eq!(driver.active_agent(), "Build");
        // `Build` is the authority for which tool A actually held.
        assert!(
            driver.stack[0].agent.tools.get("editunlock").is_some(),
            "Build holds the write tool"
        );
        assert!(driver.stack[0].agent.tools.get("read").is_some());

        // A (`Build`) makes a write call and a read call, each answered.
        push_user_turn(&mut driver, "edit the file then read it");
        driver.stack[0]
            .history
            .push(tool_call_turn("w1", "editunlock"));
        driver.stack[0]
            .history
            .push(Message::tool_result_with_call_id(
                "w1".to_string(),
                None,
                "[hash=abc ok]",
            ));
        driver.stack[0].history.push(tool_call_turn("r1", "read"));
        driver.stack[0]
            .history
            .push(Message::tool_result_with_call_id(
                "r1".to_string(),
                None,
                "file contents",
            ));

        // Swap to `Plan` (read-only — lacks `editunlock`). No annotation yet —
        // deferred to the next message.
        driver.swap_primary("Plan", &tx).await;
        assert_eq!(driver.active_agent(), "Plan");
        assert!(
            driver.stack[0].agent.tools.get("editunlock").is_none(),
            "Plan lacks the write tool"
        );
        assert!(
            !tool_result_text_for(&driver, "w1").contains("[Called by"),
            "annotation is deferred, not written at swap time"
        );

        // The user's next message: annotation fires at send time.
        driver.annotate_absent_tool_calls();

        // The write call carries the attribution note naming A (`Build`) and T.
        let w = tool_result_text_for(&driver, "w1");
        assert!(
            w.contains("[Called by `Build`, which had the `editunlock` tool. You (`Plan`) do not have this tool.]"),
            "absent-tool call annotated with maker + tool + new identity: {w:?}"
        );
        assert!(
            w.contains("[hash=abc ok]"),
            "the original tool output is preserved after the note: {w:?}"
        );
        // The `read` call (a tool `Plan` still has) is untouched.
        let r = tool_result_text_for(&driver, "r1");
        assert!(
            !r.contains("[Called by"),
            "a call for a tool the new agent still has is not annotated: {r:?}"
        );
        assert_eq!(r, "file contents");

        // Idempotent: a later message never double-stamps.
        driver.annotate_absent_tool_calls();
        let w2 = tool_result_text_for(&driver, "w1");
        assert_eq!(w2, w, "re-evaluation does not double-annotate");
    }

    /// Per-call ownership across several swaps
    /// (implementation note): a write call made under
    /// `Build`, then a swap to `Swarm` (also write-capable) that makes its own
    /// write call, then a swap to `Plan` (read-only). On the next message each
    /// write call is attributed to the agent that ACTUALLY made it — "the
    /// previous agent" is not enough.
    #[tokio::test]
    async fn annotation_attributes_each_call_to_its_actual_maker() {
        let (mut driver, _t) = test_driver(1);
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        reroot_real(&mut driver, "Build");

        // A (`Build`) makes a write call.
        driver.stack[0]
            .history
            .push(tool_call_turn("b1", "editunlock"));
        driver.stack[0]
            .history
            .push(Message::tool_result_with_call_id(
                "b1".to_string(),
                None,
                "build-write",
            ));

        // Swap to `Swarm` (still write-capable) which makes its own write call.
        driver.swap_primary("Swarm", &tx).await;
        driver.stack[0]
            .history
            .push(tool_call_turn("s1", "writeunlock"));
        driver.stack[0]
            .history
            .push(Message::tool_result_with_call_id(
                "s1".to_string(),
                None,
                "swarm-write",
            ));

        // Swap to `Plan` (read-only) and annotate at the next message.
        driver.swap_primary("Plan", &tx).await;
        driver.annotate_absent_tool_calls();

        let b = tool_result_text_for(&driver, "b1");
        assert!(
            b.contains("[Called by `Build`, which had the `editunlock` tool."),
            "the first write call is attributed to `Build`: {b:?}"
        );
        let s = tool_result_text_for(&driver, "s1");
        assert!(
            s.contains("[Called by `Swarm`, which had the `writeunlock` tool."),
            "the second write call is attributed to `Swarm`, not `Build`: {s:?}"
        );
    }

    #[tokio::test]
    async fn primary_swap_transfers_locks_between_write_capable_agents() {
        let (mut driver, _t) = test_driver(1);
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        reroot_real(&mut driver, "Build");
        let path = driver.cwd.join("swap-transfer.txt");
        std::fs::write(&path, "seed").unwrap();
        driver
            .locks
            .acquire(&path, "Build", driver.session.id)
            .unwrap();

        driver.swap_primary("Swarm", &tx).await;

        assert_eq!(driver.active_agent(), "Swarm");
        assert_eq!(
            driver.locks.holder(&path).map(|(_, a)| a).as_deref(),
            Some("Swarm")
        );
        driver
            .locks
            .check_write_permitted(&path, "Swarm", driver.session.id)
            .unwrap();
        assert!(!driver.locks.has_read(&path, "Build", driver.session.id));
    }

    #[tokio::test]
    async fn primary_swap_releases_locks_when_incoming_is_read_only() {
        let (mut driver, _t) = test_driver(1);
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        reroot_real(&mut driver, "Build");
        let path = driver.cwd.join("swap-release.txt");
        std::fs::write(&path, "seed").unwrap();
        driver
            .locks
            .acquire(&path, "Build", driver.session.id)
            .unwrap();

        driver.swap_primary("Plan", &tx).await;

        assert_eq!(driver.active_agent(), "Plan");
        assert!(driver.locks.holder(&path).is_none());
    }

    /// A swapped-in read-only agent (`Plan`) does not re-issue a write tool
    /// whose past calls are now annotated
    /// (implementation note). The behavioral
    /// guarantee is the annotation: the write call's outcome now reads as
    /// "another agent made this; you lack this tool", and `Plan`'s own surface
    /// holds no write tool, so a re-issue is impossible.
    #[tokio::test]
    async fn read_only_agent_cannot_reissue_annotated_write_tool() {
        let (mut driver, _t) = test_driver(1);
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        reroot_real(&mut driver, "Build");
        driver.stack[0]
            .history
            .push(tool_call_turn("w1", "writeunlock"));
        driver.stack[0]
            .history
            .push(Message::tool_result_with_call_id(
                "w1".to_string(),
                None,
                "[hash=def ok]",
            ));

        driver.swap_primary("Plan", &tx).await;
        driver.annotate_absent_tool_calls();

        // Annotation present (the guarantee).
        assert!(
            tool_result_text_for(&driver, "w1").contains("You (`Plan`) do not have this tool.")
        );
        // And `Plan`'s surface genuinely holds no write tool to re-issue.
        assert!(driver.stack[0].agent.tools.get("writeunlock").is_none());
        assert!(driver.stack[0].agent.tools.get("editunlock").is_none());
    }

    /// Part 2 (implementation note, the `myj42m`
    /// shape): an abandoned skill pair injected under the outgoing primary
    /// must not remain as authoritative instructions for the new primary after
    /// a swap. After `Auto` seeds a user-invoked skill and then hands off, the
    /// skill's call + result are stripped from the root history (both halves,
    /// together) so `Build` follows its own role.
    #[tokio::test]
    async fn abandoned_skill_pair_is_stripped_on_handoff_swap() {
        use crate::engine::message::AssistantContent;
        use rig::message::UserContent;

        let (mut driver, _t) = auto_rooted_driver();
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        // The user invoked a skill then described a change. The skill
        // name need not exist on disk — the seam still folds a real pair into
        // history and records ownership (the leak we're closing).
        driver
            .seed_forced_skill("definitely-not-a-real-skill-xyz", &tx)
            .await;
        push_user_turn(&mut driver, "Add a confirm-on-quit toggle to /settings");

        // The pair is present and owned by the outgoing primary (`Auto`).
        let skill_call_present = |d: &Driver| {
            d.stack[0].history.iter().any(|m| {
                matches!(m,
                Message::Assistant { content, .. }
                    if content.iter().any(|c| matches!(c,
                        AssistantContent::ToolCall(tc) if tc.function.name == "skill")))
            })
        };
        let skill_result_present = |d: &Driver| {
            d.stack[0].history.iter().any(|m| {
                matches!(m,
                Message::User { content }
                    if content.iter().any(|c| matches!(c,
                        UserContent::ToolResult(tr) if tr.id.starts_with("skillslash-"))))
            })
        };
        assert!(
            skill_call_present(&driver),
            "skill call folded in before swap"
        );
        assert!(
            skill_result_present(&driver),
            "skill result folded in before swap"
        );
        assert_eq!(driver.skill_pairs.len(), 1, "ownership recorded");

        // Hand off to `Build`. The abandoned skill pair must be gone.
        driver
            .apply_handoff("Build", "call-1".to_string(), Some("fc-1".to_string()), &tx)
            .await;

        assert!(
            !skill_call_present(&driver),
            "abandoned skill call stripped on swap (does not govern `Build`)"
        );
        assert!(
            !skill_result_present(&driver),
            "abandoned skill result stripped on swap (no orphaned tool_result)"
        );
        assert!(
            driver.skill_pairs.is_empty(),
            "stripped pair dropped from the ledger"
        );
        // The kickoff still restated the user's own request (not the skill).
        // History stays well-formed: every tool_result has its call.
        assert_eq!(driver.active_agent(), "Build");
    }

    /// A steering pair (the future "intentional steer" opt-out) survives the
    /// swap — the mechanism scopes narrowly to *abandoned* pairs and does not
    /// hard-code "drop all skills on swap." (No production path sets the flag
    /// today; this guards the seam.)
    #[tokio::test]
    async fn intentional_steer_skill_pair_survives_swap() {
        let (mut driver, _t) = auto_rooted_driver();
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        driver
            .seed_forced_skill("definitely-not-a-real-skill-xyz", &tx)
            .await;
        // Flip the recorded pair to steering, as a future intentional-steer
        // path would.
        driver.skill_pairs[0].intentional_steer = true;
        let before = driver.stack[0].history.len();

        driver
            .apply_handoff("Build", "c".to_string(), Some("fc".to_string()), &tx)
            .await;

        assert_eq!(
            driver.stack[0].history.len(),
            before,
            "a steering pair is retained across the swap"
        );
        assert_eq!(driver.skill_pairs.len(), 1, "steering ownership entry kept");
    }

    /// Part 3 (implementation note): the
    /// `task`→subagent kickoff always carries an actionable brief and the
    /// child begins its loop on the first turn. The brief is the caller's
    /// (repair-required, non-empty) `task` prompt, delivered verbatim as the
    /// child's first `Message::user`. This guards that the delegation path
    /// never stalls on a non-actionable first turn.
    #[test]
    fn delegated_subagent_first_turn_is_the_actionable_brief() {
        // The interactive spawn path delivers `Message::user(scrub(&brief))`;
        // the noninteractive path delivers `compose_subagent_brief(&brief,&why)`.
        // Both carry the caller's brief verbatim — never an empty / passive
        // first turn. We assert the brief composition is faithful (the seam the
        // live loop uses), since the `task` prompt is required by the repair
        // layer and thus always non-empty.
        let brief = "Rename `loadConfig` to `load_config` in src/config/ and update callers.";
        // No `why`: the brief is delivered unchanged (actionable as written).
        assert_eq!(compose_subagent_brief(brief, ""), brief);
        // With a `why`: the brief is still present in full, prefixed with
        // motivation — the child still receives the actionable instruction.
        let with_why = compose_subagent_brief(brief, "the API changed");
        assert!(
            with_why.contains(brief),
            "brief carried verbatim: {with_why}"
        );
        assert!(with_why.contains("the API changed"), "motivation prefixed");
    }

    #[tokio::test]
    async fn ambiguous_turn_keeps_auto_active() {
        let (driver, _t) = auto_rooted_driver();
        // No `apply_handoff` call (the model emitted no `handoff` tool call).
        assert_eq!(
            driver.active_agent(),
            "Auto",
            "ambiguous intent keeps the front door — no unsolicited swap"
        );
        assert_eq!(persisted_active_agent(&driver), "Auto");
    }

    /// Resume rehydration is automatic but applies ONLY when the root frame
    /// has no live in-memory history. A driver whose root already has a live
    /// context is left untouched — never rebuild over a live context
    /// (implementation note).
    #[test]
    fn rehydrate_skips_a_live_history() {
        let (mut driver, _t) = test_driver(1);
        // Record a couple of turns to the DB transcript.
        let session = driver.session.clone();
        session
            .record_event(
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("Build"),
                None,
                &serde_json::json!({ "text": "hi" }),
            )
            .unwrap();
        session
            .record_event(
                crate::db::session_log::SessionEventKind::AssistantMessage,
                Some("Build"),
                Some("infer-1"),
                &serde_json::json!({ "text": "hello" }),
            )
            .unwrap();
        // Simulate a LIVE worker: the root frame already has in-memory
        // history. Rehydration must be a no-op.
        driver.stack[0].history = vec![Message::user("a live message")];
        let r = driver.rehydrate_root_if_empty("Build").unwrap();
        assert!(r.is_none(), "must not rebuild over a live context");
        assert_eq!(driver.stack[0].history.len(), 1, "live history untouched");
    }

    /// Persist-every-boundary + automatic rehydration: a transcript and a
    /// prune ledger persisted to the DB (as the running driver would at each
    /// inference boundary, surviving an UNCLEAN kill — no graceful exit
    /// step) are rehydrated by a brand-new driver into the PRUNED form, with
    /// the watermark restored and the context estimate seeded.
    #[test]
    fn fresh_driver_rehydrates_persisted_pruned_context() {
        use rig::OneOrMany;
        use rig::message::{AssistantContent, ToolResultContent, UserContent};

        let (driver, _t) = test_driver(1);
        let session = driver.session.clone();
        let db = session.db.clone();
        let sid = session.id;

        // Two identical reads → the older is prunable. Record the transcript
        // exactly as the engine does (events + tool_call rows).
        let rec_user = |text: &str| {
            session
                .record_event(
                    crate::db::session_log::SessionEventKind::UserMessage,
                    Some("Build"),
                    None,
                    &serde_json::json!({ "text": text }),
                )
                .unwrap();
        };
        let rec_tool = |call_id: &str, body: &str| {
            session
                .record_tool_call(crate::session::ToolCallRow {
                    event_id: uuid::Uuid::new_v4(),
                    timestamp: chrono::Utc::now(),
                    agent: "Build".into(),
                    call_id: call_id.into(),
                    identity: crate::session::ToolCallProviderIdentity::default(),
                    tool: "read".into(),
                    path: Some("/f".into()),
                    original_input_json: serde_json::json!({ "path": "/f" }),
                    wire_input_json: serde_json::json!({ "path": "/f" }),
                    recovery: crate::engine::repair::Recovery::Clean,
                    hard_fail: false,
                    output: body.into(),
                    truncated: false,
                    duration_ms: 1,
                    llm_mode: crate::config::extended::LlmMode::default(),
                    shape_fingerprint: None,
                    hint: None,
                })
                .unwrap();
            session
                .record_event(
                    crate::db::session_log::SessionEventKind::ToolCall,
                    Some("Build"),
                    Some(call_id),
                    &serde_json::json!({ "tool": "read", "wire_input": { "path": "/f" }, "output": body }),
                )
                .unwrap();
        };
        rec_user("read it twice");
        session
            .record_event(
                crate::db::session_log::SessionEventKind::AssistantMessage,
                Some("Build"),
                Some("infer-1"),
                &serde_json::json!({ "text": "" }),
            )
            .unwrap();
        rec_tool("tc-1", "BODY ONE padding padding padding");
        session
            .record_event(
                crate::db::session_log::SessionEventKind::AssistantMessage,
                Some("Build"),
                Some("infer-2"),
                &serde_json::json!({ "text": "" }),
            )
            .unwrap();
        rec_tool("tc-2", "BODY TWO padding padding padding");

        // Persist the prune ledger as the boundary cadence would — the older
        // read (tc-1) elided.
        let ledger = prune::PruneLedger {
            elided: vec![prune::LedgerEntry {
                original_event_id: "tc-1".into(),
                reason: prune::REASON_SNAPSHOT_SUPERSEDED.into(),
                partial_body: None,
            }],
            watermark: 5,
        };
        db.save_prune_ledger(sid, &ledger).unwrap();
        drop(driver); // the daemon "died" — in-memory history is gone.

        // A brand-new driver for the SAME session (a fresh worker after an
        // unclean restart) rehydrates automatically.
        let s2 = Arc::new(Session::resume(db.clone(), sid).unwrap().unwrap());
        let locks = Arc::new(crate::locks::LockManager::from_db(db.clone()).unwrap());
        let rcfg = crate::config::extended::RedactConfig::default();
        let redact = Arc::new(RedactionTable::build(&rcfg, &s2.project_root).unwrap());
        let agent = Arc::new(Agent {
            name: "Build".into(),
            system: String::new(),
            role_prompt: String::new(),
            tools: crate::engine::tool::ToolBox::new(),
            model: Arc::new(
                crate::engine::model::Model::from_config(
                    &{
                        use crate::config::providers::{
                            ActiveModelRef, ProviderEntry, ProvidersConfig,
                        };
                        let mut providers = std::collections::BTreeMap::new();
                        providers.insert(
                            "lmstudio".to_string(),
                            ProviderEntry {
                                url: "http://localhost:1/v1".into(),
                                ..ProviderEntry::default()
                            },
                        );
                        ProvidersConfig {
                            providers,
                            active_model: Some(ActiveModelRef {
                                provider: "lmstudio".into(),
                                model: "local".into(),
                                reasoning_effort: None,
                                thinking_mode: None,
                            }),
                            ..ProvidersConfig::default()
                        }
                    },
                    std::sync::Arc::new(crate::redact::RedactionTable::empty()),
                )
                .unwrap(),
            ),
            params: crate::engine::model::ModelParams::default(),
            scan_tool_results: true,
            llm_mode: crate::config::extended::LlmMode::default(),
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        });
        let mut driver2 = Driver::with_max_schedules(
            s2.clone(),
            locks,
            redact,
            s2.project_root.clone(),
            agent,
            1,
        );
        let r = driver2
            .rehydrate_root_if_empty("Build")
            .unwrap()
            .expect("a prior conversation was rebuilt");
        assert!(!r.ledger_fallback);
        // The pruned form is restored: tc-1's body is the elision marker.
        let body = |m: &Message| match m {
            Message::User { content } => content
                .iter()
                .filter_map(|c| match c {
                    UserContent::ToolResult(tr) => Some(
                        tr.content
                            .iter()
                            .filter_map(|c| match c {
                                ToolResultContent::Text(t) => Some(t.text.clone()),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join(""),
                    ),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(""),
            _ => String::new(),
        };
        let h = &driver2.stack[0].history;
        // h: user, assistant(tc-1), result tc-1 (elided), assistant(tc-2), result tc-2.
        assert!(prune::Elision::is_marker(&body(&h[2])), "tc-1 body elided");
        assert_eq!(body(&h[4]), "BODY TWO padding padding padding");
        // Watermark restored so auto-prune's short-circuit stays consistent.
        assert_eq!(driver2.prune_watermark.get(&1).copied(), Some(5));
        // Context estimate seeded for the gauge (non-zero pruned history).
        assert!(s2.last_usage().is_some());
        // The assistant turn that issued tc-1 is unchanged (call shape kept).
        assert!(matches!(&h[1], Message::Assistant { content, .. }
            if content.iter().any(|c| matches!(c, AssistantContent::ToolCall(tc) if tc.id == "tc-1"))));
        let _ = OneOrMany::one(UserContent::text("")); // keep import used
    }

    #[test]
    fn new_constructs_idle_driver() {
        // `Driver::new` is the public default-cap constructor; exercise it
        // so the default path stays alive + correct.
        let (driver, _t) = test_driver(crate::engine::schedule::DEFAULT_MAX_CONCURRENT_SCHEDULES);
        let agent = driver.stack[0].agent.clone();
        let d2 = Driver::new(
            driver.session.clone(),
            driver.locks.clone(),
            driver.redact.clone(),
            driver.cwd.clone(),
            agent,
        );
        assert_eq!(d2.active_agent(), "Build");
        assert!(!d2.schedule.has_loop());
        assert_eq!(
            d2.schedule.max_concurrent,
            crate::engine::schedule::DEFAULT_MAX_CONCURRENT_SCHEDULES
        );
    }

    /// Build a tiny history with two identical `read` snapshots (one
    /// elidable). Mirrors the prune module's wire shape.
    fn dup_read_history() -> Vec<Message> {
        dup_read_history_with_body("FULL SNAPSHOT BODY with enough tokens to matter here")
    }

    fn dup_read_history_zero_savings() -> Vec<Message> {
        dup_read_history_with_body("x")
    }

    fn dup_read_history_tiny_savings() -> Vec<Message> {
        dup_read_history_with_body("lorem ipsum dolor sit amet ".repeat(20))
    }

    fn dup_read_history_with_body(body: impl Into<String>) -> Vec<Message> {
        use rig::OneOrMany;
        use rig::message::{AssistantContent, ToolResult, ToolResultContent, UserContent};
        let body = body.into();
        let call = |id: &str| Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(
                crate::engine::message::ToolCall {
                    id: id.to_string(),
                    call_id: None,
                    function: rig::message::ToolFunction {
                        name: "read".into(),
                        arguments: serde_json::json!({ "path": "/abs/foo.rs" }),
                    },
                    signature: None,
                    additional_params: None,
                },
            )),
        };
        let result = |id: &str| Message::User {
            content: OneOrMany::one(UserContent::ToolResult(ToolResult {
                id: id.to_string(),
                call_id: None,
                content: OneOrMany::one(ToolResultContent::text(body.clone())),
            })),
        };
        vec![call("c1"), result("c1"), call("c2"), result("c2")]
    }

    /// Like [`dup_read_history`] but with a large duplicated body so the
    /// prune reclaims a substantial token count (used by the ctx%-threshold
    /// auto-prune test, where the elision marker would otherwise dwarf a tiny
    /// body and leave `tokens_saved` at 0).
    fn dup_read_history_big() -> Vec<Message> {
        dup_read_history_with_body("lorem ipsum dolor sit amet ".repeat(400))
    }

    fn push_test_child(driver: &mut Driver, history: Vec<Message>) {
        let child = driver.stack[0].agent.clone();
        driver.stack.push(AgentSession {
            queue_target: crate::engine::message::QueueTarget::child(
                child.name.clone(),
                driver.stack.len(),
                "test",
                "default",
            ),
            agent: child,
            history,
            answering: None,
            deferred_log: crate::engine::deferred::DeferredLog::new(),
        });
    }

    fn task_tool_call(call_id: &str, function_call_id: &str) -> Message {
        use rig::OneOrMany;
        use rig::message::AssistantContent;
        Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(
                crate::engine::message::ToolCall {
                    id: call_id.to_string(),
                    call_id: Some(function_call_id.to_string()),
                    function: rig::message::ToolFunction {
                        name: "task".into(),
                        arguments: serde_json::json!({
                            "agent": "builder",
                            "prompt": "do it"
                        }),
                    },
                    signature: None,
                    additional_params: None,
                },
            )),
        }
    }

    fn tool_result_text_and_id(msg: &Message) -> Option<(String, String)> {
        use rig::message::{ToolResultContent, UserContent};
        match msg {
            Message::User { content } => content.iter().find_map(|part| match part {
                UserContent::ToolResult(result) => {
                    let text = result
                        .content
                        .iter()
                        .filter_map(|part| match part {
                            ToolResultContent::Text(text) => Some(text.text.clone()),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join("");
                    Some((result.id.clone(), text))
                }
                _ => None,
            }),
            _ => None,
        }
    }

    #[test]
    fn interactive_child_load_failure_returns_tool_error_without_pushing_child() {
        let (driver, tmp) = test_driver(8);
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&cockpit).unwrap();
        std::fs::write(
            cockpit.join("config.json"),
            r#"{"tools":{"read":{"enabled":true,"command":"echo hi"}}}"#,
        )
        .unwrap();

        let message =
            match driver.load_interactive_child_or_tool_error(InteractiveChildLoadRequest {
                child_agent: "builder",
                granted_tools: Vec::new(),
                model: None,
                child_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
                task_call_id: "task-load-fail",
                task_function_call_id: Some("fn-load-fail".to_string()),
                repair_notes: &[],
            }) {
                Ok(_) => panic!("invalid child config must return a tool error"),
                Err(message) => message,
            };

        assert_eq!(driver.stack.len(), 1, "parent session must remain alive");
        let (result_id, result_text) =
            tool_result_text_and_id(&message).expect("load failure returns tool_result");
        assert_eq!(result_id, "task-load-fail");
        assert!(
            result_text.contains("failed to load subagent `builder`"),
            "{result_text}"
        );
        assert!(result_text.contains("custom tool `read`"), "{result_text}");
    }

    fn push_answering_child(driver: &mut Driver, call_id: &str, function_call_id: &str) {
        let mut child = (*driver.stack[0].agent).clone();
        child.name = "builder".to_string();
        driver.stack.push(AgentSession {
            queue_target: crate::engine::message::QueueTarget::child(
                child.name.clone(),
                driver.stack.len(),
                call_id,
                "default",
            ),
            agent: Arc::new(child),
            history: vec![],
            answering: Some(PendingTaskCall {
                call_id: call_id.to_string(),
                function_call_id: Some(function_call_id.to_string()),
                repair_notes: Vec::new(),
            }),
            deferred_log: crate::engine::deferred::DeferredLog::new(),
        });
    }

    async fn assert_unwind_reason(reason: StackUnwindReason, expected: &str) {
        let (mut driver, tmp) = test_driver(8);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let call_id = "task-abort-1";
        let function_call_id = "fn-abort-1";
        let parent_lock = tmp.path().join("parent.txt");
        let child_lock = tmp.path().join("child.txt");
        std::fs::write(&parent_lock, "parent").unwrap();
        std::fs::write(&child_lock, "child").unwrap();

        driver.stack[0].history = vec![task_tool_call(call_id, function_call_id)];
        driver
            .locks
            .acquire(&parent_lock, "Build", driver.session.id)
            .unwrap();
        driver
            .locks
            .suspend_agent("Build", driver.session.id)
            .unwrap();
        push_answering_child(&mut driver, call_id, function_call_id);
        driver
            .locks
            .acquire(&child_lock, "builder", driver.session.id)
            .unwrap();

        let tracker = crate::engine::deleg_shrink::DelegationShrink::new(
            crate::config::providers::CacheConfig::default(),
            &crate::config::providers::ShrinkConfig::default(),
        );
        driver.deleg_shrinks.insert(
            0,
            PendingDelegationShrink {
                tracker,
                handle: None,
            },
        );

        driver.unwind_stack_to_root(reason, &tx).await;

        assert_eq!(driver.stack.len(), 1);
        assert!(
            !driver.deleg_shrinks.contains_key(&0),
            "parent-depth shrink entry must be cleared"
        );
        assert_eq!(
            driver
                .locks
                .holder(&parent_lock)
                .map(|(_, agent)| agent)
                .as_deref(),
            Some("Build"),
            "parent locks should be resumed"
        );
        assert!(
            driver.locks.holder(&child_lock).is_none(),
            "child locks should be suspended"
        );

        let (result_id, result_text) = tool_result_text_and_id(
            driver
                .stack
                .last()
                .unwrap()
                .history
                .last()
                .expect("abort tool result"),
        )
        .expect("tool result");
        assert_eq!(result_id, call_id);
        assert!(result_text.contains(expected), "{result_text}");
        assert!(!result_text.contains("## Accomplished"), "{result_text}");
        assert!(
            !result_text.contains("resume_handle"),
            "aborted child must not expose a follow-up handle: {result_text}"
        );

        let mut history = driver.stack[0].history.clone();
        let prompt = crate::engine::message::build_user_message(UserSubmission {
            kind: UserSubmissionKind::User,
            text: "next root message".into(),
            images: vec![],
            forced_skill: None,
            origin_principal: None,
            job_id: None,
            preflight_cleaned: None,
            queue_item_ids: Vec::new(),
            queue_target: None,
        });
        assert!(
            crate::engine::rehydrate::heal_live_history(&mut history, &prompt).is_empty(),
            "abort result should already pair the parent's task call"
        );

        let event = rx.try_recv().expect("subagent report event");
        match event {
            TurnEvent::SubagentReport {
                agent,
                task_call_id,
                report,
                ..
            } => {
                assert_eq!(agent, "builder");
                assert_eq!(task_call_id, call_id);
                assert!(report.contains(expected), "{report}");
            }
            other => panic!("expected subagent report, got {other:?}"),
        }
        assert!(
            rx.try_recv().is_err(),
            "one child frame should emit one report"
        );

        let events = driver
            .session
            .db
            .list_session_events(driver.session.id)
            .unwrap();
        let event = events
            .iter()
            .find(|event| {
                event.kind == "subagent_report" && event.call_id.as_deref() == Some(call_id)
            })
            .expect("subagent_report session event should be recorded");
        assert_eq!(event.data["child_agent"], "builder");
        assert_eq!(event.data["task_call_id"], call_id);
        assert_eq!(event.data["label"], "default");
        let durable_report = event
            .data
            .get("report")
            .and_then(|v| v.as_str())
            .expect("subagent_report data.report");
        assert!(durable_report.contains(expected), "{durable_report}");
        assert_eq!(event.data["provider_call_id"], function_call_id);
        assert_eq!(event.data["provider_call_id_source"], "provider");
        assert_eq!(
            event.data["provider_identity"]["provider_call_id"],
            function_call_id
        );
    }

    #[tokio::test]
    async fn unwind_stack_to_root_cancel_delivers_abort_result() {
        assert_unwind_reason(StackUnwindReason::Cancelled, "cancelled by user").await;
    }

    #[tokio::test]
    async fn unwind_stack_to_root_gate_delivers_abort_result() {
        assert_unwind_reason(StackUnwindReason::Gated, "daemon draining").await;
    }

    #[tokio::test]
    async fn unwind_stack_to_root_inference_failure_delivers_diagnostics() {
        assert_unwind_reason(
            StackUnwindReason::InferenceFailed {
                provider: "lmstudio".into(),
                model: "local".into(),
                class: "timeout_ttft".into(),
                phase: "ttft".into(),
            },
            "provider=lmstudio, model=local, class=timeout_ttft, phase=ttft",
        )
        .await;
    }

    #[tokio::test]
    async fn root_only_unwind_emits_no_report() {
        let (mut driver, _tmp) = test_driver(8);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);

        driver
            .unwind_stack_to_root(StackUnwindReason::Cancelled, &tx)
            .await;

        assert_eq!(driver.stack.len(), 1);
        assert!(driver.stack[0].history.is_empty());
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn all_unwind_paths_drain_pending_input() {
        for reason in [
            StackUnwindReason::Cancelled,
            StackUnwindReason::Gated,
            StackUnwindReason::InferenceFailed {
                provider: "lmstudio".into(),
                model: "local".into(),
                class: "network".into(),
                phase: "dispatch".into(),
            },
        ] {
            let (mut driver, _tmp) = test_driver(8);
            let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
            let (updates_tx, _updates_rx) = mpsc::unbounded_channel();
            let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
            let target = driver.active_queue_target();
            for text in ["first", "second"] {
                queue
                    .push(
                        UserSubmission {
                            kind: UserSubmissionKind::User,
                            text: text.to_string(),
                            images: vec![],
                            forced_skill: None,
                            origin_principal: None,
                            job_id: None,
                            preflight_cleaned: None,
                            queue_item_ids: Vec::new(),
                            queue_target: None,
                        },
                        target.clone(),
                    )
                    .await;
            }

            assert_eq!(
                driver
                    .unwind_stack_to_root_and_discard_pending_input(reason, &queue, &tx)
                    .await,
                2
            );
            let mut drained = Vec::new();
            queue
                .drain_into_for(&mut drained, MAX_FOLD, Some(&target.id))
                .await;
            assert!(drained.is_empty());
        }
    }

    #[tokio::test]
    async fn queued_user_fold_records_and_emits_stable_ids() {
        let (driver, _tmp) = test_driver(8);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
        let (updates_tx, _updates_rx) = mpsc::unbounded_channel();
        let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
        let target = driver.active_queue_target();
        let (first_id, _) = queue
            .push(UserSubmission::text("first queued"), target.clone())
            .await;
        let (second_id, _) = queue
            .push(UserSubmission::text("second queued"), target.clone())
            .await;

        let mut drained = Vec::new();
        queue
            .drain_into_for(&mut drained, MAX_FOLD, Some(&target.id))
            .await;
        assert_eq!(drained.len(), 2);
        let first_seq = driver
            .record_queued_user_fold(&drained[0], &tx)
            .await
            .expect("first queued message should persist");
        let second_seq = driver
            .record_queued_user_fold(&drained[1], &tx)
            .await
            .expect("second queued message should persist");

        for (expected_text, expected_id, expected_seq) in [
            ("first queued", first_id, first_seq),
            ("second queued", second_id, second_seq),
        ] {
            let event = rx.try_recv().expect("queued turn event");
            match event {
                TurnEvent::QueuedUserMessagesFolded {
                    text,
                    queue_item_ids,
                    target: event_target,
                    seq: event_seq,
                    preflight_cleaned,
                } => {
                    assert_eq!(text, expected_text);
                    assert_eq!(queue_item_ids, vec![expected_id]);
                    assert_eq!(event_target.id, target.id);
                    assert_eq!(event_seq, Some(expected_seq));
                    assert!(preflight_cleaned.is_none());
                }
                other => panic!("expected queued turn event, got {other:?}"),
            }
        }

        let events = driver
            .session
            .db
            .list_session_events(driver.session.id)
            .unwrap();
        for (expected_text, expected_id, expected_seq) in [
            ("first queued", first_id, first_seq),
            ("second queued", second_id, second_seq),
        ] {
            let recorded = events
                .iter()
                .find(|event| event.seq == expected_seq)
                .expect("queued user_message event");
            assert_eq!(recorded.kind, "user_message");
            assert_eq!(recorded.data["text"], expected_text);
            assert_eq!(recorded.data["queued"], true);
            assert_eq!(recorded.data["queue_item_ids"][0], expected_id.to_string());
            assert_eq!(recorded.data["queue_target"]["id"], target.id);
        }
    }

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

        // The auto-compact line (80%): at/above fires, below doesn't.
        let hot = context_metrics(Some(100_000), Some(85_000), 0).unwrap();
        assert!(hot.ctx_pct >= 80.0);
        let mid = context_metrics(Some(100_000), Some(70_000), 0).unwrap();
        assert!(mid.ctx_pct < 80.0);
    }

    /// Install a test providers override with the given context thresholds,
    /// cache mode, and the active model's `context_length` so the
    /// auto-prune/auto-compact triggers resolve deterministically.
    fn install_test_providers(
        driver: &mut Driver,
        cache_mode: crate::config::providers::CacheMode,
        ctx: crate::config::providers::ContextConfig,
        context_length: u32,
    ) {
        use crate::config::providers::{
            ActiveModelRef, CacheConfig, ModelEntry, ProviderEntry, ProvidersConfig,
        };
        let mut entry = ProviderEntry {
            url: "http://localhost:1/v1".into(),
            cache: CacheConfig {
                mode: cache_mode,
                ttl_secs: 300,
            },
            context: ctx,
            ..ProviderEntry::default()
        };
        entry.models.push(ModelEntry {
            id: "local".into(),
            name: None,
            thinking_modes: vec![],
            inputs: None,
            context_length: Some(context_length),
            favorite: false,
            manual: false,
            trust: None,
            location: None,
            quality_rank: None,
            cost_rank: None,
            subagent_invokable: None,
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
            wire_api: Default::default(),
            extra: Default::default(),
            capabilities: Default::default(),
            provider_metadata: Default::default(),
        });
        let mut providers = std::collections::BTreeMap::new();
        providers.insert("lmstudio".to_string(), entry);
        let cfg = ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "lmstudio".into(),
                model: "local".into(),
                reasoning_effort: None,
                thinking_mode: None,
            }),
            ..ProvidersConfig::default()
        };
        driver.test_providers_override = Some((cfg, "lmstudio".into(), "local".into()));
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

    /// Auto-compact fires at/above the configured ctx% (default 80) and is a
    /// one-shot (the second call no-ops because the session is being handed
    /// off). Below the line it doesn't fire.
    #[tokio::test]
    async fn auto_compact_fires_at_threshold_once() {
        use crate::config::providers::{CacheMode, ContextConfig};
        let (mut driver, _tmp) = test_driver(8);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(256);
        install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 100);
        let build = crate::engine::builtin::load("Build", &driver.spawn_args(true)).unwrap();
        driver.stack[0].agent = Arc::new(build);
        std::fs::write(driver.cwd.join("seed.txt"), "seed body").unwrap();
        driver
            .session
            .record_tool_call(crate::session::ToolCallRow {
                event_id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                agent: "Build".into(),
                call_id: "seed-source".into(),
                identity: crate::session::ToolCallProviderIdentity::default(),
                tool: "read".into(),
                path: Some("seed.txt".into()),
                original_input_json: serde_json::json!({ "path": "seed.txt" }),
                wire_input_json: serde_json::json!({ "path": "seed.txt" }),
                recovery: crate::engine::repair::Recovery::Clean,
                hard_fail: false,
                output: "seed body".into(),
                truncated: false,
                duration_ms: 1,
                llm_mode: crate::config::extended::LlmMode::default(),
                shape_fingerprint: None,
                hint: None,
            })
            .unwrap();

        // 70% < 80 → no compact.
        driver
            .session
            .record_usage(
                uuid::Uuid::new_v4(),
                crate::tokens::TokenUsage {
                    input_tokens: 70,
                    output_tokens: 0,
                    cached_input_tokens: 0,
                    cache_creation_input_tokens: 0,
                },
            )
            .unwrap();
        assert!(
            !driver.maybe_auto_compact(&tx).await,
            "below 80% no compact"
        );

        // 85% ≥ 80 → compact fires once.
        driver
            .session
            .record_usage(
                uuid::Uuid::new_v4(),
                crate::tokens::TokenUsage {
                    input_tokens: 85,
                    output_tokens: 0,
                    cached_input_tokens: 0,
                    cache_creation_input_tokens: 0,
                },
            )
            .unwrap();
        assert!(driver.maybe_auto_compact(&tx).await, "at/over 80% compacts");
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
            .position(|ev| matches!(ev, TurnEvent::CompactReady { brief, .. } if !brief.trim().is_empty()))
            .expect("compact ready event emitted");
        assert!(
            seed_start < seed_end && seed_end < compact_ready,
            "seed tools should run before CompactReady: {events:?}"
        );
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
        // ctx 60% is below the 80% auto-compact line, so only escalation can
        // trigger a compact here.
        install_test_providers(&mut driver, CacheMode::None, ContextConfig::default(), 100);
        driver
            .session
            .record_usage(
                uuid::Uuid::new_v4(),
                crate::tokens::TokenUsage {
                    input_tokens: 60,
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
        for ctx in [40.0, 50.0, 60.0] {
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
            wire_api: Default::default(),
            extra: Default::default(),
            capabilities: Default::default(),
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

    #[tokio::test]
    async fn dispatch_loop_start_and_cancel() {
        let (mut driver, _tmp) = test_driver(8);
        let out = driver
            .dispatch_schedule_action(&serde_json::json!({
                "action": "loop.start",
                "args": { "interval": 60, "prompt": "poll", "limit": 2 }
            }))
            .await
            .unwrap();
        assert!(out.starts_with("started loop"), "got {out}");
        assert!(driver.schedule.has_loop());
        // The capability hint for loop.cancel fires exactly once.
        let hints = driver.pending_capability_hints();
        assert_eq!(hints.len(), 1);
        assert!(hints[0].contains("loop.cancel"));
        assert!(
            driver.pending_capability_hints().is_empty(),
            "hint is one-shot"
        );

        let job_id = out
            .split('`')
            .nth(1)
            .expect("job id in backticks")
            .to_string();
        let cancel = driver
            .dispatch_schedule_action(&serde_json::json!({
                "action": "loop.cancel",
                "args": { "job_id": job_id }
            }))
            .await
            .unwrap();
        assert!(cancel.starts_with("cancelled"), "got {cancel}");
        assert!(!driver.schedule.has_loop());
    }

    /// End-to-end gate (implementation note): a
    /// `loop.start` whose `interval` AND `limit` are JSON strings (the
    /// observed weak-model failure, session `ezhcf7`) must SUCCEED — both
    /// coerced/accepted, the loop scheduled — rather than erroring on a
    /// value-vs-type confusion.
    #[tokio::test]
    async fn dispatch_loop_start_coerces_stringified_numerics_e2e() {
        let (mut driver, _tmp) = test_driver(8);
        let dispatch = driver
            .dispatch_schedule_action_repaired(&serde_json::json!({
                "action": "loop.start",
                "args": { "interval": "20000", "limit": "1", "prompt": "echo hello" }
            }))
            .await
            .expect("stringified numerics must be coerced, not rejected");
        // `limit=1` → a timer was scheduled.
        assert!(
            dispatch.output.starts_with("started timer"),
            "got {}",
            dispatch.output
        );
        assert!(driver.schedule.has_loop());

        // §14 wire-vs-user split: the row records the per-action repair as
        // its recovery, and the repaired `wire_args` show the coerced int.
        assert!(matches!(
            dispatch.recovery,
            crate::engine::repair::Recovery::ShapeRepair {
                stage: "parse_stringified_number",
                ..
            }
        ));
        assert_eq!(dispatch.wire_args["args"]["limit"], serde_json::json!(1));
        // The string interval (a schema-valid union member) survives as the
        // 20000-second value the parser read.
        assert_eq!(dispatch.wire_args["action"], "loop.start");
    }

    /// The §14 record is populated on the persisted `tool_call` row exactly
    /// like a top-level tool repair: a stringified-numeric `schedule` call stores
    /// `recovery_kind=shape_repair`/`recovery_stage=parse_stringified_number`,
    /// `original_input` = what the model sent, `wire_input` = the repaired
    /// `{action, args}`. Drives the production dispatch + record path.
    #[tokio::test]
    async fn schedule_subarg_repair_record_round_trips_recovery_and_wire() {
        let (mut driver, _tmp) = test_driver(8);
        let original = serde_json::json!({
            "action": "loop.start",
            "args": { "interval": 30, "limit": "1", "prompt": "p" }
        });
        let dispatch = driver
            .dispatch_schedule_action_repaired(&original)
            .await
            .expect("repairable call must dispatch");
        // Mirror the TurnOutcome::ScheduleAction recording (outer recovery is
        // Clean here, so the sub-arg repair is the recorded recovery).
        driver.record_schedule_tool_call(ScheduleToolCallRecord {
            agent: "builder".to_string(),
            llm_mode: crate::config::extended::LlmMode::default(),
            call_id: "call-jobs-repair".to_string(),
            original_input_json: original.clone(),
            wire_input_json: dispatch.wire_args.clone(),
            recovery: dispatch.recovery,
            hard_fail: false,
            output: dispatch.output,
            duration_ms: 1,
        });

        let rows = driver
            .session
            .db
            .list_tool_calls_for_session(driver.session.id)
            .unwrap();
        let row = rows
            .iter()
            .find(|r| r.call_id == "call-jobs-repair")
            .unwrap();
        // original_input keeps the model's stringified `limit`.
        assert_eq!(
            row.original_input_json["args"]["limit"],
            serde_json::json!("1")
        );
        // wire_input carries the coerced integer.
        assert_eq!(row.wire_input_json["args"]["limit"], serde_json::json!(1));
        // recovery_kind/recovery_stage round-trip the shape repair.
        assert!(matches!(
            row.recovery,
            crate::engine::repair::Recovery::ShapeRepair {
                stage: "parse_stringified_number",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn dispatch_timer_is_loop_with_limit_one() {
        let (mut driver, _tmp) = test_driver(8);
        let out = driver
            .dispatch_schedule_action(&serde_json::json!({
                "action": "loop.start",
                "args": { "interval": 5, "prompt": "fire", "limit": 1 }
            }))
            .await
            .unwrap();
        assert!(out.starts_with("started timer"), "got {out}");
    }

    #[tokio::test]
    async fn dispatch_list_and_capacity_error() {
        let (mut driver, _tmp) = test_driver(1);
        let empty: serde_json::Value = serde_json::from_str(
            &driver
                .dispatch_schedule_action(&serde_json::json!({ "action": "list" }))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(empty["scheduled"].as_array().unwrap().len(), 0);
        assert_eq!(empty["swarm"]["running"], 0);
        assert_eq!(empty["swarm"]["queued"], 0);
        driver
            .dispatch_schedule_action(&serde_json::json!({
                "action": "loop.start",
                "args": { "interval": 60, "prompt": "p", "limit": 2 }
            }))
            .await
            .unwrap();
        let listed: serde_json::Value = serde_json::from_str(
            &driver
                .dispatch_schedule_action(&serde_json::json!({ "action": "list" }))
                .await
                .unwrap(),
        )
        .unwrap();
        let scheduled = listed["scheduled"].as_array().unwrap();
        assert_eq!(scheduled.len(), 1, "got {listed}");
        assert_eq!(scheduled[0]["kind"], "loop");
        assert_eq!(scheduled[0]["status"], "pending");
        assert_eq!(scheduled[0]["executions_completed"], 0);
        assert_eq!(scheduled[0]["execution_limit"], serde_json::json!(2));
        assert!(
            scheduled[0]["job_id"]
                .as_str()
                .unwrap()
                .starts_with("sched-")
        );
        assert_eq!(scheduled[0]["label"], "p");
        // Cap is 1 — a second start errors.
        let err = driver
            .dispatch_schedule_action(&serde_json::json!({
                "action": "loop.start",
                "args": { "interval": 60, "prompt": "q", "limit": 2 }
            }))
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("max concurrent scheduled tasks"));
    }

    #[test]
    fn schedule_tool_call_record_persists_wire_and_original() {
        let (driver, _tmp) = test_driver(8);
        let original = serde_json::json!({ "action": "list" });
        let wire = serde_json::json!({ "action": "list", "args": {} });
        driver.record_schedule_tool_call(ScheduleToolCallRecord {
            agent: "builder".to_string(),
            llm_mode: crate::config::extended::LlmMode::default(),
            call_id: "call-sched-1".to_string(),
            original_input_json: original.clone(),
            wire_input_json: wire.clone(),
            recovery: crate::engine::repair::Recovery::Clean,
            hard_fail: false,
            output: "{\"scheduled\":[],\"swarm\":{\"running\":0,\"queued\":0}}".to_string(),
            duration_ms: 3,
        });

        let rows = driver
            .session
            .db
            .list_tool_calls_for_session(driver.session.id)
            .unwrap();
        let row = rows.iter().find(|r| r.tool == "schedule").unwrap();
        assert_eq!(row.call_id, "call-sched-1");
        assert_eq!(row.original_input_json, original);
        assert_eq!(row.wire_input_json, wire);
        assert!(!row.hard_fail);
        assert_eq!(
            row.output,
            "{\"scheduled\":[],\"swarm\":{\"running\":0,\"queued\":0}}"
        );
    }

    /// §5 dispatch record (implementation note): a dispatched
    /// `schedule` action also lands a `tool_call` row on the export timeline
    /// (`session_events`), not just the `tool_call_events` stats table — so the
    /// export reflects the successful native call, not only failed detours.
    #[test]
    fn schedule_dispatch_emits_tool_call_session_event() {
        let (driver, _tmp) = test_driver(8);
        driver.record_schedule_tool_call(ScheduleToolCallRecord {
            agent: "builder".to_string(),
            llm_mode: crate::config::extended::LlmMode::default(),
            call_id: "call-sched-evt".to_string(),
            original_input_json: serde_json::json!({ "action": "list" }),
            wire_input_json: serde_json::json!({ "action": "list", "args": {} }),
            recovery: crate::engine::repair::Recovery::Clean,
            hard_fail: false,
            output: "{\"scheduled\":[],\"swarm\":{\"running\":0,\"queued\":0}}".to_string(),
            duration_ms: 3,
        });

        let events = driver
            .session
            .db
            .list_session_events(driver.session.id)
            .unwrap();
        let tool_call = events
            .iter()
            .find(|e| e.kind == "tool_call" && e.call_id.as_deref() == Some("call-sched-evt"))
            .expect("schedule dispatch should emit a tool_call session event");
        assert_eq!(tool_call.data["tool"], "schedule");
        assert_eq!(tool_call.data["hard_fail"], false);
        assert_eq!(tool_call.data["original_input"]["action"], "list");
    }

    #[tokio::test]
    async fn dispatch_background_tail_unknown_id() {
        let (mut driver, _tmp) = test_driver(8);
        let out = driver
            .dispatch_schedule_action(&serde_json::json!({
                "action": "background.tail",
                "args": { "job_id": "sched-nope" }
            }))
            .await
            .unwrap();
        assert!(out.contains("no live background"), "got {out}");
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

    /// `finish_delegation_shrink`: a COLD-at-return parent (no-cache
    /// provider → always cold) with a computed prune-shrink resumes on the
    /// SHRUNK context — the driver swaps the foreground frame's history.
    #[tokio::test]
    async fn finish_delegation_shrink_cold_swaps_parent_history() {
        use crate::config::providers::{CacheConfig, CacheMode, ShrinkConfig};
        use crate::engine::deleg_shrink::DelegationShrink;

        let (mut driver, _tmp) = test_driver(8);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

        // Parent (foreground) frame carries elidable duplicate reads.
        driver.stack[0].history = dup_read_history();
        assert!(
            !prune::dedup_plan(&driver.stack[0].history).is_empty(),
            "parent has something prunable"
        );

        // A tracker on a no-cache provider is always cold; pre-compute the
        // prune-shrink as the parallel task would have.
        let none = CacheConfig {
            mode: CacheMode::None,
            ttl_secs: 300,
        };
        let mut tracker = DelegationShrink::new(none, &ShrinkConfig::default());
        let shrunk = crate::engine::deleg_shrink::prune_shrink(&driver.stack[0].history);
        tracker.set_shrunk(shrunk);

        driver.finish_delegation_shrink(tracker, None, &tx).await;
        drop(tx);
        while rx.recv().await.is_some() {}

        // Cold → resumed on the shrunk context: the foreground history is
        // now fully pruned (nothing left elidable).
        assert!(
            prune::dedup_plan(&driver.stack[0].history).is_empty(),
            "cold parent resumed on the shrunk (pruned) context"
        );
    }

    /// `finish_delegation_shrink`: a HOT-at-return parent (cache-capable,
    /// within TTL) keeps its FULL context even when a shrink was computed —
    /// no quality loss, the cache is paid for.
    #[tokio::test]
    async fn finish_delegation_shrink_hot_keeps_full() {
        use crate::config::providers::{CacheConfig, CacheMode, ShrinkConfig};
        use crate::engine::deleg_shrink::DelegationShrink;

        let (mut driver, _tmp) = test_driver(8);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

        driver.stack[0].history = dup_read_history();

        // Ephemeral cache, generous TTL, tracker started "now" → hot.
        let ephemeral = CacheConfig {
            mode: CacheMode::Ephemeral,
            ttl_secs: 3600,
        };
        let mut tracker = DelegationShrink::new(ephemeral, &ShrinkConfig::default());
        tracker.set_shrunk(vec![Message::user("shrunk")]);

        driver.finish_delegation_shrink(tracker, None, &tx).await;
        drop(tx);
        while rx.recv().await.is_some() {}

        // Hot → full context retained: still has the elidable duplicate.
        assert!(
            !prune::dedup_plan(&driver.stack[0].history).is_empty(),
            "hot parent kept its full (un-shrunk) context"
        );
    }

    /// `begin_delegation_shrink` on a no-cache provider spawns an EAGER
    /// shrink task that finishes promptly (ZERO delay); the prune-shrink
    /// result is adopted on `finish`. Exercises the full begin→finish path.
    #[tokio::test]
    async fn begin_delegation_shrink_eager_on_no_cache() {
        let (mut driver, _tmp) = test_driver(8);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

        // Default test driver uses provider `lmstudio` with no cache config
        // → CacheMode::None → eager.
        driver.stack[0].history = dup_read_history();
        let parent_full = driver.stack[0].history.clone();
        let (tracker, handle) = driver.begin_delegation_shrink(parent_full);
        assert!(handle.is_some(), "a shrink task was spawned");

        // Let the eager task run to completion.
        let handle = handle.unwrap();
        let shrunk = handle.await.unwrap();
        assert!(
            prune::dedup_plan(&shrunk).is_empty(),
            "eager prune-shrink produced a pruned history"
        );

        // Re-run begin to get a fresh tracker + handle to finish with the
        // already-computed result (the prior handle was consumed above).
        let (mut tracker2, h) = driver.begin_delegation_shrink(driver.stack[0].history.clone());
        if let Some(h) = h {
            h.abort();
        }
        tracker2.set_shrunk(shrunk);
        let _ = tracker; // first tracker not needed further
        driver.finish_delegation_shrink(tracker2, None, &tx).await;
        drop(tx);
        while rx.recv().await.is_some() {}

        // No-cache provider is always cold → swapped to the shrunk context.
        assert!(prune::dedup_plan(&driver.stack[0].history).is_empty());
    }

    // ---- re-queryable subagents + seeding (GOALS §3c) --------------------

    use crate::engine::compact::SeedTool;

    /// Persist a transcript under a handle, then rehydrate it: the round trip
    /// returns the same messages, so a follow-up resumes with prior context.
    #[test]
    fn rehydrate_handle_persist_round_trip() {
        let (driver, tmp) = test_driver(8);
        let history = vec![
            Message::user("earlier question"),
            Message::assistant("earlier answer"),
        ];
        let handle = driver
            .persist_subagent_handle("explore", &history, Some(tmp.path()), None)
            .expect("a handle is minted");
        // Enabled (normal-mode gate passed) + matching agent → rehydrated.
        let got = driver
            .rehydrate_handle(&handle, "explore", Some(tmp.path()), true)
            .expect("rehydrates");
        assert_eq!(got.len(), history.len());
    }

    /// An unknown handle is a clear tool error telling the caller to spawn
    /// fresh — never a silent cold start.
    #[test]
    fn rehydrate_handle_unknown_is_stale_error() {
        let (driver, tmp) = test_driver(8);
        let err = driver
            .rehydrate_handle("sub-does-not-exist", "explore", Some(tmp.path()), true)
            .unwrap_err();
        assert!(err.contains("resume_handle"), "{err}");
        assert!(err.contains("fresh"), "{err}");
    }

    #[test]
    fn resolve_child_cwd_accepts_relative_dot_and_absolute_inside_workspace() {
        let (driver, tmp) = test_driver(8);
        let child_dir = tmp.path().join("child");
        std::fs::create_dir(&child_dir).unwrap();

        let relative = driver.resolve_child_cwd(Some("child")).unwrap();
        assert_eq!(relative.requested.as_deref(), Some("child"));
        assert_eq!(relative.resolved, child_dir.canonicalize().unwrap());

        let dot = driver.resolve_child_cwd(Some(".")).unwrap();
        assert_eq!(dot.requested.as_deref(), Some("."));
        assert_eq!(dot.resolved, tmp.path().canonicalize().unwrap());

        let absolute = driver
            .resolve_child_cwd(Some(child_dir.to_str().unwrap()))
            .unwrap();
        assert_eq!(absolute.resolved, child_dir.canonicalize().unwrap());
    }

    #[test]
    fn resolve_child_cwd_rejects_missing_files_and_outside_workspace() {
        let (driver, tmp) = test_driver(8);
        let file = tmp.path().join("not-a-dir.txt");
        std::fs::write(&file, "x").unwrap();

        let missing = driver.resolve_child_cwd(Some("missing")).unwrap_err();
        assert!(missing.contains("does not exist or is not a directory"));

        let file_err = driver
            .resolve_child_cwd(Some(file.to_str().unwrap()))
            .unwrap_err();
        assert!(file_err.contains("does not exist or is not a directory"));

        let outside = tempfile::tempdir().unwrap();
        let outside_err = driver
            .resolve_child_cwd(Some(outside.path().to_str().unwrap()))
            .unwrap_err();
        assert!(outside_err.contains("outside trusted workspace"));
    }

    /// In defensive mode the whole feature is disabled at the capability
    /// level: even a valid handle is rejected (the only path is a fresh
    /// spawn). Gates behavior, not just description text.
    #[test]
    fn rehydrate_handle_disabled_in_defensive() {
        let (driver, tmp) = test_driver(8);
        let history = vec![Message::user("q")];
        let handle = driver
            .persist_subagent_handle("explore", &history, Some(tmp.path()), None)
            .unwrap();
        // `followup_enabled = false` models the defensive gate
        // (`Capability::FollowupSeed.enabled(Defensive) == false`).
        let err = driver
            .rehydrate_handle(&handle, "explore", Some(tmp.path()), false)
            .unwrap_err();
        assert!(err.contains("fresh"), "{err}");
    }

    /// A handle that belongs to a different agent (and, by construction, any
    /// `docs` follow-up — the pipeline never persists a handle) is stale.
    #[test]
    fn rehydrate_handle_wrong_agent_is_stale() {
        let (driver, tmp) = test_driver(8);
        let handle = driver
            .persist_subagent_handle("explore", &[Message::user("q")], Some(tmp.path()), None)
            .unwrap();
        // Re-querying as `docs` against an `explore` handle → stale (and docs
        // never mints one anyway, so this is the only outcome it can hit).
        let err = driver
            .rehydrate_handle(&handle, "docs", Some(tmp.path()), true)
            .unwrap_err();
        assert!(err.contains("fresh"), "{err}");
    }

    #[test]
    fn rehydrate_handle_wrong_cwd_is_stale() {
        let (driver, tmp) = test_driver(8);
        let original = tmp.path().join("original");
        let other = tmp.path().join("other");
        std::fs::create_dir(&original).unwrap();
        std::fs::create_dir(&other).unwrap();
        let handle = driver
            .persist_subagent_handle("explore", &[Message::user("q")], Some(&original), None)
            .unwrap();

        let err = driver
            .rehydrate_handle(&handle, "explore", Some(&other), true)
            .unwrap_err();
        assert!(err.contains("fresh"), "{err}");
    }

    /// A follow-up persists under the SAME handle (passed as `existing`), so
    /// the caller can keep re-querying with one stable handle.
    #[test]
    fn persist_reuses_existing_handle_on_followup() {
        let (driver, tmp) = test_driver(8);
        let h1 = driver
            .persist_subagent_handle("explore", &[Message::user("q1")], Some(tmp.path()), None)
            .unwrap();
        let h2 = driver
            .persist_subagent_handle(
                "explore",
                &[Message::user("q1"), Message::user("q2")],
                Some(tmp.path()),
                Some(&h1),
            )
            .unwrap();
        assert_eq!(h1, h2, "a follow-up keeps the same handle");
        // The transcript was refreshed (upsert) to the longer history.
        let got = driver
            .rehydrate_handle(&h2, "explore", Some(tmp.path()), true)
            .unwrap();
        assert_eq!(got.len(), 2);
    }

    // ── write-capable follow-up (implementation note) ──

    /// A finished `builder` (write-capable, interactive by default) can be
    /// persisted under a handle and re-queried via it — the round trip returns
    /// the same transcript, so the follow-up resumes with prior context. The
    /// re-query path is agent-name-agnostic: `builder` rehydrates exactly like
    /// `explore`.
    #[test]
    fn builder_followup_persist_and_rehydrate_round_trip() {
        let (driver, tmp) = test_driver(8);
        let history = vec![
            Message::user("implement the flag"),
            write_turn("w1", "/src/a.rs"),
            Message::tool_result_with_call_id("w1".to_string(), None, "[hash=abc123 ok]"),
            Message::assistant("done"),
        ];
        let handle = driver
            .persist_subagent_handle("builder", &history, Some(tmp.path()), None)
            .expect("a builder handle is minted");
        // Stored under the `builder` agent name; re-querying as `builder` rehydrates.
        let got = driver
            .rehydrate_handle(&handle, "builder", Some(tmp.path()), true)
            .expect("builder rehydrates");
        assert_eq!(got.len(), history.len());
        // Re-querying that handle under a DIFFERENT agent name is stale (the
        // handle belongs to `builder`).
        assert!(
            driver
                .rehydrate_handle(&handle, "explore", Some(tmp.path()), true)
                .is_err()
        );
    }

    /// A `builder` follow-up persisting more work under the SAME handle upserts
    /// the transcript (idempotent handle lifecycle), same as `explore`.
    #[test]
    fn builder_followup_refreshes_handle_idempotently() {
        let (driver, tmp) = test_driver(8);
        let h1 = driver
            .persist_subagent_handle(
                "builder",
                &[Message::user("step 1")],
                Some(tmp.path()),
                None,
            )
            .unwrap();
        let h2 = driver
            .persist_subagent_handle(
                "builder",
                &[Message::user("step 1"), Message::assistant("did step 1")],
                Some(tmp.path()),
                Some(&h1),
            )
            .unwrap();
        assert_eq!(h1, h2);
        assert_eq!(
            driver
                .rehydrate_handle(&h2, "builder", Some(tmp.path()), true)
                .unwrap()
                .len(),
            2
        );
    }

    /// The `docs` pipeline is excluded from follow-up: it never persists a
    /// handle, so any `docs` resume is stale (told to spawn fresh).
    #[test]
    fn docs_is_excluded_from_followup() {
        assert!(!crate::engine::builtin::is_followup_eligible("docs"));
        assert!(!crate::engine::builtin::is_followup_eligible(
            "docs-resolver"
        ));
        assert!(!crate::engine::builtin::is_followup_eligible(
            "docs-answerer"
        ));
        // builder/explore/custom are all eligible.
        assert!(crate::engine::builtin::is_followup_eligible("builder"));
        assert!(crate::engine::builtin::is_followup_eligible("explore"));
        assert!(crate::engine::builtin::is_followup_eligible(
            "my-custom-subagent"
        ));
    }

    /// End-to-end lock composition for a write-capable follow-up: the finished
    /// `builder`'s locks are snapshotted on suspend; a follow-up re-acquires them
    /// HASH-MATCHED when the worktree is unchanged, and the §3c write guard
    /// holds (the reawakened builder may write the still-matching file).
    #[test]
    fn write_capable_followup_reacquires_locks_hash_matched() {
        let (driver, tmp) = test_driver(8);
        let p = tmp.path().join("a.rs");
        std::fs::write(&p, "v1").unwrap();
        let sid = driver.session.id;
        // Original builder run: acquire + write, then finish (suspend snapshots).
        driver.locks.acquire(&p, "builder", sid).unwrap();
        driver
            .locks
            .check_write_permitted(&p, "builder", sid)
            .unwrap();
        driver.locks.suspend_agent("builder", sid).unwrap();
        assert!(
            driver.locks.holder(&p).is_none(),
            "finish releases the lock"
        );
        // Follow-up: worktree unchanged → resume reacquires hash-matched.
        let reacquired = driver.locks.resume_agent("builder", sid).unwrap();
        assert_eq!(reacquired.len(), 1);
        assert_eq!(
            driver.locks.holder(&p).map(|(_, a)| a).as_deref(),
            Some("builder")
        );
        // The reawakened builder may write the still-matching file (§3c holds).
        driver
            .locks
            .check_write_permitted(&p, "builder", sid)
            .unwrap();
    }

    /// No stale write when the worktree changed under a reawakened builder: a
    /// drifted file is NOT reacquired and its §3c read record is dropped, so a
    /// write is refused until the builder re-reads (`readlock`) it.
    #[test]
    fn write_capable_followup_forces_reread_on_drift() {
        let (driver, tmp) = test_driver(8);
        let p = tmp.path().join("a.rs");
        std::fs::write(&p, "v1").unwrap();
        let sid = driver.session.id;
        driver.locks.acquire(&p, "builder", sid).unwrap();
        driver.locks.suspend_agent("builder", sid).unwrap();
        // The user / another agent edits the file while the builder was finished.
        std::fs::write(&p, "v2-drift").unwrap();
        let reacquired = driver.locks.resume_agent("builder", sid).unwrap();
        assert!(reacquired.is_empty(), "drifted file must not reacquire");
        assert!(driver.locks.holder(&p).is_none());
        // Write is refused (the read record was invalidated) — no stale write.
        assert!(
            driver
                .locks
                .check_write_permitted(&p, "builder", sid)
                .is_err()
        );
        // After an explicit re-read the write is permitted again.
        driver.locks.note_read(&p, "builder", sid);
        driver
            .locks
            .check_write_permitted(&p, "builder", sid)
            .unwrap();
    }

    /// Lock re-acquire failure because another writer now holds the path is
    /// surfaced (the builder simply doesn't hold it) and the follow-up does NOT
    /// force-write — single-writer is preserved, the other writer keeps the
    /// lock.
    #[test]
    fn write_capable_followup_defers_to_other_lock_holder() {
        let (driver, tmp) = test_driver(8);
        let p = tmp.path().join("a.rs");
        std::fs::write(&p, "v1").unwrap();
        let sid = driver.session.id;
        // A second session/agent grabs the path while the builder is finished.
        let other = driver
            .session
            .db
            .create_session("p", "/x", "builder")
            .unwrap();
        driver.locks.acquire(&p, "builder", sid).unwrap();
        driver.locks.suspend_agent("builder", sid).unwrap();
        driver
            .locks
            .acquire(&p, "builder", other.session_id)
            .unwrap();
        // Follow-up resume can't reacquire — the other holder wins.
        let reacquired = driver.locks.resume_agent("builder", sid).unwrap();
        assert!(reacquired.is_empty());
        assert_eq!(
            driver.locks.holder(&p).map(|(s, _)| s),
            Some(other.session_id)
        );
        // The reawakened builder cannot write the path (no force-write).
        assert!(
            driver
                .locks
                .check_write_permitted(&p, "builder", sid)
                .is_err()
        );
    }

    /// The cache-aware reuse decision is driven by the session's active cache
    /// config + time-since-last-send. The test driver's provider declares no
    /// cache, so a follow-up takes the no-cache-reuse path deterministically.
    #[test]
    fn followup_reuse_decision_no_cache_provider() {
        let (driver, _t) = test_driver(8);
        assert_eq!(
            driver.followup_reuse_decision(),
            crate::engine::prune::FollowupReuse::NoCacheReuse
        );
    }

    /// Build a driver whose root (caller) agent holds the `read` tool so
    /// `inject_seeds` can re-execute a `read` seed in the caller's cwd.
    fn driver_with_read_caller() -> (Driver, tempfile::TempDir) {
        let (mut driver, tmp) = test_driver(8);
        let old = driver.stack[0].agent.clone();
        let tools = crate::engine::tool::ToolBox::new()
            .with(std::sync::Arc::new(crate::tools::read::ReadTool));
        driver.stack[0].agent = std::sync::Arc::new(Agent {
            name: old.name.clone(),
            system: old.system.clone(),
            role_prompt: old.role_prompt.clone(),
            tools,
            model: old.model.clone(),
            params: old.params.clone(),
            scan_tool_results: old.scan_tool_results,
            llm_mode: crate::config::extended::LlmMode::Normal,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            env_overlay: old.env_overlay.clone(),
        });
        (driver, tmp)
    }

    /// A caller assistant turn that ends in a `task` tool call (the turn a
    /// noninteractive delegation came from). `inject_seeds` folds seed calls
    /// into this turn.
    fn assistant_with_task_call(task_call_id: &str) -> Message {
        use crate::engine::message::{AssistantContent, OneOrMany, ToolCall};
        use rig::message::ToolFunction;
        Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(ToolCall {
                id: task_call_id.to_string(),
                call_id: None,
                function: ToolFunction {
                    name: "task".into(),
                    arguments: serde_json::json!({ "agent": "explore", "prompt": "go" }),
                },
                signature: None,
                additional_params: None,
            })),
        }
    }

    fn tool_result_id(msg: &Message) -> String {
        use rig::message::UserContent;
        match msg {
            Message::User { content } => content
                .iter()
                .find_map(|part| match part {
                    UserContent::ToolResult(result) => Some(result.id.clone()),
                    _ => None,
                })
                .expect("tool_result id"),
            _ => panic!("expected a tool_result user message"),
        }
    }

    fn tool_result_provider_call_id(msg: &Message) -> Option<String> {
        use rig::message::UserContent;
        match msg {
            Message::User { content } => content.iter().find_map(|part| match part {
                UserContent::ToolResult(result) => result.call_id.clone(),
                _ => None,
            }),
            _ => panic!("expected a tool_result user message"),
        }
    }

    fn pending_test_shrink() -> PendingDelegationShrink {
        PendingDelegationShrink {
            tracker: crate::engine::deleg_shrink::DelegationShrink::new(
                crate::config::providers::CacheConfig::default(),
                &crate::config::providers::ShrinkConfig::default(),
            ),
            handle: None,
        }
    }

    fn single_noninteractive_completion(
        task_call_id: &str,
        report: &str,
    ) -> SingleNoninteractiveCompletion {
        SingleNoninteractiveCompletion {
            child_agent: "explore".to_string(),
            task_call_id: task_call_id.to_string(),
            task_function_call_id: Some(format!("fn-{task_call_id}")),
            report: report.to_string(),
            failed: false,
            partial_progress: DelegationPartialProgress::default(),
            seeds: Vec::new(),
            new_handle: None,
            snapshot: NoninteractiveDelegationSnapshot::empty(),
            shrink: None,
            repair_notes: Vec::new(),
        }
    }

    fn cold_ready_test_shrink(shrunk: Vec<Message>) -> PendingDelegationShrink {
        use crate::config::providers::{CacheConfig, CacheMode, ShrinkConfig};
        let mut tracker = crate::engine::deleg_shrink::DelegationShrink::new(
            CacheConfig {
                mode: CacheMode::Ephemeral,
                ttl_secs: 0,
            },
            &ShrinkConfig::default(),
        );
        tracker.set_shrunk(shrunk);
        PendingDelegationShrink {
            tracker,
            handle: None,
        }
    }

    #[tokio::test]
    async fn pending_noninteractive_completion_routes_by_task_call_id() {
        let (mut driver, _tmp) = test_driver(8);
        let tx = driver.noninteractive_complete_tx.clone();
        tx.send(BackgroundNoninteractiveCompletion::Single {
            task_call_id: "task-a".to_string(),
            task_function_call_id: Some("fn-task-a".to_string()),
            result: Box::new(Ok(single_noninteractive_completion("task-a", "a done"))),
        })
        .await
        .unwrap();
        tx.send(BackgroundNoninteractiveCompletion::Single {
            task_call_id: "task-b".to_string(),
            task_function_call_id: Some("fn-task-b".to_string()),
            result: Box::new(Ok(single_noninteractive_completion("task-b", "b done"))),
        })
        .await
        .unwrap();

        let completion = driver
            .recv_noninteractive_completion_for("task-b")
            .await
            .expect("task-b completion");
        assert_eq!(completion.task_call_id(), "task-b");
        assert_eq!(driver.pending_noninteractive_completions.len(), 1);
        assert_eq!(
            driver.pending_noninteractive_completions[0].task_call_id(),
            "task-a"
        );

        let completion = driver
            .recv_noninteractive_completion_for("task-a")
            .await
            .expect("task-a completion");
        assert_eq!(completion.task_call_id(), "task-a");
        assert!(driver.pending_noninteractive_completions.is_empty());
    }

    #[tokio::test]
    async fn delivered_finished_noninteractive_job_is_reaped() {
        let (mut driver, _tmp) = test_driver(8);
        driver.noninteractive_jobs.insert(
            "task-reap".to_string(),
            BackgroundNoninteractiveJob {
                delivered: true,
                handle: tokio::spawn(async {}),
            },
        );
        tokio::task::yield_now().await;

        driver.reap_finished_noninteractive_jobs();

        assert!(!driver.noninteractive_jobs.contains_key("task-reap"));
    }

    #[tokio::test]
    async fn whole_job_cancel_releases_aborted_child_locks() {
        let (mut driver, tmp) = test_driver(8);
        let path = tmp.path().join("held.rs");
        std::fs::write(&path, "fn main() {}\n").unwrap();
        seed_task_delegation(&driver, "task-lock", "default");
        driver.noninteractive_delegations.register_running(
            "task-lock",
            "default",
            "explore".to_string(),
            NoninteractiveDelegationSnapshot::empty(),
        );
        driver
            .locks
            .acquire(&path, "explore", driver.session.id)
            .unwrap();
        driver.noninteractive_jobs.insert(
            "task-lock".to_string(),
            BackgroundNoninteractiveJob {
                delivered: false,
                handle: tokio::spawn(async {
                    std::future::pending::<()>().await;
                }),
            },
        );

        let body = driver.dispatch_task_control(
            TaskControlAction::Cancel,
            Some("task-lock".to_string()),
            None,
            None,
        );

        assert!(body.contains("cancelled"), "{body}");
        assert!(driver.locks.holder(&path).is_none());
        assert!(!driver.noninteractive_jobs.contains_key("task-lock"));
    }

    #[tokio::test]
    async fn inline_background_completion_error_keeps_original_task_pairing() {
        let (mut driver, _tmp) = test_driver(8);
        let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

        let delivery = driver
            .finalize_background_noninteractive_completion(
                Some(BackgroundNoninteractiveCompletion::Single {
                    task_call_id: "task-inline".to_string(),
                    task_function_call_id: Some("fn-inline".to_string()),
                    result: Box::new(Err(anyhow::anyhow!("child crashed"))),
                }),
                &tx,
            )
            .await
            .unwrap();

        let NoninteractiveCompletionDelivery::Inline(message) = delivery else {
            panic!("inline error should satisfy the open task tool call");
        };
        assert_eq!(tool_result_id(&message), "task-inline");
        assert_eq!(
            tool_result_provider_call_id(&message).as_deref(),
            Some("fn-inline")
        );
        assert!(tool_result_text(&message).contains("child crashed"));
    }

    #[tokio::test]
    async fn backgrounded_completion_error_becomes_async_failed_result_once() {
        let (mut driver, _tmp) = test_driver(8);
        seed_task_delegation(&driver, "task-bg-error", "default");
        driver
            .session
            .db
            .background_task_delegation_child("task-bg-error", "default")
            .unwrap();
        driver.noninteractive_delegations.register_running(
            "task-bg-error",
            "default",
            "explore".to_string(),
            NoninteractiveDelegationSnapshot::empty(),
        );
        driver
            .noninteractive_delegations
            .background_on_user_input("task-bg-error", "default");
        driver.noninteractive_jobs.insert(
            "task-bg-error".to_string(),
            BackgroundNoninteractiveJob {
                delivered: false,
                handle: tokio::spawn(async {}),
            },
        );
        let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

        let delivery = driver
            .finalize_background_noninteractive_completion(
                Some(BackgroundNoninteractiveCompletion::Single {
                    task_call_id: "task-bg-error".to_string(),
                    task_function_call_id: Some("fn-bg-error".to_string()),
                    result: Box::new(Err(anyhow::anyhow!("late child crashed"))),
                }),
                &tx,
            )
            .await
            .unwrap();

        let NoninteractiveCompletionDelivery::AsyncUser(text) = delivery else {
            panic!("backgrounded error should be delivered as async user input");
        };
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["type"], "task_delegation");
        assert_eq!(json["version"], 1);
        assert_eq!(json["state"], "failed");
        assert_eq!(json["task_call_id"], "task-bg-error");
        assert_eq!(json["children"][0]["label"], "default");
        assert_eq!(json["children"][0]["status"], "failed");
        assert_eq!(json["children"][0]["error"], "Error: late child crashed");

        let duplicate = driver
            .finalize_background_noninteractive_completion(
                Some(BackgroundNoninteractiveCompletion::Single {
                    task_call_id: "task-bg-error".to_string(),
                    task_function_call_id: Some("fn-bg-error".to_string()),
                    result: Box::new(Err(anyhow::anyhow!("late child crashed again"))),
                }),
                &tx,
            )
            .await
            .unwrap();
        assert!(matches!(duplicate, NoninteractiveCompletionDelivery::None));
    }

    #[tokio::test]
    async fn backgrounded_batch_completion_delivers_one_mixed_status_payload() {
        let (mut driver, _tmp) = test_driver(8);
        seed_batch_task_delegation(&driver, "task-mixed", &["first", "second", "third"]);
        for label in ["first", "second", "third"] {
            driver
                .session
                .db
                .background_task_delegation_child("task-mixed", label)
                .unwrap();
            driver.noninteractive_delegations.register_running(
                "task-mixed",
                label,
                "explore".to_string(),
                NoninteractiveDelegationSnapshot::empty(),
            );
            driver
                .noninteractive_delegations
                .background_on_user_input("task-mixed", label);
        }
        let (tx, _rx) = mpsc::channel::<TurnEvent>(8);

        let delivery = driver
            .finalize_background_noninteractive_completion(
                Some(BackgroundNoninteractiveCompletion::Batch {
                    task_call_id: "task-mixed".to_string(),
                    task_function_call_id: Some("fn-mixed".to_string()),
                    result: Box::new(Ok(BatchNoninteractiveCompletion {
                        task_call_id: "task-mixed".to_string(),
                        task_function_call_id: Some("fn-mixed".to_string()),
                        children: vec![
                            BatchChildCompletion {
                                idx: 0,
                                label: "first".to_string(),
                                child_agent: "explore".to_string(),
                                report: "first report".to_string(),
                                failed: false,
                                partial_progress: DelegationPartialProgress::default(),
                                snapshot: NoninteractiveDelegationSnapshot::empty(),
                            },
                            BatchChildCompletion {
                                idx: 1,
                                label: "second".to_string(),
                                child_agent: "explore".to_string(),
                                report: "second failed".to_string(),
                                failed: true,
                                partial_progress: DelegationPartialProgress::default(),
                                snapshot: NoninteractiveDelegationSnapshot::empty(),
                            },
                            BatchChildCompletion {
                                idx: 2,
                                label: "third".to_string(),
                                child_agent: "explore".to_string(),
                                report: "third report".to_string(),
                                failed: false,
                                partial_progress: DelegationPartialProgress::default(),
                                snapshot: NoninteractiveDelegationSnapshot::empty(),
                            },
                        ],
                        repair_notes: Vec::new(),
                    })),
                }),
                &tx,
            )
            .await
            .unwrap();

        let NoninteractiveCompletionDelivery::AsyncUser(text) = delivery else {
            panic!("backgrounded batch should be delivered as one async user input");
        };
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["type"], "task_delegation");
        assert_eq!(json["version"], 1);
        assert_eq!(json["state"], "failed");
        assert_eq!(json["task_call_id"], "task-mixed");
        let children = json["children"].as_array().unwrap();
        assert_eq!(children.len(), 3);
        assert_eq!(children[0]["label"], "first");
        assert_eq!(children[0]["status"], "completed");
        assert_eq!(children[0]["report"], "first report");
        assert_eq!(children[1]["label"], "second");
        assert_eq!(children[1]["status"], "failed");
        assert_eq!(children[1]["error"], "second failed");
        assert_eq!(children[2]["label"], "third");
        assert_eq!(children[2]["status"], "completed");
        assert_eq!(children[2]["report"], "third report");
    }

    #[tokio::test]
    async fn background_single_completion_does_not_apply_stale_shrink() {
        let (mut driver, _tmp) = test_driver(8);
        seed_task_delegation(&driver, "task-single", "default");
        driver
            .noninteractive_delegations
            .background_on_user_input("task-single", "default");
        let foreground_history = vec![
            Message::user("start delegated task"),
            assistant_with_task_call("task-single"),
            Message::user("foreground remains"),
        ];
        driver.stack.last_mut().unwrap().history = foreground_history.clone();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

        let result = driver
            .finalize_single_noninteractive_task(
                SingleNoninteractiveCompletion {
                    shrink: Some(cold_ready_test_shrink(vec![Message::user("stale shrink")])),
                    ..single_noninteractive_completion("task-single", "single report")
                },
                &tx,
                false,
            )
            .await;
        drop(tx);
        while rx.recv().await.is_some() {}

        assert_eq!(tool_result_id(&result), "task-single");
        assert_eq!(tool_result_text(&result), "single report");
        assert_eq!(driver.stack.last().unwrap().history, foreground_history);
    }

    #[test]
    fn subagent_report_event_data_preserves_body_for_all_writer_shapes() {
        for (child_agent, task_call_id, function_call_id, label, report, expected_source) in [
            (
                "explore",
                Some("task-single"),
                Some("fn-single"),
                "default",
                "single report",
                Some("provider"),
            ),
            (
                "reviewer",
                Some("task-batch"),
                Some("fn-batch"),
                "second",
                "batch report",
                Some("provider"),
            ),
            (
                "builder",
                Some("task-interactive"),
                Some("fn-interactive"),
                "default",
                "interactive report",
                Some("provider"),
            ),
            (
                "builder",
                Some("task-abort"),
                Some("fn-abort"),
                "default",
                "Error: cancelled by user",
                Some("provider"),
            ),
            (
                "builder",
                Some("task-synthetic"),
                None,
                "default",
                "Error: failed without provider identity",
                Some("synthetic_from_cockpit_call_id"),
            ),
            ("builder", None, None, "default", "detached report", None),
        ] {
            let data = subagent_report_event_data(
                child_agent,
                task_call_id,
                function_call_id,
                label,
                report,
                None,
            );
            assert_eq!(data["child_agent"], child_agent);
            assert_eq!(data["task_call_id"], serde_json::json!(task_call_id));
            assert_eq!(data["label"], label);
            assert_eq!(data["report"], report);
            match (task_call_id, function_call_id, expected_source) {
                (Some(task_call_id), Some(function_call_id), Some("provider")) => {
                    assert_eq!(data["provider_call_id"], function_call_id);
                    assert_eq!(data["provider_call_id_source"], "provider");
                    assert_eq!(data["provider_identity"]["cockpit_call_id"], task_call_id);
                    assert_eq!(
                        data["provider_identity"]["provider_call_id"],
                        function_call_id
                    );
                }
                (Some(task_call_id), None, Some("synthetic_from_cockpit_call_id")) => {
                    assert_eq!(data["provider_call_id"], task_call_id);
                    assert_eq!(
                        data["provider_call_id_source"],
                        "synthetic_from_cockpit_call_id"
                    );
                    assert_eq!(data["provider_identity"]["provider_call_id"], task_call_id);
                }
                (None, None, None) => {
                    assert!(data["provider_call_id"].is_null());
                    assert!(data["provider_call_id_source"].is_null());
                    assert!(data["provider_identity"].is_null());
                }
                other => panic!("uncovered test shape: {other:?}"),
            }
        }
    }

    #[test]
    fn subagent_report_event_data_includes_partial_progress_when_present() {
        let progress = partial_progress_from_history(&[
            write_turn("w1", "/src/a.rs"),
            Message::tool_result_with_call_id("w1".to_string(), None, "[hash=abc123 ok]"),
        ]);
        let report = render_failed_subagent_report("Error: turn limit", &progress);

        let data = subagent_report_event_data(
            "builder",
            Some("task-single"),
            Some("fn-single"),
            "default",
            &report,
            Some(&progress),
        );

        assert_eq!(data["report"], report);
        assert_eq!(
            data["partial_progress"]["files_edited"][0]["path"],
            "/src/a.rs"
        );
        assert_eq!(
            data["partial_progress"]["verification_state"],
            "not_completed"
        );
        assert_eq!(data["partial_progress"]["review_state"], "needs_review");
        assert_eq!(
            data["partial_progress"]["dirty_owned_changes"][0],
            "/src/a.rs"
        );
    }

    #[tokio::test]
    async fn noninteractive_single_inline_result_shape_is_unchanged() {
        let (mut driver, _tmp) = test_driver(8);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let result = driver
            .finalize_single_noninteractive_task(
                SingleNoninteractiveCompletion {
                    child_agent: "explore".to_string(),
                    task_call_id: "task-single".to_string(),
                    task_function_call_id: Some("fn-single".to_string()),
                    report: "single report".to_string(),
                    failed: false,
                    partial_progress: DelegationPartialProgress::default(),
                    seeds: Vec::new(),
                    new_handle: None,
                    snapshot: NoninteractiveDelegationSnapshot::empty(),
                    shrink: None,
                    repair_notes: Vec::new(),
                },
                &tx,
                true,
            )
            .await;
        drop(tx);
        while rx.recv().await.is_some() {}

        assert_eq!(tool_result_id(&result), "task-single");
        assert_eq!(tool_result_text(&result), "single report");
    }

    #[tokio::test]
    async fn noninteractive_single_report_body_matches_live_event_db_event_row_and_result() {
        let (mut driver, _tmp) = test_driver(8);
        seed_task_delegation(&driver, "task-single", "default");
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let result = driver
            .finalize_single_noninteractive_task(
                SingleNoninteractiveCompletion {
                    child_agent: "explore".to_string(),
                    task_call_id: "task-single".to_string(),
                    task_function_call_id: Some("fn-single".to_string()),
                    report: "single report".to_string(),
                    failed: false,
                    partial_progress: DelegationPartialProgress::default(),
                    seeds: Vec::new(),
                    new_handle: None,
                    snapshot: NoninteractiveDelegationSnapshot::empty(),
                    shrink: Some(pending_test_shrink()),
                    repair_notes: Vec::new(),
                },
                &tx,
                true,
            )
            .await;
        drop(tx);

        let mut live_report = None;
        while let Some(event) = rx.recv().await {
            if let TurnEvent::SubagentReport {
                agent,
                task_call_id,
                label,
                report,
                ..
            } = event
            {
                live_report = Some((agent, task_call_id, label, report));
            }
        }
        let (agent, task_call_id, label, report) = live_report.expect("live subagent report event");
        assert_eq!(agent, "explore");
        assert_eq!(task_call_id, "task-single");
        assert_eq!(label, "default");
        assert_eq!(report, "single report");

        let events = driver
            .session
            .db
            .list_session_events(driver.session.id)
            .unwrap();
        let event = events
            .iter()
            .find(|event| {
                event.kind == "subagent_report" && event.call_id.as_deref() == Some("task-single")
            })
            .expect("durable subagent_report event");
        assert_eq!(event.data["child_agent"], "explore");
        assert_eq!(event.data["task_call_id"], "task-single");
        assert_eq!(event.data["label"], "default");
        assert_eq!(event.data["report"], "single report");
        assert_eq!(event.data["provider_call_id"], "fn-single");
        assert_eq!(event.data["provider_call_id_source"], "provider");
        assert_eq!(
            event.data["provider_identity"]["provider_call_id"],
            "fn-single"
        );

        let row = driver
            .session
            .db
            .list_task_delegation_children(driver.session.id)
            .unwrap()
            .into_iter()
            .find(|row| row.task_call_id == "task-single" && row.label == "default")
            .expect("completed task delegation child row");
        assert_eq!(row.child_agent, "explore");
        assert_eq!(row.report.as_deref(), Some("single report"));

        assert_eq!(tool_result_id(&result), "task-single");
        assert_eq!(tool_result_text(&result), "single report");
    }

    #[tokio::test]
    async fn noninteractive_single_result_includes_task_repair_notes() {
        let (mut driver, _tmp) = test_driver(8);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let result = driver
            .finalize_single_noninteractive_task(
                SingleNoninteractiveCompletion {
                    child_agent: "explore".to_string(),
                    task_call_id: "task-single".to_string(),
                    task_function_call_id: Some("fn-single".to_string()),
                    report: "single report".to_string(),
                    failed: false,
                    partial_progress: DelegationPartialProgress::default(),
                    seeds: Vec::new(),
                    new_handle: None,
                    snapshot: NoninteractiveDelegationSnapshot::empty(),
                    shrink: None,
                    repair_notes: vec![
                        "dropped `action` (incompatible with fresh delegation) — treating as fresh spawn of `agent=explore`"
                            .to_string(),
                    ],
                },
                &tx,
                true,
            )
            .await;
        drop(tx);
        while rx.recv().await.is_some() {}

        let text = tool_result_text(&result);
        assert!(text.starts_with("dropped `action`"), "{text}");
        assert!(text.contains("\n\nsingle report"), "{text}");
    }

    #[tokio::test]
    async fn noninteractive_batch_inline_result_shape_is_unchanged() {
        let (mut driver, _tmp) = test_driver(8);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let result = driver
            .finalize_batch_noninteractive_task(
                BatchNoninteractiveCompletion {
                    task_call_id: "task-batch".to_string(),
                    task_function_call_id: Some("fn-batch".to_string()),
                    children: vec![
                        BatchChildCompletion {
                            idx: 1,
                            label: "second".to_string(),
                            child_agent: "reviewer".to_string(),
                            report: "second report".to_string(),
                            failed: false,
                            partial_progress: DelegationPartialProgress::default(),
                            snapshot: NoninteractiveDelegationSnapshot::empty(),
                        },
                        BatchChildCompletion {
                            idx: 0,
                            label: "first".to_string(),
                            child_agent: "explore".to_string(),
                            report: "Error: first issue was fixed".to_string(),
                            failed: false,
                            partial_progress: DelegationPartialProgress::default(),
                            snapshot: NoninteractiveDelegationSnapshot::empty(),
                        },
                    ],
                    repair_notes: Vec::new(),
                },
                &tx,
            )
            .await;
        drop(tx);
        while rx.recv().await.is_some() {}

        assert_eq!(tool_result_id(&result), "task-batch");
        let body: serde_json::Value = serde_json::from_str(&tool_result_text(&result)).unwrap();
        assert_eq!(body["status"], "completed");
        let children = body["children"].as_array().unwrap();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0]["label"], "first");
        assert_eq!(children[0]["agent"], "explore");
        assert_eq!(children[0]["failed"], false);
        assert_eq!(children[0]["report"], "Error: first issue was fixed");
        assert_eq!(children[1]["label"], "second");
        assert_eq!(children[1]["agent"], "reviewer");
        assert_eq!(children[1]["failed"], false);
        assert_eq!(children[1]["report"], "second report");
    }

    #[tokio::test]
    async fn noninteractive_batch_result_includes_task_repair_notes() {
        let (mut driver, _tmp) = test_driver(8);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let result = driver
            .finalize_batch_noninteractive_task(
                BatchNoninteractiveCompletion {
                    task_call_id: "task-batch".to_string(),
                    task_function_call_id: Some("fn-batch".to_string()),
                    children: vec![BatchChildCompletion {
                        idx: 0,
                        label: "first".to_string(),
                        child_agent: "explore".to_string(),
                        report: "first report".to_string(),
                        failed: false,
                        partial_progress: DelegationPartialProgress::default(),
                        snapshot: NoninteractiveDelegationSnapshot::empty(),
                    }],
                    repair_notes: vec![
                        "dropped `action` (incompatible with fresh delegation) — treating as fresh spawn of `agent=explore`"
                            .to_string(),
                    ],
                },
                &tx,
            )
            .await;
        drop(tx);
        while rx.recv().await.is_some() {}

        let body: serde_json::Value = serde_json::from_str(&tool_result_text(&result)).unwrap();
        assert_eq!(
            body["repair_notes"][0],
            "dropped `action` (incompatible with fresh delegation) — treating as fresh spawn of `agent=explore`"
        );
    }

    #[test]
    fn queued_user_input_backgrounds_running_single_delegation() {
        let mut registry = NoninteractiveDelegationRegistry::default();
        registry.register_running(
            "task-single",
            "default",
            "explore".to_string(),
            NoninteractiveDelegationSnapshot::from_history(vec![Message::user("parent snapshot")]),
        );

        assert!(registry.background_on_user_input("task-single", "default"));
        assert_eq!(
            registry.status("task-single", "default"),
            Some(NoninteractiveDelegationStatus::Backgrounded)
        );
        assert_eq!(
            registry.child_agent("task-single", "default"),
            Some("explore")
        );
        assert_eq!(registry.snapshot_len("task-single", "default"), Some(1));
        assert!(
            !registry.background_on_user_input("task-single", "default"),
            "a backgrounded delegation is not backgrounded twice"
        );
    }

    #[test]
    fn queued_user_input_backgrounds_running_batch_delegation() {
        let mut registry = NoninteractiveDelegationRegistry::default();
        registry.register_running(
            "task-batch",
            "first",
            "explore".to_string(),
            NoninteractiveDelegationSnapshot::from_history(vec![Message::user("parent snapshot")]),
        );

        assert!(registry.background_on_user_input("task-batch", "first"));
        assert_eq!(
            registry.status("task-batch", "first"),
            Some(NoninteractiveDelegationStatus::Backgrounded)
        );
        assert_eq!(registry.child_agent("task-batch", "first"), Some("explore"));
    }

    #[test]
    fn noninteractive_registry_is_live_only_for_running_and_backgrounded() {
        let mut registry = NoninteractiveDelegationRegistry::default();
        assert!(!registry.is_live("task-1", "default"));
        registry.register_running(
            "task-1",
            "default",
            "explore".to_string(),
            NoninteractiveDelegationSnapshot::empty(),
        );
        assert!(registry.is_live("task-1", "default"));
        assert!(registry.background_on_user_input("task-1", "default"));
        assert!(registry.is_live("task-1", "default"));
        assert!(registry.cancel("task-1", "default"));
        assert!(!registry.is_live("task-1", "default"));

        registry.register_running(
            "task-2",
            "default",
            "explore".to_string(),
            NoninteractiveDelegationSnapshot::empty(),
        );
        assert!(registry.complete("task-2", "default", "done".to_string(), false, None));
        assert!(!registry.is_live("task-2", "default"));
    }

    #[test]
    fn noninteractive_registry_completion_status_uses_host_flag() {
        let mut registry = NoninteractiveDelegationRegistry::default();
        registry.register_running(
            "task-1",
            "default",
            "explore".to_string(),
            NoninteractiveDelegationSnapshot::empty(),
        );

        assert!(registry.complete(
            "task-1",
            "default",
            "Error: quoted issue was fixed".to_string(),
            false,
            None,
        ));
        assert_eq!(
            registry.status("task-1", "default"),
            Some(NoninteractiveDelegationStatus::Completed)
        );

        registry.register_running(
            "task-2",
            "default",
            "explore".to_string(),
            NoninteractiveDelegationSnapshot::empty(),
        );
        assert!(registry.complete(
            "task-2",
            "default",
            "ordinary report".to_string(),
            true,
            None
        ));
        assert_eq!(
            registry.status("task-2", "default"),
            Some(NoninteractiveDelegationStatus::Failed)
        );
    }

    #[test]
    fn host_failure_sentinel_matches_only_host_error_shape() {
        assert!(is_host_failure_sentinel("Error: boom"));
        assert!(is_host_failure_sentinel("  Error: leading ws"));
        assert!(!is_host_failure_sentinel("Error:nospace"));
        assert!(!is_host_failure_sentinel("## Accomplished\nError: quoted"));
    }

    #[test]
    fn task_control_orphan_list_status_cancel_and_refuse_live_actions() {
        let (mut driver, _tmp) = test_driver(8);
        seed_task_delegation(&driver, "task-orphan", "default");

        let list = driver.dispatch_task_control(TaskControlAction::List, None, None, None);
        let list_json: serde_json::Value = serde_json::from_str(&list).unwrap();
        assert_eq!(list_json["type"], "task_delegation");
        assert_eq!(list_json["version"], 1);
        assert_eq!(list_json["state"], "list");
        assert_eq!(list_json["children"][0]["status"], "lost");
        assert_eq!(list_json["children"][0]["blocking"], false);
        assert_eq!(list_json["children"][0]["tool_call_closed"], false);
        assert_eq!(list_json["children"][0]["result_pending"], true);
        assert_eq!(list_json["children"][0]["report_available"], false);
        assert_eq!(list_json["children"][0]["report_delivered"], false);
        assert_eq!(list_json["children"][0]["pending_steers"], 0);
        assert_eq!(list_json["children"][0]["orphaned"], true);
        assert_eq!(list_json["children"][0]["actionable"], false);

        let status = driver.dispatch_task_control(
            TaskControlAction::Status,
            Some("task-orphan".to_string()),
            Some("default".to_string()),
            None,
        );
        let status_json: serde_json::Value = serde_json::from_str(&status).unwrap();
        assert_eq!(status_json["state"], "status");
        assert_eq!(status_json["children"][0]["status"], "lost");
        assert_eq!(status_json["children"][0]["orphaned"], true);

        let query = driver.dispatch_task_control(
            TaskControlAction::Query,
            Some("task-orphan".to_string()),
            Some("default".to_string()),
            None,
        );
        let query_json: serde_json::Value = serde_json::from_str(&query).unwrap();
        assert_eq!(query_json["state"], "refused");
        assert_eq!(query_json["actionable"], false);
        assert_eq!(
            query_json["reason"],
            "lost (daemon restarted; no live worker)"
        );
        assert_eq!(query_json["report_source"], "none");
        assert_eq!(query_json["children"][0]["status"], "lost");

        let steer = driver.dispatch_task_control(
            TaskControlAction::Steer,
            Some("task-orphan".to_string()),
            Some("default".to_string()),
            Some("please continue".to_string()),
        );
        let steer_json: serde_json::Value = serde_json::from_str(&steer).unwrap();
        assert_eq!(steer_json["state"], "refused");
        assert_eq!(steer_json["actionable"], false);
        assert_eq!(
            steer_json["reason"],
            "lost (daemon restarted; no live worker)"
        );
        assert_eq!(steer_json["children"][0]["status"], "lost");

        let cancel = driver.dispatch_task_control(
            TaskControlAction::Cancel,
            Some("task-orphan".to_string()),
            Some("default".to_string()),
            None,
        );
        let cancel_json: serde_json::Value = serde_json::from_str(&cancel).unwrap();
        assert_eq!(cancel_json["state"], "lost");
        assert_eq!(cancel_json["cancelled"].as_array().unwrap().len(), 0);
        assert_eq!(cancel_json["orphaned_lost"][0], "task-orphan:default");
        let rows = driver
            .session
            .db
            .list_task_delegation_children(driver.session.id)
            .unwrap();
        assert_eq!(
            rows[0].status,
            crate::db::task_delegations::DelegationStatus::Lost
        );
    }

    #[test]
    fn task_control_live_registry_entry_keeps_happy_path() {
        let (mut driver, _tmp) = test_driver(8);
        seed_task_delegation(&driver, "task-live", "default");
        driver.noninteractive_delegations.register_running(
            "task-live",
            "default",
            "explore".to_string(),
            NoninteractiveDelegationSnapshot::from_history(vec![Message::user("live context")]),
        );

        let list = driver.dispatch_task_control(TaskControlAction::List, None, None, None);
        let list_json: serde_json::Value = serde_json::from_str(&list).unwrap();
        assert_eq!(list_json["state"], "list");
        assert_eq!(list_json["children"][0]["status"], "running");
        assert_eq!(list_json["children"][0]["blocking"], true);
        assert_eq!(list_json["children"][0]["tool_call_closed"], false);
        assert_eq!(list_json["children"][0]["result_pending"], false);
        assert_eq!(list_json["children"][0]["report_available"], false);
        assert_eq!(list_json["children"][0]["report_delivered"], false);
        assert_eq!(list_json["children"][0]["pending_steers"], 0);
        assert_eq!(list_json["children"][0]["orphaned"], false);
        assert_eq!(list_json["children"][0]["actionable"], true);

        let query = driver.dispatch_task_control(
            TaskControlAction::Query,
            Some("task-live".to_string()),
            Some("default".to_string()),
            None,
        );
        let query_json: serde_json::Value = serde_json::from_str(&query).unwrap();
        assert_eq!(query_json["state"], "query");
        assert_eq!(query_json["task_call_id"], "task-live");
        assert_eq!(query_json["read_only"], true);
        assert_eq!(query_json["child_state_unchanged"], true);
        assert_eq!(query_json["report_source"], "live_snapshot");
        assert!(
            query_json["report"]
                .as_str()
                .unwrap()
                .contains("live context"),
            "{query_json}"
        );
        assert_eq!(query_json["children"][0]["status"], "running");

        let steer = driver.dispatch_task_control(
            TaskControlAction::Steer,
            Some("task-live".to_string()),
            Some("default".to_string()),
            Some("keep going".to_string()),
        );
        let steer_json: serde_json::Value = serde_json::from_str(&steer).unwrap();
        assert_eq!(steer_json["state"], "steer_queued");
        assert_eq!(steer_json["applies_at"], "next_child_turn_boundary");
        assert_eq!(steer_json["applies_if"], "child_still_running_actionable");
        assert_eq!(steer_json["children"][0]["pending_steers"], 1);

        let cancel = driver.dispatch_task_control(
            TaskControlAction::Cancel,
            Some("task-live".to_string()),
            Some("default".to_string()),
            None,
        );
        let cancel_json: serde_json::Value = serde_json::from_str(&cancel).unwrap();
        assert_eq!(cancel_json["state"], "cancelled");
        assert_eq!(cancel_json["cancelled"][0], "task-live:default");
        let rows = driver
            .session
            .db
            .list_task_delegation_children(driver.session.id)
            .unwrap();
        assert_eq!(
            rows[0].status,
            crate::db::task_delegations::DelegationStatus::Cancelled
        );
    }

    #[test]
    fn task_query_reports_db_and_none_sources() {
        let (mut driver, _tmp) = test_driver(8);
        seed_task_delegation(&driver, "task-db", "default");
        driver
            .session
            .db
            .write_blocking(move |conn| {
                conn.execute(
                    "UPDATE task_delegation_children SET report = 'db report' WHERE task_call_id = 'task-db' AND label = 'default'",
                    [],
                )?;
                Ok::<_, anyhow::Error>(())
            })
            .unwrap();
        driver.noninteractive_delegations.register_running(
            "task-db",
            "default",
            "explore".to_string(),
            NoninteractiveDelegationSnapshot::from_history(vec![Message::user("live fallback")]),
        );

        let db_query = driver.dispatch_task_control(
            TaskControlAction::Query,
            Some("task-db".to_string()),
            Some("default".to_string()),
            None,
        );
        let db_json: serde_json::Value = serde_json::from_str(&db_query).unwrap();
        assert_eq!(db_json["state"], "query");
        assert_eq!(db_json["report_source"], "db");
        assert_eq!(db_json["report"], "db report");
        assert_eq!(db_json["report_available"], true);

        seed_task_delegation(&driver, "task-none", "default");
        driver.noninteractive_delegations.register_running(
            "task-none",
            "default",
            "explore".to_string(),
            NoninteractiveDelegationSnapshot::empty(),
        );
        let none_query = driver.dispatch_task_control(
            TaskControlAction::Query,
            Some("task-none".to_string()),
            Some("default".to_string()),
            None,
        );
        let none_json: serde_json::Value = serde_json::from_str(&none_query).unwrap();
        assert_eq!(none_json["state"], "query");
        assert_eq!(none_json["report_source"], "none");
        assert_eq!(none_json["report_available"], false);
        assert!(
            none_json["report"]
                .as_str()
                .unwrap()
                .contains("No report yet")
        );
    }

    #[test]
    fn late_noninteractive_completion_delivers_once() {
        let mut registry = NoninteractiveDelegationRegistry::default();
        registry.register_running(
            "task-1",
            "default",
            "explore".to_string(),
            NoninteractiveDelegationSnapshot::empty(),
        );
        assert!(registry.background_on_user_input("task-1", "default"));

        let result =
            Message::tool_result_with_call_id("task-1".to_string(), None, "done".to_string());
        assert!(registry.complete("task-1", "default", "done".to_string(), false, Some(result)));
        assert!(
            !registry.complete(
                "task-1",
                "default",
                "duplicate".to_string(),
                false,
                Some(Message::tool_result_with_call_id(
                    "task-1".to_string(),
                    None,
                    "duplicate".to_string(),
                ))
            ),
            "completion is accepted exactly once"
        );

        let delivered = registry
            .take_late_result("task-1", "default")
            .expect("first late result");
        assert_eq!(tool_result_text(&delivered), "done");
        assert!(
            registry.take_late_result("task-1", "default").is_none(),
            "late result is delivered exactly once"
        );
    }

    #[test]
    fn background_ack_is_small_deterministic_and_omits_original_prompt() {
        let completed = vec![("first".to_string(), "first report".to_string())];
        let running = vec!["second".to_string()];
        let body = format_delegation_background_ack("task-batch", &completed, &running);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(json["type"], "task_delegation");
        assert_eq!(json["version"], 1);
        assert_eq!(json["state"], "backgrounded");
        assert_eq!(json["task_call_id"], "task-batch");
        assert_eq!(json["blocking"], false);
        assert_eq!(json["tool_call_closed"], true);
        assert_eq!(json["result_pending"], true);
        let children = json["children"].as_array().unwrap();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0]["task_call_id"], "task-batch");
        assert_eq!(children[0]["label"], "first");
        assert_eq!(children[0]["status"], "completed");
        assert_eq!(children[0]["newly_delivered"], true);
        assert_eq!(children[0]["report"], "first report");
        assert_eq!(children[1]["task_call_id"], "task-batch");
        assert_eq!(children[1]["label"], "second");
        assert_eq!(children[1]["status"], "backgrounded");
        assert_eq!(children[1]["result_pending"], true);
        assert!(!body.contains("original child prompt"));
    }

    #[test]
    fn async_delegation_result_lists_only_new_children_with_status() {
        let completed = vec![
            AsyncDelegationChildResult {
                label: "second".to_string(),
                status: "completed".to_string(),
                report: Some("second report".to_string()),
            },
            AsyncDelegationChildResult {
                label: "third".to_string(),
                status: "failed".to_string(),
                report: Some("third failed".to_string()),
            },
        ];
        let running = Vec::new();
        let body = format_async_delegation_result("task-batch", &completed, &running);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();

        assert_eq!(json["type"], "task_delegation");
        assert_eq!(json["version"], 1);
        assert_eq!(json["state"], "failed");
        assert_eq!(json["task_call_id"], "task-batch");
        assert_eq!(json["result_pending"], false);
        let children = json["children"].as_array().unwrap();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0]["task_call_id"], "task-batch");
        assert_eq!(children[0]["label"], "second");
        assert_eq!(children[0]["status"], "completed");
        assert_eq!(children[0]["newly_delivered"], true);
        assert_eq!(children[0]["report"], "second report");
        assert_eq!(children[1]["task_call_id"], "task-batch");
        assert_eq!(children[1]["label"], "third");
        assert_eq!(children[1]["status"], "failed");
        assert_eq!(children[1]["error"], "third failed");
        assert!(!body.contains("first report"));
    }

    fn seed_task_delegation(driver: &Driver, task_call_id: &str, label: &str) {
        driver
            .session
            .db
            .upsert_task_delegation_job(
                driver.session.id,
                task_call_id,
                Some("fc-test"),
                "Build",
                None,
                &[crate::db::task_delegations::DelegationChildInit {
                    label,
                    child_agent: "explore",
                    model: None,
                    output_dir: None,
                    requested_cwd: None,
                    resolved_cwd: None,
                    todo_ids_json: None,
                }],
            )
            .unwrap();
    }

    fn seed_batch_task_delegation(driver: &Driver, task_call_id: &str, labels: &[&str]) {
        let children = labels
            .iter()
            .map(|label| crate::db::task_delegations::DelegationChildInit {
                label,
                child_agent: "explore",
                model: None,
                output_dir: None,
                requested_cwd: None,
                resolved_cwd: None,
                todo_ids_json: None,
            })
            .collect::<Vec<_>>();
        driver
            .session
            .db
            .upsert_task_delegation_job(
                driver.session.id,
                task_call_id,
                Some("fc-test"),
                "Build",
                None,
                &children,
            )
            .unwrap();
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

    /// Seeds re-execute in the caller's cwd and land as native tool-call/
    /// result pairs folded into the task turn; oversized seeds are dropped
    /// under the budget and truncation is reported.
    #[tokio::test]
    async fn inject_seeds_caps_under_budget_and_injects_pairs() {
        let (mut driver, tmp) = driver_with_read_caller();
        // A small file (fits) followed by several sizeable ones. Each
        // sizeable file is ~1.5K tokens of distinct lines; the shared 2K-token
        // seed budget admits the small one, then trips before all the big ones
        // fit — so at least one whole seed is dropped, deterministically.
        let small = tmp.path().join("small.txt");
        std::fs::write(&small, "hello\n").unwrap();
        let mut big_paths = Vec::new();
        for i in 0..3 {
            let p = tmp.path().join(format!("big{i}.txt"));
            // ~600 short, distinct lines → comfortably above ~1K tokens each.
            let body: String = (0..600).map(|n| format!("file{i} line {n}\n")).collect();
            std::fs::write(&p, body).unwrap();
            big_paths.push(p);
        }

        // The caller's last turn is the `task` call the delegation came from.
        let task_call_id = "task-1";
        driver.stack[0].history = vec![
            Message::user("please investigate"),
            assistant_with_task_call(task_call_id),
        ];

        let mut seeds = vec![SeedTool {
            tool: "read".into(),
            args: serde_json::json!({ "path": small.to_string_lossy() }),
        }];
        for p in &big_paths {
            seeds.push(SeedTool {
                tool: "read".into(),
                args: serde_json::json!({ "path": p.to_string_lossy() }),
            });
        }

        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let truncated = driver.inject_seeds(&seeds, task_call_id, &tx).await;
        drop(tx);
        while rx.recv().await.is_some() {}

        // The cumulative seed output blew the 2K budget → truncation reported,
        // at least one whole seed dropped.
        assert!(truncated, "oversized seeds should trip the budget");

        let history = &driver.stack[0].history;
        // The task turn now carries the original task call PLUS exactly one
        // seed tool call (the small read); the big one was dropped whole.
        let last_assistant = history
            .iter()
            .rev()
            .find_map(|m| match m {
                Message::Assistant { content, .. } => Some(content),
                _ => None,
            })
            .unwrap();
        use crate::engine::message::AssistantContent;
        let tool_calls: Vec<_> = last_assistant
            .iter()
            .filter_map(|c| match c {
                AssistantContent::ToolCall(tc) => Some(tc.function.name.clone()),
                _ => None,
            })
            .collect();
        assert!(
            tool_calls.iter().any(|n| n == "task"),
            "task call preserved"
        );
        let seed_calls = tool_calls.iter().filter(|n| *n == "read").count();
        // At least the small seed fit, and at least one big seed was dropped
        // (so fewer than the 4 requested were folded in).
        assert!(seed_calls >= 1, "in-budget seeds folded in");
        assert!(seed_calls < seeds.len(), "an over-budget seed was dropped");
        let seed_call_ids: Vec<_> = last_assistant
            .iter()
            .filter_map(|c| match c {
                AssistantContent::ToolCall(tc) if tc.function.name == "read" => {
                    Some((tc.id.clone(), tc.call_id.clone()))
                }
                _ => None,
            })
            .collect();
        for (id, call_id) in &seed_call_ids {
            assert!(id.starts_with("seed-"), "seed call id is tagged");
            assert_eq!(
                call_id.as_deref(),
                Some(id.as_str()),
                "seed ToolCall.call_id uses the Cockpit synthetic provider id"
            );
        }

        // Each folded seed call has exactly one matching tool_result pair.
        use rig::message::UserContent;
        let seed_results: Vec<_> = history
            .iter()
            .filter_map(|m| match m {
                Message::User { content } => Some(content),
                _ => None,
            })
            .flat_map(|content| content.iter())
            .filter_map(|c| match c {
                UserContent::ToolResult(result) if result.id.starts_with("seed-") => {
                    Some((result.id.clone(), result.call_id.clone()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            seed_results.len(),
            seed_calls,
            "one result pair per folded seed"
        );
        for (id, call_id) in &seed_results {
            assert_eq!(
                call_id.as_deref(),
                Some(id.as_str()),
                "seed ToolResult.call_id matches the synthetic provider id"
            );
        }

        // Each folded seed is also persisted as a tool-call audit row (GOALS
        // §14) so it survives in a session export, not just the live stream.
        // A seed is emitted verbatim → `wire == original`, no recovery.
        let rows = driver
            .session
            .db
            .list_tool_calls_for_session(driver.session.id)
            .unwrap();
        let seed_rows: Vec<_> = rows.iter().filter(|r| r.tool == "read").collect();
        assert_eq!(
            seed_rows.len(),
            seed_calls,
            "each folded seed has a persisted tool-call row"
        );
        for r in seed_rows {
            assert!(r.call_id.starts_with("seed-"), "seed row tagged as a seed");
            assert_eq!(r.provider_item_id.as_deref(), Some(r.call_id.as_str()));
            assert_eq!(r.provider_call_id.as_deref(), Some(r.call_id.as_str()));
            assert_eq!(
                r.provider_call_id_source.as_deref(),
                Some("synthetic_from_cockpit_call_id")
            );
            assert_eq!(r.wire_api.as_deref(), Some("responses"));
            assert_eq!(r.provider_family.as_deref(), Some("cockpit"));
            assert_eq!(
                r.wire_input_json, r.original_input_json,
                "a seed is verbatim: wire == original (GOALS §14)"
            );
            assert_eq!(r.recovery, crate::engine::repair::Recovery::Clean);
        }
    }

    /// A seed naming a tool the caller doesn't hold (or a non-read-only tool)
    /// is skipped — `inject_seeds` never dispatches a write/unknown path.
    #[tokio::test]
    async fn inject_seeds_skips_tools_the_caller_lacks() {
        let (mut driver, _t) = driver_with_read_caller();
        let task_call_id = "task-1";
        driver.stack[0].history = vec![assistant_with_task_call(task_call_id)];
        // `outline` is read-only but the caller (read-only `read` toolbox)
        // doesn't hold it → skipped; nothing is folded in.
        let seeds = vec![SeedTool {
            tool: "outline".into(),
            args: serde_json::json!({ "path": "/x.rs" }),
        }];
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let _ = driver.inject_seeds(&seeds, task_call_id, &tx).await;
        drop(tx);
        while rx.recv().await.is_some() {}
        // History unchanged: only the original task turn remains.
        assert_eq!(driver.stack[0].history.len(), 1);
    }

    // ---- Caller→child read-only pre-seeding (`task.seed`) -----------------
    // (implementation note). The parent→child mirror of
    // `inject_seeds`: re-execute read-only seeds in the CHILD's cwd and
    // prepend native tool-call/result pairs to the child's initial history.

    /// A child agent holding `read` + `outline` (read-only) and `writeunlock`
    /// (write) — enough to assert read-only seeds execute, a write seed is
    /// never executed, and a failed read is surfaced (not aborted).
    fn child_with_read_write_tools(agent: &Arc<Agent>) -> Agent {
        let tools = crate::engine::tool::ToolBox::new()
            .with(std::sync::Arc::new(crate::tools::read::ReadTool))
            .with(std::sync::Arc::new(crate::tools::intel::OutlineTool))
            .with(std::sync::Arc::new(
                crate::tools::writeunlock::WriteunlockTool,
            ));
        Agent {
            name: "explore".into(),
            system: agent.system.clone(),
            role_prompt: agent.role_prompt.clone(),
            tools,
            model: agent.model.clone(),
            params: agent.params.clone(),
            scan_tool_results: false,
            llm_mode: crate::config::extended::LlmMode::Normal,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            env_overlay: agent.env_overlay.clone(),
        }
    }

    /// Read-only pre-seeds re-execute in the CHILD's cwd and become a native
    /// assistant-tool-call + matching tool_result prefix for the child's
    /// initial history — supporting any read-only tool, not just `read`.
    #[tokio::test]
    async fn prefill_child_seeds_injects_native_pairs_in_child_cwd() {
        let (driver, tmp) = test_driver(8);
        let child = child_with_read_write_tools(&driver.stack[0].agent.clone());

        let child_dir = tmp.path().join("child-cwd");
        std::fs::create_dir(&child_dir).unwrap();
        let f = child_dir.join("hello.txt");
        std::fs::write(&f, "hello from the child cwd\n").unwrap();

        let seeds = vec![SeedTool {
            tool: "read".into(),
            args: serde_json::json!({ "path": "hello.txt" }),
        }];
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let (prefix, truncated) = driver
            .prefill_child_seeds(&seeds, &child, &child_dir, Some(&tx))
            .await;
        drop(tx);
        while rx.recv().await.is_some() {}

        assert!(!truncated, "one small seed fits the budget");
        // One assistant turn carrying the read call, then one tool_result.
        assert_eq!(prefix.len(), 2, "assistant call turn + tool_result");
        use crate::engine::message::AssistantContent;
        let calls: Vec<_> = match &prefix[0] {
            Message::Assistant { content, .. } => content
                .iter()
                .filter_map(|c| match c {
                    AssistantContent::ToolCall(tc) => {
                        Some((tc.function.name.clone(), tc.id.clone(), tc.call_id.clone()))
                    }
                    _ => None,
                })
                .collect(),
            _ => panic!("first prefix message is an assistant turn"),
        };
        assert_eq!(calls.len(), 1, "the read seed became one native call");
        assert_eq!(calls[0].0, "read");
        assert_eq!(
            calls[0].2.as_deref(),
            Some(calls[0].1.as_str()),
            "prefill seed ToolCall.call_id uses the synthetic provider id"
        );
        use rig::message::{ToolResultContent, UserContent};
        match &prefix[1] {
            Message::User { content } => {
                let result = content
                    .iter()
                    .find_map(|c| match c {
                        UserContent::ToolResult(tr) => Some(tr),
                        _ => None,
                    })
                    .expect("prefill seed tool_result");
                assert_eq!(result.id, calls[0].1);
                assert_eq!(
                    result.call_id.as_deref(),
                    Some(calls[0].1.as_str()),
                    "prefill seed ToolResult.call_id matches the synthetic provider id"
                );
                let got = result.content.iter().any(|rc| {
                    matches!(
                        rc,
                        ToolResultContent::Text(t) if t.text.contains("hello from the child cwd")
                    )
                });
                assert!(
                    got,
                    "the result carries the file body read in the child cwd"
                );
            }
            _ => panic!("second prefix message is the tool_result"),
        }
        let rows = driver
            .session
            .db
            .list_tool_calls_for_session(driver.session.id)
            .unwrap();
        let row = rows
            .iter()
            .find(|row| row.call_id == calls[0].1)
            .expect("prefill seed audit row");
        assert_eq!(row.provider_call_id.as_deref(), Some(row.call_id.as_str()));
        assert_eq!(
            row.provider_call_id_source.as_deref(),
            Some("synthetic_from_cockpit_call_id")
        );
    }

    /// A write/lock seed is never executed — the execution-time read-only gate
    /// (same rule as `seed.rs`) drops it, so nothing is injected.
    #[tokio::test]
    async fn prefill_child_seeds_never_executes_a_write_seed() {
        let (driver, tmp) = test_driver(8);
        let child = child_with_read_write_tools(&driver.stack[0].agent.clone());
        let target = tmp.path().join("must_not_exist.txt");
        // A write seed (even though the child holds `writeunlock`): rejected at
        // the read-only gate, never dispatched.
        let seeds = vec![SeedTool {
            tool: "writeunlock".into(),
            args: serde_json::json!({ "path": target.to_string_lossy(), "content": "x" }),
        }];
        let (prefix, _truncated) = driver
            .prefill_child_seeds(&seeds, &child, tmp.path(), None)
            .await;
        assert!(prefix.is_empty(), "a write seed injects nothing");
        assert!(!target.exists(), "a write seed is never executed");
    }

    /// A seed that fails to execute in the child's cwd (missing path) is
    /// surfaced as a failed seed — its `Error:` body is injected as the
    /// tool_result — not a hard abort of the delegation.
    #[tokio::test]
    async fn prefill_child_seeds_surfaces_a_failed_seed_without_aborting() {
        let (driver, tmp) = test_driver(8);
        let child = child_with_read_write_tools(&driver.stack[0].agent.clone());
        let good = tmp.path().join("ok.txt");
        std::fs::write(&good, "fine\n").unwrap();
        let missing = tmp.path().join("nope.txt");
        let seeds = vec![
            SeedTool {
                tool: "read".into(),
                args: serde_json::json!({ "path": missing.to_string_lossy() }),
            },
            SeedTool {
                tool: "read".into(),
                args: serde_json::json!({ "path": good.to_string_lossy() }),
            },
        ];
        let (prefix, _truncated) = driver
            .prefill_child_seeds(&seeds, &child, tmp.path(), None)
            .await;
        // Both seeds are injected: the failed one carries an `Error:` body, the
        // good one carries its content — the run is not aborted.
        use crate::engine::message::AssistantContent;
        let n_calls = match &prefix[0] {
            Message::Assistant { content, .. } => content
                .iter()
                .filter(|c| matches!(c, AssistantContent::ToolCall(_)))
                .count(),
            _ => panic!("assistant turn expected"),
        };
        assert_eq!(n_calls, 2, "both seeds injected (failed + ok)");
        let bodies: String = prefix
            .iter()
            .skip(1)
            .filter_map(|m| match m {
                Message::User { content } => Some(
                    content
                        .iter()
                        .filter_map(|c| match c {
                            rig::message::UserContent::ToolResult(tr) => Some(
                                tr.content
                                    .iter()
                                    .filter_map(|rc| match rc {
                                        rig::message::ToolResultContent::Text(t) => {
                                            Some(t.text.clone())
                                        }
                                        _ => None,
                                    })
                                    .collect::<String>(),
                            ),
                            _ => None,
                        })
                        .collect::<String>(),
                ),
                _ => None,
            })
            .collect();
        assert!(
            bodies.contains("Error:"),
            "failed seed surfaced as an error"
        );
        assert!(bodies.contains("fine"), "the good seed still executed");
    }

    /// Oversized pre-seeds are dropped whole under the budget and the
    /// truncation flag is set so the caller appends a model-visible note.
    #[tokio::test]
    async fn prefill_child_seeds_caps_under_budget_and_drops_whole_entries() {
        let (driver, tmp) = test_driver(8);
        let child = child_with_read_write_tools(&driver.stack[0].agent.clone());
        let small = tmp.path().join("small.txt");
        std::fs::write(&small, "tiny\n").unwrap();
        let mut seeds = vec![SeedTool {
            tool: "read".into(),
            args: serde_json::json!({ "path": small.to_string_lossy() }),
        }];
        for i in 0..3 {
            let p = tmp.path().join(format!("big{i}.txt"));
            let body: String = (0..600).map(|n| format!("file{i} line {n}\n")).collect();
            std::fs::write(&p, body).unwrap();
            seeds.push(SeedTool {
                tool: "read".into(),
                args: serde_json::json!({ "path": p.to_string_lossy() }),
            });
        }
        let (prefix, truncated) = driver
            .prefill_child_seeds(&seeds, &child, tmp.path(), None)
            .await;
        assert!(truncated, "the cumulative seed output trips the budget");
        use crate::engine::message::AssistantContent;
        let n_calls = match &prefix[0] {
            Message::Assistant { content, .. } => content
                .iter()
                .filter(|c| matches!(c, AssistantContent::ToolCall(_)))
                .count(),
            _ => panic!("assistant turn expected"),
        };
        assert!(n_calls >= 1, "in-budget seeds injected");
        assert!(n_calls < seeds.len(), "at least one whole seed dropped");
    }

    /// Absent/empty pre-seeds behave exactly as today: nothing injected, no
    /// truncation.
    #[tokio::test]
    async fn prefill_child_seeds_empty_is_a_noop() {
        let (driver, tmp) = test_driver(8);
        let child = child_with_read_write_tools(&driver.stack[0].agent.clone());
        let (prefix, truncated) = driver
            .prefill_child_seeds(&[], &child, tmp.path(), None)
            .await;
        assert!(prefix.is_empty());
        assert!(!truncated);
    }

    /// Build a driver whose root agent holds the `skill` tool, so
    /// `seed_forced_skill` can synthesize a real `skill` tool call.
    fn driver_with_skill_caller() -> (Driver, tempfile::TempDir) {
        let (mut driver, tmp) = test_driver(8);
        let old = driver.stack[0].agent.clone();
        let tools = crate::engine::tool::ToolBox::new()
            .with(std::sync::Arc::new(crate::tools::skill::SkillTool));
        driver.stack[0].agent = std::sync::Arc::new(Agent {
            name: old.name.clone(),
            system: old.system.clone(),
            role_prompt: old.role_prompt.clone(),
            tools,
            model: old.model.clone(),
            params: old.params.clone(),
            scan_tool_results: old.scan_tool_results,
            llm_mode: crate::config::extended::LlmMode::Normal,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            env_overlay: old.env_overlay.clone(),
        });
        (driver, tmp)
    }

    /// A user-issued `/<skill>` seeds a real, recorded `skill` tool call —
    /// folded into history as an assistant `skill` ToolCall + its tool_result
    /// (not a model-initiated call) — with the wire-vs-user split preserved
    /// (`wire == original`, `Recovery::Clean`). An unknown skill records the
    /// invocation with the tool's error as the result (never a silent no-op).
    #[tokio::test]
    async fn seed_forced_skill_records_and_folds_a_real_skill_call() {
        use crate::engine::message::AssistantContent;
        use rig::message::UserContent;

        let (mut driver, _tmp) = driver_with_skill_caller();
        // A name almost certainly not on disk → the `skill` tool returns an
        // invalid-input error; the seam still records + folds the call. (Host
        // config can vary, so we assert the seam contract, not a body load —
        // body loading itself is covered by `tools::skill` tests.)
        let skill_name = "definitely-not-a-real-skill-xyz";

        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        driver.seed_forced_skill(skill_name, &tx).await;
        drop(tx);
        // A ToolStart + ToolEnd pair was streamed for the synthesized call.
        let mut tool_starts = 0;
        let mut tool_ends = 0;
        while let Some(ev) = rx.recv().await {
            match ev {
                TurnEvent::ToolStart { tool, .. } if tool == "skill" => tool_starts += 1,
                TurnEvent::ToolEnd { tool, .. } if tool == "skill" => tool_ends += 1,
                _ => {}
            }
        }
        assert_eq!(tool_starts, 1, "exactly one synthesized skill ToolStart");
        assert_eq!(tool_ends, 1, "exactly one synthesized skill ToolEnd");

        // History gained an assistant `skill` ToolCall (harness-synthesized,
        // not model-initiated) followed by its tool_result.
        let history = &driver.stack[0].history;
        let assistant_skill_call = history
            .iter()
            .find_map(|m| match m {
                Message::Assistant { content, .. } => content.iter().find_map(|c| match c {
                    AssistantContent::ToolCall(tc) if tc.function.name == "skill" => {
                        Some(tc.clone())
                    }
                    _ => None,
                }),
                _ => None,
            })
            .expect("a `skill` tool call was folded in");
        let tool_result = history
            .iter()
            .find_map(|m| match m {
                Message::User { content } => content.iter().find_map(|c| match c {
                    UserContent::ToolResult(result) => Some(result.clone()),
                    _ => None,
                }),
                _ => None,
            })
            .expect("the skill call's tool_result was folded in");
        assert_eq!(
            assistant_skill_call.call_id.as_deref(),
            Some(assistant_skill_call.id.as_str()),
            "synthetic Responses calls use the cockpit call id as provider call id"
        );
        assert_eq!(tool_result.id, assistant_skill_call.id);
        assert_eq!(
            tool_result.call_id.as_deref(),
            Some(assistant_skill_call.id.as_str()),
            "tool_result must carry the same synthetic provider call id"
        );

        // The call is persisted as a real tool-call audit row with the
        // wire-vs-user split intact (verbatim synth → wire == original, clean).
        let rows = driver
            .session
            .db
            .list_tool_calls_for_session(driver.session.id)
            .unwrap();
        let skill_rows: Vec<_> = rows.iter().filter(|r| r.tool == "skill").collect();
        assert_eq!(skill_rows.len(), 1, "one persisted skill tool-call row");
        let row = skill_rows[0];
        assert!(
            row.call_id.starts_with("skillslash-"),
            "row tagged as a skill-slash invocation"
        );
        assert_eq!(row.provider_item_id.as_deref(), Some(row.call_id.as_str()));
        assert_eq!(row.provider_call_id.as_deref(), Some(row.call_id.as_str()));
        assert_eq!(
            row.provider_call_id_source.as_deref(),
            Some("synthetic_from_cockpit_call_id")
        );
        assert_eq!(row.wire_api.as_deref(), Some("responses"));
        assert_eq!(row.provider_family.as_deref(), Some("cockpit"));
        assert_eq!(
            row.wire_input_json, row.original_input_json,
            "synthesized call is verbatim: wire == original (GOALS §14)"
        );
        assert_eq!(row.recovery, crate::engine::repair::Recovery::Clean);
        assert_eq!(
            row.original_input_json,
            serde_json::json!({ "name": skill_name }),
            "the recorded input is the synthesized `skill` args"
        );
    }

    // ---- auto-injected skill transcript visibility
    // (implementation note) ----

    /// The wire half of the split: every auto-injected body is folded ahead of
    /// the user's message in relevance order, so the model still receives them
    /// (the `SkillAutoInjected` transcript rows are the user-facing half).
    #[test]
    fn fold_injected_skills_folds_every_body_ahead_of_the_user_message() {
        use crate::skills::auto_select::InjectedSkill;

        let skills = vec![
            InjectedSkill {
                name: "firecrawl".to_string(),
                body: "FIRECRAWL BODY".to_string(),
                reason: Some("REASON SHOULD STAY OFF WIRE".to_string()),
            },
            InjectedSkill {
                name: "deploy".to_string(),
                body: "DEPLOY BODY".to_string(),
                reason: None,
            },
        ];
        let wire = Driver::fold_injected_skills(&skills, "scrape example.com please");

        // The model still receives each body (the wire is unchanged).
        assert!(
            wire.contains("FIRECRAWL BODY"),
            "firecrawl body on the wire"
        );
        assert!(wire.contains("DEPLOY BODY"), "deploy body on the wire");
        // The reason is display-only / off-wire (GOALS §14): it must never
        // leak into the folded body the model receives.
        assert!(
            !wire.contains("REASON SHOULD STAY OFF WIRE"),
            "the auto-injection reason must stay off the wire"
        );
        // In relevance/injection order, ahead of the user's message.
        let fc = wire.find("FIRECRAWL BODY").unwrap();
        let dp = wire.find("DEPLOY BODY").unwrap();
        let um = wire.find("scrape example.com please").unwrap();
        assert!(fc < dp, "first-ranked body precedes the second");
        assert!(dp < um, "bodies precede the user's message");
        assert!(
            wire.contains("Skill `firecrawl` (auto-selected):"),
            "each body keeps its auto-selected header"
        );
    }

    /// No injection (the empty-selection / `Selection::None` shape) leaves the
    /// user's wire text untouched — and emits no rows.
    #[test]
    fn fold_injected_skills_empty_returns_user_text_unchanged() {
        let wire = Driver::fold_injected_skills(&[], "just a question");
        assert_eq!(wire, "just a question");
    }

    // ---- request preflight (implementation note) ----

    #[test]
    fn preflight_enabled_honors_session_override_over_config() {
        let (mut driver, _tmp) = test_driver(1);
        // No override → falls back to config (default off).
        assert!(!driver.preflight_enabled());
        // Session override wins, both directions.
        driver.preflight_override = Some(true);
        assert!(driver.preflight_enabled());
        driver.preflight_override = Some(false);
        assert!(!driver.preflight_enabled());
    }

    #[tokio::test]
    async fn set_preflight_toggle_flips_and_broadcasts() {
        let (mut driver, _tmp) = test_driver(1);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
        // Bare toggle from the default-off effective state → on.
        driver
            .run_control(DriverControl::SetPreflight { enabled: None }, &tx)
            .await;
        assert_eq!(driver.preflight_override, Some(true));
        match rx.try_recv() {
            Ok(TurnEvent::PreflightState { enabled }) => assert!(enabled),
            other => panic!("expected PreflightState(on), got {other:?}"),
        }
        // Explicit off.
        driver
            .run_control(
                DriverControl::SetPreflight {
                    enabled: Some(false),
                },
                &tx,
            )
            .await;
        assert_eq!(driver.preflight_override, Some(false));
        match rx.try_recv() {
            Ok(TurnEvent::PreflightState { enabled }) => assert!(!enabled),
            other => panic!("expected PreflightState(off), got {other:?}"),
        }
    }

    #[test]
    fn preflight_will_run_gates_the_in_progress_signal() {
        // Drives the submit-time `PreflightStarted` event
        // (implementation note): the animated
        // indicator is added ONLY when preflight is enabled AND will actually
        // run (not a `should_skip` no-op).
        let (mut driver, _tmp) = test_driver(1);

        // Disabled → never runs, regardless of the text.
        driver.preflight_override = Some(false);
        assert!(!driver.preflight_will_run("please refactor the parser module"));
        assert!(!driver.preflight_will_run("ok"));

        // Enabled → runs on a rewritable message, skips the `should_skip` set
        // (trivial / bare ack / leading `/`).
        driver.preflight_override = Some(true);
        assert!(driver.preflight_will_run("please refactor the parser module"));
        assert!(!driver.preflight_will_run("ok"), "bare ack skips");
        assert!(!driver.preflight_will_run("/plan"), "leading slash skips");
        assert!(!driver.preflight_will_run("hi"), "trivial-length skips");
    }

    #[tokio::test]
    async fn resolve_preflight_outcome_rewritten_sets_display_and_skill() {
        use crate::engine::preflight::PreflightOutcome;
        let (mut driver, _tmp) = test_driver(1);
        let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
        let outcome = PreflightOutcome::Rewritten {
            cleaned: "clean body".into(),
            skill: Some("verify".into()),
        };
        let (text, display, skill) = driver
            .resolve_preflight_outcome(outcome, "raw original", None, &tx)
            .await;
        assert_eq!(text, "clean body", "model gets the cleaned body");
        assert_eq!(
            display.as_deref(),
            Some("clean body"),
            "the cleaned body drives the chip display"
        );
        assert_eq!(skill.as_deref(), Some("verify"), "mid-text skill is loaded");
    }

    #[tokio::test]
    async fn resolve_preflight_outcome_think_stripped_cleaned_flows_to_both() {
        // The strip-`<think>` `cleaned` (what the preflight path produces with
        // the toggle ON) is what `resolve_preflight_outcome` yields for BOTH
        // wire and display — one `<think>`-free string in both places.
        use crate::engine::preflight::PreflightOutcome;
        let (mut driver, _tmp) = test_driver(1);
        let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
        let outcome = PreflightOutcome::Rewritten {
            cleaned: "Refactor the parser.".into(),
            skill: None,
        };
        let (text, display, _skill) = driver
            .resolve_preflight_outcome(outcome, "raw original", None, &tx)
            .await;
        assert_eq!(text, "Refactor the parser.");
        assert_eq!(display.as_deref(), Some("Refactor the parser."));
        assert_eq!(
            Some(text.as_str()),
            display.as_deref(),
            "wire and display are the same <think>-free string"
        );
    }

    #[tokio::test]
    async fn resolve_preflight_outcome_leading_skill_wins_over_mid_text() {
        use crate::engine::preflight::PreflightOutcome;
        let (mut driver, _tmp) = test_driver(1);
        let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
        let outcome = PreflightOutcome::Rewritten {
            cleaned: "body".into(),
            skill: Some("mid".into()),
        };
        let (_text, _display, skill) = driver
            .resolve_preflight_outcome(outcome, "raw", Some("leading".into()), &tx)
            .await;
        assert_eq!(
            skill.as_deref(),
            Some("leading"),
            "an existing leading forced_skill takes precedence"
        );
    }

    #[tokio::test]
    async fn resolve_preflight_outcome_guard_trip_falls_back_with_notice() {
        use crate::engine::preflight::PreflightOutcome;
        let (mut driver, _tmp) = test_driver(1);
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(8);
        let outcome = PreflightOutcome::GuardTripped {
            original: "run /build now please".into(),
        };
        let (text, display, _skill) = driver
            .resolve_preflight_outcome(outcome, "run /build now please", None, &tx)
            .await;
        assert_eq!(
            text, "run /build now please",
            "the original is sent verbatim"
        );
        assert!(display.is_none(), "no chip on a guard-tripped fallback");
        // A one-time notice is surfaced.
        match rx.try_recv() {
            Ok(TurnEvent::Notice { text }) => assert!(text.contains("preflight")),
            other => panic!("expected a preflight-skipped Notice, got {other:?}"),
        }
        // Logged at most once per driver.
        assert!(driver.preflight_guard_logged);
        let outcome2 = PreflightOutcome::GuardTripped {
            original: "another /plan now".into(),
        };
        let _ = driver
            .resolve_preflight_outcome(outcome2, "another /plan now", None, &tx)
            .await;
        assert!(
            matches!(rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "the skipped notice fires at most once"
        );
    }

    #[tokio::test]
    async fn resolve_preflight_outcome_skipped_is_byte_for_byte_original() {
        use crate::engine::preflight::PreflightOutcome;
        let (mut driver, _tmp) = test_driver(1);
        let (tx, _rx) = mpsc::channel::<TurnEvent>(8);
        let (text, display, skill) = driver
            .resolve_preflight_outcome(
                PreflightOutcome::Skipped,
                "untouched original text",
                Some("s".into()),
                &tx,
            )
            .await;
        assert_eq!(text, "untouched original text");
        assert!(display.is_none(), "no chip when preflight didn't run");
        assert_eq!(skill.as_deref(), Some("s"), "forced_skill passes through");
    }

    // ---- parent→child skill seeding ----

    /// `record_active_skill` de-dups by name, latest body wins — a re-invoked
    /// or re-injected skill refreshes its seedable body rather than duplicating.
    #[test]
    fn record_active_skill_dedups_latest_wins() {
        let (mut driver, _tmp) = test_driver(1);
        driver.record_active_skill("release-notes", "first body");
        driver.record_active_skill("other", "x");
        driver.record_active_skill("release-notes", "refreshed body");
        // One entry per name; the latest body is what survives.
        let dp: Vec<_> = driver
            .active_skills
            .iter()
            .filter(|(n, _)| n == "release-notes")
            .collect();
        assert_eq!(dp.len(), 1, "name de-duped");
        assert_eq!(dp[0].1, "refreshed body", "latest body wins");
        // A blank name records nothing.
        driver.record_active_skill("  ", "ignored");
        assert!(
            driver
                .active_skills
                .iter()
                .all(|(n, _)| !n.trim().is_empty())
        );
    }

    /// A parent resolving an active skill seeds it into
    /// the child. An ACTIVE skill contributes its instructions PLUS the
    /// delegation framing (we are resolving skill X; it takes precedence over
    /// the child's baked-in default), so the child drafts instead of
    /// implementing.
    #[test]
    fn seed_skills_block_seeds_active_skill_with_framing() {
        let (mut driver, _tmp) = test_driver(1);
        // The release-notes skill is active in the parent's context (e.g.
        // user-invoked `/release-notes`).
        driver.record_active_skill(
            "release-notes",
            "Turn the rough change summary into release notes. Do NOT implement it.",
        );
        let block = driver.seed_skills_block(&["release-notes".to_string()], "builder");
        // Carries the skill's instructions...
        assert!(
            block.contains("release notes"),
            "block carries the skill body: {block:?}"
        );
        // ...plus the framing that this delegation is resolving the skill and
        // takes precedence over the child's default behavior.
        assert!(
            block.contains("skill `release-notes`")
                && block.contains("part of")
                && block.contains("precedence"),
            "block carries the resolving-skill framing: {block:?}"
        );
        assert!(
            block.contains("builder"),
            "framing names the delegated child: {block:?}"
        );
        // No spurious strip note when everything requested was active.
        assert!(
            !block.contains("dropped because"),
            "no strip note for an active skill: {block:?}"
        );
    }

    /// Host-side validation (validate, don't trust the model): a parent that
    /// names a skill NOT active in its context has that seed deterministically
    /// stripped, surfaced as a model-visible note — never a body conjured from
    /// thin air, never a hard error.
    #[test]
    fn seed_skills_block_strips_non_active_skill_with_note() {
        let (mut driver, _tmp) = test_driver(1);
        // Only `release-notes` is active; `made-up` is not.
        driver.record_active_skill("release-notes", "release body");
        let block = driver.seed_skills_block(
            &["release-notes".to_string(), "made-up".to_string()],
            "builder",
        );
        // The active one is still seeded...
        assert!(
            block.contains("release body"),
            "active skill still seeded: {block:?}"
        );
        // ...and the non-active one is stripped with a model-visible note that
        // names it and explains why.
        assert!(
            block.contains("`made-up`") && block.contains("dropped because"),
            "non-active skill stripped with a visible note: {block:?}"
        );
        // The non-active skill's instructions never appear (nothing conjured).
        assert!(
            !block.contains("made-up body"),
            "a non-active skill cannot inject any body: {block:?}"
        );
    }

    /// Seeding is opt-in: a delegation that requests no skill seed (or only
    /// blank names) produces an empty block — neither a seed nor a note.
    #[test]
    fn seed_skills_block_empty_when_nothing_requested() {
        let (mut driver, _tmp) = test_driver(1);
        driver.record_active_skill("release-notes", "body");
        assert!(driver.seed_skills_block(&[], "builder").is_empty());
        assert!(
            driver
                .seed_skills_block(&["   ".to_string()], "builder")
                .is_empty(),
            "blank names contribute nothing"
        );
    }

    /// End-to-end: a user-invoked `/<skill>` whose body loads makes that skill
    /// part of the seedable set, so a later `task.skill_seed` naming it passes
    /// host validation. Writes a real skill under the cwd's seeded scan dir.
    #[tokio::test(flavor = "current_thread")]
    async fn user_invoked_skill_enters_the_seedable_set() {
        let (mut driver, tmp) = driver_with_skill_caller();
        let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
        // The seeded default scan dir `./.agents/skills` resolves against cwd
        // (= the driver's tmp root, with no config.json on disk).
        let skill_dir = tmp
            .path()
            .join(".agents")
            .join("skills")
            .join("release-notes");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            "---\nname: release-notes\ndescription: draft release notes\n---\nRELEASE NOTES, do not implement.",
        )
        .unwrap();

        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        driver.seed_forced_skill("release-notes", &tx).await;

        // The stored seedable body is the rendered skill body itself — the
        // `Skill \`name\`:\n\n` wrapper the skill tool prepends is stripped, so
        // the seed carries instructions, not the tool-output wrapper line.
        let stored = driver
            .active_skills
            .iter()
            .find(|(n, _)| n == "release-notes")
            .map(|(_, b)| b.as_str());
        assert_eq!(
            stored,
            Some("RELEASE NOTES, do not implement."),
            "user-invoked skill body enters the seedable set, wrapper stripped"
        );

        // The skill is now active in the parent's context, so seeding it into a
        // child succeeds and carries the loaded body.
        let block = driver.seed_skills_block(&["release-notes".to_string()], "builder");
        assert!(
            block.contains("RELEASE NOTES, do not implement."),
            "user-invoked skill body is seedable: {block:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_user_invoked_skill_does_not_enter_seedable_set() {
        let (mut driver, tmp) = driver_with_skill_caller();
        let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());

        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);
        driver.seed_forced_skill("missing-skill", &tx).await;

        assert!(
            driver.active_skills.is_empty(),
            "failed skill invocation must not become seedable"
        );
        let block = driver.seed_skills_block(&["missing-skill".to_string()], "builder");
        assert!(
            block.contains("dropped because they are not active"),
            "inactive failed skill should be stripped with a note: {block:?}"
        );
        assert!(
            !block.contains("Skill `missing-skill`:"),
            "failed skill should not inject a seeded skill body: {block:?}"
        );
    }

    /// An async-result delivery header names both the job `kind` and the
    /// originating `job_id` (implementation note), identically
    /// across every job kind (`loop`/`timer`/`background`/`swarm`). Drives the
    /// real `ScheduleKind::as_str` so a kind-vocabulary drift is caught.
    #[test]
    fn async_result_header_names_kind_and_job_id_for_every_kind() {
        use crate::engine::schedule::spec::ScheduleKind;
        let job_id = "sched-f36b81df";
        for kind in [
            ScheduleKind::Loop,
            ScheduleKind::Timer,
            ScheduleKind::Background,
            ScheduleKind::Swarm,
        ] {
            let header = async_result_header(kind.as_str(), job_id);
            assert_eq!(
                header,
                format!("[async result · {} · sched-f36b81df]", kind.as_str()),
            );
        }
    }

    /// The recorded delivery event carries `data.job_id` set to the
    /// originating id, additively alongside `text`
    /// (implementation note). Round-trips through the real DB
    /// serialization so the exported `events.json` shape is what's asserted.
    /// Ordinary input (no job) omits the key entirely.
    #[test]
    fn delivery_event_data_carries_job_id_round_trip() {
        let (driver, _t) = test_driver(1);
        let session = driver.session.clone();

        // Async-result delivery: `data.job_id` present.
        let delivery = user_message_event_data(
            "[async result · loop · sched-abc]\nok",
            Some("sched-abc"),
            &[],
            None,
            None,
        );
        session
            .record_event(
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("Build"),
                None,
                &delivery,
            )
            .unwrap();
        // Ordinary user input: no `job_id` key.
        let ordinary = user_message_event_data("hello", None, &[], None, None);
        assert!(
            ordinary.get("job_id").is_none(),
            "ordinary input must omit data.job_id: {ordinary}"
        );
        session
            .record_event(
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("Build"),
                None,
                &ordinary,
            )
            .unwrap();

        let events = session.db.list_session_events(session.id).unwrap();
        let delivery_row = events
            .iter()
            .find(|e| e.data.get("job_id").is_some())
            .expect("delivery event with data.job_id persisted");
        assert_eq!(
            delivery_row.data.get("job_id").and_then(|v| v.as_str()),
            Some("sched-abc"),
        );
        // The text field still rides alongside, unchanged.
        assert_eq!(
            delivery_row.data.get("text").and_then(|v| v.as_str()),
            Some("[async result · loop · sched-abc]\nok"),
        );
        // Exactly one event carries the key — the ordinary message has none.
        assert_eq!(
            events
                .iter()
                .filter(|e| e.data.get("job_id").is_some())
                .count(),
            1,
        );
    }

    /// Regression (implementation note, candidate
    /// "queued-message state"): on a ctrl+c cancel-unwind the driver must
    /// discard *every* user message that was queued during the cancelled
    /// span, so `run_main_loop` doesn't immediately pick the next one up and
    /// start a fresh turn — which would make the cancel *appear* to leave the
    /// primary running. `discard_pending_input` drains the whole buffered
    /// queue (no `MAX_FOLD` cap) and reports the count; afterwards the channel
    /// yields nothing until a new send.
    #[tokio::test]
    async fn discard_pending_input_drops_all_queued_messages() {
        let (updates_tx, _updates_rx) = mpsc::unbounded_channel();
        let queue = crate::engine::message::UserSubmissionQueue::new(updates_tx);
        let target = crate::engine::message::QueueTarget::root("Build");
        // Queue more than MAX_FOLD so we prove the discard has no fold cap —
        // a partial drain would let the leftovers auto-start the next turn.
        let queued = MAX_FOLD + 5;
        for i in 0..queued {
            queue
                .push(
                    UserSubmission {
                        text: format!("queued message {i}"),
                        ..Default::default()
                    },
                    target.clone(),
                )
                .await;
        }

        let dropped = discard_pending_input(&queue).await;
        assert_eq!(
            dropped, queued,
            "every buffered queued message is discarded on cancel (no MAX_FOLD cap)"
        );
        // Nothing is left to auto-start a fresh turn after the cancel.
        let mut drained = Vec::new();
        queue
            .drain_into_for(&mut drained, MAX_FOLD, Some(&target.id))
            .await;
        assert!(
            drained.is_empty(),
            "the queue is empty after a cancel discard"
        );

        // A message sent *after* the cancel is a fresh turn and survives — the
        // discard only drops what was buffered at cancel time, it doesn't close
        // the channel.
        queue
            .push(
                UserSubmission {
                    text: "post-cancel message".into(),
                    ..Default::default()
                },
                target,
            )
            .await;
        assert_eq!(
            queue.recv().await.map(|s| s.text).as_deref(),
            Some("post-cancel message"),
            "a message sent after the cancel still drives the next turn"
        );

        // Idle discard (nothing queued) is a no-op reporting zero.
        assert_eq!(discard_pending_input(&queue).await, 0);
    }

    #[test]
    fn fold_submission_commands_preserves_compact_order() {
        let folded = fold_submission_commands(vec![
            UserSubmission::text("before"),
            UserSubmission::compact_notice(),
            UserSubmission::text("after one"),
            UserSubmission::text("after two"),
        ]);
        assert_eq!(folded.len(), 4);
        match &folded[0] {
            FoldedSubmission::User(submission) => assert_eq!(submission.text, "before"),
            FoldedSubmission::Compact(_) => panic!("expected leading user turn"),
        }
        assert!(matches!(folded[1], FoldedSubmission::Compact(_)));
        match &folded[2] {
            FoldedSubmission::User(submission) => assert_eq!(submission.text, "after one"),
            FoldedSubmission::Compact(_) => panic!("expected first trailing user turn"),
        }
        match &folded[3] {
            FoldedSubmission::User(submission) => assert_eq!(submission.text, "after two"),
            FoldedSubmission::Compact(_) => panic!("expected second trailing user turn"),
        }
    }

    #[test]
    fn fold_submission_commands_runs_lone_compact_without_dummy_user_turn() {
        let folded = fold_submission_commands(vec![UserSubmission::compact_notice()]);
        assert_eq!(folded.len(), 1);
        assert!(matches!(folded[0], FoldedSubmission::Compact(_)));
    }

    // --- Mid-session model switch (implementation note) ---

    /// A providers config with two configured `(provider, model)` pairs (A and
    /// B) — used to drive the live model-switch tests. `provider-c` is left
    /// **unconfigured** so a switch to it exercises the fail-loud path.
    fn two_model_providers_config() -> crate::config::providers::ProvidersConfig {
        use crate::config::providers::{ActiveModelRef, ProviderEntry, ProvidersConfig};
        use std::collections::BTreeMap;
        let mut providers = BTreeMap::new();
        providers.insert(
            "provider-a".to_string(),
            ProviderEntry {
                url: "http://localhost:1/v1".into(),
                headers: vec![],
                ..ProviderEntry::default()
            },
        );
        providers.insert(
            "provider-b".to_string(),
            ProviderEntry {
                url: "http://localhost:2/v1".into(),
                headers: vec![],
                ..ProviderEntry::default()
            },
        );
        ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "provider-a".into(),
                model: "model-a".into(),
                reasoning_effort: None,
                thinking_mode: None,
            }),
            ..ProvidersConfig::default()
        }
    }

    /// Re-root the driver on model A (`provider-a/model-a`) and install the
    /// two-provider test config so the live switch resolves against it. Returns
    /// the driver rooted on a real `Build` primary built through the same
    /// factory production uses.
    fn model_switch_driver() -> (Driver, tempfile::TempDir) {
        let (mut driver, tmp) = test_driver(1);
        let cfg = two_model_providers_config();
        // Build model A and root a genuine `Build` primary on it.
        let model_a = Arc::new(
            crate::engine::model::Model::for_provider(
                &cfg,
                "provider-a",
                "model-a",
                Arc::new(crate::redact::RedactionTable::empty()),
            )
            .unwrap(),
        );
        driver
            .session
            .set_active_model("provider-a", "model-a")
            .unwrap();
        driver.test_providers_override = Some((cfg, "provider-a".into(), "model-a".into()));
        let mut args = driver.spawn_args(true);
        args.model = model_a;
        driver.stack[0].agent = Arc::new(crate::engine::builtin::load("Build", &args).unwrap());
        (driver, tmp)
    }

    #[test]
    fn reasoning_params_prefer_native_capability_over_legacy_thinking_mode() {
        use crate::config::providers::{
            ActiveModelRef, ActiveReasoningEffort, CapabilitySource, CapabilityValue, ModelEntry,
            ProviderEntry, ProvidersConfig, ReasoningEffortCapability,
            ReasoningEffortRequestMapping, ThinkingMode,
        };
        use std::collections::BTreeMap;

        let (mut driver, _tmp) = test_driver(1);
        let mut mapping = BTreeMap::new();
        mapping.insert("minimal".to_string(), serde_json::json!("minimal"));
        mapping.insert("xhigh".to_string(), serde_json::json!("xhigh"));
        let mut providers = BTreeMap::new();
        providers.insert(
            "provider-a".to_string(),
            ProviderEntry {
                url: "http://localhost:1/v1".into(),
                models: vec![ModelEntry {
                    id: "model-a".into(),
                    capabilities: crate::config::providers::ModelCapabilities {
                        reasoning_effort: Some(ReasoningEffortCapability {
                            values: vec![
                                CapabilityValue {
                                    value: "minimal".into(),
                                    label: None,
                                    description: None,
                                },
                                CapabilityValue {
                                    value: "xhigh".into(),
                                    label: None,
                                    description: None,
                                },
                            ],
                            default: Some("minimal".into()),
                            request_mapping: Some(ReasoningEffortRequestMapping::JsonField {
                                field: "reasoning_effort".into(),
                                values: mapping,
                            }),
                            source: Some(CapabilitySource::Live),
                        }),
                        ..crate::config::providers::ModelCapabilities::default()
                    },
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        let cfg = ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "provider-a".into(),
                model: "model-a".into(),
                reasoning_effort: Some(ActiveReasoningEffort {
                    value: "xhigh".into(),
                }),
                thinking_mode: Some(ThinkingMode::High),
            }),
            ..ProvidersConfig::default()
        };
        let model = crate::engine::model::Model::for_provider(
            &cfg,
            "provider-a",
            "model-a",
            Arc::new(crate::redact::RedactionTable::empty()),
        )
        .unwrap();
        driver.test_providers_override = Some((cfg, "provider-a".into(), "model-a".into()));

        assert_eq!(
            driver.resolve_thinking_params_for(&model),
            Some(serde_json::json!({ "reasoning_effort": "xhigh" }))
        );
    }

    /// Regression: a session driving on model A routes the next request to model
    /// B after a mid-session `SetActiveModel`, with no restart — the root
    /// primary's bound model is rebuilt to B's id + provider.
    #[tokio::test]
    async fn live_model_switch_routes_next_request_to_new_model() {
        let (mut driver, _tmp) = model_switch_driver();
        let (tx, _rx) = mpsc::channel::<TurnEvent>(64);

        // The dispatched request's model == A's id before the switch.
        assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-a");
        assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-a");

        driver
            .run_control(
                DriverControl::SetActiveModel {
                    provider: "provider-b".into(),
                    model: "model-b".into(),
                },
                &tx,
            )
            .await;

        // The next outbound request now routes to B's id + provider, same
        // session, same root history (no restart).
        assert_eq!(
            driver.stack[0].agent.model.model_id_ref(),
            "model-b",
            "next request's model is B after the switch"
        );
        assert_eq!(
            driver.stack[0].agent.model.provider_id(),
            "provider-b",
            "next request's provider is B after the switch"
        );
        // The primary identity is unchanged — only the bound model swapped.
        assert_eq!(driver.stack[0].agent.name, "Build");
        let names = driver.stack[0].agent.tools.names();
        for tool in [
            "create_goal",
            "get_goal",
            "update_goal",
            "todo",
            "todo_read",
            "session_read",
            "session_search",
        ] {
            assert!(
                names.contains(&tool),
                "rebuilt foreground Build must preserve interactive `{tool}` tool: {names:?}"
            );
        }
        // The session's persisted active-model row is committed to B.
        assert_eq!(driver.session.active_model().as_deref(), Some("model-b"));
        assert_eq!(
            driver.session.active_provider().as_deref(),
            Some("provider-b")
        );
    }

    /// Switching to an unconfigured model surfaces a loud `Notice` error and
    /// leaves the prior model (and the persisted active-model row) active.
    #[tokio::test]
    async fn live_model_switch_to_unconfigured_keeps_current_model() {
        let (mut driver, _tmp) = model_switch_driver();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);

        driver
            .run_control(
                DriverControl::SetActiveModel {
                    provider: "provider-c".into(), // never configured
                    model: "model-c".into(),
                },
                &tx,
            )
            .await;

        // A loud notice surfaced (never a silent no-op).
        let notice = rx
            .try_recv()
            .expect("a Notice must surface on an unconfigured switch");
        match notice {
            TurnEvent::Notice { text } => {
                assert!(
                    text.contains("provider-c") && text.contains("failed"),
                    "the notice names the failed target: {text}"
                );
            }
            other => panic!("expected a Notice, got {other:?}"),
        }

        // The prior model A is still active — both the live routing and the
        // persisted row are untouched.
        assert_eq!(driver.stack[0].agent.model.model_id_ref(), "model-a");
        assert_eq!(driver.stack[0].agent.model.provider_id(), "provider-a");
        assert_eq!(driver.session.active_model().as_deref(), Some("model-a"));
        assert_eq!(
            driver.session.active_provider().as_deref(),
            Some("provider-a")
        );
    }

    /// Re-selecting the already-active model is a no-op — no rebuild, no
    /// cache-busting churn, no error.
    #[tokio::test]
    async fn live_model_switch_same_model_is_noop() {
        let (mut driver, _tmp) = model_switch_driver();
        let (tx, mut rx) = mpsc::channel::<TurnEvent>(64);
        let before = Arc::as_ptr(&driver.stack[0].agent);

        driver
            .run_control(
                DriverControl::SetActiveModel {
                    provider: "provider-a".into(),
                    model: "model-a".into(),
                },
                &tx,
            )
            .await;

        // Same Arc — the agent was not rebuilt.
        assert_eq!(
            Arc::as_ptr(&driver.stack[0].agent),
            before,
            "re-selecting the active model must not rebuild the primary"
        );
        // No notice, no projection event.
        assert!(
            rx.try_recv().is_err(),
            "a same-model re-select emits nothing"
        );
    }
}
