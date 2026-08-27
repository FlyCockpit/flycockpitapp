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
mod delegation_helpers;
mod inbound;
mod noninteractive;
#[cfg(test)]
pub(in crate::engine::driver) use noninteractive::{
    parse_noninteractive_recovery_snapshot, ready_noninteractive_recovery_snapshot_with_late_steer,
    retain_noninteractive_late_steer_checkpoint,
};
mod queue;
mod reports;
mod schedule_dispatch;
mod skills_seed;
mod swap;

use crate::engine::compact_draft::wire_token_total;
#[cfg(test)]
use context_reduction::*;
use context_reduction::{AutoCompactGate, PruneEffectiveness};
pub(crate) use delegation_helpers::scoped_write_refusal;
use delegation_helpers::*;
use inbound::injection_check_prompt_target;
#[cfg(test)]
use noninteractive::*;
use noninteractive::{
    BackgroundNoninteractiveCompletion, BackgroundNoninteractiveJob, BatchNoninteractiveTask,
    DelegationPartialProgress, NoninteractiveDelegationRegistry, PartialProgressCommand,
    PartialProgressFileEdit, SingleNoninteractiveTask, VnextChildAdmissionRegistry, handle_footer,
    stale_handle_error,
};
pub(crate) use noninteractive::{NoninteractiveSteerTarget, run_noninteractive};
use queue::*;
use reports::*;
#[allow(unused_imports)]
pub(crate) use reports::{
    FailoverCustodyBlocked, FailoverCustodyRefusal, FailoverRefusalKind, build_backup_model,
    build_backup_model_with_diagnostics, build_backup_model_with_store, build_failover_models,
    build_failover_models_with_diagnostics, build_failover_models_with_store,
    failover_custody_block, resolve_backup_model_for_session, resolve_failover_models_for_session,
};
use skills_seed::SkillPair;

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    pin::Pin,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use tokio::sync::mpsc;
use tokio::time::{Duration, Sleep};

use crate::config::extended::LlmMode;
use crate::engine::agent::{
    Agent, BackupTurnMetadata, TaskControlAction, TurnEvent, TurnOutcome, turn_with_backup,
};
use crate::engine::message::{
    Message, UserSubmission, UserSubmissionKind, extract_text, extract_user_text,
};
use crate::engine::prune;
use crate::engine::schedule::{ScheduleAuthority, ScheduleCommand, ScheduleEvent};
use crate::redact::RedactionTable;

const AUTO_COMPACT_FLOOR_PCT: u8 = 60;
const AUTO_COMPACT_CAPABLE_MODE_DEFAULT_PCT: u8 = 80;
use crate::session::Session;

/// Out-of-band control requests routed to the driver from the daemon
/// worker — `/prune`, `/compact`, `/pin`. Drained on the same boundary
/// as user input and job events so they never interleave with a
/// mid-turn state (the safe-boundary rule, `plan.md` T6.e).
#[derive(Debug)]
pub enum DriverControl {
    WakeGoal,
    /// Deliver an already-durable late user steer to the exact live executor
    /// that originally owned the automatic decision. The worker acknowledges
    /// the DB claim only after that continuation completes, so a crash before
    /// delivery leaves the steer redeliverable.
    DeliverLateUserDecisionSteer {
        agent_instance_id: uuid::Uuid,
        steer_id: uuid::Uuid,
        /// This becomes the first model-turn's external-journal identity. A
        /// recovery must reuse it, so `begin_dispatch` refuses a duplicate
        /// provider handoff instead of quietly creating another one.
        continuation_id: uuid::Uuid,
        recovery_epoch: uuid::Uuid,
        payload_json: String,
        respond_to: tokio::sync::oneshot::Sender<LateUserSteerContinuationOutcome>,
    },
    /// Resume the checkpoint of an accepted (and therefore non-redeliverable)
    /// late steer.  The immutable continuation id is reused as the first
    /// external inference identity; this is never a second acceptance.
    ResumeAcceptedLateUserDecisionSteer {
        agent_instance_id: uuid::Uuid,
        steer_id: uuid::Uuid,
        continuation_id: uuid::Uuid,
        recovery_epoch: uuid::Uuid,
        payload_json: String,
        continuation_checkpoint_json: String,
        respond_to: tokio::sync::oneshot::Sender<LateUserSteerContinuationOutcome>,
    },
    /// Redacted automatic-decision work delivered to one concrete live parent
    /// executor.  This is intentionally a separate control message from user
    /// input: no resolver packet enters transcript/history, and the worker
    /// retains the durable claim until this exact endpoint accepts it.
    ResolveAgentTreeDecision {
        agent_instance_id: uuid::Uuid,
        prompt: String,
        respond_to: tokio::sync::oneshot::Sender<std::result::Result<String, String>>,
    },
    /// Rebuild one exact interactive task frame from its durable launch
    /// descriptor before any recovered decision can be delivered.
    ReattachInteractiveTaskChild {
        recovery: RecoveredInteractiveTaskChild,
        // The child-produced generation lets the worker install the exact
        // registration before it consumes a recovery claim; the later local
        // detach carries the same token.
        respond_to: tokio::sync::oneshot::Sender<
            std::result::Result<crate::engine::agent::AgentTreeEndpointGeneration, String>,
        >,
    },
    /// Rebuild one exact detached task executor from its durable launch and
    /// continuation snapshot. Unlike an interactive frame this starts a
    /// background child, but the worker still withholds the resume claim until
    /// the child's real resolver mailbox has been installed.
    ReattachNoninteractiveTaskChild {
        recovery: RecoveredNoninteractiveTaskChild,
        // A successful reply carries the exact child-owned resolver mailboxes
        // for the whole recovered recursive subtree. The worker installs all
        // of them before it consumes any claim or resumes a pending decision.
        respond_to: tokio::sync::oneshot::Sender<
            std::result::Result<Vec<RecoveredNoninteractiveResolverEndpoint>, String>,
        >,
    },
    /// Rebuild the live members of one durable batch through a single
    /// dependency coordinator.  Batch labels are deliberately never launched
    /// as unrelated single tasks during recovery.
    ReattachNoninteractiveTaskBatch {
        recoveries: Vec<RecoveredNoninteractiveTaskChild>,
        terminal_children: Vec<RecoveredNoninteractiveTaskTerminal>,
        respond_to: tokio::sync::oneshot::Sender<
            std::result::Result<Vec<RecoveredNoninteractiveResolverEndpoint>, String>,
        >,
    },
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
    /// deterministic appendix, derive context tags, create a fresh session,
    /// and emit `CompactReady`.
    Compact,
    /// Pin a user message verbatim for the next `/compact` (`/pin`).
    Pin {
        text: String,
    },
    /// Explicitly opt into synthetic resume repair for a Responses session
    /// that strict replay opened read-only. The original transcript is not
    /// mutated; only the live root history is populated with the healed replay.
    RepairResume {
        root_agent: String,
        respond_to: tokio::sync::oneshot::Sender<std::result::Result<usize, String>>,
    },
    /// Execute a parked interrupt's persisted tool call through the canonical
    /// ordinary-tool dispatcher, injecting the already-recorded answer at the
    /// interrupt seam so approval/question behavior matches the live path.
    ReplayParkedInterrupt {
        interrupt_id: uuid::Uuid,
        /// AgentTree-owned rows retain an exact UUID owner. Legacy rows leave
        /// this absent and use the historical name check below.
        agent_instance_id: Option<uuid::Uuid>,
        payload: Box<crate::db::needs_attention::InterruptParkPayload>,
        response: crate::daemon::proto::ResolveResponse,
        question: Box<crate::engine::interrupt::PreResolvedInterruptQuestion>,
        respond_to: tokio::sync::oneshot::Sender<std::result::Result<ParkedReplayOutcome, String>>,
    },
    /// Swap the **primary** (root-frame) agent in place (`/plan` → `Plan`,
    /// `/build` → `Build`, `plan.md §4.6.d`). Handled at the idle boundary
    /// like other control requests; the root history is preserved so the
    /// new primary continues the same conversation with its own tool
    /// surface + system prompt. A no-op when an interactive subagent holds
    /// the foreground (stack depth > 1) or the name is already active.
    SwapPrimary {
        name: String,
    },
    /// Switch the active `llm_mode` live (`/llm-mode`,
    /// implementation note). Rebuilds the root-frame
    /// agent so its tool-description verbosity + per-mode prompt re-render;
    /// busts the cached system prefix (the TUI shows the cache-break warning
    /// via the shared helper, suppressed on a no-cache provider). Root
    /// history is preserved — same conversation, new steering. When
    /// `prune_after_switch` is true, the successful rebuild immediately runs
    /// through the ordinary prune path so stale mode-specific tool text is not
    /// retained. A no-op when an interactive subagent holds the foreground or
    /// the mode is unchanged.
    /// `mode = None` toggles against the driver's authoritative current value
    /// (the `/llm-mode` / `toggle` default action); `Some(_)` sets it
    /// explicitly.
    SetLlmMode {
        mode: Option<crate::config::extended::LlmMode>,
        prune_after_switch: bool,
    },
    /// Replace the root agent's session-scoped tool surface. Applied only at
    /// idle while the root frame is foreground; refused while an interactive
    /// subagent owns the foreground.
    SetToolSurfaceOverride {
        selection: crate::agents::ToolSurfaceSelection,
        prune_after_switch: bool,
        monty_nudge: Option<String>,
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
    SetPreflight {
        enabled: Option<bool>,
    },
    /// Set (or toggle) the session-only prompt-cache retention override
    /// (`/longcache`). `Some(true)` arms extended retention intent,
    /// `Some(false)` clears it, and `None` toggles. The driver re-resolves
    /// the effective wire key against curated active-model capability.
    SetLongcache {
        enabled: Option<bool>,
    },
    /// Re-read the active-model prompt-cache retention preference from the
    /// shared session config snapshot and re-resolve current frame params.
    /// Used after `RefreshConfig` so `/model-settings` edits affect the
    /// running session without a second model switch.
    /// Repin the worker's changed config snapshot and publish every
    /// active-model-derived correction without advancing selection generation.
    RefreshConfigDerivedState {
        /// Completed only after the driver has repinned the new snapshot and
        /// applied every value derived from it. The worker must not publish a
        /// successful replacement acknowledgement before this receipt.
        applied: tokio::sync::oneshot::Sender<()>,
    },
    /// Set a session-only root delegation recursion override (`/quick`).
    /// Root delegation still obeys existing allowed-target and per-agent
    /// max-depth policy; this only overrides the default enabled/depth values.
    SetDelegationRecursion {
        enabled: bool,
        default_depth: u32,
    },
    /// Update the per-user-message primary round ceiling from the latest
    /// layered settings. Applied at the next idle/control boundary so a
    /// `/settings` edit affects subsequent user messages in this session.
    SetMaxPrimaryRounds {
        max_primary_rounds: u32,
    },
    /// Switch the active model+provider live mid-session (`/model` picker,
    /// implementation note). The driver builds the new
    /// [`Model`](crate::engine::model::Model) for `(provider, model)` from the
    /// layered config — threading the session's effective redaction table
    /// ([`Self::redact`]) and inheriting the current model's shutdown gate —
    /// then rebuilds the **root primary** under it
    /// at the idle boundary, so the next outbound request routes to the new
    /// model. Breaking the prompt cache is expected (new model = new cache
    /// key). On an unconfigured/bad target it **fails loudly** via
    /// [`TurnEvent::Notice`] and keeps the current model active (never a silent
    /// no-op). Config is written **only** when `persist_as_default` explicitly
    /// asks to replace the future-session default; there is no first-default
    /// race, because a session-only selection never writes `active_model` in
    /// any layer. A model-build or session-persistence failure keeps the prior
    /// live model. An explicit default request is all-or-nothing: it is one
    /// journaled transaction that commits the guarded session revision and the
    /// config together, or converges both back to their recorded prior
    /// values — a default-write failure never leaves a half-applied switch.
    SetActiveModel {
        selection_id: uuid::Uuid,
        provider: String,
        model: String,
        persist_as_default: bool,
        trigger: crate::session::ModelSwitchTrigger,
        reasoning_effort: Option<String>,
        thinking_mode: Option<crate::config::providers::ThinkingMode>,
        prompt_cache_retention: Option<crate::config::providers::PromptCacheRetention>,
    },
    /// Production selection lifecycle: the worker awaits `completion` until
    /// the fixed deadline, while `terminal_claimed` guarantees exactly one
    /// terminal result across timeout and driver completion.
    SetActiveModelWithDeadline {
        selection_id: uuid::Uuid,
        deadline: std::time::Instant,
        terminal_claimed: std::sync::Arc<std::sync::atomic::AtomicBool>,
        completion: tokio::sync::oneshot::Sender<()>,
        provider: String,
        model: String,
        persist_as_default: bool,
        trigger: crate::session::ModelSwitchTrigger,
        reasoning_effort: Option<String>,
        thinking_mode: Option<crate::config::providers::ThinkingMode>,
        prompt_cache_retention: Option<crate::config::providers::PromptCacheRetention>,
    },
    /// Emit the correlated terminal results for effective-default
    /// transactions that a recovery pass converged on this session's behalf.
    ///
    /// Routed through the driver so the event carries *this driver's*
    /// active-model-state generation. A recovery pass has no access to that
    /// counter, and a client's terminal gate compares against it.
    EmitRecoveredDefaultTerminals {
        transactions: Vec<crate::config::providers::RecoveredTransaction>,
        /// The retained-config dispatcher must not retire its private journal
        /// until this driver has durably recorded the exact terminal receipt.
        /// `None` is retained for direct driver tests that only inspect turn
        /// events.
        respond_to: Option<tokio::sync::oneshot::Sender<std::result::Result<(), String>>>,
    },
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

#[derive(Debug, Clone)]
pub struct RecoveredInteractiveTaskChild {
    pub agent_instance_id: uuid::Uuid,
    pub parent_agent_instance_id: uuid::Uuid,
    pub task_call_id: String,
    pub label: String,
    pub child_agent: String,
    pub original_args_json: String,
    pub snapshot_json: String,
    pub payload: String,
    /// An already accepted late steer whose immutable checkpoint is named by
    /// this task snapshot. The receiver installs the association before a
    /// recovered parked QuestionTool/approval can replay; it must never turn
    /// the accepted user body into a new queued prompt.
    pub accepted_late_steer: Option<RecoveredLateUserSteerPermit>,
    /// A recovered executor is addressable before it is executable.  The
    /// session worker releases this gate only after it atomically consumes the
    /// exact durable resume claim for the whole recovered unit.
    pub activation_gate: RecoveryActivationGate,
}

/// The durable identity of an accepted late-user steer supplied by the
/// session-worker recovery pass. This is intentionally separate from the
/// provider permit token: a recovered waiting executor may retain this
/// identity while only the final model-dispatch boundary checks `running`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveredLateUserSteerPermit {
    pub steer_id: uuid::Uuid,
    pub continuation_id: uuid::Uuid,
    pub recovery_epoch: uuid::Uuid,
}

#[derive(Debug, Clone)]
pub struct RecoveredNoninteractiveTaskChild {
    pub agent_instance_id: uuid::Uuid,
    pub parent_agent_instance_id: uuid::Uuid,
    pub task_call_id: String,
    pub label: String,
    pub child_agent: String,
    pub original_args_json: String,
    pub snapshot_json: String,
    pub payload: String,
    pub was_backgrounded: bool,
    /// Shared with every recursive descendant reconstructed from this durable
    /// checkpoint.  Publishing mailboxes is safe while it is closed; model
    /// work is not.
    pub activation_gate: RecoveryActivationGate,
}

/// Boot-recovery activation barrier.  Recovery deliberately has two phases:
/// construct and publish exact executor endpoints, then atomically consume
/// their durable claims, then release model execution.  A crash in either
/// earlier phase leaves the claims retryable rather than running an unclaimed
/// continuation.
#[derive(Debug, Clone)]
pub struct RecoveryActivationGate {
    state: std::sync::Arc<std::sync::atomic::AtomicU8>,
    changed: std::sync::Arc<tokio::sync::Notify>,
}

impl RecoveryActivationGate {
    const PENDING: u8 = 0;
    const RELEASED: u8 = 1;
    const ABORTED: u8 = 2;

    pub fn new() -> Self {
        Self {
            state: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(Self::PENDING)),
            changed: std::sync::Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub fn release(&self) {
        // Terminal is first-winner-wins.  In particular, an abort caused by a
        // failed atomic claim may never be overwritten by a late success path
        // that still holds another clone of this shared gate.
        let _ = self.state.compare_exchange(
            Self::PENDING,
            Self::RELEASED,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        );
        self.changed.notify_waiters();
    }

    pub fn abort(&self) {
        let _ = self.state.compare_exchange(
            Self::PENDING,
            Self::ABORTED,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        );
        self.changed.notify_waiters();
    }

    pub fn is_aborted(&self) -> bool {
        self.state.load(std::sync::atomic::Ordering::Acquire) == Self::ABORTED
    }

    pub async fn wait(&self) -> anyhow::Result<()> {
        loop {
            // Register the waiter *before* observing `state`.  `Notify` does
            // not retain a `notify_waiters` wake-up for a future, unpolled
            // waiter, so observing pending first would leave a narrow
            // release-between-load-and-await deadlock window.
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self.state.load(std::sync::atomic::Ordering::Acquire) {
                Self::RELEASED => return Ok(()),
                Self::ABORTED => anyhow::bail!(
                    "recovered executor activation was aborted before its resume claim was consumed"
                ),
                Self::PENDING => notified.await,
                _ => anyhow::bail!("recovered executor activation gate has an invalid state"),
            }
        }
    }
}

/// A sibling that was already terminal when a batch worker restarted.  It is
/// carried into the recovered job's final aggregate result but is never
/// launched or terminalized a second time.
#[derive(Debug, Clone)]
pub struct RecoveredNoninteractiveTaskTerminal {
    pub label: String,
    pub child_agent: String,
    pub report: String,
    pub failed: bool,
}

#[derive(Debug, Clone)]
pub struct RecoveredNoninteractiveResolverEndpoint {
    pub agent_instance_id: uuid::Uuid,
    /// Exact source-owned lifecycle incarnation.  The session worker uses
    /// this same token for its early recovery registration and the later
    /// forwarded attach event, so a delayed Drop cannot detach a replacement.
    pub endpoint_generation: crate::engine::agent::AgentTreeEndpointGeneration,
    pub endpoint: tokio::sync::mpsc::Sender<crate::engine::agent::AgentTreeExecutorRequest>,
}

/// A durable late steer claimed for an exact live frame but still waiting for
/// that frame's next independently-addressable turn. The sender is
/// intentionally held until the turn finishes: queue insertion is not proof
/// that the continuation reached its provider-handoff acceptance boundary.
struct PendingLateUserSteerAck {
    agent_instance_id: uuid::Uuid,
    steer_id: uuid::Uuid,
    continuation_id: uuid::Uuid,
    recovery_epoch: uuid::Uuid,
    respond_to: tokio::sync::oneshot::Sender<LateUserSteerContinuationOutcome>,
}

/// Immutable portion of a late-steer executor permit. The runtime token is
/// attached only while the exact turn runs, so cancellation aborts the same
/// provider stream rather than a later unrelated turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LateUserSteerPermitIdentity {
    steer_id: uuid::Uuid,
    continuation_id: uuid::Uuid,
    recovery_epoch: uuid::Uuid,
    agent_instance_id: uuid::Uuid,
}

/// The exact model/tool continuation restored for an interactive task child
/// whose late user steer had already crossed its first provider handoff when
/// the previous worker died.  This is intentionally keyed by the durable
/// executor UUID, rather than by a display name or by the steer payload: the
/// payload is already in the accepted external journal and must never be
/// projected as a second user message during recovery.
struct RecoveredInteractiveLateSteerContinuation {
    permit: LateUserSteerPermitIdentity,
    continuation_id: uuid::Uuid,
    next_prompt: Message,
    /// `true` means `next_prompt` is the pre-turn snapshot from before the
    /// parked tool call. It is retained only for integrity checking; the
    /// actual continuation is the DB-owned parked payload and must be replayed
    /// before any model turn.
    has_parked_continuation: bool,
    /// Installed by the exact recovery resume control. The parked replay moves
    /// it into the normal completion map at the moment it restores the permit
    /// on the frame, so one post-question continuation owns one receipt.
    pending_response: Option<tokio::sync::oneshot::Sender<LateUserSteerContinuationOutcome>>,
}

/// The terminal result of the *continuation*, rather than of the driver's
/// administrative control handling.  `run_user_input` intentionally treats a
/// user cancellation, a parked interrupt, and a terminal inference failure as
/// orderly returns to the daemon loop.  A late steer must not mistake those
/// orderly `Ok(())` returns for an executed continuation: only `Completed`
/// authorizes the durable completion CAS and outer delivery receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LateUserSteerContinuationOutcome {
    Completed,
    Cancelled,
    /// The exact accepted continuation is parked behind a later
    /// QuestionTool/approval. This internal state is never sent to the
    /// worker: its receipt stays attached until the checkpoint reaches a
    /// terminal boundary.
    Parked,
    Interrupted {
        reason: String,
    },
    Failed {
        reason: String,
    },
}

impl LateUserSteerContinuationOutcome {
    pub(crate) fn interrupted(reason: impl Into<String>) -> Self {
        Self::Interrupted {
            reason: reason.into(),
        }
    }

    pub(crate) fn failed(reason: impl Into<String>) -> Self {
        Self::Failed {
            reason: reason.into(),
        }
    }

    pub(crate) fn diagnostic(&self) -> Option<&str> {
        match self {
            Self::Completed | Self::Cancelled | Self::Parked => None,
            Self::Interrupted { reason } | Self::Failed { reason } => Some(reason),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParkedReplayOutcome {
    Completed,
    ParkedAgain,
}

/// Maximum number of queued user messages to fold into a single
/// follow-up prompt. Generous because the worst case is a user
/// hammering Enter — concat-joining a dozen short messages is fine;
/// concat-joining a hundred would bloat the next inference. If we
/// hit this cap, extras stay in the channel for the *next* fold.
const MAX_FOLD: usize = 16;
const GOAL_WATCHDOG_DELAY: Duration = Duration::from_secs(600);
/// After a goal-supervision swarm spawn is refused, its control job stays leased
/// for the 300s lease TTL. Wake the goal loop a bit past that so a QUIESCENT
/// session (no completions to wake it) re-runs supervision, re-leases the
/// now-expired job, and retries the refused spawn.
const GOAL_REFUSED_SPAWN_RETRY_DELAY: Duration = Duration::from_secs(315);
/// Max consecutive refused-spawn retries the goal watchdog attempts before
/// giving up. A transient full queue usually drains within this; a permanent
/// refusal (oversized prompt) then stops re-waking instead of looping forever.
const GOAL_REFUSED_SPAWN_MAX_RETRIES: u8 = 4;
/// Finite continuation cap for goals created without an explicit token budget.
/// Large enough for ordinary multi-turn runs, but not unbounded if the agent
/// repeatedly fails to make durable progress.
const GOAL_USAGE_LIMIT_BACKOFF_BASE: Duration = Duration::from_secs(30);
const GOAL_USAGE_LIMIT_BACKOFF_MAX: Duration = Duration::from_secs(300);
const GOAL_USAGE_LIMIT_MAX_AUTO_RESUME_ATTEMPTS: u8 = 3;
const GOAL_USAGE_LIMIT_INTERVENTION_CODE: &str = "usage_limit_persisted";
#[derive(Debug, PartialEq, Eq)]
enum GoalUsageLimitWatchdogAction {
    NotUsageLimited,
    AutoResume,
    Exhausted,
}

#[derive(Debug, Clone)]
struct GoalSupervisionRound {
    goal_id: uuid::Uuid,
    attempt_generation: i64,
    total: usize,
    jobs: HashMap<String, crate::db::session_goals::GoalControlJob>,
}

#[cfg(test)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct GoalProgressObservation {
    observed_turn: bool,
    mutating_action: bool,
    context_delta: bool,
}

#[cfg(test)]
impl GoalProgressObservation {
    fn no_progress(self) -> bool {
        self.observed_turn && !self.mutating_action && !self.context_delta
    }
}

const ID_PRIMARY_ROUNDS_CONTINUE: &str = "primary_rounds_continue";
const ID_PRIMARY_ROUNDS_STOP: &str = "primary_rounds_stop";

/// Trigger string for a `/plan`/`/build` (and `/agent`/`Shift+Tab`)
/// slash-command swap routed through `DriverControl::SwapPrimary` at idle.
const SWAP_TRIGGER_COMMAND: &str = "swap_command";

/// The export-audit context for a primary swap (`primary_swap` event). Carries
/// the trigger and optional wire-vs-user `display`/`kickoff` halves (GOALS §14).
/// Live slash-command swaps inject no kickoff (never fabricated).
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
    recovery: crate::db::tool_calls::Recovery,
    wire_args: serde_json::Value,
}

struct ScheduleToolCallRecord {
    agent: String,
    llm_mode: crate::config::extended::LlmMode,
    call_id: String,
    provider_item_id: Option<String>,
    provider_call_id: Option<String>,
    original_input_json: serde_json::Value,
    wire_input_json: serde_json::Value,
    recovery: crate::db::tool_calls::Recovery,
    hard_fail: bool,
    output: String,
    duration_ms: u64,
}

impl<'a> PrimarySwapContext<'a> {
    /// A `/plan`/`/build` slash-command swap: trigger only, no kickoff (the
    /// new primary's first turn is the user's next message).
    fn swap_command() -> Self {
        Self {
            trigger: SWAP_TRIGGER_COMMAND,
            display: None,
            kickoff: None,
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

/// Clears the session's invocation-scoped approval override when a run ends
/// (success, failure, cancel, timeout, early return). Session mode is never
/// mutated by the override path.
struct InvocationApprovalGuard {
    session: Arc<crate::session::Session>,
}

impl Drop for InvocationApprovalGuard {
    fn drop(&mut self) {
        self.session.clear_invocation_approval_override();
    }
}

/// Per-node session-override axes consumed at a turn boundary that apply to the
/// active frame (modes AC5). `None` fields keep the config-resolved values.
#[derive(Default)]
struct ConsumedNodeOverride {
    /// Non-escalating LLM mode for this frame's next turn.
    llm_mode: Option<crate::config::extended::LlmMode>,
    /// Daemon-validated `(provider, model)` rebind for this frame's next turn.
    model: Option<(String, String)>,
}

/// One agent's slice of state on the driver stack.
pub struct AgentSession {
    pub agent: Arc<Agent>,
    /// Durable lifecycle identity for this concrete executor.  Agent display
    /// names are intentionally not used as identity: several task children can
    /// share one definition name concurrently.
    pub agent_instance_id: Option<uuid::Uuid>,
    /// Process-local incarnation of this frame's worker resolver endpoint.
    /// It is minted before the attached event and travels with the matching
    /// detached event, so a delayed teardown cannot evict a replacement frame
    /// for the same durable agent UUID.
    endpoint_generation: Option<crate::engine::agent::AgentTreeEndpointGeneration>,
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
    pub fallback_decision: Option<crate::engine::agent::BackupFallbackDecision>,
    /// A rehydrated foreground executor may expose a resolver endpoint while
    /// its exact durable resume claim is still pending.  The normal input
    /// path waits here before any model/tool turn begins.
    recovery_activation: Option<RecoveryActivationGate>,
    /// An accepted late-user steer remains attached to this exact executor
    /// through later tool/QuestionTool continuation phases.  It is not a
    /// generic driver flag: popping this frame must drop the permit before a
    /// parent gets another provider turn.
    late_user_steer_permit: Option<LateUserSteerPermitIdentity>,
    /// Reservation held by this child for the lifetime of its interactive
    /// frame. Dropping the frame releases its parent's vNext child slot.
    _vnext_child_admission: Option<tokio::sync::OwnedSemaphorePermit>,
    /// This child frame's own `subagentStop` continuation latch. Keeping it on
    /// the frame makes the 8-continuation budget independent per nested child
    /// and — because it is dropped on every pop / unwind / teardown of the
    /// frame — guarantees the child stop gate is never-reopen airtight: a
    /// cancelled / aborted / parent-cancelled child cannot re-enter or reopen
    /// it. The root frame's latch is unused (root `stop` owns a turn-scoped
    /// latch in `run_user_input` instead).
    pub stop_gate: crate::engine::agent::hooks::StopGateState,
}

/// Driver-side tracking for a detached-`Swarm` child's `subagentStop` pairing.
/// A genuine swarm child (`bee` / `scout`) runs its OWN controlling
/// `subagentStop` gate inside `run_swarm_loop` before publishing its terminal
/// result, then the loop task sends an ordered
/// [`crate::engine::schedule::ScheduleEvent::SwarmChildStopGateCompleted`] (FIFO
/// before its `Completed`). The driver flips `stop_gate_fired` on that marker so
/// the terminal drain does NOT fire a second `subagentStop` for a normally-gated
/// success; only a failure / detach-loss (which bypasses the loop gate) fires a
/// terminal stop at the drain.
#[derive(Debug, Clone)]
struct SwarmSubagentHookState {
    subagent_type: String,
    stop_gate_fired: bool,
}

#[derive(Debug, Clone)]
pub struct PendingTaskCall {
    pub call_id: String,
    pub provider_item_id: Option<String>,
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
        class: crate::engine::model::InferenceErrorClass,
        phase: String,
    },
}

const USER_MESSAGE_EVENT_WRITE_ATTEMPTS: usize = 3;
const DURABLE_SUBMISSION_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserMessageRecordOutcome {
    Recorded(i64),
    Untracked,
    RetryRequired,
}

#[derive(Debug, Clone)]
struct ReservedOversizedUserSubmission {
    reservation: crate::db::text_artifacts::TextArtifactReservation,
    source_text: String,
}

/// Keeps a receipt-keyed oversized-input lease live while preflight and any
/// utility-provider preprocessing are running.  The lease token rotates on
/// renewal, so callers must obtain the final value through [`Self::finish`]
/// before they reject or materialize.  Dropping the keeper always cancels the
/// heartbeat; the durable lease itself then remains available for normal crash
/// reconciliation rather than being modified by a detached task.
struct OversizedArtifactLeaseKeeper {
    cancel: tokio_util::sync::CancellationToken,
    state: Arc<tokio::sync::Mutex<OversizedArtifactLeaseState>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Debug, Clone)]
enum OversizedArtifactLeaseState {
    Live(crate::db::text_artifacts::TextArtifactReservation),
    Stale,
    Failed(String),
}

impl OversizedArtifactLeaseKeeper {
    /// A short cadence intentionally checks before the 5-minute renewal
    /// boundary. The DB remains the authority for whether a rotation is due,
    /// and compare-matches every identity/token/expiry field.
    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

    fn start(
        db: crate::db::Db,
        reservation: crate::db::text_artifacts::TextArtifactReservation,
    ) -> Self {
        let cancel = tokio_util::sync::CancellationToken::new();
        let task_cancel = cancel.clone();
        let state = Arc::new(tokio::sync::Mutex::new(OversizedArtifactLeaseState::Live(
            reservation,
        )));
        let task_state = state.clone();
        let task = tokio::spawn(async move {
            let mut heartbeat = tokio::time::interval(Self::HEARTBEAT_INTERVAL);
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // `interval` ticks immediately. The lease was just read/renewed by
            // the owner, so start the actual cadence one period later.
            heartbeat.tick().await;
            loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    _ = heartbeat.tick() => {
                        let reservation = match &*task_state.lock().await {
                            OversizedArtifactLeaseState::Live(reservation) => reservation.clone(),
                            OversizedArtifactLeaseState::Stale | OversizedArtifactLeaseState::Failed(_) => break,
                        };
                        let now_ms = chrono::Utc::now().timestamp_millis();
                        match db
                            .renew_text_artifact_reservation(reservation, now_ms)
                            .await
                        {
                            Ok(Some(renewed)) => {
                                *task_state.lock().await = OversizedArtifactLeaseState::Live(renewed);
                            }
                            Ok(None) => {
                                *task_state.lock().await = OversizedArtifactLeaseState::Stale;
                                break;
                            }
                            Err(error) => {
                                *task_state.lock().await = OversizedArtifactLeaseState::Failed(error.to_string());
                                break;
                            }
                        }
                    }
                }
            }
        });
        Self {
            cancel,
            state,
            task: Some(task),
        }
    }

    async fn finish(
        mut self,
    ) -> Result<Option<crate::db::text_artifacts::TextArtifactReservation>> {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.await
                .context("joining oversized artifact lease keeper")?;
        }
        match &*self.state.lock().await {
            OversizedArtifactLeaseState::Live(reservation) => Ok(Some(reservation.clone())),
            OversizedArtifactLeaseState::Stale => Ok(None),
            OversizedArtifactLeaseState::Failed(error) => {
                bail!("oversized artifact lease keeper failed: {error}")
            }
        }
    }
}

impl Drop for OversizedArtifactLeaseKeeper {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn finish_oversized_artifact_lease(
    keeper: &mut Option<OversizedArtifactLeaseKeeper>,
) -> Result<Option<crate::db::text_artifacts::TextArtifactReservation>> {
    match keeper.take() {
        Some(keeper) => keeper.finish().await,
        None => Ok(None),
    }
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
    /// Session-scoped config reader, re-pinned at each turn boundary
    /// (`engine-config-snapshot-adoption`). The single access path to resolved
    /// config for the driver and every `ToolCtx` it builds; installed by the
    /// worker via [`Self::set_config_handle`] before the loop starts.
    config: crate::daemon::session_worker::SessionConfigHandle,
    pub stack: Vec<AgentSession>,
    /// Completion acknowledgements for durable late steers queued for an exact
    /// interactive target. Keyed by the queue item's UUID, so a reused display
    /// name or queue target can never settle the wrong agent-instance claim.
    pending_late_user_steer_acks: std::collections::HashMap<uuid::Uuid, PendingLateUserSteerAck>,
    /// Explicit terminal state for the late-steer continuation currently
    /// executing in this single-threaded driver.  It is deliberately separate
    /// from `Result<()>`: normal cancellation and terminal model failures both
    /// return `Ok(())` after driver cleanup, but neither executed the durable
    /// user steer.
    late_steer_continuation_outcome: Option<LateUserSteerContinuationOutcome>,
    /// Exact serialized continuation messages restored for interactive task
    /// frames. The queue merely schedules a safe-boundary turn; its placeholder
    /// text is never authority for the recovered model input.
    recovered_interactive_continuations: std::collections::HashMap<uuid::Uuid, Message>,
    /// Reattached accepted late-steer checkpoints waiting for the worker's
    /// exact `ResumeAcceptedLateUserDecisionSteer` control.  Keeping this
    /// separate from the queue scheduler makes an accepted checkpoint
    /// impossible to accidentally run as an ordinary recovered task prompt.
    recovered_interactive_late_steer_continuations:
        std::collections::HashMap<uuid::Uuid, RecoveredInteractiveLateSteerContinuation>,
    assistant_identity_prefix: Option<String>,
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
    delegation_retry_budget_remaining: usize,
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
    /// Shared with background driver clones so child limits remain enforced
    /// while a parent continues processing later turns.
    vnext_child_admissions: VnextChildAdmissionRegistry,
    /// Exact daemon-owned UUID bindings for daemon-local vNext definitions.
    /// This arrives at root construction and is copied unchanged into every
    /// child SpawnArgs; the driver never derives it from display names.
    vnext_local_installation_resolver: crate::agents::LocalInstallationResolver,
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
    /// Live detached-`Swarm` child subagents that have fired `subagentStart`,
    /// keyed by schedule `job_id` → child agent type (`subagentType`). Populated
    /// when a [`ScheduleEvent::SwarmChildStarted`] is drained and drained back
    /// out when the same `job_id`'s [`ScheduleEvent::Completed`] arrives (firing
    /// the paired `subagentStop`), so every started swarm child pairs with
    /// exactly one stop. Goal-supervision control workers never enter this map
    /// (they never emit `SwarmChildStarted`; guidance L22). Any residual entries
    /// at driver-loop teardown are drained as `aborted` (detach loss).
    swarm_subagents: std::collections::HashMap<String, SwarmSubagentHookState>,
    /// Which cache-safe capability hints have already been appended to the
    /// active history (GOALS §22). A branch is enabled by two cache-safe
    /// moves: the dispatcher starts accepting the action (always, here),
    /// and a hint message is appended **once** announcing it — appended
    /// messages extend the cached prefix without reserializing the
    /// byte-stable tools array. We append the hint the first time the
    /// gating job kind appears.
    appended_hints: std::collections::HashSet<&'static str>,
    /// Command-capability startup notices already emitted for this driver.
    /// Keyed by rendered text so agent/toolbox/PATH changes can surface a new
    /// state without spamming every turn.
    emitted_command_capability_notices: HashSet<String>,
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
    auto_compact_gate: AutoCompactGate,
    /// Rolling effectiveness ledger of recent **auto** prunes at the root
    /// frame, for the escalate-to-compaction policy
    /// (implementation note). Each entry is one auto-prune
    /// boundary's `(ctx_pct_before, saved_pct_of_window)`. When the last
    /// [`PRUNE_INEFFECTIVE_RUN`] consecutive prunes each saved less than
    /// [`PRUNE_INEFFECTIVE_SAVING_PCT`] of the window **while** ctx% rose
    /// across them, the next boundary escalates to `/compact` instead of
    /// another tiny snapshot prune. Bounded to the last few entries.
    prune_effectiveness: std::collections::VecDeque<PruneEffectiveness>,
    /// Generation-tagged root-session shadow brief. An in-flight draft owns
    /// its cancellation token and task; dropping it aborts the utility work so
    /// no stale completion can publish after session teardown.
    shadow_brief: Option<ShadowBriefState>,
    shadow_brief_generation: u64,
    self_improvement_review: Option<crate::assistants::self_improvement::RunningReview>,
    self_improvement_schedule: crate::assistants::self_improvement::ReviewSchedule,
    goal_progress_last_seq: i64,
    /// Latches after the active-goal no-tool idle guard stops automatic
    /// continuation. Cleared when a real user turn or a non-prose/toolful state
    /// gives the agent a fresh chance to progress.
    goal_idle_intervention_pending: bool,
    goal_idle_intervention_code: Option<&'static str>,
    goal_was_active_recently: bool,
    goal_usage_limit_auto_resume_attempts: u8,
    goal_supervision_round: Option<GoalSupervisionRound>,
    /// A goal-supervision swarm spawn was refused (full queue / oversized
    /// prompt) during the current round, leaving a control job leased with no
    /// tracked job to wake the loop. Arms the goal watchdog so a quiescent
    /// session re-runs supervision after the lease TTL and retries.
    goal_refused_spawn_retry_pending: bool,
    /// Count of consecutive rounds whose swarm spawn was (re-)refused. Caps the
    /// retry watchdog at [`GOAL_REFUSED_SPAWN_MAX_RETRIES`] so a permanently
    /// failing refusal (e.g. an oversized control prompt) stops re-waking the
    /// loop forever; reset to 0 when a round spawns cleanly.
    goal_refused_spawn_retry_attempts: u8,
    goal_root_turn: Option<(uuid::Uuid, i64, uuid::Uuid)>,
    goal_scratch: Option<cockpit_host::goal_scratch::GoalScratchRoot>,
    pending_idle_reason: Option<crate::engine::IdleReason>,
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
    /// Session-only prompt-cache retention override (`/longcache`). It stores
    /// user intent only; unsupported active models omit the wire key.
    prompt_cache_retention_override: Option<crate::config::providers::PromptCacheRetention>,
    /// Persisted preference for the active model, mirrored in memory so a
    /// same-model preference write updates request params before the next
    /// config re-resolution reaches the session handle.
    prompt_cache_retention_preference: Option<crate::config::providers::PromptCacheRetention>,
    /// Session-only root delegation recursion override (`/quick`). `None`
    /// defers to layered config; `Some` replaces only the root default
    /// enabled/depth values while preserving allowed-target and max-depth
    /// policy checks.
    delegation_recursion_override: Option<DelegationRecursionOverride>,
    /// One-shot guard for the request-preflight "determinism guard skipped
    /// the rewrite" notice. Surfaced at most once per driver so a model
    /// that keeps mangling control tokens doesn't spam the transcript.
    preflight_guard_logged: bool,
    /// Last active-model refresh failure surfaced to the user. Refresh runs at
    /// every turn start, so identical config errors warn every time but produce
    /// only one transcript notice until a success clears the dedupe key.
    active_model_refresh_failure_notice: Option<String>,
    /// Last active tool-surface refresh failure surfaced to the user. Kept
    /// separate from model refresh so one recurring failure cannot suppress
    /// the other's first transcript notice.
    active_tool_surface_refresh_failure_notice: Option<String>,
    /// One-shot note about session-only Monty tool-surface changes. Appended
    /// to the next ordinary tool result so the model sees cache-neutral
    /// discoverable/disabled changes exactly once.
    pending_monty_tool_nudge: Option<String>,
    active_model_state_generation: u64,
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
    /// interrupt hub). A missing approver skips the prompt, never denies.
    approver: Option<Arc<crate::approval::Approver>>,
    /// Daemon-owned LSP manager, installed by the session worker. Optional so
    /// in-process tests and replay paths can skip advisory LSP cleanly.
    lsp: Option<Arc<crate::daemon::lsp::LspManager>>,
    /// Daemon-owned runtime resource scheduler. Persistent daemons install a
    /// shared handle; ephemeral/test/replay contexts may leave it absent.
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    /// Shared daemon scheduler handle cell. The worker installs the registry's
    /// cell rather than a snapshot so late `set_scheduler` calls are visible.
    daemon_scheduler:
        Option<Arc<std::sync::Mutex<Option<crate::daemon::scheduler::DaemonSchedulerHandle>>>>,
    /// Durable write-scope authority cell, installed by the worker. Held as the
    /// registry's cell so a late `set_write_scope` is visible.
    write_scope: Option<crate::write_scope::WriteScopeSource>,
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
    /// Fixed recursive-spawn depth ceiling.
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
    /// Active-skill ledger for `/skill <name>` handoff tags
    /// (implementation note). Records every skill genuinely
    /// **active in this primary's context** — user-invoked (folded by
    /// [`Self::seed_forced_skill`]) OR auto-injected (folded by
    /// [`Self::maybe_inject_skill`]) — keyed by skill name to its rendered
    /// (`!`-processed, scrubbed) body. When a handoff/report includes
    /// `/skill <name>`, the host expands that skill's instructions + framing
    /// **only if the name is in this set** (validate, don't trust the model);
    /// an absent name renders a model-visible note. The latest body
    /// for a given name wins (a re-invoked / re-injected skill refreshes it).
    active_skills: Vec<(String, String)>,
    /// Per-session set of skill names already **auto-injected** this session
    /// (implementation note, change 4). A skill
    /// auto-injected once stays out of every later auto-selection pass in this
    /// session: it is removed before the utility-model catalog is built, so it
    /// can be neither re-voted nor re-passed by the backstop — never re-paying
    /// its body for a skill the agent already has in context. Distinct from
    /// [`Self::active_skills`] (the handoff-tag expansion set, which also
    /// holds user-`/skill`-invoked bodies — a different intent this exclusion
    /// must not cover): scope is strictly the auto-injection
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
    /// Primary-swap marker is cleared/set only by idle-boundary primary swaps
    /// (`/plan`/`/build`); it is not a model tool-call path.
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
    #[cfg(test)]
    test_fail_next_active_model_session_persist: bool,
    #[cfg(test)]
    test_fail_next_active_model_config_write: bool,
    #[cfg(test)]
    test_fail_next_model_switch_audit_record: bool,
    #[cfg(test)]
    test_fail_next_user_message_event_write: bool,
    #[cfg(test)]
    test_fail_all_user_message_event_writes: bool,
    #[cfg(test)]
    test_reject_next_submission_preflight: bool,
    /// Hermetic compact-utility inference seam. Tests capture invocation mode,
    /// prompt, and revision history without opening a socket.
    #[cfg(test)]
    test_compact_brief_calls: Option<Arc<std::sync::Mutex<Vec<TestCompactBriefCall>>>>,
    #[cfg(test)]
    test_compact_brief_script:
        Option<Arc<std::sync::Mutex<std::collections::VecDeque<TestCompactSample>>>>,
    #[cfg(test)]
    test_compact_model_ref: Option<String>,
    #[cfg(test)]
    test_compaction_apply_trace: Option<Arc<std::sync::Mutex<Vec<&'static str>>>>,
    /// Deterministically force a compaction to fail at prepare or apply so the
    /// `preCompact`/`postCompact` hook control-flow contract can be exercised
    /// (both error paths are genuinely reachable in production — a concurrent
    /// history change makes apply `Stale`, a durable composition failure makes
    /// it `StoreTextArtifacts`, a cancelled/overflowing brief makes prepare
    /// fail — but are not reachable from a black-box unit test).
    #[cfg(test)]
    test_compact_force_failure: Option<CompactForceFailure>,
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

struct ShadowBriefInFlight {
    generation: u64,
    snapshot_history: Vec<Message>,
    snapshot_turns: usize,
    snapshot_tail_turns: usize,
    cancel: tokio_util::sync::CancellationToken,
    handle: tokio::task::JoinHandle<crate::engine::compact_draft::CompactDraftOutcome>,
}

struct ShadowBriefReady {
    generation: u64,
    snapshot_history: Vec<Message>,
    snapshot_turns: usize,
    snapshot_tail_turns: usize,
    brief: String,
    fit_rung: crate::engine::compact_draft::CompactFitRung,
    input_coverage: crate::engine::compact_draft::CompactInputCoverage,
}

#[cfg(test)]
#[derive(Clone)]
struct TestCompactBriefCall {
    purpose: &'static str,
    prompt: String,
    history: Vec<Message>,
    attempt: u8,
    fit_rung: crate::engine::compact_draft::CompactFitRung,
}

/// Which compaction stage a test forces to fail (see
/// `Driver::test_compact_force_failure`).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::engine::driver) enum CompactForceFailure {
    Prepare,
    Apply,
}

#[cfg(test)]
#[derive(Clone)]
enum TestCompactSample {
    Success(String),
    Cancelled,
    Error {
        message: String,
        status: Option<u16>,
        typed_timeout: bool,
    },
}

enum ShadowBriefState {
    InFlight(ShadowBriefInFlight),
    Ready(ShadowBriefReady),
}

impl Drop for Driver {
    fn drop(&mut self) {
        if let Some(ShadowBriefState::InFlight(task)) = &self.shadow_brief {
            task.cancel.cancel();
            task.handle.abort();
        }
        if let Some(review) = &self.self_improvement_review {
            review.abort();
        }
    }
}

/// Whether a subagent/child report is a HOST-generated failure sentinel. The
/// harness formats every failed run as `format!("Error: {e}")`, so this is the
/// single shared classifier for that sentinel — used by both the driver and the
/// noninteractive delegation paths so a child's success/failure is judged by one
/// consistent rule rather than several subtly different inline `starts_with`
/// checks. It matches the exact host prefix (`"Error: "`, after any leading
/// whitespace); a completed child whose report legitimately begins that way is a
/// residual false positive that only true execution-provenance would remove.
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

#[derive(Debug, Clone, Default)]
struct DelegationConfinement {
    lock_identity: Option<String>,
    write_scope: Option<std::path::PathBuf>,
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
    task_provider_item_id: Option<String>,
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
    task_provider_item_id: Option<&str>,
    task_function_call_id: Option<&str>,
    label: &str,
    report: &str,
    partial_progress: Option<&DelegationPartialProgress>,
) -> serde_json::Value {
    let task_identity = task_call_id.map(|call_id| {
        crate::engine::task_identity::TaskProviderIdentity::for_task_call(
            call_id,
            task_provider_item_id,
            task_function_call_id,
        )
    });
    let mut data = serde_json::json!({
        "child_agent": child_agent,
        "task_call_id": task_call_id,
        "label": label,
        "report": report,
        "provider_item_id": task_identity
            .as_ref()
            .and_then(|identity| identity.provider_item_id.clone()),
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
    data["model_trusted"] = serde_json::json!(model.is_trusted());
    data["routing"] = model.routing_metadata_json(None);
    data
}

#[derive(Debug, Clone)]
pub(in crate::engine::driver) struct ChildRoutingMetadata {
    pub(in crate::engine::driver) provider: String,
    pub(in crate::engine::driver) model: String,
    pub(in crate::engine::driver) model_trusted: bool,
    pub(in crate::engine::driver) routing: serde_json::Value,
}

impl ChildRoutingMetadata {
    pub(in crate::engine::driver) fn from_model(model: &crate::engine::model::Model) -> Self {
        Self::from_model_with_fallback_decision(model, None)
    }

    pub(in crate::engine::driver) fn from_model_with_fallback_decision(
        model: &crate::engine::model::Model,
        fallback_decision: Option<&crate::engine::agent::BackupFallbackDecision>,
    ) -> Self {
        let mut routing = model.routing_metadata_json_with_fallback_decision(
            None,
            fallback_decision
                .map(|decision| decision.routing_value())
                .unwrap_or("none"),
        );
        if let Some(decision) = fallback_decision {
            routing["fallback_tried"] = serde_json::json!(decision.fallback_tried);
        }
        Self {
            provider: model.provider_id().to_string(),
            model: model.model_id_ref().to_string(),
            model_trusted: model.is_trusted(),
            routing,
        }
    }

    pub(in crate::engine::driver) fn from_parent_model(
        model: &crate::engine::model::Model,
    ) -> Self {
        Self::from_model(model)
    }

    pub(in crate::engine::driver) fn with_fallback_decision(
        mut self,
        fallback_decision: Option<&crate::engine::agent::BackupFallbackDecision>,
    ) -> Self {
        if let Some(decision) = fallback_decision {
            self.routing["fallback_decision"] = serde_json::json!(decision.routing_value());
            self.routing["fallback_tried"] = serde_json::json!(decision.fallback_tried);
        }
        self
    }

    pub(in crate::engine::driver) fn turn_event(
        &self,
        child: impl Into<String>,
        task_call_id: impl Into<String>,
        label: impl Into<String>,
    ) -> TurnEvent {
        TurnEvent::SubagentRouting {
            task_call_id: task_call_id.into(),
            label: label.into(),
            child: child.into(),
            provider: self.provider.clone(),
            model: self.model.clone(),
            model_trusted: self.model_trusted,
            routing: self.routing.clone(),
        }
    }
}

fn with_child_routing_metadata(
    mut data: serde_json::Value,
    routing: &ChildRoutingMetadata,
) -> serde_json::Value {
    data["provider"] = serde_json::json!(routing.provider);
    data["model"] = serde_json::json!(routing.model);
    data["model_trusted"] = serde_json::json!(routing.model_trusted);
    data["routing"] = routing.routing.clone();
    data
}

fn subagent_routing_event_data(
    child: &str,
    task_call_id: &str,
    label: &str,
    routing: &ChildRoutingMetadata,
) -> serde_json::Value {
    with_child_routing_metadata(
        serde_json::json!({
            "child_agent": child,
            "task_call_id": task_call_id,
            "label": label,
        }),
        routing,
    )
}

/// Inbound channel capacity for job events / commands. Generous; job
/// lifecycle traffic is tiny.
const JOB_CHANNEL_CAPACITY: usize = 256;

impl Driver {
    async fn emit_subagent_routing_amend(
        &self,
        tx: &mpsc::Sender<TurnEvent>,
        child_agent: &str,
        task_call_id: &str,
        label: &str,
        routing: &ChildRoutingMetadata,
    ) {
        if let Err(e) = self
            .session
            .record_event_with_config(
                crate::db::session_log::SessionEventKind::SubagentRouting,
                Some(child_agent),
                Some(task_call_id),
                &self.config,
                // `self.redact` is the session's PRE-POLICY table (it is what the
                // driver hands `Model::for_provider` as the session table), so a
                // routing label / task-id carrying a session-table literal
                // journals when the routed child model is trusted (F3).
                self.redact.as_ref(),
                &subagent_routing_event_data(child_agent, task_call_id, label, routing),
            )
            .await
        {
            tracing::warn!(error = %e, "record subagent_routing event failed");
        }
        let _ = tx
            .send(routing.turn_event(
                child_agent.to_string(),
                task_call_id.to_string(),
                label.to_string(),
            ))
            .await;
    }

    async fn note_backup_fallback_for_active_frame(
        &mut self,
        fallback: crate::engine::agent::BackupFallbackDecision,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        let amend = self.stack.last_mut().and_then(|frame| {
            frame.fallback_decision = Some(fallback.clone());
            frame.answering.as_ref().map(|pending| {
                (
                    frame.agent.name.clone(),
                    pending.call_id.clone(),
                    ChildRoutingMetadata::from_model_with_fallback_decision(
                        &frame.agent.model,
                        Some(&fallback),
                    ),
                )
            })
        });

        if let Some((child_agent, task_call_id, routing)) = amend {
            self.emit_subagent_routing_amend(tx, &child_agent, &task_call_id, "default", &routing)
                .await;
        }
    }

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
            config: self.config.clone(),
            agent: self.stack[0].agent.clone(),
            write_scope: self.write_scope.clone(),
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
            config: self.config.clone(),
            stack: self
                .stack
                .iter()
                .map(|frame| AgentSession {
                    agent: frame.agent.clone(),
                    agent_instance_id: frame.agent_instance_id,
                    endpoint_generation: frame.endpoint_generation,
                    history: frame.history.clone(),
                    queue_target: frame.queue_target.clone(),
                    answering: frame.answering.clone(),
                    deferred_log: crate::engine::deferred::DeferredLog::new(),
                    fallback_decision: frame.fallback_decision.clone(),
                    recovery_activation: frame.recovery_activation.clone(),
                    late_user_steer_permit: None,
                    // This clone represents work already owned by the foreground
                    // frame, whose reservation remains held there. New children
                    // admitted by the clone use the shared registry below.
                    _vnext_child_admission: None,
                    // Carry the child's continuation budget so a cloned frame
                    // cannot silently reset its 8-cap.
                    stop_gate: frame.stop_gate.clone(),
                })
                .collect(),
            // The foreground driver owns the durable steer claims.  A
            // background clone must not inherit, acknowledge, or reroute them.
            pending_late_user_steer_acks: std::collections::HashMap::new(),
            late_steer_continuation_outcome: None,
            recovered_interactive_continuations: std::collections::HashMap::new(),
            recovered_interactive_late_steer_continuations: std::collections::HashMap::new(),
            assistant_identity_prefix: self.assistant_identity_prefix.clone(),
            time_injection_interval_minutes: self.time_injection_interval_minutes,
            loop_guard_threshold: self.loop_guard_threshold,
            max_primary_rounds: self.max_primary_rounds,
            delegation_retry_budget_remaining: self.delegation_retry_budget_remaining,
            allow_unbounded_schedule_loops: self.allow_unbounded_schedule_loops,
            unbounded_schedule_loops_approved: self.unbounded_schedule_loops_approved,
            schedule,
            noninteractive_delegations: NoninteractiveDelegationRegistry::default(),
            vnext_child_admissions: self.vnext_child_admissions.clone(),
            vnext_local_installation_resolver: self.vnext_local_installation_resolver.clone(),
            job_event_rx,
            job_cmd_rx,
            noninteractive_complete_tx: self.noninteractive_complete_tx.clone(),
            noninteractive_complete_rx,
            pending_noninteractive_completions: std::collections::VecDeque::new(),
            noninteractive_jobs: std::collections::HashMap::new(),
            // A rebuild installs a fresh schedule authority + event channel, so
            // it starts with no tracked swarm children (mirrors
            // `noninteractive_jobs`).
            swarm_subagents: std::collections::HashMap::new(),
            appended_hints: self.appended_hints.clone(),
            emitted_command_capability_notices: self.emitted_command_capability_notices.clone(),
            prune_watermark: self.prune_watermark.clone(),
            auto_compact_gate: self.auto_compact_gate.clone(),
            prune_effectiveness: self.prune_effectiveness.clone(),
            shadow_brief: None,
            shadow_brief_generation: 0,
            self_improvement_review: None,
            self_improvement_schedule: crate::assistants::self_improvement::ReviewSchedule::default(
            ),
            goal_progress_last_seq: self.goal_progress_last_seq,
            goal_idle_intervention_pending: false,
            goal_idle_intervention_code: None,
            goal_was_active_recently: self.goal_was_active_recently,
            goal_usage_limit_auto_resume_attempts: self.goal_usage_limit_auto_resume_attempts,
            goal_supervision_round: self.goal_supervision_round.clone(),
            // A fork never runs the root's goal watchdog, so it carries no
            // pending refused-spawn retry.
            goal_refused_spawn_retry_pending: false,
            goal_refused_spawn_retry_attempts: 0,
            goal_root_turn: self.goal_root_turn,
            // Forks never own or clean the root driver's supervised-goal scratch.
            goal_scratch: None,
            pending_idle_reason: self.pending_idle_reason.clone(),
            interrupts: self.interrupts.clone(),
            skills_no_utility_model_logged: self.skills_no_utility_model_logged,
            injection_no_scan_logged: self.injection_no_scan_logged,
            preflight_override: self.preflight_override,
            prompt_cache_retention_override: self.prompt_cache_retention_override,
            prompt_cache_retention_preference: self.prompt_cache_retention_preference,
            delegation_recursion_override: self.delegation_recursion_override,
            preflight_guard_logged: self.preflight_guard_logged,
            active_model_refresh_failure_notice: self.active_model_refresh_failure_notice.clone(),
            active_tool_surface_refresh_failure_notice: self
                .active_tool_surface_refresh_failure_notice
                .clone(),
            pending_monty_tool_nudge: self.pending_monty_tool_nudge.clone(),
            active_model_state_generation: self.active_model_state_generation,
            current_lifecycle_turn_id: self.current_lifecycle_turn_id.clone(),
            cancel_current: self.cancel_current.clone(),
            approver: self.approver.clone(),
            lsp: self.lsp.clone(),
            resource_scheduler: self.resource_scheduler.clone(),
            daemon_scheduler: self.daemon_scheduler.clone(),
            write_scope: self.write_scope.clone(),
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
            #[cfg(test)]
            test_fail_next_active_model_session_persist: self
                .test_fail_next_active_model_session_persist,
            #[cfg(test)]
            test_fail_next_active_model_config_write: self.test_fail_next_active_model_config_write,
            #[cfg(test)]
            test_fail_next_model_switch_audit_record: self.test_fail_next_model_switch_audit_record,
            #[cfg(test)]
            test_fail_next_user_message_event_write: self.test_fail_next_user_message_event_write,
            #[cfg(test)]
            test_fail_all_user_message_event_writes: self.test_fail_all_user_message_event_writes,
            #[cfg(test)]
            test_reject_next_submission_preflight: self.test_reject_next_submission_preflight,
            #[cfg(test)]
            test_compact_brief_calls: self.test_compact_brief_calls.clone(),
            #[cfg(test)]
            test_compact_brief_script: self.test_compact_brief_script.clone(),
            #[cfg(test)]
            test_compact_model_ref: self.test_compact_model_ref.clone(),
            #[cfg(test)]
            test_compaction_apply_trace: self.test_compaction_apply_trace.clone(),
            #[cfg(test)]
            test_compact_force_failure: self.test_compact_force_failure,
            redaction_scan_environment_override: self.redaction_scan_environment_override,
            redaction_scan_dotenv_override: self.redaction_scan_dotenv_override,
            redaction_scan_ssh_keys_override: self.redaction_scan_ssh_keys_override,
            redaction_unsupported_notified: self.redaction_unsupported_notified.clone(),
        }
    }

    async fn assign_todos_to_task(
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
        let assigned = match self
            .session
            .db
            .assign_task_todos(self.session.id, todo_ids, task_call_id, label, child_agent)
            .await
        {
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
            "\nEnd your final report with a fenced `todo_delta` JSON object: {\"todos\":[{\"id\":\"...\",\"status\":\"completed|in_progress|pending|cancelled\",\"summary\":\"one line\",\"notes\":[{\"kind\":\"summary|finding|decision|artifact|blocker|handoff\",\"body\":\"...\"}],\"suggested_edits\":[\"...\"]}]}.\n",
        );
        format!("{brief}{block}")
    }

    async fn reconcile_todo_delta(
        &self,
        task_call_id: &str,
        label: &str,
        child_agent: &str,
        report: &str,
        failed: bool,
    ) -> String {
        let state = if failed { "error" } else { "completed" };
        if let Err(e) = self
            .session
            .db
            .finish_task_assignment(self.session.id, task_call_id, label, state, None)
            .await
        {
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
                    if let Err(e) = self
                        .session
                        .db
                        .update_task_todo(self.session.id, id, status, None, None, summary)
                        .await
                    {
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
                            .await
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
                            .await
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
            config: crate::daemon::session_worker::SessionConfigHandle::detached_default(),
            agent: root.clone(),
            // Installed later by `set_write_scope_source`; the authority's copy
            // is updated through the same setter.
            write_scope: None,
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
        let initial_tools = root.tools.clone();
        session.set_active_tool_names(
            initial_tools.names(),
            crate::engine::tool::Capability::SandboxEscalate
                .enabled(&crate::agents::PostureResolution::legacy(root.llm_mode)),
        );
        Self {
            session,
            locks,
            redact,
            cwd,
            config: crate::daemon::session_worker::SessionConfigHandle::detached_default(),
            stack: vec![AgentSession {
                queue_target: crate::engine::message::QueueTarget::root(root.name.clone()),
                agent: root,
                agent_instance_id: None,
                endpoint_generation: None,
                history: Vec::new(),
                answering: None,
                deferred_log: crate::engine::deferred::DeferredLog::new(),
                fallback_decision: None,
                recovery_activation: None,
                late_user_steer_permit: None,
                _vnext_child_admission: None,
                stop_gate: crate::engine::agent::hooks::StopGateState::default(),
            }],
            pending_late_user_steer_acks: std::collections::HashMap::new(),
            late_steer_continuation_outcome: None,
            recovered_interactive_continuations: std::collections::HashMap::new(),
            recovered_interactive_late_steer_continuations: std::collections::HashMap::new(),
            assistant_identity_prefix: None,
            time_injection_interval_minutes: 5,
            loop_guard_threshold: crate::config::extended::MIN_LOOP_GUARD_THRESHOLD,
            max_primary_rounds: 0,
            delegation_retry_budget_remaining: DELEGATION_RETRY_BUDGET_PER_TURN,
            allow_unbounded_schedule_loops: false,
            unbounded_schedule_loops_approved: false,
            schedule,
            noninteractive_delegations: NoninteractiveDelegationRegistry::default(),
            vnext_child_admissions: VnextChildAdmissionRegistry::default(),
            vnext_local_installation_resolver:
                crate::agents::LocalInstallationResolver::no_installations(),
            job_event_rx,
            job_cmd_rx,
            noninteractive_complete_tx,
            noninteractive_complete_rx,
            pending_noninteractive_completions: std::collections::VecDeque::new(),
            noninteractive_jobs: std::collections::HashMap::new(),
            swarm_subagents: std::collections::HashMap::new(),
            appended_hints: std::collections::HashSet::new(),
            emitted_command_capability_notices: HashSet::new(),
            prune_watermark: std::collections::HashMap::new(),
            auto_compact_gate: AutoCompactGate::default(),
            prune_effectiveness: std::collections::VecDeque::new(),
            shadow_brief: None,
            shadow_brief_generation: 0,
            self_improvement_review: None,
            self_improvement_schedule: crate::assistants::self_improvement::ReviewSchedule::default(
            ),
            goal_progress_last_seq: -1,
            goal_idle_intervention_pending: false,
            goal_idle_intervention_code: None,
            goal_was_active_recently: false,
            goal_usage_limit_auto_resume_attempts: 0,
            goal_supervision_round: None,
            goal_refused_spawn_retry_pending: false,
            goal_refused_spawn_retry_attempts: 0,
            goal_root_turn: None,
            goal_scratch: None,
            pending_idle_reason: None,
            interrupts: Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            skills_no_utility_model_logged: false,
            injection_no_scan_logged: false,
            preflight_override: None,
            prompt_cache_retention_override: None,
            prompt_cache_retention_preference: None,
            delegation_recursion_override: None,
            preflight_guard_logged: false,
            active_model_refresh_failure_notice: None,
            active_tool_surface_refresh_failure_notice: None,
            pending_monty_tool_nudge: None,
            active_model_state_generation: 0,
            current_lifecycle_turn_id: None,
            cancel_current: Arc::new(std::sync::Mutex::new(None)),
            approver: None,
            lsp: None,
            resource_scheduler: None,
            daemon_scheduler: None,
            write_scope: None,
            deleg_shrinks: std::collections::HashMap::new(),
            model_override: None,
            swarm_max_depth: crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH,
            swarm_max_concurrency: crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_CONCURRENCY,
            rehydrated_ctx_estimate: None,
            skill_pairs: Vec::new(),
            active_skills: Vec::new(),
            auto_injected_skills: std::collections::HashSet::new(),
            pending_swap_marker_from: None,
            tool_call_owner: std::collections::HashMap::new(),
            tandem_set: crate::engine::schedule::TandemSet::default(),
            #[cfg(test)]
            test_providers_override: None,
            #[cfg(test)]
            test_fail_next_active_model_session_persist: false,
            #[cfg(test)]
            test_fail_next_active_model_config_write: false,
            #[cfg(test)]
            test_fail_next_model_switch_audit_record: false,
            #[cfg(test)]
            test_fail_next_user_message_event_write: false,
            #[cfg(test)]
            test_fail_all_user_message_event_writes: false,
            #[cfg(test)]
            test_reject_next_submission_preflight: false,
            #[cfg(test)]
            test_compact_brief_calls: Some(Arc::new(std::sync::Mutex::new(Vec::new()))),
            #[cfg(test)]
            test_compact_brief_script: Some(Arc::new(std::sync::Mutex::new(
                std::collections::VecDeque::new(),
            ))),
            #[cfg(test)]
            test_compact_model_ref: None,
            #[cfg(test)]
            test_compaction_apply_trace: None,
            #[cfg(test)]
            test_compact_force_failure: None,
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

    fn refresh_wire_api_for_turn(&mut self) {
        let providers = match self.live_providers_config() {
            Ok(providers) => providers,
            Err(error) => {
                tracing::warn!(error = %error, "providers config unavailable while refreshing wire_api");
                return;
            }
        };
        for frame in &self.stack {
            frame.agent.model.refresh_wire_api_config(&providers);
        }
        if let Some(model) = &self.model_override {
            model.refresh_wire_api_config(&providers);
        }
    }

    fn active_frame_index(&self) -> Option<usize> {
        self.stack.len().checked_sub(1)
    }

    /// Refresh the frame that is actually running at the start of each turn.
    ///
    /// The model binding and the tool surface are refreshed as separate steps.
    /// The model step re-resolves the active frame's current provider/model
    /// pair from layered config without changing the frame's pinned identity.
    /// The tool-surface step then reloads the same active agent name so live
    /// config and custom subagent files update the `task` schema every turn.
    /// Parked parent frames, tandem models, and `model_override` remain pinned.
    async fn refresh_active_frame_for_turn(&mut self, tx: &mpsc::Sender<TurnEvent>) {
        let Some(active_idx) = self.active_frame_index() else {
            return;
        };
        self.schedule
            .set_agent(self.stack[active_idx].agent.clone());
        // Modes AC5 turn-consumption: consume any pending per-node session
        // override for the active node into effect at this turn boundary. The
        // llm-mode axis is applied per-frame (below); the sandbox axis is
        // applied through the session posture (see the method) — verification
        // and question axes are consumed into the node's effective override and
        // await their resolver-site application (documented follow-on).
        let consumed = self.consume_active_node_override_for_turn(active_idx).await;
        let model_pin = self
            .refresh_active_model_for_turn(active_idx, consumed, tx)
            .await;
        self.refresh_active_tool_surface_for_turn(active_idx, model_pin, tx)
            .await;
        if self.prompt_cache_retention_override.is_some() {
            self.emit_longcache_state(tx).await;
        }
    }

    /// Consume any pending per-node session override for the active node into
    /// its effective override at this turn boundary (modes AC5 "second
    /// transaction": pending is merged into effective and cleared; the revision
    /// is unchanged). Returns the model/mode axes to apply to this frame's next
    /// turn.
    ///
    /// Application status by axis:
    ///  - `model` and `mode`: applied per-frame by the caller (returned here) —
    ///    isolated to the active frame, so an ancestor or sibling frame is never
    ///    affected. The daemon already re-validated the model choice as
    ///    hard-compatible before it was stored.
    ///  - `sandbox`: applied to the session posture below. This is session-scoped
    ///    in the current architecture; true per-node sandbox isolation across
    ///    concurrent delegated turns needs a node-aware read seam at
    ///    `turn_toolbox` (documented follow-on). Only applied when the node
    ///    actually carries a sandbox override, so the no-override path leaves
    ///    existing sandbox behavior untouched.
    ///  - `verification`: consumed into the node's effective override and
    ///    surfaced in the snapshot; runtime enforcement (candidate execution) is
    ///    out of scope for this prompt.
    ///  - `question`: consumed here and applied at the decision resolver
    ///    (`AgentTreeLifecycle::resolved_question_policy`).
    async fn consume_active_node_override_for_turn(
        &mut self,
        active_idx: usize,
    ) -> ConsumedNodeOverride {
        let Some(node_id) = self
            .stack
            .get(active_idx)
            .and_then(|frame| frame.agent_instance_id)
        else {
            return ConsumedNodeOverride::default();
        };
        let now = chrono::Utc::now().timestamp_millis();
        let effective = match self
            .session
            .db
            .consume_pending_agent_override(self.session.id, node_id, now)
            .await
        {
            Ok(Some(effective)) => effective,
            Ok(None) => return ConsumedNodeOverride::default(),
            Err(error) => {
                tracing::warn!(
                    %node_id,
                    error = %error,
                    "consuming per-node session override failed; keeping current settings"
                );
                return ConsumedNodeOverride::default();
            }
        };
        if let Some(sandbox) = effective
            .sandbox
            .as_deref()
            .and_then(crate::daemon::agent_session_override::sandbox_from_label)
        {
            self.session.set_sandbox_mode(sandbox);
        }
        ConsumedNodeOverride {
            llm_mode: effective
                .llm_mode
                .as_deref()
                .and_then(crate::daemon::agent_session_override::mode_from_label),
            model: effective
                .model
                .map(|binding| (binding.provider, binding.model)),
        }
    }

    async fn refresh_active_model_for_turn(
        &mut self,
        active_idx: usize,
        // Per-node session override axes consumed at this turn boundary (modes
        // AC5): when present they replace the config-resolved model/mode for THIS
        // frame only, so an ancestor or sibling frame is never affected. The
        // daemon already authorized them (non-escalating mode; hard-compatible
        // model).
        consumed: ConsumedNodeOverride,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Option<Arc<crate::engine::model::Model>> {
        let running = self.stack[active_idx].agent.model.clone();
        // A model rebind overrides the frame's running provider/model; otherwise
        // the running model is re-resolved from live config as before.
        let (provider, model) = match &consumed.model {
            Some((provider, model)) => (provider.clone(), model.clone()),
            None => (
                running.provider_id().to_string(),
                running.model_id_ref().to_string(),
            ),
        };
        let old_llm_mode = self.stack[active_idx].agent.llm_mode;
        match self.build_live_model_for_running(&running, &provider, &model) {
            Ok(new_model) => {
                let llm_mode = consumed
                    .llm_mode
                    .unwrap_or_else(|| self.effective_llm_mode_for(&provider, &model));
                let new_model = Arc::new(new_model);
                // Pin the rebound model so the subsequent tool-surface rebuild
                // cannot let a frontmatter `model:` revert it (modes AC5). Only
                // pinned when this frame actually carries a model override.
                let model_pin = consumed.model.is_some().then(|| new_model.clone());
                let selection = self.active_selection_for_model(&new_model);
                let refreshed =
                    self.replace_frame_model(active_idx, new_model, llm_mode, &selection);
                self.stack[active_idx].agent = Arc::new(refreshed);
                self.schedule
                    .set_agent(self.stack[active_idx].agent.clone());
                if old_llm_mode != llm_mode {
                    let _ = tx.send(TurnEvent::LlmModeChanged { mode: llm_mode }).await;
                }
                self.active_model_refresh_failure_notice = None;
                model_pin
            }
            Err(e) => {
                tracing::warn!(
                    provider,
                    model,
                    error = %e,
                    "refreshing active model from config failed"
                );
                let notice = format!(
                    "Refreshing the active model from config failed — {e:#}. \
                     Keeping the previous model active."
                );
                if self.active_model_refresh_failure_notice.as_deref() != Some(notice.as_str()) {
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: notice.clone(),
                        })
                        .await;
                    self.active_model_refresh_failure_notice = Some(notice);
                }
                None
            }
        }
    }

    async fn refresh_active_tool_surface_for_turn(
        &mut self,
        active_idx: usize,
        // The rebound model to pin as `model_override` across the rebuild so a
        // frontmatter `model:` cannot revert a per-node model override (modes
        // AC5). `None` outside a model override — normal rebuild precedence.
        model_pin: Option<Arc<crate::engine::model::Model>>,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        let model = self.stack[active_idx].agent.model.clone();
        let llm_mode = self.stack[active_idx].agent.llm_mode;
        let selection = self.active_selection_for_model(&model);
        match self.try_rebuild_frame_with_model(
            active_idx,
            model.clone(),
            llm_mode,
            &selection,
            model_pin.clone(),
        ) {
            Ok(rebuilt) => {
                self.stack[active_idx].agent = Arc::new(rebuilt);
                self.schedule
                    .set_agent(self.stack[active_idx].agent.clone());
                self.active_tool_surface_refresh_failure_notice = None;
            }
            Err(e) if active_idx == 0 => {
                tracing::warn!(error = %e, "refreshing root tool surface from config fell back to default Build");
                let rebuilt = self
                    .rebuild_frame_with_model(active_idx, model, llm_mode, &selection, model_pin);
                self.stack[active_idx].agent = Arc::new(rebuilt);
                self.schedule
                    .set_agent(self.stack[active_idx].agent.clone());
                self.active_tool_surface_refresh_failure_notice = None;
            }
            Err(e) => {
                tracing::warn!(
                    agent = %self.stack[active_idx].agent.name,
                    error = %e,
                    "refreshing active tool surface from config failed"
                );
                let notice = format!(
                    "Refreshing this agent's tool surface from config failed — {e:#}. \
                     Keeping the previous tool surface."
                );
                if self.active_tool_surface_refresh_failure_notice.as_deref()
                    != Some(notice.as_str())
                {
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: notice.clone(),
                        })
                        .await;
                    self.active_tool_surface_refresh_failure_notice = Some(notice);
                }
            }
        }
    }

    async fn load_max_primary_rounds_for_turn(&self) -> u32 {
        // Read from the turn-pinned config snapshot rather than re-reading disk
        // (`engine-config-snapshot-adoption`).
        self.config.extended().max_primary_rounds
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
        // The redact config comes from the turn-pinned snapshot; only the
        // table build (which scans .env / ssh keys on disk) stays on the
        // blocking pool (`engine-config-snapshot-adoption`).
        let mut cfg = self.config.extended().redact;
        if let Some(v) = scan_environment_override {
            cfg.scan_environment = v;
        }
        if let Some(v) = scan_dotenv_override {
            cfg.scan_dotenv = v;
        }
        if let Some(v) = scan_ssh_keys_override {
            cfg.scan_ssh_keys = v;
        }
        let store = self.session.credential_store().ok();
        match tokio::task::spawn_blocking(move || match store.as_ref() {
            Some(store) => {
                RedactionTable::build_with_env_and_credential_store(&cfg, &cwd, &session_env, store)
            }
            None => RedactionTable::build_with_env_and_store(&cfg, &cwd, &session_env),
        })
        .await
        {
            Ok(Ok(new_table)) => {
                // J2: route the per-turn refresh through the hub so it unions the
                // disk scan onto the LATEST shared table under the same
                // `redaction_table_write_lock` as sealed adoption. `self.redact`
                // is only a COPY that a mid-turn `seal_redaction_with_identity`
                // never updates; unioning onto it and persisting here (the old
                // behavior) could overwrite the durable adopted table without a
                // sealed literal committed this turn (decision 10.1). The hub
                // persists-before-swap and returns the committed table.
                let table = match self
                    .interrupts
                    .refresh_union_redaction(&self.session, &new_table)
                    .await
                {
                    Ok(Some(table)) => table,
                    Ok(None) => {
                        // Detached hub (standalone shim / tests): no shared table
                        // to serialize against, so union onto the driver's own
                        // copy and persist directly — still persist-before-swap.
                        let table = match self.redact.union(&new_table) {
                            Ok(table) => Arc::new(table),
                            Err(error) => {
                                tracing::warn!(error = %error, "unioning redaction table failed");
                                Arc::new(new_table)
                            }
                        };
                        if let Err(error) = self.session.persist_redaction_table(&table) {
                            // Fail-closed: do not advance `self.redact` ahead of
                            // the durable table when the persist did not commit.
                            tracing::warn!(error = %error, "persisting redaction table failed");
                            return;
                        }
                        table
                    }
                    Err(error) => {
                        // The committed table is left live under the hub lock;
                        // skip this refresh rather than clobber it.
                        tracing::warn!(error = %error, "refreshing redaction table under hub lock failed");
                        return;
                    }
                };
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

    pub fn set_assistant_identity_prefix(&mut self, prefix: Option<String>) {
        self.assistant_identity_prefix = prefix;
    }

    /// Install the daemon-owned local installation mapping captured at root
    /// construction.  It is intentionally an explicit input rather than a
    /// lookup by display name, and every delegated spawn reuses this snapshot.
    pub fn set_vnext_local_installation_resolver(
        &mut self,
        resolver: crate::agents::LocalInstallationResolver,
    ) {
        self.vnext_local_installation_resolver = resolver;
    }

    pub fn set_lsp_manager(&mut self, lsp: Arc<crate::daemon::lsp::LspManager>) {
        self.lsp = Some(lsp);
    }

    /// Install the session's config reader. The worker calls this before the
    /// loop starts so the driver and every `ToolCtx` it builds read config
    /// through the generationed snapshot rather than from disk
    /// (`engine-config-snapshot-adoption`).
    pub fn set_config_handle(
        &mut self,
        config: crate::daemon::session_worker::SessionConfigHandle,
    ) {
        self.schedule.set_config_handle(config.clone());
        self.config = config;
        self.refresh_prompt_cache_retention_from_session();
    }

    /// Refresh the driver's config handle from the layered config on disk for
    /// its cwd. Tests that write config into the driver's tempdir and then
    /// exercise config-dependent behavior call this so the change is observed
    /// through the snapshot handle exactly as a worker re-resolution would.
    #[cfg(test)]
    pub(crate) fn refresh_config_from_disk_for_tests(&mut self) {
        let cwd = self.cwd.clone();
        self.set_config_handle(
            crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(&cwd),
        );
    }

    /// The session config reader, re-pinned to the current generation for a
    /// fresh turn. Callers use this at a turn boundary. The async-job authority
    /// is refreshed too so a loop/timer spawned this turn reads the same view.
    fn repin_config_for_turn(&mut self) {
        self.config = self.config.repin();
        self.schedule.set_config_handle(self.config.clone());
    }

    pub fn set_resource_scheduler(
        &mut self,
        scheduler: Arc<crate::engine::resource_scheduler::ResourceScheduler>,
    ) {
        self.resource_scheduler = Some(scheduler);
    }

    pub fn set_daemon_scheduler_source(
        &mut self,
        scheduler: Arc<std::sync::Mutex<Option<crate::daemon::scheduler::DaemonSchedulerHandle>>>,
    ) {
        self.daemon_scheduler = Some(scheduler);
    }

    pub fn set_write_scope_source(&mut self, write_scope: crate::write_scope::WriteScopeSource) {
        self.write_scope = Some(write_scope.clone());
        self.schedule.set_write_scope_source(write_scope);
    }

    /// Resolve the installed coordinator, if any.
    pub fn write_scope_coordinator(
        &self,
    ) -> Option<std::sync::Arc<crate::write_scope::WriteScopeCoordinator>> {
        self.write_scope
            .as_ref()
            .and_then(|cell| crate::sync::lock_or_recover(cell).clone())
    }

    pub fn daemon_scheduler_handle(
        &self,
    ) -> Option<crate::daemon::scheduler::DaemonSchedulerHandle> {
        let scheduler = self.daemon_scheduler.as_ref()?;
        crate::sync::lock_or_recover(scheduler).clone()
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
    pub async fn rehydrate_root_if_empty(
        &mut self,
        root_agent: &str,
    ) -> Result<Option<crate::engine::rehydrate::Rehydrated>> {
        self.rehydrate_root_if_empty_with_policy(
            root_agent,
            crate::engine::rehydrate::RehydratePolicy::heal(),
        )
        .await
    }

    pub async fn rehydrate_root_if_empty_with_policy(
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
        let Some(rehydrated) =
            crate::engine::rehydrate::rehydrate_session_with_policy_and_redaction(
                &self.session.db,
                self.session.id,
                root_agent,
                policy,
                self.redact.clone(),
            )
            .await?
        else {
            return Ok(None);
        };
        // Restore the rebuilt (pruned) history + the depth-1 prune
        // watermark so auto-prune's short-circuit stays consistent.
        self.stack[0].history = rehydrated.history.clone();
        self.restore_skill_pairs_after_rehydrate(root_agent).await;
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
        self.load_compaction_shadow_from_store().await;
        Ok(Some(rehydrated))
    }

    /// Persist the foreground root agent's current prune state to the
    /// durable ledger (implementation note). Called at
    /// every inference boundary (after each turn) and on every `/prune`, so
    /// a resumed session can re-derive the exact pruned form even after an
    /// unclean daemon kill. Best-effort: a DB failure is logged, never
    /// propagated — auditing/continuity must not break a live turn.
    ///
    /// Reuses the durable projection-owner set for the prune-boundary entries
    /// in [`prune::capture_ledger_with_prune_boundary_calls`], so a tool body
    /// that merely resembles an artifact frame cannot forge an elision into
    /// the resumable ledger.
    async fn persist_prune_ledger(&self) {
        // Only the root frame's history is the resumable context.
        let history = &self.stack[0].history;
        let watermark = self.prune_watermark.get(&1).copied().unwrap_or(0);
        let projection_calls = match self
            .session
            .db
            .text_artifact_projection_call_ids(self.session.id)
            .await
        {
            Ok(calls) => calls,
            Err(error) => {
                // Do not overwrite a prior durable ledger with a text-shaped
                // guess when the owner-state read fails. The next successful
                // boundary will reconcile it from the database.
                tracing::warn!(%error, "loading durable text-artifact projection ids for prune ledger failed");
                return;
            }
        };
        let ledger = prune::capture_ledger_with_prune_boundary_calls(
            history,
            watermark,
            &projection_calls.prune_boundary_calls,
        );
        if let Err(e) = self
            .session
            .db
            .save_prune_ledger(self.session.id, &ledger)
            .await
        {
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
    pub fn set_max_primary_rounds(&mut self, max_primary_rounds: u32) {
        self.max_primary_rounds = max_primary_rounds;
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
                "Skill `{}` (auto-selected, package directory: {}):\n\n{}\n\n---\n\n",
                skill.name, skill.package_dir, skill.body
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
        let (extended, providers) = self.config.configs();
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
            Some(root.agent.model.shutdown_gate()),
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
                    match self.injection_override(rating, tx).await {
                        Ok(allowed) => allowed,
                        Err(e) if crate::engine::interrupt::is_parked(&e) => false,
                        Err(e) => {
                            tracing::warn!(error = %e, "prompt-injection override failed");
                            false
                        }
                    }
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
    ) -> Result<crate::daemon::proto::ResolveResponse> {
        Ok(crate::engine::interrupt::raise_and_wait_with_agent_tree(
            &self.session.db,
            &self.interrupts,
            self.session.id,
            agent,
            self.stack.last().and_then(|frame| frame.agent_instance_id),
            description,
            set,
            crate::agent_tree::HostDecisionSubject::UserQuestion,
            "injection override",
        )
        .await
        .into_response()?)
    }

    async fn primary_round_ceiling_allows_more(
        &self,
        rounds: u32,
        limit: u32,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<bool> {
        if limit == 0 || rounds < limit {
            return Ok(true);
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
            return Ok(false);
        }

        use crate::daemon::proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};

        let question = InterruptQuestion::Single {
            prompt: format!("{message} Allow another {limit} round(s)?"),
            options: vec![
                InterruptOption {
                    id: ID_PRIMARY_ROUNDS_CONTINUE.to_string(),
                    label: "Continue".to_string(),
                    description: Some("allow another chunk for this message".to_string()),
                    secondary: false,
                },
                InterruptOption {
                    id: ID_PRIMARY_ROUNDS_STOP.to_string(),
                    label: "Stop".to_string(),
                    description: Some("end this turn now".to_string()),
                    secondary: false,
                },
            ],
            allow_freetext: false,
            command_detail: None,
            permission: false,
            approval_class: None,
            sandbox_escalation: None,
        };
        let set = InterruptQuestionSet {
            questions: vec![question],
        };
        let response = self
            .raise_and_wait(self.active_agent(), "Primary tool-round limit reached", set)
            .await?;
        if selected_id_of(&response).as_deref() == Some(ID_PRIMARY_ROUNDS_CONTINUE) {
            let _ = tx
                .send(TurnEvent::Notice {
                    text: format!("Continuing for up to {limit} more tool round(s)."),
                })
                .await;
            Ok(true)
        } else {
            let _ = tx
                .send(TurnEvent::Notice {
                    text: "Stopped at the configured tool-round limit for this message."
                        .to_string(),
                })
                .await;
            Ok(false)
        }
    }

    fn reset_delegation_retry_budget(&mut self) {
        self.delegation_retry_budget_remaining = DELEGATION_RETRY_BUDGET_PER_TURN;
    }

    fn consume_delegation_retry_budget(&mut self) -> std::result::Result<(), String> {
        if self.delegation_retry_budget_remaining == 0 {
            return Err(format!(
                "Error: delegation retry budget exhausted before accepting another task call (limit {DELEGATION_RETRY_BUDGET_PER_TURN} per parent turn). Stop re-issuing `task` calls and summarize the failure to the user."
            ));
        }
        self.delegation_retry_budget_remaining -= 1;
        Ok(())
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

    async fn publish_active_tool_names(&self) {
        if let Some(frame) = self.stack.last() {
            let tools = crate::engine::agent::turn_toolbox(
                &frame.agent,
                &self.session,
                &self.cwd,
                &self.config,
            )
            .await;
            self.session.set_active_tool_names(
                tools.names(),
                crate::engine::tool::Capability::SandboxEscalate.enabled(
                    &crate::agents::PostureResolution::legacy(frame.agent.llm_mode),
                ),
            );
        }
    }

    async fn emit_command_capability_notice_if_new(&mut self, tx: &mpsc::Sender<TurnEvent>) {
        let Some(frame) = self.stack.last() else {
            return;
        };
        let tools = crate::engine::agent::turn_toolbox(
            &frame.agent,
            &self.session,
            &self.cwd,
            &self.config,
        )
        .await;
        let Some(text) = tools.capability_notice_text() else {
            return;
        };
        if !self.emitted_command_capability_notices.insert(text.clone()) {
            return;
        }
        let fix_command = tools.capability_notice_fix_command();
        let _ = tx
            .send(TurnEvent::CommandCapabilityUnavailable { text, fix_command })
            .await;
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

    /// Attach the worker's one durable root identity before the first driver
    /// turn.  Child IDs are attached at the task-delegation creation boundary.
    pub fn set_root_agent_instance_id(&mut self, agent_instance_id: uuid::Uuid) {
        if let Some(root) = self.stack.first_mut() {
            root.agent_instance_id = Some(agent_instance_id);
        }
    }

    /// Install the recovery activation barrier before spawning the root loop.
    /// Fresh roots have no resume claim and therefore never receive a gate.
    pub fn set_root_recovery_activation(&mut self, gate: RecoveryActivationGate) {
        if let Some(root) = self.stack.first_mut() {
            root.recovery_activation = Some(gate);
        }
    }

    /// Restore the root's exact private model/tool continuation for an
    /// accepted late steer. The root is not a task child, so it cannot borrow
    /// `task_delegation_children.snapshot_json`; this is the corresponding
    /// root-owned recovery seam. It installs no user message and does not
    /// cross a provider boundary: the worker must subsequently send the
    /// matching `ResumeAcceptedLateUserDecisionSteer` control, which carries
    /// the exact recovery epoch and owns the eventual receipt.
    pub fn restore_root_late_user_steer_continuation(
        &mut self,
        agent_instance_id: uuid::Uuid,
        permit: RecoveredLateUserSteerPermit,
        snapshot_json: &str,
        has_parked_continuation: bool,
    ) -> anyhow::Result<crate::engine::agent::AgentTreeEndpointGeneration> {
        anyhow::ensure!(
            permit.continuation_id != uuid::Uuid::nil(),
            "recovered root late-steer continuation id must not be nil"
        );
        let snapshot: serde_json::Value = serde_json::from_str(snapshot_json)
            .context("parsing recovered root late-steer continuation snapshot")?;
        anyhow::ensure!(
            snapshot.get("version").and_then(serde_json::Value::as_u64) == Some(1),
            "recovered root late-steer snapshot version is unsupported"
        );
        anyhow::ensure!(
            snapshot
                .get("agent_instance_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|id| id == agent_instance_id.to_string()),
            "recovered root late-steer snapshot belongs to another agent"
        );
        anyhow::ensure!(
            snapshot
                .get("late_user_steer_continuation_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|id| id == permit.continuation_id.to_string()),
            "recovered root late-steer snapshot is not bound to the accepted continuation"
        );
        let history = serde_json::from_value::<Vec<Message>>(
            snapshot
                .get("history")
                .cloned()
                .context("recovered root late-steer snapshot has no history")?,
        )
        .context("decoding recovered root late-steer history")?;
        let next_prompt = serde_json::from_value::<Message>(
            snapshot
                .get("next_prompt")
                .cloned()
                .context("recovered root late-steer snapshot has no next prompt")?,
        )
        .context("decoding recovered root late-steer next prompt")?;
        anyhow::ensure!(
            self.recovered_interactive_late_steer_continuations
                .get(&agent_instance_id)
                .is_none(),
            "root already has a recovered accepted late-steer checkpoint"
        );
        let endpoint_generation = {
            let root = self
                .stack
                .first_mut()
                .context("driver has no root frame for late-steer recovery")?;
            anyhow::ensure!(
                root.agent_instance_id == Some(agent_instance_id),
                "recovered root late-steer snapshot does not match the live root identity"
            );
            root.history = history;
            match root.endpoint_generation {
                Some(generation) => generation,
                None => {
                    let generation = crate::engine::agent::next_agent_tree_endpoint_generation();
                    root.endpoint_generation = Some(generation);
                    generation
                }
            }
        };
        self.recovered_interactive_late_steer_continuations.insert(
            agent_instance_id,
            RecoveredInteractiveLateSteerContinuation {
                permit: LateUserSteerPermitIdentity {
                    steer_id: permit.steer_id,
                    continuation_id: permit.continuation_id,
                    recovery_epoch: permit.recovery_epoch,
                    agent_instance_id,
                },
                continuation_id: permit.continuation_id,
                next_prompt,
                has_parked_continuation,
                pending_response: None,
            },
        );
        Ok(endpoint_generation)
    }

    async fn reattach_interactive_task_child(
        &mut self,
        recovery: RecoveredInteractiveTaskChild,
        input_queue: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> anyhow::Result<crate::engine::agent::AgentTreeEndpointGeneration> {
        anyhow::ensure!(
            self.stack.last().and_then(|frame| frame.agent_instance_id)
                == Some(recovery.parent_agent_instance_id),
            "recovered interactive task parent is not the exact live continuation"
        );
        let args: serde_json::Value = serde_json::from_str(&recovery.original_args_json)
            .context("parsing recovered interactive task launch descriptor")?;
        anyhow::ensure!(
            args.get("interactive").and_then(serde_json::Value::as_bool) == Some(true),
            "recovered task descriptor is not interactive"
        );
        anyhow::ensure!(
            args.get("child_agent").and_then(serde_json::Value::as_str)
                == Some(recovery.child_agent.as_str()),
            "recovered task child agent does not match its durable descriptor"
        );
        let model =
            crate::engine::model_roles::DelegationModelSelector::from_value(args.get("model"))
                .map_err(anyhow::Error::msg)?;
        let remaining_depth = args
            .get("remaining_depth")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .context("recovered interactive task has no valid remaining depth")?;
        let granted_tools = args
            .get("granted_tools")
            .and_then(serde_json::Value::as_array)
            .context("recovered interactive task has no granted-tools snapshot")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .context("recovered interactive task granted tool is not a string")
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let repair_notes = args
            .get("repair_notes")
            .and_then(serde_json::Value::as_array)
            .context("recovered interactive task has no repair-note snapshot")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .context("recovered interactive task repair note is not a string")
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let provider_item_id = args
            .get("provider_item_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let function_call_id = args
            .get("function_call_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let snapshot: serde_json::Value = serde_json::from_str(&recovery.snapshot_json)
            .context("parsing recovered interactive task snapshot")?;
        anyhow::ensure!(
            snapshot.get("version").and_then(serde_json::Value::as_u64) == Some(2),
            "recovered interactive task snapshot version is unsupported"
        );
        let recovered_late_user_steer_continuation_id = snapshot
            .get("late_user_steer_continuation_id")
            .and_then(serde_json::Value::as_str)
            .map(|raw| {
                uuid::Uuid::parse_str(raw)
                    .context("recovered interactive late steer continuation id is not a UUID")
            })
            .transpose()?;
        let recovered_late_steer_permit = match (
            recovered_late_user_steer_continuation_id,
            recovery.accepted_late_steer,
        ) {
            (Some(continuation_id), Some(accepted))
                if continuation_id == accepted.continuation_id =>
            {
                Some(LateUserSteerPermitIdentity {
                    steer_id: accepted.steer_id,
                    continuation_id,
                    recovery_epoch: accepted.recovery_epoch,
                    agent_instance_id: recovery.agent_instance_id,
                })
            }
            (Some(_), Some(_)) => anyhow::bail!(
                "recovered interactive late-steer snapshot and accepted durable checkpoint disagree"
            ),
            (Some(_), None) => anyhow::bail!(
                "recovered interactive late-steer snapshot has no accepted durable checkpoint"
            ),
            (None, Some(_)) => anyhow::bail!(
                "accepted durable late-steer checkpoint has no matching interactive snapshot marker"
            ),
            (None, None) => None,
        };
        let history = serde_json::from_value::<Vec<Message>>(
            snapshot
                .get("history")
                .cloned()
                .context("recovered interactive task snapshot has no history")?,
        )
        .context("decoding recovered interactive task history")?;
        let snapshot_next_prompt = snapshot
            .get("next_prompt")
            .cloned()
            .map(serde_json::from_value::<Message>)
            .transpose()
            .context("decoding recovered interactive task next prompt")?;
        // An accepted steer is already past its user-body injection.  Its
        // snapshot must therefore carry the exact model/tool continuation;
        // falling back to the task payload here would silently redeliver a
        // different user turn after restart.
        let accepted_late_steer_next_prompt = recovered_late_steer_permit
            .map(|continuation_id| {
                snapshot_next_prompt
                    .clone()
                    .context("accepted interactive late steer snapshot has no next prompt")
                    .map(|next_prompt| (continuation_id.continuation_id, next_prompt))
            })
            .transpose()?;
        let next_prompt =
            snapshot_next_prompt.unwrap_or_else(|| Message::user(recovery.payload.clone()));
        if accepted_late_steer_next_prompt.is_some()
            && self
                .recovered_interactive_late_steer_continuations
                .contains_key(&recovery.agent_instance_id)
        {
            anyhow::bail!(
                "recovered interactive executor already holds an accepted late-steer checkpoint"
            );
        }
        // A recovered child may be parked at a QuestionTool seam.  Its
        // serialized `next_prompt` is the *pre-interrupt* model turn, not a
        // continuation that may be scheduled while the durable decision is
        // still pending.  Reattach the child frame and its exact executor
        // endpoint first, then leave it idle until the worker redelivers the
        // terminal parked continuation through `ReplayParkedInterrupt`.
        //
        // This includes `executing`: that is the durable exactly-once replay
        // claim after a terminal decision won, and it must be consumed by the
        // same endpoint rather than converted into a fresh model prompt.
        let recovered_child_has_parked_continuation = self
            .session
            .db
            .list_reconcilable_interrupts(self.session.id)
            .await
            .context("loading recovered interactive child parked continuations")?
            .into_iter()
            .any(|row| {
                row.agent_instance_id == Some(recovery.agent_instance_id)
                    && row.parked.is_some()
                    && matches!(
                        row.state,
                        crate::db::needs_attention::InterruptState::Open
                            | crate::db::needs_attention::InterruptState::Parked
                            | crate::db::needs_attention::InterruptState::Executing
                    )
            });
        let child_recursion = self
            .resolve_task_recursion(&recovery.child_agent, Some(remaining_depth), &model)
            .map_err(anyhow::Error::msg)?;
        let mut admission = self
            .admit_current_vnext_children(1)
            .map_err(anyhow::Error::msg)?;
        let child = crate::engine::builtin::load(
            &recovery.child_agent,
            &self.spawn_args_delegated(true, granted_tools, model, child_recursion),
        )
        .context("loading recovered interactive task child")?;
        let endpoint_generation = crate::engine::agent::next_agent_tree_endpoint_generation();
        self.stack.push(AgentSession {
            queue_target: crate::engine::message::QueueTarget::child(
                child.name.clone(),
                self.stack.len(),
                recovery.task_call_id.clone(),
                recovery.label.clone(),
            ),
            agent: Arc::new(child),
            agent_instance_id: Some(recovery.agent_instance_id),
            endpoint_generation: Some(endpoint_generation),
            history,
            answering: Some(PendingTaskCall {
                call_id: recovery.task_call_id.clone(),
                provider_item_id,
                function_call_id,
                repair_notes,
            }),
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            fallback_decision: None,
            recovery_activation: Some(recovery.activation_gate),
            late_user_steer_permit: None,
            _vnext_child_admission: admission.pop(),
            stop_gate: crate::engine::agent::hooks::StopGateState::default(),
        });
        let _ = tx
            .send(TurnEvent::AgentTreeExecutorEndpointAttached {
                agent_instance_id: recovery.agent_instance_id,
                endpoint_generation,
            })
            .await;
        let _ = tx
            .send(TurnEvent::ForegroundInputTarget {
                target: self.active_queue_target(),
            })
            .await;
        if let Some((continuation_id, next_prompt)) = accepted_late_steer_next_prompt {
            let permit = recovered_late_steer_permit
                .expect("accepted next prompt requires a verified durable permit");
            let previous = self.recovered_interactive_late_steer_continuations.insert(
                recovery.agent_instance_id,
                RecoveredInteractiveLateSteerContinuation {
                    permit,
                    continuation_id,
                    next_prompt,
                    has_parked_continuation: recovered_child_has_parked_continuation,
                    pending_response: None,
                },
            );
            debug_assert!(
                previous.is_none(),
                "checked before attaching interactive executor"
            );
        }
        if recovered_child_has_parked_continuation
            || recovered_late_user_steer_continuation_id.is_some()
        {
            // The child is now addressable for a future terminal replay, but
            // it must not receive a synthetic empty submission. A parked
            // QuestionTool needs its terminal replay; an accepted late steer
            // needs the worker's checkpoint-resume command. Either path must
            // win before the persisted pre-crash prompt is allowed to run.
            return Ok(endpoint_generation);
        }
        // Keep the exact serialized `Message` out of the ordinary user-input
        // projection.  A continuation can be a tool result or media-bearing
        // user message, both of which `extract_user_text` would silently
        // truncate.  The queue UUID is an in-memory scheduling key only; the
        // DB snapshot remains the durable source if this worker dies before it
        // is consumed.
        let (queue_item_id, _) = input_queue
            .push(
                crate::engine::message::UserSubmission {
                    origin: crate::engine::message::SubmissionOrigin::ToolResult,
                    ..crate::engine::message::UserSubmission::text("")
                },
                self.active_queue_target(),
            )
            .await;
        self.recovered_interactive_continuations
            .insert(queue_item_id, next_prompt);
        Ok(endpoint_generation)
    }

    async fn persist_active_interactive_task_snapshot(
        &self,
        next_prompt: &Message,
        late_user_steer_continuation_id: Option<uuid::Uuid>,
    ) -> anyhow::Result<()> {
        let Some(frame) = self.stack.last() else {
            return Ok(());
        };
        if self.stack.len() == 1 {
            let Some(agent_instance_id) = frame.agent_instance_id else {
                // The session worker sets the root identity before it starts
                // accepting input. Detached/unit drivers intentionally have
                // no durable AgentTree owner.
                return Ok(());
            };
            let snapshot = serde_json::to_string(&serde_json::json!({
                "version": 1,
                "agent_instance_id": agent_instance_id,
                "history": &frame.history,
                "next_prompt": next_prompt,
                // Acceptance checks this exact durable binding for the root.
                // Every later parked/continuation phase writes a new snapshot
                // with the same accepted continuation id, so restart resumes
                // the precise post-question/post-approval continuation.
                "late_user_steer_continuation_id": late_user_steer_continuation_id,
            }))
            .context("serializing root continuation snapshot")?;
            self.session
                .db
                .persist_session_root_agent_continuation(
                    self.session.id,
                    agent_instance_id,
                    late_user_steer_continuation_id,
                    snapshot,
                    crate::agent_tree::system_now_unix_ms(),
                )
                .await
                .context("persisting root continuation snapshot")?;
            return Ok(());
        }
        let (Some(agent_instance_id), Some(pending)) =
            (frame.agent_instance_id, frame.answering.as_ref())
        else {
            return Ok(());
        };
        let snapshot = serde_json::to_string(&serde_json::json!({
            "version": 2,
            "agent_instance_id": agent_instance_id,
            "history": &frame.history,
            "next_prompt": next_prompt,
            // This marker means the serialized input is already the durable
            // continuation checkpoint for an accepted late steer. Recovery
            // must leave it idle for `ResumeAcceptedLateUserDecisionSteer`,
            // rather than scheduling the same message independently.
            "late_user_steer_continuation_id": late_user_steer_continuation_id,
        }))
        .context("serializing interactive task continuation snapshot")?;
        anyhow::ensure!(
            self.session
                .db
                .persist_task_delegation_snapshot(&pending.call_id, "default", &snapshot)
                .await?,
            "interactive task continuation is no longer recoverable"
        );
        Ok(())
    }

    async fn terminalize_agent_tree_executor(
        &self,
        agent_instance_id: uuid::Uuid,
        state: crate::db::agent_tree_decisions::AgentInstanceState,
        receipt_json: String,
    ) {
        for _ in 0..4 {
            let agent = match self
                .session
                .db
                .agent_instance(self.session.id, agent_instance_id)
                .await
            {
                Ok(Some(agent)) => agent,
                Ok(None) => return,
                Err(error) => {
                    tracing::warn!(%error, %agent_instance_id, "loading interactive agent-tree executor failed");
                    return;
                }
            };
            match self
                .session
                .db
                .transition_agent_instance(
                    self.session.id,
                    agent_instance_id,
                    agent.revision,
                    state,
                    &receipt_json,
                    crate::agent_tree::system_now_unix_ms(),
                )
                .await
            {
                Ok(crate::db::agent_tree_decisions::AgentTransitionOutcome::Transitioned(_))
                | Ok(crate::db::agent_tree_decisions::AgentTransitionOutcome::AlreadyTerminal(_)) =>
                {
                    return;
                }
                Ok(crate::db::agent_tree_decisions::AgentTransitionOutcome::RevisionConflict) => {
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, %agent_instance_id, "terminalizing interactive agent-tree executor failed");
                    return;
                }
            }
        }
        tracing::warn!(%agent_instance_id, "interactive agent-tree executor terminalization lost repeated revision races");
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

    /// Bind an accepted late-steer receipt to the exact frame immediately
    /// before replaying the later parked QuestionTool/approval.  The durable
    /// snapshot's `next_prompt` belongs to the pre-park provider turn, so it
    /// is deliberately never queued on this path.  The replayed tool result
    /// becomes the only next model prompt and carries the same permit through
    /// its final provider/completion boundary.
    fn restore_recovered_parked_late_steer(&mut self, agent_instance_id: uuid::Uuid) -> Result<()> {
        let Some(recovered) = self
            .recovered_interactive_late_steer_continuations
            .get(&agent_instance_id)
        else {
            return Ok(());
        };
        if !recovered.has_parked_continuation {
            return Ok(());
        }
        if recovered.pending_response.is_none() {
            bail!(
                "accepted late-steer parked replay reached the executor before its exact recovery receipt"
            );
        }
        let mut recovered = self
            .recovered_interactive_late_steer_continuations
            .remove(&agent_instance_id)
            .expect("checked recovered parked late-steer checkpoint disappeared");
        let respond_to = recovered
            .pending_response
            .take()
            .context("recovered parked late-steer receipt disappeared")?;
        let frame = self.stack.last().context("driver stack is empty")?;
        ensure!(
            frame.agent_instance_id == Some(agent_instance_id),
            "recovered parked late steer belongs to a different interactive frame"
        );
        ensure!(
            frame.late_user_steer_permit.is_none(),
            "interactive frame already owns a different late-steer permit"
        );
        let queue_item_id = uuid::Uuid::now_v7();
        let previous = self.pending_late_user_steer_acks.insert(
            queue_item_id,
            PendingLateUserSteerAck {
                agent_instance_id,
                steer_id: recovered.permit.steer_id,
                continuation_id: recovered.permit.continuation_id,
                recovery_epoch: recovered.permit.recovery_epoch,
                respond_to,
            },
        );
        if let Some(previous) = previous {
            let _ = previous
                .respond_to
                .send(LateUserSteerContinuationOutcome::failed(
                    "late user steer synthetic replay receipt identity collision",
                ));
            bail!("late user steer synthetic replay receipt identity collision");
        }
        self.stack
            .last_mut()
            .expect("checked recovered interactive frame disappeared")
            .late_user_steer_permit = Some(recovered.permit);
        Ok(())
    }

    async fn replay_parked_interrupt_call(
        &mut self,
        interrupt_id: uuid::Uuid,
        expected_agent_instance_id: Option<uuid::Uuid>,
        payload: crate::db::needs_attention::InterruptParkPayload,
        response: crate::daemon::proto::ResolveResponse,
        question: crate::engine::interrupt::PreResolvedInterruptQuestion,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<()> {
        use rig::message::ToolFunction;

        let agent = {
            let top = self.stack.last().context("driver stack is empty")?;
            if let Some(expected_agent_instance_id) = expected_agent_instance_id {
                ensure!(
                    top.agent_instance_id == Some(expected_agent_instance_id),
                    "parked interrupt belongs to a different live agent instance"
                );
                ensure!(
                    question.agent_instance_id == Some(expected_agent_instance_id),
                    "recovered QuestionTool identity does not match its typed parked owner"
                );
            } else if top.agent.name != payload.resume.agent_id {
                bail!(
                    "parked interrupt belongs to agent `{}`, active agent is `{}`",
                    payload.resume.agent_id,
                    top.agent.name
                );
            }
            top.agent.clone()
        };
        if let Some(agent_instance_id) = expected_agent_instance_id {
            self.restore_recovered_parked_late_steer(agent_instance_id)?;
        }
        let active_tools =
            crate::engine::agent::turn_toolbox(&agent, &self.session, &self.cwd, &self.config)
                .await;
        if active_tools.get(&payload.tool).is_none() {
            bail!("parked interrupt tool `{}` is not registered", payload.tool);
        }
        {
            let history = &mut self
                .stack
                .last_mut()
                .context("driver stack is empty")?
                .history;
            ensure_or_restore_parked_tool_call(history, &payload)?;
        }

        let ctx = crate::engine::tool::ToolCtx {
            agent_id: agent.name.clone(),
            agent_instance_id: self.stack.last().and_then(|frame| frame.agent_instance_id),
            lock_identity: agent.name.clone().clone(),
            write_scope: None,
            current_tool_call_id: None,
            llm_mode: agent.llm_mode,
            locks: self.locks.clone(),
            session: self.session.clone(),
            cwd: self.cwd.clone(),
            redact: self.redact.clone(),
            interrupts: self.interrupts.clone(),
            cancel: tokio_util::sync::CancellationToken::new(),
            shutdown_gate: agent.model.shutdown_gate(),
            approver: self.approver.clone(),
            image_generation_dispatch: None,
            deferred_log: self
                .stack
                .last()
                .context("driver stack is empty")?
                .deferred_log
                .clone(),
            root_agent_frame: self.stack.len() == 1,
            skill_write_origin: payload.resume.call_origin,
            review_cage: None,
            context_usage: Some(self.context_usage_snapshot()),
            available_tools: Arc::new(
                active_tools
                    .names()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            ),
            mcp_builtin_registry: active_tools.mcp_builtin_registry(),
            has_tree: agent.tools.get("code").is_some(),
            has_bash: agent.tools.get("bash").is_some(),
            events: Some(tx.clone()),
            lsp: self.lsp.clone(),
            resource_scheduler: self.resource_scheduler.clone(),
            env_overlay: agent.env_overlay.clone(),
            config: self.config.clone(),
        };
        let call = crate::engine::message::ToolCall {
            id: rig::message::ToolCallId::new_or_mint(payload.call_id.clone()),
            provider: payload
                .resume
                .provider_call_id
                .clone()
                .and_then(rig::message::ProviderCallId::new)
                .map(|provider| match payload.resume.provider_item_id.clone() {
                    Some(item_id) => provider.with_item_id(item_id),
                    None => provider,
                }),
            function: ToolFunction {
                name: payload.tool.clone(),
                arguments: payload.args.clone(),
            },
            signature: None,
            additional_params: None,
        };
        let config_snapshot = ctx.config.snapshot();
        let env = crate::engine::agent::tool_dispatch::DispatchEnv {
            agent: &agent,
            session: &self.session,
            model: &agent.model,
            active_tools: &active_tools,
            ctx: &ctx,
            tx,
            hint_corrections: crate::engine::agent::hint_tool_call_corrections_enabled(
                &self.session,
                &self.config,
            ),
            loop_guard_threshold: self.loop_guard_threshold,
            cwd: &self.cwd,
            hooks: config_snapshot.hooks(),
        };
        crate::engine::interrupt::with_pre_resolved_interrupt_question(
            interrupt_id,
            response,
            question,
            async {
                let frame = self.stack.last_mut().context("driver stack is empty")?;
                crate::engine::interrupt::with_interrupt_park_payload(payload.clone(), async {
                    crate::engine::agent::tool_dispatch::execute_ordinary_call(
                        &env,
                        &mut frame.history,
                        &call,
                        &payload.tool,
                        crate::db::tool_calls::Recovery::Clean,
                        None,
                    )
                    .await
                })
                .await
            },
        )
        .await
    }

    async fn continue_after_parked_interrupt_replay(
        &mut self,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<()> {
        let mut next_prompt = {
            let frame = self.stack.last_mut().context("driver stack is empty")?;
            frame
                .history
                .pop()
                .context("parked interrupt replay produced no tool result")?
        };
        let lifecycle_turn_id = uuid::Uuid::new_v4().to_string();
        self.current_lifecycle_turn_id = Some(lifecycle_turn_id.clone());
        // Modes AC5 turn-consumption is wired in `refresh_active_frame_for_turn`
        // (below): `consume_active_node_override_for_turn` runs the AC5 "second
        // transaction" for the active node (mode applied per-frame, sandbox to the
        // session posture). Follow-on: per-node sandbox isolation across concurrent
        // delegated turns, and verification/question application at their resolver
        // sites.
        // Pin the session config snapshot for this turn's duration: a
        // re-resolution that lands mid-turn is observed only at the next turn
        // boundary (`engine-config-snapshot-adoption`).
        self.repin_config_for_turn();
        self.max_primary_rounds = self.load_max_primary_rounds_for_turn().await;
        self.reset_delegation_retry_budget();
        self.refresh_redaction_table_for_turn(tx).await;
        self.refresh_active_frame_for_turn(tx).await;
        self.refresh_wire_api_for_turn();
        let cancel = tokio_util::sync::CancellationToken::new();
        let _cancel_guard = {
            *crate::sync::lock_or_recover(&self.cancel_current) = Some(cancel.clone());
            CancelSlotGuard {
                slot: self.cancel_current.clone(),
            }
        };
        let max_primary_rounds = self.max_primary_rounds;
        let mut primary_rounds_in_chunk: u32 = 0;

        loop {
            self.maybe_auto_prune(tx).await;
            let agent = {
                let top = self.stack.last().expect("stack never empty");
                top.agent.clone()
            };
            self.publish_active_tool_names().await;
            self.emit_command_capability_notice_if_new(tx).await;
            let is_root = self.stack.len() == 1;
            let mut late_user_steer_permit = self
                .stack
                .last()
                .and_then(|frame| frame.late_user_steer_permit);
            let late_user_steer_queue_item_ids = late_user_steer_permit
                .map(|permit| self.late_steer_queue_item_ids_for_permit(permit))
                .unwrap_or_default();
            let backup_model = self.resolve_backup_model(&agent.model);
            let fallback_models = self.resolve_failover_models(&agent.model);
            let call_id = uuid::Uuid::new_v4();
            self.publish_active_tool_names().await;
            let context_usage = self.context_usage_snapshot();
            let tandem = self
                .tandem_set
                .is_enabled()
                .then(|| self.tandem_set.clone());
            let mut turn_metadata = BackupTurnMetadata::default();
            if let Err(error) = self
                .persist_active_interactive_task_snapshot(
                    &next_prompt,
                    late_user_steer_permit.map(|permit| permit.continuation_id),
                )
                .await
            {
                return Err(error);
            }
            let turn_result = {
                let top = self.stack.last_mut().expect("stack never empty");
                let deferred_log = top.deferred_log.clone();
                crate::engine::agent::with_agent_instance_id(
                    top.agent_instance_id,
                    crate::engine::agent::with_agent_tree_steer_dispatch_permit(
                        late_user_steer_permit.map(|permit| {
                            crate::engine::agent::AgentTreeSteerDispatchPermit::new(
                                self.session.clone(),
                                permit.steer_id,
                                permit.continuation_id,
                                permit.agent_instance_id,
                                permit.recovery_epoch,
                                cancel.clone(),
                            )
                        }),
                        turn_with_backup(
                            &agent,
                            backup_model.as_ref(),
                            &fallback_models,
                            &mut top.history,
                            next_prompt.clone(),
                            self.session.clone(),
                            self.locks.clone(),
                            self.redact.clone(),
                            self.cwd.clone(),
                            self.config.clone(),
                            self.interrupts.clone(),
                            cancel.clone(),
                            self.approver.clone(),
                            self.lsp.clone(),
                            self.resource_scheduler.clone(),
                            self.loop_guard_threshold,
                            is_root,
                            crate::skills::manage::SkillWriteOrigin::Foreground,
                            None,
                            context_usage,
                            deferred_log,
                            call_id,
                            tandem.as_ref(),
                            self.goal_root_turn
                                .map(|(goal_id, generation, _)| (goal_id, generation)),
                            Some(lifecycle_turn_id.clone()),
                            tx,
                            Some(&mut turn_metadata),
                        ),
                    ),
                )
                .await
            };
            if let Some(fallback) = turn_metadata.fallback_decision.take() {
                self.note_backup_fallback_for_active_frame(fallback, tx)
                    .await;
            }
            let outcome = match turn_result {
                Ok(outcome) => outcome,
                Err(e) if crate::engine::interrupt::is_parked(&e) => {
                    tracing::info!(agent = %agent.name, "turn paused on parked interrupt");
                    if let Some((goal_id, generation, turn_id)) = self.goal_root_turn.take() {
                        let _ = self
                            .session
                            .db
                            .defer_goal_root_turn_for_approval(goal_id, generation, turn_id)
                            .await;
                    }
                    self.pending_idle_reason = Some(crate::engine::IdleReason::NeedsIntervention {
                        code: "parked_interrupt".to_string(),
                    });
                    return Ok(());
                }
                Err(e) if crate::engine::model::is_cancelled(&e) => {
                    self.pending_idle_reason = Some(crate::engine::IdleReason::Interrupted);
                    self.unwind_stack_to_root_and_discard_pending_input(
                        StackUnwindReason::Cancelled,
                        input_rx,
                        tx,
                    )
                    .await;
                    let _ = self
                        .take_late_steer_for_interactive_root_terminal(&mut late_user_steer_permit);
                    self.finish_late_steer_deliveries(
                        &late_user_steer_queue_item_ids,
                        LateUserSteerContinuationOutcome::Cancelled,
                    )
                    .await;
                    return Ok(());
                }
                Err(e) if crate::engine::model::is_gated(&e) => {
                    self.unwind_stack_to_root_and_discard_pending_input(
                        StackUnwindReason::Gated,
                        input_rx,
                        tx,
                    )
                    .await;
                    let _ = self
                        .take_late_steer_for_interactive_root_terminal(&mut late_user_steer_permit);
                    self.finish_late_steer_deliveries(
                        &late_user_steer_queue_item_ids,
                        LateUserSteerContinuationOutcome::interrupted(
                            "late user steer was interrupted by daemon drain",
                        ),
                    )
                    .await;
                    return Ok(());
                }
                Err(e) if crate::engine::model::as_inference_failure(&e).is_some() => {
                    let f = crate::engine::model::as_inference_failure(&e)
                        .expect("match guard established inference failure");
                    self.record_failed_turn_recovery(&agent, &next_prompt, call_id, f, tx)
                        .await;
                    if !self.handle_goal_usage_limit_failure(f, tx).await {
                        self.pending_idle_reason = Some(crate::engine::IdleReason::Error {
                            class: f.class.clone(),
                        });
                    }
                    // `stopFailure` observe hooks: an inference/API error ends
                    // the attempt without a normal stop gate. Fire before the
                    // stack unwind; never on a normal `Done`.
                    self.run_stop_failure_hooks(&f.class).await;
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
                    let _ = self
                        .take_late_steer_for_interactive_root_terminal(&mut late_user_steer_permit);
                    self.finish_late_steer_deliveries(
                        &late_user_steer_queue_item_ids,
                        LateUserSteerContinuationOutcome::failed(format!(
                            "late user steer inference failed: {}",
                            f.class
                        )),
                    )
                    .await;
                    return Ok(());
                }
                Err(e) => return Err(e),
            };

            if is_root {
                self.persist_prune_ledger().await;
                if let Err(e) = self
                    .session
                    .db
                    .refresh_session_goal_usage(self.session.id)
                    .await
                {
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
                            .await?
                        {
                            self.acknowledge_interrupted_turns_after_progress().await;
                            return Ok(());
                        }
                        if primary_rounds_in_chunk >= max_primary_rounds {
                            primary_rounds_in_chunk = 0;
                        }
                    }
                    next_prompt = self
                        .stack
                        .last_mut()
                        .expect("stack never empty")
                        .history
                        .pop()
                        .context("Continue with empty history after parked replay")?;
                }
                TurnOutcome::Done => {
                    if self.stack.len() > 1 {
                        // Genuine interactive child completion: consult its
                        // frame-owned `subagentStop` gate (the single firing for
                        // this stop). A `continue` block re-runs the child; the
                        // `!cancel` guard blocks a re-run raced by a cancel.
                        if let crate::engine::agent::hooks::StopHookOutcome::Continue {
                            reason,
                            additional_context,
                        } = self
                            .consult_active_child_stop_gate(
                                &crate::engine::agent::hooks::TokioCommandRunner::with_optional_containment(self.session.process_containment()),
                                &crate::engine::agent::hooks::DefaultProcessEnv,
                            )
                            .await
                            && !cancel.is_cancelled()
                        {
                            next_prompt =
                                Self::stop_continuation_prompt(reason, additional_context);
                            continue;
                        }
                        let late_user_steer_completion = self
                            .take_late_steer_for_interactive_child_terminal(
                                &mut late_user_steer_permit,
                            );
                        if let Some(np) = self
                            .pop_child_with_envelope(
                                None,
                                late_user_steer_completion,
                                &late_user_steer_queue_item_ids,
                                tx,
                            )
                            .await
                        {
                            next_prompt = np;
                            continue;
                        }
                    }
                    if let Some(permit) = self
                        .take_late_steer_for_interactive_root_terminal(&mut late_user_steer_permit)
                    {
                        self.finish_late_steer_deliveries(
                            &self.late_steer_queue_item_ids_for_permit(permit),
                            LateUserSteerContinuationOutcome::Completed,
                        )
                        .await;
                    }
                    self.acknowledge_interrupted_turns_after_progress().await;
                    self.maybe_spawn_self_improvement_review(tx).await;
                    return Ok(());
                }
                TurnOutcome::Return { fields } => {
                    if let crate::engine::agent::hooks::StopHookOutcome::Continue {
                        reason,
                        additional_context,
                    } = self
                        .consult_active_child_stop_gate(
                            &crate::engine::agent::hooks::TokioCommandRunner::with_optional_containment(self.session.process_containment()),
                            &crate::engine::agent::hooks::DefaultProcessEnv,
                        )
                        .await
                        && !cancel.is_cancelled()
                    {
                        next_prompt = Self::stop_continuation_prompt(reason, additional_context);
                        continue;
                    }
                    let late_user_steer_completion = self
                        .take_late_steer_for_interactive_child_terminal(
                            &mut late_user_steer_permit,
                        );
                    if let Some(np) = self
                        .pop_child_with_envelope(
                            Some(&fields),
                            late_user_steer_completion,
                            &late_user_steer_queue_item_ids,
                            tx,
                        )
                        .await
                    {
                        next_prompt = np;
                        continue;
                    }
                    self.acknowledge_interrupted_turns_after_progress().await;
                    self.maybe_spawn_self_improvement_review(tx).await;
                    return Ok(());
                }
                _ => bail!("parked interrupt replay continuation produced unsupported outcome"),
            }
        }
    }

    async fn acknowledge_interrupted_turns_after_progress(&self) {
        match self
            .session
            .db
            .acknowledge_interrupted_turns(self.session.id)
            .await
        {
            Ok(0) => {}
            Ok(count) => tracing::debug!(count, "acknowledged interrupted session markers"),
            Err(error) => tracing::warn!(%error, "acknowledging interrupted markers failed"),
        }
    }

    fn preempt_self_improvement_review_for_foreground(&mut self) {
        let Some(review) = self.self_improvement_review.take() else {
            return;
        };
        if !review.is_finished() {
            review.abort();
        }
    }

    async fn maybe_spawn_self_improvement_review(&mut self, tx: &mpsc::Sender<TurnEvent>) -> bool {
        if let Some(review) = &self.self_improvement_review {
            if review.is_finished() {
                self.self_improvement_review = None;
            } else {
                return false;
            }
        }
        let Some(assistant_name) = self.session.assistant_name.clone() else {
            return false;
        };
        let interval = match crate::assistants::snapshot(&self.session.db, &assistant_name).await {
            Ok(Some(snapshot)) => {
                match serde_json::from_str::<crate::assistants::AssistantConfig>(
                    &snapshot.row.config_json,
                ) {
                    Ok(config) => config.skill_review_interval,
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            assistant = %assistant_name,
                            "refusing self-improvement review for malformed durable assistant configuration"
                        );
                        return false;
                    }
                }
            }
            Ok(None) => return false,
            Err(error) => {
                tracing::warn!(
                    %error,
                    assistant = %assistant_name,
                    "refusing self-improvement review because assistant authority validation failed"
                );
                return false;
            }
        };
        if !self
            .self_improvement_schedule
            .record_idle_boundary(&assistant_name, interval)
        {
            return false;
        }
        let Some(root) = self.stack.first() else {
            return false;
        };
        let Some(review) = crate::assistants::self_improvement::spawn_review(
            assistant_name,
            (*root.agent).clone(),
            root.history.clone(),
            self.cwd.clone(),
            self.config.clone(),
            self.redact.clone(),
            self.session.redaction_key_resolver().clone(),
            tx.clone(),
        ) else {
            return false;
        };
        self.self_improvement_review = Some(review);
        true
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
        self.emit_command_capability_notice_if_new(tx).await;

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
                self.reset_goal_progress_tracking().await;
                self.clear_goal_idle_intervention();
                self.maybe_continue_active_goal(&input_queue, tx).await?;
                self.refresh_goal_watchdog(&mut goal_watchdog).await;
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
                        // Foreground work wins as soon as a user submission is
                        // accepted, before injection scanning or preflight can
                        // dispatch their own utility inference.
                        self.preempt_shadow_brief_for_foreground().await;
                        self.preempt_self_improvement_review_for_foreground();
                        self.reset_goal_progress_tracking().await;
                        self.clear_goal_idle_intervention();
                        self.goal_usage_limit_auto_resume_attempts = 0;
                    }
                    if let Err(error) =
                        self.run_folded_submission_commands(items, &input_queue, tx).await
                    {
                        // A failed/finished turn must not exit run_main_loop or
                        // kill the worker.  The per-turn error guards inside
                        // `run_user_input_with_leading_history_inner` already
                        // classify inference failures, cancels, parked
                        // interrupts, and drain gates — returning `Ok(())` so
                        // the loop continues.  Only a truly unexpected error
                        // reaches here; unwind to root (without discarding
                        // pending input — those submissions belong to other
                        // turns and must remain dispatchable), emit a notice,
                        // and keep the driver alive so subsequent submissions
                        // still dispatch instead of poisoning the worker.
                        tracing::error!(error = %error, "turn failed with unexpected error; returning to idle");
                        let _ = tx
                            .send(TurnEvent::Notice {
                                text: format!("internal error: {error}"),
                            })
                            .await;
                        self.unwind_stack_to_root(
                            StackUnwindReason::InferenceFailed {
                                provider: String::new(),
                                model: String::new(),
                                class: crate::engine::model::InferenceErrorClass::Other(
                                    error.to_string(),
                                ),
                                phase: "unknown".to_string(),
                            },
                            tx,
                        )
                        .await;
                        self.pending_idle_reason = Some(crate::engine::IdleReason::Error {
                            class: crate::engine::model::InferenceErrorClass::Other(
                                error.to_string(),
                            ),
                        });
                    }
                    if let Err(error) = self.maybe_continue_active_goal(&input_queue, tx).await {
                        tracing::warn!(error = %error, "goal continuation failed; returning to idle");
                    }
                    self.refresh_goal_watchdog(&mut goal_watchdog).await;
                }
                ctl = control_rx.recv() => {
                    goal_watchdog = None;
                    match ctl {
                        // Control requests arrive at idle (the stack is at
                        // the foreground agent and no turn is in flight) —
                        // a safe compaction boundary by construction.
                        //
                        // This is precisely why `RefreshConfigDerivedState`'s
                        // `applied` receipt is a follow-up and never a
                        // precondition for acknowledging a config replacement:
                        // under a long turn it cannot fire until that turn
                        // ends, so a caller that waited for it here would be
                        // measuring turn length, not worker health.
                        #[cfg(test)]
                        Some(DriverControl::AbortForTest) => {
                            anyhow::bail!("driver abort requested for test");
                        }
                        Some(control) => {
                            self.run_control_with_input_queue(control, &input_queue, tx)
                                .await
                        }
                        None => break,
                    }
                }
                ev = self.job_event_rx.recv() => {
                    goal_watchdog = None;
                    match ev {
                        Some(event) => {
                            self.reset_goal_progress_tracking().await;
                            self.clear_goal_idle_intervention();
                            self.run_job_event(event, &input_queue, tx).await?;
                            self.maybe_continue_active_goal(&input_queue, tx).await?;
                            self.refresh_goal_watchdog(&mut goal_watchdog).await;
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
                        self.reset_goal_progress_tracking().await;
                        self.clear_goal_idle_intervention();
                        self.maybe_continue_active_goal(&input_queue, tx).await?;
                        self.refresh_goal_watchdog(&mut goal_watchdog).await;
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
                    match self.goal_usage_limit_watchdog_action().await? {
                        GoalUsageLimitWatchdogAction::AutoResume => {
                            let _ = tx
                                .send(TurnEvent::Notice {
                                    text: "goal: usage limit backoff elapsed; auto-resuming".to_string(),
                                })
                                .await;
                            self.maybe_continue_active_goal(&input_queue, tx).await?;
                        }
                        GoalUsageLimitWatchdogAction::Exhausted => {
                            let _ = tx
                                .send(TurnEvent::Notice {
                                    text: "goal: usage limit persisted after bounded auto-resume attempts; run `/goal resume` to retry manually".to_string(),
                                })
                                .await;
                        }
                        GoalUsageLimitWatchdogAction::NotUsageLimited => {
                            self.maybe_continue_active_goal(&input_queue, tx).await?;
                        }
                    }
                    self.refresh_goal_watchdog(&mut goal_watchdog).await;
                }
            }
            // Stack has unwound to the root and the queue is drained — the
            // agent is idle until the next message: the same safe inference
            // boundary auto-prune uses. Auto-compact fires here when the last
            // turn pushed ctx% over the configured auto-compact line
            // (implementation note); it emits `CompactReady`
            // and the client re-attaches to the fresh session. Guarded by the
            // one-shot latch + `at_safe_boundary` so it can't loop.
            self.maybe_shadow_brief(tx).await;
            self.maybe_auto_compact(tx).await;
            // Emit the falling edge so the TUI can stop its working-indicator
            // clock, and refresh the "% prunable" projection from the
            // now-settled foreground history.
            self.emit_context_projection(tx).await;
            let turn_id = self.current_lifecycle_turn_id.take();
            let reason = self.take_idle_reason().await;
            let _ = tx.send(TurnEvent::AgentIdle { turn_id, reason }).await;
        }
        Ok(())
    }

    async fn take_idle_reason(&mut self) -> crate::engine::IdleReason {
        if let Some(reason) = self.pending_idle_reason.take() {
            self.goal_was_active_recently = false;
            return reason;
        }
        if self.goal_idle_intervention_pending {
            let code = self
                .goal_idle_intervention_code
                .unwrap_or("agent_failed_to_progress");
            return crate::engine::IdleReason::NeedsIntervention {
                code: code.to_string(),
            };
        }
        match self
            .session
            .db
            .current_session_goal(self.session.id, false)
            .await
            .ok()
            .flatten()
            .map(|goal| goal.disposition)
        {
            Some(crate::db::session_goals::GoalDisposition::BudgetLimited) => {
                crate::engine::IdleReason::BudgetLimited
            }
            Some(crate::db::session_goals::GoalDisposition::InfraPaused) => {
                crate::engine::IdleReason::UsageLimited
            }
            Some(crate::db::session_goals::GoalDisposition::Running) => {
                self.goal_was_active_recently = true;
                crate::engine::IdleReason::Completed
            }
            Some(_) => crate::engine::IdleReason::Completed,
            None if self.goal_was_active_recently => {
                self.goal_was_active_recently = false;
                crate::engine::IdleReason::GoalComplete
            }
            None => crate::engine::IdleReason::Completed,
        }
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

    /// Reject a queued durable steer if its original owner is no longer the
    /// frame about to consume it.  Queue targets carry task labels for normal
    /// UI routing, but the durable lifecycle is UUID-owned; this second fence
    /// prevents a later frame with the same target/name from receiving an old
    /// steer after a pop/rebuild race.
    fn late_steer_owner_mismatch(&self, queue_item_ids: &[uuid::Uuid]) -> Option<String> {
        let foreground_owner = self.stack.last().and_then(|frame| frame.agent_instance_id);
        queue_item_ids.iter().find_map(|queue_item_id| {
            self.pending_late_user_steer_acks
                .get(queue_item_id)
                .and_then(|pending| {
                    (foreground_owner != Some(pending.agent_instance_id)).then(|| {
                        "late user steer owner is no longer the exact live executor".to_string()
                    })
                })
        })
    }

    /// Recover the queued acknowledgement handle for one exact continuation.
    /// A parked accepted steer is no longer in the input queue, so a later
    /// QuestionTool replay must locate its receipt by immutable permit identity
    /// rather than by the now-consumed queue item.
    fn late_steer_queue_item_ids_for_permit(
        &self,
        permit: LateUserSteerPermitIdentity,
    ) -> Vec<uuid::Uuid> {
        self.pending_late_user_steer_acks
            .iter()
            .filter_map(|(queue_item_id, pending)| {
                (pending.agent_instance_id == permit.agent_instance_id
                    && pending.steer_id == permit.steer_id
                    && pending.continuation_id == permit.continuation_id
                    && pending.recovery_epoch == permit.recovery_epoch)
                    .then_some(*queue_item_id)
            })
            .collect()
    }

    /// Start recording the outcome of one exact late-steer continuation.  The
    /// pessimistic default covers every early `Ok(())` return before provider
    /// dispatch (preflight, deadline, and recovery gates): those are orderly
    /// driver exits, not evidence that the user steer ran.
    fn begin_late_steer_continuation(&mut self) {
        self.late_steer_continuation_outcome = Some(LateUserSteerContinuationOutcome::interrupted(
            "late user steer did not reach a completed continuation",
        ));
    }

    /// Record an explicit terminal result only while a late-steer run is
    /// active. Ordinary user turns intentionally do not allocate this state.
    fn finish_late_steer_continuation(&mut self, outcome: LateUserSteerContinuationOutcome) {
        if self.late_steer_continuation_outcome.is_some() {
            self.late_steer_continuation_outcome = Some(outcome);
        }
    }

    /// Settle only the late-steer completions carried by this completed run.
    /// A delivery is acknowledged after the target frame ran its continuation,
    /// not when the worker merely inserted a message into an input queue.
    async fn finish_late_steer_deliveries(
        &mut self,
        queue_item_ids: &[uuid::Uuid],
        outcome: LateUserSteerContinuationOutcome,
    ) {
        // Parking is a durable continuation phase, not a delivery result. In
        // particular, do not remove the sender: the session worker must retain
        // its claim while the exact checkpoint waits for the later decision.
        if matches!(outcome, LateUserSteerContinuationOutcome::Parked) {
            return;
        }
        for queue_item_id in queue_item_ids {
            if let Some(pending) = self.pending_late_user_steer_acks.remove(queue_item_id) {
                // This is the executor-side completion boundary.  A worker can
                // lose its acknowledgement after this point and safely retry
                // only that receipt; it cannot invoke this queued continuation
                // a second time.
                let completion = match &outcome {
                    LateUserSteerContinuationOutcome::Completed => match self
                        .session
                        .db
                        .complete_late_user_decision_steer_execution(
                            self.session.id,
                            pending.steer_id,
                            pending.recovery_epoch,
                            crate::agent_tree::system_now_unix_ms(),
                        )
                        .await
                    {
                        Ok(true) => LateUserSteerContinuationOutcome::Completed,
                        Ok(false) => LateUserSteerContinuationOutcome::failed(
                            "late user steer completion lost its exact durable claim",
                        ),
                        Err(error) => LateUserSteerContinuationOutcome::failed(format!(
                            "persisting late user steer completion failed: {error:#}"
                        )),
                    },
                    // A cancelled, interrupted, or failed continuation must
                    // keep its accepted checkpoint behind the no-redelivery
                    // fence for recovery (or for the owner-terminal rejection
                    // transaction).  Never turn an orderly driver return into
                    // a completed receipt.
                    outcome => outcome.clone(),
                };
                let _ = pending.respond_to.send(completion);
            }
        }
    }

    /// Queue the exact checkpoint of an accepted interactive late steer after
    /// recovery.  Unlike a newly delivered steer, its payload was already
    /// included in the provider request that crossed the immutable acceptance
    /// fence.  The only legal continuation is the snapshot's next model/tool
    /// message; constructing a `UserSubmission` from `payload_json` here
    /// would redeliver the user's instruction as a second turn.
    async fn resume_recovered_interactive_late_steer(
        &mut self,
        agent_instance_id: uuid::Uuid,
        steer_id: uuid::Uuid,
        continuation_id: uuid::Uuid,
        recovery_epoch: uuid::Uuid,
        continuation_checkpoint_json: &str,
        respond_to: tokio::sync::oneshot::Sender<LateUserSteerContinuationOutcome>,
        input_queue: &crate::engine::message::UserSubmissionQueue,
    ) {
        let checkpoint =
            match serde_json::from_str::<serde_json::Value>(continuation_checkpoint_json) {
                Ok(checkpoint) => checkpoint,
                Err(error) => {
                    let _ = respond_to.send(LateUserSteerContinuationOutcome::failed(format!(
                        "accepted late steer continuation checkpoint is malformed: {error}"
                    )));
                    return;
                }
            };
        let checkpoint_matches = checkpoint
            .get("version")
            .and_then(serde_json::Value::as_u64)
            == Some(1)
            && checkpoint
                .get("steer_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value == steer_id.to_string())
            && checkpoint
                .get("continuation_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value == continuation_id.to_string())
            && checkpoint
                .get("agent_instance_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| value == agent_instance_id.to_string());
        if !checkpoint_matches {
            let _ = respond_to.send(LateUserSteerContinuationOutcome::failed(
                "accepted late steer continuation checkpoint is not bound to this executor",
            ));
            return;
        }
        let owner_is_foreground = self
            .stack
            .last()
            .is_some_and(|frame| frame.agent_instance_id == Some(agent_instance_id));
        if !owner_is_foreground {
            let _ = respond_to.send(LateUserSteerContinuationOutcome::interrupted(
                "accepted late steer has no exact foreground interactive executor",
            ));
            return;
        }
        let Some(recovered) = self
            .recovered_interactive_late_steer_continuations
            .get_mut(&agent_instance_id)
        else {
            let _ = respond_to.send(LateUserSteerContinuationOutcome::interrupted(
                "interactive executor has no matching recovered late-steer checkpoint",
            ));
            return;
        };
        if recovered.continuation_id != continuation_id {
            let _ = respond_to.send(LateUserSteerContinuationOutcome::failed(
                "recovered interactive late-steer snapshot belongs to another continuation",
            ));
            return;
        }
        if recovered.permit.steer_id != steer_id
            || recovered.permit.continuation_id != continuation_id
            || recovered.permit.recovery_epoch != recovery_epoch
            || recovered.permit.agent_instance_id != agent_instance_id
        {
            let _ = respond_to.send(LateUserSteerContinuationOutcome::failed(
                "recovered interactive late-steer permit is not bound to this durable checkpoint",
            ));
            return;
        }

        if recovered.has_parked_continuation {
            // The snapshot's prompt predates the parked tool call. Queueing
            // it would re-run the already accepted user steer before the
            // answer replay has produced the real post-tool continuation.
            // Retain the receipt here; `replay_parked_interrupt_call` moves
            // it into the normal completion map while restoring the exact
            // permit on the frame.
            if recovered.pending_response.is_some() {
                let _ = respond_to.send(LateUserSteerContinuationOutcome::Parked);
                return;
            }
            recovered.pending_response = Some(respond_to);
            return;
        }
        let recovered = self
            .recovered_interactive_late_steer_continuations
            .remove(&agent_instance_id)
            .expect("validated recovered late-steer checkpoint disappeared before queueing");

        // Use the regular queue only as a safe-boundary scheduler. Its empty
        // ToolResult text cannot become the model prompt because the queue id
        // is immediately bound to the exact snapshot message below.
        let mut submission = UserSubmission::text("");
        submission.origin = crate::engine::message::SubmissionOrigin::ToolResult;
        submission.run_invocation_id = Some(uuid::Uuid::now_v7());
        let target = self.active_queue_target();
        let (queue_item_id, _) = input_queue.push(submission, target).await;
        self.recovered_interactive_continuations
            .insert(queue_item_id, recovered.next_prompt);
        if let Some(previous) = self.pending_late_user_steer_acks.insert(
            queue_item_id,
            PendingLateUserSteerAck {
                agent_instance_id,
                steer_id,
                continuation_id,
                recovery_epoch,
                respond_to,
            },
        ) {
            let _ = previous
                .respond_to
                .send(LateUserSteerContinuationOutcome::failed(
                    "late user steer queue identity collision",
                ));
        }
    }

    /// Run an out-of-band control request at an idle driver boundary. Each
    /// control owns its scope: conversational controls target the foreground
    /// frame, while session model selection updates the durable root frame.
    #[cfg(test)]
    async fn run_control(&mut self, control: DriverControl, tx: &mpsc::Sender<TurnEvent>) {
        let (queue_update_tx, _queue_update_rx) = tokio::sync::watch::channel::<
            Vec<crate::engine::message::QueuedUserMessage>,
        >(Vec::new());
        let input_queue = crate::engine::message::UserSubmissionQueue::new(queue_update_tx);
        self.run_control_with_input_queue(control, &input_queue, tx)
            .await;
    }

    async fn run_control_with_input_queue(
        &mut self,
        control: DriverControl,
        input_queue: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
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
            DriverControl::WakeGoal => {
                if let Err(error) = self.maybe_continue_active_goal(input_queue, tx).await {
                    tracing::warn!(%error, "waking supervised goal failed");
                }
            }
            DriverControl::ResumeAcceptedLateUserDecisionSteer {
                agent_instance_id,
                steer_id,
                continuation_id,
                recovery_epoch,
                continuation_checkpoint_json,
                respond_to,
                ..
            } => {
                self.resume_recovered_interactive_late_steer(
                    agent_instance_id,
                    steer_id,
                    continuation_id,
                    recovery_epoch,
                    &continuation_checkpoint_json,
                    respond_to,
                    input_queue,
                )
                .await;
            }
            DriverControl::DeliverLateUserDecisionSteer {
                agent_instance_id,
                steer_id,
                continuation_id,
                recovery_epoch,
                payload_json,
                respond_to,
            } => {
                // Mailbox reachability is not runnable-continuation
                // authority. In particular, a late steer that raced a new
                // QuestionTool/approval must remain pending behind that
                // decision rather than being folded into this driver's next
                // input. The worker releases a still-pending claim after this
                // negative receipt and re-attempts only on a later durable
                // `running` transition. A terminal owner has already rejected
                // its undelivered row in that same lifecycle transaction.
                let owner_is_runnable = match self
                    .session
                    .db
                    .agent_instance(self.session.id, agent_instance_id)
                    .await
                {
                    Ok(Some(agent)) => {
                        agent.state == crate::db::agent_tree_decisions::AgentInstanceState::Running
                    }
                    Ok(None) => false,
                    Err(error) => {
                        tracing::warn!(%error, %agent_instance_id, "loading late-steer owner lifecycle state failed closed");
                        false
                    }
                };
                if !owner_is_runnable {
                    let _ = respond_to.send(LateUserSteerContinuationOutcome::interrupted(
                        "late user steer owner is not runnable behind its current continuation",
                    ));
                    return;
                }
                // A steer may never be routed by display name or to a
                // different frame. Interactive children can be foreground;
                // accept only the exact live UUID owner and leave every other
                // durable claim retryable for its own executor.
                if let Some(target) = self
                    .stack
                    .iter()
                    .find(|frame| frame.agent_instance_id == Some(agent_instance_id))
                    .map(|frame| frame.queue_target.clone())
                {
                    // Always schedule through the target frame's queue, even
                    // when it is already foreground. This gives direct and
                    // child-target delivery the same receipt lifetime: a
                    // QuestionTool raised after provider handoff retains the
                    // sender through its later replay instead of returning an
                    // interrupted result merely because this control handler
                    // returned to the main loop.
                    let mut submission = UserSubmission::text(format!(
                        "[Durable late user decision steer for this continuation]\n{payload_json}"
                    ));
                    submission.run_invocation_id = Some(uuid::Uuid::now_v7());
                    let (queue_item_id, _) = input_queue.push(submission, target).await;
                    if let Some(previous) = self.pending_late_user_steer_acks.insert(
                        queue_item_id,
                        PendingLateUserSteerAck {
                            agent_instance_id,
                            steer_id,
                            continuation_id,
                            recovery_epoch,
                            respond_to,
                        },
                    ) {
                        // Queue ids are freshly allocated. If that invariant is
                        // ever violated, fail the prior claim closed rather
                        // than silently replacing its acknowledgement handle.
                        let _ = previous
                            .respond_to
                            .send(LateUserSteerContinuationOutcome::failed(
                                "late user steer queue identity collision",
                            ));
                    }
                } else {
                    let _ = respond_to.send(LateUserSteerContinuationOutcome::interrupted(
                        "late user steer has no live exact agent executor",
                    ));
                }
            }
            DriverControl::ResolveAgentTreeDecision {
                agent_instance_id,
                prompt,
                respond_to,
            } => {
                // Resolve through the parent frame's own model endpoint only
                // while that exact durable executor is still on this driver.
                // The worker falls back to the utility lane if this proof of
                // liveness or delivery acceptance fails.
                let result = match self
                    .stack
                    .iter()
                    .find(|frame| frame.agent_instance_id == Some(agent_instance_id))
                    .map(|frame| {
                        (
                            frame.agent.model.clone(),
                            frame.agent.params.clone(),
                            frame.agent.system.clone(),
                            frame.history.clone(),
                            frame.agent.name.clone(),
                        )
                    }) {
                    // The endpoint belongs to the actual parent frame. Reuse
                    // its complete live request context, not merely its
                    // provider/model selection: retaining the exact system,
                    // history, cache identity, and cancellation boundary is
                    // what makes this a genuine warm-parent route. The packet
                    // remains redacted and the resolver owns no tools.
                    Some((model, params, system, history, agent_name)) => {
                        let cancel = self
                            .cancel_current
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .clone()
                            .unwrap_or_default();
                        model
                            .text_completion_with_live_context(
                                crate::engine::model::UtilityCallSite::AgentTreeDecision,
                                params,
                                &system,
                                &history,
                                &prompt,
                                &agent_name,
                                &cancel,
                            )
                            .await
                            .map_err(|error| format!("warm parent resolver failed: {error:#}"))
                    }
                    None => {
                        Err("warm parent resolver has no live exact agent executor".to_string())
                    }
                };
                let _ = respond_to.send(result);
            }
            DriverControl::ReattachInteractiveTaskChild {
                recovery,
                respond_to,
            } => {
                let result = self
                    .reattach_interactive_task_child(recovery, input_queue, tx)
                    .await
                    .map_err(|error| format!("{error:#}"));
                let _ = respond_to.send(result);
            }
            DriverControl::ReattachNoninteractiveTaskChild {
                recovery,
                respond_to,
            } => {
                let result = self
                    .reattach_noninteractive_task_child(recovery, tx)
                    .await
                    .map_err(|error| format!("{error:#}"));
                let _ = respond_to.send(result);
            }
            DriverControl::ReattachNoninteractiveTaskBatch {
                recoveries,
                terminal_children,
                respond_to,
            } => {
                let result = self
                    .reattach_noninteractive_task_batch(recoveries, terminal_children, tx)
                    .await
                    .map_err(|error| format!("{error:#}"));
                let _ = respond_to.send(result);
            }
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
                let result = match self
                    .rehydrate_root_if_empty_with_policy(
                        &root_agent,
                        crate::engine::rehydrate::RehydratePolicy::heal(),
                    )
                    .await
                {
                    Ok(Some(rehydrated)) => Ok(rehydrated.heals.len()),
                    Ok(None) => Ok(0),
                    Err(error) => Err(format!("{error:#}")),
                };
                let _ = respond_to.send(result);
            }
            DriverControl::ReplayParkedInterrupt {
                interrupt_id,
                agent_instance_id,
                payload,
                response,
                question,
                respond_to,
            } => {
                let result = match Box::pin(self.replay_parked_interrupt_call(
                    interrupt_id,
                    agent_instance_id,
                    *payload,
                    response,
                    *question,
                    tx,
                ))
                .await
                {
                    Ok(()) => {
                        async {
                            self.continue_after_parked_interrupt_replay(input_queue, tx)
                                .await?;
                            Ok(ParkedReplayOutcome::Completed)
                        }
                        .await
                    }
                    Err(error) if crate::engine::interrupt::is_parked(&error) => {
                        Ok(ParkedReplayOutcome::ParkedAgain)
                    }
                    Err(error) => Err(error),
                }
                .map_err(|error| format!("{error:#}"));
                let _ = respond_to.send(result);
            }
            DriverControl::SwapPrimary { name } => {
                self.swap_primary(&name, tx).await;
            }
            DriverControl::SetLlmMode {
                mode,
                prune_after_switch,
            } => {
                self.set_llm_mode(mode, prune_after_switch, tx).await;
            }
            DriverControl::SetToolSurfaceOverride {
                selection,
                prune_after_switch,
                monty_nudge,
            } => {
                self.set_tool_surface_override(selection, prune_after_switch, monty_nudge, tx)
                    .await;
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
            DriverControl::SetLongcache { enabled } => {
                let currently_on = self.prompt_cache_retention_override.is_some();
                let target = enabled.unwrap_or(!currently_on);
                if target && !self.active_model_prompt_cache_retention_supported() {
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: "/longcache: extended prompt-cache retention is not verified for the active model".to_string(),
                        })
                        .await;
                    let _ = tx
                        .send(TurnEvent::LongcacheState {
                            enabled: currently_on,
                            supported: false,
                        })
                        .await;
                } else {
                    self.prompt_cache_retention_override =
                        target.then_some(crate::config::providers::PromptCacheRetention::Extended);
                    for idx in 0..self.stack.len() {
                        let retention =
                            self.resolve_prompt_cache_retention_for(&self.stack[idx].agent.model);
                        Arc::make_mut(&mut self.stack[idx].agent)
                            .params
                            .prompt_cache_retention = retention;
                    }
                    self.emit_longcache_state(tx).await;
                }
            }
            DriverControl::RefreshConfigDerivedState { applied } => {
                self.repin_config_for_turn();
                self.refresh_prompt_cache_retention_from_session();
                if self.prompt_cache_retention_override.is_some() {
                    self.emit_longcache_state(tx).await;
                }
                self.emit_active_model_state_correction(tx).await;
                let _ = applied.send(());
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
            DriverControl::SetMaxPrimaryRounds { max_primary_rounds } => {
                self.set_max_primary_rounds(max_primary_rounds);
            }
            DriverControl::SetActiveModel {
                selection_id,
                provider,
                model,
                persist_as_default,
                trigger,
                reasoning_effort,
                thinking_mode,
                prompt_cache_retention,
            } => {
                let target = crate::config::providers::ActiveModelRef {
                    provider,
                    model,
                    reasoning_effort: reasoning_effort
                        .map(|value| crate::config::providers::ActiveReasoningEffort { value }),
                    thinking_mode,
                    prompt_cache_retention,
                };
                let _ = self
                    .set_active_model_live(
                        selection_id,
                        target,
                        swap::DefaultModelWriteIntent::from_flags(persist_as_default),
                        None,
                        trigger,
                        tx,
                    )
                    .await;
            }
            DriverControl::EmitRecoveredDefaultTerminals {
                transactions,
                respond_to,
            } => {
                let result = self
                    .emit_recovered_default_terminals(transactions, tx)
                    .await;
                if let Some(respond_to) = respond_to {
                    let _ = respond_to.send(result);
                }
            }
            DriverControl::SetActiveModelWithDeadline {
                selection_id,
                deadline,
                terminal_claimed,
                completion,
                provider,
                model,
                persist_as_default,
                trigger,
                reasoning_effort,
                thinking_mode,
                prompt_cache_retention,
            } => {
                let target = crate::config::providers::ActiveModelRef {
                    provider,
                    model,
                    reasoning_effort: reasoning_effort
                        .map(|value| crate::config::providers::ActiveReasoningEffort { value }),
                    thinking_mode,
                    prompt_cache_retention,
                };
                let _ = self
                    .set_active_model_live(
                        selection_id,
                        target,
                        swap::DefaultModelWriteIntent::from_flags(persist_as_default),
                        Some(swap::ModelSelectionTerminal {
                            deadline,
                            claimed: &terminal_claimed,
                        }),
                        trigger,
                        tx,
                    )
                    .await;
                let _ = completion.send(());
            }
        }
    }

    async fn maybe_continue_active_goal(
        &mut self,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<()> {
        if let Some((goal_id, generation, turn_id)) = self.goal_root_turn.take() {
            let worker_evidence = self
                .stack
                .first()
                .and_then(|frame| {
                    let start = frame.history.len().saturating_sub(12);
                    serde_json::to_string(&frame.history[start..]).ok()
                })
                .unwrap_or_else(|| "successful root turn; transcript unavailable".to_string());
            let worker_evidence = self.schedule.redaction_table().scrub(&worker_evidence);
            if let Some(goal) = self
                .session
                .db
                .finish_goal_root_turn_with_evidence(goal_id, generation, turn_id, &worker_evidence)
                .await?
            {
                self.maybe_start_goal_supervision_round(&goal, tx).await?;
            }
            return Ok(());
        }
        let Some(goal) = self
            .session
            .db
            .current_session_goal(self.session.id, false)
            .await?
        else {
            if self.goal_was_active_recently {
                self.pending_idle_reason = Some(crate::engine::IdleReason::GoalComplete);
            }
            if let Some(scratch) = self.goal_scratch.take() {
                let _ = scratch.cleanup();
            }
            self.reset_goal_progress_tracking().await;
            self.clear_goal_idle_intervention();
            return Ok(());
        };
        if goal.disposition != crate::db::session_goals::GoalDisposition::Running {
            self.reset_goal_progress_tracking().await;
            self.clear_goal_idle_intervention();
            return Ok(());
        }
        self.goal_was_active_recently = true;
        self.goal_usage_limit_auto_resume_attempts = 0;
        if goal.tokens_used >= goal.token_budget {
            let _ = self
                .session
                .db
                .update_session_goal(
                    self.session.id,
                    crate::db::session_goals::GoalDisposition::BudgetLimited,
                    None,
                    None,
                    Some("token budget exhausted"),
                )
                .await;
            self.reset_goal_progress_tracking().await;
            self.clear_goal_idle_intervention();
            return Ok(());
        }
        match goal.phase {
            Some(crate::db::session_goals::GoalPhase::Planning)
            | Some(crate::db::session_goals::GoalPhase::Evaluating)
            | Some(crate::db::session_goals::GoalPhase::Verifying) => {
                self.maybe_start_goal_supervision_round(&goal, tx).await?;
                Ok(())
            }
            Some(crate::db::session_goals::GoalPhase::Executing) => {
                if self.schedule.snapshot().is_empty() {
                    self.dispatch_goal_root_turn(&goal, input_rx, tx).await?;
                }
                Ok(())
            }
            None => Ok(()),
        }
    }

    async fn maybe_start_goal_supervision_round(
        &mut self,
        goal: &crate::db::session_goals::SessionGoal,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<()> {
        if let Some(round) = &self.goal_supervision_round
            && round.goal_id == goal.id
            && round.attempt_generation == goal.attempt_generation
        {
            self.emit_goal_supervision_progress(tx).await;
            return Ok(());
        }
        let cfg = self.goal_supervision_config_for(goal)?;
        if self.goal_scratch.is_none() {
            self.goal_scratch = Some(cockpit_host::goal_scratch::GoalScratchRoot::create(
                goal.id,
            )?);
        }
        // Validate every role directory before leasing durable work. Once a row
        // is leased, no fallible filesystem setup may orphan it outside a round.
        for role in ["planner", "evaluator", "skeptic"] {
            self.goal_scratch
                .as_ref()
                .expect("created above")
                .role(role)?;
        }
        self.goal_supervision_round = Some(GoalSupervisionRound {
            goal_id: goal.id,
            attempt_generation: goal.attempt_generation,
            total: 0,
            jobs: HashMap::new(),
        });
        // Track this round's leasing outcome so the refused-spawn retry flag is
        // recomputed WITHOUT clobbering a still-pending retry. A round driven by
        // a fast panelist completion can run while a sibling's refused control
        // job is still within its 300s lease (not yet re-leasable): that round
        // leases nothing here, and must leave the flag armed so the watchdog
        // fires once the lease expires — clearing it unconditionally would strand
        // the leased job and re-stall the panel.
        let mut leased_any = false;
        let mut refused_any = false;
        while let Some(job) = self
            .session
            .db
            .lease_goal_control_job(
                goal.id,
                goal.attempt_generation,
                chrono::Utc::now().timestamp(),
                300,
            )
            .await?
        {
            leased_any = true;
            let job_id = job.job_id.to_string();
            let (worker, model) = match job.role {
                crate::db::session_goals::GoalControlRole::Planner => (
                    crate::engine::schedule::authority::SpawnWorkerKind::GoalPlanner,
                    cfg.planner_model.clone(),
                ),
                crate::db::session_goals::GoalControlRole::Evaluator => (
                    crate::engine::schedule::authority::SpawnWorkerKind::GoalEvaluator,
                    cfg.evaluator_model.clone(),
                ),
                crate::db::session_goals::GoalControlRole::Gatekeeper => (
                    crate::engine::schedule::authority::SpawnWorkerKind::GoalGatekeeper,
                    cfg.gatekeeper_model.clone(),
                ),
                crate::db::session_goals::GoalControlRole::ColdSkeptic => (
                    crate::engine::schedule::authority::SpawnWorkerKind::GoalColdSkeptic,
                    cfg.cold_skeptic_model.clone(),
                ),
            };
            let scratch_role = match job.role {
                crate::db::session_goals::GoalControlRole::Planner => "planner",
                crate::db::session_goals::GoalControlRole::Evaluator => "evaluator",
                crate::db::session_goals::GoalControlRole::Gatekeeper
                | crate::db::session_goals::GoalControlRole::ColdSkeptic => "skeptic",
            };
            let write_scope = self
                .goal_scratch
                .as_ref()
                .expect("created above")
                .role(scratch_role)?
                .display()
                .to_string();
            let spawn_result =
                self.schedule
                    .spawn_swarm(crate::engine::schedule::authority::SpawnSpec {
                        job_id: Some(job_id.clone()),
                        goal_provenance: Some((job.goal_id, job.attempt_generation)),
                        worker,
                        prompt: job.request_json.clone(),
                        write_scope,
                        model,
                        model_origin:
                            crate::engine::schedule::authority::SpawnModelOrigin::HostConfig,
                        depth: 0,
                        max_depth: 0,
                    });
            // A refused spawn (oversized prompt or a full swarm queue) registers
            // no job and will emit no `Completed`. Counting it into the round
            // would wedge goal supervision permanently, since the round only
            // retires once its job set empties. Skip it and surface the refusal.
            // The control job stays `leased` — so a Verifying panel's
            // terminal-verdict gate (which counts pending+leased panelists) still
            // correctly blocks on it rather than resolving a verdict short a
            // panelist — and is re-leased after its 300s TTL on a later
            // supervision round. This downgrades the former permanent wedge to a
            // soft stall that self-heals the next time the goal loop wakes (a
            // full queue drains and each completion wakes it; an oversized prompt
            // is a logged user error). `queued`/`scheduled` spawns DO run and
            // emit `Completed`, so they are still tracked. Deliberately NOT
            // finished-as-failed here: `finish_goal_control_job(Err)` coerces a
            // panelist to a fabricated `Refute`/pauses the goal on a transient
            // full queue.
            if let Some(refusal) = spawn_result.strip_prefix("refused:") {
                tracing::warn!(
                    job_id = %job_id,
                    reason = refusal.trim(),
                    "goal-supervision swarm spawn refused; not tracking it in this round"
                );
                // Note the refusal; the post-loop recompute arms a watchdog-
                // backed retry so a quiescent session eventually re-leases the
                // (now-leased) control job instead of stalling on it.
                refused_any = true;
                continue;
            }
            let round = self
                .goal_supervision_round
                .as_mut()
                .expect("initialized before leasing");
            round.total = round.total.saturating_add(1);
            round.jobs.insert(job_id, job);
        }
        // Recompute the refused-spawn retry state from THIS round's outcome, but
        // only when the round actually leased work. A round that leased nothing
        // (a prior refused job's 300s lease not yet expired) leaves any pending
        // retry untouched so the watchdog stays armed until the lease expires.
        if leased_any {
            if refused_any {
                // Bound the retries: a permanently-failing refusal (e.g. an
                // oversized control prompt) stops re-waking after a few attempts
                // instead of looping forever, while a transient full queue
                // usually drains within the cap. `refresh_goal_watchdog` stops
                // arming once the cap is reached.
                self.goal_refused_spawn_retry_attempts =
                    self.goal_refused_spawn_retry_attempts.saturating_add(1);
                self.goal_refused_spawn_retry_pending = true;
            } else {
                // Everything leased this round spawned cleanly — the refusal
                // condition cleared.
                self.goal_refused_spawn_retry_pending = false;
                self.goal_refused_spawn_retry_attempts = 0;
            }
        }
        let total = self
            .goal_supervision_round
            .as_ref()
            .map_or(0, |round| round.total);
        if total == 0 {
            self.goal_supervision_round = None;
            return Ok(());
        }
        self.emit_goal_supervision_progress(tx).await;
        Ok(())
    }

    fn goal_supervision_config_for(
        &self,
        goal: &crate::db::session_goals::SessionGoal,
    ) -> Result<crate::config::extended::GoalSupervisionConfig> {
        // Model selection, panel size, and attempt limits are creation-time
        // policy. A config reload may only exercise the live master switch;
        // otherwise an existing goal changes authority mid-flight.
        resolved_goal_supervision_config(
            &goal.resolved_policy_json,
            self.config.extended().goal_supervision.enabled,
        )
    }

    fn goal_host_directive(&self, goal: &crate::db::session_goals::SessionGoal) -> String {
        let contract = goal
            .contract
            .as_ref()
            .map(|contract| serde_json::to_string(contract).unwrap_or_default())
            .unwrap_or_else(|| "null".to_string());
        let gaps: Vec<String> = goal
            .unresolved_gaps
            .iter()
            .take(8)
            .map(|gap| crate::db::session_goals::sanitize_goal_finding(gap))
            .collect();
        let next = goal
            .evaluator_outcome_json
            .as_deref()
            .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok())
            .and_then(|value| {
                value
                    .get("next_step")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .or_else(|| {
                goal.contract
                    .as_ref()
                    .and_then(|contract| contract.implementation_checklist.first())
                    .cloned()
            })
            .unwrap_or_else(|| "follow the next unmet acceptance outcome".to_string());
        serde_json::json!({
            "host_goal_directive": {
                "goal_id": goal.id,
                "attempt_generation": goal.attempt_generation,
                "immutable_contract": contract,
                "lifecycle": { "disposition": goal.disposition, "phase": goal.phase },
                "usage": {
                    "tokens_used": goal.tokens_used,
                    "token_budget": goal.token_budget,
                    "remaining": goal.token_budget.saturating_sub(goal.tokens_used),
                    "elapsed_active_ms": goal.elapsed_active_ms
                },
                "unresolved_verifier_gaps": gaps,
                "next_checklist_guidance": next,
                "safety": "Do not bypass approvals, sandbox restrictions, usage limits, or no-progress safeguards. The host alone decides completion."
            }
        }).to_string()
    }

    async fn dispatch_goal_root_turn(
        &mut self,
        goal: &crate::db::session_goals::SessionGoal,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<()> {
        let turn_id = self
            .session
            .db
            .begin_goal_root_turn(goal.id, goal.attempt_generation)
            .await?;
        self.goal_root_turn = Some((goal.id, goal.attempt_generation, turn_id));
        let result = self
            .run_user_input(
                UserSubmission::text(self.goal_host_directive(goal)),
                input_rx,
                tx,
            )
            .await;
        if let Err(error) = result {
            self.goal_root_turn = None;
            let _ = self
                .session
                .db
                .fail_goal_root_turn(goal.id, goal.attempt_generation, turn_id)
                .await;
            return Err(error);
        }
        Ok(())
    }

    async fn emit_goal_supervision_progress(&self, tx: &mpsc::Sender<TurnEvent>) {
        if let Some(round) = &self.goal_supervision_round {
            let done = round.total.saturating_sub(round.jobs.len());
            let _ = tx
                .send(TurnEvent::GoalSupervisionProgress {
                    done,
                    total: round.total,
                })
                .await;
        }
    }

    pub(in crate::engine::driver) async fn handle_goal_supervision_completion(
        &mut self,
        job_id: &str,
        result: &str,
        failed: bool,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<bool> {
        let Some(mut round) = self.goal_supervision_round.take() else {
            return Ok(false);
        };
        let Some(job) = round.jobs.remove(job_id) else {
            self.goal_supervision_round = Some(round);
            return Ok(false);
        };

        let updated = self
            .session
            .db
            .finish_goal_control_job(
                job,
                if failed {
                    Err("scheduler job failed")
                } else {
                    Ok(result)
                },
            )
            .await?;
        let done = round.total.saturating_sub(round.jobs.len());
        let total = round.total;
        if !round.jobs.is_empty() {
            self.goal_supervision_round = Some(round);
        }
        let _ = tx
            .send(TurnEvent::GoalSupervisionProgress { done, total })
            .await;

        if let Some(goal) = updated {
            match (goal.disposition, goal.phase) {
                (crate::db::session_goals::GoalDisposition::Complete, None) => {
                    if let Some(scratch) = self.goal_scratch.take() {
                        let _ = scratch.cleanup();
                    }
                    self.pending_idle_reason = Some(crate::engine::IdleReason::GoalComplete);
                    self.goal_was_active_recently = false;
                }
                (
                    crate::db::session_goals::GoalDisposition::Running,
                    Some(crate::db::session_goals::GoalPhase::Executing),
                ) => {
                    self.dispatch_goal_root_turn(&goal, input_rx, tx).await?;
                }
                _ => {}
            }
        }
        Ok(true)
    }

    async fn reset_goal_progress_tracking(&mut self) {
        self.goal_progress_last_seq = self.latest_session_event_seq().await;
    }

    fn clear_goal_idle_intervention(&mut self) {
        self.goal_idle_intervention_pending = false;
        self.goal_idle_intervention_code = None;
    }

    fn inference_failure_provider_status(
        failure: &crate::engine::model::InferenceFailure,
    ) -> Option<u16> {
        // Prefer the retained observed HTTP status. A billing-body HTTP 429 is
        // reclassified to `BillingOrQuotaExhausted` (whose class carries no
        // status), but `observed_status` retains the real 429 so this recovery
        // helper still sees it; fall back to the class-derived status otherwise.
        failure
            .observed_status
            .or_else(|| failure.class.provider_status())
    }

    async fn handle_goal_usage_limit_failure(
        &mut self,
        failure: &crate::engine::model::InferenceFailure,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> bool {
        let provider_status = Self::inference_failure_provider_status(failure);
        if !crate::engine::retry::is_usage_limit_failure(&failure.class, provider_status) {
            return false;
        }
        let Ok(Some(goal)) = self
            .session
            .db
            .current_session_goal(self.session.id, false)
            .await
        else {
            return false;
        };
        if goal.disposition != crate::db::session_goals::GoalDisposition::Running {
            return false;
        }
        if let Err(e) = self
            .session
            .db
            .update_session_goal(
                self.session.id,
                crate::db::session_goals::GoalDisposition::InfraPaused,
                None,
                None,
                Some("provider usage or rate limit reached"),
            )
            .await
        {
            tracing::warn!(error = %e, "marking goal usage_limited failed");
            return false;
        }
        self.reset_goal_progress_tracking().await;
        self.clear_goal_idle_intervention();
        if self.goal_usage_limit_auto_resume_attempts >= GOAL_USAGE_LIMIT_MAX_AUTO_RESUME_ATTEMPTS {
            self.pending_idle_reason = Some(crate::engine::IdleReason::NeedsIntervention {
                code: GOAL_USAGE_LIMIT_INTERVENTION_CODE.to_string(),
            });
            let _ = tx
                .send(TurnEvent::Notice {
                    text: "goal: usage limit persisted after bounded auto-resume attempts; run `/goal resume` to retry manually".to_string(),
                })
                .await;
        } else {
            self.pending_idle_reason = Some(crate::engine::IdleReason::UsageLimited);
            let _ = tx
                .send(TurnEvent::Notice {
                    text: "goal: provider usage limit reached; auto-resuming after backoff"
                        .to_string(),
                })
                .await;
        }
        true
    }

    fn goal_usage_limit_backoff(&self) -> Duration {
        let multiplier = 1u64
            .checked_shl(u32::from(self.goal_usage_limit_auto_resume_attempts))
            .unwrap_or(u64::MAX);
        let secs = GOAL_USAGE_LIMIT_BACKOFF_BASE
            .as_secs()
            .saturating_mul(multiplier)
            .min(GOAL_USAGE_LIMIT_BACKOFF_MAX.as_secs());
        Duration::from_secs(secs)
    }

    async fn goal_usage_limit_watchdog_action(&mut self) -> Result<GoalUsageLimitWatchdogAction> {
        let Some(goal) = self
            .session
            .db
            .current_session_goal(self.session.id, false)
            .await?
        else {
            return Ok(GoalUsageLimitWatchdogAction::NotUsageLimited);
        };
        if goal.disposition != crate::db::session_goals::GoalDisposition::InfraPaused {
            return Ok(GoalUsageLimitWatchdogAction::NotUsageLimited);
        }
        if goal.pause_reason != Some(crate::db::session_goals::GoalPauseReason::ProviderUsageLimit)
        {
            return Ok(GoalUsageLimitWatchdogAction::NotUsageLimited);
        }
        if self.goal_usage_limit_auto_resume_attempts >= GOAL_USAGE_LIMIT_MAX_AUTO_RESUME_ATTEMPTS {
            self.pending_idle_reason = Some(crate::engine::IdleReason::NeedsIntervention {
                code: GOAL_USAGE_LIMIT_INTERVENTION_CODE.to_string(),
            });
            return Ok(GoalUsageLimitWatchdogAction::Exhausted);
        }
        self.goal_usage_limit_auto_resume_attempts =
            self.goal_usage_limit_auto_resume_attempts.saturating_add(1);
        self.session
            .db
            .update_session_goal(
                self.session.id,
                crate::db::session_goals::GoalDisposition::Running,
                None,
                None,
                Some("auto-resuming after provider usage-limit backoff"),
            )
            .await?;
        self.goal_idle_intervention_pending = false;
        self.goal_idle_intervention_code = None;
        Ok(GoalUsageLimitWatchdogAction::AutoResume)
    }

    #[cfg(test)]
    async fn observe_goal_progress_turn(&mut self) -> Result<GoalProgressObservation> {
        let latest_seq = self.latest_session_event_seq().await;
        if self.goal_progress_last_seq < 0 {
            self.goal_progress_last_seq = latest_seq;
            if !self.root_last_assistant_was_prose_without_tools() {
                return Ok(GoalProgressObservation::default());
            }
        }
        let observation = self
            .goal_progress_observation_since(self.goal_progress_last_seq)
            .await?;
        self.goal_progress_last_seq = latest_seq;
        Ok(observation)
    }

    #[cfg(test)]
    async fn goal_progress_observation_since(
        &self,
        anchor_seq: i64,
    ) -> Result<GoalProgressObservation> {
        let mut observation = GoalProgressObservation {
            observed_turn: self.root_last_assistant_was_prose_without_tools(),
            mutating_action: false,
            context_delta: false,
        };
        for event in self
            .session
            .db
            .list_session_events(self.session.id)
            .await?
            .into_iter()
            .filter(|event| event.seq > anchor_seq)
        {
            match event.kind.as_str() {
                "assistant_message" | "inference_failure" | "failed_turn_recovery" => {
                    observation.observed_turn = true;
                }
                "tool_call" | "tool_call_completed" => {
                    observation.observed_turn = true;
                    if Self::goal_event_is_mutating_action(&event.data) {
                        observation.mutating_action = true;
                    }
                    if Self::goal_event_has_context_delta(&event.data) {
                        observation.context_delta = true;
                    }
                }
                "resource_promotion" | "session_compacted" => {
                    observation.observed_turn = true;
                    observation.mutating_action = true;
                }
                _ => {}
            }
        }
        Ok(observation)
    }

    #[cfg(test)]
    fn goal_event_is_mutating_action(data: &serde_json::Value) -> bool {
        let Some(tool) = data.get("tool").and_then(serde_json::Value::as_str) else {
            return false;
        };
        match tool {
            "write" | "edit" => true,
            "bash" => data
                .get("wire_input")
                .or_else(|| data.get("original_input"))
                .and_then(|input| input.get("command"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(Self::goal_bash_command_is_mutating),
            _ => false,
        }
    }

    #[cfg(test)]
    fn goal_event_has_context_delta(data: &serde_json::Value) -> bool {
        data.get("tool")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|tool| tool == "goal")
            && data
                .get("wire_input")
                .or_else(|| data.get("original_input"))
                .and_then(|input| {
                    (input.get("action").and_then(serde_json::Value::as_str) == Some("update"))
                        .then_some(input)
                })
                .and_then(|input| input.get("context_delta"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|delta| !delta.trim().is_empty())
    }

    #[cfg(test)]
    fn goal_bash_command_is_mutating(command: &str) -> bool {
        let normalized = command.split_whitespace().collect::<Vec<_>>().join(" ");
        normalized == "git commit"
            || normalized.starts_with("git commit ")
            || normalized.contains("&& git commit ")
            || normalized.contains("; git commit ")
            || normalized.contains("| git commit ")
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

    async fn is_goal_intervention_continue(&self, text: &str) -> bool {
        if !self.goal_idle_intervention_pending {
            return false;
        }
        if !is_continue_command(text) {
            return false;
        }
        self.session
            .db
            .current_session_goal(self.session.id, false)
            .await
            .ok()
            .flatten()
            .is_some_and(|goal| {
                goal.disposition == crate::db::session_goals::GoalDisposition::Running
            })
    }

    async fn latest_session_event_seq(&self) -> i64 {
        self.session
            .db
            .list_session_events(self.session.id)
            .await
            .ok()
            .and_then(|events| events.last().map(|event| event.seq))
            .unwrap_or(0)
    }

    async fn failed_turn_retry_prompt_for(&self, text: &str) -> Option<(String, String)> {
        if !is_continue_command(text) {
            return None;
        }
        let events = self
            .session
            .db
            .list_session_events(self.session.id)
            .await
            .ok()?;
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
        // Host-generated recovery record: fixed status/trigger strings and the
        // host-minted recovery_id / recommended-action shape — no model-authored
        // free text, so no session-table literal. Frame-less `record_event` is
        // correct; nothing to journal.
        if let Err(e) = self
            .session
            .record_event(
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
            )
            .await
        {
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
            .await
            .ok()
            .flatten()
            .map(|goal| {
                serde_json::json!({
                    "id": goal.id.to_string(),
                    "objective": goal.objective,
                    "status": goal.disposition.as_str(),
                    "token_budget": goal.token_budget,
                    "tokens_used": goal.tokens_used,
                    "blocked_attempts": goal.blocked_attempts,
                })
            });
        // The rationale/routing stays class-based; the DIAGNOSTIC `provider_status`
        // below uses the retained observed status so a billing failure
        // reclassified to `BillingOrQuotaExhausted` still reports its observed 429
        // (issue #23, B4).
        let class_status = failure.class.provider_status();
        // Route the raw provider body through the omission funnel: the recovery
        // record carries the fixed marker plus the queryable observed-status and
        // recovery metadata, never the provider text.
        let safe = crate::engine::model::safe_provider_detail(failure);
        let provider_status = safe.observed_status;
        let (retry_final_decision, classification_rationale) =
            crate::engine::retry::failure_retry_decision_and_rationale(
                &failure.class,
                class_status,
            );
        let provider_body_snippet = safe.marker_string();
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
            "recovery": safe.recovery.as_str(),
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
        // Host-observed progress snapshot: every field is derived from the host's
        // own tool-call history (files read/edited, commands run, worktree dirty
        // set — `dirty_files_source: host_tool_history`), not from model-authored
        // free text. Any secret a model placed in a tool argument was already
        // journaled at that originating tool_call (tool_dispatch.rs frames it), so
        // this recovery summary carries no un-journaled session-table literal.
        // Frame-less `record_event` is correct.
        if let Err(e) = self
            .session
            .record_event(
                crate::db::session_log::SessionEventKind::FailedTurnRecovery,
                Some(&agent.name),
                Some(&recovery_id),
                &data,
            )
            .await
        {
            tracing::warn!(error = %e, "record failed_turn_recovery event failed");
        }
        let _ = tx
            .send(TurnEvent::Notice {
                text: "inference failed; type `continue` to retry the same turn from the stored recovery record".to_string(),
            })
            .await;
    }

    async fn goal_continue_progress_since(&self, anchor_seq: i64) -> bool {
        let Ok(events) = self.session.db.list_session_events(self.session.id).await else {
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
                .await
                .ok()
                .flatten()
                .is_none_or(|goal| {
                    goal.disposition != crate::db::session_goals::GoalDisposition::Running
                })
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
        // Host-generated goal diagnostic (fixed kind/reason strings + host anchor
        // seq) — no model-authored free text, so no session-table literal.
        // Frame-less `record_event` is correct; nothing to journal.
        if let Err(e) = self
            .session
            .record_event(
                crate::db::session_log::SessionEventKind::GoalProgressDiagnostic,
                Some(self.active_agent()),
                None,
                &data,
            )
            .await
        {
            tracing::warn!(error = %e, "recording goal progress diagnostic failed");
        }
        let _ = tx.send(TurnEvent::Notice { text }).await;
        self.reset_goal_progress_tracking().await;
        self.goal_idle_intervention_pending = true;
        self.goal_idle_intervention_code = Some("agent_failed_to_progress_after_continue");
    }

    /// Fire matching observe-only lifecycle hooks against the turn-pinned hook
    /// registry (`self.config.snapshot().hooks()` — the same snapshot handed to
    /// `DispatchEnv.hooks`). Observe hooks never block and are fail-open;
    /// production always spawns through the shipped `TokioCommandRunner` /
    /// `DefaultProcessEnv`, exactly like the pre/post-tool sites.
    async fn fire_observe_hook(
        &self,
        event: crate::config::extended::hooks::HookEvent,
        match_value: &str,
        tool_name: Option<&str>,
        tool_call_id: Option<&str>,
        fields: crate::engine::agent::hooks::ObserveFields<'_>,
    ) {
        let snapshot = self.config.snapshot();
        crate::engine::agent::hooks::run_observe_hooks(
            &crate::engine::agent::hooks::TokioCommandRunner::with_optional_containment(
                self.session.process_containment(),
            ),
            &crate::engine::agent::hooks::DefaultProcessEnv,
            snapshot.hooks(),
            event,
            match_value,
            self.session.id,
            &self.cwd,
            &self.session.db,
            tool_name,
            tool_call_id,
            None,
            None,
            fields,
        )
        .await;
    }

    /// Fire a `subagentStart` observe hook for a CHILD subagent, against the
    /// turn-pinned hook registry. CHILD-ONLY by construction: every remaining
    /// call site is a genuine child spawn (interactive stack push, noninteractive
    /// register-running, detached Swarm start) — never a root boundary. Matcher /
    /// `subagentType` is the child agent type; `subagentId` identifies the
    /// delegating `task` call so the downstream attention consumer can pair
    /// start/stop. Observe-only / fail-open.
    ///
    /// `subagentStop` is NOT fired through here: it is a G::Stop event dispatched
    /// (in every mode) through [`Self::consult_active_child_stop_gate`] /
    /// [`Self::fire_terminal_subagent_stop`] / the noninteractive + Swarm loop
    /// gates, all of which call [`run_stop_hooks`]. The `event` parameter is
    /// retained so this stays a single observe helper, but only `SubagentStart`
    /// reaches it.
    async fn fire_subagent_hook(
        &self,
        event: crate::config::extended::hooks::HookEvent,
        subagent_type: &str,
        subagent_id: Option<&str>,
        end_reason: Option<&str>,
    ) {
        let snapshot = self.config.snapshot();
        crate::engine::agent::hooks::run_observe_hooks(
            &crate::engine::agent::hooks::TokioCommandRunner::with_optional_containment(
                self.session.process_containment(),
            ),
            &crate::engine::agent::hooks::DefaultProcessEnv,
            snapshot.hooks(),
            event,
            // Matcher = child agent type (the `ChildAgentType` matcher policy).
            subagent_type,
            self.session.id,
            &self.cwd,
            &self.session.db,
            None,
            None,
            Some(subagent_type),
            subagent_id,
            crate::engine::agent::hooks::ObserveFields {
                end_reason,
                ..Default::default()
            },
        )
        .await;
    }

    /// Fire a paired `subagentStop` for every interactive child frame still on
    /// the stack at driver-loop teardown.
    ///
    /// The normal child-teardown paths (`pop_child_with_envelope` on success,
    /// `unwind_stack_to_root` on cancel / gate / interrupt / inference failure)
    /// already fire `subagentStop` and return with the stack back at the root
    /// frame. The one remaining escape is a driver-loop exit via a fatal error
    /// (`Err` propagation) that abandons a still-active child frame WITHOUT
    /// unwinding. Called once when the driver loop resolves (see
    /// `run_main_loop`'s caller in `session_worker/run.rs`), this closes that
    /// gap so no `subagentStart` is left unpaired: each abandoned child emits
    /// exactly one `subagentStop` with `endReason` = `aborted`. On every clean
    /// / already-unwound exit the stack is at root, so this fires nothing (no
    /// double-stop). Deepest child first, mirroring an unwind.
    pub(crate) async fn drain_orphaned_child_stop_hooks(&self) {
        // Collect first so no borrow of `self.stack` is held across the await
        // inside `fire_subagent_hook`.
        let orphans: Vec<(String, Option<String>)> = self
            .stack
            .iter()
            .skip(1)
            .rev()
            .map(|frame| {
                (
                    frame.agent.name.clone(),
                    frame
                        .answering
                        .as_ref()
                        .map(|pending| pending.call_id.clone()),
                )
            })
            .collect();
        for (subagent_type, subagent_id) in orphans {
            self.fire_terminal_subagent_stop(&subagent_type, subagent_id.as_deref(), "aborted")
                .await;
        }
    }

    /// Fire `subagentStart` for a detached-`Swarm` child that just started
    /// (spawn mode 3 of 3), and record it so its paired `subagentStop` can fire
    /// on completion. Driven by draining [`ScheduleEvent::SwarmChildStarted`],
    /// which the schedule authority emits ONLY for genuine swarm children
    /// (`bee` / `scout`) — never goal-supervision control workers (guidance
    /// L22), so this only ever runs for real subagents. Child-only; matcher /
    /// `subagentType` is the child agent type, `subagentId` is the schedule
    /// `job_id` (the correlation the paired stop reuses).
    async fn fire_swarm_subagent_start(&mut self, job_id: &str, subagent_type: &str) {
        // Record before firing so a completion racing on the same turn boundary
        // (it cannot: SwarmChildStarted is always drained first) still pairs.
        self.swarm_subagents.insert(
            job_id.to_string(),
            SwarmSubagentHookState {
                subagent_type: subagent_type.to_string(),
                stop_gate_fired: false,
            },
        );
        self.fire_subagent_hook(
            crate::config::extended::hooks::HookEvent::SubagentStart,
            subagent_type,
            Some(job_id),
            None,
        )
        .await;
    }

    /// Record that a genuine detached-`Swarm` child already ran its controlling
    /// `subagentStop` gate inside `run_swarm_loop`. Driven by the ordered
    /// [`crate::engine::schedule::ScheduleEvent::SwarmChildStopGateCompleted`]
    /// marker (drained FIFO before the child's `Completed`), so
    /// [`Self::fire_swarm_subagent_stop_if_tracked`] can skip the terminal fire
    /// for a normally-gated success and never double-fire.
    fn mark_swarm_subagent_stop_gate_completed(&mut self, job_id: &str) {
        if let Some(state) = self.swarm_subagents.get_mut(job_id) {
            state.stop_gate_fired = true;
        }
    }

    /// Fire the TERMINAL `subagentStop` for a detached-`Swarm` child if — and
    /// only if — its `job_id` was tracked by a prior
    /// [`Self::fire_swarm_subagent_start`] AND its controlling gate did NOT
    /// already fire inside `run_swarm_loop`. Called when a swarm job's
    /// [`ScheduleEvent::Completed`] is drained (the single terminal event per job
    /// — the runner sends it on success/failure, the authority synthesizes it on
    /// cancel). A genuine success ran its own gate in the loop (marked via
    /// [`Self::mark_swarm_subagent_stop_gate_completed`]) and is skipped here, so
    /// there is exactly ONE `subagentStop` per stop. A failure / detach-loss
    /// bypasses the loop gate and fires a terminal stop here (`failed`, or
    /// `aborted` for a non-failed terminal with no gate — a cancel). A `Completed`
    /// for a job never in the map (a goal-supervision worker, guidance L22; or a
    /// loop/timer/background job) fires nothing.
    async fn fire_swarm_subagent_stop_if_tracked(&mut self, job_id: &str, failed: bool) {
        let Some(state) = self.swarm_subagents.remove(job_id) else {
            return;
        };
        if state.stop_gate_fired {
            // The child's in-loop gate already fired its single `subagentStop`
            // (`completed`). No terminal fire may follow on ANY drained
            // `Completed` — success OR a cancel-synthesized non-failed terminal
            // OR a late/failed terminal — else it would double the stop.
            return;
        }
        let end_reason = if failed { "failed" } else { "aborted" };
        self.fire_terminal_subagent_stop(&state.subagent_type, Some(job_id), end_reason)
            .await;
    }

    /// Fire a paired `subagentStop` for every detached-`Swarm` child still
    /// tracked at driver-loop teardown. The normal path pairs each start with a
    /// stop when the child's `Completed` is drained; the one remaining escape is
    /// a driver-loop exit that abandons a live child whose terminal `Completed`
    /// will never be drained (detach loss / shutdown). Called once when the
    /// driver loop resolves (alongside [`Self::drain_orphaned_child_stop_hooks`]),
    /// this closes that gap: each residual child emits exactly one `subagentStop`
    /// with `endReason` = `aborted`. On every clean exit the map is empty (each
    /// child's `Completed` already removed it), so this fires nothing — no
    /// double-stop.
    pub(crate) async fn drain_orphaned_swarm_stop_hooks(&mut self) {
        // Drain first so no borrow of `self.swarm_subagents` is held across the
        // await inside `fire_terminal_subagent_stop`.
        let orphans: Vec<(String, SwarmSubagentHookState)> = self.swarm_subagents.drain().collect();
        for (job_id, state) in orphans {
            // Skip a child whose in-loop gate already fired its single
            // `subagentStop` (`completed`) — e.g. detach loss between its
            // `SwarmChildStopGateCompleted` marker and its (never-drained)
            // `Completed`. Firing `aborted` for it here would double the stop.
            if state.stop_gate_fired {
                continue;
            }
            self.fire_terminal_subagent_stop(&state.subagent_type, Some(&job_id), "aborted")
                .await;
        }
    }

    /// Fire `stopFailure` observe hooks on an inference/API error that ends the
    /// attempt without a normal stop gate. Matcher / `errorClass` are the stable
    /// per-variant token from [`error_class_match_value`]. Never fired on a
    /// normal `TurnOutcome::Done`.
    async fn run_stop_failure_hooks(&self, class: &crate::engine::model::InferenceErrorClass) {
        let match_value = crate::engine::agent::hooks::error_class_match_value(class);
        self.fire_observe_hook(
            crate::config::extended::hooks::HookEvent::StopFailure,
            match_value,
            None,
            None,
            crate::engine::agent::hooks::ObserveFields {
                error_class: Some(match_value),
                ..Default::default()
            },
        )
        .await;
    }

    /// Consult the ROOT stop gate on a genuine normal end of the root turn.
    ///
    /// This is the ONE production caller of the root stop gate. It is reached
    /// only from the `TurnOutcome::Done` arm of the main loop, with the stack at
    /// the root frame and no queued user work left to fold — i.e. the point the
    /// root turn would otherwise end normally. Every non-genuine boundary
    /// (cancel, parked interrupt, daemon-drain gate, terminal inference/API
    /// error) `return`s from the `Err(..)` arms BEFORE the `match outcome`, and
    /// the primary-round ceiling returns from the `Continue` arm, so none of
    /// them can enter the gate. Compaction never routes here.
    ///
    /// Runs the matching `stop` hooks (matcher `end_turn`) via [`run_stop_hooks`]
    /// against the caller-owned per-turn [`StopGateState`] latch. The runner /
    /// process-environment seams are injected so the production call passes the
    /// shipped `TokioCommandRunner` / `DefaultProcessEnv` (exactly like every
    /// other hook site) while tests can drive real `block` / `continue:false`
    /// decisions through a fake runner.
    ///
    /// NEVER-REOPEN by construction: the latch is a LOCAL owned by the single
    /// `run_user_input` invocation that runs this turn (`root_stop_gate`). It is
    /// created fresh per turn (per originating user-turn id) and dropped on EVERY
    /// exit path of that method — normal end, cancel, parked interrupt, drain
    /// gate, and inference error alike — so no latch can outlive its turn, be
    /// consulted after the turn's loop returns, or be resurrected by a
    /// late/replayed boundary. The caller additionally re-checks the cancel token
    /// AFTER this returns and before injecting any continuation, so a cancel that
    /// races in DURING the hook cannot force another model round.
    async fn consult_root_stop_gate(
        &self,
        runner: &dyn crate::engine::agent::hooks::CommandRunner,
        process_env: &dyn crate::engine::agent::hooks::ProcessEnv,
        state: &mut crate::engine::agent::hooks::StopGateState,
    ) -> crate::engine::agent::hooks::StopHookOutcome {
        let snapshot = self.config.snapshot();
        crate::engine::agent::hooks::run_stop_hooks(
            runner,
            process_env,
            snapshot.hooks(),
            crate::config::extended::hooks::HookEvent::Stop,
            "end_turn",
            self.session.id,
            &self.cwd,
            &self.session.db,
            // Root `stop` carries no child identity; the closed matcher token
            // `end_turn` becomes `stopReason` inside `run_stop_hooks`.
            None,
            None,
            None,
            state,
        )
        .await
    }

    /// Fire the unified `subagentStop` for a TERMINAL child stop (abort / fail /
    /// cancel), through the ONE G::Stop dispatcher [`run_stop_hooks`]. A dead or
    /// aborted child can never continue, so this runs the hooks and records the
    /// envelope (camelCase `subagentType` / `subagentId` / `endReason`) against a
    /// FRESH, discarded [`StopGateState`] and ignores the returned outcome — there
    /// is no continuation gate and no latch to reopen. This is the SINGLE firing
    /// per stop for every terminal child path (interactive unwind / orphan drain,
    /// noninteractive failure / whole-job cancel, detached-Swarm failure / detach
    /// loss), so no `subagentStop` observe double is possible.
    async fn fire_terminal_subagent_stop(
        &self,
        subagent_type: &str,
        subagent_id: Option<&str>,
        end_reason: &str,
    ) {
        let snapshot = self.config.snapshot();
        let mut discarded = crate::engine::agent::hooks::StopGateState::default();
        let _ = crate::engine::agent::hooks::run_stop_hooks(
            &crate::engine::agent::hooks::TokioCommandRunner::with_optional_containment(
                self.session.process_containment(),
            ),
            &crate::engine::agent::hooks::DefaultProcessEnv,
            snapshot.hooks(),
            crate::config::extended::hooks::HookEvent::SubagentStop,
            // Matcher = child agent type (the `ChildAgentType` matcher policy).
            subagent_type,
            self.session.id,
            &self.cwd,
            &self.session.db,
            Some(subagent_type),
            subagent_id,
            Some(end_reason),
            &mut discarded,
        )
        .await;
    }

    /// Consult the stop gate owned by the currently-active INTERACTIVE child
    /// frame on a genuine child completion (`TurnOutcome::Return` / `Done` with a
    /// child on the stack), through the unified [`run_stop_hooks`] G::Stop
    /// dispatcher (`endReason = completed`). The latch lives ON the child frame
    /// (`AgentSession::stop_gate`), so the continuation budget is independent per
    /// nested child and — being dropped when the frame pops / unwinds — is
    /// never-reopen airtight by construction: a cancelled / aborted / parent-
    /// cancelled child unwinds (dropping the frame + its latch) and can never
    /// re-enter the gate. The state is moved out across the hook await so no stack
    /// borrow is held, and restored only if the SAME child is still active.
    async fn consult_active_child_stop_gate(
        &mut self,
        runner: &dyn crate::engine::agent::hooks::CommandRunner,
        process_env: &dyn crate::engine::agent::hooks::ProcessEnv,
    ) -> crate::engine::agent::hooks::StopHookOutcome {
        if self.stack.len() <= 1 {
            return crate::engine::agent::hooks::StopHookOutcome::End;
        }
        let frame = self.stack.last_mut().expect("stack checked nonempty");
        let child_type = frame.agent.name.clone();
        let child_id = frame
            .answering
            .as_ref()
            .map(|pending| pending.call_id.clone());
        let mut state = std::mem::take(&mut frame.stop_gate);
        let snapshot = self.config.snapshot();
        let outcome = crate::engine::agent::hooks::run_stop_hooks(
            runner,
            process_env,
            snapshot.hooks(),
            crate::config::extended::hooks::HookEvent::SubagentStop,
            &child_type,
            self.session.id,
            &self.cwd,
            &self.session.db,
            Some(&child_type),
            child_id.as_deref(),
            Some("completed"),
            &mut state,
        )
        .await;
        if let Some(frame) = self.stack.last_mut()
            && frame.agent.name == child_type
            && frame
                .answering
                .as_ref()
                .map(|pending| pending.call_id.as_str())
                == child_id.as_deref()
        {
            frame.stop_gate = state;
        }
        outcome
    }

    /// Build the host-generated continuation message injected into the ROOT
    /// frame when a `stop` hook blocks the turn from ending.
    ///
    /// The aggregated block reason(s) and any `additionalContext` become a
    /// single host-authored user message. It is built directly and threaded
    /// back through the loop as the next prompt; it NEVER passes through
    /// [`Self::record_user_message_event`], and its origin
    /// ([`SubmissionOrigin::Internal`], whose `user_prompt_submit_source()` is
    /// `None`) marks it as host-driven — so stop-continuation feedback can never
    /// re-fire `userPromptSubmit`.
    pub(crate) fn stop_continuation_prompt(
        reason: String,
        additional_context: Option<String>,
    ) -> Message {
        let mut text = reason;
        if let Some(ctx) = additional_context
            && !ctx.is_empty()
        {
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(&ctx);
        }
        crate::engine::message::build_user_message(UserSubmission {
            expected_model_state_generation: None,
            expected_model: None,
            kind: UserSubmissionKind::User,
            origin: crate::engine::message::SubmissionOrigin::Internal,
            text,
            display_text: None,
            tag_expansions: Vec::new(),
            images: Vec::new(),
            forced_skill: None,
            origin_principal: None,
            job_id: None,
            preflight_cleaned: None,
            queue_item_ids: Vec::new(),
            client_submissions: Vec::new(),
            queue_target: None,
            pending_terminal_disposition: None,
            run_invocation_id: None,
        })
    }

    async fn record_user_message_event(
        &mut self,
        agent: Option<&str>,
        origin_principal: Option<&str>,
        data: &serde_json::Value,
        receipts: &[crate::engine::message::ClientSubmissionReceipt],
        tx: &mpsc::Sender<TurnEvent>,
        // `userPromptSubmit` matcher / `promptSource`: `Some("user")` for a
        // genuine direct external submission, `Some("queued")` for a queued-user
        // fold, and `None` to SUPPRESS the event entirely for host / goal /
        // scheduled / system-driven auto-turns (which reach the same recording
        // path via `run_user_input` but are not user prompts). Host-injected
        // stop-continuation feedback never calls this method at all.
        prompt_source: Option<&'static str>,
    ) -> UserMessageRecordOutcome {
        for attempt in 0..USER_MESSAGE_EVENT_WRITE_ATTEMPTS {
            #[cfg(test)]
            let result = if self.test_fail_all_user_message_event_writes {
                Err(anyhow::anyhow!(
                    "test injected persistent user-message event write failure"
                ))
            } else if self.test_fail_next_user_message_event_write {
                self.test_fail_next_user_message_event_write = false;
                Err(anyhow::anyhow!(
                    "test injected user-message event write failure"
                ))
            } else {
                self.session
                    .record_event_with_origin(
                        crate::db::session_log::SessionEventKind::UserMessage,
                        agent,
                        None,
                        origin_principal,
                        data,
                    )
                    .await
            };
            #[cfg(not(test))]
            let result = self
                .session
                .record_event_with_origin(
                    crate::db::session_log::SessionEventKind::UserMessage,
                    agent,
                    None,
                    origin_principal,
                    data,
                )
                .await;

            match result {
                Ok(seq) => {
                    // `userPromptSubmit` observe hooks: fire once, AFTER the
                    // user-message row is durably persisted, keyed off the real
                    // user-submit source. Suppressed (never fired) for host /
                    // goal / scheduled auto-turns (`prompt_source == None`).
                    // Observe-only / fail-open.
                    if let Some(source) = prompt_source {
                        self.fire_observe_hook(
                            crate::config::extended::hooks::HookEvent::UserPromptSubmit,
                            source,
                            None,
                            None,
                            crate::engine::agent::hooks::ObserveFields {
                                prompt_source: Some(source),
                                ..Default::default()
                            },
                        )
                        .await;
                    }
                    return UserMessageRecordOutcome::Recorded(seq);
                }
                Err(error) if receipts.is_empty() => {
                    tracing::warn!(%error, "record user_message event failed");
                    return UserMessageRecordOutcome::Untracked;
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        receipt_count = receipts.len(),
                        attempt = attempt + 1,
                        max_attempts = USER_MESSAGE_EVENT_WRITE_ATTEMPTS,
                        "durable client-submission receipt write failed before inference"
                    );
                    if attempt == 0 {
                        let _ = tx
                            .send(TurnEvent::Notice {
                                text: "Saving the accepted message failed; inference has not started and the exact payload will be retried."
                                    .to_string(),
                            })
                            .await;
                    }
                    if attempt + 1 < USER_MESSAGE_EVENT_WRITE_ATTEMPTS {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        UserMessageRecordOutcome::RetryRequired
    }

    async fn record_terminal_client_submissions(
        &self,
        receipts: &[crate::engine::message::ClientSubmissionReceipt],
        disposition: crate::db::session_log::ClientSubmissionTerminalDisposition,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> bool {
        if receipts.is_empty() {
            return true;
        }
        match self
            .session
            .record_terminal_client_submissions(receipts, disposition)
            .await
        {
            Ok(()) => {
                let _ = tx
                    .send(TurnEvent::UserMessagesTerminated {
                        client_submission_ids: receipts.iter().map(|receipt| receipt.id).collect(),
                        disposition: disposition.into(),
                    })
                    .await;
                true
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    receipt_count = receipts.len(),
                    disposition = disposition.as_str(),
                    "terminal client-submission receipt write failed"
                );
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: "Saving the terminal message disposition failed; retained accepted payloads remain held for a later retry."
                            .to_string(),
                    })
                    .await;
                false
            }
        }
    }

    async fn record_queued_user_fold(
        &mut self,
        folded: &UserSubmission,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> std::result::Result<Option<i64>, ()> {
        if matches!(
            folded.pending_terminal_disposition,
            Some(
                crate::engine::message::PendingSubmissionTerminalDisposition::OversizedTextArtifact
            )
        ) {
            tracing::error!("refusing to fold a receipt-keyed oversized text artifact submission");
            return Err(());
        }
        if folded.queue_item_ids.is_empty() {
            return Ok(None);
        }
        let target = folded
            .queue_target
            .clone()
            .unwrap_or_else(|| self.active_queue_target());
        let data = user_message_event_data(UserMessageEventData {
            text: &folded.text,
            display_text: folded.display_text.as_deref(),
            tag_expansions: &folded.tag_expansions,
            job_id: folded.job_id.as_deref(),
            queue_item_ids: &folded.queue_item_ids,
            client_submissions: &folded.client_submissions,
            queue_target: Some(&target),
            preflight_cleaned: folded.preflight_cleaned.as_deref(),
        });
        let seq = match self
            .record_user_message_event(
                Some(target.agent.as_str()),
                folded.origin_principal.as_deref(),
                &data,
                &folded.client_submissions,
                tx,
                // A fold is a genuine queued-USER submission — fire `queued`
                // only when the folded submission is itself an external user
                // origin, never for a host-driven origin that reached the batch.
                folded.origin.user_prompt_submit_source().map(|_| "queued"),
            )
            .await
        {
            UserMessageRecordOutcome::Recorded(seq) => Some(seq),
            UserMessageRecordOutcome::Untracked => None,
            UserMessageRecordOutcome::RetryRequired => return Err(()),
        };
        let _ = tx
            .send(TurnEvent::QueuedUserMessagesFolded {
                text: folded.text.clone(),
                display_text: folded.display_text.clone(),
                tag_expansions: folded.tag_expansions.clone(),
                queue_item_ids: folded.queue_item_ids.clone(),
                target,
                seq,
                preflight_cleaned: folded.preflight_cleaned.clone(),
            })
            .await;
        Ok(seq)
    }

    /// Loads the durable phase-one record for a submission. The queue's mutable
    /// string is never trusted as source identity: FCM2 is decoded again and
    /// compared with the receipt-keyed lease before any provider boundary.
    async fn reserved_oversized_user_submission(
        &self,
        submission: &UserSubmission,
        require_current_source_match: bool,
    ) -> Result<Option<ReservedOversizedUserSubmission>> {
        let Some(receipt) = submission.client_submissions.first() else {
            return Ok(None);
        };
        if submission.client_submissions.len() != 1 || !submission.images.is_empty() {
            return Ok(None);
        }
        let Some(stored) = self
            .session
            .db
            .reserved_text_artifact_submission(self.session.id, *receipt.id.as_bytes())
            .await?
        else {
            return Ok(None);
        };
        let canonical =
            crate::proto_crate::send_user_message_v2::CanonicalSendUserMessageV2::decode(
                &stored.canonical_message,
            )?;
        anyhow::ensure!(
            canonical.session_id == self.session.id,
            "FCM2 session mismatch"
        );
        anyhow::ensure!(
            canonical.request.client_submission_id == receipt.id,
            "FCM2 client submission mismatch"
        );
        anyhow::ensure!(
            canonical.request.attachments.is_empty(),
            "oversized source carries media attachments"
        );
        anyhow::ensure!(
            canonical.request.text.len() > 64 * 1024
                && canonical.request.text.len()
                    <= crate::proto_crate::send_user_message_v2::MAX_MESSAGE_TEXT_BYTES,
            "oversized source violates FCM2 bounds"
        );
        anyhow::ensure!(
            crate::db::text_artifacts::source_digest(&canonical.request.text)
                == stored.reservation.source_digest
                && canonical.request.text.len() == stored.reservation.source_bytes,
            "FCM2 source differs from its reservation identity"
        );
        if require_current_source_match {
            anyhow::ensure!(
                canonical.request.text == submission.text,
                "queued source differs from the reserved FCM2 source"
            );
        }
        Ok(Some(ReservedOversizedUserSubmission {
            reservation: stored.reservation,
            source_text: canonical.request.text,
        }))
    }

    async fn reject_reserved_oversized_user_submission(
        &self,
        reservation: crate::db::text_artifacts::TextArtifactReservation,
        reason: crate::db::text_artifacts::TextArtifactRejectReason,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> bool {
        match self
            .session
            .db
            .reject_and_release_text_artifact_reservation(
                reservation,
                reason,
                chrono::Utc::now().timestamp_millis(),
            )
            .await
        {
            Ok(crate::db::text_artifacts::TextArtifactReservationTransition::Applied(_)) => true,
            Ok(crate::db::text_artifacts::TextArtifactReservationTransition::Stale) => {
                // A renew/reaper/materializer won. Do not write a legacy
                // terminal receipt over that durable winner.
                false
            }
            Err(error) => {
                tracing::warn!(%error, "reject-and-release of oversized user artifact failed");
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: "Saving oversized-message rejection failed; no provider will run and durable replay will reconcile it."
                            .to_owned(),
                    })
                    .await;
                false
            }
        }
    }

    /// A queued oversized FCM2 source is receipt-owned. Once its exact lease
    /// is absent, this durable receipt state — never the queue's mutable text
    /// or an in-memory marker — decides the only safe branch: do not execute
    /// the source again. This helper is used at every no-lease race boundary
    /// so a reaper/materializer winner cannot accidentally re-enter the
    /// ordinary inline/provider path.
    async fn oversized_artifact_no_lease_notice(
        &self,
        client_submission_id: Option<uuid::Uuid>,
    ) -> String {
        let Some(client_submission_id) = client_submission_id else {
            return "Oversized message has no durable submission identity; it will not execute its source."
                .to_owned();
        };
        match self
            .session
            .db
            .text_artifact_submission_durable_state(
                self.session.id,
                *client_submission_id.as_bytes(),
            )
            .await
        {
            Ok(crate::db::text_artifacts::TextArtifactSubmissionDurableState::Terminal {
                reason,
            }) => {
                format!(
                    "Oversized message reached durable terminal outcome {}; it will not execute its source.",
                    reason.as_str()
                )
            }
            Ok(crate::db::text_artifacts::TextArtifactSubmissionDurableState::Materialized) => {
                "Oversized message was already durably materialized; it will not execute its source again."
                    .to_owned()
            }
            Ok(crate::db::text_artifacts::TextArtifactSubmissionDurableState::Accepted) => {
                "Oversized message has an accepted durable receipt but no live lease; it will not execute its source."
                    .to_owned()
            }
            Ok(crate::db::text_artifacts::TextArtifactSubmissionDurableState::Missing) => {
                "Oversized message lost its durable receipt; it will not execute its source."
                    .to_owned()
            }
            Err(error) => {
                tracing::warn!(%error, "loading durable oversized message receipt state failed");
                "Oversized message outcome could not be loaded; it will not execute its source."
                    .to_owned()
            }
        }
    }

    async fn prepare_queued_user_submission(
        &mut self,
        mut submission: UserSubmission,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Option<UserSubmission> {
        let requires_durable_oversized_outcome = matches!(
            submission.pending_terminal_disposition,
            Some(
                crate::engine::message::PendingSubmissionTerminalDisposition::OversizedTextArtifact
            )
        );
        let initial_oversized_reservation = match self
            .reserved_oversized_user_submission(&submission, true)
            .await
        {
            Ok(Some(stored)) => {
                let now_ms = chrono::Utc::now().timestamp_millis();
                match self
                    .session
                    .db
                    .renew_text_artifact_reservation(stored.reservation.clone(), now_ms)
                    .await
                {
                    Ok(Some(reservation)) => Some(reservation),
                    Ok(None) => {
                        // A concurrent renew/reaper/materializer owns the
                        // durable winner. This worker must not run security or
                        // a utility provider until a replay has established it.
                        let durable_notice = self
                            .oversized_artifact_no_lease_notice(
                                submission
                                    .client_submissions
                                    .first()
                                    .map(|receipt| receipt.id),
                            )
                            .await;
                        let _ = tx
                            .send(TurnEvent::Notice {
                                text: durable_notice,
                            })
                            .await;
                        return None;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "renewing oversized message reservation failed");
                        return None;
                    }
                }
            }
            Ok(None) if requires_durable_oversized_outcome => {
                // A durable FCM2 identity was queued, but its exact lease is
                // no longer live. This is a terminal/replay-only branch (for
                // example a reaper won); never reinterpret the original body
                // as an ordinary inline submission and never run a provider.
                // Consult the receipt itself rather than trusting the
                // in-memory marker: a reaper/materializer can have won after
                // the lookup, and an accepted-without-lease row is corruption
                // that must remain non-executable too.
                let durable_notice = self
                    .oversized_artifact_no_lease_notice(
                        submission
                            .client_submissions
                            .first()
                            .map(|receipt| receipt.id),
                    )
                    .await;
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: durable_notice,
                    })
                    .await;
                return None;
            }
            Ok(None) => None,
            Err(error) => {
                tracing::warn!(%error, "loading oversized message reservation failed");
                return None;
            }
        };
        let has_oversized_artifact_lease = initial_oversized_reservation.is_some();
        // Preflight and inbound translation may await utility providers. Keep
        // the exact phase-one lease renewed for that entire interval, rather
        // than discovering an expired token only when phase two starts.
        let mut oversized_lease = initial_oversized_reservation.map(|reservation| {
            OversizedArtifactLeaseKeeper::start(self.session.db.clone(), reservation)
        });
        if matches!(
            submission.pending_terminal_disposition,
            Some(crate::engine::message::PendingSubmissionTerminalDisposition::PreflightRejected)
        ) {
            if oversized_lease.is_some() {
                let reservation = match finish_oversized_artifact_lease(&mut oversized_lease).await
                {
                    Ok(Some(reservation)) => reservation,
                    Ok(None) => {
                        let durable_notice = self
                            .oversized_artifact_no_lease_notice(
                                submission
                                    .client_submissions
                                    .first()
                                    .map(|receipt| receipt.id),
                            )
                            .await;
                        let _ = tx
                            .send(TurnEvent::Notice {
                                text: durable_notice,
                            })
                            .await;
                        return None;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "finishing oversized message lease before pending rejection failed");
                        return None;
                    }
                };
                let client_submission_ids = submission
                    .client_submissions
                    .iter()
                    .map(|receipt| receipt.id)
                    .collect();
                let _ = self
                    .reject_reserved_oversized_user_submission(
                        reservation,
                        crate::db::text_artifacts::TextArtifactRejectReason::PreflightRejected,
                        tx,
                    )
                    .await;
                let _ = tx
                    .send(TurnEvent::UserMessageRetracted {
                        client_submission_ids,
                    })
                    .await;
                self.emit_context_projection(tx).await;
                return None;
            }
            self.settle_preflight_rejection(submission, input_rx, tx)
                .await;
            return None;
        }
        // Defensive for callers outside the main dequeue branch: no
        // foreground preparation may overlap unfinished shadow utility work.
        self.preempt_shadow_brief_for_foreground().await;
        self.preempt_self_improvement_review_for_foreground();
        if self.preflight_will_run(&submission.text) {
            let _ = tx
                .send(TurnEvent::PreflightStarted {
                    client_submission_ids: submission
                        .client_submissions
                        .iter()
                        .map(|receipt| receipt.id)
                        .collect(),
                })
                .await;
        }
        let (injection, preflight) = tokio::join!(
            self.injection_check_only(&submission.text),
            self.run_preflight(&submission.text),
        );
        #[cfg(test)]
        let rejected_for_test = std::mem::take(&mut self.test_reject_next_submission_preflight);
        #[cfg(not(test))]
        let rejected_for_test = false;
        let injection_rejected = if rejected_for_test {
            true
        } else if let Some((threshold, outcome)) = injection {
            !self.apply_injection_outcome(threshold, outcome, tx).await
        } else {
            false
        };
        if injection_rejected {
            if oversized_lease.is_some() {
                let reservation = match finish_oversized_artifact_lease(&mut oversized_lease).await
                {
                    Ok(Some(reservation)) => reservation,
                    Ok(None) => {
                        let durable_notice = self
                            .oversized_artifact_no_lease_notice(
                                submission
                                    .client_submissions
                                    .first()
                                    .map(|receipt| receipt.id),
                            )
                            .await;
                        let _ = tx
                            .send(TurnEvent::Notice {
                                text: durable_notice,
                            })
                            .await;
                        return None;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "finishing oversized message lease before rejection failed");
                        return None;
                    }
                };
                let client_submission_ids = submission
                    .client_submissions
                    .iter()
                    .map(|receipt| receipt.id)
                    .collect();
                let rejection = if rejected_for_test {
                    crate::db::text_artifacts::TextArtifactRejectReason::PreflightRejected
                } else {
                    crate::db::text_artifacts::TextArtifactRejectReason::SecurityRejected
                };
                let _ = self
                    .reject_reserved_oversized_user_submission(reservation, rejection, tx)
                    .await;
                let _ = tx
                    .send(TurnEvent::UserMessageRetracted {
                        client_submission_ids,
                    })
                    .await;
                self.emit_context_projection(tx).await;
                return None;
            }
            submission.pending_terminal_disposition = Some(
                crate::engine::message::PendingSubmissionTerminalDisposition::PreflightRejected,
            );
            self.settle_preflight_rejection(submission, input_rx, tx)
                .await;
            return None;
        }
        let (raw_text, cleaned_for_display, forced_skill) = self
            .resolve_preflight_outcome(preflight, &submission.text, submission.forced_skill, tx)
            .await;
        let inbound_text = self.translate_inbound(&raw_text).await;
        if oversized_lease.is_some() {
            match finish_oversized_artifact_lease(&mut oversized_lease).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    let durable_notice = self
                        .oversized_artifact_no_lease_notice(
                            submission
                                .client_submissions
                                .first()
                                .map(|receipt| receipt.id),
                        )
                        .await;
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: durable_notice,
                        })
                        .await;
                    return None;
                }
                Err(error) => {
                    tracing::warn!(%error, "finishing oversized message lease after preprocessing failed");
                    return None;
                }
            }
        }
        Some(UserSubmission {
            expected_model_state_generation: None,
            expected_model: None,
            kind: UserSubmissionKind::User,
            origin: submission.origin,
            text: inbound_text,
            display_text: submission.display_text,
            tag_expansions: submission.tag_expansions,
            images: submission.images,
            forced_skill,
            origin_principal: submission.origin_principal,
            job_id: submission.job_id,
            preflight_cleaned: cleaned_for_display,
            queue_item_ids: submission.queue_item_ids,
            client_submissions: submission.client_submissions,
            queue_target: submission.queue_target,
            pending_terminal_disposition: has_oversized_artifact_lease.then_some(
                crate::engine::message::PendingSubmissionTerminalDisposition::OversizedTextArtifact,
            ),
            run_invocation_id: submission.run_invocation_id,
        })
    }

    async fn settle_preflight_rejection(
        &mut self,
        mut submission: UserSubmission,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        let client_submission_ids = submission
            .client_submissions
            .iter()
            .map(|receipt| receipt.id)
            .collect();
        if !self
            .record_terminal_client_submissions(
                &submission.client_submissions,
                crate::db::session_log::ClientSubmissionTerminalDisposition::PreflightRejected,
                tx,
            )
            .await
        {
            submission.pending_terminal_disposition = Some(
                crate::engine::message::PendingSubmissionTerminalDisposition::PreflightRejected,
            );
            input_rx
                .requeue_front_after(
                    submission,
                    self.active_queue_target(),
                    DURABLE_SUBMISSION_RETRY_BACKOFF,
                )
                .await;
            return;
        }
        let _ = tx
            .send(TurnEvent::UserMessageRetracted {
                client_submission_ids,
            })
            .await;
        self.emit_context_projection(tx).await;
        let turn_id = self.current_lifecycle_turn_id.take();
        let reason = self.take_idle_reason().await;
        let _ = tx.send(TurnEvent::AgentIdle { turn_id, reason }).await;
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
        // A phase-one FCM2 lease is tied to exactly one user event and must
        // survive to that event's phase-two materialization. Folding it into
        // leading history would both lose the owner slot and let the old
        // inline recording path run, so process every member independently.
        if submissions.iter().any(|submission| {
            matches!(
                submission.pending_terminal_disposition,
                Some(
                    crate::engine::message::PendingSubmissionTerminalDisposition::OversizedTextArtifact
                )
            )
        }) {
            for submission in submissions {
                self.run_user_input(submission, input_rx, tx).await?;
            }
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

        let mut pending = std::collections::VecDeque::from(submissions);
        let last = pending
            .pop_back()
            .expect("non-empty batch has a final turn");
        let mut leading_history = Vec::with_capacity(pending.len());
        let mut leading_queue_item_ids = Vec::new();
        while let Some(submission) = pending.pop_front() {
            if self.record_queued_user_fold(&submission, tx).await.is_err() {
                if let Some(top) = self.stack.last_mut() {
                    top.history.extend(leading_history);
                }
                pending.push_front(submission);
                pending.push_back(last);
                while let Some(submission) = pending.pop_back() {
                    input_rx
                        .requeue_front_after(
                            submission,
                            self.active_queue_target(),
                            DURABLE_SUBMISSION_RETRY_BACKOFF,
                        )
                        .await;
                }
                input_rx.finish(&leading_queue_item_ids).await;
                return Ok(());
            }
            leading_queue_item_ids.extend(submission.queue_item_ids.iter().copied());
            leading_history.push(crate::engine::message::build_user_message(UserSubmission {
                expected_model_state_generation: None,
                expected_model: None,
                kind: UserSubmissionKind::User,
                origin: submission.origin,
                text: submission.text,
                display_text: None,
                tag_expansions: Vec::new(),
                images: submission.images,
                forced_skill: None,
                origin_principal: None,
                job_id: None,
                preflight_cleaned: None,
                queue_item_ids: Vec::new(),
                client_submissions: Vec::new(),
                queue_target: None,
                pending_terminal_disposition: None,
                run_invocation_id: None,
            }));
        }
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
                    let Some(prepared) = self
                        .prepare_queued_user_submission(*submission, input_rx, tx)
                        .await
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

    async fn refresh_goal_watchdog(&self, watchdog: &mut Option<Pin<Box<Sleep>>>) {
        let status = self
            .session
            .db
            .current_session_goal(self.session.id, false)
            .await
            .ok()
            .flatten()
            .map(|g| (g.disposition, g.pause_reason));
        let delay = match status {
            Some((crate::db::session_goals::GoalDisposition::Running, _)) => {
                // Idle root with pending background work — nudge the goal loop
                // to re-evaluate once it settles.
                let prose = (self.root_last_assistant_was_prose_without_tools()
                    && !self.schedule.snapshot().is_empty())
                .then_some(GOAL_WATCHDOG_DELAY);
                // A refused swarm spawn left a control job leased with nothing to
                // wake the loop; retry after the lease TTL so a quiescent session
                // self-heals instead of stalling the panel indefinitely — but
                // only up to the retry cap, so a permanently-failing refusal
                // stops re-waking the loop.
                let refused = (self.goal_refused_spawn_retry_pending
                    && self.goal_refused_spawn_retry_attempts < GOAL_REFUSED_SPAWN_MAX_RETRIES)
                    .then_some(GOAL_REFUSED_SPAWN_RETRY_DELAY);
                // Arm for whichever fires first.
                [prose, refused].into_iter().flatten().min()
            }
            Some((
                crate::db::session_goals::GoalDisposition::InfraPaused,
                Some(crate::db::session_goals::GoalPauseReason::ProviderUsageLimit),
            )) if self.goal_usage_limit_auto_resume_attempts
                < GOAL_USAGE_LIMIT_MAX_AUTO_RESUME_ATTEMPTS =>
            {
                Some(self.goal_usage_limit_backoff())
            }
            _ => None,
        };
        if let Some(delay) = delay {
            if watchdog.is_none() {
                *watchdog = Some(Box::pin(tokio::time::sleep(delay)));
            }
        } else {
            *watchdog = None;
        }
    }

    /// Load the layered providers config for the live model switch, honoring a
    /// test-injected config when present (mirrors [`Self::active_providers_config`])
    /// and otherwise reading the worker's generation-aware config snapshot.
    /// Disk writes become visible here when the config watcher refreshes it.
    fn live_providers_config(&self) -> Result<crate::config::providers::ProvidersConfig> {
        #[cfg(test)]
        if let Some((providers, _, _)) = &self.test_providers_override {
            return Ok(providers.clone());
        }
        Ok(self.config.providers())
    }

    fn resolve_prompt_cache_retention_for(
        &self,
        model: &crate::engine::model::Model,
    ) -> Option<String> {
        let selection = self.active_selection_for_model(model);
        self.resolve_prompt_cache_retention_for_selection(model, &selection)
    }

    fn resolve_prompt_cache_retention_for_selection(
        &self,
        model: &crate::engine::model::Model,
        selection: &crate::config::providers::ActiveModelRef,
    ) -> Option<String> {
        let selection_preference = (selection.provider == model.provider_id()
            && selection.model == model.model_id_ref())
        .then_some(selection.prompt_cache_retention)
        .flatten();
        self.live_providers_config()
            .ok()?
            .resolve_prompt_cache_retention(
                model.provider_id(),
                model.model_id_ref(),
                self.prompt_cache_retention_override
                    .or(selection_preference),
            )
            .map(str::to_string)
    }

    fn active_model_prompt_cache_retention_supported(&self) -> bool {
        let Some(active_idx) = self.active_frame_index() else {
            return false;
        };
        let model = &self.stack[active_idx].agent.model;
        self.live_providers_config()
            .ok()
            .and_then(|cfg| {
                cfg.resolve_prompt_cache_retention(
                    model.provider_id(),
                    model.model_id_ref(),
                    Some(crate::config::providers::PromptCacheRetention::Extended),
                )
            })
            .is_some()
    }

    async fn emit_longcache_state(&self, tx: &mpsc::Sender<TurnEvent>) {
        let _ = tx
            .send(TurnEvent::LongcacheState {
                enabled: self.prompt_cache_retention_override.is_some(),
                supported: self.active_model_prompt_cache_retention_supported(),
            })
            .await;
    }

    fn refresh_prompt_cache_retention_from_session(&mut self) {
        self.prompt_cache_retention_preference = match self.session.active_model_ref() {
            Some(active) => active.prompt_cache_retention,
            None => self.live_providers_config().ok().and_then(|cfg| {
                cfg.active_model
                    .and_then(|active| active.prompt_cache_retention)
            }),
        };
        for idx in 0..self.stack.len() {
            let retention = self.resolve_prompt_cache_retention_for(&self.stack[idx].agent.model);
            Arc::make_mut(&mut self.stack[idx].agent)
                .params
                .prompt_cache_retention = retention;
        }
    }

    /// Re-load a foreground frame under `new_model` (live model switch),
    /// preserving its name and applying the caller's re-resolved LLM mode. The
    /// new model's reasoning and cache preferences are resolved from the
    /// daemon-authoritative session/request selection. Provider config supplies
    /// capabilities and wire mappings, but its default selection must not leak
    /// into a session-only choice. The session-scoped `prompt_cache_key` is
    /// carried across unchanged.
    fn replace_frame_model(
        &self,
        frame_idx: usize,
        new_model: Arc<crate::engine::model::Model>,
        llm_mode: crate::config::extended::LlmMode,
        selection: &crate::config::providers::ActiveModelRef,
    ) -> Agent {
        let mut refreshed = (*self.stack[frame_idx].agent).clone();
        // Resolve preferences from the daemon-authoritative session selection.
        // The providers config supplies capabilities and wire mappings only;
        // its default selection must never override a session-only choice.
        let (additional_params, endpoint_recovery_additional_params) =
            self.resolve_reasoning_params_for_selection(&new_model, selection);
        let prompt_cache_retention =
            self.resolve_prompt_cache_retention_for_selection(&new_model, selection);
        refreshed.model = new_model;
        refreshed.llm_mode = llm_mode;
        refreshed.params = crate::engine::model::ModelParams {
            additional_params,
            endpoint_recovery_additional_params,
            // The cache key is the session id — model-agnostic, carried across.
            prompt_cache_key: self.stack[frame_idx].agent.params.prompt_cache_key.clone(),
            prompt_cache_retention,
            ..crate::engine::model::ModelParams::default()
        };
        refreshed
    }

    fn rebuild_frame_args(
        &self,
        frame_idx: usize,
        new_model: Arc<crate::engine::model::Model>,
        llm_mode: crate::config::extended::LlmMode,
        selection: &crate::config::providers::ActiveModelRef,
        // A per-node model override to pin as `model_override` so it wins over a
        // frontmatter `model:` in `resolve_agent_model` (modes AC5). `None` for
        // ordinary rebuilds, preserving the previous behaviour.
        model_pin: Option<Arc<crate::engine::model::Model>>,
    ) -> (String, crate::engine::builtin::SpawnArgs) {
        let name = self.stack[frame_idx].agent.name.clone();
        let (additional_params, endpoint_recovery_additional_params) =
            self.resolve_reasoning_params_for_selection(&new_model, selection);
        let prompt_cache_retention =
            self.resolve_prompt_cache_retention_for_selection(&new_model, selection);
        // Every frame on `self.stack` is foreground/user-facing: index 0 is the
        // root primary, and deeper frames are interactive subagents. One-shot
        // noninteractive delegations run off-stack, so rebuilding a stack frame
        // must preserve the interactive recall/todo/goal tool surface.
        let mut args = self.spawn_args(true);
        args.llm_mode = llm_mode;
        args.model = new_model;
        args.model_override = model_pin;
        args.delegation_model = None;
        // Preserve the frame's already-resolved vNext grant across rebuilds so
        // portable child refs (including workspace-authored agents admitted at
        // session start) stay reachable in the task schema after refresh.
        args.vnext_grant = self.stack[frame_idx].agent.vnext_grant.clone();
        args.params = crate::engine::model::ModelParams {
            additional_params,
            endpoint_recovery_additional_params,
            // The cache key is the session id — model-agnostic, carried across.
            prompt_cache_key: self.stack[frame_idx].agent.params.prompt_cache_key.clone(),
            prompt_cache_retention,
            ..crate::engine::model::ModelParams::default()
        };
        (name, args)
    }

    fn try_rebuild_frame_with_model(
        &self,
        frame_idx: usize,
        new_model: Arc<crate::engine::model::Model>,
        llm_mode: crate::config::extended::LlmMode,
        selection: &crate::config::providers::ActiveModelRef,
        model_pin: Option<Arc<crate::engine::model::Model>>,
    ) -> Result<Agent> {
        let (name, args) =
            self.rebuild_frame_args(frame_idx, new_model, llm_mode, selection, model_pin);
        crate::engine::builtin::load(&name, &args)
    }

    fn rebuild_frame_with_model(
        &self,
        frame_idx: usize,
        new_model: Arc<crate::engine::model::Model>,
        llm_mode: crate::config::extended::LlmMode,
        selection: &crate::config::providers::ActiveModelRef,
        model_pin: Option<Arc<crate::engine::model::Model>>,
    ) -> Agent {
        let (name, args) =
            self.rebuild_frame_args(frame_idx, new_model, llm_mode, selection, model_pin);
        // `builtin::load` honors a user override of a bundled primary; fall back
        // to the same agent name's default build on a load failure so the swap
        // never strands the session without a primary.
        crate::engine::builtin::load(&name, &args)
            .unwrap_or_else(|_| crate::engine::builtin::default_build(&args))
    }

    fn effective_llm_mode_for(
        &self,
        provider: &str,
        model: &str,
    ) -> crate::config::extended::LlmMode {
        self.live_providers_config()
            .map(|providers| {
                providers.resolve_mode(provider, model, self.config.extended().llm_mode)
            })
            .unwrap_or_else(|_| self.stack[0].agent.llm_mode)
    }

    /// Re-resolve the reasoning-param fragment for `model` from the config's
    /// rich reasoning-effort capability first, falling back to the legacy
    /// active-model thinking mode (implementation note) only
    /// when the model has no typed capability.
    #[cfg(test)]
    fn resolve_thinking_params_for(
        &self,
        model: &crate::engine::model::Model,
    ) -> Option<serde_json::Value> {
        let selection = self.active_selection_for_model(model);
        self.resolve_reasoning_params_for_selection(model, &selection)
            .0
    }

    /// Resolve both endpoint-specific reasoning fragments together so a live
    /// model rebuild retains the safe alternate payload used by endpoint
    /// recovery. A model switch must never inherit the previous model's
    /// fragment, but it must preserve the selected model's own catalog mapping.
    fn resolve_reasoning_params_for_selection(
        &self,
        model: &crate::engine::model::Model,
        selection: &crate::config::providers::ActiveModelRef,
    ) -> (
        Option<serde_json::Value>,
        Option<crate::engine::model::EndpointRecoveryAdditionalParams>,
    ) {
        if selection.provider != model.provider_id() || selection.model != model.model_id_ref() {
            return (None, None);
        }
        let Some(providers) = self.live_providers_config().ok() else {
            return (None, None);
        };
        let mut providers = providers;
        providers.active_model = Some(selection.clone());
        (
            model.resolve_reasoning_params(&providers),
            model.endpoint_recovery_reasoning_params(&providers),
        )
    }

    fn active_selection_for_model(
        &self,
        model: &crate::engine::model::Model,
    ) -> crate::config::providers::ActiveModelRef {
        if let Some(selection) = self.session.active_model_ref() {
            return if selection.provider == model.provider_id()
                && selection.model == model.model_id_ref()
            {
                selection
            } else {
                crate::config::providers::ActiveModelRef {
                    provider: model.provider_id().to_string(),
                    model: model.model_id_ref().to_string(),
                    reasoning_effort: None,
                    thinking_mode: None,
                    prompt_cache_retention: None,
                }
            };
        }

        self.live_providers_config()
            .ok()
            .and_then(|providers| providers.active_model)
            .filter(|selection| {
                selection.provider == model.provider_id() && selection.model == model.model_id_ref()
            })
            .unwrap_or_else(|| crate::config::providers::ActiveModelRef {
                provider: model.provider_id().to_string(),
                model: model.model_id_ref().to_string(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            })
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
                            .entry(tc.id.to_string())
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
    async fn drop_stale_owner_ledgers(&mut self) {
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
                            tool_call_ids.insert(tc.id.to_string());
                        }
                    }
                }
                Message::User { content } => {
                    for part in content.iter() {
                        if let UserContent::ToolResult(tr) = part {
                            tool_result_ids.insert(tr.call.to_string());
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
        self.delete_persisted_skill_pairs(stale_skill_pair_ids.iter())
            .await;
    }

    /// Switch the active `llm_mode` live (`/llm-mode`). Rebuilds the
    /// root-frame agent under the new mode so its tool-description verbosity
    /// and per-mode prompt re-render, preserving the root history (same
    /// conversation, new steering). Busts the cached system prefix — the
    /// client warns the user (suppressed on a no-cache provider via the
    /// shared cache-break helper) before sending the switch. When requested by
    /// the control caller, a successful rebuild immediately runs the ordinary
    /// prune path. Only the root frame at idle is touched; a deeper
    /// interactive subagent frame is left alone. No-op when the mode is
    /// unchanged or a subagent holds the foreground.
    async fn set_llm_mode(
        &mut self,
        requested: Option<crate::config::extended::LlmMode>,
        prune_after_switch: bool,
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
            let _ = tx
                .send(TurnEvent::Notice {
                    text: format!(
                        "LLM mode switch to `{}` was refused because an interactive subagent holds the foreground.",
                        mode.as_str()
                    ),
                })
                .await;
            return;
        }
        if current == mode {
            return;
        }
        let name = self.stack[0].agent.name.clone();
        // Spawn args start from the current root agent; override only the mode
        // for the rebuilt root.
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
                if prune_after_switch {
                    self.do_prune(false, tx).await;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, requested = %mode.as_str(), "llm_mode switch failed to reload agent");
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: format!(
                            "LLM mode switch to `{}` failed — {e:#}. Keeping the current mode active.",
                            mode.as_str()
                        ),
                    })
                    .await;
            }
        }
    }

    async fn set_tool_surface_override(
        &mut self,
        selection: crate::agents::ToolSurfaceSelection,
        prune_after_switch: bool,
        monty_nudge: Option<String>,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        if self.stack.len() != 1 {
            tracing::warn!(
                "tool surface override ignored: an interactive subagent holds the foreground"
            );
            let _ = tx
                .send(TurnEvent::Notice {
                    text: "Tool surface changes were refused because an interactive subagent holds the foreground.".to_string(),
                })
                .await;
            return;
        }
        let name = self.stack[0].agent.name.clone();
        let mut args = self.spawn_args(true);
        args.vnext_grant = self.stack[0].agent.vnext_grant.clone();
        match crate::agents::resolve(&self.cwd, &name) {
            Ok(Some(mut def)) => {
                match crate::agents::apply_tool_surface_override(&mut def, &selection)
                    .and_then(|_| crate::engine::builtin::agent_from_def(&def, &args))
                {
                    Ok(agent) => {
                        self.stack[0].agent = Arc::new(agent);
                        self.schedule.set_agent(self.stack[0].agent.clone());
                        if let Some(note) = monty_nudge {
                            self.pending_monty_tool_nudge = Some(note);
                        }
                        let _ = tx
                            .send(TurnEvent::Notice {
                                text: "Tool surface updated for this session.".to_string(),
                            })
                            .await;
                        self.emit_context_projection(tx).await;
                        if prune_after_switch {
                            self.do_prune(false, tx).await;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "tool surface override failed to rebuild agent");
                        let _ = tx
                            .send(TurnEvent::Notice {
                                text: format!(
                                    "Tool surface update failed — {e:#}. Keeping the current tool surface active."
                                ),
                            })
                            .await;
                    }
                }
            }
            Ok(None) => {
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: format!(
                            "Tool surface update failed — agent `{name}` could not be resolved."
                        ),
                    })
                    .await;
            }
            Err(e) => {
                let _ = tx
                    .send(TurnEvent::Notice {
                        text: format!(
                            "Tool surface update failed — {e:#}. Keeping the current tool surface active."
                        ),
                    })
                    .await;
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
    /// (provider, model). Uses the context-config defaults when the config
    /// can't be loaded (implementation note).
    fn resolve_context_config(&self) -> crate::config::providers::ContextConfig {
        Self::context_config_from(self.active_providers_config().as_ref())
    }

    fn root_can_self_compact(&self) -> bool {
        self.session
            .active_tool_names()
            .iter()
            .any(|name| name == "mcp")
    }

    fn effective_auto_compact_pct(
        &self,
        ctx_cfg: &crate::config::providers::ContextConfig,
        mode: LlmMode,
        context_policy: Option<&crate::agents::ContextPolicy>,
        can_self_compact: bool,
    ) -> u8 {
        if let Some(explicit) = ctx_cfg.auto_compact_pct {
            return explicit;
        }
        // Issue #75: the def's contextPolicy.autoCompactPct overrides the
        // mode-derived floor; the default is 80 (CAPABLE_MODE_DEFAULT_PCT).
        if let Some(policy) = context_policy
            && let Some(pct) = policy.auto_compact_pct
        {
            return pct;
        }
        if !can_self_compact {
            return AUTO_COMPACT_FLOOR_PCT;
        }
        match mode {
            LlmMode::Defensive => AUTO_COMPACT_FLOOR_PCT,
            LlmMode::Normal | LlmMode::Frontier => AUTO_COMPACT_CAPABLE_MODE_DEFAULT_PCT,
        }
    }

    fn effective_root_auto_compact_pct(
        &self,
        ctx_cfg: &crate::config::providers::ContextConfig,
    ) -> u8 {
        let frame = self.stack.first();
        let mode = frame.map(|f| f.agent.llm_mode).unwrap_or_default();
        let policy = frame.and_then(|f| f.agent.context_policy.as_ref());
        self.effective_auto_compact_pct(ctx_cfg, mode, policy, self.root_can_self_compact())
    }

    /// Last provider-reported input usage, with a debug-build-only threshold
    /// forcing seam for deterministic manual compaction verification.
    fn context_input_tokens(&self, _context_length: Option<u32>) -> Option<u64> {
        #[cfg(debug_assertions)]
        if let (Some(window), Ok(raw)) =
            (_context_length, std::env::var("COCKPIT_DEV_FORCE_CTX_PCT"))
            && let Ok(pct) = raw.parse::<f64>()
            && pct.is_finite()
            && pct >= 0.0
        {
            return Some((f64::from(window) * pct / 100.0).round() as u64);
        }
        self.session.last_usage().map(|usage| usage.input_tokens)
    }

    fn context_usage_snapshot(&self) -> crate::engine::tool::ContextUsageSnapshot {
        let ctx_cfg = self.resolve_context_config();
        let total_tokens = self.active_model_context_length().map(u64::from);
        let used_tokens =
            self.context_input_tokens(total_tokens.and_then(|n| u32::try_from(n).ok()));
        let ctx_pct = match (used_tokens, total_tokens) {
            (Some(used), Some(total)) if total > 0 => Some(used as f64 / total as f64 * 100.0),
            _ => None,
        };
        crate::engine::tool::ContextUsageSnapshot {
            ctx_pct,
            used_tokens,
            total_tokens,
            compact_nudge_pct: ctx_cfg.compact_nudge_pct,
            auto_compact_pct: self.effective_root_auto_compact_pct(&ctx_cfg),
        }
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

    /// The active model's effective context window, or `None` when no model is
    /// selected, the config can't be loaded, or no context limit is known. This
    /// uses the capability resolver so probed context-window values power the
    /// ctx%-gated triggers without pretending to be a user-authored
    /// `context_length` edit.
    fn active_model_context_length(&self) -> Option<u32> {
        let (providers, provider, model) = self.active_providers_config()?;
        providers
            .resolve_effective_model_capabilities(
                &provider,
                &model,
                providers.resolution_generation,
            )
            .context_tokens
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
        // `active_providers_config`), else load from the cwd config chain. Either
        // way the store is OWNER-SCOPED to the exact providers config so a backup
        // model can never resolve a foreign workspace's `$secret:`.
        #[cfg(test)]
        if let Some((providers, _, _)) = &self.test_providers_override {
            let store = self.session.provider_credential_store(providers).ok();
            return build_backup_model_with_store(providers, model, store);
        }
        resolve_backup_model_for_session(&self.config, model, &self.session)
    }

    fn resolve_failover_models(
        &self,
        model: &crate::engine::model::Model,
    ) -> Vec<Arc<crate::engine::model::Model>> {
        #[cfg(test)]
        if let Some((providers, _, _)) = &self.test_providers_override {
            let store = self.session.provider_credential_store(providers).ok();
            return build_failover_models_with_store(providers, model, store);
        }
        resolve_failover_models_for_session(&self.config, model, &self.session)
    }

    /// Load the layered providers config plus the session's active
    /// (provider, model). `None` when no model is selected or the config
    /// can't be loaded — callers fall back to conservative defaults. Same
    /// first-hit rule as the daemon's production
    /// `daemon::config_source::ConfigSource`.
    fn active_providers_config(
        &self,
    ) -> Option<(crate::config::providers::ProvidersConfig, String, String)> {
        #[cfg(test)]
        if let Some(o) = &self.test_providers_override {
            return Some(o.clone());
        }
        let provider = self.session.active_provider()?;
        let model = self.session.active_model()?;
        let providers = self.config.providers();
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
    async fn rehydrate_handle(
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
            .await
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
    async fn persist_subagent_handle(
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
        match self
            .session
            .db
            .save_subagent_handle(
                &handle,
                self.session.id,
                child_agent,
                cwd.as_deref(),
                &transcript_json,
            )
            .await
        {
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

    fn expand_handoff_tags(
        &self,
        text: &str,
        cwd: &std::path::Path,
        llm_mode: crate::config::extended::LlmMode,
        child_agent: &str,
    ) -> String {
        let text = self.expand_skill_tags(text, child_agent);
        let mut allow = crate::config::extended::resolve_gitignore_allow(cwd);
        allow.extend(self.session.gitignore_session_allow());
        let policy = crate::tags::TagPolicy::new_for_mode(cwd, allow, llm_mode);
        crate::tags::expand_assembly_tags_with_policy(&text, &policy).wire
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
        let compact_prompt = self.config.extended().compact_prompt;

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
                    self.drop_stale_owner_ledgers().await;
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

        use crate::approval::{ApprovalOptionId, ApprovalOptionSet};
        use crate::daemon::proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};
        let options = ApprovalOptionSet::new(
            "schedule_unbounded_loop_approval",
            [ApprovalOptionId::Approve, ApprovalOptionId::Reject],
        );
        let question = InterruptQuestion::Single {
            prompt: "Allow unbounded schedule loops for this session?".to_string(),
            options: vec![
                InterruptOption {
                    id: ApprovalOptionId::Approve.as_str().into(),
                    label: "Allow".into(),
                    description: Some(
                        "Permit schedule limit=0 loops until this session ends".into(),
                    ),
                    secondary: false,
                },
                InterruptOption {
                    id: ApprovalOptionId::Reject.as_str().into(),
                    label: "Deny".into(),
                    description: Some("Reject this unbounded loop request".into()),
                    secondary: false,
                },
            ],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: None,
            sandbox_escalation: None,
        };
        loop {
            let resp = self
                .raise_and_wait(
                    self.active_agent(),
                    "Unbounded schedule loop approval",
                    InterruptQuestionSet {
                        questions: vec![question.clone()],
                    },
                )
                .await?;
            let Some(id) = (match crate::approval::decode_option_response(&resp, &options) {
                Ok(id) => id,
                Err(foreign) => {
                    crate::approval::warn_foreign_option_id(&foreign);
                    continue;
                }
            }) else {
                anyhow::bail!("unbounded schedule loop rejected");
            };
            match id {
                ApprovalOptionId::Approve => {
                    self.unbounded_schedule_loops_approved = true;
                    return Ok(());
                }
                ApprovalOptionId::Reject => {
                    anyhow::bail!("unbounded schedule loop rejected");
                }
                _ => unreachable!("schedule unbounded loop accepted set is fixed"),
            }
        }
    }

    /// Detach a late-steer permit from its exact interactive child at the
    /// child's terminal boundary.  The returned identity is handed straight
    /// to [`Self::pop_child_with_envelope`], which commits its durable
    /// completion in the *same transaction* as the child/task terminal
    /// receipt.  Do not complete it here: a standalone completion followed by
    /// a crash before the child settlement reintroduced the reject-on-pop
    /// race this boundary is meant to close.
    fn take_late_steer_for_interactive_child_terminal(
        &mut self,
        late_user_steer_permit: &mut Option<LateUserSteerPermitIdentity>,
    ) -> Option<LateUserSteerPermitIdentity> {
        let Some(permit) = *late_user_steer_permit else {
            return None;
        };
        let child_is_exact_owner = self
            .stack
            .last()
            .is_some_and(|frame| frame.agent_instance_id == Some(permit.agent_instance_id));
        if !child_is_exact_owner || self.stack.len() <= 1 {
            return None;
        }
        if let Some(frame) = self.stack.last_mut() {
            frame.late_user_steer_permit = None;
        }
        *late_user_steer_permit = None;
        Some(permit)
    }

    /// Clear a completed late steer from the root frame. Root completion has
    /// no task-row transaction to share, but it still must drop the permit
    /// before the next unrelated root turn can be dispatched.
    fn take_late_steer_for_interactive_root_terminal(
        &mut self,
        late_user_steer_permit: &mut Option<LateUserSteerPermitIdentity>,
    ) -> Option<LateUserSteerPermitIdentity> {
        let Some(permit) = *late_user_steer_permit else {
            return None;
        };
        let root_is_exact_owner = self.stack.len() == 1
            && self
                .stack
                .last()
                .is_some_and(|frame| frame.agent_instance_id == Some(permit.agent_instance_id));
        if !root_is_exact_owner {
            return None;
        }
        if let Some(frame) = self.stack.last_mut() {
            frame.late_user_steer_permit = None;
        }
        *late_user_steer_permit = None;
        Some(permit)
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
        late_user_steer_completion: Option<LateUserSteerPermitIdentity>,
        queue_item_ids: &[uuid::Uuid],
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Option<Message> {
        let popped_depth = self.stack.len();
        let child = self.stack.pop().expect("pop_child requires a child frame");
        if let (Some(agent_instance_id), Some(endpoint_generation)) =
            (child.agent_instance_id, child.endpoint_generation)
        {
            let _ = tx
                .send(TurnEvent::AgentTreeExecutorEndpointDetached {
                    agent_instance_id,
                    endpoint_generation,
                })
                .await;
        }
        self.publish_active_tool_names().await;
        self.emit_command_capability_notice_if_new(tx).await;
        self.prune_watermark.remove(&popped_depth);
        // Drop any locks the child still held — the §3c invariant doesn't
        // extend across the child's lifetime, and lingering locks would block
        // whatever takes its slot next.
        if let Err(e) = self
            .locks
            .suspend_agent(&child.agent.name, self.session.id)
            .await
        {
            tracing::warn!(error = ?e, agent = %child.agent.name, "suspend_agent on pop failed");
        }
        // The agent now back on top regains its lock set for files whose hash
        // matches the snapshot taken when it was suspended.
        if let Some(parent) = self.stack.last()
            && let Err(e) = self
                .locks
                .resume_agent(&parent.agent.name, self.session.id)
                .await
        {
            tracing::warn!(error = ?e, agent = %parent.agent.name, "resume_agent on pop failed");
        }
        let _ = tx
            .send(TurnEvent::ForegroundInputTarget {
                target: self.active_queue_target(),
            })
            .await;
        if self.prompt_cache_retention_override.is_some() {
            self.emit_longcache_state(tx).await;
        }
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
        // Seeding a re-query handle for the finished child is a child-execution
        // capability, so it is gated on the CHILD's own resolved posture — the
        // child was built with its selected model's mode — not the root frame's.
        let followup_enabled = crate::engine::tool::Capability::FollowupSeed.enabled(
            &crate::agents::PostureResolution::legacy(child.agent.llm_mode),
        );
        let followup_handle = if followup_enabled
            && crate::engine::builtin::is_followup_eligible(&child.agent.name)
        {
            self.persist_subagent_handle(&child.agent.name, &child.history, Some(&self.cwd), None)
                .await
        } else {
            None
        };
        let report = if let Some(handle) = followup_handle {
            format!("{report}{}", handle_footer(&handle))
        } else {
            report
        };
        let parent = self.stack.last().expect("stack never empty").agent.clone();
        let report = self.expand_handoff_tags(&report, &self.cwd, parent.llm_mode, &parent.name);
        let task_call_id = child
            .answering
            .as_ref()
            .map(|pending| pending.call_id.as_str());
        let task_function_call_id = child
            .answering
            .as_ref()
            .and_then(|pending| pending.function_call_id.as_deref());
        let task_provider_item_id = child
            .answering
            .as_ref()
            .and_then(|pending| pending.provider_item_id.as_deref());
        // NO `subagentStop` fire here: the INTERACTIVE child's stop is dispatched
        // through the unified `run_stop_hooks` G::Stop gate in the driver loop's
        // `Return` / `Done` arm (`consult_active_child_stop_gate`) BEFORE this pop
        // runs — that is the single firing for a genuine child completion. Firing
        // an observe stop here too would double it.
        let routing = ChildRoutingMetadata::from_model_with_fallback_decision(
            &child.agent.model,
            child.fallback_decision.as_ref(),
        );
        // The subagent report is authored by the CHILD model, so route it through
        // the frame-carrying journaling path with the child's trust + pre-policy
        // session table (F4). A frame-less `record_event` skips the trusted
        // journaling branch entirely, so a session-table literal in a trusted
        // child's report would never journal. When the child model is untrusted
        // the frame path journals nothing (its report is already post-redaction),
        // preserving today's semantics.
        let child_session_table = child.agent.model.session_redact_table();
        if let Err(e) = self
            .session
            .record_event_with_model_frame(
                crate::db::session_log::SessionEventKind::SubagentReport,
                Some(&child.agent.name),
                task_call_id,
                crate::session::SessionEventModelFrame {
                    provider_id: child.agent.model.provider_id(),
                    model_id: child.agent.model.model_id_ref(),
                    config: &self.config,
                    session_table: child_session_table.as_ref(),
                },
                &with_child_routing_metadata(
                    subagent_report_event_data(
                        &child.agent.name,
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        "default",
                        &report,
                        None,
                    ),
                    &routing,
                ),
            )
            .await
        {
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
                failed: false,
                model_trusted: routing.model_trusted,
                routing: routing.routing,
            })
            .await;
        if let (Some(_agent_instance_id), Some(pending)) =
            (child.agent_instance_id, child.answering.as_ref())
        {
            match self
                .session
                .db
                .settle_task_delegation_child_and_agent(
                    self.session.id,
                    pending.call_id.clone(),
                    "default".to_owned(),
                    crate::db::agent_tree_decisions::TaskDelegationTerminalState::Completed,
                    Some(report.clone()),
                    None,
                    serde_json::json!({
                        "source": "interactive_task",
                        "task_call_id": pending.call_id.as_str(),
                    })
                    .to_string(),
                    crate::agent_tree::system_now_unix_ms(),
                    late_user_steer_completion
                        .map(|permit| (permit.steer_id, permit.recovery_epoch)),
                )
                .await
            {
                Ok(_) => {
                    if late_user_steer_completion.is_some() {
                        self.finish_late_steer_continuation(
                            LateUserSteerContinuationOutcome::Completed,
                        );
                        self.finish_late_steer_deliveries(
                            queue_item_ids,
                            LateUserSteerContinuationOutcome::Completed,
                        )
                        .await;
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, task_call_id = %pending.call_id, "completing interactive task child failed")
                }
            }
        }
        child.answering.map(|pending| {
            // The task call's tool_result becomes the parent's next prompt. The
            // parent's history already ends with the assistant turn that
            // emitted the task call.
            let report = prepend_task_repair_notes(report, &pending.repair_notes);
            let result = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                pending.call_id,
                pending.provider_item_id,
                pending.function_call_id,
                "task",
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
            if let (Some(agent_instance_id), Some(endpoint_generation)) =
                (child.agent_instance_id, child.endpoint_generation)
            {
                let _ = tx
                    .send(TurnEvent::AgentTreeExecutorEndpointDetached {
                        agent_instance_id,
                        endpoint_generation,
                    })
                    .await;
            }
            self.prune_watermark.remove(&popped_depth);

            if let Err(e) = self
                .locks
                .suspend_agent(&child.agent.name, self.session.id)
                .await
            {
                tracing::warn!(
                    error = ?e,
                    agent = %child.agent.name,
                    "suspend_agent on unwind failed"
                );
            }
            if let Some(parent) = self.stack.last()
                && let Err(e) = self
                    .locks
                    .resume_agent(&parent.agent.name, self.session.id)
                    .await
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
            let task_provider_item_id = child
                .answering
                .as_ref()
                .and_then(|pending| pending.provider_item_id.as_deref());
            // TERMINAL `subagentStop`: an INTERACTIVE child is being torn down on
            // a cancelled / draining / terminally-failed parent turn (the abort
            // counterpart of the success pop, which gates its stop in the loop
            // arm). A dead child cannot continue, so this dispatches through the
            // unified `run_stop_hooks` G::Stop path with a fresh discarded latch
            // and ignores the outcome. Firing here keeps every `subagentStart`
            // paired with exactly one `subagentStop`: a child that started always
            // emits a stop, whether it completed or was aborted. `endReason` is
            // `aborted` (distinct from a genuine completion's `completed`).
            self.fire_terminal_subagent_stop(&child.agent.name, task_call_id, "aborted")
                .await;
            let routing = ChildRoutingMetadata::from_model_with_fallback_decision(
                &child.agent.model,
                child.fallback_decision.as_ref(),
            );
            // Unlike the two success-pop SubagentReport sites, this abort report is
            // NOT model-authored: `report` is `reason.abort_report()`, a fixed
            // host-generated string (cancelled / draining / a provider+class+phase
            // failure summary), so it can carry no session-table literal from the
            // child model. A frame-less `record_event` is correct here — there is
            // nothing trusted-authored to journal (H2 verified). The child's own
            // history/report (which could carry a literal) is discarded on unwind
            // and never persisted through this path.
            if let Err(e) = self
                .session
                .record_event(
                    crate::db::session_log::SessionEventKind::SubagentReport,
                    Some(&child.agent.name),
                    task_call_id,
                    &with_child_routing_metadata(
                        subagent_report_event_data(
                            &child.agent.name,
                            task_call_id,
                            task_provider_item_id,
                            task_function_call_id,
                            "default",
                            &report,
                            None,
                        ),
                        &routing,
                    ),
                )
                .await
            {
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
                    failed: true,
                    model_trusted: routing.model_trusted,
                    routing: routing.routing,
                })
                .await;

            if let (Some(_agent_instance_id), Some(pending)) =
                (child.agent_instance_id, child.answering.as_ref())
            {
                let state = match reason {
                    StackUnwindReason::Cancelled => {
                        crate::db::agent_tree_decisions::TaskDelegationTerminalState::Cancelled
                    }
                    StackUnwindReason::Gated | StackUnwindReason::InferenceFailed { .. } => {
                        crate::db::agent_tree_decisions::TaskDelegationTerminalState::Failed
                    }
                };
                match self
                    .session
                    .db
                    .settle_task_delegation_child_and_agent(
                        self.session.id,
                        pending.call_id.clone(),
                        "default".to_owned(),
                        state,
                        Some(report.clone()),
                        None,
                        serde_json::json!({
                            "source": "interactive_task_unwind",
                            "task_call_id": pending.call_id.as_str(),
                        })
                        .to_string(),
                        crate::agent_tree::system_now_unix_ms(),
                        None,
                    )
                    .await
                {
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(%error, task_call_id = %pending.call_id, "failing interactive task child failed")
                    }
                }
            }

            if let Some(pending) = child.answering {
                let result =
                    crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        pending.call_id,
                        pending.provider_item_id,
                        pending.function_call_id,
                        "task",
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
        if self.prompt_cache_retention_override.is_some() {
            self.emit_longcache_state(tx).await;
        }
    }

    async fn unwind_stack_to_root_and_discard_pending_input(
        &mut self,
        reason: StackUnwindReason,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> usize {
        self.unwind_stack_to_root(reason, tx).await;
        let Some(staged) = input_rx.stage_discard_pending().await else {
            return 0;
        };
        let dropped = staged.ids().len();
        let dropped_queue_item_ids = staged.ids().to_vec();
        let receipts = input_rx.accepted_receipts(staged.ids()).await;
        if !self
            .record_terminal_client_submissions(
                &receipts,
                crate::db::session_log::ClientSubmissionTerminalDisposition::Cancelled,
                tx,
            )
            .await
        {
            return 0;
        }
        input_rx.commit_staged_removal(staged).await;
        self.finish_late_steer_deliveries(
            &dropped_queue_item_ids,
            LateUserSteerContinuationOutcome::Cancelled,
        )
        .await;
        tracing::info!(dropped, "discarded queued user messages on cancel");
        dropped
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
        if let Some(gate) = self
            .stack
            .last()
            .and_then(|frame| frame.recovery_activation.clone())
        {
            // The endpoint is published first so recovery can prove exact
            // ownership, but no queued prompt (including a pre-crash tool
            // result) is executable until the worker has consumed its claim.
            gate.wait().await?;
        }
        let queue_item_ids = submission.queue_item_ids.clone();
        if let Some(error) = self.late_steer_owner_mismatch(&queue_item_ids) {
            // Do not run a durable steer on a same-named successor.  The
            // worker receives this negative acknowledgement and releases the
            // durable claim for the original executor/recovery epoch.
            input_rx.finish(&queue_item_ids).await;
            self.finish_late_steer_deliveries(
                &queue_item_ids,
                LateUserSteerContinuationOutcome::interrupted(error),
            )
            .await;
            return Ok(());
        }
        let tracks_late_steer = queue_item_ids.iter().any(|queue_item_id| {
            self.pending_late_user_steer_acks
                .contains_key(queue_item_id)
        });
        if tracks_late_steer {
            self.begin_late_steer_continuation();
        }
        let media_invocations: Vec<_> = submission
            .client_submissions
            .iter()
            .map(|receipt| receipt.id.to_string())
            .collect();
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
        struct CompletionClock;
        impl crate::media_reservation::MonotonicClock for CompletionClock {
            fn now_ms(&self) -> u64 {
                0
            }
        }
        let media_ledger = crate::media_reservation::MediaReservationLedger::new(
            self.session.db.clone(),
            std::sync::Arc::new(CompletionClock),
        );
        let completion_wall_ms = chrono::Utc::now()
            .timestamp_millis()
            .try_into()
            .unwrap_or(0);
        for invocation in media_invocations {
            if let Err(error) = media_ledger
                .complete_downstream_invocation(&invocation, completion_wall_ms)
                .await
            {
                tracing::warn!(%error,%invocation,"downstream media cleanup did not settle; durable ownership remains retryable");
            }
        }
        if tracks_late_steer {
            if let Err(error) = &result {
                self.finish_late_steer_continuation(LateUserSteerContinuationOutcome::failed(
                    error.to_string(),
                ));
            }
            let outcome = self
                .late_steer_continuation_outcome
                .take()
                .unwrap_or_else(|| {
                    LateUserSteerContinuationOutcome::interrupted(
                        "late user steer completion outcome was not recorded",
                    )
                });
            self.finish_late_steer_deliveries(&queue_item_ids, outcome)
                .await;
        }
        if result.is_ok() {
            self.acknowledge_interrupted_turns_after_progress().await;
        }
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
        // Recovery scheduling is keyed by the queue item's fresh UUID, never
        // by an agent name or by the placeholder text accepted by the queue.
        // Removing the entry here is safe: if the worker dies earlier the
        // durable task snapshot causes a fresh reattach; once this method owns
        // it, the normal turn path persists the next checkpoint before any
        // further model call.
        let recovered_next_prompt = submission.queue_item_ids.iter().find_map(|queue_item_id| {
            self.recovered_interactive_continuations
                .remove(queue_item_id)
        });
        let submission_has_oversized_artifact_lease = matches!(
            submission.pending_terminal_disposition,
            Some(
                crate::engine::message::PendingSubmissionTerminalDisposition::OversizedTextArtifact
            )
        );
        let oversized_artifact_submission_id = submission_has_oversized_artifact_lease
            .then(|| {
                submission
                    .client_submissions
                    .first()
                    .map(|receipt| receipt.id)
            })
            .flatten();
        // The ordinary path may expose the activity epoch as soon as the turn
        // starts. A receipt-keyed oversized turn has not reached phase two
        // yet, so advancing it here would make a rejected/expired source an
        // accepted-turn side effect.
        if submission.origin.advances_activity_epoch() && !submission_has_oversized_artifact_lease {
            self.auto_compact_gate.external_activity();
        }
        // Shadow drafting is utility work: a foreground user turn always wins.
        // Preserve a task that already completed, but cancel an unfinished one
        // before assembling or dispatching the user's inference.
        self.preempt_shadow_brief_for_foreground().await;
        self.preempt_self_improvement_review_for_foreground();
        let lifecycle_turn_id = uuid::Uuid::new_v4().to_string();
        self.current_lifecycle_turn_id = Some(lifecycle_turn_id.clone());
        // Modes AC5 turn-consumption is wired in `refresh_active_frame_for_turn`
        // (below): `consume_active_node_override_for_turn` runs the AC5 "second
        // transaction" for the active node (mode applied per-frame, sandbox to the
        // session posture). Follow-on: per-node sandbox isolation across concurrent
        // delegated turns, and verification/question application at their resolver
        // sites.
        // Pin the session config snapshot for this turn's duration: a
        // re-resolution that lands mid-turn is observed only at the next turn
        // boundary (`engine-config-snapshot-adoption`).
        self.repin_config_for_turn();
        self.max_primary_rounds = self.load_max_primary_rounds_for_turn().await;
        self.reset_delegation_retry_budget();
        self.refresh_redaction_table_for_turn(tx).await;
        self.refresh_active_frame_for_turn(tx).await;
        self.refresh_wire_api_for_turn();
        // Pasted image parts (vision models only) ride alongside the text
        // through every text-only step below (titling, skills, seed,
        // time prelude) and are reattached when the prompt `Message` is
        // built. Non-vision callers already folded images into `text` and
        // pass none here (composer-paste-handling).
        let submission_kind = submission.kind;
        // Classify the root-turn origin for the `userPromptSubmit` hook: only a
        // genuine external user submission fires the event; goal / scheduled /
        // auto-continue / retry / tool-result / internal directives reach this
        // same path but must NOT (see `SubmissionOrigin::user_prompt_submit_source`).
        let user_prompt_source = submission.origin.user_prompt_submit_source();
        // Re-read the FCM2-bound lease before moving any fields out of the
        // structured submission. This is deliberately a typed receipt lookup,
        // not a size check on the mutable queue text: a stale/reaped lease
        // must fail closed rather than falling through to the legacy inline
        // event path.
        let oversized_artifact_submission = if submission_has_oversized_artifact_lease {
            match self
                .reserved_oversized_user_submission(&submission, false)
                .await
            {
                Ok(Some(stored)) => Some(stored),
                Ok(None) => {
                    let durable_notice = self
                        .oversized_artifact_no_lease_notice(oversized_artifact_submission_id)
                        .await;
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: durable_notice,
                        })
                        .await;
                    return Ok(());
                }
                Err(error) => {
                    tracing::warn!(%error, "loading phase-two oversized message reservation failed");
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: "Could not verify oversized-message admission; no provider was called."
                                .to_owned(),
                        })
                        .await;
                    return Ok(());
                }
            }
        } else {
            None
        };
        let images = submission.images;
        let user_text = submission.text;
        let display_text = submission.display_text;
        let tag_expansions = submission.tag_expansions;
        let origin_principal = submission.origin_principal;
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
        let goal_continue_anchor_seq = if self.is_goal_intervention_continue(&user_text).await {
            Some(self.latest_session_event_seq().await)
        } else {
            None
        };
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
        // Run-invocation deadline: child cancel token so expiry aborts provider/
        // tool/approval work without waiting for cooperation.
        let mut _run_deadline_task: Option<tokio::task::JoinHandle<()>> = None;
        // Timeline event (session-log-export Part B): the unit of user /
        // injected input that drives this run. Tagged with the foreground
        // agent. Recorded before prelude/seed wrapping so the export shows
        // the user's actual text.
        // Additive, optional `data.job_id` on async-result deliveries
        // (implementation note) — no exporter schema bump.
        let queue_item_ids = submission.queue_item_ids.clone();
        let client_submissions = submission.client_submissions.clone();
        let queue_target = submission.queue_target.clone();
        let pending_terminal_disposition = submission.pending_terminal_disposition;
        let run_invocation_id = submission.run_invocation_id;
        // RAII: clear invocation approval override on every exit of this run.
        let mut _invocation_approval_guard: Option<InvocationApprovalGuard> = None;
        if !submission_has_oversized_artifact_lease && let Some(run_id) = run_invocation_id {
            let now = crate::daemon::server::run_invocation_wall_ms_now();
            // Checkpoint remaining before any side effect (queue already done).
            if let Ok(Some(row)) = self.session.db.get_run_invocation(run_id).await {
                // Prefer immutable client options by client_submission_id.
                // Missing approval_mode falls through to session mode.
                if let Ok(options) = serde_json::from_str::<
                    crate::daemon::proto::RunInvocationOptions,
                >(&row.options_json)
                    && let Some(mode) = options.approval_mode
                {
                    self.session.set_invocation_approval_override(run_id, mode);
                    _invocation_approval_guard = Some(InvocationApprovalGuard {
                        session: self.session.clone(),
                    });
                }
                if let Some(remaining) = row.remaining_ms {
                    if remaining == 0 {
                        let _ = self
                            .session
                            .db
                            .fire_run_invocation_timeout(run_id, now)
                            .await;
                        self.pending_idle_reason = Some(crate::engine::IdleReason::Error {
                            class: crate::engine::model::InferenceErrorClass::TimeoutIdle,
                        });
                        return Ok(());
                    }
                    // Parent cancel is owned by the live deadline: expiry cancels
                    // in-flight provider/tool/approval work and commits TimeoutExpired once.
                    let deadline_cancel = cancel.clone();
                    let db = self.session.db.clone();
                    _run_deadline_task = Some(tokio::spawn(async move {
                        tokio::select! {
                            _ = deadline_cancel.cancelled() => {
                                // External cancel already owns the outcome.
                            }
                            _ = tokio::time::sleep(std::time::Duration::from_millis(remaining)) => {
                                // Cancel first so non-cooperative work begins reaping.
                                deadline_cancel.cancel();
                                let wall = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_millis() as i64)
                                    .unwrap_or(0);
                                let _ = db.fire_run_invocation_timeout(run_id, wall).await;
                            }
                        }
                    }));
                }
                // Transition accepted → queued/running bookkeeping.
                let _ = self
                    .session
                    .db
                    .update_run_invocation_state(
                        run_id,
                        row.state_version,
                        "queued",
                        row.remaining_ms,
                        None,
                        None,
                        None,
                        None,
                        now,
                    )
                    .await;
            }
        }
        // The immutable authored source is the FCM2 text, never a preflight
        // rewrite or translation. The ordinary path has no separate source,
        // so its canonical event remains the model text exactly as before.
        let canonical_user_text = oversized_artifact_submission
            .as_ref()
            .map(|stored| stored.source_text.clone())
            .unwrap_or_else(|| user_text.clone());
        let raw_user_text = canonical_user_text.clone();
        let event_data = user_message_event_data(UserMessageEventData {
            text: &canonical_user_text,
            display_text: display_text.as_deref(),
            tag_expansions: &tag_expansions,
            job_id: job_id.as_deref(),
            queue_item_ids: &queue_item_ids,
            client_submissions: &client_submissions,
            queue_target: queue_target.as_ref(),
            preflight_cleaned: preflight_cleaned.as_deref(),
        });
        let active_agent = self.active_agent().to_string();
        // Resolve every model-bound textual addition before phase two.  The
        // reservation is already durable, so utility selection is allowed;
        // phase two persists the exact resulting composition before the first
        // primary-provider handoff.
        let prepared_auto_skill = if submission_has_oversized_artifact_lease {
            let skill_probe =
                crate::engine::text_artifact_frame::bounded_utf8_prefix(&user_text, 4 * 1024)
                    .to_owned();
            Some(self.prepare_auto_skill_injection(&skill_probe).await)
        } else {
            None
        };
        // Loading a forced skill is read-only, but applying it mutates active
        // skills, history, audit rows and the skill-pair ledger.  For an
        // oversized submission prepare that exact contribution before phase
        // two, then apply it only after the reservation materializes.
        let prepared_forced_skill = if submission_has_oversized_artifact_lease {
            if let Some(skill_name) = forced_skill.as_deref() {
                Some(self.prepare_forced_skill(skill_name).await)
            } else {
                None
            }
        } else {
            None
        };
        // This exact ordering is durable phase-two composition: forced seed,
        // auto-selected guidance, then the authored artifact slot.  The
        // prepared values are pure; no active-skill/event/history mutation is
        // permitted before materialization succeeds.
        let accepted_oversized_guidance = if submission_has_oversized_artifact_lease {
            let mut guidance = String::new();
            if let Some(prepared) = prepared_auto_skill.as_ref() {
                guidance.push_str(&prepared.guidance(
                    crate::engine::text_artifact_frame::bounded_utf8_prefix(&user_text, 4 * 1024),
                ));
            }
            Some(guidance)
        } else {
            None
        };
        let artifact_frame = if let Some(mut oversized) = oversized_artifact_submission {
            // Long preprocessing can consume most of the original lease. Renew
            // at this final boundary, rotating the token when required, before
            // asking the one phase-two composition to own the event.
            let now_ms = chrono::Utc::now().timestamp_millis();
            match self
                .session
                .db
                .renew_text_artifact_reservation(oversized.reservation.clone(), now_ms)
                .await
            {
                Ok(Some(reservation)) => oversized.reservation = reservation,
                Ok(None) => {
                    let _ = self
                        .session
                        .db
                        .reap_expired_text_artifact_reservations(now_ms)
                        .await;
                    let durable_notice = self
                        .oversized_artifact_no_lease_notice(oversized_artifact_submission_id)
                        .await;
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: durable_notice,
                        })
                        .await;
                    return Ok(());
                }
                Err(error) => {
                    tracing::warn!(%error, "renewing oversized message lease before materialization failed");
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: "Could not renew oversized-message admission; no provider was called."
                                .to_owned(),
                        })
                        .await;
                    return Ok(());
                }
            }
            let materialization = self
                .session
                .db
                .materialize_reserved_user_text_artifacts(
                    crate::db::text_artifacts::ReservedUserArtifactMaterialization {
                        reservation: oversized.reservation.clone(),
                        canonical_event_json: match serde_json::to_string(&event_data) {
                            Ok(value) => value,
                            Err(error) => {
                                tracing::warn!(%error, "serializing oversized canonical user event failed");
                                let _ = self
                                    .reject_reserved_oversized_user_submission(
                                        oversized.reservation,
                                        crate::db::text_artifacts::TextArtifactRejectReason::PersistenceFailed,
                                        tx,
                                    )
                                    .await;
                                return Ok(());
                            }
                        },
                        // This is the accepted model-facing composition, not
                        // a replay hint. Later restart rendering replaces only
                        // its authored slot with the artifact frame.
                        model_envelope_json: crate::engine::text_artifact_frame::accepted_user_envelope_from_parts(
                            prepared_forced_skill.as_ref().and_then(crate::engine::driver::skills_seed::PreparedForcedSkill::envelope_prelude),
                            &{
                                let mut parts = Vec::new();
                                if let Some(guidance) = accepted_oversized_guidance.as_deref().filter(|guidance| !guidance.is_empty()) {
                                    parts.push(rig::message::UserContent::text(guidance));
                                }
                                parts.push(rig::message::UserContent::text(&user_text));
                                parts
                            },
                            &user_text,
                        ).expect("accepted oversized composition is constructed from closed host parts"),
                        source_text: oversized.source_text.clone(),
                        model_projection: (user_text != oversized.source_text)
                            .then_some(user_text.clone()),
                        agent: Some(active_agent.clone()),
                        context: crate::db::text_artifacts::TextArtifactEventContext {
                            origin_principal: origin_principal.clone(),
                            ..Default::default()
                        },
                        now_ms,
                    },
                )
                .await;
            match materialization {
                Ok(
                    crate::db::text_artifacts::ReservedUserArtifactMaterializationResult::Materialized(
                        materialized,
                    ),
                ) => {
                    let crate::db::text_artifacts::ReservedUserArtifactMaterialized {
                        event_seq,
                        source_artifact,
                        projection_artifact,
                    } = *materialized;
                    // From this point the turn is durably accepted. No rejected
                    // source can advance activity/title/provider state.
                    if submission_kind == UserSubmissionKind::User
                        && user_prompt_source.is_some()
                    {
                        // The FCM2 scheduler epoch is intentionally advanced
                        // only after phase two has atomically materialized the
                        // source/event/receipt and released its reservation.
                        // Dispatch handles the ordinary inline path earlier.
                        if let Some(scheduler) = self.daemon_scheduler_handle() {
                            scheduler.record_user_activity().await;
                        }
                        self.auto_compact_gate.external_activity();
                    }
                    if !queue_item_ids.is_empty() {
                        let _ = tx
                            .send(TurnEvent::QueuedUserMessagesFolded {
                                text: canonical_user_text.clone(),
                                display_text: display_text.clone(),
                                tag_expansions: tag_expansions.clone(),
                                queue_item_ids: queue_item_ids.clone(),
                                target: queue_target
                                    .clone()
                                    .unwrap_or_else(|| self.active_queue_target()),
                                seq: Some(event_seq),
                                preflight_cleaned: preflight_cleaned.clone(),
                            })
                            .await;
                    }
                    let _ = tx
                        .send(TurnEvent::UserMessageRecorded {
                            seq: event_seq,
                            client_submission_ids: client_submissions
                                .iter()
                                .map(|receipt| receipt.id)
                                .collect(),
                            preflight_cleaned: preflight_cleaned.clone(),
                        })
                        .await;
                    if let Some(source) = user_prompt_source {
                        self.fire_observe_hook(
                            crate::config::extended::hooks::HookEvent::UserPromptSubmit,
                            source,
                            None,
                            None,
                            crate::engine::agent::hooks::ObserveFields {
                                prompt_source: Some(source),
                                ..Default::default()
                            },
                        )
                        .await;
                    }
                    let effective = projection_artifact.as_ref().unwrap_or(&source_artifact);
                    let outbound_content = self.redact.scrub(&effective.content);
                    match crate::engine::text_artifact_frame::render_user_input_artifact_frame_with_outbound_content(
                        effective,
                        &outbound_content,
                    ) {
                        Ok(frame) => Some((event_seq, frame)),
                        Err(error) => {
                            // The materialized event is intentionally retained
                            // for audit/replay, but malformed owner bindings may
                            // never fall back to the source or inline text.
                            tracing::error!(%error, event_seq, "materialized oversized user artifact binding is invalid");
                            let _ = tx
                                .send(TurnEvent::Notice {
                                    text: "Oversized message was stored but its model projection is invalid; no provider was called."
                                        .to_owned(),
                                })
                                .await;
                            return Ok(());
                        }
                    }
                }
                Ok(
                    crate::db::text_artifacts::ReservedUserArtifactMaterializationResult::ProjectionTooLarge,
                ) => {
                    // The phase-two composition has already terminalized the
                    // exact receipt triple and released its lease atomically.
                    // Do not issue a second best-effort terminal update: a
                    // renewed/replayed winner must remain untouched.
                    let _ = tx
                        .send(TurnEvent::UserMessageRetracted {
                            client_submission_ids: client_submissions
                                .iter()
                                .map(|receipt| receipt.id)
                                .collect(),
                        })
                        .await;
                    self.emit_context_projection(tx).await;
                    return Ok(());
                }
                Ok(
                    crate::db::text_artifacts::ReservedUserArtifactMaterializationResult::Stale
                    | crate::db::text_artifacts::ReservedUserArtifactMaterializationResult::Expired,
                ) => {
                    let _ = self
                        .session
                        .db
                        .reap_expired_text_artifact_reservations(now_ms)
                        .await;
                    let durable_notice = self
                        .oversized_artifact_no_lease_notice(oversized_artifact_submission_id)
                        .await;
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: durable_notice,
                        })
                        .await;
                    return Ok(());
                }
                Err(error) => {
                    tracing::warn!(%error, "materializing oversized user artifacts failed");
                    // A database fault rolls the whole phase-two transaction
                    // back.  Preserve its accepted lease for the durable
                    // replay/reaper path instead of attempting a separate
                    // terminal write that could turn an injected statement
                    // fault into a misleading partial rejection.
                    let _ = tx
                        .send(TurnEvent::Notice {
                            text: "Saving oversized-message artifacts failed; no provider was called and durable replay will reconcile it."
                                .to_owned(),
                        })
                        .await;
                    return Ok(());
                }
            }
        } else {
            match self
                .record_user_message_event(
                    Some(active_agent.as_str()),
                    origin_principal.as_deref(),
                    &event_data,
                    &client_submissions,
                    tx,
                    user_prompt_source,
                )
                .await
            {
                UserMessageRecordOutcome::Recorded(seq) => {
                    // Carry the assigned `seq` (the message's stable id) back to
                    // the client so it can stamp the already-pushed user history
                    // row. UI/DB-only — the seq never enters model context.
                    if !queue_item_ids.is_empty() {
                        let _ = tx
                            .send(TurnEvent::QueuedUserMessagesFolded {
                                text: user_text.clone(),
                                display_text: display_text.clone(),
                                tag_expansions: tag_expansions.clone(),
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
                            client_submission_ids: client_submissions
                                .iter()
                                .map(|receipt| receipt.id)
                                .collect(),
                            preflight_cleaned: preflight_cleaned.clone(),
                        })
                        .await;
                }
                UserMessageRecordOutcome::Untracked => {}
                UserMessageRecordOutcome::RetryRequired => {
                    if let Some(top) = self.stack.last_mut() {
                        top.history.extend(leading_history);
                    }
                    input_rx
                        .requeue_front_after(
                            UserSubmission {
                                expected_model_state_generation: None,
                                expected_model: None,
                                kind: submission_kind,
                                origin: crate::engine::message::SubmissionOrigin::Internal,
                                text: user_text,
                                display_text,
                                tag_expansions,
                                images,
                                forced_skill,
                                origin_principal,
                                job_id,
                                preflight_cleaned,
                                queue_item_ids,
                                client_submissions,
                                queue_target,
                                pending_terminal_disposition,
                                run_invocation_id,
                            },
                            self.active_queue_target(),
                            DURABLE_SUBMISSION_RETRY_BACKOFF,
                        )
                        .await;
                    return Ok(());
                }
            }
            None
        };

        // The worker accepted an invocation-marked oversized source only
        // after phase one. Its runtime state/approval deadline must likewise
        // begin only after phase two made the canonical event and artifacts
        // durable, never while a reservation can still be rejected.
        if submission_has_oversized_artifact_lease && let Some(run_id) = run_invocation_id {
            let now = crate::daemon::server::run_invocation_wall_ms_now();
            if let Ok(Some(row)) = self.session.db.get_run_invocation(run_id).await {
                if let Ok(options) = serde_json::from_str::<
                    crate::daemon::proto::RunInvocationOptions,
                >(&row.options_json)
                    && let Some(mode) = options.approval_mode
                {
                    self.session.set_invocation_approval_override(run_id, mode);
                    _invocation_approval_guard = Some(InvocationApprovalGuard {
                        session: self.session.clone(),
                    });
                }
                if row.timeout_ms.is_some() {
                    // Phase two starts this clock inside the same DB transaction
                    // that materializes the FCM2 event. Account for the small
                    // elapsed interval before arming the live watcher rather than
                    // resetting it to the full configured budget on the driver
                    // side. The ordinary (non-FCM2) branch above keeps its
                    // historical acceptance-time behavior unchanged.
                    let remaining =
                        match crate::daemon::server::run_invocation_remaining_after_restart(
                            &row, now,
                        ) {
                            crate::daemon::server::RunInvocationRemaining::ClockNotStarted => {
                                // A materialized bound FCM2 row must have armed its
                                // clock. Do not dispatch if the durable composition
                                // is inconsistent.
                                return Ok(());
                            }
                            crate::daemon::server::RunInvocationRemaining::Remaining(remaining) => {
                                let Some(checkpointed) = self
                                    .session
                                    .db
                                    .checkpoint_run_invocation_remaining(
                                        run_id,
                                        Some(remaining),
                                        now,
                                    )
                                    .await
                                    .ok()
                                    .flatten()
                                else {
                                    return Ok(());
                                };
                                if checkpointed.terminal_at_wall_ms.is_some() {
                                    return Ok(());
                                }
                                remaining
                            }
                            crate::daemon::server::RunInvocationRemaining::Expired
                            | crate::daemon::server::RunInvocationRemaining::ClockRollback => {
                                let _ = self
                                    .session
                                    .db
                                    .fire_run_invocation_timeout(run_id, now)
                                    .await;
                                cancel.cancel();
                                self.pending_idle_reason = Some(crate::engine::IdleReason::Error {
                                    class: crate::engine::model::InferenceErrorClass::TimeoutIdle,
                                });
                                return Ok(());
                            }
                            crate::daemon::server::RunInvocationRemaining::Unbounded => {
                                return Ok(());
                            }
                        };
                    let deadline_cancel = cancel.clone();
                    let db = self.session.db.clone();
                    _run_deadline_task = Some(tokio::spawn(async move {
                        tokio::select! {
                            _ = deadline_cancel.cancelled() => {}
                            _ = tokio::time::sleep(std::time::Duration::from_millis(remaining)) => {
                                deadline_cancel.cancel();
                                let wall = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_millis() as i64)
                                    .unwrap_or(0);
                                let _ = db.fire_run_invocation_timeout(run_id, wall).await;
                            }
                        }
                    }));
                }
                // `materialize_reserved_user_text_artifacts` already changed a
                // bound oversized invocation from phase-one `accepted` to
                // `running` and armed its timeout in that exact transaction.
                // Do not overwrite it with the ordinary path's `queued`
                // bookkeeping: doing so would make a materialized FCM2 run look
                // like an unarmed pre-provider invocation after restart.
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
        // The title accounting is based on the exact authored source, while
        // the detached utility request gets only a bounded prefix. In
        // particular it must not independently expand an 8MiB artifact.
        let title_action = self.session.note_user_content(&canonical_user_text);
        if !matches!(title_action, crate::session::TitleAction::None) {
            let session = self.session.clone();
            let content_prefix = if artifact_frame.is_some() {
                crate::engine::text_artifact_frame::bounded_utf8_prefix(
                    &canonical_user_text,
                    4 * 1024,
                )
                .to_owned()
            } else {
                user_text.clone()
            };
            // Resolve auto-title config from the turn-pinned snapshot before the
            // detached task spawns, rather than re-reading disk inside it
            // (`engine-config-snapshot-adoption`).
            let (extended, providers) = self.config.configs();
            // Thread the session's effective redaction table so the detached
            // auto-title call routes through the same non-bypassable scrub
            // chokepoint as the foreground turn (GOALS §7).
            let redact = self.redact.clone();
            let tx = tx.clone();
            let shutdown_gate = self.stack[0].agent.model.shutdown_gate();
            tokio::spawn(async move {
                crate::auto_title::generate_session_title(
                    session,
                    extended,
                    providers,
                    redact,
                    content_prefix,
                    title_action,
                    Some(shutdown_gate),
                    tx,
                )
                .await;
            });
        }

        // Skills auto-selection (GOALS §5): consult the cheap utility
        // model with the skill catalog + this message; if it picks one,
        // prepend the (`!`-processed, scrubbed) body so the main agent's
        // first inference carries it. Skipped gracefully (logged once)
        // when no utility model is configured — never falls back to the
        // main model.
        // Skill selection is a utility-model boundary too. It may inspect a
        // bounded authored prefix to choose guidance, but the assembled
        // foreground prompt retains that guidance and swaps only authored text
        // for the durable artifact frame.
        let rendered_oversized_composition =
            if let Some((event_seq, frame)) = artifact_frame.as_ref() {
                let envelope = self
                    .session
                    .db
                    .user_message_model_envelope(self.session.id, *event_seq)
                    .await?
                    .ok_or_else(|| {
                        anyhow!("materialized oversized user event lacks accepted envelope")
                    })?;
                Some(
                crate::engine::text_artifact_frame::render_accepted_user_composition_with_redaction(
                    &envelope,
                    frame,
                    &self.redact,
                )?,
            )
            } else {
                None
            };
        let user_text = if rendered_oversized_composition.is_none() {
            self.maybe_inject_skill(&user_text, tx).await
        } else {
            // The accepted envelope already carries the prepared guidance.
            // Apply only its observable bookkeeping now that phase two won;
            // never use the returned text or it would double-inject on live
            // dispatch while restart rendering correctly uses the envelope.
            if let Some(prepared) = prepared_auto_skill {
                let _ = self
                    .apply_prepared_auto_skill_injection(prepared, &user_text, tx)
                    .await;
            }
            user_text
        };

        // Seeded skill slash command (implementation note):
        // synthesize a real `skill` tool call now, before the first inference,
        // so the body loads deterministically (priority #1 — weaker models may
        // not follow through on a tool call). Reuses the one skill-tool loading
        // path and the wire-vs-user transcript machinery — the call is recorded
        // and folded into history as a native call/result pair, then the user's
        // text (with any trailing args) drives the turn as the task input.
        if let Some(prepared) = prepared_forced_skill {
            self.apply_prepared_forced_skill(
                prepared,
                tx,
                rendered_oversized_composition.is_none(),
            )
            .await;
        } else if let Some(skill_name) = forced_skill {
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

        let retry_recovery = self.failed_turn_retry_prompt_for(&raw_user_text).await;
        let mut next_prompt = if let Some(recovered_next_prompt) = recovered_next_prompt {
            recovered_next_prompt
        } else if let Some((recovery_id, recovered_text)) = &retry_recovery {
            self.record_failed_turn_retry_started(recovery_id, tx).await;
            crate::engine::message::build_user_message(UserSubmission {
                expected_model_state_generation: None,
                expected_model: None,
                kind: UserSubmissionKind::User,
                origin: crate::engine::message::SubmissionOrigin::RetryRecovery,
                text: recovered_text.clone(),
                display_text: None,
                tag_expansions: Vec::new(),
                images: Vec::new(),
                forced_skill: None,
                origin_principal: None,
                job_id: None,
                preflight_cleaned: None,
                queue_item_ids: Vec::new(),
                client_submissions: Vec::new(),
                queue_target: None,
                pending_terminal_disposition: None,
                run_invocation_id: None,
            })
        } else if let Some(composition) = rendered_oversized_composition {
            if !composition.leading.is_empty() {
                self.stack
                    .last_mut()
                    .expect("stack never empty")
                    .history
                    .extend(composition.leading);
            }
            Message::User {
                content: composition.content,
            }
        } else {
            crate::engine::message::build_user_message(UserSubmission {
                expected_model_state_generation: None,
                expected_model: None,
                kind: UserSubmissionKind::User,
                origin: crate::engine::message::SubmissionOrigin::Internal,
                text: if time_prelude_as_system {
                    user_text
                } else {
                    self.with_time_prelude(user_text)
                },
                display_text: None,
                tag_expansions: Vec::new(),
                images,
                forced_skill: None,
                origin_principal: None,
                job_id: None,
                preflight_cleaned: None,
                queue_item_ids: Vec::new(),
                client_submissions: Vec::new(),
                queue_target: None,
                pending_terminal_disposition: None,
                run_invocation_id: None,
            })
        };
        let max_primary_rounds = self.max_primary_rounds;
        let mut primary_rounds_in_chunk: u32 = 0;
        // ROOT stop-gate latch for THIS user turn (`tool-hooks-lifecycle-
        // completion`, increment 2B-ii). Turn-scoped by construction: it is
        // owned per this single `run_user_input` invocation — i.e. per
        // `(session, root frame, originating user turn)` — accumulates the
        // 8-continuation cap across the stop-hook rounds of this turn, and is
        // DROPPED on every exit path (normal end, cancel, interrupt, drain,
        // inference error), so it can never leak into, or reopen the gate for, a
        // later turn. It is NOT a process-global counter.
        let mut root_stop_gate = crate::engine::agent::hooks::StopGateState::default();
        // Capture the immutable permit once per submitted steer-run.  It stays
        // in scope across model/tool continuation rounds, while only the first
        // round consumes the durable external-journal continuation id.
        let mut late_user_steer_permit = queue_item_ids.iter().find_map(|queue_item_id| {
            self.pending_late_user_steer_acks
                .get(queue_item_id)
                .map(|pending| LateUserSteerPermitIdentity {
                    steer_id: pending.steer_id,
                    continuation_id: pending.continuation_id,
                    recovery_epoch: pending.recovery_epoch,
                    agent_instance_id: pending.agent_instance_id,
                })
        });
        let mut late_user_steer_first_call_id =
            late_user_steer_permit.map(|permit| permit.continuation_id);
        if let Some(permit) = late_user_steer_permit {
            if let Some(frame) = self.stack.last_mut() {
                // The owner match was checked before queue delivery. Store
                // the permit on the frame as well so a later QuestionTool
                // replay keeps the same continuation checkpoint instead of
                // treating its post-answer model turn as unrelated work.
                if frame.agent_instance_id == Some(permit.agent_instance_id) {
                    frame.late_user_steer_permit = Some(permit);
                }
            }
        }

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

            // A late steer consumes the immutable continuation identity minted
            // at durable acceptance. All other turns allocate a fresh id as
            // before. This is the bridge from the steer checkpoint to the
            // external-journal before-handoff fence: a crash/recovery cannot
            // dispatch its provider turn a second time under a new UUID.
            let late_user_steer_continuation_id = late_user_steer_first_call_id.take();
            let call_id = late_user_steer_continuation_id.unwrap_or_else(uuid::Uuid::new_v4);
            let context_usage = self.context_usage_snapshot();

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
            self.emit_command_capability_notice_if_new(tx).await;
            let mut turn_metadata = BackupTurnMetadata::default();
            let fallback_models = self.resolve_failover_models(&agent.model);
            // The durable snapshot carries the accepted continuation marker
            // for *every* subsequent model/tool phase, not merely its first
            // provider handoff.  A later QuestionTool park must recover the
            // same no-redelivery checkpoint instead of falling back to a
            // fresh user-body injection after restart.
            self.persist_active_interactive_task_snapshot(
                &next_prompt,
                late_user_steer_permit.map(|permit| permit.continuation_id),
            )
            .await?;
            // Run-invocation turn reservation: exact N max, terminal before N+1.
            if let Some(run_id) = run_invocation_id {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);
                // Checkpoint remaining before provider dispatch.
                if let Ok(Some(row)) = self.session.db.get_run_invocation(run_id).await {
                    if row.terminal_at_wall_ms.is_some() {
                        self.pending_idle_reason = Some(crate::engine::IdleReason::Error {
                            class: crate::engine::model::InferenceErrorClass::TimeoutIdle,
                        });
                        return Ok(());
                    }
                    if row.timeout_ms.is_some() {
                        let _ = self
                            .session
                            .db
                            .checkpoint_run_invocation_remaining(
                                run_id,
                                match crate::daemon::server::run_invocation_remaining_after_restart(
                                    &row, now,
                                ) {
                                    crate::daemon::server::RunInvocationRemaining::ClockNotStarted => {
                                        // A phase-one FCM2 reservation must be
                                        // materialized before any provider turn
                                        // can spend its configured timeout.
                                        return Ok(());
                                    }
                                    crate::daemon::server::RunInvocationRemaining::Remaining(ms) => {
                                        Some(ms)
                                    }
                                    crate::daemon::server::RunInvocationRemaining::Expired
                                    | crate::daemon::server::RunInvocationRemaining::ClockRollback => {
                                        let _ = self
                                            .session
                                            .db
                                            .fire_run_invocation_timeout(run_id, now)
                                            .await;
                                        cancel.cancel();
                                        self.pending_idle_reason =
                                            Some(crate::engine::IdleReason::Error {
                                                class: crate::engine::model::InferenceErrorClass::TimeoutIdle,
                                            });
                                        return Ok(());
                                    }
                                    crate::daemon::server::RunInvocationRemaining::Unbounded => None,
                                },
                                now,
                            )
                            .await;
                    }
                }
                match self
                    .session
                    .db
                    .reserve_run_invocation_turn(run_id, now)
                    .await
                {
                    Ok(crate::db::run_invocations::ReserveTurnOutcome::Reserved(_)) => {}
                    Ok(crate::db::run_invocations::ReserveTurnOutcome::MaxTurnsExceeded(_)) => {
                        self.pending_idle_reason = Some(crate::engine::IdleReason::Error {
                            class: crate::engine::model::InferenceErrorClass::Other(
                                "max_turns_exceeded".into(),
                            ),
                        });
                        return Ok(());
                    }
                    Ok(
                        crate::db::run_invocations::ReserveTurnOutcome::AlreadyTerminal(_)
                        | crate::db::run_invocations::ReserveTurnOutcome::CancelRequested(_)
                        | crate::db::run_invocations::ReserveTurnOutcome::ClockNotStarted(_),
                    ) => {
                        cancel.cancel();
                        return Ok(());
                    }
                    Ok(crate::db::run_invocations::ReserveTurnOutcome::NotFound) | Err(_) => {
                        // Fail closed: do not dispatch without a reservation.
                        return Ok(());
                    }
                }
            }
            let turn_result = {
                let top = self.stack.last_mut().expect("stack never empty");
                // The foreground frame's deferred-log buffer (`plan.md §3d`):
                // a subagent's `defer_to_orchestrator` calls land here, and
                // the driver folds them into the report when the frame pops.
                let deferred_log = top.deferred_log.clone();
                crate::engine::agent::with_agent_instance_id(
                    top.agent_instance_id,
                    crate::engine::agent::with_agent_tree_steer_dispatch_permit(
                        late_user_steer_permit.map(|permit| {
                            crate::engine::agent::AgentTreeSteerDispatchPermit::new(
                                self.session.clone(),
                                permit.steer_id,
                                permit.continuation_id,
                                permit.agent_instance_id,
                                permit.recovery_epoch,
                                cancel.clone(),
                            )
                        }),
                        turn_with_backup(
                            &agent,
                            backup_model.as_ref(),
                            &fallback_models,
                            &mut top.history,
                            next_prompt.clone(),
                            self.session.clone(),
                            self.locks.clone(),
                            self.redact.clone(),
                            self.cwd.clone(),
                            self.config.clone(),
                            self.interrupts.clone(),
                            cancel.clone(),
                            self.approver.clone(),
                            self.lsp.clone(),
                            self.resource_scheduler.clone(),
                            self.loop_guard_threshold,
                            is_root,
                            crate::skills::manage::SkillWriteOrigin::Foreground,
                            None,
                            context_usage,
                            deferred_log,
                            // The main/interactive frames never register the `seed`
                            // tool (it's a read-only-noninteractive-subagent + normal-
                            // mode affordance, GOALS §3c); a fresh empty collector
                            // satisfies the signature and is never drained here.
                            call_id,
                            tandem.as_ref(),
                            self.goal_root_turn
                                .map(|(goal_id, generation, _)| (goal_id, generation)),
                            Some(lifecycle_turn_id.clone()),
                            tx,
                            Some(&mut turn_metadata),
                        ),
                    ),
                )
                .await
            };
            if let Some(fallback) = turn_metadata.fallback_decision.take() {
                self.note_backup_fallback_for_active_frame(fallback, tx)
                    .await;
            }
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
                Err(e) if crate::engine::interrupt::is_parked(&e) => {
                    tracing::info!(agent = %agent.name, "turn paused on parked interrupt");
                    self.pending_idle_reason = Some(crate::engine::IdleReason::NeedsIntervention {
                        code: "parked_interrupt".to_string(),
                    });
                    self.finish_late_steer_continuation(LateUserSteerContinuationOutcome::Parked);
                    return Ok(());
                }
                Err(e) if crate::engine::model::is_late_user_steer_deferred(&e) => {
                    // The final provider-handoff transaction observed a new
                    // owner revision/state first. No provider request was
                    // made, so this is not a user cancellation and must not
                    // unwind/cancel the live owner frame. The worker releases
                    // the still-pending claim after our receipt; its ordered
                    // lifecycle scheduler re-delivers only after `running`.
                    self.finish_late_steer_continuation(
                        LateUserSteerContinuationOutcome::interrupted(
                            "late user steer deferred behind a newer owner continuation",
                        ),
                    );
                    let _ = self
                        .take_late_steer_for_interactive_root_terminal(&mut late_user_steer_permit);
                    return Ok(());
                }
                Err(e) if crate::engine::model::is_cancelled(&e) => {
                    tracing::info!(agent = %agent.name, "turn cancelled by user");
                    if let Some((goal_id, generation, turn_id)) = self.goal_root_turn.take() {
                        let _ = self
                            .session
                            .db
                            .cancel_goal_root_turn_for_user(goal_id, generation, turn_id)
                            .await;
                    }
                    self.pending_idle_reason = Some(crate::engine::IdleReason::Interrupted);
                    self.finish_late_steer_continuation(
                        LateUserSteerContinuationOutcome::Cancelled,
                    );
                    if let Some(run_id) = run_invocation_id {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or(0);
                        // Deadline may have already timed out; mark cancel only if still active.
                        let _ = self
                            .session
                            .db
                            .mark_run_invocation_terminal(run_id, "cancelled", "cancelled", now)
                            .await;
                    }
                    self.unwind_stack_to_root_and_discard_pending_input(
                        StackUnwindReason::Cancelled,
                        input_rx,
                        tx,
                    )
                    .await;
                    let _ = self
                        .take_late_steer_for_interactive_root_terminal(&mut late_user_steer_permit);
                    return Ok(());
                }
                // The daemon began draining (`daemon-graceful-drain-shutdown.md`):
                // the inference-dispatch chokepoint refused this *new* round-
                // trip. Unwind cleanly back to idle exactly like a cancel —
                // the worker proceeds to its `Shutdown`/drain teardown rather
                // than logging a real error.
                Err(e) if crate::engine::model::is_gated(&e) => {
                    tracing::info!(agent = %agent.name, "turn refused: daemon draining");
                    self.finish_late_steer_continuation(
                        LateUserSteerContinuationOutcome::interrupted(
                            "late user steer was interrupted by daemon drain",
                        ),
                    );
                    self.unwind_stack_to_root_and_discard_pending_input(
                        StackUnwindReason::Gated,
                        input_rx,
                        tx,
                    )
                    .await;
                    let _ = self
                        .take_late_steer_for_interactive_root_terminal(&mut late_user_steer_permit);
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
                    self.finish_late_steer_continuation(LateUserSteerContinuationOutcome::failed(
                        format!("late user steer inference failed: {}", f.class),
                    ));
                    if !self.handle_goal_usage_limit_failure(f, tx).await {
                        self.pending_idle_reason = Some(crate::engine::IdleReason::Error {
                            class: f.class.clone(),
                        });
                    }
                    if let Some(run_id) = run_invocation_id {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or(0);
                        let _ = self
                            .session
                            .db
                            .mark_run_invocation_terminal(run_id, "failed", "failed", now)
                            .await;
                    }
                    // `stopFailure` observe hooks: a terminal inference/API
                    // error ends the root attempt without a normal stop gate.
                    // Fire before the stack unwind; never on a normal `Done`.
                    self.run_stop_failure_hooks(&f.class).await;
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
                    let _ = self
                        .take_late_steer_for_interactive_root_terminal(&mut late_user_steer_permit);
                    return Ok(());
                }
                Err(e) => {
                    let _ = self
                        .take_late_steer_for_interactive_root_terminal(&mut late_user_steer_permit);
                    return Err(e);
                }
            };

            // Inference boundary (implementation note):
            // a turn just completed. Persist the root frame's prune ledger
            // so an unclean daemon kill still resumes with the last pruned
            // context — not only on a graceful `/exit`. Root frame only (a
            // subagent frame is transient and never resumed); best-effort.
            if is_root {
                self.persist_prune_ledger().await;
                if let Err(e) = self
                    .session
                    .db
                    .refresh_session_goal_usage(self.session.id)
                    .await
                {
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
                            .await?
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
                                let Some(prepared) = self
                                    .prepare_queued_user_submission(queued, input_rx, tx)
                                    .await
                                else {
                                    input_rx.finish(&queue_item_ids).await;
                                    return Ok(());
                                };
                                if self.record_queued_user_fold(&prepared, tx).await.is_err() {
                                    input_rx
                                        .requeue_front_after(
                                            prepared,
                                            self.active_queue_target(),
                                            DURABLE_SUBMISSION_RETRY_BACKOFF,
                                        )
                                        .await;
                                    if let Some(frame) = self.stack.last_mut() {
                                        let _ = frame.history.pop();
                                    }
                                    next_prompt = last_tool_result;
                                    continue;
                                }
                                input_rx.finish(&queue_item_ids).await;
                                self.reset_delegation_retry_budget();
                                next_prompt =
                                    crate::engine::message::build_user_message(UserSubmission {
                                        expected_model_state_generation: None,
                                        expected_model: None,
                                        kind: UserSubmissionKind::User,
                                        origin:
                                            crate::engine::message::SubmissionOrigin::AutoContinue,
                                        text: self.with_time_prelude(prepared.text),
                                        display_text: None,
                                        tag_expansions: Vec::new(),
                                        images: prepared.images,
                                        forced_skill: None,
                                        origin_principal: None,
                                        job_id: None,
                                        preflight_cleaned: None,
                                        queue_item_ids: Vec::new(),
                                        client_submissions: Vec::new(),
                                        queue_target: None,
                                        pending_terminal_disposition: None,
                                        run_invocation_id: None,
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
                    //
                    // Before publishing the child's envelope, consult the child's
                    // frame-owned `subagentStop` gate — the SINGLE firing for this
                    // genuine child stop (all three modes route child stop through
                    // `run_stop_hooks`; there is no separate observe fire). A
                    // blocking stop hook re-runs the CHILD with host feedback
                    // (`SubmissionOrigin::Internal`, so it never re-fires
                    // `userPromptSubmit`); the `!cancel` guard blocks a re-run
                    // raced by a cancel (the frame's latch drops on the ensuing
                    // unwind — never-reopen).
                    if let crate::engine::agent::hooks::StopHookOutcome::Continue {
                        reason,
                        additional_context,
                    } = self
                        .consult_active_child_stop_gate(
                            &crate::engine::agent::hooks::TokioCommandRunner::with_optional_containment(self.session.process_containment()),
                            &crate::engine::agent::hooks::DefaultProcessEnv,
                        )
                        .await
                        && !cancel.is_cancelled()
                    {
                        next_prompt = Self::stop_continuation_prompt(reason, additional_context);
                        continue;
                    }
                    let late_user_steer_completion = self
                        .take_late_steer_for_interactive_child_terminal(
                            &mut late_user_steer_permit,
                        );
                    if let Some(np) = self
                        .pop_child_with_envelope(
                            Some(&fields),
                            late_user_steer_completion,
                            &queue_item_ids,
                            tx,
                        )
                        .await
                    {
                        next_prompt = np;
                        continue;
                    }
                    return Ok(());
                }
                TurnOutcome::Done => {
                    if self.stack.len() > 1 {
                        // Genuine child completion with no `return` call. Consult
                        // the child's frame-owned `subagentStop` gate (the single
                        // firing for this stop) before popping; a blocking stop
                        // hook re-runs the child, else the envelope falls back to
                        // wrapping the child's final text as `accomplished`
                        // (priority #1 — never fail the delegation; `None` selects
                        // that path).
                        if let crate::engine::agent::hooks::StopHookOutcome::Continue {
                            reason,
                            additional_context,
                        } = self
                            .consult_active_child_stop_gate(
                                &crate::engine::agent::hooks::TokioCommandRunner::with_optional_containment(self.session.process_containment()),
                                &crate::engine::agent::hooks::DefaultProcessEnv,
                            )
                            .await
                            && !cancel.is_cancelled()
                        {
                            next_prompt =
                                Self::stop_continuation_prompt(reason, additional_context);
                            continue;
                        }
                        let late_user_steer_completion = self
                            .take_late_steer_for_interactive_child_terminal(
                                &mut late_user_steer_permit,
                            );
                        if let Some(np) = self
                            .pop_child_with_envelope(
                                None,
                                late_user_steer_completion,
                                &queue_item_ids,
                                tx,
                            )
                            .await
                        {
                            next_prompt = np;
                            continue;
                        }
                    }
                    // Root agent is done with this user message. Before
                    // we wait for the next user input, check if more
                    // landed in the queue while we were busy — fold
                    // them and start a new run with the combined text.
                    // A late steer reaches its receipt boundary at this `Done`.
                    // Do not fold a subsequently queued ordinary user turn into
                    // that continuation: it must run only after the permit is
                    // cleared and the durable completion is acknowledged.
                    if late_user_steer_permit.is_none() {
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
                                    let Some(prepared) = self
                                        .prepare_queued_user_submission(queued, input_rx, tx)
                                        .await
                                    else {
                                        input_rx.finish(&queue_item_ids).await;
                                        return Ok(());
                                    };
                                    if self.record_queued_user_fold(&prepared, tx).await.is_err() {
                                        input_rx
                                            .requeue_front_after(
                                                prepared,
                                                self.active_queue_target(),
                                                DURABLE_SUBMISSION_RETRY_BACKOFF,
                                            )
                                            .await;
                                        return Ok(());
                                    }
                                    input_rx.finish(&queue_item_ids).await;
                                    self.reset_delegation_retry_budget();
                                    next_prompt =
                                    crate::engine::message::build_user_message(UserSubmission {
                                        expected_model_state_generation: None,
                                        expected_model: None,
                                        kind: UserSubmissionKind::User,
                                        origin: crate::engine::message::SubmissionOrigin::GoalContinuation,
                                        text: prepared.text,
                                        display_text: None,
                                        tag_expansions: Vec::new(),
                                        images: prepared.images,
                                        forced_skill: None,
                                        origin_principal: None,
                                        job_id: None,
                                        preflight_cleaned: None,
                                        queue_item_ids: Vec::new(),
                                        client_submissions: Vec::new(),
                                        queue_target: None,
                                        pending_terminal_disposition: None,
                                        run_invocation_id: prepared.run_invocation_id,
                                    });
                                    // Continue under the next invocation's identity when present.
                                    // (Outer `run_invocation_id` still binds the original run.)
                                    continue;
                                }
                            }
                        }
                    }
                    // Root turn reached a genuine normal `Done` and no queued
                    // user work remains: consult the ROOT stop gate. This is the
                    // ONLY entry to the gate — the cancel / parked-interrupt /
                    // daemon-drain / inference-error branches all `return`ed from
                    // the `Err(..)` arms above WITHOUT reaching this `match`, and
                    // the primary-round ceiling returns from the `Continue` arm,
                    // so no aborted/errored/capped turn can enter or reopen it.
                    // Production uses the shipped runner / process-env, exactly
                    // like every other hook site.
                    match self
                        .consult_root_stop_gate(
                            &crate::engine::agent::hooks::TokioCommandRunner::with_optional_containment(self.session.process_containment()),
                            &crate::engine::agent::hooks::DefaultProcessEnv,
                            &mut root_stop_gate,
                        )
                        .await
                    {
                        crate::engine::agent::hooks::StopHookOutcome::Continue {
                            reason,
                            additional_context,
                        } if !cancel.is_cancelled() => {
                            // A `stop` hook blocked the turn from ending. Inject
                            // the aggregated feedback into the ROOT frame as
                            // host-generated context and run another model round.
                            // `stop_continuation_prompt` builds the message
                            // directly (never via `record_user_message_event`),
                            // so this cannot re-fire `userPromptSubmit`.
                            //
                            // The `!cancel.is_cancelled()` guard closes the race
                            // where a user cancel (or run-deadline abort) arrives
                            // AFTER `Done` but DURING the stop-hook consultation:
                            // a cancelled turn must never be forced into another
                            // model round, so a `Continue` decided under a
                            // now-cancelled token is dropped and the turn ends.
                            next_prompt =
                                Self::stop_continuation_prompt(reason, additional_context);
                            continue;
                        }
                        // `End` (no blocking stop hook), `ForcedEnd`
                        // (`continue:false` won, or the per-turn 8-cap latched),
                        // or a `Continue` superseded by a mid-consult cancel: the
                        // root turn ends normally below.
                        crate::engine::agent::hooks::StopHookOutcome::Continue { .. }
                        | crate::engine::agent::hooks::StopHookOutcome::End
                        | crate::engine::agent::hooks::StopHookOutcome::ForcedEnd(_) => {}
                    }
                    if let Some(anchor_seq) = goal_continue_anchor_seq {
                        if self.goal_continue_progress_since(anchor_seq).await {
                            self.reset_goal_progress_tracking().await;
                            self.clear_goal_idle_intervention();
                        } else {
                            self.emit_goal_continue_no_progress(anchor_seq, tx).await;
                        }
                    }
                    self.maybe_spawn_self_improvement_review(tx).await;
                    if let Some(run_id) = run_invocation_id {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or(0);
                        let _ = self
                            .session
                            .db
                            .mark_run_invocation_terminal(run_id, "succeeded", "succeeded", now)
                            .await;
                    }
                    self.finish_late_steer_continuation(
                        LateUserSteerContinuationOutcome::Completed,
                    );
                    let _ = self
                        .take_late_steer_for_interactive_root_terminal(&mut late_user_steer_permit);
                    return Ok(());
                }
                TurnOutcome::SpawnSubagent {
                    child_agent,
                    prompt: mut brief,
                    model,
                    remaining_depth,
                    granted_tools,
                    todo_ids,
                    repair_notes,
                    task_call_id,
                    task_provider_item_id,
                    task_function_call_id,
                } => {
                    if let Err(err) = self.consume_delegation_retry_budget() {
                        next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                            task_call_id,
                            task_provider_item_id,
                            task_function_call_id,
                            "task",
                            prepend_task_repair_notes(err, &repair_notes),
                        );
                        continue;
                    }
                    let child_recursion = match self.resolve_task_recursion(
                        &child_agent,
                        remaining_depth,
                        &model,
                    ) {
                        Ok(ctx) => ctx,
                        Err(err) => {
                            next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                    task_call_id,
                                    task_provider_item_id,
                                    task_function_call_id,
                                    "task",
                                    prepend_task_repair_notes(err, &repair_notes),
                                );
                            continue;
                        }
                    };
                    let parent_agent = self.stack.last().unwrap().agent.name.clone();
                    let parent_vnext_grant = self
                        .stack
                        .last()
                        .and_then(|frame| frame.agent.vnext_grant.clone());
                    // Per-delegation tool grants (prompt `parent-granted-tools.md`):
                    // validate against the target's role invariants before the
                    // handoff. An invalid grant is rejected as this `task`
                    // call's result — the conversation stays with the parent.
                    if let Some(err) = grant_rejection(GrantRejectionInput {
                        parent_cwd: &self.cwd,
                        cwd: &self.cwd,
                        config: &self.config,
                        parent_agent: &parent_agent,
                        parent_vnext_grant: parent_vnext_grant.as_ref(),
                        child_agent: &child_agent,
                        grant: &granted_tools,
                        assistant_db: &self.session.db,
                        local_installations: &self.vnext_local_installation_resolver,
                    })
                    .await
                    {
                        next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                            task_call_id,
                            task_provider_item_id,
                            task_function_call_id,
                            "task",
                            prepend_task_repair_notes(err, &repair_notes),
                        );
                        continue;
                    }
                    // Interactive children normally serialize their parent, but
                    // they can overlap a previously backgrounded task. Reserve a
                    // vNext direct-child slot here as well so that route cannot
                    // bypass the same live-concurrency ceiling.
                    let mut vnext_admissions = match self.admit_current_vnext_children(1) {
                        Ok(permits) => permits,
                        Err(err) => {
                            next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                task_call_id,
                                task_provider_item_id,
                                task_function_call_id,
                                "task",
                                prepend_task_repair_notes(err, &repair_notes),
                            );
                            continue;
                        }
                    };
                    let task_args_json = serde_json::to_string(&serde_json::json!({
                        "child_agent": &child_agent,
                        "model": model_selector_json(&model),
                        "remaining_depth": remaining_depth,
                        "granted_tools": &granted_tools,
                        "todo_ids": &todo_ids,
                        "provider_item_id": &task_provider_item_id,
                        "function_call_id": &task_function_call_id,
                        "repair_notes": &repair_notes,
                        "interactive": true,
                    }))
                    .ok();
                    let model_display = model_selector_display(&model);
                    let child_inits = [crate::db::task_delegations::DelegationChildInit {
                        label: "default",
                        child_agent: &child_agent,
                        model: model_display.as_deref(),
                        output_dir: None,
                        requested_cwd: None,
                        resolved_cwd: None,
                        todo_ids_json: None,
                    }];
                    match self
                        .session
                        .db
                        .upsert_task_delegation_job_and_payload(
                            crate::db::task_delegations::TaskDelegationJobUpsert {
                                session_id: self.session.id,
                                task_call_id: &task_call_id,
                                function_call_id: task_function_call_id.as_deref(),
                                parent_agent: &parent_agent,
                                original_args_json: task_args_json.as_deref(),
                                children: &child_inits,
                            },
                            crate::db::task_delegation_payloads::NewTaskDelegationPayload {
                                task_call_id: &task_call_id,
                                function_call_id: task_function_call_id.as_deref(),
                                parent_session_id: self.session.id,
                                parent_agent: &parent_agent,
                                label: "default",
                                child_agent: &child_agent,
                                prompt: &brief,
                            },
                        )
                        .await
                    {
                        Ok(row) => brief = delegation_payload_reference_prompt(&row),
                        Err(e) => {
                            tracing::warn!(error = %e, task_call_id, "persist interactive task delegation job and payload failed");
                            next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                task_call_id,
                                task_provider_item_id,
                                task_function_call_id,
                                "task",
                                prepend_task_repair_notes(
                                    DELEGATION_PAYLOAD_REFUSAL.to_string(),
                                    &repair_notes,
                                ),
                            );
                            continue;
                        }
                    }
                    let Some(parent_agent_instance_id) =
                        self.stack.last().and_then(|frame| frame.agent_instance_id)
                    else {
                        tracing::warn!("interactive task started without a durable parent agent");
                        next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                            task_call_id,
                            task_provider_item_id,
                            task_function_call_id,
                            "task",
                            prepend_task_repair_notes(
                                DELEGATION_PAYLOAD_REFUSAL.to_string(),
                                &repair_notes,
                            ),
                        );
                        continue;
                    };
                    let (delegation_payload_history, brief) = match self
                        .delegation_payload_delivery(&task_call_id, "default", &brief, true)
                        .await
                    {
                        Ok(delivery) => delivery,
                        Err(e) => {
                            tracing::warn!(error = %e, task_call_id, "interactive task delegation payload delivery failed");
                            next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                task_call_id,
                                task_provider_item_id,
                                task_function_call_id,
                                "task",
                                prepend_task_repair_notes(
                                    DELEGATION_PAYLOAD_REFUSAL.to_string(),
                                    &repair_notes,
                                ),
                            );
                            continue;
                        }
                    };
                    let snapshot_json = match serde_json::to_string(&serde_json::json!({
                        "version": 1,
                        "history": &delegation_payload_history,
                    })) {
                        Ok(snapshot_json) => snapshot_json,
                        Err(error) => {
                            tracing::warn!(%error, %task_call_id, "serializing interactive task recovery snapshot failed");
                            next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                task_call_id,
                                task_provider_item_id,
                                task_function_call_id,
                                "task",
                                prepend_task_repair_notes(
                                    DELEGATION_PAYLOAD_REFUSAL.to_string(),
                                    &repair_notes,
                                ),
                            );
                            continue;
                        }
                    };
                    // The first continuation and its durable AgentTree node
                    // publish together.  A restart can therefore observe
                    // either an unstarted task child or a fully-addressable
                    // interactive executor, never the old orphaned middle.
                    let child_agent_instance_id = match self
                        .session
                        .db
                        .publish_task_delegation_children_and_agents(
                            self.session.id,
                            parent_agent_instance_id,
                            task_call_id.clone(),
                            vec![crate::db::agent_tree_decisions::NewTaskDelegationAgent {
                                label: "default".to_string(),
                                snapshot_json,
                            }],
                            crate::agent_tree::system_now_unix_ms(),
                        )
                        .await
                    {
                        Ok(mut children) if children.len() == 1 => {
                            children
                                .pop()
                                .expect("one published interactive child")
                                .agent_instance_id
                        }
                        Ok(_) => {
                            tracing::error!(%task_call_id, "interactive task publication returned an invalid child count");
                            next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                task_call_id,
                                task_provider_item_id,
                                task_function_call_id,
                                "task",
                                prepend_task_repair_notes(
                                    DELEGATION_PAYLOAD_REFUSAL.to_string(),
                                    &repair_notes,
                                ),
                            );
                            continue;
                        }
                        Err(error) => {
                            tracing::warn!(%error, %task_call_id, "atomically publishing interactive task child and agent tree identity failed");
                            next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                task_call_id,
                                task_provider_item_id,
                                task_function_call_id,
                                "task",
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
                            task_provider_item_id: task_provider_item_id.clone(),
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
                    let child_routing = ChildRoutingMetadata::from_model(&child.model);
                    let child_llm_mode = child.llm_mode;
                    self.emit_subagent_routing_amend(
                        tx,
                        &child_agent,
                        &task_call_id,
                        "default",
                        &child_routing,
                    )
                    .await;

                    // Snapshot the outgoing primary's locks before the
                    // child takes over. If the parent ever resumes (the
                    // child pops via TurnOutcome::Done above), the
                    // matching-hash files can come back without a re-
                    // read round-trip.
                    if let Some(parent) = self.stack.last()
                        && let Err(e) = self
                            .locks
                            .suspend_agent(&parent.agent.name, self.session.id)
                            .await
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
                    let endpoint_generation =
                        crate::engine::agent::next_agent_tree_endpoint_generation();
                    self.stack.push(AgentSession {
                        queue_target: crate::engine::message::QueueTarget::child(
                            child.name.clone(),
                            self.stack.len(),
                            task_call_id.clone(),
                            "default",
                        ),
                        agent: Arc::new(child),
                        agent_instance_id: Some(child_agent_instance_id),
                        endpoint_generation: Some(endpoint_generation),
                        history: delegation_payload_history,
                        answering: Some(PendingTaskCall {
                            call_id: task_call_id.clone(),
                            provider_item_id: task_provider_item_id,
                            function_call_id: task_function_call_id,
                            repair_notes,
                        }),
                        deferred_log: crate::engine::deferred::DeferredLog::new(),
                        fallback_decision: None,
                        recovery_activation: None,
                        late_user_steer_permit: None,
                        // Exactly one permit was reserved above. Holding it on
                        // the child frame releases the parent slot when this
                        // interactive child returns or the stack unwinds.
                        _vnext_child_admission: vnext_admissions.pop(),
                        stop_gate: crate::engine::agent::hooks::StopGateState::default(),
                    });
                    // A warm automatic-decision request may be delivered only
                    // after this exact durable frame is on the stack. The
                    // session worker binds this event to its driver control
                    // endpoint; the control handler rechecks the UUID before
                    // it performs any model work.
                    let _ = tx
                        .send(TurnEvent::AgentTreeExecutorEndpointAttached {
                            agent_instance_id: child_agent_instance_id,
                            endpoint_generation,
                        })
                        .await;
                    // `subagentStart` observe hooks: the INTERACTIVE child
                    // session has just been pushed onto the stack (spawn mode 1
                    // of 3). Child-only; matcher / `subagentType` is the child
                    // agent type, `subagentId` is the delegating `task` call id.
                    self.fire_subagent_hook(
                        crate::config::extended::hooks::HookEvent::SubagentStart,
                        &child_agent,
                        Some(&task_call_id),
                        None,
                    )
                    .await;
                    self.publish_active_tool_names().await;
                    self.emit_command_capability_notice_if_new(tx).await;
                    let _ = tx
                        .send(TurnEvent::ForegroundInputTarget {
                            target: self.active_queue_target(),
                        })
                        .await;
                    if self.prompt_cache_retention_override.is_some() {
                        self.emit_longcache_state(tx).await;
                    }
                    let brief = self
                        .assign_todos_to_task(
                            brief,
                            &todo_ids,
                            &task_call_id,
                            "default",
                            &child_agent,
                        )
                        .await;
                    let brief =
                        self.expand_handoff_tags(&brief, &self.cwd, child_llm_mode, &child_agent);
                    // Render the handoff brief for the interactive child's
                    // resolved custody class before it is dispatched: an
                    // untrusted (cloud) child gets the session redaction-table
                    // rendering, a trusted (self-hosted / no-log) child gets it
                    // unchanged.
                    let brief = {
                        let (extended, providers) =
                            crate::engine::model_roles::load_model_role_config(&self.config);
                        let child_model = self
                            .stack
                            .last()
                            .expect("stack never empty")
                            .agent
                            .model
                            .clone();
                        crate::engine::model_roles::render_brief_for_model(
                            &providers,
                            &child_model,
                            &extended,
                            &brief,
                        )
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
                    write_scope,
                    context,
                    granted_tools,
                    todo_ids,
                    repair_notes,
                    task_call_id,
                    task_provider_item_id,
                    task_function_call_id,
                } => {
                    if let Err(err) = self.consume_delegation_retry_budget() {
                        next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                            task_call_id,
                            task_provider_item_id,
                            task_function_call_id,
                            "task",
                            prepend_task_repair_notes(err, &repair_notes),
                        );
                        continue;
                    }
                    let child_recursion = match self.resolve_task_recursion(
                        &child_agent,
                        remaining_depth,
                        &model,
                    ) {
                        Ok(ctx) => ctx,
                        Err(err) => {
                            next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                    task_call_id,
                                    task_provider_item_id,
                                    task_function_call_id,
                                    "task",
                                    prepend_task_repair_notes(err, &repair_notes),
                                );
                            continue;
                        }
                    };
                    let child_cwd = match self.resolve_child_cwd(cwd.as_deref()) {
                        Ok(child_cwd) => child_cwd,
                        Err(err) => {
                            next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                task_call_id,
                                task_provider_item_id,
                                task_function_call_id,
                                "task",
                                prepend_task_repair_notes(err, &repair_notes),
                            );
                            continue;
                        }
                    };
                    let parent_agent = self.stack.last().unwrap().agent.name.clone();
                    let parent_vnext_grant = self
                        .stack
                        .last()
                        .and_then(|frame| frame.agent.vnext_grant.clone());
                    if let Some(err) = grant_rejection(GrantRejectionInput {
                        parent_cwd: &self.cwd,
                        cwd: &child_cwd.resolved,
                        config: &self.config,
                        parent_agent: &parent_agent,
                        parent_vnext_grant: parent_vnext_grant.as_ref(),
                        child_agent: &child_agent,
                        grant: &granted_tools,
                        assistant_db: &self.session.db,
                        local_installations: &self.vnext_local_installation_resolver,
                    })
                    .await
                    {
                        next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                            task_call_id,
                            task_provider_item_id,
                            task_function_call_id,
                            "task",
                            prepend_task_repair_notes(err, &repair_notes),
                        );
                        continue;
                    }
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
                                context,
                                write_scope,
                                granted_tools,
                                todo_ids,
                                child_recursion,
                                repair_notes,
                                task_call_id,
                                task_provider_item_id,
                                task_function_call_id,
                                recovery: None,
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
                    task_provider_item_id,
                    task_function_call_id,
                } => {
                    if let Err(err) = self.consume_delegation_retry_budget() {
                        next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                            task_call_id,
                            task_provider_item_id,
                            task_function_call_id,
                            "task",
                            prepend_task_repair_notes(err, &repair_notes),
                        );
                        continue;
                    }
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
                        next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                            task_call_id,
                            task_provider_item_id,
                            task_function_call_id,
                            "task",
                            prepend_task_repair_notes(err, &repair_notes),
                        );
                        continue;
                    }
                    let parent_agent = self.stack.last().unwrap().agent.name.clone();
                    let parent_vnext_grant = self
                        .stack
                        .last()
                        .and_then(|frame| frame.agent.vnext_grant.clone());
                    let mut unknown_agent_error = None;
                    for (entry, child_cwd) in entries.iter().zip(child_cwds.iter()) {
                        if let Some(err) = grant_rejection(GrantRejectionInput {
                            parent_cwd: &self.cwd,
                            cwd: &child_cwd.resolved,
                            config: &self.config,
                            parent_agent: &parent_agent,
                            parent_vnext_grant: parent_vnext_grant.as_ref(),
                            child_agent: &entry.child_agent,
                            grant: &entry.granted_tools,
                            assistant_db: &self.session.db,
                            local_installations: &self.vnext_local_installation_resolver,
                        })
                        .await
                        {
                            unknown_agent_error = Some(format!(
                                "Error: batch entry `{}`: {}",
                                entry.label,
                                err.strip_prefix("Error: ").unwrap_or(&err)
                            ));
                            break;
                        }
                    }
                    if let Some(err) = unknown_agent_error {
                        next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                            task_call_id,
                            task_provider_item_id,
                            task_function_call_id,
                            "task",
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
                                task_provider_item_id,
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
                    task_provider_item_id,
                    task_function_call_id,
                } => {
                    let body = self
                        .dispatch_task_control(action, target_task_call_id, label, message)
                        .await;
                    next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        "task",
                        body,
                    );
                    continue;
                }
                TurnOutcome::ToolResult {
                    task_call_id,
                    task_provider_item_id,
                    task_function_call_id,
                    mut body,
                } => {
                    if let Some(note) = self.pending_monty_tool_nudge.take() {
                        body.push_str("\n\n[tool surface update]\n");
                        body.push_str(&note);
                    }
                    next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        "task",
                        body,
                    );
                    continue;
                }
                TurnOutcome::Spawn {
                    prompt,
                    write_scope,
                    model,
                    task_call_id,
                    task_provider_item_id,
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
                    // `write_scope` is the contention-avoidance mechanism: each
                    // child writes only there, so disjoint scopes coexist and
                    // the lock manager still serializes any same-path write.
                    let agent_name = self.stack.last().unwrap().agent.name.clone();
                    let _ = tx
                        .send(TurnEvent::ToolStart {
                            agent: agent_name.clone(),
                            call_id: task_call_id.clone(),
                            tool: "spawn".to_string(),
                            args: serde_json::json!({ "write_scope": write_scope }),
                        })
                        .await;
                    let parent_depth = self.foreground_swarm_depth();
                    let worker = match agent_name.as_str() {
                        "Multireview" | "scout" => {
                            crate::engine::schedule::authority::SpawnWorkerKind::Scout
                        }
                        _ => crate::engine::schedule::authority::SpawnWorkerKind::Bee,
                    };
                    let output = match spawn_gate(parent_depth, self.swarm_max_depth, &write_scope)
                    {
                        Err(refusal) => refusal,
                        Ok(child_depth) => {
                            // Strict writable delegation needs a backend that
                            // can isolate arbitrary child syscalls. Refuse
                            // before any child record, token, or event exists.
                            // Probe the SAME backend the coordinator enforces
                            // against, so the fast gate and the durable transfer
                            // can never disagree.
                            //
                            // `worker` is resolved once above and reused here.
                            let coordinator = self.write_scope_coordinator();
                            let backend: &dyn crate::write_scope::ScopedWriteBackend =
                                match coordinator.as_ref() {
                                    Some(c) => c.backend().as_ref(),
                                    None => &crate::write_scope::DirectWorkspaceBackend,
                                };
                            match scoped_write_refusal(worker, &self.cwd, &write_scope, backend) {
                                Some(refusal) => refusal,
                                None => self.schedule.spawn_swarm(
                                    crate::engine::schedule::authority::SpawnSpec {
                                        job_id: None,
                                        goal_provenance: None,
                                        worker,
                                        prompt,
                                        write_scope,
                                        model,
                                        // The `spawn` tool argument is
                                        // model-authored, so the selector is
                                        // forced onto redacted-untrusted
                                        // custody and cannot claim
                                        // host-named-target privileges.
                                        model_origin:
                                            crate::engine::schedule::authority::SpawnModelOrigin::ModelDirected,
                                        depth: child_depth,
                                        max_depth: self.swarm_max_depth,
                                    },
                                ),
                            }
                        }
                    };
                    let _ = tx
                        .send(TurnEvent::ToolEnd {
                            agent: agent_name,
                            call_id: task_call_id.clone(),
                            tool: "spawn".to_string(),
                            output: output.clone(),
                            truncated: false,
                            seq: None,
                            // The hint layer is `bash`-only.
                            hint: None,
                        })
                        .await;
                    next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        "spawn",
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
                    task_provider_item_id,
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
                                    if matches!(recovery, crate::db::tool_calls::Recovery::Clean) {
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
                                seq: None,
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
                                seq: None,
                                // The hint layer is `bash`-only.
                                hint: None,
                            })
                            .await;
                    }
                    self.record_schedule_tool_call(ScheduleToolCallRecord {
                        agent: agent_name.clone(),
                        llm_mode,
                        call_id: task_call_id.clone(),
                        provider_item_id: task_provider_item_id.clone(),
                        provider_call_id: task_function_call_id.clone(),
                        original_input_json: original_args,
                        wire_input_json: wire_input,
                        recovery,
                        hard_fail,
                        output: output.clone(),
                        duration_ms: start.elapsed().as_millis() as u64,
                    })
                    .await;
                    next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        "schedule",
                        output,
                    );
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
                Err(Box::new(
                    crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        req.task_call_id.to_string(),
                        req.task_provider_item_id,
                        req.task_function_call_id,
                        "task",
                        prepend_task_repair_notes(
                            format!(
                                "Error: failed to load subagent `{}`: {e:#}",
                                req.child_agent
                            ),
                            req.repair_notes,
                        ),
                    ),
                ))
            }
        }
    }

    fn spawn_args(&self, interactive: bool) -> crate::engine::builtin::SpawnArgs {
        let mut params = self.stack[0].agent.params.clone();
        if !interactive {
            params.prompt_cache_key = None;
            params.prompt_cache_retention = None;
        }
        crate::engine::builtin::SpawnArgs {
            model: self.stack[0].agent.model.clone(),
            params,
            env_overlay: self.stack[0].agent.env_overlay.clone(),
            cwd: self.cwd.clone(),
            config: self.config.clone(),
            session_short_id: self.session.short_id(),
            assistant_identity_prefix: self.assistant_identity_prefix.clone(),
            model_system_prompt_snapshot: self.session.model_system_prompt_snapshot(),
            interactive,
            // The root frame's posture. This is the authoritative mode only for
            // a root/primary build; a DELEGATED child re-resolves its own
            // posture from its selected model at build time
            // ([`crate::engine::builtin::child_llm_mode_for_model`]), so this
            // value is just the baseline a non-delegated spawn keeps.
            llm_mode: self.stack[0].agent.llm_mode,
            // A plan-level model override propagates to the whole delegation
            // tree so every spawned agent runs under it.
            model_override: self.model_override.clone(),
            delegation_model: None,
            delegated: false,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            vnext_grant: None,
            // Keep the root's already-snapshotted daemon policy available for
            // root replacement/handoff construction. Delegated vNext children
            // use their parent's effective grant rather than re-reading this.
            vnext_host_policy: self
                .stack
                .first()
                .and_then(|frame| frame.agent.vnext_grant.as_ref())
                .map(|grant| Arc::new(grant.host_policy.clone())),
            vnext_local_installation_resolver: self.vnext_local_installation_resolver.clone(),
            parent_vnext_grant: None,
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
            lock_identity: None,
            write_scope: None,
            // Owner-scoped store for delegated/computer-use model construction,
            // derived from the driver's pinned providers config: a child can only
            // resolve a `$secret:` owned by (provider, this workspace). See
            // `named-secret-ownership-boundary`.
            credential_store: self
                .session
                .provider_credential_store(&self.config.providers())
                .ok(),
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
            // The child factory consumes this immutable parent snapshot and
            // derives the child grant under the same host ceilings. It never
            // reinterprets the parent markdown declaration.
            parent_vnext_grant: self
                .stack
                .last()
                .and_then(|frame| frame.agent.vnext_grant.clone()),
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
        self.spawn_args_delegated_in_cwd_scoped(
            child_cwd,
            interactive,
            grant,
            model,
            recursion,
            DelegationConfinement::default(),
        )
    }

    fn spawn_args_delegated_in_cwd_scoped(
        &self,
        child_cwd: &std::path::Path,
        interactive: bool,
        grant: Vec<String>,
        model: Option<crate::engine::model_roles::DelegationModelSelector>,
        recursion: crate::engine::builtin::DelegationRecursionContext,
        confinement: DelegationConfinement,
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
            parent_vnext_grant: self
                .stack
                .last()
                .and_then(|frame| frame.agent.vnext_grant.clone()),
            model_override,
            cwd: child_cwd.to_path_buf(),
            lock_identity: confinement.lock_identity,
            write_scope: confinement.write_scope,
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
        if parent.vnext_grant.is_some() {
            // v2 has no projection onto the legacy recursive-task context.
            // The asynchronous task-admission seam resolves the selected child
            // under this parent's EffectiveVnextGrant immediately before
            // construction, including depth, targets, and the caller/child
            // kind matrix. `remaining_depth` is legacy wire input and cannot
            // widen a v2 grant.
            let _ = (child_agent, requested_depth, model);
            return Ok(crate::engine::builtin::DelegationRecursionContext::default());
        }
        let cfg = self.config.extended().delegation;
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

fn resolved_goal_supervision_config(
    persisted: &str,
    live_enabled: bool,
) -> Result<crate::config::extended::GoalSupervisionConfig> {
    if !live_enabled {
        anyhow::bail!("goal supervision disabled while goal is running");
    }
    serde_json::from_str(persisted).context("decoding persisted resolved goal supervision policy")
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

/// Per-parent-turn cap on accepted `task` delegations. This bounds a weak
/// parent model that keeps re-issuing delegation after child failures; each
/// batch consumes one unit so siblings in a batch do not starve one another.
pub(crate) const DELEGATION_RETRY_BUDGET_PER_TURN: usize = 4;

#[cfg(test)]
mod tests;
