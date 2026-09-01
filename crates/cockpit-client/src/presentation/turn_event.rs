use super::{
    AssistantAttemptId, AssistantTextPayload, ControlRequestId, ControlRequestOutcome,
    DisplayErrorKind, ResponsePerformance, TokenUsage, ToolProgress,
};
use cockpit_proto::IdleReason;

/// Events the agent emits during a turn. The driver forwards these to
/// the TUI for display; the persistence layer can subscribe to the
/// same channel.
#[derive(Debug, Clone)]
pub enum TurnEvent {
    /// TUI-local result for a response-bearing control request sent to the
    /// attached daemon session. It is not forwarded over the daemon event bus.
    ControlRequestFinished {
        request_id: ControlRequestId,
        outcome: ControlRequestOutcome,
    },
    InterruptDecision {
        session_id: uuid::Uuid,
        interrupt_id: uuid::Uuid,
        decision: cockpit_proto::InterruptDecision,
        seq: Option<i64>,
    },
    /// Authoritative daemon-owned queue snapshot for pending user messages.
    /// The TUI renders this mirror and never locally removes queue entries
    /// unless the daemon confirms removal.
    QueueUpdated {
        queue: Vec<cockpit_proto::QueueItem>,
    },
    /// Foreground input target snapshot. The daemon uses it to stamp queued
    /// user messages and forwards it to clients so queue editability is visible.
    ForegroundInputTarget { target: cockpit_proto::QueueTarget },
    /// Authoritative active model state after a daemon-owned switch attempt or
    /// same-model reselect. TUI chrome is driven from this snapshot instead of
    /// local config writes.
    ActiveModelState {
        selection: cockpit_proto::ActiveModelRef,
        default_selection: Option<cockpit_proto::ActiveModelRef>,
        diverged: bool,
        generation: u64,
    },
    /// Terminal result for a client-correlated active-model selection.
    ModelSelectionResult {
        selection_id: uuid::Uuid,
        provider: String,
        model: String,
        reasoning_effort: Option<String>,
        thinking_mode: Option<cockpit_proto::ThinkingMode>,
        prompt_cache_retention: Option<cockpit_proto::PromptCacheRetention>,
        outcome: cockpit_proto::ModelSelectionOutcome,
    },
    /// Terminal result for a config-only default update from Settings.
    DefaultModelUpdateResult {
        default_update_id: uuid::Uuid,
        outcome: cockpit_proto::DefaultModelStandaloneOutcome,
    },
    /// Authoritative daemon-resolved config snapshot for the attached
    /// session (`tui-config-single-source`). Delivered on attach and on every
    /// daemon re-resolution; the TUI renders from it instead of re-reading
    /// config from disk. Carries the generation used to drop stale pushes.
    /// TUI-inbound only — never emitted from a `TurnEvent` back onto the wire.
    ConfigSnapshot {
        snapshot: Box<cockpit_proto::ConfigSnapshot>,
    },
    /// Authoritative daemon-owned host capability snapshot. Delivered on
    /// `GetHostCapabilities` / `RefreshHostCapabilities` / KEK migrate and
    /// whenever the daemon republishes probes.
    HostCapabilitiesChanged {
        snapshot: Box<cockpit_proto::HostCapabilitySnapshot>,
    },
    /// Model inference started; nothing has been emitted yet. The TUI
    /// shows a "Thinking…" placeholder until the first text delta
    /// arrives. Fires once per round-trip; also fires before reasoning-
    /// mode models start emitting their reasoning chunks (which we
    /// currently drop — see [`crate::engine::model::Model::complete`]).
    ThinkingStarted {
        agent: String,
        #[allow(dead_code)]
        turn_id: Option<String>,
    },
    /// An inference call failed with a network/transient error and is
    /// being auto-retried (GOALS network-retry). `attempt` is the 1-based
    /// retry number; `provider`/`model`/`url` name the unreachable target.
    /// The TUI shows a distinct, persistent `reconnecting — <provider>/
    /// <model> unreachable at <url> (attempt N)` status (never the generic
    /// working spinner, no per-attempt toast spam); cleared by the next
    /// `AssistantTextDelta` / `AgentIdle` / a settled turn once output
    /// flows again.
    Reconnecting {
        agent: String,
        attempt: u32,
        provider: String,
        model: String,
        url: String,
    },
    /// The TUI lost its daemon socket and is retrying the local link.
    DaemonLinkReconnecting { restarting: bool, attempt: u32 },
    /// The TUI reattached to the daemon after a socket drop. The attach
    /// snapshot starts a new worker-local model-generation epoch even when
    /// the durable session id is unchanged.
    DaemonLinkReconnected {
        active_model_state: Option<cockpit_proto::ActiveModelState>,
    },
    /// An event-stream lag marker triggered an authoritative attach resync on
    /// the existing socket. No reconnect chrome is shown, but the attach
    /// snapshot still starts a fresh client-side model-generation epoch.
    DaemonLinkResynced {
        active_model_state: Option<cockpit_proto::ActiveModelState>,
    },
    /// Reattach reached a terminal attach error and will not retry.
    DaemonLinkTerminal { error: String },
    /// Reattach found durable paused work that needs a local decision.
    PausedWorkAvailable {
        session_id: uuid::Uuid,
        items: Vec<cockpit_proto::PausedWorkSummary>,
    },
    /// Reattach found a read-only resume-repair state that needs a local
    /// decision before continuing.
    ResumeRepairRequired {
        state: cockpit_proto::ResumeRepairState,
    },
    /// Warm daemon reattach replay of persisted history entries.
    HistoryReplay {
        entries: Vec<cockpit_proto::HistoryEntry>,
        /// Durable user rows deleted by retractions since the client's replay
        /// cursor. These targeted ids never carry user text.
        removed_user_message_seqs: Vec<i64>,
    },
    /// A configured stream wait threshold elapsed. The TUI shows a yellow
    /// warning; without a backup the stream keeps waiting, while with a backup
    /// this can immediately precede fallback. UI-only and never enters model
    /// context.
    InferenceWarning {
        agent: String,
        provider: String,
        model: String,
        /// `ttft` before the first token, `idle` between tokens.
        phase: String,
        waited_secs: u64,
    },
    /// One streaming chunk of the assistant's text response. The TUI
    /// accumulates these in a live-rendered line.
    ///
    /// **Legacy live path.** Production interactive/noninteractive display
    /// uses [`Self::AssistantDisplayTextDelta`] from the attempt-dispatch
    /// classifier. This variant remains only for synthetic/test emitters that
    /// do not own a classifier; it must not drive the performance chip.
    AssistantTextDelta { agent: String, delta: String },
    /// One streaming chunk of the model's *reasoning* (thinking-mode
    /// models only). The TUI hides this by default — the
    /// "Thinking…" placeholder is the visible affordance — but
    /// captures it so the user can expand a thinking block later to
    /// inspect the chain of thought.
    ///
    /// **Legacy live path.** Prefer [`Self::AssistantDisplayReasoningDelta`].
    ReasoningDelta { agent: String, delta: String },
    /// Classified visible assistant text delta from the attempt-dispatch
    /// [`crate::engine::DisplayStreamClassifier`]. Carries `attempt_id` for
    /// provisional-row correlation; never durable.
    AssistantDisplayTextDelta {
        agent: String,
        attempt_id: AssistantAttemptId,
        delta: String,
    },
    /// Classified reasoning delta from the attempt-dispatch classifier.
    AssistantDisplayReasoningDelta {
        agent: String,
        attempt_id: AssistantAttemptId,
        delta: String,
    },
    /// Display-only reset: remove the failed attempt's provisional row before
    /// any next-attempt delta. Not durable.
    AssistantDisplayAttemptReset {
        agent: String,
        failed_attempt_id: AssistantAttemptId,
        replacement_attempt_id: AssistantAttemptId,
        reason: String,
    },
    /// Terminal live display complete for one attempt. Owns the durable
    /// assistant payload (also emitted as [`Self::AssistantText`] for history).
    AssistantDisplayComplete {
        agent: String,
        attempt_id: AssistantAttemptId,
        assistant: AssistantTextPayload,
    },
    /// Terminal live display error for a visible primary partial failure/cancel.
    /// Never follows Complete; no performance chip.
    AssistantDisplayError {
        agent: String,
        attempt_id: AssistantAttemptId,
        kind: DisplayErrorKind,
        message: String,
        presentation_text: Option<String>,
    },
    /// Assistant turn's text is complete. Emitted right after the
    /// stream finishes (or, in non-streaming mode, after the response
    /// returns). `text` is the full accumulated body with inline
    /// `<think>` blocks already stripped (the authoritative clean form);
    /// `reasoning` is the finalized (channel + inline) reasoning the chip
    /// renders — non-empty for a think-only turn that has no body. The TUI
    /// uses this as a "finalize the streaming entry" signal. `seq` is the
    /// `session_events` row id assigned to this message (the stable id a
    /// pin references — `pinned-messages`); `None` only when the timeline
    /// write failed. UI/DB-only — never enters the model's context.
    /// Durable history transport only — not live chip input.
    AssistantText {
        agent: String,
        /// Model-context/wire body.
        text: String,
        /// The exact final text shown to users when it differs from `text`
        /// (translation success). `None` for legacy/fallback/identical —
        /// consumers display `presentation_text.unwrap_or(text)`.
        presentation_text: Option<String>,
        reasoning: String,
        seq: Option<i64>,
        /// Optional durable response-performance snapshot. Absent for
        /// empty/think-only/no-visible-body/zero-duration responses.
        response_performance: Option<ResponsePerformance>,
    },
    /// A user/injected message was recorded to the timeline; carries the
    /// assigned `session_events` `seq` so the TUI can stamp it onto the
    /// already-pushed user history row (the stable id a pin references —
    /// `pinned-messages`). UI/DB-only — never enters the model's context.
    ///
    /// `preflight_cleaned` carries the request-preflight rewritten body
    /// (implementation note) when this turn was preflighted, so
    /// the TUI can show the cleaned text + `⚙ preflighted` chip and reveal
    /// the user's original typed input on click (the wire-vs-user split,
    /// GOALS §14). `None` when preflight didn't run / was a no-op / fell back.
    UserMessageRecorded {
        seq: i64,
        client_submission_ids: Vec<uuid::Uuid>,
        preflight_cleaned: Option<String>,
    },
    /// The latest durable user row was retracted by an initial-thinking
    /// cancellation. Every client removes `seq`; only a client that owns one
    /// of `client_submission_ids` restores its local draft, so user text is
    /// never broadcast.
    UserMessageRemoved {
        seq: i64,
        client_submission_ids: Vec<uuid::Uuid>,
    },
    /// One or more daemon-queued user messages were drained and folded into
    /// the next model request. This is the authoritative transcript signal for
    /// queued folds; clients must not infer it from `ThinkingStarted`.
    QueuedUserMessagesFolded {
        text: String,
        display_text: Option<String>,
        tag_expansions: Vec<cockpit_proto::TagExpansionMeta>,
        queue_item_ids: Vec<uuid::Uuid>,
        target: cockpit_proto::QueueTarget,
        seq: Option<i64>,
        preflight_cleaned: Option<String>,
    },
    /// Deferred session persistence failed before inference started. UI-only:
    /// the exact optimistic row stays retryable, but its working span clears.
    SessionPersistFailed {
        client_submission_id: uuid::Uuid,
        error: String,
    },
    /// The session driver died while the worker was serving. UI-only:
    /// the optimistic user row stays visible, but the working span must clear.
    SessionDriverFailed { error: String },
    /// The daemon rejected a user-message dispatch before it reached the
    /// session worker, for example while uploading image attachments. UI-only:
    /// the optimistic user row stays visible, but the working span must clear.
    UserMessageDispatchFailed {
        error: String,
        /// TUI-local identity of the exact optimistic submission rejected by
        /// the client-side transport. This is never serialized onto the
        /// daemon wire; it lets the originating client reconcile identical
        /// or interleaved optimistic rows without relying on their position.
        optimistic_submission_id: uuid::Uuid,
    },
    /// The daemon deterministically rejected a message before accepting it.
    /// The dispatcher retains the complete payload under this exact id and
    /// retries only after a state-change signal or a later same-session send.
    UserMessageDispatchRetained {
        error: String,
        optimistic_submission_id: uuid::Uuid,
    },
    /// A client-owned exact submission is about to be retried after its
    /// session is reattached. UI-only and never serialized: the originating
    /// TUI recreates the optimistic row if an attach snapshot replaced its
    /// in-memory transcript before the payload became durable.
    UserMessageDispatchRestored {
        optimistic_submission_id: uuid::Uuid,
        text: String,
        display_text: Option<String>,
        tag_expansions: Vec<cockpit_proto::TagExpansionMeta>,
    },
    /// A tool call started. `args` are post-repair.
    ToolStart {
        agent: String,
        call_id: String,
        tool: String,
        args: serde_json::Value,
    },
    /// UI-only progress tick for a running tool row. Generic by design:
    /// producers send numeric progress and the client owns formatting.
    ToolProgress(ToolProgress),
    /// Tool finished. `output` is what the model will see next turn.
    ToolEnd {
        agent: String,
        call_id: String,
        tool: String,
        output: String,
        truncated: bool,
        /// `session_events.seq` for the durable tool-call timeline row when
        /// the call was persisted. `None` for synthetic/display-only tool
        /// events or when persistence failed.
        seq: Option<i64>,
        /// Post-result hint text (`engine::bash_hints`, the user-side
        /// `data.hint.text`) when a rule fired on this `bash` call; `None`
        /// otherwise. UI-only — the model's copy carries the separate wire
        /// `--- hint(…)` line (wire-vs-user split, GOALS §14).
        hint: Option<String>,
    },
    /// A resource-managed tool call is waiting for scheduler permits.
    ResourceWait {
        agent: String,
        request_id: uuid::Uuid,
        display_id: String,
        resources: std::collections::HashMap<String, u32>,
        queue_position: Option<usize>,
        command_label: Option<String>,
    },
    /// A resource-managed tool call acquired scheduler permits.
    ResourceStart {
        agent: String,
        request_id: uuid::Uuid,
        display_id: String,
        resources: std::collections::HashMap<String, u32>,
        wait_ms: u64,
        command_label: Option<String>,
    },
    /// A resource-managed tool call released scheduler permits.
    ResourceClear {
        agent: String,
        request_id: uuid::Uuid,
        display_id: String,
        resources: std::collections::HashMap<String, u32>,
        command_label: Option<String>,
    },
    /// A tool errored. The model will see this string as the tool
    /// result; the TUI renders it red. `kind` tells the TUI whether the
    /// model built the call badly (bold red) or the tool failed for
    /// another reason (red).
    ToolError {
        agent: String,
        call_id: String,
        tool: String,
        error: String,
        kind: cockpit_proto::ToolFailKind,
        /// `session_events.seq` for the durable tool-call timeline row when
        /// the call was persisted. `None` for synthetic/display-only tool
        /// events or when persistence failed.
        seq: Option<i64>,
    },
    /// An inference call failed terminally — a TTFT / idle timeout, a
    /// connection error, or a non-retryable HTTP response
    /// (implementation note). The TUI
    /// renders this as a RED inline error in the turn (same treatment as a
    /// `ToolError`): the spinner stops and the user sees provider/model + the
    /// reason. UI-only — never enters the model's context (the wire-vs-user
    /// split, GOALS §14; the recorded failure event is the data-side surface).
    InferenceFailed {
        agent: String,
        provider: String,
        model: String,
        /// Typed error class whose display text matches the legacy flat
        /// string form.
        error_class: cockpit_proto::InferenceErrorClass,
        /// Human-readable reason shown after provider/model (empty for a pure
        /// timeout, whose class already says everything).
        detail: String,
        auth_failure: Option<cockpit_proto::AuthFailureKind>,
    },
    /// A concrete provider/model inference completed successfully. UI-only;
    /// used to clear last-known auth failure state for this exact model.
    InferenceSucceeded { provider: String, model: String },
    /// The primary model failed a qualifying inference on this turn and the
    /// turn was answered by the configured backup model
    /// (implementation note). The TUI renders a
    /// DISPLAY-ONLY YELLOW banner naming what happened. This is the
    /// wire-vs-user split (GOALS §14): the banner is user-facing only and
    /// NEVER enters model context — the model sees only its own (backup) turn,
    /// with no annotation about the fallback.
    BackupUsed {
        agent: String,
        /// The primary model id that failed (e.g. `qwen3.6-plus-free`).
        primary_model: String,
        /// The failure class that engaged the backup, rendered
        /// human-readable by the TUI.
        error_class: cockpit_proto::InferenceErrorClass,
        /// The backup model id that answered (e.g. `claude-sonnet-4-6`).
        backup_model: String,
    },
    /// `task` invoked a subagent; primary handoff (GOALS §3b) starts.
    /// Driver handles the actual stack push.
    SubagentSpawned {
        parent: String,
        child: String,
        task_call_id: String,
        label: String,
        prompt: String,
        requested_cwd: Option<String>,
        resolved_cwd: Option<String>,
        model_trusted: bool,
        routing: serde_json::Value,
    },
    /// A later amend to a subagent spawn once the child model has been loaded
    /// and its resolved routing is knowable. Lifecycle consumers keep using
    /// `SubagentSpawned` as the pairing anchor.
    SubagentRouting {
        task_call_id: String,
        label: String,
        child: String,
        provider: String,
        model: String,
        model_trusted: bool,
        routing: serde_json::Value,
    },
    /// A subagent's final text. Delivered back to the parent as the
    /// tool result for its outstanding `task` call.
    SubagentReport {
        agent: String,
        task_call_id: String,
        label: String,
        report: String,
        failed: bool,
        model_trusted: bool,
        routing: serde_json::Value,
    },
    /// A noninteractive child turn event forwarded through its parent
    /// session stream with delegation lineage.
    NestedTurn {
        task_call_id: String,
        label: String,
        parent_task_call_id: Option<String>,
        inner: Box<TurnEvent>,
    },
    /// Provider-reported token usage for the round-trip that just
    /// completed. Absent when the provider didn't include a usage
    /// chunk in the response stream.
    Usage { agent: String, usage: TokenUsage },
    /// A non-blocking system notice for the transcript (warn chip). Used
    /// by the prompt-injection guard (GOALS §4i) to surface a flagged-but-
    /// below-threshold prompt and the fail-open "scan could not run"
    /// case. Rendered as a muted/yellow plain line; never enters the
    /// model's context (it's UI-only — the user message itself proceeds
    /// unchanged).
    Notice { text: String },

    /// Required external binary capabilities are missing for one or more
    /// granted tools. UI-only: the TUI renders this as persistent startup
    /// chrome with a copyable install command when the remedy has one. Never
    /// enters the model context.
    CommandCapabilityUnavailable {
        text: String,
        fix_command: Option<String>,
    },

    /// The utility-model skill auto-selector injected a skill's body onto
    /// this turn's wire message (`auto-injected-skill-transcript-
    /// visibility.md`). UI-only: the TUI renders a distinct
    /// `/{name} · injected by agent` row ahead of the user's message so the
    /// user can see which skills were auto-loaded — and that they were
    /// auto-injected (not user-typed, not the agent's `skill` tool call).
    /// Wire-vs-user split (GOALS §14): this is the user-facing half; the
    /// model still receives the body folded into the user message. One event
    /// per injected skill, emitted in injection/relevance order. `reason` is
    /// the short justification (implementation note) —
    /// the utility model's clause when given, else a keyword-overlap fallback
    /// — rendered as a muted sub-line; `None` → plain row. Display-only and
    /// off-wire: the reason never enters the model's context.
    SkillAutoInjected {
        name: String,
        reason: Option<String>,
    },

    /// The driver finished a main-loop select iteration and is waiting
    /// for the next user message. Emitted by the driver (not by [`turn`])
    /// as the falling edge that stops the TUI's span-long working
    /// indicator. No agent name — it's a whole-stack signal, not a
    /// per-agent one. This is not a stack-frame change: a child can still
    /// be on the stack (recovered attach, control at idle). Input routing
    /// follows [`Self::ForegroundInputTarget`].
    AgentIdle {
        #[allow(dead_code)]
        turn_id: Option<String>,
        reason: IdleReason,
    },

    /// A pending goal-completion verification round progressed. UI-only:
    /// the TUI renders this instead of a success toast while skeptic checks
    /// are still in flight.
    GoalSupervisionProgress { done: usize, total: usize },

    /// The primary (root-frame) agent was swapped in place (`/plan` →
    /// `Plan`, `/build` → `Build`, `plan.md §4.6.d`). Emitted by the driver
    /// so the client chrome's active-agent slot tracks the new primary.
    PrimarySwapped { name: String },

    /// A `question` tool raised an interrupt (GOALS §3b): the agent is
    /// blocked until the user answers. The TUI opens the answering
    /// dialog from this; the answer round-trips back to the daemon as
    /// `ResolveInterrupt`. Carries the batch of questions to render.
    InterruptRaised {
        session_id: uuid::Uuid,
        interrupt_id: uuid::Uuid,
        /// Interrupt-level context (from `raise_interrupt(description, …)`),
        /// rendered as a muted context header above the question prompt.
        /// Empty when the agent supplied none.
        description: String,
        questions: cockpit_proto::InterruptQuestionSet,
        pending_count: usize,
        reason: cockpit_proto::InterruptRaiseReason,
    },
    InterruptQueueChanged {
        session_id: uuid::Uuid,
        active_interrupt_id: Option<uuid::Uuid>,
        pending_count: usize,
    },
    InterruptResolved {
        session_id: uuid::Uuid,
        interrupt_id: uuid::Uuid,
    },

    /// An async job (loop / timer / background, GOALS §22) started. UI
    /// only — drives the transient schedule strip. `kind` is `loop` /
    /// `timer` / `background`. `session_id` lets a multi-session client
    /// scope per-session views (`/ps`, `/stop`) without reaching across
    /// sessions.
    ScheduleStarted {
        session_id: uuid::Uuid,
        job_id: String,
        label: String,
        kind: String,
    },
    /// A background job produced an output line (it's in the ring buffer
    /// now). UI-only progress tick so the strip can show liveness; the
    /// output itself reaches the model only via `background.tail` or the
    /// budget-capped completion.
    ScheduleProgress { job_id: String },
    /// A note from an ephemeral-fork loop iteration. Shown live in the
    /// UI; enters main context only at loop termination (bundled with the
    /// terminal result) — token economy (§22).
    ScheduleNote { job_id: String, text: String },
    /// An async job reached a terminal state. UI-only marker; the
    /// model-facing result is injected separately as a late-arriving turn
    /// by the driver. `failed` drives the red treatment + needs_attention
    /// wording.
    ScheduleCompleted {
        job_id: String,
        label: String,
        kind: String,
        failed: bool,
    },

    /// How many wire tokens `/prune` would drop from the **foreground**
    /// agent's context right now (GOALS §1a / §10). Recomputed by the
    /// driver from the same `dedup_plan` `/prune` executes, so the
    /// status-line `ctx X% → Y% prunable` figure equals what `/prune`
    /// then removes. Emitted after every turn settles and after a prune.
    /// `cache_cold` carries the cache-cold predicate's verdict so the
    /// `/prune` confirm copy reports hot-vs-cold without guessing.
    ContextProjection {
        prunable_tokens: u64,
        cache_cold: bool,
    },

    /// A `/prune` (manual or auto) completed on the foreground agent.
    /// `auto` distinguishes the cache-aware auto-fire from a user
    /// invocation. `bodies` is how many snapshot bodies were elided this
    /// prune; `tokens_saved` is the wire-token drop. `elided` is the
    /// **current** full set of `original_event_id`s whose tool-result body
    /// is now an elision marker in the wire history (cumulative across
    /// prunes, not just this one). The TUI dims the matching scrollback
    /// tool-result bodies by their `call_id`; full text stays visible
    /// (GOALS §14 wire-vs-user split). UI marker for the transcript.
    Pruned {
        auto: bool,
        bodies: usize,
        tokens_saved: u64,
        elided: Vec<String>,
        /// Machine-readable auto-prune trigger reason. Present for automatic
        /// prunes and absent for manual `/prune`.
        trigger_reason: Option<String>,
        /// True when this prune broke a warm prompt cache — the
        /// ctx%-threshold auto-prune branch firing on a warm cache
        /// (implementation note). The client surfaces the
        /// shared cache-break warning. Always false for cache-cold (free)
        /// prunes and manual `/prune`.
        cache_break: bool,
    },

    /// `/compact` assembled a fresh-thread handoff. Carries the
    /// review-ready handoff text (brief + deterministic appendix +
    /// context tags) for the TUI to drop into the composer, plus the
    /// new session id the daemon created and the context-tag count. The
    /// old session stays recoverable in SQLite.
    CompactReady {
        new_session_id: uuid::Uuid,
        handoff: String,
        brief: String,
        source: String,
        trigger_ctx_pct: Option<f64>,
        tokens_before: u64,
        tokens_after: u64,
        turns_summarized: usize,
        tail_kept: usize,
        tail_trimmed: usize,
        seed_tool_count: usize,
        seed_tool_tokens: u64,
    },

    /// Filesystem sandboxing was toggled for the session (`/sandbox`,
    /// sandboxing part 2). UI-only: the TUI surfaces the resulting state
    /// as a toast. Emitted by the daemon's `SetSandbox` handler.
    SandboxState {
        mode: cockpit_proto::SandboxMode,
        container_network_enabled: bool,
        container_availability: cockpit_proto::ContainerAvailability,
        persisted_intent: Option<cockpit_proto::SandboxMode>,
    },

    /// Sandbox-escalation availability changed for the live session. UI-only:
    /// the TUI mirrors the daemon-owned flag and surfaces the result as a
    /// toast/chrome state. Emitted by the daemon's `SetSandboxEscalation`
    /// handler and on attach.
    SandboxEscalationState { enabled: bool },

    /// The shell sandbox cannot initialize (a confined `bash` hit the
    /// `SandboxGate::Refuse` path — Linux userns case; `implementation notes`
    /// §6.5). Emitted by [`turn`] on detection, carrying the diagnosed
    /// `remedy` plus an optional exact host fix command. The worker fires the
    /// broadcast once per session (de-dupe); the TUI raises a persistent
    /// below-input notice. **Never** enters the model's context — purely
    /// client-side chrome state, deterministic and model-independent.
    SandboxUnavailable {
        remedy: String,
        fix_command: Option<String>,
    },

    /// Redaction sources were toggled for the session (`/toggle-redaction`).
    /// UI-only: the TUI surfaces the resulting state as a toast. Emitted by
    /// the daemon's `SetRedaction` handler. Session-only — not persisted.
    RedactionState {
        scan_environment: bool,
        scan_dotenv: bool,
        scan_ssh_keys: bool,
    },

    /// Request preflight was set/toggled for the session (`/preflight`,
    /// implementation note). UI-only: the TUI surfaces the
    /// resulting state as a toast + updates the live `/preflight` description
    /// mirror. Emitted by the DRIVER (which owns the session-only override).
    /// Session-only — not persisted.
    PreflightState { enabled: bool },

    /// Long prompt-cache retention intent was set/toggled for the session.
    /// UI-only: the TUI mirrors this for `/longcache` status. Request params
    /// still re-resolve against active-model capability and may omit the key.
    LongcacheState { enabled: bool, supported: bool },

    /// Command-approval mode was set for the session. UI-only and
    /// session-only; never enters model context.
    ApprovalModeState { mode: cockpit_proto::ApprovalMode },

    /// Delegation recursion override was set for the session. UI-only and
    /// session-only; never enters model context.
    DelegationRecursionState { enabled: bool, default_depth: u32 },

    /// The session's model-comparison tandem (shadow) set changed
    /// (`/model-comparison`, implementation note).
    /// UI-only: the TUI surfaces the resulting set + token-burn warning as a
    /// notice. `models` are the `provider/model` labels now active (empty =
    /// feature off). Session-only — not persisted; never enters model context.
    TandemState {
        models: Vec<String>,
        warning: Option<String>,
    },

    /// The session's gitignore read-allowlist changed or is being hydrated on
    /// attach (implementation note). UI-only: the
    /// TUI overwrites its tracked session set so the `@`-tag popup re-includes
    /// session-approved gitignored entries. Carries the full set (replace).
    /// Never enters the model's context.
    GitignoreAllow { allow: Vec<String> },

    /// Caffeination (`/caffeinate`) state changed — daemon-global,
    /// broadcast to every client (incl. until-idle auto-off). Drives the
    /// `☕` chrome glyph on all clients + a toast on the originator.
    /// `message` is `Some` only for the client that issued the request.
    CaffeinateState {
        active: bool,
        lid_close_guaranteed: bool,
        message: Option<String>,
    },

    /// Remote relay connector state changed — daemon-global and UI-only.
    #[cfg(feature = "remote")]
    ConnectorStatus {
        enabled: bool,
        status: String,
        relay_url: Option<String>,
        relay_id: Option<String>,
        relay_region: Option<String>,
        last_error: Option<String>,
    },

    /// The daemon began (or escalated) a graceful shutdown
    /// (`daemon-graceful-drain-shutdown.md`). Daemon-global. The TUI shows
    /// the drain notice and refuses new input; `forced` distinguishes the
    /// initial drain (in-flight work finishing) from the force-deadline
    /// case (work was aborted — a truncated turn isn't a clean finish).
    DaemonDraining { forced: bool },

    /// A `read` is blocked waiting on a lock another agent/session
    /// holds (implementation note). A transient,
    /// UI-only start/clear pair: `waiting == true` when the wait begins,
    /// `false` when it ends (lock acquired or wait cancelled). The TUI
    /// shows a transient indicator naming the contended `path` + the
    /// `holder_agent`, alongside the fixed chrome like the `☕` glyph —
    /// never displacing a fixed slot. Never enters the model's context (the
    /// blocked-then-acquired `read` returns its normal read output).
    WaitingForLock {
        path: String,
        holder_agent: String,
        waiting: bool,
    },

    /// Durable agent-tree invalidation. The TUI refreshes the session-setup
    /// snapshot and the tree overlay; it must not advance the transcript
    /// replay cursor.
    AgentTreeChanged { session_id: uuid::Uuid },

    /// Request preflight (implementation note) is actually running
    /// for the just-submitted message — emitted by the driver at submit time,
    /// before the injection-guard / preflight `tokio::join!`, ONLY when
    /// preflight is enabled AND will run (not a `should_skip` no-op). The TUI
    /// marks the optimistically-shown user row so its top-border slot carries
    /// the animated `Preflight…` indicator (reusing the busy/Thinking spinner)
    /// until the resolved-message event reconciles it (replace-on-`Rewritten`,
    /// clear otherwise). UI-only — the optimistic row is a display concern; the
    /// model-facing text is still only the resolved body (the wire-vs-user
    /// split, GOALS §14). A disabled/skipped pass emits nothing — the row shows
    /// instantly with no indicator.
    PreflightStarted {
        client_submission_ids: Vec<uuid::Uuid>,
    },

    /// Exact accepted submissions that reached a durable terminal outcome
    /// without being recorded in the transcript.
    UserMessagesTerminated {
        client_submission_ids: Vec<uuid::Uuid>,
        disposition: cockpit_proto::UserMessageTerminalDisposition,
    },

    /// The just-submitted message was retracted before it was sent — the
    /// prompt-injection guard blocked it (`apply_injection_outcome` returned
    /// false) and the message must not linger as if sent. Emitted by the driver
    /// in place of the resolved-message event; the TUI removes the
    /// optimistically-shown user row (and any `Preflight…` indicator on it) so
    /// the injection-block / override UX stands alone. UI-only.
    UserMessageRetracted {
        client_submission_ids: Vec<uuid::Uuid>,
    },
}
