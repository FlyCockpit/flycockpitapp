use super::*;

/// Events the agent emits during a turn. The driver forwards these to
/// the TUI for display; the persistence layer can subscribe to the
/// same channel.
#[derive(Debug, Clone)]
pub enum TurnEvent {
    /// Authoritative daemon-owned queue snapshot for pending user messages.
    /// The TUI renders this mirror and never locally removes queue entries
    /// unless the daemon confirms removal.
    QueueUpdated {
        queue: Vec<crate::engine::message::QueuedUserMessage>,
    },
    /// Foreground input target snapshot. The daemon uses it to stamp queued
    /// user messages and forwards it to clients so queue editability is visible.
    ForegroundInputTarget {
        target: crate::engine::message::QueueTarget,
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
    AssistantTextDelta { agent: String, delta: String },
    /// One streaming chunk of the model's *reasoning* (thinking-mode
    /// models only). The TUI hides this by default — the
    /// "Thinking…" placeholder is the visible affordance — but
    /// captures it so the user can expand a thinking block later to
    /// inspect the chain of thought.
    ReasoningDelta { agent: String, delta: String },
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
    AssistantText {
        agent: String,
        text: String,
        reasoning: String,
        seq: Option<i64>,
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
        preflight_cleaned: Option<String>,
    },
    /// One or more daemon-queued user messages were drained and folded into
    /// the next model request. This is the authoritative transcript signal for
    /// queued folds; clients must not infer it from `ThinkingStarted`.
    QueuedUserMessagesFolded {
        text: String,
        queue_item_ids: Vec<uuid::Uuid>,
        target: crate::engine::message::QueueTarget,
        seq: Option<i64>,
        preflight_cleaned: Option<String>,
    },
    /// Deferred session persistence failed before inference started. UI-only:
    /// the optimistic user row stays visible, but the working span must clear.
    SessionPersistFailed { error: String },
    /// The session driver died while the worker was serving. UI-only:
    /// the optimistic user row stays visible, but the working span must clear.
    SessionDriverFailed { error: String },
    /// The daemon rejected a user-message dispatch before it reached the
    /// session worker, for example while uploading image attachments. UI-only:
    /// the optimistic user row stays visible, but the working span must clear.
    UserMessageDispatchFailed { error: String },
    /// A tool call started. `args` are post-repair.
    ToolStart {
        agent: String,
        call_id: String,
        tool: String,
        args: Value,
    },
    /// Tool finished. `output` is what the model will see next turn.
    ToolEnd {
        agent: String,
        call_id: String,
        tool: String,
        output: String,
        truncated: bool,
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
        kind: crate::engine::tool::ToolFailKind,
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
        /// Stable error class (`timeout_ttft` / `timeout_idle` / `network` /
        /// `http_<status>`).
        error_class: String,
        /// Human-readable reason shown after provider/model (empty for a pure
        /// timeout, whose class already says everything).
        detail: String,
    },
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
        /// The failure class that engaged the backup (`timeout_ttft` /
        /// `timeout_idle` / `network` / `http_<status>`), rendered
        /// human-readable.
        error_class: String,
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
        trusted_only: bool,
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
        trusted_only: bool,
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
    Usage {
        agent: String,
        usage: crate::tokens::TokenUsage,
    },
    /// A non-blocking system notice for the transcript (warn chip). Used
    /// by the prompt-injection guard (GOALS §4i) to surface a flagged-but-
    /// below-threshold prompt and the fail-open "scan could not run"
    /// case. Rendered as a muted/yellow plain line; never enters the
    /// model's context (it's UI-only — the user message itself proceeds
    /// unchanged).
    Notice { text: String },

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

    /// The driver loop unwound to the root and drained its queue: the
    /// agent is idle, waiting for the next user message. Emitted by the
    /// driver (not by [`turn`]) as the falling edge that stops the
    /// TUI's span-long working indicator. No agent name — it's a
    /// whole-stack signal, not a per-agent one.
    AgentIdle {
        #[allow(dead_code)]
        turn_id: Option<String>,
    },

    /// The primary (root-frame) agent was swapped in place (`/plan` →
    /// `Plan`, `/build` → `Build`, `plan.md §4.6.d`). Emitted by the driver
    /// so the client chrome's active-agent slot tracks the new primary.
    PrimarySwapped { name: String },
    /// The active `llm_mode` was switched live (`/llm-mode`,
    /// implementation note). The client tracks `mode` so
    /// its `/llm-mode` toggle + cache-break warning resolve against the
    /// authoritative current value.
    LlmModeChanged {
        mode: crate::config::extended::LlmMode,
    },

    /// A `question` tool raised an interrupt (GOALS §3b): the agent is
    /// blocked until the user answers. The TUI opens the answering
    /// dialog from this; the answer round-trips back to the daemon as
    /// `ResolveInterrupt`. Carries the batch of questions to render.
    InterruptRaised {
        interrupt_id: uuid::Uuid,
        /// Interrupt-level context (from `raise_interrupt(description, …)`),
        /// rendered as a muted context header above the question prompt.
        /// Empty when the agent supplied none.
        description: String,
        questions: crate::daemon::proto::InterruptQuestionSet,
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
    /// seed-tool plan) for the TUI to drop into the composer, plus the
    /// new session id the daemon created and the seed-tool count. The
    /// old session stays recoverable in SQLite.
    CompactReady {
        new_session_id: uuid::Uuid,
        handoff: String,
        brief: String,
        seed_tool_count: usize,
        seed_tool_tokens: u64,
    },

    /// Filesystem sandboxing was toggled for the session (`/sandbox`,
    /// sandboxing part 2). UI-only: the TUI surfaces the resulting state
    /// as a toast. Emitted by the daemon's `SetSandbox` handler.
    SandboxState {
        mode: crate::tools::sandbox_mode::SandboxMode,
        container_network_enabled: bool,
        container_availability: crate::container::ContainerAvailability,
    },

    /// The shell sandbox cannot initialize (a confined `bash` hit the
    /// `SandboxGate::Refuse` path — Linux userns case; `implementation notes`
    /// §6.5). Emitted by [`turn`] on detection, carrying the diagnosed
    /// `remedy` (the `reason`, incl. the `sudo sysctl …=0` command when
    /// diagnosed). The worker fires the broadcast once per session (de-dupe);
    /// the TUI raises a persistent below-input notice. **Never** enters the
    /// model's context — purely client-side chrome state, deterministic and
    /// model-independent.
    SandboxUnavailable { remedy: String },

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

    /// Trusted-only inference mode was set/toggled for the session.
    /// UI-only: the TUI surfaces the resulting state as a toast and updates
    /// the live `/trusted-only` description mirror.
    TrustedOnlyState { enabled: bool },

    /// Command-approval mode was set for the session. UI-only and
    /// session-only; never enters model context.
    ApprovalModeState {
        mode: crate::config::extended::ApprovalMode,
    },

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

    /// A `readlock` is blocked waiting on a lock another agent/session
    /// holds (implementation note). A transient,
    /// UI-only start/clear pair: `waiting == true` when the wait begins,
    /// `false` when it ends (lock acquired or wait cancelled). The TUI
    /// shows a transient indicator naming the contended `path` + the
    /// `holder_agent`, alongside the fixed chrome like the `☕` glyph —
    /// never displacing a fixed slot. Never enters the model's context (the
    /// blocked-then-acquired `readlock` returns its normal read output).
    WaitingForLock {
        path: String,
        holder_agent: String,
        waiting: bool,
    },

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
    PreflightStarted,

    /// The just-submitted message was retracted before it was sent — the
    /// prompt-injection guard blocked it (`apply_injection_outcome` returned
    /// false) and the message must not linger as if sent. Emitted by the driver
    /// in place of the resolved-message event; the TUI removes the
    /// optimistically-shown user row (and any `Preflight…` indicator on it) so
    /// the injection-block / override UX stands alone. UI-only.
    UserMessageRetracted,
}
