use super::*;
use crate::engine::TurnEvent;

// ---- Events ----------------------------------------------------------------

/// Unsolicited daemon → client notifications. The event stream is
/// fire-and-forget — clients do not ack individual events. A client
/// that misses events (e.g. dropped connection) re-`Attach`es and
/// receives a fresh history snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", content = "data")]
pub enum Event {
    EnvDriftWarning {
        baseline: crate::env_snapshot::EnvSnapshotMeta,
        candidate: crate::env_snapshot::EnvSnapshotMeta,
        diff: crate::env_snapshot::EnvDiffSummary,
        policy: crate::env_snapshot::EnvDriftPolicy,
    },

    /// Authoritative pending user-message queue snapshot for one session.
    QueueUpdated {
        session_id: Uuid,
        queue: Vec<QueueItem>,
    },

    /// Current queue-edit foreground target for one session. Clients seed this
    /// from `Attached::foreground_target`; this event supplies live changes.
    ForegroundInputTarget {
        session_id: Uuid,
        target: QueueTarget,
    },

    /// Model inference started. TUI shows `Thinking…` until the first
    /// `AssistantTextDelta` arrives.
    ThinkingStarted {
        session_id: Uuid,
        agent: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        turn_id: Option<String>,
    },

    /// An inference call hit a network/transient failure and is being
    /// auto-retried. TUI shows a distinct, persistent `reconnecting —
    /// <provider>/<model> unreachable at <url> (attempt N)` status (daemon
    /// owns inference state — this is forwarded, not computed client-side);
    /// the headless `run` path logs a recurring attempt-numbered line.
    /// `attempt` is the 1-based retry number; `provider`/`model`/`url` name
    /// the unreachable target.
    Reconnecting {
        session_id: Uuid,
        agent: String,
        attempt: u32,
        provider: String,
        model: String,
        url: String,
    },

    /// A configured stream wait threshold elapsed. Without a backup model the
    /// daemon keeps waiting; with a backup model this warning precedes the
    /// timeout failure that engages fallback.
    InferenceWarning {
        session_id: Uuid,
        agent: String,
        provider: String,
        model: String,
        phase: String,
        waited_secs: u64,
    },

    /// One streaming chunk of assistant text.
    AssistantTextDelta {
        session_id: Uuid,
        agent: String,
        delta: String,
    },

    /// One streaming chunk of model reasoning (thinking-mode models).
    /// TUI hides this by default but persists it so the user can
    /// expand the chain of thought later.
    ReasoningDelta {
        session_id: Uuid,
        agent: String,
        delta: String,
    },

    /// Assistant turn complete — `text` is the full accumulated body with
    /// inline `<think>` blocks already stripped. `reasoning` is the
    /// finalized (channel + inline) reasoning the thinking chip renders;
    /// non-empty for a think-only turn with no body, so the chip survives
    /// across the wire. `seq` is the `session_events` row id of this message
    /// (the stable id a pin references — `pinned-messages`); `None` when the
    /// timeline write failed. UI/DB-only — never enters the model's context.
    AssistantText {
        session_id: Uuid,
        agent: String,
        text: String,
        #[serde(default)]
        reasoning: String,
        #[serde(default)]
        seq: Option<i64>,
    },

    /// A user/injected message was recorded to the timeline. Carries the
    /// assigned `session_events` `seq` so the client can stamp it onto the
    /// already-pushed user history row (the stable id a pin references —
    /// `pinned-messages`). UI/DB-only — never enters the model's context.
    ///
    /// `preflight_cleaned` carries the request-preflight rewritten body
    /// (implementation note) when this turn was preflighted, so the
    /// client can show the cleaned text + `⚙ preflighted` chip and reveal the
    /// original typed input on click. `None` when preflight didn't run.
    UserMessageRecorded {
        session_id: Uuid,
        seq: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preflight_cleaned: Option<String>,
    },
    /// One or more daemon-queued user messages were drained and folded into a
    /// model request. Carries stable queue ids plus the persisted timeline seq
    /// when the session log write succeeded.
    QueuedUserMessagesFolded {
        session_id: Uuid,
        text: String,
        queue_item_ids: Vec<Uuid>,
        target: QueueTarget,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seq: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preflight_cleaned: Option<String>,
    },
    /// Deferred session persistence failed before inference started. The
    /// server dropped the message; clients should clear optimistic busy state
    /// and show the full error chain.
    SessionPersistFailed {
        session_id: Uuid,
        error: String,
    },

    /// The session driver's task ended unexpectedly while the worker was
    /// still serving. Terminal: clients should clear optimistic busy state
    /// and show the error because the worker will end this session.
    SessionDriverFailed {
        session_id: Uuid,
        error: String,
    },

    /// Request preflight is actually running for the just-submitted message
    /// (implementation note). Emitted at submit time, before the
    /// injection/preflight `tokio::join!`, only when preflight is enabled AND
    /// will run (not a `should_skip` no-op). The client marks the optimistic
    /// user row so its border slot shows the animated `Preflight…` indicator
    /// until the message resolves. UI-only — never enters the model's context.
    PreflightStarted {
        session_id: Uuid,
    },

    /// The just-submitted message was retracted before send because the
    /// prompt-injection guard blocked it (implementation note edge
    /// case). The client removes the optimistically-shown user row so the
    /// block/override UX stands alone. UI-only.
    UserMessageRetracted {
        session_id: Uuid,
    },

    /// A non-blocking system notice (warn chip) for the transcript.
    /// Used by the prompt-injection guard (GOALS §4i). UI-only: never
    /// enters the model's context.
    Notice {
        session_id: Uuid,
        text: String,
    },

    /// A daemon-global LSP warning/status notice. Used for language-server
    /// install failures that may be triggered from advisory write/edit
    /// diagnostics rather than a foreground settings request.
    LspNotice {
        text: String,
    },

    /// The utility-model skill auto-selector injected a skill onto this
    /// turn's wire message (`auto-injected-skill-transcript-
    /// visibility.md`). The client renders a distinct `/{name} · injected
    /// by agent` row ahead of the user's message. UI-only: never enters the
    /// model's context (the body is folded into the user message on the
    /// wire — wire-vs-user split, GOALS §14). One per injected skill.
    /// `reason` is the optional muted sub-line justification
    /// (implementation note); display-only and off-wire.
    SkillAutoInjected {
        session_id: Uuid,
        name: String,
        reason: Option<String>,
    },

    /// Tool dispatch started; args are post-repair.
    ToolStart {
        session_id: Uuid,
        agent: String,
        call_id: String,
        tool: String,
        args: Value,
    },

    /// Tool finished cleanly. `output` is what the model sees on its
    /// next inference call.
    ToolEnd {
        session_id: Uuid,
        agent: String,
        call_id: String,
        tool: String,
        output: String,
        truncated: bool,
        /// Post-result hint text (`engine::bash_hints`, the user-side
        /// `data.hint.text`) when a rule fired on this `bash` call; `None`
        /// otherwise. UI-only (wire-vs-user split, GOALS §14). `#[serde(default)]`
        /// keeps the NDJSON wire backward-compatible with older peers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hint: Option<String>,
    },

    /// A resource-managed tool call is waiting for scheduler permits. UI-only:
    /// never enters model context.
    ResourceWait {
        session_id: Uuid,
        agent: String,
        request_id: Uuid,
        display_id: String,
        resources: HashMap<String, u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        queue_position: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command_label: Option<String>,
    },

    /// A resource-managed tool call acquired permits. UI-only.
    ResourceStart {
        session_id: Uuid,
        agent: String,
        request_id: Uuid,
        display_id: String,
        resources: HashMap<String, u32>,
        wait_ms: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command_label: Option<String>,
    },

    /// A resource-managed tool call released permits. UI-only.
    ResourceClear {
        session_id: Uuid,
        agent: String,
        request_id: Uuid,
        display_id: String,
        resources: HashMap<String, u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command_label: Option<String>,
    },

    /// Tool errored. The model sees this string as the tool result.
    /// `kind` distinguishes a bad call (the model's fault) from a bad
    /// outcome (the tool's fault) for the TUI's color treatment.
    ToolError {
        session_id: Uuid,
        agent: String,
        call_id: String,
        tool: String,
        error: String,
        kind: crate::engine::tool::ToolFailKind,
    },

    /// An inference call failed terminally (TTFT / idle timeout, connection
    /// error, or non-retryable HTTP —
    /// implementation note). The TUI
    /// renders a RED inline error (same treatment as `ToolError`): the spinner
    /// stops and the user sees provider/model + the reason. UI-only: never
    /// enters the model's context (the recorded failure event is the data side).
    InferenceFailed {
        session_id: Uuid,
        agent: String,
        provider: String,
        model: String,
        error_class: String,
        detail: String,
    },

    /// The primary model failed a qualifying inference and the turn was
    /// answered by the configured backup model
    /// (implementation note). The TUI renders a
    /// DISPLAY-ONLY YELLOW banner. Wire-vs-user split (GOALS §14): never enters
    /// model context.
    BackupUsed {
        session_id: Uuid,
        agent: String,
        primary_model: String,
        error_class: String,
        backup_model: String,
    },

    /// `task` invoked an interactive subagent; primary handoff begins.
    SubagentSpawned {
        session_id: Uuid,
        parent: String,
        child: String,
        task_call_id: String,
        label: String,
        prompt: String,
        requested_cwd: Option<String>,
        resolved_cwd: Option<String>,
        #[serde(default)]
        trusted_only: bool,
        #[serde(default)]
        model_trusted: bool,
        #[serde(default)]
        routing: serde_json::Value,
    },

    /// A subagent finished and emitted its report back to the parent.
    SubagentReport {
        session_id: Uuid,
        agent: String,
        task_call_id: String,
        label: String,
        report: String,
        #[serde(default)]
        trusted_only: bool,
        #[serde(default)]
        model_trusted: bool,
        #[serde(default)]
        routing: serde_json::Value,
    },

    /// A noninteractive child event forwarded through the parent session
    /// stream with enough lineage for clients to build a delegation tree.
    NestedTurn {
        session_id: Uuid,
        task_call_id: String,
        label: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_task_call_id: Option<String>,
        inner: Box<Event>,
    },

    /// Provider-reported token usage for the round-trip that just
    /// finished. Emitted once per `model.complete` call; absent when
    /// the provider didn't include a usage chunk.
    Usage {
        session_id: Uuid,
        agent: String,
        input_tokens: u64,
        output_tokens: u64,
        cached_input_tokens: u64,
        /// Input tokens written into the prompt cache on a miss (Anthropic
        /// `cache_creation`). Carried so the TUI's cache hit-rate display
        /// (prompt `prompt-caching-strategy.md`) sees the full per-turn
        /// cache picture.
        #[serde(default)]
        cache_creation_input_tokens: u64,
    },

    /// A background builder paused with a question (GOALS §3b). Wire
    /// shape lands now; the dispatch logic that pauses turns ships
    /// in a later milestone.
    InterruptRaised {
        session_id: Uuid,
        interrupt_id: Uuid,
        agent: String,
        description: String,
        /// Legacy single-question payload (the `schedule` needs-attention
        /// nudge raises with neither field set). Kept for wire
        /// back-compat; new question-tool interrupts use `questions`.
        #[serde(default)]
        question: Option<InterruptQuestion>,
        /// Multi-question batch (GOALS §3b). Present when an agent's
        /// `question` tool raised the interrupt; drives the answering
        /// dialog. Mutually exclusive with `question` in practice.
        #[serde(default)]
        questions: Option<InterruptQuestionSet>,
        #[serde(default)]
        pending_count: usize,
    },

    InterruptQueueChanged {
        session_id: Uuid,
        active_interrupt_id: Option<Uuid>,
        pending_count: usize,
    },

    /// An outstanding interrupt was resolved — emitted to every client
    /// attached to the session (forward-compat for multi-client per
    /// GOALS §8e; v1 single-client receives it as a no-op echo).
    InterruptResolved {
        session_id: Uuid,
        interrupt_id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decision: Option<super::InterruptDecision>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seq: Option<i64>,
    },

    /// The agent yielded control back to the human: the driver loop
    /// finished the current user message (and any folded queue) and is
    /// now awaiting input. Distinct from the mid-turn gaps where no
    /// model call is in flight (between tools, between inference
    /// rounds) — this fires only when the stack unwinds to the root and
    /// the queue is empty. The TUI keys its span-long "agent is
    /// working" indicator off the user-submit (rising) / this (falling)
    /// edges. Forward-compat: it means "no longer actively working," so
    /// a future agent that is *waiting* (agent-invoked timers/loops)
    /// emits it too.
    AgentIdle {
        session_id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        turn_id: Option<String>,
    },

    /// The primary (root-frame) agent was swapped in place (`/plan` →
    /// `Plan`, `/build` → `Build`, `plan.md §4.6.d`). The client chrome's
    /// active-agent slot tracks `name`.
    PrimarySwapped {
        session_id: Uuid,
        name: String,
    },

    /// The active `llm_mode` was switched live (`/llm-mode`,
    /// implementation note). The client tracks `mode`
    /// so its `/llm-mode` toggle + cache-break warning resolve against the
    /// authoritative current value.
    LlmModeChanged {
        session_id: Uuid,
        mode: crate::config::extended::LlmMode,
    },

    /// The session ended (user requested, daemon shutting down,
    /// crash recovery couldn't restore it, …).
    SessionEnded {
        session_id: Uuid,
        reason: String,
    },

    /// An async job (loop / timer / background, GOALS §22) started.
    /// Drives the transient schedule strip. `kind` is `loop` / `timer` /
    /// `background`.
    ScheduleStarted {
        session_id: Uuid,
        job_id: String,
        label: String,
        kind: String,
    },
    /// A background job produced output (liveness tick for the strip).
    ScheduleProgress {
        session_id: Uuid,
        job_id: String,
    },
    /// A note from an ephemeral-fork loop iteration. Shown live in the
    /// transcript; the model sees it in main context only at loop end.
    ScheduleNote {
        session_id: Uuid,
        job_id: String,
        text: String,
    },
    /// An async job reached a terminal state (completed / failed /
    /// cancelled). Clears the strip entry + posts an inline marker; the
    /// model-facing result arrives separately as a late-arriving turn.
    ScheduleCompleted {
        session_id: Uuid,
        job_id: String,
        label: String,
        kind: String,
        failed: bool,
    },

    /// Live "% prunable" projection for the foreground agent (GOALS §1a).
    /// `prunable_tokens` is the wire-token drop `/prune` would achieve
    /// right now, computed by the same `dedup_plan` `/prune` executes.
    /// The TUI divides by the model's max context for the status line.
    ContextProjection {
        session_id: Uuid,
        prunable_tokens: u64,
        cache_cold: bool,
    },

    /// A `/prune` completed (manual or cache-aware auto). UI marker.
    /// `elided` is the **current** full set of `original_event_id`s whose
    /// tool-result body is now a wire-side elision marker; the TUI dims the
    /// matching scrollback tool-result bodies by `call_id`. Render-time
    /// view of live wire state, not a persisted transcript flag (§14).
    Pruned {
        session_id: Uuid,
        auto: bool,
        bodies: usize,
        tokens_saved: u64,
        #[serde(default)]
        elided: Vec<String>,
        /// Machine-readable auto-prune trigger reason. Present for automatic
        /// prunes and absent for manual `/prune`.
        #[serde(default)]
        trigger_reason: Option<String>,
        /// True when a warm prompt cache was broken by a ctx%-threshold
        /// auto-prune (implementation note); the client
        /// surfaces the shared cache-break warning.
        #[serde(default)]
        cache_break: bool,
    },

    /// A `/compact` handoff was assembled and applied in place.
    CompactReady {
        session_id: Uuid,
        new_session_id: Uuid,
        handoff: String,
        #[serde(default)]
        brief: String,
        seed_tool_count: usize,
        seed_tool_tokens: u64,
    },

    /// Sandboxing mode was set/toggled for the session (`/sandbox`). Broadcast
    /// to every attached client so they surface the resulting state.
    SandboxState {
        session_id: Uuid,
        mode: crate::tools::sandbox_mode::SandboxMode,
        enabled: bool,
        #[serde(default)]
        container_network_enabled: bool,
        container_availability: crate::container::ContainerAvailability,
    },

    /// Sandbox-escalation availability changed for the session. Broadcast to
    /// every attached client and re-emitted on attach so reconnecting clients
    /// mirror the daemon-owned flag.
    SandboxEscalationState {
        session_id: Uuid,
        enabled: bool,
    },

    /// The shell sandbox cannot initialize for this session (`bash` hit the
    /// refuse path — Linux userns case; `implementation notes` §6.5). Broadcast
    /// **once per session** (the worker de-dupes) so attached clients raise a
    /// deterministic, persistent, user-facing indicator. `remedy` is the
    /// diagnosed reason; `fix_command` is the exact user-copyable host command
    /// when the diagnosis has one. The TUI renders it as a persistent
    /// below-input notice, cleared when a later `SandboxState { enabled: false }`
    /// arrives. Model-independent and never part of any inference request.
    SandboxUnavailable {
        session_id: Uuid,
        remedy: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fix_command: Option<String>,
    },

    /// Redaction sources were toggled for the session
    /// (`/toggle-redaction`). Broadcast to every attached client so they
    /// surface the resulting state (TUI: a toast). Session-only.
    RedactionState {
        session_id: Uuid,
        scan_environment: bool,
        scan_dotenv: bool,
        scan_ssh_keys: bool,
    },

    /// Request preflight was set/toggled for the session (`/preflight`,
    /// implementation note). Broadcast to every attached client so
    /// they surface the resulting state (TUI: a toast + the live `/preflight`
    /// description mirror). Session-only — reverts on restart.
    PreflightState {
        session_id: Uuid,
        enabled: bool,
    },

    /// Trusted-only inference mode was set/toggled for the session
    /// (`/trusted-only`). Broadcast to every attached client so they surface
    /// the resulting state and update the live slash-command description.
    TrustedOnlyState {
        session_id: Uuid,
        enabled: bool,
    },

    /// Command-approval mode changed for the session (`/quick`).
    ApprovalModeState {
        session_id: Uuid,
        mode: crate::config::extended::ApprovalMode,
    },

    /// Delegation recursion override changed for the session (`/quick`).
    DelegationRecursionState {
        session_id: Uuid,
        enabled: bool,
        default_depth: u32,
    },

    /// The session's model-comparison tandem (shadow) set changed
    /// (`/model-comparison`, implementation note).
    /// Broadcast to every attached client so they surface the resulting set
    /// (`models` = `provider/model` labels; empty = feature off) and, on a
    /// non-empty set, the one-line token-burn `warning` (warning only — no
    /// cap/meter). Session-only — reverts on restart.
    TandemState {
        session_id: Uuid,
        models: Vec<String>,
        #[serde(default)]
        warning: Option<String>,
    },

    /// The session's in-memory gitignore read-allowlist
    /// (implementation note) — the set of globs
    /// added via the approval flow's "Approve for this session" choice.
    /// Carries the **full current set** (replace, not delta) so the TUI's
    /// `@`-tag popup can union it with the persisted per-layer config and
    /// re-include session-approved gitignored entries. Broadcast on change
    /// (a new glob landed) and on attach (hydration), so a late/reconnecting
    /// client and any second concurrent client see prior approvals. Only the
    /// allow-set is ever broadcast — never the session reject-memory.
    /// Session-only — reverts on daemon restart. Never enters the model's
    /// context.
    GitignoreAllow {
        session_id: Uuid,
        allow: Vec<String>,
    },

    /// Caffeination (`/caffeinate`) turned on or off — including the
    /// daemon-decided `until-idle` auto-off. **Daemon-global**: carries no
    /// `session_id` and is broadcast to *every* connected client so the
    /// `☕` chrome glyph appears (and clears) on all of them in lockstep.
    /// `message` is `Some` for the originating client's toast; other
    /// clients use `active` to drive the glyph. `lid_close_guaranteed`
    /// lets a client word the lid-close caveat if it shows one.
    CaffeinateState {
        active: bool,
        lid_close_guaranteed: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },

    /// Remote relay connector state changed. **Daemon-global**: carries no
    /// session content and is broadcast to every connected client so status
    /// chrome can show connected/reconnecting/off without polling.
    ConnectorStatus {
        enabled: bool,
        status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_region: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_error: Option<String>,
    },

    TerminalOutput {
        terminal_id: Uuid,
        bytes: Vec<u8>,
    },

    TerminalClipboard {
        terminal_id: Uuid,
        text: String,
    },

    TerminalViewers {
        terminal_id: Uuid,
        count: usize,
    },

    TerminalClosed {
        terminal_id: Uuid,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
    },

    /// The daemon began (or escalated) a graceful shutdown
    /// (`daemon-graceful-drain-shutdown.md`). **Daemon-global**: carries no
    /// `session_id` and is broadcast to *every* connected client so each
    /// TUI shows the drain notice and stops offering new input. `forced` is
    /// `false` when the drain just began (in-flight work is finishing) and
    /// `true` once the grace deadline was hit with work still outstanding,
    /// so a truncated turn isn't mistaken for a clean finish.
    DaemonDraining {
        forced: bool,
    },

    /// A session has durable paused work that needs a user's explicit resume
    /// or cancel decision.
    PausedWorkAvailable {
        session_id: Uuid,
        items: Vec<PausedWorkSummary>,
    },

    /// A `readlock` in this session is blocked waiting on a lock held by
    /// another agent/session, or that wait just ended
    /// (implementation note). Per-session
    /// (`session_id`-scoped): the attached TUI shows a transient indicator
    /// — `` waiting for lock on `{path}` (held by `{holder_agent}`) `` —
    /// alongside the fixed chrome, like the `☕` caffeinate glyph, and
    /// clears it on `waiting == false` (lock acquired or wait cancelled).
    /// UI-only: never enters the model's context.
    WaitingForLock {
        session_id: Uuid,
        path: String,
        holder_agent: String,
        waiting: bool,
    },
}

/// Convert a single engine `TurnEvent` into one or more wire
/// `proto::Event`s. Some events (e.g. `ThinkingStarted`) map 1:1;
/// others (subagent spawn / report) are kept as the natural-enough
/// proto equivalents. Returning a `Vec` keeps the door open for a
/// 1:N expansion when, e.g., we attach a recovery chip alongside a
/// `ToolEnd` in the future.
pub(crate) fn turn_event_to_proto(event: TurnEvent, session_id: Uuid) -> Vec<Event> {
    match event {
        TurnEvent::InterruptDecision {
            session_id: _,
            interrupt_id,
            decision,
            seq,
        } => vec![Event::InterruptResolved {
            session_id,
            interrupt_id,
            decision: Some(decision),
            seq,
        }],
        TurnEvent::InterruptQueueChanged {
            session_id: _,
            active_interrupt_id,
            pending_count,
        } => vec![Event::InterruptQueueChanged {
            session_id,
            active_interrupt_id,
            pending_count,
        }],
        TurnEvent::ThinkingStarted { agent, turn_id } => {
            vec![Event::ThinkingStarted {
                session_id,
                agent,
                turn_id,
            }]
        }
        TurnEvent::Reconnecting {
            agent,
            attempt,
            provider,
            model,
            url,
        } => {
            vec![Event::Reconnecting {
                session_id,
                agent,
                attempt,
                provider,
                model,
                url,
            }]
        }
        TurnEvent::AssistantTextDelta { agent, delta } => {
            vec![Event::AssistantTextDelta {
                session_id,
                agent,
                delta,
            }]
        }
        TurnEvent::ReasoningDelta { agent, delta } => {
            vec![Event::ReasoningDelta {
                session_id,
                agent,
                delta,
            }]
        }
        TurnEvent::AssistantText {
            agent,
            text,
            reasoning,
            seq,
        } => {
            vec![Event::AssistantText {
                session_id,
                agent,
                text,
                reasoning,
                seq,
            }]
        }
        TurnEvent::UserMessageRecorded {
            seq,
            preflight_cleaned,
        } => {
            vec![Event::UserMessageRecorded {
                session_id,
                seq,
                preflight_cleaned,
            }]
        }
        TurnEvent::QueuedUserMessagesFolded {
            text,
            queue_item_ids,
            target,
            seq,
            preflight_cleaned,
        } => {
            vec![Event::QueuedUserMessagesFolded {
                session_id,
                text,
                queue_item_ids,
                target: queue_target_to_proto(target),
                seq,
                preflight_cleaned,
            }]
        }
        TurnEvent::SessionPersistFailed { error } => {
            vec![Event::SessionPersistFailed { session_id, error }]
        }
        TurnEvent::SessionDriverFailed { error } => {
            vec![Event::SessionDriverFailed { session_id, error }]
        }
        TurnEvent::UserMessageDispatchFailed { .. } => vec![],
        TurnEvent::PreflightStarted => {
            vec![Event::PreflightStarted { session_id }]
        }
        TurnEvent::UserMessageRetracted => {
            vec![Event::UserMessageRetracted { session_id }]
        }
        TurnEvent::Notice { text } => {
            vec![Event::Notice { session_id, text }]
        }
        TurnEvent::SkillAutoInjected { name, reason } => {
            vec![Event::SkillAutoInjected {
                session_id,
                name,
                reason,
            }]
        }
        TurnEvent::ToolStart {
            agent,
            call_id,
            tool,
            args,
        } => vec![Event::ToolStart {
            session_id,
            agent,
            call_id,
            tool,
            args,
        }],
        TurnEvent::ToolEnd {
            agent,
            call_id,
            tool,
            output,
            truncated,
            hint,
        } => vec![Event::ToolEnd {
            session_id,
            agent,
            call_id,
            tool,
            output,
            truncated,
            hint,
        }],
        TurnEvent::ResourceWait {
            agent,
            request_id,
            display_id,
            resources,
            queue_position,
            command_label,
        } => vec![Event::ResourceWait {
            session_id,
            agent,
            request_id,
            display_id,
            resources,
            queue_position,
            command_label,
        }],
        TurnEvent::ResourceStart {
            agent,
            request_id,
            display_id,
            resources,
            wait_ms,
            command_label,
        } => vec![Event::ResourceStart {
            session_id,
            agent,
            request_id,
            display_id,
            resources,
            wait_ms,
            command_label,
        }],
        TurnEvent::ResourceClear {
            agent,
            request_id,
            display_id,
            resources,
            command_label,
        } => vec![Event::ResourceClear {
            session_id,
            agent,
            request_id,
            display_id,
            resources,
            command_label,
        }],
        TurnEvent::ToolError {
            agent,
            call_id,
            tool,
            error,
            kind,
        } => vec![Event::ToolError {
            session_id,
            agent,
            call_id,
            tool,
            error,
            kind,
        }],
        TurnEvent::InferenceFailed {
            agent,
            provider,
            model,
            error_class,
            detail,
        } => vec![Event::InferenceFailed {
            session_id,
            agent,
            provider,
            model,
            error_class,
            detail,
        }],
        TurnEvent::InferenceWarning {
            agent,
            provider,
            model,
            phase,
            waited_secs,
        } => vec![Event::InferenceWarning {
            session_id,
            agent,
            provider,
            model,
            phase,
            waited_secs,
        }],
        TurnEvent::BackupUsed {
            agent,
            primary_model,
            error_class,
            backup_model,
        } => vec![Event::BackupUsed {
            session_id,
            agent,
            primary_model,
            error_class,
            backup_model,
        }],
        TurnEvent::SubagentSpawned {
            parent,
            child,
            task_call_id,
            label,
            prompt,
            requested_cwd,
            resolved_cwd,
            trusted_only,
            model_trusted,
            routing,
        } => vec![Event::SubagentSpawned {
            session_id,
            parent,
            child,
            task_call_id,
            label,
            prompt,
            requested_cwd,
            resolved_cwd,
            trusted_only,
            model_trusted,
            routing,
        }],
        TurnEvent::SubagentReport {
            agent,
            task_call_id,
            label,
            report,
            trusted_only,
            model_trusted,
            routing,
        } => {
            vec![Event::SubagentReport {
                session_id,
                agent,
                task_call_id,
                label,
                report,
                trusted_only,
                model_trusted,
                routing,
            }]
        }
        TurnEvent::NestedTurn {
            task_call_id,
            label,
            parent_task_call_id,
            inner,
        } => turn_event_to_proto(*inner, session_id)
            .into_iter()
            .map(|inner| Event::NestedTurn {
                session_id,
                task_call_id: task_call_id.clone(),
                label: label.clone(),
                parent_task_call_id: parent_task_call_id.clone(),
                inner: Box::new(inner),
            })
            .collect(),
        TurnEvent::Usage { agent, usage } => {
            vec![Event::Usage {
                session_id,
                agent,
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                cached_input_tokens: usage.cached_input_tokens,
                cache_creation_input_tokens: usage.cache_creation_input_tokens,
            }]
        }
        TurnEvent::AgentIdle { turn_id } => {
            vec![Event::AgentIdle {
                session_id,
                turn_id,
            }]
        }
        TurnEvent::PrimarySwapped { name } => {
            vec![Event::PrimarySwapped { session_id, name }]
        }
        TurnEvent::LlmModeChanged { mode } => {
            vec![Event::LlmModeChanged { session_id, mode }]
        }
        // Engine→proto direction never produces this — the `question`
        // tool emits `Event::InterruptRaised` directly through
        // the interrupt hub, and the TUI-client direction
        // (`proto_event_to_turn_event`) is the only place that
        // synthesizes the `TurnEvent` form. No wire event to forward.
        TurnEvent::InterruptRaised { .. } => vec![],
        TurnEvent::InterruptResolved { .. } => vec![],
        TurnEvent::ScheduleStarted {
            // The engine stamps the originating session; the worker's own
            // `session_id` is authoritative for the wire event and equals it.
            session_id: _,
            job_id,
            label,
            kind,
        } => vec![Event::ScheduleStarted {
            session_id,
            job_id,
            label,
            kind,
        }],
        TurnEvent::ScheduleProgress { job_id } => {
            vec![Event::ScheduleProgress { session_id, job_id }]
        }
        TurnEvent::ScheduleNote { job_id, text } => {
            vec![Event::ScheduleNote {
                session_id,
                job_id,
                text,
            }]
        }
        TurnEvent::ScheduleCompleted {
            job_id,
            label,
            kind,
            failed,
        } => vec![Event::ScheduleCompleted {
            session_id,
            job_id,
            label,
            kind,
            failed,
        }],
        TurnEvent::ContextProjection {
            prunable_tokens,
            cache_cold,
        } => {
            vec![Event::ContextProjection {
                session_id,
                prunable_tokens,
                cache_cold,
            }]
        }
        TurnEvent::Pruned {
            auto,
            bodies,
            tokens_saved,
            elided,
            trigger_reason,
            cache_break,
        } => vec![Event::Pruned {
            session_id,
            auto,
            bodies,
            tokens_saved,
            elided,
            trigger_reason,
            cache_break,
        }],
        TurnEvent::CompactReady {
            new_session_id,
            handoff,
            brief,
            seed_tool_count,
            seed_tool_tokens,
        } => vec![Event::CompactReady {
            session_id,
            new_session_id,
            handoff,
            brief,
            seed_tool_count,
            seed_tool_tokens,
        }],
        // The engine never emits `SandboxState` — the daemon's
        // `SetSandbox` handler broadcasts the wire event directly (it
        // carries `session_id`). This arm exists only for exhaustiveness.
        TurnEvent::SandboxState {
            mode,
            container_network_enabled,
            container_availability,
        } => {
            vec![Event::SandboxState {
                session_id,
                mode,
                enabled: mode.enabled(),
                container_network_enabled,
                container_availability,
            }]
        }
        TurnEvent::SandboxEscalationState { enabled } => {
            vec![Event::SandboxEscalationState {
                session_id,
                enabled,
            }]
        }
        // Emitted by `engine::agent::turn` on the sandbox-unavailable refuse
        // path (§6.5). The mapping carries the remedy + session_id verbatim;
        // the per-session de-dupe (fire once per condition, not per failed
        // bash call) lives in the forward seam below, so a repeated failure
        // produces no second broadcast.
        TurnEvent::SandboxUnavailable {
            remedy,
            fix_command,
        } => vec![Event::SandboxUnavailable {
            session_id,
            remedy,
            fix_command,
        }],
        // The engine never emits `RedactionState` — the daemon's
        // `SetRedaction` handler broadcasts the wire event directly. This
        // arm exists only for exhaustiveness.
        TurnEvent::RedactionState {
            scan_environment,
            scan_dotenv,
            scan_ssh_keys,
        } => {
            vec![Event::RedactionState {
                session_id,
                scan_environment,
                scan_dotenv,
                scan_ssh_keys,
            }]
        }
        // Unlike redaction/sandbox, the DRIVER emits `PreflightState` — it
        // owns the session-only override + the toggle resolution (`/preflight`,
        // implementation note). Mapped to the broadcast event here.
        TurnEvent::PreflightState { enabled } => {
            vec![Event::PreflightState {
                session_id,
                enabled,
            }]
        }
        TurnEvent::TrustedOnlyState { enabled } => {
            vec![Event::TrustedOnlyState {
                session_id,
                enabled,
            }]
        }
        TurnEvent::ApprovalModeState { mode } => {
            vec![Event::ApprovalModeState { session_id, mode }]
        }
        TurnEvent::DelegationRecursionState {
            enabled,
            default_depth,
        } => {
            vec![Event::DelegationRecursionState {
                session_id,
                enabled,
                default_depth,
            }]
        }
        // The session gitignore-allowlist push is emitted directly over the
        // per-session bus — by the approval flow's `emit_gitignore_allow`
        // (`InterruptHub`) on change and by `broadcast_gitignore_allow` on
        // attach (implementation note). The engine
        // never routes it through the turn stream; this arm is for
        // exhaustiveness only.
        TurnEvent::GitignoreAllow { .. } => vec![],
        // The model-comparison tandem-set push is broadcast directly by the
        // `SetTandemModels` handler (`model-comparison-tandem-
        // inference.md`); the engine never routes it through the turn stream,
        // so this arm is for exhaustiveness only.
        TurnEvent::TandemState { .. } => vec![],
        // Caffeination is daemon-global, not a session event: the
        // `SetCaffeinate` handler / until-idle watcher broadcast
        // `Event::CaffeinateState` over the global bus directly.
        // The engine never emits this; the arm is for exhaustiveness.
        TurnEvent::CaffeinateState { .. } => vec![],
        // The drain notice is daemon-global, broadcast by the daemon's
        // graceful-shutdown path directly (`server::request_shutdown`); the
        // engine never emits it. This arm is for exhaustiveness only.
        TurnEvent::DaemonDraining { .. } => vec![],
        // A blocked/unblocked `readlock` (`readlock-wait-and-lock-expiry.md`):
        // emitted by the `readlock` tool through the per-turn event stream;
        // forwarded verbatim, scoped to this session so only its attached
        // clients show the transient waiting indicator.
        TurnEvent::WaitingForLock {
            path,
            holder_agent,
            waiting,
        } => vec![Event::WaitingForLock {
            session_id,
            path,
            holder_agent,
            waiting,
        }],
        TurnEvent::QueueUpdated { .. } => vec![],
        TurnEvent::ForegroundInputTarget { target } => vec![Event::ForegroundInputTarget {
            session_id,
            target: queue_target_to_proto(target),
        }],
        TurnEvent::ConnectorStatus { .. } => vec![],
    }
}

fn queue_target_to_proto(target: crate::engine::message::QueueTarget) -> QueueTarget {
    QueueTarget {
        id: target.id,
        agent: target.agent,
        depth: target.depth,
        task_call_id: target.task_call_id,
    }
}
