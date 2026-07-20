use super::*;

/// Client → daemon RPCs. The daemon answers each with a matching
/// [`Response`] keyed by envelope id, or an [`ErrorPayload`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", content = "params")]
pub enum Request {
    /// Attach to an existing session by id, or create a new one.
    /// Returns the session's identity + a snapshot of its existing
    /// history so the TUI can re-render the transcript after a
    /// reconnect.
    Attach {
        #[serde(default)]
        session_id: Option<Uuid>,
        /// Replay cursor for reconnecting clients. When set, the daemon
        /// returns an empty attach history and emits persisted timeline
        /// entries with `seq > since_seq` as replay events before live events.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since_seq: Option<i64>,
        /// Project root override; when None the daemon uses the cwd
        /// it knows for this client connection.
        #[serde(default)]
        project_root: Option<String>,
        /// The client's `--no-sandbox` flag (sandboxing part 2). When
        /// `true`, sessions this client *creates* start with filesystem
        /// sandboxing OFF — unless the daemon itself was launched
        /// `--no-sandbox` (which wins). Ignored on resume of an existing
        /// session (the session keeps its own state). Defaults to
        /// `false` so older clients attach sandboxed.
        #[serde(default)]
        no_sandbox: bool,
        /// Whether this client can *answer* interrupts (approval / loop-
        /// guard / `question` prompts). The TUI sets `true`; a `cockpit
        /// run` event pump sets `false` (it streams events but has no UI
        /// to answer with). The daemon tracks the interactive-client count
        /// per session so the loop guard knows when a run is headless and
        /// must auto-reject a repeat rather than block. Defaults to
        /// `false` so an older client (and any non-answering attach) is
        /// treated as headless — the safe, non-blocking default.
        #[serde(default)]
        interactive: bool,
        /// Plan-level model override (prompt
        /// `plan-duplication-and-model-override.md`): a `provider/model`
        /// selector that overrides every spawned agent's frontmatter model
        /// for this session's run. Set by `cockpit run --model` (the plan
        /// executor passes the plan's pinned model). `None` leaves the
        /// session on its active model + per-agent frontmatter. Ignored on
        /// resume of an existing session. Defaults to `None`.
        #[serde(default)]
        model_override: Option<String>,
        #[serde(default = "default_client_protocol_version")]
        client_protocol_version: u32,
        /// Full client-side environment snapshot for sessions this attach
        /// creates or cold-resumes after daemon restart. Raw values are used
        /// only in memory and never persisted; responses/events carry only
        /// [`EnvSnapshotMeta`] and safe diff summaries.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        env_snapshot: Option<EnvSnapshotWire>,
        /// Non-interactive drift policy. Interactive clients may still choose
        /// client/update-daemon explicitly before attach; the daemon default
        /// is conservative and keeps its baseline.
        #[serde(default)]
        env_policy: EnvDriftPolicy,
    },

    /// Fetch one noninteractive child run's persisted transcript. This is
    /// read-only and independent of attach/resume history projection.
    SubagentTranscript {
        session_id: Uuid,
        task_call_id: String,
        label: String,
    },

    /// Send a user message into the currently attached session. The
    /// daemon enqueues it on the driver and acks immediately —
    /// per-turn progress flows over the event stream. `image_refs` carries
    /// lightweight refs to already-uploaded pasted image attachments
    /// (vision models only; non-vision clients fold images into `text`
    /// and leave this empty — composer-paste-handling). The `text` may
    /// contain `IMAGE_PART_SENTINEL` markers, one per image, in order.
    SendUserMessage {
        text: String,
        /// User-facing transcript form. When absent, clients display `text`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        display_text: Option<String>,
        /// Structured display metadata for composer-expanded `@` tags.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tag_expansions: Vec<TagExpansionMeta>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        image_refs: Vec<ImageAttachmentRef>,
        /// A user-issued skill slash command (`/<skill-name>` or
        /// `/skill <name>`, implementation note): the exact
        /// skill name to invoke deterministically before this turn's
        /// inference. `text` carries any trailing args. `None` for an
        /// ordinary message.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        forced_skill: Option<String>,
    },

    /// Side-channel steer for a running noninteractive child. This bypasses
    /// the main user-message queue, so it does not background the child or
    /// redirect the text to the parent.
    SteerDelegation {
        session_id: Uuid,
        task_call_id: String,
        label: String,
        message: String,
    },

    BeginAttachmentUpload {
        mime: String,
        byte_len: usize,
        sha256: String,
        purpose: AttachmentPurpose,
    },

    UploadAttachmentChunk {
        upload_id: Uuid,
        offset: usize,
        data_base64: String,
    },

    FinishAttachmentUpload {
        upload_id: Uuid,
    },

    CancelAttachmentUpload {
        upload_id: Uuid,
    },

    /// Remove a daemon-owned user message that has been accepted but not yet
    /// folded into an inference request. Returns a non-applied result when the
    /// item has already started folding or is unknown to this worker.
    RemoveQueuedUserMessage {
        queue_item_id: Uuid,
    },

    /// Atomically remove the newest queued user message for a foreground
    /// target. When `target_id` is absent, the worker uses its current
    /// foreground input target.
    RemoveNewestQueuedUserMessage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_id: Option<String>,
    },

    /// Atomically remove every editable queued user message for a foreground
    /// target. When `target_id` is absent, the worker uses its current
    /// foreground input target.
    RemoveEditableQueuedUserMessages {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_id: Option<String>,
    },

    /// Explicitly resume durable work that was paused during daemon shutdown.
    /// Safe work continues through the normal driver/tool approval path; work
    /// that needs an interactive approval remains parked until a client can
    /// answer it.
    ResumePausedWork {
        session_id: Uuid,
    },

    /// Cancel durable work that was paused during daemon shutdown. The audit
    /// row is retained and marked cancelled; the session remains available for
    /// new user input.
    CancelPausedWork {
        session_id: Uuid,
    },

    /// Explicitly repair a Responses resume that was opened read-only because
    /// provider replay could not be rebuilt strictly. This opts into the
    /// existing synthetic resume-heal path; the original transcript is not
    /// rewritten.
    RepairResume {
        session_id: Uuid,
    },

    /// Read the current open goal for a session after refreshing token usage.
    GoalStatus {
        session_id: Uuid,
    },

    /// Pause or resume the current open goal for a session.
    SetGoalStatus {
        session_id: Uuid,
        status: GoalStatus,
    },

    /// Mark the current open goal complete without requiring model evidence.
    ClearGoal {
        session_id: Uuid,
    },

    /// List persisted assistant definitions.
    ListAssistants,

    /// Create a new assistant session through the daemon registry. The
    /// session is deferred and is not persisted until its first user message.
    CreateAssistantSession {
        name: String,
        project_root: String,
        #[serde(default)]
        no_sandbox: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        env_snapshot: Option<EnvSnapshotWire>,
    },

    /// Return export-ready session data while leaving user-path file writing
    /// to the client.
    ExportSessionData {
        session_id: Uuid,
        kind: ExportSessionKind,
        #[serde(default)]
        include_generated_artifacts: bool,
        #[serde(default)]
        include_sensitive: bool,
    },

    /// Execute a daemon-owned skill curator operation for a trusted project.
    Curator {
        project_root: String,
        action: CuratorAction,
    },

    /// Cancel the in-flight model call for the attached session. The
    /// daemon aborts the streaming completion and returns control to
    /// the agent stack so the user can redirect.
    CancelTurn,

    FsList {
        project_root: String,
        path: String,
        #[serde(default)]
        show_hidden: bool,
    },

    FsStat {
        project_root: String,
        path: String,
    },

    FsRead {
        project_root: String,
        path: String,
        #[serde(default)]
        base64: bool,
    },

    FsWrite {
        project_root: String,
        path: String,
        content: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        base_hash: Option<String>,
    },

    FsCreateDir {
        project_root: String,
        path: String,
    },

    FsRename {
        project_root: String,
        from_path: String,
        to_path: String,
    },

    FsDelete {
        project_root: String,
        path: String,
    },

    GitStatus {
        project_root: String,
    },

    GitDiffFile {
        project_root: String,
        path: String,
    },

    OpenTerminal {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        cols: u16,
        rows: u16,
    },

    AttachTerminal {
        terminal_id: Uuid,
        cols: u16,
        rows: u16,
    },

    TerminalInput {
        terminal_id: Uuid,
        bytes: Vec<u8>,
    },

    TerminalResize {
        terminal_id: Uuid,
        cols: u16,
        rows: u16,
    },

    CloseTerminal {
        terminal_id: Uuid,
    },

    /// Control a daemon-owned LSP server. The TUI may request these from
    /// `/settings`, but the daemon remains the only process that checks,
    /// installs, uninstalls, restarts, or kills language servers.
    LspControl {
        project_root: String,
        server_id: String,
        action: LspControlAction,
    },

    /// Resolve an outstanding interrupt (GOALS §3b) raised by a
    /// background builder.
    ResolveInterrupt {
        interrupt_id: Uuid,
        response: ResolveResponse,
    },

    /// List sessions, newest first. Both filters default to None:
    ///
    /// - `project_id = None, parent_session_id = None` — every session
    ///   (legacy behavior, used by `cockpit session list`).
    /// - `project_id = Some(p), parent_session_id = None` — root
    ///   sessions in project `p` (the top level of the `/sessions`
    ///   browser, GOALS §17f).
    /// - `project_id = _, parent_session_id = Some(s)` — direct forks
    ///   of session `s` (the right-arrow descent in `/sessions`).
    ListSessions {
        #[serde(default)]
        project_id: Option<String>,
        #[serde(default)]
        parent_session_id: Option<Uuid>,
    },

    /// Read a paginated page of plain user/agent messages for a session.
    /// `before_seq = None` reads the newest page; `Some(seq)` reads older
    /// messages with `seq < before_seq`. The daemon clamps `limit`.
    ReadSessionMessages {
        session_id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        before_seq: Option<i64>,
        limit: u32,
    },

    /// Per-session live status for the `/sessions` browser's top two
    /// tiers (GOALS §17f): which of `session_ids` currently have active
    /// async jobs (loop/timer/background) and which are mid-turn
    /// (processing). Sourced from the in-daemon per-session `ScheduleAuthority`
    /// plus worker turn-state — the TUI is a socket client and can't see
    /// in-memory daemon state otherwise. Sessions with no live worker are
    /// simply absent from the response (the browser treats them as
    /// not-processing, no-jobs and falls back to DB tiers).
    SessionLiveStatus {
        session_ids: Vec<Uuid>,
    },

    /// Archive a session (recoverable soft-delete, GOALS §17h). With
    /// `cascade`, archives the whole descendant fork subtree. The browser
    /// hides archived sessions by default with a toggle to reveal them.
    ArchiveSession {
        session_id: Uuid,
        #[serde(default)]
        cascade: bool,
    },

    /// Clear a session's archive flag (recover it from the archived view).
    UnarchiveSession {
        session_id: Uuid,
    },

    /// Branch a fork off `parent_session_id` at `fork_point_turn_id`
    /// (None = tail). GOALS §17e. `ephemeral` marks a throwaway `/side`
    /// side-conversation fork — excluded from lists, never auto-titled,
    /// discarded on end/exit.
    ForkSession {
        parent_session_id: Uuid,
        #[serde(default)]
        fork_point_turn_id: Option<String>,
        #[serde(default)]
        ephemeral: bool,
    },

    /// Stop an ephemeral side-conversation (`/side`) worker and discard its
    /// row + descendant forks. No-op for a non-ephemeral session (guarded).
    DiscardSession {
        session_id: Uuid,
    },

    /// Create or return the one live persistent `/btw` fork for a parent
    /// session. When `tangent` is true, the fork starts with an empty
    /// transcript; otherwise it is seeded from the parent at the current fork
    /// ceiling. Parent compaction after creation does not re-seed the fork.
    CreateBtwFork {
        parent_session_id: Uuid,
        #[serde(default)]
        tangent: bool,
    },

    /// End and discard the live `/btw` fork for a parent session, if any.
    /// Idempotent when no fork exists.
    EndBtwFork {
        parent_session_id: Uuid,
    },

    /// Manually set a session's title; locks out auto-titling.
    /// GOALS §17d.
    RenameSession {
        session_id: Uuid,
        title: String,
    },

    /// Owner-only broad sharing toggle. When enabled, collaborators holding
    /// `agent` or `agent_readonly` for this project can see the session;
    /// write rights are still governed by their scope.
    ShareSession {
        session_id: Uuid,
        shared: bool,
    },

    /// Append a user-authored session-history note (`/note <text>`,
    /// implementation note). Records a `user_note` session event
    /// and returns its assigned `seq` ([`Response::NoteRecorded`]). The note is
    /// local/export state only — never sent to the model and never triggers an
    /// inference call.
    RecordSessionNote {
        session_id: Uuid,
        text: String,
    },

    /// Drop a session and (optionally) its descendant forks.
    /// FK cascades take care of tool_call_events / inference_calls /
    /// lock state. GOALS §17h.
    DeleteSession {
        session_id: Uuid,
        #[serde(default)]
        cascade: bool,
    },

    /// List discovered skills, resolving the configured scan dirs from
    /// `project_root` (the client's cwd) so per-project config applies.
    ListSkills {
        project_root: String,
    },

    /// Snapshot the daemon-wide resource scheduler for `/resources`.
    ResourceSnapshot,

    /// Promote one queued resource request to the front of the waiting queue.
    /// `request_id` accepts either the scheduler's short display id (`rs-0001`)
    /// or the internal UUID. Running/completed/stale ids return a typed
    /// non-applied result rather than a transport error.
    PromoteResource {
        request_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<Uuid>,
    },

    /// Create or replace a durable daemon scheduler job. Owner-only; future
    /// assistant-facing tools will call this RPC after assistant policy checks.
    CreateScheduledJob {
        job: ScheduledJobCreate,
    },

    /// List durable scheduler jobs. Owner filtering is exact, e.g.
    /// `assistant:alice` or `system:dreamer`.
    ListScheduledJobs {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner: Option<String>,
    },

    /// Delete a durable scheduler job.
    DeleteScheduledJob {
        id: String,
    },

    /// Enable or disable a durable scheduler job.
    SetScheduledJobEnabled {
        id: String,
        enabled: bool,
    },

    /// Fire a durable scheduler job immediately without changing its schedule.
    RunScheduledJob {
        id: String,
    },

    /// List discovered agents (bundled + on-disk + agent_dirs).
    ListAgents,

    /// List models known for the active provider, or for a specific
    /// provider when set.
    ListModels {
        #[serde(default)]
        provider: Option<String>,
    },

    /// Switch the attached session to a different model.
    SetActiveModel {
        provider: String,
        model: String,
        #[serde(default)]
        trigger: ActiveModelSwitchTrigger,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reasoning_effort: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        thinking_mode: Option<String>,
    },

    /// Swap which built-in or user agent owns the conversation.
    SetAgent {
        name: String,
    },

    /// Switch the active `llm_mode` for the attached session live
    /// (`/llm-mode`, implementation note). `mode = None`
    /// toggles between `normal`/`defensive` against the daemon's
    /// authoritative current value; `Some(_)` sets it explicitly. Busts the
    /// cached system prefix (the client shows the cache-break warning, unless
    /// the provider doesn't cache). Acked with the resulting mode via
    /// [`Event::LlmModeChanged`].
    SetLlmMode {
        #[serde(default)]
        mode: Option<LlmMode>,
    },

    /// Switch the active `llm_mode` for the attached session without writing
    /// the config default. Used by `/quick`; acknowledged with
    /// [`Event::LlmModeChanged`].
    SetSessionLlmMode {
        mode: LlmMode,
    },

    /// Set the attached session's live command-approval mode. Session-only;
    /// does not write `defaultApprovalMode`.
    SetApprovalMode {
        mode: ApprovalMode,
    },

    /// Set a live session override for root delegation recursion. Session-only;
    /// does not write `delegation.recursionEnabled` or
    /// `delegation.defaultRecursionDepth`.
    SetDelegationRecursion {
        enabled: bool,
        default_depth: u32,
    },

    /// Set (or toggle) sandbox mode for the attached session at runtime.
    /// `mode = None` toggles the legacy off/sandbox state; container-mode
    /// selection is explicit. `container_network_enabled` updates the live
    /// per-session container network flag when present.
    SetSandbox {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<SandboxMode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        container_network_enabled: Option<bool>,
    },

    /// Enable or disable explicit sandbox-escalation retries for the attached
    /// session. Session-only; the settings dialog persists the default
    /// separately before sending this live update.
    SetSandboxEscalation {
        enabled: bool,
    },

    /// Set (or toggle) request preflight for the attached session at runtime
    /// (`/preflight`, implementation note). `enabled = None`
    /// toggles the current effective state; `Some(true)`/`Some(false)` set it
    /// explicitly. The driver holds the session-only override (precedence over
    /// config). **Session-only / in-memory** — no config-file write; reverts
    /// on restart. Acked with the resulting state via
    /// [`Response::PreflightState`] (and the broadcast [`Event::PreflightState`]).
    SetPreflight {
        #[serde(default)]
        enabled: Option<bool>,
    },

    /// Set (or toggle) trusted-only inference mode for the attached session
    /// (`/trusted-only`). `enabled = None` toggles the live session state;
    /// `Some(true)`/`Some(false)` set it explicitly. Effective immediately
    /// for subsequent provider dispatches, including already-built model
    /// handles. Acked with [`Event::TrustedOnlyState`].
    SetTrustedOnly {
        #[serde(default)]
        enabled: Option<bool>,
    },

    /// Toggle redaction sources for the attached session at runtime
    /// (`/toggle-redaction`). `scan_environment`/`scan_dotenv`/`scan_ssh_keys`
    /// each set the matching source explicitly (`Some`) or leave it unchanged
    /// (`None`); the daemon rebuilds the session's effective redaction table
    /// for subsequent outbound prompts. **Session-only / in-memory** — no
    /// config-file write; reverts on restart. `scrub()` stays
    /// non-bypassable; this only changes what enters the table. Acked with
    /// the resulting state via [`Response::RedactionState`].
    SetRedaction {
        #[serde(default)]
        scan_environment: Option<bool>,
        #[serde(default)]
        scan_dotenv: Option<bool>,
        #[serde(default)]
        scan_ssh_keys: Option<bool>,
    },

    /// Set the session's model-comparison tandem (shadow) set
    /// (`/model-comparison`, implementation note).
    /// `models` is the full selected set of `(provider, model)` pairs from
    /// already-configured providers (the active model is excluded by the
    /// client). The daemon builds a completion model for each and routes them
    /// to the driver; **empty = feature off** (no separate enable flag).
    /// **Session-only / in-memory** — no config write; reverts on restart.
    /// Acked immediately; the resulting set + token-burn warning arrive via the
    /// broadcast [`Event::TandemState`].
    SetTandemModels {
        #[serde(default)]
        models: Vec<(String, String)>,
    },

    /// Set caffeination (`/caffeinate`): suppress system sleep + lid-close
    /// so agents survive a closed lid. Daemon-global state — the daemon
    /// holds the OS sleep assertion in its own (long-lived) process and
    /// broadcasts the resulting [`Event::CaffeinateState`] to **every**
    /// connected client (not just the attached session). `until_idle`
    /// auto-off is decided by the daemon once no agent is running. Acked
    /// with [`Response::CaffeinateState`].
    SetCaffeinate {
        mode: CaffeinateMode,
    },

    /// Cancel a live async job (loop / timer / background, GOALS §22) by
    /// id, on behalf of the human (the `/schedule cancel <id>` affordance).
    CancelSchedule {
        job_id: String,
    },

    /// Run `/prune` (snapshot dedup) on the attached session's foreground
    /// agent. Acked immediately; the `Pruned` + refreshed
    /// `ContextProjection` events flow over the stream. The confirm UX
    /// lives in the TUI — this request means the user already accepted.
    Prune,

    /// Run `/compact` on the attached session's foreground agent. Acked
    /// immediately; the in-place boundary arrives as a `CompactReady` event.
    Compact,

    /// Pin a user message verbatim for the next `/compact` (`/pin`).
    Pin {
        text: String,
    },

    /// Store Flycockpit instance credentials in the daemon-owned credential file
    /// and wake the relay connector immediately. Owner-only; ephemeral daemons
    /// reject it because they must not own persistent credentials.
    StoreFlycockpitCredential {
        credential: StoredFlycockpitCredential,
    },

    /// Clear Flycockpit instance credentials from the daemon-owned credential
    /// file and wake the relay connector so active sockets stop promptly.
    /// Owner-only; ephemeral daemons reject it.
    ClearFlycockpitCredential,

    /// Cheap liveness probe. Replaces the legacy `"ok\n"` greeting.
    DaemonStatus,

    /// Refresh the daemon's view of selected environment variables.
    /// The TUI sends a curated snapshot of *its* env on every launch so
    /// API tokens / API-URL overrides the user just exported in their
    /// shell rc become visible to a long-running daemon without
    /// requiring `cockpit daemon restart`.
    RefreshEnv {
        vars: HashMap<String, String>,
    },

    /// Explicitly re-resolve the attached session's layered config in the
    /// daemon and push the next [`Event::ConfigSnapshot`] generation. A failed
    /// re-resolution keeps the last good generation and emits a notice.
    RefreshConfig,

    /// Record one accepted autocomplete pick into the 30-day frequency
    /// tally (GOALS §1; tie-breaker for the model / slash / @-tag
    /// surfaces). Fire-and-forget — acked immediately; no attached
    /// session is required since the tally is global. `project_id` is
    /// set only for `tag` picks.
    RecordUsage {
        kind: UsageKind,
        key: String,
        #[serde(default)]
        project_id: Option<String>,
    },

    /// Fetch the three 30-day autocomplete count maps. `project_id`
    /// scopes the `tag` map (model + slash are global); `None` yields an
    /// empty `tags` map.
    GetUsageCounts {
        #[serde(default)]
        project_id: Option<String>,
    },

    /// Return the `/stats` rollup from the daemon-owned database handle.
    StatsRollup {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        project_id: Option<String>,
        range: StatsRange,
        #[serde(default)]
        by_role: bool,
    },

    /// Pre-flight sizing of the project's instruction/guidance file and
    /// full system prompt, for the fresh-chat context indicator. The
    /// daemon resolves the guidance file for `project_root` and estimates
    /// both its body and the full composed system prompt with the
    /// tokenizer calibrated for `(provider, model)`. The daemon's count is
    /// calibrated; the TUI computes the same locally (raw cl100k) when no
    /// daemon is running.
    GuidanceEstimate {
        project_root: String,
        #[serde(default)]
        provider: Option<String>,
        #[serde(default)]
        model: Option<String>,
    },

    /// Request orderly shutdown. The daemon flushes in-flight writes
    /// (session DB, lock state) before exiting.
    StopDaemon {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grace_secs: Option<u64>,
    },
}

// Keep daemon command metadata centralized. Callers provide a local callback
// macro so each module can expand the same exhaustive Request table into the
// shape it needs without changing Request's serde representation.
#[macro_export]
macro_rules! command {
    ($with_commands:ident $(, $context:ident)*) => {
        $with_commands! { ($($context),*) [
            (Request::Attach { session_id, .. }, "attach", custom(authorize_attach), option_field(session_id), true, none);
            (Request::SubagentTranscript { session_id, .. }, "subagent_transcript", custom(authorize_subagent_transcript), field(session_id), false, none);
            (Request::SendUserMessage { .. }, "send_user_message", session_writer, attached, true, none);
            (Request::SteerDelegation { session_id, .. }, "steer_delegation", custom(authorize_steer_delegation), field(session_id), true, none);
            (Request::BeginAttachmentUpload { .. }, "begin_attachment_upload", custom(authorize_begin_attachment_upload), attached, true, none);
            (Request::UploadAttachmentChunk { .. }, "upload_attachment_chunk", custom(authorize_attachment_upload_step), attached, true, none);
            (Request::FinishAttachmentUpload { .. }, "finish_attachment_upload", custom(authorize_attachment_upload_step), attached, true, none);
            (Request::CancelAttachmentUpload { .. }, "cancel_attachment_upload", custom(authorize_attachment_upload_step), attached, true, none);
            (Request::RemoveQueuedUserMessage { .. }, "remove_queued_user_message", session_writer, attached, true, none);
            (Request::RemoveNewestQueuedUserMessage { .. }, "remove_newest_queued_user_message", session_writer, attached, true, none);
            (Request::RemoveEditableQueuedUserMessages { .. }, "remove_editable_queued_user_messages", session_writer, attached, true, none);
            (Request::ResumePausedWork { session_id }, "resume_paused_work", session_row_writer(session_id), field(session_id), true, none);
            (Request::CancelPausedWork { session_id }, "cancel_paused_work", session_row_writer(session_id), field(session_id), true, none);
            (Request::RepairResume { session_id }, "repair_resume", session_writer, field(session_id), true, none);
            (Request::GoalStatus { session_id }, "goal_status", session_row_reader(session_id), field(session_id), false, none);
            (Request::SetGoalStatus { session_id, .. }, "set_goal_status", session_row_writer(session_id), field(session_id), true, none);
            (Request::ClearGoal { session_id }, "clear_goal", session_row_writer(session_id), field(session_id), true, none);
            (Request::ListAssistants, "list_assistants", owner_only, none, false, none);
            (Request::CreateAssistantSession { .. }, "create_assistant_session", owner_only, none, true, none);
            (Request::ExportSessionData { session_id, .. }, "export_session_data", owner_only, field(session_id), false, none);
            (Request::Curator { project_root, .. }, "curator", owner_only, none, true, path(project_root));
            (Request::CancelTurn, "cancel_turn", session_writer, attached, true, none);
            (Request::FsList { project_root, .. }, "fs_list", project_files(project_root), none, false, none);
            (Request::FsStat { project_root, .. }, "fs_stat", project_files(project_root), none, false, none);
            (Request::FsRead { project_root, .. }, "fs_read", project_files(project_root), none, false, none);
            (Request::FsWrite { project_root, path, .. }, "fs_write", project_files(project_root), none, true, path(path));
            (Request::FsCreateDir { project_root, path }, "fs_create_dir", project_files(project_root), none, true, path(path));
            (Request::FsRename { project_root, from_path, to_path }, "fs_rename", project_files(project_root), none, true, rename(from_path, to_path));
            (Request::FsDelete { path, .. }, "fs_delete", owner_only, none, true, path(path));
            (Request::GitStatus { project_root }, "git_status", project_files(project_root), none, false, none);
            (Request::GitDiffFile { project_root, path }, "git_diff_file", project_files(project_root), none, false, path(path));
            (Request::OpenTerminal { .. }, "open_terminal", terminal, none, true, none);
            (Request::AttachTerminal { .. }, "attach_terminal", terminal, none, false, none);
            (Request::TerminalInput { .. }, "terminal_input", terminal, none, false, none);
            (Request::TerminalResize { .. }, "terminal_resize", terminal, none, false, none);
            (Request::CloseTerminal { .. }, "close_terminal", terminal, none, true, none);
            (Request::LspControl { .. }, "lsp_control", custom(authorize_lsp_control), attached, true, none);
            (Request::ResolveInterrupt { .. }, "resolve_interrupt", session_writer, attached, true, none);
            (Request::ListSessions { .. }, "list_sessions", public_read, none, false, none);
            (Request::ReadSessionMessages { session_id, .. }, "read_session_messages", custom(authorize_read_session_messages), field(session_id), false, none);
            (Request::SessionLiveStatus { .. }, "session_live_status", public_read, none, false, none);
            (Request::ArchiveSession { session_id, .. }, "archive_session", session_row_writer(session_id), field(session_id), true, none);
            (Request::UnarchiveSession { session_id }, "unarchive_session", session_row_writer(session_id), field(session_id), true, none);
            (Request::ForkSession { parent_session_id, .. }, "fork_session", session_row_writer(parent_session_id), field(parent_session_id), true, none);
            (Request::DiscardSession { session_id }, "discard_session", session_row_writer(session_id), field(session_id), true, none);
            (Request::CreateBtwFork { parent_session_id, .. }, "btw_create", session_row_writer(parent_session_id), field(parent_session_id), true, none);
            (Request::EndBtwFork { parent_session_id }, "btw_end", session_row_writer(parent_session_id), field(parent_session_id), true, none);
            (Request::RenameSession { session_id, .. }, "rename_session", session_row_writer(session_id), field(session_id), true, none);
            (Request::ShareSession { session_id, .. }, "share_session", owner_only, field(session_id), true, none);
            (Request::RecordSessionNote { session_id, .. }, "record_session_note", session_row_writer(session_id), field(session_id), true, none);
            (Request::DeleteSession { session_id, .. }, "delete_session", session_row_writer(session_id), field(session_id), true, none);
            (Request::ListSkills { project_root }, "list_skills", project_read(project_root), none, false, none);
            (Request::ResourceSnapshot, "resource_snapshot", owner_only, none, false, none);
            (Request::PromoteResource { session_id, .. }, "promote_resource", owner_only, option_field(session_id), true, none);
            (Request::CreateScheduledJob { .. }, "create_scheduled_job", owner_only, none, true, none);
            (Request::ListScheduledJobs { .. }, "list_scheduled_jobs", owner_only, none, false, none);
            (Request::DeleteScheduledJob { .. }, "delete_scheduled_job", owner_only, none, true, none);
            (Request::SetScheduledJobEnabled { .. }, "set_scheduled_job_enabled", owner_only, none, true, none);
            (Request::RunScheduledJob { .. }, "run_scheduled_job", owner_only, none, true, none);
            (Request::ListAgents, "list_agents", owner_only, none, false, none);
            (Request::ListModels { .. }, "list_models", owner_only, none, false, none);
            (Request::SetActiveModel { .. }, "set_active_model", session_writer, attached, true, none);
            (Request::SetAgent { .. }, "set_agent", session_writer, attached, true, none);
            (Request::SetLlmMode { .. }, "set_llm_mode", session_writer, attached, true, none);
            (Request::SetSessionLlmMode { .. }, "set_session_llm_mode", session_writer, attached, true, none);
            (Request::SetApprovalMode { .. }, "set_approval_mode", session_writer, attached, true, none);
            (Request::SetDelegationRecursion { .. }, "set_delegation_recursion", session_writer, attached, true, none);
            (Request::SetSandbox { .. }, "set_sandbox", session_writer, attached, true, none);
            (Request::SetSandboxEscalation { .. }, "set_sandbox_escalation", session_writer, attached, true, none);
            (Request::SetPreflight { .. }, "set_preflight", session_writer, attached, true, none);
            (Request::SetTrustedOnly { .. }, "set_trusted_only", session_writer, attached, true, none);
            (Request::SetRedaction { .. }, "set_redaction", session_writer, attached, true, none);
            (Request::SetTandemModels { .. }, "set_tandem_models", session_writer, attached, true, none);
            (Request::SetCaffeinate { .. }, "set_caffeinate", owner_only, none, true, none);
            (Request::CancelSchedule { .. }, "cancel_schedule", session_writer, attached, true, none);
            (Request::Prune, "prune", session_writer, attached, true, none);
            (Request::Compact, "compact", session_writer, attached, true, none);
            (Request::Pin { .. }, "pin", session_writer, attached, true, none);
            (Request::StoreFlycockpitCredential { .. }, "store_flycockpit_credential", owner_only, none, true, none);
            (Request::ClearFlycockpitCredential, "clear_flycockpit_credential", owner_only, none, true, none);
            (Request::DaemonStatus, "daemon_status", public_read, none, false, none);
            (Request::RefreshEnv { .. }, "refresh_env", session_writer, attached, true, none);
            (Request::RefreshConfig, "refresh_config", session_writer, attached, true, none);
            (Request::RecordUsage { .. }, "record_usage", owner_only, none, true, none);
            (Request::GetUsageCounts { .. }, "get_usage_counts", owner_only, none, false, none);
            (Request::StatsRollup { .. }, "stats_rollup", owner_only, none, false, none);
            (Request::GuidanceEstimate { project_root, .. }, "guidance_estimate", project_read(project_root), none, false, none);
            (Request::StopDaemon { .. }, "stop_daemon", owner_only, none, true, none);
        ] }
    };
}

/// Which autocomplete surface a [`Request::RecordUsage`] belongs to.
/// Serializes to the `kind` column verbatim (`model` / `slash` / `tag`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageKind {
    Model,
    Slash,
    Tag,
}

impl UsageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Slash => "slash",
            Self::Tag => "tag",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LspControlAction {
    Check,
    Install,
    Uninstall,
    Restart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentPurpose {
    UserMessageImage,
    TerminalPasteImage { terminal_id: Uuid },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ActiveModelSwitchTrigger {
    Picker,
    Quick,
    Cycle,
    #[default]
    Daemon,
}
