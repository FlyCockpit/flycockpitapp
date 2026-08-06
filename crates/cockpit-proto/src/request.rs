use super::*;

fn deserialize_optional_nonempty_string<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    if value.as_ref().is_some_and(String::is_empty) {
        return Err(serde::de::Error::custom("string must not be empty"));
    }
    Ok(value)
}

fn deserialize_nonempty_string<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.is_empty() {
        return Err(serde::de::Error::custom("string must not be empty"));
    }
    Ok(value)
}

/// Client-owned immutable options attached to a `cockpit run` submission.
///
/// Presence of this object (including every field `None`) is the run marker
/// that creates a durable `RunInvocationState`. Fields are never defaulted by
/// the daemon; omitted bounds stay unbounded and omitted `approval_mode`
/// falls through to the session/default mode. `approval_mode` is client-owned
/// immutable input only — it never appears on daemon-owned state/version/
/// checkpoint fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunInvocationOptions {
    /// Maximum provider-dispatch reservations. `None` is unbounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_turns: Option<u32>,
    /// Wall/monotonic timeout budget in milliseconds from durable acceptance.
    /// `None` is unbounded. Zero is never treated as unbounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Invocation-scoped Manual/Auto/Yolo override. `None` uses the live
    /// session mode. Concurrent runs may carry different values; none mutate
    /// session approval state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_mode: Option<ApprovalMode>,
}

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
        /// Full model selection used to create a new session, or to recover a
        /// model-less existing session. Resume never overwrites an existing
        /// durable selection; intentional changes use `SetActiveModel` after
        /// attach.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        initial_model: Option<cockpit_config::config::providers::ActiveModelRef>,
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
        /// Plan-level model pin (prompt
        /// `plan-duplication-and-model-override.md`). The complete selection
        /// is also the new session's authoritative active model, while this
        /// field makes the same model override every spawned agent's
        /// frontmatter for the run. Ignored on resume of an existing session.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model_override: Option<cockpit_config::config::providers::ActiveModelRef>,
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
        /// Stable, client-generated identity for this exact submission. The
        /// daemon uses it as the queue item id and durable idempotency key, so
        /// a retry after an ambiguous response/socket loss cannot execute the
        /// message twice or reconcile the wrong optimistic transcript row.
        ///
        /// When `run_invocation_options` is present this UUID is also the
        /// daemon-global run invocation id (no parallel identity exists).
        client_submission_id: Uuid,
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
        /// Client-owned immutable bounds marker. Presence (even when both
        /// dimensions are `None`/unbounded) creates a durable run invocation
        /// keyed solely by `client_submission_id`. Non-run clients omit this
        /// field; `cockpit run` always sends `Some(...)`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        run_invocation_options: Option<RunInvocationOptions>,
    },

    /// Query durable run-invocation status by the canonical client submission
    /// id. Does not require an attached session.
    GetRunInvocationStatus {
        client_submission_id: Uuid,
    },

    /// Request cancellation of a run invocation by the same client submission
    /// id used at start. Idempotent compare-and-set; does not introduce a
    /// second cancellation identity.
    CancelRunInvocation {
        client_submission_id: Uuid,
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

    PinMessage {
        session_id: Uuid,
        seq: i64,
    },
    UnpinMessage {
        session_id: Uuid,
        seq: i64,
    },
    TogglePinnedMessage {
        session_id: Uuid,
        seq: i64,
    },
    CountPinnedMessages {
        session_id: Uuid,
    },
    ListPinnedMessageSeqs {
        session_id: Uuid,
    },
    ListPinnedMessagesWithText {
        session_id: Uuid,
    },
    PinnedMessageState {
        session_id: Uuid,
    },
    ListSealedValues {
        session_id: Uuid,
    },
    DeleteSealedValue {
        session_id: Uuid,
        value_id: String,
    },

    ListProjectNotes {
        project_root: String,
    },
    CreateProjectNote {
        project_root: String,
        name: String,
    },
    SetProjectNoteContent {
        project_root: String,
        id: Uuid,
        content: String,
    },
    RenameProjectNote {
        project_root: String,
        id: Uuid,
        name: String,
    },
    DeleteProjectNote {
        project_root: String,
        id: Uuid,
    },

    /// List persisted assistant definitions.
    ListAssistants,

    UpsertAssistant {
        name: String,
        home_dir: String,
        config_json: String,
        content_hash: String,
    },

    /// Create a new assistant session through the daemon registry. The
    /// session is deferred and is not persisted until its first user message.
    CreateAssistantSession {
        name: String,
        project_root: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        initial_model: Option<cockpit_config::config::providers::ActiveModelRef>,
        #[serde(default)]
        no_sandbox: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        env_snapshot: Option<EnvSnapshotWire>,
    },

    /// Generate and persist a title for an untitled session.
    AutoTitle {
        session_id: Uuid,
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

    // Import a ZIP archive through the daemon-owned database writer.
    ImportSessionArchive {
        archive_base64: String,
        #[serde(default)]
        as_new: bool,
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

    /// Read a paginated page of full transcript history for a session.
    /// `before_seq = None` reads the newest page; `Some(seq)` reads older
    /// events with `seq < before_seq`. The daemon clamps `limit`.
    ReadHistoryPage {
        session_id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        before_seq: Option<i64>,
        limit: u32,
    },

    /// Read a paginated page of full transcript history for one subagent
    /// lineage inside a session.
    /// `before_seq = None` reads the newest page; `Some(seq)` reads older
    /// events with `seq < before_seq`. The daemon clamps `limit`.
    ReadSubagentHistoryPage {
        session_id: Uuid,
        task_call_id: String,
        label: String,
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

    /// Drop a session and its complete descendant fork subtree. SQLite
    /// owns the cascading relationship and all session-owned rows.
    DeleteSession {
        session_id: Uuid,
    },

    /// Return one atomic agents/models/skills inventory bundle for the
    /// selected session and agent from a single daemon snapshot.
    GetInventoryBundle {
        project_root: String,
        session_id: Uuid,
        selected_agent: String,
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

    /// Set or clear one configured model’s favorite flag. The daemon validates
    /// the model, owns the config write, then broadcasts a fresh config snapshot.
    SetModelFavorite {
        provider: String,
        model: String,
        favorite: bool,
    },

    /// Replace the effective default model for new sessions in the attached
    /// client's configuration context. Local-owner-only; does not switch the
    /// live session. Callers cannot supply an arbitrary filesystem target.
    SetDefaultModel {
        default_update_id: Uuid,
        /// Absent exactly when `clear` is set. A clear carries no reference,
        /// so an empty-string placeholder would be rejected by the
        /// non-empty-string contract every other model field uses.
        #[serde(
            default,
            deserialize_with = "deserialize_optional_nonempty_string",
            skip_serializing_if = "Option::is_none"
        )]
        provider: Option<String>,
        #[serde(
            default,
            deserialize_with = "deserialize_optional_nonempty_string",
            skip_serializing_if = "Option::is_none"
        )]
        model: Option<String>,
        #[serde(
            default,
            deserialize_with = "deserialize_optional_nonempty_string",
            skip_serializing_if = "Option::is_none"
        )]
        reasoning_effort: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        thinking_mode: Option<cockpit_config::config::providers::ThinkingMode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prompt_cache_retention: Option<PromptCacheRetention>,
        /// When true, clear the context default instead of writing `provider/model`.
        /// The resulting reloaded effective configuration must still resolve to a
        /// deterministic inherited default or explicit no-default state.
        #[serde(default)]
        clear: bool,
    },

    /// Switch the attached session to a different model.
    SetActiveModel {
        selection_id: Uuid,
        #[serde(deserialize_with = "deserialize_nonempty_string")]
        provider: String,
        #[serde(deserialize_with = "deserialize_nonempty_string")]
        model: String,
        /// Persist this model as the resolution default after the live session
        /// switch commits. Session-only selection must not modify config.
        persist_as_default: bool,
        /// Establish this selection as the default only if the daemon still
        /// has no configured default at commit time. This is distinct from an
        /// explicit default replacement and prevents stale clients from
        /// overwriting a concurrently-added default.
        #[serde(default)]
        trigger: ActiveModelSwitchTrigger,
        #[serde(
            default,
            deserialize_with = "deserialize_optional_nonempty_string",
            skip_serializing_if = "Option::is_none"
        )]
        reasoning_effort: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        thinking_mode: Option<cockpit_config::config::providers::ThinkingMode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prompt_cache_retention: Option<PromptCacheRetention>,
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

    /// Replace the attached session's tool-surface override and rebuild the
    /// root agent at the next idle/control boundary. The payload is serialized
    /// `agents::ToolSurfaceSelection`; kept JSON here so the wire crate does
    /// not depend on the core agent-definition crate.
    SetToolSurfaceOverride {
        override_json: String,
        #[serde(default = "default_true")]
        persist_session: bool,
        #[serde(default)]
        prune_after_switch: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        monty_nudge: Option<String>,
    },

    /// Replace or clear the attached session's goal-verification override.
    /// The payload is serialized goal-settings JSON; kept opaque here so the
    /// wire crate does not depend on core agent definitions.
    SetGoalSettingsOverride {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        override_json: Option<String>,
        #[serde(default = "default_true")]
        persist_session: bool,
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
    /// on restart. Returns the resulting [`Response::PreflightState`] and broadcasts
    /// [`Event::PreflightState`].
    SetPreflight {
        #[serde(default)]
        enabled: Option<bool>,
    },

    /// Set (or toggle) extended prompt-cache retention intent for the attached
    /// session (`/longcache`). Session-only; the driver re-resolves support
    /// against the active model's curated capability before sending a wire key. Returns the effective [`Response::LongcacheState`].
    SetLongcache {
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

    /// Atomically request daemon restart only if no session worker is busy.
    RestartIfIdle,

    #[serde(other)]
    Unknown,
}

impl Request {
    /// Validate semantic invariants independently of Serde.
    ///
    /// Requests carried over an in-process transport are already typed and do
    /// not pass through deserialization. The daemon calls this before
    /// authorization or dispatch so those requests cannot bypass the strict
    /// protocol-v6 active-model contract.
    pub fn validate_semantics(&self) -> std::result::Result<(), String> {
        fn validate_selection(
            field: &str,
            selection: &cockpit_config::config::providers::ActiveModelRef,
        ) -> std::result::Result<(), String> {
            selection
                .validate()
                .map_err(|error| format!("{field}: {error}"))
        }

        match self {
            Self::Attach {
                initial_model,
                model_override,
                ..
            } => {
                if let Some(selection) = initial_model {
                    validate_selection("initial_model", selection)?;
                }
                if let Some(selection) = model_override {
                    validate_selection("model_override", selection)?;
                }
            }
            Self::CreateAssistantSession {
                initial_model: Some(selection),
                ..
            } => validate_selection("initial_model", selection)?,
            Self::SetModelFavorite {
                provider, model, ..
            } => {
                if provider.is_empty() {
                    return Err("provider must not be empty".to_string());
                }
                if model.is_empty() {
                    return Err("model must not be empty".to_string());
                }
            }
            Self::SetDefaultModel {
                provider,
                model,
                reasoning_effort,
                clear,
                default_update_id,
                ..
            } => {
                if default_update_id.is_nil() {
                    return Err("default_update_id must not be nil".to_string());
                }
                // The reference and the clear flag are mutually exclusive, and
                // exactly one of them must be present.
                if *clear {
                    if provider.is_some() || model.is_some() {
                        return Err("clear must not be combined with provider/model".to_string());
                    }
                } else {
                    if provider.is_none() {
                        return Err("provider is required unless clear is set".to_string());
                    }
                    if model.is_none() {
                        return Err("model is required unless clear is set".to_string());
                    }
                }
                if reasoning_effort.as_ref().is_some_and(String::is_empty) {
                    return Err("reasoning_effort must not be empty".to_string());
                }
            }
            Self::SetActiveModel {
                provider,
                model,
                reasoning_effort,
                ..
            } => {
                if provider.is_empty() {
                    return Err("provider must not be empty".to_string());
                }
                if model.is_empty() {
                    return Err("model must not be empty".to_string());
                }
                if reasoning_effort.as_ref().is_some_and(String::is_empty) {
                    return Err("reasoning_effort must not be empty".to_string());
                }
            }
            Self::SendUserMessage {
                client_submission_id,
                run_invocation_options,
                ..
            } => {
                if client_submission_id.is_nil() {
                    return Err("client_submission_id must not be nil".to_string());
                }
                if let Some(options) = run_invocation_options {
                    if options.max_turns == Some(0) {
                        return Err("run_invocation_options.max_turns must not be zero".to_string());
                    }
                    if options.timeout_ms == Some(0) {
                        return Err(
                            "run_invocation_options.timeout_ms must not be zero".to_string()
                        );
                    }
                }
            }
            Self::GetRunInvocationStatus {
                client_submission_id,
            }
            | Self::CancelRunInvocation {
                client_submission_id,
            } if client_submission_id.is_nil() => {
                return Err("client_submission_id must not be nil".to_string());
            }
            _ => {}
        }
        Ok(())
    }
}
#[macro_export]
macro_rules! request_variants {
    ($with_variants:ident $(, $context:ident)*) => {
        $with_variants! { ($($context),*) [
            (Request::Attach { .. }, "attach");
            (Request::SubagentTranscript { .. }, "subagent_transcript");
            (Request::SendUserMessage { .. }, "send_user_message");
            (Request::GetRunInvocationStatus { .. }, "get_run_invocation_status");
            (Request::CancelRunInvocation { .. }, "cancel_run_invocation");
            (Request::SteerDelegation { .. }, "steer_delegation");
            (Request::BeginAttachmentUpload { .. }, "begin_attachment_upload");
            (Request::UploadAttachmentChunk { .. }, "upload_attachment_chunk");
            (Request::FinishAttachmentUpload { .. }, "finish_attachment_upload");
            (Request::CancelAttachmentUpload { .. }, "cancel_attachment_upload");
            (Request::RemoveQueuedUserMessage { .. }, "remove_queued_user_message");
            (Request::RemoveNewestQueuedUserMessage { .. }, "remove_newest_queued_user_message");
            (Request::RemoveEditableQueuedUserMessages { .. }, "remove_editable_queued_user_messages");
            (Request::ResumePausedWork { .. }, "resume_paused_work");
            (Request::CancelPausedWork { .. }, "cancel_paused_work");
            (Request::RepairResume { .. }, "repair_resume");
            (Request::GoalStatus { .. }, "goal_status");
            (Request::SetGoalStatus { .. }, "set_goal_status");
            (Request::ClearGoal { .. }, "clear_goal");
            (Request::PinMessage { .. }, "pin_message");
            (Request::UnpinMessage { .. }, "unpin_message");
            (Request::TogglePinnedMessage { .. }, "toggle_pinned_message");
            (Request::CountPinnedMessages { .. }, "count_pinned_messages");
            (Request::ListPinnedMessageSeqs { .. }, "list_pinned_message_seqs");
            (Request::ListPinnedMessagesWithText { .. }, "list_pinned_messages_with_text");
            (Request::PinnedMessageState { .. }, "pinned_message_state");
            (Request::ListSealedValues { .. }, "list_sealed_values");
            (Request::DeleteSealedValue { .. }, "delete_sealed_value");
            (Request::ListProjectNotes { .. }, "list_project_notes");
            (Request::CreateProjectNote { .. }, "create_project_note");
            (Request::SetProjectNoteContent { .. }, "set_project_note_content");
            (Request::RenameProjectNote { .. }, "rename_project_note");
            (Request::DeleteProjectNote { .. }, "delete_project_note");
            (Request::ListAssistants, "list_assistants");
            (Request::UpsertAssistant { .. }, "upsert_assistant");
            (Request::CreateAssistantSession { .. }, "create_assistant_session");
            (Request::AutoTitle { .. }, "auto_title");
            (Request::ExportSessionData { .. }, "export_session_data");
            (Request::ImportSessionArchive { .. }, "import_session_archive");
            (Request::Curator { .. }, "curator");
            (Request::CancelTurn, "cancel_turn");
            (Request::FsList { .. }, "fs_list");
            (Request::FsStat { .. }, "fs_stat");
            (Request::FsRead { .. }, "fs_read");
            (Request::FsWrite { .. }, "fs_write");
            (Request::FsCreateDir { .. }, "fs_create_dir");
            (Request::FsRename { .. }, "fs_rename");
            (Request::FsDelete { .. }, "fs_delete");
            (Request::GitStatus { .. }, "git_status");
            (Request::GitDiffFile { .. }, "git_diff_file");
            (Request::OpenTerminal { .. }, "open_terminal");
            (Request::AttachTerminal { .. }, "attach_terminal");
            (Request::TerminalInput { .. }, "terminal_input");
            (Request::TerminalResize { .. }, "terminal_resize");
            (Request::CloseTerminal { .. }, "close_terminal");
            (Request::LspControl { .. }, "lsp_control");
            (Request::ResolveInterrupt { .. }, "resolve_interrupt");
            (Request::ListSessions { .. }, "list_sessions");
            (Request::ReadSessionMessages { .. }, "read_session_messages");
            (Request::ReadHistoryPage { .. }, "read_history_page");
            (Request::ReadSubagentHistoryPage { .. }, "read_subagent_history_page");
            (Request::SessionLiveStatus { .. }, "session_live_status");
            (Request::ArchiveSession { .. }, "archive_session");
            (Request::UnarchiveSession { .. }, "unarchive_session");
            (Request::ForkSession { .. }, "fork_session");
            (Request::DiscardSession { .. }, "discard_session");
            (Request::CreateBtwFork { .. }, "create_btw_fork");
            (Request::EndBtwFork { .. }, "end_btw_fork");
            (Request::RenameSession { .. }, "rename_session");
            (Request::ShareSession { .. }, "share_session");
            (Request::RecordSessionNote { .. }, "record_session_note");
            (Request::DeleteSession { .. }, "delete_session");
            (Request::GetInventoryBundle { .. }, "get_inventory_bundle");
            (Request::ResourceSnapshot, "resource_snapshot");
            (Request::PromoteResource { .. }, "promote_resource");
            (Request::CreateScheduledJob { .. }, "create_scheduled_job");
            (Request::ListScheduledJobs { .. }, "list_scheduled_jobs");
            (Request::DeleteScheduledJob { .. }, "delete_scheduled_job");
            (Request::SetScheduledJobEnabled { .. }, "set_scheduled_job_enabled");
            (Request::RunScheduledJob { .. }, "run_scheduled_job");
            (Request::SetModelFavorite { .. }, "set_model_favorite");
            (Request::SetDefaultModel { .. }, "set_default_model");
            (Request::SetActiveModel { .. }, "set_active_model");
            (Request::SetAgent { .. }, "set_agent");
            (Request::SetLlmMode { .. }, "set_llm_mode");
            (Request::SetSessionLlmMode { .. }, "set_session_llm_mode");
            (Request::SetToolSurfaceOverride { .. }, "set_tool_surface_override");
            (Request::SetGoalSettingsOverride { .. }, "set_goal_settings_override");
            (Request::SetApprovalMode { .. }, "set_approval_mode");
            (Request::SetDelegationRecursion { .. }, "set_delegation_recursion");
            (Request::SetSandbox { .. }, "set_sandbox");
            (Request::SetSandboxEscalation { .. }, "set_sandbox_escalation");
            (Request::SetPreflight { .. }, "set_preflight");
            (Request::SetLongcache { .. }, "set_longcache");
            (Request::SetRedaction { .. }, "set_redaction");
            (Request::SetTandemModels { .. }, "set_tandem_models");
            (Request::SetCaffeinate { .. }, "set_caffeinate");
            (Request::CancelSchedule { .. }, "cancel_schedule");
            (Request::Prune, "prune");
            (Request::Compact, "compact");
            (Request::Pin { .. }, "pin");
            (Request::StoreFlycockpitCredential { .. }, "store_flycockpit_credential");
            (Request::ClearFlycockpitCredential, "clear_flycockpit_credential");
            (Request::DaemonStatus, "daemon_status");
            (Request::RefreshEnv { .. }, "refresh_env");
            (Request::RefreshConfig, "refresh_config");
            (Request::RecordUsage { .. }, "record_usage");
            (Request::GetUsageCounts { .. }, "get_usage_counts");
            (Request::StatsRollup { .. }, "stats_rollup");
            (Request::GuidanceEstimate { .. }, "guidance_estimate");
            (Request::StopDaemon { .. }, "stop_daemon");
            (Request::RestartIfIdle, "restart_if_idle");
            (Request::Unknown, "__unknown");
        ] }
    };
}

impl Request {
    pub fn wire_tag(&self) -> &'static str {
        macro_rules! wire_tag {
            (($($context:ident),*) [$(($pattern:pat, $tag:expr);)+]) => {
                match self {
                    $($pattern => $tag,)+
                }
            };
        }
        request_variants!(wire_tag)
    }
}

// Keep daemon command metadata centralized. Callers provide a local callback
// macro so each module can expand the same exhaustive Request table into the
// shape it needs without changing Request's serde representation.
#[macro_export]
macro_rules! command {
    ($with_commands:ident $(, $context:ident)*) => {
        $with_commands! { ($($context),*) [
            (Request::Attach { session_id, .. }, "attach", custom(authorize_attach), option_field(session_id), true, serialized, none);
            (Request::SubagentTranscript { session_id, .. }, "subagent_transcript", custom(authorize_subagent_transcript), field(session_id), false, concurrent, none);
            (Request::SendUserMessage { .. }, "send_user_message", session_writer, attached, true, serialized, none);
            (Request::GetRunInvocationStatus { .. }, "get_run_invocation_status", public_read, none, false, concurrent, none);
            (Request::CancelRunInvocation { .. }, "cancel_run_invocation", public_read, none, true, serialized, none);
            (Request::SteerDelegation { session_id, .. }, "steer_delegation", custom(authorize_steer_delegation), field(session_id), true, serialized, none);
            (Request::BeginAttachmentUpload { .. }, "begin_attachment_upload", custom(authorize_begin_attachment_upload), attached, true, serialized, none);
            (Request::UploadAttachmentChunk { .. }, "upload_attachment_chunk", custom(authorize_attachment_upload_step), attached, true, serialized, none);
            (Request::FinishAttachmentUpload { .. }, "finish_attachment_upload", custom(authorize_attachment_upload_step), attached, true, serialized, none);
            (Request::CancelAttachmentUpload { .. }, "cancel_attachment_upload", custom(authorize_attachment_upload_step), attached, true, serialized, none);
            (Request::RemoveQueuedUserMessage { .. }, "remove_queued_user_message", session_writer, attached, true, serialized, none);
            (Request::RemoveNewestQueuedUserMessage { .. }, "remove_newest_queued_user_message", session_writer, attached, true, serialized, none);
            (Request::RemoveEditableQueuedUserMessages { .. }, "remove_editable_queued_user_messages", session_writer, attached, true, serialized, none);
            (Request::ResumePausedWork { session_id }, "resume_paused_work", session_row_writer(session_id), field(session_id), true, serialized, none);
            (Request::CancelPausedWork { session_id }, "cancel_paused_work", session_row_writer(session_id), field(session_id), true, serialized, none);
            (Request::RepairResume { session_id }, "repair_resume", session_writer, field(session_id), true, serialized, none);
            (Request::GoalStatus { session_id }, "goal_status", session_row_reader(session_id), field(session_id), false, serialized, none);
            (Request::SetGoalStatus { session_id, .. }, "set_goal_status", session_row_writer(session_id), field(session_id), true, serialized, none);
            (Request::ClearGoal { session_id }, "clear_goal", session_row_writer(session_id), field(session_id), true, serialized, none);
            (Request::PinMessage { session_id, .. }, "pin_message", session_row_writer(session_id), field(session_id), true, serialized, none);
            (Request::UnpinMessage { session_id, .. }, "unpin_message", session_row_writer(session_id), field(session_id), true, serialized, none);
            (Request::TogglePinnedMessage { session_id, .. }, "toggle_pinned_message", session_row_writer(session_id), field(session_id), true, serialized, none);
            (Request::CountPinnedMessages { session_id }, "count_pinned_messages", session_row_reader(session_id), field(session_id), false, concurrent, none);
            (Request::ListPinnedMessageSeqs { session_id }, "list_pinned_message_seqs", session_row_reader(session_id), field(session_id), false, concurrent, none);
            (Request::ListPinnedMessagesWithText { session_id }, "list_pinned_messages_with_text", session_row_reader(session_id), field(session_id), false, concurrent, none);
            (Request::PinnedMessageState { session_id }, "pinned_message_state", session_row_reader(session_id), field(session_id), false, concurrent, none);
            (Request::ListSealedValues { session_id }, "list_sealed_values", owner_only, field(session_id), false, concurrent, none);
            (Request::DeleteSealedValue { session_id, .. }, "delete_sealed_value", owner_only, field(session_id), true, serialized, none);
            (Request::ListProjectNotes { project_root }, "list_project_notes", owner_only, none, true, serialized, path(project_root));
            (Request::CreateProjectNote { project_root, .. }, "create_project_note", owner_only, none, true, serialized, path(project_root));
            (Request::SetProjectNoteContent { project_root, .. }, "set_project_note_content", owner_only, none, true, serialized, path(project_root));
            (Request::RenameProjectNote { project_root, .. }, "rename_project_note", owner_only, none, true, serialized, path(project_root));
            (Request::DeleteProjectNote { project_root, .. }, "delete_project_note", owner_only, none, true, serialized, path(project_root));
            (Request::ListAssistants, "list_assistants", owner_only, none, false, concurrent, none);
            (Request::UpsertAssistant { .. }, "upsert_assistant", owner_only, none, true, serialized, none);
            (Request::CreateAssistantSession { .. }, "create_assistant_session", owner_only, none, true, serialized, none);
            (Request::AutoTitle { session_id }, "auto_title", session_row_writer(session_id), field(session_id), true, serialized, none);
            (Request::ExportSessionData { session_id, .. }, "export_session_data", owner_only, field(session_id), false, concurrent, none);
            (Request::ImportSessionArchive { .. }, "import_session_archive", owner_only, none, true, serialized, none);
            (Request::Curator { project_root, .. }, "curator", owner_only, none, true, serialized, path(project_root));
            (Request::CancelTurn, "cancel_turn", session_writer, attached, true, serialized, none);
            (Request::FsList { project_root, .. }, "fs_list", project_files(project_root), none, false, concurrent, none);
            (Request::FsStat { project_root, .. }, "fs_stat", project_files(project_root), none, false, concurrent, none);
            (Request::FsRead { project_root, .. }, "fs_read", project_files(project_root), none, false, concurrent, none);
            (Request::FsWrite { project_root, path, .. }, "fs_write", project_files(project_root), none, true, serialized, path(path));
            (Request::FsCreateDir { project_root, path }, "fs_create_dir", project_files(project_root), none, true, serialized, path(path));
            (Request::FsRename { project_root, from_path, to_path }, "fs_rename", project_files(project_root), none, true, serialized, rename(from_path, to_path));
            (Request::FsDelete { path, .. }, "fs_delete", owner_only, none, true, serialized, path(path));
            (Request::GitStatus { project_root }, "git_status", project_files(project_root), none, false, concurrent, none);
            (Request::GitDiffFile { project_root, path }, "git_diff_file", project_files(project_root), none, false, concurrent, path(path));
            (Request::OpenTerminal { .. }, "open_terminal", terminal, none, true, serialized, none);
            (Request::AttachTerminal { .. }, "attach_terminal", terminal, none, false, serialized, none);
            (Request::TerminalInput { .. }, "terminal_input", terminal, none, false, serialized, none);
            (Request::TerminalResize { .. }, "terminal_resize", terminal, none, false, serialized, none);
            (Request::CloseTerminal { .. }, "close_terminal", terminal, none, true, serialized, none);
            (Request::LspControl { .. }, "lsp_control", custom(authorize_lsp_control), attached, true, serialized, none);
            (Request::ResolveInterrupt { .. }, "resolve_interrupt", session_writer, attached, true, serialized, none);
            (Request::ListSessions { .. }, "list_sessions", public_read, none, false, concurrent, none);
            (Request::ReadSessionMessages { session_id, .. }, "read_session_messages", custom(authorize_read_session_messages), field(session_id), false, concurrent, none);
            (Request::ReadHistoryPage { session_id, .. }, "read_history_page", custom(authorize_read_history_page), field(session_id), false, concurrent, none);
            (Request::ReadSubagentHistoryPage { session_id, .. }, "read_subagent_history_page", custom(authorize_read_subagent_history_page), field(session_id), false, concurrent, none);
            (Request::SessionLiveStatus { .. }, "session_live_status", public_read, none, false, concurrent, none);
            (Request::ArchiveSession { session_id, .. }, "archive_session", session_row_writer(session_id), field(session_id), true, serialized, none);
            (Request::UnarchiveSession { session_id }, "unarchive_session", session_row_writer(session_id), field(session_id), true, serialized, none);
            (Request::ForkSession { parent_session_id, .. }, "fork_session", session_row_writer(parent_session_id), field(parent_session_id), true, serialized, none);
            (Request::DiscardSession { session_id }, "discard_session", session_row_writer(session_id), field(session_id), true, serialized, none);
            (Request::CreateBtwFork { parent_session_id, .. }, "btw_create", session_row_writer(parent_session_id), field(parent_session_id), true, serialized, none);
            (Request::EndBtwFork { parent_session_id }, "btw_end", session_row_writer(parent_session_id), field(parent_session_id), true, serialized, none);
            (Request::RenameSession { session_id, .. }, "rename_session", session_row_writer(session_id), field(session_id), true, serialized, none);
            (Request::ShareSession { session_id, .. }, "share_session", owner_only, field(session_id), true, serialized, none);
            (Request::RecordSessionNote { session_id, .. }, "record_session_note", session_row_writer(session_id), field(session_id), true, serialized, none);
            (Request::DeleteSession { session_id, .. }, "delete_session", session_row_writer(session_id), field(session_id), true, serialized, none);
            (Request::GetInventoryBundle { session_id, project_root, .. }, "get_inventory_bundle", session_row_reader(session_id), field(session_id), false, concurrent, path(project_root));
            (Request::ResourceSnapshot, "resource_snapshot", owner_only, none, false, concurrent, none);
            (Request::PromoteResource { session_id, .. }, "promote_resource", owner_only, option_field(session_id), true, serialized, none);
            (Request::CreateScheduledJob { .. }, "create_scheduled_job", owner_only, none, true, serialized, none);
            (Request::ListScheduledJobs { .. }, "list_scheduled_jobs", owner_only, none, false, concurrent, none);
            (Request::DeleteScheduledJob { .. }, "delete_scheduled_job", owner_only, none, true, serialized, none);
            (Request::SetScheduledJobEnabled { .. }, "set_scheduled_job_enabled", owner_only, none, true, serialized, none);
            (Request::RunScheduledJob { .. }, "run_scheduled_job", owner_only, none, true, serialized, none);
            (Request::SetModelFavorite { .. }, "set_model_favorite", owner_only, attached, true, serialized, none);
            (Request::SetDefaultModel { .. }, "set_default_model", owner_only, attached, true, serialized, none);
            (Request::SetActiveModel { .. }, "set_active_model", custom(authorize_set_active_model), attached, true, serialized, none);
            (Request::SetAgent { .. }, "set_agent", session_writer, attached, true, serialized, none);
            (Request::SetLlmMode { .. }, "set_llm_mode", session_writer, attached, true, serialized, none);
            (Request::SetSessionLlmMode { .. }, "set_session_llm_mode", session_writer, attached, true, serialized, none);
            (Request::SetToolSurfaceOverride { .. }, "set_tool_surface_override", session_writer, attached, true, serialized, none);
            (Request::SetGoalSettingsOverride { .. }, "set_goal_settings_override", session_writer, attached, true, serialized, none);
            (Request::SetApprovalMode { .. }, "set_approval_mode", session_writer, attached, true, serialized, none);
            (Request::SetDelegationRecursion { .. }, "set_delegation_recursion", session_writer, attached, true, serialized, none);
            (Request::SetSandbox { .. }, "set_sandbox", session_writer, attached, true, serialized, none);
            (Request::SetSandboxEscalation { .. }, "set_sandbox_escalation", session_writer, attached, true, serialized, none);
            (Request::SetPreflight { .. }, "set_preflight", session_writer, attached, true, serialized, none);
            (Request::SetLongcache { .. }, "set_longcache", session_writer, attached, true, serialized, none);
            (Request::SetRedaction { .. }, "set_redaction", session_writer, attached, true, serialized, none);
            (Request::SetTandemModels { .. }, "set_tandem_models", session_writer, attached, true, serialized, none);
            (Request::SetCaffeinate { .. }, "set_caffeinate", owner_only, none, true, serialized, none);
            (Request::CancelSchedule { .. }, "cancel_schedule", session_writer, attached, true, serialized, none);
            (Request::Prune, "prune", session_writer, attached, true, serialized, none);
            (Request::Compact, "compact", session_writer, attached, true, serialized, none);
            (Request::Pin { .. }, "pin", session_writer, attached, true, serialized, none);
            (Request::StoreFlycockpitCredential { .. }, "store_flycockpit_credential", owner_only, none, true, serialized, none);
            (Request::ClearFlycockpitCredential, "clear_flycockpit_credential", owner_only, none, true, serialized, none);
            (Request::DaemonStatus, "daemon_status", public_read, none, false, concurrent, none);
            (Request::RefreshEnv { .. }, "refresh_env", session_writer, attached, true, serialized, none);
            (Request::RefreshConfig, "refresh_config", session_writer, attached, true, serialized, none);
            (Request::RecordUsage { .. }, "record_usage", owner_only, none, true, serialized, none);
            (Request::GetUsageCounts { .. }, "get_usage_counts", owner_only, none, false, concurrent, none);
            (Request::StatsRollup { .. }, "stats_rollup", owner_only, none, false, concurrent, none);
            (Request::GuidanceEstimate { project_root, .. }, "guidance_estimate", project_read(project_root), none, false, concurrent, none);
            (Request::StopDaemon { .. }, "stop_daemon", owner_only, none, true, serialized, none);
            (Request::RestartIfIdle, "restart_if_idle", owner_only, none, true, serialized, none);
            (Request::Unknown, "unknown", owner_only, none, false, serialized, none);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn active_model(
        provider: &str,
        model: &str,
        reasoning_effort: Option<&str>,
    ) -> cockpit_config::config::providers::ActiveModelRef {
        cockpit_config::config::providers::ActiveModelRef {
            provider: provider.to_string(),
            model: model.to_string(),
            reasoning_effort: reasoning_effort.map(|value| {
                cockpit_config::config::providers::ActiveReasoningEffort {
                    value: value.to_string(),
                }
            }),
            thinking_mode: None,
            prompt_cache_retention: None,
        }
    }

    #[test]
    fn semantic_validation_covers_every_active_model_request_shape() {
        let invalid = active_model("", "model", None);
        let requests = [
            Request::Attach {
                session_id: None,
                since_seq: None,
                project_root: None,
                initial_model: Some(invalid.clone()),
                no_sandbox: false,
                interactive: false,
                model_override: None,
                client_protocol_version: PROTOCOL_VERSION,
                env_snapshot: None,
                env_policy: EnvDriftPolicy::Daemon,
            },
            Request::Attach {
                session_id: None,
                since_seq: None,
                project_root: None,
                initial_model: None,
                no_sandbox: false,
                interactive: false,
                model_override: Some(invalid.clone()),
                client_protocol_version: PROTOCOL_VERSION,
                env_snapshot: None,
                env_policy: EnvDriftPolicy::Daemon,
            },
            Request::CreateAssistantSession {
                name: "assistant".to_string(),
                project_root: "/repo".to_string(),
                initial_model: Some(invalid),
                no_sandbox: false,
                env_snapshot: None,
            },
            Request::SetModelFavorite {
                provider: "provider".to_string(),
                model: String::new(),
                favorite: true,
            },
            Request::SetActiveModel {
                selection_id: Uuid::nil(),
                provider: "provider".to_string(),
                model: "model".to_string(),
                persist_as_default: false,
                trigger: ActiveModelSwitchTrigger::Picker,
                reasoning_effort: Some(String::new()),
                thinking_mode: None,
                prompt_cache_retention: None,
            },
        ];

        for request in requests {
            assert!(
                request.validate_semantics().is_err(),
                "{} accepted an invalid typed active-model value",
                request.wire_tag()
            );
        }

        let valid = Request::SetActiveModel {
            selection_id: Uuid::nil(),
            provider: "provider".to_string(),
            model: "model".to_string(),
            persist_as_default: false,
            trigger: ActiveModelSwitchTrigger::Picker,
            reasoning_effort: Some("high".to_string()),
            thinking_mode: None,
            prompt_cache_retention: None,
        };
        valid
            .validate_semantics()
            .expect("complete active-model request should validate");
    }

    #[test]
    fn semantic_validation_rejects_ambiguous_model_flags_and_nil_submission_id() {
        let nil_submission = Request::SendUserMessage {
            client_submission_id: Uuid::nil(),
            text: "hello".to_string(),
            display_text: None,
            tag_expansions: Vec::new(),
            image_refs: Vec::new(),
            forced_skill: None,
            run_invocation_options: None,
        };
        assert_eq!(
            nil_submission.validate_semantics().unwrap_err(),
            "client_submission_id must not be nil"
        );
    }

    macro_rules! command_tags {
        (($($context:ident),*) [$(($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?);)+]) => {{
            vec![$($tag),+]
        }};
    }

    #[test]
    fn pin_rpcs_are_registered_in_both_macro_tables() {
        let session_id = Uuid::nil();
        let requests = [
            Request::PinMessage { session_id, seq: 1 },
            Request::UnpinMessage { session_id, seq: 1 },
            Request::TogglePinnedMessage { session_id, seq: 1 },
            Request::CountPinnedMessages { session_id },
            Request::ListPinnedMessageSeqs { session_id },
            Request::ListPinnedMessagesWithText { session_id },
            Request::PinnedMessageState { session_id },
        ];
        let tags: Vec<_> = requests.iter().map(Request::wire_tag).collect();
        assert_eq!(
            tags,
            vec![
                "pin_message",
                "unpin_message",
                "toggle_pinned_message",
                "count_pinned_messages",
                "list_pinned_message_seqs",
                "list_pinned_messages_with_text",
                "pinned_message_state",
            ]
        );
        let command_tags = crate::command!(command_tags);
        for tag in tags {
            assert!(command_tags.contains(&tag), "missing command row for {tag}");
        }
    }

    #[test]
    fn project_note_rpcs_are_registered_in_both_macro_tables() {
        let id = Uuid::nil();
        let requests = [
            Request::ListProjectNotes {
                project_root: "/repo".into(),
            },
            Request::CreateProjectNote {
                project_root: "/repo".into(),
                name: "n".into(),
            },
            Request::SetProjectNoteContent {
                project_root: "/repo".into(),
                id,
                content: "c".into(),
            },
            Request::RenameProjectNote {
                project_root: "/repo".into(),
                id,
                name: "n".into(),
            },
            Request::DeleteProjectNote {
                project_root: "/repo".into(),
                id,
            },
        ];
        let tags: Vec<_> = requests.iter().map(Request::wire_tag).collect();
        assert_eq!(
            tags,
            vec![
                "list_project_notes",
                "create_project_note",
                "set_project_note_content",
                "rename_project_note",
                "delete_project_note"
            ]
        );
        let command_tags = crate::command!(command_tags);
        for tag in tags {
            assert!(command_tags.contains(&tag), "missing command row for {tag}");
        }
    }

    #[test]
    fn upsert_assistant_rpc_is_registered_in_both_macro_tables() {
        let request = Request::UpsertAssistant {
            name: "a".into(),
            home_dir: "/a".into(),
            config_json: "{}".into(),
            content_hash: "h".into(),
        };
        assert_eq!(request.wire_tag(), "upsert_assistant");
        assert!(crate::command!(command_tags).contains(&request.wire_tag()));
    }

    #[test]
    fn sealed_value_rpcs_are_registered_in_both_macro_tables() {
        let session_id = Uuid::nil();
        let requests = [
            Request::ListSealedValues { session_id },
            Request::DeleteSealedValue {
                session_id,
                value_id: "prod_token".into(),
            },
        ];
        let tags: Vec<_> = requests.iter().map(Request::wire_tag).collect();
        assert_eq!(tags, ["list_sealed_values", "delete_sealed_value"]);
        let command_tags = crate::command!(command_tags);
        for tag in tags {
            assert!(command_tags.contains(&tag), "missing command row for {tag}");
        }
    }

    #[test]
    fn run_invocation_options_protocol() {
        let id = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
        let unbounded = RunInvocationOptions::default();
        let bounded = RunInvocationOptions {
            max_turns: Some(3),
            timeout_ms: Some(60_000),
            approval_mode: None,
        };

        let send = Request::SendUserMessage {
            client_submission_id: id,
            text: "run me".into(),
            display_text: None,
            tag_expansions: Vec::new(),
            image_refs: Vec::new(),
            forced_skill: None,
            run_invocation_options: Some(unbounded.clone()),
        };
        let json = serde_json::to_value(&send).unwrap();
        assert_eq!(json["request"], "send_user_message");
        assert_eq!(json["params"]["client_submission_id"], id.to_string());
        // Empty options object is the run marker; absent dimensions omit/null.
        assert_eq!(
            json["params"]["run_invocation_options"],
            serde_json::json!({})
        );
        assert!(json["params"].get("invocation_id").is_none());
        assert!(json["params"].get("state_version").is_none());
        assert!(json["params"].get("remaining_ms").is_none());

        let bounded_send = Request::SendUserMessage {
            client_submission_id: id,
            text: "run me".into(),
            display_text: None,
            tag_expansions: Vec::new(),
            image_refs: Vec::new(),
            forced_skill: None,
            run_invocation_options: Some(bounded.clone()),
        };
        let bounded_json = serde_json::to_value(&bounded_send).unwrap();
        assert_eq!(
            bounded_json["params"]["run_invocation_options"]["max_turns"],
            3
        );
        assert_eq!(
            bounded_json["params"]["run_invocation_options"]["timeout_ms"],
            60_000
        );

        let with_mode = RunInvocationOptions {
            max_turns: None,
            timeout_ms: None,
            approval_mode: Some(ApprovalMode::Yolo),
        };
        let mode_send = Request::SendUserMessage {
            client_submission_id: id,
            text: "run me".into(),
            display_text: None,
            tag_expansions: Vec::new(),
            image_refs: Vec::new(),
            forced_skill: None,
            run_invocation_options: Some(with_mode),
        };
        let mode_json = serde_json::to_value(&mode_send).unwrap();
        assert_eq!(
            mode_json["params"]["run_invocation_options"]["approval_mode"],
            "yolo"
        );
        // approval_mode is only under options — not daemon state/version fields.
        assert!(mode_json["params"].get("approval_mode").is_none());
        assert!(mode_json["params"].get("state_version").is_none());

        let non_run = Request::SendUserMessage {
            client_submission_id: id,
            text: "interactive".into(),
            display_text: None,
            tag_expansions: Vec::new(),
            image_refs: Vec::new(),
            forced_skill: None,
            run_invocation_options: None,
        };
        let non_run_json = serde_json::to_value(&non_run).unwrap();
        assert!(
            non_run_json["params"]
                .get("run_invocation_options")
                .is_none()
        );

        let status = Request::GetRunInvocationStatus {
            client_submission_id: id,
        };
        assert_eq!(status.wire_tag(), "get_run_invocation_status");
        let status_json = serde_json::to_value(&status).unwrap();
        assert_eq!(
            status_json["params"]["client_submission_id"],
            id.to_string()
        );
        assert!(status_json["params"].get("session_id").is_none());
        assert!(status_json["params"].get("invocation_id").is_none());

        let cancel = Request::CancelRunInvocation {
            client_submission_id: id,
        };
        assert_eq!(cancel.wire_tag(), "cancel_run_invocation");
        let cancel_json = serde_json::to_value(&cancel).unwrap();
        assert_eq!(
            cancel_json["params"]["client_submission_id"],
            id.to_string()
        );
        assert!(cancel_json["params"].get("session_id").is_none());

        let command_tags = crate::command!(command_tags);
        assert!(command_tags.contains(&"get_run_invocation_status"));
        assert!(command_tags.contains(&"cancel_run_invocation"));

        // Zero is never unbounded: semantic validation rejects it.
        let zero_turns = Request::SendUserMessage {
            client_submission_id: id,
            text: "x".into(),
            display_text: None,
            tag_expansions: Vec::new(),
            image_refs: Vec::new(),
            forced_skill: None,
            run_invocation_options: Some(RunInvocationOptions {
                max_turns: Some(0),
                timeout_ms: None,
                approval_mode: None,
            }),
        };
        assert!(
            zero_turns
                .validate_semantics()
                .unwrap_err()
                .contains("max_turns")
        );
        let zero_timeout = Request::SendUserMessage {
            client_submission_id: id,
            text: "x".into(),
            display_text: None,
            tag_expansions: Vec::new(),
            image_refs: Vec::new(),
            forced_skill: None,
            run_invocation_options: Some(RunInvocationOptions {
                max_turns: None,
                timeout_ms: Some(0),
                approval_mode: None,
            }),
        };
        assert!(
            zero_timeout
                .validate_semantics()
                .unwrap_err()
                .contains("timeout_ms")
        );

        // Round-trip preserves options immutably.
        let again: Request = serde_json::from_value(bounded_json).unwrap();
        match again {
            Request::SendUserMessage {
                run_invocation_options: Some(opts),
                ..
            } => assert_eq!(opts, bounded),
            other => panic!("expected SendUserMessage, got {other:?}"),
        }
    }
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
