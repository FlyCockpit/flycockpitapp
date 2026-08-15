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
        /// For a fenced interactive submission, the exact daemon-owned model
        /// generation captured by the client. Omitted by non-fenced clients.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_model_state_generation: Option<u64>,
        /// Complete provider/model identity captured with the expected
        /// generation. Both fields must be present or absent together.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_model: Option<cockpit_config::config::providers::ActiveModelRef>,
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

    /// Query the durable outcome of an operation on the authenticated logical attachment.
    OperationStatus {
        operation_id: Uuid,
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
        byte_len: u64,
        sha256: String,
        purpose: AttachmentPurpose,
    },

    UploadAttachmentChunk {
        upload_id: Uuid,
        offset: u64,
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

    /// Sole host ingress for creating a supervised goal.
    CreateGoal {
        session_id: Uuid,
        objective: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token_budget: Option<i64>,
    },

    /// Read the current open goal for a session after refreshing token usage.
    GoalStatus {
        session_id: Uuid,
    },

    /// Pause or resume the current open goal for a session.
    SetGoalStatus {
        session_id: Uuid,
        status: GoalDisposition,
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

    /// `/leaks`: machine-wide Owner list of safe leak-report metadata,
    /// newest-first, with stable paging. Optional `session_id` narrows to one
    /// session without changing ownership scope. `cursor` is the opaque
    /// cursor from the prior page; `None` starts a new traversal. `limit` is
    /// clamped to 1..=100.
    ListLeakReports {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        project_root: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<Uuid>,
        /// Optional rotation-state filter. `None` means all rotation states.
        /// Bound into the list cursor MAC alongside the other filters.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rotation: Option<LeakRotationState>,
    },
    /// Begin a leak reveal: mint a fresh one-use capability bound to exactly
    /// one report id. Secret-free. The reveal itself is **not** an ordinary
    /// proto request — the protected literal travels only on the sensitive
    /// local endpoint (in-process handoff or the Unix peer-authenticated reveal
    /// socket), never on any ordinary codec.
    BeginLeakReveal {
        report_id: String,
    },
    /// Update the rotation disposition of a leak record. Metadata-only and
    /// reversible.
    MarkLeakRotated {
        report_id: String,
        rotation: LeakRotationDisposition,
    },
    /// Delete the protected plaintext/ciphertext for a leak record while
    /// retaining safe historical report metadata and mandatory redaction.
    DeleteLeakReport {
        report_id: String,
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

    SetWorkspaceTrust {
        project_root: String,
        mode: WorkspaceTrustMode,
        expected_config_generation: u64,
    },
    GetStartupDisclosures {
        project_root: String,
    },
    GetAppFlag {
        key: AppFlagKey,
    },
    MarkAppFlagSeen {
        key: AppFlagKey,
        expected_version: u64,
    },
    ResolveAssistantSession {
        assistant_id: String,
        project_root: String,
        mode: AssistantSessionResolutionMode,
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
    /// to the client. Every RPC export is a permanently redacted, portable
    /// artifact: this request carries no raw/bypass field, and the daemon
    /// always assembles it through the enforced redaction path, so
    /// `redact.enabled = false` and provider trust never relax export
    /// redaction. The single unredacted export is the explicit local
    /// `cockpit export --include-sensitive` CLI flag, which never travels over
    /// this RPC.
    ExportSessionData {
        session_id: Uuid,
        kind: ExportSessionKind,
        #[serde(default)]
        include_generated_artifacts: bool,
    },

    /// Import a ZIP archive through the daemon-owned database writer.
    ///
    /// The archive never travels inline. `transfer` references a completed
    /// bulk-lane transfer; the daemon reads the bytes from there after the
    /// transfer's digest and length have been verified.
    ImportSessionArchive {
        transfer: crate::remote_transport::bulk::RemoteBulkTransferRef,
        #[serde(default)]
        as_new: bool,
    },

    /// Push one chunk of a bulk transfer into daemon-side staging.
    ///
    /// `transfer` describes the whole transfer (length, digest, class), so no
    /// separate begin round trip is needed. Chunks are contiguous from index 0
    /// and each body is bounded by [`crate::MAX_ATTACHMENT_CHUNK_BASE64_BYTES`],
    /// which keeps the encoded frame inside one bulk-lane logical payload.
    WriteBulkTransferChunk {
        transfer: crate::remote_transport::bulk::RemoteBulkTransferRef,
        chunk_index: u32,
        data_base64: String,
    },

    /// Pull one chunk of a staged bulk transfer.
    ReadBulkTransferChunk {
        transfer_id: crate::remote_protocol_id::RemoteTransferId,
        chunk_index: u32,
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

    TerminalIngressBegin {
        terminal_id: Uuid,
        binding: crate::terminal::TerminalBinding,
        metadata: crate::terminal::TerminalIngressMetadata,
    },

    TerminalIngressChunk {
        terminal_id: Uuid,
        binding: crate::terminal::TerminalBinding,
        operation_id: Uuid,
        offset: u64,
        data_base64: String,
    },

    TerminalIngressFinish {
        terminal_id: Uuid,
        binding: crate::terminal::TerminalBinding,
        operation_id: Uuid,
    },

    TerminalIngressStatus {
        terminal_id: Uuid,
        binding: crate::terminal::TerminalBinding,
        operation_id: Uuid,
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

    /// Probe the durable terminal state of one idempotent user submission
    /// without changing the daemon's current attachment.
    ReadClientSubmissionReceipt {
        session_id: Uuid,
        client_submission_id: Uuid,
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

    /// Owner-only, daemon-local disposition of a security-blocked aggregate.
    RecoverSecurityBlockedMedia(cockpit_db::media_attachments::RecoverSecurityBlockedMediaV1),

    /// Register a project-contained local file while retaining its verified handle.
    RegisterLocalPathMedia(cockpit_db::media_attachments::RegisterLocalPathMediaV1),

    /// Owner-only daemon-local retained HTTPS ingress.
    RetainHttpsMedia(cockpit_db::media_attachments::RetainHttpsMediaV1),

    GetMediaAttachmentStatus(cockpit_db::media_attachments::GetMediaAttachmentStatusV1),

    GetMediaAttachmentPreview(cockpit_db::media_attachments::GetMediaAttachmentPreviewV1),

    BeginMediaUpload(cockpit_db::media_attachments::BeginMediaUploadV1),

    AppendMediaUploadChunk(cockpit_db::media_attachments::AppendMediaUploadChunkV1),

    CancelMediaUpload(cockpit_db::media_attachments::CancelMediaUploadV1),

    GetMediaUploadStatus(cockpit_db::media_attachments::GetMediaUploadStatusV1),

    FinalizeMediaUpload(cockpit_db::media_attachments::FinalizeMediaUploadV1),

    DiscardUnreferencedMediaAttachment(cockpit_db::media_attachments::LocalMediaMutationV1),

    /// Request orderly shutdown. The daemon flushes in-flight writes
    /// (session DB, lock state) before exiting.
    StopDaemon {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grace_secs: Option<u64>,
    },

    /// Atomically request daemon restart only if no session worker is busy.
    RestartIfIdle,

    /// Return the last daemon-owned [`HostCapabilitySnapshot`].
    GetHostCapabilities,

    /// Re-run the shared host-capability probes and publish a new snapshot
    /// when the reserved generation is still current.
    RefreshHostCapabilities,

    /// Move the wrap-key vault KEK between OS keyring and `private_fs`.
    /// Commits `secret_vault_authority` in the same SQLite transaction as
    /// the migrate saga. Not a layered `secretStore` config key.
    MigrateKekPlacement {
        dest: crate::SecretStorePlacement,
    },

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
            Self::BeginAttachmentUpload { byte_len, .. } => {
                usize::try_from(*byte_len)
                    .map_err(|_| "byte_len exceeds daemon platform capacity".to_string())?;
            }
            Self::UploadAttachmentChunk { offset, .. } => {
                usize::try_from(*offset)
                    .map_err(|_| "offset exceeds daemon platform capacity".to_string())?;
            }
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
                expected_model_state_generation,
                expected_model,
                run_invocation_options,
                ..
            } => {
                if client_submission_id.is_nil() {
                    return Err("client_submission_id must not be nil".to_string());
                }
                if expected_model_state_generation.is_some() != expected_model.is_some() {
                    return Err(
                        "expected model generation and identity must be supplied together"
                            .to_string(),
                    );
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
            Self::OperationStatus { operation_id }
                if operation_id.is_nil() || operation_id.get_version_num() != 7 =>
            {
                return Err("operation_id must be UUIDv7".to_string());
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
            (Request::OperationStatus { .. }, "operation_status");
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
            (Request::CreateGoal { .. }, "create_goal");
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
            (Request::ListLeakReports { .. }, "list_leak_reports");
            (Request::BeginLeakReveal { .. }, "begin_leak_reveal");
            (Request::MarkLeakRotated { .. }, "mark_leak_rotated");
            (Request::DeleteLeakReport { .. }, "delete_leak_report");
            (Request::ListProjectNotes { .. }, "list_project_notes");
            (Request::CreateProjectNote { .. }, "create_project_note");
            (Request::SetProjectNoteContent { .. }, "set_project_note_content");
            (Request::RenameProjectNote { .. }, "rename_project_note");
            (Request::DeleteProjectNote { .. }, "delete_project_note");
            (Request::SetWorkspaceTrust { .. }, "set_workspace_trust");
            (Request::GetStartupDisclosures { .. }, "get_startup_disclosures");
            (Request::GetAppFlag { .. }, "get_app_flag");
            (Request::MarkAppFlagSeen { .. }, "mark_app_flag_seen");
            (Request::ResolveAssistantSession { .. }, "resolve_assistant_session");
            (Request::ListAssistants, "list_assistants");
            (Request::UpsertAssistant { .. }, "upsert_assistant");
            (Request::CreateAssistantSession { .. }, "create_assistant_session");
            (Request::AutoTitle { .. }, "auto_title");
            (Request::ExportSessionData { .. }, "export_session_data");
            (Request::ImportSessionArchive { .. }, "import_session_archive");
            (Request::WriteBulkTransferChunk { .. }, "write_bulk_transfer_chunk");
            (Request::ReadBulkTransferChunk { .. }, "read_bulk_transfer_chunk");
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
            (Request::TerminalIngressBegin { .. }, "terminal_ingress_begin");
            (Request::TerminalIngressChunk { .. }, "terminal_ingress_chunk");
            (Request::TerminalIngressFinish { .. }, "terminal_ingress_finish");
            (Request::TerminalIngressStatus { .. }, "terminal_ingress_status");
            (Request::LspControl { .. }, "lsp_control");
            (Request::ResolveInterrupt { .. }, "resolve_interrupt");
            (Request::ListSessions { .. }, "list_sessions");
            (Request::ReadSessionMessages { .. }, "read_session_messages");
            (Request::ReadClientSubmissionReceipt { .. }, "read_client_submission_receipt");
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
            (Request::RecoverSecurityBlockedMedia(..), "recover_security_blocked_media");
            (Request::RegisterLocalPathMedia(..), "register_local_path_media");
            (Request::RetainHttpsMedia(..), "retain_https_media");
            (Request::GetMediaAttachmentStatus(..), "get_media_attachment_status");
            (Request::GetMediaAttachmentPreview(..), "get_media_attachment_preview");
            (Request::BeginMediaUpload(..), "begin_media_upload");
            (Request::AppendMediaUploadChunk(..), "append_media_upload_chunk");
            (Request::CancelMediaUpload(..), "cancel_media_upload");
            (Request::DiscardUnreferencedMediaAttachment(..), "discard_unreferenced_media_attachment");
            (Request::GetMediaUploadStatus(..), "get_media_upload_status");
            (Request::FinalizeMediaUpload(..), "finalize_media_upload");
            (Request::StopDaemon { .. }, "stop_daemon");
            (Request::RestartIfIdle, "restart_if_idle");
            (Request::GetHostCapabilities, "get_host_capabilities");
            (Request::RefreshHostCapabilities, "refresh_host_capabilities");
            (Request::MigrateKekPlacement { .. }, "migrate_kek_placement");
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
    /// Returns the tag used by the `command!` metadata table. This differs
    /// from `wire_tag()` for a small number of variants whose serde rename
    /// does not match the command-table tag (e.g. `create_btw_fork` vs
    /// `btw_create`).
    pub fn command_tag(&self) -> &'static str {
        macro_rules! command_tag {
            (($($context:ident),*) [$(($pattern:pat, $tag:literal, $($rest:tt)*);)+]) => {
                #[allow(unused_variables)]
                match self {
                    $($pattern => $tag,)+
                }
            };
        }
        crate::command!(command_tag)
    }
}

// Keep daemon command metadata centralized. Callers provide a local callback
// macro so each module can expand the same exhaustive Request table into the
// shape it needs without changing Request's serde representation.
#[macro_export]
macro_rules! command {
    ($with_commands:ident $(, $context:ident)*) => {
        $with_commands! { ($($context),*) [
            (Request::Attach { session_id, since_seq, project_root, initial_model, no_sandbox, interactive, model_override, client_protocol_version, env_snapshot, env_policy }, "attach", custom(authorize_attach), option_field(session_id), true, idempotent_adapter_mutation, domain_transaction(domain_result_tuple), serialized, none, "session_id:Option<Uuid>|since_seq:Option<i64>|project_root:Option<String>|initial_model:Option<cockpit_config::config::providers::ActiveModelRef>|no_sandbox:bool|interactive:bool|model_override:Option<cockpit_config::config::providers::ActiveModelRef>|client_protocol_version:u32|env_snapshot:Option<EnvSnapshotWire>|env_policy:EnvDriftPolicy", [session_id: Option<Uuid> => session, since_seq: Option<i64> => param, project_root: Option<String> => project_root_effective, initial_model: Option<cockpit_config::config::providers::ActiveModelRef> => param, no_sandbox: bool => param, interactive: bool => param, model_override: Option<cockpit_config::config::providers::ActiveModelRef> => param, client_protocol_version: u32 => param, env_snapshot: Option<EnvSnapshotWire> => param, env_policy: EnvDriftPolicy => param]);
            (Request::SubagentTranscript { session_id, task_call_id, label }, "subagent_transcript", custom(authorize_subagent_transcript), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid|task_call_id:String|label:String", [session_id: Uuid => session, task_call_id: String => param, label: String => param]);
            (Request::SendUserMessage { client_submission_id, expected_model_state_generation, expected_model, text, display_text, tag_expansions, image_refs, forced_skill, run_invocation_options }, "send_user_message", session_writer, attached, true, transactional_mutation, sql_transaction, serialized, none, "client_submission_id:Uuid|expected_model_state_generation:Option<u64>|expected_model:Option<cockpit_config::config::providers::ActiveModelRef>|text:String|display_text:Option<String>|tag_expansions:Vec<TagExpansionMeta>|image_refs:Vec<ImageAttachmentRef>|forced_skill:Option<String>|run_invocation_options:Option<RunInvocationOptions>", [client_submission_id: Uuid => legacy_message, expected_model_state_generation: Option<u64> => param, expected_model: Option<cockpit_config::config::providers::ActiveModelRef> => param, text: String => param, display_text: Option<String> => param, tag_expansions: Vec<TagExpansionMeta> => param, image_refs: Vec<ImageAttachmentRef> => param, forced_skill: Option<String> => param, run_invocation_options: Option<RunInvocationOptions> => param]);
            (Request::GetRunInvocationStatus { client_submission_id }, "get_run_invocation_status", public_read, none, false, read_only, none, concurrent, none, "client_submission_id:Uuid", [client_submission_id: Uuid => param]);
            (Request::OperationStatus { operation_id }, "operation_status", public_read, none, false, read_only, none, serialized, none, "operation_id:Uuid", [operation_id: Uuid => param]);
            (Request::CancelRunInvocation { client_submission_id }, "cancel_run_invocation", public_read, none, true, transactional_mutation, sql_transaction, serialized, none, "client_submission_id:Uuid", [client_submission_id: Uuid => param]);
            (Request::SteerDelegation { session_id, task_call_id, label, message }, "steer_delegation", custom(authorize_steer_delegation), field(session_id), true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "session_id:Uuid|task_call_id:String|label:String|message:String", [session_id: Uuid => session, task_call_id: String => param, label: String => param, message: String => param]);
            (Request::BeginAttachmentUpload { mime, byte_len, sha256, purpose }, "begin_attachment_upload", custom(authorize_begin_attachment_upload), attached, true, idempotent_adapter_mutation, domain_transaction(domain_result_tuple), serialized, none, "mime:String|byte_len:u64|sha256:String|purpose:AttachmentPurpose", [mime: String => param, byte_len: u64 => param, sha256: String => param, purpose: AttachmentPurpose => param]);
            (Request::UploadAttachmentChunk { upload_id, offset, data_base64 }, "upload_attachment_chunk", custom(authorize_attachment_upload_step), attached, true, idempotent_adapter_mutation, domain_transaction(domain_result_tuple), serialized, none, "upload_id:Uuid|offset:u64|data_base64:String", [upload_id: Uuid => upload, offset: u64 => param, data_base64: String => param]);
            (Request::FinishAttachmentUpload { upload_id }, "finish_attachment_upload", custom(authorize_attachment_upload_step), attached, true, idempotent_adapter_mutation, domain_transaction(domain_result_tuple), serialized, none, "upload_id:Uuid", [upload_id: Uuid => upload]);
            (Request::CancelAttachmentUpload { upload_id }, "cancel_attachment_upload", custom(authorize_attachment_upload_step), attached, true, idempotent_adapter_mutation, domain_transaction(domain_result_tuple), serialized, none, "upload_id:Uuid", [upload_id: Uuid => upload]);
            (Request::RemoveQueuedUserMessage { queue_item_id }, "remove_queued_user_message", session_writer, attached, true, transactional_mutation, sql_transaction, serialized, none, "queue_item_id:Uuid", [queue_item_id: Uuid => queue]);
            (Request::RemoveNewestQueuedUserMessage { target_id }, "remove_newest_queued_user_message", session_writer, attached, true, transactional_mutation, sql_transaction, serialized, none, "target_id:Option<String>", [target_id: Option<String> => param]);
            (Request::RemoveEditableQueuedUserMessages { target_id }, "remove_editable_queued_user_messages", session_writer, attached, true, transactional_mutation, sql_transaction, serialized, none, "target_id:Option<String>", [target_id: Option<String> => param]);
            (Request::ResumePausedWork { session_id }, "resume_paused_work", session_row_writer(session_id), field(session_id), true, transactional_mutation, sql_transaction, serialized, none, "session_id:Uuid", [session_id: Uuid => session]);
            (Request::CancelPausedWork { session_id }, "cancel_paused_work", session_row_writer(session_id), field(session_id), true, transactional_mutation, sql_transaction, serialized, none, "session_id:Uuid", [session_id: Uuid => session]);
            (Request::RepairResume { session_id }, "repair_resume", session_writer, field(session_id), true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "session_id:Uuid", [session_id: Uuid => session]);
            (Request::GoalStatus { session_id }, "goal_status", session_row_reader(session_id), field(session_id), false, read_only, none, serialized, none, "session_id:Uuid", [session_id: Uuid => session]);
            (Request::CreateGoal { session_id, objective, token_budget }, "create_goal", session_row_writer(session_id), field(session_id), true, transactional_mutation, sql_transaction, serialized, none, "session_id:Uuid|objective:String|token_budget:Option<i64>", [session_id: Uuid => session, objective: String => param, token_budget: Option<i64> => param]);
            (Request::SetGoalStatus { session_id, status }, "set_goal_status", session_row_writer(session_id), field(session_id), true, transactional_mutation, sql_transaction, serialized, none, "session_id:Uuid|status:GoalDisposition", [session_id: Uuid => session, status: GoalDisposition => param]);
            (Request::ClearGoal { session_id }, "clear_goal", session_row_writer(session_id), field(session_id), true, transactional_mutation, sql_transaction, serialized, none, "session_id:Uuid", [session_id: Uuid => session]);
            (Request::PinMessage { session_id, seq }, "pin_message", session_row_writer(session_id), field(session_id), true, transactional_mutation, sql_transaction, serialized, none, "session_id:Uuid|seq:i64", [session_id: Uuid => session, seq: i64 => param]);
            (Request::UnpinMessage { session_id, seq }, "unpin_message", session_row_writer(session_id), field(session_id), true, transactional_mutation, sql_transaction, serialized, none, "session_id:Uuid|seq:i64", [session_id: Uuid => session, seq: i64 => param]);
            (Request::TogglePinnedMessage { session_id, seq }, "toggle_pinned_message", session_row_writer(session_id), field(session_id), true, transactional_mutation, sql_transaction, serialized, none, "session_id:Uuid|seq:i64", [session_id: Uuid => session, seq: i64 => param]);
            (Request::CountPinnedMessages { session_id }, "count_pinned_messages", session_row_reader(session_id), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid", [session_id: Uuid => session]);
            (Request::ListPinnedMessageSeqs { session_id }, "list_pinned_message_seqs", session_row_reader(session_id), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid", [session_id: Uuid => session]);
            (Request::ListPinnedMessagesWithText { session_id }, "list_pinned_messages_with_text", session_row_reader(session_id), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid", [session_id: Uuid => session]);
            (Request::PinnedMessageState { session_id }, "pinned_message_state", session_row_reader(session_id), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid", [session_id: Uuid => session]);
            (Request::ListSealedValues { session_id }, "list_sealed_values", owner_only, field(session_id), false, local_only, none, concurrent, none, "session_id:Uuid", [session_id: Uuid => session]);
            (Request::DeleteSealedValue { session_id, value_id }, "delete_sealed_value", owner_only, field(session_id), true, local_only, none, serialized, none, "session_id:Uuid|value_id:String", [session_id: Uuid => session, value_id: String => param]);
            (Request::ListLeakReports { cursor, limit, project_root, session_id, rotation }, "list_leak_reports", owner_only, none, false, local_only, none, concurrent, none, "cursor:Option<String>|limit:Option<u32>|project_root:Option<String>|session_id:Option<Uuid>|rotation:Option<LeakRotationState>", [cursor: Option<String> => param, limit: Option<u32> => param, project_root: Option<String> => project_root_effective, session_id: Option<Uuid> => param, rotation: Option<LeakRotationState> => param]);
            (Request::BeginLeakReveal { report_id }, "begin_leak_reveal", owner_only, none, false, local_only, none, serialized, none, "report_id:String", [report_id: String => param]);
            (Request::MarkLeakRotated { report_id, rotation }, "mark_leak_rotated", owner_only, none, true, local_only, none, serialized, none, "report_id:String|rotation:LeakRotationDisposition", [report_id: String => param, rotation: LeakRotationDisposition => param]);
            (Request::DeleteLeakReport { report_id }, "delete_leak_report", owner_only, none, true, local_only, none, serialized, none, "report_id:String", [report_id: String => param]);
            (Request::ListProjectNotes { project_root }, "list_project_notes", owner_only, none, true, local_only, none, serialized, path(project_root), "project_root:String", [project_root: String => project_root]);
            (Request::CreateProjectNote { project_root, name }, "create_project_note", owner_only, none, true, local_only, none, serialized, path(project_root), "project_root:String|name:String", [project_root: String => project_root, name: String => param]);
            (Request::SetProjectNoteContent { project_root, id, content }, "set_project_note_content", owner_only, none, true, local_only, none, serialized, path(project_root), "project_root:String|id:Uuid|content:String", [project_root: String => project_root, id: Uuid => param, content: String => param]);
            (Request::RenameProjectNote { project_root, id, name }, "rename_project_note", owner_only, none, true, local_only, none, serialized, path(project_root), "project_root:String|id:Uuid|name:String", [project_root: String => project_root, id: Uuid => param, name: String => param]);
            (Request::DeleteProjectNote { project_root, id }, "delete_project_note", owner_only, none, true, local_only, none, serialized, path(project_root), "project_root:String|id:Uuid", [project_root: String => project_root, id: Uuid => param]);
            (Request::SetWorkspaceTrust { project_root, mode, expected_config_generation }, "set_workspace_trust", owner_only, none, true, local_only, none, serialized, path(project_root), "project_root:String|mode:WorkspaceTrustMode|expected_config_generation:u64", [project_root: String => project_root, mode: WorkspaceTrustMode => param, expected_config_generation: u64 => param]);
            (Request::GetStartupDisclosures { project_root }, "get_startup_disclosures", owner_only, none, false, local_only, none, serialized, path(project_root), "project_root:String", [project_root: String => project_root]);
            (Request::GetAppFlag { key }, "get_app_flag", owner_only, none, false, local_only, none, serialized, none, "key:AppFlagKey", [key: AppFlagKey => param]);
            (Request::MarkAppFlagSeen { key, expected_version }, "mark_app_flag_seen", owner_only, none, true, local_only, none, serialized, none, "key:AppFlagKey|expected_version:u64", [key: AppFlagKey => param, expected_version: u64 => param]);
            (Request::ResolveAssistantSession { assistant_id, project_root, mode }, "resolve_assistant_session", owner_only, none, true, local_only, none, serialized, path(project_root), "assistant_id:String|project_root:String|mode:AssistantSessionResolutionMode", [assistant_id: String => param, project_root: String => project_root, mode: AssistantSessionResolutionMode => param]);
            (Request::ListAssistants, "list_assistants", owner_only, none, false, local_only, none, concurrent, none, "-", []);
            (Request::UpsertAssistant { name, home_dir, config_json, content_hash }, "upsert_assistant", owner_only, none, true, local_only, none, serialized, none, "name:String|home_dir:String|config_json:String|content_hash:String", [name: String => param, home_dir: String => param, config_json: String => param, content_hash: String => param]);
            (Request::CreateAssistantSession { name, project_root, initial_model, no_sandbox, env_snapshot }, "create_assistant_session", owner_only, none, true, local_only, none, serialized, none, "name:String|project_root:String|initial_model:Option<cockpit_config::config::providers::ActiveModelRef>|no_sandbox:bool|env_snapshot:Option<EnvSnapshotWire>", [name: String => param, project_root: String => project_root, initial_model: Option<cockpit_config::config::providers::ActiveModelRef> => param, no_sandbox: bool => param, env_snapshot: Option<EnvSnapshotWire> => param]);
            (Request::AutoTitle { session_id }, "auto_title", session_row_writer(session_id), field(session_id), true, idempotent_adapter_mutation, durable_dispatch_key(dispatch_key_and_generation), serialized, none, "session_id:Uuid", [session_id: Uuid => session]);
            (Request::ExportSessionData { session_id, kind, include_generated_artifacts }, "export_session_data", owner_only, field(session_id), false, local_only, none, concurrent, none, "session_id:Uuid|kind:ExportSessionKind|include_generated_artifacts:bool", [session_id: Uuid => session, kind: ExportSessionKind => param, include_generated_artifacts: bool => param]);
            (Request::ImportSessionArchive { transfer, as_new }, "import_session_archive", owner_only, none, true, local_only, none, serialized, none, "transfer:crate::remote_transport::bulk::RemoteBulkTransferRef|as_new:bool", [transfer: $crate::remote_transport::bulk::RemoteBulkTransferRef => param, as_new: bool => param]);
            (Request::WriteBulkTransferChunk { transfer, chunk_index, data_base64 }, "write_bulk_transfer_chunk", owner_only, none, true, local_only, none, serialized, none, "transfer:crate::remote_transport::bulk::RemoteBulkTransferRef|chunk_index:u32|data_base64:String", [transfer: $crate::remote_transport::bulk::RemoteBulkTransferRef => param, chunk_index: u32 => param, data_base64: String => param]);
            (Request::ReadBulkTransferChunk { transfer_id, chunk_index }, "read_bulk_transfer_chunk", owner_only, none, false, local_only, none, concurrent, none, "transfer_id:crate::remote_protocol_id::RemoteTransferId|chunk_index:u32", [transfer_id: $crate::remote_protocol_id::RemoteTransferId => param, chunk_index: u32 => param]);
            (Request::Curator { project_root, action }, "curator", owner_only, none, true, local_only, none, serialized, path(project_root), "project_root:String|action:CuratorAction", [project_root: String => project_root, action: CuratorAction => param]);
            (Request::CancelTurn, "cancel_turn", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "-", []);
            (Request::FsList { project_root, path, show_hidden }, "fs_list", project_files(project_root), none, false, read_only, none, concurrent, none, "project_root:String|path:String|show_hidden:bool", [project_root: String => project_root, path: String => file_existing(project_root), show_hidden: bool => param]);
            (Request::FsStat { project_root, path }, "fs_stat", project_files(project_root), none, false, read_only, none, concurrent, none, "project_root:String|path:String", [project_root: String => project_root, path: String => file_existing(project_root)]);
            (Request::FsRead { project_root, path, base64 }, "fs_read", project_files(project_root), none, false, read_only, none, concurrent, none, "project_root:String|path:String|base64:bool", [project_root: String => project_root, path: String => file_existing(project_root), base64: bool => param]);
            (Request::FsWrite { project_root, path, content, base_hash }, "fs_write", project_files(project_root), none, true, idempotent_adapter_mutation, staged_filesystem_commit(staged_artifact_fingerprints_and_fsync_barriers), serialized, path(path), "project_root:String|path:String|content:String|base_hash:Option<String>", [project_root: String => project_root, path: String => file_write_target(project_root), content: String => param, base_hash: Option<String> => param]);
            (Request::FsCreateDir { project_root, path }, "fs_create_dir", project_files(project_root), none, true, idempotent_adapter_mutation, staged_filesystem_commit(staged_artifact_fingerprints_and_fsync_barriers), serialized, path(path), "project_root:String|path:String", [project_root: String => project_root, path: String => file_write_target(project_root)]);
            (Request::FsRename { project_root, from_path, to_path }, "fs_rename", project_files(project_root), none, true, idempotent_adapter_mutation, staged_filesystem_commit(staged_artifact_fingerprints_and_fsync_barriers), serialized, rename(from_path, to_path), "project_root:String|from_path:String|to_path:String", [project_root: String => project_root, from_path: String => rename_source(project_root), to_path: String => file_write_target(project_root)]);
            (Request::FsDelete { project_root, path }, "fs_delete", owner_only, none, true, local_only, none, serialized, path(path), "project_root:String|path:String", [project_root: String => project_root, path: String => file_existing(project_root)]);
            (Request::GitStatus { project_root }, "git_status", project_files(project_root), none, false, read_only, none, concurrent, none, "project_root:String", [project_root: String => project_root]);
            (Request::GitDiffFile { project_root, path }, "git_diff_file", project_files(project_root), none, false, read_only, none, concurrent, path(path), "project_root:String|path:String", [project_root: String => project_root, path: String => file_existing(project_root)]);
            (Request::OpenTerminal { cwd, cols, rows }, "open_terminal", terminal, none, true, idempotent_adapter_mutation, durable_dispatch_key(dispatch_key_and_generation), serialized, none, "cwd:Option<String>|cols:u16|rows:u16", [cwd: Option<String> => param, cols: u16 => param, rows: u16 => param]);
            (Request::AttachTerminal { terminal_id, cols, rows }, "attach_terminal", terminal, none, false, read_only, none, serialized, none, "terminal_id:Uuid|cols:u16|rows:u16", [terminal_id: Uuid => terminal, cols: u16 => param, rows: u16 => param]);
            (Request::TerminalInput { terminal_id, bytes }, "terminal_input", terminal, none, false, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "terminal_id:Uuid|bytes:Vec<u8>", [terminal_id: Uuid => terminal, bytes: Vec<u8> => param]);
            (Request::TerminalResize { terminal_id, cols, rows }, "terminal_resize", terminal, none, false, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "terminal_id:Uuid|cols:u16|rows:u16", [terminal_id: Uuid => terminal, cols: u16 => param, rows: u16 => param]);
            (Request::CloseTerminal { terminal_id }, "close_terminal", terminal, none, true, idempotent_adapter_mutation, durable_dispatch_key(dispatch_key_and_generation), serialized, none, "terminal_id:Uuid", [terminal_id: Uuid => terminal]);
            (Request::TerminalIngressBegin { terminal_id, binding, metadata }, "terminal_ingress_begin", terminal, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "terminal_id:Uuid|binding:crate::terminal::TerminalBinding|metadata:crate::terminal::TerminalIngressMetadata", [terminal_id: Uuid => terminal, binding: $crate::terminal::TerminalBinding => param, metadata: $crate::terminal::TerminalIngressMetadata => param]);
            (Request::TerminalIngressChunk { terminal_id, binding, operation_id, offset, data_base64 }, "terminal_ingress_chunk", terminal, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "terminal_id:Uuid|binding:crate::terminal::TerminalBinding|operation_id:Uuid|offset:u64|data_base64:String", [terminal_id: Uuid => terminal, binding: $crate::terminal::TerminalBinding => param, operation_id: Uuid => param, offset: u64 => param, data_base64: String => param]);
            (Request::TerminalIngressFinish { terminal_id, binding, operation_id }, "terminal_ingress_finish", terminal, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "terminal_id:Uuid|binding:crate::terminal::TerminalBinding|operation_id:Uuid", [terminal_id: Uuid => terminal, binding: $crate::terminal::TerminalBinding => param, operation_id: Uuid => param]);
            (Request::TerminalIngressStatus { terminal_id, binding, operation_id }, "terminal_ingress_status", terminal, none, false, read_only, none, concurrent, none, "terminal_id:Uuid|binding:crate::terminal::TerminalBinding|operation_id:Uuid", [terminal_id: Uuid => terminal, binding: $crate::terminal::TerminalBinding => param, operation_id: Uuid => param]);
            (Request::LspControl { project_root, server_id, action }, "lsp_control", custom(authorize_lsp_control), attached, true, idempotent_adapter_mutation, durable_dispatch_key(dispatch_key_and_generation), serialized, none, "project_root:String|server_id:String|action:LspControlAction", [project_root: String => project_root, server_id: String => param, action: LspControlAction => param]);
            (Request::ResolveInterrupt { interrupt_id, response }, "resolve_interrupt", session_writer, attached, true, idempotent_adapter_mutation, durable_dispatch_key(dispatch_key_and_generation), serialized, none, "interrupt_id:Uuid|response:ResolveResponse", [interrupt_id: Uuid => interrupt, response: ResolveResponse => param]);
            (Request::ListSessions { project_id, parent_session_id }, "list_sessions", public_read, none, false, read_only, none, concurrent, none, "project_id:Option<String>|parent_session_id:Option<Uuid>", [project_id: Option<String> => project, parent_session_id: Option<Uuid> => param]);
            (Request::ReadSessionMessages { session_id, before_seq, limit }, "read_session_messages", custom(authorize_read_session_messages), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid|before_seq:Option<i64>|limit:u32", [session_id: Uuid => session, before_seq: Option<i64> => param, limit: u32 => param]);
            (Request::ReadClientSubmissionReceipt { session_id, client_submission_id }, "read_client_submission_receipt", custom(authorize_read_session_messages), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid|client_submission_id:Uuid", [session_id: Uuid => session, client_submission_id: Uuid => param]);
            (Request::ReadHistoryPage { session_id, before_seq, limit }, "read_history_page", custom(authorize_read_history_page), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid|before_seq:Option<i64>|limit:u32", [session_id: Uuid => session, before_seq: Option<i64> => param, limit: u32 => param]);
            (Request::ReadSubagentHistoryPage { session_id, task_call_id, label, before_seq, limit }, "read_subagent_history_page", custom(authorize_read_subagent_history_page), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid|task_call_id:String|label:String|before_seq:Option<i64>|limit:u32", [session_id: Uuid => session, task_call_id: String => param, label: String => param, before_seq: Option<i64> => param, limit: u32 => param]);
            (Request::SessionLiveStatus { session_ids }, "session_live_status", public_read, none, false, read_only, none, concurrent, none, "session_ids:Vec<Uuid>", [session_ids: Vec<Uuid> => param]);
            (Request::ArchiveSession { session_id, cascade }, "archive_session", session_row_writer(session_id), field(session_id), true, transactional_mutation, sql_transaction, serialized, none, "session_id:Uuid|cascade:bool", [session_id: Uuid => session, cascade: bool => param]);
            (Request::UnarchiveSession { session_id }, "unarchive_session", session_row_writer(session_id), field(session_id), true, transactional_mutation, sql_transaction, serialized, none, "session_id:Uuid", [session_id: Uuid => session]);
            (Request::ForkSession { parent_session_id, fork_point_turn_id, ephemeral }, "fork_session", session_row_writer(parent_session_id), field(parent_session_id), true, transactional_mutation, sql_transaction, serialized, none, "parent_session_id:Uuid|fork_point_turn_id:Option<String>|ephemeral:bool", [parent_session_id: Uuid => param, fork_point_turn_id: Option<String> => param, ephemeral: bool => param]);
            (Request::DiscardSession { session_id }, "discard_session", session_row_writer(session_id), field(session_id), true, transactional_mutation, sql_transaction, serialized, none, "session_id:Uuid", [session_id: Uuid => session]);
            (Request::CreateBtwFork { parent_session_id, tangent }, "btw_create", session_row_writer(parent_session_id), field(parent_session_id), true, transactional_mutation, sql_transaction, serialized, none, "parent_session_id:Uuid|tangent:bool", [parent_session_id: Uuid => param, tangent: bool => param]);
            (Request::EndBtwFork { parent_session_id }, "btw_end", session_row_writer(parent_session_id), field(parent_session_id), true, transactional_mutation, sql_transaction, serialized, none, "parent_session_id:Uuid", [parent_session_id: Uuid => param]);
            (Request::RenameSession { session_id, title }, "rename_session", session_row_writer(session_id), field(session_id), true, transactional_mutation, sql_transaction, serialized, none, "session_id:Uuid|title:String", [session_id: Uuid => session, title: String => param]);
            (Request::ShareSession { session_id, shared }, "share_session", owner_only, field(session_id), true, local_only, none, serialized, none, "session_id:Uuid|shared:bool", [session_id: Uuid => session, shared: bool => param]);
            (Request::RecordSessionNote { session_id, text }, "record_session_note", session_row_writer(session_id), field(session_id), true, transactional_mutation, sql_transaction, serialized, none, "session_id:Uuid|text:String", [session_id: Uuid => session, text: String => param]);
            (Request::DeleteSession { session_id }, "delete_session", session_row_writer(session_id), field(session_id), true, transactional_mutation, sql_transaction, serialized, none, "session_id:Uuid", [session_id: Uuid => session]);
            (Request::GetInventoryBundle { project_root, session_id, selected_agent }, "get_inventory_bundle", session_row_reader(session_id), field(session_id), false, read_only, none, concurrent, path(project_root), "project_root:String|session_id:Uuid|selected_agent:String", [project_root: String => project_root, session_id: Uuid => session, selected_agent: String => param]);
            (Request::ResourceSnapshot, "resource_snapshot", owner_only, none, false, local_only, none, concurrent, none, "-", []);
            (Request::PromoteResource { request_id, session_id }, "promote_resource", owner_only, option_field(session_id), true, local_only, none, serialized, none, "request_id:String|session_id:Option<Uuid>", [request_id: String => param, session_id: Option<Uuid> => session]);
            (Request::CreateScheduledJob { job }, "create_scheduled_job", owner_only, none, true, local_only, none, serialized, none, "job:ScheduledJobCreate", [job: ScheduledJobCreate => scheduled]);
            (Request::ListScheduledJobs { owner }, "list_scheduled_jobs", owner_only, none, false, local_only, none, concurrent, none, "owner:Option<String>", [owner: Option<String> => param]);
            (Request::DeleteScheduledJob { id }, "delete_scheduled_job", owner_only, none, true, local_only, none, serialized, none, "id:String", [id: String => param]);
            (Request::SetScheduledJobEnabled { id, enabled }, "set_scheduled_job_enabled", owner_only, none, true, local_only, none, serialized, none, "id:String|enabled:bool", [id: String => param, enabled: bool => param]);
            (Request::RunScheduledJob { id }, "run_scheduled_job", owner_only, none, true, local_only, none, serialized, none, "id:String", [id: String => param]);
            (Request::SetModelFavorite { provider, model, favorite }, "set_model_favorite", owner_only, attached, true, local_only, none, serialized, none, "provider:String|model:String|favorite:bool", [provider: String => provider_model_left(model), model: String => provider_model_right(provider), favorite: bool => param]);
            (Request::SetDefaultModel { default_update_id, provider, model, reasoning_effort, thinking_mode, prompt_cache_retention, clear }, "set_default_model", owner_only, attached, true, local_only, none, serialized, none, "default_update_id:Uuid|provider:Option<String>|model:Option<String>|reasoning_effort:Option<String>|thinking_mode:Option<cockpit_config::config::providers::ThinkingMode>|prompt_cache_retention:Option<PromptCacheRetention>|clear:bool", [default_update_id: Uuid => param, provider: Option<String> => provider_model_left(model), model: Option<String> => provider_model_right(provider), reasoning_effort: Option<String> => param, thinking_mode: Option<cockpit_config::config::providers::ThinkingMode> => param, prompt_cache_retention: Option<PromptCacheRetention> => param, clear: bool => param]);
            (Request::SetActiveModel { selection_id, provider, model, persist_as_default, trigger, reasoning_effort, thinking_mode, prompt_cache_retention }, "set_active_model", custom(authorize_set_active_model), attached, true, idempotent_adapter_mutation, durable_desired_state(desired_state_generation_and_observed_digest), serialized, none, "selection_id:Uuid|provider:String|model:String|persist_as_default:bool|trigger:ActiveModelSwitchTrigger|reasoning_effort:Option<String>|thinking_mode:Option<cockpit_config::config::providers::ThinkingMode>|prompt_cache_retention:Option<PromptCacheRetention>", [selection_id: Uuid => param, provider: String => provider_model_left(model), model: String => provider_model_right(provider), persist_as_default: bool => param, trigger: ActiveModelSwitchTrigger => param, reasoning_effort: Option<String> => param, thinking_mode: Option<cockpit_config::config::providers::ThinkingMode> => param, prompt_cache_retention: Option<PromptCacheRetention> => param]);
            (Request::SetAgent { name }, "set_agent", session_writer, attached, true, idempotent_adapter_mutation, durable_desired_state(desired_state_generation_and_observed_digest), serialized, none, "name:String", [name: String => param]);
            (Request::SetLlmMode { mode }, "set_llm_mode", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "mode:Option<LlmMode>", [mode: Option<LlmMode> => param]);
            (Request::SetSessionLlmMode { mode }, "set_session_llm_mode", session_writer, attached, true, idempotent_adapter_mutation, durable_desired_state(desired_state_generation_and_observed_digest), serialized, none, "mode:LlmMode", [mode: LlmMode => param]);
            (Request::SetToolSurfaceOverride { override_json, persist_session, prune_after_switch, monty_nudge }, "set_tool_surface_override", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "override_json:String|persist_session:bool|prune_after_switch:bool|monty_nudge:Option<String>", [override_json: String => param, persist_session: bool => param, prune_after_switch: bool => param, monty_nudge: Option<String> => param]);
            (Request::SetGoalSettingsOverride { override_json, persist_session }, "set_goal_settings_override", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "override_json:Option<String>|persist_session:bool", [override_json: Option<String> => param, persist_session: bool => param]);
            (Request::SetApprovalMode { mode }, "set_approval_mode", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "mode:ApprovalMode", [mode: ApprovalMode => param]);
            (Request::SetDelegationRecursion { enabled, default_depth }, "set_delegation_recursion", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "enabled:bool|default_depth:u32", [enabled: bool => param, default_depth: u32 => param]);
            (Request::SetSandbox { mode, container_network_enabled }, "set_sandbox", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "mode:Option<SandboxMode>|container_network_enabled:Option<bool>", [mode: Option<SandboxMode> => param, container_network_enabled: Option<bool> => param]);
            (Request::SetSandboxEscalation { enabled }, "set_sandbox_escalation", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "enabled:bool", [enabled: bool => param]);
            (Request::SetPreflight { enabled }, "set_preflight", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "enabled:Option<bool>", [enabled: Option<bool> => param]);
            (Request::SetLongcache { enabled }, "set_longcache", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "enabled:Option<bool>", [enabled: Option<bool> => param]);
            (Request::SetRedaction { scan_environment, scan_dotenv, scan_ssh_keys }, "set_redaction", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "scan_environment:Option<bool>|scan_dotenv:Option<bool>|scan_ssh_keys:Option<bool>", [scan_environment: Option<bool> => param, scan_dotenv: Option<bool> => param, scan_ssh_keys: Option<bool> => param]);
            (Request::SetTandemModels { models }, "set_tandem_models", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "models:Vec<(String,String)>", [models: Vec<(String,String)> => param]);
            (Request::SetCaffeinate { mode }, "set_caffeinate", owner_only, none, true, local_only, none, serialized, none, "mode:CaffeinateMode", [mode: CaffeinateMode => param]);
            (Request::CancelSchedule { job_id }, "cancel_schedule", session_writer, attached, true, idempotent_adapter_mutation, durable_dispatch_key(dispatch_key_and_generation), serialized, none, "job_id:String", [job_id: String => param]);
            (Request::Prune, "prune", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "-", []);
            (Request::Compact, "compact", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "-", []);
            (Request::Pin { text }, "pin", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "text:String", [text: String => param]);
            (Request::StoreFlycockpitCredential { credential }, "store_flycockpit_credential", owner_only, none, true, local_only, none, serialized, none, "credential:StoredFlycockpitCredential", [credential: StoredFlycockpitCredential => param]);
            (Request::ClearFlycockpitCredential, "clear_flycockpit_credential", owner_only, none, true, local_only, none, serialized, none, "-", []);
            (Request::DaemonStatus, "daemon_status", public_read, none, false, read_only, none, concurrent, none, "-", []);
            (Request::RefreshEnv { vars }, "refresh_env", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "vars:HashMap<String,String>", [vars: HashMap<String,String> => param]);
            (Request::RefreshConfig, "refresh_config", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "-", []);
            (Request::RecordUsage { kind, key, project_id }, "record_usage", owner_only, none, true, local_only, none, serialized, none, "kind:UsageKind|key:String|project_id:Option<String>", [kind: UsageKind => param, key: String => param, project_id: Option<String> => project]);
            (Request::GetUsageCounts { project_id }, "get_usage_counts", owner_only, none, false, local_only, none, concurrent, none, "project_id:Option<String>", [project_id: Option<String> => project]);
            (Request::StatsRollup { project_id, range, by_role }, "stats_rollup", owner_only, none, false, local_only, none, concurrent, none, "project_id:Option<String>|range:StatsRange|by_role:bool", [project_id: Option<String> => project, range: StatsRange => param, by_role: bool => param]);
            (Request::GuidanceEstimate { project_root, provider, model }, "guidance_estimate", project_read(project_root), none, false, read_only, none, concurrent, none, "project_root:String|provider:Option<String>|model:Option<String>", [project_root: String => project_root, provider: Option<String> => provider_model_left(model), model: Option<String> => provider_model_right(provider)]);
            (Request::RecoverSecurityBlockedMedia(..), "recover_security_blocked_media", owner_only, none, true, local_only, none, serialized, none, "-", []);
            (Request::RegisterLocalPathMedia(..), "register_local_path_media", owner_only, none, true, local_only, none, serialized, none, "-", []);
            (Request::RetainHttpsMedia(..), "retain_https_media", owner_only, none, true, local_only, none, serialized, none, "-", []);
            (Request::GetMediaAttachmentStatus(..), "get_media_attachment_status", public_read, none, false, read_only, none, serialized, none, "-", []);
            (Request::GetMediaAttachmentPreview(..), "get_media_attachment_preview", public_read, none, false, read_only, none, serialized, none, "-", []);
            (Request::BeginMediaUpload(..), "begin_media_upload", public_read, none, true, idempotent_adapter_mutation, domain_transaction(domain_result_tuple), serialized, none, "-", []);
            (Request::AppendMediaUploadChunk(..), "append_media_upload_chunk", public_read, none, true, idempotent_adapter_mutation, domain_transaction(domain_result_tuple), serialized, none, "-", []);
            (Request::CancelMediaUpload(..), "cancel_media_upload", public_read, none, true, idempotent_adapter_mutation, domain_transaction(domain_result_tuple), serialized, none, "-", []);
            (Request::DiscardUnreferencedMediaAttachment(..), "discard_unreferenced_media_attachment", public_read, none, true, idempotent_adapter_mutation, domain_transaction(domain_result_tuple), serialized, none, "-", []);
            (Request::GetMediaUploadStatus(..), "get_media_upload_status", public_read, none, false, read_only, none, serialized, none, "-", []);
            (Request::FinalizeMediaUpload(..), "finalize_media_upload", public_read, none, true, idempotent_adapter_mutation, domain_transaction(domain_result_tuple), serialized, none, "-", []);
            (Request::StopDaemon { grace_secs }, "stop_daemon", owner_only, none, true, local_only, none, serialized, none, "grace_secs:Option<u64>", [grace_secs: Option<u64> => param]);
            (Request::RestartIfIdle, "restart_if_idle", owner_only, none, true, local_only, none, serialized, none, "-", []);
            (Request::GetHostCapabilities, "get_host_capabilities", public_read, none, false, read_only, none, concurrent, none, "-", []);
            (Request::RefreshHostCapabilities, "refresh_host_capabilities", public_read, none, true, local_only, none, serialized, none, "-", []);
            (Request::MigrateKekPlacement { .. }, "migrate_kek_placement", owner_only, none, true, local_only, none, serialized, none, "dest:SecretStorePlacement", []);
            (Request::Unknown, "unknown", owner_only, none, false, rejected, rejected_before_dispatch, serialized, none, "-", []);
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
}

/// Cross-transport retry semantics for request tags that are reachable as
/// remote ledger operations. These are the only four *remote* classes.
///
/// The `command!` table (and the shared classification fixture) additionally
/// carry two non-remote class tokens, `local_only` and `rejected`, which
/// [`remote_class_value!`] maps to `None`: they never reserve a remote
/// operation. `owner_only` tags are always one of those two (see
/// `remote_operation_classification_is_exhaustive`), so a remote principal can
/// never obtain `Some(RemoteOperationClass)` for owner-bound work — authz stays
/// the barrier, class alone is not sufficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteOperationClass {
    ReadOnly,
    TransactionalMutation,
    IdempotentAdapterMutation,
    NonrepeatableMutation,
}

/// Durable evidence required before an adapter operation can report a
/// terminal outcome. This is independent of authorization/audit mutability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteAdapterRecoveryStrategy {
    DomainTransaction,
    DurableDispatchKey,
    DurableDesiredState,
    StagedFilesystemCommit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteAdapterEvidenceV1 {
    DomainResultTuple,
    DispatchKeyAndGeneration,
    DesiredStateGenerationAndObservedDigest,
    StagedArtifactFingerprintsAndFsyncBarriers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteAdapterRecoveryContractV1 {
    pub schema_version: u8,
    pub strategy: RemoteAdapterRecoveryStrategy,
    pub evidence: RemoteAdapterEvidenceV1,
    pub binds_operation_id: bool,
    pub binds_actor_generation: bool,
    pub binds_request_hash: bool,
    pub requires_dispatch_generation: bool,
}

macro_rules! remote_class_value {
    (read_only) => {
        Some(RemoteOperationClass::ReadOnly)
    };
    (transactional_mutation) => {
        Some(RemoteOperationClass::TransactionalMutation)
    };
    (idempotent_adapter_mutation) => {
        Some(RemoteOperationClass::IdempotentAdapterMutation)
    };
    (nonrepeatable_mutation) => {
        Some(RemoteOperationClass::NonrepeatableMutation)
    };
    // `local_only` and `rejected` are first-class table/fixture class strings
    // that are NOT remote ledger classes: they resolve to `None`, so the tag
    // never reserves a remote operation. `local_only` is owner-bound local work
    // gated by authz; `rejected` is the `unknown` catch-all.
    (local_only) => {
        None
    };
    (rejected) => {
        None
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownRemoteOperationClass;

macro_rules! recovery_contract_value {
    (none) => {
        None
    };
    (sql_transaction) => {
        None
    };
    (nonrepeatable_dispatch) => {
        None
    };
    (rejected_before_dispatch) => {
        None
    };
    (domain_transaction(domain_result_tuple)) => {
        Some(RemoteAdapterRecoveryContractV1::new(
            RemoteAdapterRecoveryStrategy::DomainTransaction,
            RemoteAdapterEvidenceV1::DomainResultTuple,
            false,
        ))
    };
    (durable_dispatch_key(dispatch_key_and_generation)) => {
        Some(RemoteAdapterRecoveryContractV1::new(
            RemoteAdapterRecoveryStrategy::DurableDispatchKey,
            RemoteAdapterEvidenceV1::DispatchKeyAndGeneration,
            true,
        ))
    };
    (durable_desired_state(desired_state_generation_and_observed_digest)) => {
        Some(RemoteAdapterRecoveryContractV1::new(
            RemoteAdapterRecoveryStrategy::DurableDesiredState,
            RemoteAdapterEvidenceV1::DesiredStateGenerationAndObservedDigest,
            true,
        ))
    };
    (staged_filesystem_commit(staged_artifact_fingerprints_and_fsync_barriers)) => {
        Some(RemoteAdapterRecoveryContractV1::new(
            RemoteAdapterRecoveryStrategy::StagedFilesystemCommit,
            RemoteAdapterEvidenceV1::StagedArtifactFingerprintsAndFsyncBarriers,
            true,
        ))
    };
}

impl RemoteAdapterRecoveryContractV1 {
    const fn new(
        strategy: RemoteAdapterRecoveryStrategy,
        evidence: RemoteAdapterEvidenceV1,
        requires_dispatch_generation: bool,
    ) -> Self {
        Self {
            schema_version: 1,
            strategy,
            evidence,
            binds_operation_id: true,
            binds_actor_generation: true,
            binds_request_hash: true,
            requires_dispatch_generation,
        }
    }
}

macro_rules! command_remote_class_tag {
    (($tag_value:ident) [$(($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $tag_value { $($tag => remote_class_value!($remote_class),)+ _ => None }
    }};
}
macro_rules! command_remote_recovery_tag {
    (($tag_value:ident) [$(($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $tag_value { $($tag => recovery_contract_value!($recovery $(($recovery_evidence))?),)+ _ => None }
    }};
}
macro_rules! command_remote_fcor_schema_tag {
    (($tag_value:ident) [$(($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $tag_value { $($tag => Some($fcor_schema),)+ _ => None }
    }};
}

macro_rules! command_typed_fcor_fields {
    (($request:ident) [$(($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($pattern => {
                // Matching `&Request` binds every field by reference. These
                // assignments make a wrong typed token a compile error and
                // make every token a consumed runtime value rather than
                // decorative metadata.
                $(let _: &$fcor_type = $fcor_field;)*
                ($tag, vec![$((stringify!($fcor_field), stringify!($fcor_type))),*])
            },)+
        }
    }};
}

macro_rules! encode_fcor_bound_fields {
    ($out:ident; $($name:ident: $ty:ty => $role:ident $(($($arg:ident),*))?),* $(,)?) => {{
        $(encode_fcor_role!($out, $name, $role);)*
    }};
}

macro_rules! encode_fcor_role {
    ($out:ident, $name:ident, param) => {
        $name.encode_fcor_value_v1(&mut $out)?;
    };
    ($out:ident, $name:ident, scheduled) => {
        $name.encode_fcor_value_v1(&mut $out)?;
    };
    ($out:ident, $name:ident, legacy_message) => {
        // Rejection is performed before entering the exhaustive generated
        // encoder. Keeping this role as an omission preserves the one typed
        // command-table source without placing a diverging expression ahead
        // of the remaining field encoders in this arm.
        let _ = $name;
    };
    ($out:ident, $name:ident, $resource:ident) => {
        let _ = $name;
    };
}

macro_rules! command_encode_fcor_params {
    (($request:ident) [$(($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        use $crate::remote_operation_fcor::CanonicalFcorValueV1 as _;
        match $request {
            $($pattern => {
                $(let _: &$fcor_type = $fcor_field;)*
                let mut out = $crate::remote_operation_fcor::CanonicalParamsV1::new();
                // Resource-only and fieldless variants still share this arm.
                // Taking the mutable reference keeps the generated binding
                // uniform without changing canonical bytes.
                let _: &mut $crate::remote_operation_fcor::CanonicalParamsV1 = &mut out;
                encode_fcor_bound_fields!(out; $($fcor_field: $fcor_type => $fcor_role $(($($fcor_role_arg),*))?),*);
                Ok(out.into_bytes())
            },)+
        }
    }};
}

impl Request {
    pub fn remote_operation_class(
        &self,
    ) -> std::result::Result<RemoteOperationClass, UnknownRemoteOperationClass> {
        remote_operation_class_for_tag(self.command_tag()).ok_or(UnknownRemoteOperationClass)
    }

    /// Ordered, type-checked FCOR fields for this concrete request variant.
    /// The value encoder expands this same command-table callback so field
    /// declaration, field access, and canonical order cannot drift apart.
    pub fn typed_remote_operation_fcor_fields(
        &self,
    ) -> (&'static str, Vec<(&'static str, &'static str)>) {
        crate::command!(command_typed_fcor_fields, self)
    }

    /// Canonical parameter bytes for legacy daemon requests. The foundation
    /// v2 message envelope is intentionally a separate protocol and the
    /// retired legacy message variant has no remote-operation encoding.
    pub fn canonical_remote_operation_params_v1(&self) -> anyhow::Result<Vec<u8>> {
        if matches!(self, Self::SendUserMessage { .. }) {
            anyhow::bail!("legacy_send_user_message_not_remote_operation");
        }
        crate::command!(command_encode_fcor_params, self)
    }
}
pub fn remote_operation_class_for_tag(tag: &str) -> Option<RemoteOperationClass> {
    crate::command!(command_remote_class_tag, tag)
}
pub fn remote_operation_fcor_schema_for_tag(tag: &str) -> Option<&'static str> {
    crate::command!(command_remote_fcor_schema_tag, tag)
}

fn canonical_fcor_codec_for_rust_type(ty: &str) -> Option<&'static str> {
    Some(match ty {
        "u16" => "u16",
        "u32" => "u32",
        "u64" => "u64",
        "i64" => "i64",
        "bool" => "bool",
        "String" => "string",
        "Uuid" => "uuid",
        "Vec<u8>" => "bytes",
        "Option<String>" => "option<string>",
        "Option<Uuid>" => "option<uuid>",
        "Option<bool>" => "option<bool>",
        "Option<i64>" => "option<i64>",
        "Option<u32>" => "option<u32>",
        "Option<u64>" => "option<u64>",
        "Vec<Uuid>" => "list<uuid>",
        "Vec<(String,String)>" => "list<tuple<string,string>>",
        "HashMap<String,String>" => "map<string,string>",
        "Vec<ImageAttachmentRef>" => "list<struct:ImageAttachmentRef:v1>",
        "Vec<TagExpansionMeta>" => "list<struct:TagExpansionMeta:v1>",
        "Option<EnvSnapshotWire>" => "option<struct:EnvSnapshotWire:v1>",
        "Option<RunInvocationOptions>" => "option<struct:RunInvocationOptions:v1>",
        "Option<LeakRotationState>" => "option<enum16:LeakRotationState>",
        "Option<LlmMode>" => "option<enum16:LlmMode>",
        "Option<PromptCacheRetention>" => "option<enum16:PromptCacheRetention>",
        "Option<SandboxMode>" => "option<enum16:SandboxMode>",
        "Option<cockpit_config::config::providers::ThinkingMode>" => "option<enum16:ThinkingMode>",
        "Option<cockpit_config::config::providers::ActiveModelRef>" => {
            "option<struct:ActiveModelRef:v1>"
        }
        "ActiveModelSwitchTrigger"
        | "AppFlagKey"
        | "ApprovalMode"
        | "AssistantSessionResolutionMode"
        | "AttachmentPurpose"
        | "CaffeinateMode"
        | "CuratorAction"
        | "EnvDriftPolicy"
        | "ExportSessionKind"
        | "GoalDisposition"
        | "LeakRotationDisposition"
        | "LlmMode"
        | "LspControlAction"
        | "UsageKind"
        | "WorkspaceTrustMode"
        | "StatsRange" => "enum16",
        "ResolveResponse" | "ScheduledJobCreate" | "StoredFlycockpitCredential" => "struct:v1",
        // Fully-path-qualified struct types used by some command fcor schemas map to
        // their short canonical `struct:<Name>:v1` form (crate paths never leak into the
        // cross-language canonical identifier).
        "crate::terminal::TerminalBinding" => "struct:TerminalBinding:v1",
        "crate::terminal::TerminalIngressMetadata" => "struct:TerminalIngressMetadata:v1",
        "crate::remote_transport::bulk::RemoteBulkTransferRef" => "struct:RemoteBulkTransferRef:v1",
        "crate::remote_protocol_id::RemoteTransferId" => "struct:RemoteTransferId:v1",
        _ => return None,
    })
}

pub fn canonical_remote_operation_fcor_schema_for_tag(tag: &str) -> Option<String> {
    let source = remote_operation_fcor_schema_for_tag(tag)?;
    if source == "-" {
        return Some("-".to_owned());
    }
    source
        .split('|')
        .map(|field| {
            let (name, ty) = field.split_once(':')?;
            let codec = canonical_fcor_codec_for_rust_type(ty)?;
            let codec = match codec {
                "enum16" => format!("enum16:{ty}"),
                "struct:v1" => format!("struct:{ty}:v1"),
                other => other.to_owned(),
            };
            Some(format!("{name}:{codec}"))
        })
        .collect::<Option<Vec<_>>>()
        .map(|fields| fields.join("|"))
}
pub fn remote_adapter_recovery_contract_for_tag(
    tag: &str,
) -> Option<RemoteAdapterRecoveryContractV1> {
    crate::command!(command_remote_recovery_tag, tag)
}
pub fn remote_adapter_recovery_strategy_for_tag(
    tag: &str,
) -> Option<RemoteAdapterRecoveryStrategy> {
    remote_adapter_recovery_contract_for_tag(tag).map(|contract| contract.strategy)
}

/// Largest 48-bit Unix-millisecond timestamp an RFC 9562 UUIDv7 can encode
/// (`2^48 - 1`). Timestamps beyond this range cannot be represented and are
/// rejected by [`remote_operation_uuid_v7_from_parts`].
pub const MAX_UUID_V7_UNIX_MS: u64 = 0xffff_ffff_ffff;

/// Build an RFC 9562 UUIDv7 operation identity from an injected wall clock and
/// 16 random bytes, using the exact byte layout the TypeScript
/// `generateRemoteOperationUuidV7` reproduces so both languages emit
/// byte-identical operation identities. The 48-bit big-endian `unix_ms` fills
/// bytes 0-5, version `7` occupies the high nibble of byte 6, the RFC 4122
/// variant (`0b10`) the top two bits of byte 8, and every other bit is random.
/// The shared vectors in `remote-operation-uuidv7-v1.json` lock this contract
/// across languages. This is a pure constructor; it makes no claim of
/// process-global monotonic ordering.
pub fn remote_operation_uuid_v7_from_parts(
    unix_ms: u64,
    mut bytes: [u8; 16],
) -> anyhow::Result<Uuid> {
    anyhow::ensure!(
        unix_ms <= MAX_UUID_V7_UNIX_MS,
        "UUIDv7 timestamp {unix_ms} exceeds the 48-bit range"
    );
    bytes[0] = (unix_ms >> 40) as u8;
    bytes[1] = (unix_ms >> 32) as u8;
    bytes[2] = (unix_ms >> 24) as u8;
    bytes[3] = (unix_ms >> 16) as u8;
    bytes[4] = (unix_ms >> 8) as u8;
    bytes[5] = unix_ms as u8;
    // Version 7 in the high nibble of byte 6; keep the four random low bits.
    bytes[6] = 0x70 | (bytes[6] & 0x0f);
    // RFC 4122 variant (0b10) in the top two bits of byte 8; keep six random bits.
    bytes[8] = 0x80 | (bytes[8] & 0x3f);
    Ok(Uuid::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ImportSessionArchive` must not be able to carry archive bytes inline.
    ///
    /// Before this prompt the variant was
    /// `ImportSessionArchive { archive_base64: String, as_new: bool }`, so a
    /// whole ZIP rode one NDJSON frame bounded only by the retired 8 MiB
    /// `MAX_FRAME_BYTES`. The corrected expectation rejects that shape
    /// outright: the old wire form no longer deserializes, and the type system
    /// offers nowhere to put the bytes.
    #[test]
    fn import_session_archive_rejects_inline_bytes() {
        use crate::remote_transport::bulk::{RemoteBulkMimeClass, RemoteBulkTransferRef};
        use crate::remote_transport::lane::MAX_LOGICAL_PAYLOAD_BYTES;

        // The retired inline shape fails to parse. This is the assertion the
        // pre-migration production code could not satisfy.
        let legacy = serde_json::json!({
            "request": "import_session_archive",
            "params": { "archive_base64": "UEsDBAoAAAAA", "as_new": true },
        });
        assert!(
            serde_json::from_value::<Request>(legacy).is_err(),
            "inline archive_base64 must no longer be accepted"
        );

        // A very large inline archive is likewise unrepresentable.
        let huge = serde_json::json!({
            "request": "import_session_archive",
            "params": { "archive_base64": "A".repeat(1024 * 1024), "as_new": false },
        });
        assert!(serde_json::from_value::<Request>(huge).is_err());

        // The accepted shape is a bounded typed transfer reference.
        let transfer_id = crate::remote_protocol_id::tag_protocol_id_bytes::<
            crate::remote_protocol_id::kind::Transfer,
        >([9u8; 16])
        .unwrap();
        let request = Request::ImportSessionArchive {
            transfer: RemoteBulkTransferRef::new(
                transfer_id,
                64 * 1024 * 1024,
                [0xAB; 32],
                RemoteBulkMimeClass::Archive,
            )
            .unwrap(),
            as_new: true,
        };
        assert_eq!(request.wire_tag(), "import_session_archive");

        let encoded = serde_json::to_string(&request).unwrap();
        // A 64 MiB archive now produces a tiny request frame.
        assert!(
            encoded.len() < 1024,
            "a transfer reference must stay small, got {} bytes",
            encoded.len()
        );
        assert!(encoded.len() < MAX_LOGICAL_PAYLOAD_BYTES);
        // No base64 blob field survives anywhere in the encoding.
        assert!(!encoded.contains("archive_base64"));

        let round_tripped: Request = serde_json::from_str(&encoded).unwrap();
        match round_tripped {
            Request::ImportSessionArchive { transfer, as_new } => {
                assert!(as_new);
                assert_eq!(transfer.total_length_value(), 64 * 1024 * 1024);
                assert_eq!(transfer.mime_class, RemoteBulkMimeClass::Archive);
            }
            other => panic!("unexpected variant: {}", other.wire_tag()),
        }
    }

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
            expected_model_state_generation: None,
            expected_model: None,
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
        (($($context:ident),*) [$(($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
            vec![$($tag),+]
        }};
    }

    macro_rules! remote_operation_rows {
        (($($context:ident),*) [$(($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
            vec![$(($tag, $mutating, stringify!($authz), stringify!($remote_class))),+]
        }};
    }

    macro_rules! fcor_source_rows {
        (($($context:ident),*) [$(($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
            vec![$((
                stringify!($pattern),
                $tag,
                $fcor_schema,
                vec![$((stringify!($fcor_field), stringify!($fcor_type), concat!(stringify!($fcor_role), $("(", stringify!($($fcor_role_arg),*), ")")?))),*],
            )),+]
        }};
    }

    fn request_source_field_schemas() -> std::collections::BTreeMap<String, String> {
        use quote::ToTokens;
        let syntax = syn::parse_file(include_str!("request.rs")).expect("request.rs parses");
        let request = syntax
            .items
            .into_iter()
            .find_map(|item| match item {
                syn::Item::Enum(item) if item.ident == "Request" => Some(item),
                _ => None,
            })
            .expect("Request enum declaration");
        request
            .variants
            .into_iter()
            .map(|variant| {
                let schema = match variant.fields {
                    syn::Fields::Unit => "-".to_owned(),
                    // Newtype variants wrap an opaque versioned payload whose
                    // fields live in `cockpit-db` and are FCOR-audited there.
                    // At the proto level they are opaque, matching the "-"
                    // schema the command table declares for them.
                    syn::Fields::Unnamed(_) => "-".to_owned(),
                    syn::Fields::Named(fields) => fields
                        .named
                        .into_iter()
                        .map(|field| {
                            let name = field.ident.expect("named Request field");
                            let ty = field.ty.into_token_stream().to_string().replace(' ', "");
                            format!("{name}:{ty}")
                        })
                        .collect::<Vec<_>>()
                        .join("|"),
                };
                (variant.ident.to_string(), schema)
            })
            .collect()
    }

    #[test]
    fn remote_operation_fcor_source_schema_cannot_drift() {
        let declared = request_source_field_schemas();
        let rows = crate::command!(fcor_source_rows);
        assert_eq!(
            declared.len(),
            rows.len(),
            "enum/command row count mismatch"
        );
        let mut variants = std::collections::BTreeSet::new();
        let mut tags = std::collections::BTreeSet::new();
        for (pattern, tag, schema, typed_fields) in rows {
            // Newtype/unit variants are FCOR-opaque (schema "-") and their
            // patterns legitimately use `(..)`; only named-field patterns can
            // conceal auditable fields behind `..`.
            assert!(
                schema == "-" || !pattern.contains(".."),
                "FCOR pattern conceals fields: {pattern}"
            );
            // `(` terminates the variant name for newtype patterns
            // (`RecoverSecurityBlockedMedia(..)`), just as `{` does for
            // named-field patterns; otherwise the `(..)` would be carried into
            // the lookup key and never match the declared variant ident.
            let variant = pattern
                .strip_prefix("Request :: ")
                .or_else(|| pattern.strip_prefix("Request::"))
                .unwrap_or(pattern)
                .split([' ', '\t', '\n', '\r', '{', '('])
                .next()
                .unwrap();
            assert!(
                variants.insert(variant),
                "duplicate command variant {variant}"
            );
            assert!(tags.insert(tag), "duplicate command tag {tag}");
            assert_eq!(
                declared.get(variant).map(String::as_str),
                Some(schema),
                "FCOR source schema drift for {tag} ({variant})"
            );
            let typed_schema = if typed_fields.is_empty() {
                "-".to_owned()
            } else {
                typed_fields
                    .iter()
                    .map(|(name, ty, _)| {
                        format!("{name}:{}", ty.replace(' ', "").replace("$crate", "crate"))
                    })
                    .collect::<Vec<_>>()
                    .join("|")
            };
            assert_eq!(typed_schema, schema, "typed FCOR token drift for {tag}");
            let field_names = typed_fields
                .iter()
                .map(|(name, _, _)| *name)
                .collect::<std::collections::BTreeSet<_>>();
            for (name, ty, role) in &typed_fields {
                let ty = ty.replace(' ', "");
                let valid = match role.split_once('(').map(|(head, _)| head).unwrap_or(role) {
                    "param" | "legacy_message" => true,
                    "session" => ty == "Uuid" || ty == "Option<Uuid>",
                    "project" => ty == "Option<String>",
                    "project_root" => ty == "String",
                    "project_root_effective" => ty == "Option<String>",
                    "file_existing" | "file_write_target" | "rename_source" => ty == "String",
                    "terminal" | "upload" | "interrupt" | "queue" => ty == "Uuid",
                    "provider_model_left" | "provider_model_right" => {
                        ty == "String" || ty == "Option<String>"
                    }
                    "scheduled" => ty == "ScheduledJobCreate",
                    _ => false,
                };
                assert!(valid, "invalid FCOR role {role} for {tag}.{name}:{ty}");
                if let Some((_, argument)) = role.split_once('(') {
                    let counterpart = argument.trim_end_matches(')');
                    assert!(
                        field_names.contains(counterpart),
                        "missing FCOR role counterpart {tag}.{counterpart}"
                    );
                    if role.starts_with("provider_model_left") {
                        let expected = format!("provider_model_right({name})");
                        assert!(typed_fields.iter().any(|(other, _, other_role)| {
                            *other == counterpart && *other_role == expected
                        }));
                    }
                }
            }
            assert!(
                canonical_remote_operation_fcor_schema_for_tag(tag).is_some(),
                "unsupported canonical FCOR type in {tag}: {schema}"
            );
            assert!(
                !schema.contains("usize"),
                "platform-width FCOR field in {tag}"
            );
        }
        assert_eq!(
            variants.len(),
            declared.len(),
            "not every Request variant was consumed"
        );
    }

    macro_rules! remote_evidence_json {
        () => {
            serde_json::Value::Null
        };
        ($evidence:ident) => {
            serde_json::Value::String(stringify!($evidence).to_owned())
        };
    }

    macro_rules! remote_operation_fixture_rows {
        (($($context:ident),*) [$(($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
            vec![$(serde_json::json!({
                "tag": $tag,
                "class": stringify!($remote_class),
                "strategy": stringify!($recovery),
                "evidence": remote_evidence_json!($($recovery_evidence)?),
                "fcorSchema": $fcor_schema,
                "fcorCanonicalSchema": canonical_remote_operation_fcor_schema_for_tag($tag)
                    .unwrap_or_else(|| panic!(
                        "no registered canonical FCOR schema for tag {} (source schema {:?})",
                        $tag,
                        remote_operation_fcor_schema_for_tag($tag)
                    )),
                "fcorRoles": [$({
                    "field": stringify!($fcor_field),
                    "type": stringify!($fcor_type).replace(' ', "").replace("$crate", "crate"),
                    "role": concat!(stringify!($fcor_role), $("(", stringify!($($fcor_role_arg),*), ")")?),
                }),*],
            })),+]
        }};
    }

    #[test]
    fn remote_operation_classification_is_exhaustive() {
        use std::collections::BTreeSet;

        let rows = crate::command!(remote_operation_rows);
        let unique: BTreeSet<_> = rows.iter().map(|(tag, ..)| *tag).collect();
        assert_eq!(unique.len(), rows.len(), "request tags must be unique");
        for (tag, audit_mutating, authz, declared_class) in rows {
            let class = remote_operation_class_for_tag(tag);
            if authz == "owner_only" {
                assert_eq!(
                    declared_class,
                    if tag == "unknown" {
                        "rejected"
                    } else {
                        "local_only"
                    }
                );
                assert_eq!(class, None, "{tag} must be rejected before reservation");
                continue;
            }
            let class = class.unwrap_or_else(|| panic!("{tag} has no remote operation class"));
            if audit_mutating && tag != "list_project_notes" {
                assert_ne!(
                    class,
                    RemoteOperationClass::ReadOnly,
                    "audit-mutating request {tag} needs an explicit remote mutation class"
                );
            }
            match class {
                RemoteOperationClass::IdempotentAdapterMutation => assert!(
                    remote_adapter_recovery_contract_for_tag(tag).is_some(),
                    "adapter mutation {tag} needs a recovery strategy"
                ),
                _ => assert_eq!(
                    remote_adapter_recovery_strategy_for_tag(tag),
                    None,
                    "non-adapter {tag} must not acquire an adapter strategy"
                ),
            }
        }
        assert_eq!(
            remote_operation_class_for_tag("terminal_input"),
            Some(RemoteOperationClass::NonrepeatableMutation),
            "remote consequence is independent of the audit mutating bit"
        );
        assert_eq!(
            remote_operation_class_for_tag("write_bulk_transfer_chunk"),
            None
        );
        assert_eq!(
            remote_adapter_recovery_strategy_for_tag("set_default_model"),
            None
        );
        assert_eq!(remote_operation_class_for_tag("set_workspace_trust"), None);
        assert_eq!(
            remote_adapter_recovery_contract_for_tag("set_workspace_trust"),
            None
        );

        let rows = serde_json::Value::Array(crate::command!(remote_operation_fixture_rows));
        // Golden-update path (parity with the other cross-language fixtures): regenerate
        // the shared classification fixture with `COCKPIT_UPDATE_GOLDEN=1`.
        if std::env::var("COCKPIT_UPDATE_GOLDEN").is_ok() {
            let out = serde_json::json!({ "schemaVersion": 1, "rows": rows });
            let path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../packages/cockpit-protocol/fixtures/remote-operation-classification-v1.json"
            );
            std::fs::write(
                path,
                format!("{}\n", serde_json::to_string_pretty(&out).unwrap()),
            )
            .unwrap();
            return;
        }
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../packages/cockpit-protocol/fixtures/remote-operation-classification-v1.json"
        ))
        .unwrap();
        assert_eq!(fixture["schemaVersion"], 1);
        assert_eq!(
            fixture["rows"], rows,
            "the shared Rust/TypeScript classification fixture must match every command column exactly"
        );
    }

    #[test]
    fn remote_operation_uuidv7_vectors() {
        // Byte-identity with the TypeScript `generateRemoteOperationUuidV7`:
        // both languages consume this same fixture and must reproduce every
        // `expected` identity from the injected timestamp and random bytes.
        let raw = include_str!(
            "../../../packages/cockpit-protocol/fixtures/remote-operation-uuidv7-v1.json"
        );
        let fixture: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert_eq!(fixture["schemaVersion"], 1);
        let vectors = fixture["vectors"].as_array().expect("vectors array");
        assert!(!vectors.is_empty(), "fixture must carry vectors");
        for vector in vectors {
            let unix_ms = vector["unixMs"].as_u64().expect("unixMs u64");
            let random_hex = vector["randomHex"].as_str().expect("randomHex string");
            let expected = vector["expected"].as_str().expect("expected string");
            assert_eq!(random_hex.len(), 32, "randomHex must be 16 bytes");
            let mut bytes = [0u8; 16];
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&random_hex[index * 2..index * 2 + 2], 16)
                    .expect("hex byte");
            }
            let id = remote_operation_uuid_v7_from_parts(unix_ms, bytes)
                .unwrap_or_else(|error| panic!("vector {} failed: {error}", vector["name"]));
            assert_eq!(id.to_string(), expected, "vector {}", vector["name"]);
            // Strict version-7 identity, independent of the random low bits.
            assert_eq!(id.get_version_num(), 7, "vector {}", vector["name"]);
            assert_eq!(
                Uuid::parse_str(expected).unwrap(),
                id,
                "canonical parse mismatch for {}",
                vector["name"]
            );
        }
        let rejected = fixture["rejectedUnixMs"]
            .as_array()
            .expect("rejectedUnixMs array");
        assert!(
            !rejected.is_empty(),
            "fixture must carry rejected timestamps"
        );
        for entry in rejected {
            let unix_ms = entry["unixMs"].as_u64().expect("rejected unixMs u64");
            assert!(
                remote_operation_uuid_v7_from_parts(unix_ms, [0u8; 16]).is_err(),
                "timestamp {unix_ms} must be rejected as out of range"
            );
        }
        // The 48-bit boundary is accepted; one past it is not.
        assert!(remote_operation_uuid_v7_from_parts(MAX_UUID_V7_UNIX_MS, [0u8; 16]).is_ok());
        assert!(remote_operation_uuid_v7_from_parts(MAX_UUID_V7_UNIX_MS + 1, [0u8; 16]).is_err());
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
    fn leak_rpcs_are_registered_in_both_macro_tables() {
        let requests = [
            Request::ListLeakReports {
                cursor: None,
                limit: Some(50),
                project_root: None,
                session_id: None,
                rotation: None,
            },
            Request::BeginLeakReveal {
                report_id: "r1".into(),
            },
            Request::MarkLeakRotated {
                report_id: "r1".into(),
                rotation: crate::LeakRotationDisposition::Accept,
            },
            Request::DeleteLeakReport {
                report_id: "r1".into(),
            },
        ];
        let tags: Vec<_> = requests.iter().map(Request::wire_tag).collect();
        assert_eq!(
            tags,
            [
                "list_leak_reports",
                "begin_leak_reveal",
                "mark_leak_rotated",
                "delete_leak_report",
            ]
        );
        let command_tags = crate::command!(command_tags);
        for tag in &tags {
            assert!(command_tags.contains(tag), "missing command row for {tag}");
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
            expected_model_state_generation: None,
            expected_model: None,
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
            expected_model_state_generation: None,
            expected_model: None,
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
            expected_model_state_generation: None,
            expected_model: None,
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
            expected_model_state_generation: None,
            expected_model: None,
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
            expected_model_state_generation: None,
            expected_model: None,
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
            expected_model_state_generation: None,
            expected_model: None,
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

    #[test]
    fn fenced_model_expectation_is_strict_and_round_trips() {
        let model = cockpit_config::config::providers::ActiveModelRef {
            provider: "openai".to_string(),
            model: "gpt-5".to_string(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        };
        let request = Request::SendUserMessage {
            expected_model_state_generation: Some(7),
            expected_model: Some(model.clone()),
            client_submission_id: Uuid::new_v4(),
            text: "fenced".to_string(),
            display_text: None,
            tag_expansions: Vec::new(),
            image_refs: Vec::new(),
            forced_skill: None,
            run_invocation_options: None,
        };
        request.validate_semantics().unwrap();
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["params"]["expected_model_state_generation"], 7);
        assert_eq!(json["params"]["expected_model"]["provider"], "openai");

        let invalid = Request::SendUserMessage {
            expected_model_state_generation: Some(7),
            expected_model: None,
            client_submission_id: Uuid::new_v4(),
            text: "invalid".to_string(),
            display_text: None,
            tag_expansions: Vec::new(),
            image_refs: Vec::new(),
            forced_skill: None,
            run_invocation_options: None,
        };
        assert!(invalid.validate_semantics().is_err());
    }

    #[test]
    fn retained_https_wire_accepts_production_uuid_v4_session_authority() {
        use cockpit_db::media_attachments::{RequestedLocalPathMediaKind, RetainHttpsMediaV1};

        let session_id = Uuid::new_v4();
        let request = Request::RetainHttpsMedia(RetainHttpsMediaV1 {
            schema_version: 1,
            kind: "retainHttpsMedia".into(),
            local_operation_id: Uuid::now_v7(),
            owner_principal_digest: "11".repeat(32),
            session_id,
            canonical_project_digest: "22".repeat(32),
            client_draft_id: Uuid::now_v7(),
            requested_media_kind: RequestedLocalPathMediaKind::Image,
            url: "https://media.example.test/image.png".into(),
        });
        let encoded = serde_json::to_string(&request).unwrap();
        let decoded: Request = serde_json::from_str(&encoded).unwrap();
        let Request::RetainHttpsMedia(decoded) = decoded else {
            panic!("wrong typed-media wire variant")
        };
        assert_eq!(decoded.session_id, session_id);
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
