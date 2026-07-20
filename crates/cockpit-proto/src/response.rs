use super::*;

// ---- Responses -------------------------------------------------------------

/// Daemon → client RPC responses. Each variant is the typed answer to
/// one [`Request`] kind. The envelope id pairs the two sides.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "response", rename_all = "snake_case", content = "data")]
pub enum Response {
    /// Generic "yes, accepted." Used by fire-and-forget requests
    /// whose effects flow back as events (`SendUserMessage`,
    /// `CancelTurn`, `ResolveInterrupt`, …).
    Ack,

    /// A user message was accepted by the session worker. `status = queued`
    /// means it is still removable; `status = folding` means it has already
    /// crossed the driver boundary and remove requests will not apply.
    UserMessageQueued {
        item: QueueItem,
        queue: Vec<QueueItem>,
    },

    DelegationSteer {
        result: DelegationSteerResult,
    },

    AttachmentUploadStarted {
        upload_id: Uuid,
        max_chunk_base64_bytes: usize,
    },

    AttachmentChunkAccepted {
        upload_id: Uuid,
        next_offset: usize,
    },

    AttachmentUploaded {
        image_ref: ImageAttachmentRef,
    },

    TerminalPasteImage {
        terminal_id: Uuid,
        path: String,
    },

    /// Result of [`Request::RemoveQueuedUserMessage`].
    RemoveQueuedUserMessageResult {
        applied: bool,
        reason: RemoveQueuedUserMessageReason,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        removed_item: Option<QueueItem>,
        queue: Vec<QueueItem>,
    },

    /// Result of [`Request::RemoveEditableQueuedUserMessages`].
    RemoveQueuedUserMessagesResult {
        applied: bool,
        reason: RemoveQueuedUserMessageReason,
        removed_items: Vec<QueueItem>,
        queue: Vec<QueueItem>,
    },

    Attached {
        session_id: Uuid,
        /// 6-char display id (GOALS §17b). Used by the TUI as the
        /// predecessor short-id when this session later spawns a
        /// `/compact` handoff. Empty for pre-§17 rows not yet backfilled.
        #[serde(default)]
        short_id: String,
        project_root: String,
        project_id: String,
        active_agent: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        active_agent_path: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        foreground_target: Option<QueueTarget>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        active_subagent: Option<ActiveSubagent>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        active_model_state: Option<ActiveModelState>,
        history: Vec<HistoryEntry>,
        #[serde(default)]
        paused_work: Vec<PausedWorkSummary>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        repair_required: Option<Box<ResumeRepairState>>,
        #[serde(default = "default_daemon_version")]
        daemon_version: String,
        #[serde(default)]
        compatible: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        env_baseline: Option<EnvSnapshotMeta>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        env_session: Option<EnvSnapshotMeta>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        env_drift: Option<Box<EnvDiffSummary>>,
        #[serde(default)]
        env_policy_applied: EnvDriftPolicy,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        btw_fork: Option<BtwForkInfo>,
    },

    SubagentTranscript {
        session_id: Uuid,
        task_call_id: String,
        label: String,
        history: Vec<HistoryEntry>,
    },

    Sessions {
        sessions: Vec<SessionSummary>,
    },

    SessionMessages {
        session_id: Uuid,
        messages: Vec<SessionMessage>,
        has_more: bool,
    },

    /// A `/note` session-history note was recorded ([`Request::RecordSessionNote`]).
    /// `seq` is the assigned monotonic `session_events` sequence so the client
    /// can place the note row in the correct chronological position.
    NoteRecorded {
        seq: i64,
    },

    GoalStatus {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        goal: Option<GoalSummary>,
    },

    GoalUpdated {
        goal: GoalSummary,
    },

    GoalCleared {
        cleared: bool,
    },

    Assistants {
        assistants: Vec<AssistantSummary>,
    },

    AssistantSessionCreated {
        session: AssistantSessionCreated,
    },

    AutoTitle {
        session_id: Uuid,
        title: String,
    },

    ExportSessionData {
        data: ExportSessionData,
    },

    Curator {
        result: CuratorResult,
    },

    /// Per-session live status. Answer to [`Request::SessionLiveStatus`].
    /// Only sessions with a live worker appear; everything else is
    /// implicitly not-processing / no-jobs.
    SessionLiveStatus {
        statuses: Vec<LiveStatus>,
    },

    /// New session created by `ForkSession`.
    Forked {
        session_id: Uuid,
        short_id: String,
        parent_session_id: Uuid,
        #[serde(default)]
        fork_point_turn_id: Option<String>,
    },

    /// Result of [`Request::CreateBtwFork`].
    BtwFork {
        info: BtwForkInfo,
        created: bool,
    },

    Skills {
        skills: Vec<SkillSummary>,
    },

    /// Answer to [`Request::ResourceSnapshot`].
    ResourceSnapshot {
        snapshot: ResourceSchedulerSnapshot,
    },

    /// Answer to [`Request::PromoteResource`].
    PromoteResourceResult {
        status: ResourcePromoteStatus,
        message: String,
        snapshot: ResourceSchedulerSnapshot,
    },

    ScheduledJob {
        job: ScheduledJobSummary,
    },

    ScheduledJobs {
        jobs: Vec<ScheduledJobSummary>,
    },

    ScheduledJobDeleted {
        id: String,
        deleted: bool,
    },

    ScheduledJobRunQueued {
        id: String,
    },

    Agents {
        agents: Vec<AgentSummary>,
    },

    Models {
        models: Vec<ModelSummary>,
    },

    FsList {
        entries: Vec<FsEntry>,
        truncated: bool,
    },

    FsStat {
        entry: FsEntry,
    },

    FsRead {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content: Option<String>,
        hash: String,
        truncated: bool,
        kind: FsReadKind,
    },

    FsWrite {
        hash: String,
    },

    GitStatus {
        entries: Vec<GitStatusEntry>,
    },

    GitDiffFile {
        diff: String,
        truncated: bool,
    },

    TerminalOpened {
        terminal_id: Uuid,
        viewer_count: usize,
        recording: bool,
    },

    LspControlResult {
        message: String,
    },

    DaemonStatus {
        pid: u32,
        uptime_secs: u64,
        active_sessions: u32,
        socket_path: String,
        #[serde(default = "default_daemon_version")]
        daemon_version: String,
        #[serde(default)]
        protocol_version: u32,
        #[serde(default)]
        paused_sessions: u32,
        /// Resolved backing SQLite path used by this daemon process.
        #[serde(default)]
        database_path: String,
        /// Exact amended-squash schema identity (`PRAGMA user_version`).
        #[serde(default)]
        schema_version: i64,
    },

    /// The three 30-day autocomplete count maps. `models` and `slash`
    /// are global; `tags` is scoped to the requested project. Answer to
    /// [`Request::GetUsageCounts`].
    UsageCounts {
        models: HashMap<String, u64>,
        slash: HashMap<String, u64>,
        tags: HashMap<String, u64>,
    },

    StatsRollup {
        rollup: StatsRollup,
    },

    /// Pre-flight sizing for the fresh-chat context indicator. `file` is
    /// the basename of the matched guidance file, or `None` when none was
    /// found. `tokens` is the guidance-file **body** size (the `… in
    /// <file>` label); `system_tokens` is the composed system prompt
    /// (role prompt + OS + session). Both are estimated with the
    /// tokenizer calibrated for the request's `(provider, model)`.
    /// Answer to [`Request::GuidanceEstimate`].
    GuidanceEstimate {
        #[serde(default)]
        file: Option<String>,
        tokens: u64,
        system_tokens: u64,
        #[serde(default)]
        model_instruction_tokens: u64,
    },

    /// The resulting sandbox mode after a [`Request::SetSandbox`].
    SandboxState {
        mode: SandboxMode,
        enabled: bool,
        #[serde(default)]
        container_network_enabled: bool,
        container_availability: ContainerAvailability,
    },

    /// The resulting sandbox-escalation availability after
    /// [`Request::SetSandboxEscalation`]. Session-only — not persisted.
    SandboxEscalationState {
        enabled: bool,
    },

    /// The resulting redaction-source state after a
    /// [`Request::SetRedaction`] (`/toggle-redaction`). The TUI surfaces it
    /// via a toast. Session-only — not persisted.
    RedactionState {
        scan_environment: bool,
        scan_dotenv: bool,
        scan_ssh_keys: bool,
    },

    /// The resulting request-preflight state after a [`Request::SetPreflight`]
    /// (`/preflight`). The TUI surfaces it via a toast + mirror update.
    /// Session-only — not persisted.
    PreflightState {
        enabled: bool,
    },

    /// The resulting trusted-only state after [`Request::SetTrustedOnly`].
    TrustedOnlyState {
        enabled: bool,
    },

    /// The resulting command-approval mode after
    /// [`Request::SetApprovalMode`]. Session-only — not persisted.
    ApprovalModeState {
        mode: ApprovalMode,
    },

    /// The resulting delegation-recursion override after
    /// [`Request::SetDelegationRecursion`]. Session-only — not persisted.
    DelegationRecursionState {
        enabled: bool,
        default_depth: u32,
    },

    /// The resulting caffeination state after a [`Request::SetCaffeinate`].
    /// `message` is the honest confirmation text for the toast (names the
    /// lid-close limitation / missing mechanism where applicable);
    /// `lid_close_guaranteed` is `true` only when active *and* lid-close
    /// survival is assured on this platform/config. The matching
    /// broadcast for other clients is [`Event::CaffeinateState`].
    CaffeinateState {
        active: bool,
        lid_close_guaranteed: bool,
        message: String,
    },

    PausedWork {
        items: Vec<PausedWorkSummary>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveModelState {
    pub provider: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_model: Option<String>,
    pub diverged: bool,
    #[serde(default)]
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BtwForkInfo {
    pub session_id: Uuid,
    pub parent_session_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
    pub tangent: bool,
    pub created_at: i64,
    pub message_count: u32,
}
