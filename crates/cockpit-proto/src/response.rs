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

    /// Terminal proof that an explicit config refresh was adopted.
    ConfigRefreshed {
        applied_generation: u64,
        changed: bool,
    },

    /// Result of [`Request::RestartIfIdle`].
    RestartDecision {
        will_restart: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },

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

    ClientSubmissionReceipt {
        session_id: Uuid,
        client_submission_id: Uuid,
        status: ClientSubmissionReceiptStatus,
    },

    HistoryPage {
        session_id: Uuid,
        entries: Vec<HistoryEntry>,
        has_more: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        oldest_seq: Option<i64>,
    },

    SubagentHistoryPage {
        session_id: Uuid,
        task_call_id: String,
        label: String,
        entries: Vec<HistoryEntry>,
        has_more: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        oldest_seq: Option<i64>,
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

    /// Deterministic secret-free terminal projection for remote goal mutations.
    RemoteGoalOutcome {
        outcome: RemoteGoalOutcomeV1,
    },

    GoalCleared {
        cleared: bool,
    },

    PinChanged {
        changed: bool,
    },
    PinToggled {
        pinned: bool,
    },
    PinCount {
        count: i64,
    },
    PinSeqs {
        seqs: Vec<i64>,
    },
    PinsWithText {
        pins: Vec<PinnedMessage>,
    },
    PinState {
        state: PinState,
    },
    SealedValues {
        values: Vec<SealedValueMetadata>,
    },

    ProjectNotes {
        notes: Vec<ProjectNote>,
    },
    ProjectNoteCreated {
        note: ProjectNote,
    },
    ProjectNoteRenamed {
        name: String,
    },

    WorkspaceTrustSet {
        config_generation: u64,
    },
    StartupDisclosures {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        org_sync: Option<OrgSyncDisclosure>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        connector: Option<ConnectorDisclosure>,
        config_generation: u64,
    },
    AppFlag {
        key: AppFlagKey,
        seen: bool,
        version: u64,
    },
    AppFlagSeen {
        key: AppFlagKey,
        version: u64,
        changed: bool,
    },
    AssistantSessionResolved {
        session: SessionSummary,
        created: bool,
    },

    Assistants {
        assistants: Vec<AssistantSummary>,
    },

    AssistantUpserted {
        assistant: AssistantSummary,
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

    ImportSessionArchive {
        imported: Vec<Uuid>,
        redacted: bool,
    },

    /// Acknowledgement for [`crate::Request::WriteBulkTransferChunk`].
    BulkTransferChunkAccepted {
        next_chunk_index: u32,
        received_bytes: crate::remote_protocol_id::CanonicalU64DecimalStringV1,
        /// True once the staged bytes match the reference's length and digest.
        complete: bool,
        /// How long the daemon will hold this transfer without further
        /// activity before reclaiming it.
        ///
        /// The deadline is advertised rather than implicit: a peer that may be
        /// backpressured or stalled knows exactly how long it has, and can
        /// resume, keep the transfer alive, or restart it deliberately instead
        /// of discovering an unannounced expiry as a mysterious failure.
        idle_timeout_ms: u32,
    },

    /// One chunk of a staged bulk transfer.
    BulkTransferChunk {
        chunk_index: u32,
        data_base64: String,
        last: bool,
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

    /// Answer to [`Request::GetInventoryBundle`]: one atomic projection of
    /// agents, models, and selected-agent skills with a single generation triple.
    InventoryBundle {
        selected_agent: String,
        agents: Vec<AgentSummary>,
        models: Vec<ModelSummary>,
        skills: Vec<SkillSummary>,
        session_generation: u64,
        config_generation: u64,
        inventory_generation: u64,
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

    /// The resulting `/longcache` session override state.
    LongcacheState {
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

    /// Durable status for a run invocation ([`Request::GetRunInvocationStatus`]).
    RunInvocationStatus {
        status: RunInvocationStatusV1,
    },
    RemoteOperationStatus {
        status: Option<RemoteOperationStatusV1>,
    },

    /// Idempotent cancel result ([`Request::CancelRunInvocation`]).
    RunInvocationCancelResult {
        result: RunInvocationCancelResultV1,
    },

    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ClientSubmissionReceiptStatus {
    Pending,
    Accepted {
        seq: i64,
        wire_fingerprint: String,
    },
    Terminal {
        disposition: String,
        wire_fingerprint: String,
    },
}

/// Closed content-free lifecycle state for a durable run invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunInvocationLifecycleState {
    NotFound,
    Accepted,
    Queued,
    Dispatching,
    SubmissionUnknown,
    Running,
    CancellationRequested,
    Succeeded,
    Failed,
    Cancelled,
    TimeoutExpired,
    MaxTurnsExceeded,
    ClockRollbackTimedOut,
    OutcomeUnknown,
}

impl RunInvocationLifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Accepted => "accepted",
            Self::Queued => "queued",
            Self::Dispatching => "dispatching",
            Self::SubmissionUnknown => "submission_unknown",
            Self::Running => "running",
            Self::CancellationRequested => "cancellation_requested",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimeoutExpired => "timeout_expired",
            Self::MaxTurnsExceeded => "max_turns_exceeded",
            Self::ClockRollbackTimedOut => "clock_rollback_timed_out",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Cancelled
                | Self::TimeoutExpired
                | Self::MaxTurnsExceeded
                | Self::ClockRollbackTimedOut
                | Self::OutcomeUnknown
        )
    }
}

impl std::fmt::Display for RunInvocationLifecycleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Closed content-free terminal reason for a durable run invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunInvocationTerminalReason {
    Succeeded,
    Failed,
    Cancelled,
    CancelledSessionDeleted,
    TimeoutExpired,
    MaxTurnsExceeded,
    ClockRollbackTimedOut,
    OutcomeUnknown,
}

impl RunInvocationTerminalReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::CancelledSessionDeleted => "cancelled_session_deleted",
            Self::TimeoutExpired => "timeout_expired",
            Self::MaxTurnsExceeded => "max_turns_exceeded",
            Self::ClockRollbackTimedOut => "clock_rollback_timed_out",
            Self::OutcomeUnknown => "outcome_unknown",
        }
    }

    pub fn to_lifecycle_state(self) -> RunInvocationLifecycleState {
        match self {
            Self::Succeeded => RunInvocationLifecycleState::Succeeded,
            Self::Failed => RunInvocationLifecycleState::Failed,
            Self::Cancelled | Self::CancelledSessionDeleted => {
                RunInvocationLifecycleState::Cancelled
            }
            Self::TimeoutExpired => RunInvocationLifecycleState::TimeoutExpired,
            Self::MaxTurnsExceeded => RunInvocationLifecycleState::MaxTurnsExceeded,
            Self::ClockRollbackTimedOut => RunInvocationLifecycleState::ClockRollbackTimedOut,
            Self::OutcomeUnknown => RunInvocationLifecycleState::OutcomeUnknown,
        }
    }
}

/// Versioned, content-free run-invocation status response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunInvocationStatusV1 {
    pub schema_version: u32,
    pub client_submission_id: Uuid,
    pub state: RunInvocationLifecycleState,
    pub state_version: u64,
    pub created_at_wall_ms: i64,
    pub updated_at_wall_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_turns: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_ms: Option<u64>,
    pub reserved_turns: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_at_wall_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_reason: Option<RunInvocationTerminalReason>,
}

impl RunInvocationStatusV1 {
    pub const SCHEMA_VERSION: u32 = 1;
}

/// Closed cancel-result kind for [`RunInvocationCancelResultV1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunInvocationCancelOutcome {
    CancellationRequested,
    AlreadyCancelled,
    AlreadyTerminal,
    /// The authoritative lookup installed or observed a durable tombstone.
    NotFound,
}

impl RunInvocationCancelOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CancellationRequested => "cancellation_requested",
            Self::AlreadyCancelled => "already_cancelled",
            Self::AlreadyTerminal => "already_terminal",
            Self::NotFound => "not_found",
        }
    }
}

/// Versioned, content-free response for a remote goal mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteGoalOutcomeV1 {
    pub schema_version: u8,
    pub session_id: Uuid,
    pub goal_id: Uuid,
    pub attempt_generation: i64,
    pub disposition: GoalDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteOperationStatusV1 {
    pub schema_version: u8,
    pub operation_id: Uuid,
    pub state: RemoteOperationStateV1,
    pub operation_seq: crate::remote_protocol_id::CanonicalU64DecimalStringV1,
    pub safe_response: Option<Vec<u8>>,
    pub event_high_water_mark: Option<crate::remote_protocol_id::CanonicalU64DecimalStringV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteOperationStateV1 {
    Reserved,
    Committed,
    Rejected,
    OutcomeUnknown,
}

/// Versioned, content-free cancel response for a run invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunInvocationCancelResultV1 {
    pub schema_version: u32,
    pub client_submission_id: Uuid,
    pub outcome: RunInvocationCancelOutcome,
    pub state: RunInvocationLifecycleState,
    pub state_version: u64,
}

impl RunInvocationCancelResultV1 {
    pub const SCHEMA_VERSION: u32 = 1;
}
#[macro_export]
macro_rules! response_variants {
    ($with_variants:ident $(, $context:ident)*) => {
        $with_variants! { ($($context),*) [
            (Response::Ack, "ack");
            (Response::ConfigRefreshed { .. }, "config_refreshed");
            (Response::RestartDecision { .. }, "restart_decision");
            (Response::UserMessageQueued { .. }, "user_message_queued");
            (Response::DelegationSteer { .. }, "delegation_steer");
            (Response::AttachmentUploadStarted { .. }, "attachment_upload_started");
            (Response::AttachmentChunkAccepted { .. }, "attachment_chunk_accepted");
            (Response::AttachmentUploaded { .. }, "attachment_uploaded");
            (Response::TerminalPasteImage { .. }, "terminal_paste_image");
            (Response::RemoveQueuedUserMessageResult { .. }, "remove_queued_user_message_result");
            (Response::RemoveQueuedUserMessagesResult { .. }, "remove_queued_user_messages_result");
            (Response::Attached { .. }, "attached");
            (Response::SubagentTranscript { .. }, "subagent_transcript");
            (Response::Sessions { .. }, "sessions");
            (Response::SessionMessages { .. }, "session_messages");
            (Response::ClientSubmissionReceipt { .. }, "client_submission_receipt");
            (Response::HistoryPage { .. }, "history_page");
            (Response::SubagentHistoryPage { .. }, "subagent_history_page");
            (Response::NoteRecorded { .. }, "note_recorded");
            (Response::GoalStatus { .. }, "goal_status");
            (Response::GoalUpdated { .. }, "goal_updated");
            (Response::RemoteGoalOutcome { .. }, "remote_goal_outcome");
            (Response::GoalCleared { .. }, "goal_cleared");
            (Response::PinChanged { .. }, "pin_changed");
            (Response::PinToggled { .. }, "pin_toggled");
            (Response::PinCount { .. }, "pin_count");
            (Response::PinSeqs { .. }, "pin_seqs");
            (Response::PinsWithText { .. }, "pins_with_text");
            (Response::PinState { .. }, "pin_state");
            (Response::SealedValues { .. }, "sealed_values");
            (Response::ProjectNotes { .. }, "project_notes");
            (Response::ProjectNoteCreated { .. }, "project_note_created");
            (Response::ProjectNoteRenamed { .. }, "project_note_renamed");
            (Response::WorkspaceTrustSet { .. }, "workspace_trust_set");
            (Response::StartupDisclosures { .. }, "startup_disclosures");
            (Response::AppFlag { .. }, "app_flag");
            (Response::AppFlagSeen { .. }, "app_flag_seen");
            (Response::AssistantSessionResolved { .. }, "assistant_session_resolved");
            (Response::Assistants { .. }, "assistants");
            (Response::AssistantUpserted { .. }, "assistant_upserted");
            (Response::AssistantSessionCreated { .. }, "assistant_session_created");
            (Response::AutoTitle { .. }, "auto_title");
            (Response::ExportSessionData { .. }, "export_session_data");
            (Response::ImportSessionArchive { .. }, "import_session_archive");
            (Response::BulkTransferChunkAccepted { .. }, "bulk_transfer_chunk_accepted");
            (Response::BulkTransferChunk { .. }, "bulk_transfer_chunk");
            (Response::Curator { .. }, "curator");
            (Response::SessionLiveStatus { .. }, "session_live_status");
            (Response::Forked { .. }, "forked");
            (Response::BtwFork { .. }, "btw_fork");
            (Response::InventoryBundle { .. }, "inventory_bundle");
            (Response::ResourceSnapshot { .. }, "resource_snapshot");
            (Response::PromoteResourceResult { .. }, "promote_resource_result");
            (Response::ScheduledJob { .. }, "scheduled_job");
            (Response::ScheduledJobs { .. }, "scheduled_jobs");
            (Response::ScheduledJobDeleted { .. }, "scheduled_job_deleted");
            (Response::ScheduledJobRunQueued { .. }, "scheduled_job_run_queued");
            (Response::FsList { .. }, "fs_list");
            (Response::FsStat { .. }, "fs_stat");
            (Response::FsRead { .. }, "fs_read");
            (Response::FsWrite { .. }, "fs_write");
            (Response::GitStatus { .. }, "git_status");
            (Response::GitDiffFile { .. }, "git_diff_file");
            (Response::TerminalOpened { .. }, "terminal_opened");
            (Response::LspControlResult { .. }, "lsp_control_result");
            (Response::DaemonStatus { .. }, "daemon_status");
            (Response::UsageCounts { .. }, "usage_counts");
            (Response::StatsRollup { .. }, "stats_rollup");
            (Response::GuidanceEstimate { .. }, "guidance_estimate");
            (Response::SandboxState { .. }, "sandbox_state");
            (Response::SandboxEscalationState { .. }, "sandbox_escalation_state");
            (Response::RedactionState { .. }, "redaction_state");
            (Response::PreflightState { .. }, "preflight_state");
            (Response::LongcacheState { .. }, "longcache_state");
            (Response::ApprovalModeState { .. }, "approval_mode_state");
            (Response::DelegationRecursionState { .. }, "delegation_recursion_state");
            (Response::CaffeinateState { .. }, "caffeinate_state");
            (Response::PausedWork { .. }, "paused_work");
            (Response::RunInvocationStatus { .. }, "run_invocation_status");
            (Response::RemoteOperationStatus { .. }, "remote_operation_status");
            (Response::RunInvocationCancelResult { .. }, "run_invocation_cancel_result");
            (Response::Unknown, "__unknown");
        ] }
    };
}

impl Response {
    pub fn wire_tag(&self) -> &'static str {
        macro_rules! wire_tag {
            (($($context:ident),*) [$(($pattern:pat, $tag:expr);)+]) => {
                match self {
                    $($pattern => $tag,)+
                }
            };
        }
        response_variants!(wire_tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `ExportSessionData` must reference a bulk transfer, not embed the export.
    ///
    /// Before this prompt `ExportSessionData` carried
    /// `content_base64: String` — the entire transcript JSON or debug-bundle
    /// ZIP, base64-encoded, bounded only by the retired 8 MiB
    /// `MAX_FRAME_BYTES`. The corrected expectation rejects that shape: the old
    /// wire form no longer deserializes and the response frame is now bounded
    /// regardless of export size.
    #[test]
    fn export_session_data_uses_bulk_transfer() {
        use crate::remote_transport::bulk::{RemoteBulkMimeClass, RemoteBulkTransferRef};
        use crate::remote_transport::lane::MAX_LOGICAL_PAYLOAD_BYTES;

        // The retired inline shape fails to parse.
        let legacy = json!({
            "response": "export_session_data",
            "data": { "data": {
                "session_id": "11111111-1111-4111-8111-111111111111",
                "kind": "transcript_json",
                "filename_extension": "json",
                "mime": "application/json",
                "content_base64": "Zmlyc3QgZGF0YQ==",
                "byte_len": 12,
                "redacted": true,
            }},
        });
        assert!(
            serde_json::from_value::<Response>(legacy).is_err(),
            "inline content_base64 must no longer be accepted"
        );

        let transfer_id = crate::remote_protocol_id::tag_protocol_id_bytes::<
            crate::remote_protocol_id::kind::Transfer,
        >([7u8; 16])
        .unwrap();
        // A 300 MiB debug bundle: far beyond anything an 8 MiB frame allowed.
        let total_length = 300 * 1024 * 1024;
        let response = Response::ExportSessionData {
            data: ExportSessionData {
                session_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
                kind: ExportSessionKind::DebugBundle,
                filename_extension: "zip".into(),
                mime: "application/zip".into(),
                transfer: RemoteBulkTransferRef::new(
                    transfer_id,
                    total_length,
                    [0x5C; 32],
                    RemoteBulkMimeClass::Export,
                )
                .unwrap(),
                session_count: Some(3),
                redacted: false,
            },
        };
        assert_eq!(response.wire_tag(), "export_session_data");

        let encoded = serde_json::to_string(&response).unwrap();
        assert!(
            encoded.len() < 1024,
            "an export reference must stay small, got {} bytes",
            encoded.len()
        );
        assert!(encoded.len() < MAX_LOGICAL_PAYLOAD_BYTES);
        assert!(!encoded.contains("content_base64"));

        let round_tripped: Response = serde_json::from_str(&encoded).unwrap();
        match round_tripped {
            Response::ExportSessionData { data } => {
                assert_eq!(data.byte_len(), total_length);
                assert_eq!(data.transfer.mime_class, RemoteBulkMimeClass::Export);
                assert_eq!(data.session_count, Some(3));
            }
            other => panic!("unexpected variant: {}", other.wire_tag()),
        }
    }

    #[test]
    fn sealed_values_response_is_registered() {
        assert_eq!(
            Response::SealedValues { values: Vec::new() }.wire_tag(),
            "sealed_values"
        );
    }

    #[test]
    fn run_invocation_status_and_cancel_response_fixtures() {
        let id = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
        let status = RunInvocationStatusV1 {
            schema_version: RunInvocationStatusV1::SCHEMA_VERSION,
            client_submission_id: id,
            state: RunInvocationLifecycleState::Queued,
            state_version: 2,
            created_at_wall_ms: 1_700_000_000_000,
            updated_at_wall_ms: 1_700_000_001_000,
            max_turns: None,
            timeout_ms: Some(86_400_000),
            remaining_ms: Some(86_399_000),
            reserved_turns: 0,
            terminal_at_wall_ms: None,
            terminal_reason: None,
        };
        let status_json = serde_json::to_value(&Response::RunInvocationStatus {
            status: status.clone(),
        })
        .unwrap();
        assert_eq!(status_json["response"], "run_invocation_status");
        let data = &status_json["data"]["status"];
        assert_eq!(data["schema_version"], 1);
        assert_eq!(data["client_submission_id"], id.to_string());
        assert_eq!(data["state"], "queued");
        assert_eq!(data["state_version"], 2);
        assert!(data.get("max_turns").is_none());
        assert_eq!(data["timeout_ms"], 86_400_000);
        assert!(data.get("prompt").is_none());
        assert!(data.get("session_id").is_none());
        assert!(data.get("project_root").is_none());
        assert!(data.get("output").is_none());
        assert!(data.get("error").is_none());
        assert!(data.get("provider").is_none());

        let terminal = RunInvocationStatusV1 {
            state: RunInvocationLifecycleState::TimeoutExpired,
            terminal_at_wall_ms: Some(1_700_000_100_000),
            terminal_reason: Some(RunInvocationTerminalReason::TimeoutExpired),
            remaining_ms: Some(0),
            reserved_turns: 1,
            ..status
        };
        let terminal_json = serde_json::to_value(&terminal).unwrap();
        assert_eq!(terminal_json["state"], "timeout_expired");
        assert_eq!(terminal_json["terminal_reason"], "timeout_expired");

        let cancel = RunInvocationCancelResultV1 {
            schema_version: RunInvocationCancelResultV1::SCHEMA_VERSION,
            client_submission_id: id,
            outcome: RunInvocationCancelOutcome::CancellationRequested,
            state: RunInvocationLifecycleState::CancellationRequested,
            state_version: 3,
        };
        let cancel_resp = Response::RunInvocationCancelResult { result: cancel };
        assert_eq!(cancel_resp.wire_tag(), "run_invocation_cancel_result");
        let cancel_json = serde_json::to_value(&cancel_resp).unwrap();
        assert_eq!(
            cancel_json["data"]["result"]["outcome"],
            "cancellation_requested"
        );
        assert!(cancel_json["data"]["result"].get("session_id").is_none());

        // Closed enums reject unknown variants at the wire boundary.
        assert!(
            serde_json::from_value::<RunInvocationLifecycleState>(json!("still_cooking")).is_err()
        );
        assert!(serde_json::from_value::<RunInvocationTerminalReason>(json!("oops")).is_err());
    }

    #[test]
    fn active_model_state_requires_generation_in_protocol_v6() {
        let missing_generation = json!({
            "selection": {
                "provider": "openai",
                "model": "gpt-5",
                "reasoning_effort": null,
                "thinking_mode": null,
                "prompt_cache_retention": null
            },
            "default_selection": null,
            "diverged": false
        });

        serde_json::from_value::<ActiveModelState>(missing_generation)
            .expect_err("protocol v6 active-model state must include generation");
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveModelState {
    pub selection: cockpit_config::config::providers::ActiveModelRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_selection: Option<cockpit_config::config::providers::ActiveModelRef>,
    pub diverged: bool,
    /// Monotonic only within the current attachment/worker epoch. An attach
    /// snapshot is authoritative generation zero; clients must reset their
    /// comparison baseline before applying it.
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
