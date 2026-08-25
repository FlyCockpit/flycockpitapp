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

    MediaOwnerRecovery(cockpit_db::media_attachments::LocalMediaOwnerReceiptV1),

    LocalPathMediaRegistration(cockpit_db::media_attachments::LocalPathRegistrationReceiptV1),

    RetainedHttpsMedia(cockpit_db::media_attachments::RetainedHttpsMediaReceiptV1),

    MediaAttachmentStatus(cockpit_db::media_attachments::MediaAttachmentStatusV1),

    MediaAttachmentPreview(cockpit_db::media_attachments::MediaAttachmentPreviewV1),

    LocalMediaMutation(cockpit_db::media_attachments::LocalMediaMutationReceiptV1),

    MediaUploadStatus(cockpit_db::media_attachments::MediaUploadStatusV1),

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

    TerminalIngress {
        receipt: crate::terminal::TerminalIngressReceipt,
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
    #[cfg(feature = "remote")]
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
    // ---- v10-only owner-remoted sealed-owner sensitive channel ---------
    // The plaintext literal appears ONLY on `SealedOwnerOperationApplied` for a
    // recover success (`revealed_literal`); every other response below is
    // secret-free by construction.
    /// A sealed-owner capability was minted. Carries no literal.
    SealedOwnerOperationBegun {
        capability_id: String,
        expires_at_ms: i64,
    },
    /// A sealed-owner apply succeeded. For a create/replace/rotate write there
    /// is no literal (`revealed_literal: None`); for a recover, this is the ONLY
    /// remoted payload that reveals the plaintext, to the authenticated owner
    /// session that minted the capability. The literal is the redacting,
    /// zeroizing [`crate::SensitiveWireLiteral`].
    SealedOwnerOperationApplied {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        revealed_literal: Option<crate::SensitiveWireLiteral>,
    },
    /// A sealed-owner capability was cancelled (its single-use CAS spent).
    SealedOwnerOperationCancelled {
        spent: bool,
    },
    /// The safe sealed-value inventory. Never carries a literal.
    SealedOwnerInventory {
        items: Vec<crate::SealedOwnerInventoryItem>,
    },
    /// A sealed value's safe description was edited.
    SealedOwnerDescriptionEdited {
        record_id: String,
    },
    /// Safe summaries of sealed action instances. No origins/templates/creds.
    SealedActions {
        actions: Vec<crate::SealedActionSummaryWire>,
    },
    /// A sealed action instance was created; the daemon minted `action_id`.
    SealedActionCreated {
        action_id: String,
        revision: u32,
    },
    /// A sealed action instance was revised to a new revision.
    SealedActionRevised {
        action_id: String,
        revision: u32,
    },
    /// A sealed action instance was retired.
    SealedActionRetired {
        action_id: String,
        retired: bool,
    },

    /// `/leaks` list response: a page of safe leak-report metadata. Never
    /// carries plaintext, ciphertext, prefix, length, or fingerprint.
    LeakReports {
        page: LeakReportsPage,
    },
    /// BeginLeakReveal response: a fresh one-use capability bound to exactly
    /// one report id. Secret-free. The reveal consumption itself has **no**
    /// ordinary-proto response — the plaintext travels only on the sensitive
    /// local endpoint (in-process handoff or the Unix peer-authenticated reveal
    /// socket), so ordinary codecs cannot represent a revealed secret.
    LeakRevealCapability {
        capability: LeakRevealCapability,
    },
    /// An exact leak-reveal capability was spent without revealing a secret.
    LeakRevealCancelled {
        report_id: String,
    },
    /// MarkLeakRotated response: the updated rotation disposition.
    LeakRotationUpdated {
        report_id: String,
        rotation: String,
    },
    /// DeleteLeakReport response: the protected value was deleted; safe
    /// historical metadata is retained.
    LeakReportDeleted {
        report_id: String,
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
    WorkspaceTrust {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<WorkspaceTrustMode>,
        config_generation: u64,
    },
    #[cfg(feature = "remote")]
    FlycockpitStored,
    #[cfg(feature = "remote")]
    FlycockpitAlreadyLoggedIn {
        email: String,
        server_url: String,
    },
    #[cfg(feature = "remote")]
    FlycockpitCleared {
        server_url: String,
    },
    #[cfg(feature = "remote")]
    FlycockpitNotLoggedIn,
    #[cfg(feature = "remote")]
    FlycockpitOrgSync {
        outcome: crate::FlycockpitOrgSyncOutcome,
    },
    SecretInventory {
        entries: Vec<SecretInventoryEntry>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next_cursor: Option<String>,
    },
    #[cfg(feature = "remote")]
    FlycockpitAccount {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account: Option<FlycockpitAccountView>,
    },
    /// Owner-only instructions for a daemon-owned provider OAuth flow. The
    /// `authorize_url` is the provider's authorization endpoint the owner opens
    /// to authorize; by OAuth necessity it carries the flow's `state`/CSRF
    /// parameter (and any PKCE challenge), which is not a secret. It NEVER
    /// carries access/refresh tokens, an authorization code, or any credential
    /// secret.
    #[serde(rename = "provider_oauth_started")]
    ProviderOAuthStarted {
        client_operation_id: String,
        /// Unkeyed SHA-256 of the canonical request tuple. The daemon uses a
        /// separate keyed identity for durable idempotency; this wire value is
        /// deliberately client-computable so direct and recovered receipts
        /// can be bound to the exact request.
        request_hash: String,
        flow_id: String,
        authorize_url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_code: Option<String>,
    },
    /// Completion/poll result for a daemon-owned provider OAuth flow.
    #[serde(rename = "provider_oauth_completed")]
    ProviderOAuthCompleted {
        client_operation_id: String,
        /// Public correlation over the non-secret client operation id and
        /// flow id. Callback/code bytes are bound only by the daemon's keyed
        /// durable-operation identity and never have an offline verifier.
        request_hash: String,
        flow_id: String,
        logged_in: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_seconds: Option<u64>,
    },
    /// Idempotent terminal cancellation receipt. `cancelled` is true only
    /// when cancellation fenced credential persistence; false means the exact
    /// flow had already reached another terminal state.
    #[serde(rename = "provider_oauth_cancelled")]
    ProviderOAuthCancelled {
        client_operation_id: String,
        request_hash: String,
        flow_id: Option<String>,
        cancelled: bool,
    },
    /// Owner-only instructions for a daemon-owned MCP OAuth flow. The
    /// `authorize_url` is the authorization endpoint the owner opens; by OAuth
    /// necessity it carries the flow's `state`/CSRF parameter (and any PKCE
    /// challenge), which is not a secret. It NEVER carries an access/refresh
    /// token, an authorization/callback code, or any credential secret.
    #[serde(rename = "mcp_oauth_started")]
    McpOAuthStarted {
        client_operation_id: String,
        /// Client-computable canonical request hash; never the daemon's keyed
        /// durable-operation identity.
        request_hash: String,
        flow_id: String,
        authorize_url: String,
    },
    /// Completion result for a daemon-owned MCP OAuth flow.
    #[serde(rename = "mcp_oauth_completed")]
    McpOAuthCompleted {
        client_operation_id: String,
        /// Public correlation over non-secret request identifiers only.
        request_hash: String,
        flow_id: String,
        authenticated: bool,
    },
    #[serde(rename = "mcp_oauth_cancelled")]
    McpOAuthCancelled {
        client_operation_id: String,
        request_hash: String,
        flow_id: Option<String>,
        cancelled: bool,
    },
    /// Authoritative result of an MCP config publication. Credential refs are
    /// intentionally omitted; clients refresh their redacted view/inventory.
    McpConfigCommitted {
        client_operation_id: String,
        /// Daemon-keyed digest binding the terminal receipt to the exact
        /// request body. Older archived fixtures predate this field.
        #[serde(default)]
        request_hash: String,
        project_root: String,
        owner_root: String,
        config_path: String,
        consumed_revision: String,
        result_revision: String,
        config_generation: u64,
        credential_count: u32,
    },
    ProviderCatalogSnapshot {
        config: ProviderConfigView,
        snapshot_session_id: String,
        layer_id: String,
        owner_root: String,
        base_revision: String,
        config_generation: u64,
    },
    ProviderModelsFetched {
        results: Vec<ProviderModelFetchResult>,
        config: ProviderConfigView,
    },
    ProviderUsageSnapshot {
        snapshots: Vec<ProviderUsageSnapshotView>,
    },
    ProviderConfigUpserted {
        config: ProviderConfigView,
    },
    /// Exact receipt for one atomic provider-layer CAS mutation.
    ProviderMutationCommitted {
        client_operation_id: String,
        snapshot_session_id: String,
        layer_id: String,
        owner_root: String,
        mutation_intent_hash: String,
        consumed_revision: String,
        result_revision: String,
        config_generation: u64,
        config: ProviderConfigView,
        status: crate::ConfigCommitStatus,
        publication: crate::ConfigPublicationStatus,
    },
    /// Exact receipt for a daemon-owned provider credential mutation.
    ProviderCredentialCommitted {
        client_operation_id: String,
        provider_id: String,
        project_root: Option<String>,
        owner_root: Option<String>,
        /// Canonical authority identity: `global` or `project:<canonical-root>`.
        #[serde(default)]
        owner_scope: String,
        stored: bool,
        changed: bool,
        #[serde(default)]
        consumed_vault_generation: u64,
        #[serde(default)]
        result_vault_generation: u64,
        config_generation: u64,
    },
    /// Owner-scoped resolution of a transport-ambiguous local mutation.
    /// `response` is present only after the durable terminal receipt commits.
    LocalOperationSettlement {
        client_operation_id: String,
        /// Daemon-recorded domain; prevents a reused operation id from being
        /// accepted as settlement for a different mutation.
        operation_kind: String,
        /// Lowercase SHA-256 of the exact request identity recorded at begin.
        request_hash: String,
        pending: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response: Option<Box<Response>>,
        /// Authoritative terminal rejection. Transport errors never populate
        /// this field and therefore cannot be confused with a committed reject.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        terminal_error: Option<crate::ErrorPayload>,
        /// True only for a durably recorded terminal cancellation.
        #[serde(default)]
        terminal_cancelled: bool,
    },
    CopilotAuthCommitted {
        client_operation_id: String,
        project_root: String,
        owner_root: String,
        #[serde(default)]
        owner_scope: String,
        provider_id: String,
        #[serde(default)]
        consumed_vault_generation: u64,
        #[serde(default)]
        result_vault_generation: u64,
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

    AssistantDefinitionSaved {
        assistant: AssistantSummary,
        consumed_definition_revision: String,
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
        received_bytes: crate::wire_scalar::CanonicalU64DecimalStringV1,
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

    /// Result of a daemon-owned extended config mutation. The target path is
    /// intentionally not echoed; callers receive only an opaque committed
    /// revision and can reload their own safe view.
    ExtendedConfigSaved {
        #[serde(default)]
        client_operation_id: String,
        #[serde(default)]
        request_hash: String,
        hash: String,
        config_generation: u64,
        layer_id: String,
        layer: crate::CockpitConfigLayer,
        consumed_revision: String,
        result_revision: String,
        status: crate::ConfigCommitStatus,
        publication: crate::ConfigPublicationStatus,
        /// Exact safe post-commit order. New occurrence nonces bind assigned
        /// IDs to this request; no value-derived digest or literal is exposed.
        denylist: Vec<crate::CommittedDenylistEntry>,
    },

    /// Legacy whole-document writer receipt. Daemon-connected settings UI
    /// never uses this unscoped path.
    ExtendedConfigWritten {
        hash: String,
        config_generation: u64,
    },

    ExtendedConfigSnapshot {
        layers: Vec<crate::ExtendedConfigLayerSnapshot>,
        config_generation: u64,
    },

    AgentInventory {
        entries: Vec<crate::AgentInventoryEntry>,
        /// Opaque revision covering the resettable workspace inventory.
        inventory_revision: String,
        config_generation: u64,
    },

    AgentEditSnapshot(crate::AgentEditSnapshot),

    AgentMutated(crate::AgentMutationResult),

    AgentEditorLeaseBegun(crate::AgentEditorLease),

    AgentEditorLeaseCompleted(crate::AgentMutationResult),

    /// Safe outcome of a daemon-owned setup wizard mutation.
    SetupWizardApplied {
        changed: bool,
        model_file_written: bool,
        default_scope: Option<String>,
    },

    PolicyExported {
        bundle_json: String,
    },

    PolicyImported {
        target: String,
        provider_count: u32,
    },

    ImageSpendPolicy {
        settings: Option<cockpit_config::config::image_spend::ImageSpendSettings>,
        policy_version: Option<u64>,
    },

    ImageSpendPolicySaved {
        policy_version: u64,
    },

    /// Redacted LOCAL image-generation control-plane read reply
    /// (endpoint/target/workflow list/get). Carries only safe projections.
    ImageControlRead(crate::image_control::ImageControlReadResponseV1),

    /// LOCAL image-generation control-plane config-mutation reply
    /// (endpoint/target create/update/delete/set_default). Carries the new
    /// authoritative config generation and the safe change set that was applied
    /// and emitted; never raw credential/header/workflow material.
    ImageControlMutated(crate::image_control::ImageControlMutationResponseV1),

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
        binding: crate::terminal::TerminalBinding,
        terminal_generation: u64,
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
        /// Persisted `sandbox.defaultMode` after this call. Absent on older
        /// peers; `mode` remains the session's effective mode.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        persisted_intent: Option<SandboxMode>,
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
    #[cfg(feature = "remote")]
    RemoteOperationStatus {
        status: Option<RemoteOperationStatusV1>,
    },

    /// Idempotent cancel result ([`Request::CancelRunInvocation`]).
    RunInvocationCancelResult {
        result: RunInvocationCancelResultV1,
    },

    /// Answer to [`Request::GetHostCapabilities`] / [`Request::RefreshHostCapabilities`]
    /// / [`Request::MigrateKekPlacement`].
    HostCapabilities {
        snapshot: crate::HostCapabilitySnapshot,
    },

    // ---- v10-only owner-remoted CLI-surface responses ------------------
    // JSON-string payloads (no secret bytes) so the daemon owns assembly
    // and persistence; the CLI renders. Mirrors `PolicyExported`.
    /// Registered package list, JSON array of `{identifier,display_name,...}`.
    Packages {
        packages_json: String,
    },
    /// A single registered package row as JSON.
    PackageAdded {
        package_json: String,
    },
    /// Package import summary as JSON.
    PackageImported {
        summary_json: String,
    },
    /// Package prune report as JSON.
    PackagesPruned {
        report_json: String,
    },
    /// kcl import result as JSON.
    KclPackagesImported {
        result_json: String,
    },
    /// FlyCockpit connector state for the current account (JSON, or `null`).
    #[cfg(feature = "remote")]
    ConnectorState {
        connector_json: String,
    },
    /// Org-sync and remote-audit-upload state lists as JSON.
    #[cfg(feature = "remote")]
    OrgSyncStatus {
        org_states_json: String,
        audit_states_json: String,
    },
    /// Failed/recovered tool-call rows as a JSON array.
    FailedToolCalls {
        calls_json: String,
    },
    /// The complete compaction-event list for a session as a JSON array.
    SessionCompactions {
        session_id: Uuid,
        compactions_json: String,
    },
    /// Result of purging ended sessions.
    EndedSessionsPurged {
        purged: u32,
        session_ids_json: String,
    },
    /// A single assistant registry row, or `None` when not found.
    Assistant {
        assistant: Option<AssistantSummary>,
    },
    /// Result of deleting an assistant registry row.
    AssistantDeleted {
        name: String,
        consumed_registration_revision: String,
        deleted: bool,
    },
    /// Media reservation accounting diagnosis as JSON.
    MediaReservationDiagnosis {
        diagnosis_json: String,
    },
    /// Media reservation accounting repair outcome code.
    MediaReservationRepaired {
        outcome: String,
    },
    /// Rendered doctor diagnostics snapshot plus the failure flag.
    DoctorSnapshot {
        rendered: String,
        has_failures: bool,
    },

    /// Rendered dependency-docs answer for [`crate::Request::DocsAsk`].
    /// `answer` is model-authored free text; the daemon scrubs it through
    /// the redaction table before it crosses the socket (see the owner
    /// backstop in `daemon::server`).
    DocsAnswer {
        answer: String,
    },

    /// Typed, redacted daemon-owned agent installation operation outcome.
    AgentInstallation(crate::AgentInstallationResultV1),

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
#[cfg(feature = "remote")]
pub struct RemoteGoalOutcomeV1 {
    pub schema_version: u8,
    pub session_id: Uuid,
    pub goal_id: Uuid,
    pub attempt_generation: i64,
    pub disposition: GoalDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg(feature = "remote")]
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
#[cfg(feature = "remote")]
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
            (Response::MediaOwnerRecovery(..), "media_owner_recovery");
            (Response::LocalPathMediaRegistration(..), "local_path_media_registration");
            (Response::RetainedHttpsMedia(..), "retained_https_media");
            (Response::MediaAttachmentStatus(..), "media_attachment_status");
            (Response::MediaAttachmentPreview(..), "media_attachment_preview");
            (Response::LocalMediaMutation(..), "local_media_mutation");
            (Response::MediaUploadStatus(..), "media_upload_status");
            (Response::ConfigRefreshed { .. }, "config_refreshed");
            (Response::RestartDecision { .. }, "restart_decision");
            (Response::UserMessageQueued { .. }, "user_message_queued");
            (Response::DelegationSteer { .. }, "delegation_steer");
            (Response::AttachmentUploadStarted { .. }, "attachment_upload_started");
            (Response::AttachmentChunkAccepted { .. }, "attachment_chunk_accepted");
            (Response::AttachmentUploaded { .. }, "attachment_uploaded");
            (Response::TerminalIngress { .. }, "terminal_ingress");
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
            #[cfg(feature = "remote")]
            (Response::RemoteGoalOutcome { .. }, "remote_goal_outcome");
            (Response::GoalCleared { .. }, "goal_cleared");
            (Response::PinChanged { .. }, "pin_changed");
            (Response::PinToggled { .. }, "pin_toggled");
            (Response::PinCount { .. }, "pin_count");
            (Response::PinSeqs { .. }, "pin_seqs");
            (Response::PinsWithText { .. }, "pins_with_text");
            (Response::PinState { .. }, "pin_state");
            (Response::SealedOwnerOperationBegun { .. }, "sealed_owner_operation_begun");
            (Response::SealedOwnerOperationApplied { .. }, "sealed_owner_operation_applied");
            (Response::SealedOwnerOperationCancelled { .. }, "sealed_owner_operation_cancelled");
            (Response::SealedOwnerInventory { .. }, "sealed_owner_inventory");
            (Response::SealedOwnerDescriptionEdited { .. }, "sealed_owner_description_edited");
            (Response::SealedActions { .. }, "sealed_actions");
            (Response::SealedActionCreated { .. }, "sealed_action_created");
            (Response::SealedActionRevised { .. }, "sealed_action_revised");
            (Response::SealedActionRetired { .. }, "sealed_action_retired");
            (Response::LeakReports { .. }, "leak_reports");
            (Response::LeakRevealCapability { .. }, "leak_reveal_capability");
            (Response::LeakRevealCancelled { .. }, "leak_reveal_cancelled");
            (Response::LeakRotationUpdated { .. }, "leak_rotation_updated");
            (Response::LeakReportDeleted { .. }, "leak_report_deleted");
            (Response::ProjectNotes { .. }, "project_notes");
            (Response::ProjectNoteCreated { .. }, "project_note_created");
            (Response::ProjectNoteRenamed { .. }, "project_note_renamed");
            (Response::WorkspaceTrustSet { .. }, "workspace_trust_set");
            (Response::WorkspaceTrust { .. }, "workspace_trust");
            #[cfg(feature = "remote")]
            (Response::FlycockpitStored, "flycockpit_stored");
            #[cfg(feature = "remote")]
            (Response::FlycockpitAlreadyLoggedIn { .. }, "flycockpit_already_logged_in");
            #[cfg(feature = "remote")]
            (Response::FlycockpitCleared { .. }, "flycockpit_cleared");
            #[cfg(feature = "remote")]
            (Response::FlycockpitNotLoggedIn, "flycockpit_not_logged_in");
            #[cfg(feature = "remote")]
            (Response::FlycockpitOrgSync { .. }, "flycockpit_org_sync");
            (Response::SecretInventory { .. }, "secret_inventory");
            #[cfg(feature = "remote")]
            (Response::FlycockpitAccount { .. }, "flycockpit_account");
            (Response::ProviderOAuthStarted { .. }, "provider_oauth_started");
            (Response::ProviderOAuthCompleted { .. }, "provider_oauth_completed");
            (Response::ProviderOAuthCancelled { .. }, "provider_oauth_cancelled");
            (Response::McpOAuthStarted { .. }, "mcp_oauth_started");
            (Response::McpOAuthCompleted { .. }, "mcp_oauth_completed");
            (Response::McpOAuthCancelled { .. }, "mcp_oauth_cancelled");
            (Response::McpConfigCommitted { .. }, "mcp_config_committed");
            (Response::ProviderCatalogSnapshot { .. }, "provider_catalog_snapshot");
            (Response::ProviderModelsFetched { .. }, "provider_models_fetched");
            (Response::ProviderUsageSnapshot { .. }, "provider_usage_snapshot");
            (Response::ProviderConfigUpserted { .. }, "provider_config_upserted");
            (Response::ProviderMutationCommitted { .. }, "provider_mutation_committed");
            (Response::ProviderCredentialCommitted { .. }, "provider_credential_committed");
            (Response::CopilotAuthCommitted { .. }, "copilot_auth_committed");
            (Response::StartupDisclosures { .. }, "startup_disclosures");
            (Response::AppFlag { .. }, "app_flag");
            (Response::AppFlagSeen { .. }, "app_flag_seen");
            (Response::AssistantSessionResolved { .. }, "assistant_session_resolved");
            (Response::Assistants { .. }, "assistants");
            (Response::AssistantUpserted { .. }, "assistant_upserted");
            (Response::AssistantDefinitionSaved { .. }, "assistant_definition_saved");
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
            (Response::ExtendedConfigSaved { .. }, "extended_config_saved");
            (Response::ExtendedConfigWritten { .. }, "extended_config_written");
            (Response::ExtendedConfigSnapshot { .. }, "extended_config_snapshot");
            (Response::AgentInventory { .. }, "agent_inventory");
            (Response::AgentEditSnapshot(..), "agent_edit_snapshot");
            (Response::AgentMutated(..), "agent_mutated");
            (Response::AgentEditorLeaseBegun(..), "agent_editor_lease_begun");
            (Response::AgentEditorLeaseCompleted(..), "agent_editor_lease_completed");
            (Response::LocalOperationSettlement { .. }, "local_operation_settlement");
            (Response::SetupWizardApplied { .. }, "setup_wizard_applied");
            (Response::PolicyExported { .. }, "policy_exported");
            (Response::PolicyImported { .. }, "policy_imported");
            (Response::ImageSpendPolicy { .. }, "image_spend_policy");
            (Response::ImageSpendPolicySaved { .. }, "image_spend_policy_saved");
            (Response::ImageControlRead(..), "image_control_read");
            (Response::ImageControlMutated(..), "image_control_mutated");
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
            #[cfg(feature = "remote")]
            (Response::RemoteOperationStatus { .. }, "remote_operation_status");
            (Response::RunInvocationCancelResult { .. }, "run_invocation_cancel_result");
            (Response::HostCapabilities { .. }, "host_capabilities");
            (Response::Packages { .. }, "packages");
            (Response::PackageAdded { .. }, "package_added");
            (Response::PackageImported { .. }, "package_imported");
            (Response::PackagesPruned { .. }, "packages_pruned");
            (Response::KclPackagesImported { .. }, "kcl_packages_imported");
            #[cfg(feature = "remote")]
            (Response::ConnectorState { .. }, "connector_state");
            #[cfg(feature = "remote")]
            (Response::OrgSyncStatus { .. }, "org_sync_status");
            (Response::FailedToolCalls { .. }, "failed_tool_calls");
            (Response::SessionCompactions { .. }, "session_compactions");
            (Response::EndedSessionsPurged { .. }, "ended_sessions_purged");
            (Response::Assistant { .. }, "assistant");
            (Response::AssistantDeleted { .. }, "assistant_deleted");
            (Response::MediaReservationDiagnosis { .. }, "media_reservation_diagnosis");
            (Response::MediaReservationRepaired { .. }, "media_reservation_repaired");
            (Response::DoctorSnapshot { .. }, "doctor_snapshot");
            (Response::DocsAnswer { .. }, "docs_answer");
            (Response::AgentInstallation(..), "agent_installation");
            (Response::Unknown, "__unknown");
        ] }
    };
}

impl Response {
    pub fn wire_tag(&self) -> &'static str {
        macro_rules! wire_tag {
            (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:expr);)+]) => {
                match self {
                    $($(#[$row_attr])* $pattern => $tag,)+
                }
            };
        }
        response_variants!(wire_tag)
    }

    /// Build a `SealedOwnerInventory` response clamped to
    /// [`crate::MAX_SEALED_OWNER_INVENTORY_ROWS`] rows so the frame stays within
    /// the `BoundedRequestResponse` class by construction. The daemon directory
    /// funnel MUST build the response through this constructor rather than the
    /// bare variant.
    pub fn sealed_owner_inventory(mut items: Vec<crate::SealedOwnerInventoryItem>) -> Self {
        items.truncate(crate::MAX_SEALED_OWNER_INVENTORY_ROWS);
        Self::SealedOwnerInventory { items }
    }

    /// Build a `SealedActions` response clamped to
    /// [`crate::MAX_SEALED_OWNER_INVENTORY_ROWS`] rows so the frame stays within
    /// the `BoundedRequestResponse` class by construction. The daemon directory
    /// funnel MUST build the response through this constructor rather than the
    /// bare variant.
    pub fn sealed_actions(mut actions: Vec<crate::SealedActionSummaryWire>) -> Self {
        actions.truncate(crate::MAX_SEALED_OWNER_INVENTORY_ROWS);
        Self::SealedActions { actions }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_oauth_wire_responses_are_opaque_to_tokens() {
        let started = serde_json::to_string(&Response::McpOAuthStarted {
            client_operation_id: "begin".into(),
            request_hash: "00".repeat(32),
            flow_id: "flow-opaque".into(),
            authorize_url: "https://auth.example.test/authorize?state=daemon-state".into(),
        })
        .unwrap();
        assert!(started.contains("flow-opaque"));
        assert!(!started.contains("access_token"));
        assert!(!started.contains("refresh_token"));

        let completed = serde_json::to_value(Response::McpOAuthCompleted {
            client_operation_id: "complete".into(),
            request_hash: "00".repeat(32),
            flow_id: "flow-opaque".into(),
            authenticated: true,
        })
        .unwrap();
        assert_eq!(completed["response"], "mcp_oauth_completed");
        assert_eq!(completed["data"]["authenticated"], true);
        assert!(completed.to_string().find("token").is_none());
    }
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
        use crate::bulk_transfer::{
            BulkMimeClass as RemoteBulkMimeClass, BulkTransferRef as RemoteBulkTransferRef,
            transfer_id_from_bytes,
        };

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

        let transfer_id = transfer_id_from_bytes([7u8; 16]).unwrap();
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
        assert!(encoded.len() < crate::MAX_NDJSON_FRAME_BYTES);
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
    fn sealed_owner_responses_are_registered() {
        assert_eq!(
            Response::SealedOwnerOperationBegun {
                capability_id: "cap".into(),
                expires_at_ms: 1,
            }
            .wire_tag(),
            "sealed_owner_operation_begun"
        );
        assert_eq!(
            Response::SealedOwnerOperationApplied {
                revealed_literal: None,
            }
            .wire_tag(),
            "sealed_owner_operation_applied"
        );
        assert_eq!(
            Response::SealedOwnerInventory { items: Vec::new() }.wire_tag(),
            "sealed_owner_inventory"
        );
        assert_eq!(
            Response::SealedActions {
                actions: Vec::new()
            }
            .wire_tag(),
            "sealed_actions"
        );
    }

    #[test]
    fn only_recover_apply_response_reveals_a_planted_literal() {
        // AC1 / AC6 (proto boundary): a sealed-value plaintext appears ONLY on
        // the recover-apply success response's `revealed_literal`. Plant a unique
        // marker as the would-be literal into EVERY non-recover response that
        // could plausibly carry it, and prove the marker is absent from both the
        // serialized wire form AND the Debug form of each — while the recover
        // success carries it on the wire (positive control) but redacts it in
        // Debug.
        let marker = "RECOVER-REVEAL-PLAINTEXT-marker-9f3a";

        // Positive control: the recover success reveals the marker on the wire
        // (daemon -> owner) and redacts it in Debug.
        let recover = Response::SealedOwnerOperationApplied {
            revealed_literal: Some(crate::SensitiveWireLiteral::new(marker.into())),
        };
        assert!(
            serde_json::to_string(&recover).unwrap().contains(marker),
            "the recover-apply success must reveal the literal on the wire"
        );
        assert!(
            !format!("{recover:?}").contains(marker),
            "the recover-apply Debug must redact the literal"
        );

        // Negative control: a recover-apply with NO literal (a write success)
        // never carries the marker — proving `revealed_literal` is the sole
        // carrier, not the variant itself.
        assert!(
            !serde_json::to_string(&Response::SealedOwnerOperationApplied {
                revealed_literal: None,
            })
            .unwrap()
            .contains(marker)
        );

        // Drive real construction of every OTHER sealed-owner response with
        // benign safe metadata. Because none has a literal field, the sealed
        // plaintext marker cannot ride them: assert it is absent from BOTH the
        // serialized wire form AND the Debug form of each. (If a future change
        // added a literal-bearing field to any of these, or routed the recovered
        // plaintext into one, this fails.)
        let non_recover = [
            Response::SealedOwnerOperationBegun {
                capability_id: "cap-1".into(),
                expires_at_ms: 1,
            },
            Response::SealedOwnerOperationApplied {
                revealed_literal: None,
            },
            Response::SealedOwnerOperationCancelled { spent: true },
            Response::sealed_owner_inventory(vec![crate::SealedOwnerInventoryItem {
                record_id: "rec-1".into(),
                name: "deploy_token".into(),
                description: "safe description".into(),
                scope_kind: crate::SealedOwnerScopeKind::Global,
                scope_key: String::new(),
                active_version: 1,
                created_at_ms: 0,
            }]),
            Response::SealedOwnerDescriptionEdited {
                record_id: "rec-1".into(),
            },
            Response::sealed_actions(vec![crate::SealedActionSummaryWire {
                action_id: "act-1".into(),
                revision: 1,
                enabled: true,
                description: "safe description".into(),
                project_key: "proj".into(),
            }]),
            Response::SealedActionCreated {
                action_id: "act-1".into(),
                revision: 1,
            },
            Response::SealedActionRevised {
                action_id: "act-1".into(),
                revision: 2,
            },
            Response::SealedActionRetired {
                action_id: "act-1".into(),
                retired: true,
            },
        ];
        for response in non_recover {
            let tag = response.wire_tag();
            assert!(
                !serde_json::to_string(&response).unwrap().contains(marker),
                "{tag} must not serialize the sealed-value plaintext"
            );
            assert!(
                !format!("{response:?}").contains(marker),
                "{tag} must not Debug-print the sealed-value plaintext"
            );
            // No non-recover response embeds a sensitive literal type at all.
            assert!(
                !format!("{response:?}").contains("SensitiveWireLiteral"),
                "{tag} must not embed a sensitive literal"
            );
        }
    }

    #[test]
    fn sealed_owner_collection_responses_are_clamped_to_the_bound() {
        // FINDING 2: the collection constructors clamp to
        // MAX_SEALED_OWNER_INVENTORY_ROWS so the frame stays within the Bounded
        // class by construction.
        let over = crate::MAX_SEALED_OWNER_INVENTORY_ROWS + 25;
        let items = (0..over)
            .map(|i| crate::SealedOwnerInventoryItem {
                record_id: format!("rec-{i}"),
                name: "n".into(),
                description: "d".into(),
                scope_kind: crate::SealedOwnerScopeKind::Global,
                scope_key: String::new(),
                active_version: 1,
                created_at_ms: 0,
            })
            .collect();
        match Response::sealed_owner_inventory(items) {
            Response::SealedOwnerInventory { items } => {
                assert_eq!(items.len(), crate::MAX_SEALED_OWNER_INVENTORY_ROWS)
            }
            other => panic!("expected inventory, got {}", other.wire_tag()),
        }
        let actions = (0..over)
            .map(|i| crate::SealedActionSummaryWire {
                action_id: format!("act-{i}"),
                revision: 1,
                enabled: true,
                description: "d".into(),
                project_key: "p".into(),
            })
            .collect();
        match Response::sealed_actions(actions) {
            Response::SealedActions { actions } => {
                assert_eq!(actions.len(), crate::MAX_SEALED_OWNER_INVENTORY_ROWS)
            }
            other => panic!("expected actions, got {}", other.wire_tag()),
        }
    }

    #[test]
    fn leak_response_variants_are_registered() {
        assert_eq!(
            Response::LeakReports {
                page: LeakReportsPage {
                    reports: Vec::new(),
                    next_cursor: None,
                    has_more: false,
                }
            }
            .wire_tag(),
            "leak_reports"
        );
        assert_eq!(
            Response::LeakRevealCapability {
                capability: LeakRevealCapability {
                    capability: LeakRevealToken::new("00".repeat(32)),
                    report_id: String::new(),
                    expires_at_ms: 0,
                }
            }
            .wire_tag(),
            "leak_reveal_capability"
        );
        assert_eq!(
            Response::LeakRevealCancelled {
                report_id: String::new(),
            }
            .wire_tag(),
            "leak_reveal_cancelled"
        );
        assert_eq!(
            Response::LeakRotationUpdated {
                report_id: String::new(),
                rotation: String::new(),
            }
            .wire_tag(),
            "leak_rotation_updated"
        );
        assert_eq!(
            Response::LeakReportDeleted {
                report_id: String::new(),
            }
            .wire_tag(),
            "leak_report_deleted"
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
