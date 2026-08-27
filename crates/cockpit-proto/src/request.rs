use super::*;

/// Provenance of a submitted turn as classified by the originating client.
///
/// This is a required prerelease wire field: the daemon must retain the
/// classification chosen at the client ingress rather than reconstructing an
/// external-root turn for every `send_user_message` request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserMessageOrigin {
    #[default]
    ExternalRoot,
    GoalContinuation,
    ScheduledJob,
    AutoContinue,
    RetryRecovery,
    ToolResult,
    CompactNotice,
    Internal,
}

impl UserMessageOrigin {
    /// Stable FCM2 representation. The canonical artifact envelope is also a
    /// replay identity, so provenance must be encoded rather than restored
    /// from a default after restart.
    pub(crate) fn fcm2_code(self) -> u8 {
        match self {
            Self::ExternalRoot => 1,
            Self::GoalContinuation => 2,
            Self::ScheduledJob => 3,
            Self::AutoContinue => 4,
            Self::RetryRecovery => 5,
            Self::ToolResult => 6,
            Self::CompactNotice => 7,
            Self::Internal => 8,
        }
    }

    pub(crate) fn from_fcm2_code(code: u8) -> anyhow::Result<Self> {
        match code {
            1 => Ok(Self::ExternalRoot),
            2 => Ok(Self::GoalContinuation),
            3 => Ok(Self::ScheduledJob),
            4 => Ok(Self::AutoContinue),
            5 => Ok(Self::RetryRecovery),
            6 => Ok(Self::ToolResult),
            7 => Ok(Self::CompactNotice),
            8 => Ok(Self::Internal),
            _ => anyhow::bail!("invalid user message origin"),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ImageIngressSourceV1 {
    /// One-shot token minted by the in-process terminal host. It resolves to
    /// a retained no-follow handle; it is not a pathname or filename.
    PrivateTerminalCapability { capability: String },
    /// Clipboard pixels are captured and PNG-encoded by the terminal UI, then
    /// admitted by the same daemon policy/retention pipeline.
    ClipboardPng {
        png_base64: SensitiveWirePayload,
        byte_length: u64,
        #[serde(deserialize_with = "deserialize_lower_hex_sha256")]
        sha256: String,
    },
}

impl std::fmt::Debug for ImageIngressSourceV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrivateTerminalCapability { capability } => formatter
                .debug_struct("PrivateTerminalCapability")
                .field(
                    "capability",
                    &format_args!("[REDACTED; {} bytes]", capability.len()),
                )
                .finish(),
            Self::ClipboardPng {
                byte_length,
                sha256,
                ..
            } => formatter
                .debug_struct("ClipboardPng")
                .field("png_base64", &"[REDACTED]")
                .field("byte_length", byte_length)
                .field("sha256", sha256)
                .finish(),
        }
    }
}

#[cfg(feature = "remote")]
impl crate::remote_operation_fcor::CanonicalFcorValueV1 for ImageIngressSourceV1 {
    fn encode_fcor_value_v1(
        &self,
        out: &mut crate::remote_operation_fcor::CanonicalParamsV1,
    ) -> anyhow::Result<()> {
        use sha2::Digest as _;
        let material = zeroize::Zeroizing::new(serde_json::to_vec(self)?);
        out.push_bytes(sha2::Sha256::digest(material.as_slice()).as_slice())
    }
}

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

fn deserialize_lower_hex_sha256<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(serde::de::Error::custom(
            "value must be a 64-character lowercase SHA-256 digest",
        ));
    }
    Ok(value)
}

fn deserialize_bounded_string<'de, const MAX: usize, D>(
    deserializer: D,
) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() > MAX {
        return Err(serde::de::Error::custom(format!(
            "string exceeds maximum length of {MAX} bytes"
        )));
    }
    Ok(value)
}

fn deserialize_bounded_optional_string<'de, const MAX: usize, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?.map_or(Ok(None), |value| {
        if value.len() > MAX {
            Err(serde::de::Error::custom(format!(
                "string exceeds maximum length of {MAX} bytes"
            )))
        } else {
            Ok(Some(value))
        }
    })
}

fn deserialize_bounded_optional_limit<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<u16>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<u16>::deserialize(deserializer)?;
    if value.is_some_and(|value| value == 0 || value as usize > MAX_OWNER_INVENTORY_PAGE_ENTRIES) {
        return Err(serde::de::Error::custom(format!(
            "inventory page limit must be between 1 and {}",
            MAX_OWNER_INVENTORY_PAGE_ENTRIES
        )));
    }
    Ok(value)
}

fn deserialize_inventory_cursor<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_optional_string::<MAX_OWNER_INVENTORY_CURSOR_BYTES, D>(deserializer)
}

fn validate_agent_tree_page_request(
    session_id: Uuid,
    root_agent_instance_id: Option<Uuid>,
    after: Option<&AgentTreeCursor>,
    limit: u16,
) -> std::result::Result<(), String> {
    if session_id.is_nil()
        || root_agent_instance_id.is_some_and(|id| id.is_nil())
        || after.is_some_and(|cursor| cursor.id.is_nil())
    {
        return Err("agent tree identifiers must not be nil".to_string());
    }
    if !(1..=100).contains(&limit) {
        return Err("agent tree page limit must be between 1 and 100".to_string());
    }
    Ok(())
}

fn deserialize_owner_secret_name<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<MAX_OWNER_SECRET_NAME_BYTES, D>(deserializer)
}

fn deserialize_owner_secret_value<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<MAX_OWNER_SECRET_VALUE_BYTES, D>(deserializer)
}

fn deserialize_owner_provider_id<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<MAX_OWNER_PROVIDER_ID_BYTES, D>(deserializer)
}

fn deserialize_owner_provider_record<'de, D>(
    deserializer: D,
) -> std::result::Result<SensitiveWirePayload, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<MAX_OWNER_PROVIDER_RECORD_BYTES, D>(deserializer)
        .map(SensitiveWirePayload::new)
}

fn deserialize_owner_project_root<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<MAX_OWNER_PROJECT_ROOT_BYTES, D>(deserializer)
}

fn deserialize_owner_optional_project_root<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_optional_string::<MAX_OWNER_PROJECT_ROOT_BYTES, D>(deserializer)
}

#[cfg(feature = "remote")]
fn deserialize_owner_org_id<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<MAX_OWNER_ORG_ID_BYTES, D>(deserializer)
}

fn deserialize_owner_optional_provider_id<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_optional_string::<MAX_OWNER_PROVIDER_ID_BYTES, D>(deserializer)
}

fn validate_owner_identifier(label: &str, value: &str, max: usize) -> Result<(), String> {
    if value.trim().is_empty() || value.contains('\0') || value.len() > max {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

/// Wire-boundary cap for owner identifiers (operation ids, capabilities,
/// revisions, intent hashes). Field validation re-checks the exact per-field
/// bound; ingress enforces the loosest one.
const MAX_OWNER_WIRE_IDENTIFIER_BYTES: usize = 128;

fn deserialize_owner_identifier<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_owner_identifier("owner identifier", &value, MAX_OWNER_WIRE_IDENTIFIER_BYTES)
        .map_err(serde::de::Error::custom)?;
    Ok(value)
}

fn validate_optional_oauth_flow_id(value: Option<&str>, label: &str) -> Result<(), String> {
    if value.is_some_and(|flow_id| {
        flow_id.is_empty() || flow_id.len() > MAX_OWNER_PROVIDER_ID_BYTES || flow_id.contains('\0')
    }) {
        return Err(format!("{label} OAuth flow id is invalid"));
    }
    Ok(())
}

fn validate_owner_project_root(value: &str) -> Result<(), String> {
    validate_owner_identifier("project root", value, MAX_OWNER_PROJECT_ROOT_BYTES)
}

/// Provider endpoints are configuration, never a credential transport. Keep
/// this check in one shared helper so every owner ingress (including the
/// staged SaveProviderConfig path) rejects URL userinfo and covert query or
/// fragment credentials before the value can be journaled.
fn validate_credential_free_provider_url(url: &str) -> Result<(), String> {
    if url.len() > MAX_OWNER_PROVIDER_URL_BYTES {
        return Err("provider URL exceeds maximum length".to_string());
    }
    let parsed =
        url::Url::parse(url).map_err(|_| "provider URL must be an absolute URL".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("provider URL must use HTTP or HTTPS".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("provider URL must not include credentials".to_string());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("provider URL must not include a query string or fragment".to_string());
    }
    Ok(())
}

fn deserialize_owner_optional_model_id<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_optional_string::<MAX_OWNER_PROVIDER_MODEL_ID_BYTES, D>(deserializer)
}

fn deserialize_owner_provider_metadata_json<'de, D>(
    deserializer: D,
) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<MAX_OWNER_PROVIDER_METADATA_JSON_BYTES, D>(deserializer)
}

fn deserialize_owner_sensitive_metadata_json<'de, D>(
    deserializer: D,
) -> std::result::Result<SensitiveWirePayload, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<MAX_OWNER_PROVIDER_METADATA_JSON_BYTES, D>(deserializer)
        .map(SensitiveWirePayload::new)
}

fn deserialize_owner_mcp_secret_json<'de, D>(
    deserializer: D,
) -> std::result::Result<SensitiveWirePayload, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<MAX_OWNER_PROVIDER_METADATA_JSON_BYTES, D>(deserializer)
        .map(SensitiveWirePayload::new)
}

fn deserialize_owner_mcp_json<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_bounded_string::<MAX_OWNER_PROVIDER_METADATA_JSON_BYTES, D>(deserializer)
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
#[derive(Clone, Serialize, Deserialize)]
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
        /// Immutable daemon-owned entry setup for a newly-created session.
        /// It is required for new sessions. Existing-session attaches omit it
        /// in all first-party clients; if another client supplies it, the
        /// daemon requires exact equality with the durable value and never
        /// permits it to overwrite that value.
        #[serde(skip_serializing_if = "Option::is_none")]
        session_entry_mode: Option<crate::SessionEntryMode>,
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
        origin: UserMessageOrigin,
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

    /// Remote-safe oversized text ingress. The UTF-8 source itself is staged
    /// and integrity-checked on the existing bulk lane; this bounded request
    /// carries only its typed reference and the canonical FCM2 metadata.
    ///
    /// `display_transfer` is deliberately a second typed reference rather
    /// than an inline escape hatch. FCM2 gives `display_text` the same 8 MiB
    /// domain as `text`, so leaving a large display form inline would bypass
    /// the 524360-byte remote application-frame cap even when the authored
    /// source correctly used the bulk path. It is mutually exclusive with
    /// `display_text`. When it is present, `transfer` may carry an otherwise
    /// inline-sized source so a large display form can still be transported
    /// without inventing a second request shape.
    /// This is intentionally text-only, so it cannot mix bulk ownership with
    /// the existing image-attachment composition.
    SendUserMessageBulk {
        client_submission_id: Uuid,
        origin: UserMessageOrigin,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_model_state_generation: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_model: Option<cockpit_config::config::providers::ActiveModelRef>,
        transfer: crate::bulk_transfer::BulkTransferRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        display_text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        display_transfer: Option<crate::bulk_transfer::BulkTransferRef>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tag_expansions: Vec<TagExpansionMeta>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        forced_skill: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        run_invocation_options: Option<RunInvocationOptions>,
    },

    /// Query durable run-invocation status by the canonical client submission
    /// id. Does not require an attached session.
    GetRunInvocationStatus {
        client_submission_id: Uuid,
    },

    /// Query the durable outcome of an operation on the authenticated logical attachment.
    #[cfg(feature = "remote")]
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
    // ---- v10-only owner-remoted sealed-owner sensitive channel ---------
    // Every variant below is a NEW wire shape gated to protocol v10 by
    // `body_required_protocol_version`. The plaintext literal rides ONLY the
    // apply request (create/replace/rotate) and the recover-apply success
    // response; it never appears on begin, cancel, inventory, edit-description,
    // action-admin, or any error payload.
    /// Begin a sealed-owner sensitive operation: mint a single-use,
    /// capability bound to one exact disposition, owner principal, minting
    /// session, and daemon-loaded scope/version. `disposition` is one of
    /// `create|replace|rotate|recover`. Create carries `name`, `description`,
    /// `scope_kind` (`session|project|global`), and `scope_key`;
    /// replace/rotate/recover carry only `record_id`. Secret-free.
    BeginSealedOwnerOperation {
        disposition: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        record_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope_kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope_key: Option<String>,
    },
    /// Apply a sealed-owner operation against a minted capability. The `literal`
    /// carries the plaintext for a create/replace/rotate write and is absent for
    /// a recover. It is the redacting, zeroizing [`SensitiveWireLiteral`],
    /// bounded by [`crate::MAX_SENSITIVE_FRAME_BYTES`]. Consumes the capability
    /// through the shared compare-and-swap.
    ApplySealedOwnerOperation {
        capability_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        literal: Option<SensitiveWireLiteral>,
    },
    /// Cancel a minted sealed-owner capability, spending the same compare-and-swap
    /// as apply without performing the operation. Secret-free.
    CancelSealedOwnerOperation {
        capability_id: String,
    },
    /// List the safe sealed-value inventory (machine-wide, or narrowed by an
    /// optional safe scope filter). Never carries a literal.
    SealedOwnerInventory {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope_kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope_key: Option<String>,
    },
    /// Edit the safe description of a sealed value. Metadata-only; no literal.
    EditSealedOwnerDescription {
        record_id: String,
        description: String,
    },
    /// List sealed action instances as safe summaries. No origins, templates,
    /// or credentials.
    ListSealedActions,
    /// Create a sealed action instance. The three ids (`kind_id`, `origin_id`,
    /// `projection_id`) are closed server-side lookups the daemon resolves to a
    /// compiled action kind; an unknown id is rejected before any persist. The
    /// wire carries no origin URL, path template, or projection blob. The daemon
    /// mints the `action_id`.
    CreateSealedAction {
        kind_id: String,
        project_id: String,
        description: String,
        origin_id: String,
        projection_id: String,
    },
    /// Revise a sealed action instance's safe description (new revision).
    ReviseSealedActionDescription {
        action_id: String,
        description: String,
    },
    /// Enable or disable a sealed action instance (new revision).
    ReviseSealedActionEnabled {
        action_id: String,
        enabled: bool,
    },
    /// Retire a sealed action instance. `confirm` must equal `action_id`.
    RetireSealedAction {
        action_id: String,
        confirm: String,
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
    /// Spend an unconsumed leak-reveal capability without revealing its
    /// protected value. The daemon validates the exact opaque token and
    /// returns a report-bound settlement receipt.
    CancelLeakReveal {
        capability: LeakRevealToken,
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
    GetWorkspaceTrust {
        project_root: String,
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
        description: String,
        prompt: String,
    },

    /// Validate, CAS-write, and update the assistant registry as one daemon
    /// operation. Clients never combine generic FsWrite with registry upsert.
    SaveAssistantDefinition {
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
        mutation_intent_hash: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        name: String,
        markdown: String,
        expected_revision: String,
        /// Exact paired inventory generation that authorized this mutation.
        expected_config_generation: u64,
    },

    /// Create a new assistant session through the daemon registry. The
    /// session is deferred until worker start flushes the row, immediately
    /// before durable lifecycle setup.
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

    /// Assemble export-ready session data into a staged bulk transfer and
    /// return its reference; the client streams the bytes back with a chunk
    /// reader and writes the user-path file itself.
    ///
    /// The default (`include_sensitive = false`) is a permanently redacted,
    /// portable artifact assembled through the enforced redaction path, so
    /// `redact.enabled = false` and provider trust never relax export
    /// redaction. It is staged as
    /// [`crate::bulk_transfer::BulkMimeClass::RedactedExport`]
    /// and served over the owner-remoted type-bound
    /// [`Request::ReadRedactedExportChunk`] reader.
    ///
    /// `include_sensitive = true` is the single UNREDACTED export — the
    /// explicit local `cockpit export --include-sensitive` opt-in. It is
    /// owner-LOCAL only: the daemon rejects it for any remoted caller (a
    /// remote-operation dispatch), stages the raw bytes as the raw `Export`
    /// class, and serves them ONLY over the owner-local generic
    /// [`Request::ReadBulkTransferChunk`] reader — never a remoted reader.
    ExportSessionData {
        session_id: Uuid,
        kind: ExportSessionKind,
        #[serde(default)]
        include_generated_artifacts: bool,
        /// v10-only: request the raw, unredacted archive. Owner-LOCAL only;
        /// a remoted caller is rejected. Absent/`false` on v9 wires.
        #[serde(default)]
        include_sensitive: bool,
    },

    /// Import a ZIP archive through the daemon-owned database writer.
    ///
    /// The archive never travels inline. `transfer` references a completed
    /// bulk-lane transfer; the daemon reads the bytes from there after the
    /// transfer's digest and length have been verified.
    ImportSessionArchive {
        transfer: crate::bulk_transfer::BulkTransferRef,
    },

    /// Push one chunk of a bulk transfer into daemon-side staging.
    ///
    /// `transfer` describes the whole transfer (length, digest, class), so no
    /// separate begin round trip is needed. Chunks are contiguous from index 0
    /// and each body is bounded by [`crate::MAX_ATTACHMENT_CHUNK_BASE64_BYTES`],
    /// which keeps the encoded frame inside one bulk-lane logical payload.
    WriteBulkTransferChunk {
        transfer: crate::bulk_transfer::BulkTransferRef,
        chunk_index: u32,
        data_base64: String,
    },

    /// Pull one chunk of a staged bulk transfer. Owner-LOCAL only (the generic
    /// reader): a remoted caller is rejected, so raw `Export` bytes never leave
    /// the host over this reader.
    ReadBulkTransferChunk {
        transfer_id: crate::bulk_transfer::BulkTransferId,
        chunk_index: u32,
    },

    /// v10-only owner-remoted type-bound reader for a REDACTED export transfer.
    ///
    /// Pull one chunk of a staged transfer, admitting it ONLY when its staged
    /// kind is
    /// [`crate::bulk_transfer::BulkMimeClass::RedactedExport`].
    /// A raw `Export` transfer id (or any other bulk kind) is rejected with no
    /// bytes — this is what lets a remoted owner download a redacted export
    /// while the raw archive stays owner-local behind
    /// [`Request::ReadBulkTransferChunk`].
    ReadRedactedExportChunk {
        transfer_id: crate::bulk_transfer::BulkTransferId,
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

    /// Read a complete worktree/index projection through daemon-owned Git
    /// authority. The response is capped before crossing the wire.
    GitDiff {
        project_root: String,
        source: crate::GitReadSource,
    },

    /// Resolve the selected `/multireview` sources in one daemon operation.
    GitReviewSources {
        project_root: String,
        sources: Vec<crate::GitReadSource>,
    },

    /// Read the branch/ahead-behind status pill through daemon-owned Git
    /// authority. Backs the TUI chrome poller so the terminal process never
    /// shells out to `git` itself.
    GitRepoStatus {
        project_root: String,
    },

    /// Resolve `path` to its git worktree root through daemon-owned Git
    /// authority (`git rev-parse --show-toplevel`). `None` when `path` is not
    /// inside a repository. Lets TUI panes discover the worktree root without
    /// shelling out to `git` themselves.
    FindWorktreeRoot {
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
    ///
    /// `assistant_id` is a v10-only extended filter: when `Some(name)`,
    /// only sessions belonging to that assistant are returned. A v9
    /// envelope carrying this field is rejected by the version gate.
    ListSessions {
        #[serde(default)]
        project_id: Option<String>,
        #[serde(default)]
        parent_session_id: Option<Uuid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        assistant_id: Option<String>,
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

    /// Read a stable, paginated daemon-owned projection of one recursive
    /// agent tree. `root_agent_instance_id = None` returns the session forest.
    /// The response deliberately contains no provider context or process
    /// handles; frontends render only durable lifecycle state.
    ReadAgentTree {
        session_id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        root_agent_instance_id: Option<Uuid>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        after: Option<AgentTreeCursor>,
        limit: u16,
    },

    /// Read typed, decision-owned Attention entries. This is intentionally
    /// separate from the legacy interrupt history so decision lifecycle state
    /// has one ordered durable projection.
    ReadAgentAttention {
        session_id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        after: Option<AgentTreeCursor>,
        limit: u16,
    },

    /// Deliver a user-authored steer to the agent that requested a decision.
    /// The daemon validates this answer against the persisted redacted
    /// contract. Host approvals have no client resolution path.
    ResolveAgentDecision {
        session_id: Uuid,
        decision_request_id: Uuid,
        answer: AgentDecisionAnswer,
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

    /// Return daemon-owned installed-agent/model setup choices for the
    /// attached session. The daemon derives both workspace and selected
    /// installation; callers cannot select another session's inventory.
    GetSessionSetupSnapshot {
        session_id: Uuid,
    },

    /// Return the focused agent node's daemon-resolved effective settings,
    /// allowed transitions, locked reasons, and effective-settings revision.
    /// Read-only; the daemon owns every authority fact.
    GetAgentEffectiveSettings {
        session_id: Uuid,
        agent_instance_id: Uuid,
    },

    /// Apply one typed, non-escalating session override to a focused agent
    /// node. In a single daemon transaction the request compares
    /// `expected_override_revision`, deterministically merges its typed field
    /// into the node's pending override, increments/returns the revision, and
    /// makes every competing old-revision request stale. Stale, unauthorized,
    /// completed, or cancelled targets are rejected without a state change. The
    /// pending override is consumed into effect at the node's next model turn.
    ApplyAgentSessionOverride {
        session_id: Uuid,
        agent_instance_id: Uuid,
        expected_override_revision: u64,
        field: AgentSessionOverrideFieldV1,
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

    /// Store Flycockpit instance credentials in the daemon vault (ciphertext
    /// in SQLite; the daemon holds the unwrapped key in memory) and wake the
    /// relay connector immediately. Owner-only; ephemeral daemons reject it
    /// because they must not own persistent credentials.
    #[cfg(feature = "remote")]
    StoreFlycockpitCredential {
        credential: StoredFlycockpitCredential,
        /// When false, a vault hit returns [`crate::Response::FlycockpitAlreadyLoggedIn`]
        /// instead of replacing the stored credential.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        force: bool,
    },

    /// Clear Flycockpit instance credentials from the daemon vault and wake
    /// the relay connector so active sockets stop promptly. Owner-only;
    /// ephemeral daemons reject it.
    #[cfg(feature = "remote")]
    ClearFlycockpitCredential,

    /// Enable or disable the daemon-owned relay connector for the current
    /// FlyCockpit account. The daemon resolves the account from its vault.
    #[cfg(feature = "remote")]
    SetFlycockpitConnectorEnabled {
        enabled: bool,
    },

    /// Fetch and apply the current organization session-log policy for the
    /// daemon-owned FlyCockpit account. No credential material is returned.
    #[cfg(feature = "remote")]
    SyncFlycockpitOrgPolicy,

    /// Persist the owner's explicit organization session-log enrollment.
    /// The daemon resolves the account and server URL from its vault.
    #[cfg(feature = "remote")]
    EnrollFlycockpitOrgSync {
        #[serde(deserialize_with = "deserialize_owner_org_id")]
        org_id: String,
    },

    /// Return names and safe metadata for daemon-owned secret entries.
    ListSecretInventory {
        /// Opaque cursor returned by the preceding page.
        #[serde(default, deserialize_with = "deserialize_inventory_cursor")]
        cursor: Option<String>,
        /// Desired page size. The daemon applies the same hard upper bound
        /// when an in-process caller constructs this request directly.
        #[serde(default, deserialize_with = "deserialize_bounded_optional_limit")]
        limit: Option<u16>,
    },

    /// Store one named secret in the daemon vault.
    PutNamedSecret {
        #[serde(deserialize_with = "deserialize_owner_secret_name")]
        name: String,
        #[serde(deserialize_with = "deserialize_owner_secret_value")]
        value: String,
    },

    /// Record that the owner explicitly acknowledged the subscription OAuth
    /// disclosure.  This has a distinct vault kind and a typed JSON `true`
    /// payload; it is not a named secret and is never returned over the wire.
    PutSubscriptionAck {
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        provider_id: String,
    },

    /// Remove one named secret from the daemon vault.
    DeleteNamedSecret {
        #[serde(deserialize_with = "deserialize_owner_secret_name")]
        name: String,
    },

    /// Store one provider credential record as canonical JSON in the daemon
    /// vault. The JSON string is intentionally opaque to the wire contract.
    PutProviderCredential {
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        provider_id: String,
        #[serde(deserialize_with = "deserialize_owner_provider_record")]
        record: SensitiveWirePayload,
    },

    /// Query an owner-scoped durable local mutation after its transport
    /// outcome became unknown. The daemon never returns another owner's row.
    GetLocalOperationSettlement {
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
    },

    /// Begin a daemon-owned provider OAuth exchange. The daemon retains PKCE,
    /// device-code polling state, and eventual tokens; the client receives
    /// only display-safe instructions and an opaque flow id.
    #[serde(rename = "begin_provider_oauth")]
    BeginProviderOAuth {
        /// Stable owner-generated idempotency key for this begin attempt.
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        provider_id: String,
    },

    /// Complete or poll a daemon-owned provider OAuth exchange. `input` is
    /// limited to the pasted browser callback for browser flows; device flows
    /// ignore it and poll using state retained by the daemon.
    #[serde(rename = "complete_provider_oauth")]
    CompleteProviderOAuth {
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
        flow_id: String,
        #[serde(default)]
        input: Option<crate::SensitiveWirePayload>,
    },

    /// Cancel an in-progress daemon-owned provider OAuth flow. Cancellation is
    /// idempotent so a client can settle a timed-out or already-consumed flow.
    #[serde(rename = "cancel_provider_oauth")]
    CancelProviderOAuth {
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
        /// The begin operation is always known, even when its response (and
        /// therefore the daemon flow id) was lost in transport.
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        begin_client_operation_id: String,
        #[serde(default, deserialize_with = "deserialize_owner_optional_provider_id")]
        flow_id: Option<String>,
    },

    /// Begin daemon-owned MCP OAuth. The daemon retains PKCE and loopback
    /// callback state; the client receives only an opaque flow id and URL.
    #[serde(rename = "begin_mcp_oauth")]
    BeginMcpOAuth {
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        server: String,
    },

    /// Complete or poll daemon-owned MCP OAuth. `input` may carry a callback
    /// URL/code supplied by a UI, but never a token.
    #[serde(rename = "complete_mcp_oauth")]
    CompleteMcpOAuth {
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
        flow_id: String,
        #[serde(default)]
        input: Option<crate::SensitiveWirePayload>,
    },

    /// Cancel an in-progress daemon-owned MCP OAuth flow.
    #[serde(rename = "cancel_mcp_oauth")]
    CancelMcpOAuth {
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        begin_client_operation_id: String,
        #[serde(default, deserialize_with = "deserialize_owner_optional_provider_id")]
        flow_id: Option<String>,
    },

    /// Remove one provider credential record from the daemon vault.
    DeleteProviderCredential {
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        provider_id: String,
        /// When supplied, `provider_id` is a configured provider identifier.
        /// The daemon resolves its credential reference privately before
        /// deleting. Omitted preserves the direct credential-record form for
        /// owner callers that already hold a vault record identifier.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_owner_optional_project_root"
        )]
        project_root: Option<String>,
    },

    /// Return redacted Flycockpit account metadata, never the instance token.
    #[cfg(feature = "remote")]
    GetFlycockpitAccount,

    /// Return the daemon-owned, redacted provider catalog/config projection.
    GetProviderCatalogSnapshot {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_owner_optional_provider_id"
        )]
        provider_id: Option<String>,
        /// Client nonce binding the returned opaque edit capability.
        #[serde(deserialize_with = "deserialize_nonempty_string")]
        snapshot_session_id: String,
    },

    /// Apply one complete provider-layer edit under the daemon's snapshot CAS.
    /// No filesystem path crosses this mutation boundary.
    ApplyProviderMutation {
        #[serde(deserialize_with = "deserialize_nonempty_string")]
        snapshot_session_id: String,
        #[serde(deserialize_with = "deserialize_nonempty_string")]
        layer_id: String,
        #[serde(deserialize_with = "deserialize_nonempty_string")]
        expected_revision: String,
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
        /// Non-secret digest of the exact staged provider mutation intent.
        #[serde(
            default,
            deserialize_with = "deserialize_lower_hex_sha256",
            skip_serializing_if = "String::is_empty"
        )]
        mutation_intent_hash: String,
        mutation: crate::ProviderMutationBatch,
    },

    /// Resolve credentials, fetch provider models, and persist resulting
    /// provider metadata in the daemon. The response never contains secrets.
    FetchProviderModels {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_owner_optional_provider_id"
        )]
        provider_id: Option<String>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_owner_optional_model_id"
        )]
        model_id: Option<String>,
        #[serde(default)]
        deep: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        on_unlisted: Option<cockpit_config::config::providers::OnUnlistedModelsFetch>,
        /// When a live catalog is unavailable, explicitly activate the
        /// daemon's built-in fallback catalog.  Keeping this decision on the
        /// request makes an accepted fallback a durable daemon retry rather
        /// than a client-side merge.
        #[serde(default)]
        allow_fallback: bool,
    },

    /// Fetch daemon-owned provider quota/usage snapshots.
    GetProviderUsageSnapshot {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "deserialize_owner_optional_provider_id"
        )]
        provider_id: Option<String>,
    },

    /// Persist non-secret provider configuration through the daemon's
    /// trust-aware config writer.
    #[cfg(feature = "remote")]
    UpsertProviderConfig {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        provider_id: String,
        entry: cockpit_config::config::providers::ProviderEntry,
    },

    /// Atomically stage private provider-header material in the daemon vault
    /// and persist the corresponding reference-only provider configuration.
    /// `header_secrets` is positional with `entry.headers`; only the daemon
    /// assigns durable vault record names.
    #[cfg(feature = "remote")]
    SaveProviderConfig {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        provider_id: String,
        entry: cockpit_config::config::providers::ProviderEntry,
        header_secrets: Vec<Option<crate::ProviderSecretValue>>,
    },

    /// Ask the daemon to acquire Copilot credentials from its own environment
    /// and persist them through the provider-config owner path.  The response
    /// is status-only; the credential never crosses the RPC boundary.
    SetupCopilotAuth {
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        provider_id: String,
    },

    /// Apply the security or model setup wizard through the daemon owner.
    /// Answers are validated against the daemon's current descriptor; the
    /// descriptor itself never crosses the wire.
    #[cfg(feature = "remote")]
    ApplySetupWizard {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        wizard_id: String,
        #[serde(deserialize_with = "deserialize_owner_mcp_json")]
        answers_json: String,
    },

    /// Atomically persist one daemon-owned MCP config layer and its named
    /// secret changes. Secret values and cleanup names are JSON envelopes so
    /// the wire never exposes the core MCP implementation type.
    SaveMcpConfig {
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        snapshot_capability: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        owner_root: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        config_path: String,
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        expected_revision: String,
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        mutation_intent_hash: String,
        #[serde(deserialize_with = "deserialize_owner_mcp_secret_json")]
        patch: SensitiveWirePayload,
        #[serde(deserialize_with = "deserialize_owner_mcp_secret_json")]
        secret_values_json: SensitiveWirePayload,
    },

    /// Discover the effective daemon-owned agent inventory for a workspace.
    GetAgentInventory {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
    },

    /// Resolve one agent to a safe editable projection and opaque revision.
    GetAgentEditSnapshot {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        name: String,
    },

    /// Apply one typed agent mutation. `expected_revision` is mandatory for
    /// every mutation except creation; reset-all consumes an inventory
    /// revision rather than a document revision.
    MutateAgent {
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
        mutation_intent_hash: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        mutation: crate::AgentMutation,
        #[serde(deserialize_with = "deserialize_optional_nonempty_string")]
        expected_revision: Option<String>,
    },

    /// Acquire a daemon-side lease before handing an agent draft to an
    /// external editor. The editor works on a host-owned staging file, never
    /// the authoritative agent path.
    BeginAgentEditorLease {
        /// Owner-generated idempotency key. Repeating an exact Begin after a
        /// lost response returns the same durable lease and snapshot.
        client_operation_id: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        name: String,
        expected_revision: String,
    },

    /// Complete or cancel an external-editor lease. On commit the daemon
    /// validates and CAS-publishes the returned markdown.
    CompleteAgentEditorLease {
        client_operation_id: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        lease_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        markdown: Option<SensitiveWirePayload>,
    },

    /// Query the durable outcome of an exact external-editor settlement
    /// without resending the edited document.
    GetAgentEditorLeaseSettlement {
        client_operation_id: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        lease_id: String,
    },

    /// Read a daemon-redacted settings layer and its opaque on-disk revision.
    GetExtendedConfigSnapshot {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        /// Client-generated opaque lifetime for one settings pane. Refreshing
        /// this same session atomically replaces its earlier capabilities.
        snapshot_session_id: String,
    },

    /// Read the daemon-owned local image-sidecar authority and safe audit
    /// projection. `config_generation` and `selection_id` fence stale settings
    /// panes; grants are never inferred from a client reducer.
    GetImageSidecarAuthoritySnapshot {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        config_generation: u64,
        selection_id: String,
    },

    /// Create an explicit LOCAL image-sidecar destination grant. Global scope
    /// is intentionally not representable in the exact-v1 wire contract.
    CreateImageSidecarGrant {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        config_generation: u64,
        selection_id: String,
        /// Opaque daemon-issued candidate identity from the matching authority
        /// snapshot. Never a caller-controlled destination or bearer URL.
        grant_candidate_id: String,
        purpose: String,
        scope: crate::image_sidecar_authority::ImageSidecarGrantScopeV1,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        invocation_id: Option<String>,
    },

    /// Revoke the exact grant version shown in a confirmed settings pane.
    RevokeImageSidecarGrant {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        config_generation: u64,
        selection_id: String,
        grant_id: String,
        expected_version: u64,
    },

    /// Apply a typed field patch to the authoritative daemon-selected layer.
    ApplyExtendedConfigPatch {
        #[serde(default, deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        layer_id: String,
        patch: crate::ExtendedConfigPatch,
        expected_revision: String,
        snapshot_session_id: String,
    },

    /// Atomically persist a rendered extended settings layer. The daemon
    /// validates the target as a config.json layer, reloads it under the
    /// config mutation lock, and rejects stale `base_hash` writes.
    SaveExtendedConfig {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_metadata_json")]
        path: String,
        #[serde(deserialize_with = "deserialize_owner_provider_metadata_json")]
        content: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        base_hash: Option<String>,
    },

    /// Export the daemon-owned portable policy bundle for a project.
    ExportPolicy {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
    },

    /// Import a portable policy bundle through the daemon owner boundary.
    ImportPolicy {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_mcp_json")]
        bundle_json: String,
        #[serde(default)]
        replace: bool,
    },

    /// Return the current daemon-owned image spend policy.
    #[cfg(feature = "extended")]
    GetImageSpendPolicy {
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        project_key: String,
    },

    /// Validate and persist an image spend policy through the daemon owner.
    #[cfg(feature = "extended")]
    SaveImageSpendPolicy {
        /// Stable owner-chosen id used for durable replay and settlement.
        client_operation_id: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        project_key: String,
        #[serde(deserialize_with = "deserialize_owner_provider_metadata_json")]
        settings_json: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_policy_version: Option<u64>,
    },

    /// LOCAL owner READ: list the redacted image-generation endpoints for a
    /// project. Owner-only, local-only, concurrent. Secret-bearing fields
    /// (credential_ref/headers) are dropped by the safe projection.
    ImageEndpointList {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    },

    /// LOCAL owner READ: get one redacted image-generation endpoint.
    ImageEndpointGet {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        endpoint_id: String,
    },

    /// LOCAL owner READ: list the redacted image-generation targets.
    ImageTargetList {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    },

    /// LOCAL owner READ: get one redacted image-generation target.
    ImageTargetGet {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        target_id: String,
    },

    /// LOCAL owner READ: list the redacted registered image workflows. The
    /// safe projection drops the opaque `graph_json` blob.
    ImageWorkflowList {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    },

    /// LOCAL owner READ: get one redacted registered image workflow.
    ImageWorkflowGet {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        workflow_id: String,
    },

    /// LOCAL owner CONFIG MUTATION: append a new image endpoint. Owner-only,
    /// local-only, serialized. The endpoint is carried as one OPAQUE JSON blob
    /// (the raw `credential_ref`/`headers` never appear as typed wire fields);
    /// it is validated through the single `ImageGenerationConfig::new` funnel
    /// before any write. The generation and authoritative target-document
    /// revision are mandatory optimistic-CAS fences; there is no freshness
    /// bypass.
    ImageEndpointCreate {
        client_operation_id: String,
        mutation_intent_hash: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_sensitive_metadata_json")]
        endpoint_json: SensitiveWirePayload,
        expected_config_generation: u64,
        expected_config_revision: String,
        mutation_capability: crate::image_control::ImageConfigMutationCapabilityV1,
    },

    /// LOCAL owner CONFIG MUTATION: replace an existing image endpoint by id
    /// with the supplied opaque endpoint JSON.
    ImageEndpointUpdate {
        client_operation_id: String,
        mutation_intent_hash: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        endpoint_id: String,
        #[serde(deserialize_with = "deserialize_owner_sensitive_metadata_json")]
        endpoint_json: SensitiveWirePayload,
        expected_config_generation: u64,
        expected_config_revision: String,
        mutation_capability: crate::image_control::ImageConfigMutationCapabilityV1,
    },

    /// LOCAL owner CONFIG MUTATION: remove an image endpoint by id.
    ImageEndpointDelete {
        client_operation_id: String,
        mutation_intent_hash: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        endpoint_id: String,
        expected_config_generation: u64,
        expected_config_revision: String,
        mutation_capability: crate::image_control::ImageConfigMutationCapabilityV1,
    },

    /// LOCAL owner CONFIG MUTATION: append a new image target (opaque JSON).
    ImageTargetCreate {
        client_operation_id: String,
        mutation_intent_hash: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_sensitive_metadata_json")]
        target_json: SensitiveWirePayload,
        expected_config_generation: u64,
        expected_config_revision: String,
        mutation_capability: crate::image_control::ImageConfigMutationCapabilityV1,
    },

    /// LOCAL owner CONFIG MUTATION: replace an existing image target by id.
    ImageTargetUpdate {
        client_operation_id: String,
        mutation_intent_hash: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        target_id: String,
        #[serde(deserialize_with = "deserialize_owner_sensitive_metadata_json")]
        target_json: SensitiveWirePayload,
        expected_config_generation: u64,
        expected_config_revision: String,
        mutation_capability: crate::image_control::ImageConfigMutationCapabilityV1,
    },

    /// LOCAL owner CONFIG MUTATION: remove an image target by id.
    ImageTargetDelete {
        client_operation_id: String,
        mutation_intent_hash: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        target_id: String,
        expected_config_generation: u64,
        expected_config_revision: String,
        mutation_capability: crate::image_control::ImageConfigMutationCapabilityV1,
    },

    /// LOCAL owner CONFIG MUTATION: make the target with `target_id` the single
    /// enabled default (clearing any prior default). Enforced by the
    /// exactly-one-default invariant in `ImageGenerationConfig::new`.
    ImageTargetSetDefault {
        client_operation_id: String,
        mutation_intent_hash: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        target_id: String,
        expected_config_generation: u64,
        expected_config_revision: String,
        mutation_capability: crate::image_control::ImageConfigMutationCapabilityV1,
    },

    /// LOCAL owner CONFIG MUTATION: register a new ComfyUI workflow. Owner-only,
    /// local-only, serialized. The workflow (including the opaque `graph_json`
    /// blob, where a token can hide anywhere) is carried as one OPAQUE JSON blob;
    /// it is validated through the single `ImageGenerationConfig::new` funnel —
    /// which parses `graph_json`, REJECTS a `graph_digest` that does not match the
    /// actual graph (a client cannot register a lying digest), and enforces
    /// unique ids — before any write.
    ImageWorkflowUpload {
        client_operation_id: String,
        mutation_intent_hash: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_sensitive_metadata_json")]
        workflow_json: SensitiveWirePayload,
        expected_config_generation: u64,
        expected_config_revision: String,
        mutation_capability: crate::image_control::ImageConfigMutationCapabilityV1,
    },

    /// LOCAL owner CONFIG MUTATION: replace an existing workflow by id with the
    /// supplied opaque workflow JSON (updated bindings/outputs over the same
    /// graph). The `graph_digest` is re-verified against `graph_json` by
    /// `ImageGenerationConfig::new`.
    ImageWorkflowBind {
        client_operation_id: String,
        mutation_intent_hash: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        workflow_id: String,
        #[serde(deserialize_with = "deserialize_owner_sensitive_metadata_json")]
        bindings_json: SensitiveWirePayload,
        expected_config_generation: u64,
        expected_config_revision: String,
        mutation_capability: crate::image_control::ImageConfigMutationCapabilityV1,
    },

    /// LOCAL owner CONFIG MUTATION: remove a workflow by id. Fails closed if a
    /// still-enabled target binds it.
    ImageWorkflowDelete {
        client_operation_id: String,
        mutation_intent_hash: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        workflow_id: String,
        expected_config_generation: u64,
        expected_config_revision: String,
        mutation_capability: crate::image_control::ImageConfigMutationCapabilityV1,
    },

    /// Remove a provider entry through the daemon's trust-aware writer.
    #[cfg(feature = "remote")]
    DeleteProviderConfig {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_id")]
        provider_id: String,
        /// Delete only secrets no longer referenced by another provider.
        /// Cleanup is performed by the daemon before removing the config so
        /// a retry cannot strand a credential when either phase fails.
        #[serde(default)]
        delete_stored_secrets: bool,
    },

    /// Persist layer-wide non-secret provider metadata through the daemon.
    #[cfg(feature = "remote")]
    SetProviderLayerMetadata {
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        #[serde(deserialize_with = "deserialize_owner_provider_metadata_json")]
        category_defaults_json: String,
        on_unlisted_models_fetch: cockpit_config::config::providers::OnUnlistedModelsFetch,
    },

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

    /// Consume an opaque terminal-host capability or admit clipboard PNG
    /// bytes into daemon-owned retained media. Host paths never cross this
    /// protocol boundary.
    AdmitImageIngress {
        session_id: Uuid,
        source: ImageIngressSourceV1,
        admission_id: Uuid,
    },

    /// Dispose an admitted image draft that never crossed the daemon's
    /// first-reference boundary. The daemon derives principal/project and
    /// current generations; these opaque identities only bind the exact
    /// admission and idempotent operation.
    DiscardImageIngressDraft {
        session_id: Uuid,
        admission_id: Uuid,
        local_operation_id: Uuid,
    },

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
        dest: SecretStorePlacement,
    },

    // ---- v10-only owner-remoted CLI-surface RPCs -----------------------
    // Every variant below is a NEW wire shape gated to protocol v10 by
    // `body_required_protocol_version`. Responses carry no secret bytes.
    /// List registered packages through the daemon-owned registry.
    ListPackages,

    /// Register a package clone (git or local) through the daemon.
    AddPackage {
        project_root: String,
        identifier: String,
        git: Option<String>,
        branch: Option<String>,
        local_path: Option<String>,
        deep: bool,
    },

    /// Import one or more packages from a directory or single package dir.
    ImportPackage {
        project_root: String,
        dir: Option<String>,
        package: Option<String>,
        id: Option<String>,
        as_path: bool,
    },

    /// Prune stale package clones through the daemon-owned registry.
    PrunePackages {
        project_root: String,
        days: u32,
        dry_run: bool,
    },

    /// Import packages from a local kcl install through the daemon.
    ImportKclPackages {
        project_root: String,
    },

    /// Read the FlyCockpit connector state for the current account.
    #[cfg(feature = "remote")]
    GetConnectorState,

    /// Read org-policy session-log sync state and audit upload cursors.
    #[cfg(feature = "remote")]
    GetOrgSyncStatus,

    /// List recent failed/recovered tool calls (owner-remoted read).
    ListFailedToolCalls {
        since_epoch: i64,
        tool: Option<String>,
        model: Option<String>,
        project_id: Option<String>,
        include_recovered: bool,
        limit: u32,
    },

    /// Return the complete compaction-event list for a session. Distinct
    /// from `ReadHistoryPage`: no pagination, no event-kind ambiguity.
    GetSessionCompactions {
        session_id: Uuid,
    },

    /// Purge every ended session whose end time is before `before`
    /// (unix-epoch seconds).
    PurgeEndedSessions {
        before: i64,
    },

    /// Read a single assistant registry row by name.
    GetAssistant {
        name: String,
    },

    /// Delete an assistant registry row by name (home dir left intact).
    DeleteAssistant {
        #[serde(deserialize_with = "deserialize_owner_identifier")]
        client_operation_id: String,
        mutation_intent_hash: String,
        #[serde(deserialize_with = "deserialize_owner_project_root")]
        project_root: String,
        name: String,
        /// Revision returned by `GetAssistant`, covering the registry row and
        /// exact daemon-read definition bytes.
        #[serde(default)]
        expected_revision: String,
        /// Exact paired inventory generation that authorized this mutation.
        expected_config_generation: u64,
    },

    /// Diagnose a media reservation accounting scope (owner-remoted read).
    DiagnoseMediaReservation {
        scope: String,
        id: String,
    },

    /// Repair a media reservation accounting scope (owner-remoted mutation).
    RepairMediaReservation {
        scope: String,
        id: String,
        expected_block_generation: u64,
        repair_plan_digest: String,
        idempotency_key: String,
    },

    /// Assemble the doctor diagnostics snapshot through the daemon.
    GetDoctorSnapshot {
        project_root: Option<String>,
        no_sandbox: bool,
        offline: bool,
    },

    /// Answer a read-only dependency-docs question through the daemon.
    /// The daemon creates a `"docs"`-agent session, runs the existing
    /// read-only package-question pipeline, and returns the rendered
    /// answer on [`crate::Response::DocsAnswer`]. `project_root` supplies
    /// the workspace whose layered config/trust resolve the answering
    /// model (absent ⇒ the daemon's canonical cwd, mirroring
    /// `get_doctor_snapshot`).
    DocsAsk {
        question: String,
        package: Option<String>,
        project_root: Option<String>,
    },

    /// Begin a daemon-owned agent installation/update/bind/create operation.
    /// Its DTO never carries a credential or response-visible filesystem path.
    AgentInstallationBegin(crate::AgentInstallationBeginV1),

    /// Submit a durable daemon-issued installation choice token.
    AgentInstallationSubmitChoice(crate::AgentInstallationSubmitChoiceV1),

    AgentInstallationList(crate::AgentInstallationReadV1),

    AgentInstallationInspect(crate::AgentInstallationReadV1),

    #[serde(other)]
    Unknown,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Requests can carry plaintext credentials. Keep diagnostics useful
        // for routing while making accidental `{:?}` logging secret-free.
        formatter
            .debug_struct("Request")
            .field("wire_tag", &self.wire_tag())
            .field("payload", &"<redacted>")
            .finish()
    }
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
            #[cfg(feature = "remote")]
            Self::StoreFlycockpitCredential { credential, .. } => {
                credential
                    .validate()
                    .map_err(|error| format!("invalid Flycockpit credential: {error}"))?;
            }
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
                origin,
                expected_model_state_generation,
                expected_model,
                run_invocation_options,
                ..
            } => {
                if *origin != UserMessageOrigin::ExternalRoot {
                    return Err(
                        "send_user_message origin must be external_root; internal provenance is daemon-owned"
                            .to_string(),
                    );
                }
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
            Self::SendUserMessageBulk {
                client_submission_id,
                origin,
                expected_model_state_generation,
                expected_model,
                transfer,
                display_text,
                display_transfer,
                run_invocation_options,
                ..
            } => {
                if *origin != UserMessageOrigin::ExternalRoot {
                    return Err(
                        "send_user_message_bulk origin must be external_root; internal provenance is daemon-owned"
                            .to_string(),
                    );
                }
                if client_submission_id.is_nil() {
                    return Err("client_submission_id must not be nil".to_string());
                }
                if expected_model_state_generation.is_some() != expected_model.is_some() {
                    return Err(
                        "expected model generation and identity must be supplied together"
                            .to_string(),
                    );
                }
                let is_opaque_text_transfer =
                    |reference: &crate::bulk_transfer::BulkTransferRef, minimum_length: u64| {
                        reference.mime_class == crate::bulk_transfer::BulkMimeClass::Opaque
                            && (minimum_length
                                ..=crate::send_user_message_v2::MAX_MESSAGE_TEXT_BYTES as u64)
                                .contains(&reference.total_length_value())
                    };
                let source_minimum_length = if display_transfer.is_some() {
                    1
                } else {
                    65_537
                };
                if !is_opaque_text_transfer(transfer, source_minimum_length) {
                    return Err(
                        "bulk user message must be an opaque 64KiB..8MiB transfer".to_string()
                    );
                }
                if display_text
                    .as_ref()
                    .is_some_and(|value| value.len() > 64 * 1024)
                {
                    return Err(
                        "bulk user message display text over 64KiB must use a transfer".to_string(),
                    );
                }
                if let Some(display_transfer) = display_transfer {
                    if display_text.is_some() {
                        return Err(
                            "bulk user message display text must be inline or a transfer, not both"
                                .to_string(),
                        );
                    }
                    if !is_opaque_text_transfer(display_transfer, 1) {
                        return Err(
                            "bulk user message display transfer must be an opaque 1B..8MiB transfer"
                                .to_string(),
                        );
                    }
                    if display_transfer.transfer_id == transfer.transfer_id {
                        return Err(
                            "bulk user message text and display transfers must be distinct"
                                .to_string(),
                        );
                    }
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
            Self::ListSecretInventory { cursor, limit } => {
                if cursor
                    .as_ref()
                    .is_some_and(|value| value.len() > MAX_OWNER_INVENTORY_CURSOR_BYTES)
                {
                    return Err("inventory cursor exceeds maximum length".to_string());
                }
                if limit.is_some_and(|value| {
                    value == 0 || value as usize > MAX_OWNER_INVENTORY_PAGE_ENTRIES
                }) {
                    return Err(format!(
                        "inventory page limit must be between 1 and {MAX_OWNER_INVENTORY_PAGE_ENTRIES}"
                    ));
                }
            }
            Self::ReadAgentTree {
                session_id,
                root_agent_instance_id,
                after,
                limit,
            } => {
                validate_agent_tree_page_request(
                    *session_id,
                    *root_agent_instance_id,
                    after.as_ref(),
                    *limit,
                )?;
            }
            Self::ReadAgentAttention {
                session_id,
                after,
                limit,
            } => validate_agent_tree_page_request(*session_id, None, after.as_ref(), *limit)?,
            Self::ResolveAgentDecision {
                session_id,
                decision_request_id,
                answer,
            } => {
                if session_id.is_nil() || decision_request_id.is_nil() {
                    return Err("agent decision identifiers must not be nil".to_string());
                }
                match answer {
                    AgentDecisionAnswer::Option { option_id } if option_id.is_empty() => {
                        return Err("agent decision option id must not be empty".to_string());
                    }
                    AgentDecisionAnswer::FreeText { text } if text.is_empty() => {
                        return Err("agent decision free text must not be empty".to_string());
                    }
                    AgentDecisionAnswer::InterruptResponse { response } => {
                        validate_agent_interrupt_response(response)?;
                    }
                    _ => {}
                }
            }
            Self::PutNamedSecret { name, value } => {
                if name.len() > MAX_OWNER_SECRET_NAME_BYTES {
                    return Err("named secret name exceeds maximum length".to_string());
                }
                if value.len() > MAX_OWNER_SECRET_VALUE_BYTES {
                    return Err("named secret value exceeds maximum length".to_string());
                }
            }
            Self::ApplySealedOwnerOperation {
                literal: Some(literal),
                ..
            } => {
                // In-process apply requests bypass the wire newtype's bounding
                // deserialize, so re-enforce the frame bound here (fail closed)
                // before dispatch.
                if literal.len() > MAX_SENSITIVE_FRAME_BYTES {
                    return Err(
                        "sealed-owner apply literal exceeds maximum frame length".to_string()
                    );
                }
            }
            Self::CancelLeakReveal { capability }
                if capability.len() != 64
                    || !capability
                        .as_str()
                        .as_bytes()
                        .iter()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)) =>
            {
                return Err("leak reveal capability must be 64 lowercase hex bytes".to_string());
            }
            Self::PutSubscriptionAck {
                client_operation_id,
                provider_id,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                if provider_id.trim().is_empty() {
                    return Err("subscription provider id must not be empty".to_string());
                }
                if provider_id.contains('\0') {
                    return Err("subscription provider id contains NUL".to_string());
                }
                if provider_id.len() > MAX_OWNER_PROVIDER_ID_BYTES {
                    return Err("subscription provider id exceeds maximum length".to_string());
                }
            }
            #[cfg(feature = "remote")]
            Self::EnrollFlycockpitOrgSync { org_id } => {
                validate_owner_identifier("organization id", org_id, MAX_OWNER_ORG_ID_BYTES)?;
            }
            Self::DeleteNamedSecret { name } => {
                if name.len() > MAX_OWNER_SECRET_NAME_BYTES {
                    return Err("named secret name exceeds maximum length".to_string());
                }
            }
            Self::PutProviderCredential {
                client_operation_id,
                provider_id,
                record,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                if provider_id.len() > MAX_OWNER_PROVIDER_ID_BYTES {
                    return Err("provider id exceeds maximum length".to_string());
                }
                if provider_id.starts_with(RESERVED_OWNER_PROVIDER_ID_PREFIX)
                    || provider_id == RESERVED_FLYCOCKPIT_PROVIDER_ID
                {
                    return Err("provider id namespace is reserved".to_string());
                }
                if record.len() > MAX_OWNER_PROVIDER_RECORD_BYTES {
                    return Err("provider credential record exceeds maximum length".to_string());
                }
            }
            Self::GetLocalOperationSettlement {
                client_operation_id,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
            }
            Self::BeginProviderOAuth {
                client_operation_id,
                provider_id,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                validate_owner_identifier("provider id", provider_id, MAX_OWNER_PROVIDER_ID_BYTES)?;
                if !matches!(provider_id.as_str(), "grok-oauth" | "codex-oauth") {
                    return Err("provider OAuth is only available for Grok or Codex".to_string());
                }
            }
            Self::CompleteProviderOAuth {
                client_operation_id,
                flow_id,
                input,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                if flow_id.is_empty()
                    || flow_id.len() > MAX_OWNER_PROVIDER_ID_BYTES
                    || flow_id.contains('\0')
                {
                    return Err("OAuth flow id is invalid".to_string());
                }
                if input
                    .as_ref()
                    .is_some_and(|value| value.len() > MAX_OWNER_SECRET_VALUE_BYTES)
                {
                    return Err("OAuth callback input exceeds maximum length".to_string());
                }
            }
            Self::CancelProviderOAuth {
                client_operation_id,
                begin_client_operation_id,
                flow_id,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                validate_owner_identifier(
                    "begin client operation",
                    begin_client_operation_id,
                    128,
                )?;
                validate_optional_oauth_flow_id(flow_id.as_deref(), "provider")?;
            }
            Self::BeginMcpOAuth {
                client_operation_id,
                project_root,
                server,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                validate_owner_project_root(project_root)?;
                validate_owner_identifier("MCP server", server, MAX_OWNER_PROVIDER_ID_BYTES)?;
            }
            Self::CompleteMcpOAuth {
                client_operation_id,
                flow_id,
                input,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                if flow_id.is_empty()
                    || flow_id.len() > MAX_OWNER_PROVIDER_ID_BYTES
                    || flow_id.contains('\0')
                {
                    return Err("MCP OAuth flow id is invalid".to_string());
                }
                if input
                    .as_ref()
                    .is_some_and(|value| value.len() > MAX_OWNER_SECRET_VALUE_BYTES)
                {
                    return Err("MCP OAuth callback input exceeds maximum length".to_string());
                }
            }
            Self::CancelMcpOAuth {
                client_operation_id,
                begin_client_operation_id,
                flow_id,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                validate_owner_identifier(
                    "begin client operation",
                    begin_client_operation_id,
                    128,
                )?;
                validate_optional_oauth_flow_id(flow_id.as_deref(), "MCP")?;
            }
            Self::DeleteProviderCredential {
                client_operation_id,
                provider_id,
                project_root,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                validate_owner_identifier("provider id", provider_id, MAX_OWNER_PROVIDER_ID_BYTES)?;
                if provider_id.starts_with(RESERVED_OWNER_PROVIDER_ID_PREFIX)
                    || provider_id == RESERVED_FLYCOCKPIT_PROVIDER_ID
                {
                    return Err("provider id namespace is reserved".to_string());
                }
                if let Some(project_root) = project_root {
                    validate_owner_project_root(project_root)?;
                }
            }
            #[cfg(feature = "remote")]
            Self::UpsertProviderConfig {
                project_root,
                provider_id,
                entry,
            } => {
                validate_owner_project_root(project_root)?;
                validate_owner_identifier("provider id", provider_id, MAX_OWNER_PROVIDER_ID_BYTES)?;
                let entry_size = serde_json::to_vec(entry)
                    .map_err(|_| "provider entry must be serializable".to_string())?
                    .len();
                if entry_size > MAX_OWNER_PROVIDER_ENTRY_BYTES {
                    return Err("provider entry exceeds maximum length".to_string());
                }
                validate_credential_free_provider_url(&entry.url)?;
                cockpit_config::config::providers::validate_provider_headers(
                    provider_id,
                    &entry.headers,
                )
                .map_err(|error| error.to_string())?;
                for header in &entry.headers {
                    let value = header.value.trim();
                    if value.is_empty() {
                        continue;
                    }
                    // Owner RPCs never accept arbitrary literal header values:
                    // callers must materialize private values through the vault
                    // RPCs first.  Existing on-disk config remains readable;
                    // this is an ingress-only custody boundary.
                    if !cockpit_config::config::providers::is_safe_provider_header_reference(
                        &header.name.to_ascii_lowercase(),
                        value,
                    ) {
                        return Err(format!(
                            "header `{}` must use a $secret: or environment reference, not a literal value",
                            header.name
                        ));
                    }
                    if value.contains("$secret:") {
                        for reference in value.split("$secret:").skip(1) {
                            let name = reference
                                .chars()
                                .take_while(|ch| {
                                    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_')
                                })
                                .collect::<String>();
                            if name.is_empty() {
                                return Err(format!(
                                    "header `{}` has an invalid $secret reference",
                                    header.name
                                ));
                            }
                        }
                    }
                }
            }
            #[cfg(feature = "remote")]
            Self::SaveProviderConfig {
                project_root,
                provider_id,
                entry,
                header_secrets,
            } => {
                validate_owner_project_root(project_root)?;
                validate_owner_identifier("provider id", provider_id, MAX_OWNER_PROVIDER_ID_BYTES)?;
                if header_secrets.len() != entry.headers.len() {
                    return Err("provider header secret count does not match headers".to_string());
                }
                let entry_size = serde_json::to_vec(entry)
                    .map_err(|_| "provider entry must be serializable".to_string())?
                    .len();
                if entry_size > MAX_OWNER_PROVIDER_ENTRY_BYTES {
                    return Err("provider entry exceeds maximum length".to_string());
                }
                validate_credential_free_provider_url(&entry.url)?;
                for value in header_secrets.iter().flatten() {
                    if value.is_empty() || value.len() > MAX_OWNER_SECRET_VALUE_BYTES {
                        return Err("provider header secret exceeds maximum length".to_string());
                    }
                }
                cockpit_config::config::providers::validate_provider_headers(
                    provider_id,
                    &entry.headers,
                )
                .map_err(|error| error.to_string())?;
            }
            Self::SetupCopilotAuth {
                client_operation_id,
                project_root,
                provider_id,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                validate_owner_project_root(project_root)?;
                validate_owner_identifier("provider id", provider_id, MAX_OWNER_PROVIDER_ID_BYTES)?;
            }
            #[cfg(feature = "remote")]
            Self::ApplySetupWizard {
                project_root,
                wizard_id,
                answers_json,
            } => {
                validate_owner_project_root(project_root)?;
                if !matches!(wizard_id.as_str(), "security" | "model") {
                    return Err("setup wizard must be security or model".to_string());
                }
                if answers_json.len() > MAX_OWNER_PROVIDER_METADATA_JSON_BYTES {
                    return Err("setup wizard answers exceed maximum length".to_string());
                }
            }
            Self::FetchProviderModels {
                project_root,
                provider_id,
                model_id,
                ..
            } => {
                validate_owner_project_root(project_root)?;
                if let Some(provider_id) = provider_id {
                    validate_owner_identifier(
                        "provider id",
                        provider_id,
                        MAX_OWNER_PROVIDER_ID_BYTES,
                    )?;
                }
                if let Some(model_id) = model_id {
                    validate_owner_identifier(
                        "model id",
                        model_id,
                        MAX_OWNER_PROVIDER_MODEL_ID_BYTES,
                    )?;
                }
            }
            Self::SaveMcpConfig {
                client_operation_id,
                project_root,
                snapshot_capability,
                owner_root,
                config_path,
                expected_revision,
                mutation_intent_hash,
                patch,
                secret_values_json,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                validate_owner_project_root(project_root)?;
                validate_owner_identifier("MCP snapshot capability", snapshot_capability, 128)?;
                validate_owner_project_root(owner_root)?;
                validate_owner_project_root(config_path)?;
                validate_owner_identifier("MCP expected revision", expected_revision, 64)?;
                validate_owner_identifier("MCP mutation intent", mutation_intent_hash, 64)?;
                for (label, value) in [
                    ("MCP patch", patch.as_str()),
                    ("MCP secret values", secret_values_json.as_str()),
                ] {
                    if value.len() > MAX_OWNER_PROVIDER_METADATA_JSON_BYTES {
                        return Err(format!("{label} JSON exceeds maximum length"));
                    }
                }
            }
            Self::GetAgentInventory { project_root } => {
                validate_owner_project_root(project_root)?;
            }
            Self::SaveAssistantDefinition {
                client_operation_id,
                mutation_intent_hash,
                project_root,
                name,
                markdown,
                expected_revision,
                expected_config_generation: _,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                validate_owner_project_root(project_root)?;
                validate_owner_identifier("assistant name", name, crate::MAX_AGENT_NAME_BYTES)?;
                if markdown.len() > crate::MAX_AGENT_MARKDOWN_BYTES {
                    return Err("assistant markdown exceeds maximum length".into());
                }
                if expected_revision.is_empty() || expected_revision.len() > 128 {
                    return Err("assistant definition revision is invalid".into());
                }
                let expected = crate::assistant_mutation_intent_hash(
                    project_root,
                    "save",
                    name,
                    expected_revision,
                    Some(markdown),
                );
                if mutation_intent_hash != &expected {
                    return Err("assistant mutation intent hash does not match its request".into());
                }
            }
            Self::DeleteAssistant {
                client_operation_id,
                mutation_intent_hash,
                project_root,
                name,
                expected_revision,
                expected_config_generation: _,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                validate_owner_project_root(project_root)?;
                validate_owner_identifier("assistant name", name, crate::MAX_AGENT_NAME_BYTES)?;
                if expected_revision.is_empty() || expected_revision.len() > 128 {
                    return Err("assistant registration revision is invalid".into());
                }
                let expected = crate::assistant_mutation_intent_hash(
                    project_root,
                    "delete",
                    name,
                    expected_revision,
                    None,
                );
                if mutation_intent_hash != &expected {
                    return Err("assistant mutation intent hash does not match its request".into());
                }
            }
            Self::GetAgentEditSnapshot { project_root, name } => {
                validate_owner_project_root(project_root)?;
                validate_owner_identifier("agent name", name, crate::MAX_AGENT_NAME_BYTES)?;
            }
            Self::MutateAgent {
                client_operation_id,
                mutation_intent_hash,
                project_root,
                mutation,
                expected_revision,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                validate_owner_project_root(project_root)?;
                if mutation_intent_hash.len() != 64
                    || !mutation_intent_hash
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                {
                    return Err("agent mutation intent hash must be lowercase SHA-256".to_string());
                }
                let expected_hash = crate::agent_mutation_intent_hash(
                    project_root,
                    mutation,
                    expected_revision.as_deref(),
                );
                if mutation_intent_hash != &expected_hash {
                    return Err("agent mutation intent hash does not match its request".to_string());
                }
                let name = match mutation {
                    crate::AgentMutation::EjectBuiltin { name }
                    | crate::AgentMutation::SaveDefinition { name, .. }
                    | crate::AgentMutation::CreateDefinition { name, .. }
                    | crate::AgentMutation::DeleteCustom { name }
                    | crate::AgentMutation::ResetBuiltin { name }
                    | crate::AgentMutation::SaveGoalSupervision { name, .. } => Some(name),
                    crate::AgentMutation::ResetAllBuiltins => None,
                };
                if let Some(name) = name {
                    validate_owner_identifier("agent name", name, crate::MAX_AGENT_NAME_BYTES)?;
                }
                let markdown = match mutation {
                    crate::AgentMutation::SaveDefinition { markdown, .. }
                    | crate::AgentMutation::CreateDefinition { markdown, .. } => Some(markdown),
                    _ => None,
                };
                if markdown.is_some_and(|markdown| markdown.len() > crate::MAX_AGENT_MARKDOWN_BYTES)
                {
                    return Err("agent markdown exceeds maximum length".to_string());
                }
                if expected_revision
                    .as_ref()
                    .is_some_and(|value| value.len() > 128)
                {
                    return Err("agent revision exceeds maximum length".to_string());
                }
                match mutation {
                    crate::AgentMutation::CreateDefinition { .. }
                        if expected_revision.is_some() =>
                    {
                        return Err("agent creation must not carry a consumed revision".into());
                    }
                    crate::AgentMutation::CreateDefinition { .. } => {}
                    _ if expected_revision.is_none() => {
                        return Err("agent mutation requires a consumed revision".into());
                    }
                    _ => {}
                }
            }
            Self::BeginAgentEditorLease {
                client_operation_id,
                project_root,
                name,
                expected_revision,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                validate_owner_project_root(project_root)?;
                validate_owner_identifier("agent name", name, crate::MAX_AGENT_NAME_BYTES)?;
                if expected_revision.is_empty() || expected_revision.len() > 128 {
                    return Err("agent revision is invalid".to_string());
                }
            }
            Self::CompleteAgentEditorLease {
                client_operation_id,
                project_root,
                lease_id,
                markdown,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                validate_owner_project_root(project_root)?;
                validate_owner_identifier("agent editor lease", lease_id, 128)?;
                if markdown
                    .as_ref()
                    .is_some_and(|value| value.len() > crate::MAX_AGENT_MARKDOWN_BYTES)
                {
                    return Err("agent markdown exceeds maximum length".to_string());
                }
            }
            Self::GetAgentEditorLeaseSettlement {
                client_operation_id,
                project_root,
                lease_id,
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                validate_owner_project_root(project_root)?;
                validate_owner_identifier("agent editor lease", lease_id, 128)?;
            }
            Self::GetExtendedConfigSnapshot {
                project_root,
                snapshot_session_id,
            } => {
                validate_owner_project_root(project_root)?;
                validate_owner_identifier("settings snapshot session", snapshot_session_id, 128)?;
            }
            Self::GetImageSidecarAuthoritySnapshot {
                project_root,
                config_generation,
                selection_id,
            } => {
                validate_owner_project_root(project_root)?;
                if *config_generation == 0 {
                    return Err("image-sidecar config generation is invalid".into());
                }
                validate_owner_identifier("image-sidecar selection", selection_id, 128)?;
            }
            Self::CreateImageSidecarGrant {
                project_root,
                config_generation,
                selection_id,
                grant_candidate_id,
                purpose,
                scope,
                session_id,
                invocation_id,
            } => {
                validate_owner_project_root(project_root)?;
                if *config_generation == 0
                    || grant_candidate_id.is_empty()
                    || grant_candidate_id.len() > 128
                {
                    return Err("image-sidecar grant target is invalid".into());
                }
                validate_owner_identifier("image-sidecar selection", selection_id, 128)?;
                if !matches!(purpose.as_str(), "dossier" | "ask_image") {
                    return Err("image-sidecar grant purpose is invalid".into());
                }
                for binding in [session_id.as_deref(), invocation_id.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    validate_owner_identifier("image-sidecar grant binding", binding, 128)?;
                }
                match scope {
                    crate::image_sidecar_authority::ImageSidecarGrantScopeV1::Once
                        if session_id.is_some() && invocation_id.is_some() => {}
                    crate::image_sidecar_authority::ImageSidecarGrantScopeV1::Session
                        if session_id.is_some() && invocation_id.is_none() => {}
                    crate::image_sidecar_authority::ImageSidecarGrantScopeV1::Project
                        if session_id.is_none() && invocation_id.is_none() => {}
                    _ => return Err("image-sidecar grant scope bindings are invalid".into()),
                }
            }
            Self::RevokeImageSidecarGrant {
                project_root,
                config_generation,
                selection_id,
                grant_id,
                expected_version,
            } => {
                validate_owner_project_root(project_root)?;
                if *config_generation == 0 || *expected_version == 0 {
                    return Err("image-sidecar revoke version is invalid".into());
                }
                validate_owner_identifier("image-sidecar selection", selection_id, 128)?;
                validate_owner_identifier("image-sidecar grant", grant_id, 128)?;
            }
            Self::ApplyExtendedConfigPatch {
                client_operation_id,
                project_root,
                layer_id,
                patch,
                expected_revision,
                snapshot_session_id,
            } => {
                validate_owner_identifier("settings client operation", client_operation_id, 128)?;
                validate_owner_project_root(project_root)?;
                validate_owner_identifier("settings layer capability", layer_id, 128)?;
                validate_owner_identifier("settings snapshot session", snapshot_session_id, 128)?;
                let encoded = serde_json::to_vec(patch)
                    .map_err(|error| format!("extended config patch is invalid: {error}"))?;
                if encoded.len() > MAX_OWNER_PROVIDER_METADATA_JSON_BYTES {
                    return Err("extended config patch exceeds maximum length".to_string());
                }
                if patch.operations.len() > 128
                    || (patch.operations.is_empty()
                        && patch.denylist.is_empty()
                        && patch.redacted_mutations.is_empty()
                        && !patch.materialize)
                {
                    return Err("extended config patch operation count is invalid".to_string());
                }
                let mut paths = std::collections::HashSet::new();
                for operation in &patch.operations {
                    let path = operation.path();
                    if path.is_empty()
                        || path.len() > 16
                        || path.iter().any(|part| {
                            part.is_empty()
                                || part.len() > 128
                                || part.contains('\0')
                                || part.contains("__cockpit_redacted_setting_v1_")
                        })
                        || !paths.insert(path)
                    {
                        return Err("extended config patch path is invalid or repeated".to_string());
                    }
                }
                if expected_revision.is_empty() || expected_revision.len() > 128 {
                    return Err("extended config revision is invalid".to_string());
                }
            }
            Self::SaveExtendedConfig {
                project_root,
                path,
                content,
                base_hash,
            } => {
                validate_owner_project_root(project_root)?;
                if path.is_empty()
                    || path.len() > MAX_OWNER_PROVIDER_METADATA_JSON_BYTES
                    || path.starts_with('/')
                    || path.contains("..")
                    || path.contains('\0')
                {
                    return Err("extended config path must name a config.json layer".to_string());
                }
                if content.len() > MAX_OWNER_PROVIDER_METADATA_JSON_BYTES {
                    return Err("extended config content exceeds maximum length".to_string());
                }
                if base_hash.as_ref().is_some_and(|hash| hash.len() > 128) {
                    return Err("extended config base hash exceeds maximum length".to_string());
                }
            }
            Self::ExportPolicy { project_root } => validate_owner_project_root(project_root)?,
            Self::ImportPolicy {
                project_root,
                bundle_json,
                ..
            } => {
                validate_owner_project_root(project_root)?;
                if bundle_json.len() > MAX_OWNER_PROVIDER_METADATA_JSON_BYTES {
                    return Err("policy bundle exceeds maximum length".to_string());
                }
            }
            #[cfg(feature = "extended")]
            Self::GetImageSpendPolicy { project_key } => {
                validate_owner_identifier("project key", project_key, MAX_OWNER_PROVIDER_ID_BYTES)?;
            }
            #[cfg(feature = "extended")]
            Self::SaveImageSpendPolicy {
                client_operation_id,
                project_key,
                settings_json,
                ..
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                validate_owner_identifier("project key", project_key, MAX_OWNER_PROVIDER_ID_BYTES)?;
                if settings_json.len() > MAX_OWNER_PROVIDER_METADATA_JSON_BYTES {
                    return Err("image spend settings exceed maximum length".to_string());
                }
            }
            Self::ImageEndpointCreate {
                client_operation_id,
                mutation_intent_hash,
                project_root,
                expected_config_generation: _,
                expected_config_revision,
                mutation_capability,
                ..
            }
            | Self::ImageEndpointUpdate {
                client_operation_id,
                mutation_intent_hash,
                project_root,
                expected_config_generation: _,
                expected_config_revision,
                mutation_capability,
                ..
            }
            | Self::ImageEndpointDelete {
                client_operation_id,
                mutation_intent_hash,
                project_root,
                expected_config_generation: _,
                expected_config_revision,
                mutation_capability,
                ..
            }
            | Self::ImageTargetCreate {
                client_operation_id,
                mutation_intent_hash,
                project_root,
                expected_config_generation: _,
                expected_config_revision,
                mutation_capability,
                ..
            }
            | Self::ImageTargetUpdate {
                client_operation_id,
                mutation_intent_hash,
                project_root,
                expected_config_generation: _,
                expected_config_revision,
                mutation_capability,
                ..
            }
            | Self::ImageTargetDelete {
                client_operation_id,
                mutation_intent_hash,
                project_root,
                expected_config_generation: _,
                expected_config_revision,
                mutation_capability,
                ..
            }
            | Self::ImageTargetSetDefault {
                client_operation_id,
                mutation_intent_hash,
                project_root,
                expected_config_generation: _,
                expected_config_revision,
                mutation_capability,
                ..
            }
            | Self::ImageWorkflowUpload {
                client_operation_id,
                mutation_intent_hash,
                project_root,
                expected_config_generation: _,
                expected_config_revision,
                mutation_capability,
                ..
            }
            | Self::ImageWorkflowBind {
                client_operation_id,
                mutation_intent_hash,
                project_root,
                expected_config_generation: _,
                expected_config_revision,
                mutation_capability,
                ..
            }
            | Self::ImageWorkflowDelete {
                client_operation_id,
                mutation_intent_hash,
                project_root,
                expected_config_generation: _,
                expected_config_revision,
                mutation_capability,
                ..
            } => {
                validate_owner_identifier("client operation", client_operation_id, 128)?;
                validate_owner_project_root(project_root)?;
                for (label, value) in [
                    ("image mutation public intent hash", mutation_intent_hash),
                    ("image configuration revision", expected_config_revision),
                    ("image mutation capability", &mutation_capability.0),
                ] {
                    if value.len() != 64
                        || !value
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                    {
                        return Err(format!("{label} must be 64 lowercase hex characters"));
                    }
                }
            }
            Self::GetProviderCatalogSnapshot {
                project_root,
                provider_id,
                snapshot_session_id,
            } => {
                validate_owner_project_root(project_root)?;
                validate_owner_identifier("provider snapshot session", snapshot_session_id, 128)?;
                if let Some(provider_id) = provider_id {
                    validate_owner_identifier(
                        "provider id",
                        provider_id,
                        MAX_OWNER_PROVIDER_ID_BYTES,
                    )?;
                }
            }
            Self::GetProviderUsageSnapshot {
                project_root,
                provider_id,
            } => {
                validate_owner_project_root(project_root)?;
                if let Some(provider_id) = provider_id {
                    validate_owner_identifier(
                        "provider id",
                        provider_id,
                        MAX_OWNER_PROVIDER_ID_BYTES,
                    )?;
                }
            }
            Self::ApplyProviderMutation {
                snapshot_session_id,
                layer_id,
                expected_revision,
                client_operation_id,
                mutation_intent_hash: _,
                mutation,
            } => {
                for (label, value) in [
                    ("provider snapshot session", snapshot_session_id),
                    ("provider layer capability", layer_id),
                    ("provider base revision", expected_revision),
                    ("provider client operation", client_operation_id),
                ] {
                    validate_owner_identifier(label, value, 128)?;
                }
                if mutation
                    .upserts
                    .len()
                    .saturating_add(mutation.deletes.len())
                    > 64
                {
                    return Err("provider mutation exceeds maximum batch size".into());
                }
                if mutation.metadata.as_ref().is_some_and(|metadata| {
                    serde_json::to_vec(metadata)
                        .map(|bytes| bytes.len() > MAX_OWNER_PROVIDER_METADATA_JSON_BYTES)
                        .unwrap_or(true)
                }) {
                    return Err("provider metadata exceeds maximum encoded length".into());
                }
                if mutation.upserts.is_empty()
                    && mutation.deletes.is_empty()
                    && mutation.metadata.is_none()
                {
                    return Err("provider mutation contains no changes".into());
                }
                let mut ids = std::collections::BTreeSet::new();
                for upsert in &mutation.upserts {
                    validate_owner_identifier(
                        "provider id",
                        &upsert.provider_id,
                        MAX_OWNER_PROVIDER_ID_BYTES,
                    )?;
                    if !ids.insert(upsert.provider_id.as_str()) {
                        return Err("provider mutation contains duplicate ids".into());
                    }
                    if upsert.header_secrets.len() != upsert.entry.headers.len() {
                        return Err("provider header secret count does not match headers".into());
                    }
                    if serde_json::to_vec(&upsert.entry)
                        .map_err(|_| "provider entry must be serializable".to_string())?
                        .len()
                        > MAX_OWNER_PROVIDER_ENTRY_BYTES
                    {
                        return Err("provider entry exceeds maximum length".into());
                    }
                    validate_credential_free_provider_url(&upsert.entry.url)?;
                    cockpit_config::config::providers::validate_provider_headers(
                        &upsert.provider_id,
                        &upsert.entry.headers,
                    )
                    .map_err(|error| error.to_string())?;
                    for secret in upsert.header_secrets.iter().flatten() {
                        if secret.is_empty() || secret.len() > MAX_OWNER_SECRET_VALUE_BYTES {
                            return Err("provider header secret exceeds maximum length".into());
                        }
                    }
                }
                for delete in &mutation.deletes {
                    validate_owner_identifier(
                        "provider id",
                        &delete.provider_id,
                        MAX_OWNER_PROVIDER_ID_BYTES,
                    )?;
                    if !ids.insert(delete.provider_id.as_str()) {
                        return Err("provider mutation contains duplicate ids".into());
                    }
                }
            }
            #[cfg(feature = "remote")]
            Self::SetProviderLayerMetadata {
                project_root,
                category_defaults_json,
                ..
            } => {
                validate_owner_project_root(project_root)?;
                if category_defaults_json.len() > MAX_OWNER_PROVIDER_METADATA_JSON_BYTES {
                    return Err("provider metadata exceeds maximum length".to_string());
                }
            }
            #[cfg(feature = "remote")]
            Self::DeleteProviderConfig {
                project_root,
                provider_id,
                ..
            } => {
                validate_owner_project_root(project_root)?;
                validate_owner_identifier("provider id", provider_id, MAX_OWNER_PROVIDER_ID_BYTES)?;
            }
            Self::GetRunInvocationStatus {
                client_submission_id,
            }
            | Self::CancelRunInvocation {
                client_submission_id,
            } if client_submission_id.is_nil() => {
                return Err("client_submission_id must not be nil".to_string());
            }
            #[cfg(feature = "remote")]
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

fn validate_agent_interrupt_response(response: &AgentInterruptResponse) -> Result<(), String> {
    match response {
        AgentInterruptResponse::Single { selected_id } => {
            if selected_id.is_empty() {
                return Err("agent interrupt selected id must not be empty".to_string());
            }
        }
        AgentInterruptResponse::Multi { selected_ids } => {
            if selected_ids.is_empty() || selected_ids.iter().any(String::is_empty) {
                return Err("agent interrupt selected ids must not be empty".to_string());
            }
        }
        AgentInterruptResponse::Freetext { text } => {
            if text.is_empty() {
                return Err("agent interrupt free text must not be empty".to_string());
            }
        }
        AgentInterruptResponse::Batch { responses } => {
            if responses.is_empty() {
                return Err("agent interrupt batch must not be empty".to_string());
            }
            for response in responses {
                validate_agent_interrupt_response(response)?;
            }
        }
        AgentInterruptResponse::Cancel => {}
    }
    Ok(())
}
#[macro_export]
macro_rules! request_variants {
    ($with_variants:ident $(, $context:ident)*) => {
        $with_variants! { ($($context),*) [
            (Request::Attach { .. }, "attach");
            (Request::SubagentTranscript { .. }, "subagent_transcript");
            (Request::SendUserMessage { .. }, "send_user_message");
            (Request::SendUserMessageBulk { .. }, "send_user_message_bulk");
            (Request::GetRunInvocationStatus { .. }, "get_run_invocation_status");
            #[cfg(feature = "remote")]
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
            (Request::BeginSealedOwnerOperation { .. }, "begin_sealed_owner_operation");
            (Request::ApplySealedOwnerOperation { .. }, "apply_sealed_owner_operation");
            (Request::CancelSealedOwnerOperation { .. }, "cancel_sealed_owner_operation");
            (Request::SealedOwnerInventory { .. }, "sealed_owner_inventory");
            (Request::EditSealedOwnerDescription { .. }, "edit_sealed_owner_description");
            (Request::ListSealedActions, "list_sealed_actions");
            (Request::CreateSealedAction { .. }, "create_sealed_action");
            (Request::ReviseSealedActionDescription { .. }, "revise_sealed_action_description");
            (Request::ReviseSealedActionEnabled { .. }, "revise_sealed_action_enabled");
            (Request::RetireSealedAction { .. }, "retire_sealed_action");
            (Request::ListLeakReports { .. }, "list_leak_reports");
            (Request::BeginLeakReveal { .. }, "begin_leak_reveal");
            (Request::CancelLeakReveal { .. }, "cancel_leak_reveal");
            (Request::MarkLeakRotated { .. }, "mark_leak_rotated");
            (Request::DeleteLeakReport { .. }, "delete_leak_report");
            (Request::ListProjectNotes { .. }, "list_project_notes");
            (Request::CreateProjectNote { .. }, "create_project_note");
            (Request::SetProjectNoteContent { .. }, "set_project_note_content");
            (Request::RenameProjectNote { .. }, "rename_project_note");
            (Request::DeleteProjectNote { .. }, "delete_project_note");
            (Request::SetWorkspaceTrust { .. }, "set_workspace_trust");
            (Request::GetWorkspaceTrust { .. }, "get_workspace_trust");
            (Request::GetStartupDisclosures { .. }, "get_startup_disclosures");
            (Request::GetAppFlag { .. }, "get_app_flag");
            (Request::MarkAppFlagSeen { .. }, "mark_app_flag_seen");
            (Request::ResolveAssistantSession { .. }, "resolve_assistant_session");
            (Request::ListAssistants, "list_assistants");
            (Request::UpsertAssistant { .. }, "upsert_assistant");
            (Request::SaveAssistantDefinition { .. }, "save_assistant_definition");
            (Request::CreateAssistantSession { .. }, "create_assistant_session");
            (Request::AutoTitle { .. }, "auto_title");
            (Request::ExportSessionData { .. }, "export_session_data");
            (Request::ImportSessionArchive { .. }, "import_session_archive");
            (Request::WriteBulkTransferChunk { .. }, "write_bulk_transfer_chunk");
            (Request::ReadBulkTransferChunk { .. }, "read_bulk_transfer_chunk");
            (Request::ReadRedactedExportChunk { .. }, "read_redacted_export_chunk");
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
            (Request::GitDiff { .. }, "git_diff");
            (Request::GitReviewSources { .. }, "git_review_sources");
            (Request::GitRepoStatus { .. }, "git_repo_status");
            (Request::FindWorktreeRoot { .. }, "find_worktree_root");
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
            (Request::ReadAgentTree { .. }, "read_agent_tree");
            (Request::ReadAgentAttention { .. }, "read_agent_attention");
            (Request::ResolveAgentDecision { .. }, "resolve_agent_decision");
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
            (Request::GetSessionSetupSnapshot { .. }, "get_session_setup_snapshot");
            (Request::GetAgentEffectiveSettings { .. }, "get_agent_effective_settings");
            (Request::ApplyAgentSessionOverride { .. }, "apply_agent_session_override");
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
            #[cfg(feature = "remote")]
            (Request::StoreFlycockpitCredential { .. }, "store_flycockpit_credential");
            #[cfg(feature = "remote")]
            (Request::ClearFlycockpitCredential, "clear_flycockpit_credential");
            #[cfg(feature = "remote")]
            (Request::SetFlycockpitConnectorEnabled { .. }, "set_flycockpit_connector_enabled");
            #[cfg(feature = "remote")]
            (Request::SyncFlycockpitOrgPolicy, "sync_flycockpit_org_policy");
            #[cfg(feature = "remote")]
            (Request::EnrollFlycockpitOrgSync { .. }, "enroll_flycockpit_org_sync");
            (Request::ListSecretInventory { .. }, "list_secret_inventory");
            (Request::PutNamedSecret { .. }, "put_named_secret");
            (Request::PutSubscriptionAck { .. }, "put_subscription_ack");
            (Request::DeleteNamedSecret { .. }, "delete_named_secret");
            (Request::PutProviderCredential { .. }, "put_provider_credential");
            (Request::GetLocalOperationSettlement { .. }, "get_local_operation_settlement");
            (Request::BeginProviderOAuth { .. }, "begin_provider_oauth");
            (Request::CompleteProviderOAuth { .. }, "complete_provider_oauth");
            (Request::CancelProviderOAuth { .. }, "cancel_provider_oauth");
            (Request::BeginMcpOAuth { .. }, "begin_mcp_oauth");
            (Request::CompleteMcpOAuth { .. }, "complete_mcp_oauth");
            (Request::CancelMcpOAuth { .. }, "cancel_mcp_oauth");
            (Request::DeleteProviderCredential { .. }, "delete_provider_credential");
            #[cfg(feature = "remote")]
            (Request::GetFlycockpitAccount, "get_flycockpit_account");
            (Request::GetProviderCatalogSnapshot { .. }, "get_provider_catalog_snapshot");
            (Request::ApplyProviderMutation { .. }, "apply_provider_mutation");
            (Request::FetchProviderModels { .. }, "fetch_provider_models");
            (Request::GetProviderUsageSnapshot { .. }, "get_provider_usage_snapshot");
            #[cfg(feature = "remote")]
            (Request::UpsertProviderConfig { .. }, "upsert_provider_config");
            #[cfg(feature = "remote")]
            (Request::SaveProviderConfig { .. }, "save_provider_config");
            (Request::SetupCopilotAuth { .. }, "setup_copilot_auth");
            #[cfg(feature = "remote")]
            (Request::ApplySetupWizard { .. }, "apply_setup_wizard");
            (Request::SaveMcpConfig { .. }, "save_mcp_config");
            (Request::GetAgentInventory { .. }, "get_agent_inventory");
            (Request::GetAgentEditSnapshot { .. }, "get_agent_edit_snapshot");
            (Request::MutateAgent { .. }, "mutate_agent");
            (Request::BeginAgentEditorLease { .. }, "begin_agent_editor_lease");
            (Request::CompleteAgentEditorLease { .. }, "complete_agent_editor_lease");
            (Request::GetAgentEditorLeaseSettlement { .. }, "get_agent_editor_lease_settlement");
            (Request::GetExtendedConfigSnapshot { .. }, "get_extended_config_snapshot");
            (Request::GetImageSidecarAuthoritySnapshot { .. }, "get_image_sidecar_authority_snapshot");
            (Request::CreateImageSidecarGrant { .. }, "create_image_sidecar_grant");
            (Request::RevokeImageSidecarGrant { .. }, "revoke_image_sidecar_grant");
            (Request::ApplyExtendedConfigPatch { .. }, "apply_extended_config_patch");
            (Request::SaveExtendedConfig { .. }, "save_extended_config");
            (Request::ExportPolicy { .. }, "export_policy");
            (Request::ImportPolicy { .. }, "import_policy");
            #[cfg(feature = "extended")]
            (Request::GetImageSpendPolicy { .. }, "get_image_spend_policy");
            #[cfg(feature = "extended")]
            (Request::SaveImageSpendPolicy { .. }, "save_image_spend_policy");
            (Request::ImageEndpointList { .. }, "image_endpoint_list");
            (Request::ImageEndpointGet { .. }, "image_endpoint_get");
            (Request::ImageTargetList { .. }, "image_target_list");
            (Request::ImageTargetGet { .. }, "image_target_get");
            (Request::ImageWorkflowList { .. }, "image_workflow_list");
            (Request::ImageWorkflowGet { .. }, "image_workflow_get");
            (Request::ImageEndpointCreate { .. }, "image_endpoint_create");
            (Request::ImageEndpointUpdate { .. }, "image_endpoint_update");
            (Request::ImageEndpointDelete { .. }, "image_endpoint_delete");
            (Request::ImageTargetCreate { .. }, "image_target_create");
            (Request::ImageTargetUpdate { .. }, "image_target_update");
            (Request::ImageTargetDelete { .. }, "image_target_delete");
            (Request::ImageTargetSetDefault { .. }, "image_target_set_default");
            (Request::ImageWorkflowUpload { .. }, "image_workflow_upload");
            (Request::ImageWorkflowBind { .. }, "image_workflow_bind");
            (Request::ImageWorkflowDelete { .. }, "image_workflow_delete");
            #[cfg(feature = "remote")]
            (Request::DeleteProviderConfig { .. }, "delete_provider_config");
            #[cfg(feature = "remote")]
            (Request::SetProviderLayerMetadata { .. }, "set_provider_layer_metadata");
            (Request::DaemonStatus, "daemon_status");
            (Request::RefreshEnv { .. }, "refresh_env");
            (Request::RefreshConfig, "refresh_config");
            (Request::RecordUsage { .. }, "record_usage");
            (Request::GetUsageCounts { .. }, "get_usage_counts");
            (Request::StatsRollup { .. }, "stats_rollup");
            (Request::GuidanceEstimate { .. }, "guidance_estimate");
            (Request::RecoverSecurityBlockedMedia(..), "recover_security_blocked_media");
            (Request::RegisterLocalPathMedia(..), "register_local_path_media");
            (Request::AdmitImageIngress { .. }, "admit_image_ingress");
            (Request::DiscardImageIngressDraft { .. }, "discard_image_ingress_draft");
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
            (Request::ListPackages, "list_packages");
            (Request::AddPackage { .. }, "add_package");
            (Request::ImportPackage { .. }, "import_package");
            (Request::PrunePackages { .. }, "prune_packages");
            (Request::ImportKclPackages { .. }, "import_kcl_packages");
            #[cfg(feature = "remote")]
            (Request::GetConnectorState, "get_connector_state");
            #[cfg(feature = "remote")]
            (Request::GetOrgSyncStatus, "get_org_sync_status");
            (Request::ListFailedToolCalls { .. }, "list_failed_tool_calls");
            (Request::GetSessionCompactions { .. }, "get_session_compactions");
            (Request::PurgeEndedSessions { .. }, "purge_ended_sessions");
            (Request::GetAssistant { .. }, "get_assistant");
            (Request::DeleteAssistant { .. }, "delete_assistant");
            (Request::DiagnoseMediaReservation { .. }, "diagnose_media_reservation");
            (Request::RepairMediaReservation { .. }, "repair_media_reservation");
            (Request::GetDoctorSnapshot { .. }, "get_doctor_snapshot");
            (Request::DocsAsk { .. }, "docs_ask");
            (Request::AgentInstallationBegin(_), "agent_installation_begin");
            (Request::AgentInstallationSubmitChoice(_), "agent_installation_submit_choice");
            (Request::AgentInstallationList(_), "agent_installation_list");
            (Request::AgentInstallationInspect(_), "agent_installation_inspect");
            (Request::Unknown, "__unknown");
        ] }
    };
}

impl Request {
    pub fn wire_tag(&self) -> &'static str {
        macro_rules! wire_tag {
            (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:expr);)+]) => {
                match self {
                    $($(#[$row_attr])* $pattern => $tag,)+
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
            (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:literal, $($rest:tt)*);)+]) => {
                #[allow(unused_variables)]
                match self {
                    $($(#[$row_attr])* $pattern => $tag,)+
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
            (Request::Attach { session_id, since_seq, project_root, initial_model, no_sandbox, interactive, session_entry_mode, model_override, client_protocol_version, env_snapshot, env_policy }, "attach", custom(authorize_attach), option_field(session_id), true, idempotent_adapter_mutation, domain_transaction(domain_result_tuple), serialized, none, "session_id:Option<Uuid>|since_seq:Option<i64>|project_root:Option<String>|initial_model:Option<cockpit_config::config::providers::ActiveModelRef>|no_sandbox:bool|interactive:bool|session_entry_mode:Option<SessionEntryMode>|model_override:Option<cockpit_config::config::providers::ActiveModelRef>|client_protocol_version:u32|env_snapshot:Option<EnvSnapshotWire>|env_policy:EnvDriftPolicy", [session_id: Option<Uuid> => session, since_seq: Option<i64> => param, project_root: Option<String> => project_root_effective, initial_model: Option<cockpit_config::config::providers::ActiveModelRef> => param, no_sandbox: bool => param, interactive: bool => param, session_entry_mode: Option<SessionEntryMode> => param, model_override: Option<cockpit_config::config::providers::ActiveModelRef> => param, client_protocol_version: u32 => param, env_snapshot: Option<EnvSnapshotWire> => param, env_policy: EnvDriftPolicy => param]);
            (Request::SubagentTranscript { session_id, task_call_id, label }, "subagent_transcript", custom(authorize_subagent_transcript), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid|task_call_id:String|label:String", [session_id: Uuid => session, task_call_id: String => param, label: String => param]);
            (Request::SendUserMessage { client_submission_id, origin, expected_model_state_generation, expected_model, text, display_text, tag_expansions, image_refs, forced_skill, run_invocation_options }, "send_user_message", session_writer, attached, true, transactional_mutation, sql_transaction, serialized, none, "client_submission_id:Uuid|origin:UserMessageOrigin|expected_model_state_generation:Option<u64>|expected_model:Option<cockpit_config::config::providers::ActiveModelRef>|text:String|display_text:Option<String>|tag_expansions:Vec<TagExpansionMeta>|image_refs:Vec<ImageAttachmentRef>|forced_skill:Option<String>|run_invocation_options:Option<RunInvocationOptions>", [client_submission_id: Uuid => legacy_message, origin: UserMessageOrigin => param, expected_model_state_generation: Option<u64> => param, expected_model: Option<cockpit_config::config::providers::ActiveModelRef> => param, text: String => param, display_text: Option<String> => param, tag_expansions: Vec<TagExpansionMeta> => param, image_refs: Vec<ImageAttachmentRef> => param, forced_skill: Option<String> => param, run_invocation_options: Option<RunInvocationOptions> => param]);
            (Request::SendUserMessageBulk { client_submission_id, origin, expected_model_state_generation, expected_model, transfer, display_text, display_transfer, tag_expansions, forced_skill, run_invocation_options }, "send_user_message_bulk", session_writer, attached, true, transactional_mutation, sql_transaction, serialized, none, "client_submission_id:Uuid|origin:UserMessageOrigin|expected_model_state_generation:Option<u64>|expected_model:Option<cockpit_config::config::providers::ActiveModelRef>|transfer:crate::bulk_transfer::BulkTransferRef|display_text:Option<String>|display_transfer:Option<crate::bulk_transfer::BulkTransferRef>|tag_expansions:Vec<TagExpansionMeta>|forced_skill:Option<String>|run_invocation_options:Option<RunInvocationOptions>", [client_submission_id: Uuid => legacy_message, origin: UserMessageOrigin => param, expected_model_state_generation: Option<u64> => param, expected_model: Option<cockpit_config::config::providers::ActiveModelRef> => param, transfer: $crate::bulk_transfer::BulkTransferRef => param, display_text: Option<String> => param, display_transfer: Option<$crate::bulk_transfer::BulkTransferRef> => param, tag_expansions: Vec<TagExpansionMeta> => param, forced_skill: Option<String> => param, run_invocation_options: Option<RunInvocationOptions> => param]);
            (Request::GetRunInvocationStatus { client_submission_id }, "get_run_invocation_status", public_read, none, false, read_only, none, concurrent, none, "client_submission_id:Uuid", [client_submission_id: Uuid => param]);
            #[cfg(feature = "remote")]
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
            (Request::BeginSealedOwnerOperation { disposition, record_id, name, description, scope_kind, scope_key }, "begin_sealed_owner_operation", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "disposition:String|record_id:Option<String>|name:Option<String>|description:Option<String>|scope_kind:Option<String>|scope_key:Option<String>", [disposition: String => param, record_id: Option<String> => param, name: Option<String> => param, description: Option<String> => param, scope_kind: Option<String> => param, scope_key: Option<String> => param]);
            (Request::ApplySealedOwnerOperation { capability_id, literal }, "apply_sealed_owner_operation", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "capability_id:String|literal:Option<SensitiveWireLiteral>", [capability_id: String => param, literal: Option<SensitiveWireLiteral> => param]);
            (Request::CancelSealedOwnerOperation { capability_id }, "cancel_sealed_owner_operation", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "capability_id:String", [capability_id: String => param]);
            (Request::SealedOwnerInventory { scope_kind, scope_key }, "sealed_owner_inventory", owner_only, none, false, read_only, none, concurrent, none, "scope_kind:Option<String>|scope_key:Option<String>", [scope_kind: Option<String> => param, scope_key: Option<String> => param]);
            (Request::EditSealedOwnerDescription { record_id, description }, "edit_sealed_owner_description", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "record_id:String|description:String", [record_id: String => param, description: String => param]);
            (Request::ListSealedActions, "list_sealed_actions", owner_only, none, false, read_only, none, concurrent, none, "-", []);
            (Request::CreateSealedAction { kind_id, project_id, description, origin_id, projection_id }, "create_sealed_action", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "kind_id:String|project_id:String|description:String|origin_id:String|projection_id:String", [kind_id: String => param, project_id: String => param, description: String => param, origin_id: String => param, projection_id: String => param]);
            (Request::ReviseSealedActionDescription { action_id, description }, "revise_sealed_action_description", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "action_id:String|description:String", [action_id: String => param, description: String => param]);
            (Request::ReviseSealedActionEnabled { action_id, enabled }, "revise_sealed_action_enabled", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "action_id:String|enabled:bool", [action_id: String => param, enabled: bool => param]);
            (Request::RetireSealedAction { action_id, confirm }, "retire_sealed_action", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "action_id:String|confirm:String", [action_id: String => param, confirm: String => param]);
            (Request::ListLeakReports { cursor, limit, project_root, session_id, rotation }, "list_leak_reports", owner_only, none, false, local_only, none, concurrent, none, "cursor:Option<String>|limit:Option<u32>|project_root:Option<String>|session_id:Option<Uuid>|rotation:Option<LeakRotationState>", [cursor: Option<String> => param, limit: Option<u32> => param, project_root: Option<String> => project_root_effective, session_id: Option<Uuid> => param, rotation: Option<LeakRotationState> => param]);
            (Request::BeginLeakReveal { report_id }, "begin_leak_reveal", owner_only, none, false, local_only, none, serialized, none, "report_id:String", [report_id: String => param]);
            (Request::CancelLeakReveal { capability }, "cancel_leak_reveal", owner_only, none, true, local_only, none, serialized, none, "capability:LeakRevealToken", [capability: LeakRevealToken => param]);
            (Request::MarkLeakRotated { report_id, rotation }, "mark_leak_rotated", owner_only, none, true, local_only, none, serialized, none, "report_id:String|rotation:LeakRotationDisposition", [report_id: String => param, rotation: LeakRotationDisposition => param]);
            (Request::DeleteLeakReport { report_id }, "delete_leak_report", owner_only, none, true, local_only, none, serialized, none, "report_id:String", [report_id: String => param]);
            (Request::ListProjectNotes { project_root }, "list_project_notes", owner_only, none, true, local_only, none, serialized, path(project_root), "project_root:String", [project_root: String => project_root]);
            (Request::CreateProjectNote { project_root, name }, "create_project_note", owner_only, none, true, local_only, none, serialized, path(project_root), "project_root:String|name:String", [project_root: String => project_root, name: String => param]);
            (Request::SetProjectNoteContent { project_root, id, content }, "set_project_note_content", owner_only, none, true, local_only, none, serialized, path(project_root), "project_root:String|id:Uuid|content:String", [project_root: String => project_root, id: Uuid => param, content: String => param]);
            (Request::RenameProjectNote { project_root, id, name }, "rename_project_note", owner_only, none, true, local_only, none, serialized, path(project_root), "project_root:String|id:Uuid|name:String", [project_root: String => project_root, id: Uuid => param, name: String => param]);
            (Request::DeleteProjectNote { project_root, id }, "delete_project_note", owner_only, none, true, local_only, none, serialized, path(project_root), "project_root:String|id:Uuid", [project_root: String => project_root, id: Uuid => param]);
            (Request::SetWorkspaceTrust { project_root, mode, expected_config_generation }, "set_workspace_trust", owner_only, none, true, transactional_mutation, sql_transaction, serialized, path(project_root), "project_root:String|mode:WorkspaceTrustMode|expected_config_generation:u64", [project_root: String => project_root, mode: WorkspaceTrustMode => param, expected_config_generation: u64 => param]);
            (Request::GetWorkspaceTrust { project_root }, "get_workspace_trust", owner_only, none, false, read_only, none, serialized, path(project_root), "project_root:String", [project_root: String => project_root]);
            (Request::GetStartupDisclosures { project_root }, "get_startup_disclosures", owner_only, none, false, read_only, none, serialized, path(project_root), "project_root:String", [project_root: String => project_root]);
            (Request::GetAppFlag { key }, "get_app_flag", owner_only, none, false, local_only, none, serialized, none, "key:AppFlagKey", [key: AppFlagKey => param]);
            (Request::MarkAppFlagSeen { key, expected_version }, "mark_app_flag_seen", owner_only, none, true, local_only, none, serialized, none, "key:AppFlagKey|expected_version:u64", [key: AppFlagKey => param, expected_version: u64 => param]);
            (Request::ResolveAssistantSession { assistant_id, project_root, mode }, "resolve_assistant_session", owner_only, none, true, transactional_mutation, sql_transaction, serialized, path(project_root), "assistant_id:String|project_root:String|mode:AssistantSessionResolutionMode", [assistant_id: String => param, project_root: String => project_root, mode: AssistantSessionResolutionMode => param]);
            (Request::ListAssistants, "list_assistants", owner_only, none, false, read_only, none, concurrent, none, "-", []);
            (Request::UpsertAssistant { name, description, prompt }, "upsert_assistant", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "name:String|description:String|prompt:String", [name: String => param, description: String => param, prompt: String => param]);
            (Request::SaveAssistantDefinition { client_operation_id, mutation_intent_hash, project_root, name, markdown, expected_revision, expected_config_generation }, "save_assistant_definition", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|mutation_intent_hash:String|project_root:String|name:String|markdown:String|expected_revision:String|expected_config_generation:u64", [client_operation_id: String => param, mutation_intent_hash: String => param, project_root: String => project_root, name: String => param, markdown: String => param, expected_revision: String => param, expected_config_generation: u64 => param]);
            (Request::CreateAssistantSession { name, project_root, initial_model, no_sandbox, env_snapshot }, "create_assistant_session", owner_only, none, true, transactional_mutation, sql_transaction, serialized, none, "name:String|project_root:String|initial_model:Option<cockpit_config::config::providers::ActiveModelRef>|no_sandbox:bool|env_snapshot:Option<EnvSnapshotWire>", [name: String => param, project_root: String => project_root, initial_model: Option<cockpit_config::config::providers::ActiveModelRef> => param, no_sandbox: bool => param, env_snapshot: Option<EnvSnapshotWire> => param]);
            (Request::AutoTitle { session_id }, "auto_title", session_row_writer(session_id), field(session_id), true, idempotent_adapter_mutation, durable_dispatch_key(dispatch_key_and_generation), serialized, none, "session_id:Uuid", [session_id: Uuid => session]);
            (Request::ExportSessionData { session_id, kind, include_generated_artifacts, include_sensitive }, "export_session_data", owner_only, field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid|kind:ExportSessionKind|include_generated_artifacts:bool|include_sensitive:bool", [session_id: Uuid => session, kind: ExportSessionKind => param, include_generated_artifacts: bool => param, include_sensitive: bool => param]);
            (Request::ImportSessionArchive { transfer }, "import_session_archive", owner_only, none, true, transactional_mutation, sql_transaction, serialized, none, "transfer:crate::bulk_transfer::BulkTransferRef", [transfer: $crate::bulk_transfer::BulkTransferRef => param]);
            // Remote oversized text ingress stages source bytes over the bulk
            // lane before its reference-only FCM2 request. It is scoped to the
            // attached session writer (while local owners retain their normal
            // bypass), and exact chunk replay is acknowledged by bulk staging.
            (Request::WriteBulkTransferChunk { transfer, chunk_index, data_base64 }, "write_bulk_transfer_chunk", session_writer, attached, true, idempotent_adapter_mutation, domain_transaction(domain_result_tuple), serialized, none, "transfer:crate::bulk_transfer::BulkTransferRef|chunk_index:u32|data_base64:String", [transfer: $crate::bulk_transfer::BulkTransferRef => param, chunk_index: u32 => param, data_base64: String => param]);
            (Request::ReadBulkTransferChunk { transfer_id, chunk_index }, "read_bulk_transfer_chunk", owner_only, none, false, local_only, none, concurrent, none, "transfer_id:crate::bulk_transfer::BulkTransferId|chunk_index:u32", [transfer_id: $crate::bulk_transfer::BulkTransferId => param, chunk_index: u32 => param]);
            (Request::ReadRedactedExportChunk { transfer_id, chunk_index }, "read_redacted_export_chunk", owner_only, none, false, read_only, none, concurrent, none, "transfer_id:crate::bulk_transfer::BulkTransferId|chunk_index:u32", [transfer_id: $crate::bulk_transfer::BulkTransferId => param, chunk_index: u32 => param]);
            (Request::Curator { project_root, action }, "curator", owner_only, none, true, transactional_mutation, sql_transaction, serialized, path(project_root), "project_root:String|action:CuratorAction", [project_root: String => project_root, action: CuratorAction => param]);
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
            (Request::GitDiff { project_root, source }, "git_diff", owner_only, none, false, local_only, none, concurrent, none, "project_root:String|source:crate::GitReadSource", [project_root: String => project_root, source: $crate::GitReadSource => param]);
            (Request::GitReviewSources { project_root, sources }, "git_review_sources", owner_only, none, false, local_only, none, concurrent, none, "project_root:String|sources:Vec<crate::GitReadSource>", [project_root: String => project_root, sources: Vec<$crate::GitReadSource> => param]);
            (Request::GitRepoStatus { project_root }, "git_repo_status", owner_only, none, false, local_only, none, concurrent, none, "project_root:String", [project_root: String => project_root]);
            (Request::FindWorktreeRoot { path }, "find_worktree_root", owner_only, none, false, local_only, none, concurrent, none, "path:String", [path: String => param]);
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
            (Request::ListSessions { project_id, parent_session_id, assistant_id }, "list_sessions", public_read, none, false, read_only, none, concurrent, none, "project_id:Option<String>|parent_session_id:Option<Uuid>|assistant_id:Option<String>", [project_id: Option<String> => project, parent_session_id: Option<Uuid> => param, assistant_id: Option<String> => param]);
            (Request::ReadSessionMessages { session_id, before_seq, limit }, "read_session_messages", custom(authorize_read_session_messages), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid|before_seq:Option<i64>|limit:u32", [session_id: Uuid => session, before_seq: Option<i64> => param, limit: u32 => param]);
            (Request::ReadClientSubmissionReceipt { session_id, client_submission_id }, "read_client_submission_receipt", custom(authorize_read_session_messages), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid|client_submission_id:Uuid", [session_id: Uuid => session, client_submission_id: Uuid => param]);
            (Request::ReadHistoryPage { session_id, before_seq, limit }, "read_history_page", custom(authorize_read_history_page), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid|before_seq:Option<i64>|limit:u32", [session_id: Uuid => session, before_seq: Option<i64> => param, limit: u32 => param]);
            (Request::ReadSubagentHistoryPage { session_id, task_call_id, label, before_seq, limit }, "read_subagent_history_page", custom(authorize_read_subagent_history_page), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid|task_call_id:String|label:String|before_seq:Option<i64>|limit:u32", [session_id: Uuid => session, task_call_id: String => param, label: String => param, before_seq: Option<i64> => param, limit: u32 => param]);
            (Request::ReadAgentTree { session_id, root_agent_instance_id, after, limit }, "read_agent_tree", session_row_reader(session_id), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid|root_agent_instance_id:Option<Uuid>|after:Option<AgentTreeCursor>|limit:u16", [session_id: Uuid => session, root_agent_instance_id: Option<Uuid> => param, after: Option<AgentTreeCursor> => param, limit: u16 => param]);
            (Request::ReadAgentAttention { session_id, after, limit }, "read_agent_attention", session_row_reader(session_id), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid|after:Option<AgentTreeCursor>|limit:u16", [session_id: Uuid => session, after: Option<AgentTreeCursor> => param, limit: u16 => param]);
            (Request::ResolveAgentDecision { session_id, decision_request_id, answer }, "resolve_agent_decision", session_row_writer(session_id), field(session_id), true, transactional_mutation, sql_transaction, serialized, none, "session_id:Uuid|decision_request_id:Uuid|answer:AgentDecisionAnswer", [session_id: Uuid => session, decision_request_id: Uuid => param, answer: AgentDecisionAnswer => param]);
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
            (Request::GetSessionSetupSnapshot { session_id }, "get_session_setup_snapshot", session_row_reader(session_id), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid", [session_id: Uuid => session]);
            (Request::GetAgentEffectiveSettings { session_id, agent_instance_id }, "get_agent_effective_settings", session_row_reader(session_id), field(session_id), false, read_only, none, concurrent, none, "session_id:Uuid|agent_instance_id:Uuid", [session_id: Uuid => session, agent_instance_id: Uuid => param]);
            (Request::ApplyAgentSessionOverride { session_id, agent_instance_id, expected_override_revision, field }, "apply_agent_session_override", session_row_writer(session_id), field(session_id), true, transactional_mutation, sql_transaction, serialized, none, "session_id:Uuid|agent_instance_id:Uuid|expected_override_revision:u64|field:AgentSessionOverrideFieldV1", [session_id: Uuid => session, agent_instance_id: Uuid => param, expected_override_revision: u64 => param, field: AgentSessionOverrideFieldV1 => param]);
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
            #[cfg(feature = "remote")]
            (Request::StoreFlycockpitCredential { credential, force }, "store_flycockpit_credential", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "credential:StoredFlycockpitCredential|force:bool", [credential: StoredFlycockpitCredential => param, force: bool => param]);
            #[cfg(feature = "remote")]
            (Request::ClearFlycockpitCredential, "clear_flycockpit_credential", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "-", []);
            #[cfg(feature = "remote")]
            (Request::SetFlycockpitConnectorEnabled { enabled }, "set_flycockpit_connector_enabled", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "enabled:bool", [enabled: bool => param]);
            #[cfg(feature = "remote")]
            (Request::SyncFlycockpitOrgPolicy, "sync_flycockpit_org_policy", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "-", []);
            #[cfg(feature = "remote")]
            (Request::EnrollFlycockpitOrgSync { org_id }, "enroll_flycockpit_org_sync", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "org_id:String", [org_id: String => param]);
            (Request::ListSecretInventory { cursor, limit }, "list_secret_inventory", owner_only, none, false, read_only, none, serialized, none, "cursor:Option<String>|limit:Option<u16>", [cursor: Option<String> => param, limit: Option<u16> => param]);
            (Request::PutNamedSecret { name, value }, "put_named_secret", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "name:String|value:String", [name: String => param, value: String => param]);
            (Request::PutSubscriptionAck { client_operation_id, provider_id }, "put_subscription_ack", owner_only, none, true, local_only, none, serialized, none, "client_operation_id:String|provider_id:String", [client_operation_id: String => param, provider_id: String => param]);
            (Request::DeleteNamedSecret { name }, "delete_named_secret", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "name:String", [name: String => param]);
            (Request::PutProviderCredential { client_operation_id, provider_id, record }, "put_provider_credential", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "client_operation_id:String|provider_id:String|record:SensitiveWirePayload", [client_operation_id: String => param, provider_id: String => param, record: SensitiveWirePayload => param]);
            (Request::GetLocalOperationSettlement { client_operation_id }, "get_local_operation_settlement", owner_only, none, false, local_only, none, serialized, none, "client_operation_id:String", [client_operation_id: String => param]);
            // OAuth is deliberately local-only as one coherent flow. Begin,
            // completion, and cancellation all carry owner idempotency keys and
            // use the local settlement ledger; none can cross the remote lane.
            (Request::BeginProviderOAuth { client_operation_id, provider_id }, "begin_provider_oauth", owner_only, none, true, local_only, none, serialized, none, "client_operation_id:String|provider_id:String", [client_operation_id: String => param, provider_id: String => param]);
            (Request::CompleteProviderOAuth { client_operation_id, flow_id, input }, "complete_provider_oauth", owner_only, none, true, local_only, none, serialized, none, "client_operation_id:String|flow_id:String|input:Option<SensitiveWirePayload>", [client_operation_id: String => param, flow_id: String => param, input: Option<SensitiveWirePayload> => param]);
            (Request::CancelProviderOAuth { client_operation_id, begin_client_operation_id, flow_id }, "cancel_provider_oauth", owner_only, none, true, local_only, none, serialized, none, "client_operation_id:String|begin_client_operation_id:String|flow_id:Option<String>", [client_operation_id: String => param, begin_client_operation_id: String => param, flow_id: Option<String> => param]);
            (Request::BeginMcpOAuth { client_operation_id, project_root, server }, "begin_mcp_oauth", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|project_root:String|server:String", [client_operation_id: String => param, project_root: String => project_root, server: String => param]);
            (Request::CompleteMcpOAuth { client_operation_id, flow_id, input }, "complete_mcp_oauth", owner_only, none, true, local_only, none, serialized, none, "client_operation_id:String|flow_id:String|input:Option<SensitiveWirePayload>", [client_operation_id: String => param, flow_id: String => param, input: Option<SensitiveWirePayload> => param]);
            (Request::CancelMcpOAuth { client_operation_id, begin_client_operation_id, flow_id }, "cancel_mcp_oauth", owner_only, none, true, local_only, none, serialized, none, "client_operation_id:String|begin_client_operation_id:String|flow_id:Option<String>", [client_operation_id: String => param, begin_client_operation_id: String => param, flow_id: Option<String> => param]);
            (Request::DeleteProviderCredential { client_operation_id, provider_id, project_root }, "delete_provider_credential", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "client_operation_id:String|provider_id:String|project_root:Option<String>", [client_operation_id: String => param, provider_id: String => param, project_root: Option<String> => param]);
            #[cfg(feature = "remote")]
            (Request::GetFlycockpitAccount, "get_flycockpit_account", owner_only, none, false, read_only, none, serialized, none, "-", []);
            (Request::GetProviderCatalogSnapshot { project_root, provider_id, snapshot_session_id }, "get_provider_catalog_snapshot", owner_only, none, false, local_only, none, concurrent, path(project_root), "project_root:String|provider_id:Option<String>|snapshot_session_id:String", [project_root: String => project_root, provider_id: Option<String> => param, snapshot_session_id: String => param]);
            (Request::ApplyProviderMutation { snapshot_session_id, layer_id, expected_revision, client_operation_id, mutation_intent_hash, mutation }, "apply_provider_mutation", owner_only, none, true, local_only, none, serialized, none, "snapshot_session_id:String|layer_id:String|expected_revision:String|client_operation_id:String|mutation_intent_hash:String|mutation:crate::ProviderMutationBatch", [snapshot_session_id: String => param, layer_id: String => param, expected_revision: String => param, client_operation_id: String => param, mutation_intent_hash: String => param, mutation: cockpit_proto::ProviderMutationBatch => param]);
            (Request::FetchProviderModels { project_root, provider_id, model_id, deep, on_unlisted, allow_fallback }, "fetch_provider_models", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, path(project_root), "project_root:String|provider_id:Option<String>|model_id:Option<String>|deep:bool|on_unlisted:Option<cockpit_config::config::providers::OnUnlistedModelsFetch>|allow_fallback:bool", [project_root: String => project_root, provider_id: Option<String> => param, model_id: Option<String> => param, deep: bool => param, on_unlisted: Option<cockpit_config::config::providers::OnUnlistedModelsFetch> => param, allow_fallback: bool => param]);
            (Request::GetProviderUsageSnapshot { project_root, provider_id }, "get_provider_usage_snapshot", owner_only, none, false, read_only, none, serialized, path(project_root), "project_root:String|provider_id:Option<String>", [project_root: String => project_root, provider_id: Option<String> => param]);
            #[cfg(feature = "remote")]
            (Request::UpsertProviderConfig { project_root, provider_id, entry }, "upsert_provider_config", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, path(project_root), "project_root:String|provider_id:String|entry:cockpit_config::config::providers::ProviderEntry", [project_root: String => project_root, provider_id: String => param, entry: cockpit_config::config::providers::ProviderEntry => param]);
            #[cfg(feature = "remote")]
            (Request::SaveProviderConfig { project_root, provider_id, entry, header_secrets }, "save_provider_config", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, path(project_root), "project_root:String|provider_id:String|entry:cockpit_config::config::providers::ProviderEntry|header_secrets:Vec<Option<crate::ProviderSecretValue>>", [project_root: String => project_root, provider_id: String => param, entry: cockpit_config::config::providers::ProviderEntry => param, header_secrets: Vec<Option<cockpit_proto::ProviderSecretValue>> => param]);
            (Request::SetupCopilotAuth { client_operation_id, project_root, provider_id }, "setup_copilot_auth", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, path(project_root), "client_operation_id:String|project_root:String|provider_id:String", [client_operation_id: String => param, project_root: String => project_root, provider_id: String => param]);
            #[cfg(feature = "remote")]
            (Request::ApplySetupWizard { project_root, wizard_id, answers_json }, "apply_setup_wizard", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, path(project_root), "project_root:String|wizard_id:String|answers_json:String", [project_root: String => project_root, wizard_id: String => param, answers_json: String => param]);
            // Composite MCP publication is reserved in the remote ledger
            // before dispatch. The daemon's journal + staged vault commit
            // makes the nonrepeatable outcome replay-safe.
            (Request::SaveMcpConfig { client_operation_id, project_root, snapshot_capability, owner_root, config_path, expected_revision, mutation_intent_hash, patch, secret_values_json }, "save_mcp_config", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, path(project_root), "client_operation_id:String|project_root:String|snapshot_capability:String|owner_root:String|config_path:String|expected_revision:String|mutation_intent_hash:String|patch:SensitiveWirePayload|secret_values_json:SensitiveWirePayload", [client_operation_id: String => param, project_root: String => project_root, snapshot_capability: String => param, owner_root: String => param, config_path: String => param, expected_revision: String => param, mutation_intent_hash: String => param, patch: SensitiveWirePayload => param, secret_values_json: SensitiveWirePayload => param]);
            (Request::GetAgentInventory { project_root }, "get_agent_inventory", owner_only, none, false, local_only, none, concurrent, path(project_root), "project_root:String", [project_root: String => project_root]);
            (Request::GetAgentEditSnapshot { project_root, name }, "get_agent_edit_snapshot", owner_only, none, false, local_only, none, concurrent, path(project_root), "project_root:String|name:String", [project_root: String => project_root, name: String => param]);
            (Request::MutateAgent { client_operation_id, mutation_intent_hash, project_root, mutation, expected_revision }, "mutate_agent", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|mutation_intent_hash:String|project_root:String|mutation:crate::AgentMutation|expected_revision:Option<String>", [client_operation_id: String => param, mutation_intent_hash: String => param, project_root: String => project_root, mutation: cockpit_proto::AgentMutation => param, expected_revision: Option<String> => param]);
            (Request::BeginAgentEditorLease { client_operation_id, project_root, name, expected_revision }, "begin_agent_editor_lease", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|project_root:String|name:String|expected_revision:String", [client_operation_id: String => param, project_root: String => project_root, name: String => param, expected_revision: String => param]);
            (Request::CompleteAgentEditorLease { client_operation_id, project_root, lease_id, markdown }, "complete_agent_editor_lease", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|project_root:String|lease_id:String|markdown:Option<SensitiveWirePayload>", [client_operation_id: String => param, project_root: String => project_root, lease_id: String => param, markdown: Option<SensitiveWirePayload> => param]);
            (Request::GetAgentEditorLeaseSettlement { client_operation_id, project_root, lease_id }, "get_agent_editor_lease_settlement", owner_only, none, false, local_only, none, concurrent, path(project_root), "client_operation_id:String|project_root:String|lease_id:String", [client_operation_id: String => param, project_root: String => project_root, lease_id: String => param]);
            (Request::GetExtendedConfigSnapshot { project_root, snapshot_session_id }, "get_extended_config_snapshot", owner_only, none, false, local_only, none, concurrent, path(project_root), "project_root:String|snapshot_session_id:String", [project_root: String => project_root, snapshot_session_id: String => param]);
            (Request::GetImageSidecarAuthoritySnapshot { project_root, config_generation, selection_id }, "get_image_sidecar_authority_snapshot", owner_only, none, false, local_only, none, concurrent, path(project_root), "project_root:String|config_generation:u64|selection_id:String", [project_root: String => project_root, config_generation: u64 => param, selection_id: String => param]);
            (Request::CreateImageSidecarGrant { project_root, config_generation, selection_id, grant_candidate_id, purpose, scope, session_id, invocation_id }, "create_image_sidecar_grant", owner_only, none, true, local_only, none, serialized, path(project_root), "project_root:String|config_generation:u64|selection_id:String|grant_candidate_id:String|purpose:String|scope:crate::image_sidecar_authority::ImageSidecarGrantScopeV1|session_id:Option<String>|invocation_id:Option<String>", [project_root: String => project_root, config_generation: u64 => param, selection_id: String => param, grant_candidate_id: String => param, purpose: String => param, scope: cockpit_proto::image_sidecar_authority::ImageSidecarGrantScopeV1 => param, session_id: Option<String> => param, invocation_id: Option<String> => param]);
            (Request::RevokeImageSidecarGrant { project_root, config_generation, selection_id, grant_id, expected_version }, "revoke_image_sidecar_grant", owner_only, none, true, local_only, none, serialized, path(project_root), "project_root:String|config_generation:u64|selection_id:String|grant_id:String|expected_version:u64", [project_root: String => project_root, config_generation: u64 => param, selection_id: String => param, grant_id: String => param, expected_version: u64 => param]);
            (Request::ApplyExtendedConfigPatch { client_operation_id, project_root, layer_id, patch, expected_revision, snapshot_session_id }, "apply_extended_config_patch", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|project_root:String|layer_id:String|patch:crate::ExtendedConfigPatch|expected_revision:String|snapshot_session_id:String", [client_operation_id: String => param, project_root: String => project_root, layer_id: String => param, patch: cockpit_proto::ExtendedConfigPatch => param, expected_revision: String => param, snapshot_session_id: String => param]);
            (Request::SaveExtendedConfig { project_root, path, content, base_hash }, "save_extended_config", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, path(project_root), "project_root:String|path:String|content:String|base_hash:Option<String>", [project_root: String => project_root, path: String => param, content: String => param, base_hash: Option<String> => param]);
            (Request::ExportPolicy { project_root }, "export_policy", owner_only, none, false, local_only, none, concurrent, path(project_root), "project_root:String", [project_root: String => project_root]);
            (Request::ImportPolicy { project_root, bundle_json, replace }, "import_policy", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, path(project_root), "project_root:String|bundle_json:String|replace:bool", [project_root: String => project_root, bundle_json: String => param, replace: bool => param]);
            #[cfg(feature = "extended")]
            (Request::GetImageSpendPolicy { project_key }, "get_image_spend_policy", owner_only, none, false, local_only, none, concurrent, none, "project_key:String", [project_key: String => param]);
            (Request::ImageEndpointList { project_root, limit, cursor }, "image_endpoint_list", owner_only, none, false, local_only, none, concurrent, path(project_root), "project_root:String|limit:Option<u16>|cursor:Option<String>", [project_root: String => project_root, limit: Option<u16> => param, cursor: Option<String> => param]);
            (Request::ImageEndpointGet { project_root, endpoint_id }, "image_endpoint_get", owner_only, none, false, local_only, none, concurrent, path(project_root), "project_root:String|endpoint_id:String", [project_root: String => project_root, endpoint_id: String => param]);
            (Request::ImageTargetList { project_root, limit, cursor }, "image_target_list", owner_only, none, false, local_only, none, concurrent, path(project_root), "project_root:String|limit:Option<u16>|cursor:Option<String>", [project_root: String => project_root, limit: Option<u16> => param, cursor: Option<String> => param]);
            (Request::ImageTargetGet { project_root, target_id }, "image_target_get", owner_only, none, false, local_only, none, concurrent, path(project_root), "project_root:String|target_id:String", [project_root: String => project_root, target_id: String => param]);
            (Request::ImageWorkflowList { project_root, limit, cursor }, "image_workflow_list", owner_only, none, false, local_only, none, concurrent, path(project_root), "project_root:String|limit:Option<u16>|cursor:Option<String>", [project_root: String => project_root, limit: Option<u16> => param, cursor: Option<String> => param]);
            (Request::ImageWorkflowGet { project_root, workflow_id }, "image_workflow_get", owner_only, none, false, local_only, none, concurrent, path(project_root), "project_root:String|workflow_id:String", [project_root: String => project_root, workflow_id: String => param]);
            #[cfg(feature = "extended")]
            (Request::SaveImageSpendPolicy { client_operation_id, project_key, settings_json, expected_policy_version }, "save_image_spend_policy", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "client_operation_id:String|project_key:String|settings_json:String|expected_policy_version:Option<u64>", [client_operation_id: String => param, project_key: String => param, settings_json: String => param, expected_policy_version: Option<u64> => param]);
            (Request::ImageEndpointCreate { client_operation_id, mutation_intent_hash, project_root, endpoint_json, expected_config_generation, expected_config_revision, mutation_capability }, "image_endpoint_create", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|mutation_intent_hash:String|project_root:String|endpoint_json:SensitiveWirePayload|expected_config_generation:u64|expected_config_revision:String|mutation_capability:crate::image_control::ImageConfigMutationCapabilityV1", [client_operation_id: String => param, mutation_intent_hash: String => param, project_root: String => project_root, endpoint_json: SensitiveWirePayload => param, expected_config_generation: u64 => param, expected_config_revision: String => param, mutation_capability: cockpit_proto::image_control::ImageConfigMutationCapabilityV1 => param]);
            (Request::ImageEndpointUpdate { client_operation_id, mutation_intent_hash, project_root, endpoint_id, endpoint_json, expected_config_generation, expected_config_revision, mutation_capability }, "image_endpoint_update", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|mutation_intent_hash:String|project_root:String|endpoint_id:String|endpoint_json:SensitiveWirePayload|expected_config_generation:u64|expected_config_revision:String|mutation_capability:crate::image_control::ImageConfigMutationCapabilityV1", [client_operation_id: String => param, mutation_intent_hash: String => param, project_root: String => project_root, endpoint_id: String => param, endpoint_json: SensitiveWirePayload => param, expected_config_generation: u64 => param, expected_config_revision: String => param, mutation_capability: cockpit_proto::image_control::ImageConfigMutationCapabilityV1 => param]);
            (Request::ImageEndpointDelete { client_operation_id, mutation_intent_hash, project_root, endpoint_id, expected_config_generation, expected_config_revision, mutation_capability }, "image_endpoint_delete", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|mutation_intent_hash:String|project_root:String|endpoint_id:String|expected_config_generation:u64|expected_config_revision:String|mutation_capability:crate::image_control::ImageConfigMutationCapabilityV1", [client_operation_id: String => param, mutation_intent_hash: String => param, project_root: String => project_root, endpoint_id: String => param, expected_config_generation: u64 => param, expected_config_revision: String => param, mutation_capability: cockpit_proto::image_control::ImageConfigMutationCapabilityV1 => param]);
            (Request::ImageTargetCreate { client_operation_id, mutation_intent_hash, project_root, target_json, expected_config_generation, expected_config_revision, mutation_capability }, "image_target_create", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|mutation_intent_hash:String|project_root:String|target_json:SensitiveWirePayload|expected_config_generation:u64|expected_config_revision:String|mutation_capability:crate::image_control::ImageConfigMutationCapabilityV1", [client_operation_id: String => param, mutation_intent_hash: String => param, project_root: String => project_root, target_json: SensitiveWirePayload => param, expected_config_generation: u64 => param, expected_config_revision: String => param, mutation_capability: cockpit_proto::image_control::ImageConfigMutationCapabilityV1 => param]);
            (Request::ImageTargetUpdate { client_operation_id, mutation_intent_hash, project_root, target_id, target_json, expected_config_generation, expected_config_revision, mutation_capability }, "image_target_update", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|mutation_intent_hash:String|project_root:String|target_id:String|target_json:SensitiveWirePayload|expected_config_generation:u64|expected_config_revision:String|mutation_capability:crate::image_control::ImageConfigMutationCapabilityV1", [client_operation_id: String => param, mutation_intent_hash: String => param, project_root: String => project_root, target_id: String => param, target_json: SensitiveWirePayload => param, expected_config_generation: u64 => param, expected_config_revision: String => param, mutation_capability: cockpit_proto::image_control::ImageConfigMutationCapabilityV1 => param]);
            (Request::ImageTargetDelete { client_operation_id, mutation_intent_hash, project_root, target_id, expected_config_generation, expected_config_revision, mutation_capability }, "image_target_delete", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|mutation_intent_hash:String|project_root:String|target_id:String|expected_config_generation:u64|expected_config_revision:String|mutation_capability:crate::image_control::ImageConfigMutationCapabilityV1", [client_operation_id: String => param, mutation_intent_hash: String => param, project_root: String => project_root, target_id: String => param, expected_config_generation: u64 => param, expected_config_revision: String => param, mutation_capability: cockpit_proto::image_control::ImageConfigMutationCapabilityV1 => param]);
            (Request::ImageTargetSetDefault { client_operation_id, mutation_intent_hash, project_root, target_id, expected_config_generation, expected_config_revision, mutation_capability }, "image_target_set_default", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|mutation_intent_hash:String|project_root:String|target_id:String|expected_config_generation:u64|expected_config_revision:String|mutation_capability:crate::image_control::ImageConfigMutationCapabilityV1", [client_operation_id: String => param, mutation_intent_hash: String => param, project_root: String => project_root, target_id: String => param, expected_config_generation: u64 => param, expected_config_revision: String => param, mutation_capability: cockpit_proto::image_control::ImageConfigMutationCapabilityV1 => param]);
            (Request::ImageWorkflowUpload { client_operation_id, mutation_intent_hash, project_root, workflow_json, expected_config_generation, expected_config_revision, mutation_capability }, "image_workflow_upload", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|mutation_intent_hash:String|project_root:String|workflow_json:SensitiveWirePayload|expected_config_generation:u64|expected_config_revision:String|mutation_capability:crate::image_control::ImageConfigMutationCapabilityV1", [client_operation_id: String => param, mutation_intent_hash: String => param, project_root: String => project_root, workflow_json: SensitiveWirePayload => param, expected_config_generation: u64 => param, expected_config_revision: String => param, mutation_capability: cockpit_proto::image_control::ImageConfigMutationCapabilityV1 => param]);
            (Request::ImageWorkflowBind { client_operation_id, mutation_intent_hash, project_root, workflow_id, bindings_json, expected_config_generation, expected_config_revision, mutation_capability }, "image_workflow_bind", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|mutation_intent_hash:String|project_root:String|workflow_id:String|bindings_json:SensitiveWirePayload|expected_config_generation:u64|expected_config_revision:String|mutation_capability:crate::image_control::ImageConfigMutationCapabilityV1", [client_operation_id: String => param, mutation_intent_hash: String => param, project_root: String => project_root, workflow_id: String => param, bindings_json: SensitiveWirePayload => param, expected_config_generation: u64 => param, expected_config_revision: String => param, mutation_capability: cockpit_proto::image_control::ImageConfigMutationCapabilityV1 => param]);
            (Request::ImageWorkflowDelete { client_operation_id, mutation_intent_hash, project_root, workflow_id, expected_config_generation, expected_config_revision, mutation_capability }, "image_workflow_delete", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|mutation_intent_hash:String|project_root:String|workflow_id:String|expected_config_generation:u64|expected_config_revision:String|mutation_capability:crate::image_control::ImageConfigMutationCapabilityV1", [client_operation_id: String => param, mutation_intent_hash: String => param, project_root: String => project_root, workflow_id: String => param, expected_config_generation: u64 => param, expected_config_revision: String => param, mutation_capability: cockpit_proto::image_control::ImageConfigMutationCapabilityV1 => param]);
            #[cfg(feature = "remote")]
            (Request::DeleteProviderConfig { project_root, provider_id, delete_stored_secrets }, "delete_provider_config", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, path(project_root), "project_root:String|provider_id:String|delete_stored_secrets:bool", [project_root: String => project_root, provider_id: String => param, delete_stored_secrets: bool => param]);
            #[cfg(feature = "remote")]
            (Request::SetProviderLayerMetadata { project_root, category_defaults_json, on_unlisted_models_fetch }, "set_provider_layer_metadata", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, path(project_root), "project_root:String|category_defaults_json:String|on_unlisted_models_fetch:cockpit_config::config::providers::OnUnlistedModelsFetch", [project_root: String => project_root, category_defaults_json: String => param, on_unlisted_models_fetch: cockpit_config::config::providers::OnUnlistedModelsFetch => param]);
            (Request::DaemonStatus, "daemon_status", public_read, none, false, read_only, none, concurrent, none, "-", []);
            (Request::RefreshEnv { vars }, "refresh_env", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "vars:HashMap<String,String>", [vars: HashMap<String,String> => param]);
            (Request::RefreshConfig, "refresh_config", session_writer, attached, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "-", []);
            (Request::RecordUsage { kind, key, project_id }, "record_usage", owner_only, none, true, local_only, none, serialized, none, "kind:UsageKind|key:String|project_id:Option<String>", [kind: UsageKind => param, key: String => param, project_id: Option<String> => project]);
            (Request::GetUsageCounts { project_id }, "get_usage_counts", owner_only, none, false, local_only, none, concurrent, none, "project_id:Option<String>", [project_id: Option<String> => project]);
            (Request::StatsRollup { project_id, range, by_role }, "stats_rollup", owner_only, none, false, read_only, none, concurrent, none, "project_id:Option<String>|range:StatsRange|by_role:bool", [project_id: Option<String> => project, range: StatsRange => param, by_role: bool => param]);
            (Request::GuidanceEstimate { project_root, provider, model }, "guidance_estimate", project_read(project_root), none, false, read_only, none, concurrent, none, "project_root:String|provider:Option<String>|model:Option<String>", [project_root: String => project_root, provider: Option<String> => provider_model_left(model), model: Option<String> => provider_model_right(provider)]);
            (Request::RecoverSecurityBlockedMedia(..), "recover_security_blocked_media", owner_only, none, true, local_only, none, serialized, none, "-", []);
            (Request::RegisterLocalPathMedia(..), "register_local_path_media", owner_only, none, true, local_only, none, serialized, none, "-", []);
            (Request::AdmitImageIngress { session_id, source, admission_id }, "admit_image_ingress", session_writer, attached, true, local_only, none, serialized, none, "session_id:Uuid|source:ImageIngressSourceV1|admission_id:Uuid", [session_id: Uuid => session, source: ImageIngressSourceV1 => param, admission_id: Uuid => param]);
            // Disposal remains available after the frontend has switched its
            // attached session, but requires the same session-writer authority
            // that could create the exact admission in the first place.
            (Request::DiscardImageIngressDraft { session_id, admission_id, local_operation_id }, "discard_image_ingress_draft", session_row_writer(session_id), none, true, local_only, none, serialized, none, "session_id:Uuid|admission_id:Uuid|local_operation_id:Uuid", [session_id: Uuid => session, admission_id: Uuid => param, local_operation_id: Uuid => param]);
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
            // The durable HostEffect itself is serialized by the attached
            // session worker. Its client request must remain concurrent so a
            // single attached client can submit the matching ResolveInterrupt
            // while this original request is awaiting that decision.
            (Request::RefreshHostCapabilities, "refresh_host_capabilities", owner_only, none, true, local_only, none, concurrent, none, "-", []);
            (Request::MigrateKekPlacement { dest }, "migrate_kek_placement", owner_only, none, true, local_only, none, serialized, none, "dest:SecretStorePlacement", [dest: SecretStorePlacement => param]);
            (Request::ListPackages, "list_packages", owner_only, none, false, read_only, none, concurrent, none, "-", []);
            (Request::AddPackage { project_root, identifier, git, branch, local_path, deep }, "add_package", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "project_root:String|identifier:String|git:Option<String>|branch:Option<String>|local_path:Option<String>|deep:bool", [project_root: String => param, identifier: String => param, git: Option<String> => param, branch: Option<String> => param, local_path: Option<String> => param, deep: bool => param]);
            (Request::ImportPackage { project_root, dir, package, id, as_path }, "import_package", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "project_root:String|dir:Option<String>|package:Option<String>|id:Option<String>|as_path:bool", [project_root: String => param, dir: Option<String> => param, package: Option<String> => param, id: Option<String> => param, as_path: bool => param]);
            (Request::PrunePackages { project_root, days, dry_run }, "prune_packages", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "project_root:String|days:u32|dry_run:bool", [project_root: String => param, days: u32 => param, dry_run: bool => param]);
            (Request::ImportKclPackages { project_root }, "import_kcl_packages", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "project_root:String", [project_root: String => param]);
            #[cfg(feature = "remote")]
            (Request::GetConnectorState, "get_connector_state", owner_only, none, false, read_only, none, concurrent, none, "-", []);
            #[cfg(feature = "remote")]
            (Request::GetOrgSyncStatus, "get_org_sync_status", owner_only, none, false, read_only, none, concurrent, none, "-", []);
            (Request::ListFailedToolCalls { since_epoch, tool, model, project_id, include_recovered, limit }, "list_failed_tool_calls", owner_only, none, false, read_only, none, concurrent, none, "since_epoch:i64|tool:Option<String>|model:Option<String>|project_id:Option<String>|include_recovered:bool|limit:u32", [since_epoch: i64 => param, tool: Option<String> => param, model: Option<String> => param, project_id: Option<String> => param, include_recovered: bool => param, limit: u32 => param]);
            (Request::GetSessionCompactions { session_id }, "get_session_compactions", owner_only, none, false, read_only, none, concurrent, none, "session_id:Uuid", [session_id: Uuid => param]);
            (Request::PurgeEndedSessions { before }, "purge_ended_sessions", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "before:i64", [before: i64 => param]);
            (Request::GetAssistant { name }, "get_assistant", owner_only, none, false, read_only, none, concurrent, none, "name:String", [name: String => param]);
            (Request::DeleteAssistant { client_operation_id, mutation_intent_hash, project_root, name, expected_revision, expected_config_generation }, "delete_assistant", owner_only, none, true, local_only, none, serialized, path(project_root), "client_operation_id:String|mutation_intent_hash:String|project_root:String|name:String|expected_revision:String|expected_config_generation:u64", [client_operation_id: String => param, mutation_intent_hash: String => param, project_root: String => project_root, name: String => param, expected_revision: String => param, expected_config_generation: u64 => param]);
            (Request::DiagnoseMediaReservation { scope, id }, "diagnose_media_reservation", owner_only, none, false, read_only, none, concurrent, none, "scope:String|id:String", [scope: String => param, id: String => param]);
            (Request::RepairMediaReservation { scope, id, expected_block_generation, repair_plan_digest, idempotency_key }, "repair_media_reservation", owner_only, none, true, nonrepeatable_mutation, nonrepeatable_dispatch, serialized, none, "scope:String|id:String|expected_block_generation:u64|repair_plan_digest:String|idempotency_key:String", [scope: String => param, id: String => param, expected_block_generation: u64 => param, repair_plan_digest: String => param, idempotency_key: String => param]);
            (Request::GetDoctorSnapshot { project_root, no_sandbox, offline }, "get_doctor_snapshot", owner_only, none, false, read_only, none, concurrent, none, "project_root:Option<String>|no_sandbox:bool|offline:bool", [project_root: Option<String> => param, no_sandbox: bool => param, offline: bool => param]);
            (Request::DocsAsk { question, package, project_root }, "docs_ask", owner_only, none, false, read_only, none, serialized, none, "question:String|package:Option<String>|project_root:Option<String>", [question: String => param, package: Option<String> => param, project_root: Option<String> => param]);
            // Installation DTOs are opaque at this boundary and handled by the
            // local daemon only: the request can name a local workspace and
            // the resulting installation state is local SQLite state. Bind the
            // newtype explicitly so the FCOR source-schema guard cannot hide
            // it behind a `(..)` pattern.
            (Request::AgentInstallationBegin(_request), "agent_installation_begin", owner_only, none, true, local_only, none, serialized, none, "-", []);
            (Request::AgentInstallationSubmitChoice(_request), "agent_installation_submit_choice", owner_only, none, true, local_only, none, serialized, none, "-", []);
            (Request::AgentInstallationList(_request), "agent_installation_list", owner_only, none, false, local_only, none, concurrent, none, "-", []);
            (Request::AgentInstallationInspect(_request), "agent_installation_inspect", owner_only, none, false, local_only, none, concurrent, none, "-", []);
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
/// operation. Most `owner_only` tags are one of those two. The explicit
/// owner-remoted allowlist in `remote_operation_classification_is_exhaustive`
/// instead carries a remote class for future authenticated-owner transports.
/// A class defines retry semantics, not authority: authorization remains the
/// barrier and current remote principals are denied owner-only work.
#[cfg(feature = "remote")]
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
#[cfg(feature = "remote")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteAdapterRecoveryStrategy {
    DomainTransaction,
    DurableDispatchKey,
    DurableDesiredState,
    StagedFilesystemCommit,
}

#[cfg(feature = "remote")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteAdapterEvidenceV1 {
    DomainResultTuple,
    DispatchKeyAndGeneration,
    DesiredStateGenerationAndObservedDigest,
    StagedArtifactFingerprintsAndFsyncBarriers,
}

#[cfg(feature = "remote")]
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

#[cfg(feature = "remote")]
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

#[cfg(feature = "remote")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownRemoteOperationClass;

#[cfg(feature = "remote")]
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

#[cfg(feature = "remote")]
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

#[cfg(feature = "remote")]
macro_rules! command_remote_class_tag {
    (($tag_value:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $tag_value { $($(#[$row_attr])* $tag => remote_class_value!($remote_class),)+ _ => None }
    }};
}
#[cfg(feature = "remote")]
macro_rules! command_remote_recovery_tag {
    (($tag_value:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $tag_value { $($(#[$row_attr])* $tag => recovery_contract_value!($recovery $(($recovery_evidence))?),)+ _ => None }
    }};
}
#[cfg(feature = "remote")]
macro_rules! command_remote_fcor_schema_tag {
    (($tag_value:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $tag_value { $($(#[$row_attr])* $tag => Some($fcor_schema),)+ _ => None }
    }};
}

#[cfg(feature = "remote")]
macro_rules! command_typed_fcor_fields {
    (($request:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($(#[$row_attr])* $pattern => {
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

#[cfg(feature = "remote")]
macro_rules! encode_fcor_bound_fields {
    ($out:ident; $($name:ident: $ty:ty => $role:ident $(($($arg:ident),*))?),* $(,)?) => {{
        $(encode_fcor_role!($out, $name, $role);)*
    }};
}

#[cfg(feature = "remote")]
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

#[cfg(feature = "remote")]
macro_rules! command_encode_fcor_params {
    (($request:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        use $crate::remote_operation_fcor::CanonicalFcorValueV1 as _;
        match $request {
            $($(#[$row_attr])* $pattern => {
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

#[cfg(feature = "remote")]
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
        if matches!(
            self,
            Self::SendUserMessage { .. } | Self::SendUserMessageBulk { .. }
        ) {
            anyhow::bail!("legacy_send_user_message_not_remote_operation");
        }
        crate::command!(command_encode_fcor_params, self)
    }
}
#[cfg(feature = "remote")]
pub fn remote_operation_class_for_tag(tag: &str) -> Option<RemoteOperationClass> {
    crate::command!(command_remote_class_tag, tag)
}
#[cfg(feature = "remote")]
pub fn remote_operation_fcor_schema_for_tag(tag: &str) -> Option<&'static str> {
    crate::command!(command_remote_fcor_schema_tag, tag)
}

#[cfg(feature = "remote")]
fn canonical_fcor_codec_for_rust_type(ty: &str) -> Option<&'static str> {
    Some(match ty {
        "u16" => "u16",
        "u32" => "u32",
        "u64" => "u64",
        "i64" => "i64",
        "bool" => "bool",
        "String" => "string",
        // Secret-bearing JSON payloads contribute only a SHA-256 digest, never
        // plaintext, to FCOR's ordinary canonical byte buffer.
        "SensitiveWirePayload" => "sha256-redacted",
        "ImageIngressSourceV1" => "sha256-redacted",
        "Option<SensitiveWirePayload>" => "option<sha256-redacted>",
        "crate::image_control::ImageConfigMutationCapabilityV1" => "sha256-redacted",
        "Uuid" => "uuid",
        "Vec<u8>" => "bytes",
        "Option<String>" => "option<string>",
        // The sealed-owner apply literal is a redacting/zeroizing newtype. Its
        // plaintext is deliberately EXCLUDED from FCOR canonicalization (a fixed
        // placeholder is encoded instead — see
        // `SensitiveWireLiteral::encode_fcor_value_v1`), so the plaintext never
        // reaches the non-zeroizing canonical buffer. The `redacted` codec makes
        // that redaction explicit in the cross-language schema.
        "Option<SensitiveWireLiteral>" => "option<redacted>",
        "LeakRevealToken" => "redacted",
        "Option<Uuid>" => "option<uuid>",
        "Option<bool>" => "option<bool>",
        "Option<i64>" => "option<i64>",
        "Option<u32>" => "option<u32>",
        "Option<u16>" => "option<u16>",
        "Option<u64>" => "option<u64>",
        "Vec<Uuid>" => "list<uuid>",
        "Vec<Option<String>>" => "list<option<string>>",
        "Vec<(String,String)>" => "list<tuple<string,string>>",
        "HashMap<String,String>" => "map<string,string>",
        "Vec<ImageAttachmentRef>" => "list<struct:ImageAttachmentRef:v1>",
        "Vec<TagExpansionMeta>" => "list<struct:TagExpansionMeta:v1>",
        "UserMessageOrigin" => "enum16",
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
        "Option<cockpit_config::config::providers::OnUnlistedModelsFetch>" => {
            "option<enum16:OnUnlistedModelsFetch>"
        }
        // Bare (non-`Option`) fully-path-qualified external enum maps to its short
        // canonical `enum16:<Name>` form (crate paths never leak into the
        // cross-language canonical identifier), matching the short-spelling
        // `OnUnlistedModelsFetch` arm below.
        "cockpit_config::config::providers::OnUnlistedModelsFetch" => {
            "enum16:OnUnlistedModelsFetch"
        }
        "cockpit_config::config::providers::ProviderEntry" | "ProviderEntry" => {
            "struct:ProviderEntry:v1"
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
        | "OnUnlistedModelsFetch"
        | "LspControlAction"
        | "SecretStorePlacement"
        | "UsageKind"
        | "WorkspaceTrustMode"
        | "StatsRange" => "enum16",
        "ResolveResponse" | "ScheduledJobCreate" | "StoredFlycockpitCredential" => "struct:v1",
        // Fully-path-qualified struct types used by some command fcor schemas map to
        // their short canonical `struct:<Name>:v1` form (crate paths never leak into the
        // cross-language canonical identifier).
        "crate::terminal::TerminalBinding" => "struct:TerminalBinding:v1",
        "crate::terminal::TerminalIngressMetadata" => "struct:TerminalIngressMetadata:v1",
        "crate::bulk_transfer::BulkTransferRef" => "struct:RemoteBulkTransferRef:v1",
        "Option<crate::bulk_transfer::BulkTransferRef>" => {
            "option<struct:RemoteBulkTransferRef:v1>"
        }
        "crate::bulk_transfer::BulkTransferId" => "struct:RemoteTransferId:v1",
        "crate::AgentMutation" => "struct:AgentMutation:v1",
        "crate::ExtendedConfigPatch" => "struct:ExtendedConfigPatch:v1",
        _ => return None,
    })
}

#[cfg(feature = "remote")]
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
#[cfg(feature = "remote")]
pub fn remote_adapter_recovery_contract_for_tag(
    tag: &str,
) -> Option<RemoteAdapterRecoveryContractV1> {
    crate::command!(command_remote_recovery_tag, tag)
}
#[cfg(feature = "remote")]
pub fn remote_adapter_recovery_strategy_for_tag(
    tag: &str,
) -> Option<RemoteAdapterRecoveryStrategy> {
    remote_adapter_recovery_contract_for_tag(tag).map(|contract| contract.strategy)
}

/// Largest 48-bit Unix-millisecond timestamp an RFC 9562 UUIDv7 can encode
/// (`2^48 - 1`). Timestamps beyond this range cannot be represented and are
/// rejected by [`remote_operation_uuid_v7_from_parts`].
#[cfg(feature = "remote")]
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
#[cfg(feature = "remote")]
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

    #[test]
    fn agent_interrupt_response_rejects_the_same_empty_shapes_as_typescript() {
        for response in [
            AgentInterruptResponse::Multi {
                selected_ids: Vec::new(),
            },
            AgentInterruptResponse::Freetext {
                text: String::new(),
            },
            AgentInterruptResponse::Batch {
                responses: Vec::new(),
            },
        ] {
            assert!(
                validate_agent_interrupt_response(&response).is_err(),
                "empty response shape must be rejected: {response:?}"
            );
        }
    }

    #[cfg(feature = "remote")]
    #[test]
    fn optional_sensitive_wire_payload_fcor_is_exactly_digest_redacted() {
        for tag in ["complete_provider_oauth", "complete_mcp_oauth"] {
            let schema = canonical_remote_operation_fcor_schema_for_tag(tag)
                .expect("OAuth completion has a canonical FCOR schema");
            assert_eq!(
                schema,
                "client_operation_id:string|flow_id:string|input:option<sha256-redacted>"
            );
        }
    }

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
        use crate::MAX_NDJSON_FRAME_BYTES;
        use crate::bulk_transfer::{
            BulkMimeClass as RemoteBulkMimeClass, BulkTransferRef as RemoteBulkTransferRef,
        };

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
        let transfer_id = crate::bulk_transfer::transfer_id_from_bytes([9u8; 16]).unwrap();
        let request = Request::ImportSessionArchive {
            transfer: RemoteBulkTransferRef::new(
                transfer_id,
                64 * 1024 * 1024,
                [0xAB; 32],
                RemoteBulkMimeClass::Archive,
            )
            .unwrap(),
        };
        assert_eq!(request.wire_tag(), "import_session_archive");

        let encoded = serde_json::to_string(&request).unwrap();
        // A 64 MiB archive now produces a tiny request frame.
        assert!(
            encoded.len() < 1024,
            "a transfer reference must stay small, got {} bytes",
            encoded.len()
        );
        assert!(encoded.len() < MAX_NDJSON_FRAME_BYTES);
        // No base64 blob field survives anywhere in the encoding.
        assert!(!encoded.contains("archive_base64"));

        let round_tripped: Request = serde_json::from_str(&encoded).unwrap();
        match round_tripped {
            Request::ImportSessionArchive { transfer } => {
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
                session_entry_mode: Some(SessionEntryMode::Code),
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
                session_entry_mode: Some(SessionEntryMode::Code),
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
            origin: Default::default(),
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

    #[test]
    fn bulk_user_message_is_reference_only_at_exact_transport_boundaries() {
        use crate::bulk_transfer::{
            BulkMimeClass as RemoteBulkMimeClass, BulkTransferRef as RemoteBulkTransferRef,
            transfer_id_from_bytes,
        };

        let request = |total_length, mime_class| Request::SendUserMessageBulk {
            client_submission_id: Uuid::new_v4(),
            origin: Default::default(),
            expected_model_state_generation: None,
            expected_model: None,
            transfer: RemoteBulkTransferRef::new(
                transfer_id_from_bytes([7; 16]).unwrap(),
                total_length,
                [0xAB; 32],
                mime_class,
            )
            .unwrap(),
            display_text: Some("large remote preview".to_owned()),
            display_transfer: None,
            tag_expansions: Vec::new(),
            forced_skill: None,
            run_invocation_options: None,
        };

        for boundary in [65_537, 8 * 1024 * 1024] {
            let request = request(boundary, RemoteBulkMimeClass::Opaque);
            request
                .validate_semantics()
                .expect("exact bulk text boundary must be accepted");
            let encoded = serde_json::to_vec(&request).unwrap();
            assert!(
                encoded.len() < 1024 && encoded.len() < crate::MAX_NDJSON_FRAME_BYTES,
                "the {boundary}-byte body must stay on the bulk lane"
            );
            assert!(
                !String::from_utf8_lossy(&encoded).contains("\"text\""),
                "bulk request must contain a transfer reference, not a text body"
            );
        }

        let under = request(65_536, RemoteBulkMimeClass::Opaque);
        assert!(under.validate_semantics().is_err());
        let over = request(8 * 1024 * 1024 + 1, RemoteBulkMimeClass::Opaque);
        assert!(over.validate_semantics().is_err());
        let wrong_kind = request(65_537, RemoteBulkMimeClass::Archive);
        assert!(wrong_kind.validate_semantics().is_err());
    }

    #[test]
    fn bulk_user_message_can_stage_a_large_display_form_without_inline_frame_growth() {
        use crate::bulk_transfer::{
            BulkMimeClass as RemoteBulkMimeClass, BulkTransferRef as RemoteBulkTransferRef,
            transfer_id_from_bytes,
        };

        let transfer = RemoteBulkTransferRef::new(
            transfer_id_from_bytes([8; 16]).unwrap(),
            5,
            [0xAC; 32],
            RemoteBulkMimeClass::Opaque,
        )
        .unwrap();
        let display_transfer = RemoteBulkTransferRef::new(
            transfer_id_from_bytes([9; 16]).unwrap(),
            8 * 1024 * 1024,
            [0xBD; 32],
            RemoteBulkMimeClass::Opaque,
        )
        .unwrap();
        let request = Request::SendUserMessageBulk {
            client_submission_id: Uuid::new_v4(),
            origin: Default::default(),
            expected_model_state_generation: None,
            expected_model: None,
            transfer: transfer.clone(),
            display_text: None,
            display_transfer: Some(display_transfer.clone()),
            tag_expansions: Vec::new(),
            forced_skill: None,
            run_invocation_options: None,
        };
        request
            .validate_semantics()
            .expect("a display transfer permits an inline-sized source transfer");
        let encoded = serde_json::to_vec(&request).unwrap();
        assert!(encoded.len() < 1024 && encoded.len() < crate::MAX_NDJSON_FRAME_BYTES);
        assert!(!String::from_utf8_lossy(&encoded).contains("large remote preview"));

        let mut conflicting_inline = request.clone();
        let Request::SendUserMessageBulk { display_text, .. } = &mut conflicting_inline else {
            unreachable!();
        };
        *display_text = Some("inline too".to_owned());
        assert!(conflicting_inline.validate_semantics().is_err());
        let mut oversized_inline_display = request.clone();
        let Request::SendUserMessageBulk {
            display_transfer,
            display_text,
            ..
        } = &mut oversized_inline_display
        else {
            unreachable!();
        };
        *display_transfer = None;
        *display_text = Some("x".repeat(65_537));
        assert!(oversized_inline_display.validate_semantics().is_err());
        let mut shared_transfer = request;
        let Request::SendUserMessageBulk {
            display_transfer, ..
        } = &mut shared_transfer
        else {
            unreachable!();
        };
        *display_transfer = Some(transfer);
        assert!(shared_transfer.validate_semantics().is_err());
    }

    #[cfg(feature = "remote")]
    #[test]
    fn semantic_validation_rechecks_in_process_owner_credential() {
        let mut invalid = crate::StoredFlycockpitCredential {
            server_url: "http://not-loopback.example.test".into(),
            instance_id: "instance".into(),
            instance_token: "token".into(),
            account: crate::AccountInfo {
                user_id: "user".into(),
                email: "user@example.test".into(),
            },
            display_name: None,
            relay_choice: None,
        };
        let request = Request::StoreFlycockpitCredential {
            credential: invalid.clone(),
            force: true,
        };
        assert!(request.validate_semantics().is_err());

        invalid.server_url = "https://cockpit.example.test".into();
        invalid.relay_choice = Some(crate::RelayChoice {
            relay_id: String::new(),
            region: None,
            ws_url: "wss://relay.example.test/ws".into(),
            rtt_ms: None,
            chosen_at: 1,
        });
        assert!(
            Request::StoreFlycockpitCredential {
                credential: invalid,
                force: true,
            }
            .validate_semantics()
            .is_err()
        );
    }

    #[test]
    fn semantic_validation_reserves_flycockpit_provider_credential_key() {
        for request in [
            Request::PutProviderCredential {
                client_operation_id: "reserved-provider-put".into(),
                provider_id: RESERVED_FLYCOCKPIT_PROVIDER_ID.to_string(),
                record: "{}".to_string().into(),
            },
            Request::DeleteProviderCredential {
                client_operation_id: "reserved-provider-delete".into(),
                provider_id: RESERVED_FLYCOCKPIT_PROVIDER_ID.to_string(),
                project_root: None,
            },
        ] {
            assert!(request.validate_semantics().is_err());
        }
    }

    #[test]
    fn provider_credential_delete_keeps_direct_ref_compatibility_and_can_bind_a_workspace() {
        let direct = Request::DeleteProviderCredential {
            client_operation_id: "direct-provider-delete".into(),
            provider_id: "legacy-record-ref".into(),
            project_root: None,
        };
        let direct_wire = serde_json::to_value(&direct).expect("serialize direct delete");
        assert!(direct_wire["params"].get("project_root").is_none());

        let configured = Request::DeleteProviderCredential {
            client_operation_id: "configured-provider-delete".into(),
            provider_id: "custom-oauth".into(),
            project_root: Some("/workspace".into()),
        };
        let configured_wire =
            serde_json::to_value(&configured).expect("serialize configured delete");
        assert_eq!(configured_wire["params"]["project_root"], "/workspace");
    }

    macro_rules! command_tags {
        (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
            vec![$($(#[$row_attr])* $tag),+]
        }};
    }

    #[cfg(feature = "remote")]
    macro_rules! remote_operation_rows {
        (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
            let mut rows = Vec::new();
            $($(#[$row_attr])* rows.push(($tag, $mutating, stringify!($authz), stringify!($remote_class)));)+
            rows
        }};
    }

    #[cfg(feature = "remote")]
    macro_rules! fcor_source_rows {
        (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
            let mut rows = Vec::new();
            $($(#[$row_attr])* rows.push((
                stringify!($pattern),
                $tag,
                $fcor_schema,
                vec![$((stringify!($fcor_field), stringify!($fcor_type), concat!(stringify!($fcor_role), $("(", stringify!($($fcor_role_arg),*), ")")?))),*],
            ));)+
            rows
        }};
    }

    #[cfg(feature = "remote")]
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

    #[cfg(feature = "remote")]
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

    #[cfg(feature = "remote")]
    macro_rules! remote_evidence_json {
        () => {
            serde_json::Value::Null
        };
        ($evidence:ident) => {
            serde_json::Value::String(stringify!($evidence).to_owned())
        };
    }

    #[cfg(feature = "remote")]
    macro_rules! remote_operation_fixture_rows {
        (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
            let mut rows = Vec::new();
            $($(#[$row_attr])* rows.push(serde_json::json!({
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
            }));)+
            rows
        }};
    }

    #[cfg(feature = "remote")]
    #[test]
    fn remote_operation_classification_is_exhaustive() {
        use std::collections::BTreeSet;

        let rows = crate::command!(remote_operation_rows);
        let unique: BTreeSet<_> = rows.iter().map(|(tag, ..)| *tag).collect();
        assert_eq!(unique.len(), rows.len(), "request tags must be unique");
        for (tag, audit_mutating, authz, declared_class) in rows {
            let class = remote_operation_class_for_tag(tag);
            if authz == "owner_only" {
                let owner_remoted = matches!(
                    tag,
                    "store_flycockpit_credential"
                        | "clear_flycockpit_credential"
                        | "set_flycockpit_connector_enabled"
                        | "sync_flycockpit_org_policy"
                        | "enroll_flycockpit_org_sync"
                        | "get_startup_disclosures"
                        | "list_secret_inventory"
                        | "put_named_secret"
                        | "delete_named_secret"
                        | "put_provider_credential"
                        | "delete_provider_credential"
                        | "get_flycockpit_account"
                        | "get_provider_catalog_snapshot"
                        | "fetch_provider_models"
                        | "get_provider_usage_snapshot"
                        | "upsert_provider_config"
                        | "save_provider_config"
                        | "save_mcp_config"
                        | "delete_provider_config"
                        | "set_provider_layer_metadata"
                        // Owner-remoted settings/setup/OAuth mutations: durable
                        // config writes reserve a nonrepeatable remote operation;
                        // the OAuth `begin_*` handshakes carry the non-durable
                        // `read_only` remote class (they return only the public
                        // authorize URL), and `complete_*` reserves the durable
                        // token-exchange operation.
                        | "save_extended_config"
                        | "save_image_spend_policy"
                        | "import_policy"
                        | "apply_setup_wizard"
                        | "setup_copilot_auth"
                        | "begin_provider_oauth"
                        | "complete_provider_oauth"
                        | "begin_mcp_oauth"
                        | "complete_mcp_oauth"
                        | "set_workspace_trust"
                        | "get_workspace_trust"
                        | "resolve_assistant_session"
                        | "list_assistants"
                        | "upsert_assistant"
                        | "create_assistant_session"
                        | "import_session_archive"
                        | "curator"
                        | "stats_rollup"
                        // v10-only owner-remoted redacted session export: the
                        // redacted assemble and its type-bound reader are
                        // owner-remoted `read_only`; the raw `--include-sensitive`
                        // assemble and the generic bulk reader stay `local_only`.
                        | "export_session_data"
                        | "read_redacted_export_chunk"
                        // v10-only owner-remoted CLI-surface RPCs.
                        | "list_packages"
                        | "add_package"
                        | "import_package"
                        | "prune_packages"
                        | "import_kcl_packages"
                        | "get_connector_state"
                        | "get_org_sync_status"
                        | "list_failed_tool_calls"
                        | "get_session_compactions"
                        | "purge_ended_sessions"
                        | "get_assistant"
                        | "diagnose_media_reservation"
                        | "repair_media_reservation"
                        | "get_doctor_snapshot"
                        | "docs_ask"
                        // v10-only owner-remoted sealed-owner sensitive channel.
                        | "begin_sealed_owner_operation"
                        | "apply_sealed_owner_operation"
                        | "cancel_sealed_owner_operation"
                        | "sealed_owner_inventory"
                        | "edit_sealed_owner_description"
                        | "list_sealed_actions"
                        | "create_sealed_action"
                        | "revise_sealed_action_description"
                        | "revise_sealed_action_enabled"
                        | "retire_sealed_action"
                );
                if owner_remoted {
                    assert_ne!(declared_class, "local_only");
                    assert!(class.is_some(), "{tag} must reserve a remote operation");
                    continue;
                }
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
            Some(RemoteOperationClass::IdempotentAdapterMutation),
            "remote FCM2 ingress must be able to stage its opaque source before the bounded reference request"
        );
        assert_eq!(
            remote_adapter_recovery_strategy_for_tag("write_bulk_transfer_chunk"),
            Some(RemoteAdapterRecoveryStrategy::DomainTransaction)
        );
        assert_eq!(
            remote_adapter_recovery_strategy_for_tag("set_default_model"),
            None
        );
        assert_eq!(
            remote_operation_class_for_tag("set_workspace_trust"),
            Some(RemoteOperationClass::TransactionalMutation)
        );
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

    #[cfg(feature = "remote")]
    #[test]
    fn docs_ask_is_owner_remoted_read_only() {
        // AC6/AC7: `docs_ask` is owner-remoted (it reserves a remote operation,
        // so it is NOT `local_only`) and its remote class is `ReadOnly` — the
        // pipeline reads the dependency source/workspace and returns the answer
        // on the response, persisting no audit-mutating consequence.
        assert_eq!(
            remote_operation_class_for_tag("docs_ask"),
            Some(RemoteOperationClass::ReadOnly),
            "docs_ask must be an owner-remoted read-only operation, not local_only"
        );
        assert_eq!(
            remote_adapter_recovery_strategy_for_tag("docs_ask"),
            None,
            "a read-only docs question acquires no adapter recovery strategy"
        );
    }

    #[cfg(feature = "remote")]
    #[test]
    fn agent_installation_rpcs_are_local_owner_only() {
        // Installation commands operate on the daemon's local workspace and
        // SQLite state. They must never reserve a remote operation, whether
        // they mutate (begin/choice) or read (list/inspect).
        for tag in [
            "agent_installation_begin",
            "agent_installation_submit_choice",
            "agent_installation_list",
            "agent_installation_inspect",
        ] {
            assert_eq!(
                remote_operation_class_for_tag(tag),
                None,
                "{tag} must remain local_only"
            );
            assert_eq!(
                remote_adapter_recovery_strategy_for_tag(tag),
                None,
                "{tag} must not reserve remote adapter recovery"
            );
        }
    }

    #[cfg(feature = "remote")]
    #[test]
    fn owner_secret_wire_projections_and_debug_never_include_plaintext() {
        let unique = "owner_rpc_plaintext_must_not_escape";
        let inventory = serde_json::to_string(&Response::SecretInventory {
            entries: vec![SecretInventoryEntry {
                name: unique.to_string(),
                kind: SecretInventoryKind::NamedSecret,
                configured: true,
            }],
            next_cursor: None,
        })
        .unwrap();
        assert!(inventory.contains(unique));
        assert!(!inventory.contains("secret-value"));

        let account = serde_json::to_string(&Response::FlycockpitAccount {
            account: Some(FlycockpitAccountView {
                server_url: "https://app.example.test".into(),
                instance_id: "instance".into(),
                account: AccountInfo {
                    user_id: "user".into(),
                    email: "user@example.test".into(),
                },
                display_name: None,
                relay_choice: None,
                token_fingerprint: "fingerprint".into(),
            }),
        })
        .unwrap();
        assert!(!account.contains("refresh-token"));
        assert!(account.contains("fingerprint"));

        let request = Request::PutNamedSecret {
            name: unique.into(),
            value: "secret-value".into(),
        };
        assert!(!format!("{request:?}").contains(unique));
        assert!(!format!("{request:?}").contains("secret-value"));
    }

    #[test]
    fn owner_provider_rpcs_bound_typed_and_wire_ingress() {
        let oversized_provider_id = "p".repeat(MAX_OWNER_PROVIDER_ID_BYTES + 1);
        let oversized_metadata = "x".repeat(MAX_OWNER_PROVIDER_METADATA_JSON_BYTES + 1);
        assert!(
            Request::PutSubscriptionAck {
                client_operation_id: "subscription-ack".into(),
                provider_id: oversized_provider_id.clone(),
            }
            .validate_semantics()
            .is_err()
        );

        assert!(
            Request::FetchProviderModels {
                project_root: "/repo".into(),
                provider_id: Some("p".repeat(MAX_OWNER_PROVIDER_ID_BYTES + 1)),
                model_id: None,
                deep: false,
                on_unlisted: None,
                allow_fallback: false,
            }
            .validate_semantics()
            .is_err()
        );
        assert!(
            Request::FetchProviderModels {
                project_root: "/repo".into(),
                provider_id: Some("provider".into()),
                model_id: Some("m".repeat(MAX_OWNER_PROVIDER_MODEL_ID_BYTES + 1)),
                deep: false,
                on_unlisted: None,
                allow_fallback: false,
            }
            .validate_semantics()
            .is_err()
        );
        let metadata_wire = serde_json::json!({
            "request": "set_provider_layer_metadata",
            "params": {
                "project_root": "/repo",
                "category_defaults_json": oversized_metadata,
                "on_unlisted_models_fetch": "keep"
            }
        });
        assert!(serde_json::from_value::<Request>(metadata_wire).is_err());

        let fetch_wire = serde_json::json!({
            "request": "fetch_provider_models",
            "params": {
                "project_root": "/repo",
                "provider_id": oversized_provider_id,
                "deep": false,
                "allow_fallback": false
            }
        });
        assert!(serde_json::from_value::<Request>(fetch_wire).is_err());
    }

    #[cfg(feature = "remote")]
    #[test]
    fn provider_config_owner_ingress_rejects_credential_bearing_urls() {
        let request = Request::UpsertProviderConfig {
            project_root: "/repo".into(),
            provider_id: "custom".into(),
            entry: cockpit_config::config::providers::ProviderEntry {
                url: "https://user:secret@api.example.test/v1?key=secret".into(),
                ..Default::default()
            },
        };
        let error = request.validate_semantics().unwrap_err();
        assert!(error.contains("credentials"));
        assert!(!error.contains("secret"));

        let request = Request::UpsertProviderConfig {
            project_root: "/repo".into(),
            provider_id: "custom".into(),
            entry: cockpit_config::config::providers::ProviderEntry {
                url: "https://api.example.test/v1?key=secret".into(),
                ..Default::default()
            },
        };
        let error = request.validate_semantics().unwrap_err();
        assert!(error.contains("query string"));
        assert!(!error.contains("secret"));
    }

    #[cfg(not(feature = "remote"))]
    #[test]
    fn local_v17_rejects_revisionless_provider_mutation_tags() {
        for tag in [
            "upsert_provider_config",
            "save_provider_config",
            "delete_provider_config",
            "set_provider_layer_metadata",
            "apply_setup_wizard",
        ] {
            let wire = serde_json::json!({ "request": tag, "params": {} });
            assert!(
                serde_json::from_value::<Request>(wire).is_err(),
                "local protocol unexpectedly accepts legacy provider mutation `{tag}`"
            );
        }
        // Full-shape daemon fixtures are intentionally remote-profile
        // archaeology and are exhaustively checked only with `remote`.
        // This test is the local-profile source of truth: it exercises the
        // actual default-feature deserializer rather than inspecting that
        // remote fixture as if it represented a local binary.
    }

    #[cfg(feature = "remote")]
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
            description: "assistant".into(),
            prompt: "help".into(),
        };
        assert_eq!(request.wire_tag(), "upsert_assistant");
        assert!(crate::command!(command_tags).contains(&request.wire_tag()));
    }

    #[cfg(feature = "remote")]
    #[test]
    fn upsert_assistant_is_owner_remoted() {
        // AC6: reclassified away from `local_only`; reserves a remote op.
        assert_eq!(
            remote_operation_class_for_tag("upsert_assistant"),
            Some(RemoteOperationClass::NonrepeatableMutation)
        );
    }

    #[cfg(feature = "remote")]
    #[test]
    fn export_session_data_is_owner_remoted() {
        // AC4: the redacted session export is reclassified from `local_only` to
        // owner-remoted `read_only` — it reserves a remote operation so a remoted
        // owner can download it. The new type-bound redacted reader is likewise
        // owner-remoted `read_only`.
        assert_eq!(
            remote_operation_class_for_tag("export_session_data"),
            Some(RemoteOperationClass::ReadOnly)
        );
        assert_eq!(
            remote_operation_class_for_tag("read_redacted_export_chunk"),
            Some(RemoteOperationClass::ReadOnly)
        );
    }

    #[cfg(feature = "remote")]
    #[test]
    fn raw_export_reader_stays_local_only_while_opaque_ingress_is_remoted() {
        // AC5/AC8: the generic bulk reader that serves the raw `--include-sensitive`
        // archive stays `local_only` (no remote operation class), so a remote
        // principal is refused it at admission — the sanctioned owner-local carve
        // out. The write side is different: it is the authenticated, attached
        // session-writer ingress for reference-only opaque FCM2 bodies.
        assert_eq!(
            remote_operation_class_for_tag("read_bulk_transfer_chunk"),
            None
        );
        assert_eq!(
            remote_operation_class_for_tag("write_bulk_transfer_chunk"),
            Some(RemoteOperationClass::IdempotentAdapterMutation)
        );
    }

    #[cfg(feature = "remote")]
    #[test]
    fn repair_media_reservation_is_owner_remoted() {
        // AC7: owner-remoted serialized mutation, not `local_only`.
        assert_eq!(
            remote_operation_class_for_tag("repair_media_reservation"),
            Some(RemoteOperationClass::NonrepeatableMutation)
        );
    }

    #[cfg(feature = "remote")]
    #[test]
    fn get_workspace_trust_is_required_owner_remoted() {
        // AC8: the existing workspace-trust tag is the owner-remoted read;
        // `GetStartupDisclosures` is unchanged and is NOT the trust read.
        assert_eq!(
            remote_operation_class_for_tag("get_workspace_trust"),
            Some(RemoteOperationClass::ReadOnly)
        );
        assert_ne!("get_workspace_trust", "get_startup_disclosures");
        assert_eq!(
            remote_operation_class_for_tag("get_startup_disclosures"),
            Some(RemoteOperationClass::ReadOnly)
        );
    }

    #[cfg(feature = "remote")]
    #[test]
    fn new_cli_surface_rpcs_are_owner_remoted_never_local_only() {
        // AC1: every new row exists and is not `local_only` (None class).
        for tag in [
            "list_packages",
            "get_connector_state",
            "get_org_sync_status",
            "list_failed_tool_calls",
            "get_session_compactions",
            "get_assistant",
            "diagnose_media_reservation",
            "get_doctor_snapshot",
        ] {
            assert_eq!(
                remote_operation_class_for_tag(tag),
                Some(RemoteOperationClass::ReadOnly),
                "{tag} must be an owner-remoted read"
            );
        }
        for tag in [
            "add_package",
            "import_package",
            "prune_packages",
            "import_kcl_packages",
            "purge_ended_sessions",
            "repair_media_reservation",
        ] {
            assert_eq!(
                remote_operation_class_for_tag(tag),
                Some(RemoteOperationClass::NonrepeatableMutation),
                "{tag} must be an owner-remoted mutation"
            );
        }
    }

    #[test]
    fn get_session_compactions_is_a_distinct_tag_from_read_history_page() {
        // AC9 (proto half): a dedicated tag, never `ReadHistoryPage`.
        assert_eq!(
            Request::GetSessionCompactions {
                session_id: Uuid::nil()
            }
            .wire_tag(),
            "get_session_compactions"
        );
        assert_ne!("get_session_compactions", "read_history_page");
        // ReadHistoryPage is unchanged (still a read).
        #[cfg(feature = "remote")]
        {
            assert_eq!(
                remote_operation_class_for_tag("read_history_page"),
                Some(RemoteOperationClass::ReadOnly)
            );
        }
    }

    #[test]
    fn legacy_list_delete_sealed_removed() {
        // AC2: the legacy session-scoped sealed list/delete tags are gone from
        // both macro tables; no command row survives for them.
        let command_tags = crate::command!(command_tags);
        assert!(!command_tags.contains(&"list_sealed_values"));
        assert!(!command_tags.contains(&"delete_sealed_value"));
        // No `Request` variant serializes to the retired tags either.
        #[cfg(feature = "remote")]
        {
            assert_eq!(remote_operation_class_for_tag("list_sealed_values"), None);
            assert_eq!(remote_operation_class_for_tag("delete_sealed_value"), None);
        }
    }

    #[test]
    fn sealed_owner_rpcs_are_registered_in_both_macro_tables() {
        // AC3 (registration half): every new sealed-owner tag exists in the
        // `request_variants!` and `command!` tables.
        let requests = [
            Request::BeginSealedOwnerOperation {
                disposition: "recover".into(),
                record_id: Some("rec".into()),
                name: None,
                description: None,
                scope_kind: None,
                scope_key: None,
            },
            Request::ApplySealedOwnerOperation {
                capability_id: "cap".into(),
                literal: None,
            },
            Request::CancelSealedOwnerOperation {
                capability_id: "cap".into(),
            },
            Request::SealedOwnerInventory {
                scope_kind: None,
                scope_key: None,
            },
            Request::EditSealedOwnerDescription {
                record_id: "rec".into(),
                description: "desc".into(),
            },
            Request::ListSealedActions,
            Request::CreateSealedAction {
                kind_id: "k".into(),
                project_id: "p".into(),
                description: "d".into(),
                origin_id: "0".into(),
                projection_id: "none".into(),
            },
            Request::ReviseSealedActionDescription {
                action_id: "a".into(),
                description: "d".into(),
            },
            Request::ReviseSealedActionEnabled {
                action_id: "a".into(),
                enabled: true,
            },
            Request::RetireSealedAction {
                action_id: "a".into(),
                confirm: "a".into(),
            },
        ];
        let tags: Vec<_> = requests.iter().map(Request::wire_tag).collect();
        assert_eq!(
            tags,
            [
                "begin_sealed_owner_operation",
                "apply_sealed_owner_operation",
                "cancel_sealed_owner_operation",
                "sealed_owner_inventory",
                "edit_sealed_owner_description",
                "list_sealed_actions",
                "create_sealed_action",
                "revise_sealed_action_description",
                "revise_sealed_action_enabled",
                "retire_sealed_action",
            ]
        );
        let command_tags = crate::command!(command_tags);
        for tag in tags {
            assert!(command_tags.contains(&tag), "missing command row for {tag}");
        }
    }

    #[cfg(feature = "remote")]
    #[test]
    fn sealed_owner_rpcs_are_owner_remoted() {
        // AC3: every new tag reserves a remote operation (not `local_only`,
        // not `rejected`) — reads as `ReadOnly`, mutations as
        // `NonrepeatableMutation`.
        for tag in ["sealed_owner_inventory", "list_sealed_actions"] {
            assert_eq!(
                remote_operation_class_for_tag(tag),
                Some(RemoteOperationClass::ReadOnly),
                "{tag} must be an owner-remoted read"
            );
        }
        for tag in [
            "begin_sealed_owner_operation",
            "apply_sealed_owner_operation",
            "cancel_sealed_owner_operation",
            "edit_sealed_owner_description",
            "create_sealed_action",
            "revise_sealed_action_description",
            "revise_sealed_action_enabled",
            "retire_sealed_action",
        ] {
            assert_eq!(
                remote_operation_class_for_tag(tag),
                Some(RemoteOperationClass::NonrepeatableMutation),
                "{tag} must be an owner-remoted serialized mutation"
            );
        }
    }

    #[cfg(feature = "remote")]
    #[test]
    fn apply_sealed_owner_operation_carries_bounded_zeroizing_literal() {
        // AC1 / core security property: the plaintext rides the apply request
        // frame as the redacting, zeroizing literal, and an over-bound literal
        // fails closed at the wire funnel.
        let marker = "APPLY-REQUEST-PLAINTEXT-marker";
        let request = Request::ApplySealedOwnerOperation {
            capability_id: "cap-1".into(),
            literal: Some(crate::SensitiveWireLiteral::new(marker.into())),
        };
        // Debug of the whole request never prints the plaintext.
        assert!(!format!("{request:?}").contains(marker));
        // The literal round-trips on the wire (owner -> daemon).
        let wire = serde_json::to_string(&request).unwrap();
        assert!(
            wire.contains(marker),
            "the apply request carries the literal"
        );
        let back: Request = serde_json::from_str(&wire).unwrap();
        match back {
            Request::ApplySealedOwnerOperation { literal, .. } => {
                assert_eq!(literal.unwrap().as_str(), marker);
            }
            other => panic!("expected apply, got {other:?}"),
        }
        // An over-bound literal on the apply request fails closed at deserialize.
        let oversized = "z".repeat(crate::MAX_SENSITIVE_FRAME_BYTES + 1);
        let forged = format!(
            "{{\"request\":\"apply_sealed_owner_operation\",\"params\":{{\"capability_id\":\"c\",\"literal\":{}}}}}",
            serde_json::to_string(&oversized).unwrap()
        );
        assert!(
            serde_json::from_str::<Request>(&forged).is_err(),
            "an apply request literal over MAX_SENSITIVE_FRAME_BYTES must fail closed"
        );
    }

    #[cfg(feature = "remote")]
    #[test]
    fn apply_literal_plaintext_never_enters_fcor_canonical_params() {
        // FINDING 1: the sealed plaintext must never be copied into the
        // non-zeroizing FCOR canonical digest buffer. The apply's dedup identity
        // is the single-use capability_id + CAS, so the literal is excluded from
        // canonicalization entirely (a fixed placeholder is encoded instead).
        let marker = "FCOR-PLAINTEXT-marker-must-not-appear";
        let with_literal = Request::ApplySealedOwnerOperation {
            capability_id: "cap-1".into(),
            literal: Some(crate::SensitiveWireLiteral::new(marker.into())),
        };
        let params = with_literal
            .canonical_remote_operation_params_v1()
            .expect("apply canonicalizes");
        // Precondition: the marker really was in the request (positive control).
        assert!(
            serde_json::to_string(&with_literal)
                .unwrap()
                .contains(marker),
            "precondition: the apply request carries the marker on the wire"
        );
        // The plaintext bytes must be absent from the canonical digest buffer.
        assert!(
            !params
                .windows(marker.len())
                .any(|window| window == marker.as_bytes()),
            "sealed plaintext must not enter the FCOR canonical params"
        );
        // Present/absent is still distinguished (so the Option bit is honest):
        // an apply with a literal canonicalizes differently from a recover apply
        // with no literal.
        let no_literal = Request::ApplySealedOwnerOperation {
            capability_id: "cap-1".into(),
            literal: None,
        };
        assert_ne!(
            params,
            no_literal
                .canonical_remote_operation_params_v1()
                .expect("recover apply canonicalizes"),
            "present vs absent literal must canonicalize distinctly"
        );
        // Two different literals under the same capability canonicalize
        // IDENTICALLY (the literal is redacted from the key), so no length or
        // content oracle leaks through the digest.
        let other_literal = Request::ApplySealedOwnerOperation {
            capability_id: "cap-1".into(),
            literal: Some(crate::SensitiveWireLiteral::new(
                "a-different-secret".into(),
            )),
        };
        assert_eq!(
            params,
            other_literal
                .canonical_remote_operation_params_v1()
                .expect("apply canonicalizes"),
            "the literal content must not influence the FCOR key"
        );
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
            Request::CancelLeakReveal {
                capability: LeakRevealToken::new("00".repeat(32)),
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
                "cancel_leak_reveal",
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
            origin: Default::default(),
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
            origin: Default::default(),
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
            origin: Default::default(),
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
            origin: Default::default(),
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
            origin: Default::default(),
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
            origin: Default::default(),
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
            origin: Default::default(),
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
            origin: Default::default(),
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
