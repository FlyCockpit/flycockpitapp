//! Wire protocol — NDJSON envelopes carried over any byte stream.
//!
//! One envelope per newline-terminated frame. Same shape on the
//! in-process channel (today), the Unix socket (P3), and the future
//! WebSocket relay for `cockpit connect` (GOALS §8c, §8d).
//!
//! Layout:
//!
//! ```text
//! { "v": 1, "kind": "req"|"res"|"evt"|"err", ... }
//! ```
//!
//! - **`req`** — client → daemon. Carries a uuid `id` the daemon
//!   echoes on the matching `res` / `err`.
//! - **`res`** — daemon → client. Pairs with `req` by `id`.
//! - **`evt`** — daemon → client. Unsolicited stream event (assistant
//!   text deltas, tool starts/ends, interrupt-raised, …). No id; the
//!   client routes events by `session_id` payload.
//! - **`err`** — daemon → client. Used both as a paired response to a
//!   failed `req` (carries the matching `id`) and as an
//!   out-of-band notification (`id = null`).
//!
//! The schema version (`v`) sits on every envelope so a future bump
//! can be detected on a per-line basis without buffering. Clients
//! refuse envelopes whose `v` is outside the supported range.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LinesCodec, LinesCodecError};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvSnapshotSource {
    DaemonStart,
    TuiShell,
    TuiProcessFallback,
    ExplicitCli,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvSnapshotMeta {
    pub source: EnvSnapshotSource,
    pub digest: String,
    pub key_count: usize,
    pub path_entry_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvSnapshotWire {
    pub source: EnvSnapshotSource,
    pub digest: String,
    pub vars: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    pub session_id: Uuid,
    pub generation: u64,
    pub extended: cockpit_config::config::extended::ExtendedConfig,
    pub providers: ProviderConfigView,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderConfigView {
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderEntryView>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub category_defaults: BTreeMap<String, cockpit_config::config::providers::ProviderModelRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_unlisted_models_fetch: Option<cockpit_config::config::providers::OnUnlistedModelsFetch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_model: Option<cockpit_config::config::providers::ActiveModelRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHeaderView {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderEntryView {
    pub entry: cockpit_config::config::providers::ProviderEntry,
    #[serde(default)]
    pub headers: Vec<ProviderHeaderView>,
    #[serde(default)]
    pub credential_configured: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EnvDriftPolicy {
    #[default]
    Daemon,
    Client,
    UpdateDaemon,
    ErrorOnDrift,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvDiffSummary {
    pub baseline_digest: String,
    pub candidate_digest: String,
    pub added_keys: usize,
    pub removed_keys: usize,
    pub changed_keys: usize,
    pub changed_secret_keys: Vec<String>,
    pub path_added: Vec<String>,
    pub path_removed: Vec<String>,
}

impl EnvDiffSummary {
    pub fn meaningful(&self) -> bool {
        self.added_keys > 0
            || self.removed_keys > 0
            || self.changed_keys > 0
            || !self.path_added.is_empty()
            || !self.path_removed.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub pools: BTreeMap<String, u32>,
}

impl ResourceRequirements {
    pub fn new(pools: impl IntoIterator<Item = (impl Into<String>, u32)>) -> Self {
        Self {
            pools: pools
                .into_iter()
                .filter_map(|(name, count)| (count > 0).then(|| (name.into(), count)))
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pools.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRequestMetadata {
    pub session_id: Option<Uuid>,
    pub agent_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub command_label: Option<String>,
    pub declared_requirements: ResourceRequirements,
    pub policy_requirements: ResourceRequirements,
    pub reviewer_requirements: ResourceRequirements,
    pub effective_requirements: ResourceRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSchedulerSnapshot {
    pub enabled: bool,
    pub pools: Vec<ResourcePoolSnapshot>,
    pub running: Vec<ResourceRunningSnapshot>,
    pub queued: Vec<ResourceQueuedSnapshot>,
    pub max_queued: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePoolSnapshot {
    pub name: String,
    pub capacity: u32,
    pub used: u32,
    pub available: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRunningSnapshot {
    pub id: Uuid,
    pub display_id: String,
    pub resources: ResourceRequirements,
    pub metadata: ResourceRequestMetadata,
    pub queued_at_ms: i64,
    pub started_at_ms: i64,
    pub wait_ms: u64,
    pub promoted_by: Option<String>,
    pub promoted_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceQueuedSnapshot {
    pub id: Uuid,
    pub display_id: String,
    pub resources: ResourceRequirements,
    pub metadata: ResourceRequestMetadata,
    pub queued_at_ms: i64,
    pub wait_ms: u64,
    pub promoted_by: Option<String>,
    pub promoted_at_ms: Option<i64>,
    pub state: ResourceQueuedState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScheduledJobSchedule {
    Cron {
        expr: String,
    },
    Every {
        seconds: u64,
    },
    Once {
        at: i64,
    },
    Idle {
        min_idle_seconds: u64,
        max_age_seconds: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScheduledJobPayload {
    RunPrompt {
        assistant: String,
        prompt: String,
        project_root: String,
    },
    Callback {
        subsystem: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MissedRunPolicy {
    #[default]
    Skip,
    RunOnceOnStart,
}

impl MissedRunPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::RunOnceOnStart => "run_once_on_start",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledJobCreate {
    pub id: String,
    pub owner: String,
    pub schedule: ScheduledJobSchedule,
    pub payload: ScheduledJobPayload,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub missed_run_policy: MissedRunPolicy,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledJobLastResult {
    pub ok: bool,
    pub summary: String,
    pub finished_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledJobSummary {
    pub id: String,
    pub owner: String,
    pub schedule: ScheduledJobSchedule,
    pub payload: ScheduledJobPayload,
    pub enabled: bool,
    pub missed_run_policy: MissedRunPolicy,
    pub last_run_at: Option<i64>,
    pub next_run_at: Option<i64>,
    pub last_result: Option<ScheduledJobLastResult>,
    pub failure_count: u32,
    pub backoff_until: Option<i64>,
    pub disabled_notice: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceQueuedState {
    Queued,
    Promoted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerRuntimeKind {
    Docker,
    Podman,
}

impl ContainerRuntimeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerUnavailableReason {
    NoRuntime,
    HarnessInContainer,
}

impl ContainerUnavailableReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoRuntime => "no_runtime",
            Self::HarnessInContainer => "harness_in_container",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerAvailability {
    pub runtime: Option<ContainerRuntimeKind>,
    pub harness_in_container: bool,
    pub available: bool,
    pub reason: Option<ContainerUnavailableReason>,
}

impl Default for ContainerAvailability {
    fn default() -> Self {
        Self {
            runtime: None,
            harness_in_container: false,
            available: false,
            reason: Some(ContainerUnavailableReason::NoRuntime),
        }
    }
}

impl ContainerAvailability {
    pub fn unavailable_reason_text(&self) -> Option<String> {
        self.reason.map(|reason| match reason {
            ContainerUnavailableReason::NoRuntime => {
                "no docker or podman executable found on PATH".to_string()
            }
            ContainerUnavailableReason::HarnessInContainer => {
                "cockpit is already running inside a container".to_string()
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaffeinateMode {
    Toggle,
    On,
    Off,
    UntilIdle,
}

impl CaffeinateMode {
    pub fn parse(arg: &str) -> std::result::Result<Self, String> {
        match arg.trim() {
            "" | "toggle" => Ok(Self::Toggle),
            "on" => Ok(Self::On),
            "off" => Ok(Self::Off),
            "until-idle" | "until_idle" | "untilidle" => Ok(Self::UntilIdle),
            other => Err(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IdleReason {
    Completed,
    GoalComplete,
    NeedsIntervention { code: String },
    BudgetLimited,
    UsageLimited,
    Error { class: String },
    Interrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolFailKind {
    Invocation,
    Execution,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountInfo {
    pub user_id: String,
    pub email: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredFlycockpitCredential {
    pub server_url: String,
    pub instance_id: String,
    pub instance_token: String,
    pub account: AccountInfo,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_choice: Option<RelayChoice>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RelayChoice {
    pub relay_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub ws_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u64>,
    pub chosen_at: i64,
}

impl RelayChoice {
    pub fn is_fresh_at(&self, now_ms: i64) -> bool {
        const TTL_MS: i64 = 30 * 60 * 1000;
        now_ms.saturating_sub(self.chosen_at) < TTL_MS
    }
}

impl fmt::Debug for StoredFlycockpitCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredFlycockpitCredential")
            .field("server_url", &self.server_url)
            .field("instance_id", &self.instance_id)
            .field("instance_token", &"<redacted>")
            .field("account", &self.account)
            .field("display_name", &self.display_name)
            .field("relay_choice", &self.relay_choice)
            .finish()
    }
}

/// Current wire schema version. Bumped only with a written migration
/// note in `the design notes`.
pub const PROTOCOL_VERSION: u32 = 3;

/// Oldest wire schema version this binary accepts.
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 3;

/// Version string the daemon advertises to clients on attach/status.
pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Max length of a single NDJSON frame. Tool args + read payloads can
/// be large; keep this generous so a `read` of an 8 KB-capped file
/// plus the envelope wrapper has headroom.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Pasted-image upload limits. Chunks are base64 strings inside JSON frames,
/// so keep the base64 payload well below [`MAX_FRAME_BYTES`].
pub const MAX_SINGLE_IMAGE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TOTAL_IMAGE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_IMAGES_PER_USER_MESSAGE: usize = 4;
pub const MAX_IMAGE_DIMENSION_PIXELS: u32 = 8192;
pub const MAX_ATTACHMENT_CHUNK_BASE64_BYTES: usize = 512 * 1024;
pub const PENDING_ATTACHMENT_TTL_SECS: u64 = 10 * 60;
pub const IMAGE_ATTACHMENT_MIME_PNG: &str = "image/png";
pub const IMAGE_PART_SENTINEL: &str = "\u{0}<cockpit-image-part>\u{0}";

pub fn is_protocol_compatible(v: u32) -> bool {
    (MIN_SUPPORTED_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&v)
}

pub fn version_mismatch_message(v: u32) -> String {
    format!(
        "wire protocol version mismatch: peer sent v{v}, this binary speaks v{} (supported {}..={})",
        PROTOCOL_VERSION, MIN_SUPPORTED_PROTOCOL_VERSION, PROTOCOL_VERSION
    )
}

// ---- Envelope --------------------------------------------------------------

/// Top-level frame. Always carries the protocol version and one of four
/// body variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u32,
    #[serde(flatten)]
    pub body: Body,
}

#[derive(Debug, Clone)]
pub enum RecvFrame {
    Envelope(Box<Envelope>),
    VersionMismatch {
        v: u32,
        kind: String,
        id: Option<Uuid>,
    },
}

impl Envelope {
    pub fn request(id: Uuid, request: Request) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            body: Body::Request { id, request },
        }
    }

    pub fn response(id: Uuid, response: Response) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            body: Body::Response {
                id,
                response: Box::new(response),
            },
        }
    }

    pub fn event(event: Event) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            body: Body::Event { event },
        }
    }

    pub fn error(id: Option<Uuid>, error: ErrorPayload) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            body: Body::Error { id, error },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Body {
    #[serde(rename = "req")]
    Request {
        id: Uuid,
        #[serde(flatten)]
        request: Request,
    },
    #[serde(rename = "res")]
    Response {
        id: Uuid,
        #[serde(flatten)]
        response: Box<Response>,
    },
    #[serde(rename = "evt")]
    Event {
        #[serde(flatten)]
        event: Event,
    },
    #[serde(rename = "err")]
    Error {
        /// `Some` when this `err` pairs with a `req`; `None` for
        /// out-of-band errors.
        #[serde(default)]
        id: Option<Uuid>,
        error: ErrorPayload,
    },
}

// ---- Requests --------------------------------------------------------------

mod request;
pub use request::{
    ActiveModelSwitchTrigger, AttachmentPurpose, LspControlAction, Request, UsageKind,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsReadKind {
    Text,
    Binary,
    Image,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsEntry {
    pub name: String,
    pub path: String,
    pub kind: FsEntryKind,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_ms: Option<i64>,
    pub gitignored: bool,
    pub blocked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitStatusEntry {
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageAttachmentRef {
    pub id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationSteerStatus {
    Queued,
    NotSteerable,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationSteerResult {
    pub status: DelegationSteerStatus,
    pub task_call_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub message: String,
    #[serde(default)]
    pub pending_steers: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_principal: Option<String>,
    #[serde(default)]
    pub scrubbed: bool,
}

impl DelegationSteerResult {
    pub fn queued(
        task_call_id: String,
        label: String,
        pending_steers: i64,
        origin_principal: String,
        scrubbed: bool,
    ) -> Self {
        Self {
            status: DelegationSteerStatus::Queued,
            task_call_id,
            label: Some(label),
            message: "steer queued".to_string(),
            pending_steers,
            origin_principal: Some(origin_principal),
            scrubbed,
        }
    }

    pub fn not_steerable(task_call_id: String, label: Option<String>, reason: String) -> Self {
        Self {
            status: DelegationSteerStatus::NotSteerable,
            task_call_id,
            label,
            message: reason,
            pending_steers: 0,
            origin_principal: None,
            scrubbed: false,
        }
    }

    pub fn internal(message: String) -> Self {
        Self {
            status: DelegationSteerStatus::InternalError,
            task_call_id: String::new(),
            label: None,
            message,
            pending_steers: 0,
            origin_principal: None,
            scrubbed: false,
        }
    }

    pub fn to_task_envelope_value(&self) -> serde_json::Value {
        match self.status {
            DelegationSteerStatus::Queued => {
                let label = self.label.clone().unwrap_or_default();
                serde_json::json!({
                    "state": "steer_queued",
                    "task_call_id": self.task_call_id,
                    "label": label,
                    "blocking": false,
                    "tool_call_closed": false,
                    "result_pending": false,
                    "report_available": false,
                    "report_delivered": false,
                    "actionable": true,
                    "applies_at": "next_child_turn_boundary",
                    "applies_if": "child_still_running_actionable",
                    "origin_principal": self.origin_principal,
                    "scrubbed": self.scrubbed,
                    "children": [{
                        "task_call_id": self.task_call_id,
                        "label": label,
                        "pending_steers": self.pending_steers,
                        "actionable": true,
                    }],
                })
            }
            DelegationSteerStatus::NotSteerable => serde_json::json!({
                "state": "refused",
                "task_call_id": self.task_call_id,
                "label": self.label,
                "reason": self.message,
                "actionable": false,
            }),
            DelegationSteerStatus::InternalError => serde_json::json!({
                "state": "error",
                "reason": self.message,
                "actionable": false,
            }),
        }
    }
}

mod response;
pub use response::{ActiveModelState, BtwForkInfo, Response};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResumeRepairState {
    pub session_id: Uuid,
    #[serde(default)]
    pub short_id: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub wire_api: String,
    pub failure_kind: String,
    #[serde(default)]
    pub failing_tool_call_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_last_turn_seq: Option<i64>,
    #[serde(default)]
    pub suggested_actions: Vec<ResumeRepairAction>,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourcePromoteStatus {
    Promoted,
    NotQueued,
    NotFound,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResumeRepairAction {
    OpenReadOnly,
    ForkFromLastProviderValidTurn,
    RepairSyntheticToolResults,
    ExportDebugBundle,
    Cancel,
}

fn default_daemon_version() -> String {
    DAEMON_VERSION.to_string()
}

fn default_client_protocol_version() -> u32 {
    MIN_SUPPORTED_PROTOCOL_VERSION
}

// (The wire event variant for the same state change lives on `Event`
// below, carrying `session_id` so the client can route it.)

mod event;
pub use event::{AuthFailureKind, Event};

// ---- Errors ----------------------------------------------------------------

/// Structured error response. The model and the TUI both render
/// `message` directly; `code` lets the client branch on
/// machine-readable kinds without parsing the message.
#[derive(Debug, Clone, Serialize, Deserialize, Error)]
#[error("{code}: {message}")]
pub struct ErrorPayload {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Request payload didn't parse / failed validation.
    BadRequest,
    /// Daemon doesn't speak this protocol version.
    ProtocolVersion,
    /// No active session — `Attach` first.
    NotAttached,
    /// Session id unknown.
    UnknownSession,
    /// Interrupt id unknown / already resolved.
    UnknownInterrupt,
    /// Daemon is shutting down.
    Shutdown,
    /// Principal is not authorized for the requested operation.
    Authorization,
    /// Principal has read-only access to this session.
    ReadOnly,
    /// Project root is missing or not a directory.
    RootMissing,
    /// Requested path escapes the project root.
    PathOutsideRoot,
    /// Optimistic-concurrency base hash did not match current content.
    HashMismatch,
    /// Requested path is locked by another writer.
    LockConflict,
    /// Workspace trust is unset or explicitly refuses access.
    WorkspaceTrust,
    /// Anything else.
    Internal,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::BadRequest => "bad_request",
            Self::ProtocolVersion => "protocol_version",
            Self::NotAttached => "not_attached",
            Self::UnknownSession => "unknown_session",
            Self::UnknownInterrupt => "unknown_interrupt",
            Self::Shutdown => "shutdown",
            Self::Authorization => "authorization",
            Self::ReadOnly => "read_only",
            Self::RootMissing => "root_missing",
            Self::PathOutsideRoot => "path_outside_root",
            Self::HashMismatch => "hash_mismatch",
            Self::LockConflict => "lock_conflict",
            Self::WorkspaceTrust => "workspace_trust",
            Self::Internal => "internal",
        };
        f.write_str(s)
    }
}

// ---- Shared payload types --------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum HistoryEntry {
    InterruptDecision {
        decision: InterruptDecision,
        #[serde(default)]
        seq: i64,
    },
    User {
        text: String,
        /// User-facing transcript form. Legacy rows omit it and display
        /// `text` unchanged.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        display_text: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tag_expansions: Vec<TagExpansionMeta>,
        /// `session_events.ts_ms` of this message (epoch millis) — the wall
        /// clock the TUI stamps on the restored row so a resumed transcript
        /// shows the original send time, not the resume time.
        #[serde(default)]
        ts_ms: i64,
        /// `session_events.seq` of this message — the stable id a pin
        /// references (`pinned-messages`) and the chronological ordering key.
        #[serde(default)]
        seq: i64,
        /// Principal that authored this user row (`flycockpit:<user_id>` for
        /// remote sharees). `None` is the local machine owner / legacy rows.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origin_principal: Option<String>,
    },
    Assistant {
        agent: String,
        /// Body text with inline `<think>` blocks stripped (the clean,
        /// stored form). Never carries reasoning tags.
        text: String,
        /// The turn's (channel + inline) reasoning, repopulating the
        /// thinking chip on resume (implementation note).
        /// Empty when the turn had none. UI/DB-only — never re-enters the
        /// model's context.
        #[serde(default)]
        reasoning: String,
        /// `session_events.ts_ms` of this turn (epoch millis).
        #[serde(default)]
        ts_ms: i64,
        /// `session_events.seq` of this turn — pin id + ordering key.
        #[serde(default)]
        seq: i64,
    },
    /// Tool calls appear inline in history so the TUI re-renders the
    /// turn faithfully on reconnect. The shape mirrors the
    /// `tool_call_events` row (GOALS §15b): the user transcript sees
    /// `original_input` and the recovery chip; the model on its next
    /// inference call sees `wire_input` (which equals
    /// `original_input` unless §12 repair or §13c cascade rewrite
    /// fired).
    ToolCall {
        /// `session_events.seq` of this tool-call timeline row.
        #[serde(default)]
        seq: i64,
        agent: String,
        call_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_call_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_child_index: Option<i64>,
        tool: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mcp_server: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mcp_builtin: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mcp_kind: Option<String>,
        original_input: Value,
        wire_input: Value,
        recovery_kind: Option<String>,
        recovery_stage: Option<String>,
        output: String,
        hard_fail: bool,
        truncated: bool,
        /// Post-result hint text (`engine::bash_hints`, the user-side
        /// `data.hint.text`) when a rule fired on this `bash` call; `None`
        /// otherwise. `#[serde(default)]` keeps the restore wire backward-
        /// compatible with rows/peers that predate the hint layer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hint: Option<String>,
    },
    /// Display-only terminal inference failure restored into attach history.
    /// Never enters model-bound rehydration context.
    InferenceError {
        /// `session_events.seq` of this inference-failure timeline row.
        #[serde(default)]
        seq: i64,
        summary: String,
        #[serde(default)]
        detail: String,
    },
    CompactBoundary {
        /// `session_events.seq` of this compaction timeline row.
        #[serde(default)]
        seq: i64,
        predecessor_short_id: String,
        seed_tool_count: usize,
        seed_tool_tokens: u64,
        #[serde(default)]
        source: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trigger_ctx_pct: Option<f64>,
        #[serde(default)]
        tokens_before: u64,
        #[serde(default)]
        tokens_after: u64,
        #[serde(default)]
        turns_summarized: usize,
        #[serde(default)]
        tail_kept: usize,
        #[serde(default)]
        tail_trimmed: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        brief: Option<String>,
        /// Exact handoff (brief + deterministic appendix) installed on wire.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        handoff: Option<String>,
    },
    Subagent {
        /// `session_events.seq` of this subagent-spawn timeline row.
        #[serde(default)]
        seq: i64,
        parent: String,
        child: String,
        task_call_id: String,
        label: String,
    },
}

/// One session's live in-daemon status, from the per-session
/// `ScheduleAuthority` + worker turn-state. Drives the browser's tiers 1-2
/// (GOALS §17f). Only emitted for sessions with a live worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveStatus {
    pub session_id: Uuid,
    /// At least one loop/timer/background job is live.
    pub has_active_schedules: bool,
    /// A turn is in flight (between `ThinkingStarted` and `AgentIdle`).
    pub processing: bool,
}

#[allow(unused_imports)]
pub use cockpit_config::{
    config::extended::{ApprovalMode, LlmMode},
    config::sandbox_mode::SandboxMode,
};

#[allow(unused_imports)]
pub use cockpit_db::wire::{
    CharSpan, CommandDetail, GrantKind, InterruptDecision, InterruptDecisionLine, InterruptOption,
    InterruptQuestion, InterruptQuestionSet, MessageRole, ResolveResponse, SandboxEscalation,
    SessionActivityState, SessionMessage, SessionSummary, WriteContentPreview,
};

pub use cockpit_db::db::session_goals::GoalStatus;
pub use cockpit_db::stats::StatsRollup;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoalSummary {
    pub id: Uuid,
    pub session_id: Uuid,
    pub project_id: String,
    pub objective: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    pub status: GoalStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_budget: Option<i64>,
    pub tokens_used: i64,
    pub blocked_attempts: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_read_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatsRange {
    Last7Days,
    AllTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PausedWorkSummary {
    pub session_id: Uuid,
    pub active_agent: String,
    pub project_root: String,
    pub reason: String,
    pub pending_tool_count: i64,
    pub daemon_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveSubagent {
    pub parent: String,
    pub child: String,
    pub task_call_id: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueItem {
    pub id: Uuid,
    pub status: QueueItemStatus,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_text: Option<String>,
    #[serde(default)]
    pub target: QueueTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TagExpansionMeta {
    pub tool: String,
    pub path: String,
    pub detail: String,
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct QueueTarget {
    pub id: String,
    pub agent: String,
    pub depth: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_call_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueItemStatus {
    Queued,
    Folding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoveQueuedUserMessageReason {
    Removed,
    AlreadyStarted,
    NotFound,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveQueuedUserMessageResult {
    pub applied: bool,
    pub reason: RemoveQueuedUserMessageReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_item: Option<QueueItem>,
    pub queue: Vec<QueueItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveQueuedUserMessagesResult {
    pub applied: bool,
    pub reason: RemoveQueuedUserMessageReason,
    pub removed_items: Vec<QueueItem>,
    pub queue: Vec<QueueItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillSummary {
    pub name: String,
    pub description: String,
    pub source: String,
    pub user_invocable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSummary {
    pub name: String,
    pub description: String,
    pub mode: String,
    pub source: String,
    /// `true` for the built-in cast (`Build`, `builder`,
    /// `explore`, …).
    pub builtin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSummary {
    pub provider: String,
    pub id: String,
    pub display_name: Option<String>,
    pub favorite: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InterruptRaiseReason {
    Initial,
    Advance,
    Rehydration,
}

// ---- Codec -----------------------------------------------------------------

/// NDJSON framed codec over an arbitrary byte stream. Use the same
/// type for both ends — the schema is symmetric, only the legal
/// `Body` variants differ per direction.
pub struct ProtoStream<S> {
    framed: Framed<S, LinesCodec>,
}

impl<S> ProtoStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub fn new(stream: S) -> Self {
        Self {
            framed: Framed::new(stream, LinesCodec::new_with_max_length(MAX_FRAME_BYTES)),
        }
    }

    /// Send one envelope. Serializes to a compact single-line JSON
    /// string and writes a trailing newline (`LinesCodec` adds the
    /// newline).
    pub async fn send(&mut self, env: &Envelope) -> Result<()> {
        let line = serde_json::to_string(env).context("serializing envelope")?;
        self.framed
            .send(line)
            .await
            .map_err(codec_error)
            .context("writing envelope")?;
        Ok(())
    }

    pub async fn send_raw_line(&mut self, line: String) -> Result<()> {
        self.framed
            .send(line)
            .await
            .map_err(codec_error)
            .context("writing raw envelope")?;
        Ok(())
    }

    /// Receive the next frame. Returns `Ok(None)` on clean EOF;
    /// returns `Err` on framing failure (frame too large, invalid UTF-8)
    /// or JSON/header deserialization failure.
    pub async fn recv(&mut self) -> Result<Option<RecvFrame>> {
        match self.framed.next().await {
            None => Ok(None),
            Some(Err(e)) => Err(codec_error(e)).context("reading envelope"),
            Some(Ok(line)) => {
                let value: serde_json::Value =
                    serde_json::from_str(&line).context("deserializing envelope")?;
                let v = value
                    .get("v")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
                    .context("deserializing envelope: missing or invalid v")?;
                if !is_protocol_compatible(v) {
                    let kind = value
                        .get("kind")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let id = value
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .and_then(|raw| Uuid::parse_str(raw).ok());
                    return Ok(Some(RecvFrame::VersionMismatch { v, kind, id }));
                }
                let env: Envelope =
                    serde_json::from_value(value).context("deserializing envelope")?;
                Ok(Some(RecvFrame::Envelope(Box::new(env))))
            }
        }
    }
}

fn codec_error(err: LinesCodecError) -> io::Error {
    match err {
        LinesCodecError::Io(e) => e,
        LinesCodecError::MaxLineLengthExceeded => io::Error::new(
            io::ErrorKind::InvalidData,
            "NDJSON frame exceeded MAX_FRAME_BYTES",
        ),
    }
}

#[cfg(test)]
mod proto_fixture_tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use serde_json::{Map, Value};

    use super::*;

    #[test]
    fn proto_fixture_request_full_shapes_round_trip() {
        assert_enum_fixture::<Request>(
            "request",
            "request.json",
            enum_variant_kinds(include_str!("request.rs"), "Request"),
        );
    }

    #[test]
    fn proto_fixture_response_full_shapes_round_trip() {
        assert_enum_fixture::<Response>(
            "response",
            "response.json",
            enum_variant_kinds(include_str!("response.rs"), "Response"),
        );
    }

    #[test]
    fn proto_fixture_event_full_shapes_round_trip() {
        assert_enum_fixture::<Event>(
            "event",
            "event.json",
            enum_variant_kinds(include_str!("event.rs"), "Event"),
        );
    }

    fn assert_enum_fixture<T>(tag: &str, file_name: &str, expected_kinds: Vec<String>)
    where
        T: DeserializeOwned + Serialize,
    {
        let path = fixture_root().join(file_name);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let fixtures: Map<String, Value> = serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
        let expected = expected_kinds.into_iter().collect::<BTreeSet<_>>();
        let actual = fixtures.keys().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            actual, expected,
            "{file_name} must contain exactly one full-shape fixture per {tag} variant"
        );

        for (kind, value) in fixtures {
            assert_eq!(
                value.get(tag).and_then(Value::as_str),
                Some(kind.as_str()),
                "{file_name}:{kind} must carry its serde tag"
            );
            let parsed: T = serde_json::from_value(value.clone())
                .unwrap_or_else(|error| panic!("deserialize {file_name}:{kind}: {error}"));
            let serialized = serde_json::to_value(parsed)
                .unwrap_or_else(|error| panic!("serialize {file_name}:{kind}: {error}"));
            assert_eq!(
                canonical(serialized),
                canonical(value),
                "{file_name}:{kind} must round-trip byte-equivalent after canonicalization"
            );
        }
    }

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("daemon_proto")
    }

    fn enum_variant_kinds(source: &str, enum_name: &str) -> Vec<String> {
        let mut in_enum = false;
        let mut brace_depth = 0usize;
        let mut out = Vec::new();
        for line in source.lines() {
            let trimmed = line.trim();
            if !in_enum {
                if trimmed == format!("pub enum {enum_name} {{") {
                    in_enum = true;
                    brace_depth = 1;
                }
                continue;
            }

            if brace_depth == 1
                && let Some(first) = trimmed.chars().next()
                && first.is_ascii_uppercase()
            {
                let name = trimmed
                    .split(|c: char| c == ' ' || c == '{' || c == ',')
                    .next()
                    .expect("variant name");
                out.push(to_snake_case(name));
            }

            brace_depth += line.chars().filter(|ch| *ch == '{').count();
            brace_depth = brace_depth.saturating_sub(line.chars().filter(|ch| *ch == '}').count());
            if brace_depth == 0 {
                break;
            }
        }
        out
    }

    fn to_snake_case(name: &str) -> String {
        let mut out = String::new();
        for (index, ch) in name.chars().enumerate() {
            if ch.is_ascii_uppercase() {
                if index > 0 {
                    out.push('_');
                }
                out.push(ch.to_ascii_lowercase());
            } else {
                out.push(ch);
            }
        }
        out
    }

    fn canonical(value: Value) -> Value {
        match value {
            Value::Array(items) => Value::Array(items.into_iter().map(canonical).collect()),
            Value::Object(map) => {
                let mut sorted = Map::new();
                let mut keys = map.keys().cloned().collect::<Vec<_>>();
                keys.sort();
                for key in keys {
                    sorted.insert(key.clone(), canonical(map.get(&key).unwrap().clone()));
                }
                Value::Object(sorted)
            }
            other => other,
        }
    }
}

// ---- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::duplex;

    #[test]
    fn request_round_trip() {
        let env = Envelope::request(
            Uuid::new_v4(),
            Request::SendUserMessage {
                text: "hello".into(),
                display_text: None,
                tag_expansions: Vec::new(),
                image_refs: Vec::new(),
                forced_skill: None,
            },
        );
        let s = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        match back.body {
            Body::Request {
                request: Request::SendUserMessage { text, .. },
                ..
            } => assert_eq!(text, "hello"),
            other => panic!("expected SendUserMessage, got {other:?}"),
        }
    }

    #[test]
    fn send_user_message_serializes_image_refs_not_raw_byte_arrays() {
        let image_ref = ImageAttachmentRef { id: Uuid::new_v4() };
        let env = Envelope::request(
            Uuid::new_v4(),
            Request::SendUserMessage {
                text: IMAGE_PART_SENTINEL.to_string(),
                display_text: None,
                tag_expansions: Vec::new(),
                image_refs: vec![image_ref],
                forced_skill: None,
            },
        );
        let json = serde_json::to_value(&env).unwrap();
        let params = &json["params"];
        assert!(params.get("images").is_none());
        assert!(params["image_refs"].is_array());
        assert!(
            !serde_json::to_string(&params["image_refs"])
                .unwrap()
                .contains("[1,2,3]")
        );
    }

    #[test]
    fn attachment_chunk_frame_stays_below_max_frame_with_headroom() {
        let data_base64 = "A".repeat(MAX_ATTACHMENT_CHUNK_BASE64_BYTES);
        let env = Envelope::request(
            Uuid::new_v4(),
            Request::UploadAttachmentChunk {
                upload_id: Uuid::new_v4(),
                offset: 0,
                data_base64,
            },
        );
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.len() < MAX_FRAME_BYTES / 4);
    }

    #[test]
    fn event_round_trip() {
        let sid = Uuid::new_v4();
        let env = Envelope::event(Event::AssistantTextDelta {
            session_id: sid,
            agent: "builder".into(),
            delta: "patch ".into(),
        });
        let s = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        match back.body {
            Body::Event {
                event:
                    Event::AssistantTextDelta {
                        session_id,
                        agent,
                        delta,
                    },
            } => {
                assert_eq!(session_id, sid);
                assert_eq!(agent, "builder");
                assert_eq!(delta, "patch ");
            }
            other => panic!("expected AssistantTextDelta, got {other:?}"),
        }
    }

    #[test]
    fn error_with_null_id() {
        let env = Envelope::error(
            None,
            ErrorPayload {
                code: ErrorCode::Shutdown,
                message: "daemon shutting down".into(),
            },
        );
        let s = serde_json::to_string(&env).unwrap();
        assert!(s.contains("\"id\":null"));
        let back: Envelope = serde_json::from_str(&s).unwrap();
        assert!(matches!(
            back.body,
            Body::Error {
                id: None,
                error: ErrorPayload {
                    code: ErrorCode::Shutdown,
                    ..
                }
            }
        ));
    }

    #[test]
    fn session_live_status_round_trip() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let env = Envelope::request(
            Uuid::new_v4(),
            Request::SessionLiveStatus {
                session_ids: vec![a, b],
            },
        );
        let s = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        match back.body {
            Body::Request {
                request: Request::SessionLiveStatus { session_ids },
                ..
            } => assert_eq!(session_ids, vec![a, b]),
            other => panic!("expected SessionLiveStatus, got {other:?}"),
        }

        // Response side.
        let res = Envelope::response(
            Uuid::new_v4(),
            Response::SessionLiveStatus {
                statuses: vec![LiveStatus {
                    session_id: a,
                    has_active_schedules: true,
                    processing: false,
                }],
            },
        );
        let s = serde_json::to_string(&res).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        match back.body {
            Body::Response { response, .. } => match *response {
                Response::SessionLiveStatus { statuses } => {
                    assert_eq!(statuses.len(), 1);
                    assert!(statuses[0].has_active_schedules);
                    assert!(!statuses[0].processing);
                }
                other => panic!("expected SessionLiveStatus response, got {other:?}"),
            },
            other => panic!("expected SessionLiveStatus response, got {other:?}"),
        }
    }

    #[test]
    fn set_caffeinate_round_trip() {
        use super::CaffeinateMode;

        // Request side: each mode survives the wire.
        for mode in [
            CaffeinateMode::Toggle,
            CaffeinateMode::On,
            CaffeinateMode::Off,
            CaffeinateMode::UntilIdle,
        ] {
            let env = Envelope::request(Uuid::new_v4(), Request::SetCaffeinate { mode });
            let s = serde_json::to_string(&env).unwrap();
            let back: Envelope = serde_json::from_str(&s).unwrap();
            match back.body {
                Body::Request {
                    request: Request::SetCaffeinate { mode: got },
                    ..
                } => assert_eq!(got, mode),
                other => panic!("expected SetCaffeinate, got {other:?}"),
            }
        }
        // `until-idle` serializes as snake_case `until_idle`.
        let env = Envelope::request(
            Uuid::new_v4(),
            Request::SetCaffeinate {
                mode: CaffeinateMode::UntilIdle,
            },
        );
        let v: Value = serde_json::from_str(&serde_json::to_string(&env).unwrap()).unwrap();
        assert_eq!(v["params"]["mode"], json!("until_idle"));

        // Response side carries the honest message + lid-close flag.
        let res = Envelope::response(
            Uuid::new_v4(),
            Response::CaffeinateState {
                active: true,
                lid_close_guaranteed: false,
                message: "caffeinate on — note: lid-close not guaranteed".into(),
            },
        );
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&res).unwrap()).unwrap();
        match back.body {
            Body::Response { response, .. } => match *response {
                Response::CaffeinateState {
                    active,
                    lid_close_guaranteed,
                    message,
                } => {
                    assert!(active);
                    assert!(!lid_close_guaranteed);
                    assert!(message.contains("note:"));
                }
                other => panic!("expected CaffeinateState response, got {other:?}"),
            },
            other => panic!("expected CaffeinateState response, got {other:?}"),
        }

        // Event side is the daemon-global broadcast (no session_id, no
        // message for non-originating clients).
        let evt = Envelope::event(Event::CaffeinateState {
            active: false,
            lid_close_guaranteed: false,
            message: None,
        });
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&evt).unwrap()).unwrap();
        match back.body {
            Body::Event {
                event:
                    Event::CaffeinateState {
                        active, message, ..
                    },
            } => {
                assert!(!active);
                assert!(message.is_none());
            }
            other => panic!("expected CaffeinateState event, got {other:?}"),
        }
    }

    /// The `WaitingForLock` event (`readlock-wait-and-lock-expiry.md`) is a
    /// per-session transient: it carries `session_id`, the contended `path`,
    /// the `holder_agent`, and the `waiting` start/clear flag, and survives a
    /// wire roundtrip intact.
    #[test]
    fn waiting_for_lock_event_roundtrips() {
        let sid = Uuid::new_v4();
        let evt = Envelope::event(Event::WaitingForLock {
            session_id: sid,
            path: "/repo/src/main.rs".to_string(),
            holder_agent: "builder".to_string(),
            waiting: true,
        });
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&evt).unwrap()).unwrap();
        match back.body {
            Body::Event {
                event:
                    Event::WaitingForLock {
                        session_id,
                        path,
                        holder_agent,
                        waiting,
                    },
            } => {
                assert_eq!(session_id, sid);
                assert_eq!(path, "/repo/src/main.rs");
                assert_eq!(holder_agent, "builder");
                assert!(waiting);
            }
            other => panic!("expected WaitingForLock event, got {other:?}"),
        }
    }

    #[test]
    fn sandbox_unavailable_event_round_trips_with_remedy() {
        // §6.5: the user-facing sandbox-down broadcast carries the session_id
        // and the diagnosed remedy verbatim across the wire.
        let sid = Uuid::new_v4();
        let remedy = "unprivileged user namespaces are restricted by AppArmor (Ubuntu 23.10+); \
             `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` re-enables confinement";
        let evt = Envelope::event(Event::SandboxUnavailable {
            session_id: sid,
            remedy: remedy.into(),
            fix_command: Some(
                "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0".to_string(),
            ),
        });
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&evt).unwrap()).unwrap();
        match back.body {
            Body::Event {
                event:
                    Event::SandboxUnavailable {
                        session_id,
                        remedy: r,
                        fix_command,
                    },
            } => {
                assert_eq!(session_id, sid);
                assert_eq!(r, remedy);
                assert_eq!(
                    fix_command.as_deref(),
                    Some("sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0")
                );
            }
            other => panic!("expected SandboxUnavailable event, got {other:?}"),
        }
    }

    #[test]
    fn interrupt_question_serializes_as_tagged() {
        let q = InterruptQuestion::Single {
            prompt: "Backfill strategy?".into(),
            options: vec![
                InterruptOption {
                    id: "now".into(),
                    label: "Backfill now".into(),
                    description: None,
                    secondary: false,
                },
                InterruptOption {
                    id: "later".into(),
                    label: "Defer".into(),
                    description: None,
                    secondary: false,
                },
            ],
            allow_freetext: true,
            command_detail: None,
            permission: false,
            approval_class: None,
            sandbox_escalation: None,
        };
        let s = serde_json::to_string(&q).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["kind"], json!("single"));
        assert_eq!(v["data"]["options"].as_array().unwrap().len(), 2);
        // A `None` command_detail is omitted from the wire (back-compat).
        assert!(v["data"].get("command_detail").is_none());
        // A `false` permission is omitted (back-compat: un-annotated `Single`
        // is a question).
        assert!(v["data"].get("permission").is_none());
    }

    #[test]
    fn permission_flag_round_trips_and_is_additive() {
        // A permission `Single` serializes the flag; a legacy shape (no
        // `permission` key) deserializes to `false` (a question).
        let q = InterruptQuestion::Single {
            prompt: "Run `cargo build`?".into(),
            options: vec![InterruptOption {
                id: "once".into(),
                label: "Yes, once".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: None,
            sandbox_escalation: None,
        };
        let s = serde_json::to_string(&q).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["data"]["permission"], json!(true));
        let back: InterruptQuestion = serde_json::from_str(&s).unwrap();
        match back {
            InterruptQuestion::Single { permission, .. } => assert!(permission),
            other => panic!("expected Single, got {other:?}"),
        }
        // Legacy shape (no `permission` field) deserializes to `false`.
        let legacy = json!({
            "kind": "single",
            "data": { "prompt": "?", "options": [], "allow_freetext": false }
        });
        let back: InterruptQuestion = serde_json::from_value(legacy).unwrap();
        match back {
            InterruptQuestion::Single { permission, .. } => assert!(!permission),
            other => panic!("expected Single, got {other:?}"),
        }
    }

    #[test]
    fn command_detail_round_trips_and_is_additive() {
        // A populated command_detail survives the wire and an old-shape
        // `Single` (no command_detail key) still deserializes.
        let q = InterruptQuestion::Single {
            prompt: "Run `cargo build`?".into(),
            options: vec![InterruptOption {
                id: "once".into(),
                label: "Yes, once".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            permission: true,
            approval_class: None,
            sandbox_escalation: None,
            command_detail: Some(Box::new(CommandDetail {
                full_command: "git push && cargo build".into(),
                highlight: Some(CharSpan { start: 11, end: 22 }),
                step: 2,
                step_count: 2,
                cwd: None,
                remembered_key: None,
                write_content: None,
                risk_tier: None,
                risk_reasons: Vec::new(),
                affected_targets: Vec::new(),
                native_tool_hints: Vec::new(),
                offered_scopes: Vec::new(),
                policy_cap: None,
            })),
        };
        let s = serde_json::to_string(&q).unwrap();
        let back: InterruptQuestion = serde_json::from_str(&s).unwrap();
        match back {
            InterruptQuestion::Single { command_detail, .. } => {
                let cd = command_detail.expect("command_detail survives");
                assert_eq!(cd.full_command, "git push && cargo build");
                assert_eq!(cd.highlight, Some(CharSpan { start: 11, end: 22 }));
                assert_eq!((cd.step, cd.step_count), (2, 2));
            }
            other => panic!("expected Single, got {other:?}"),
        }

        // Legacy shape (no command_detail field) deserializes to `None`.
        let legacy = json!({
            "kind": "single",
            "data": {
                "prompt": "Run `ls`?",
                "options": [{ "id": "once", "label": "Yes, once" }],
                "allow_freetext": false
            }
        });
        let back: InterruptQuestion = serde_json::from_value(legacy).unwrap();
        match back {
            InterruptQuestion::Single { command_detail, .. } => {
                assert!(command_detail.is_none());
            }
            other => panic!("expected Single, got {other:?}"),
        }
    }

    #[test]
    fn sandbox_escalation_round_trips_and_is_additive() {
        // A populated sandbox_escalation survives the wire; an old-shape
        // `Single` (no key) deserializes to `None` (a first-time approval).
        let q = InterruptQuestion::Single {
            prompt: "Re-run `cargo test` without the sandbox?".into(),
            options: vec![InterruptOption {
                id: "once".into(),
                label: "Yes, once".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            permission: true,
            approval_class: None,
            command_detail: None,
            sandbox_escalation: Some(SandboxEscalation {
                confined_exit: 101,
                confined_stderr: "permission denied".into(),
                suggested_paths: vec!["/var/cache/tool".into()],
                suggested_access: Some("read-write".into()),
            }),
        };
        let s = serde_json::to_string(&q).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["data"]["sandbox_escalation"]["confined_exit"], json!(101));
        assert_eq!(
            v["data"]["sandbox_escalation"]["suggested_paths"],
            json!(["/var/cache/tool"])
        );
        assert_eq!(
            v["data"]["sandbox_escalation"]["suggested_access"],
            json!("read-write")
        );
        let back: InterruptQuestion = serde_json::from_str(&s).unwrap();
        match back {
            InterruptQuestion::Single {
                sandbox_escalation, ..
            } => {
                let esc = sandbox_escalation.expect("sandbox_escalation survives");
                assert_eq!(esc.confined_exit, 101);
                assert_eq!(esc.confined_stderr, "permission denied");
                assert_eq!(esc.suggested_paths, vec!["/var/cache/tool"]);
                assert_eq!(esc.suggested_access.as_deref(), Some("read-write"));
            }
            other => panic!("expected Single, got {other:?}"),
        }

        // Legacy shape (no sandbox_escalation field) → None (first-time).
        let legacy = json!({
            "kind": "single",
            "data": {
                "prompt": "Run `ls`?",
                "options": [{ "id": "once", "label": "Yes, once" }],
                "allow_freetext": false
            }
        });
        let back: InterruptQuestion = serde_json::from_value(legacy).unwrap();
        match back {
            InterruptQuestion::Single {
                sandbox_escalation, ..
            } => assert!(sandbox_escalation.is_none()),
            other => panic!("expected Single, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn codec_round_trip_over_duplex() {
        let (a, b) = duplex(64 * 1024);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);

        let id = Uuid::new_v4();
        let out = Envelope::request(id, Request::DaemonStatus);
        left.send(&out).await.unwrap();

        let got = right.recv().await.unwrap().expect("EOF unexpected");
        let RecvFrame::Envelope(got) = got else {
            panic!("expected envelope, got {got:?}");
        };
        match got.body {
            Body::Request {
                id: got_id,
                request: Request::DaemonStatus,
            } => assert_eq!(got_id, id),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn queued_user_message_wire_shapes_round_trip() {
        let session_id = Uuid::new_v4();
        let item_id = Uuid::new_v4();
        let item = QueueItem {
            id: item_id,
            status: QueueItemStatus::Queued,
            text: "queued text".to_string(),
            display_text: Some("queued @file".to_string()),
            target: QueueTarget {
                id: "root".to_string(),
                agent: "Build".to_string(),
                depth: 0,
                task_call_id: None,
            },
        };

        let response = Envelope::response(
            Uuid::new_v4(),
            Response::UserMessageQueued {
                item: item.clone(),
                queue: vec![item.clone()],
            },
        );
        let back: Envelope =
            serde_json::from_str(&serde_json::to_string(&response).unwrap()).unwrap();
        match back.body {
            Body::Response { response, .. } => match *response {
                Response::UserMessageQueued { item: got, queue } => {
                    assert_eq!(got.id, item_id);
                    assert_eq!(got.status, QueueItemStatus::Queued);
                    assert_eq!(got.display_text.as_deref(), Some("queued @file"));
                    assert_eq!(got.target.id, "root");
                    assert_eq!(queue.len(), 1);
                }
                other => panic!("unexpected response: {other:?}"),
            },
            other => panic!("unexpected response: {other:?}"),
        }

        let event = Envelope::event(Event::QueueUpdated {
            session_id,
            queue: vec![item.clone()],
        });
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        match back.body {
            Body::Event {
                event:
                    Event::QueueUpdated {
                        session_id: got_session,
                        queue,
                    },
            } => {
                assert_eq!(got_session, session_id);
                assert_eq!(queue[0].id, item_id);
                assert_eq!(queue[0].target.agent, "Build");
            }
            other => panic!("unexpected event: {other:?}"),
        }

        let event = Envelope::event(Event::ForegroundInputTarget {
            session_id,
            target: QueueTarget {
                id: "task:call-1:default".to_string(),
                agent: "Explore".to_string(),
                depth: 1,
                task_call_id: Some("call-1".to_string()),
            },
        });
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        match back.body {
            Body::Event {
                event:
                    Event::ForegroundInputTarget {
                        session_id: got_session,
                        target,
                    },
            } => {
                assert_eq!(got_session, session_id);
                assert_eq!(target.id, "task:call-1:default");
                assert_eq!(target.agent, "Explore");
                assert_eq!(target.task_call_id.as_deref(), Some("call-1"));
            }
            other => panic!("unexpected foreground event: {other:?}"),
        }

        let request = Envelope::request(
            Uuid::new_v4(),
            Request::RemoveQueuedUserMessage {
                queue_item_id: item_id,
            },
        );
        let back: Envelope =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        match back.body {
            Body::Request {
                request: Request::RemoveQueuedUserMessage { queue_item_id },
                ..
            } => assert_eq!(queue_item_id, item_id),
            other => panic!("unexpected request: {other:?}"),
        }

        let request = Envelope::request(
            Uuid::new_v4(),
            Request::RemoveNewestQueuedUserMessage {
                target_id: Some("root".to_string()),
            },
        );
        let back: Envelope =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        match back.body {
            Body::Request {
                request: Request::RemoveNewestQueuedUserMessage { target_id },
                ..
            } => assert_eq!(target_id.as_deref(), Some("root")),
            other => panic!("unexpected request: {other:?}"),
        }

        let request = Envelope::request(
            Uuid::new_v4(),
            Request::RemoveEditableQueuedUserMessages {
                target_id: Some("root".to_string()),
            },
        );
        let back: Envelope =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        match back.body {
            Body::Request {
                request: Request::RemoveEditableQueuedUserMessages { target_id },
                ..
            } => assert_eq!(target_id.as_deref(), Some("root")),
            other => panic!("unexpected request: {other:?}"),
        }

        let response = Envelope::response(
            Uuid::new_v4(),
            Response::RemoveQueuedUserMessagesResult {
                applied: true,
                reason: RemoveQueuedUserMessageReason::Removed,
                removed_items: vec![item.clone()],
                queue: Vec::new(),
            },
        );
        let back: Envelope =
            serde_json::from_str(&serde_json::to_string(&response).unwrap()).unwrap();
        match back.body {
            Body::Response { response, .. } => match *response {
                Response::RemoveQueuedUserMessagesResult {
                    applied,
                    reason,
                    removed_items,
                    queue,
                } => {
                    assert!(applied);
                    assert_eq!(reason, RemoveQueuedUserMessageReason::Removed);
                    assert_eq!(removed_items[0].id, item_id);
                    assert!(queue.is_empty());
                }
                other => panic!("unexpected response: {other:?}"),
            },
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    #[tokio::test]
    async fn recv_salvages_out_of_range_request() {
        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);

        // Bypass the helper to inject a bad version.
        let id = Uuid::new_v4();
        let bad = serde_json::json!({
            "v": 999,
            "kind": "req",
            "id": id,
            "request": "daemon_status",
            "params": null,
        });
        let line = serde_json::to_string(&bad).unwrap();
        left.framed.send(line).await.unwrap();
        match right.recv().await.unwrap().expect("frame") {
            RecvFrame::VersionMismatch {
                v,
                kind,
                id: got_id,
            } => {
                assert_eq!(v, 999);
                assert_eq!(kind, "req");
                assert_eq!(got_id, Some(id));
            }
            other => panic!("expected version mismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn recv_salvages_out_of_range_event_without_id() {
        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);

        let bad = serde_json::json!({
            "v": 999,
            "kind": "evt",
            "event": "notice",
            "data": { "message": "hi" },
        });
        left.framed
            .send(serde_json::to_string(&bad).unwrap())
            .await
            .unwrap();
        match right.recv().await.unwrap().expect("frame") {
            RecvFrame::VersionMismatch { v, kind, id } => {
                assert_eq!(v, 999);
                assert_eq!(kind, "evt");
                assert_eq!(id, None);
            }
            other => panic!("expected version mismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn recv_rejects_non_object_and_missing_v() {
        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);

        left.framed.send("[]".to_string()).await.unwrap();
        assert!(right.recv().await.is_err());

        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);
        left.framed
            .send(r#"{"kind":"req","request":"daemon_status"}"#.to_string())
            .await
            .unwrap();
        assert!(right.recv().await.is_err());
    }

    #[test]
    fn is_protocol_compatible_window() {
        assert!(is_protocol_compatible(MIN_SUPPORTED_PROTOCOL_VERSION));
        assert!(is_protocol_compatible(PROTOCOL_VERSION));
        assert!(!is_protocol_compatible(PROTOCOL_VERSION + 1));
        if MIN_SUPPORTED_PROTOCOL_VERSION > 0 {
            assert!(!is_protocol_compatible(MIN_SUPPORTED_PROTOCOL_VERSION - 1));
        }
    }
}
