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
use serde_json::{Value, json};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio_util::codec::{Framed, FramedRead, FramedWrite, LinesCodec, LinesCodecError};
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
    Error { class: InferenceErrorClass },
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

/// Current wire schema version.
///
/// Additive wire changes, including new request/response/event variants and
/// new fields carrying `#[serde(default)]`, bump only this value: older peers
/// keep the connection open and degrade feature-by-feature. Breaking changes
/// such as removals, renames, and type changes bump
/// [`MIN_SUPPORTED_PROTOCOL_VERSION`] and are the only class that narrows the
/// compatibility window.
pub const PROTOCOL_VERSION: u32 = 2;

/// Oldest wire schema version this binary accepts.
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 1;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonHello {
    pub daemon_version: String,
    pub protocol_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedProtocol {
    pub version: u32,
    pub daemon_version: String,
    pub daemon_protocol_version: u32,
}

impl NegotiatedProtocol {
    pub fn current() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            daemon_version: "unknown".to_string(),
            daemon_protocol_version: PROTOCOL_VERSION,
        }
    }

    pub fn from_hello(hello: &DaemonHello) -> std::result::Result<Self, ErrorPayload> {
        let version = PROTOCOL_VERSION.min(hello.protocol_version);
        if version < MIN_SUPPORTED_PROTOCOL_VERSION {
            return Err(ErrorPayload {
                code: ErrorCode::ProtocolVersion,
                message: incompatible_daemon_protocol_message(hello.protocol_version),
            });
        }
        Ok(Self {
            version,
            daemon_version: hello.daemon_version.clone(),
            daemon_protocol_version: hello.protocol_version,
        })
    }
}

pub fn incompatible_daemon_protocol_message(daemon_protocol_version: u32) -> String {
    format!(
        "daemon speaks protocol v{daemon_protocol_version}; this client supports v{}..=v{}. run `cockpit daemon restart`",
        MIN_SUPPORTED_PROTOCOL_VERSION, PROTOCOL_VERSION
    )
}

pub fn daemon_hello_from_envelope(env: &Envelope) -> Option<DaemonHello> {
    let Body::Response { id, response } = &env.body else {
        return None;
    };
    if !id.is_nil() {
        return None;
    }
    let Response::DaemonStatus {
        daemon_version,
        protocol_version,
        ..
    } = response.as_ref()
    else {
        return None;
    };
    Some(DaemonHello {
        daemon_version: daemon_version.clone(),
        protocol_version: *protocol_version,
    })
}

pub fn parse_daemon_hello_line(line: &str) -> Result<Option<DaemonHello>> {
    let env: Envelope = serde_json::from_str(line).context("deserializing daemon hello")?;
    Ok(daemon_hello_from_envelope(&env))
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
    Unknown {
        v: u32,
        kind: String,
        tag: Option<String>,
        id: Option<Uuid>,
    },
    VersionMismatch {
        v: u32,
        kind: String,
        id: Option<Uuid>,
    },
}

impl Envelope {
    pub fn request(id: Uuid, request: Request) -> Self {
        Self::request_at(PROTOCOL_VERSION, id, request)
    }

    pub fn request_at(v: u32, id: Uuid, request: Request) -> Self {
        Self {
            v,
            body: Body::Request { id, request },
        }
    }

    pub fn response(id: Uuid, response: Response) -> Self {
        Self::response_at(PROTOCOL_VERSION, id, response)
    }

    pub fn response_at(v: u32, id: Uuid, response: Response) -> Self {
        Self {
            v,
            body: Body::Response {
                id,
                response: Box::new(response),
            },
        }
    }

    pub fn event(event: Event) -> Self {
        Self::event_at(PROTOCOL_VERSION, event)
    }

    pub fn event_at(v: u32, event: Event) -> Self {
        Self {
            v,
            body: Body::Event { event },
        }
    }

    pub fn error(id: Option<Uuid>, error: ErrorPayload) -> Self {
        Self::error_at(PROTOCOL_VERSION, id, error)
    }

    pub fn error_at(v: u32, id: Option<Uuid>, error: ErrorPayload) -> Self {
        Self {
            v,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<Uuid>,
        error: ErrorPayload,
    },
    #[serde(other)]
    Unknown,
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
pub use event::{AuthFailureKind, Event, InferenceErrorClass};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    /// Request payload didn't parse / failed validation.
    BadRequest,
    /// Daemon doesn't speak this protocol version.
    ProtocolVersion,
    /// Peer sent a request variant this daemon does not know.
    UnsupportedRequest,
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
    /// Error code from a future peer that this binary does not know yet.
    Other(String),
}

impl Serialize for ErrorCode {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(match raw.as_str() {
            "bad_request" => Self::BadRequest,
            "protocol_version" => Self::ProtocolVersion,
            "unsupported_request" => Self::UnsupportedRequest,
            "not_attached" => Self::NotAttached,
            "unknown_session" => Self::UnknownSession,
            "unknown_interrupt" => Self::UnknownInterrupt,
            "shutdown" => Self::Shutdown,
            "authorization" => Self::Authorization,
            "read_only" => Self::ReadOnly,
            "root_missing" => Self::RootMissing,
            "path_outside_root" => Self::PathOutsideRoot,
            "hash_mismatch" => Self::HashMismatch,
            "lock_conflict" => Self::LockConflict,
            "workspace_trust" => Self::WorkspaceTrust,
            "internal" => Self::Internal,
            _ => Self::Other(raw),
        })
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::BadRequest => "bad_request",
            Self::ProtocolVersion => "protocol_version",
            Self::UnsupportedRequest => "unsupported_request",
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
            Self::Other(raw) => raw,
        };
        f.write_str(s)
    }
}

pub fn unsupported_request_error(v: u32, tag: Option<&str>) -> ErrorPayload {
    let tag = tag.unwrap_or("unknown");
    ErrorPayload {
        code: ErrorCode::UnsupportedRequest,
        message: format!(
            "unsupported request \"{tag}\" in protocol v{v}; this daemon speaks v{PROTOCOL_VERSION}"
        ),
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
    /// Display-only `/note` transcript annotation restored into attach/export
    /// history. It never enters model-bound rehydration context.
    UserNote {
        text: String,
        #[serde(default)]
        ts_ms: i64,
        #[serde(default)]
        seq: i64,
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
    InterruptQuestion, InterruptQuestionSet, MessageRole, ResolveResponse, SandboxDenialConfidence,
    SandboxDenialEvidence, SandboxDenialReport, SandboxEscalation, SessionActivityState,
    SessionMessage, SessionSummary, WriteContentPreview,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssistantSummary {
    pub name: String,
    pub created_at: i64,
    pub home_dir: String,
    pub config_json: String,
    pub content_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssistantSessionCreated {
    pub session_id: Uuid,
    pub short_id: String,
    pub project_root: String,
    pub project_id: String,
    pub assistant_name: String,
    pub active_agent: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportSessionKind {
    TranscriptJson,
    DebugBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportSessionData {
    pub session_id: Uuid,
    pub kind: ExportSessionKind,
    pub filename_extension: String,
    pub mime: String,
    pub content_base64: String,
    pub byte_len: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_count: Option<usize>,
    #[serde(default)]
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum CuratorAction {
    Status,
    Run {
        #[serde(default)]
        dry_run: bool,
        #[serde(default)]
        consolidate: bool,
    },
    Pin {
        name: String,
    },
    Unpin {
        name: String,
    },
    Restore {
        name: String,
    },
    Rollback {
        #[serde(default)]
        list: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CuratorResult {
    Status {
        status: CuratorStatus,
    },
    Run {
        report: CuratorRunReport,
    },
    Pinned {
        name: String,
        pinned: bool,
    },
    Restored {
        name: String,
    },
    Snapshots {
        snapshots: Vec<CuratorSnapshotStatus>,
    },
    RolledBack {
        snapshot: CuratorSnapshotStatus,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CuratorRunReport {
    pub dry_run: bool,
    pub scanned: usize,
    pub stale: Vec<String>,
    pub archived: Vec<String>,
    pub reactivated: Vec<String>,
    pub skipped: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consolidation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CuratorStatus {
    pub skills: Vec<CuratorSkillStatus>,
    pub snapshots: Vec<CuratorSnapshotStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CuratorSkillStatus {
    pub name: String,
    pub state: String,
    pub created_by: String,
    pub use_count: u64,
    pub view_count: u64,
    pub pinned: bool,
    pub source_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CuratorSnapshotStatus {
    pub id: String,
    pub path: String,
    pub reason: String,
    pub created_at: i64,
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
    version: u32,
}

impl<S> ProtoStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub fn new(stream: S) -> Self {
        Self::with_version(stream, PROTOCOL_VERSION)
    }

    pub fn with_version(stream: S, version: u32) -> Self {
        Self {
            framed: Framed::new(stream, LinesCodec::new_with_max_length(MAX_FRAME_BYTES)),
            version,
        }
    }

    pub fn into_split(self) -> (ProtoReadHalf<ReadHalf<S>>, ProtoWriteHalf<WriteHalf<S>>) {
        let version = self.version;
        let (read, write) = tokio::io::split(self.framed.into_inner());
        (
            ProtoReadHalf {
                framed: FramedRead::new(read, LinesCodec::new_with_max_length(MAX_FRAME_BYTES)),
            },
            ProtoWriteHalf {
                framed: FramedWrite::new(write, LinesCodec::new_with_max_length(MAX_FRAME_BYTES)),
                version,
            },
        )
    }

    pub fn negotiated_version(&self) -> u32 {
        self.version
    }

    pub fn set_negotiated_version(&mut self, version: u32) {
        self.version = version;
    }

    /// Send one envelope. Serializes to a compact single-line JSON
    /// string and writes a trailing newline (`LinesCodec` adds the
    /// newline).
    pub async fn send(&mut self, env: &Envelope) -> Result<()> {
        let mut env = env.clone();
        env.v = self.version;
        let line = serde_json::to_string(&env).context("serializing envelope")?;
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

    pub async fn recv(&mut self) -> Result<Option<RecvFrame>> {
        recv_frame(&mut self.framed).await
    }

    pub async fn recv_raw_line(&mut self) -> Result<Option<String>> {
        recv_raw_line(&mut self.framed).await
    }
}

pub struct ProtoReadHalf<R> {
    framed: FramedRead<R, LinesCodec>,
}

impl<R> ProtoReadHalf<R>
where
    R: AsyncRead + Unpin,
{
    /// Receive the next frame. Returns `Ok(None)` on clean EOF;
    /// returns `Err` on framing failure (frame too large, invalid UTF-8)
    /// or JSON/header deserialization failure.
    pub async fn recv(&mut self) -> Result<Option<RecvFrame>> {
        recv_frame(&mut self.framed).await
    }
}

pub struct ProtoWriteHalf<W> {
    framed: FramedWrite<W, LinesCodec>,
    version: u32,
}

impl<W> ProtoWriteHalf<W>
where
    W: AsyncWrite + Unpin,
{
    pub fn set_negotiated_version(&mut self, version: u32) {
        self.version = version;
    }

    /// Send one envelope. Serializes to a compact single-line JSON
    /// string and writes a trailing newline (`LinesCodec` adds the
    /// newline).
    pub async fn send(&mut self, env: &Envelope) -> Result<()> {
        let mut env = env.clone();
        env.v = self.version;
        let line = serde_json::to_string(&env).context("serializing envelope")?;
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
}

async fn recv_raw_line<T>(framed: &mut T) -> Result<Option<String>>
where
    T: futures::Stream<Item = std::result::Result<String, LinesCodecError>> + Unpin,
{
    match framed.next().await {
        None => Ok(None),
        Some(Err(e)) => Err(codec_error(e)).context("reading envelope"),
        Some(Ok(line)) => Ok(Some(line)),
    }
}

async fn recv_frame<T>(framed: &mut T) -> Result<Option<RecvFrame>>
where
    T: futures::Stream<Item = std::result::Result<String, LinesCodecError>> + Unpin,
{
    match recv_raw_line(framed).await? {
        None => Ok(None),
        Some(line) => {
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
            let kind = value
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            let tag = unknown_variant_tag(&value);
            let id = value
                .get("id")
                .and_then(serde_json::Value::as_str)
                .and_then(|raw| Uuid::parse_str(raw).ok());
            if payload_tag_is_unknown(&kind, tag.as_deref()) {
                return Ok(Some(RecvFrame::Unknown { v, kind, tag, id }));
            }
            let env: Envelope = serde_json::from_value(value).context("deserializing envelope")?;
            if envelope_contains_unknown(&env) {
                return Ok(Some(RecvFrame::Unknown { v, kind, tag, id }));
            }
            Ok(Some(RecvFrame::Envelope(Box::new(env))))
        }
    }
}

fn unknown_variant_tag(value: &serde_json::Value) -> Option<String> {
    for key in ["request", "response", "event"] {
        if let Some(tag) = value.get(key).and_then(serde_json::Value::as_str) {
            return Some(tag.to_string());
        }
    }
    if let Some(tag) = value
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(serde_json::Value::as_str)
    {
        return Some(tag.to_string());
    }
    None
}

fn payload_tag_is_unknown(kind: &str, tag: Option<&str>) -> bool {
    let Some(tag) = tag else {
        return false;
    };
    match kind {
        "req" => serde_json::from_value::<Request>(json!({ "request": tag }))
            .is_ok_and(|request| matches!(request, Request::Unknown)),
        "res" => serde_json::from_value::<Response>(json!({ "response": tag }))
            .is_ok_and(|response| matches!(response, Response::Unknown)),
        "evt" => serde_json::from_value::<Event>(json!({ "event": tag }))
            .is_ok_and(|event| matches!(event, Event::Unknown)),
        "err" => serde_json::from_value::<ErrorCode>(json!(tag))
            .is_ok_and(|code| matches!(code, ErrorCode::Other(_))),
        _ => false,
    }
}

fn envelope_contains_unknown(env: &Envelope) -> bool {
    match &env.body {
        Body::Request { request, .. } => matches!(request, Request::Unknown),
        Body::Response { response, .. } => matches!(**response, Response::Unknown),
        Body::Event { event } => matches!(event, Event::Unknown),
        Body::Error { error, .. } => matches!(error.code, ErrorCode::Other(_)),
        Body::Unknown => true,
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
    //! Fixture release ritual: when `PROTOCOL_VERSION` is bumped, copy the
    //! current `vN/` directory to `vN+1/` and let the strict tests re-point to
    //! the new current version. Never edit a frozen `v*/` directory.

    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use serde_json::{Map, Value};

    use super::*;

    const UNKNOWN_SENTINEL: &str = "__unknown";
    const RELEASED_PROTOCOL_VERSIONS: &[u32] = &[1, 2];
    const DAEMON_PROTO_FIXTURE_FILES: &[&str] = &["event.json", "request.json", "response.json"];

    #[test]
    fn proto_fixture_request_full_shapes_round_trip() {
        assert_enum_fixture::<Request>(
            "request",
            "request.json",
            fixture_expected_kinds(request_variant_tags()),
        );
    }

    #[test]
    fn proto_fixture_response_full_shapes_round_trip() {
        assert_enum_fixture::<Response>(
            "response",
            "response.json",
            fixture_expected_kinds(response_variant_tags()),
        );
    }

    #[test]
    fn proto_fixture_event_full_shapes_round_trip() {
        assert_enum_fixture::<Event>(
            "event",
            "event.json",
            fixture_expected_kinds(event_variant_tags()),
        );
    }

    #[test]
    fn wire_tag_matches_serde_tag_for_every_request_fixture() {
        assert_fixture_wire_tags::<Request>("request", "request.json", Request::wire_tag);
    }

    #[test]
    fn wire_tag_matches_serde_tag_for_every_response_fixture() {
        assert_fixture_wire_tags::<Response>("response", "response.json", Response::wire_tag);
    }

    #[test]
    fn wire_tag_matches_serde_tag_for_every_event_fixture() {
        assert_fixture_wire_tags::<Event>("event", "event.json", Event::wire_tag);
    }

    #[test]
    fn wire_tag_unknown_sentinel_appears_once_per_enum_and_is_never_a_fixture_key() {
        for (name, file_name, tags) in [
            ("request", "request.json", request_variant_tags()),
            ("response", "response.json", response_variant_tags()),
            ("event", "event.json", event_variant_tags()),
        ] {
            assert_eq!(
                tags.iter().filter(|tag| **tag == UNKNOWN_SENTINEL).count(),
                1,
                "{name} table must contain exactly one unknown sentinel"
            );
            let fixture_keys = read_fixture(file_name)
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>();
            assert!(
                !fixture_keys.contains(UNKNOWN_SENTINEL),
                "{name} fixture must not include the unknown sentinel"
            );
        }
    }

    #[test]
    fn frozen_fixture_every_released_version_still_deserializes() {
        for version in RELEASED_PROTOCOL_VERSIONS {
            assert_frozen_fixture_deserializes::<Request>(*version, "request.json");
            assert_frozen_fixture_deserializes::<Response>(*version, "response.json");
            assert_frozen_fixture_deserializes::<Event>(*version, "event.json");
        }
    }

    #[test]
    fn frozen_fixture_released_version_list_matches_directories() {
        let listed = RELEASED_PROTOCOL_VERSIONS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        assert!(
            !listed.is_empty(),
            "released protocol version list is empty"
        );
        let directories = released_fixture_directories();
        assert!(
            !directories.is_empty(),
            "daemon_proto has no v*/ fixture directories"
        );
        assert_eq!(
            directories, listed,
            "released protocol version list must match daemon_proto/v*/ directories"
        );
        for version in listed {
            assert_fixture_directory_files(version);
        }
    }

    #[test]
    fn frozen_fixture_current_version_directory_exists() {
        assert!(
            RELEASED_PROTOCOL_VERSIONS.contains(&PROTOCOL_VERSION),
            "current protocol v{PROTOCOL_VERSION} must be listed as released"
        );
        let root = fixture_root_for(PROTOCOL_VERSION);
        assert!(
            root.is_dir(),
            "current protocol fixture directory must exist: {}",
            root.display()
        );
    }

    fn assert_enum_fixture<T>(tag: &str, file_name: &str, expected_kinds: Vec<String>)
    where
        T: DeserializeOwned + Serialize,
    {
        let fixtures = read_fixture(file_name);
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

    fn assert_frozen_fixture_deserializes<T>(version: u32, file_name: &str)
    where
        T: DeserializeOwned,
    {
        for (kind, value) in read_fixture_for(version, file_name) {
            let _: T = serde_json::from_value(value).unwrap_or_else(|error| {
                panic!(
                    "frozen fixture v{version}/{file_name}:{kind} no longer deserializes — this is a breaking wire change; bump MIN_SUPPORTED_PROTOCOL_VERSION deliberately or restore compatibility: {error}"
                )
            });
        }
    }

    fn assert_fixture_wire_tags<T>(
        tag: &str,
        file_name: &str,
        wire_tag: impl Fn(&T) -> &'static str,
    ) where
        T: DeserializeOwned,
    {
        for (kind, value) in read_fixture(file_name) {
            assert_eq!(
                value.get(tag).and_then(Value::as_str),
                Some(kind.as_str()),
                "{file_name}:{kind} must carry its serde tag"
            );
            let parsed: T = serde_json::from_value(value)
                .unwrap_or_else(|error| panic!("deserialize {file_name}:{kind}: {error}"));
            assert_eq!(
                wire_tag(&parsed),
                kind,
                "{file_name}:{kind} table wire tag must match serde tag"
            );
        }
    }

    fn read_fixture(file_name: &str) -> Map<String, Value> {
        read_fixture_for(PROTOCOL_VERSION, file_name)
    }

    fn read_fixture_for(version: u32, file_name: &str) -> Map<String, Value> {
        let path = fixture_root_for(version).join(file_name);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
    }

    fn fixture_expected_kinds(tags: Vec<&'static str>) -> Vec<String> {
        assert_eq!(
            tags.iter().filter(|tag| **tag == UNKNOWN_SENTINEL).count(),
            1,
            "variant table must contain exactly one unknown sentinel"
        );
        tags.into_iter()
            .filter(|tag| *tag != UNKNOWN_SENTINEL)
            .map(str::to_string)
            .collect()
    }

    fn request_variant_tags() -> Vec<&'static str> {
        macro_rules! collect_tags {
            (($($context:ident),*) [$(($pattern:pat, $tag:expr);)+]) => {
                vec![$($tag),+]
            };
        }
        crate::request_variants!(collect_tags)
    }

    fn response_variant_tags() -> Vec<&'static str> {
        macro_rules! collect_tags {
            (($($context:ident),*) [$(($pattern:pat, $tag:expr);)+]) => {
                vec![$($tag),+]
            };
        }
        crate::response_variants!(collect_tags)
    }

    fn event_variant_tags() -> Vec<&'static str> {
        macro_rules! collect_tags {
            (($($context:ident),*) [$(($pattern:pat, $tag:expr);)+]) => {
                vec![$($tag),+]
            };
        }
        crate::event_variants!(collect_tags)
    }

    fn fixture_root_for(version: u32) -> PathBuf {
        let path = daemon_proto_fixture_root().join(format!("v{version}"));
        if !path.is_dir() {
            panic!(
                "missing daemon proto fixture directory for protocol v{version}: {}",
                path.display()
            );
        }
        path
    }

    fn daemon_proto_fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("daemon_proto")
    }

    fn released_fixture_directories() -> BTreeSet<u32> {
        let root = daemon_proto_fixture_root();
        let entries = std::fs::read_dir(&root)
            .unwrap_or_else(|error| panic!("read {}: {error}", root.display()));
        let mut versions = BTreeSet::new();
        for entry in entries {
            let entry =
                entry.unwrap_or_else(|error| panic!("read {} entry: {error}", root.display()));
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            assert!(
                path.is_dir(),
                "unexpected file directly under daemon_proto fixtures: {}",
                path.display()
            );
            let Some(raw) = name.strip_prefix('v') else {
                panic!(
                    "unexpected non-version directory under daemon_proto fixtures: {}",
                    path.display()
                );
            };
            let version = raw.parse::<u32>().unwrap_or_else(|error| {
                panic!(
                    "unexpected non-numeric daemon_proto fixture directory {}: {error}",
                    path.display()
                )
            });
            versions.insert(version);
        }
        versions
    }

    fn assert_fixture_directory_files(version: u32) {
        let root = fixture_root_for(version);
        let entries = std::fs::read_dir(&root)
            .unwrap_or_else(|error| panic!("read {}: {error}", root.display()));
        let mut actual = BTreeSet::new();
        for entry in entries {
            let entry =
                entry.unwrap_or_else(|error| panic!("read {} entry: {error}", root.display()));
            let path = entry.path();
            assert!(
                path.is_file(),
                "unexpected non-file under frozen daemon_proto v{version}: {}",
                path.display()
            );
            actual.insert(entry.file_name().to_string_lossy().to_string());
        }
        let expected = DAEMON_PROTO_FIXTURE_FILES
            .iter()
            .map(|name| (*name).to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual, expected,
            "frozen daemon_proto v{version} must contain exactly the known fixture files"
        );
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

#[cfg(test)]
mod golden_wire_fixtures {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use serde_json::{Map, Value};

    use super::*;

    const UPDATE_ENV: &str = "COCKPIT_UPDATE_GOLDEN";
    const UNKNOWN_SENTINEL: &str = "__unknown";
    const SENTINEL_UUID: &str = "11111111-1111-4111-8111-111111111111";
    const GOLDEN_DIR: &str = "../../packages/cockpit-protocol/fixtures/daemon-wire";
    const README: &str = "\
# Daemon Wire Fixtures

This directory is generated by `cockpit-proto` golden wire tests.
Do not hand edit these files.

Regenerate from the repository root with:

```sh
COCKPIT_UPDATE_GOLDEN=1 cargo test -p cockpit-proto golden_wire_
```
";

    const REQUEST_ALLOWLIST: &[&str] = &[
        "archive_session",
        "attach",
        "cancel_paused_work",
        "delete_session",
        "fork_session",
        "fs_create_dir",
        "fs_delete",
        "fs_list",
        "fs_read",
        "fs_rename",
        "fs_stat",
        "fs_write",
        "git_diff_file",
        "git_status",
        "list_sessions",
        "read_history_page",
        "read_session_messages",
        "rename_session",
        "resolve_interrupt",
        "restart_if_idle",
        "resume_paused_work",
        "send_user_message",
        "session_live_status",
        "set_active_model",
        "set_agent",
        "share_session",
        "stats_rollup",
        "unarchive_session",
    ];

    const RESPONSE_ALLOWLIST: &[&str] = &[
        "ack",
        "attached",
        "forked",
        "fs_list",
        "fs_read",
        "fs_stat",
        "fs_write",
        "git_diff_file",
        "git_status",
        "history_page",
        "models",
        "restart_decision",
        "session_messages",
        "sessions",
        "stats_rollup",
    ];

    #[test]
    fn golden_wire_requests_match_checked_in() {
        let generated = generated_requests();
        assert_allowlist_exact("requests", &generated, REQUEST_ALLOWLIST);
        assert_checked_in("requests.json", generated);
    }

    #[test]
    fn golden_wire_responses_match_checked_in() {
        let generated = generated_responses();
        assert_allowlist_exact("responses", &generated, RESPONSE_ALLOWLIST);
        assert_checked_in("responses.json", generated);
    }

    #[test]
    fn golden_wire_events_cover_every_kind_and_match_checked_in() {
        let generated = generated_events();
        let expected = fixture_expected_kinds(event_variant_tags())
            .into_iter()
            .collect::<BTreeSet<_>>();
        let actual = object_keys(&generated);
        assert_eq!(
            actual, expected,
            "events.json must contain exactly one evt frame per Event variant"
        );
        for (name, envelope) in generated.as_object().expect("events fixture is an object") {
            assert_eq!(
                envelope.get("event").and_then(Value::as_str),
                Some(name.as_str()),
                "events.json:{name} key must match its serialized event tag"
            );
        }
        assert_checked_in("events.json", generated);
    }

    #[test]
    fn golden_wire_errors_match_checked_in() {
        let generated = generated_errors();
        let errors = generated.as_object().expect("errors fixture is an object");
        assert!(
            errors
                .values()
                .any(|value| value.get("id").is_some_and(|id| id.is_string())),
            "errors.json must include a request-paired err frame"
        );
        assert!(
            errors.values().any(|value| value.get("id").is_none()),
            "errors.json must include an out-of-band err frame with id omitted"
        );
        for code in ["authorization", "protocol_version", "bad_request"] {
            assert!(
                errors.values().any(|value| value
                    .pointer("/error/code")
                    .and_then(Value::as_str)
                    == Some(code)),
                "errors.json must include ErrorCode::{code}"
            );
        }
        assert_checked_in("errors.json", generated);
    }

    #[test]
    fn golden_wire_interrupts_cover_every_question_and_resolve_variant() {
        let generated = generated_interrupts();
        let fixtures = generated
            .as_object()
            .expect("interrupts fixture is an object");

        for (key, expected_kind) in [
            ("event_single_command_detail_present", "single"),
            ("event_multi", "multi"),
            ("event_freetext_masked_true", "freetext"),
            ("event_freetext_masked_false", "freetext"),
        ] {
            assert_eq!(
                question(fixtures, key).get("kind").and_then(Value::as_str),
                Some(expected_kind),
                "{key} must cover InterruptQuestion::{expected_kind}"
            );
        }
        assert_eq!(
            question(fixtures, "event_freetext_masked_true")
                .pointer("/data/masked")
                .and_then(Value::as_bool),
            Some(true),
            "masked:true freetext fixture must carry masked:true"
        );
        assert!(
            question(fixtures, "event_freetext_masked_false")
                .pointer("/data/masked")
                .is_none(),
            "masked:false freetext fixture must omit the additive masked key"
        );
        for (key, value) in fixtures {
            let Some(question) = value.pointer("/data/question") else {
                continue;
            };
            let data = question
                .get("data")
                .unwrap_or_else(|| panic!("{key} question must carry data"));
            if data.get("permission").and_then(Value::as_bool) == Some(true) {
                assert!(
                    data.get("options")
                        .and_then(Value::as_array)
                        .is_some_and(|options| !options.is_empty()),
                    "{key} permission interrupt must carry at least one option"
                );
            }
        }

        for (key, expected_kind) in [
            ("request_resolve_single", "single"),
            ("request_resolve_multi", "multi"),
            ("request_resolve_freetext", "freetext"),
            ("request_resolve_batch", "batch"),
            ("request_resolve_cancel", "cancel"),
        ] {
            assert_eq!(
                resolve_response(fixtures, key)
                    .get("kind")
                    .and_then(Value::as_str),
                Some(expected_kind),
                "{key} must cover ResolveResponse::{expected_kind}"
            );
        }
        assert_eq!(
            resolve_response(fixtures, "request_resolve_batch")
                .pointer("/data/responses/0/kind")
                .and_then(Value::as_str),
            Some("single"),
            "ResolveResponse::Batch must nest at least one non-batch response"
        );
        assert_checked_in("interrupts.json", generated);
    }

    #[test]
    fn golden_wire_command_detail_present_and_absent() {
        let generated = generated_interrupts();
        let fixtures = generated
            .as_object()
            .expect("interrupts fixture is an object");

        let present = question_data(fixtures, "event_single_command_detail_present");
        assert!(
            present.get("command_detail").is_some(),
            "command_detail-present fixture must carry command_detail"
        );
        let command_detail = present
            .get("command_detail")
            .and_then(Value::as_object)
            .expect("command_detail is an object");
        for field in [
            "affected_targets",
            "cwd",
            "full_command",
            "highlight",
            "native_tool_hints",
            "offered_scopes",
            "policy_cap",
            "remembered_key",
            "risk_reasons",
            "risk_tier",
            "step",
            "step_count",
            "write_content",
        ] {
            assert!(
                command_detail.contains_key(field),
                "command_detail-present fixture must carry {field}"
            );
        }
        assert!(
            question_data(fixtures, "event_single_command_detail_absent")
                .get("command_detail")
                .is_none(),
            "command_detail-absent fixture must omit command_detail"
        );

        let denial_present = question_data(fixtures, "event_single_sandbox_denial_present")
            .pointer("/sandbox_escalation/denial")
            .expect("sandbox denial report is present");
        assert_eq!(
            denial_present
                .pointer("/confidence")
                .and_then(Value::as_str),
            Some("high")
        );
        let evidence = denial_present
            .pointer("/evidence")
            .and_then(Value::as_array)
            .expect("denial evidence is an array");
        assert!(
            evidence
                .iter()
                .any(|item| item.get("kind").and_then(Value::as_str)
                    == Some("write_outside_allowlist")),
            "denial evidence must include write_outside_allowlist"
        );
        assert!(
            evidence
                .iter()
                .any(|item| item.get("kind").and_then(Value::as_str)
                    == Some("stderr_permission_marker")),
            "denial evidence must include stderr_permission_marker"
        );
        assert!(
            question_data(fixtures, "event_single_sandbox_denial_absent")
                .pointer("/sandbox_escalation/denial")
                .is_none(),
            "sandbox denial absent fixture must omit denial"
        );
    }

    #[test]
    fn golden_wire_grant_kinds_all_present() {
        let generated = generated_interrupts();
        let fixtures = generated
            .as_object()
            .expect("interrupts fixture is an object");
        let actual = [
            "event_single_grant_command",
            "event_single_grant_path",
            "event_single_grant_mcp_tool",
        ]
        .into_iter()
        .map(|key| {
            question_data(fixtures, key)
                .get("approval_class")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{key} must carry approval_class"))
                .to_string()
        })
        .collect::<BTreeSet<_>>();
        let expected = ["command", "path", "mcp_tool"]
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected, "all GrantKind values must be goldenized");
    }

    #[test]
    fn golden_wire_envelope_v_equals_protocol_version() {
        for (file_name, fixture) in [
            ("requests.json", generated_requests()),
            ("responses.json", generated_responses()),
            ("events.json", generated_events()),
            ("errors.json", generated_errors()),
            ("interrupts.json", generated_interrupts()),
        ] {
            for (name, envelope) in fixture.as_object().expect("fixture is an object") {
                assert_eq!(
                    envelope.get("v").and_then(Value::as_u64),
                    Some(u64::from(PROTOCOL_VERSION)),
                    "{file_name}:{name} must carry v=PROTOCOL_VERSION"
                );
            }
        }
    }

    fn generated_requests() -> Value {
        let bare = read_bare_fixture("request.json");
        let mut generated = Map::new();
        for name in REQUEST_ALLOWLIST {
            let value = bare.get(*name).unwrap_or_else(|| {
                panic!("request allowlist entry {name} is missing from bare fixture")
            });
            let request: Request = serde_json::from_value(value.clone())
                .unwrap_or_else(|error| panic!("deserialize bare request {name}: {error}"));
            generated.insert(
                (*name).to_string(),
                envelope_value(Envelope::request(sentinel_uuid(), request)),
            );
        }
        Value::Object(generated)
    }

    fn generated_responses() -> Value {
        let bare = read_bare_fixture("response.json");
        let mut generated = Map::new();
        for name in RESPONSE_ALLOWLIST {
            let value = bare.get(*name).unwrap_or_else(|| {
                panic!("response allowlist entry {name} is missing from bare fixture")
            });
            let response: Response = serde_json::from_value(value.clone())
                .unwrap_or_else(|error| panic!("deserialize bare response {name}: {error}"));
            generated.insert(
                (*name).to_string(),
                envelope_value(Envelope::response(sentinel_uuid(), response)),
            );
        }
        Value::Object(generated)
    }

    fn generated_events() -> Value {
        let bare = read_bare_fixture("event.json");
        let expected = fixture_expected_kinds(event_variant_tags())
            .into_iter()
            .collect::<BTreeSet<_>>();
        let actual = bare.keys().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            actual, expected,
            "bare event fixtures must contain every Event variant before envelope generation"
        );

        let mut generated = Map::new();
        for (name, value) in bare {
            let event: Event = serde_json::from_value(value)
                .unwrap_or_else(|error| panic!("deserialize bare event {name}: {error}"));
            generated.insert(name, envelope_value(Envelope::event(event)));
        }
        Value::Object(generated)
    }

    fn generated_errors() -> Value {
        let mut generated = Map::new();
        for (name, id, code, message) in [
            (
                "authorization_paired",
                Some(sentinel_uuid()),
                ErrorCode::Authorization,
                "principal cannot access this session",
            ),
            (
                "protocol_version_paired",
                Some(sentinel_uuid()),
                ErrorCode::ProtocolVersion,
                "wire protocol version mismatch",
            ),
            (
                "bad_request_out_of_band",
                None,
                ErrorCode::BadRequest,
                "malformed daemon frame",
            ),
        ] {
            generated.insert(
                name.to_string(),
                envelope_value(Envelope::error(
                    id,
                    ErrorPayload {
                        code,
                        message: message.to_string(),
                    },
                )),
            );
        }
        Value::Object(generated)
    }

    fn generated_interrupts() -> Value {
        let mut generated = Map::new();
        for (name, question) in [
            (
                "event_single_command_detail_present",
                single_question(
                    "Run `cargo test --locked`?",
                    Some(full_command_detail()),
                    Some(GrantKind::Command),
                    Some(sandbox_escalation_with_denial()),
                ),
            ),
            (
                "event_single_command_detail_absent",
                single_question(
                    "Run `cargo fmt --check`?",
                    None,
                    Some(GrantKind::Command),
                    None,
                ),
            ),
            (
                "event_single_sandbox_denial_present",
                single_question(
                    "Retry outside the sandbox?",
                    None,
                    Some(GrantKind::Path),
                    Some(sandbox_escalation_with_denial()),
                ),
            ),
            (
                "event_single_sandbox_denial_absent",
                single_question(
                    "Retry with broader access?",
                    None,
                    Some(GrantKind::Path),
                    Some(sandbox_escalation_without_denial()),
                ),
            ),
            (
                "event_single_grant_command",
                single_question("Approve command?", None, Some(GrantKind::Command), None),
            ),
            (
                "event_single_grant_path",
                single_question("Approve path?", None, Some(GrantKind::Path), None),
            ),
            (
                "event_single_grant_mcp_tool",
                single_question("Approve MCP tool?", None, Some(GrantKind::McpTool), None),
            ),
            (
                "event_multi",
                InterruptQuestion::Multi {
                    prompt: "Select checks to run".into(),
                    options: vec![option("fmt", "Format"), option("test", "Test")],
                    allow_freetext: false,
                },
            ),
            (
                "event_freetext_masked_true",
                InterruptQuestion::Freetext {
                    prompt: "Enter token".into(),
                    masked: true,
                },
            ),
            (
                "event_freetext_masked_false",
                InterruptQuestion::Freetext {
                    prompt: "Explain the decision".into(),
                    masked: false,
                },
            ),
        ] {
            generated.insert(name.to_string(), interrupt_event(question));
        }

        for (name, response) in [
            (
                "request_resolve_single",
                ResolveResponse::Single {
                    selected_id: "approve_once".into(),
                },
            ),
            (
                "request_resolve_multi",
                ResolveResponse::Multi {
                    selected_ids: vec!["fmt".into(), "test".into()],
                },
            ),
            (
                "request_resolve_freetext",
                ResolveResponse::Freetext {
                    text: "Use the existing design".into(),
                },
            ),
            (
                "request_resolve_batch",
                ResolveResponse::Batch {
                    responses: vec![ResolveResponse::Single {
                        selected_id: "approve_once".into(),
                    }],
                },
            ),
            ("request_resolve_cancel", ResolveResponse::Cancel),
        ] {
            generated.insert(name.to_string(), resolve_interrupt_request(response));
        }

        Value::Object(generated)
    }

    fn interrupt_event(question: InterruptQuestion) -> Value {
        envelope_value(Envelope::event(Event::InterruptRaised {
            session_id: sentinel_uuid(),
            interrupt_id: interrupt_uuid(),
            agent: "builder".into(),
            description: "Fixture interrupt".into(),
            question: Some(question),
            questions: None,
            pending_count: 1,
            reason: InterruptRaiseReason::Initial,
        }))
    }

    fn resolve_interrupt_request(response: ResolveResponse) -> Value {
        envelope_value(Envelope::request(
            sentinel_uuid(),
            Request::ResolveInterrupt {
                interrupt_id: interrupt_uuid(),
                response,
            },
        ))
    }

    fn single_question(
        prompt: &str,
        command_detail: Option<CommandDetail>,
        approval_class: Option<GrantKind>,
        sandbox_escalation: Option<SandboxEscalation>,
    ) -> InterruptQuestion {
        InterruptQuestion::Single {
            prompt: prompt.into(),
            options: vec![option("approve_once", "Approve once")],
            allow_freetext: false,
            command_detail: command_detail.map(Box::new),
            permission: true,
            approval_class,
            sandbox_escalation,
        }
    }

    fn option(id: &str, label: &str) -> InterruptOption {
        InterruptOption {
            id: id.into(),
            label: label.into(),
            description: Some(format!("{label} for this fixture")),
            secondary: false,
        }
    }

    fn full_command_detail() -> CommandDetail {
        CommandDetail {
            full_command: "cargo test --locked".into(),
            highlight: Some(CharSpan { start: 0, end: 5 }),
            step: 1,
            step_count: 2,
            cwd: Some("/workspace/flycockpitapp".into()),
            remembered_key: Some("cargo-test".into()),
            write_content: Some(WriteContentPreview {
                content: "fixture body".into(),
                dynamic: true,
            }),
            risk_tier: Some("medium".into()),
            risk_reasons: vec!["runs tests".into()],
            affected_targets: vec!["crates/cockpit-proto/src/lib.rs".into()],
            native_tool_hints: vec!["cargo".into()],
            offered_scopes: vec!["session".into()],
            policy_cap: Some("ask".into()),
        }
    }

    fn sandbox_escalation_with_denial() -> SandboxEscalation {
        SandboxEscalation {
            confined_exit: 13,
            confined_stderr: "Permission denied".into(),
            suggested_paths: vec!["/workspace/flycockpitapp/target".into()],
            suggested_access: Some("write".into()),
            denial: Some(SandboxDenialReport {
                confidence: SandboxDenialConfidence::High,
                evidence: vec![
                    SandboxDenialEvidence::WriteOutsideAllowlist {
                        path: "/workspace/flycockpitapp/target".into(),
                    },
                    SandboxDenialEvidence::StderrPermissionMarker,
                ],
            }),
        }
    }

    fn sandbox_escalation_without_denial() -> SandboxEscalation {
        SandboxEscalation {
            confined_exit: 13,
            confined_stderr: "Permission denied".into(),
            suggested_paths: vec!["/workspace/flycockpitapp/target".into()],
            suggested_access: Some("write".into()),
            denial: None,
        }
    }

    fn assert_checked_in(file_name: &str, generated: Value) {
        let canonical_generated = canonical(generated);
        let path = golden_root().join(file_name);
        if update_golden() {
            let _guard = update_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::fs::create_dir_all(golden_root()).unwrap_or_else(|error| {
                panic!(
                    "create golden fixture directory {}: {error}",
                    golden_root().display()
                )
            });
            std::fs::write(golden_root().join("README.md"), README).unwrap_or_else(|error| {
                panic!(
                    "write golden fixture README {}: {error}",
                    golden_root().join("README.md").display()
                )
            });
            let mut pretty = serde_json::to_string_pretty(&canonical_generated)
                .unwrap_or_else(|error| panic!("serialize {file_name}: {error}"));
            pretty.push('\n');
            std::fs::write(&path, pretty)
                .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
            format_golden_json(&path);
            return;
        }

        let raw = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "read {}: {error}; regenerate with COCKPIT_UPDATE_GOLDEN=1 cargo test -p cockpit-proto golden_wire_",
                path.display()
            )
        });
        let checked_in: Value = serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
        assert_eq!(
            canonical(checked_in),
            canonical_generated,
            "{} drifted; regenerate with COCKPIT_UPDATE_GOLDEN=1 cargo test -p cockpit-proto golden_wire_",
            path.display()
        );
    }

    fn assert_allowlist_exact(surface: &str, generated: &Value, allowlist: &[&str]) {
        let actual = object_keys(generated);
        let expected = allowlist
            .iter()
            .map(|name| (*name).to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual, expected,
            "{surface}.json emitted keys must exactly match the explicit allowlist"
        );
    }

    fn read_bare_fixture(file_name: &str) -> Map<String, Value> {
        let path = bare_fixture_root().join(file_name);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
    }

    fn envelope_value(envelope: Envelope) -> Value {
        let value = serde_json::to_value(envelope).expect("serialize envelope");
        let parsed: Envelope =
            serde_json::from_value(value.clone()).expect("deserialize generated envelope");
        let reparsed = serde_json::to_value(parsed).expect("re-serialize generated envelope");
        assert_eq!(
            canonical(reparsed),
            canonical(value.clone()),
            "generated envelope must round-trip canonically"
        );
        value
    }

    fn question<'a>(fixtures: &'a Map<String, Value>, key: &str) -> &'a Value {
        fixtures
            .get(key)
            .unwrap_or_else(|| panic!("missing interrupt fixture {key}"))
            .pointer("/data/question")
            .unwrap_or_else(|| panic!("{key} must carry data.question"))
    }

    fn question_data<'a>(fixtures: &'a Map<String, Value>, key: &str) -> &'a Value {
        question(fixtures, key)
            .get("data")
            .unwrap_or_else(|| panic!("{key} question must carry data"))
    }

    fn resolve_response<'a>(fixtures: &'a Map<String, Value>, key: &str) -> &'a Value {
        fixtures
            .get(key)
            .unwrap_or_else(|| panic!("missing interrupt fixture {key}"))
            .pointer("/params/response")
            .unwrap_or_else(|| panic!("{key} must carry params.response"))
    }

    fn object_keys(value: &Value) -> BTreeSet<String> {
        value
            .as_object()
            .expect("fixture value is an object")
            .keys()
            .cloned()
            .collect()
    }

    fn fixture_expected_kinds(tags: Vec<&'static str>) -> Vec<String> {
        assert_eq!(
            tags.iter().filter(|tag| **tag == UNKNOWN_SENTINEL).count(),
            1,
            "variant table must contain exactly one unknown sentinel"
        );
        tags.into_iter()
            .filter(|tag| *tag != UNKNOWN_SENTINEL)
            .map(str::to_string)
            .collect()
    }

    fn event_variant_tags() -> Vec<&'static str> {
        macro_rules! collect_tags {
            (($($context:ident),*) [$(($pattern:pat, $tag:expr);)+]) => {
                vec![$($tag),+]
            };
        }
        crate::event_variants!(collect_tags)
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

    fn golden_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN_DIR)
    }

    fn bare_fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("daemon_proto")
            .join(format!("v{PROTOCOL_VERSION}"))
    }

    fn sentinel_uuid() -> Uuid {
        Uuid::parse_str(SENTINEL_UUID).expect("sentinel UUID parses")
    }

    fn interrupt_uuid() -> Uuid {
        Uuid::parse_str("22222222-2222-4222-8222-222222222222").expect("interrupt UUID parses")
    }

    fn update_golden() -> bool {
        std::env::var(UPDATE_ENV).is_ok()
    }

    fn update_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    fn format_golden_json(path: &Path) {
        let status = std::process::Command::new(biome_bin())
            .args(["format", "--write"])
            .arg(path)
            .current_dir(workspace_root())
            .status()
            .unwrap_or_else(|error| {
                panic!(
                    "format golden fixture {} with biome: {error}",
                    path.display()
                )
            });
        assert!(
            status.success(),
            "format golden fixture {} with biome exited with {status}",
            path.display()
        );
    }

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn biome_bin() -> PathBuf {
        let executable = if cfg!(windows) { "biome.cmd" } else { "biome" };
        let local = workspace_root()
            .join("node_modules")
            .join(".bin")
            .join(executable);
        if local.is_file() {
            local
        } else {
            PathBuf::from(executable)
        }
    }
}

#[cfg(test)]
mod forward_open_guard_tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use tokio::io::duplex;

    #[test]
    fn forward_open_guard_no_deny_unknown_fields_in_proto_src() {
        let mut violations = Vec::new();
        collect_deny_unknown_fields_violations(&src_root(), &mut violations);
        assert!(
            violations.is_empty(),
            "cockpit-proto wire structs must stay forward-open for additive compatibility \
             (see proto-additive-forward-compat); remove serde deny_unknown_fields from: {}",
            violations.join(", ")
        );
    }

    #[test]
    fn forward_open_guard_struct_payload_accepts_unknown_field() {
        let value = read_forward_fixture("response-extra-field.json");
        let response: Response =
            serde_json::from_value(value).expect("future response fixture should parse");
        match response {
            Response::ApprovalModeState { mode } => assert_eq!(mode, ApprovalMode::Auto),
            other => panic!("expected approval mode response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn forward_open_guard_frame_accepts_unknown_top_level_variant() {
        let mut value = read_forward_fixture("unknown-top-level-variant.json");
        value["v"] = serde_json::json!(PROTOCOL_VERSION);
        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);
        left.send_raw_line(value.to_string()).await.unwrap();

        match right.recv().await.unwrap().expect("frame") {
            RecvFrame::Unknown { v, kind, tag, id } => {
                assert_eq!(v, PROTOCOL_VERSION);
                assert_eq!(kind, "req");
                assert_eq!(tag.as_deref(), Some("future_request"));
                assert_eq!(
                    id,
                    Some(Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap())
                );
            }
            other => panic!("expected unknown frame, got {other:?}"),
        }
    }

    fn collect_deny_unknown_fields_violations(path: &Path, violations: &mut Vec<String>) {
        for entry in std::fs::read_dir(path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        {
            let entry = entry.unwrap_or_else(|error| panic!("read dir entry: {error}"));
            let path = entry.path();
            if path.is_dir() {
                collect_deny_unknown_fields_violations(&path, violations);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            let mut in_serde_attr = false;
            for (index, line) in source.lines().enumerate() {
                if line.trim_start().starts_with("#[serde") {
                    in_serde_attr = true;
                }
                if in_serde_attr && line.contains("deny_unknown_fields") {
                    violations.push(format!("{}:{}", path.display(), index + 1));
                }
                if in_serde_attr && line.contains(']') {
                    in_serde_attr = false;
                }
            }
        }
    }

    fn src_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    fn read_forward_fixture(file_name: &str) -> serde_json::Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("forward_compat")
            .join(file_name);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
    }
}

#[cfg(test)]
mod errorcode_forward_tests {
    use super::*;

    #[test]
    fn errorcode_forward_unknown_string_deserializes_to_catch_all() {
        let code: ErrorCode = serde_json::from_str("\"future_code\"").unwrap();
        assert_eq!(code, ErrorCode::Other("future_code".to_string()));
        assert_eq!(code.to_string(), "future_code");
    }

    #[test]
    fn errorcode_forward_known_string_still_deserializes_to_specific_variant() {
        let code: ErrorCode = serde_json::from_str("\"protocol_version\"").unwrap();
        assert_eq!(code, ErrorCode::ProtocolVersion);
    }

    #[test]
    fn errorcode_forward_catch_all_round_trips() {
        let original = ErrorCode::Other("future_code".to_string());
        let serialized = serde_json::to_string(&original).unwrap();
        assert_eq!(serialized, "\"future_code\"");
        let parsed: ErrorCode = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed, original);
    }
}

// ---- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::duplex;

    fn hello(protocol_version: u32) -> DaemonHello {
        DaemonHello {
            daemon_version: "0.0.test-daemon".to_string(),
            protocol_version,
        }
    }

    #[test]
    fn negotiated_version_is_min_of_client_and_daemon() {
        let current = NegotiatedProtocol::from_hello(&hello(PROTOCOL_VERSION)).unwrap();
        assert_eq!(current.version, PROTOCOL_VERSION);
        assert_eq!(current.daemon_protocol_version, PROTOCOL_VERSION);

        let newer = NegotiatedProtocol::from_hello(&hello(PROTOCOL_VERSION + 100)).unwrap();
        assert_eq!(newer.version, PROTOCOL_VERSION);
        assert_eq!(newer.daemon_protocol_version, PROTOCOL_VERSION + 100);

        if PROTOCOL_VERSION > MIN_SUPPORTED_PROTOCOL_VERSION {
            let older = NegotiatedProtocol::from_hello(&hello(PROTOCOL_VERSION - 1)).unwrap();
            assert_eq!(older.version, PROTOCOL_VERSION - 1);
        }
    }

    #[test]
    fn negotiated_version_below_min_supported_is_rejected() {
        let below_min = MIN_SUPPORTED_PROTOCOL_VERSION.saturating_sub(1);
        let err = NegotiatedProtocol::from_hello(&hello(below_min))
            .expect_err("below-min daemon protocol must be rejected");
        assert_eq!(err.code, ErrorCode::ProtocolVersion);
        assert_eq!(err.message, incompatible_daemon_protocol_message(below_min));
    }

    #[tokio::test]
    async fn envelope_constructors_stamp_the_negotiated_version() {
        let negotiated = MIN_SUPPORTED_PROTOCOL_VERSION;
        let (left, right) = duplex(4096);
        let mut sender = ProtoStream::with_version(left, negotiated);
        let mut receiver = ProtoStream::new(right);

        let request = Envelope::request(Uuid::new_v4(), Request::DaemonStatus);
        assert_eq!(request.v, PROTOCOL_VERSION);
        sender.send(&request).await.unwrap();

        match receiver.recv().await.unwrap().expect("frame") {
            RecvFrame::Envelope(env) => assert_eq!(env.v, negotiated),
            other => panic!("expected envelope, got {other:?}"),
        }

        assert_eq!(
            Envelope::request_at(negotiated, Uuid::new_v4(), Request::DaemonStatus).v,
            negotiated
        );
        assert_eq!(
            Envelope::response_at(negotiated, Uuid::new_v4(), Response::Ack).v,
            negotiated
        );
        assert_eq!(
            Envelope::event_at(
                negotiated,
                Event::LspNotice {
                    text: "notice".to_string()
                }
            )
            .v,
            negotiated
        );
        assert_eq!(
            Envelope::error_at(
                negotiated,
                None,
                ErrorPayload {
                    code: ErrorCode::Internal,
                    message: "error".to_string()
                }
            )
            .v,
            negotiated
        );
    }

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
    fn read_history_page_request_round_trips_without_before_seq() {
        let session_id = Uuid::new_v4();
        let value = serde_json::to_value(Request::ReadHistoryPage {
            session_id,
            before_seq: None,
            limit: 25,
        })
        .unwrap();
        assert_eq!(
            value,
            json!({
                "request": "read_history_page",
                "params": {
                    "session_id": session_id,
                    "limit": 25,
                }
            })
        );

        let back: Request = serde_json::from_value(value).unwrap();
        match back {
            Request::ReadHistoryPage {
                session_id: got,
                before_seq,
                limit,
            } => {
                assert_eq!(got, session_id);
                assert_eq!(before_seq, None);
                assert_eq!(limit, 25);
            }
            other => panic!("expected ReadHistoryPage, got {other:?}"),
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
    fn error_without_id_omits_id_key() {
        let env = Envelope::error(
            None,
            ErrorPayload {
                code: ErrorCode::Shutdown,
                message: "daemon shutting down".into(),
            },
        );
        let s = serde_json::to_string(&env).unwrap();
        let value: Value = serde_json::from_str(&s).unwrap();
        assert!(value.get("id").is_none());
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
    fn command_capability_unavailable_event_round_trips_with_fix_command() {
        let sid = Uuid::new_v4();
        let text = "Required command capability unavailable: `demo` missing for `tool`.";
        let fix_command = "sudo apt-get install demo";
        let evt = Envelope::event(Event::CommandCapabilityUnavailable {
            session_id: sid,
            text: text.to_string(),
            fix_command: Some(fix_command.to_string()),
        });
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&evt).unwrap()).unwrap();
        match back.body {
            Body::Event {
                event:
                    Event::CommandCapabilityUnavailable {
                        session_id,
                        text: got_text,
                        fix_command: got_fix_command,
                    },
            } => {
                assert_eq!(session_id, sid);
                assert_eq!(got_text, text);
                assert_eq!(got_fix_command.as_deref(), Some(fix_command));
            }
            other => panic!("expected CommandCapabilityUnavailable event, got {other:?}"),
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
                denial: None,
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
    fn unknown_variant_request_tag_deserializes_to_catch_all() {
        let request: Request = serde_json::from_value(json!({
            "request": "definitely_not_a_real_request",
        }))
        .unwrap();
        assert!(matches!(request, Request::Unknown));
    }

    #[test]
    fn unknown_variant_event_tag_deserializes_to_catch_all() {
        let event: Event = serde_json::from_value(json!({
            "event": "future_event",
        }))
        .unwrap();
        assert!(matches!(event, Event::Unknown));
    }

    #[test]
    fn unknown_variant_body_kind_deserializes_to_catch_all() {
        let env: Envelope = serde_json::from_value(json!({
            "v": PROTOCOL_VERSION,
            "kind": "future_kind",
            "id": Uuid::new_v4(),
        }))
        .unwrap();
        assert!(matches!(env.body, Body::Unknown));
    }

    #[tokio::test]
    async fn unknown_variant_recv_yields_unknown_frame_with_tag_and_id() {
        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);
        let id = Uuid::new_v4();
        left.send_raw_line(
            serde_json::to_string(&json!({
                "v": PROTOCOL_VERSION,
                "kind": "req",
                "id": id,
                "request": "definitely_not_a_real_request",
                "params": { "future": true },
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        match right.recv().await.unwrap().expect("frame") {
            RecvFrame::Unknown {
                v,
                kind,
                tag,
                id: got_id,
            } => {
                assert_eq!(v, PROTOCOL_VERSION);
                assert_eq!(kind, "req");
                assert_eq!(tag.as_deref(), Some("definitely_not_a_real_request"));
                assert_eq!(got_id, Some(id));
            }
            other => panic!("expected unknown frame, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_variant_recv_still_errors_on_malformed_json() {
        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);
        left.send_raw_line("{not json".to_string()).await.unwrap();

        let error = right
            .recv()
            .await
            .expect_err("malformed JSON remains fatal");
        assert!(
            error.to_string().contains("deserializing envelope"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn unknown_variant_recv_still_errors_on_known_variant_with_bad_params() {
        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);
        left.send_raw_line(
            serde_json::to_string(&json!({
                "v": PROTOCOL_VERSION,
                "kind": "req",
                "id": Uuid::new_v4(),
                "request": "read_history_page",
                "params": {
                    "session_id": 7,
                    "limit": 25,
                },
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        let error = right
            .recv()
            .await
            .expect_err("known bad params remain fatal");
        assert!(
            error.to_string().contains("deserializing envelope"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn unknown_variant_recv_yields_unknown_frame_for_unknown_error_code() {
        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);
        let id = Uuid::new_v4();
        left.send_raw_line(
            serde_json::to_string(&json!({
                "v": PROTOCOL_VERSION,
                "kind": "err",
                "id": id,
                "error": {
                    "code": "future_error",
                    "message": "future error shape"
                },
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        match right.recv().await.unwrap().expect("frame") {
            RecvFrame::Unknown {
                v,
                kind,
                tag,
                id: got_id,
            } => {
                assert_eq!(v, PROTOCOL_VERSION);
                assert_eq!(kind, "err");
                assert_eq!(tag.as_deref(), Some("future_error"));
                assert_eq!(got_id, Some(id));
            }
            other => panic!("expected unknown frame, got {other:?}"),
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
