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

use std::collections::HashMap;
use std::io;

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LinesCodec, LinesCodecError};
use uuid::Uuid;

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
pub(crate) use request::command;
pub use request::{AttachmentPurpose, LspControlAction, Request, UsageKind};

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
pub use response::Response;

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
pub use event::Event;
pub(crate) use event::turn_event_to_proto;

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
            Self::Internal => "internal",
        };
        f.write_str(s)
    }
}

// ---- Shared payload types --------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum HistoryEntry {
    User {
        text: String,
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
        agent: String,
        call_id: String,
        tool: String,
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
        summary: String,
        #[serde(default)]
        detail: String,
    },
    CompactBoundary {
        predecessor_short_id: String,
        seed_tool_count: usize,
        seed_tool_tokens: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        brief: Option<String>,
    },
    Subagent {
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
    #[serde(default)]
    pub target: QueueTarget,
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
pub struct SessionSummary {
    pub session_id: Uuid,
    /// 6-char display id (GOALS §17b). Optional for backwards-compat
    /// with pre-§17 rows that haven't been backfilled yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
    pub project_root: String,
    pub project_id: String,
    pub started_at: i64,
    pub last_active_at: i64,
    pub turns: u32,
    pub active_agent: String,
    /// Auto- or user-set title (GOALS §17d). `None` until generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Parent session in the fork tree (§17e). `None` = root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<Uuid>,
    /// Principal that created the session (`flycockpit:<user_id>` for
    /// remote sharees). `None` is the local machine owner / legacy rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by_principal: Option<String>,
    /// Owner-controlled broad sharing flag: visible to collaborators holding
    /// agent/agent_readonly grants for this project.
    #[serde(default)]
    pub shared_with_collaborators: bool,
    /// Number of direct forks. The `/sessions` browser renders
    /// `[N forks]` from this.
    #[serde(default)]
    pub fork_count: u32,
    /// Total descendant forks (depth-unbounded, excluding this session).
    /// The archive/delete confirm states this as the cascade count.
    #[serde(default)]
    pub descendant_count: u32,
    /// Epoch seconds the user last opened/resumed this session (GOALS
    /// §17f). `None` = never viewed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_viewed_at: Option<i64>,
    /// Epoch seconds of the most recent agent-produced event (max across
    /// tool calls + inference). `None` = no agent activity yet. The
    /// browser marks a session unread when this is newer than
    /// `last_viewed_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_activity_at: Option<i64>,
    /// Count of open (unresolved) interrupts/questions for this session
    /// (`needs_attention`). Drives the "read, pending question" tier.
    #[serde(default)]
    pub open_interrupts: u32,
    /// Epoch seconds the session was archived (GOALS §17h). `None` = live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<i64>,
    /// Number of pinned messages in this session (`pinned-messages`). The
    /// `/sessions` browser renders this; `0` = no pin chrome.
    #[serde(default)]
    pub pin_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillSummary {
    pub name: String,
    pub description: String,
    pub source: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", content = "data")]
pub enum InterruptQuestion {
    Single {
        prompt: String,
        options: Vec<InterruptOption>,
        #[serde(default = "default_allow_freetext")]
        allow_freetext: bool,
        /// Optional structured command-detail block (bash approval, §sandbox
        /// part 1). When present the answering dialog renders the full
        /// verbatim command beneath the heading, with the current step's
        /// constituent highlighted and a `step N of M` indicator for
        /// compound commands. Absent for every non-approval `Single`
        /// question, so the field is wire-equivalent to the legacy shape
        /// (back-compat: an un-annotated `Single` carries `None`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command_detail: Option<Box<CommandDetail>>,
        /// `true` when this `Single` is a **tool/permission approval** (scope
        /// select, bash-command approval, loop-guard) rather than an
        /// agent-asked question. Drives the answering dialog's stripped
        /// presentation: no `(•)` radio marker and no free-text custom row —
        /// cursor-highlight + Enter (plus number-key) is the only selection.
        /// Agent questions leave this `false` (back-compat: un-annotated
        /// `Single` is a question), keeping radios and free-text.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        permission: bool,
        /// Optional sandbox-escalation context (`bash` run-fail-escalate).
        /// Present only when this approval fired *after* a confined run
        /// exited non-zero — it makes this a **distinct** prompt variant from
        /// a first-time command approval: the answering dialog renders the
        /// "ran in the sandbox and failed; re-run without it?" framing plus
        /// the confined exit code and captured stderr. Absent for every
        /// other approval (back-compat: an un-annotated `Single` carries
        /// `None`, the first-time-approval wording).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sandbox_escalation: Option<SandboxEscalation>,
    },
    Multi {
        prompt: String,
        options: Vec<InterruptOption>,
        #[serde(default = "default_allow_freetext")]
        allow_freetext: bool,
    },
    Freetext {
        prompt: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        masked: bool,
    },
}

fn default_allow_freetext() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterruptOption {
    pub id: String,
    pub label: String,
    /// Optional one-line description rendered dimmed beneath the label.
    /// Absent for options the agent didn't annotate (back-compat: an
    /// un-annotated option is wire-equivalent to the legacy shape).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Structured detail for a bash-command approval prompt. Rides on a
/// [`InterruptQuestion::Single`] so the answering dialog can show the full
/// verbatim command beneath the (terse) heading and, for compound
/// commands, point at the constituent this prompt is deciding. Purely
/// presentational — the grant still keys on the heading's approval key,
/// never on this text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandDetail {
    /// The full command string the agent proposed, verbatim.
    pub full_command: String,
    /// Char range `[start, end)` (0-based, end-exclusive) of the
    /// constituent this prompt decides, within `full_command`. `None` for
    /// a single-constituent command (no highlight) or when the parser
    /// could not place the constituent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highlight: Option<CharSpan>,
    /// 1-based position of this prompt among the constituents that
    /// actually prompt, and the total count of such constituents. `(1, 1)`
    /// for a single-prompt command, which the dialog renders with no `step`
    /// indicator.
    pub step: u32,
    pub step_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_tier: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risk_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_targets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub native_tool_hints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub offered_scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_cap: Option<String>,
}

/// A 0-based, end-exclusive char range into a source string. Char-indexed
/// (not byte-indexed) so multi-byte input slices correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CharSpan {
    pub start: u32,
    pub end: u32,
}

/// Context for a `bash` run-fail-escalate approval (sandboxing part 2):
/// the command ran confined, exited non-zero, and *may* have been blocked
/// from reading/writing outside the working directory — but zerobox is a
/// silent deny, so cockpit **cannot confirm** the sandbox was the cause.
/// The answering dialog renders the honest "failed while sandboxed; re-run
/// without the sandbox?" framing plus this confined attempt's exit code and
/// captured stderr, so the user can judge a likely sandbox denial from an
/// ordinary failure before approving. Never asserts the sandbox blocked
/// the command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxEscalation {
    /// The confined attempt's exit code (`-1` for a signaled exit).
    pub confined_exit: i32,
    /// The confined attempt's captured stderr, already reasonably
    /// truncated for display. Empty when the command wrote no stderr.
    pub confined_stderr: String,
}

/// A batch of one or more questions raised in a single interrupt. The
/// `question` tool (GOALS §3b) carries an array of questions in one
/// call because tool dispatch is sequential and structural tools drop
/// the rest of the turn — so everything the agent needs has to ride in
/// one interrupt. Each entry reuses [`InterruptQuestion`], so a
/// single-question batch is wire-equivalent to the legacy shape (the
/// answering UI and the resolution path treat `[q]` and a bare `q`
/// identically).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterruptQuestionSet {
    pub questions: Vec<InterruptQuestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", content = "data")]
pub enum ResolveResponse {
    Single {
        selected_id: String,
    },
    Multi {
        selected_ids: Vec<String>,
    },
    Freetext {
        text: String,
    },
    /// One answer per question in an [`InterruptQuestionSet`], in the
    /// same order the questions were posed. Each entry is a `Single` /
    /// `Multi` / `Freetext` — never a nested `Batch` or `Cancel`. The
    /// `question` tool maps these back to its result array; a
    /// single-question batch may equally arrive as a bare `Single` /
    /// `Multi` / `Freetext` (the resolver unwraps both shapes).
    Batch {
        responses: Vec<ResolveResponse>,
    },
    /// User dismissed the interrupt without answering. The agent
    /// receives an empty resolution and decides how to proceed.
    Cancel,
}

impl ResolveResponse {
    /// Normalize a resolution into the per-question answer list a
    /// [`InterruptQuestionSet`] of `n` questions expects. `Batch` is
    /// returned as-is; a bare single-question answer wraps to a
    /// one-element list; `Cancel` fans out to `n` `Cancel`s so every
    /// question reads as dismissed.
    pub fn into_batch(self, n: usize) -> Vec<ResolveResponse> {
        match self {
            ResolveResponse::Batch { responses } => responses,
            ResolveResponse::Cancel => std::iter::repeat_n(ResolveResponse::Cancel, n).collect(),
            other => vec![other],
        }
    }
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

    #[cfg(test)]
    pub(crate) async fn send_raw_line(&mut self, line: String) -> Result<()> {
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
                text: crate::engine::message::IMAGE_PART_SENTINEL.to_string(),
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
        use crate::daemon::caffeinate::CaffeinateMode;

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
        });
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&evt).unwrap()).unwrap();
        match back.body {
            Body::Event {
                event:
                    Event::SandboxUnavailable {
                        session_id,
                        remedy: r,
                    },
            } => {
                assert_eq!(session_id, sid);
                assert_eq!(r, remedy);
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
                },
                InterruptOption {
                    id: "later".into(),
                    label: "Defer".into(),
                    description: None,
                },
            ],
            allow_freetext: true,
            command_detail: None,
            permission: false,
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
            }],
            allow_freetext: false,
            command_detail: None,
            permission: true,
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
            }],
            allow_freetext: false,
            permission: true,
            sandbox_escalation: None,
            command_detail: Some(Box::new(CommandDetail {
                full_command: "git push && cargo build".into(),
                highlight: Some(CharSpan { start: 11, end: 22 }),
                step: 2,
                step_count: 2,
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
            }],
            allow_freetext: false,
            permission: true,
            command_detail: None,
            sandbox_escalation: Some(SandboxEscalation {
                confined_exit: 101,
                confined_stderr: "permission denied".into(),
            }),
        };
        let s = serde_json::to_string(&q).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["data"]["sandbox_escalation"]["confined_exit"], json!(101));
        let back: InterruptQuestion = serde_json::from_str(&s).unwrap();
        match back {
            InterruptQuestion::Single {
                sandbox_escalation, ..
            } => {
                let esc = sandbox_escalation.expect("sandbox_escalation survives");
                assert_eq!(esc.confined_exit, 101);
                assert_eq!(esc.confined_stderr, "permission denied");
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
