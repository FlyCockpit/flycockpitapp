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
pub const PROTOCOL_VERSION: u32 = 2;

/// Oldest wire schema version this binary accepts.
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 2;

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

#[derive(Debug, Clone, Deserialize)]
struct EnvelopeHeader {
    v: u32,
    kind: String,
    #[serde(default)]
    id: Option<Uuid>,
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
        /// [`crate::env_snapshot::EnvSnapshotMeta`] and safe diff summaries.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        env_snapshot: Option<crate::env_snapshot::EnvSnapshotWire>,
        /// Non-interactive drift policy. Interactive clients may still choose
        /// client/update-daemon explicitly before attach; the daemon default
        /// is conservative and keeps its baseline.
        #[serde(default)]
        env_policy: crate::env_snapshot::EnvDriftPolicy,
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
        mode: Option<crate::config::extended::LlmMode>,
    },

    /// Switch the active `llm_mode` for the attached session without writing
    /// the config default. Used by `/quick`; acknowledged with
    /// [`Event::LlmModeChanged`].
    SetSessionLlmMode {
        mode: crate::config::extended::LlmMode,
    },

    /// Set the attached session's live command-approval mode. Session-only;
    /// does not write `defaultApprovalMode`.
    SetApprovalMode {
        mode: crate::config::extended::ApprovalMode,
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
        mode: Option<crate::tools::sandbox_mode::SandboxMode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        container_network_enabled: Option<bool>,
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
        mode: crate::daemon::caffeinate::CaffeinateMode,
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
        credential: crate::auth::flycockpit::StoredFlycockpitCredential,
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
    StopDaemon,
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
        env_baseline: Option<crate::env_snapshot::EnvSnapshotMeta>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        env_session: Option<crate::env_snapshot::EnvSnapshotMeta>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        env_drift: Option<Box<crate::env_snapshot::EnvDiffSummary>>,
        #[serde(default)]
        env_policy_applied: crate::env_snapshot::EnvDriftPolicy,
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

    /// A `/note` session-history note was recorded ([`Request::RecordSessionNote`]).
    /// `seq` is the assigned monotonic `session_events` sequence so the client
    /// can place the note row in the correct chronological position.
    NoteRecorded {
        seq: i64,
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

    Skills {
        skills: Vec<SkillSummary>,
    },

    /// Answer to [`Request::ResourceSnapshot`].
    ResourceSnapshot {
        snapshot: crate::engine::resource_scheduler::ResourceSchedulerSnapshot,
    },

    /// Answer to [`Request::PromoteResource`].
    PromoteResourceResult {
        status: ResourcePromoteStatus,
        message: String,
        snapshot: crate::engine::resource_scheduler::ResourceSchedulerSnapshot,
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
    },

    /// The three 30-day autocomplete count maps. `models` and `slash`
    /// are global; `tags` is scoped to the requested project. Answer to
    /// [`Request::GetUsageCounts`].
    UsageCounts {
        models: HashMap<String, u64>,
        slash: HashMap<String, u64>,
        tags: HashMap<String, u64>,
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
    },

    /// The resulting sandbox mode after a [`Request::SetSandbox`].
    SandboxState {
        mode: crate::tools::sandbox_mode::SandboxMode,
        enabled: bool,
        #[serde(default)]
        container_network_enabled: bool,
        container_availability: crate::container::ContainerAvailability,
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
        mode: crate::config::extended::ApprovalMode,
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

// ---- Events ----------------------------------------------------------------

/// Unsolicited daemon → client notifications. The event stream is
/// fire-and-forget — clients do not ack individual events. A client
/// that misses events (e.g. dropped connection) re-`Attach`es and
/// receives a fresh history snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", content = "data")]
pub enum Event {
    EnvDriftWarning {
        baseline: crate::env_snapshot::EnvSnapshotMeta,
        candidate: crate::env_snapshot::EnvSnapshotMeta,
        diff: crate::env_snapshot::EnvDiffSummary,
        policy: crate::env_snapshot::EnvDriftPolicy,
    },

    /// Authoritative pending user-message queue snapshot for one session.
    QueueUpdated {
        session_id: Uuid,
        queue: Vec<QueueItem>,
    },

    /// Model inference started. TUI shows `Thinking…` until the first
    /// `AssistantTextDelta` arrives.
    ThinkingStarted {
        session_id: Uuid,
        agent: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        turn_id: Option<String>,
    },

    /// An inference call hit a network/transient failure and is being
    /// auto-retried. TUI shows a distinct, persistent `reconnecting —
    /// <provider>/<model> unreachable at <url> (attempt N)` status (daemon
    /// owns inference state — this is forwarded, not computed client-side);
    /// the headless `run` path logs a recurring attempt-numbered line.
    /// `attempt` is the 1-based retry number; `provider`/`model`/`url` name
    /// the unreachable target.
    Reconnecting {
        session_id: Uuid,
        agent: String,
        attempt: u32,
        provider: String,
        model: String,
        url: String,
    },

    /// A configured stream wait threshold elapsed. Without a backup model the
    /// daemon keeps waiting; with a backup model this warning precedes the
    /// timeout failure that engages fallback.
    InferenceWarning {
        session_id: Uuid,
        agent: String,
        provider: String,
        model: String,
        phase: String,
        waited_secs: u64,
    },

    /// One streaming chunk of assistant text.
    AssistantTextDelta {
        session_id: Uuid,
        agent: String,
        delta: String,
    },

    /// One streaming chunk of model reasoning (thinking-mode models).
    /// TUI hides this by default but persists it so the user can
    /// expand the chain of thought later.
    ReasoningDelta {
        session_id: Uuid,
        agent: String,
        delta: String,
    },

    /// Assistant turn complete — `text` is the full accumulated body with
    /// inline `<think>` blocks already stripped. `reasoning` is the
    /// finalized (channel + inline) reasoning the thinking chip renders;
    /// non-empty for a think-only turn with no body, so the chip survives
    /// across the wire. `seq` is the `session_events` row id of this message
    /// (the stable id a pin references — `pinned-messages`); `None` when the
    /// timeline write failed. UI/DB-only — never enters the model's context.
    AssistantText {
        session_id: Uuid,
        agent: String,
        text: String,
        #[serde(default)]
        reasoning: String,
        #[serde(default)]
        seq: Option<i64>,
    },

    /// A user/injected message was recorded to the timeline. Carries the
    /// assigned `session_events` `seq` so the client can stamp it onto the
    /// already-pushed user history row (the stable id a pin references —
    /// `pinned-messages`). UI/DB-only — never enters the model's context.
    ///
    /// `preflight_cleaned` carries the request-preflight rewritten body
    /// (implementation note) when this turn was preflighted, so the
    /// client can show the cleaned text + `⚙ preflighted` chip and reveal the
    /// original typed input on click. `None` when preflight didn't run.
    UserMessageRecorded {
        session_id: Uuid,
        seq: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preflight_cleaned: Option<String>,
    },
    /// One or more daemon-queued user messages were drained and folded into a
    /// model request. Carries stable queue ids plus the persisted timeline seq
    /// when the session log write succeeded.
    QueuedUserMessagesFolded {
        session_id: Uuid,
        text: String,
        queue_item_ids: Vec<Uuid>,
        target: QueueTarget,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seq: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preflight_cleaned: Option<String>,
    },
    /// Deferred session persistence failed before inference started. The
    /// server dropped the message; clients should clear optimistic busy state
    /// and show the full error chain.
    SessionPersistFailed {
        session_id: Uuid,
        error: String,
    },

    /// The session driver's task ended unexpectedly while the worker was
    /// still serving. Terminal: clients should clear optimistic busy state
    /// and show the error because the worker will end this session.
    SessionDriverFailed {
        session_id: Uuid,
        error: String,
    },

    /// Request preflight is actually running for the just-submitted message
    /// (implementation note). Emitted at submit time, before the
    /// injection/preflight `tokio::join!`, only when preflight is enabled AND
    /// will run (not a `should_skip` no-op). The client marks the optimistic
    /// user row so its border slot shows the animated `Preflight…` indicator
    /// until the message resolves. UI-only — never enters the model's context.
    PreflightStarted {
        session_id: Uuid,
    },

    /// The just-submitted message was retracted before send because the
    /// prompt-injection guard blocked it (implementation note edge
    /// case). The client removes the optimistically-shown user row so the
    /// block/override UX stands alone. UI-only.
    UserMessageRetracted {
        session_id: Uuid,
    },

    /// A non-blocking system notice (warn chip) for the transcript.
    /// Used by the prompt-injection guard (GOALS §4i). UI-only: never
    /// enters the model's context.
    Notice {
        session_id: Uuid,
        text: String,
    },

    /// A daemon-global LSP warning/status notice. Used for language-server
    /// install failures that may be triggered from advisory write/edit
    /// diagnostics rather than a foreground settings request.
    LspNotice {
        text: String,
    },

    /// The utility-model skill auto-selector injected a skill onto this
    /// turn's wire message (`auto-injected-skill-transcript-
    /// visibility.md`). The client renders a distinct `/{name} · injected
    /// by agent` row ahead of the user's message. UI-only: never enters the
    /// model's context (the body is folded into the user message on the
    /// wire — wire-vs-user split, GOALS §14). One per injected skill.
    /// `reason` is the optional muted sub-line justification
    /// (implementation note); display-only and off-wire.
    SkillAutoInjected {
        session_id: Uuid,
        name: String,
        reason: Option<String>,
    },

    /// Tool dispatch started; args are post-repair.
    ToolStart {
        session_id: Uuid,
        agent: String,
        call_id: String,
        tool: String,
        args: Value,
    },

    /// Tool finished cleanly. `output` is what the model sees on its
    /// next inference call.
    ToolEnd {
        session_id: Uuid,
        agent: String,
        call_id: String,
        tool: String,
        output: String,
        truncated: bool,
        /// Post-result hint text (`engine::bash_hints`, the user-side
        /// `data.hint.text`) when a rule fired on this `bash` call; `None`
        /// otherwise. UI-only (wire-vs-user split, GOALS §14). `#[serde(default)]`
        /// keeps the NDJSON wire backward-compatible with older peers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hint: Option<String>,
    },

    /// A resource-managed tool call is waiting for scheduler permits. UI-only:
    /// never enters model context.
    ResourceWait {
        session_id: Uuid,
        agent: String,
        request_id: Uuid,
        display_id: String,
        resources: HashMap<String, u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        queue_position: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command_label: Option<String>,
    },

    /// A resource-managed tool call acquired permits. UI-only.
    ResourceStart {
        session_id: Uuid,
        agent: String,
        request_id: Uuid,
        display_id: String,
        resources: HashMap<String, u32>,
        wait_ms: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command_label: Option<String>,
    },

    /// A resource-managed tool call released permits. UI-only.
    ResourceClear {
        session_id: Uuid,
        agent: String,
        request_id: Uuid,
        display_id: String,
        resources: HashMap<String, u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command_label: Option<String>,
    },

    /// Tool errored. The model sees this string as the tool result.
    /// `kind` distinguishes a bad call (the model's fault) from a bad
    /// outcome (the tool's fault) for the TUI's color treatment.
    ToolError {
        session_id: Uuid,
        agent: String,
        call_id: String,
        tool: String,
        error: String,
        kind: crate::engine::tool::ToolFailKind,
    },

    /// An inference call failed terminally (TTFT / idle timeout, connection
    /// error, or non-retryable HTTP —
    /// implementation note). The TUI
    /// renders a RED inline error (same treatment as `ToolError`): the spinner
    /// stops and the user sees provider/model + the reason. UI-only: never
    /// enters the model's context (the recorded failure event is the data side).
    InferenceFailed {
        session_id: Uuid,
        agent: String,
        provider: String,
        model: String,
        error_class: String,
        detail: String,
    },

    /// The primary model failed a qualifying inference and the turn was
    /// answered by the configured backup model
    /// (implementation note). The TUI renders a
    /// DISPLAY-ONLY YELLOW banner. Wire-vs-user split (GOALS §14): never enters
    /// model context.
    BackupUsed {
        session_id: Uuid,
        agent: String,
        primary_model: String,
        error_class: String,
        backup_model: String,
    },

    /// `task` invoked an interactive subagent; primary handoff begins.
    SubagentSpawned {
        session_id: Uuid,
        parent: String,
        child: String,
        task_call_id: String,
        label: String,
        prompt: String,
        requested_cwd: Option<String>,
        resolved_cwd: Option<String>,
        #[serde(default)]
        trusted_only: bool,
        #[serde(default)]
        model_trusted: bool,
        #[serde(default)]
        routing: serde_json::Value,
    },

    /// A subagent finished and emitted its report back to the parent.
    SubagentReport {
        session_id: Uuid,
        agent: String,
        task_call_id: String,
        label: String,
        report: String,
        #[serde(default)]
        trusted_only: bool,
        #[serde(default)]
        model_trusted: bool,
        #[serde(default)]
        routing: serde_json::Value,
    },

    /// A noninteractive child event forwarded through the parent session
    /// stream with enough lineage for clients to build a delegation tree.
    NestedTurn {
        session_id: Uuid,
        task_call_id: String,
        label: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_task_call_id: Option<String>,
        inner: Box<Event>,
    },

    /// Provider-reported token usage for the round-trip that just
    /// finished. Emitted once per `model.complete` call; absent when
    /// the provider didn't include a usage chunk.
    Usage {
        session_id: Uuid,
        agent: String,
        input_tokens: u64,
        output_tokens: u64,
        cached_input_tokens: u64,
        /// Input tokens written into the prompt cache on a miss (Anthropic
        /// `cache_creation`). Carried so the TUI's cache hit-rate display
        /// (prompt `prompt-caching-strategy.md`) sees the full per-turn
        /// cache picture.
        #[serde(default)]
        cache_creation_input_tokens: u64,
    },

    /// A background builder paused with a question (GOALS §3b). Wire
    /// shape lands now; the dispatch logic that pauses turns ships
    /// in a later milestone.
    InterruptRaised {
        session_id: Uuid,
        interrupt_id: Uuid,
        agent: String,
        description: String,
        /// Legacy single-question payload (the `schedule` needs-attention
        /// nudge raises with neither field set). Kept for wire
        /// back-compat; new question-tool interrupts use `questions`.
        #[serde(default)]
        question: Option<InterruptQuestion>,
        /// Multi-question batch (GOALS §3b). Present when an agent's
        /// `question` tool raised the interrupt; drives the answering
        /// dialog. Mutually exclusive with `question` in practice.
        #[serde(default)]
        questions: Option<InterruptQuestionSet>,
    },

    /// An outstanding interrupt was resolved — emitted to every client
    /// attached to the session (forward-compat for multi-client per
    /// GOALS §8e; v1 single-client receives it as a no-op echo).
    InterruptResolved {
        session_id: Uuid,
        interrupt_id: Uuid,
    },

    /// The agent yielded control back to the human: the driver loop
    /// finished the current user message (and any folded queue) and is
    /// now awaiting input. Distinct from the mid-turn gaps where no
    /// model call is in flight (between tools, between inference
    /// rounds) — this fires only when the stack unwinds to the root and
    /// the queue is empty. The TUI keys its span-long "agent is
    /// working" indicator off the user-submit (rising) / this (falling)
    /// edges. Forward-compat: it means "no longer actively working," so
    /// a future agent that is *waiting* (agent-invoked timers/loops)
    /// emits it too.
    AgentIdle {
        session_id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        turn_id: Option<String>,
    },

    /// The primary (root-frame) agent was swapped in place (`/plan` →
    /// `Plan`, `/build` → `Build`, `plan.md §4.6.d`). The client chrome's
    /// active-agent slot tracks `name`.
    PrimarySwapped {
        session_id: Uuid,
        name: String,
    },

    /// The active `llm_mode` was switched live (`/llm-mode`,
    /// implementation note). The client tracks `mode`
    /// so its `/llm-mode` toggle + cache-break warning resolve against the
    /// authoritative current value.
    LlmModeChanged {
        session_id: Uuid,
        mode: crate::config::extended::LlmMode,
    },

    /// The session ended (user requested, daemon shutting down,
    /// crash recovery couldn't restore it, …).
    SessionEnded {
        session_id: Uuid,
        reason: String,
    },

    /// An async job (loop / timer / background, GOALS §22) started.
    /// Drives the transient schedule strip. `kind` is `loop` / `timer` /
    /// `background`.
    ScheduleStarted {
        session_id: Uuid,
        job_id: String,
        label: String,
        kind: String,
    },
    /// A background job produced output (liveness tick for the strip).
    ScheduleProgress {
        session_id: Uuid,
        job_id: String,
    },
    /// A note from an ephemeral-fork loop iteration. Shown live in the
    /// transcript; the model sees it in main context only at loop end.
    ScheduleNote {
        session_id: Uuid,
        job_id: String,
        text: String,
    },
    /// An async job reached a terminal state (completed / failed /
    /// cancelled). Clears the strip entry + posts an inline marker; the
    /// model-facing result arrives separately as a late-arriving turn.
    ScheduleCompleted {
        session_id: Uuid,
        job_id: String,
        label: String,
        kind: String,
        failed: bool,
    },

    /// Live "% prunable" projection for the foreground agent (GOALS §1a).
    /// `prunable_tokens` is the wire-token drop `/prune` would achieve
    /// right now, computed by the same `dedup_plan` `/prune` executes.
    /// The TUI divides by the model's max context for the status line.
    ContextProjection {
        session_id: Uuid,
        prunable_tokens: u64,
        cache_cold: bool,
    },

    /// A `/prune` completed (manual or cache-aware auto). UI marker.
    /// `elided` is the **current** full set of `original_event_id`s whose
    /// tool-result body is now a wire-side elision marker; the TUI dims the
    /// matching scrollback tool-result bodies by `call_id`. Render-time
    /// view of live wire state, not a persisted transcript flag (§14).
    Pruned {
        session_id: Uuid,
        auto: bool,
        bodies: usize,
        tokens_saved: u64,
        #[serde(default)]
        elided: Vec<String>,
        /// Machine-readable auto-prune trigger reason. Present for automatic
        /// prunes and absent for manual `/prune`.
        #[serde(default)]
        trigger_reason: Option<String>,
        /// True when a warm prompt cache was broken by a ctx%-threshold
        /// auto-prune (implementation note); the client
        /// surfaces the shared cache-break warning.
        #[serde(default)]
        cache_break: bool,
    },

    /// A `/compact` handoff was assembled and applied in place.
    CompactReady {
        session_id: Uuid,
        new_session_id: Uuid,
        handoff: String,
        #[serde(default)]
        brief: String,
        seed_tool_count: usize,
        seed_tool_tokens: u64,
    },

    /// Sandboxing mode was set/toggled for the session (`/sandbox`). Broadcast
    /// to every attached client so they surface the resulting state.
    SandboxState {
        session_id: Uuid,
        mode: crate::tools::sandbox_mode::SandboxMode,
        enabled: bool,
        #[serde(default)]
        container_network_enabled: bool,
        container_availability: crate::container::ContainerAvailability,
    },

    /// The shell sandbox cannot initialize for this session (`bash` hit the
    /// refuse path — Linux userns case; `implementation notes` §6.5). Broadcast
    /// **once per session** (the worker de-dupes) so attached clients raise a
    /// deterministic, persistent, user-facing indicator. `remedy` is the
    /// diagnosed reason (incl. the `sudo sysctl …=0` command when diagnosed);
    /// the TUI renders it as a persistent below-input notice, cleared when a
    /// later `SandboxState { enabled: false }` arrives. Model-independent and
    /// never part of any inference request.
    SandboxUnavailable {
        session_id: Uuid,
        remedy: String,
    },

    /// Redaction sources were toggled for the session
    /// (`/toggle-redaction`). Broadcast to every attached client so they
    /// surface the resulting state (TUI: a toast). Session-only.
    RedactionState {
        session_id: Uuid,
        scan_environment: bool,
        scan_dotenv: bool,
        scan_ssh_keys: bool,
    },

    /// Request preflight was set/toggled for the session (`/preflight`,
    /// implementation note). Broadcast to every attached client so
    /// they surface the resulting state (TUI: a toast + the live `/preflight`
    /// description mirror). Session-only — reverts on restart.
    PreflightState {
        session_id: Uuid,
        enabled: bool,
    },

    /// Trusted-only inference mode was set/toggled for the session
    /// (`/trusted-only`). Broadcast to every attached client so they surface
    /// the resulting state and update the live slash-command description.
    TrustedOnlyState {
        session_id: Uuid,
        enabled: bool,
    },

    /// Command-approval mode changed for the session (`/quick`).
    ApprovalModeState {
        session_id: Uuid,
        mode: crate::config::extended::ApprovalMode,
    },

    /// Delegation recursion override changed for the session (`/quick`).
    DelegationRecursionState {
        session_id: Uuid,
        enabled: bool,
        default_depth: u32,
    },

    /// The session's model-comparison tandem (shadow) set changed
    /// (`/model-comparison`, implementation note).
    /// Broadcast to every attached client so they surface the resulting set
    /// (`models` = `provider/model` labels; empty = feature off) and, on a
    /// non-empty set, the one-line token-burn `warning` (warning only — no
    /// cap/meter). Session-only — reverts on restart.
    TandemState {
        session_id: Uuid,
        models: Vec<String>,
        #[serde(default)]
        warning: Option<String>,
    },

    /// The session's in-memory gitignore read-allowlist
    /// (implementation note) — the set of globs
    /// added via the approval flow's "Approve for this session" choice.
    /// Carries the **full current set** (replace, not delta) so the TUI's
    /// `@`-tag popup can union it with the persisted per-layer config and
    /// re-include session-approved gitignored entries. Broadcast on change
    /// (a new glob landed) and on attach (hydration), so a late/reconnecting
    /// client and any second concurrent client see prior approvals. Only the
    /// allow-set is ever broadcast — never the session reject-memory.
    /// Session-only — reverts on daemon restart. Never enters the model's
    /// context.
    GitignoreAllow {
        session_id: Uuid,
        allow: Vec<String>,
    },

    /// Caffeination (`/caffeinate`) turned on or off — including the
    /// daemon-decided `until-idle` auto-off. **Daemon-global**: carries no
    /// `session_id` and is broadcast to *every* connected client so the
    /// `☕` chrome glyph appears (and clears) on all of them in lockstep.
    /// `message` is `Some` for the originating client's toast; other
    /// clients use `active` to drive the glyph. `lid_close_guaranteed`
    /// lets a client word the lid-close caveat if it shows one.
    CaffeinateState {
        active: bool,
        lid_close_guaranteed: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },

    /// Remote relay connector state changed. **Daemon-global**: carries no
    /// session content and is broadcast to every connected client so status
    /// chrome can show connected/reconnecting/off without polling.
    ConnectorStatus {
        enabled: bool,
        status: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_error: Option<String>,
    },

    TerminalOutput {
        terminal_id: Uuid,
        bytes: Vec<u8>,
    },

    TerminalClipboard {
        terminal_id: Uuid,
        text: String,
    },

    TerminalViewers {
        terminal_id: Uuid,
        count: usize,
    },

    TerminalClosed {
        terminal_id: Uuid,
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
    },

    /// The daemon began (or escalated) a graceful shutdown
    /// (`daemon-graceful-drain-shutdown.md`). **Daemon-global**: carries no
    /// `session_id` and is broadcast to *every* connected client so each
    /// TUI shows the drain notice and stops offering new input. `forced` is
    /// `false` when the drain just began (in-flight work is finishing) and
    /// `true` once the grace deadline was hit with work still outstanding,
    /// so a truncated turn isn't mistaken for a clean finish.
    DaemonDraining {
        forced: bool,
    },

    /// A session has durable paused work that needs a user's explicit resume
    /// or cancel decision.
    PausedWorkAvailable {
        session_id: Uuid,
        items: Vec<PausedWorkSummary>,
    },

    /// A `readlock` in this session is blocked waiting on a lock held by
    /// another agent/session, or that wait just ended
    /// (implementation note). Per-session
    /// (`session_id`-scoped): the attached TUI shows a transient indicator
    /// — `` waiting for lock on `{path}` (held by `{holder_agent}`) `` —
    /// alongside the fixed chrome, like the `☕` caffeinate glyph, and
    /// clears it on `waiting == false` (lock acquired or wait cancelled).
    /// UI-only: never enters the model's context.
    WaitingForLock {
        session_id: Uuid,
        path: String,
        holder_agent: String,
        waiting: bool,
    },
}

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
                let header: EnvelopeHeader =
                    serde_json::from_str(&line).context("deserializing envelope header")?;
                if !is_protocol_compatible(header.v) {
                    return Ok(Some(RecvFrame::VersionMismatch {
                        v: header.v,
                        kind: header.kind,
                        id: header.id,
                    }));
                }
                let env: Envelope =
                    serde_json::from_str(&line).context("deserializing envelope")?;
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
