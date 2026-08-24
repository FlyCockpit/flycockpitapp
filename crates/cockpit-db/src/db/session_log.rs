//! Session-log capture: `inference_requests` + `session_events`.
//!
//! Two always-on surfaces (migration `0009_session_log.sql`) that feed
//! `cockpit export <session>`:
//!
//! - [`Db::insert_inference_request`] stores the full post-redaction
//!   assembled request body keyed by the same `call_id` the
//!   `inference_calls` metadata row uses.
//! - [`Db::insert_session_event`] appends one row to the per-session
//!   event timeline. `seq` (the AUTOINCREMENT rowid) is globally
//!   monotonic — the authoritative ordering across the whole fork tree —
//!   and `ts_ms` is millisecond-resolution for human reading.
//!
//! The event `type` discriminant aligns with the engine [`TurnEvent`]
//! vocabulary (see [`SessionEventKind`]); per-type fields ride in a JSON
//! payload so the schema is stable as the event set grows.
//!
//! [`TurnEvent`]: crate::engine::TurnEvent

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::db::Db;

const READ_SESSION_MESSAGES_MAX_LIMIT: u32 = 200;
const LIST_SESSION_EVENTS_MAX_LIMIT: u32 = 500;

/// Structural, content-free redaction descriptor for a trusted-body JSON
/// [`Value`]. Used by every manual `Debug` over a raw request / response /
/// payload body so `{:?}`/`tracing`/panic paths never print the verbatim
/// trusted artifact. Emits the JSON kind plus a coarse size (key/element count
/// or string length) — never a key name or value — behind the shared
/// `[REDACTED; …]` marker.
pub(crate) fn redacted_json_debug(value: &Value) -> String {
    match value {
        Value::Null => "[REDACTED; null]".to_string(),
        Value::Bool(_) => "[REDACTED; bool]".to_string(),
        Value::Number(_) => "[REDACTED; number]".to_string(),
        Value::String(s) => format!("[REDACTED; string; len {}]", s.len()),
        Value::Array(a) => format!("[REDACTED; array; {} items]", a.len()),
        Value::Object(o) => format!("[REDACTED; object; {} keys]", o.len()),
    }
}

/// Event-type discriminants for the session log. The string forms are
/// the stable on-disk + `events.json` values; keep them aligned with the
/// engine `TurnEvent` vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEventKind {
    /// The user's input text for a turn.
    UserMessage,
    /// A user-authored session-history note (`/note <text>`,
    /// implementation note). Carries the note `text`. A
    /// local-only annotation: rendered as a distinct transcript row and
    /// included in exports, but **never** part of the model-bound history —
    /// rehydration deliberately skips it (it is not in `rebuild_history`'s
    /// recognized set), so it never enters outbound context.
    UserNote,
    /// Assistant text (and reasoning, when captured).
    AssistantMessage,
    /// An inference request was sent. Carries `call_id` + the
    /// `inference_requests/` `file` name + token usage once known.
    InferenceRequest,
    /// A tool call resolved. Carries the wire-vs-user split + recovery, and
    /// — for `bash` calls only — a `sandbox` sub-object recording the
    /// confinement state (enabled / confined / escalated / broad-grant skip
    /// / approval scope) so an export is diagnosable across all four
    /// sandbox states. Data/export only; never enters the model's context.
    ToolCall,
    /// A model-comparison shadow inference record linked to its primary call.
    TandemInference,
    /// A model-requested tool call passed dispatch validation and entered the
    /// execution flow. Carries intent/input fields only so exports can measure
    /// queue/approval/gating time separately from runtime.
    ToolCallStarted,
    /// A previously started tool call reached a terminal lifecycle outcome.
    /// Carries result fields and an explicit status/dispatched flag; loop or
    /// safety blocks are represented as non-dispatched completions.
    ToolCallCompleted,
    /// A `task` delegation spawned a child fork.
    SubagentSpawned,
    /// A spawned subagent's resolved child routing became known.
    SubagentRouting,
    /// A subagent returned its report to the parent.
    SubagentReport,
    /// `/prune` (manual or auto) elided wire-only snapshot bodies.
    ContextPruned,
    /// `/compact` started a fresh successor session (a session boundary).
    SessionCompacted,
    /// The approval machinery resolved a permission decision (allow at a
    /// scope, or deny). Carries the trigger (`tool`/`tool_call_id`/the
    /// command line or path), the offered scope set, the decision, and the
    /// resolution source (`already_granted` / `user_prompt` /
    /// `headless_auto_reject` / `loop_guard_rule`). Data/export only.
    PermissionDecision,
    /// A user interactively resolved or dismissed a question/approval interrupt.
    InterruptDecision,
    /// The dispatcher's validate-then-repair path (GOALS §12) rejected a tool
    /// call **before** it became a `tool_call` row. Carries the attempted tool
    /// `name` and a `reason` (`not_in_advertised_set` /
    /// `schema_invalid_unrepairable`) so a hallucinated / unrepairable call is
    /// directly queryable instead of inferred from assistant prose.
    /// Data/export only.
    ToolRejected,
    /// The root-frame primary agent was swapped (GOALS §26). Carries `from`/`to`
    /// agent, the `trigger` (`handoff` tool vs a `/plan`/`/build`/`/swarm`
    /// slash-command swap), and — preserving the wire-vs-user split (GOALS §14)
    /// — both the user-facing `display` row and the model-facing wire `kickoff`
    /// (absent for the slash-command swaps, which inject no kickoff).
    /// Data/export only.
    PrimarySwap,
    /// An inference call failed
    /// (implementation note): a TTFT /
    /// idle timeout, a connection error, or a non-retryable HTTP response.
    /// Carries `provider`, `model`, `phase_reached`
    /// (`prep`/`dispatched`/`first_token`/`streaming`), typed `error_class`,
    /// and `elapsed_ms`. Cancellation is not an error class; it is recorded as
    /// the separate [`InferenceRequestStatus::Cancelled`] dispatch status.
    /// Keyed by the same `call_id` as the dispatch-time `inference_request`
    /// record. Data/export only — never enters the model's context (the
    /// user-facing inline error is a separate UI surface).
    InferenceFailure,
    /// A terminal inference failure aborted a turn and the driver captured the
    /// prompt/progress needed for an explicit retry. Data/export only; the
    /// model sees the retried prompt only if the user triggers the retry.
    FailedTurnRecovery,
    /// Daemon shutdown grace expired while this session still had live agent
    /// work. Data/export only; paired with an `interrupted` needs-attention
    /// marker so session lists surface the unrecoverable mid-turn stop.
    TurnInterrupted,
    /// The utility-model skill selector skipped or rejected auto-injection
    /// candidates. Data/export only: never enters the transcript or model
    /// context.
    SkillAutoSelect,
    /// Auto-prune evaluated a candidate plan and skipped it before mutating
    /// history. Data/export only: never enters the transcript or model
    /// context.
    AutoPruneDiagnostic,
    /// Active-goal continuation finished without a user-visible progress,
    /// status, tool, or failure event. Data/export only.
    GoalProgressDiagnostic,
    /// A user promoted or attempted to promote a queued resource-scheduler
    /// request. Data/export only.
    ResourcePromotion,
    /// A user-visible notice emitted by the engine or daemon. Carries
    /// redacted `text`, typed `severity`, and stable `source` metadata so
    /// exports preserve diagnostic warnings that were previously UI-only.
    Notice,
    /// The active-model switch transaction was attempted. Carries old/new
    /// provider/model ids, a closed trigger, outcome, and optional redacted
    /// error text. Data/export only.
    ModelSwitch,
    /// A configured hook handler reached an observable execution outcome.
    /// Carries only bounded, redacted audit metadata and is data/export only.
    HookRun,
    /// A turn scheduler recorded its lane/barrier decision for a tool call.
    /// The payload is core-owned JSON that records original call ids,
    /// lane/barrier classifications, and the terminal scheduling outcome
    /// only — never tool arguments, title candidates, or provider bodies.
    /// Data/export only; never enters the model's context.
    ToolCallScheduling,
}

impl SessionEventKind {
    pub const ALL: [Self; 28] = [
        Self::UserMessage,
        Self::UserNote,
        Self::AssistantMessage,
        Self::InferenceRequest,
        Self::ToolCall,
        Self::TandemInference,
        Self::ToolCallStarted,
        Self::ToolCallCompleted,
        Self::SubagentSpawned,
        Self::SubagentRouting,
        Self::SubagentReport,
        Self::ContextPruned,
        Self::SessionCompacted,
        Self::PermissionDecision,
        Self::InterruptDecision,
        Self::ToolRejected,
        Self::PrimarySwap,
        Self::InferenceFailure,
        Self::FailedTurnRecovery,
        Self::TurnInterrupted,
        Self::SkillAutoSelect,
        Self::AutoPruneDiagnostic,
        Self::GoalProgressDiagnostic,
        Self::ResourcePromotion,
        Self::Notice,
        Self::ModelSwitch,
        Self::HookRun,
        Self::ToolCallScheduling,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            SessionEventKind::UserMessage => "user_message",
            SessionEventKind::UserNote => "user_note",
            SessionEventKind::AssistantMessage => "assistant_message",
            SessionEventKind::InferenceRequest => "inference_request",
            SessionEventKind::TandemInference => "tandem_inference",
            SessionEventKind::ToolCall => "tool_call",
            SessionEventKind::ToolCallStarted => "tool_call_started",
            SessionEventKind::ToolCallCompleted => "tool_call_completed",
            SessionEventKind::SubagentSpawned => "subagent_spawned",
            SessionEventKind::SubagentRouting => "subagent_routing",
            SessionEventKind::SubagentReport => "subagent_report",
            SessionEventKind::ContextPruned => "context_pruned",
            SessionEventKind::SessionCompacted => "session_compacted",
            SessionEventKind::PermissionDecision => "permission_decision",
            SessionEventKind::InterruptDecision => "interrupt_decision",
            SessionEventKind::ToolRejected => "tool_rejected",
            SessionEventKind::PrimarySwap => "primary_swap",
            SessionEventKind::InferenceFailure => "inference_failure",
            SessionEventKind::FailedTurnRecovery => "failed_turn_recovery",
            SessionEventKind::TurnInterrupted => "turn_interrupted",
            SessionEventKind::SkillAutoSelect => "skill_auto_select",
            SessionEventKind::AutoPruneDiagnostic => "auto_prune_diagnostic",
            SessionEventKind::GoalProgressDiagnostic => "goal_progress_diagnostic",
            SessionEventKind::ResourcePromotion => "resource_promotion",
            SessionEventKind::Notice => "notice",
            SessionEventKind::ModelSwitch => "model_switch",
            SessionEventKind::HookRun => "hook_run",
            SessionEventKind::ToolCallScheduling => "tool_call_scheduling",
        }
    }
}

const HOOK_EVENT_MAX_BYTES: usize = 128;
const HOOK_CORRELATION_MAX_BYTES: usize = 256;
const HOOK_REASON_MAX_BYTES: usize = 1_024;

/// Closed outcome vocabulary for a configured hook invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookRunStatus {
    Success,
    Denied,
    Blocked,
    Failed,
}

impl HookRunStatus {
    pub const ALL: [Self; 4] = [Self::Success, Self::Denied, Self::Blocked, Self::Failed];
}

/// The complete safe projection persisted for one configured hook invocation.
///
/// This deliberately has no payload, process-output, command, working-directory,
/// environment, or transport fields. Import deserialization rejects every field
/// outside this projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookRunAudit {
    pub event: String,
    pub hook: String,
    pub origin: String,
    pub status: HookRunStatus,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subagent_id: Option<String>,
}

impl HookRunAudit {
    /// Parse an imported hook-run payload through the same closed validation
    /// used for live writes. Unknown and sensitive fields are rejected by
    /// `deny_unknown_fields` before any row can be restored.
    pub fn from_json(value: &Value) -> Result<Self> {
        let audit: Self = serde_json::from_value(value.clone())
            .context("parsing closed hook_run audit payload")?;
        audit.validated_import()
    }

    fn validated_live(mut self) -> Result<Self> {
        self.validate_common()?;
        self.reason = self
            .reason
            .map(|reason| truncate_utf8_bytes(&reason, HOOK_REASON_MAX_BYTES));
        Ok(self)
    }

    fn validated_import(self) -> Result<Self> {
        self.validate_common()?;
        if let Some(reason) = self.reason.as_deref() {
            anyhow::ensure!(
                reason.len() <= HOOK_REASON_MAX_BYTES,
                "hook_run `reason` exceeds {HOOK_REASON_MAX_BYTES} bytes"
            );
        }
        Ok(self)
    }

    fn validate_common(&self) -> Result<()> {
        validate_event_name(&self.event)?;
        validate_hook_origin("hook", &self.hook)?;
        validate_hook_origin("origin", &self.origin)?;
        for (field, value, max) in [
            (
                "turn_id",
                self.turn_id.as_deref(),
                HOOK_CORRELATION_MAX_BYTES,
            ),
            ("tool_name", self.tool_name.as_deref(), HOOK_EVENT_MAX_BYTES),
            (
                "tool_call_id",
                self.tool_call_id.as_deref(),
                HOOK_CORRELATION_MAX_BYTES,
            ),
            (
                "subagent_id",
                self.subagent_id.as_deref(),
                HOOK_CORRELATION_MAX_BYTES,
            ),
        ] {
            if let Some(value) = value {
                validate_bounded_text(field, value, max)?;
            }
        }
        Ok(())
    }
}

fn validate_event_name(value: &str) -> Result<()> {
    validate_bounded_text("event", value, HOOK_EVENT_MAX_BYTES)?;
    anyhow::ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
        "hook_run `event` must be an ASCII identifier"
    );
    Ok(())
}

fn validate_bounded_text(field: &str, value: &str, max_bytes: usize) -> Result<()> {
    anyhow::ensure!(!value.is_empty(), "hook_run `{field}` must not be empty");
    anyhow::ensure!(
        value.len() <= max_bytes,
        "hook_run `{field}` exceeds {max_bytes} bytes"
    );
    Ok(())
}

fn validate_hook_origin(field: &str, value: &str) -> Result<()> {
    let mut parts = value.split(':');
    let layer = parts.next().unwrap_or_default();
    let digest = parts.next().unwrap_or_default();
    let index = parts.next().unwrap_or_default();
    anyhow::ensure!(parts.next().is_none(), "invalid hook_run `{field}` origin");
    anyhow::ensure!(
        matches!(
            layer,
            "global" | "user" | "machine" | "project" | "explicit"
        ),
        "invalid hook_run `{field}` layer kind"
    );
    anyhow::ensure!(
        digest.len() == 16
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid hook_run `{field}` source digest"
    );
    let parsed_index = index
        .parse::<usize>()
        .with_context(|| format!("invalid hook_run `{field}` handler index"))?;
    anyhow::ensure!(
        parsed_index.to_string() == index,
        "invalid hook_run `{field}` handler index"
    );
    Ok(())
}

fn truncate_utf8_bytes(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

/// Terminal lifecycle status of an inference attempt's dispatch-time record
/// (implementation note). Written
/// `Pending` at dispatch and updated to a terminal value on settle so a hung
/// or failed turn still exports a record with a non-`completed` status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InferenceRequestStatus {
    /// Dispatched; not yet settled (the state a hung turn is frozen in).
    Pending,
    /// Returned successfully.
    Completed,
    /// Failed with a non-timeout error (network / non-retryable HTTP).
    Errored,
    /// Aborted by a TTFT or idle stream timeout.
    TimedOut,
    /// Aborted by the user (ctrl+c).
    Cancelled,
}

impl InferenceRequestStatus {
    pub const ALL: [Self; 5] = [
        Self::Pending,
        Self::Completed,
        Self::Errored,
        Self::TimedOut,
        Self::Cancelled,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            InferenceRequestStatus::Pending => "pending",
            InferenceRequestStatus::Completed => "completed",
            InferenceRequestStatus::Errored => "errored",
            InferenceRequestStatus::TimedOut => "timed_out",
            InferenceRequestStatus::Cancelled => "cancelled",
        }
    }
}

/// Per-attempt provider/model/trust metadata stamped on an inference-attempt
/// row at body-insert time. Nullable columns: a write path that does not know
/// one leaves it `None`.
#[derive(Debug, Clone, Copy, Default)]
pub struct InferenceAttemptMeta<'a> {
    pub provider: Option<&'a str>,
    pub model: Option<&'a str>,
    pub trust: Option<&'a str>,
}

/// Phase timestamps (ms from dispatch) written by the monotonic status-advance
/// path only. A `None` field leaves the existing column untouched (`COALESCE`),
/// so an advance never clears a phase a prior advance recorded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InferencePhaseTimings {
    pub first_token_ms: Option<i64>,
    pub completed_ms: Option<i64>,
    pub failed_ms: Option<i64>,
}

/// One inference-attempt row read back from `inference_requests`, keyed
/// `(call_id, ordinal)`. `payload` is the immutable post-render request body;
/// lifecycle metadata (`status` + phase columns) lives beside it, never inside
/// it. (`serde_json::Value` is not `Eq`, so this derives `PartialEq` only.)
#[derive(Clone, PartialEq)]
pub struct InferenceRequestRow {
    pub call_id: String,
    pub ordinal: i64,
    pub session_id: String,
    pub ts_ms: i64,
    pub payload: Value,
    pub status: String,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub trust: Option<String>,
    pub first_token_ms: Option<i64>,
    pub completed_ms: Option<i64>,
    pub failed_ms: Option<i64>,
}

impl std::fmt::Debug for InferenceRequestRow {
    /// `payload` is the raw trusted request body; never print it verbatim. Show
    /// its structural descriptor plus the (non-body) lifecycle metadata.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InferenceRequestRow")
            .field("call_id", &self.call_id)
            .field("ordinal", &self.ordinal)
            .field("session_id", &self.session_id)
            .field("ts_ms", &self.ts_ms)
            .field(
                "payload",
                &format_args!("{}", redacted_json_debug(&self.payload)),
            )
            .field("status", &self.status)
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("trust", &self.trust)
            .field("first_token_ms", &self.first_token_ms)
            .field("completed_ms", &self.completed_ms)
            .field("failed_ms", &self.failed_ms)
            .finish()
    }
}

/// A full inference-attempt row restored by the import path. Unlike live
/// dispatch (body insert then monotonic status-advance), a restore writes the
/// already-terminal row — body, status, phases, and per-attempt metadata — in
/// one authoritative insert.
#[derive(Clone)]
pub struct ImportedInferenceRequest<'a> {
    pub call_id: &'a str,
    pub ordinal: i64,
    pub session_id: Uuid,
    pub ts_ms: i64,
    pub payload: &'a Value,
    pub status: &'a str,
    pub provider: Option<&'a str>,
    pub model: Option<&'a str>,
    pub trust: Option<&'a str>,
    pub phases: InferencePhaseTimings,
}

impl std::fmt::Debug for ImportedInferenceRequest<'_> {
    /// `payload` is the raw trusted request body carried by the import path;
    /// never print it verbatim. Show its structural descriptor plus metadata.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedInferenceRequest")
            .field("call_id", &self.call_id)
            .field("ordinal", &self.ordinal)
            .field("session_id", &self.session_id)
            .field("ts_ms", &self.ts_ms)
            .field(
                "payload",
                &format_args!("{}", redacted_json_debug(self.payload)),
            )
            .field("status", &self.status)
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("trust", &self.trust)
            .field("phases", &self.phases)
            .finish()
    }
}

/// Columns of `inference_requests` in canonical read order.
const INFERENCE_REQUEST_COLUMNS: &str = "call_id, ordinal, session_id, ts_ms, payload_json, \
     status, provider, model, trust, first_token_ms, completed_ms, failed_ms";

struct RawInferenceRequestRow {
    call_id: String,
    ordinal: i64,
    session_id: String,
    ts_ms: i64,
    payload_json: String,
    status: String,
    provider: Option<String>,
    model: Option<String>,
    trust: Option<String>,
    first_token_ms: Option<i64>,
    completed_ms: Option<i64>,
    failed_ms: Option<i64>,
}

fn decode_inference_request_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<RawInferenceRequestRow> {
    Ok(RawInferenceRequestRow {
        call_id: row.get(0)?,
        ordinal: row.get(1)?,
        session_id: row.get(2)?,
        ts_ms: row.get(3)?,
        payload_json: row.get(4)?,
        status: row.get(5)?,
        provider: row.get(6)?,
        model: row.get(7)?,
        trust: row.get(8)?,
        first_token_ms: row.get(9)?,
        completed_ms: row.get(10)?,
        failed_ms: row.get(11)?,
    })
}

impl RawInferenceRequestRow {
    fn into_row(self) -> Result<InferenceRequestRow> {
        let payload: Value =
            serde_json::from_str(&self.payload_json).context("deserializing payload_json")?;
        Ok(InferenceRequestRow {
            call_id: self.call_id,
            ordinal: self.ordinal,
            session_id: self.session_id,
            ts_ms: self.ts_ms,
            payload,
            status: self.status,
            provider: self.provider,
            model: self.model,
            trust: self.trust,
            first_token_ms: self.first_token_ms,
            completed_ms: self.completed_ms,
            failed_ms: self.failed_ms,
        })
    }
}

/// Optional context stamped onto a `session_events` row.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionEventContext<'a> {
    pub origin_principal: Option<&'a str>,
    pub task_call_id: Option<&'a str>,
    pub label: Option<&'a str>,
    pub provider_id: Option<&'a str>,
    pub model_id: Option<&'a str>,
    pub llm_mode: Option<&'a str>,
    pub model_trust: Option<&'a str>,
}

/// A row read back from `session_events`.
#[derive(Clone)]
pub struct SessionEventRow {
    pub seq: i64,
    pub session_id: Uuid,
    pub ts_ms: i64,
    pub kind: String,
    pub agent: Option<String>,
    pub call_id: Option<String>,
    pub task_call_id: Option<String>,
    pub label: Option<String>,
    pub origin_principal: Option<String>,
    pub provider_id: Option<String>,
    pub model_id: Option<String>,
    pub llm_mode: Option<String>,
    pub model_trust: Option<String>,
    pub data: Value,
}

impl std::fmt::Debug for SessionEventRow {
    /// `data` is the raw trusted per-event JSON payload; never print it
    /// verbatim. Show its structural descriptor plus the (non-body) event
    /// metadata.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionEventRow")
            .field("seq", &self.seq)
            .field("session_id", &self.session_id)
            .field("ts_ms", &self.ts_ms)
            .field("kind", &self.kind)
            .field("agent", &self.agent)
            .field("call_id", &self.call_id)
            .field("task_call_id", &self.task_call_id)
            .field("label", &self.label)
            .field("origin_principal", &self.origin_principal)
            .field("provider_id", &self.provider_id)
            .field("model_id", &self.model_id)
            .field("llm_mode", &self.llm_mode)
            .field("model_trust", &self.model_trust)
            .field("data", &format_args!("{}", redacted_json_debug(&self.data)))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSubmissionReceiptRow {
    pub seq: i64,
    pub fingerprint: String,
    pub wire_fingerprint: String,
    pub origin_principal: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientSubmissionTerminalDisposition {
    Removed,
    Cancelled,
    PreflightRejected,
}

impl ClientSubmissionTerminalDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::Cancelled => "cancelled",
            Self::PreflightRejected => "preflight_rejected",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "removed" => Ok(Self::Removed),
            "cancelled" => Ok(Self::Cancelled),
            "preflight_rejected" => Ok(Self::PreflightRejected),
            other => bail!("unknown client submission terminal disposition {other:?}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSubmissionTerminalReceipt {
    pub client_submission_id: Uuid,
    pub fingerprint: String,
    pub wire_fingerprint: String,
    pub origin_principal: Option<String>,
    pub disposition: ClientSubmissionTerminalDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSubmissionTerminalReceiptRow {
    pub fingerprint: String,
    pub wire_fingerprint: String,
    pub origin_principal: Option<String>,
    pub disposition: ClientSubmissionTerminalDisposition,
}

/// Bounded page of session events strictly before a cursor, ordered by `seq`
/// ascending like the full event readers.
#[derive(Debug, Clone)]
pub struct SessionEventPage {
    pub events: Vec<SessionEventRow>,
    pub has_more: bool,
    pub oldest_seq: Option<i64>,
}

/// Current epoch milliseconds. One helper so every session-log timestamp
/// uses the same clock + resolution.
pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

impl Db {
    /// Return the committed timeline row for a durable compaction identity.
    /// The matching partial unique index makes this the authoritative
    /// idempotency lookup for restart recovery.
    pub async fn session_compaction_event_seq(
        &self,
        session_id: Uuid,
        compaction_id: Uuid,
    ) -> Result<Option<i64>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT seq FROM session_events
                  WHERE session_id = ?1
                    AND type = 'session_compacted'
                    AND json_extract(data_json, '$.compaction_id') = ?2",
                params![session_id.to_string(), compaction_id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .context("querying compaction timeline identity")
        })
        .await
    }

    /// Persist one live hook-run audit through its closed safe projection.
    ///
    /// Ledger failure must remain best-effort at the hook runtime call site:
    /// callers must log and continue rather than alter or repeat a hook result.
    pub async fn insert_hook_run(&self, session_id: Uuid, audit: HookRunAudit) -> Result<i64> {
        let audit = audit.validated_live()?;
        let data_json = serde_json::to_string(&audit).context("serializing hook_run audit")?;
        let ts_ms = now_ms();
        self.write(move |conn| Self::insert_hook_run_json_conn(conn, session_id, ts_ms, &data_json))
            .await
    }

    /// Restore one imported hook-run row after closed typed parsing.
    pub fn insert_imported_hook_run_conn(
        conn: &Connection,
        session_id: Uuid,
        ts_ms: i64,
        data: &Value,
    ) -> Result<i64> {
        let audit = HookRunAudit::from_json(data)?;
        let data_json = serde_json::to_string(&audit).context("serializing hook_run audit")?;
        Self::insert_hook_run_json_conn(conn, session_id, ts_ms, &data_json)
    }

    fn insert_hook_run_json_conn(
        conn: &Connection,
        session_id: Uuid,
        ts_ms: i64,
        data_json: &str,
    ) -> Result<i64> {
        // Hook correlations intentionally live only in the closed JSON
        // projection. Populating generic columns would create a second,
        // independently writable representation and weaken the sole-writer
        // guarantee.
        Self::insert_session_event_json_conn_unchecked(
            conn,
            session_id,
            SessionEventKind::HookRun,
            None,
            None,
            SessionEventContext::default(),
            ts_ms,
            data_json,
        )
    }

    pub async fn store_compaction_payload(
        &self,
        handoff_id: Uuid,
        session_id: Uuid,
        payload_json: &str,
    ) -> Result<()> {
        let payload_json = payload_json.to_string();
        self.write(move |conn| {
            Self::store_compaction_payload_conn(conn, handoff_id, session_id, &payload_json)
        })
        .await
    }

    /// Connection-scoped compaction-payload insert, so a trusted compaction
    /// record can compose the offloaded-payload write with its protected
    /// redaction-history journal in one transaction (K1). No crypto here — the
    /// blob is stored opaque; the caller in `cockpit-core` owns matching /
    /// encryption.
    pub fn store_compaction_payload_conn(
        conn: &Connection,
        handoff_id: Uuid,
        session_id: Uuid,
        payload_json: &str,
    ) -> Result<()> {
        if let Some(existing) = Self::compaction_payload_conn(
            conn,
            session_id,
            &handoff_id.to_string(),
        )? {
            anyhow::ensure!(
                existing == payload_json,
                "compaction payload identity reused with different content"
            );
            return Ok(());
        }
        conn.execute(
            "INSERT INTO compaction_handoffs (handoff_id, session_id, payload_json, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
            params![
                handoff_id.to_string(),
                session_id.to_string(),
                payload_json,
                now_ms(),
            ],
        )
        .context("storing compaction payload")?;
        Ok(())
    }

    pub fn compaction_payload_conn(
        conn: &Connection,
        session_id: Uuid,
        handoff_id: &str,
    ) -> Result<Option<String>> {
        let mut stmt = conn
            .prepare(
                "SELECT payload_json FROM compaction_handoffs
                  WHERE handoff_id = ?1 AND session_id = ?2",
            )
            .context("preparing compaction payload lookup")?;
        let mut rows = stmt
            .query(params![handoff_id, session_id.to_string()])
            .context("querying compaction payload")?;
        rows.next()
            .context("reading compaction payload")?
            .map(|row| row.get(0))
            .transpose()
            .context("decoding compaction payload")
    }

    pub async fn compaction_payload(
        &self,
        session_id: Uuid,
        handoff_id: &str,
    ) -> Result<Option<String>> {
        let handoff_id = handoff_id.to_string();
        self.read(move |conn| Self::compaction_payload_conn(conn, session_id, &handoff_id))
            .await
    }

    /// Read one inference attempt keyed `(call_id, ordinal)`.
    pub fn get_inference_request_conn(
        conn: &Connection,
        call_id: &str,
        ordinal: i64,
    ) -> Result<Option<InferenceRequestRow>> {
        let result: rusqlite::Result<RawInferenceRequestRow> = conn.query_row(
            &format!(
                "SELECT {INFERENCE_REQUEST_COLUMNS} FROM inference_requests \
                 WHERE call_id = ?1 AND ordinal = ?2"
            ),
            params![call_id, ordinal],
            decode_inference_request_row,
        );
        match result {
            Ok(raw) => Ok(Some(raw.into_row()?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e).context("querying inference_request"),
        }
    }

    /// Every attempt of one logical `call_id`, ordered by ordinal ascending
    /// (primary first). Multi-attempt consumers (export, failover auditing)
    /// read the per-attempt immutable bodies through this.
    pub fn list_inference_requests_for_call_conn(
        conn: &Connection,
        call_id: &str,
    ) -> Result<Vec<InferenceRequestRow>> {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {INFERENCE_REQUEST_COLUMNS} FROM inference_requests \
                 WHERE call_id = ?1 ORDER BY ordinal ASC"
            ))
            .context("preparing list_inference_requests_for_call")?;
        let rows = stmt.query_map([call_id], decode_inference_request_row)?;
        let mut out = Vec::new();
        for raw in rows {
            out.push(raw.context("querying inference_requests")?.into_row()?);
        }
        Ok(out)
    }

    /// Restore an exported inference attempt within an existing transaction.
    /// A restore writes the already-terminal row authoritatively — body,
    /// status, phase columns, and per-attempt provider/model/trust — keyed
    /// `(call_id, ordinal)`. The archive timestamp is authoritative; unlike
    /// live dispatch this does not substitute the current clock.
    ///
    /// The IMMUTABLE audited body (`payload_json`) is NEVER rewritten on
    /// conflict: a re-import of an already-present `(call_id, ordinal)` refreshes
    /// only lifecycle columns (status, phase timestamps) and leaves the stored
    /// post-render body byte-for-byte as first imported. Re-import stays
    /// idempotent (identical archive ⇒ identical row) but cannot mutate a stored
    /// body, preserving the immutability funnel across the import path too.
    pub fn insert_inference_request_conn(
        conn: &Connection,
        req: &ImportedInferenceRequest<'_>,
    ) -> Result<()> {
        if !matches!(
            req.status,
            "pending" | "completed" | "errored" | "timed_out" | "cancelled"
        ) {
            bail!("invalid imported inference request status `{}`", req.status);
        }
        let payload_json =
            serde_json::to_string(req.payload).context("serializing request payload")?;
        conn.execute(
            "INSERT INTO inference_requests
               (call_id, ordinal, session_id, ts_ms, payload_json, status,
                provider, model, trust, first_token_ms, completed_ms, failed_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(call_id, ordinal) DO UPDATE SET
               session_id     = excluded.session_id,
               ts_ms          = excluded.ts_ms,
               status         = excluded.status,
               provider       = excluded.provider,
               model          = excluded.model,
               trust          = excluded.trust,
               first_token_ms = excluded.first_token_ms,
               completed_ms   = excluded.completed_ms,
               failed_ms      = excluded.failed_ms",
            params![
                req.call_id,
                req.ordinal,
                req.session_id.to_string(),
                req.ts_ms,
                payload_json,
                req.status,
                req.provider,
                req.model,
                req.trust,
                req.phases.first_token_ms,
                req.phases.completed_ms,
                req.phases.failed_ms,
            ],
        )
        .context("restoring inference_request")?;
        Ok(())
    }

    /// Insert the IMMUTABLE post-render request body for one dispatched-target
    /// attempt, keyed `(call_id, ordinal)`, with initial status `pending` and
    /// the per-attempt provider/model/trust metadata. This is INSERT-ONLY: a
    /// second body write to an existing `(call_id, ordinal)` raises a UNIQUE
    /// constraint error rather than rewriting the audited body. Phase columns
    /// and the terminal status are filled separately by
    /// [`Self::advance_inference_request`].
    pub async fn insert_inference_request(
        &self,
        call_id: &str,
        ordinal: i64,
        session_id: Uuid,
        payload: &Value,
        meta: InferenceAttemptMeta<'_>,
        goal_provenance: Option<(Uuid, i64)>,
    ) -> Result<()> {
        let payload_json = serde_json::to_string(payload).context("serializing request payload")?;
        let call_id = call_id.to_owned();
        let provider = meta.provider.map(str::to_owned);
        let model = meta.model.map(str::to_owned);
        let trust = meta.trust.map(str::to_owned);
        self.write(move |conn| {
            let meta = InferenceAttemptMeta {
                provider: provider.as_deref(),
                model: model.as_deref(),
                trust: trust.as_deref(),
            };
            Self::insert_inference_attempt_body_conn(
                conn,
                &call_id,
                ordinal,
                session_id,
                &payload_json,
                meta,
                goal_provenance,
            )?;
            Ok(())
        })
        .await
    }

    /// Connection-scoped form of the production dispatch insert
    /// ([`Self::insert_inference_request`]): write the IMMUTABLE post-render
    /// request body for one attempt keyed `(call_id, ordinal)` with initial
    /// status `pending` and the per-attempt provider/model/trust metadata.
    ///
    /// This is INSERT-ONLY (a plain `INSERT`, no `ON CONFLICT`): a second body
    /// write to an existing `(call_id, ordinal)` raises a UNIQUE constraint
    /// error rather than rewriting the audited body, so a success unambiguously
    /// means this call is the one that FIRST persisted the payload for that
    /// attempt. Returns the number of rows inserted (always `1` on success).
    /// Callers that must compose the payload write with protected-history
    /// journal rows in one transaction use this instead of the async
    /// [`Self::insert_inference_request`], keying "journal on first insert" off
    /// the returned count. `payload_json` is the already-serialized body.
    pub fn insert_inference_attempt_body_conn(
        conn: &Connection,
        call_id: &str,
        ordinal: i64,
        session_id: Uuid,
        payload_json: &str,
        meta: InferenceAttemptMeta<'_>,
        goal_provenance: Option<(Uuid, i64)>,
    ) -> Result<usize> {
        let affected = conn
            .execute(
                "INSERT INTO inference_requests
                   (call_id, ordinal, session_id, ts_ms, payload_json, status,
                    provider, model, trust, goal_id, goal_attempt_generation)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7, ?8, ?9, ?10)",
                params![
                    call_id,
                    ordinal,
                    session_id.to_string(),
                    now_ms(),
                    payload_json,
                    meta.provider,
                    meta.model,
                    meta.trust,
                    goal_provenance.map(|(goal_id, _)| goal_id.to_string()),
                    goal_provenance.map(|(_, generation)| generation),
                ],
            )
            .context("inserting inference_request")?;
        Ok(affected)
    }

    /// Advance one attempt's lifecycle: set `status` (monotonically) and fill
    /// phase-timestamp columns. This NEVER touches `payload_json` — the body is
    /// immutable once inserted. Status precedence: ONLY a `pending` row may
    /// advance, and it advances to whatever terminal the incoming status names;
    /// once a row holds any terminal (`completed`/`errored`/`timed_out`/
    /// `cancelled`) that terminal is STICKY — no later advance (terminal or
    /// `pending`) can change it. This guarantees a terminal never regresses,
    /// including the `errored → completed` direction a late success observation
    /// could otherwise force. Phase columns are `COALESCE`d so an advance only
    /// fills a column it actually carries.
    pub async fn advance_inference_request(
        &self,
        call_id: &str,
        ordinal: i64,
        status: InferenceRequestStatus,
        phases: InferencePhaseTimings,
    ) -> Result<()> {
        let call_id = call_id.to_owned();
        self.write(move |conn| {
            conn.execute(
                "UPDATE inference_requests SET
                   status = CASE
                     WHEN status = 'pending' AND ?3 <> 'pending' THEN ?3
                     ELSE status
                   END,
                   first_token_ms = COALESCE(?4, first_token_ms),
                   completed_ms   = COALESCE(?5, completed_ms),
                   failed_ms      = COALESCE(?6, failed_ms)
                 WHERE call_id = ?1 AND ordinal = ?2",
                params![
                    call_id,
                    ordinal,
                    status.as_str(),
                    phases.first_token_ms,
                    phases.completed_ms,
                    phases.failed_ms,
                ],
            )
            .context("advancing inference_request status")?;
            Ok(())
        })
        .await
    }

    /// Append one event to the per-session timeline. Returns the assigned
    /// monotonic `seq` (the rowid). `data` carries the per-type payload.
    pub async fn insert_session_event(
        &self,
        session_id: Uuid,
        kind: SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        data: &Value,
    ) -> Result<i64> {
        self.insert_session_event_with_origin(session_id, kind, agent, call_id, None, data)
            .await
    }

    pub async fn insert_session_event_with_origin(
        &self,
        session_id: Uuid,
        kind: SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        origin_principal: Option<&str>,
        data: &Value,
    ) -> Result<i64> {
        self.insert_session_event_with_context(
            session_id,
            kind,
            agent,
            call_id,
            SessionEventContext {
                origin_principal,
                task_call_id: None,
                label: None,
                provider_id: None,
                model_id: None,
                llm_mode: None,
                model_trust: None,
            },
            data,
        )
        .await
    }

    pub async fn insert_session_event_with_context(
        &self,
        session_id: Uuid,
        kind: SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        context: SessionEventContext<'_>,
        data: &Value,
    ) -> Result<i64> {
        reject_generic_hook_run(kind)?;
        let data_json = serde_json::to_string(data).context("serializing event data")?;
        let ts_ms = now_ms();
        let agent = agent.map(str::to_owned);
        let call_id = call_id.map(str::to_owned);
        let task_call_id = context.task_call_id.map(str::to_owned);
        let label = context.label.map(str::to_owned);
        let origin_principal = context.origin_principal.map(str::to_owned);
        let provider_id = context.provider_id.map(str::to_owned);
        let model_id = context.model_id.map(str::to_owned);
        let llm_mode = context.llm_mode.map(str::to_owned);
        let model_trust = context.model_trust.map(str::to_owned);
        self.write(move |conn| {
            Self::insert_session_event_json_conn(
                conn,
                session_id,
                kind,
                agent.as_deref(),
                call_id.as_deref(),
                SessionEventContext {
                    origin_principal: origin_principal.as_deref(),
                    task_call_id: task_call_id.as_deref(),
                    label: label.as_deref(),
                    provider_id: provider_id.as_deref(),
                    model_id: model_id.as_deref(),
                    llm_mode: llm_mode.as_deref(),
                    model_trust: model_trust.as_deref(),
                },
                ts_ms,
                &data_json,
            )
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_session_event_json_conn(
        conn: &Connection,
        session_id: Uuid,
        kind: SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        context: SessionEventContext<'_>,
        ts_ms: i64,
        data_json: &str,
    ) -> Result<i64> {
        reject_generic_hook_run(kind)?;
        Self::insert_session_event_json_conn_unchecked(
            conn, session_id, kind, agent, call_id, context, ts_ms, data_json,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_session_event_json_conn_unchecked(
        conn: &Connection,
        session_id: Uuid,
        kind: SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        context: SessionEventContext<'_>,
        ts_ms: i64,
        data_json: &str,
    ) -> Result<i64> {
        conn.execute(
            "INSERT INTO session_events
             (session_id, ts_ms, type, agent, call_id, task_call_id, label, origin_principal,
              provider_id, model_id, llm_mode, model_trust, data_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                session_id.to_string(),
                ts_ms,
                kind.as_str(),
                agent,
                call_id,
                context.task_call_id,
                context.label,
                context.origin_principal,
                context.provider_id,
                context.model_id,
                context.llm_mode,
                context.model_trust,
                data_json,
            ],
        )
        .context("inserting session_event")?;
        Ok(conn.last_insert_rowid())
    }

    /// All events for one session, ordered by `seq` (oldest first). Used
    /// by the exporter to merge per-fork timelines.
    pub async fn list_session_events(&self, session_id: Uuid) -> Result<Vec<SessionEventRow>> {
        self.read(move |conn| Self::list_session_events_conn(conn, session_id))
            .await
    }

    /// Return the durable user-message row for a client idempotency key.
    /// One folded row can represent multiple accepted submissions.
    pub async fn client_submission_receipt(
        &self,
        session_id: Uuid,
        client_submission_id: Uuid,
    ) -> Result<Option<ClientSubmissionReceiptRow>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT e.seq,
                        json_extract(receipt.value, '$.fingerprint'),
                        json_extract(receipt.value, '$.wire_fingerprint'),
                        json_extract(receipt.value, '$.origin_principal')
                   FROM session_events e,
                        json_each(e.data_json, '$.client_submissions') receipt
                  WHERE e.session_id = ?1
                    AND e.type = 'user_message'
                    AND json_extract(receipt.value, '$.id') = ?2
                  LIMIT 1",
                params![session_id.to_string(), client_submission_id.to_string()],
                |row| {
                    Ok(ClientSubmissionReceiptRow {
                        seq: row.get(0)?,
                        fingerprint: row.get(1)?,
                        wire_fingerprint: row.get(2)?,
                        origin_principal: row.get(3)?,
                    })
                },
            )
            .optional()
            .context("looking up client submission id")
        })
        .await
    }

    /// Persist terminal accepted-submission dispositions atomically. Repeating
    /// the exact batch is idempotent; reusing a UUID with different receipt
    /// metadata or a different terminal disposition is an integrity error.
    pub async fn insert_client_submission_terminal_receipts(
        &self,
        session_id: Uuid,
        receipts: Vec<ClientSubmissionTerminalReceipt>,
    ) -> Result<()> {
        if receipts.is_empty() {
            return Ok(());
        }
        self.transaction(move |conn| {
            Self::insert_client_submission_terminal_receipts_conn(conn, session_id, &receipts)
        })
        .await
    }

    pub fn insert_client_submission_terminal_receipts_conn(
        conn: &Connection,
        session_id: Uuid,
        receipts: &[ClientSubmissionTerminalReceipt],
    ) -> Result<()> {
        for receipt in receipts {
            let id = receipt.client_submission_id.to_string();
            let disposition = receipt.disposition.as_str();
            let inserted = conn
                .execute(
                    "INSERT OR IGNORE INTO client_submission_terminal_receipts
                         (session_id, client_submission_id, fingerprint, wire_fingerprint,
                          origin_principal, disposition, created_at_ms)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        session_id.to_string(),
                        id,
                        &receipt.fingerprint,
                        &receipt.wire_fingerprint,
                        receipt.origin_principal.as_deref(),
                        disposition,
                        now_ms(),
                    ],
                )
                .context("inserting terminal client submission receipt")?;
            if inserted == 0 {
                let existing = conn
                    .query_row(
                        "SELECT fingerprint, wire_fingerprint, origin_principal, disposition
                               FROM client_submission_terminal_receipts
                              WHERE session_id = ?1 AND client_submission_id = ?2",
                        params![session_id.to_string(), id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, Option<String>>(2)?,
                                row.get::<_, String>(3)?,
                            ))
                        },
                    )
                    .context("reading existing terminal client submission receipt")?;
                if existing.0 != receipt.fingerprint
                    || existing.1 != receipt.wire_fingerprint
                    || existing.2.as_ref() != receipt.origin_principal.as_ref()
                    || existing.3 != disposition
                {
                    bail!(
                        "client submission {} already has a different terminal receipt",
                        receipt.client_submission_id
                    );
                }
            }
        }
        Ok(())
    }

    pub async fn client_submission_terminal_receipt(
        &self,
        session_id: Uuid,
        client_submission_id: Uuid,
    ) -> Result<Option<ClientSubmissionTerminalReceiptRow>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT fingerprint, wire_fingerprint, origin_principal, disposition
                   FROM client_submission_terminal_receipts
                  WHERE session_id = ?1 AND client_submission_id = ?2",
                params![session_id.to_string(), client_submission_id.to_string()],
                |row| {
                    let disposition = row.get::<_, String>(3)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        disposition,
                    ))
                },
            )
            .optional()
            .context("looking up terminal client submission receipt")?
            .map(
                |(fingerprint, wire_fingerprint, origin_principal, disposition)| {
                    Ok(ClientSubmissionTerminalReceiptRow {
                        fingerprint,
                        wire_fingerprint,
                        origin_principal,
                        disposition: ClientSubmissionTerminalDisposition::parse(&disposition)?,
                    })
                },
            )
            .transpose()
        })
        .await
    }

    pub fn list_session_events_conn(
        conn: &Connection,
        session_id: Uuid,
    ) -> Result<Vec<SessionEventRow>> {
        let mut stmt = conn
            .prepare(
                "SELECT seq, session_id, ts_ms, type, agent, call_id, task_call_id, label,
                        origin_principal, provider_id, model_id, llm_mode, model_trust, data_json
                   FROM session_events
                  WHERE session_id = ?1
                  ORDER BY seq ASC",
            )
            .context("preparing list_session_events")?;
        let rows = stmt
            .query_map([session_id.to_string()], raw_event_row)
            .context("querying session_events")?;
        let mut raw = Vec::new();
        for r in rows {
            raw.push(r.context("reading session_event row")?);
        }
        let mut events = decode_event_rows(raw)?;
        hydrate_compaction_payloads_conn(conn, session_id, &mut events)?;
        Ok(events)
    }

    pub fn list_session_events_since_conn(
        conn: &Connection,
        session_id: Uuid,
        since_seq: i64,
    ) -> Result<Vec<SessionEventRow>> {
        let mut stmt = conn
            .prepare(
                "SELECT seq, session_id, ts_ms, type, agent, call_id, task_call_id, label,
                        origin_principal, provider_id, model_id, llm_mode, model_trust, data_json
                   FROM session_events
                  WHERE session_id = ?1 AND seq > ?2
                  ORDER BY seq ASC",
            )
            .context("preparing list_session_events_since")?;
        let rows = stmt
            .query_map(params![session_id.to_string(), since_seq], raw_event_row)
            .context("querying session_events since seq")?;
        let mut raw = Vec::new();
        for r in rows {
            raw.push(r.context("reading session_event row")?);
        }
        let mut events = decode_event_rows(raw)?;
        hydrate_compaction_payloads_conn(conn, session_id, &mut events)?;
        Ok(events)
    }

    pub async fn list_session_events_before(
        &self,
        session_id: Uuid,
        before_seq: Option<i64>,
        limit: u32,
    ) -> Result<SessionEventPage> {
        self.read(move |conn| {
            Self::list_session_events_before_conn(conn, session_id, before_seq, limit)
        })
        .await
    }

    pub fn list_session_events_before_conn(
        conn: &Connection,
        session_id: Uuid,
        before_seq: Option<i64>,
        limit: u32,
    ) -> Result<SessionEventPage> {
        let limit = limit.clamp(1, LIST_SESSION_EVENTS_MAX_LIMIT);
        let fetch_limit = i64::from(limit) + 1;
        let mut stmt = conn
            .prepare(
                "SELECT seq, session_id, ts_ms, type, agent, call_id, task_call_id, label,
                        origin_principal, provider_id, model_id, llm_mode, model_trust, data_json
                   FROM session_events
                  WHERE session_id = ?1
                    AND (?2 IS NULL OR seq < ?3)
                  ORDER BY seq DESC
                  LIMIT ?4",
            )
            .context("preparing list_session_events_before")?;
        let rows = stmt
            .query_map(
                params![session_id.to_string(), before_seq, before_seq, fetch_limit],
                raw_event_row,
            )
            .context("querying session_events before seq")?;
        let mut raw = Vec::new();
        for row in rows {
            raw.push(row.context("reading session_event row")?);
        }
        let has_more = raw.len() > limit as usize;
        if has_more {
            raw.truncate(limit as usize);
        }
        raw.reverse();
        let mut events = decode_event_rows(raw)?;
        hydrate_compaction_payloads_conn(conn, session_id, &mut events)?;
        let oldest_seq = events.first().map(|event| event.seq);
        Ok(SessionEventPage {
            events,
            has_more,
            oldest_seq,
        })
    }

    pub fn list_subagent_session_events_before_conn(
        conn: &Connection,
        session_id: Uuid,
        task_call_id: &str,
        label: &str,
        before_seq: Option<i64>,
        limit: u32,
    ) -> Result<SessionEventPage> {
        let limit = limit.clamp(1, LIST_SESSION_EVENTS_MAX_LIMIT);
        let fetch_limit = i64::from(limit) + 1;
        let mut stmt = conn
            .prepare(
                "SELECT seq, session_id, ts_ms, type, agent, call_id, task_call_id, label,
                        origin_principal, provider_id, model_id, llm_mode, model_trust, data_json
                   FROM session_events
                  WHERE session_id = ?1
                    AND task_call_id = ?2
                    AND label = ?3
                    AND (?4 IS NULL OR seq < ?5)
                  ORDER BY seq DESC
                  LIMIT ?6",
            )
            .context("preparing list_subagent_session_events_before")?;
        let rows = stmt
            .query_map(
                params![
                    session_id.to_string(),
                    task_call_id,
                    label,
                    before_seq,
                    before_seq,
                    fetch_limit
                ],
                raw_event_row,
            )
            .context("querying subagent session_events before seq")?;
        let mut raw = Vec::new();
        for row in rows {
            raw.push(row.context("reading subagent session_event row")?);
        }
        let has_more = raw.len() > limit as usize;
        if has_more {
            raw.truncate(limit as usize);
        }
        raw.reverse();
        let mut events = decode_event_rows(raw)?;
        hydrate_compaction_payloads_conn(conn, session_id, &mut events)?;
        let oldest_seq = events.first().map(|event| event.seq);
        Ok(SessionEventPage {
            events,
            has_more,
            oldest_seq,
        })
    }

    pub async fn read_session_messages(
        &self,
        session_id: Uuid,
        before_seq: Option<i64>,
        limit: u32,
    ) -> Result<(Vec<crate::db::wire::SessionMessage>, bool)> {
        self.read(move |conn| Self::read_session_messages_conn(conn, session_id, before_seq, limit))
            .await
    }

    pub fn read_session_messages_conn(
        conn: &Connection,
        session_id: Uuid,
        before_seq: Option<i64>,
        limit: u32,
    ) -> Result<(Vec<crate::db::wire::SessionMessage>, bool)> {
        let limit = limit.clamp(1, READ_SESSION_MESSAGES_MAX_LIMIT);
        let fetch_limit = i64::from(limit) + 1;
        let mut stmt = conn
            .prepare(
                "SELECT e.seq, e.ts_ms, e.type,
                        CASE WHEN e.type = 'session_compacted' THEN
                          COALESCE(
                            json_extract(e.data_json, '$.handoff_text'),
                            json_extract(h.payload_json, '$.handoff_text'),
                            json_extract(e.data_json, '$.brief_text'),
                            json_extract(h.payload_json, '$.brief_text')
                          )
                        ELSE json_extract(e.data_json, '$.text') END AS text
                   FROM session_events e
                   LEFT JOIN compaction_handoffs h
                     ON h.handoff_id = json_extract(e.data_json, '$.handoff_ref')
                    AND h.session_id = e.session_id
                  WHERE e.session_id = ?1
                    AND e.type IN ('user_message', 'assistant_message', 'session_compacted')
                    AND (?2 IS NULL OR e.seq < ?3)
                  ORDER BY e.seq DESC
                  LIMIT ?4",
            )
            .context("preparing read_session_messages")?;
        let rows = stmt
            .query_map(
                params![session_id.to_string(), before_seq, before_seq, fetch_limit],
                |row| {
                    let kind: String = row.get("type")?;
                    let role = match kind.as_str() {
                        "assistant_message" => crate::db::wire::MessageRole::Agent,
                        _ => crate::db::wire::MessageRole::User,
                    };
                    let text: Option<String> = row.get("text")?;
                    Ok(crate::db::wire::SessionMessage {
                        seq: row.get("seq")?,
                        ts_ms: row.get("ts_ms")?,
                        role,
                        text: text.unwrap_or_default(),
                    })
                },
            )
            .context("querying read_session_messages")?;
        let mut messages = Vec::new();
        for row in rows {
            messages.push(row.context("decoding session message")?);
        }
        let has_more = messages.len() > limit as usize;
        if has_more {
            messages.truncate(limit as usize);
        }
        messages.reverse();
        Ok((messages, has_more))
    }

    /// Look up one inference attempt keyed `(call_id, ordinal)`: its immutable
    /// post-render request body plus lifecycle `status` and phase columns.
    /// `None` when that attempt has no row. The export writes the body verbatim
    /// and surfaces status + phases beside it (never folded into the body) so a
    /// hung/failed turn's attempt carries its non-`completed` status.
    pub async fn get_inference_request(
        &self,
        call_id: &str,
        ordinal: i64,
    ) -> Result<Option<InferenceRequestRow>> {
        let call_id = call_id.to_string();
        self.read(move |conn| Self::get_inference_request_conn(conn, &call_id, ordinal))
            .await
    }

    /// Every attempt of one `call_id`, ordered by ordinal ascending.
    pub async fn list_inference_requests_for_call(
        &self,
        call_id: &str,
    ) -> Result<Vec<InferenceRequestRow>> {
        let call_id = call_id.to_string();
        self.read(move |conn| Self::list_inference_requests_for_call_conn(conn, &call_id))
            .await
    }
}

struct RawSessionEventRow {
    seq: i64,
    session_id: String,
    ts_ms: i64,
    kind: String,
    agent: Option<String>,
    call_id: Option<String>,
    task_call_id: Option<String>,
    label: Option<String>,
    origin_principal: Option<String>,
    provider_id: Option<String>,
    model_id: Option<String>,
    llm_mode: Option<String>,
    model_trust: Option<String>,
    data_json: String,
}

fn raw_event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawSessionEventRow> {
    Ok(RawSessionEventRow {
        seq: row.get("seq")?,
        session_id: row.get("session_id")?,
        ts_ms: row.get("ts_ms")?,
        kind: row.get("type")?,
        agent: row.get("agent")?,
        call_id: row.get("call_id")?,
        task_call_id: row.get("task_call_id")?,
        label: row.get("label")?,
        origin_principal: row.get("origin_principal")?,
        provider_id: row.get("provider_id")?,
        model_id: row.get("model_id")?,
        llm_mode: row.get("llm_mode")?,
        model_trust: row.get("model_trust")?,
        data_json: row.get("data_json")?,
    })
}

fn decode_event_rows(rows: Vec<RawSessionEventRow>) -> Result<Vec<SessionEventRow>> {
    let last = rows.len().saturating_sub(1);
    let mut out = Vec::new();
    for (index, row) in rows.into_iter().enumerate() {
        match decode_event_row(row) {
            Ok(row) => out.push(row),
            Err(err) if index == last && is_truncated_tail_error(&err) => {
                tracing::warn!(error = %err, "ignoring truncated session_event tail row");
                break;
            }
            Err(err) => return Err(err).context("decoding session_event row"),
        }
    }
    Ok(out)
}

fn hydrate_compaction_payloads_conn(
    conn: &Connection,
    session_id: Uuid,
    events: &mut [SessionEventRow],
) -> Result<()> {
    for event in events {
        if event.kind != SessionEventKind::SessionCompacted.as_str() {
            continue;
        }
        let Some(reference) = event.data.get("handoff_ref").and_then(Value::as_str) else {
            continue;
        };
        let Some(payload) = Db::compaction_payload_conn(conn, session_id, reference)? else {
            continue;
        };
        let data: Value =
            serde_json::from_str(&payload).context("deserializing stored compaction payload")?;
        anyhow::ensure!(
            data.is_object(),
            "stored compaction payload must be an object"
        );
        event.data = data;
    }
    Ok(())
}

fn decode_event_row(row: RawSessionEventRow) -> Result<SessionEventRow> {
    let session_id = Uuid::parse_str(&row.session_id)
        .with_context(|| format!("session_id `{}`", row.session_id))?;
    let data: Value = serde_json::from_str(&row.data_json).context("deserializing data_json")?;
    anyhow::ensure!(
        data.is_object(),
        "deserializing data_json: expected object payload"
    );
    Ok(SessionEventRow {
        seq: row.seq,
        session_id,
        ts_ms: row.ts_ms,
        kind: row.kind,
        agent: row.agent,
        call_id: row.call_id,
        task_call_id: row.task_call_id,
        label: row.label,
        origin_principal: row.origin_principal,
        provider_id: row.provider_id,
        model_id: row.model_id,
        llm_mode: row.llm_mode,
        model_trust: row.model_trust,
        data,
    })
}

fn reject_generic_hook_run(kind: SessionEventKind) -> Result<()> {
    anyhow::ensure!(
        kind != SessionEventKind::HookRun,
        "hook_run events must use the typed hook-run writer"
    );
    Ok(())
}

fn is_truncated_tail_error(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.to_string().contains("deserializing data_json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hook_audit(status: HookRunStatus) -> HookRunAudit {
        HookRunAudit {
            event: "PreToolUse".to_string(),
            hook: "project:0123456789abcdef:7".to_string(),
            origin: "project:0123456789abcdef:7".to_string(),
            status,
            duration_ms: 42,
            reason: None,
            turn_id: None,
            tool_name: None,
            tool_call_id: None,
            subagent_id: None,
        }
    }

    #[test]
    fn hook_run_event_kind_is_exhaustive_and_stable() {
        let expected = [
            "user_message",
            "user_note",
            "assistant_message",
            "inference_request",
            "tool_call",
            "tandem_inference",
            "tool_call_started",
            "tool_call_completed",
            "subagent_spawned",
            "subagent_routing",
            "subagent_report",
            "context_pruned",
            "session_compacted",
            "permission_decision",
            "interrupt_decision",
            "tool_rejected",
            "primary_swap",
            "inference_failure",
            "failed_turn_recovery",
            "turn_interrupted",
            "skill_auto_select",
            "auto_prune_diagnostic",
            "goal_progress_diagnostic",
            "resource_promotion",
            "notice",
            "model_switch",
            "hook_run",
            "tool_call_scheduling",
        ];
        let actual = SessionEventKind::ALL.map(SessionEventKind::as_str);
        assert_eq!(actual, expected);
        assert_eq!(actual.iter().filter(|kind| **kind == "hook_run").count(), 1);
        assert_eq!(SessionEventKind::HookRun.as_str(), "hook_run");
    }

    #[test]
    fn tool_call_scheduling_event_kind_is_exhaustive_and_stable() {
        // `ToolCallScheduling` is present in the closed inventory exactly once
        // and maps to the stable wire string. Independent literals — not a
        // re-derivation of `as_str` — so a rename of either side is caught.
        let kinds = SessionEventKind::ALL.map(SessionEventKind::as_str);
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind == "tool_call_scheduling")
                .count(),
            1,
            "tool_call_scheduling must appear exactly once in ALL"
        );
        assert_eq!(
            SessionEventKind::ToolCallScheduling.as_str(),
            "tool_call_scheduling"
        );
        // The kind grew the inventory to 28 (appended, not substituted) and
        // every wire string is distinct.
        assert_eq!(SessionEventKind::ALL.len(), 28);
        let unique: std::collections::BTreeSet<&str> = kinds.iter().copied().collect();
        assert_eq!(
            unique.len(),
            kinds.len(),
            "event-kind strings must be distinct"
        );
    }

    #[tokio::test]
    async fn tool_call_scheduling_event_writes_through_schema_check() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let data = json!({ "outcome": "dispatched" });
        db.insert_session_event(
            session.session_id,
            SessionEventKind::ToolCallScheduling,
            None,
            None,
            &data,
        )
        .await
        .expect("tool_call_scheduling must satisfy the session_events.type CHECK");
        let events = db.list_session_events(session.session_id).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "tool_call_scheduling");
    }

    #[tokio::test]
    async fn compaction_payload_retry_is_content_checked_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let handoff_id = Uuid::new_v4();

        db.store_compaction_payload(handoff_id, session.session_id, r#"{"brief":"same"}"#)
            .await
            .unwrap();
        db.store_compaction_payload(handoff_id, session.session_id, r#"{"brief":"same"}"#)
            .await
            .expect("an exact crash retry converges on the existing handoff");

        let error = db
            .store_compaction_payload(
                handoff_id,
                session.session_id,
                r#"{"brief":"different"}"#,
            )
            .await
            .expect_err("one compaction identity cannot be rebound to new content");
        assert!(
            error
                .to_string()
                .contains("identity reused with different content")
        );
    }

    #[tokio::test]
    async fn hook_run_audit_serialization_is_closed_and_bounded() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        for status in HookRunStatus::ALL {
            db.insert_hook_run(session.session_id, hook_audit(status))
                .await
                .unwrap();
        }

        let mut correlated = hook_audit(HookRunStatus::Denied);
        correlated.reason = Some(format!("{}é", "r".repeat(HOOK_REASON_MAX_BYTES - 1)));
        correlated.turn_id = Some("turn-1".to_string());
        correlated.tool_name = Some("bash".to_string());
        correlated.tool_call_id = Some("tool-call-1".to_string());
        correlated.subagent_id = Some("subagent-1".to_string());
        db.insert_hook_run(session.session_id, correlated)
            .await
            .unwrap();

        let events = db.list_session_events(session.session_id).await.unwrap();
        assert_eq!(events.len(), 5);
        assert!(events.iter().all(|event| event.kind == "hook_run"));
        assert_eq!(
            events[..4]
                .iter()
                .map(|event| event.data["status"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["success", "denied", "blocked", "failed"]
        );
        let data = events.last().unwrap().data.as_object().unwrap();
        assert_eq!(
            data.keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>(),
            [
                "duration_ms",
                "event",
                "hook",
                "origin",
                "reason",
                "status",
                "subagent_id",
                "tool_call_id",
                "tool_name",
                "turn_id",
            ]
            .into_iter()
            .map(str::to_string)
            .collect()
        );
        let reason = data["reason"].as_str().unwrap();
        assert!(reason.len() <= HOOK_REASON_MAX_BYTES);
        assert_eq!(reason, "r".repeat(HOOK_REASON_MAX_BYTES - 1));

        for forbidden in [
            "payload",
            "output",
            "argv",
            "cwd",
            "environment",
            "stdout",
            "stderr",
            "http",
            "unknown",
        ] {
            let mut value = serde_json::to_value(hook_audit(HookRunStatus::Success)).unwrap();
            value[forbidden] = json!("secret");
            assert!(
                HookRunAudit::from_json(&value).is_err(),
                "field {forbidden} must be rejected"
            );
        }

        for field in ["hook", "origin"] {
            let mut value = serde_json::to_value(hook_audit(HookRunStatus::Success)).unwrap();
            value[field] = json!("/home/alice/.config/cockpit/config.toml");
            assert!(HookRunAudit::from_json(&value).is_err());
        }
        let mut overlong = hook_audit(HookRunStatus::Success);
        overlong.event = "é".repeat(HOOK_EVENT_MAX_BYTES);
        assert!(
            db.insert_hook_run(session.session_id, overlong)
                .await
                .is_err()
        );
        let mut invalid_event = hook_audit(HookRunStatus::Success);
        invalid_event.event = "PreToolUse\nsecret".to_string();
        assert!(
            db.insert_hook_run(session.session_id, invalid_event)
                .await
                .is_err()
        );
        for (field, value) in [
            ("turn_id", String::new()),
            ("tool_name", "t".repeat(HOOK_EVENT_MAX_BYTES + 1)),
            ("tool_call_id", "c".repeat(HOOK_CORRELATION_MAX_BYTES + 1)),
            ("subagent_id", "s".repeat(HOOK_CORRELATION_MAX_BYTES + 1)),
        ] {
            let mut bounded = hook_audit(HookRunStatus::Success);
            match field {
                "turn_id" => bounded.turn_id = Some(value),
                "tool_name" => bounded.tool_name = Some(value),
                "tool_call_id" => bounded.tool_call_id = Some(value),
                "subagent_id" => bounded.subagent_id = Some(value),
                _ => unreachable!(),
            }
            assert!(
                db.insert_hook_run(session.session_id, bounded)
                    .await
                    .is_err(),
                "{field} must be non-empty and within its byte bound"
            );
        }
        let mut oversized_import = hook_audit(HookRunStatus::Success);
        oversized_import.reason = Some("é".repeat(HOOK_REASON_MAX_BYTES));
        assert!(HookRunAudit::from_json(&serde_json::to_value(oversized_import).unwrap()).is_err());

        let imported = serde_json::to_value(hook_audit(HookRunStatus::Blocked)).unwrap();
        db.write(move |conn| {
            Db::insert_imported_hook_run_conn(conn, session.session_id, 123, &imported)
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn generic_session_event_writer_rejects_hook_run() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let data = serde_json::to_value(hook_audit(HookRunStatus::Success)).unwrap();
        assert!(
            db.insert_session_event(
                session.session_id,
                SessionEventKind::HookRun,
                None,
                None,
                &data,
            )
            .await
            .is_err()
        );
        assert!(
            db.insert_session_event_with_origin(
                session.session_id,
                SessionEventKind::HookRun,
                None,
                None,
                None,
                &data,
            )
            .await
            .is_err()
        );
        assert!(
            db.insert_session_event_with_context(
                session.session_id,
                SessionEventKind::HookRun,
                None,
                None,
                SessionEventContext::default(),
                &data,
            )
            .await
            .is_err()
        );
        let data_json = serde_json::to_string(&data).unwrap();
        db.write(move |conn| {
            let result = Db::insert_session_event_json_conn(
                conn,
                session.session_id,
                SessionEventKind::HookRun,
                None,
                None,
                SessionEventContext::default(),
                123,
                &data_json,
            );
            assert!(result.is_err());
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            db.list_session_events(session.session_id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    async fn insert_numbered_events(db: &Db, session_id: Uuid, count: usize) -> Vec<i64> {
        let mut seqs = Vec::new();
        for index in 1..=count {
            let kind = match index % 3 {
                0 => SessionEventKind::ToolCall,
                1 => SessionEventKind::UserMessage,
                _ => SessionEventKind::AssistantMessage,
            };
            seqs.push(
                db.insert_session_event(
                    session_id,
                    kind,
                    Some("builder"),
                    None,
                    &json!({"text": format!("event-{index}")}),
                )
                .await
                .unwrap(),
            );
        }
        seqs
    }

    #[tokio::test]
    async fn db_async_session_log_append_and_list_roundtrip_through_async_api() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let first = json!({"text": "hello"});
        let second = json!({"text": "world"});

        db.insert_session_event(
            session.session_id,
            SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &first,
        )
        .await
        .unwrap();
        db.insert_session_event(
            session.session_id,
            SessionEventKind::AssistantMessage,
            Some("Build"),
            Some("call-1"),
            &second,
        )
        .await
        .unwrap();

        let events = db.list_session_events(session.session_id).await.unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, "user_message");
        assert_eq!(events[0].data, first);
        assert_eq!(events[1].kind, "assistant_message");
        assert_eq!(events[1].call_id.as_deref(), Some("call-1"));
        assert_eq!(events[1].data, second);
    }

    #[tokio::test]
    async fn client_submission_receipt_finds_exact_fold_member_and_fingerprint() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let first_id = Uuid::new_v4();
        let second_id = Uuid::new_v4();
        let seq = db
            .insert_session_event(
                session.session_id,
                SessionEventKind::UserMessage,
                Some("Build"),
                None,
                &json!({
                    "text": "folded",
                    "client_submission_ids": [first_id, second_id],
                    "client_submissions": [
                        {"id": first_id, "fingerprint": "sha-first", "wire_fingerprint": "wire-first", "origin_principal": null},
                        {"id": second_id, "fingerprint": "sha-second", "wire_fingerprint": "wire-second", "origin_principal": "flycockpit:user-2"}
                    ]
                }),
            )
            .await
            .unwrap();

        assert_eq!(
            db.client_submission_receipt(session.session_id, second_id)
                .await
                .unwrap(),
            Some(ClientSubmissionReceiptRow {
                seq,
                fingerprint: "sha-second".to_string(),
                wire_fingerprint: "wire-second".to_string(),
                origin_principal: Some("flycockpit:user-2".to_string()),
            })
        );
        assert_eq!(
            db.client_submission_receipt(session.session_id, Uuid::new_v4())
                .await
                .unwrap(),
            None
        );

        let other = db.create_session("p", "/y", "Build").await.unwrap();
        assert_eq!(
            db.client_submission_receipt(other.session_id, second_id)
                .await
                .unwrap(),
            None,
            "receipt lookup must remain session-scoped"
        );
    }

    #[tokio::test]
    async fn terminal_client_submission_receipts_are_durable_idempotent_and_session_scoped() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let other = db.create_session("p", "/y", "Build").await.unwrap();
        let id = Uuid::new_v4();
        let terminal = ClientSubmissionTerminalReceipt {
            client_submission_id: id,
            fingerprint: "content-sha".to_string(),
            wire_fingerprint: "wire-sha".to_string(),
            origin_principal: Some("flycockpit:user-1".to_string()),
            disposition: ClientSubmissionTerminalDisposition::Removed,
        };

        db.insert_client_submission_terminal_receipts(session.session_id, vec![terminal.clone()])
            .await
            .unwrap();
        db.insert_client_submission_terminal_receipts(session.session_id, vec![terminal.clone()])
            .await
            .expect("an exact retry is idempotent");

        assert_eq!(
            db.client_submission_terminal_receipt(session.session_id, id)
                .await
                .unwrap(),
            Some(ClientSubmissionTerminalReceiptRow {
                fingerprint: "content-sha".to_string(),
                wire_fingerprint: "wire-sha".to_string(),
                origin_principal: Some("flycockpit:user-1".to_string()),
                disposition: ClientSubmissionTerminalDisposition::Removed,
            })
        );
        assert_eq!(
            db.client_submission_terminal_receipt(other.session_id, id)
                .await
                .unwrap(),
            None
        );

        let conflict = ClientSubmissionTerminalReceipt {
            disposition: ClientSubmissionTerminalDisposition::Cancelled,
            ..terminal
        };
        let error = db
            .insert_client_submission_terminal_receipts(session.session_id, vec![conflict])
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("different terminal receipt"),
            "{error:#}"
        );
        assert_eq!(
            db.client_submission_terminal_receipt(session.session_id, id)
                .await
                .unwrap()
                .unwrap()
                .disposition,
            ClientSubmissionTerminalDisposition::Removed,
            "a conflicting retry must not mutate the committed tombstone"
        );

        let preflight_id = Uuid::new_v4();
        db.insert_client_submission_terminal_receipts(
            session.session_id,
            vec![ClientSubmissionTerminalReceipt {
                client_submission_id: preflight_id,
                fingerprint: "preflight-content".to_string(),
                wire_fingerprint: "preflight-wire".to_string(),
                origin_principal: None,
                disposition: ClientSubmissionTerminalDisposition::PreflightRejected,
            }],
        )
        .await
        .unwrap();
        assert_eq!(
            db.client_submission_terminal_receipt(session.session_id, preflight_id)
                .await
                .unwrap()
                .unwrap()
                .disposition,
            ClientSubmissionTerminalDisposition::PreflightRejected
        );
    }

    #[tokio::test]
    async fn session_event_provenance_schema_columns_and_index_exist() {
        let db = Db::open_in_memory().unwrap();
        let columns = db
            .read(|conn| {
                let mut stmt = conn.prepare("PRAGMA table_info(session_events)")?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>("name")?,
                        row.get::<_, String>("type")?,
                        row.get::<_, i64>("notnull")?,
                    ))
                })?;
                let mut out = Vec::new();
                for row in rows {
                    out.push(row?);
                }
                Ok(out)
            })
            .await
            .unwrap();

        for name in ["provider_id", "model_id", "llm_mode", "model_trust"] {
            assert!(
                columns
                    .iter()
                    .any(|(column, ty, notnull)| column == name && ty == "TEXT" && *notnull == 0),
                "missing nullable TEXT column {name}"
            );
        }

        let index_sql: Option<String> = db
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_sevents_session_trust_seq'",
                    [],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        let index_sql = index_sql.unwrap();
        assert!(index_sql.contains("session_id, model_trust, seq"));
        assert!(index_sql.contains("model_trust IS NOT NULL"));
    }

    #[tokio::test]
    async fn session_event_provenance_context_roundtrips_through_all_event_readers() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let seq = db
            .insert_session_event_with_context(
                session.session_id,
                SessionEventKind::AssistantMessage,
                Some("Build"),
                Some("call-1"),
                SessionEventContext {
                    origin_principal: Some("principal-1"),
                    task_call_id: Some("task-1"),
                    label: Some("label-1"),
                    provider_id: Some("openai"),
                    model_id: Some("gpt-5"),
                    llm_mode: Some("frontier"),
                    model_trust: Some("trusted"),
                },
                &json!({"text": "hello"}),
            )
            .await
            .unwrap();

        let all = db.list_session_events(session.session_id).await.unwrap();
        let since = db
            .read(move |conn| Db::list_session_events_since_conn(conn, session.session_id, seq - 1))
            .await
            .unwrap();
        let before = db
            .list_session_events_before(session.session_id, Some(seq + 1), 10)
            .await
            .unwrap()
            .events;

        for rows in [all, since, before] {
            let event = rows.into_iter().next().unwrap();
            assert_eq!(event.seq, seq);
            assert_eq!(event.origin_principal.as_deref(), Some("principal-1"));
            assert_eq!(event.task_call_id.as_deref(), Some("task-1"));
            assert_eq!(event.label.as_deref(), Some("label-1"));
            assert_eq!(event.provider_id.as_deref(), Some("openai"));
            assert_eq!(event.model_id.as_deref(), Some("gpt-5"));
            assert_eq!(event.llm_mode.as_deref(), Some("frontier"));
            assert_eq!(event.model_trust.as_deref(), Some("trusted"));
        }
    }

    #[tokio::test]
    async fn session_event_provenance_convenience_insert_writes_nulls() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        db.insert_session_event_with_origin(
            session.session_id,
            SessionEventKind::UserMessage,
            Some("Build"),
            None,
            Some("principal-1"),
            &json!({"text": "hello"}),
        )
        .await
        .unwrap();

        let event = db
            .list_session_events(session.session_id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(event.origin_principal.as_deref(), Some("principal-1"));
        assert_eq!(event.provider_id, None);
        assert_eq!(event.model_id, None);
        assert_eq!(event.llm_mode, None);
        assert_eq!(event.model_trust, None);
    }

    #[tokio::test]
    async fn db_async_session_log_append_then_read_sees_committed_event() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();

        let seq = db
            .insert_session_event(
                session.session_id,
                SessionEventKind::UserMessage,
                Some("Build"),
                None,
                &json!({"text": "committed"}),
            )
            .await
            .unwrap();

        let events = db.list_session_events(session.session_id).await.unwrap();
        assert_eq!(
            events.iter().map(|event| event.seq).collect::<Vec<_>>(),
            vec![seq]
        );
        let (messages, has_more) = db
            .read_session_messages(session.session_id, None, 10)
            .await
            .unwrap();
        assert!(!has_more);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].seq, seq);
        assert_eq!(messages[0].text, "committed");
    }

    #[tokio::test]
    async fn db_async_session_log_writes_from_one_task_apply_in_order() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let writer_db = db.clone();
        let session_id = session.session_id;

        let seqs = tokio::spawn(async move {
            let mut seqs = Vec::new();
            for text in ["one", "two", "three"] {
                seqs.push(
                    writer_db
                        .insert_session_event(
                            session_id,
                            SessionEventKind::UserMessage,
                            Some("Build"),
                            None,
                            &json!({"text": text}),
                        )
                        .await
                        .unwrap(),
                );
            }
            seqs
        })
        .await
        .unwrap();

        assert!(seqs.windows(2).all(|pair| pair[0] < pair[1]));
        let events = db.list_session_events(session.session_id).await.unwrap();
        assert_eq!(
            events
                .iter()
                .map(|event| event.data["text"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["one", "two", "three"]
        );
    }

    #[tokio::test]
    async fn db_async_session_log_event_and_counter_update_is_atomic() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        db.write(|conn| {
            conn.execute(
                "CREATE TEMP TABLE db_async_session_log_counter (value INTEGER)",
                [],
            )?;
            conn.execute(
                "INSERT INTO db_async_session_log_counter (value) VALUES (0)",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        let session_id = session.session_id;
        let data_json = serde_json::to_string(&json!({"text": "rolled back"})).unwrap();

        let result: Result<()> = db
            .write(move |conn| {
                let tx = conn.unchecked_transaction()?;
                tx.execute(
                    "INSERT INTO session_events
                     (session_id, ts_ms, type, agent, data_json)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        session_id.to_string(),
                        now_ms(),
                        SessionEventKind::UserMessage.as_str(),
                        "Build",
                        data_json,
                    ],
                )?;
                tx.execute(
                    "UPDATE db_async_session_log_counter SET value = value + 1",
                    [],
                )?;
                anyhow::bail!("injected failure after event and counter update");
            })
            .await;

        assert!(result.is_err());
        assert!(
            db.list_session_events(session.session_id)
                .await
                .unwrap()
                .is_empty()
        );
        let counter: i64 = db
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT value FROM db_async_session_log_counter",
                    [],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(counter, 0);
    }

    #[tokio::test]
    async fn db_async_session_log_tool_call_payload_is_serialized_before_write_submit() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let payload = json!({
            "tool": "bash",
            "original_input": {"cmd": "printf '%s' \"$VALUE\""},
            "wire_input": {"cmd": "printf '%s' \"$VALUE\"", "timeout_ms": 1000},
        });

        let seq = db
            .insert_session_event(
                session.session_id,
                SessionEventKind::ToolCall,
                Some("Build"),
                Some("tool-call-1"),
                &payload,
            )
            .await
            .unwrap();

        let raw: String = db
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT data_json FROM session_events WHERE seq = ?1",
                    [seq],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&raw).unwrap(),
            payload
        );
    }

    #[tokio::test]
    async fn db_async_session_log_concurrent_reads_proceed_during_slow_append() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("db.sqlite3")).unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        db.insert_session_event(
            session.session_id,
            SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &json!({"text": "already visible"}),
        )
        .await
        .unwrap();
        let (write_started_tx, write_started_rx) = tokio::sync::oneshot::channel();
        let (release_write_tx, release_write_rx) = std::sync::mpsc::channel();
        let writer_db = db.clone();

        let writer = tokio::spawn(async move {
            writer_db
                .write(move |_conn| {
                    write_started_tx.send(()).ok();
                    release_write_rx.recv().unwrap();
                    Ok(())
                })
                .await
                .unwrap();
        });

        write_started_rx.await.unwrap();
        let events = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            db.list_session_events(session.session_id),
        )
        .await
        .expect("read should not wait behind slow writer")
        .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data["text"], "already visible");

        release_write_tx.send(()).unwrap();
        writer.await.unwrap();
    }

    fn assert_session_event_rows_eq(left: &[SessionEventRow], right: &[SessionEventRow]) {
        assert_eq!(left.len(), right.len(), "event row count mismatch");
        for (index, (left, right)) in left.iter().zip(right).enumerate() {
            assert_eq!(left.seq, right.seq, "seq mismatch at index {index}");
            assert_eq!(
                left.session_id, right.session_id,
                "session_id mismatch at index {index}"
            );
            assert_eq!(left.ts_ms, right.ts_ms, "ts_ms mismatch at index {index}");
            assert_eq!(left.kind, right.kind, "kind mismatch at index {index}");
            assert_eq!(left.agent, right.agent, "agent mismatch at index {index}");
            assert_eq!(
                left.call_id, right.call_id,
                "call_id mismatch at index {index}"
            );
            assert_eq!(
                left.task_call_id, right.task_call_id,
                "task_call_id mismatch at index {index}"
            );
            assert_eq!(left.label, right.label, "label mismatch at index {index}");
            assert_eq!(
                left.origin_principal, right.origin_principal,
                "origin_principal mismatch at index {index}"
            );
            assert_eq!(left.data, right.data, "data mismatch at index {index}");
        }
    }

    #[tokio::test]
    async fn inference_request_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").await.unwrap();
        let call_id = Uuid::new_v4().to_string();
        let payload = json!({
            "model": "claude-opus-4-7",
            "provider": "anthropic",
            "system": "you are a builder",
            "tools": [{"name": "read"}],
            "history": [{"role": "user", "content": "hi"}],
        });
        db.insert_inference_request(
            &call_id,
            0,
            s.session_id,
            &payload,
            InferenceAttemptMeta {
                provider: Some("anthropic"),
                model: Some("claude-opus-4-7"),
                trust: Some("untrusted"),
            },
            None,
        )
        .await
        .unwrap();
        db.advance_inference_request(
            &call_id,
            0,
            InferenceRequestStatus::Completed,
            InferencePhaseTimings {
                completed_ms: Some(42),
                ..InferencePhaseTimings::default()
            },
        )
        .await
        .unwrap();
        let row = db
            .get_inference_request(&call_id, 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.payload, payload);
        assert_eq!(row.status, "completed");
        assert_eq!(row.provider.as_deref(), Some("anthropic"));
        assert_eq!(row.trust.as_deref(), Some("untrusted"));
        assert_eq!(row.completed_ms, Some(42));
        // Unknown (call_id, ordinal) resolves to None.
        assert!(
            db.get_inference_request("missing", 0)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.get_inference_request(&call_id, 1)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn inference_request_body_is_immutable_across_status_advance() {
        // Renamed from `inference_request_dispatch_then_terminal_update_supersedes`:
        // the old contract (terminal payload *supersedes* the pending body on a
        // single mutable row) is exactly what the immutable-body design rejects.
        // Now: the body is written once at dispatch and a monotonic status-advance
        // fills status + phase columns WITHOUT touching `payload_json`. This test
        // fails against the old CASE-overwrite behavior, which rewrote the blob on
        // the terminal write.
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").await.unwrap();
        let call_id = Uuid::new_v4().to_string();
        let body = json!({ "model": "m", "history": [{ "role": "user", "content": "hi" }] });
        db.insert_inference_request(
            &call_id,
            0,
            s.session_id,
            &body,
            InferenceAttemptMeta::default(),
            None,
        )
        .await
        .unwrap();
        let before = db
            .get_inference_request(&call_id, 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before.status, "pending");
        assert_eq!(before.first_token_ms, None);
        assert_eq!(before.completed_ms, None);
        let before_bytes = serde_json::to_string(&before.payload).unwrap();

        // A hung turn that timed out: status advances, phase column populates.
        db.advance_inference_request(
            &call_id,
            0,
            InferenceRequestStatus::TimedOut,
            InferencePhaseTimings {
                first_token_ms: Some(7),
                failed_ms: Some(9000),
                ..InferencePhaseTimings::default()
            },
        )
        .await
        .unwrap();
        let after = db
            .get_inference_request(&call_id, 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.status, "timed_out");
        assert_eq!(after.first_token_ms, Some(7));
        assert_eq!(after.failed_ms, Some(9000));
        // The body blob is byte-identical before and after the status-advance.
        let after_bytes = serde_json::to_string(&after.payload).unwrap();
        assert_eq!(before_bytes, after_bytes, "body blob is immutable");
        assert_eq!(after.payload, body);

        // Still exactly one row for this attempt.
        let count_call_id = call_id.clone();
        let count: i64 = db
            .read(move |c| {
                c.query_row(
                    "SELECT COUNT(*) FROM inference_requests WHERE call_id = ?1",
                    [count_call_id.as_str()],
                    |r| r.get(0),
                )
                .map_err(anyhow::Error::from)
            })
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn inference_status_precedence() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let call_id = Uuid::new_v4().to_string();
        let body = json!({ "phase": "terminal" });
        db.insert_inference_request(
            &call_id,
            0,
            session.session_id,
            &body,
            InferenceAttemptMeta::default(),
            None,
        )
        .await
        .unwrap();
        db.advance_inference_request(
            &call_id,
            0,
            InferenceRequestStatus::Completed,
            InferencePhaseTimings::default(),
        )
        .await
        .unwrap();
        // A later erroneous re-advance must not regress the terminal status.
        db.advance_inference_request(
            &call_id,
            0,
            InferenceRequestStatus::Pending,
            InferencePhaseTimings::default(),
        )
        .await
        .unwrap();
        db.advance_inference_request(
            &call_id,
            0,
            InferenceRequestStatus::Errored,
            InferencePhaseTimings::default(),
        )
        .await
        .unwrap();
        let row = db
            .get_inference_request(&call_id, 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.status, "completed",
            "completed is sticky; terminal never regresses"
        );
        assert_eq!(row.payload, body);

        // Every terminal is sticky in EVERY direction — including the
        // errored/timed_out/cancelled → completed direction the old CASE
        // (`WHEN status = 'pending' OR ?3 = 'completed' THEN ?3`) wrongly let
        // regress to `completed` whenever a late success observation arrived.
        // Advancing any already-terminal row with `completed` must be a no-op.
        for terminal in [
            InferenceRequestStatus::Errored,
            InferenceRequestStatus::TimedOut,
            InferenceRequestStatus::Cancelled,
        ] {
            let sticky_call_id = Uuid::new_v4().to_string();
            let sticky_body = json!({ "terminal": terminal.as_str() });
            db.insert_inference_request(
                &sticky_call_id,
                0,
                session.session_id,
                &sticky_body,
                InferenceAttemptMeta::default(),
                None,
            )
            .await
            .unwrap();
            db.advance_inference_request(
                &sticky_call_id,
                0,
                terminal,
                InferencePhaseTimings::default(),
            )
            .await
            .unwrap();
            // A late `completed` observation must NOT overwrite the terminal.
            db.advance_inference_request(
                &sticky_call_id,
                0,
                InferenceRequestStatus::Completed,
                InferencePhaseTimings::default(),
            )
            .await
            .unwrap();
            let sticky = db
                .get_inference_request(&sticky_call_id, 0)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                sticky.status,
                terminal.as_str(),
                "{} must stay sticky against a later completed advance",
                terminal.as_str()
            );
        }

        // Per-attempt failover: primary (ordinal 0) and backup (ordinal 1) share
        // one call_id and are BOTH retained as distinct rows with distinct
        // immutable payloads. The old design collapsed them onto one row and let
        // the backup body replace the primary's — this segment asserts the
        // opposite.
        let failover_call_id = Uuid::new_v4().to_string();
        let primary = json!({ "attempt": "primary" });
        let backup = json!({ "attempt": "backup" });
        db.insert_inference_request(
            &failover_call_id,
            0,
            session.session_id,
            &primary,
            InferenceAttemptMeta::default(),
            None,
        )
        .await
        .unwrap();
        db.advance_inference_request(
            &failover_call_id,
            0,
            InferenceRequestStatus::Errored,
            InferencePhaseTimings::default(),
        )
        .await
        .unwrap();
        db.insert_inference_request(
            &failover_call_id,
            1,
            session.session_id,
            &backup,
            InferenceAttemptMeta::default(),
            None,
        )
        .await
        .unwrap();
        db.advance_inference_request(
            &failover_call_id,
            1,
            InferenceRequestStatus::Completed,
            InferencePhaseTimings::default(),
        )
        .await
        .unwrap();

        // A second body write to an existing (call_id, ordinal) errors — the
        // audited body cannot be rewritten through the API.
        assert!(
            db.insert_inference_request(
                &failover_call_id,
                0,
                session.session_id,
                &json!({ "attempt": "rewrite" }),
                InferenceAttemptMeta::default(),
                None,
            )
            .await
            .is_err(),
            "a second body insert to (call_id, 0) must error"
        );

        let attempts = db
            .list_inference_requests_for_call(&failover_call_id)
            .await
            .unwrap();
        assert_eq!(attempts.len(), 2, "both attempts retained");
        assert_eq!(attempts[0].ordinal, 0);
        assert_eq!(attempts[0].payload, primary);
        assert_eq!(attempts[0].status, "errored");
        assert_eq!(attempts[1].ordinal, 1);
        assert_eq!(attempts[1].payload, backup);
        assert_eq!(attempts[1].status, "completed");
    }

    #[tokio::test]
    async fn inference_attempt_log_preserves_cross_trust_retries() {
        // AC11: a trusted primary attempt (ordinal 0) and an untrusted failover
        // attempt (ordinal 1) under one call_id both persist with distinct
        // immutable payloads and correct per-attempt provider/model/trust; a
        // second body write to an existing (call_id, ordinal) errors; a
        // status-advance populates phase columns without altering the body;
        // terminal never regresses; goal provenance round-trips when supplied.
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").await.unwrap();
        let call_id = Uuid::new_v4().to_string();
        let goal_id = Uuid::new_v4();
        let provenance = Some((goal_id, 3_i64));

        // Trusted primary carries the raw sentinel (raw custody is not a leak).
        let trusted_body = json!({ "model": "local", "history": [{ "role": "user", "content": "raw SENTINEL here" }] });
        db.insert_inference_request(
            &call_id,
            0,
            s.session_id,
            &trusted_body,
            InferenceAttemptMeta {
                provider: Some("local"),
                model: Some("primary-model"),
                trust: Some("trusted"),
            },
            provenance,
        )
        .await
        .unwrap();
        db.advance_inference_request(
            &call_id,
            0,
            InferenceRequestStatus::Errored,
            InferencePhaseTimings {
                failed_ms: Some(120),
                ..InferencePhaseTimings::default()
            },
        )
        .await
        .unwrap();

        // Untrusted failover carries the redacted body (no sentinel).
        let untrusted_body = json!({ "model": "cloud", "history": [{ "role": "user", "content": "raw ***REDACT*** here" }] });
        db.insert_inference_request(
            &call_id,
            1,
            s.session_id,
            &untrusted_body,
            InferenceAttemptMeta {
                provider: Some("cloud"),
                model: Some("backup-model"),
                trust: Some("untrusted"),
            },
            provenance,
        )
        .await
        .unwrap();
        let before = db
            .get_inference_request(&call_id, 1)
            .await
            .unwrap()
            .unwrap();
        let before_bytes = serde_json::to_string(&before.payload).unwrap();
        db.advance_inference_request(
            &call_id,
            1,
            InferenceRequestStatus::Completed,
            InferencePhaseTimings {
                first_token_ms: Some(30),
                completed_ms: Some(210),
                ..InferencePhaseTimings::default()
            },
        )
        .await
        .unwrap();

        // A second body write to (call_id, 1) errors.
        assert!(
            db.insert_inference_request(
                &call_id,
                1,
                s.session_id,
                &json!({ "attempt": "rewrite" }),
                InferenceAttemptMeta::default(),
                provenance,
            )
            .await
            .is_err()
        );

        let attempts = db.list_inference_requests_for_call(&call_id).await.unwrap();
        assert_eq!(attempts.len(), 2);

        let primary = &attempts[0];
        assert_eq!(primary.ordinal, 0);
        assert_eq!(primary.payload, trusted_body);
        assert_eq!(primary.trust.as_deref(), Some("trusted"));
        assert_eq!(primary.provider.as_deref(), Some("local"));
        assert_eq!(primary.status, "errored");
        assert!(
            serde_json::to_string(&primary.payload)
                .unwrap()
                .contains("SENTINEL"),
            "trusted attempt keeps the raw sentinel"
        );

        let failover = &attempts[1];
        assert_eq!(failover.ordinal, 1);
        assert_eq!(failover.payload, untrusted_body);
        assert_eq!(failover.trust.as_deref(), Some("untrusted"));
        assert_eq!(failover.provider.as_deref(), Some("cloud"));
        assert_eq!(failover.status, "completed");
        assert_eq!(failover.first_token_ms, Some(30));
        assert_eq!(failover.completed_ms, Some(210));
        // The body blob was not altered by the status-advance.
        assert_eq!(
            serde_json::to_string(&failover.payload).unwrap(),
            before_bytes
        );
        assert!(
            !serde_json::to_string(&failover.payload)
                .unwrap()
                .contains("SENTINEL"),
            "untrusted attempt holds no raw sentinel"
        );

        // Goal provenance round-trips on every ordinal.
        let goal_col_call_id = call_id.clone();
        let goal_ids: Vec<Option<String>> = db
            .read(move |c| {
                let mut stmt = c
                    .prepare(
                        "SELECT goal_id FROM inference_requests WHERE call_id = ?1 ORDER BY ordinal",
                    )
                    .map_err(anyhow::Error::from)?;
                let rows = stmt
                    .query_map([goal_col_call_id.as_str()], |r| r.get::<_, Option<String>>(0))
                    .map_err(anyhow::Error::from)?;
                let mut out = Vec::new();
                for r in rows {
                    out.push(r.map_err(anyhow::Error::from)?);
                }
                Ok(out)
            })
            .await
            .unwrap();
        assert_eq!(
            goal_ids,
            vec![Some(goal_id.to_string()), Some(goal_id.to_string())],
            "goal provenance present on every ordinal"
        );
    }

    #[tokio::test]
    async fn permission_decision_event_round_trips() {
        // The `permission_decision` variant persists with its stable
        // discriminant string and its data payload flows back verbatim.
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").await.unwrap();
        let data = json!({
            "tool": "bash",
            "tool_call_id": null,
            "target": "rm file",
            "offered_scopes": ["once", "session", "project", "global"],
            "decision": "deny",
            "scope": null,
            "source": "user_prompt",
        });
        db.insert_session_event(
            s.session_id,
            SessionEventKind::PermissionDecision,
            Some("builder"),
            None,
            &data,
        )
        .await
        .unwrap();
        let events = db.list_session_events(s.session_id).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "permission_decision");
        assert_eq!(events[0].data, data);
    }

    #[tokio::test]
    async fn notice_event_kind_wire_string_is_notice() {
        assert_eq!(SessionEventKind::Notice.as_str(), "notice");
    }

    #[tokio::test]
    async fn session_event_kind_export_audit_events_round_trip() {
        // The export-audit-fidelity event kinds persist with their stable
        // discriminant strings and flow their data payloads back verbatim.
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").await.unwrap();
        let sid = s.session_id;

        let rejected = json!({"tool": "handoff", "reason": "not_in_advertised_set"});
        db.insert_session_event(
            sid,
            SessionEventKind::ToolRejected,
            Some("Build"),
            Some("tc-1"),
            &rejected,
        )
        .await
        .unwrap();
        let swap = json!({
            "from": "Auto",
            "to": "Build",
            "trigger": "handoff",
            "display": "Handed off to `Build`.",
            "kickoff": "User's request:\nfix it\n\nBegin now.",
        });
        db.insert_session_event(
            sid,
            SessionEventKind::PrimarySwap,
            Some("Auto"),
            None,
            &swap,
        )
        .await
        .unwrap();
        let model_switch = json!({
            "from_provider": "provider-a",
            "from_model": "model-a",
            "to_provider": "provider-b",
            "to_model": "model-b",
            "trigger": "daemon",
            "outcome": "ok",
            "error": null,
        });
        db.insert_session_event(
            sid,
            SessionEventKind::ModelSwitch,
            None,
            None,
            &model_switch,
        )
        .await
        .unwrap();

        let events = db.list_session_events(sid).await.unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].kind, "tool_rejected");
        assert_eq!(events[0].data, rejected);
        assert_eq!(events[0].call_id.as_deref(), Some("tc-1"));
        assert_eq!(events[1].kind, "primary_swap");
        assert_eq!(events[1].data, swap);
        assert_eq!(events[2].kind, "model_switch");
        assert_eq!(events[2].data, model_switch);
    }

    #[tokio::test]
    async fn user_note_event_persists_with_stable_discriminant() {
        // `/note` records a `user_note` session event that persists durably
        // (survives a fresh Db handle to the same file) with its stable
        // discriminant string and verbatim text payload — the basis for both
        // resume and `/export debug` inclusion. No truncation in storage.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cockpit.db");
        let long = "x".repeat(10_000);
        let sid;
        let seq;
        {
            let db = Db::open(&path).unwrap();
            let s = db.create_session("p", "/x", "Build").await.unwrap();
            sid = s.session_id;
            assert_eq!(SessionEventKind::UserNote.as_str(), "user_note");
            seq = db
                .insert_session_event(
                    sid,
                    SessionEventKind::UserNote,
                    Some("Build"),
                    None,
                    &json!({ "text": long }),
                )
                .await
                .unwrap();
            assert!(seq > 0, "a monotonic seq is assigned");
        }
        // A fresh handle (a restart / resume) still sees the note in place.
        {
            let db = Db::open(&path).unwrap();
            let events = db.list_session_events(sid).await.unwrap();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].kind, "user_note");
            assert_eq!(events[0].seq, seq);
            assert_eq!(
                events[0].data.get("text").and_then(|v| v.as_str()),
                Some(long.as_str()),
                "the full note text is stored untruncated"
            );
        }
    }

    #[tokio::test]
    async fn session_events_seq_is_monotonic_across_sessions() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_session("p", "/x", "builder").await.unwrap();
        let b = db.create_fork(a.session_id, None).await.unwrap();
        // Interleave inserts across two sessions; seq must be globally
        // monotonic so the export's unified timeline orders correctly.
        let s1 = db
            .insert_session_event(
                a.session_id,
                SessionEventKind::UserMessage,
                Some("builder"),
                None,
                &json!({"text": "first"}),
            )
            .await
            .unwrap();
        let s2 = db
            .insert_session_event(
                b.session_id,
                SessionEventKind::AssistantMessage,
                Some("explore"),
                None,
                &json!({"text": "second"}),
            )
            .await
            .unwrap();
        let s3 = db
            .insert_session_event(
                a.session_id,
                SessionEventKind::InferenceRequest,
                Some("builder"),
                Some("call-1"),
                &json!({"file": "00003_x_call-1.json"}),
            )
            .await
            .unwrap();
        assert!(s1 < s2 && s2 < s3, "seq must be globally monotonic");

        let a_events = db.list_session_events(a.session_id).await.unwrap();
        assert_eq!(a_events.len(), 2);
        assert_eq!(a_events[0].kind, "user_message");
        assert_eq!(a_events[1].kind, "inference_request");
        assert_eq!(a_events[1].call_id.as_deref(), Some("call-1"));

        let b_events = db.list_session_events(b.session_id).await.unwrap();
        assert_eq!(b_events.len(), 1);
        assert_eq!(b_events[0].kind, "assistant_message");
        assert_eq!(b_events[0].data, json!({"text": "second"}));
    }

    #[tokio::test]
    async fn concurrent_session_event_writers_assign_unique_monotonic_seq() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cockpit.db");
        let db = Db::open(&path).unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();

        let mut tasks = Vec::new();
        for worker in 0..8 {
            let db = db.clone();
            let session_id = session.session_id;
            tasks.push(tokio::spawn(async move {
                let mut seqs = Vec::new();
                for index in 0..10 {
                    seqs.push(
                        db.insert_session_event(
                            session_id,
                            SessionEventKind::UserMessage,
                            Some("builder"),
                            None,
                            &json!({ "worker": worker, "index": index }),
                        )
                        .await
                        .unwrap(),
                    );
                }
                seqs
            }));
        }

        let mut seqs = Vec::new();
        for task in tasks {
            seqs.extend(task.await.unwrap());
        }
        assert_eq!(seqs.len(), 80);
        seqs.sort_unstable();
        seqs.dedup();
        assert_eq!(seqs.len(), 80, "each concurrent append gets one seq");

        let events = db.list_session_events(session.session_id).await.unwrap();
        assert_eq!(events.len(), 80);
        assert!(
            events.windows(2).all(|pair| pair[0].seq < pair[1].seq),
            "readback order must stay strictly monotonic"
        );
    }

    #[tokio::test]
    async fn crash_mid_append_rolls_back_uncommitted_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cockpit.db");
        let db = Db::open(&path).unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let committed = db
            .insert_session_event(
                session.session_id,
                SessionEventKind::UserMessage,
                Some("builder"),
                None,
                &json!({"text": "committed"}),
            )
            .await
            .unwrap();
        drop(db);

        {
            let mut conn = Connection::open(&path).unwrap();
            let tx = conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO session_events
                 (session_id, ts_ms, type, agent, call_id, task_call_id, label, origin_principal, data_json)
                 VALUES (?1, ?2, ?3, ?4, NULL, NULL, NULL, NULL, ?5)",
                params![
                    session.session_id.to_string(),
                    now_ms(),
                    SessionEventKind::AssistantMessage.as_str(),
                    "builder",
                    serde_json::to_string(&json!({"text": "uncommitted"})).unwrap(),
                ],
            )
            .unwrap();
            drop(tx);
        }

        let reopened = Db::open(&path).unwrap();
        let events = reopened
            .list_session_events(session.session_id)
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].seq, committed);
        assert_eq!(events[0].data, json!({"text": "committed"}));
    }

    #[tokio::test]
    async fn error_class_wire_session_log_payload_round_trips() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let data = json!({
            "provider": "xai",
            "model": "grok",
            "phase_reached": "prep",
            "error_class": {
                "kind": "missing_tool_entitlement",
                "feature": "xai_multi_agent_tools_beta"
            },
            "elapsed_ms": 7,
        });

        db.insert_session_event(
            session.session_id,
            SessionEventKind::InferenceFailure,
            Some("Build"),
            Some("call-1"),
            &data,
        )
        .await
        .unwrap();

        let events = db.list_session_events(session.session_id).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "inference_failure");
        assert_eq!(events[0].data, data);
    }

    #[tokio::test]
    async fn error_class_wire_legacy_flat_string_row_still_reads() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let legacy = r#"{
            "provider": "openai-compatible",
            "model": "qwen3",
            "phase_reached": "dispatched",
            "error_class": "network",
            "elapsed_ms": 37
        }"#;

        db.insert_session_event(
            session.session_id,
            SessionEventKind::InferenceFailure,
            Some("Build"),
            Some("call-legacy"),
            &serde_json::from_str::<Value>(legacy).unwrap(),
        )
        .await
        .unwrap();

        let events = db.list_session_events(session.session_id).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data["error_class"], "network");
    }

    #[tokio::test]
    async fn truncated_tail_is_ignored_when_rehydrating_committed_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cockpit.db");
        let db = Db::open(&path).unwrap();
        let session = db.create_session("p", "/x", "builder").await.unwrap();
        let user_seq = db
            .insert_session_event(
                session.session_id,
                SessionEventKind::UserMessage,
                Some("builder"),
                None,
                &json!({"text": "before"}),
            )
            .await
            .unwrap();
        let assistant_seq = db
            .insert_session_event(
                session.session_id,
                SessionEventKind::AssistantMessage,
                Some("builder"),
                None,
                &json!({"text": "still committed"}),
            )
            .await
            .unwrap();
        drop(db);

        let _reopened = Db::open(&path).unwrap();
        let events = decode_event_rows(vec![
            RawSessionEventRow {
                seq: user_seq,
                session_id: session.session_id.to_string(),
                ts_ms: now_ms(),
                kind: SessionEventKind::UserMessage.as_str().to_string(),
                agent: Some("builder".to_string()),
                call_id: None,
                task_call_id: None,
                label: None,
                origin_principal: None,
                provider_id: None,
                model_id: None,
                llm_mode: None,
                model_trust: None,
                data_json: serde_json::to_string(&json!({"text": "before"})).unwrap(),
            },
            RawSessionEventRow {
                seq: assistant_seq,
                session_id: session.session_id.to_string(),
                ts_ms: now_ms(),
                kind: SessionEventKind::AssistantMessage.as_str().to_string(),
                agent: Some("builder".to_string()),
                call_id: None,
                task_call_id: None,
                label: None,
                origin_principal: None,
                provider_id: None,
                model_id: None,
                llm_mode: None,
                model_trust: None,
                data_json: serde_json::to_string(&json!({"text": "still committed"})).unwrap(),
            },
            RawSessionEventRow {
                seq: assistant_seq + 1,
                session_id: session.session_id.to_string(),
                ts_ms: now_ms(),
                kind: SessionEventKind::AssistantMessage.as_str().to_string(),
                agent: Some("builder".to_string()),
                call_id: None,
                task_call_id: None,
                label: None,
                origin_principal: None,
                provider_id: None,
                model_id: None,
                llm_mode: None,
                model_trust: None,
                data_json: "{\"text\":".to_string(),
            },
        ])
        .unwrap();
        assert_eq!(
            events.iter().map(|row| row.seq).collect::<Vec<_>>(),
            vec![user_seq, assistant_seq]
        );

        assert_eq!(events[0].data["text"], "before");
        assert_eq!(events[1].data["text"], "still committed");
    }

    #[tokio::test]
    async fn list_session_events_since_filters_strictly_after_seq() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").await.unwrap();
        let seq1 = db
            .insert_session_event(
                s.session_id,
                SessionEventKind::UserMessage,
                Some("builder"),
                None,
                &json!({"text": "one"}),
            )
            .await
            .unwrap();
        let seq2 = db
            .insert_session_event(
                s.session_id,
                SessionEventKind::AssistantMessage,
                Some("builder"),
                None,
                &json!({"text": "two"}),
            )
            .await
            .unwrap();
        let seq3 = db
            .insert_session_event(
                s.session_id,
                SessionEventKind::UserNote,
                Some("builder"),
                None,
                &json!({"text": "three"}),
            )
            .await
            .unwrap();

        let rows = db
            .read(move |conn| Db::list_session_events_since_conn(conn, s.session_id, seq1))
            .await
            .unwrap();
        let got: Vec<i64> = rows.into_iter().map(|row| row.seq).collect();
        assert_eq!(got, vec![seq2, seq3]);

        let rows = db
            .read(move |conn| Db::list_session_events_since_conn(conn, s.session_id, seq3))
            .await
            .unwrap();
        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn list_session_events_before_returns_newest_page_oldest_first() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").await.unwrap();
        let seqs = insert_numbered_events(&db, s.session_id, 5).await;

        let page = db
            .list_session_events_before(s.session_id, None, 2)
            .await
            .expect("newest page");
        assert_eq!(
            page.events
                .iter()
                .map(|event| event.seq)
                .collect::<Vec<_>>(),
            vec![seqs[3], seqs[4]]
        );
        assert!(page.has_more);
        assert_eq!(page.oldest_seq, Some(seqs[3]));

        let missing_cursor_page = db
            .list_session_events_before(s.session_id, Some(seqs[4] + 100), 2)
            .await
            .expect("page before missing cursor");
        assert_eq!(
            missing_cursor_page
                .events
                .iter()
                .map(|event| event.seq)
                .collect::<Vec<_>>(),
            vec![seqs[3], seqs[4]]
        );
    }

    #[tokio::test]
    async fn list_session_events_before_walk_reconstructs_full_event_list() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").await.unwrap();
        insert_numbered_events(&db, s.session_id, 7).await;
        let full = db.list_session_events(s.session_id).await.unwrap();

        let mut pages = Vec::new();
        let mut before_seq = None;
        loop {
            let page = db
                .list_session_events_before(s.session_id, before_seq, 3)
                .await
                .expect("page before cursor");
            before_seq = page.oldest_seq;
            pages.push(page.events);
            if !page.has_more {
                break;
            }
        }
        let reconstructed = pages
            .into_iter()
            .rev()
            .flatten()
            .collect::<Vec<SessionEventRow>>();

        assert_session_event_rows_eq(&reconstructed, &full);
    }

    #[tokio::test]
    async fn list_session_events_before_reports_has_more_until_oldest_event() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").await.unwrap();
        let seqs = insert_numbered_events(&db, s.session_id, 5).await;

        let first = db
            .list_session_events_before(s.session_id, None, 2)
            .await
            .expect("first page");
        assert_eq!(
            first
                .events
                .iter()
                .map(|event| event.seq)
                .collect::<Vec<_>>(),
            vec![seqs[3], seqs[4]]
        );
        assert!(first.has_more);
        assert_eq!(first.oldest_seq, Some(seqs[3]));

        let second = db
            .list_session_events_before(s.session_id, first.oldest_seq, 2)
            .await
            .expect("second page");
        assert_eq!(
            second
                .events
                .iter()
                .map(|event| event.seq)
                .collect::<Vec<_>>(),
            vec![seqs[1], seqs[2]]
        );
        assert!(second.has_more);
        assert_eq!(second.oldest_seq, Some(seqs[1]));

        let third = db
            .list_session_events_before(s.session_id, second.oldest_seq, 2)
            .await
            .expect("third page");
        assert_eq!(
            third
                .events
                .iter()
                .map(|event| event.seq)
                .collect::<Vec<_>>(),
            vec![seqs[0]]
        );
        assert!(!third.has_more);
        assert_eq!(third.oldest_seq, Some(seqs[0]));

        let before_oldest = db
            .list_session_events_before(s.session_id, Some(0), 2)
            .await
            .expect("before oldest seq");
        assert!(before_oldest.events.is_empty());
        assert!(!before_oldest.has_more);
        assert_eq!(before_oldest.oldest_seq, None);
    }

    #[tokio::test]
    async fn list_session_events_before_clamps_limit() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").await.unwrap();
        let seqs = insert_numbered_events(&db, s.session_id, 501).await;

        let minimum = db
            .list_session_events_before(s.session_id, None, 0)
            .await
            .expect("minimum clamped page");
        assert_eq!(minimum.events.len(), 1);
        assert_eq!(minimum.events[0].seq, *seqs.last().unwrap());
        assert!(minimum.has_more);
        assert_eq!(minimum.oldest_seq, seqs.last().copied());

        let capped = db
            .list_session_events_before(s.session_id, None, u32::MAX)
            .await
            .expect("maximum clamped page");
        assert_eq!(capped.events.len(), LIST_SESSION_EVENTS_MAX_LIMIT as usize);
        assert!(capped.has_more);
        assert_eq!(capped.oldest_seq, Some(seqs[1]));
        assert!(
            capped
                .events
                .windows(2)
                .all(|pair| pair[0].seq < pair[1].seq)
        );
    }

    #[tokio::test]
    async fn list_session_events_before_hydrates_compaction_payload() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").await.unwrap();
        let handoff_id = Uuid::new_v4();
        let payload = json!({
            "handoff_text": "resume from stored handoff",
            "brief_text": "stored brief",
        });
        db.store_compaction_payload(handoff_id, s.session_id, &payload.to_string())
            .await
            .unwrap();
        let compacted = db
            .insert_session_event(
                s.session_id,
                SessionEventKind::SessionCompacted,
                Some("builder"),
                None,
                &json!({"handoff_ref": handoff_id.to_string(), "brief_text": "inline brief"}),
            )
            .await
            .unwrap();

        let full = db.list_session_events(s.session_id).await.unwrap();
        let page = db
            .list_session_events_before(s.session_id, None, 10)
            .await
            .expect("compaction page");
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].seq, compacted);
        assert_eq!(page.events[0].data, payload);
        assert_session_event_rows_eq(&page.events, &full);
    }

    #[tokio::test]
    async fn list_session_events_before_empty_session_returns_empty_page() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").await.unwrap();

        let page = db
            .list_session_events_before(s.session_id, None, 10)
            .await
            .expect("empty session page");
        assert!(page.events.is_empty());
        assert!(!page.has_more);
        assert_eq!(page.oldest_seq, None);

        let unknown = db
            .list_session_events_before(Uuid::new_v4(), None, 10)
            .await
            .expect("unknown session page");
        assert!(unknown.events.is_empty());
        assert!(!unknown.has_more);
        assert_eq!(unknown.oldest_seq, None);
    }

    #[tokio::test]
    async fn list_session_events_before_does_not_leak_across_sessions() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_session("p", "/x", "builder").await.unwrap();
        let b = db.create_fork(a.session_id, None).await.unwrap();

        let a1 = db
            .insert_session_event(
                a.session_id,
                SessionEventKind::UserMessage,
                Some("builder"),
                None,
                &json!({"text": "a-one"}),
            )
            .await
            .unwrap();
        let b1 = db
            .insert_session_event(
                b.session_id,
                SessionEventKind::UserMessage,
                Some("builder"),
                None,
                &json!({"text": "b-one"}),
            )
            .await
            .unwrap();
        let a2 = db
            .insert_session_event(
                a.session_id,
                SessionEventKind::AssistantMessage,
                Some("builder"),
                None,
                &json!({"text": "a-two"}),
            )
            .await
            .unwrap();
        let b2 = db
            .insert_session_event(
                b.session_id,
                SessionEventKind::AssistantMessage,
                Some("builder"),
                None,
                &json!({"text": "b-two"}),
            )
            .await
            .unwrap();

        let a_page = db
            .list_session_events_before(a.session_id, None, 10)
            .await
            .expect("session a page");
        assert_eq!(
            a_page
                .events
                .iter()
                .map(|event| event.seq)
                .collect::<Vec<_>>(),
            vec![a1, a2]
        );

        let b_page = db
            .list_session_events_before(b.session_id, Some(b2), 10)
            .await
            .expect("session b older page");
        assert_eq!(
            b_page
                .events
                .iter()
                .map(|event| event.seq)
                .collect::<Vec<_>>(),
            vec![b1]
        );
        assert!(
            !b_page
                .events
                .iter()
                .any(|event| event.seq == a1 || event.seq == a2)
        );
    }

    #[tokio::test]
    async fn read_session_messages_pages_message_rows_only() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").await.unwrap();
        let user_one = db
            .insert_session_event(
                s.session_id,
                SessionEventKind::UserMessage,
                Some("builder"),
                None,
                &json!({"text": "one"}),
            )
            .await
            .unwrap();
        db.insert_session_event(
            s.session_id,
            SessionEventKind::ToolCall,
            Some("builder"),
            None,
            &json!({"text": "ignored tool"}),
        )
        .await
        .unwrap();
        let agent_two = db
            .insert_session_event(
                s.session_id,
                SessionEventKind::AssistantMessage,
                Some("builder"),
                None,
                &json!({"text": "two"}),
            )
            .await
            .unwrap();
        let user_three = db
            .insert_session_event(
                s.session_id,
                SessionEventKind::UserMessage,
                Some("builder"),
                None,
                &json!({"text": "three"}),
            )
            .await
            .unwrap();

        let before = db
            .list_session_summaries(Some("p"), None, 10)
            .await
            .unwrap()
            .remove(0);
        let (page, has_more) = db
            .read_session_messages(s.session_id, None, 2)
            .await
            .expect("newest page");
        assert!(has_more);
        assert_eq!(
            page.iter().map(|message| message.seq).collect::<Vec<_>>(),
            vec![agent_two, user_three]
        );
        assert_eq!(page[0].role, crate::db::wire::MessageRole::Agent);
        assert_eq!(page[0].text, "two");
        assert_eq!(page[1].role, crate::db::wire::MessageRole::User);
        assert_eq!(page[1].text, "three");

        let (older, has_more) = db
            .read_session_messages(s.session_id, Some(agent_two), 2)
            .await
            .expect("older page");
        assert!(!has_more);
        assert_eq!(older.len(), 1);
        assert_eq!(older[0].seq, user_one);

        let after = db
            .list_session_summaries(Some("p"), None, 10)
            .await
            .unwrap()
            .remove(0);
        assert_eq!(after.last_viewed_at, before.last_viewed_at);
        assert_eq!(after.latest_activity_at, before.latest_activity_at);
    }

    // ---- Redacting Debug over trusted request/event bodies -----------------

    #[test]
    fn inference_request_row_debug_redacts_payload() {
        let secret = "TRUSTED-BODY-SECRET-inference-payload-987";
        let row = InferenceRequestRow {
            call_id: "call-1".to_string(),
            ordinal: 0,
            session_id: "sess-1".to_string(),
            ts_ms: 123,
            payload: json!({ "system": secret, "history": [1, 2, 3] }),
            status: "completed".to_string(),
            provider: Some("anthropic".to_string()),
            model: Some("claude".to_string()),
            trust: Some("trusted".to_string()),
            first_token_ms: Some(10),
            completed_ms: Some(20),
            failed_ms: None,
        };
        let rendered = format!("{row:?}");
        assert!(!rendered.contains(secret), "leaked payload: {rendered}");
        assert!(rendered.contains("REDACTED"), "missing marker: {rendered}");
        // Non-body metadata stays visible.
        assert!(rendered.contains("call-1"), "dropped call_id: {rendered}");
        assert!(
            rendered.contains("anthropic"),
            "dropped provider: {rendered}"
        );
    }

    #[test]
    fn imported_inference_request_debug_redacts_payload() {
        let secret = "TRUSTED-BODY-SECRET-imported-payload-654";
        let payload = json!({ "prompt": secret });
        let session_id = Uuid::nil();
        let imported = ImportedInferenceRequest {
            call_id: "call-2",
            ordinal: 1,
            session_id,
            ts_ms: 456,
            payload: &payload,
            status: "completed",
            provider: Some("openai"),
            model: Some("gpt"),
            trust: Some("trusted"),
            phases: InferencePhaseTimings::default(),
        };
        let rendered = format!("{imported:?}");
        assert!(!rendered.contains(secret), "leaked payload: {rendered}");
        assert!(rendered.contains("REDACTED"), "missing marker: {rendered}");
        assert!(rendered.contains("call-2"), "dropped call_id: {rendered}");
    }

    #[test]
    fn session_event_row_debug_redacts_data() {
        let secret = "TRUSTED-BODY-SECRET-event-data-321";
        let row = SessionEventRow {
            seq: 7,
            session_id: Uuid::nil(),
            ts_ms: 789,
            kind: "assistant_message".to_string(),
            agent: Some("primary".to_string()),
            call_id: None,
            task_call_id: None,
            label: None,
            origin_principal: None,
            provider_id: None,
            model_id: None,
            llm_mode: None,
            model_trust: None,
            data: json!({ "text": secret }),
        };
        let rendered = format!("{row:?}");
        assert!(!rendered.contains(secret), "leaked data: {rendered}");
        assert!(rendered.contains("REDACTED"), "missing marker: {rendered}");
        assert!(
            rendered.contains("assistant_message"),
            "dropped kind: {rendered}"
        );
    }
}
