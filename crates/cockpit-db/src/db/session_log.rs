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

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde_json::Value;
use uuid::Uuid;

use crate::db::Db;

const READ_SESSION_MESSAGES_MAX_LIMIT: u32 = 200;
const LIST_SESSION_EVENTS_MAX_LIMIT: u32 = 500;

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
    /// (`prep`/`dispatched`/`first_token`/`streaming`), `error_class`
    /// (`timeout_ttft`/`timeout_idle`/`network`/`http_<status>`/`cancelled`),
    /// and `elapsed_ms`. Keyed by the same `call_id` as the dispatch-time
    /// `inference_request` record. Data/export only — never enters the model's
    /// context (the user-facing inline error is a separate UI surface).
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
}

impl SessionEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionEventKind::UserMessage => "user_message",
            SessionEventKind::UserNote => "user_note",
            SessionEventKind::AssistantMessage => "assistant_message",
            SessionEventKind::InferenceRequest => "inference_request",
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
        }
    }
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

/// Optional context stamped onto a `session_events` row.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionEventContext<'a> {
    pub origin_principal: Option<&'a str>,
    pub task_call_id: Option<&'a str>,
    pub label: Option<&'a str>,
}

/// A row read back from `session_events`.
#[derive(Debug, Clone)]
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
    pub data: Value,
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
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn store_compaction_payload(
        &self,
        handoff_id: Uuid,
        session_id: Uuid,
        payload_json: &str,
    ) -> Result<()> {
        let payload_json = payload_json.to_string();
        self.write_blocking(move |conn| {
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
        })
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

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn compaction_payload(&self, session_id: Uuid, handoff_id: &str) -> Result<Option<String>> {
        self.read_blocking(|conn| Self::compaction_payload_conn(conn, session_id, handoff_id))
    }

    /// Store the full assembled (post-redaction) request body for one
    /// inference call with its lifecycle `status`. `call_id` must match the
    /// `inference_calls` row's `call_id` so the export can join usage onto the
    /// payload. Uses `INSERT OR REPLACE` so the dispatch-time write
    /// (status `pending`) and the terminal update (status
    /// `completed`/`errored`/`timed_out`/`cancelled`) for the same `call_id`
    /// land on one row — the terminal write supersedes the pending one
    /// (implementation note). The
    /// dispatch `ts_ms` is preserved across the update via `COALESCE` so the
    /// recorded timestamp is when the request went out, not when it settled.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn insert_inference_request(
        &self,
        call_id: &str,
        session_id: Uuid,
        payload: &Value,
        status: InferenceRequestStatus,
    ) -> Result<()> {
        let payload_json = serde_json::to_string(payload).context("serializing request payload")?;
        let ts_ms = now_ms();
        let call_id = call_id.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO inference_requests
                   (call_id, session_id, ts_ms, payload_json, status)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(call_id) DO UPDATE SET
                   payload_json = excluded.payload_json,
                   status       = excluded.status",
                params![
                    call_id,
                    session_id.to_string(),
                    ts_ms,
                    payload_json,
                    status.as_str()
                ],
            )
            .context("inserting inference_request")?;
            Ok(())
        })
    }

    /// Append one event to the per-session timeline. Returns the assigned
    /// monotonic `seq` (the rowid). `data` carries the per-type payload.
    pub fn insert_session_event(
        &self,
        session_id: Uuid,
        kind: SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        data: &Value,
    ) -> Result<i64> {
        self.insert_session_event_with_origin(session_id, kind, agent, call_id, None, data)
    }

    pub fn insert_session_event_with_origin(
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
            },
            data,
        )
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn insert_session_event_with_context(
        &self,
        session_id: Uuid,
        kind: SessionEventKind,
        agent: Option<&str>,
        call_id: Option<&str>,
        context: SessionEventContext<'_>,
        data: &Value,
    ) -> Result<i64> {
        let data_json = serde_json::to_string(data).context("serializing event data")?;
        let ts_ms = now_ms();
        let agent = agent.map(str::to_owned);
        let call_id = call_id.map(str::to_owned);
        let task_call_id = context.task_call_id.map(str::to_owned);
        let label = context.label.map(str::to_owned);
        let origin_principal = context.origin_principal.map(str::to_owned);
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO session_events
                 (session_id, ts_ms, type, agent, call_id, task_call_id, label, origin_principal, data_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    session_id.to_string(),
                    ts_ms,
                    kind.as_str(),
                    agent,
                    call_id,
                    task_call_id,
                    label,
                    origin_principal,
                    data_json,
                ],
            )
            .context("inserting session_event")?;
            Ok(conn.last_insert_rowid())
        })
    }

    /// All events for one session, ordered by `seq` (oldest first). Used
    /// by the exporter to merge per-fork timelines.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn list_session_events(&self, session_id: Uuid) -> Result<Vec<SessionEventRow>> {
        self.read_blocking(|conn| Self::list_session_events_conn(conn, session_id))
    }

    pub fn list_session_events_conn(
        conn: &Connection,
        session_id: Uuid,
    ) -> Result<Vec<SessionEventRow>> {
        let mut stmt = conn
            .prepare(
                "SELECT seq, session_id, ts_ms, type, agent, call_id, task_call_id, label, origin_principal, data_json
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
                "SELECT seq, session_id, ts_ms, type, agent, call_id, task_call_id, label, origin_principal, data_json
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

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn list_session_events_before(
        &self,
        session_id: Uuid,
        before_seq: Option<i64>,
        limit: u32,
    ) -> Result<SessionEventPage> {
        self.read_blocking(|conn| {
            Self::list_session_events_before_conn(conn, session_id, before_seq, limit)
        })
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
                "SELECT seq, session_id, ts_ms, type, agent, call_id, task_call_id, label, origin_principal, data_json
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

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn read_session_messages(
        &self,
        session_id: Uuid,
        before_seq: Option<i64>,
        limit: u32,
    ) -> Result<(Vec<crate::db::wire::SessionMessage>, bool)> {
        self.read_blocking(|conn| {
            Self::read_session_messages_conn(conn, session_id, before_seq, limit)
        })
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

    /// Look up the stored (post-redaction) request payload + lifecycle
    /// `status` for one `call_id`. `None` when no payload was captured (e.g. a
    /// pre-0009 call). The export writes the payload verbatim and surfaces the
    /// status on the emitted file so a hung/failed turn's record carries its
    /// non-`completed` status.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn get_inference_request(&self, call_id: &str) -> Result<Option<(Value, String)>> {
        self.read_blocking(|conn| {
            let result: rusqlite::Result<(String, String)> = conn.query_row(
                "SELECT payload_json, status FROM inference_requests WHERE call_id = ?1",
                [call_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            );
            match result {
                Ok((payload_json, status)) => {
                    let payload: Value = serde_json::from_str(&payload_json)
                        .context("deserializing payload_json")?;
                    Ok(Some((payload, status)))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e).context("querying inference_request"),
            }
        })
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
        data,
    })
}

fn is_truncated_tail_error(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.to_string().contains("deserializing data_json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn insert_numbered_events(db: &Db, session_id: Uuid, count: usize) -> Vec<i64> {
        (1..=count)
            .map(|index| {
                let kind = match index % 3 {
                    0 => SessionEventKind::ToolCall,
                    1 => SessionEventKind::UserMessage,
                    _ => SessionEventKind::AssistantMessage,
                };
                db.insert_session_event(
                    session_id,
                    kind,
                    Some("builder"),
                    None,
                    &json!({"text": format!("event-{index}")}),
                )
                .unwrap()
            })
            .collect()
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

    #[test]
    fn inference_request_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
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
            s.session_id,
            &payload,
            InferenceRequestStatus::Completed,
        )
        .unwrap();
        let (got, status) = db.get_inference_request(&call_id).unwrap().unwrap();
        assert_eq!(got, payload);
        assert_eq!(status, "completed");
        // Unknown call_id resolves to None.
        assert!(db.get_inference_request("missing").unwrap().is_none());
    }

    #[test]
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    fn inference_request_dispatch_then_terminal_update_supersedes() {
        // The dispatch-time write (status `pending`) and the terminal update
        // (status `timed_out`) for one call_id collapse onto a single row,
        // with the terminal status + payload winning — the
        // dispatch-time-recording lifecycle
        // (implementation note).
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let call_id = Uuid::new_v4().to_string();
        let pending_payload = json!({ "model": "m", "status_hint": "pre-dispatch" });
        db.insert_inference_request(
            &call_id,
            s.session_id,
            &pending_payload,
            InferenceRequestStatus::Pending,
        )
        .unwrap();
        let (_, status) = db.get_inference_request(&call_id).unwrap().unwrap();
        assert_eq!(status, "pending");

        // Terminal update: a hung turn that timed out.
        let final_payload = json!({ "model": "m", "phases": { "dispatched_ms": 0 } });
        db.insert_inference_request(
            &call_id,
            s.session_id,
            &final_payload,
            InferenceRequestStatus::TimedOut,
        )
        .unwrap();
        let (got, status) = db.get_inference_request(&call_id).unwrap().unwrap();
        assert_eq!(status, "timed_out");
        assert_eq!(got, final_payload, "terminal payload supersedes pending");

        // Exactly one row — the update collapsed onto the dispatch row.
        let count: i64 = db
            .read_blocking(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM inference_requests WHERE call_id = ?1",
                    [&call_id],
                    |r| r.get(0),
                )
                .map_err(anyhow::Error::from)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn permission_decision_event_round_trips() {
        // The `permission_decision` variant persists with its stable
        // discriminant string and its data payload flows back verbatim.
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
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
        .unwrap();
        let events = db.list_session_events(s.session_id).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "permission_decision");
        assert_eq!(events[0].data, data);
    }

    #[test]
    fn notice_event_kind_wire_string_is_notice() {
        assert_eq!(SessionEventKind::Notice.as_str(), "notice");
    }

    #[test]
    fn session_event_kind_export_audit_events_round_trip() {
        // The export-audit-fidelity event kinds persist with their stable
        // discriminant strings and flow their data payloads back verbatim.
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").unwrap();
        let sid = s.session_id;

        let rejected = json!({"tool": "handoff", "reason": "not_in_advertised_set"});
        db.insert_session_event(
            sid,
            SessionEventKind::ToolRejected,
            Some("Build"),
            Some("tc-1"),
            &rejected,
        )
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
        .unwrap();

        let events = db.list_session_events(sid).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].kind, "tool_rejected");
        assert_eq!(events[0].data, rejected);
        assert_eq!(events[0].call_id.as_deref(), Some("tc-1"));
        assert_eq!(events[1].kind, "primary_swap");
        assert_eq!(events[1].data, swap);
        assert_eq!(events[2].kind, "model_switch");
        assert_eq!(events[2].data, model_switch);
    }

    #[test]
    fn user_note_event_persists_with_stable_discriminant() {
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
            let s = db.create_session("p", "/x", "Build").unwrap();
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
                .unwrap();
            assert!(seq > 0, "a monotonic seq is assigned");
        }
        // A fresh handle (a restart / resume) still sees the note in place.
        {
            let db = Db::open(&path).unwrap();
            let events = db.list_session_events(sid).unwrap();
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

    #[test]
    fn session_events_seq_is_monotonic_across_sessions() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_session("p", "/x", "builder").unwrap();
        let b = db.create_fork(a.session_id, None).unwrap();
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
            .unwrap();
        let s2 = db
            .insert_session_event(
                b.session_id,
                SessionEventKind::AssistantMessage,
                Some("explore"),
                None,
                &json!({"text": "second"}),
            )
            .unwrap();
        let s3 = db
            .insert_session_event(
                a.session_id,
                SessionEventKind::InferenceRequest,
                Some("builder"),
                Some("call-1"),
                &json!({"file": "00003_x_call-1.json"}),
            )
            .unwrap();
        assert!(s1 < s2 && s2 < s3, "seq must be globally monotonic");

        let a_events = db.list_session_events(a.session_id).unwrap();
        assert_eq!(a_events.len(), 2);
        assert_eq!(a_events[0].kind, "user_message");
        assert_eq!(a_events[1].kind, "inference_request");
        assert_eq!(a_events[1].call_id.as_deref(), Some("call-1"));

        let b_events = db.list_session_events(b.session_id).unwrap();
        assert_eq!(b_events.len(), 1);
        assert_eq!(b_events[0].kind, "assistant_message");
        assert_eq!(b_events[0].data, json!({"text": "second"}));
    }

    #[test]
    fn concurrent_session_event_writers_assign_unique_monotonic_seq() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cockpit.db");
        let db = Db::open(&path).unwrap();
        let session = db.create_session("p", "/x", "builder").unwrap();

        let mut threads = Vec::new();
        for worker in 0..8 {
            let db = db.clone();
            let session_id = session.session_id;
            threads.push(std::thread::spawn(move || {
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
                        .unwrap(),
                    );
                }
                seqs
            }));
        }

        let mut seqs = threads
            .into_iter()
            .flat_map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(seqs.len(), 80);
        seqs.sort_unstable();
        seqs.dedup();
        assert_eq!(seqs.len(), 80, "each concurrent append gets one seq");

        let events = db.list_session_events(session.session_id).unwrap();
        assert_eq!(events.len(), 80);
        assert!(
            events.windows(2).all(|pair| pair[0].seq < pair[1].seq),
            "readback order must stay strictly monotonic"
        );
    }

    #[test]
    fn crash_mid_append_rolls_back_uncommitted_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cockpit.db");
        let db = Db::open(&path).unwrap();
        let session = db.create_session("p", "/x", "builder").unwrap();
        let committed = db
            .insert_session_event(
                session.session_id,
                SessionEventKind::UserMessage,
                Some("builder"),
                None,
                &json!({"text": "committed"}),
            )
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
        let events = reopened.list_session_events(session.session_id).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].seq, committed);
        assert_eq!(events[0].data, json!({"text": "committed"}));
    }

    #[test]
    fn truncated_tail_is_ignored_when_rehydrating_committed_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cockpit.db");
        let db = Db::open(&path).unwrap();
        let session = db.create_session("p", "/x", "builder").unwrap();
        let user_seq = db
            .insert_session_event(
                session.session_id,
                SessionEventKind::UserMessage,
                Some("builder"),
                None,
                &json!({"text": "before"}),
            )
            .unwrap();
        let assistant_seq = db
            .insert_session_event(
                session.session_id,
                SessionEventKind::AssistantMessage,
                Some("builder"),
                None,
                &json!({"text": "still committed"}),
            )
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

    #[test]
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    fn list_session_events_since_filters_strictly_after_seq() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let seq1 = db
            .insert_session_event(
                s.session_id,
                SessionEventKind::UserMessage,
                Some("builder"),
                None,
                &json!({"text": "one"}),
            )
            .unwrap();
        let seq2 = db
            .insert_session_event(
                s.session_id,
                SessionEventKind::AssistantMessage,
                Some("builder"),
                None,
                &json!({"text": "two"}),
            )
            .unwrap();
        let seq3 = db
            .insert_session_event(
                s.session_id,
                SessionEventKind::UserNote,
                Some("builder"),
                None,
                &json!({"text": "three"}),
            )
            .unwrap();

        let rows = db
            .read_blocking(|conn| Db::list_session_events_since_conn(conn, s.session_id, seq1))
            .unwrap();
        let got: Vec<i64> = rows.into_iter().map(|row| row.seq).collect();
        assert_eq!(got, vec![seq2, seq3]);

        let rows = db
            .read_blocking(|conn| Db::list_session_events_since_conn(conn, s.session_id, seq3))
            .unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn list_session_events_before_returns_newest_page_oldest_first() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let seqs = insert_numbered_events(&db, s.session_id, 5);

        let page = db
            .list_session_events_before(s.session_id, None, 2)
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

    #[test]
    fn list_session_events_before_walk_reconstructs_full_event_list() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        insert_numbered_events(&db, s.session_id, 7);
        let full = db.list_session_events(s.session_id).unwrap();

        let mut pages = Vec::new();
        let mut before_seq = None;
        loop {
            let page = db
                .list_session_events_before(s.session_id, before_seq, 3)
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

    #[test]
    fn list_session_events_before_reports_has_more_until_oldest_event() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let seqs = insert_numbered_events(&db, s.session_id, 5);

        let first = db
            .list_session_events_before(s.session_id, None, 2)
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
            .expect("before oldest seq");
        assert!(before_oldest.events.is_empty());
        assert!(!before_oldest.has_more);
        assert_eq!(before_oldest.oldest_seq, None);
    }

    #[test]
    fn list_session_events_before_clamps_limit() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let seqs = insert_numbered_events(&db, s.session_id, 501);

        let minimum = db
            .list_session_events_before(s.session_id, None, 0)
            .expect("minimum clamped page");
        assert_eq!(minimum.events.len(), 1);
        assert_eq!(minimum.events[0].seq, *seqs.last().unwrap());
        assert!(minimum.has_more);
        assert_eq!(minimum.oldest_seq, seqs.last().copied());

        let capped = db
            .list_session_events_before(s.session_id, None, u32::MAX)
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

    #[test]
    fn list_session_events_before_hydrates_compaction_payload() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let handoff_id = Uuid::new_v4();
        let payload = json!({
            "handoff_text": "resume from stored handoff",
            "brief_text": "stored brief",
        });
        db.store_compaction_payload(handoff_id, s.session_id, &payload.to_string())
            .unwrap();
        let compacted = db
            .insert_session_event(
                s.session_id,
                SessionEventKind::SessionCompacted,
                Some("builder"),
                None,
                &json!({"handoff_ref": handoff_id.to_string(), "brief_text": "inline brief"}),
            )
            .unwrap();

        let full = db.list_session_events(s.session_id).unwrap();
        let page = db
            .list_session_events_before(s.session_id, None, 10)
            .expect("compaction page");
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].seq, compacted);
        assert_eq!(page.events[0].data, payload);
        assert_session_event_rows_eq(&page.events, &full);
    }

    #[test]
    fn list_session_events_before_empty_session_returns_empty_page() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();

        let page = db
            .list_session_events_before(s.session_id, None, 10)
            .expect("empty session page");
        assert!(page.events.is_empty());
        assert!(!page.has_more);
        assert_eq!(page.oldest_seq, None);

        let unknown = db
            .list_session_events_before(Uuid::new_v4(), None, 10)
            .expect("unknown session page");
        assert!(unknown.events.is_empty());
        assert!(!unknown.has_more);
        assert_eq!(unknown.oldest_seq, None);
    }

    #[test]
    fn list_session_events_before_does_not_leak_across_sessions() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_session("p", "/x", "builder").unwrap();
        let b = db.create_fork(a.session_id, None).unwrap();

        let a1 = db
            .insert_session_event(
                a.session_id,
                SessionEventKind::UserMessage,
                Some("builder"),
                None,
                &json!({"text": "a-one"}),
            )
            .unwrap();
        let b1 = db
            .insert_session_event(
                b.session_id,
                SessionEventKind::UserMessage,
                Some("builder"),
                None,
                &json!({"text": "b-one"}),
            )
            .unwrap();
        let a2 = db
            .insert_session_event(
                a.session_id,
                SessionEventKind::AssistantMessage,
                Some("builder"),
                None,
                &json!({"text": "a-two"}),
            )
            .unwrap();
        let b2 = db
            .insert_session_event(
                b.session_id,
                SessionEventKind::AssistantMessage,
                Some("builder"),
                None,
                &json!({"text": "b-two"}),
            )
            .unwrap();

        let a_page = db
            .list_session_events_before(a.session_id, None, 10)
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

    #[test]
    fn read_session_messages_pages_message_rows_only() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "builder").unwrap();
        let user_one = db
            .insert_session_event(
                s.session_id,
                SessionEventKind::UserMessage,
                Some("builder"),
                None,
                &json!({"text": "one"}),
            )
            .unwrap();
        db.insert_session_event(
            s.session_id,
            SessionEventKind::ToolCall,
            Some("builder"),
            None,
            &json!({"text": "ignored tool"}),
        )
        .unwrap();
        let agent_two = db
            .insert_session_event(
                s.session_id,
                SessionEventKind::AssistantMessage,
                Some("builder"),
                None,
                &json!({"text": "two"}),
            )
            .unwrap();
        let user_three = db
            .insert_session_event(
                s.session_id,
                SessionEventKind::UserMessage,
                Some("builder"),
                None,
                &json!({"text": "three"}),
            )
            .unwrap();

        let before = db
            .list_session_summaries(Some("p"), None, 10)
            .unwrap()
            .remove(0);
        let (page, has_more) = db
            .read_session_messages(s.session_id, None, 2)
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
            .expect("older page");
        assert!(!has_more);
        assert_eq!(older.len(), 1);
        assert_eq!(older[0].seq, user_one);

        let after = db
            .list_session_summaries(Some("p"), None, 10)
            .unwrap()
            .remove(0);
        assert_eq!(after.last_viewed_at, before.last_viewed_at);
        assert_eq!(after.latest_activity_at, before.latest_activity_at);
    }
}
