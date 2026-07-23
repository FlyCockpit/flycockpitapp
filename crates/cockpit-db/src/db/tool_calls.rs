//! `tool_call_events` writes + history reads.
//!
//! Row shape mirrors GOALS §15b exactly. The two projections
//! (`original_input_json`, `wire_input_json`) live on the same row
//! per GOALS §14a.

use std::borrow::Cow;

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde_json::Value;
use uuid::Uuid;

use crate::db::{
    Db,
    lang::language_for_path,
    sql::{PredicateBuilder, SqlColumn},
};

/// What a tool-input repair pass did. One row per dispatched tool call,
/// persisted to `tool_call_events.recovery_kind` + `recovery_stage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovery {
    /// Args were already valid; no repair needed.
    Clean,
    /// A shape repair fired. `stage` is the catalog name; `path` names the
    /// top-level argument rewritten. `hint` is in-memory only.
    ShapeRepair {
        stage: &'static str,
        path: String,
        hint: Option<String>,
    },
    /// The `edit` cascade matched at a stage past `exact`.
    EditCascade { stage: &'static str, path: String },
    /// A session-resume rehydration heal stubbed or dropped an unpairable row.
    ResumeHeal { kind: &'static str, id: String },
    /// The emitted tool name was repaired before dispatch.
    NameRepair {
        stage: &'static str,
        original: String,
    },
    /// A tool call emitted as text was recovered into a real call.
    TextEmbedded {
        stage: &'static str,
        original: String,
        dropped_trailing: bool,
    },
    /// A persisted recovery kind/stage from a newer, renamed, or downgraded
    /// build that this binary does not recognize.
    Unknown { kind: String, stage: Option<String> },
}

impl Recovery {
    /// `(recovery_kind, recovery_stage)` for the session-DB row.
    pub fn db_fields(&self) -> (Option<&'static str>, Option<&'static str>) {
        match self {
            Recovery::Clean => (None, None),
            Recovery::ShapeRepair { stage, .. } => (Some("shape_repair"), Some(stage)),
            Recovery::EditCascade { stage, .. } => (Some("edit_cascade"), Some(stage)),
            Recovery::ResumeHeal { kind, .. } => (Some("resume_heal"), Some(kind)),
            Recovery::NameRepair { stage, .. } => (Some("name_repair"), Some(stage)),
            Recovery::TextEmbedded { stage, .. } => (Some("text_embedded"), Some(stage)),
            Recovery::Unknown { .. } => (None, None),
        }
    }

    /// Dynamic `(recovery_kind, recovery_stage)` for display/export paths that
    /// may need to surface unknown persisted values.
    pub fn raw_db_fields(&self) -> (Option<Cow<'_, str>>, Option<Cow<'_, str>>) {
        match self {
            Recovery::Unknown { kind, stage } => (
                Some(Cow::Borrowed(kind.as_str())),
                stage.as_deref().map(Cow::Borrowed),
            ),
            _ => {
                let (kind, stage) = self.db_fields();
                (kind.map(Cow::Borrowed), stage.map(Cow::Borrowed))
            }
        }
    }
}

/// Text-embedded recovery stage names.
pub const TEXT_RECOVERY_STAGES: &[&str] = &["openai", "agent_keyed"];

/// Name-repair stages.
pub const NAME_REPAIR_STAGES: &[&str] = &["rebind", "sanitize"];

/// Resume-heal kinds.
pub const RESUME_HEAL_KINDS: &[&str] = &[
    "stub_orphan_tool_call",
    "drop_orphan_tool_result",
    "stub_missing_subagent_report",
];

/// Known cascade stage names.
pub const EDIT_CASCADE_STAGES: &[&str] = &[
    "exact",
    "line_trim",
    "block_anchor",
    "whitespace_normalized",
    "indent_flexible",
    "escape_normalized",
    "trimmed_boundary",
    "context_aware",
];

/// Known shape-repair stage names, in catalog order.
pub const SHAPE_REPAIR_STAGES: &[&str] = &[
    "wrap_root_string_as_object",
    "parse_root_string_as_object",
    "rename_aliased_field",
    "null_for_optional",
    "parse_stringified_number",
    "parse_stringified_array",
    "wrap_bare_string",
    "markdown_autolink_unwrap",
    "absolute_prefix_rewrite",
];

#[derive(Debug, Clone)]
pub struct ToolCallEvent {
    pub event_id: Uuid,
    pub session_id: Uuid,
    pub call_id: String,
    pub parent_call_id: Option<String>,
    pub parent_child_index: Option<i64>,
    pub provider_item_id: Option<String>,
    pub provider_call_id: Option<String>,
    pub provider_call_id_source: Option<String>,
    pub wire_api: Option<String>,
    pub provider_family: Option<String>,
    pub timestamp: i64,
    pub model: String,
    pub provider: String,
    pub project_id: String,
    pub project_root: String,
    pub agent: String,
    pub tool: String,
    pub mcp_server: Option<String>,
    pub path: Option<String>,
    pub recovery: Recovery,
    pub hard_fail: bool,
    pub exit_code: Option<i32>,
    pub sandbox_enabled: bool,
    pub sandboxed: bool,
    pub sandbox_unavailable_reason: Option<String>,
    pub original_input_json: Value,
    pub wire_input_json: Value,
    pub output: String,
    pub truncated: bool,
    pub duration_ms: u64,
    /// Cockpit version at call time (`env!("CARGO_PKG_VERSION")`).
    /// `None` for historical rows (pre-0032).
    pub cockpit_version: Option<String>,
    /// LLM steering mode at call time (`"defensive"`, `"normal"`).
    /// `None` for historical rows (pre-0032).
    pub llm_mode: Option<String>,
    /// §12 repair shape-fingerprint
    /// (implementation note) — a short stable hash of
    /// the malformed input shape, shared by structurally-identical bad calls.
    /// `Some` on a recovered/unrepairable call, `None` on a clean call and for
    /// historical rows (pre-0035). Lets `cockpit debug failed-calls` group and
    /// count failures by model + fingerprint.
    pub shape_fingerprint: Option<String>,
    /// Post-result hint (`engine::bash_hints`) recorded on a `bash` call when a
    /// rule matched: a JSON `{ kind, text, severity }`. `None` on clean calls,
    /// every non-`bash` tool, and historical rows (pre-0039). Mirrors the
    /// session-export `data.hint` field — same wire-vs-user split as `recovery`.
    pub hint: Option<Value>,
}

impl Db {
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn insert_tool_call(&self, ev: &ToolCallEvent) -> Result<()> {
        let language = ev.path.as_deref().and_then(language_for_path);
        let (recovery_kind, recovery_stage) = ev.recovery.db_fields();

        let original_json =
            serde_json::to_string(&ev.original_input_json).context("serializing original_input")?;
        let wire_json =
            serde_json::to_string(&ev.wire_input_json).context("serializing wire_input")?;
        let hint_json = ev
            .hint
            .as_ref()
            .map(|h| serde_json::to_string(h).context("serializing hint"))
            .transpose()?;

        let ev = ev.clone();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO tool_call_events (
                    event_id, session_id, call_id, parent_call_id, parent_child_index, timestamp,
                    provider_item_id, provider_call_id, provider_call_id_source,
                    wire_api, provider_family,
                    model, provider, project_id, project_root,
                    agent, tool, mcp_server, path, language,
                    recovery_kind, recovery_stage, hard_fail,
                    exit_code, sandbox_enabled, sandboxed, sandbox_unavailable_reason,
                    original_input_json, wire_input_json,
                    output, truncated, duration_ms,
                    cockpit_version, llm_mode, shape_fingerprint, hint
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6,
                    ?7, ?8, ?9,
                    ?10, ?11,
                    ?12, ?13, ?14, ?15,
                    ?16, ?17, ?18, ?19,
                    ?20, ?21, ?22,
                    ?23, ?24, ?25, ?26,
                    ?27, ?28,
                    ?29, ?30, ?31,
                    ?32, ?33, ?34, ?35, ?36
                 )",
                params![
                    ev.event_id.to_string(),
                    ev.session_id.to_string(),
                    ev.call_id,
                    ev.parent_call_id,
                    ev.parent_child_index,
                    ev.timestamp,
                    ev.provider_item_id,
                    ev.provider_call_id,
                    ev.provider_call_id_source,
                    ev.wire_api,
                    ev.provider_family,
                    ev.model,
                    ev.provider,
                    ev.project_id,
                    ev.project_root,
                    ev.agent,
                    ev.tool,
                    ev.mcp_server,
                    ev.path,
                    language,
                    recovery_kind,
                    recovery_stage,
                    ev.hard_fail as i64,
                    ev.exit_code.map(i64::from),
                    ev.sandbox_enabled as i64,
                    ev.sandboxed as i64,
                    ev.sandbox_unavailable_reason,
                    original_json,
                    wire_json,
                    ev.output,
                    ev.truncated as i64,
                    ev.duration_ms as i64,
                    ev.cockpit_version,
                    ev.llm_mode,
                    ev.shape_fingerprint,
                    hint_json,
                ],
            )
            .context("inserting tool_call_event")?;
            Ok(())
        })
    }

    /// Recent rows where the call either hard-failed or fired any
    /// recovery. Newest-first. Used by `cockpit debug failed-calls` to
    /// surface candidates for new repair-catalog entries.
    ///
    /// Filtering:
    /// - `since_epoch`: only include rows with `timestamp >= since_epoch`.
    /// - `tool`, `model`, `project_id`: exact-match filters (NULL =
    ///   "any").
    /// - `include_recovered`: when `false`, only `hard_fail = 1` rows
    ///   are returned. When `true`, rows with any non-NULL
    ///   `recovery_kind` are included too — useful for spotting
    ///   patterns the catalog is already catching.
    /// - `limit`: max rows returned.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn list_failed_tool_calls(&self, filter: FailedCallsFilter) -> Result<Vec<ToolCallEvent>> {
        self.read_blocking(|conn| {
            let mut where_sql = PredicateBuilder::new();
            where_sql.push_value("timestamp >=", filter.since_epoch);
            if filter.include_recovered {
                where_sql.push_static("(hard_fail = 1 OR recovery_kind IS NOT NULL)");
            } else {
                where_sql.push_static("hard_fail = 1");
            }
            if let Some(t) = filter.tool {
                where_sql.push_eq(SqlColumn::Tool, t);
            }
            if let Some(m) = filter.model {
                where_sql.push_eq(SqlColumn::Model, m);
            }
            if let Some(p) = filter.project_id {
                where_sql.push_eq(SqlColumn::ProjectId, p);
            }
            let limit_placeholder = where_sql.push_param(filter.limit as i64);
            let (pred, params_vec) = where_sql.finish();

            let sql = format!(
                "SELECT event_id, session_id, call_id,
                        parent_call_id, parent_child_index, timestamp,
                        provider_item_id, provider_call_id, provider_call_id_source,
                        wire_api, provider_family,
                        model, provider, project_id, project_root,
                        agent, tool, mcp_server, path,
                        recovery_kind, recovery_stage, hard_fail,
                        exit_code, sandbox_enabled, sandboxed, sandbox_unavailable_reason,
                        original_input_json, wire_input_json,
                        output, truncated, duration_ms,
                        cockpit_version, llm_mode, shape_fingerprint, hint
                   FROM tool_call_events
                  WHERE {pred}
                  ORDER BY timestamp DESC, rowid DESC
                  LIMIT {limit_placeholder}",
            );

            let mut stmt = conn
                .prepare(&sql)
                .context("preparing list_failed_tool_calls")?;
            let param_refs: Vec<&dyn rusqlite::ToSql> =
                params_vec.iter().map(|b| b.as_ref()).collect();
            let rows = stmt
                .query_map(param_refs.as_slice(), decode_row)
                .context("querying tool_call_events")?;
            let mut out = Vec::new();
            for r in rows {
                let raw = r.context("decoding tool_call row")?;
                out.push(raw.try_into()?);
            }
            Ok(out)
        })
    }

    /// Lookup one tool call by model call id within a session. Used by `escalate`:
    /// sandbox refusals and confined non-zero exits are ordinary tool results,
    /// not hard failures, so this intentionally does not apply the failed-call
    /// filter.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn get_tool_call_by_call_id(
        &self,
        session_id: Uuid,
        call_id: &str,
    ) -> Result<Option<ToolCallEvent>> {
        let call_id = call_id.to_string();
        self.read_blocking(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT event_id, session_id, call_id,
                            parent_call_id, parent_child_index, timestamp,
                            provider_item_id, provider_call_id, provider_call_id_source,
                            wire_api, provider_family,
                            model, provider, project_id, project_root,
                            agent, tool, mcp_server, path,
                            recovery_kind, recovery_stage, hard_fail,
                            exit_code, sandbox_enabled, sandboxed, sandbox_unavailable_reason,
                            original_input_json, wire_input_json,
                            output, truncated, duration_ms,
                            cockpit_version, llm_mode, shape_fingerprint, hint
                       FROM tool_call_events
                      WHERE session_id = ?1 AND call_id = ?2
                      ORDER BY timestamp DESC, rowid DESC
                      LIMIT 1",
                )
                .context("preparing get_tool_call_by_call_id")?;
            let mut rows = stmt
                .query(params![session_id.to_string(), call_id])
                .context("querying tool_call_event by call_id")?;
            let Some(row) = rows.next().context("reading tool_call_event by call_id")? else {
                return Ok(None);
            };
            let raw = decode_row(row).context("decoding tool_call row")?;
            Ok(Some(raw.try_into()?))
        })
    }

    /// All tool-call rows for one session, oldest-first. Used by
    /// `Attach` to rebuild the user transcript on the client.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn list_tool_calls_for_session(&self, session_id: Uuid) -> Result<Vec<ToolCallEvent>> {
        self.read_blocking(|conn| Self::list_tool_calls_for_session_conn(conn, session_id))
    }

    pub fn list_tool_calls_for_session_conn(
        conn: &Connection,
        session_id: Uuid,
    ) -> Result<Vec<ToolCallEvent>> {
        let mut stmt = conn
            .prepare(
                "SELECT event_id, session_id, call_id,
                        parent_call_id, parent_child_index, timestamp,
                        provider_item_id, provider_call_id, provider_call_id_source,
                        wire_api, provider_family,
                        model, provider, project_id, project_root,
                        agent, tool, mcp_server, path,
                        recovery_kind, recovery_stage, hard_fail,
                        exit_code, sandbox_enabled, sandboxed, sandbox_unavailable_reason,
                        original_input_json, wire_input_json,
                        output, truncated, duration_ms,
                        cockpit_version, llm_mode, shape_fingerprint, hint
                   FROM tool_call_events
                  WHERE session_id = ?1
                  ORDER BY timestamp ASC, rowid ASC",
            )
            .context("preparing list_tool_calls")?;

        let rows = stmt
            .query_map([session_id.to_string()], decode_row)
            .context("querying tool_call_events")?;

        let mut out = Vec::new();
        for r in rows {
            let raw = r.context("decoding tool_call row")?;
            out.push(raw.try_into()?);
        }
        Ok(out)
    }
}

/// Filter for [`Db::list_failed_tool_calls`].
#[derive(Debug, Clone)]
pub struct FailedCallsFilter {
    pub since_epoch: i64,
    pub tool: Option<String>,
    pub model: Option<String>,
    pub project_id: Option<String>,
    pub include_recovered: bool,
    pub limit: usize,
}

fn decode_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ToolCallEventRaw> {
    let event_id: String = row.get("event_id")?;
    let sid: String = row.get("session_id")?;
    let original_json: String = row.get("original_input_json")?;
    let wire_json: String = row.get("wire_input_json")?;
    let recovery_kind: Option<String> = row.get("recovery_kind")?;
    let recovery_stage: Option<String> = row.get("recovery_stage")?;
    let hard_fail: i64 = row.get("hard_fail")?;
    let exit_code: Option<i64> = row.get("exit_code")?;
    let sandbox_enabled: i64 = row.get("sandbox_enabled")?;
    let sandboxed: i64 = row.get("sandboxed")?;
    let sandbox_unavailable_reason: Option<String> = row.get("sandbox_unavailable_reason")?;
    let truncated: i64 = row.get("truncated")?;
    let duration_ms: Option<i64> = row.get("duration_ms")?;
    let cockpit_version: Option<String> = row.get("cockpit_version")?;
    let llm_mode: Option<String> = row.get("llm_mode")?;
    let shape_fingerprint: Option<String> = row.get("shape_fingerprint")?;
    let hint: Option<String> = row.get("hint")?;

    Ok(ToolCallEventRaw {
        event_id,
        session_id: sid,
        call_id: row.get("call_id")?,
        parent_call_id: row.get("parent_call_id")?,
        parent_child_index: row.get("parent_child_index")?,
        provider_item_id: row.get("provider_item_id")?,
        provider_call_id: row.get("provider_call_id")?,
        provider_call_id_source: row.get("provider_call_id_source")?,
        wire_api: row.get("wire_api")?,
        provider_family: row.get("provider_family")?,
        timestamp: row.get("timestamp")?,
        model: row.get("model")?,
        provider: row.get("provider")?,
        project_id: row.get("project_id")?,
        project_root: row.get("project_root")?,
        agent: row.get("agent")?,
        tool: row.get("tool")?,
        mcp_server: row.get("mcp_server")?,
        path: row.get("path")?,
        recovery_kind,
        recovery_stage,
        hard_fail: hard_fail != 0,
        exit_code: exit_code.map(|code| code as i32),
        sandbox_enabled: sandbox_enabled != 0,
        sandboxed: sandboxed != 0,
        sandbox_unavailable_reason,
        original_input_json: original_json,
        wire_input_json: wire_json,
        output: row.get("output")?,
        truncated: truncated != 0,
        duration_ms: duration_ms.unwrap_or(0) as u64,
        cockpit_version,
        llm_mode,
        shape_fingerprint,
        hint,
    })
}

struct ToolCallEventRaw {
    event_id: String,
    session_id: String,
    call_id: String,
    parent_call_id: Option<String>,
    parent_child_index: Option<i64>,
    provider_item_id: Option<String>,
    provider_call_id: Option<String>,
    provider_call_id_source: Option<String>,
    wire_api: Option<String>,
    provider_family: Option<String>,
    timestamp: i64,
    model: String,
    provider: String,
    project_id: String,
    project_root: String,
    agent: String,
    tool: String,
    mcp_server: Option<String>,
    path: Option<String>,
    recovery_kind: Option<String>,
    recovery_stage: Option<String>,
    hard_fail: bool,
    exit_code: Option<i32>,
    sandbox_enabled: bool,
    sandboxed: bool,
    sandbox_unavailable_reason: Option<String>,
    original_input_json: String,
    wire_input_json: String,
    output: String,
    truncated: bool,
    duration_ms: u64,
    cockpit_version: Option<String>,
    llm_mode: Option<String>,
    shape_fingerprint: Option<String>,
    hint: Option<String>,
}

impl TryFrom<ToolCallEventRaw> for ToolCallEvent {
    type Error = anyhow::Error;

    fn try_from(r: ToolCallEventRaw) -> Result<Self> {
        let event_id =
            Uuid::parse_str(&r.event_id).with_context(|| format!("event_id `{}`", r.event_id))?;
        let session_id = Uuid::parse_str(&r.session_id)
            .with_context(|| format!("session_id `{}`", r.session_id))?;
        let original_input_json: Value = serde_json::from_str(&r.original_input_json)
            .context("deserializing original_input_json")?;
        let wire_input_json: Value =
            serde_json::from_str(&r.wire_input_json).context("deserializing wire_input_json")?;
        let recovery = decode_recovery(&r.recovery_kind, &r.recovery_stage);
        // A malformed stored hint must never crash a history read — decode to
        // `None` (forward-compat, matching the recovery round-trip's fallback).
        let hint = r
            .hint
            .as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok());

        Ok(Self {
            event_id,
            session_id,
            call_id: r.call_id,
            parent_call_id: r.parent_call_id,
            parent_child_index: r.parent_child_index,
            provider_item_id: r.provider_item_id,
            provider_call_id: r.provider_call_id,
            provider_call_id_source: r.provider_call_id_source,
            wire_api: r.wire_api,
            provider_family: r.provider_family,
            timestamp: r.timestamp,
            model: r.model,
            provider: r.provider,
            project_id: r.project_id,
            project_root: r.project_root,
            agent: r.agent,
            tool: r.tool,
            mcp_server: r.mcp_server,
            path: r.path,
            recovery,
            hard_fail: r.hard_fail,
            exit_code: r.exit_code,
            sandbox_enabled: r.sandbox_enabled,
            sandboxed: r.sandboxed,
            sandbox_unavailable_reason: r.sandbox_unavailable_reason,
            original_input_json,
            wire_input_json,
            output: r.output,
            truncated: r.truncated,
            duration_ms: r.duration_ms,
            cockpit_version: r.cockpit_version,
            llm_mode: r.llm_mode,
            shape_fingerprint: r.shape_fingerprint,
            hint,
        })
    }
}

/// Inverse of [`Recovery::db_fields`]. Stages live in fixed catalogs; we
/// round-trip by matching the stored stage name against the catalog so we can
/// hand the `&'static str` back without leaking. Unknown persisted values stay
/// visible as [`Recovery::Unknown`] instead of being misclassified as clean.
fn decode_recovery(kind: &Option<String>, stage: &Option<String>) -> Recovery {
    let stage_str = stage.as_deref().unwrap_or("");
    match kind.as_deref() {
        None => Recovery::Clean,
        Some("shape_repair") => SHAPE_REPAIR_STAGES
            .iter()
            .find(|s| **s == stage_str)
            .map(|s| Recovery::ShapeRepair {
                stage: s,
                // `path` and `hint` are in-memory-only (not persisted DB
                // columns); on read-back they reconstruct as empty/None.
                path: String::new(),
                hint: None,
            })
            .unwrap_or_else(|| Recovery::Unknown {
                kind: "shape_repair".to_string(),
                stage: stage.clone(),
            }),
        Some("edit_cascade") => EDIT_CASCADE_STAGES
            .iter()
            .find(|s| **s == stage_str)
            .map(|s| Recovery::EditCascade {
                stage: s,
                path: "old_string".to_string(),
            })
            .unwrap_or_else(|| Recovery::Unknown {
                kind: "edit_cascade".to_string(),
                stage: stage.clone(),
            }),
        Some("resume_heal") => RESUME_HEAL_KINDS
            .iter()
            .find(|k| **k == stage_str)
            .map(|k| Recovery::ResumeHeal {
                kind: k,
                id: String::new(),
            })
            .unwrap_or_else(|| Recovery::Unknown {
                kind: "resume_heal".to_string(),
                stage: stage.clone(),
            }),
        Some("name_repair") => NAME_REPAIR_STAGES
            .iter()
            .find(|s| **s == stage_str)
            .map(|s| Recovery::NameRepair {
                stage: s,
                // The original (malformed) name isn't a persisted column; it
                // lives only in the live in-memory recovery + event. Decode to
                // an empty original, matching how `ShapeRepair.path` /
                // `ResumeHeal.id` round-trip.
                original: String::new(),
            })
            .unwrap_or_else(|| Recovery::Unknown {
                kind: "name_repair".to_string(),
                stage: stage.clone(),
            }),
        Some("text_embedded") => TEXT_RECOVERY_STAGES
            .iter()
            .find(|s| **s == stage_str)
            .map(|s| Recovery::TextEmbedded {
                stage: s,
                // The original text block + drop flag aren't persisted columns;
                // they live only in the live in-memory recovery + event. Decode
                // to empty/false, matching how the other in-memory fields
                // round-trip.
                original: String::new(),
                dropped_trailing: false,
            })
            .unwrap_or_else(|| Recovery::Unknown {
                kind: "text_embedded".to_string(),
                stage: stage.clone(),
            }),
        Some(kind) => Recovery::Unknown {
            kind: kind.to_string(),
            stage: stage.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn fixture(db: &Db) -> Uuid {
        let s = db.create_session("p", "/x", "a").await.unwrap();
        s.session_id
    }

    fn tool_call_fixture(sid: Uuid, call_id: &str, tool: &str, timestamp: i64) -> ToolCallEvent {
        ToolCallEvent {
            event_id: Uuid::new_v4(),
            session_id: sid,
            call_id: call_id.into(),
            parent_call_id: None,
            parent_child_index: None,
            provider_item_id: None,
            provider_call_id: None,
            provider_call_id_source: None,
            wire_api: None,
            provider_family: None,
            timestamp,
            model: "claude-opus-4-7".into(),
            provider: "anthropic".into(),
            project_id: "p".into(),
            project_root: "/x".into(),
            agent: "builder".into(),
            tool: tool.into(),
            mcp_server: None,
            path: None,
            recovery: Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            original_input_json: json!({}),
            wire_input_json: json!({}),
            output: String::new(),
            truncated: false,
            duration_ms: 0,
            cockpit_version: None,
            llm_mode: None,
            shape_fingerprint: None,
            hint: None,
        }
    }

    #[tokio::test]
    async fn insert_and_list_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let sid = fixture(&db).await;
        let ev = ToolCallEvent {
            event_id: Uuid::new_v4(),
            session_id: sid,
            call_id: "call-1".into(),
            parent_call_id: None,
            parent_child_index: None,
            provider_item_id: None,
            provider_call_id: None,
            provider_call_id_source: None,
            wire_api: None,
            provider_family: None,
            timestamp: 1700000000,
            model: "claude-opus-4-7".into(),
            provider: "anthropic".into(),
            project_id: "p".into(),
            project_root: "/x".into(),
            agent: "builder".into(),
            tool: "read".into(),
            path: Some("src/main.rs".into()),
            mcp_server: None,
            recovery: Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            original_input_json: json!({"path": "src/main.rs"}),
            wire_input_json: json!({"path": "src/main.rs"}),
            output: "1: fn main()".into(),
            truncated: false,
            duration_ms: 3,
            cockpit_version: Some("0.1.130".into()),
            llm_mode: Some("defensive".into()),
            shape_fingerprint: None,
            hint: None,
        };
        db.insert_tool_call(&ev).unwrap();
        let rows = db.list_tool_calls_for_session(sid).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tool, "read");
        assert_eq!(rows[0].path.as_deref(), Some("src/main.rs"));
        assert_eq!(rows[0].original_input_json, json!({"path": "src/main.rs"}));
        assert_eq!(rows[0].cockpit_version, Some("0.1.130".to_string()));
        assert_eq!(rows[0].llm_mode, Some("defensive".to_string()));
    }

    #[tokio::test]
    async fn child_rows_round_trip_with_parent_linkage() {
        let db = Db::open_in_memory().unwrap();
        let sid = fixture(&db).await;
        let parent = tool_call_fixture(sid, "outer", "mcp", 100);
        let mut child_a = tool_call_fixture(sid, "outer:mcp:0", "test_count", 101);
        child_a.parent_call_id = Some("outer".into());
        child_a.parent_child_index = Some(0);
        child_a.mcp_server = Some("cockpit".into());
        child_a.wire_input_json = json!({
            "server": "cockpit",
            "tool": "test_count",
            "args": { "count": 1 }
        });
        let mut child_b = tool_call_fixture(sid, "outer:mcp:1", "echo", 102);
        child_b.parent_call_id = Some("outer".into());
        child_b.parent_child_index = Some(1);
        child_b.mcp_server = Some("external".into());

        db.insert_tool_call(&parent).unwrap();
        db.insert_tool_call(&child_a).unwrap();
        db.insert_tool_call(&child_b).unwrap();

        let rows = db.list_tool_calls_for_session(sid).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].parent_call_id, None);
        assert_eq!(rows[0].parent_child_index, None);
        assert_eq!(rows[0].mcp_server, None);
        assert_eq!(rows[1].parent_call_id.as_deref(), Some("outer"));
        assert_eq!(rows[1].parent_child_index, Some(0));
        assert_eq!(rows[1].mcp_server.as_deref(), Some("cockpit"));
        assert_eq!(rows[1].wire_input_json["args"]["count"], 1);
        assert_eq!(rows[2].parent_call_id.as_deref(), Some("outer"));
        assert_eq!(rows[2].parent_child_index, Some(1));
        assert_eq!(rows[2].mcp_server.as_deref(), Some("external"));
    }

    #[tokio::test]
    async fn existing_call_sites_unchanged() {
        let db = Db::open_in_memory().unwrap();
        let sid = fixture(&db).await;
        let ev = tool_call_fixture(sid, "top-level", "read", 100);

        db.insert_tool_call(&ev).unwrap();

        let rows = db.list_tool_calls_for_session(sid).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].parent_call_id, None);
        assert_eq!(rows[0].parent_child_index, None);
        assert_eq!(rows[0].mcp_server, None);
        assert_eq!(rows[0].tool, ev.tool);
        assert_eq!(rows[0].wire_input_json, ev.wire_input_json);
        assert_eq!(rows[0].output, ev.output);
    }

    #[tokio::test]
    async fn list_failed_tool_calls_filters_correctly() {
        let db = Db::open_in_memory().unwrap();
        let sid = fixture(&db).await;
        let mk = |tool: &str, ts: i64, hard_fail: bool, recovery: Recovery| ToolCallEvent {
            event_id: Uuid::new_v4(),
            session_id: sid,
            call_id: "c".into(),
            parent_call_id: None,
            parent_child_index: None,
            provider_item_id: None,
            provider_call_id: None,
            provider_call_id_source: None,
            wire_api: None,
            provider_family: None,
            timestamp: ts,
            model: "claude-opus-4-7".into(),
            provider: "anthropic".into(),
            project_id: "p".into(),
            project_root: "/x".into(),
            agent: "builder".into(),
            tool: tool.into(),
            path: None,
            mcp_server: None,
            recovery,
            hard_fail,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            original_input_json: json!({}),
            wire_input_json: json!({}),
            output: "".into(),
            truncated: false,
            duration_ms: 0,
            cockpit_version: None,
            llm_mode: None,
            shape_fingerprint: None,
            hint: None,
        };

        db.insert_tool_call(&mk("read", 100, false, Recovery::Clean))
            .unwrap();
        db.insert_tool_call(&mk("read", 200, true, Recovery::Clean))
            .unwrap();
        db.insert_tool_call(&mk(
            "editunlock",
            300,
            false,
            Recovery::EditCascade {
                stage: "line_trim",
                path: "old_string".into(),
            },
        ))
        .unwrap();
        db.insert_tool_call(&mk("bash", 400, true, Recovery::Clean))
            .unwrap();

        // hard-fail only, newest-first.
        let rows = db
            .list_failed_tool_calls(FailedCallsFilter {
                since_epoch: 0,
                tool: None,
                model: None,
                project_id: None,
                include_recovered: false,
                limit: 10,
            })
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].tool, "bash");
        assert_eq!(rows[1].tool, "read");

        // include recoveries.
        let rows = db
            .list_failed_tool_calls(FailedCallsFilter {
                since_epoch: 0,
                tool: None,
                model: None,
                project_id: None,
                include_recovered: true,
                limit: 10,
            })
            .unwrap();
        assert_eq!(rows.len(), 3);

        // tool filter.
        let rows = db
            .list_failed_tool_calls(FailedCallsFilter {
                since_epoch: 0,
                tool: Some("bash".into()),
                model: None,
                project_id: None,
                include_recovered: true,
                limit: 10,
            })
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tool, "bash");

        // since filter.
        let rows = db
            .list_failed_tool_calls(FailedCallsFilter {
                since_epoch: 250,
                tool: None,
                model: None,
                project_id: None,
                include_recovered: true,
                limit: 10,
            })
            .unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    async fn language_populated_from_extension() {
        let db = Db::open_in_memory().unwrap();
        let sid = fixture(&db).await;
        let ev = ToolCallEvent {
            event_id: Uuid::new_v4(),
            session_id: sid,
            call_id: "c".into(),
            parent_call_id: None,
            parent_child_index: None,
            provider_item_id: None,
            provider_call_id: None,
            provider_call_id_source: None,
            wire_api: None,
            provider_family: None,
            timestamp: 1,
            model: "m".into(),
            provider: "p".into(),
            project_id: "p".into(),
            project_root: "/x".into(),
            agent: "builder".into(),
            tool: "read".into(),
            path: Some("a.py".into()),
            mcp_server: None,
            recovery: Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            original_input_json: json!({}),
            wire_input_json: json!({}),
            output: "".into(),
            truncated: false,
            duration_ms: 0,
            cockpit_version: None,
            llm_mode: None,
            shape_fingerprint: None,
            hint: None,
        };
        db.insert_tool_call(&ev).unwrap();
        let language: Option<String> = db
            .read_blocking(|c| {
                Ok(
                    c.query_row("SELECT language FROM tool_call_events LIMIT 1", [], |r| {
                        r.get(0)
                    })?,
                )
            })
            .unwrap();
        assert_eq!(language.as_deref(), Some("Python"));
    }

    #[tokio::test]
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    async fn shape_fingerprint_persists_and_groups_by_model_and_fingerprint() {
        let db = Db::open_in_memory().unwrap();
        let sid = fixture(&db).await;
        let mk = |model: &str, fp: Option<&str>, ts: i64| ToolCallEvent {
            event_id: Uuid::new_v4(),
            session_id: sid,
            call_id: "c".into(),
            parent_call_id: None,
            parent_child_index: None,
            provider_item_id: None,
            provider_call_id: None,
            provider_call_id_source: None,
            wire_api: None,
            provider_family: None,
            timestamp: ts,
            model: model.into(),
            provider: "p".into(),
            project_id: "p".into(),
            project_root: "/x".into(),
            agent: "builder".into(),
            tool: "read".into(),
            path: None,
            mcp_server: None,
            recovery: Recovery::Clean,
            hard_fail: true,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            original_input_json: json!({}),
            wire_input_json: json!({}),
            output: "".into(),
            truncated: false,
            duration_ms: 0,
            cockpit_version: None,
            llm_mode: None,
            shape_fingerprint: fp.map(str::to_string),
            hint: None,
        };
        // Two calls of the same shape on model-a, one on model-b, one with a
        // different shape on model-a.
        db.insert_tool_call(&mk("model-a", Some("abc123abc123"), 100))
            .unwrap();
        db.insert_tool_call(&mk("model-a", Some("abc123abc123"), 200))
            .unwrap();
        db.insert_tool_call(&mk("model-b", Some("abc123abc123"), 300))
            .unwrap();
        db.insert_tool_call(&mk("model-a", Some("deadbeefdead"), 400))
            .unwrap();

        // The column round-trips on read.
        let rows = db.list_tool_calls_for_session(sid).unwrap();
        assert_eq!(rows.len(), 4);
        assert!(rows.iter().all(|r| r.shape_fingerprint.is_some()));

        // Grouping by (model, fingerprint) — the failed-calls audit query.
        let counts: Vec<(String, String, i64)> = db
            .read_blocking(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT model, shape_fingerprint, COUNT(*)
                       FROM tool_call_events
                      WHERE shape_fingerprint IS NOT NULL
                   GROUP BY model, shape_fingerprint
                   ORDER BY model, shape_fingerprint",
                )?;
                let rows = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })?;
                Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
            })
            .unwrap();
        assert_eq!(
            counts,
            vec![
                ("model-a".to_string(), "abc123abc123".to_string(), 2),
                ("model-a".to_string(), "deadbeefdead".to_string(), 1),
                ("model-b".to_string(), "abc123abc123".to_string(), 1),
            ]
        );
    }

    #[tokio::test]
    async fn decode_recovery_unknown_kind_preserves_raw_fields() {
        let raw = ToolCallEventRaw {
            event_id: Uuid::new_v4().to_string(),
            session_id: Uuid::new_v4().to_string(),
            call_id: "c".into(),
            parent_call_id: None,
            parent_child_index: None,
            provider_item_id: None,
            provider_call_id: None,
            provider_call_id_source: None,
            wire_api: None,
            provider_family: None,
            timestamp: 0,
            model: "m".into(),
            provider: "p".into(),
            project_id: "p".into(),
            project_root: "/".into(),
            agent: "a".into(),
            tool: "t".into(),
            mcp_server: None,
            path: None,
            recovery_kind: Some("unknown_future_kind".into()),
            recovery_stage: Some("stage".into()),
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            original_input_json: "{}".into(),
            wire_input_json: "{}".into(),
            output: String::new(),
            truncated: false,
            duration_ms: 0,
            cockpit_version: None,
            llm_mode: None,
            shape_fingerprint: None,
            hint: None,
        };
        let ev: ToolCallEvent = raw.try_into().unwrap();
        assert_eq!(
            ev.recovery,
            Recovery::Unknown {
                kind: "unknown_future_kind".into(),
                stage: Some("stage".into())
            }
        );
    }

    #[tokio::test]
    async fn decode_recovery_known_kind_unknown_stage_preserves_raw_fields() {
        assert_eq!(
            decode_recovery(&Some("name_repair".into()), &Some("future".into())),
            Recovery::Unknown {
                kind: "name_repair".into(),
                stage: Some("future".into())
            }
        );
        assert_eq!(
            decode_recovery(&Some("shape_repair".into()), &None),
            Recovery::Unknown {
                kind: "shape_repair".into(),
                stage: None
            }
        );
    }

    #[tokio::test]
    async fn decode_recovery_name_repair_stages_round_trip() {
        for stage in ["rebind", "sanitize"] {
            let decoded =
                decode_recovery(&Some("name_repair".to_string()), &Some(stage.to_string()));
            match decoded {
                Recovery::NameRepair { stage: s, original } => {
                    assert_eq!(s, stage);
                    // The original (malformed) name is not a persisted column;
                    // it decodes to empty, like ShapeRepair.path / ResumeHeal.id.
                    assert_eq!(original, "");
                }
                other => panic!("expected NameRepair, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn decode_recovery_text_embedded_stages_round_trip() {
        for stage in ["openai", "agent_keyed"] {
            let decoded =
                decode_recovery(&Some("text_embedded".to_string()), &Some(stage.to_string()));
            match decoded {
                Recovery::TextEmbedded {
                    stage: s,
                    original,
                    dropped_trailing,
                } => {
                    assert_eq!(s, stage);
                    // The original text + drop flag aren't persisted columns;
                    // they decode to empty/false (like NameRepair.original).
                    assert_eq!(original, "");
                    assert!(!dropped_trailing);
                }
                other => panic!("expected TextEmbedded, got {other:?}"),
            }
        }
    }
}
