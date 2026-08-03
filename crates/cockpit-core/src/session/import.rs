use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::OptionalExtension;
use serde_json::{Value, json};
use uuid::Uuid;

use cockpit_db::db::Db;
use cockpit_db::db::compressed_results::CompressedToolResultEntry;
use cockpit_db::db::session_log::{SessionEventContext, SessionEventKind};

// Current exports may emit one sidecar per tool or inference event; 16,384 permits
// realistic long-lived session bundles while the independent 64MiB decompressed cap
// bounds archive resource use.
const MAX_IMPORT_ENTRIES: usize = 16_384;
const MAX_IMPORT_UNCOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
const EXPORT_SCHEMA: &str = "cockpit-session-export/1";

#[derive(Debug, Clone)]
struct ImportedSession {
    source_id: Uuid,
    parent_source_id: Option<Uuid>,
    short_id: Option<String>,
    fork_point_turn_id: Option<String>,
    provider: Option<String>,
    model: Option<String>,
    active_agent: String,
    started_at: i64,
    ended_at: Option<i64>,
    title: Option<String>,
}

#[derive(Debug, Clone)]
struct ImportedEvent {
    seq: i64,
    ts_ms: i64,
    kind: SessionEventKind,
    source_session_id: Uuid,
    agent: Option<String>,
    call_id: Option<String>,
    data_json: String,
}

#[derive(Debug, Clone)]
struct ImportedCompressedResult {
    source_session_id: Uuid,
    hash: String,
    agent_id: String,
    tool: String,
    call_id: String,
    original_byte_len: usize,
    compressed_byte_len: Option<usize>,
    created_at: i64,
    kind: String,
    content: String,
}

#[derive(Debug, Clone)]
struct ImportedDelegationChild {
    label: String,
    child_agent: String,
    model: Option<String>,
    status: String,
    report: Option<String>,
    output_dir: Option<String>,
    todo_ids_json: Option<String>,
    result_delivered: bool,
    started_at: Option<i64>,
    finished_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
    requested_cwd: Option<String>,
    resolved_cwd: Option<String>,
}
#[derive(Debug, Clone)]
struct ImportedDelegationJob {
    task_call_id: String,
    function_call_id: Option<String>,
    parent_source_id: Uuid,
    parent_agent: String,
    original_args_json: Option<String>,
    status: String,
    ack_delivered: bool,
    final_delivered: bool,
    created_at: i64,
    updated_at: i64,
    children: Vec<ImportedDelegationChild>,
}

#[derive(Debug, Clone)]
struct ImportedDelegationPayload {
    task_call_id: String,
    function_call_id: Option<String>,
    source_session_id: Uuid,
    parent_agent: String,
    label: String,
    payload_hash: String,
    child_agent: String,
    prompt_byte_len: usize,
    created_at: i64,
    delivered_at: Option<i64>,
    body: Option<String>,
}

#[derive(Debug, Clone)]
struct ImportedDelegationSteer {
    task_call_id: String,
    label: String,
    source_session_id: Uuid,
    origin_principal: String,
    body: String,
    delivered: bool,
    created_at: i64,
    delivered_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ImportArchive {
    project_id: String,
    project_root: String,
    pub redacted: bool,
    sessions: Vec<ImportedSession>,
    events: Vec<ImportedEvent>,
    compressed_results: Vec<ImportedCompressedResult>,
    delegation_jobs: Vec<ImportedDelegationJob>,
    delegation_payloads: Vec<ImportedDelegationPayload>,
    delegation_steers: Vec<ImportedDelegationSteer>,
    inference_calls: Vec<Value>,
    tool_calls: Vec<Value>,
}

pub async fn import_archive(db: &Db, archive: ImportArchive, as_new: bool) -> Result<ImportResult> {
    db.transaction(move |conn| restore_archive_conn(conn, archive, as_new))
        .await
}

#[derive(Debug, Clone)]
pub struct ImportResult {
    pub imported: Vec<Uuid>,
    pub redacted: bool,
}

fn restore_archive_conn(
    conn: &rusqlite::Connection,
    archive: ImportArchive,
    as_new: bool,
) -> Result<ImportResult> {
    let source_ids: BTreeSet<Uuid> = archive
        .sessions
        .iter()
        .map(|session| session.source_id)
        .collect();
    if source_ids.len() != archive.sessions.len() {
        bail!("import archive lists a session more than once");
    }
    for session in &archive.sessions {
        if let Some(parent) = session.parent_source_id
            && !source_ids.contains(&parent)
        {
            bail!("import archive references a parent session that is not in the archive");
        }
    }
    for event in &archive.events {
        if !source_ids.contains(&event.source_session_id) {
            bail!("import archive contains an event for an unknown session");
        }
    }
    for result in &archive.compressed_results {
        if !source_ids.contains(&result.source_session_id) {
            bail!("import archive contains a compressed result for an unknown session");
        }
    }
    let delegation_jobs: BTreeMap<&str, &ImportedDelegationJob> = archive
        .delegation_jobs
        .iter()
        .map(|job| (job.task_call_id.as_str(), job))
        .collect();
    if delegation_jobs.len() != archive.delegation_jobs.len() {
        bail!("import archive lists a delegation job more than once");
    }
    for job in &archive.delegation_jobs {
        if !source_ids.contains(&job.parent_source_id) {
            bail!("import archive contains a delegation job for an unknown session");
        }
        validate_delegation_status(&job.status, "delegation job")?;
        let labels: BTreeSet<&str> = job
            .children
            .iter()
            .map(|child| child.label.as_str())
            .collect();
        if labels.len() != job.children.len() {
            bail!("import archive lists a delegation child more than once");
        }
        for child in &job.children {
            validate_delegation_status(&child.status, "delegation child")?;
        }
    }
    for payload in &archive.delegation_payloads {
        let job = delegation_jobs
            .get(payload.task_call_id.as_str())
            .ok_or_else(|| {
                anyhow!("import archive contains a payload for an unknown delegation job")
            })?;
        if job.parent_source_id != payload.source_session_id {
            bail!("import archive delegation payload session does not match its job");
        }
        if !job
            .children
            .iter()
            .any(|child| child.label == payload.label)
        {
            bail!("import archive contains a payload for an unknown delegation child");
        }
    }
    for steer in &archive.delegation_steers {
        let job = delegation_jobs
            .get(steer.task_call_id.as_str())
            .ok_or_else(|| {
                anyhow!("import archive contains a steer for an unknown delegation job")
            })?;
        if job.parent_source_id != steer.source_session_id {
            bail!("import archive delegation steer session does not match its job");
        }
        if !job.children.iter().any(|child| child.label == steer.label) {
            bail!("import archive contains a steer for an unknown delegation child");
        }
    }

    preflight_global_call_id_collisions(conn, &archive, as_new)?;

    let mut id_map = BTreeMap::new();
    for source_id in &source_ids {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sessions WHERE session_id = ?1)",
            [source_id.to_string()],
            |row| row.get(0),
        )?;
        if exists && !as_new {
            bail!(
                "session `{source_id}` already exists; rerun with --as-new to import a separate copy"
            );
        }
        id_map.insert(*source_id, if as_new { Uuid::new_v4() } else { *source_id });
    }

    let task_call_id_map: BTreeMap<String, String> = if as_new {
        archive
            .delegation_jobs
            .iter()
            .map(|job| {
                (
                    job.task_call_id.clone(),
                    format!(
                        "import:{}:{}",
                        id_map[&job.parent_source_id], job.task_call_id
                    ),
                )
            })
            .collect()
    } else {
        BTreeMap::new()
    };

    let mut remaining: BTreeMap<Uuid, ImportedSession> = archive
        .sessions
        .into_iter()
        .map(|session| (session.source_id, session))
        .collect();
    let mut inserted = BTreeSet::new();
    let mut imported = Vec::new();
    while !remaining.is_empty() {
        let ready: Vec<Uuid> = remaining
            .iter()
            .filter_map(|(source_id, session)| {
                session
                    .parent_source_id
                    .is_none_or(|parent| inserted.contains(&parent))
                    .then_some(*source_id)
            })
            .collect();
        if ready.is_empty() {
            bail!("import archive contains a cyclic session parent relationship");
        }
        for source_id in ready {
            let session = remaining.remove(&source_id).expect("ready session exists");
            let mut row = Db::build_new_session_row_conn(
                conn,
                &archive.project_id,
                &archive.project_root,
                &session.active_agent,
            )?;
            row.session_id = id_map[&source_id];
            row.parent_session_id = session.parent_source_id.map(|parent| id_map[&parent]);
            row.short_id = session.short_id;
            row.fork_point_turn_id = session.fork_point_turn_id;
            row.provider = session.provider;
            row.model = session.model;
            row.started_at = session.started_at;
            row.last_active_at = session.started_at;
            row.ended_at = session.ended_at;
            row.title = session.title;
            Db::insert_session_row_conn(conn, &row)?;
            conn.execute(
                "UPDATE sessions\n                    SET parent_session_id = ?1, fork_point_turn_id = ?2, ended_at = ?3,\n                        title = ?4, last_active_at = ?5\n                  WHERE session_id = ?6",
                rusqlite::params![
                    row.parent_session_id.map(|id| id.to_string()),
                    row.fork_point_turn_id,
                    row.ended_at,
                    row.title,
                    row.last_active_at,
                    row.session_id.to_string(),
                ],
            )?;
            inserted.insert(source_id);
            imported.push(row.session_id);
        }
    }

    for job in &archive.delegation_jobs {
        conn.execute(
            "INSERT INTO task_delegation_jobs (
                task_call_id, function_call_id, parent_session_id, parent_agent,
                original_args_json, status, ack_delivered, final_delivered, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                task_call_id_map
                    .get(&job.task_call_id)
                    .unwrap_or(&job.task_call_id),
                job.function_call_id,
                id_map[&job.parent_source_id].to_string(),
                job.parent_agent,
                job.original_args_json,
                job.status,
                job.ack_delivered as i64,
                job.final_delivered as i64,
                job.created_at,
                job.updated_at,
            ],
        )?;
    }
    for job in &archive.delegation_jobs {
        for child in &job.children {
            conn.execute(
                "INSERT INTO task_delegation_children (
                    task_call_id, label, child_agent, model, status, report, output_dir,
                    todo_ids_json, result_delivered, started_at, finished_at, created_at,
                    updated_at, requested_cwd, resolved_cwd
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                rusqlite::params![
                    task_call_id_map
                        .get(&job.task_call_id)
                        .unwrap_or(&job.task_call_id),
                    child.label,
                    child.child_agent,
                    child.model,
                    child.status,
                    child.report,
                    child.output_dir,
                    child.todo_ids_json,
                    child.result_delivered as i64,
                    child.started_at,
                    child.finished_at,
                    child.created_at,
                    child.updated_at,
                    child.requested_cwd,
                    child.resolved_cwd,
                ],
            )?;
        }
    }
    for payload in &archive.delegation_payloads {
        // The schema requires an inline body or a sidecar path. Archives with
        // `load_error` intentionally have neither, so retain their index metadata
        // during parsing but do not manufacture an unreadable DB payload row.
        let Some(body) = payload.body.as_deref() else {
            continue;
        };
        conn.execute(
            "INSERT INTO task_delegation_payloads (
                task_call_id, label, payload_hash, parent_session_id, parent_agent,
                function_call_id, child_agent, prompt_byte_len, body_inline, created_at, delivered_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                task_call_id_map.get(&payload.task_call_id).unwrap_or(&payload.task_call_id), payload.label, payload.payload_hash,
                id_map[&payload.source_session_id].to_string(), payload.parent_agent,
                payload.function_call_id, payload.child_agent, payload.prompt_byte_len as i64,
                body, payload.created_at, payload.delivered_at,
            ],
        )?;
    }
    for steer in &archive.delegation_steers {
        conn.execute(
            "INSERT INTO task_delegation_steers (
                task_call_id, label, body, origin_principal, delivered, created_at, delivered_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                task_call_id_map
                    .get(&steer.task_call_id)
                    .unwrap_or(&steer.task_call_id),
                steer.label,
                steer.body,
                steer.origin_principal,
                steer.delivered as i64,
                steer.created_at,
                steer.delivered_at,
            ],
        )?;
    }

    let compressed_results = archive
        .compressed_results
        .iter()
        .map(|result| CompressedToolResultEntry {
            hash: result.hash.clone(),
            session_id: id_map[&result.source_session_id],
            agent_id: result.agent_id.clone(),
            tool: result.tool.clone(),
            call_id: result.call_id.clone(),
            original_byte_len: result.original_byte_len,
            compressed_byte_len: result.compressed_byte_len,
            created_at: result.created_at,
            kind: result.kind.clone(),
            content: result.content.clone(),
        })
        .collect::<Vec<_>>();
    Db::insert_compressed_tool_results_conn(conn, &compressed_results)?;

    restore_telemetry_rows(conn, &archive.inference_calls, &archive.tool_calls, &id_map)?;

    let provenance_ts = archive
        .events
        .iter()
        .map(|event| event.ts_ms)
        .max()
        .unwrap_or(0)
        + 1;
    let mut events = archive.events;
    events.sort_by_key(|event| event.seq);
    let mut event_seq_map = BTreeMap::new();
    let mut tandem_sidecars = Vec::new();
    for mut event in events {
        let mut event_data: Value =
            serde_json::from_str(&event.data_json).context("parsing hydrated import event data")?;
        if let Some(remapped) = event
            .call_id
            .as_ref()
            .and_then(|id| task_call_id_map.get(id))
        {
            event.call_id = Some(remapped.clone());
        }
        remap_task_call_id_references(&mut event_data, &task_call_id_map);
        event.data_json = serde_json::to_string(&event_data)?;
        if let Some(sidecar) = event_data.get("inference_request_sidecar")
            && let Some(request) = sidecar.get("request")
        {
            let call_id = event
                .call_id
                .as_deref()
                .ok_or_else(|| anyhow!("inference request sidecar event lacks call_id"))?;
            let status = sidecar
                .get("status")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("inference request sidecar lacks status"))?;
            Db::insert_inference_request_conn(
                conn,
                call_id,
                id_map[&event.source_session_id],
                event.ts_ms,
                request,
                status,
            )?;
        }
        let restored_seq = Db::insert_session_event_json_conn(
            conn,
            id_map[&event.source_session_id],
            event.kind,
            event.agent.as_deref(),
            event.call_id.as_deref(),
            SessionEventContext::default(),
            event.ts_ms,
            &event.data_json,
        )?;
        event_seq_map.insert((event.source_session_id, event.seq), restored_seq);
        if let Some(sidecar) = event_data.get("tandem_inference_sidecar") {
            tandem_sidecars.push((event, sidecar.clone()));
        }
    }
    for (event, sidecar) in tandem_sidecars {
        let call_id = event
            .call_id
            .as_deref()
            .ok_or_else(|| anyhow!("tandem inference sidecar event lacks call_id"))?;
        let provider = required_sidecar_string(&sidecar, "provider", "tandem inference sidecar")?;
        let model = required_sidecar_string(&sidecar, "model", "tandem inference sidecar")?;
        let status = required_sidecar_string(&sidecar, "status", "tandem inference sidecar")?;
        let request = sidecar
            .get("request")
            .ok_or_else(|| anyhow!("tandem inference sidecar lacks request"))?;
        let parent_seq = *event_seq_map
            .get(&(event.source_session_id, event.seq))
            .ok_or_else(|| anyhow!("tandem inference parent event was not restored"))?;
        let target_session_id = id_map[&event.source_session_id];
        let imported_id = format!("import:{target_session_id}:{call_id}:{provider}:{model}");
        Db::upsert_tandem_inference_conn(
            conn,
            &imported_id,
            target_session_id,
            call_id,
            Some(parent_seq),
            event.agent.as_deref(),
            provider,
            model,
            event.ts_ms,
            request,
            sidecar.get("response"),
            sidecar.get("usage"),
            status,
        )?;
    }

    // Provenance is a durable, user-visible notice rather than a hidden schema
    // mutation. It intentionally records redaction so a restored transcript is
    // never mistaken for the original unredacted conversation.
    for source_id in &source_ids {
        let data_json = serde_json::to_string(&json!({
            "source": "session_import",
            "original_session_id": source_id,
            "redacted": archive.redacted,
            "as_new": as_new,
        }))?;
        Db::insert_session_event_json_conn(
            conn,
            id_map[source_id],
            SessionEventKind::Notice,
            None,
            None,
            SessionEventContext::default(),
            provenance_ts,
            &data_json,
        )?;
    }
    let foreign_key_violation: Option<String> = conn
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()?;
    if let Some(violation) = foreign_key_violation {
        bail!("import produced a foreign-key violation: {violation}");
    }
    Ok(ImportResult {
        imported,
        redacted: archive.redacted,
    })
}

fn remap_task_call_id_references(value: &mut Value, task_call_id_map: &BTreeMap<String, String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object.iter_mut() {
                if key == "task_call_id" || key == "cockpit_call_id" {
                    if let Some(old) = value.as_str()
                        && let Some(new) = task_call_id_map.get(old)
                    {
                        *value = Value::String(new.clone());
                    }
                } else {
                    remap_task_call_id_references(value, task_call_id_map);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                remap_task_call_id_references(value, task_call_id_map);
            }
        }
        _ => {}
    }
}

fn restore_telemetry_rows(
    conn: &rusqlite::Connection,
    inference_calls: &[Value],
    tool_calls: &[Value],
    id_map: &BTreeMap<Uuid, Uuid>,
) -> Result<()> {
    for value in inference_calls {
        let o = value
            .as_object()
            .ok_or_else(|| anyhow!("inference call index entry must be an object"))?;
        let source_session = parse_uuid(
            required_string(o, "session_id", "inference call index")?,
            "session_id",
        )?;
        let session_id = *id_map
            .get(&source_session)
            .ok_or_else(|| anyhow!("inference call references unknown session"))?;
        let call_id = parse_uuid(
            required_string(o, "call_id", "inference call index")?,
            "call_id",
        )?;
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM inference_calls WHERE call_id = ?1)",
            [call_id.to_string()],
            |r| r.get(0),
        )?;
        if exists {
            bail!("inference call `{call_id}` already exists in the destination");
        }
        cockpit_db::db::Db::insert_inference_call_conn(
            conn,
            &cockpit_db::db::inference_calls::InferenceCallRow {
                call_id,
                session_id,
                project_id: required_string(o, "project_id", "inference call index")?,
                project_root: required_string(o, "project_root", "inference call index")?,
                model: required_string(o, "model", "inference call index")?,
                provider: required_string(o, "provider", "inference call index")?,
                timestamp: required_i64(o, "timestamp", "inference call index")?,
                input_tokens: required_i64(o, "input_tokens", "inference call index")?,
                output_tokens: required_i64(o, "output_tokens", "inference call index")?,
                cached_input_tokens: required_i64(
                    o,
                    "cached_input_tokens",
                    "inference call index",
                )?,
                cache_creation_input_tokens: required_i64(
                    o,
                    "cache_creation_input_tokens",
                    "inference call index",
                )?,
                cost_usd_micros: optional_i64(o.get("cost_usd_micros"), "cost_usd_micros")?,
                is_utility: required_bool(o, "is_utility", "inference call index")?,
            },
        )?;
    }
    for value in tool_calls {
        let o = value
            .as_object()
            .ok_or_else(|| anyhow!("tool call index entry must be an object"))?;
        let source_session = parse_uuid(
            required_string(o, "session_id", "tool call index")?,
            "session_id",
        )?;
        let session_id = *id_map
            .get(&source_session)
            .ok_or_else(|| anyhow!("tool call references unknown session"))?;
        let event_id = parse_uuid(
            required_string(o, "event_id", "tool call index")?,
            "event_id",
        )?;
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM tool_call_events WHERE event_id = ?1)",
            [event_id.to_string()],
            |r| r.get(0),
        )?;
        if exists {
            bail!("tool call event `{event_id}` already exists in the destination");
        }
        let recovery_kind = optional_string(o.get("recovery_kind"), "recovery_kind")?;
        let recovery_stage = optional_string(o.get("recovery_stage"), "recovery_stage")?;
        let recovery = match recovery_kind {
            Some(kind) => cockpit_db::db::tool_calls::Recovery::Unknown {
                kind,
                stage: recovery_stage,
            },
            None => cockpit_db::db::tool_calls::Recovery::Clean,
        };
        let original_input_json = o
            .get("original_input_json")
            .cloned()
            .ok_or_else(|| anyhow!("tool call index lacks original_input_json"))?;
        let wire_input_json = o
            .get("wire_input_json")
            .cloned()
            .ok_or_else(|| anyhow!("tool call index lacks wire_input_json"))?;
        cockpit_db::db::Db::insert_tool_call_conn(
            conn,
            &cockpit_db::db::tool_calls::ToolCallEvent {
                event_id,
                session_id,
                call_id: required_string(o, "call_id", "tool call index")?,
                parent_call_id: optional_string(o.get("parent_call_id"), "parent_call_id")?,
                parent_child_index: optional_i64(
                    o.get("parent_child_index"),
                    "parent_child_index",
                )?,
                provider_item_id: optional_string(o.get("provider_item_id"), "provider_item_id")?,
                provider_call_id: optional_string(o.get("provider_call_id"), "provider_call_id")?,
                provider_call_id_source: optional_string(
                    o.get("provider_call_id_source"),
                    "provider_call_id_source",
                )?,
                wire_api: optional_string(o.get("wire_api"), "wire_api")?,
                provider_family: optional_string(o.get("provider_family"), "provider_family")?,
                timestamp: required_i64(o, "timestamp", "tool call index")?,
                model: required_string(o, "model", "tool call index")?,
                provider: required_string(o, "provider", "tool call index")?,
                project_id: required_string(o, "project_id", "tool call index")?,
                project_root: required_string(o, "project_root", "tool call index")?,
                agent: required_string(o, "agent", "tool call index")?,
                tool: required_string(o, "tool", "tool call index")?,
                mcp_server: optional_string(o.get("mcp_server"), "mcp_server")?,
                path: optional_string(o.get("path"), "path")?,
                recovery,
                hard_fail: required_bool(o, "hard_fail", "tool call index")?,
                exit_code: optional_i64(o.get("exit_code"), "exit_code")?
                    .map(i32::try_from)
                    .transpose()
                    .context("tool call exit_code")?,
                sandbox_enabled: required_bool(o, "sandbox_enabled", "tool call index")?,
                sandboxed: required_bool(o, "sandboxed", "tool call index")?,
                sandbox_unavailable_reason: optional_string(
                    o.get("sandbox_unavailable_reason"),
                    "sandbox_unavailable_reason",
                )?,
                original_input_json,
                wire_input_json,
                output: required_string(o, "output", "tool call index")?,
                truncated: required_bool(o, "truncated", "tool call index")?,
                duration_ms: required_i64(o, "duration_ms", "tool call index")?
                    .try_into()
                    .context("tool call duration_ms")?,
                cockpit_version: optional_string(o.get("cockpit_version"), "cockpit_version")?,
                llm_mode: optional_string(o.get("llm_mode"), "llm_mode")?,
                shape_fingerprint: optional_string(
                    o.get("shape_fingerprint"),
                    "shape_fingerprint",
                )?,
                hint: o.get("hint").filter(|v| !v.is_null()).cloned(),
            },
        )?;
    }
    Ok(())
}

fn preflight_global_call_id_collisions(
    conn: &rusqlite::Connection,
    archive: &ImportArchive,
    as_new: bool,
) -> Result<()> {
    let mut inference_call_ids = BTreeSet::new();
    for event in &archive.events {
        let data: Value = serde_json::from_str(&event.data_json)
            .context("parsing imported event data for collision preflight")?;
        if data.get("inference_request_sidecar").is_some()
            && let Some(call_id) = event.call_id.as_deref()
            && !inference_call_ids.insert(call_id)
        {
            bail!("import archive repeats inference request call_id `{call_id}`");
        }
    }
    for call_id in inference_call_ids {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM inference_requests WHERE call_id = ?1)",
            [&call_id],
            |row| row.get(0),
        )?;
        if exists {
            bail!(
                "inference request `{call_id}` already exists in the destination; import refuses to overwrite an existing captured request"
            );
        }
    }
    if !as_new {
        for job in &archive.delegation_jobs {
            let exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM task_delegation_jobs WHERE task_call_id = ?1)",
                [&job.task_call_id],
                |row| row.get(0),
            )?;
            if exists {
                bail!(
                    "delegation `{}` already exists in the destination",
                    job.task_call_id
                );
            }
        }
    }
    Ok(())
}

pub fn read_archive(path: &Path) -> Result<ImportArchive> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading import archive {}", path.display()))?;
    read_archive_bytes(&bytes)
}

pub fn read_archive_bytes(bytes: &[u8]) -> Result<ImportArchive> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).context("opening import ZIP")?;
    if archive.len() > MAX_IMPORT_ENTRIES {
        bail!("import archive has too many entries");
    }
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let name = entry.name();
        if name.starts_with('/') || name.split('/').any(|part| part == "..") {
            bail!("import archive contains unsafe path `{name}`");
        }
        total = total.saturating_add(entry.size());
        if total > MAX_IMPORT_UNCOMPRESSED_BYTES {
            bail!("import archive is too large when decompressed");
        }
    }
    let manifest = read_json_entry(&mut archive, "manifest.json")?;
    if manifest.get("schema").and_then(Value::as_str) != Some(EXPORT_SCHEMA) {
        bail!("unsupported session export schema");
    }
    let target = manifest
        .get("target")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("import manifest lacks target metadata"))?;
    let project_id = required_string(target, "project_id", "import manifest target")?;
    let project_root = required_string(target, "project_root", "import manifest target")?;
    let sessions = manifest
        .get("sessions")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("import manifest lacks sessions"))?
        .iter()
        .map(parse_session)
        .collect::<Result<Vec<_>>>()?;
    if sessions.is_empty() {
        bail!("import archive contains no sessions");
    }
    let events = read_json_entry(&mut archive, "events.json")?
        .as_array()
        .ok_or_else(|| anyhow!("import events must be a JSON array"))?
        .iter()
        .map(|value| parse_event(value, &mut archive))
        .collect::<Result<Vec<_>>>()?;
    let compressed_results = parse_compressed_results(&mut archive)?;
    let delegation_jobs = parse_delegation_jobs(&mut archive)?;
    let delegation_payloads = parse_delegation_payloads(&mut archive)?;
    let delegation_steers = parse_delegation_steers(&mut archive)?;
    let inference_calls = optional_index(&mut archive, "inference_calls/index.json")?;
    let tool_calls = optional_index(&mut archive, "tool_calls/index.json")?;
    // Approval snapshots remain in exports for auditability, but are deliberately
    // ignored on import: an archive must never grant commands, paths, or loop rules
    // in the importing environment.
    Ok(ImportArchive {
        project_id,
        project_root,
        redacted: manifest
            .get("redacted")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        sessions,
        events,
        compressed_results,
        delegation_jobs,
        delegation_payloads,
        delegation_steers,
        inference_calls,
        tool_calls,
    })
}

fn optional_index(archive: &mut zip::ZipArchive<Cursor<&[u8]>>, path: &str) -> Result<Vec<Value>> {
    match read_json_entry(archive, path) {
        Ok(Value::Array(entries)) => Ok(entries),
        Ok(_) => bail!("import {path} must be a JSON array"),
        Err(error) if error.to_string().contains(&format!("lacks {path}")) => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

fn parse_delegation_jobs(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
) -> Result<Vec<ImportedDelegationJob>> {
    optional_index(archive, "delegations/index.json")?
        .iter()
        .map(|value| {
            let object = value
                .as_object()
                .ok_or_else(|| anyhow!("delegation index entry must be an object"))?;
            let children = object
                .get("children")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("delegation index entry lacks children"))?
                .iter()
                .map(parse_delegation_child)
                .collect::<Result<Vec<_>>>()?;
            Ok(ImportedDelegationJob {
                task_call_id: required_string(object, "task_call_id", "delegation index")?,
                function_call_id: optional_string(
                    object.get("function_call_id"),
                    "function_call_id",
                )?,
                parent_source_id: parse_uuid(
                    required_string(object, "parent_session_id", "delegation index")?,
                    "parent_session_id",
                )?,
                parent_agent: required_string(object, "parent_agent", "delegation index")?,
                original_args_json: optional_string(
                    object.get("original_args_json"),
                    "original_args_json",
                )?,
                status: required_string(object, "status", "delegation index")?,
                ack_delivered: required_bool(object, "ack_delivered", "delegation index")?,
                final_delivered: required_bool(object, "final_delivered", "delegation index")?,
                created_at: required_i64(object, "created_at", "delegation index")?,
                updated_at: required_i64(object, "updated_at", "delegation index")?,
                children,
            })
        })
        .collect()
}

fn parse_delegation_child(value: &Value) -> Result<ImportedDelegationChild> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("delegation child must be an object"))?;
    Ok(ImportedDelegationChild {
        label: required_string(object, "label", "delegation child")?,
        child_agent: required_string(object, "child_agent", "delegation child")?,
        model: optional_string(object.get("model"), "model")?,
        status: required_string(object, "status", "delegation child")?,
        report: optional_string(object.get("report"), "report")?,
        output_dir: optional_string(object.get("output_dir"), "output_dir")?,
        todo_ids_json: optional_string(object.get("todo_ids_json"), "todo_ids_json")?,
        result_delivered: required_bool(object, "result_delivered", "delegation child")?,
        started_at: optional_i64(object.get("started_at"), "started_at")?,
        finished_at: optional_i64(object.get("finished_at"), "finished_at")?,
        created_at: required_i64(object, "created_at", "delegation child")?,
        updated_at: required_i64(object, "updated_at", "delegation child")?,
        requested_cwd: optional_string(object.get("requested_cwd"), "requested_cwd")?,
        resolved_cwd: optional_string(object.get("resolved_cwd"), "resolved_cwd")?,
    })
}

fn parse_delegation_payloads(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
) -> Result<Vec<ImportedDelegationPayload>> {
    optional_index(archive, "delegation_payloads/index.json")?
        .iter()
        .map(|value| {
            let object = value
                .as_object()
                .ok_or_else(|| anyhow!("delegation payload index entry must be an object"))?;
            let body =
                match optional_string(object.get("file"), "file")? {
                    Some(file) => {
                        if !file.starts_with("delegation_payloads/") {
                            bail!("delegation payload file is outside its archive directory");
                        }
                        Some(read_text_entry(archive, &file).with_context(|| {
                            format!("reading delegation payload sidecar `{file}`")
                        })?)
                    }
                    None => None,
                };
            Ok(ImportedDelegationPayload {
                task_call_id: required_string(object, "task_call_id", "delegation payload index")?,
                function_call_id: optional_string(
                    object.get("function_call_id"),
                    "function_call_id",
                )?,
                source_session_id: parse_uuid(
                    required_string(object, "session_id", "delegation payload index")?,
                    "session_id",
                )?,
                parent_agent: required_string(object, "parent_agent", "delegation payload index")?,
                label: required_string(object, "label", "delegation payload index")?,
                payload_hash: required_string(object, "payload_hash", "delegation payload index")?,
                child_agent: required_string(object, "child_agent", "delegation payload index")?,
                prompt_byte_len: required_i64(
                    object,
                    "prompt_byte_len",
                    "delegation payload index",
                )?
                .try_into()
                .context("delegation payload prompt_byte_len")?,
                created_at: required_i64(object, "created_at", "delegation payload index")?,
                delivered_at: optional_i64(object.get("delivered_at"), "delivered_at")?,
                body,
            })
        })
        .collect()
}

fn parse_delegation_steers(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
) -> Result<Vec<ImportedDelegationSteer>> {
    optional_index(archive, "delegation_steers/index.json")?
        .iter()
        .map(|value| {
            let object = value
                .as_object()
                .ok_or_else(|| anyhow!("delegation steer index entry must be an object"))?;
            Ok(ImportedDelegationSteer {
                task_call_id: required_string(object, "task_call_id", "delegation steer index")?,
                label: required_string(object, "label", "delegation steer index")?,
                source_session_id: parse_uuid(
                    required_string(object, "session_id", "delegation steer index")?,
                    "session_id",
                )?,
                origin_principal: required_string(
                    object,
                    "origin_principal",
                    "delegation steer index",
                )?,
                body: required_string(object, "body", "delegation steer index")?,
                delivered: required_bool(object, "delivered", "delegation steer index")?,
                created_at: required_i64(object, "created_at", "delegation steer index")?,
                delivered_at: optional_i64(object.get("delivered_at"), "delivered_at")?,
            })
        })
        .collect()
}

fn parse_compressed_results(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
) -> Result<Vec<ImportedCompressedResult>> {
    let index = match read_json_entry(archive, "compressed_tool_results/index.json") {
        Ok(value) => value,
        Err(error)
            if error
                .to_string()
                .contains("lacks compressed_tool_results/index.json") =>
        {
            return Ok(Vec::new());
        }
        Err(error) => return Err(error),
    };
    let entries = index
        .as_array()
        .ok_or_else(|| anyhow!("compressed result index must be an array"))?;
    entries
        .iter()
        .map(|value| {
            let object = value
                .as_object()
                .ok_or_else(|| anyhow!("compressed result index entry must be an object"))?;
            let file = required_string(object, "file", "compressed result index")?;
            if !file.starts_with("compressed_tool_results/") {
                bail!("compressed result file is outside its archive directory");
            }
            let content = read_text_entry(archive, &file)?;
            Ok(ImportedCompressedResult {
                source_session_id: parse_uuid(
                    required_string(object, "session_id", "compressed result index")?,
                    "session_id",
                )?,
                hash: required_string(object, "hash", "compressed result index")?,
                agent_id: required_string(object, "agent_id", "compressed result index")?,
                tool: required_string(object, "tool", "compressed result index")?,
                call_id: required_string(object, "call_id", "compressed result index")?,
                original_byte_len: required_i64(
                    object,
                    "original_byte_len",
                    "compressed result index",
                )?
                .try_into()
                .context("compressed result original_byte_len")?,
                compressed_byte_len: optional_i64(
                    object.get("compressed_byte_len"),
                    "compressed_byte_len",
                )?
                .map(usize::try_from)
                .transpose()
                .context("compressed result compressed_byte_len")?,
                created_at: required_i64(object, "created_at", "compressed result index")?,
                kind: required_string(object, "kind", "compressed result index")?,
                content,
            })
        })
        .collect()
}

fn read_text_entry(archive: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str) -> Result<String> {
    let mut raw = String::new();
    archive
        .by_name(name)
        .with_context(|| format!("import archive lacks {name}"))?
        .read_to_string(&mut raw)?;
    Ok(raw)
}

fn read_json_entry(archive: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str) -> Result<Value> {
    let mut raw = String::new();
    archive
        .by_name(name)
        .with_context(|| format!("import archive lacks {name}"))?
        .read_to_string(&mut raw)?;
    serde_json::from_str(&raw).with_context(|| format!("parsing import {name}"))
}

fn parse_session(value: &Value) -> Result<ImportedSession> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("import manifest session must be an object"))?;
    Ok(ImportedSession {
        source_id: parse_uuid(
            required_string(object, "session_id", "import manifest session")?,
            "session_id",
        )?,
        parent_source_id: optional_uuid(object.get("parent_session_id"), "parent_session_id")?,
        short_id: optional_string(object.get("short_id"), "short_id")?,
        fork_point_turn_id: optional_string(
            object.get("fork_point_turn_id"),
            "fork_point_turn_id",
        )?,
        provider: optional_string(object.get("provider"), "provider")?,
        model: optional_string(object.get("model"), "model")?,
        active_agent: required_string(object, "active_agent", "import manifest session")?,
        started_at: required_i64(object, "started_at", "import manifest session")?,
        ended_at: optional_i64(object.get("ended_at"), "ended_at")?,
        title: optional_string(object.get("title"), "title")?,
    })
}

fn parse_event(
    value: &Value,
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
) -> Result<ImportedEvent> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("import event must be an object"))?;
    let mut data = object
        .get("data")
        .cloned()
        .ok_or_else(|| anyhow!("import event lacks data"))?;
    if let Some(output_file) = optional_string(object.get("output_file"), "output_file")? {
        if !output_file.starts_with("tool_outputs/") {
            bail!("import event output_file must be under tool_outputs/");
        }
        let output = read_json_entry(archive, &output_file)
            .with_context(|| format!("reading tool-output sidecar `{output_file}`"))?;
        let data_object = data
            .as_object_mut()
            .ok_or_else(|| anyhow!("import event with output_file must have object data"))?;
        data_object.insert("output_sidecar".to_owned(), output);
    }
    if let Some(request_file) = optional_string(object.get("file"), "file")? {
        if request_file.starts_with("inference_requests/")
            || request_file.starts_with("inference_requests_utility/")
        {
            let request = read_json_entry(archive, &request_file)
                .with_context(|| format!("reading inference sidecar `{request_file}`"))?;
            let data_object = data
                .as_object_mut()
                .ok_or_else(|| anyhow!("import event with file must have object data"))?;
            data_object.insert("inference_request_sidecar".to_owned(), request);
        } else if request_file.starts_with("inference_requests_tandem/") {
            let tandem = read_json_entry(archive, &request_file)
                .with_context(|| format!("reading tandem inference sidecar `{request_file}`"))?;
            let data_object = data
                .as_object_mut()
                .ok_or_else(|| anyhow!("import event with file must have object data"))?;
            data_object.insert("tandem_inference_sidecar".to_owned(), tandem);
        }
    }
    Ok(ImportedEvent {
        seq: required_i64(object, "seq", "import event")?,
        ts_ms: required_i64(object, "ts_ms", "import event")?,
        kind: parse_event_kind(required_string(object, "type", "import event")?)?,
        source_session_id: parse_uuid(
            required_string(object, "session_id", "import event")?,
            "session_id",
        )?,
        agent: optional_string(object.get("agent"), "agent")?,
        call_id: optional_string(object.get("call_id"), "call_id")?,
        data_json: serde_json::to_string(&data)?,
    })
}

fn required_sidecar_string<'a>(value: &'a Value, key: &str, context: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{context} lacks string `{key}`"))
}

fn required_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
    context: &str,
) -> Result<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("{context} lacks string `{key}`"))
}
fn optional_string(value: Option<&Value>, key: &str) -> Result<Option<String>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(ToOwned::to_owned)
            .map(Some)
            .ok_or_else(|| anyhow!("import value `{key}` must be a string or null")),
    }
}
fn required_i64(object: &serde_json::Map<String, Value>, key: &str, context: &str) -> Result<i64> {
    object
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("{context} lacks integer `{key}`"))
}
fn required_bool(
    object: &serde_json::Map<String, Value>,
    key: &str,
    context: &str,
) -> Result<bool> {
    object
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("{context} lacks boolean `{key}`"))
}
fn validate_delegation_status(status: &str, context: &str) -> Result<()> {
    match status {
        "running"
        | "backgrounded"
        | "completed"
        | "failed"
        | "cancelled"
        | "paused_pending_tool"
        | "lost" => Ok(()),
        _ => bail!("import {context} has unsupported status `{status}`"),
    }
}
fn optional_i64(value: Option<&Value>, key: &str) -> Result<Option<i64>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| anyhow!("import value `{key}` must be an integer or null")),
    }
}
fn parse_uuid(raw: String, key: &str) -> Result<Uuid> {
    Uuid::parse_str(&raw).with_context(|| format!("invalid import {key} UUID `{raw}`"))
}
fn optional_uuid(value: Option<&Value>, key: &str) -> Result<Option<Uuid>> {
    optional_string(value, key)?
        .map(|raw| parse_uuid(raw, key))
        .transpose()
}

fn parse_event_kind(raw: String) -> Result<SessionEventKind> {
    use SessionEventKind::*;
    let kind = match raw.as_str() {
        "user_message" => UserMessage,
        "user_note" => UserNote,
        "assistant_message" => AssistantMessage,
        "inference_request" => InferenceRequest,
        "tandem_inference" => TandemInference,
        "tool_call" => ToolCall,
        "tool_call_started" => ToolCallStarted,
        "tool_call_completed" => ToolCallCompleted,
        "subagent_spawned" => SubagentSpawned,
        "subagent_routing" => SubagentRouting,
        "subagent_report" => SubagentReport,
        "context_pruned" => ContextPruned,
        "session_compacted" => SessionCompacted,
        "permission_decision" => PermissionDecision,
        "interrupt_decision" => InterruptDecision,
        "tool_rejected" => ToolRejected,
        "primary_swap" => PrimarySwap,
        "inference_failure" => InferenceFailure,
        "failed_turn_recovery" => FailedTurnRecovery,
        "turn_interrupted" => TurnInterrupted,
        "skill_auto_select" => SkillAutoSelect,
        "auto_prune_diagnostic" => AutoPruneDiagnostic,
        "goal_progress_diagnostic" => GoalProgressDiagnostic,
        "resource_promotion" => ResourcePromotion,
        "notice" => Notice,
        "model_switch" => ModelSwitch,
        _ => bail!("unsupported import event type `{raw}`"),
    };
    Ok(kind)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use zip::write::{SimpleFileOptions, ZipWriter};

    fn session(id: Uuid, parent: Option<Uuid>) -> Value {
        json!({
            "session_id": id,
            "short_id": "export",
            "parent_session_id": parent,
            "fork_point_turn_id": null,
            "provider": "test-provider",
            "model": "test-model",
            "active_agent": "Build",
            "started_at": 100,
            "ended_at": null,
            "title": "Imported session",
        })
    }

    fn archive_bytes(sessions: Vec<Value>, events: Vec<Value>, redacted: bool) -> Vec<u8> {
        archive_bytes_with_schema(EXPORT_SCHEMA, sessions, events, redacted)
    }

    fn archive_bytes_with_schema(
        schema: &str,
        sessions: Vec<Value>,
        events: Vec<Value>,
        redacted: bool,
    ) -> Vec<u8> {
        let manifest = json!({
            "schema": schema,
            "redacted": redacted,
            "target": { "project_id": "import-test", "project_root": "/tmp/import-test" },
            "sessions": sessions,
        });
        let mut cursor = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(&mut cursor);
        let options = SimpleFileOptions::default();
        zip.start_file("manifest.json", options).unwrap();
        zip.write_all(serde_json::to_string(&manifest).unwrap().as_bytes())
            .unwrap();
        zip.start_file("events.json", options).unwrap();
        zip.write_all(serde_json::to_string(&events).unwrap().as_bytes())
            .unwrap();
        zip.finish().unwrap();
        cursor.into_inner()
    }

    fn event(session_id: Uuid, ts_ms: i64) -> Value {
        json!({
            "seq": 1,
            "ts_ms": ts_ms,
            "type": "user_message",
            "session_id": session_id,
            "short_id": "export",
            "agent": "Build",
            "call_id": null,
            "data": { "text": "round trip content" },
        })
    }

    #[tokio::test]
    async fn import_existing_id_refuses() {
        let db = Db::open_in_memory().unwrap();
        let id = Uuid::new_v4();
        let archive =
            read_archive_bytes(&archive_bytes(vec![session(id, None)], vec![], false)).unwrap();
        db.transaction(move |conn| {
            let mut row =
                Db::build_new_session_row_conn(conn, "import-test", "/tmp/import-test", "Build")?;
            row.session_id = id;
            Db::insert_session_row_conn(conn, &row)?;
            Ok(())
        })
        .await
        .unwrap();
        let error = import_archive(&db, archive, false).await.unwrap_err();
        assert!(error.to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn import_as_new_records_provenance() {
        let db = Db::open_in_memory().unwrap();
        let id = Uuid::new_v4();
        db.transaction(move |conn| {
            let mut row =
                Db::build_new_session_row_conn(conn, "import-test", "/tmp/import-test", "Build")?;
            row.session_id = id;
            Db::insert_session_row_conn(conn, &row)?;
            Ok(())
        })
        .await
        .unwrap();
        let archive = read_archive_bytes(&archive_bytes(
            vec![session(id, None)],
            vec![event(id, 321)],
            true,
        ))
        .unwrap();
        let imported = import_archive(&db, archive, true).await.unwrap();
        assert_ne!(imported.imported[0], id);
        let restored = db.get_session(imported.imported[0]).await.unwrap().unwrap();
        assert_eq!(restored.short_id.as_deref(), Some("export"));
        let events = db.list_session_events(imported.imported[0]).await.unwrap();
        assert!(events.iter().any(|event| event.kind == "notice"
            && event.data["original_session_id"] == id.to_string()
            && event.data["redacted"] == true));
    }

    #[tokio::test]
    async fn import_failure_is_atomic() {
        let db = Db::open_in_memory().unwrap();
        let root = Uuid::new_v4();
        let cycle = Uuid::new_v4();
        let archive = read_archive_bytes(&archive_bytes(
            vec![session(root, None), session(cycle, Some(cycle))],
            vec![],
            false,
        ))
        .unwrap();
        let error = import_archive(&db, archive, false).await.unwrap_err();
        assert!(error.to_string().contains("cyclic"));
        assert!(db.get_session(root).await.unwrap().is_none());
        assert!(db.get_session(cycle).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn import_preserves_exported_event_timestamp() {
        let db = Db::open_in_memory().unwrap();
        let id = Uuid::new_v4();
        let archive = read_archive_bytes(&archive_bytes(
            vec![session(id, None)],
            vec![event(id, 1_234_567)],
            false,
        ))
        .unwrap();
        let imported = import_archive(&db, archive, false).await.unwrap();
        let events = db.list_session_events(imported.imported[0]).await.unwrap();
        assert!(
            events
                .iter()
                .any(|event| event.kind == "user_message" && event.ts_ms == 1_234_567)
        );
    }

    #[tokio::test]
    async fn import_restores_exported_session_metadata() {
        let db = Db::open_in_memory().unwrap();
        let root = Uuid::new_v4();
        let child = Uuid::new_v4();
        let mut child_manifest = session(child, Some(root));
        child_manifest["fork_point_turn_id"] = json!("42");
        child_manifest["ended_at"] = json!(777);
        child_manifest["title"] = json!("Restored title");
        child_manifest["short_id"] = json!("child1");
        let archive = read_archive_bytes(&archive_bytes(
            vec![session(root, None), child_manifest],
            vec![event(child, 456_789)],
            false,
        ))
        .unwrap();
        import_archive(&db, archive, false).await.unwrap();
        let restored = db.get_session(child).await.unwrap().unwrap();
        assert_eq!(restored.parent_session_id, Some(root));
        assert_eq!(restored.fork_point_turn_id.as_deref(), Some("42"));
        assert_eq!(restored.ended_at, Some(777));
        assert_eq!(restored.title.as_deref(), Some("Restored title"));
        assert_eq!(restored.short_id.as_deref(), Some("child1"));
        let events = db.list_session_events(child).await.unwrap();
        assert!(
            events
                .iter()
                .any(|event| event.kind == "user_message" && event.ts_ms == 456_789)
        );
    }

    #[test]
    fn import_unsupported_version_refuses() {
        let bytes = archive_bytes_with_schema(
            "cockpit-session-export/999",
            vec![session(Uuid::new_v4(), None)],
            vec![],
            false,
        );
        let error = read_archive_bytes(&bytes).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported session export schema")
        );
    }

    #[test]
    fn import_rejects_zip_slip() {
        let mut cursor = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(&mut cursor);
        zip.start_file("../manifest.json", SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"{}").unwrap();
        zip.finish().unwrap();
        let error = read_archive_bytes(&cursor.into_inner()).unwrap_err();
        assert!(error.to_string().contains("unsafe path"));
    }

    #[tokio::test]
    async fn import_leaves_foreign_keys_valid() {
        let db = Db::open_in_memory().unwrap();
        let id = Uuid::new_v4();
        let archive = read_archive_bytes(&archive_bytes(
            vec![session(id, None)],
            vec![event(id, 12)],
            false,
        ))
        .unwrap();
        import_archive(&db, archive, false).await.unwrap();
        let violations: Option<String> = db
            .read(|conn| {
                Ok(conn
                    .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
                    .optional()?)
            })
            .await
            .unwrap();
        assert!(violations.is_none());
    }

    #[tokio::test]
    async fn import_reports_redacted_provenance() {
        let db = Db::open_in_memory().unwrap();
        let id = Uuid::new_v4();
        let archive = read_archive_bytes(&archive_bytes(
            vec![session(id, None)],
            vec![event(id, 99)],
            true,
        ))
        .unwrap();
        let imported = import_archive(&db, archive, false).await.unwrap();
        assert!(imported.redacted);
        let events = db.list_session_events(imported.imported[0]).await.unwrap();
        assert!(events.iter().any(|event| event.kind == "notice"
            && event.data["source"] == "session_import"
            && event.data["redacted"] == true));
    }
    #[tokio::test]
    async fn import_ignores_approval_grants() {
        let source = Db::open_in_memory().unwrap();
        let row = source
            .transaction(|conn| {
                let row = Db::build_new_session_row_conn(
                    conn,
                    "approval-import",
                    "/tmp/approval-import",
                    "Build",
                )?;
                Db::insert_session_row_conn(conn, &row)
            })
            .await
            .unwrap();
        let source_id = row.session_id;
        source
            .transaction(move |conn| {
                conn.execute(
                    "INSERT INTO approval_grants (session_id, grant_kind, grant_key, granted_at, verdict, access, risk_tier) VALUES (?1, 'command', 'git status', 1, 'allow', NULL, 'ordinary')",
                    [source_id.to_string()],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let bytes = crate::session::export::build_zip(&source, &row, std::slice::from_ref(&row))
            .await
            .unwrap();
        let destination = Db::open_in_memory().unwrap();
        import_archive(&destination, read_archive_bytes(&bytes).unwrap(), false)
            .await
            .unwrap();
        let grants: i64 = destination
            .read(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM approval_grants WHERE session_id = ?1",
                    [source_id.to_string()],
                    |row| row.get(0),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(grants, 0, "import must not restore approval grants");
    }

    #[tokio::test]
    async fn export_import_round_trips() {
        use cockpit_db::db::inference_calls::InferenceCallRow;

        let source = Db::open_in_memory().unwrap();
        let row = source
            .transaction(|conn| {
                let row =
                    Db::build_new_session_row_conn(conn, "round-trip", "/tmp/round-trip", "Build")?;
                Db::insert_session_row_conn(conn, &row)
            })
            .await
            .unwrap();
        let source_id = row.session_id;
        source
            .transaction(move |conn| {
                Db::insert_session_event_json_conn(
                    conn,
                    source_id,
                    SessionEventKind::UserMessage,
                    Some("Build"),
                    None,
                    SessionEventContext::default(),
                    1234,
                    r#"{"text":"round trip"}"#,
                )?;
                Db::insert_inference_call_conn(
                    conn,
                    &InferenceCallRow {
                        call_id: Uuid::new_v4(),
                        session_id: source_id,
                        project_id: "round-trip".into(),
                        project_root: "/tmp/round-trip".into(),
                        model: "test-model".into(),
                        provider: "test-provider".into(),
                        timestamp: 1235,
                        input_tokens: 2,
                        output_tokens: 3,
                        cached_input_tokens: 0,
                        cache_creation_input_tokens: 0,
                        cost_usd_micros: Some(4),
                        is_utility: false,
                    },
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let bytes = crate::session::export::build_zip(&source, &row, std::slice::from_ref(&row))
            .await
            .unwrap();
        let destination = Db::open_in_memory().unwrap();
        let imported = import_archive(&destination, read_archive_bytes(&bytes).unwrap(), false)
            .await
            .unwrap();
        assert_eq!(imported.imported, vec![source_id]);
        let source_counts: (i64, i64) = source
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT COUNT(*) FROM session_events WHERE session_id = ?1",
                        [source_id.to_string()],
                        |r| r.get(0),
                    )?,
                    conn.query_row(
                        "SELECT COUNT(*) FROM inference_calls WHERE session_id = ?1",
                        [source_id.to_string()],
                        |r| r.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        let destination_counts: (i64, i64) = destination.read(move |conn| Ok((
            conn.query_row("SELECT COUNT(*) FROM session_events WHERE session_id = ?1 AND type != 'notice'", [source_id.to_string()], |r| r.get(0))?,
            conn.query_row("SELECT COUNT(*) FROM inference_calls WHERE session_id = ?1", [source_id.to_string()], |r| r.get(0))?,
        ))).await.unwrap();
        assert_eq!(destination_counts, source_counts);
    }
}
