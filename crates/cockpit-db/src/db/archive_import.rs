//! One-transaction session archive restoration.
//!
//! Core parses ZIP bytes and performs archive/path/representation preflight,
//! then passes this graph to the sole public import composition. All
//! destination-id allocation, SQL writes, and source-to-destination mapping
//! happen below this module's transaction boundary.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::db::{
    Db,
    session_log::{SessionEventContext, SessionEventKind},
    text_artifacts::{
        CaptureReason, ImportedTextArtifactSlot, TextArtifactCandidate, TextArtifactKind,
        TextArtifactRelation, TextArtifactRepresentation, import_text_artifact_slots_conn,
    },
};

/// The model selection recorded in an exported session. Core validates and
/// serializes its configuration DTO while parsing; database restoration only
/// persists the already-preflighted scalar fields and canonical JSON.
#[derive(Debug, Clone)]
pub struct ImportedArchiveActiveModel {
    pub provider: String,
    pub model: String,
    pub selection_json: String,
}

#[derive(Debug, Clone)]
pub struct ImportedArchiveSession {
    pub source_id: Uuid,
    pub parent_source_id: Option<Uuid>,
    pub short_id: Option<String>,
    pub fork_point_turn_id: Option<String>,
    pub assistant_name: Option<String>,
    pub is_assistant_thread: bool,
    pub active_model: Option<ImportedArchiveActiveModel>,
    pub session_entry_mode: String,
    pub active_agent: String,
    pub started_at_unix_ms: i64,
    pub ended_at_unix_ms: Option<i64>,
    pub title: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ImportedArchiveEvent {
    pub seq: i64,
    pub ts_ms: i64,
    pub kind: SessionEventKind,
    pub source_session_id: Uuid,
    pub agent: Option<String>,
    pub call_id: Option<String>,
    pub data_json: String,
}

#[derive(Debug, Clone)]
pub struct ImportedArchiveTextArtifact {
    pub source_artifact_id: Uuid,
    pub source_session_id: Uuid,
    pub source_event_seq: i64,
    pub relation: TextArtifactRelation,
    pub projection_slot: Option<i64>,
    pub kind: TextArtifactKind,
    pub capture_reason: CaptureReason,
    pub provenance_json: String,
    pub host_captured_bytes: usize,
    pub host_original_bytes: usize,
    pub host_dropped_bytes: usize,
    pub stored_source_bytes: usize,
    pub representation: TextArtifactRepresentation,
    pub created_at: i64,
    pub content: String,
    /// A daemon-owned path staged by core before this import transaction. It
    /// is absent for small inline bodies.
    pub staged_blob_session_id: Option<Uuid>,
    /// Present only on a user-input source owner. The event sequence is
    /// remapped by the one import transaction before this immutable envelope
    /// is inserted.
    pub model_envelope_json: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ImportedArchiveDelegationChild {
    pub label: String,
    pub child_agent: String,
    pub model: Option<String>,
    pub status: String,
    pub report: Option<String>,
    pub output_dir: Option<String>,
    pub todo_ids_json: Option<String>,
    pub result_delivered: bool,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub requested_cwd: Option<String>,
    pub resolved_cwd: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ImportedArchiveDelegationJob {
    pub task_call_id: String,
    pub function_call_id: Option<String>,
    pub parent_source_id: Uuid,
    pub parent_agent: String,
    pub original_args_json: Option<String>,
    pub status: String,
    pub ack_delivered: bool,
    pub final_delivered: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub children: Vec<ImportedArchiveDelegationChild>,
}

#[derive(Debug, Clone)]
pub struct ImportedArchiveDelegationPayload {
    pub task_call_id: String,
    pub function_call_id: Option<String>,
    pub source_session_id: Uuid,
    pub parent_agent: String,
    pub label: String,
    pub payload_hash: String,
    pub child_agent: String,
    pub prompt_byte_len: usize,
    pub created_at: i64,
    pub delivered_at: Option<i64>,
    pub body: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ImportedArchiveDelegationSteer {
    pub task_call_id: String,
    pub label: String,
    pub source_session_id: Uuid,
    pub origin_principal: String,
    pub body: String,
    pub delivered: bool,
    pub created_at: i64,
    pub delivered_at: Option<i64>,
}

/// Fully parsed and structurally preflighted archive graph. Every import
/// allocates a fresh destination graph inside the public database operation,
/// which has exactly one input and exactly one writer transaction.
#[derive(Debug, Clone)]
pub struct SessionArchiveImportGraph {
    pub project_id: String,
    pub project_root: String,
    pub redacted: bool,
    pub sessions: Vec<ImportedArchiveSession>,
    pub events: Vec<ImportedArchiveEvent>,
    pub text_artifacts: Vec<ImportedArchiveTextArtifact>,
    pub delegation_jobs: Vec<ImportedArchiveDelegationJob>,
    pub delegation_payloads: Vec<ImportedArchiveDelegationPayload>,
    pub delegation_steers: Vec<ImportedArchiveDelegationSteer>,
    pub inference_calls: Vec<Value>,
    pub tool_calls: Vec<Value>,
}

#[derive(Debug, Clone)]
pub struct ArchiveImportResult {
    pub imported: Vec<Uuid>,
    pub redacted: bool,
}

/// Validates the two durable projections of a fresh assistant thread's
/// originating message. The session row is relational lineage; the
/// `thread_anchor` event is portable audit data. Neither may exist without the
/// other, and they must identify the same parent message.
pub fn validate_thread_anchors(
    sessions: &[ImportedArchiveSession],
    events: &[ImportedArchiveEvent],
) -> Result<()> {
    thread_anchor_sources(sessions, events).map(|_| ())
}

fn thread_anchor_sources(
    sessions: &[ImportedArchiveSession],
    events: &[ImportedArchiveEvent],
) -> Result<BTreeMap<Uuid, (Uuid, i64)>> {
    let sessions_by_id: BTreeMap<Uuid, &ImportedArchiveSession> = sessions
        .iter()
        .map(|session| (session.source_id, session))
        .collect();
    let mut events_by_identity = BTreeMap::new();
    let mut anchors = BTreeMap::new();
    for event in events {
        if events_by_identity
            .insert((event.source_session_id, event.seq), event.kind)
            .is_some()
        {
            bail!("import archive has a duplicate session event sequence");
        }
        if event.kind != SessionEventKind::ThreadAnchor {
            continue;
        }
        let session = sessions_by_id
            .get(&event.source_session_id)
            .ok_or_else(|| {
                anyhow!("import archive contains a thread anchor for an unknown session")
            })?;
        if !session.is_assistant_thread {
            bail!("import archive thread anchor belongs to a non-thread session");
        }
        let data: Value = serde_json::from_str(&event.data_json)
            .context("parsing imported thread anchor payload")?;
        let object = data
            .as_object()
            .ok_or_else(|| anyhow!("import thread anchor payload must be an object"))?;
        let parent_source_id = object
            .get("parent_session_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("import thread anchor lacks parent_session_id"))
            .and_then(|value| {
                Uuid::parse_str(value)
                    .with_context(|| "import thread anchor has invalid parent_session_id")
            })?;
        let parent_turn_id = object
            .get("parent_turn_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("import thread anchor lacks parent_turn_id"))?;
        let parent_seq: i64 = parent_turn_id
            .parse()
            .with_context(|| "import thread anchor parent_turn_id is not an integer")?;
        let relational_parent = session
            .parent_source_id
            .ok_or_else(|| anyhow!("import assistant thread lacks parent_session_id"))?;
        let relational_turn = session
            .fork_point_turn_id
            .as_deref()
            .ok_or_else(|| anyhow!("import assistant thread lacks fork_point_turn_id"))?;
        if parent_source_id != relational_parent || parent_turn_id != relational_turn {
            bail!("import thread anchor does not match assistant-thread lineage");
        }
        if anchors
            .insert(event.source_session_id, (parent_source_id, parent_seq))
            .is_some()
        {
            bail!("import assistant thread has more than one thread anchor");
        }
    }
    for session in sessions {
        if session.is_assistant_thread && !anchors.contains_key(&session.source_id) {
            bail!("import assistant thread lacks a thread anchor event");
        }
    }
    for (parent_id, parent_seq) in anchors.values() {
        let parent_kind = events_by_identity
            .get(&(*parent_id, *parent_seq))
            .ok_or_else(|| anyhow!("import thread anchor points to a missing parent event"))?;
        if !matches!(
            parent_kind,
            SessionEventKind::UserMessage | SessionEventKind::AssistantMessage
        ) {
            bail!("import thread anchor must point to a parent message");
        }
    }
    Ok(anchors)
}

impl Db {
    /// Restore all sessions, events, sidecars, artifact associations, and
    /// import provenance inside one database-owned writer transaction.
    ///
    /// `establish_redaction_custody` runs for each destination session id
    /// before that row is inserted. The insert primitive requires a
    /// `redaction_table` vault item on this connection.
    pub async fn import_session_archive_graph(
        &self,
        graph: SessionArchiveImportGraph,
        establish_redaction_custody: impl FnMut(&Connection, Uuid) -> Result<()> + Send + 'static,
    ) -> Result<ArchiveImportResult> {
        self.transaction(move |conn| {
            Self::import_session_archive_graph_conn(conn, graph, establish_redaction_custody)
        })
        .await
    }

    /// Conn-level import body so callers can compose vault redaction custody
    /// in the same SQLite transaction as the restored session rows.
    pub fn import_session_archive_graph_conn(
        conn: &Connection,
        graph: SessionArchiveImportGraph,
        establish_redaction_custody: impl FnMut(&Connection, Uuid) -> Result<()>,
    ) -> Result<ArchiveImportResult> {
        import_session_archive_graph_conn(conn, graph, establish_redaction_custody)
    }
}

fn import_session_archive_graph_conn(
    conn: &Connection,
    mut graph: SessionArchiveImportGraph,
    mut establish_redaction_custody: impl FnMut(&Connection, Uuid) -> Result<()>,
) -> Result<ArchiveImportResult> {
    let source_ids: BTreeSet<Uuid> = graph
        .sessions
        .iter()
        .map(|session| session.source_id)
        .collect();
    if source_ids.len() != graph.sessions.len() {
        bail!("import archive lists a session more than once");
    }
    for session in &graph.sessions {
        if let Some(parent) = session.parent_source_id
            && !source_ids.contains(&parent)
        {
            bail!("import archive references a parent session that is not in the archive");
        }
    }
    for event in &graph.events {
        if !source_ids.contains(&event.source_session_id) {
            bail!("import archive contains an event for an unknown session");
        }
    }
    let thread_anchors = thread_anchor_sources(&graph.sessions, &graph.events)?;
    for result in &graph.text_artifacts {
        if !source_ids.contains(&result.source_session_id) {
            bail!("import archive contains a text artifact for an unknown session");
        }
    }
    let delegation_jobs: BTreeMap<&str, &ImportedArchiveDelegationJob> = graph
        .delegation_jobs
        .iter()
        .map(|job| (job.task_call_id.as_str(), job))
        .collect();
    if delegation_jobs.len() != graph.delegation_jobs.len() {
        bail!("import archive lists a delegation job more than once");
    }
    for job in &graph.delegation_jobs {
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
    for payload in &graph.delegation_payloads {
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
    for steer in &graph.delegation_steers {
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

    // Inference-call identifiers are globally keyed in both the telemetry and
    // captured-request tables. They are source identities too, so remap them
    // as one graph before writing either surface. In particular, an import
    // must remain repeatable into the same database even when its source has
    // multiple captured attempts for one logical call.
    let inference_call_id_map = build_import_inference_call_id_map(&graph)?;

    // An archive is always a source graph, never a request to reuse its
    // durable identities. Mint every destination session identity before any
    // rows are written so repeated imports cannot share session/event/artifact
    // ownership.
    let id_map = source_ids
        .iter()
        .map(|source_id| (*source_id, Uuid::new_v4()))
        .collect::<BTreeMap<_, _>>();

    // Delegation task ids are global rather than session-scoped, so they are
    // remapped alongside the fresh session graph on every import.
    let task_call_id_map: BTreeMap<String, String> = graph
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
        .collect();

    let sessions = std::mem::take(&mut graph.sessions);
    let mut remaining: BTreeMap<Uuid, ImportedArchiveSession> = sessions
        .into_iter()
        .map(|session| (session.source_id, session))
        .collect();
    let mut inserted = BTreeSet::new();
    let mut imported = Vec::new();
    let mut pending_forks = Vec::new();
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
                &graph.project_id,
                &graph.project_root,
                &session.active_agent,
            )?;
            row.session_id = id_map[&source_id];
            // The builder minted the lineage root for its throwaway id. An
            // imported session is always the root of a fresh lineage in the
            // destination graph (archives do not carry compaction lineage),
            // so rebase it to the remapped identity before the insert hits
            // the `compaction_lineage_root_id` self-foreign-key.
            row.compaction_lineage_root_id = Some(row.session_id);
            row.parent_session_id = session.parent_source_id.map(|parent| id_map[&parent]);
            row.assistant_name = session.assistant_name.clone();
            if let Some(short_id) = session.short_id.filter(|id| is_crockford_short_id(id)) {
                let exists: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM sessions WHERE project_id = ?1 AND short_id = ?2",
                    params![graph.project_id, short_id],
                    |row| row.get(0),
                )?;
                if exists == 0 {
                    row.short_id = Some(short_id);
                }
            }
            if let (Some(parent_source_id), Some(fork_point_turn_id)) =
                (session.parent_source_id, session.fork_point_turn_id.clone())
            {
                pending_forks.push((
                    row.session_id,
                    parent_source_id,
                    fork_point_turn_id,
                    session.is_assistant_thread,
                ));
            }
            row.fork_point_turn_id = None;
            // The parent/event FK is restored after its event-sequence map is
            // known. Keep the type marker false until that same UPDATE makes
            // the complete thread invariant true.
            row.is_assistant_thread = false;
            row.session_entry_mode = session.session_entry_mode;
            if let Some(active_model) = session.active_model {
                row.provider = Some(active_model.provider);
                row.model = Some(active_model.model);
                row.model_selection_json = Some(active_model.selection_json);
            }
            row.started_at_unix_ms = session.started_at_unix_ms;
            row.last_active_at_unix_ms = session.started_at_unix_ms;
            row.ended_at_unix_ms = session.ended_at_unix_ms;
            row.title = session.title;
            establish_redaction_custody(conn, row.session_id)?;
            let custody = crate::db::sessions::SessionRedactionCustody::require_on_conn(
                conn,
                row.session_id,
            )?;
            Db::insert_session_row_conn(conn, &row, custody)?;
            conn.execute(
                "UPDATE sessions
                    SET parent_session_id = ?1, fork_point_turn_id = ?2, ended_at_unix_ms = ?3,
                        title = ?4, last_active_at_unix_ms = ?5
                  WHERE session_id = ?6",
                params![
                    row.parent_session_id.map(|id| id.to_string()),
                    row.fork_point_turn_id,
                    row.ended_at_unix_ms,
                    row.title,
                    row.last_active_at_unix_ms,
                    row.session_id.to_string(),
                ],
            )?;
            inserted.insert(source_id);
            imported.push(row.session_id);
        }
    }

    restore_delegations(conn, &graph, &id_map, &task_call_id_map)?;
    restore_telemetry_rows(
        conn,
        &graph.inference_calls,
        &graph.tool_calls,
        &id_map,
        &inference_call_id_map,
    )?;
    restore_events_and_artifacts(
        conn,
        graph,
        source_ids,
        id_map,
        task_call_id_map,
        inference_call_id_map,
        imported,
        pending_forks,
        thread_anchors,
    )
}

fn is_crockford_short_id(value: &str) -> bool {
    value.len() == 6
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'0'..=b'9' | b'a'..=b'h' | b'j' | b'k' | b'm' | b'n' | b'p'..=b't' | b'v'..=b'z'
            )
        })
}

fn restore_delegations(
    conn: &Connection,
    graph: &SessionArchiveImportGraph,
    id_map: &BTreeMap<Uuid, Uuid>,
    task_call_id_map: &BTreeMap<String, String>,
) -> Result<()> {
    for job in &graph.delegation_jobs {
        conn.execute(
            "INSERT INTO task_delegation_jobs (
                task_call_id, function_call_id, parent_session_id, parent_agent,
                original_args_json, status, ack_delivered, final_delivered, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
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
    for job in &graph.delegation_jobs {
        for child in &job.children {
            conn.execute(
                "INSERT INTO task_delegation_children (
                    task_call_id, label, child_uuid, child_agent, model, status, report, output_dir,
                    todo_ids_json, result_delivered, started_at, finished_at, created_at,
                    updated_at, requested_cwd, resolved_cwd
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                params![
                    task_call_id_map
                        .get(&job.task_call_id)
                        .unwrap_or(&job.task_call_id),
                    child.label,
                    imported_delegation_child_uuid(
                        task_call_id_map
                            .get(&job.task_call_id)
                            .unwrap_or(&job.task_call_id),
                        &child.label,
                    )
                    .to_string(),
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
    for payload in &graph.delegation_payloads {
        // Load-error sidecars intentionally have no readable body; preserve
        // their archive metadata during parse without creating an invalid row.
        let Some(body) = payload.body.as_deref() else {
            continue;
        };
        conn.execute(
            "INSERT INTO task_delegation_payloads (
                task_call_id, label, payload_hash, parent_session_id, parent_agent,
                function_call_id, child_agent, prompt_byte_len, body_inline, created_at, delivered_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                task_call_id_map
                    .get(&payload.task_call_id)
                    .unwrap_or(&payload.task_call_id),
                payload.label,
                payload.payload_hash,
                id_map[&payload.source_session_id].to_string(),
                payload.parent_agent,
                payload.function_call_id,
                payload.child_agent,
                payload.prompt_byte_len as i64,
                body,
                payload.created_at,
                payload.delivered_at,
            ],
        )?;
    }
    for steer in &graph.delegation_steers {
        conn.execute(
            "INSERT INTO task_delegation_steers (
                task_call_id, label, body, origin_principal, delivered, created_at, delivered_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
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
    Ok(())
}

fn restore_events_and_artifacts(
    conn: &Connection,
    graph: SessionArchiveImportGraph,
    source_ids: BTreeSet<Uuid>,
    id_map: BTreeMap<Uuid, Uuid>,
    task_call_id_map: BTreeMap<String, String>,
    inference_call_id_map: BTreeMap<String, String>,
    imported: Vec<Uuid>,
    pending_forks: Vec<(Uuid, Uuid, String, bool)>,
    thread_anchors: BTreeMap<Uuid, (Uuid, i64)>,
) -> Result<ArchiveImportResult> {
    let provenance_ts = graph
        .events
        .iter()
        .map(|event| event.ts_ms)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| anyhow!("import event timestamp overflows provenance notice timestamp"))?;
    let mut events = graph.events;
    events.sort_by_key(|event| event.seq);
    let mut event_seq_map = BTreeMap::new();
    let mut tandem_sidecars = Vec::new();
    let mut pending_thread_anchors = Vec::new();
    for mut event in events {
        if event.seq <= 0 || event_seq_map.contains_key(&(event.source_session_id, event.seq)) {
            bail!("import archive has an invalid or duplicate session event sequence");
        }
        let mut event_data: Value =
            serde_json::from_str(&event.data_json).context("parsing hydrated import event data")?;
        let has_inference_sidecar = event_data.get("inference_request_sidecar").is_some();
        let has_tandem_sidecar = event_data.get("tandem_inference_sidecar").is_some();
        if (has_inference_sidecar || has_tandem_sidecar)
            && let Some(remapped) = event
                .call_id
                .as_ref()
                .and_then(|id| inference_call_id_map.get(id))
        {
            event.call_id = Some(remapped.clone());
        } else if let Some(remapped) = event
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
            let status = required_sidecar_string(sidecar, "status", "inference request sidecar")?;
            let ordinal = sidecar.get("ordinal").and_then(Value::as_i64).unwrap_or(0);
            let phases = sidecar.get("phases");
            let phase_ms = |key: &str| phases.and_then(|p| p.get(key)).and_then(Value::as_i64);
            Db::insert_inference_request_conn(
                conn,
                &crate::db::session_log::ImportedInferenceRequest {
                    call_id,
                    ordinal,
                    session_id: id_map[&event.source_session_id],
                    ts_ms: event.ts_ms,
                    payload: request,
                    status,
                    provider: sidecar.get("provider").and_then(Value::as_str),
                    model: sidecar.get("model").and_then(Value::as_str),
                    trust: sidecar.get("trust").and_then(Value::as_str),
                    phases: crate::db::session_log::InferencePhaseTimings {
                        first_token_ms: phase_ms("first_token_ms"),
                        completed_ms: phase_ms("completed_ms"),
                        failed_ms: phase_ms("failed_ms"),
                    },
                },
            )?;
        }
        let restored_seq = if event.kind == SessionEventKind::HookRun {
            Db::insert_imported_hook_run_conn(
                conn,
                id_map[&event.source_session_id],
                event.ts_ms,
                &event_data,
            )?
        } else {
            Db::insert_session_event_json_conn(
                conn,
                id_map[&event.source_session_id],
                event.kind,
                event.agent.as_deref(),
                event.call_id.as_deref(),
                SessionEventContext::default(),
                event.ts_ms,
                &event.data_json,
            )?
        };
        event_seq_map.insert((event.source_session_id, event.seq), restored_seq);
        if event.kind == SessionEventKind::ThreadAnchor {
            let (parent_source_id, parent_source_seq) = thread_anchors
                .get(&event.source_session_id)
                .copied()
                .ok_or_else(|| anyhow!("import thread anchor has no validated lineage"))?;
            pending_thread_anchors.push((
                id_map[&event.source_session_id],
                restored_seq,
                parent_source_id,
                parent_source_seq,
            ));
        }
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

    let mut artifact_ids = BTreeSet::new();
    let mut artifact_slots = Vec::with_capacity(graph.text_artifacts.len());
    for artifact in &graph.text_artifacts {
        if !artifact_ids.insert(artifact.source_artifact_id) {
            bail!("import archive repeats a text artifact ID");
        }
        let event_seq = *event_seq_map
            .get(&(artifact.source_session_id, artifact.source_event_seq))
            .ok_or_else(|| {
                anyhow!("text artifact references an event missing from the import graph")
            })?;
        let mut provenance: Value = serde_json::from_str(&artifact.provenance_json)
            .context("text artifact provenance must be JSON")?;
        if artifact.kind == TextArtifactKind::UserInputSource {
            let object = provenance
                .as_object_mut()
                .ok_or_else(|| anyhow!("source artifact provenance must be an object"))?;
            object.insert("event_seq".to_string(), json!(event_seq));
        }
        artifact_slots.push(ImportedTextArtifactSlot {
            source_artifact_id: artifact.source_artifact_id,
            session_id: id_map[&artifact.source_session_id],
            event_seq,
            staged_blob_session_id: artifact.staged_blob_session_id,
            candidate: TextArtifactCandidate {
                relation: artifact.relation,
                projection_slot: artifact.projection_slot,
                kind: artifact.kind,
                capture_reason: artifact.capture_reason,
                content: artifact.content.clone(),
                host_captured_bytes: artifact.host_captured_bytes,
                host_original_bytes: artifact.host_original_bytes,
                host_dropped_bytes: artifact.host_dropped_bytes,
                stored_source_bytes: artifact.stored_source_bytes,
                provenance_json: serde_json::to_string(&provenance)?,
                created_at: artifact.created_at,
            },
            representation: artifact.representation,
        });
    }
    // The relational provenance row is what makes `export_redacted` an
    // archive-only representation at the schema boundary. Raw archive bodies
    // intentionally do not acquire it, and child forks retain it only when
    // copying an already irreversible redacted body.
    let archive_import_id = artifact_slots
        .iter()
        .any(|slot| slot.representation == TextArtifactRepresentation::ExportRedacted)
        .then(Uuid::new_v4);
    if let Some(import_id) = archive_import_id {
        conn.execute(
            "INSERT INTO session_text_artifact_archive_imports (import_id,imported_at) VALUES (?1,?2)",
            params![import_id.to_string(), provenance_ts],
        )?;
    }
    import_text_artifact_slots_conn(conn, &artifact_slots, archive_import_id)?;
    for artifact in &graph.text_artifacts {
        let Some(envelope) = artifact.model_envelope_json.as_deref() else {
            continue;
        };
        if artifact.kind != TextArtifactKind::UserInputSource {
            bail!("only a user-input source may carry a model envelope");
        }
        crate::db::text_artifacts::validate_user_model_envelope(envelope)?;
        let event_seq = event_seq_map[&(artifact.source_session_id, artifact.source_event_seq)];
        conn.execute(
            "INSERT INTO session_user_message_model_envelopes(session_id,event_seq,envelope_json) VALUES(?1,?2,?3)",
            params![id_map[&artifact.source_session_id].to_string(), event_seq, envelope],
        )?;
    }

    for (dest_session_id, parent_source_id, source_seq, is_assistant_thread) in pending_forks {
        let parsed: i64 = source_seq.parse().with_context(|| {
            format!("import fork_point_turn_id `{source_seq}` is not an integer")
        })?;
        let dest_seq = event_seq_map
            .get(&(parent_source_id, parsed))
            .ok_or_else(|| {
                anyhow!(
                    "import fork_point_turn_id `{source_seq}` is missing from parent session events"
                )
            })?;
        conn.execute(
            "UPDATE sessions
                SET fork_point_turn_id = ?1, is_assistant_thread = ?2
              WHERE session_id = ?3",
            params![
                dest_seq.to_string(),
                is_assistant_thread as i64,
                dest_session_id.to_string(),
            ],
        )?;
    }

    // Insertions allocate destination event sequences. Rewrite the validated
    // portable projection only after every parent mapping is known, keeping it
    // identical to the relational parent/fork projection even when the child
    // anchor was restored before its parent event.
    for (thread_id, thread_event_seq, parent_source_id, parent_source_seq) in pending_thread_anchors
    {
        let parent_event_seq = event_seq_map
            .get(&(parent_source_id, parent_source_seq))
            .ok_or_else(|| anyhow!("import thread anchor points to an unrestored parent event"))?;
        let data_json = serde_json::to_string(&json!({
            "parent_session_id": id_map[&parent_source_id],
            "parent_turn_id": parent_event_seq.to_string(),
        }))?;
        conn.execute(
            "UPDATE session_events SET data_json = ?1 WHERE session_id = ?2 AND seq = ?3",
            params![data_json, thread_id.to_string(), thread_event_seq],
        )?;
    }

    for source_id in &source_ids {
        let data_json = serde_json::to_string(&json!({
            "source": "session_import",
            "original_session_id": source_id,
            "redacted": graph.redacted,
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
    Ok(ArchiveImportResult {
        imported,
        redacted: graph.redacted,
    })
}

fn restore_telemetry_rows(
    conn: &Connection,
    inference_calls: &[Value],
    tool_calls: &[Value],
    id_map: &BTreeMap<Uuid, Uuid>,
    inference_call_id_map: &BTreeMap<String, String>,
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
        let source_call_id = required_string(o, "call_id", "inference call index")?;
        let call_id = inference_call_id_map
            .get(&source_call_id)
            .ok_or_else(|| anyhow!("inference call is missing its destination id mapping"))?
            .parse::<Uuid>()
            .context("parsing generated inference call id")?;
        Db::insert_inference_call_conn(
            conn,
            &crate::db::inference_calls::InferenceCallRow {
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
        let _source_event_id = parse_uuid(
            required_string(o, "event_id", "tool call index")?,
            "event_id",
        )?;
        // This audit-row key is global, not scoped by session. Preserve its
        // validated source payload while allocating a fresh destination event
        // identity so repeat imports never collide with an earlier graph.
        let event_id = Uuid::new_v4();
        let recovery_kind = optional_string(o.get("recovery_kind"), "recovery_kind")?;
        let recovery_stage = optional_string(o.get("recovery_stage"), "recovery_stage")?;
        let recovery = match recovery_kind {
            Some(kind) => crate::db::tool_calls::Recovery::Unknown {
                kind,
                stage: recovery_stage,
            },
            None => crate::db::tool_calls::Recovery::Clean,
        };
        let original_input_json = o
            .get("original_input_json")
            .cloned()
            .ok_or_else(|| anyhow!("tool call index lacks original_input_json"))?;
        let wire_input_json = o
            .get("wire_input_json")
            .cloned()
            .ok_or_else(|| anyhow!("tool call index lacks wire_input_json"))?;
        Db::insert_tool_call_conn(
            conn,
            &crate::db::tool_calls::ToolCallEvent {
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

fn build_import_inference_call_id_map(
    graph: &SessionArchiveImportGraph,
) -> Result<BTreeMap<String, String>> {
    let mut source_call_ids = BTreeSet::new();
    for value in &graph.inference_calls {
        let object = value
            .as_object()
            .ok_or_else(|| anyhow!("inference call index entry must be an object"))?;
        let call_id = required_string(object, "call_id", "inference call index")?;
        parse_uuid(call_id.clone(), "call_id")?;
        if !source_call_ids.insert(call_id.to_owned()) {
            bail!("import archive repeats inference call_id {call_id}");
        }
    }
    for event in &graph.events {
        let data: Value = serde_json::from_str(&event.data_json)
            .context("parsing imported event data for inference-id remapping")?;
        if data.get("inference_request_sidecar").is_some()
            || data.get("tandem_inference_sidecar").is_some()
        {
            let call_id = event
                .call_id
                .as_deref()
                .ok_or_else(|| anyhow!("inference sidecar event lacks call_id"))?;
            source_call_ids.insert(call_id.to_owned());
        }
    }
    Ok(source_call_ids
        .into_iter()
        .map(|source_call_id| (source_call_id, Uuid::new_v4().to_string()))
        .collect())
}

fn imported_delegation_child_uuid(task_call_id: &str, label: &str) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(b"flycockpit-imported-delegation-child/v1\0");
    digest.update(task_call_id.as_bytes());
    digest.update(b"\0");
    digest.update(label.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
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

fn required_sidecar_string<'a>(value: &'a Value, key: &str, context: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{context} lacks string {key}"))
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
        .ok_or_else(|| anyhow!("{context} lacks string {key}"))
}

fn optional_string(value: Option<&Value>, key: &str) -> Result<Option<String>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(ToOwned::to_owned)
            .map(Some)
            .ok_or_else(|| anyhow!("import value {key} must be a string or null")),
    }
}

fn required_i64(object: &serde_json::Map<String, Value>, key: &str, context: &str) -> Result<i64> {
    object
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("{context} lacks integer {key}"))
}

fn optional_i64(value: Option<&Value>, key: &str) -> Result<Option<i64>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| anyhow!("import value {key} must be an integer or null")),
    }
}

fn required_bool(
    object: &serde_json::Map<String, Value>,
    key: &str,
    context: &str,
) -> Result<bool> {
    object
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("{context} lacks boolean {key}"))
}

fn parse_uuid(raw: String, key: &str) -> Result<Uuid> {
    Uuid::parse_str(&raw).with_context(|| format!("invalid import {key} UUID {raw}"))
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
        _ => bail!("import {context} has unsupported status {status}"),
    }
}
