use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use uuid::Uuid;

pub use cockpit_db::db::archive_import::{
    ArchiveImportResult as ImportResult, SessionArchiveImportGraph as ImportArchive,
};
#[cfg(test)]
use cockpit_db::db::session_log::SessionEventContext;
use cockpit_db::db::{
    Db,
    archive_import::{
        ImportedArchiveActiveModel, ImportedArchiveDelegationChild as ImportedDelegationChild,
        ImportedArchiveDelegationJob as ImportedDelegationJob,
        ImportedArchiveDelegationPayload as ImportedDelegationPayload,
        ImportedArchiveDelegationSteer as ImportedDelegationSteer,
        ImportedArchiveEvent as ImportedEvent, ImportedArchiveSession as ImportedSession,
        ImportedArchiveTextArtifact as ImportedTextArtifact, validate_thread_anchors,
    },
    session_log::SessionEventKind,
    text_artifacts::{
        CaptureReason, TextArtifactKind, TextArtifactRelation, TextArtifactRepresentation,
    },
};

// Current exports may emit one sidecar per tool or inference event; 16,384 permits
// realistic long-lived session bundles while the independent 1GiB decompressed cap
// bounds archive resource use.
const MAX_IMPORT_ENTRIES: usize = 16_384;
const MAX_IMPORT_UNCOMPRESSED_BYTES: u64 = 1024 * 1024 * 1024;
const EXPORT_SCHEMA: &str = "cockpit-session-export/4";
const INLINE_USER_TEXT_BYTES: usize = 64 * 1024;
const MAX_TEXT_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
const MAX_SESSION_TEXT_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

pub async fn import_archive(db: &Db, archive: ImportArchive) -> Result<ImportResult> {
    let mut archive = archive;
    stage_blob_backed_import_artifacts(db, &mut archive).await?;
    db.import_session_archive_graph(archive).await
}

/// Archive members contain the complete portable body, while the source
/// daemon's pathname is intentionally discarded during parsing.  Recreate a
/// daemon-owned blob before the one database import transaction starts; its
/// cleanup intent remains durable until that transaction claims it alongside
/// the destination artifact row.
async fn stage_blob_backed_import_artifacts(db: &Db, archive: &mut ImportArchive) -> Result<()> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("reading import blob staging clock")?
        .as_millis()
        .try_into()
        .context("import blob staging clock exceeds i64")?;
    for artifact_index in 0..archive.text_artifacts.len() {
        let artifact = &archive.text_artifacts[artifact_index];
        let source_session_id = artifact.source_session_id;
        let source_event_seq = artifact.source_event_seq;
        let projection_slot = artifact.projection_slot;
        let kind = artifact.kind;
        let content = artifact.content.clone();
        let mut provenance: Value = serde_json::from_str(&artifact.provenance_json)
            .context("parsing imported text artifact provenance for blob staging")?;
        // `preview_lines` is the durable ingress-pseudofile contract.  It is
        // carried by tool results, user sources, and rewritten user
        // projections, including the latter which deliberately has no
        // `source` tag of its own.
        let needs_blob = provenance
            .as_object()
            .is_some_and(|object| object.contains_key("preview_lines"));
        if !needs_blob {
            archive.text_artifacts[artifact_index].staged_blob_session_id = None;
            continue;
        }
        let path = crate::text_artifact_blob::new_path(source_session_id);
        db.stage_text_artifact_blob_cleanup_intent(path.clone(), source_session_id, now_ms)
            .await
            .context("staging imported text artifact blob cleanup")?;
        crate::text_artifact_blob::write_at(&path, &content)
            .context("writing imported text artifact blob")?;
        let original_provenance = provenance.clone();
        provenance
            .as_object_mut()
            .expect("object checked above")
            .insert("blob_path".to_owned(), Value::String(path.clone()));
        if kind == TextArtifactKind::ToolResult {
            update_imported_tool_projection_blob_path(
                archive,
                source_session_id,
                source_event_seq,
                projection_slot,
                &original_provenance,
                &path,
            )?;
        }
        archive.text_artifacts[artifact_index].provenance_json =
            serde_json::to_string(&provenance)?;
        archive.text_artifacts[artifact_index].staged_blob_session_id = Some(source_session_id);
    }
    Ok(())
}

/// Tool events duplicate their immutable artifact provenance in the durable
/// projection state.  When import substitutes the portable archive body with
/// a destination daemon blob, update that paired state in lockstep; leaving
/// the source-machine path out of either side would make rehydration fail
/// closed on the mismatch.
fn update_imported_tool_projection_blob_path(
    archive: &mut ImportArchive,
    source_session_id: Uuid,
    source_event_seq: i64,
    projection_slot: Option<i64>,
    original_provenance: &Value,
    blob_path: &str,
) -> Result<()> {
    let event = archive
        .events
        .iter_mut()
        .find(|event| event.source_session_id == source_session_id && event.seq == source_event_seq)
        .ok_or_else(|| anyhow!("imported tool artifact lacks its owner event"))?;
    let mut data: Value =
        serde_json::from_str(&event.data_json).context("parsing imported tool owner event")?;
    let projection = match event.kind {
        SessionEventKind::ToolCall => data
            .get_mut("artifact_projection")
            .ok_or_else(|| anyhow!("imported tool artifact owner lacks its projection"))?,
        SessionEventKind::ContextPruned => data
            .get_mut("artifact_projections")
            .and_then(Value::as_array_mut)
            .and_then(|projections| {
                projections.iter_mut().find(|projection| {
                    projection.get("projection_slot").and_then(Value::as_i64) == projection_slot
                })
            })
            .ok_or_else(|| anyhow!("imported pruned tool artifact lacks its projection"))?,
        _ => bail!("imported tool artifact has a non-tool owner event"),
    };
    let provenance = projection
        .get_mut("provenance")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("imported tool projection lacks object provenance"))?;
    if Value::Object(provenance.clone()) != *original_provenance {
        bail!("imported tool projection provenance differs from its artifact");
    }
    provenance.insert("blob_path".to_owned(), Value::String(blob_path.to_owned()));
    event.data_json = serde_json::to_string(&data)?;
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
    let mut archive_paths = BTreeSet::new();
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let name = entry.name().to_string();
        if name.starts_with('/') || name.split('/').any(|part| part == "..") {
            bail!("import archive contains unsafe path `{name}`");
        }
        if name.is_empty() || name.split('/').any(|part| part.is_empty()) {
            bail!("import archive contains malformed path `{name}`");
        }
        if !archive_paths.insert(name.clone()) {
            bail!("import archive contains duplicate path `{name}`");
        }
        total = total
            .checked_add(entry.size())
            .ok_or_else(|| anyhow!("import archive decompressed byte accounting overflow"))?;
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
    // The anchor event and relational fork fields are two durable projections
    // of one originating parent message. Reject a malformed graph before any
    // blob staging or database work.
    validate_thread_anchors(&sessions, &events)?;
    let text_artifacts = parse_text_artifacts(&mut archive, &archive_paths)?;
    validate_text_artifact_graph(&sessions, &events, &text_artifacts)?;
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
        text_artifacts,
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

fn parse_text_artifacts(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
    archive_paths: &BTreeSet<String>,
) -> Result<Vec<ImportedTextArtifact>> {
    let index = read_json_entry(archive, "text_artifacts/index.json")?;
    let entries = index
        .as_array()
        .ok_or_else(|| anyhow!("text artifact index must be an array"))?;
    let mut seen_artifact_ids = BTreeSet::new();
    let mut seen_content_paths = BTreeSet::new();
    let mut expected_paths = BTreeSet::from(["text_artifacts/index.json".to_owned()]);
    let mut parsed = Vec::with_capacity(entries.len());
    for value in entries {
        let object = value
            .as_object()
            .ok_or_else(|| anyhow!("text artifact index entry must be an object"))?;
        let representation_meta = object
            .get("representation")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("text artifact representation is missing"))?;
        let representation_mode =
            required_string(representation_meta, "mode", "text artifact representation")?;
        let representation = match representation_mode.as_str() {
            "raw" => TextArtifactRepresentation::Raw,
            "redacted_length_preserving" => TextArtifactRepresentation::ExportRedacted,
            _ => bail!("unsupported text artifact representation"),
        };
        let source_artifact_id = parse_uuid(
            required_string(object, "artifact_id", "text artifact index")?,
            "artifact_id",
        )?;
        if !seen_artifact_ids.insert(source_artifact_id) {
            bail!("text artifact index repeats an artifact ID");
        }
        let file = required_string(
            representation_meta,
            "content_file",
            "text artifact representation",
        )?;
        let expected_file = format!("text_artifacts/{source_artifact_id}.txt");
        if file != expected_file {
            bail!("text artifact content file is not its canonical safe path");
        }
        if !seen_content_paths.insert(file.clone()) || !archive_paths.contains(&file) {
            bail!("text artifact content file is duplicate or missing");
        }
        expected_paths.insert(file.clone());
        let content = read_text_entry(archive, &file)?;
        let content_bytes: usize = required_i64(
            representation_meta,
            "content_bytes",
            "text artifact representation",
        )?
        .try_into()?;
        if content_bytes == 0
            || content_bytes > MAX_TEXT_ARTIFACT_BYTES
            || content.len() != content_bytes
        {
            bail!("text artifact content byte accounting mismatch");
        }
        let stored_source_bytes: usize =
            required_i64(object, "stored_source_bytes", "text artifact index")?.try_into()?;
        if content_bytes != stored_source_bytes {
            bail!("text artifact representation must preserve stored source bytes");
        }
        let source_event_seq = required_i64(object, "event_seq", "text artifact index")?;
        if source_event_seq <= 0 {
            bail!("text artifact event sequence must be positive");
        }
        let host_captured_bytes: usize =
            required_i64(object, "host_captured_bytes", "text artifact index")?.try_into()?;
        let host_original_bytes: usize =
            required_i64(object, "host_original_bytes", "text artifact index")?.try_into()?;
        let host_dropped_bytes: usize =
            required_i64(object, "host_dropped_bytes", "text artifact index")?.try_into()?;
        if host_original_bytes < host_captured_bytes
            || host_dropped_bytes != host_original_bytes - host_captured_bytes
            || stored_source_bytes > host_captured_bytes
        {
            bail!("text artifact host/source accounting is invalid");
        }
        let provenance = object
            .get("provenance")
            .ok_or_else(|| anyhow!("text artifact provenance missing"))?;
        if !provenance.is_object() {
            bail!("text artifact provenance must be an object");
        }
        // The archive member is the authoritative full body.  Its source
        // machine's daemon-local pathname is neither portable nor valid in
        // the destination, so preserve semantic provenance but never import a
        // dangling disk reference.
        let mut provenance = provenance.clone();
        provenance
            .as_object_mut()
            .expect("object checked above")
            .remove("blob_path");
        parsed.push(ImportedTextArtifact {
            source_artifact_id,
            source_session_id: parse_uuid(
                required_string(object, "session_id", "text artifact index")?,
                "session_id",
            )?,
            source_event_seq,
            relation: serde_json::from_value(
                object
                    .get("relation")
                    .cloned()
                    .ok_or_else(|| anyhow!("text artifact relation missing"))?,
            )?,
            projection_slot: optional_i64(object.get("projection_slot"), "projection_slot")?,
            kind: serde_json::from_value(
                object
                    .get("kind")
                    .cloned()
                    .ok_or_else(|| anyhow!("text artifact kind missing"))?,
            )?,
            capture_reason: serde_json::from_value(
                object
                    .get("capture_reason")
                    .cloned()
                    .ok_or_else(|| anyhow!("text artifact capture reason missing"))?,
            )?,
            provenance_json: serde_json::to_string(&provenance)?,
            host_captured_bytes,
            host_original_bytes,
            host_dropped_bytes,
            stored_source_bytes,
            representation,
            created_at: required_i64(object, "created_at", "text artifact index")?,
            content,
            staged_blob_session_id: None,
            model_envelope_json: match object.get("model_envelope") {
                None | Some(Value::Null) => None,
                Some(Value::String(value)) if value.len() <= 131_072 => Some(value.clone()),
                Some(_) => bail!("text artifact model envelope is invalid"),
            },
        });
    }
    for path in archive_paths
        .iter()
        .filter(|path| path.starts_with("text_artifacts/"))
    {
        if !expected_paths.contains(path) {
            bail!("text artifact directory contains an unindexed member");
        }
    }
    Ok(parsed)
}

/// Validate the complete immutable-artifact ownership graph before the import
/// transaction writes a destination session.  The DB repeats these checks at
/// the relational boundary, but doing them here keeps malformed archives from
/// partially constructing unrelated imported rows before a late artifact
/// failure rolls the outer transaction back.
fn validate_text_artifact_graph(
    sessions: &[ImportedSession],
    events: &[ImportedEvent],
    artifacts: &[ImportedTextArtifact],
) -> Result<()> {
    let session_ids = sessions
        .iter()
        .map(|session| session.source_id)
        .collect::<BTreeSet<_>>();
    if session_ids.len() != sessions.len() {
        bail!("import archive lists a session more than once");
    }

    let mut events_by_key = BTreeMap::<(Uuid, i64), &ImportedEvent>::new();
    for event in events {
        if event.seq <= 0 || !session_ids.contains(&event.source_session_id) {
            bail!("text artifact graph contains an invalid event owner");
        }
        if events_by_key
            .insert((event.source_session_id, event.seq), event)
            .is_some()
        {
            bail!("text artifact graph repeats an event owner");
        }
    }

    let mut slots = BTreeSet::new();
    let mut source_by_event = BTreeMap::<(Uuid, i64), &ImportedTextArtifact>::new();
    let mut quota_by_session = BTreeMap::<Uuid, usize>::new();
    for artifact in artifacts {
        let event = events_by_key
            .get(&(artifact.source_session_id, artifact.source_event_seq))
            .ok_or_else(|| {
                anyhow!("text artifact references an event missing from the import graph")
            })?;
        let slot_key = (
            artifact.source_session_id,
            artifact.source_event_seq,
            artifact.relation.as_str(),
            artifact.projection_slot,
        );
        if !slots.insert(slot_key) {
            bail!("text artifact graph repeats an owner slot");
        }
        let quota = quota_by_session
            .entry(artifact.source_session_id)
            .or_default();
        *quota = quota
            .checked_add(artifact.content.len())
            .ok_or_else(|| anyhow!("text artifact quota accounting overflow"))?;
        if *quota > MAX_SESSION_TEXT_ARTIFACT_BYTES {
            bail!("text artifact graph exceeds a session quota");
        }
        validate_import_artifact_provenance(artifact, event)?;
        match (
            artifact.kind,
            artifact.capture_reason,
            artifact.relation,
            artifact.projection_slot,
        ) {
            (
                TextArtifactKind::ToolResult,
                CaptureReason::DisplayTruncation | CaptureReason::PruneBoundary,
                TextArtifactRelation::ModelContextToolResult,
                Some(slot),
            ) if slot >= 0
                && matches!(
                    event.kind,
                    SessionEventKind::ToolCall | SessionEventKind::ContextPruned
                ) => {}
            (
                TextArtifactKind::UserInputSource,
                CaptureReason::OversizedUserInput,
                TextArtifactRelation::SourceUserInput,
                None,
            ) if event.kind == SessionEventKind::UserMessage => {
                if artifact.content.len()
                    < crate::db::text_artifacts::MIN_USER_ARTIFACT_SOURCE_BYTES
                {
                    bail!("user input source is below the supported spill threshold");
                }
                let envelope = artifact
                    .model_envelope_json
                    .as_deref()
                    .ok_or_else(|| anyhow!("oversized user source lacks its model envelope"))?;
                crate::engine::text_artifact_frame::render_accepted_user_envelope(envelope, "")
                    .context("text artifact model envelope is malformed")?;
                if source_by_event
                    .insert(
                        (artifact.source_session_id, artifact.source_event_seq),
                        artifact,
                    )
                    .is_some()
                {
                    bail!("user message owns more than one source text artifact");
                }
            }
            (
                TextArtifactKind::UserInputProjection,
                CaptureReason::OversizedUserInput,
                TextArtifactRelation::ModelUserInputProjection,
                Some(0),
            ) if event.kind == SessionEventKind::UserMessage => {}
            _ => bail!("text artifact kind/reason/owner binding is invalid"),
        }
    }

    for ((session_id, event_seq), source) in &source_by_event {
        let event = events_by_key[&(*session_id, *event_seq)];
        let data: Value = serde_json::from_str(&event.data_json)
            .context("parsing source user event while validating text artifacts")?;
        let text = data
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("source user artifact event lacks canonical text"))?;
        let provenance: Value = serde_json::from_str(&source.provenance_json)?;
        let preview_lines = provenance
            .get("preview_lines")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| *value > 0)
            .unwrap_or(crate::agents::ContextPolicy::DEFAULT_ARTIFACT_PREVIEW_LINES);
        if text
            != crate::engine::text_artifact_frame::utf8_preview_lines(
                &source.content,
                preview_lines,
            )
        {
            bail!("source user artifact differs from its bounded event preview");
        }
        if provenance.get("event_seq").and_then(Value::as_i64) != Some(*event_seq) {
            bail!("source user artifact provenance does not bind its event");
        }
    }

    for artifact in artifacts {
        if artifact.kind != TextArtifactKind::UserInputProjection {
            continue;
        }
        let owner = (artifact.source_session_id, artifact.source_event_seq);
        let source = source_by_event
            .get(&owner)
            .ok_or_else(|| anyhow!("user projection lacks an owned source artifact"))?;
        if artifact.content == source.content {
            bail!("equal user projection must be omitted");
        }
        let provenance: Value = serde_json::from_str(&artifact.provenance_json)?;
        let expected_source_id = source.source_artifact_id.to_string();
        if provenance.get("source_artifact_id").and_then(Value::as_str)
            != Some(expected_source_id.as_str())
            || provenance
                .get("preprocessing_version")
                .and_then(Value::as_i64)
                != Some(1)
        {
            bail!("user projection provenance does not bind its source artifact");
        }
    }

    for event in events {
        if event.kind != SessionEventKind::UserMessage {
            continue;
        }
        let data: Value = serde_json::from_str(&event.data_json)
            .context("parsing user event while validating text artifacts")?;
        let Some(text) = data.get("text").and_then(Value::as_str) else {
            continue;
        };
        let has_source_artifact =
            source_by_event.contains_key(&(event.source_session_id, event.seq));
        if has_source_artifact && user_event_has_media_or_file_parts(&data) {
            bail!("oversized user event cannot carry media/file parts");
        }
        if text.len() > INLINE_USER_TEXT_BYTES && !has_source_artifact {
            bail!("oversized user event lacks its source text artifact");
        }
    }
    validate_tool_artifact_projection_graph(&events_by_key, artifacts)?;
    Ok(())
}

/// Returns true for a nonempty media/file part or a malformed non-array
/// declaration. Oversized typed-source events are text-only by construction,
/// so archives must not restore either shape.
fn user_event_has_media_or_file_parts(data: &Value) -> bool {
    const MEDIA_OR_FILE_KEYS: [&str; 5] =
        ["images", "image_refs", "attachments", "files", "file_refs"];

    data.as_object().is_some_and(|object| {
        MEDIA_OR_FILE_KEYS.iter().any(|key| match object.get(*key) {
            Some(Value::Array(parts)) => !parts.is_empty(),
            Some(_) => true,
            None => false,
        })
    })
}

/// The database repeats these closed provenance checks when it attaches an
/// owner ref.  Import performs them before opening its one writer transaction
/// so malformed archive metadata cannot get as far as a destination event.
fn validate_import_artifact_provenance(
    artifact: &ImportedTextArtifact,
    event: &ImportedEvent,
) -> Result<()> {
    if artifact.provenance_json.len() > 256 {
        bail!("text artifact provenance exceeds 256 UTF-8 bytes");
    }
    let value: Value = serde_json::from_str(&artifact.provenance_json)
        .context("parsing text artifact provenance during import preflight")?;
    if !provenance_strings_are_bounded(&value) {
        bail!("text artifact provenance has oversized or control-bearing text");
    }
    let provenance = value
        .as_object()
        .ok_or_else(|| anyhow!("text artifact provenance must be an object"))?;
    match artifact.kind {
        TextArtifactKind::ToolResult => {
            require_provenance_keys(provenance, &["agent_id", "tool", "call_id"])?;
            let agent = provenance
                .get("agent_id")
                .ok_or_else(|| anyhow!("tool artifact provenance lacks agent_id"))?;
            match (agent, event.agent.as_deref()) {
                (Value::Null, None) => {}
                (Value::String(agent), Some(event_agent))
                    if valid_provenance_identifier(agent) && agent == event_agent => {}
                _ => bail!("tool artifact provenance agent does not match its event"),
            }
            let tool = required_provenance_identifier(provenance, "tool")?;
            let call_id = required_provenance_identifier(provenance, "call_id")?;
            let _ = tool;
            if event.kind == SessionEventKind::ToolCall && event.call_id.as_deref() != Some(call_id)
            {
                bail!("tool artifact provenance call id does not match its event");
            }
        }
        TextArtifactKind::UserInputSource => {
            require_provenance_keys(provenance, &["event_seq"])?;
            if provenance.get("event_seq").and_then(Value::as_i64)
                != Some(artifact.source_event_seq)
            {
                bail!("source artifact provenance does not bind its event");
            }
        }
        TextArtifactKind::UserInputProjection => {
            require_provenance_keys(provenance, &["source_artifact_id", "preprocessing_version"])?;
            let source = provenance
                .get("source_artifact_id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("projection provenance lacks source artifact id"))?;
            Uuid::parse_str(source)
                .context("projection provenance has invalid source artifact id")?;
            if provenance
                .get("preprocessing_version")
                .and_then(Value::as_i64)
                != Some(1)
            {
                bail!("projection provenance has an invalid preprocessing version");
            }
        }
    }
    Ok(())
}

fn provenance_strings_are_bounded(value: &Value) -> bool {
    match value {
        Value::String(text) => {
            text.len() <= 256 && !text.bytes().any(|byte| byte.is_ascii_control())
        }
        Value::Array(values) => values.iter().all(provenance_strings_are_bounded),
        Value::Object(values) => values.values().all(provenance_strings_are_bounded),
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
    }
}

fn require_exact_provenance_keys(
    provenance: &serde_json::Map<String, Value>,
    expected: &[&str],
) -> Result<()> {
    if provenance.len() != expected.len()
        || !expected.iter().all(|key| provenance.contains_key(*key))
    {
        bail!("text artifact provenance has an invalid shape");
    }
    Ok(())
}

fn require_provenance_keys(
    provenance: &serde_json::Map<String, Value>,
    required: &[&str],
) -> Result<()> {
    if !required.iter().all(|key| provenance.contains_key(*key))
        || !provenance.keys().all(|key| {
            required.contains(&key.as_str()) || key == "source" || key == "preview_lines"
        })
    {
        bail!("text artifact provenance has unexpected keys");
    }
    if let Some(source) = provenance.get("source") {
        if !matches!(source.as_str(), Some("tool_result") | Some("user_paste")) {
            bail!("text artifact provenance source is invalid");
        }
    }
    if let Some(lines) = provenance.get("preview_lines") {
        if !matches!(lines.as_u64(), Some(1..=10_000)) {
            bail!("text artifact provenance preview line count is invalid");
        }
    }
    Ok(())
}

fn valid_provenance_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn required_provenance_identifier<'a>(
    provenance: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str> {
    let value = provenance
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("text artifact provenance lacks {key}"))?;
    if !valid_provenance_identifier(value) {
        bail!("text artifact provenance {key} is invalid");
    }
    Ok(value)
}

/// Verify the complete durable projection-state graph before writes. Available
/// tool states and immutable owner refs are a bijection; state-array ordinals
/// are the stable prune slots, never a row-order convention.
fn validate_tool_artifact_projection_graph(
    events_by_key: &BTreeMap<(Uuid, i64), &ImportedEvent>,
    artifacts: &[ImportedTextArtifact],
) -> Result<()> {
    let mut artifacts_by_slot = BTreeMap::<(Uuid, i64, i64), &ImportedTextArtifact>::new();
    for artifact in artifacts
        .iter()
        .filter(|artifact| artifact.relation == TextArtifactRelation::ModelContextToolResult)
    {
        let slot = artifact
            .projection_slot
            .ok_or_else(|| anyhow!("tool artifact owner lacks a projection slot"))?;
        if artifacts_by_slot
            .insert(
                (artifact.source_session_id, artifact.source_event_seq, slot),
                artifact,
            )
            .is_some()
        {
            bail!("tool artifact graph repeats an owner slot");
        }
    }

    let mut matched_available_slots = BTreeSet::new();
    for ((session_id, event_seq), event) in events_by_key {
        let data: Value = serde_json::from_str(&event.data_json)
            .context("parsing event data while validating text artifact projection state")?;
        let data = data
            .as_object()
            .ok_or_else(|| anyhow!("artifact-owning event data must be an object"))?;
        match event.kind {
            SessionEventKind::ToolCall => {
                if data.get("artifact_projections").is_some() {
                    bail!("ordinary tool event has a prune projection array");
                }
                match data.get("artifact_projection") {
                    Some(projection) => {
                        let artifact = artifacts_by_slot
                            .get(&(*session_id, *event_seq, 0))
                            .copied();
                        if validate_tool_artifact_projection_state(projection, artifact, 0)? {
                            matched_available_slots.insert((*session_id, *event_seq, 0));
                        }
                    }
                    None if artifacts_by_slot.contains_key(&(*session_id, *event_seq, 0)) => {
                        bail!("tool artifact owner has no durable projection state")
                    }
                    None => {}
                }
            }
            SessionEventKind::ContextPruned => {
                if data.get("artifact_projection").is_some() {
                    bail!("prune event has an ordinary tool projection state");
                }
                match data.get("artifact_projections") {
                    Some(Value::Array(projections)) => {
                        for (ordinal, projection) in projections.iter().enumerate() {
                            let slot: i64 = ordinal
                                .try_into()
                                .map_err(|_| anyhow!("prune projection slot overflows i64"))?;
                            let artifact = artifacts_by_slot
                                .get(&(*session_id, *event_seq, slot))
                                .copied();
                            if validate_tool_artifact_projection_state(projection, artifact, slot)?
                            {
                                matched_available_slots.insert((*session_id, *event_seq, slot));
                            }
                        }
                    }
                    Some(_) => bail!("prune artifact projections must be an array"),
                    None if artifacts_by_slot
                        .keys()
                        .any(|(owner, seq, _)| owner == session_id && seq == event_seq) =>
                    {
                        bail!("prune artifact owner has no durable projection states")
                    }
                    None => {}
                }
            }
            _ => {
                if artifacts_by_slot
                    .keys()
                    .any(|(owner, seq, _)| owner == session_id && seq == event_seq)
                {
                    bail!("tool artifact relation is attached to a non-owning event");
                }
            }
        }
    }
    if matched_available_slots.len() != artifacts_by_slot.len()
        || artifacts_by_slot
            .keys()
            .any(|slot| !matched_available_slots.contains(slot))
    {
        bail!("tool artifact owner has no matching available projection state");
    }
    Ok(())
}

/// Return whether a state is available. An available state must join one
/// immutable artifact; an unavailable state must join none.
fn validate_tool_artifact_projection_state(
    projection: &Value,
    artifact: Option<&ImportedTextArtifact>,
    expected_slot: i64,
) -> Result<bool> {
    let projection = projection
        .as_object()
        .ok_or_else(|| anyhow!("tool artifact projection must be an object"))?;
    const FIELDS: &[&str] = &[
        "version",
        "status",
        "reason",
        "kind",
        "capture_reason",
        "projection_slot",
        "provenance",
        "host_captured_bytes",
        "host_original_bytes",
        "host_dropped_bytes",
        "stored_source_bytes",
        "content_bytes",
        "line_count",
        "preview_head",
        "preview_tail",
    ];
    require_exact_provenance_keys(projection, FIELDS)
        .context("tool artifact projection has an invalid shape")?;
    if projection.get("version").and_then(Value::as_i64) != Some(1)
        || projection.get("projection_slot").and_then(Value::as_i64) != Some(expected_slot)
        || projection.get("kind").and_then(Value::as_str) != Some("tool_result")
    {
        bail!("tool artifact projection has an invalid version, kind, or slot");
    }
    let capture_reason = projection
        .get("capture_reason")
        .and_then(Value::as_str)
        .filter(|reason| matches!(*reason, "display_truncation" | "prune_boundary"))
        .ok_or_else(|| anyhow!("tool artifact projection has an invalid capture reason"))?;
    let provenance = projection
        .get("provenance")
        .ok_or_else(|| anyhow!("tool artifact projection lacks provenance"))?;
    if !provenance_strings_are_bounded(provenance) {
        bail!("tool artifact projection provenance has unsafe text");
    }
    let provenance = provenance
        .as_object()
        .ok_or_else(|| anyhow!("tool artifact projection provenance must be an object"))?;
    let valid_provenance_keys = ["agent_id", "tool", "call_id", "source", "preview_lines"];
    if !provenance.contains_key("agent_id")
        || !provenance.contains_key("tool")
        || !provenance.contains_key("call_id")
        || !provenance
            .keys()
            .all(|key| valid_provenance_keys.contains(&key.as_str()))
    {
        bail!("tool artifact projection provenance has an invalid shape");
    }
    if provenance.contains_key("source")
        && provenance.get("source").and_then(Value::as_str) != Some("tool_result")
    {
        bail!("tool artifact projection provenance source is invalid");
    }
    if let Some(preview_lines) = provenance.get("preview_lines")
        && !matches!(preview_lines.as_u64(), Some(1..=10_000))
    {
        bail!("tool artifact projection provenance preview_lines is invalid");
    }
    let agent = provenance
        .get("agent_id")
        .ok_or_else(|| anyhow!("tool artifact projection provenance lacks agent_id"))?;
    if !agent.is_null() && !agent.as_str().is_some_and(valid_provenance_identifier) {
        bail!("tool artifact projection provenance agent_id is invalid");
    }
    required_provenance_identifier(provenance, "tool")?;
    required_provenance_identifier(provenance, "call_id")?;

    let numeric = |field: &str| -> Result<usize> {
        projection
            .get(field)
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow!("tool artifact projection lacks {field}"))?
            .try_into()
            .map_err(|_| anyhow!("tool artifact projection {field} exceeds usize"))
    };
    let host_captured_bytes = numeric("host_captured_bytes")?;
    let host_original_bytes = numeric("host_original_bytes")?;
    let host_dropped_bytes = numeric("host_dropped_bytes")?;
    let stored_source_bytes = numeric("stored_source_bytes")?;
    let content_bytes = numeric("content_bytes")?;
    let _line_count = numeric("line_count")?;
    if host_original_bytes < host_captured_bytes
        || host_dropped_bytes != host_original_bytes - host_captured_bytes
        || stored_source_bytes > host_captured_bytes
        || content_bytes == 0
    {
        bail!("tool artifact projection has invalid byte accounting");
    }
    let preview = |field: &str| -> Result<&str> {
        let value = projection
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("tool artifact projection lacks {field}"))?;
        if value.len() > 16 * 1024 {
            bail!("tool artifact projection {field} exceeds the preview cap");
        }
        Ok(value)
    };
    let preview_head = preview("preview_head")?;
    let preview_tail = preview("preview_tail")?;

    match projection.get("status").and_then(Value::as_str) {
        Some("available") => {
            if projection.get("reason") != Some(&Value::Null) {
                bail!("available tool artifact projection has a reason");
            }
            let artifact = artifact
                .ok_or_else(|| anyhow!("available tool projection lacks an artifact owner"))?;
            if artifact.capture_reason.as_str() != capture_reason
                || artifact.host_captured_bytes != host_captured_bytes
                || artifact.host_original_bytes != host_original_bytes
                || artifact.host_dropped_bytes != host_dropped_bytes
                || artifact.stored_source_bytes != stored_source_bytes
                || artifact.content.len() != content_bytes
            {
                bail!("available tool artifact projection differs from its sidecar");
            }
            let artifact_provenance: Value = serde_json::from_str(&artifact.provenance_json)
                .context("parsing artifact provenance while validating projection state")?;
            if artifact_provenance != Value::Object(provenance.clone()) {
                bail!("available tool artifact projection provenance differs from its sidecar");
            }
            let preview_lines = provenance
                .get("preview_lines")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(crate::agents::ContextPolicy::DEFAULT_ARTIFACT_PREVIEW_LINES);
            let expected_head = crate::engine::text_artifact_frame::utf8_preview_lines(
                &artifact.content,
                preview_lines,
            );
            if projection.get("line_count").and_then(Value::as_u64)
                != Some(artifact.content.lines().count() as u64)
                || preview_head != expected_head
                || !preview_tail.is_empty()
            {
                bail!("available tool artifact projection previews differ from its sidecar");
            }
            Ok(true)
        }
        Some("unavailable") => {
            if artifact.is_some() {
                bail!("unavailable tool projection has an artifact owner");
            }
            if !matches!(
                projection.get("reason").and_then(Value::as_str),
                Some("artifact_limit" | "session_quota" | "persistence_unavailable")
            ) {
                bail!("unavailable tool projection has an invalid reason");
            }
            Ok(false)
        }
        _ => bail!("tool artifact projection has an invalid status"),
    }
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
    let session_entry_mode =
        required_string(object, "session_entry_mode", "import manifest session")?;
    anyhow::ensure!(
        matches!(
            session_entry_mode.as_str(),
            "code" | "assistant" | "computer"
        ),
        "import manifest session has invalid session_entry_mode"
    );
    let parent_source_id = optional_uuid(object.get("parent_session_id"), "parent_session_id")?;
    let fork_point_turn_id =
        optional_string(object.get("fork_point_turn_id"), "fork_point_turn_id")?;
    let assistant_name = optional_string(
        Some(
            object
                .get("assistant_name")
                .ok_or_else(|| anyhow!("import manifest session lacks assistant_name"))?,
        ),
        "assistant_name",
    )?;
    let is_assistant_thread =
        required_bool(object, "is_assistant_thread", "import manifest session")?;
    anyhow::ensure!(
        !is_assistant_thread
            || (parent_source_id.is_some()
                && fork_point_turn_id.is_some()
                && assistant_name.is_some()),
        "import manifest assistant thread lacks its parent, anchor, or assistant owner"
    );
    Ok(ImportedSession {
        source_id: parse_uuid(
            required_string(object, "session_id", "import manifest session")?,
            "session_id",
        )?,
        parent_source_id,
        short_id: optional_string(object.get("short_id"), "short_id")?,
        fork_point_turn_id,
        assistant_name,
        is_assistant_thread,
        active_model: match object.get("active_model") {
            Some(Value::Null) => None,
            Some(value) => {
                let active_model: cockpit_config::config::providers::ActiveModelRef =
                    serde_json::from_value(value.clone())
                        .context("decoding import manifest session active_model")?;
                active_model
                    .validate()
                    .map_err(|error| anyhow!("invalid import manifest active_model: {error}"))?;
                Some(ImportedArchiveActiveModel {
                    provider: active_model.provider.clone(),
                    model: active_model.model.clone(),
                    selection_json: serde_json::to_string(&active_model)
                        .context("encoding import manifest session active_model")?,
                })
            }
            None => bail!("import manifest session lacks active_model"),
        },
        session_entry_mode,
        active_agent: required_string(object, "active_agent", "import manifest session")?,
        started_at_unix_ms: required_i64(object, "started_at_unix_ms", "import manifest session")?,
        ended_at_unix_ms: optional_i64(object.get("ended_at_unix_ms"), "ended_at_unix_ms")?,
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
        "tool_call_scheduling" => ToolCallScheduling,
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
        "hook_run" => HookRun,
        "agent_tree" => AgentTree,
        _ => bail!("unsupported import event type `{raw}`"),
    };
    Ok(kind)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use rusqlite::OptionalExtension;
    use zip::write::{SimpleFileOptions, ZipWriter};

    #[test]
    fn queued_fcm2_limit_matches_protocol_and_shared_fixture() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../packages/cockpit-protocol/fixtures/send-user-message-v2-canonical-vectors.json"
        ))
        .unwrap();
        assert_eq!(
            cockpit_db::db::message_attachments::MAX_QUEUED_CANONICAL_MESSAGE_BYTES,
            crate::proto_crate::send_user_message_v2::MAX_CANONICAL_SEND_USER_MESSAGE_V2_BYTES
        );
        assert_eq!(
            fixture["limits"]["fcm2_max_bytes"].as_u64(),
            Some(cockpit_db::db::message_attachments::MAX_QUEUED_CANONICAL_MESSAGE_BYTES as u64)
        );
    }

    #[tokio::test]
    async fn import_persists_deterministic_child_uuid_for_legacy_delegation_archives() {
        let db = Db::open_in_memory().unwrap();
        let source_session_id = Uuid::new_v4();
        let archive = ImportArchive {
            project_id: "import-test".into(),
            project_root: "/tmp/import-test".into(),
            redacted: true,
            sessions: vec![ImportedSession {
                source_id: source_session_id,
                parent_source_id: None,
                short_id: Some("mprt01".into()),
                fork_point_turn_id: None,
                assistant_name: None,
                is_assistant_thread: false,
                active_model: None,
                session_entry_mode: "code".into(),
                active_agent: "Build".into(),
                started_at_unix_ms: 1,
                ended_at_unix_ms: None,
                title: Some("Imported".into()),
            }],
            events: Vec::new(),
            text_artifacts: Vec::new(),
            delegation_jobs: vec![ImportedDelegationJob {
                task_call_id: "legacy-task".into(),
                function_call_id: None,
                parent_source_id: source_session_id,
                parent_agent: "Build".into(),
                original_args_json: None,
                status: "completed".into(),
                ack_delivered: true,
                final_delivered: true,
                created_at: 1,
                updated_at: 2,
                children: vec![ImportedDelegationChild {
                    label: "worker".into(),
                    child_agent: "worker".into(),
                    model: None,
                    status: "completed".into(),
                    report: None,
                    output_dir: None,
                    todo_ids_json: None,
                    result_delivered: true,
                    started_at: Some(1),
                    finished_at: Some(2),
                    created_at: 1,
                    updated_at: 2,
                    requested_cwd: None,
                    resolved_cwd: None,
                }],
            }],
            delegation_payloads: Vec::new(),
            delegation_steers: Vec::new(),
            inference_calls: Vec::new(),
            tool_calls: Vec::new(),
        };
        import_archive(&db, archive).await.unwrap();
        let child_uuid: String = db
            .read(|conn| {
                let child_uuid = conn.query_row(
                    "SELECT child_uuid FROM task_delegation_children
                     WHERE label = 'worker'",
                    [],
                    |row| row.get(0),
                )?;
                Ok(child_uuid)
            })
            .await
            .unwrap();
        assert_eq!(Uuid::parse_str(&child_uuid).unwrap().get_version_num(), 5);
    }

    fn session(id: Uuid, parent: Option<Uuid>) -> Value {
        json!({
            "session_id": id,
            "short_id": "ab3def",
            "parent_session_id": parent,
            "fork_point_turn_id": null,
            "assistant_name": null,
            "is_assistant_thread": false,
            "active_model": {
                "provider": "test-provider",
                "model": "test-model",
            },
            "session_entry_mode": "code",
            "active_agent": "Build",
            "started_at_unix_ms": 100,
            "ended_at_unix_ms": null,
            "title": "Imported session",
        })
    }

    #[test]
    fn modes_session_setup_archive_mode_is_required_and_exact() {
        let id = Uuid::new_v4();
        let mut missing = session(id, None);
        missing
            .as_object_mut()
            .expect("session fixture is an object")
            .remove("session_entry_mode");
        assert!(
            parse_session(&missing)
                .expect_err("archive import must not default a missing entry mode")
                .to_string()
                .contains("session_entry_mode")
        );

        let mut invalid = session(id, None);
        invalid["session_entry_mode"] = json!("operator");
        assert!(
            parse_session(&invalid)
                .expect_err("archive import must reject an unknown entry mode")
                .to_string()
                .contains("invalid session_entry_mode")
        );

        let mut computer = session(id, None);
        computer["session_entry_mode"] = json!("computer");
        assert_eq!(
            parse_session(&computer)
                .expect("canonical entry mode imports")
                .session_entry_mode,
            "computer"
        );
    }

    #[test]
    fn modes_session_setup_rejects_prerelease_export_schema_three_without_a_shim() {
        let archive = archive_bytes_with_schema(
            "cockpit-session-export/3",
            vec![session(Uuid::new_v4(), None)],
            Vec::new(),
            false,
        );
        let error = read_archive_bytes(&archive)
            .expect_err("the obsolete export schema must not be parsed as v4")
            .to_string();
        assert!(
            error.contains("unsupported session export schema"),
            "{error}"
        );
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
        zip.start_file("text_artifacts/index.json", options)
            .unwrap();
        zip.write_all(b"[]").unwrap();
        zip.finish().unwrap();
        cursor.into_inner()
    }

    fn event(session_id: Uuid, ts_ms: i64) -> Value {
        json!({
            "seq": 1,
            "ts_ms": ts_ms,
            "type": "user_message",
            "session_id": session_id,
            "short_id": "ab3def",
            "agent": "Build",
            "call_id": null,
            "data": { "text": "round trip content" },
        })
    }

    #[tokio::test]
    async fn import_always_allocates_fresh_destination_session_ids() {
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
        let imported = import_archive(&db, archive).await.unwrap();
        assert_ne!(imported.imported, vec![id]);
        assert!(db.get_session(id).await.unwrap().is_some());
        assert!(
            db.get_session(imported.imported[0])
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn import_records_provenance_for_a_fresh_destination() {
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
        let imported = import_archive(&db, archive).await.unwrap();
        assert_ne!(imported.imported[0], id);
        let restored = db.get_session(imported.imported[0]).await.unwrap().unwrap();
        assert_eq!(restored.short_id.as_deref(), Some("ab3def"));
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
        let error = import_archive(&db, archive).await.unwrap_err();
        assert!(error.to_string().contains("cyclic"));
        assert!(db.get_session(root).await.unwrap().is_none());
        assert!(db.get_session(cycle).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn text_artifact_import_rejects_a_long_mixed_media_event_before_artifact_lookup() {
        let db = Db::open_in_memory().unwrap();
        let source_session_id = Uuid::new_v4();
        let malformed_event = json!({
            "seq": 1,
            "ts_ms": 123,
            "type": "user_message",
            "session_id": source_session_id,
            "short_id": "ab3def",
            "agent": "Build",
            "call_id": null,
            "data": {
                "text": "x".repeat(64 * 1024 + 1),
                "images": [{"id": Uuid::new_v4()}],
            },
        });
        let error = read_archive_bytes(&archive_bytes(
            vec![session(source_session_id, None)],
            vec![malformed_event],
            false,
        ))
        .expect_err("an archive cannot reintroduce an artifact-ineligible long media event");
        assert!(
            error.to_string().contains("cannot carry media/file parts"),
            "unexpected import error: {error:#}"
        );
        // The rejection happens during archive parsing (before import), so no
        // destination rows can ever be written.
        let sessions: i64 = db
            .read(|conn| {
                conn.query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
                    .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(
            sessions, 0,
            "validation fails before any destination rows are written"
        );
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
        let imported = import_archive(&db, archive).await.unwrap();
        let events = db.list_session_events(imported.imported[0]).await.unwrap();
        assert!(
            events
                .iter()
                .any(|event| event.kind == "user_message" && event.ts_ms == 1_234_567)
        );
    }

    /// The complete closed hook-run audit projection an export emits for a
    /// live `hook_run` ledger row.
    fn hook_run_audit() -> Value {
        json!({
            "event": "postToolUse",
            "hook": "project:abcdef0123456789:0",
            "origin": "project:abcdef0123456789:0",
            "status": "success",
            "duration_ms": 12,
            "tool_name": "bash",
            "tool_call_id": "call-1",
            "turn_id": "turn-9",
        })
    }

    fn hook_run_event(session_id: Uuid, ts_ms: i64, data: Value) -> Value {
        json!({
            "seq": 1,
            "ts_ms": ts_ms,
            "type": "hook_run",
            "session_id": session_id,
            "short_id": "ab3def",
            "agent": null,
            "call_id": null,
            "data": data,
        })
    }

    #[tokio::test]
    async fn hook_run_event_import_and_rehydration() {
        // A valid `hook_run` ledger entry exported as a data-only row imports
        // through the typed writer and rehydrates identically.
        let db = Db::open_in_memory().unwrap();
        let id = Uuid::new_v4();
        let audit = hook_run_audit();
        let archive = read_archive_bytes(&archive_bytes(
            vec![session(id, None)],
            vec![hook_run_event(id, 4242, audit.clone())],
            false,
        ))
        .unwrap();
        let imported = import_archive(&db, archive).await.unwrap();
        let events = db.list_session_events(imported.imported[0]).await.unwrap();
        let hook_rows: Vec<_> = events.iter().filter(|e| e.kind == "hook_run").collect();
        assert_eq!(hook_rows.len(), 1, "exactly one hook_run row restored");
        let row = hook_rows[0];
        assert_eq!(row.ts_ms, 4242, "exported hook_run timestamp preserved");
        // The closed audit projection round-trips byte-for-byte as data (the
        // typed import writer re-serializes the same validated projection).
        assert_eq!(row.data, audit, "hook_run audit rehydrated identically");

        // A hook_run carrying a field outside the closed projection is rejected
        // by the typed import writer (`HookRunAudit::from_json`), so the whole
        // import fails atomically rather than admitting a sensitive field.
        let db_forbidden = Db::open_in_memory().unwrap();
        let forbidden_id = Uuid::new_v4();
        let mut forbidden = hook_run_audit();
        forbidden["payload"] = json!("secret command output");
        let archive = read_archive_bytes(&archive_bytes(
            vec![session(forbidden_id, None)],
            vec![hook_run_event(forbidden_id, 5, forbidden)],
            false,
        ))
        .unwrap();
        assert!(
            import_archive(&db_forbidden, archive).await.is_err(),
            "hook_run with a field outside the closed audit projection must be rejected"
        );
        assert!(
            db_forbidden
                .get_session(forbidden_id)
                .await
                .unwrap()
                .is_none(),
            "a rejected hook_run import leaves no partial session"
        );

        // Unknown event kinds remain a hard error (the parser gate is intact),
        // whether it surfaces during archive hydration or the restore itself.
        let db_unknown = Db::open_in_memory().unwrap();
        let unknown_id = Uuid::new_v4();
        let mut unknown = hook_run_event(unknown_id, 7, hook_run_audit());
        unknown["type"] = json!("totally_unknown_kind");
        let bytes = archive_bytes(vec![session(unknown_id, None)], vec![unknown], false);
        let error = match read_archive_bytes(&bytes) {
            Err(error) => error,
            Ok(archive) => import_archive(&db_unknown, archive).await.unwrap_err(),
        };
        assert!(
            error.to_string().contains("unsupported import event type"),
            "unknown event kinds must still be rejected: {error}"
        );
    }

    #[tokio::test]
    async fn import_restores_exported_session_metadata() {
        let db = Db::open_in_memory().unwrap();
        let root = Uuid::new_v4();
        let child = Uuid::new_v4();
        let mut child_manifest = session(child, Some(root));
        child_manifest["fork_point_turn_id"] = json!("42");
        child_manifest["ended_at_unix_ms"] = json!(777);
        child_manifest["title"] = json!("Restored title");
        child_manifest["short_id"] = json!("ch1d23");
        let mut parent_event = event(root, 100);
        parent_event["seq"] = json!(42);
        let archive = read_archive_bytes(&archive_bytes(
            vec![session(root, None), child_manifest],
            vec![parent_event, event(child, 456_789)],
            false,
        ))
        .unwrap();
        let imported = import_archive(&db, archive).await.unwrap();
        assert_eq!(imported.imported.len(), 2);
        let root_destination_id = imported.imported[0];
        let child_destination_id = imported.imported[1];
        assert_ne!(root_destination_id, root);
        assert_ne!(child_destination_id, child);
        let restored = db.get_session(child_destination_id).await.unwrap().unwrap();
        assert_eq!(restored.parent_session_id, Some(root_destination_id));
        let parent_id = root_destination_id.to_string();
        let mapped_fork = db
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT seq FROM session_events
                     WHERE session_id = ?1
                     ORDER BY seq ASC LIMIT 1",
                    [parent_id],
                    |row| row.get::<_, i64>(0),
                )?)
            })
            .await
            .unwrap()
            .to_string();
        assert_eq!(
            restored.fork_point_turn_id.as_deref(),
            Some(mapped_fork.as_str())
        );
        assert_eq!(restored.ended_at_unix_ms, Some(777));
        assert_eq!(restored.title.as_deref(), Some("Restored title"));
        assert_eq!(restored.short_id.as_deref(), Some("ch1d23"));
        assert_eq!(restored.provider.as_deref(), Some("test-provider"));
        assert_eq!(restored.model.as_deref(), Some("test-model"));
        assert_eq!(
            serde_json::from_str::<cockpit_config::config::providers::ActiveModelRef>(
                restored
                    .model_selection_json
                    .as_deref()
                    .expect("imported active model is durable"),
            )
            .unwrap(),
            cockpit_config::config::providers::ActiveModelRef {
                provider: "test-provider".to_string(),
                model: "test-model".to_string(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            }
        );
        let events = db.list_session_events(child_destination_id).await.unwrap();
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
    fn import_rejects_flat_v1_export_shape() {
        let id = Uuid::new_v4();
        let flat = json!({
            "session_id": id,
            "short_id": "ab3def",
            "parent_session_id": null,
            "fork_point_turn_id": null,
            "provider": "test-provider",
            "model": "test-model",
            "active_agent": "Build",
            "started_at": 100,
            "ended_at": null,
            "title": "Old export",
        });
        let bytes =
            archive_bytes_with_schema("cockpit-session-export/1", vec![flat], vec![], false);
        let error = read_archive_bytes(&bytes).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported session export schema")
        );
    }

    #[tokio::test]
    async fn import_preserves_null_active_model_without_projections() {
        let db = Db::open_in_memory().unwrap();
        let id = Uuid::new_v4();
        let mut without_model = session(id, None);
        without_model["active_model"] = Value::Null;
        let archive =
            read_archive_bytes(&archive_bytes(vec![without_model], vec![], false)).unwrap();

        let imported = import_archive(&db, archive).await.unwrap();
        let destination_id = imported.imported[0];

        assert_ne!(destination_id, id);
        let restored = db.get_session(destination_id).await.unwrap().unwrap();
        assert!(restored.provider.is_none());
        assert!(restored.model.is_none());
        assert!(restored.model_selection_json.is_none());
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
        import_archive(&db, archive).await.unwrap();
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
        let imported = import_archive(&db, archive).await.unwrap();
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
        let imported = import_archive(&destination, read_archive_bytes(&bytes).unwrap())
            .await
            .unwrap();
        let destination_id = imported.imported[0];
        let grants: i64 = destination
            .read(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM approval_grants WHERE session_id = ?1",
                    [destination_id.to_string()],
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
        let active_model = cockpit_config::config::providers::ActiveModelRef {
            provider: "test-provider".to_string(),
            model: "test-model".to_string(),
            reasoning_effort: Some(cockpit_config::config::providers::ActiveReasoningEffort {
                value: "high".to_string(),
            }),
            thinking_mode: Some(cockpit_config::config::providers::ThinkingMode::High),
            prompt_cache_retention: Some(
                cockpit_config::config::providers::PromptCacheRetention::Extended,
            ),
        };
        let row_active_model = active_model.clone();
        let row = source
            .transaction(move |conn| {
                let mut row =
                    Db::build_new_session_row_conn(conn, "round-trip", "/tmp/round-trip", "Build")?;
                row.provider = Some(row_active_model.provider.clone());
                row.model = Some(row_active_model.model.clone());
                row.model_selection_json = Some(serde_json::to_string(&row_active_model)?);
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
                Db::insert_session_event_json_conn(
                    conn,
                    source_id,
                    SessionEventKind::AgentTree,
                    None,
                    None,
                    SessionEventContext::default(),
                    1234,
                    r#"{"kind":"agent_transition","subject_kind":"agent","subject_id":"00000000-0000-0000-0000-000000000001","state":"running"}"#,
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
        let imported = import_archive(&destination, read_archive_bytes(&bytes).unwrap())
            .await
            .unwrap();
        assert_eq!(imported.imported.len(), 1);
        let destination_id = imported.imported[0];
        assert_ne!(destination_id, source_id);
        let imported_again = import_archive(&destination, read_archive_bytes(&bytes).unwrap())
            .await
            .unwrap();
        assert_eq!(imported_again.imported.len(), 1);
        assert_ne!(imported_again.imported[0], source_id);
        assert_ne!(imported_again.imported[0], destination_id);
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
            conn.query_row("SELECT COUNT(*) FROM session_events WHERE session_id = ?1 AND type != 'notice'", [destination_id.to_string()], |r| r.get(0))?,
            conn.query_row("SELECT COUNT(*) FROM inference_calls WHERE session_id = ?1", [destination_id.to_string()], |r| r.get(0))?,
        ))).await.unwrap();
        assert_eq!(destination_counts, source_counts);
        assert!(
            destination
                .list_session_events(destination_id)
                .await
                .unwrap()
                .iter()
                .any(|event| event.kind == "agent_tree"),
            "typed agent-tree timeline invalidations must survive export/import"
        );
        let restored = destination
            .get_session(destination_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(restored.provider.as_deref(), Some("test-provider"));
        assert_eq!(restored.model.as_deref(), Some("test-model"));
        assert_eq!(
            serde_json::from_str::<cockpit_config::config::providers::ActiveModelRef>(
                restored
                    .model_selection_json
                    .as_deref()
                    .expect("round-tripped active model is durable"),
            )
            .unwrap(),
            active_model
        );
    }
}
