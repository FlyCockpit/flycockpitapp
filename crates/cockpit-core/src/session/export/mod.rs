//! Session debug-bundle assembly — session-log export (session-log-export
//! Part D).
//!
//! The single zip-assembly implementation shared by the CLI
//! `cockpit export <session>` command and the TUI `/export debug`
//! command. The CLI command surface (arg parsing, stdout reporting)
//! lives in `apps/cli/src/commands/export.rs`; everything that builds
//! the archive lives here.
//!
//! Bundles a session — plus every descendant fork **and** every
//! `/compact` successor session it links to — into a self-contained
//! `.zip` an auditor can read cold: the full post-redaction inference
//! requests, in order, with tool-input corrections and prune/compaction
//! boundaries.
//!
//! Reads the DB **directly** (read-only, like `debug.rs`), so it works
//! whether or not the daemon is running.
//!
//! Layout (flat):
//!
//! ```text
//! cockpit-session-<short_id>.zip
//! ├── manifest.json          # session metadata + fork tree
//! ├── events.json            # ONE unified seq-sorted timeline (all sessions),
//! │                           # including notice rows; orphaned
//! │                           # tool_call_started rows carry
//! │                           # data.orphaned=true
//! ├── tool_outputs/
//! │   └── {seq:05}_{short_id}_{tool_call_id}.json
//! ├── compressed_tool_results/
//! │   ├── index.json          # nullable compression lengths are omitted
//! │   └── {short_id}_{hash}.txt
//! ├── delegation_payloads/
//! │   └── {short_id}_{task_call_id}_{label}_{hash}.txt
//! ├── inference_requests/
//! │   └── {seq:05}_{short_id}_{call_id}.json
//! └── inference_requests_tandem/   # model-comparison shadow records
//!     └── {seq:05}_{short_id}_{call_id}__{provider}_{model}.json
//! ```

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{Value, json};
use uuid::Uuid;
use zip::write::{SimpleFileOptions, ZipWriter};

use crate::approval::store::{ManagedGrants, global_approvals_dir, list_managed_grants};
use crate::config::dirs::{ConfigDir, ConfigDirKind, discover_config_dirs};
use crate::db::Db;
use crate::db::session_log::SessionEventRow;
use crate::db::sessions::SessionRow;
use crate::db::tool_calls::ToolCallEvent;
use crate::redact::RedactionTable;

mod tandem_validation;

/// Directory holding regular (foreground) inference request bodies.
const REQ_DIR: &str = "inference_requests";
/// Sibling directory holding utility / background inference request bodies.
const REQ_DIR_UTILITY: &str = "inference_requests_utility";
/// Sibling directory holding model-comparison tandem (shadow) inference
/// records — one file per `(main call, tandem model)`
/// (implementation note).
const REQ_DIR_TANDEM: &str = "inference_requests_tandem";
/// Full post-redaction tool output sidecars for verbose `bash` calls.
const TOOL_OUTPUT_DIR: &str = "tool_outputs";
const COMPRESSED_TOOL_RESULTS_DIR: &str = "compressed_tool_results";
const DELEGATION_PAYLOADS_DIR: &str = "delegation_payloads";
const DELEGATION_STEERS_DIR: &str = "delegation_steers";

/// Sanitize a `provider`/`model` id for use in a tandem export filename:
/// replace any character that isn't alphanumeric / `-` / `_` / `.` with `_`,
/// so a model id containing `/`, `:`, etc. stays filesystem-safe and on one
/// path segment.
fn fs_safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// What a completed bundle write produced — surfaced so callers (CLI
/// and the TUI debug export) can report identical stats.
#[derive(Debug)]
pub struct BundleSummary {
    pub session_count: usize,
    pub byte_len: usize,
}

#[derive(Debug)]
pub struct BundleBytes {
    pub bytes: Vec<u8>,
    pub summary: BundleSummary,
}

/// Assemble the full debug bundle for `target` and return the zip bytes
/// instead of writing them to a caller-selected path.
pub fn build_bundle_zip_bytes(
    db: &Db,
    target: &SessionRow,
    include_generated_artifacts: bool,
    include_sensitive: bool,
) -> Result<BundleBytes> {
    // The walk is cheap point-lookups per session; the read is bounded
    // by each session's history.
    let bundle = collect_bundle(db, target.session_id)?;
    let bytes = build_zip_with_options(
        db,
        target,
        &bundle,
        ExportBundleOptions {
            include_generated_artifacts,
            include_sensitive,
        },
    )?;
    let summary = BundleSummary {
        session_count: bundle.len(),
        byte_len: bytes.len(),
    };
    Ok(BundleBytes { bytes, summary })
}

/// Assemble the full debug bundle for `target` (the session plus its
/// descendant forks and `/compact` successors) and write it to
/// `out_path`. This is the single zip-assembly implementation behind
/// both the CLI `cockpit export` and the TUI `/export debug` command.
///
/// `overwrite` controls the clobber policy: `false` refuses to replace
/// an existing file (the CLI's no-clobber-without-`--force` guarantee);
/// `true` replaces it unconditionally (the TUI path, which has no force
/// flag and is specified to overwrite its own prior export). The CLI
/// passes `args.force` here, so its guarantee is preserved.
pub fn write_bundle_zip(
    db: &Db,
    target: &SessionRow,
    out_path: &std::path::Path,
    overwrite: bool,
    include_generated_artifacts: bool,
    include_sensitive: bool,
) -> Result<BundleSummary> {
    if out_path.exists() && !overwrite {
        anyhow::bail!(
            "output path `{}` already exists — pass `--force` to overwrite",
            out_path.display()
        );
    }

    let bundle =
        build_bundle_zip_bytes(db, target, include_generated_artifacts, include_sensitive)?;

    if let Some(parent) = out_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating export directory `{}`", parent.display()))?;
    }
    std::fs::write(out_path, &bundle.bytes)
        .with_context(|| format!("writing export to `{}`", out_path.display()))?;

    Ok(bundle.summary)
}

/// Resolve a user-supplied identifier to a session row. `Ok(Ok(row))` on
/// success; `Ok(Err(message))` for a usage error (not found / ambiguous)
/// the caller surfaces with exit 64. A full UUID resolves directly; any
/// other string is treated as a `short_id` and matched globally.
pub fn resolve_session(db: &Db, ident: &str) -> Result<std::result::Result<SessionRow, String>> {
    if let Ok(uuid) = Uuid::parse_str(ident) {
        return Ok(match db.get_session(uuid)? {
            Some(row) => Ok(row),
            None => Err(format!("no session with id `{ident}`")),
        });
    }
    let matches = db.find_sessions_by_short_id_global(ident)?;
    match matches.len() {
        0 => Ok(Err(format!("no session with short id `{ident}`"))),
        1 => Ok(Ok(matches.into_iter().next().unwrap())),
        n => Ok(Err(format!(
            "short id `{ident}` is ambiguous — it matches {n} sessions across projects; \
             pass the full UUID instead"
        ))),
    }
}

/// Walk the fork tree (descendant `parent_session_id`) and follow every
/// `/compact` successor link, breadth-first, deduping. Returns the
/// session rows in discovery order with the target first.
fn collect_bundle(db: &Db, target_id: Uuid) -> Result<Vec<SessionRow>> {
    let mut seen: HashSet<Uuid> = HashSet::new();
    let mut order: Vec<SessionRow> = Vec::new();
    let mut frontier: VecDeque<Uuid> = VecDeque::new();
    frontier.push_back(target_id);

    while let Some(id) = frontier.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        let Some(row) = db.get_session(id)? else {
            continue;
        };
        order.push(row);

        // Descendant forks.
        for child in db.list_forks(id)? {
            frontier.push_back(child.session_id);
        }
        // `/compact` successor sessions (a session boundary, not a fork —
        // followed like the fork tree per Part C).
        for ev in db.list_session_events(id)? {
            if ev.kind == "session_compacted"
                && let Some(succ) = ev
                    .data
                    .get("successor_session_id")
                    .and_then(Value::as_str)
                    .and_then(|s| Uuid::parse_str(s).ok())
            {
                frontier.push_back(succ);
            }
        }
    }
    Ok(order)
}

/// Assemble the `.zip` bytes in memory: `manifest.json`, the unified
/// `events.json`, and one `inference_requests/` file per inference call
/// across every session in the bundle.
#[derive(Debug, Clone, Copy, Default)]
struct ExportBundleOptions {
    include_generated_artifacts: bool,
    include_sensitive: bool,
}

#[cfg(test)]
fn test_export_env() -> HashMap<String, String> {
    HashMap::new()
}

#[cfg(test)]
fn build_zip(db: &Db, target: &SessionRow, bundle: &[SessionRow]) -> Result<Vec<u8>> {
    build_zip_with_options_and_env(
        db,
        target,
        bundle,
        ExportBundleOptions::default(),
        &test_export_env(),
    )
}

fn build_zip_with_options(
    db: &Db,
    target: &SessionRow,
    bundle: &[SessionRow],
    options: ExportBundleOptions,
) -> Result<Vec<u8>> {
    let env = process_env_map();
    build_zip_with_options_and_env(db, target, bundle, options, &env)
}

fn build_zip_with_options_and_env(
    db: &Db,
    target: &SessionRow,
    bundle: &[SessionRow],
    options: ExportBundleOptions,
    env: &HashMap<String, String>,
) -> Result<Vec<u8>> {
    // session_id → short_id lookup for tagging events.
    let short_ids: BTreeMap<Uuid, String> = bundle
        .iter()
        .map(|s| {
            (
                s.session_id,
                s.short_id
                    .clone()
                    .unwrap_or_else(|| s.session_id.to_string()),
            )
        })
        .collect();

    // Gather + merge every session's events into one seq-sorted timeline.
    let mut all_events: Vec<SessionEventRow> = Vec::new();
    for s in bundle {
        all_events.extend(db.list_session_events(s.session_id)?);
    }
    all_events.sort_by_key(|e| e.seq);

    // Which inference calls were made by the utility model / background
    // machinery — read from the persisted `inference_calls.is_utility` flag
    // (never inferred at export time). Calls without a row (pre-flag, or a
    // captured request with no usage row) are absent → treated as regular.
    let candidate_call_ids: Vec<String> = all_events
        .iter()
        .filter(|e| e.kind == "inference_request")
        .filter_map(|e| e.call_id.clone())
        .collect();
    let utility_call_ids = db.utility_call_ids(&candidate_call_ids)?;
    let export_redactor = export_redaction_table_with_env(target, env);

    // Call ids that have a successful `inference_request` event: those own the
    // captured-body file. A failed/hung turn records an `inference_failure`
    // event (not an `inference_request`) instead — its captured body (status
    // `timed_out`/`errored`/`pending`) is still stored, so we assign a file
    // off the failure event when no request event exists for that call
    // (implementation note). This keeps
    // exactly one file per call id while ensuring a hung/failed turn is no
    // longer an empty export.
    let request_event_call_ids: HashSet<String> = all_events
        .iter()
        .filter(|e| e.kind == "inference_request")
        .filter_map(|e| e.call_id.clone())
        .collect();

    // First pass: assign inference_request filenames so the matching
    // event can reference the exact file (explicit correlation).
    // `{seq:05}_{short_id}_{call_id}.json`, in `inference_requests/` for
    // regular calls and `inference_requests_utility/` for utility calls.
    let mut request_files: Vec<(String, String)> = Vec::new(); // (path, call_id)
    let mut tool_output_files: Vec<(String, Value)> = Vec::new(); // (path, sidecar payload)
    let mut compressed_result_files: Vec<(String, String)> = Vec::new(); // (path, content)
    let mut compressed_result_index: Vec<Value> = Vec::new();
    let mut delegation_payload_files: Vec<(String, String)> = Vec::new(); // (path, content)
    let mut delegation_payload_index: Vec<Value> = Vec::new();
    let mut delegation_steer_index: Vec<Value> = Vec::new();
    let mut tool_identity_by_call: BTreeMap<(Uuid, String), Value> = BTreeMap::new();
    for s in bundle {
        for tool_call in db.list_tool_calls_for_session(s.session_id)? {
            let identity = tool_provider_identity_json(&tool_call)?;
            tool_identity_by_call
                .insert((tool_call.session_id, tool_call.call_id.clone()), identity);
        }
        let short = short_ids
            .get(&s.session_id)
            .cloned()
            .unwrap_or_else(|| s.session_id.to_string());
        for entry in db.list_compressed_tool_results(s.session_id)? {
            let path = format!(
                "{COMPRESSED_TOOL_RESULTS_DIR}/{}_{}.txt",
                short,
                fs_safe(&entry.hash)
            );
            let mut index_entry = json!({
                "hash": entry.hash,
                "session_id": entry.session_id.to_string(),
                "short_id": short,
                "agent_id": entry.agent_id,
                "tool": entry.tool,
                "call_id": entry.call_id,
                "original_byte_len": entry.original_byte_len,
                "created_at": entry.created_at,
                "kind": entry.kind,
                "file": path,
            });
            if let Some(compressed_byte_len) = entry.compressed_byte_len {
                index_entry["compressed_byte_len"] = json!(compressed_byte_len);
            }
            compressed_result_index.push(index_entry);
            compressed_result_files.push((path, entry.content));
        }
        for row in db.list_task_delegation_steers(s.session_id)? {
            let body =
                redact_string_for_export(row.body, &export_redactor, options.include_sensitive);
            delegation_steer_index.push(json!({
                "id": row.id,
                "task_call_id": row.task_call_id,
                "label": row.label,
                "session_id": s.session_id.to_string(),
                "short_id": short,
                "origin_principal": row.origin_principal,
                "body": body,
                "delivered": row.delivered,
                "created_at": row.created_at,
                "delivered_at": row.delivered_at,
            }));
        }
        for row in db.list_task_delegation_payloads(s.session_id)? {
            let file = format!(
                "{DELEGATION_PAYLOADS_DIR}/{}_{}_{}_{}.txt",
                short,
                fs_safe(&row.task_call_id),
                fs_safe(&row.label),
                fs_safe(&row.payload_hash)
            );
            let loaded = db.load_task_delegation_payload(&row.task_call_id, &row.label);
            let (excerpt, load_error, emit_file) = match loaded {
                Ok(payload) => {
                    let body = redact_string_for_export(
                        payload.body,
                        &export_redactor,
                        options.include_sensitive,
                    );
                    (Some(row.excerpt(&body)), None::<String>, Some(body))
                }
                Err(e) => (None, Some(format!("{e:#}")), None),
            };
            let mut meta = json!({
                "task_call_id": row.task_call_id,
                "function_call_id": row.function_call_id,
                "label": row.label,
                "payload_hash": row.payload_hash,
                "session_id": row.parent_session_id.to_string(),
                "short_id": short,
                "parent_agent": row.parent_agent,
                "child_agent": row.child_agent,
                "prompt_byte_len": row.prompt_byte_len,
                "created_at": row.created_at,
                "delivered": row.delivered(),
                "delivered_at": row.delivered_at,
                "excerpt": excerpt,
                "file": if emit_file.is_some() { Some(file.clone()) } else { None },
                "source_sidecar": row.sidecar_path,
            });
            if let Some(load_error) = load_error
                && let Some(obj) = meta.as_object_mut()
            {
                obj.insert("load_error".to_string(), json!(load_error));
            }
            delegation_payload_index.push(meta);
            if let Some(body) = emit_file {
                delegation_payload_files.push((file, body));
            }
        }
    }
    let mut event_values: Vec<Value> = Vec::with_capacity(all_events.len());
    let mut completed_tool_calls: HashMap<String, usize> = HashMap::new();
    for ev in &all_events {
        if ev.kind == "tool_call_completed"
            && let Some(call_id) = ev.call_id.as_deref()
        {
            *completed_tool_calls.entry(call_id.to_string()).or_default() += 1;
        }
    }
    for ev in &all_events {
        let short = short_ids
            .get(&ev.session_id)
            .cloned()
            .unwrap_or_else(|| ev.session_id.to_string());
        let mut value = json!({
            "seq": ev.seq,
            "ts_ms": ev.ts_ms,
            "type": ev.kind,
            "session_id": ev.session_id.to_string(),
            "short_id": short,
            "agent": ev.agent,
            "call_id": ev.call_id,
            "data": ev.data,
        });
        if ev.kind == "tool_call_started"
            && let Some(call_id) = ev.call_id.as_deref()
            && let Some(data) = value["data"].as_object_mut()
        {
            let has_completion = match completed_tool_calls.get_mut(call_id) {
                Some(count) if *count > 0 => {
                    *count -= 1;
                    true
                }
                _ => false,
            };
            if !has_completion {
                data.insert("orphaned".into(), json!(true));
            }
        }
        if ev.kind == "tool_call"
            && let Some(call_id) = ev.call_id.as_deref()
            && let Some(identity) = tool_identity_by_call.get(&(ev.session_id, call_id.to_string()))
            && let Some(data) = value["data"].as_object_mut()
        {
            data.insert("provider_identity".into(), identity.clone());
        }
        if let Some(sidecar) = value["data"].get("output_sidecar").cloned()
            && let Some(call_id) = ev.call_id.as_deref()
        {
            let path = format!(
                "{TOOL_OUTPUT_DIR}/{:05}_{}_{}.json",
                ev.seq,
                short,
                fs_safe(call_id)
            );
            value["output_file"] = json!(path);
            if let Some(data) = value["data"].as_object_mut() {
                data.remove("output_sidecar");
            }
            tool_output_files.push((path, sidecar));
        }
        // An `inference_request` event always owns a file; an
        // `inference_failure` event owns one only when there's no successful
        // request event for the same call (the hung/failed case — the captured
        // body still exists, with a non-`completed` status).
        let owns_file = match ev.kind.as_str() {
            "inference_request" => true,
            "inference_failure" => ev
                .call_id
                .as_deref()
                .is_some_and(|c| !request_event_call_ids.contains(c)),
            _ => false,
        };
        if owns_file && let Some(call_id) = ev.call_id.as_deref() {
            let dir = if utility_call_ids.contains(call_id) {
                REQ_DIR_UTILITY
            } else {
                REQ_DIR
            };
            let path = format!("{dir}/{:05}_{}_{}.json", ev.seq, short, fs_safe(call_id));
            // Surface the file reference on the event itself — pointing at
            // the correct (regular vs utility) folder.
            value["file"] = json!(path);
            request_files.push((path, call_id.to_string()));
        }
        redact_value_for_export(&mut value, &export_redactor, options.include_sensitive);
        event_values.push(value);
    }

    // Model-comparison tandem (shadow) records
    // (implementation note): one
    // `inference_requests_tandem/` file per `(main call, tandem model)`, plus a
    // `tandem_inference` event linking each back to the main call it shadows.
    // The parent call's `seq` + `short_id` are resolved from its
    // `inference_request` (or `inference_failure`) event so the tandem event
    // sorts right alongside the call it shadows.
    let parent_info: BTreeMap<String, (i64, String)> = all_events
        .iter()
        .filter(|e| e.kind == "inference_request" || e.kind == "inference_failure")
        .filter_map(|e| {
            let call_id = e.call_id.clone()?;
            let short = short_ids
                .get(&e.session_id)
                .cloned()
                .unwrap_or_else(|| e.session_id.to_string());
            Some((call_id, (e.seq, short)))
        })
        .collect();

    let mut tandem_files: Vec<(String, Value)> = Vec::new(); // (path, file body)
    for s in bundle {
        for rec in db.list_tandem_inference(s.session_id)? {
            let (parent_seq, short) = parent_info
                .get(&rec.parent_call_id)
                .cloned()
                .unwrap_or_else(|| {
                    // No parent event captured (e.g. the main call never settled
                    // its event): fall back to the record's own seq hint + the
                    // session short id so the file/event still emit.
                    let short = short_ids
                        .get(&rec.session_id)
                        .cloned()
                        .unwrap_or_else(|| rec.session_id.to_string());
                    (rec.parent_seq.unwrap_or(0), short)
                });
            let path = format!(
                "{REQ_DIR_TANDEM}/{:05}_{}_{}__{}_{}.json",
                parent_seq,
                short,
                fs_safe(&rec.parent_call_id),
                fs_safe(&rec.provider),
                fs_safe(&rec.model),
            );
            let tool_call_validation = tandem_validation::validate_tandem_tool_calls(
                &rec.request,
                rec.response.as_ref(),
                Path::new(&target.project_root),
                None,
            );
            // The on-disk tandem file: identity + status + request + response +
            // usage (the response/usage distinguish a tandem record from a plain
            // `inference_requests/` file, which stores only the request).
            let file_body = json!({
                "provider": rec.provider,
                "model": rec.model,
                "status": rec.status,
                "request": rec.request,
                "response": rec.response,
                "usage": rec.usage,
                "tool_call_validation": tool_call_validation,
            });
            tandem_files.push((path.clone(), file_body));
            // The timeline event mapping this tandem response to the main call.
            let mut event = json!({
                // Sort immediately after the shadowed call's event.
                "seq": parent_seq,
                "ts_ms": rec.ts_ms,
                "type": "tandem_inference",
                "session_id": rec.session_id.to_string(),
                "short_id": short,
                "agent": rec.agent,
                // The MAIN call this shadows (the join key).
                "call_id": rec.parent_call_id,
                "data": {
                    "provider": rec.provider,
                    "model": rec.model,
                    "status": rec.status,
                    "tool_call_validation": tool_call_validation,
                },
                "file": path,
            });
            redact_value_for_export(&mut event, &export_redactor, options.include_sensitive);
            event_values.push(event);
        }
    }
    // Keep the unified timeline seq-sorted with the tandem events folded in.
    event_values.sort_by(|a, b| {
        let sa = a["seq"].as_i64().unwrap_or(0);
        let sb = b["seq"].as_i64().unwrap_or(0);
        sa.cmp(&sb)
            // Tandem events tie on the parent's seq; place them right after the
            // parent's own row (which is not `tandem_inference`).
            .then_with(|| {
                let ta = a["type"] == "tandem_inference";
                let tb = b["type"] == "tandem_inference";
                ta.cmp(&tb)
            })
    });

    let manifest = build_manifest(db, target, bundle, options, env);
    let config_entries =
        collect_config_entries_with_env(target, options.include_generated_artifacts, env);
    let approval_entries = collect_approval_entries(db, bundle)?;

    // Write the archive.
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut zw = ZipWriter::new(&mut buf);
        let opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        zw.start_file("manifest.json", opts)
            .context("zip: manifest entry")?;
        zw.write_all(serde_json::to_string_pretty(&manifest)?.as_bytes())
            .context("zip: writing manifest")?;

        zw.start_file("events.json", opts)
            .context("zip: events entry")?;
        zw.write_all(serde_json::to_string_pretty(&event_values)?.as_bytes())
            .context("zip: writing events")?;

        // One file per inference request, split across `inference_requests/`
        // (regular) and `inference_requests_utility/` (utility) by the
        // persisted flag. The payload is the full post-redaction request body
        // — no second redaction pass (the leak-detection use case wants the
        // exact wire form).
        for (path, call_id) in &request_files {
            let mut payload = match db.get_inference_request(call_id)? {
                // Surface the dispatch-time lifecycle `status` on the emitted
                // file so a hung/failed turn's record carries its non-
                // `completed` status without a separate lookup
                // (implementation note).
                Some((payload, status)) => json!({ "status": status, "request": payload }),
                // A captured event without a stored payload (e.g. capture
                // failed mid-turn). Emit a marker so the file the event
                // references always exists.
                None => json!({ "error": "no captured request payload for this call_id" }),
            };
            redact_value_for_export(&mut payload, &export_redactor, options.include_sensitive);
            zw.start_file(path, opts)
                .with_context(|| format!("zip: request entry `{path}`"))?;
            zw.write_all(serde_json::to_string_pretty(&payload)?.as_bytes())
                .with_context(|| format!("zip: writing request `{path}`"))?;
        }

        // Model-comparison tandem (shadow) records: one file per (main call,
        // tandem model) under `inference_requests_tandem/`. An unsettled tandem
        // request at export time carries `status: "pending"` (its body's status
        // field) — the export does not block waiting for it.
        for (path, body) in &tandem_files {
            let mut body = body.clone();
            redact_value_for_export(&mut body, &export_redactor, options.include_sensitive);
            zw.start_file(path, opts)
                .with_context(|| format!("zip: tandem entry `{path}`"))?;
            zw.write_all(serde_json::to_string_pretty(&body)?.as_bytes())
                .with_context(|| format!("zip: writing tandem `{path}`"))?;
        }

        for (path, body) in &tool_output_files {
            let mut body = body.clone();
            redact_value_for_export(&mut body, &export_redactor, options.include_sensitive);
            zw.start_file(path, opts)
                .with_context(|| format!("zip: tool output entry `{path}`"))?;
            zw.write_all(serde_json::to_string_pretty(&body)?.as_bytes())
                .with_context(|| format!("zip: writing tool output `{path}`"))?;
        }

        if !compressed_result_index.is_empty() {
            let path = format!("{COMPRESSED_TOOL_RESULTS_DIR}/index.json");
            zw.start_file(&path, opts)
                .with_context(|| format!("zip: compressed result index `{path}`"))?;
            zw.write_all(serde_json::to_string_pretty(&compressed_result_index)?.as_bytes())
                .context("zip: writing compressed result index")?;
        }
        for (path, body) in &compressed_result_files {
            zw.start_file(path, opts)
                .with_context(|| format!("zip: compressed result entry `{path}`"))?;
            let body =
                redact_string_for_export(body.clone(), &export_redactor, options.include_sensitive);
            zw.write_all(body.as_bytes())
                .with_context(|| format!("zip: writing compressed result `{path}`"))?;
        }

        if !delegation_payload_index.is_empty() {
            let path = format!("{DELEGATION_PAYLOADS_DIR}/index.json");
            zw.start_file(&path, opts)
                .with_context(|| format!("zip: delegation payload index `{path}`"))?;
            zw.write_all(serde_json::to_string_pretty(&delegation_payload_index)?.as_bytes())
                .context("zip: writing delegation payload index")?;
        }
        if !delegation_steer_index.is_empty() {
            let path = format!("{DELEGATION_STEERS_DIR}/index.json");
            zw.start_file(&path, opts)
                .with_context(|| format!("zip: delegation steer index `{path}`"))?;
            zw.write_all(serde_json::to_string_pretty(&delegation_steer_index)?.as_bytes())
                .context("zip: writing delegation steer index")?;
        }
        for (path, body) in &delegation_payload_files {
            zw.start_file(path, opts)
                .with_context(|| format!("zip: delegation payload entry `{path}`"))?;
            zw.write_all(body.as_bytes())
                .with_context(|| format!("zip: writing delegation payload `{path}`"))?;
        }

        // Config copy: a deep-merged effective extended-config plus untouched
        // raw per-layer trees, every file scrubbed through the same redaction
        // table the inference bodies pass through (debug bundles must never
        // leak credentials). Always writes at least a marker so `config/`
        // exists even on a machine with no cockpit config on disk.
        for (path, body) in &config_entries {
            zw.start_file(path, opts)
                .with_context(|| format!("zip: config entry `{path}`"))?;
            zw.write_all(body.as_bytes())
                .with_context(|| format!("zip: writing config `{path}`"))?;
        }

        // Explicit approval snapshot: `events.json` records decisions as
        // they happened, but persisted grants are what explain why a later
        // tool did not prompt. Keep them separate from raw config copies so
        // audits have a stable, direct place to inspect.
        for (path, body) in &approval_entries {
            zw.start_file(path, opts)
                .with_context(|| format!("zip: approvals entry `{path}`"))?;
            zw.write_all(body.as_bytes())
                .with_context(|| format!("zip: writing approvals `{path}`"))?;
        }

        zw.finish().context("zip: finalizing archive")?;
    }
    Ok(buf.into_inner())
}

/// Build `manifest.json`: target session metadata + the fork/compaction
/// tree across the whole bundle. Kept small.
fn build_manifest(
    db: &Db,
    target: &SessionRow,
    bundle: &[SessionRow],
    options: ExportBundleOptions,
    env: &HashMap<String, String>,
) -> Value {
    let session_model = session_active_model_value(&target.provider, &target.model);
    let config_active_model = config_active_model_value(&target.project_root, env);
    let active_model_diverged =
        active_models_diverged(session_model.as_ref(), config_active_model.as_ref());
    let sessions: Vec<Value> = bundle
        .iter()
        .map(|s| {
            json!({
                "session_id": s.session_id.to_string(),
                "short_id": s.short_id,
                "parent_session_id": s.parent_session_id.map(|p| p.to_string()),
                "fork_point_turn_id": s.fork_point_turn_id,
                "provider": s.provider,
                "model": s.model,
                "active_agent": s.active_agent,
                "started_at": s.started_at,
                "ended_at": s.ended_at,
                "title": s.title,
            })
        })
        .collect();

    let mut manifest = json!({
        "schema": "cockpit-session-export/1",
        // The version of the cockpit binary producing THIS export — not
        // persisted per session, so a CLI export of an old session reflects
        // the exporting binary, not the one that created the session.
        "cockpit_version": env!("CARGO_PKG_VERSION"),
        "exporter_cockpit_version": env!("CARGO_PKG_VERSION"),
        // The target/root session's date, derived from `started_at` (epoch
        // seconds), as both ISO-8601 and the raw epoch for convenience.
        "session_date": iso8601_from_epoch(target.started_at),
        "session_started_at": target.started_at,
        "target": {
            "session_id": target.session_id.to_string(),
            "short_id": target.short_id,
            "project_id": target.project_id,
            "project_root": target.project_root,
            "provider": target.provider,
            "model": target.model,
            "session_model": session_model,
            "config_active_model": config_active_model,
            "active_model_diverged": active_model_diverged,
            "title": target.title,
            "started_at": target.started_at,
            "ended_at": target.ended_at,
        },
        "session_count": bundle.len(),
        "excluded_generated_artifacts": !options.include_generated_artifacts,
        "include_generated_artifacts": options.include_generated_artifacts,
        "redacted": !options.include_sensitive,
        "include_sensitive": options.include_sensitive,
        "sessions": sessions,
    });
    if let Some(repair) = export_resume_repair_state(db, target)
        && let Some(obj) = manifest.as_object_mut()
    {
        obj.insert("resume_repair_required".to_string(), repair);
    }
    manifest
}

fn session_active_model_value(provider: &Option<String>, model: &Option<String>) -> Option<Value> {
    Some(json!({
        "provider": provider.as_ref()?,
        "model": model.as_ref()?,
    }))
}

fn config_active_model_value(project_root: &str, env: &HashMap<String, String>) -> Option<Value> {
    let paths = config_file_paths_for_export(Path::new(project_root), env);
    crate::config::providers::ConfigDoc::providers_from_paths(&paths)
        .active_model
        .map(|active| {
            json!({
                "provider": active.provider,
                "model": active.model,
            })
        })
}

fn config_file_paths_for_export(cwd: &Path, env: &HashMap<String, String>) -> Vec<PathBuf> {
    if let Some(path) = env
        .get(crate::config::dirs::COCKPIT_CONFIG_ENV)
        .map(String::as_str)
        .filter(|path| !path.is_empty())
    {
        let path = PathBuf::from(path);
        if crate::config::trust::project_config_allowed(path.parent().unwrap_or(Path::new(""))) {
            return vec![path];
        }
        return Vec::new();
    }

    let mut home_and_local = Vec::new();
    let mut project = Vec::new();
    for dir in discover_config_dirs(cwd) {
        match dir.kind {
            ConfigDirKind::Project => project.push(dir.path.join(crate::config::dirs::CONFIG_FILE)),
            ConfigDirKind::HomeXdg | ConfigDirKind::HomeDot | ConfigDirKind::MachineLocal => {
                home_and_local.push(dir.path.join(crate::config::dirs::CONFIG_FILE));
            }
        }
    }
    project.reverse();
    home_and_local.extend(project);
    home_and_local
}

fn active_models_diverged(
    session_model: Option<&Value>,
    config_active_model: Option<&Value>,
) -> bool {
    let (Some(session_model), Some(config_active_model)) = (session_model, config_active_model)
    else {
        return false;
    };
    session_model.get("provider") != config_active_model.get("provider")
        || session_model.get("model") != config_active_model.get("model")
}

fn export_resume_repair_state(db: &Db, target: &SessionRow) -> Option<Value> {
    let provider = target.provider.clone().unwrap_or_default();
    let model = target.model.clone().unwrap_or_default();
    let providers = crate::secret_ref::load_effective(Path::new(&target.project_root));
    let configured = providers.resolve_wire_api(&provider, &model);
    let wire_api = if configured.is_auto() {
        crate::config::providers::WireApi::detect_for_provider(&provider, &model)
    } else {
        configured
    };
    if !matches!(wire_api, crate::config::providers::WireApi::Responses) {
        return None;
    }
    let err = crate::engine::rehydrate::rehydrate_session_with_policy(
        db,
        target.session_id,
        &target.active_agent,
        crate::engine::rehydrate::RehydratePolicy::strict(),
    )
    .err()?;
    let repair = err.downcast_ref::<crate::engine::rehydrate::RehydrateRepairRequired>()?;
    Some(json!({
        "session_id": target.session_id.to_string(),
        "short_id": target.short_id,
        "provider": provider,
        "model": model,
        "wire_api": "responses",
        "failure_kind": repair.failure_kind,
        "failing_tool_call_ids": repair.failing_tool_call_ids,
        "safe_last_turn_seq": repair.safe_last_turn_seq,
        "suggested_actions": [
            "open_read_only",
            "fork_from_last_provider_valid_turn",
            "repair_synthetic_tool_results",
            "export_debug_bundle",
            "cancel",
        ],
        "detail": repair.detail,
    }))
}

fn tool_provider_identity_json(tool_call: &ToolCallEvent) -> Result<Value> {
    let has_any_identity = tool_call.provider_item_id.is_some()
        || tool_call.provider_call_id.is_some()
        || tool_call.provider_call_id_source.is_some()
        || tool_call.wire_api.is_some()
        || tool_call.provider_family.is_some();
    if has_any_identity {
        if tool_call.provider_call_id.is_some() != tool_call.provider_call_id_source.is_some() {
            anyhow::bail!(
                "invalid provider identity for tool_call row {}: provider_call_id and provider_call_id_source must be present together",
                tool_call.call_id
            );
        }
        match tool_call.wire_api.as_deref() {
            Some("completions") | Some("responses") => {
                if tool_call.provider_call_id.is_none() {
                    anyhow::bail!(
                        "invalid provider identity for tool_call row {}: {} wire requires provider_call_id",
                        tool_call.call_id,
                        tool_call.wire_api.as_deref().unwrap_or("unknown")
                    );
                }
            }
            Some(other) => {
                anyhow::bail!(
                    "invalid provider identity for tool_call row {}: unsupported wire_api `{}`",
                    tool_call.call_id,
                    other
                );
            }
            None => {}
        }
        if tool_call.provider_call_id == tool_call.provider_item_id
            && tool_call.provider_call_id_source.as_deref() == Some("provider")
        {
            anyhow::bail!(
                "invalid provider identity for tool_call row {}: mirrored provider_call_id cannot use source `provider`",
                tool_call.call_id
            );
        }
    }
    Ok(json!({
        "cockpit_call_id": tool_call.call_id.clone(),
        "provider_item_id": tool_call.provider_item_id.clone(),
        "provider_call_id": tool_call.provider_call_id.clone(),
        "provider_call_id_source": tool_call.provider_call_id_source.clone(),
        "wire_api": tool_call.wire_api.clone(),
        "provider_family": tool_call.provider_family.clone(),
    }))
}

fn process_env_map() -> HashMap<String, String> {
    std::env::vars_os()
        .map(|(name, value)| {
            (
                name.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        })
        .collect()
}

fn export_redaction_table_with_env(
    target: &SessionRow,
    env: &HashMap<String, String>,
) -> RedactionTable {
    let cwd = PathBuf::from(&target.project_root);
    let extended = crate::config::extended::load_for_cwd(&cwd);
    RedactionTable::build_with_env_and_store(&extended.redact, &cwd, env).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "export: redaction table build failed; payload scrub is a no-op");
        RedactionTable::empty()
    })
}

fn redact_value_for_export(value: &mut Value, redactor: &RedactionTable, include_sensitive: bool) {
    if include_sensitive {
        return;
    }
    match value {
        Value::String(s) => {
            let scrubbed = redactor.scrub(s);
            if scrubbed != *s {
                *s = scrubbed;
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_value_for_export(item, redactor, false);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                redact_value_for_export(item, redactor, false);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn redact_string_for_export(
    value: String,
    redactor: &RedactionTable,
    include_sensitive: bool,
) -> String {
    if include_sensitive {
        value
    } else {
        redactor.scrub(&value)
    }
}

/// Format an epoch-seconds timestamp as an ISO-8601 / RFC 3339 UTC string.
/// Returns `None` (serialized as JSON `null`) for an out-of-range value
/// rather than failing the export.
fn iso8601_from_epoch(epoch_secs: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(epoch_secs, 0).map(|dt| dt.to_rfc3339())
}

/// A short, stable, filename-safe label for a config layer, used as the
/// per-layer subdirectory name under `config/layers/`. Project layers are
/// numbered by walk position (0 = closest to cwd) so multiple ancestor
/// `.cockpit/` dirs stay distinct and inspectable.
fn layer_label(kind: &ConfigDirKind, project_index: usize) -> String {
    match kind {
        ConfigDirKind::HomeXdg => "home-xdg".to_string(),
        ConfigDirKind::HomeDot => "home-dot".to_string(),
        ConfigDirKind::MachineLocal => "machine-local".to_string(),
        ConfigDirKind::Project => format!("project-{project_index}"),
    }
}

/// Build the `config/` bundle entries: a deep-merged effective
/// `config.json` plus untouched raw per-layer trees, every file
/// scrubbed through the redaction table. Returns `(zip_path, contents)`
/// pairs. Always returns at least one entry (a marker when no config exists)
/// so `config/` is present and the export never fails on missing config.
fn collect_config_entries_with_env(
    target: &SessionRow,
    include_generated_artifacts: bool,
    env: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let cwd = PathBuf::from(&target.project_root);
    let layers = discover_config_dirs(&cwd);

    // Same redaction table the inference bodies were scrubbed with: built
    // from the redact config + cwd. A build failure (or globally-disabled
    // redaction) must not block the export — fall back to a no-op table that
    // returns input unchanged, which a disabled config would do anyway.
    let extended = crate::config::extended::load_for_cwd(&cwd);
    let redactor = RedactionTable::build_with_env_and_store(&extended.redact, &cwd, env)
        .unwrap_or_else(|e| {
        tracing::warn!(error = %e, "export: redaction table build failed; config scrub is a no-op");
        RedactionTable::empty()
    });

    config_entries_from_layers(&layers, &redactor, include_generated_artifacts)
}

/// Export the effective persisted approval grants relevant to this bundle.
///
/// `events.json` already includes individual `permission_decision` events,
/// including one-time approvals and denials. This snapshot covers the durable
/// grants that suppress future prompts:
///
/// - session scope: SQLite `approval_grants` + `loop_guard_rules`,
/// - project scope: each bundled session's project-root `.cockpit/approvals.json`,
/// - global scope: user-level `~/.config/cockpit/approvals.json`.
fn collect_approval_entries(db: &Db, bundle: &[SessionRow]) -> Result<Vec<(String, String)>> {
    let session_grants = session_approval_snapshot(db, bundle)?;

    let mut project_roots: Vec<PathBuf> = bundle
        .iter()
        .map(|s| PathBuf::from(&s.project_root))
        .collect();
    project_roots.sort();
    project_roots.dedup();

    let projects: Vec<Value> = project_roots
        .iter()
        .map(|root| {
            json!({
                "project_root": root,
                "approvals_file": root.join(".cockpit").join("approvals.json"),
                "grants": managed_grants_json(list_managed_grants(&root.join(".cockpit"))),
            })
        })
        .collect();

    let global = global_approvals_dir().map(|dir| {
        json!({
            "approvals_file": dir.join("approvals.json"),
            "grants": managed_grants_json(list_managed_grants(&dir)),
        })
    });

    let snapshot = json!({
        "schema": "cockpit-approval-grants/1",
        "note": "Session export also includes permission_decision events in events.json; this file snapshots durable grants that can suppress future approval prompts.",
        "session": session_grants,
        "project": projects,
        "global": global,
    });

    Ok(vec![(
        "approvals/grants.json".to_string(),
        serde_json::to_string_pretty(&snapshot)?,
    )])
}

fn session_approval_snapshot(db: &Db, bundle: &[SessionRow]) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for session in bundle {
        let session_id = session.session_id.to_string();
        let (commands, paths, loop_accept, loop_reject): (
            Vec<String>,
            Vec<Value>,
            Vec<String>,
            Vec<String>,
        ) = db.read_blocking(|conn| {
            let read_keys = |sql: &str| -> Result<Vec<String>> {
                let mut stmt = conn.prepare(sql)?;
                let rows = stmt.query_map([session_id.as_str()], |row| row.get::<_, String>(0))?;
                let mut values = Vec::new();
                for row in rows {
                    values.push(row?);
                }
                Ok(values)
            };
            let read_paths = || -> Result<Vec<Value>> {
                let mut stmt = conn.prepare(
                    "SELECT grant_key, access FROM approval_grants \
                     WHERE session_id = ?1 AND grant_kind = 'path' \
                     ORDER BY grant_key",
                )?;
                let rows = stmt.query_map([session_id.as_str()], |row| {
                    let key: String = row.get(0)?;
                    let access: String = row.get(1)?;
                    Ok(json!({ "key": key, "access": access }))
                })?;
                let mut values = Vec::new();
                for row in rows {
                    values.push(row?);
                }
                Ok(values)
            };

            Ok((
                read_keys(
                    "SELECT grant_key FROM approval_grants \
                     WHERE session_id = ?1 AND grant_kind = 'command' \
                     ORDER BY grant_key",
                )?,
                read_paths()?,
                read_keys(
                    "SELECT signature FROM loop_guard_rules \
                     WHERE session_id = ?1 AND rule_verdict = 'accept' \
                     ORDER BY signature",
                )?,
                read_keys(
                    "SELECT signature FROM loop_guard_rules \
                     WHERE session_id = ?1 AND rule_verdict = 'reject' \
                     ORDER BY signature",
                )?,
            ))
        })?;

        out.push(json!({
            "session_id": session.session_id.to_string(),
            "short_id": session.short_id,
            "grants": {
                "commands": commands,
                "paths": paths,
                "loop_accept": loop_accept,
                "loop_reject": loop_reject,
            },
        }));
    }
    Ok(out)
}

fn managed_grants_json(grants: ManagedGrants) -> Value {
    json!({
        "commands": grants.commands,
        "paths": grants.paths,
        "loop_accept": grants.loop_accept,
        "loop_reject": grants.loop_reject,
    })
}

/// Pure builder behind [`collect_config_entries`]: turn a set of config
/// layers + a redaction table into the `config/` bundle entries. Split out so
/// it's testable without depending on the machine's real `~/.config` chain.
fn config_entries_from_layers(
    layers: &[ConfigDir],
    redactor: &RedactionTable,
    include_generated_artifacts: bool,
) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = Vec::new();

    // (a) Synthesized merge: deep-merge every layer's `config.json`
    // in precedence order (home layers first, then machine-local, then
    // project layers from farthest ancestor down to cwd so the closest layer
    // wins). Provider bodies live in sibling `providers/*.json`, so legacy
    // inline `providers` maps are stripped from this global-config snapshot.
    // For-export synthesis only — runtime resolution is unchanged.
    let mut merged = Value::Object(serde_json::Map::new());
    let mut any_config = false;
    let ordered_layers = merge_order(layers);
    for dir in &ordered_layers {
        let path = dir.path.join(crate::config::dirs::CONFIG_FILE);
        if let Some(mut value) = read_json_value(&path) {
            if let Some(obj) = value.as_object_mut() {
                obj.remove("providers");
            }
            crate::config::extended::deep_merge_value(&mut merged, &value);
            any_config = true;
        }
    }
    if any_config {
        let pretty = serde_json::to_string_pretty(&merged).unwrap_or_else(|_| "{}".to_string());
        entries.push((
            "config/effective-config.json".to_string(),
            redactor.scrub(&sanitize_config_json_text(&pretty)),
        ));
    }
    let provider_paths: Vec<PathBuf> = ordered_layers
        .iter()
        .map(|dir| dir.path.join(crate::config::dirs::CONFIG_FILE))
        .collect();
    let effective_providers =
        crate::config::providers::ConfigDoc::providers_from_paths(&provider_paths);
    if !effective_providers.providers.is_empty()
        || effective_providers.active_model.is_some()
        || effective_providers.on_unlisted_models_fetch.is_some()
    {
        let pretty =
            serde_json::to_string_pretty(&effective_providers).unwrap_or_else(|_| "{}".to_string());
        entries.push((
            "config/effective-providers.json".to_string(),
            redactor.scrub(&sanitize_config_json_text(&pretty)),
        ));
    }
    let mut effective_mcp = crate::mcp::config::McpConfig::default();
    let mut any_mcp = false;
    for dir in &ordered_layers {
        let path = dir.path.join("mcp.json");
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(layer) = crate::mcp::config::McpConfig::parse(&raw) else {
            continue;
        };
        effective_mcp.servers.extend(layer.servers);
        any_mcp = true;
    }
    if any_mcp {
        let pretty =
            serde_json::to_string_pretty(&effective_mcp).unwrap_or_else(|_| "{}".to_string());
        entries.push((
            "config/effective-mcp.json".to_string(),
            redactor.scrub(&sanitize_mcp_json_text(&pretty)),
        ));
    }

    // (b) Raw per-layer copies: an untouched (but secret-scrubbed) copy of
    // each layer's `.cockpit` tree under `config/layers/<label>/...` so real
    // precedence is inspectable and nothing is lost.
    let mut project_index = 0usize;
    for dir in layers {
        let label = layer_label(&dir.kind, project_index);
        if dir.kind == ConfigDirKind::Project {
            project_index += 1;
        }
        collect_layer_tree(
            &dir.path,
            &label,
            redactor,
            include_generated_artifacts,
            &mut entries,
        );
    }

    if entries.is_empty() {
        // No config found anywhere: write a small marker so `config/` exists
        // rather than failing or omitting the folder.
        entries.push((
            "config/NO-CONFIG-FOUND.txt".to_string(),
            "No cockpit config layers were found for this session's project root.\n".to_string(),
        ));
    }

    entries
}

/// Layers in deep-merge application order: less-specific first so the more-
/// specific layer's keys win (overlay-wins `deep_merge_value`). Home layers
/// keep discovery order; machine-local sits above them; project layers are
/// reversed (farthest ancestor first, cwd last) so the closest `.cockpit/`
/// has the final say.
fn merge_order(layers: &[ConfigDir]) -> Vec<&ConfigDir> {
    let home: Vec<&ConfigDir> = layers
        .iter()
        .filter(|d| matches!(d.kind, ConfigDirKind::HomeXdg | ConfigDirKind::HomeDot))
        .collect();
    let machine: Vec<&ConfigDir> = layers
        .iter()
        .filter(|d| d.kind == ConfigDirKind::MachineLocal)
        .collect();
    let mut project: Vec<&ConfigDir> = layers
        .iter()
        .filter(|d| d.kind == ConfigDirKind::Project)
        .collect();
    // discover_config_dirs lists project layers cwd-first; reverse so the
    // closest (cwd) layer is applied last and wins.
    project.reverse();

    let mut out = home;
    out.extend(machine);
    out.extend(project);
    out
}

/// Read a file as a JSON `Value`, or `None` if missing / unparseable.
fn read_json_value(path: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Recursively copy every regular file under `root` into the bundle at
/// `config/layers/<label>/<relative-path>`, scrubbing each file's contents
/// through `redactor`. Skips unreadable files and non-UTF-8 contents (config
/// is JSON / markdown / text — binary blobs aren't cockpit config and are
/// not exported). A missing / empty layer simply contributes nothing.
fn collect_layer_tree(
    root: &Path,
    label: &str,
    redactor: &RedactionTable,
    include_generated_artifacts: bool,
    out: &mut Vec<(String, String)>,
) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            let Ok(rel) = path.strip_prefix(root) else {
                continue;
            };
            if !include_generated_artifacts && is_generated_layer_artifact(rel, ft.is_dir()) {
                continue;
            }
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                let Some(rel_str) = rel.to_str() else {
                    continue;
                };
                // zip paths use forward slashes on every platform.
                let rel_str = rel_str.replace('\\', "/");
                match std::fs::read_to_string(&path) {
                    Ok(contents) => {
                        let contents = if rel_str == "mcp.json" {
                            sanitize_mcp_json_text(&contents)
                        } else if rel_str == "config.json"
                            || (rel_str.starts_with("providers/") && rel_str.ends_with(".json"))
                        {
                            sanitize_config_json_text(&contents)
                        } else {
                            contents
                        };
                        out.push((
                            format!("config/layers/{label}/{rel_str}"),
                            redactor.scrub(&contents),
                        ));
                    }
                    Err(_) => {
                        // Unreadable or non-UTF-8 (binary) — not cockpit
                        // config; skip rather than embed undecodable bytes.
                    }
                }
            }
        }
    }
}

const CONFIG_REDACTED: &str = "[REDACTED]";

fn sanitize_config_json_text(contents: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<Value>(contents) else {
        return contents.to_string();
    };
    sanitize_config_value(&mut value, false);
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| contents.to_string())
}

fn sanitize_config_value(value: &mut Value, auth_context: bool) {
    match value {
        Value::Object(obj) => {
            for (key, child) in obj.iter_mut() {
                let norm = normalize_secret_key(key);
                if is_secret_scalar_key(&norm) || (auth_context && norm == "value") {
                    redact_json_scalar_or_container(child);
                } else if norm == "headers" {
                    redact_header_container(child);
                } else if norm == "auth" || norm == "authorization" {
                    sanitize_config_value(child, true);
                    if child.is_string() {
                        redact_json_scalar_or_container(child);
                    }
                } else {
                    sanitize_config_value(child, auth_context);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                sanitize_config_value(item, auth_context);
            }
        }
        _ => {}
    }
}

fn normalize_secret_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}

fn is_secret_scalar_key(norm: &str) -> bool {
    norm == "apikey"
        || norm == "credentialref"
        || norm == "authorization"
        || norm.contains("token")
        || norm.contains("secret")
        || norm.contains("password")
}

fn redact_header_container(value: &mut Value) {
    match value {
        Value::Object(obj) => {
            for value in obj.values_mut() {
                redact_json_scalar_or_container(value);
            }
        }
        Value::Array(items) => {
            for item in items {
                if let Some(obj) = item.as_object_mut() {
                    for (key, value) in obj.iter_mut() {
                        let norm = normalize_secret_key(key);
                        if norm == "value" || is_secret_scalar_key(&norm) {
                            redact_json_scalar_or_container(value);
                        }
                    }
                } else {
                    redact_json_scalar_or_container(item);
                }
            }
        }
        _ => redact_json_scalar_or_container(value),
    }
}

fn redact_json_scalar_or_container(value: &mut Value) {
    match value {
        Value::Object(obj) => {
            for value in obj.values_mut() {
                redact_json_scalar_or_container(value);
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_json_scalar_or_container(item);
            }
        }
        Value::String(_) | Value::Number(_) | Value::Bool(_) => {
            *value = Value::String(CONFIG_REDACTED.to_string());
        }
        Value::Null => {}
    }
}

const MCP_REDACTED: &str = "[REDACTED]";

fn sanitize_mcp_json_text(contents: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<Value>(contents) else {
        return contents.to_string();
    };
    sanitize_mcp_value(&mut value);
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| contents.to_string())
}

fn sanitize_mcp_value(value: &mut Value) {
    let Some(servers) = value.get_mut("servers").and_then(Value::as_object_mut) else {
        return;
    };
    for server in servers.values_mut() {
        let Some(obj) = server.as_object_mut() else {
            continue;
        };
        if let Some(endpoint) = obj.get("endpoint").and_then(Value::as_str) {
            let endpoint = redact_endpoint_url(endpoint);
            obj.insert("endpoint".to_string(), Value::String(endpoint));
        }
        redact_object_values(obj.get_mut("env"));
        redact_object_values(obj.get_mut("env_credential_refs"));
        if let Some(auth) = obj.get_mut("auth").and_then(Value::as_object_mut) {
            match auth.get("kind").and_then(Value::as_str) {
                Some("header") => {
                    redact_scalar(auth.get_mut("value"));
                    redact_scalar(auth.get_mut("credential_ref"));
                }
                Some("env") => {
                    redact_object_values(auth.get_mut("vars"));
                    redact_object_values(auth.get_mut("credential_refs"));
                }
                Some("oauth") => {
                    redact_scalar(auth.get_mut("credential_ref"));
                }
                _ => {}
            }
        }
    }
}

fn redact_scalar(value: Option<&mut Value>) {
    if let Some(value @ Value::String(_)) = value {
        *value = Value::String(MCP_REDACTED.to_string());
    }
}

fn redact_object_values(value: Option<&mut Value>) {
    let Some(obj) = value.and_then(Value::as_object_mut) else {
        return;
    };
    for value in obj.values_mut() {
        if value.is_string() {
            *value = Value::String(MCP_REDACTED.to_string());
        }
    }
}

fn redact_endpoint_url(endpoint: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(endpoint) else {
        return endpoint.to_string();
    };
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| {
            let value = if is_sensitive_query_key(&k) {
                MCP_REDACTED.to_string()
            } else {
                v.into_owned()
            };
            (k.into_owned(), value)
        })
        .collect();
    if pairs.is_empty() {
        return endpoint.to_string();
    }
    url.query_pairs_mut().clear().extend_pairs(pairs.iter());
    url.to_string()
}

fn is_sensitive_query_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("api_key")
        || key.contains("apikey")
        || key.contains("access_token")
        || key.contains("auth_token")
        || key == "token"
        || key == "key"
        || key == "bearer"
        || key == "authorization"
        || key == "password"
        || key == "secret"
}

fn is_generated_layer_artifact(rel: &Path, is_dir: bool) -> bool {
    let mut components = rel.components();
    let Some(first) = components.next().and_then(|c| c.as_os_str().to_str()) else {
        return false;
    };
    let is_top_level = components.next().is_none();

    let generated_root = matches!(
        first,
        "exports" | "cache" | "caches" | "tmp" | "temp" | "scratch"
    );
    if generated_root {
        return true;
    }
    if is_dir {
        return false;
    }

    let name = rel.file_name().and_then(|s| s.to_str()).unwrap_or_default();
    is_top_level
        && (name.ends_with(".zip")
            || name.ends_with(".tar")
            || name.ends_with(".tar.gz")
            || name.ends_with(".tgz")
            || name.ends_with(".debug.json")
            || name.ends_with(".debug.log"))
}

/// `./cockpit-session-<short_id>.zip`, falling back to the UUID when no
/// short id is set.
pub fn default_output_path(target: &SessionRow) -> PathBuf {
    let id = target
        .short_id
        .clone()
        .unwrap_or_else(|| target.session_id.to_string());
    PathBuf::from(format!("cockpit-session-{id}.zip"))
}

#[cfg(test)]
mod tests;
