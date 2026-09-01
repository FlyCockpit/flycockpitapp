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
//! ├── text_artifacts/
//! │   ├── index.json          # typed owner/ref/accounting manifest
//! │   └── {artifact_uuid}.txt
//! ├── delegation_payloads/
//! │   └── {short_id}_{task_call_id}_{label}_{hash}.txt
//! ├── inference_requests/
//! │   └── {seq:05}_{short_id}_{call_id}.json
//! └── inference_requests_tandem/   # model-comparison shadow records
//!     └── {seq:05}_{short_id}_{call_id}__{provider}_{model}.json
//! ```

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{Cursor, Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use rusqlite::Connection;
use serde_json::{Value, json};
use uuid::Uuid;
use zip::write::{SimpleFileOptions, ZipWriter};

use crate::approval::store::{ManagedGrants, global_approvals_dir, list_managed_grants};
use crate::config::dirs::{ConfigDir, ConfigDirKind, discover_config_dirs};
use crate::daemon::proto;
use crate::db::Db;
use crate::db::session_log::SessionEventRow;
use crate::db::sessions::SessionRow;
use crate::db::task_delegation_payloads::{LoadedTaskDelegationPayload, TaskDelegationPayloadRow};
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
const TEXT_ARTIFACTS_DIR: &str = "text_artifacts";
const DELEGATION_PAYLOADS_DIR: &str = "delegation_payloads";
const DELEGATION_STEERS_DIR: &str = "delegation_steers";
const DELEGATIONS_DIR: &str = "delegations";

/// Build the user-facing `/export` transcript from durable session history.
///
/// The transcript reflects the session rows persisted at the instant the DB
/// snapshot is read; it does not impose an extra daemon flush barrier. It is
/// scoped to the current root session's display history. Fork trees and
/// compaction predecessors remain part of `/export debug`, and rows that never
/// persist to the DB (local command errors, local commands, warning notices,
/// maintenance lines, skill auto-injection notices) cannot appear here.
pub async fn transcript_json(db: &Db, session_id: Uuid, root_agent: &str) -> Result<Value> {
    let history = crate::engine::rehydrate::history_snapshot(db, session_id, root_agent).await?;
    Ok(transcript_json_from_history(&history))
}

pub fn transcript_json_blocking_for_sync_cli(
    db: &Db,
    session_id: Uuid,
    root_agent: &str,
) -> Result<Value> {
    let root_agent = root_agent.to_string();
    db.blocking_for_sync_cli(move |conn| transcript_json_conn(conn, session_id, &root_agent))
}

pub fn transcript_json_conn(
    conn: &Connection,
    session_id: Uuid,
    root_agent: &str,
) -> Result<Value> {
    let history = crate::engine::rehydrate::history_snapshot_conn(conn, session_id, root_agent)?;
    Ok(transcript_json_from_history(&history))
}

fn transcript_json_from_history(history: &[proto::HistoryEntry]) -> Value {
    let mut turns = Vec::new();
    let mut pending_tool_calls = Vec::new();

    for entry in history {
        match entry {
            proto::HistoryEntry::ToolCall {
                call_id,
                parent_call_id,
                parent_child_index,
                tool,
                mcp_server,
                mcp_builtin,
                mcp_kind,
                original_input,
                output,
                hard_fail,
                ..
            } => {
                if is_edit_tool(tool)
                    && let Some((path, old, new)) = extract_edit_args(original_input)
                {
                    flush_tool_calls(&mut turns, &mut pending_tool_calls);
                    turns.push(json!({
                        "type": "diff",
                        "tool": tool,
                        "path": path,
                        "old": old,
                        "new": new,
                    }));
                    continue;
                }
                let presentation =
                    crate::engine::tool::known_tool_presentation(tool, original_input);
                if is_write_tool(tool) {
                    flush_tool_calls(&mut turns, &mut pending_tool_calls);
                    turns.push(json!({
                        "type": "tool_call",
                        "call_id": call_id,
                        "tool": tool,
                        "summary": presentation.summary,
                        "state": tool_state_str(*hard_fail),
                    }));
                    continue;
                }

                let mut value = json!({
                    "call_id": call_id,
                    "tool": tool,
                    "summary": presentation.summary,
                    "input": presentation.full_input,
                    "output": output,
                    "state": tool_state_str(*hard_fail),
                });
                if let (Some(parent_call_id), Some(parent_child_index)) =
                    (parent_call_id, parent_child_index)
                {
                    value["mcp_child"] = json!({
                        "parent_call_id": parent_call_id,
                        "parent_child_index": parent_child_index,
                        "server": mcp_server,
                        "builtin": mcp_builtin,
                        "kind": mcp_kind,
                    });
                }
                pending_tool_calls.push(value);
            }
            proto::HistoryEntry::InterruptDecision { decision, .. } => {
                flush_tool_calls(&mut turns, &mut pending_tool_calls);
                turns.push(json!({
                    "type": "interrupt_decision",
                    "permission": decision.permission,
                    "cancelled": decision.cancelled,
                    "lines": decision.lines,
                }));
            }
            proto::HistoryEntry::User {
                text,
                display_text,
                tag_expansions,
                ts_ms,
                origin_principal,
                ..
            } => {
                flush_tool_calls(&mut turns, &mut pending_tool_calls);
                let display = display_text
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .unwrap_or(text);
                if let Some(origin) = origin_principal
                    .as_deref()
                    .filter(|origin| !origin.trim().is_empty())
                {
                    turns.push(json!({
                        "type": "note",
                        "text": format!("steer from {origin}: {display}"),
                    }));
                } else {
                    turns.push(json!({
                        "type": "user",
                        "text": display,
                        "timestamp": timestamp_json(*ts_ms),
                    }));
                }
                for expansion in tag_expansions {
                    let mark = if expansion.ok { '✓' } else { '✗' };
                    turns.push(json!({
                        "type": "note",
                        "text": format!(
                            "  → {}({}) {mark} {}",
                            expansion.tool, expansion.path, expansion.detail
                        ),
                    }));
                }
            }
            proto::HistoryEntry::UserNote { text, ts_ms, .. } => {
                flush_tool_calls(&mut turns, &mut pending_tool_calls);
                turns.push(json!({
                    "type": "user_note",
                    "text": text,
                    "timestamp": timestamp_json(*ts_ms),
                }));
            }
            proto::HistoryEntry::Assistant {
                agent,
                text,
                presentation_text,
                reasoning,
                response_performance,
                ts_ms,
                ..
            } => {
                flush_tool_calls(&mut turns, &mut pending_tool_calls);
                let display_text = presentation_text.as_deref().unwrap_or(text);
                turns.push(json!({
                    "type": "assistant",
                    "agent": agent,
                    "text": display_text,
                    "reasoning": reasoning,
                    "timestamp": timestamp_json(*ts_ms),
                    "think_ms": Option::<u64>::None,
                    "response_performance": response_performance.as_ref().map(|p| json!({
                        "ttft_ms": p.ttft_ms,
                        "generation_ms": p.generation_ms,
                        "displayed_tokens": p.displayed_tokens,
                        "encoding": p.encoding,
                    })),
                }));
            }
            proto::HistoryEntry::InferenceError {
                summary, detail, ..
            } => {
                flush_tool_calls(&mut turns, &mut pending_tool_calls);
                turns.push(json!({
                    "type": "inference_error",
                    "text": summary,
                    "summary": summary,
                    "detail": detail,
                }));
            }
            proto::HistoryEntry::CompactBoundary {
                predecessor_short_id,
                seed_tool_count,
                seed_tool_tokens,
                source,
                trigger_ctx_pct,
                tokens_before,
                tokens_after,
                turns_summarized,
                tail_kept,
                tail_trimmed,
                brief,
                handoff,
                ..
            } => {
                flush_tool_calls(&mut turns, &mut pending_tool_calls);
                turns.push(json!({
                    "type": "compact_boundary",
                    "predecessor_short_id": predecessor_short_id,
                    "seed_tool_count": seed_tool_count,
                    "seed_tool_tokens": seed_tool_tokens,
                    "source": source,
                    "trigger_ctx_pct": trigger_ctx_pct,
                    "tokens_before": tokens_before,
                    "tokens_after": tokens_after,
                    "turns_summarized": turns_summarized,
                    "tail_kept": tail_kept,
                    "tail_trimmed": tail_trimmed,
                    "handoff": handoff.as_ref().or(brief.as_ref()),
                }));
            }
            proto::HistoryEntry::Subagent { parent, child, .. } => {
                flush_tool_calls(&mut turns, &mut pending_tool_calls);
                turns.push(json!({
                    "type": "subagent",
                    "parent": parent,
                    "child": child,
                    "model_trusted": false,
                    "routing": {
                        "model": Option::<String>::None,
                        "location": Option::<String>::None,
                        "fallback": Option::<String>::None,
                    },
                    "report": Option::<String>::None,
                    "failed": Option::<bool>::None,
                    "duration_ms": Option::<u64>::None,
                }));
            }
        }
    }
    flush_tool_calls(&mut turns, &mut pending_tool_calls);
    Value::Array(turns)
}

fn flush_tool_calls(turns: &mut Vec<Value>, pending_tool_calls: &mut Vec<Value>) {
    if pending_tool_calls.is_empty() {
        return;
    }
    turns.push(json!({
        "type": "tool_calls",
        "calls": std::mem::take(pending_tool_calls),
    }));
}

fn timestamp_json(ts_ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ts_ms)
        .map(|dt| dt.with_timezone(&chrono::Local))
        .unwrap_or_else(chrono::Local::now)
        .to_rfc3339()
}

fn tool_state_str(hard_fail: bool) -> &'static str {
    if hard_fail { "bad_call" } else { "success" }
}

fn is_edit_tool(tool: &str) -> bool {
    tool == "edit"
}

fn is_write_tool(tool: &str) -> bool {
    tool == "write"
}

fn extract_edit_args(args: &Value) -> Option<(&str, &str, &str)> {
    Some((
        args.get("path")?.as_str()?,
        args.get("old_string")?.as_str()?,
        args.get("new_string")?.as_str()?,
    ))
}

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

/// `fs_safe` applied to a session-derived path component **after** it has been
/// scrubbed through the export redaction table. Every ZIP member path built
/// from session data (call ids, provider/model names, delegation labels) is
/// routed through here so a secret embedded in an identifier is redacted before
/// `fs_safe` sanitization and before `start_file` — never written raw into an
/// archive entry name. Scrub first, then `fs_safe`, so the placeholder's spaces
/// and `*` collapse to `_`. The corresponding event `"file"`/`"output_file"`
/// values are always set from the same emitted path, so references never dangle.
fn fs_safe_scrubbed(s: &str, redactor: &RedactionTable) -> String {
    fs_safe(&redactor.scrub(s))
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
///
/// This is the **default, non-bypassable** path: every member is scrubbed
/// through the enforced export redaction table, so `redact.enabled = false`
/// cannot disable export scrubbing, and provider trust — which may let raw
/// values reach a trusted model during inference — never relaxes export
/// redaction. The daemon RPC and TUI export exclusively through this path. The
/// only unredacted export is the explicit local
/// [`build_bundle_zip_bytes_raw_local`] (`cockpit export --include-sensitive`),
/// which is never reachable over the RPC or the TUI.
///
/// `env` is the live daemon environment (the RPC threads `ctx.env_baseline`) so
/// the export redaction table's `scan_environment` pass keeps env-derived
/// secrets scrubbed even when they were never persisted, journaled, or vaulted —
/// the same env source the live per-session redaction path consumes.
pub async fn build_bundle_zip_bytes(
    db: &Db,
    target: &SessionRow,
    include_generated_artifacts: bool,
    vault: &crate::secure_key::SecretVault,
    resolver: std::sync::Arc<dyn crate::redact::protected_redaction_history::RedactionKeyResolver>,
    env: HashMap<String, String>,
) -> Result<BundleBytes> {
    let db_for_files = db.clone();
    let target_id = target.session_id;
    let vault = vault.clone();
    let store =
        crate::credentials::CredentialStore::from_vault(std::sync::Arc::new(vault.clone()))?;
    // Warm EVERY historical key version before entering the read snapshot, so the
    // in-snapshot protected-history fold can decrypt any bundled session's rows
    // synchronously (the resolver `resolve` is warm-cache-only). Fails closed if
    // a historical key is unavailable.
    crate::redact::protected_redaction_history::warm_all_redaction_key_versions(resolver.as_ref())
        .await?;
    db.read(move |conn| {
        assemble_bundle_snapshot_conn(
            &db_for_files,
            conn,
            target_id,
            ExportBundleOptions {
                include_generated_artifacts,
                redacted: true,
            },
            &env,
            Some(&vault),
            Some(&store),
            Some(resolver.as_ref()),
        )
    })
    .await
}

/// Assemble the REDACTED transcript-JSON export inside ONE read snapshot: the
/// message reads, the protected-history fold, and the scrub all run against the
/// same `tx`, so the emitted transcript body and the folded-literal set come
/// from the SAME snapshot by construction. A protected-history row classifying a
/// literal that appears in the transcript, committed concurrently, is either
/// visible to the snapshot (and folded) or invisible to it (and its message is
/// not in the transcript either) — closing the discover-then-assemble TOCTOU the
/// two-snapshot path had. Warms the resolver before the sync snapshot (its
/// `resolve` is warm-cache-only). Fails closed on any resolver/integrity error.
///
/// `env` is the live daemon environment (the RPC threads `ctx.env_baseline`) so
/// an env-derived secret surfacing in a transcript member is scrubbed by the
/// table's `scan_environment` pass even when it was never persisted or journaled.
pub async fn build_redacted_transcript_json_bytes(
    db: &Db,
    target: &SessionRow,
    vault: &crate::secure_key::SecretVault,
    resolver: std::sync::Arc<dyn crate::redact::protected_redaction_history::RedactionKeyResolver>,
    env: HashMap<String, String>,
) -> Result<Vec<u8>> {
    let target_id = target.session_id;
    let vault = vault.clone();
    let store =
        crate::credentials::CredentialStore::from_vault(std::sync::Arc::new(vault.clone()))?;
    crate::redact::protected_redaction_history::warm_all_redaction_key_versions(resolver.as_ref())
        .await?;
    db.read(move |conn| {
        let tx = conn
            .unchecked_transaction()
            .context("starting transcript export read snapshot")?;
        let conn: &Connection = &tx;
        // Reload the target inside the snapshot so its rows and its history are
        // read consistently with the messages below.
        let target = Db::get_session_conn(conn, target_id)?
            .with_context(|| format!("export target session `{target_id}` no longer exists"))?;

        let mut messages = Vec::new();
        let mut before_seq = None;
        loop {
            let (mut page, has_more) =
                Db::read_session_messages_conn(conn, target_id, before_seq, u32::MAX)?;
            if page.is_empty() {
                break;
            }
            before_seq = page.first().map(|message| message.seq);
            messages.append(&mut page);
            if !has_more {
                break;
            }
        }
        messages.sort_by_key(|message| message.seq);

        // Build the enforced redactor IN the snapshot, folding this session's
        // protected-history literals from the same `tx`.
        let export_redactor = export_redaction_table_for_sessions(
            Some(&vault),
            Some(&store),
            Some(conn),
            &target,
            std::slice::from_ref(&target),
            &env,
            Some(resolver.as_ref()),
        )?;
        let mut messages_value = serde_json::to_value(&messages)?;
        scrub_export_json_value(&mut messages_value, &export_redactor);
        let bytes = serde_json::to_vec_pretty(&messages_value)?;
        tx.commit()
            .context("finishing transcript export read snapshot")?;
        Ok(bytes)
    })
    .await
}

/// EXPLICIT LOCAL RAW EXPORT — the single unredacted export path (user-settled
/// exception).
///
/// This emits every stored artifact **as-is**, with no scrubbing: it builds an
/// empty redaction table (a no-op matcher), performs **no**
/// `protected_redaction_history` rehydration, and starts **no** secure-key
/// actor / key resolver. `manifest.json` records `"redacted": false`.
///
/// It is a distinct entry point rather than a boolean threaded onto the
/// redacted path precisely so a future RPC/TUI caller cannot reach raw output
/// by omission: only the local `cockpit export --include-sensitive` command
/// surface calls this. The daemon RPC (`Request::ExportSessionData`) and the
/// TUI have no raw option and stay invariantly redacted.
pub async fn build_bundle_zip_bytes_raw_local(
    db: &Db,
    target: &SessionRow,
    include_generated_artifacts: bool,
) -> Result<BundleBytes> {
    let db_for_files = db.clone();
    let target_id = target.session_id;
    db.read(move |conn| {
        // Raw export: no redactor, and therefore no journal rehydration — the
        // `None` resolver is never consulted (the redacted branch owns it).
        assemble_bundle_snapshot_conn(
            &db_for_files,
            conn,
            target_id,
            ExportBundleOptions {
                include_generated_artifacts,
                redacted: false,
            },
            &HashMap::new(),
            None,
            None,
            None,
        )
    })
    .await
}

/// Assemble the full debug bundle for `target` (the session plus its
/// descendant forks and `/compact` successors) and write it to
/// `out_path`. This is the single zip-assembly implementation behind
/// both the CLI `cockpit export` and the TUI `/export debug` command.
///
/// `overwrite` controls the clobber policy: `false` refuses to replace
/// an existing file (the CLI's no-clobber-without-`--force` guarantee);
/// `true` replaces it unconditionally (the TUI path, which has no force
/// flag and is specified to overwrite its own prior export).
///
/// `#[cfg(test)]`-ONLY: the production CLI/TUI export exclusively through the
/// daemon RPC (`build_bundle_zip_bytes`), which threads the real warm redaction
/// key resolver so protected-history secrets are folded. Compile-gating this
/// file-writing helper guarantees no production path can assemble a redacted
/// archive with an inert (test) resolver.
#[cfg(test)]
pub async fn write_bundle_zip(
    db: &Db,
    target: &SessionRow,
    out_path: &std::path::Path,
    overwrite: bool,
    include_generated_artifacts: bool,
    vault: &crate::secure_key::SecretVault,
) -> Result<BundleSummary> {
    if out_path.exists() && !overwrite {
        anyhow::bail!(
            "output path `{}` already exists — pass `--force` to overwrite",
            out_path.display()
        );
    }

    let bundle = build_bundle_zip_bytes(
        db,
        target,
        include_generated_artifacts,
        vault,
        crate::session::test_redaction_key_resolver(),
        HashMap::new(),
    )
    .await?;

    if let Some(parent) = out_path.parent()
        && !parent.as_os_str().is_empty()
    {
        cockpit_host::private_fs::ensure_output_parent_private(parent)
            .with_context(|| format!("securing export directory `{}`", parent.display()))?;
    }
    cockpit_host::private_fs::write_private_export_file(out_path, &bundle.bytes)
        .with_context(|| format!("writing private export to `{}`", out_path.display()))?;

    Ok(bundle.summary)
}

/// EXPLICIT LOCAL RAW EXPORT twin of [`write_bundle_zip`] for the
/// `cockpit export --include-sensitive` command. Assembles the **unredacted**
/// archive via [`build_bundle_zip_bytes_raw_local`] and writes it through the
/// same fail-closed private-file gate and `overwrite`/`--force` clobber policy
/// as the redacted path. It starts no secure-key actor and rehydrates nothing.
/// The stderr "raw secrets" warning is emitted by the CLI command surface, not
/// here.
pub async fn write_bundle_zip_raw_local(
    db: &Db,
    target: &SessionRow,
    out_path: &std::path::Path,
    overwrite: bool,
    include_generated_artifacts: bool,
) -> Result<BundleSummary> {
    if out_path.exists() && !overwrite {
        anyhow::bail!(
            "output path `{}` already exists — pass `--force` to overwrite",
            out_path.display()
        );
    }

    let bundle = build_bundle_zip_bytes_raw_local(db, target, include_generated_artifacts).await?;

    if let Some(parent) = out_path.parent()
        && !parent.as_os_str().is_empty()
    {
        cockpit_host::private_fs::ensure_output_parent_private(parent)
            .with_context(|| format!("securing export directory `{}`", parent.display()))?;
    }
    cockpit_host::private_fs::write_private_export_file(out_path, &bundle.bytes)
        .with_context(|| format!("writing private export to `{}`", out_path.display()))?;

    Ok(bundle.summary)
}

/// Assemble every database-backed export entry under one deferred read
/// transaction. On a WAL database this pins one snapshot without excluding
/// concurrent writers. Reloading the target is deliberately the first query:
/// callers resolve a session before reaching this function, and that row may
/// have changed (or disappeared) before the export worker checks out its
/// connection.
#[allow(clippy::too_many_arguments)]
fn assemble_bundle_snapshot_conn(
    db: &Db,
    conn: &Connection,
    target_id: Uuid,
    options: ExportBundleOptions,
    env: &HashMap<String, String>,
    vault: Option<&crate::secure_key::SecretVault>,
    store: Option<&crate::credentials::CredentialStore>,
    resolver: Option<&dyn crate::redact::protected_redaction_history::RedactionKeyResolver>,
) -> Result<BundleBytes> {
    assemble_bundle_snapshot_conn_with_after_collect(
        db,
        conn,
        target_id,
        options,
        env,
        vault,
        store,
        resolver,
        || Ok(()),
    )
}

#[allow(clippy::too_many_arguments)]
fn assemble_bundle_snapshot_conn_with_after_collect<F>(
    db: &Db,
    conn: &Connection,
    target_id: Uuid,
    options: ExportBundleOptions,
    env: &HashMap<String, String>,
    vault: Option<&crate::secure_key::SecretVault>,
    store: Option<&crate::credentials::CredentialStore>,
    resolver: Option<&dyn crate::redact::protected_redaction_history::RedactionKeyResolver>,
    after_collect: F,
) -> Result<BundleBytes>
where
    F: FnOnce() -> Result<()>,
{
    // `unchecked_transaction` accepts `&Connection`, which is required by the
    // read-pool closure API. Its default DEFERRED behavior is important here:
    // the first SELECT below establishes a WAL read snapshot while writers
    // remain free to commit.
    let tx = conn
        .unchecked_transaction()
        .context("starting session export read snapshot")?;
    let target = Db::get_session_conn(&tx, target_id)?
        .with_context(|| format!("export target session `{target_id}` no longer exists"))?;
    let bundle = collect_bundle_conn(&tx, target_id)?;

    // Deterministic test seam for committing an independent WAL writer after
    // bundle discovery but before the export's later event/manifest queries.
    after_collect()?;

    let bytes = build_zip_with_options_and_env_conn(
        db, &tx, &target, &bundle, options, env, vault, store, resolver,
    )?;
    let summary = BundleSummary {
        session_count: bundle.len(),
        byte_len: bytes.len(),
    };
    tx.commit()
        .context("finishing session export read snapshot")?;
    Ok(BundleBytes { bytes, summary })
}

/// Resolve a user-supplied identifier to a session row. `Ok(Ok(row))` on
/// success; `Ok(Err(message))` for a usage error (not found / ambiguous)
/// the caller surfaces with exit 64. A full UUID resolves directly; any
/// other string is treated as a `short_id` and matched globally.
pub async fn resolve_session(
    db: &Db,
    ident: &str,
) -> Result<std::result::Result<SessionRow, String>> {
    if let Ok(uuid) = Uuid::parse_str(ident) {
        return Ok(
            match db
                .read(move |conn| crate::db::Db::get_session_conn(conn, uuid))
                .await?
            {
                Some(row) => Ok(row),
                None => Err(format!("no session with id `{ident}`")),
            },
        );
    }
    let ident_for_db = ident.to_string();
    let matches = db
        .read(move |conn| crate::db::Db::find_sessions_by_short_id_global_conn(conn, &ident_for_db))
        .await?;
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
fn collect_bundle_conn(conn: &Connection, target_id: Uuid) -> Result<Vec<SessionRow>> {
    let mut seen: HashSet<Uuid> = HashSet::new();
    let mut order: Vec<SessionRow> = Vec::new();
    let mut frontier: VecDeque<Uuid> = VecDeque::new();
    frontier.push_back(target_id);

    while let Some(id) = frontier.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        let Some(row) = Db::get_session_conn(conn, id)? else {
            continue;
        };
        order.push(row);

        // Descendant forks.
        for child in Db::list_forks_conn(conn, id)? {
            frontier.push_back(child.session_id);
        }
        // `/compact` successor sessions (a session boundary, not a fork —
        // followed like the fork tree per Part C).
        for ev in Db::list_session_events_conn(conn, id)? {
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

#[cfg(test)]
async fn collect_bundle(db: &Db, target_id: Uuid) -> Result<Vec<SessionRow>> {
    db.read(move |conn| collect_bundle_conn(conn, target_id))
        .await
}

/// Assemble the `.zip` bytes in memory: `manifest.json`, the unified
/// `events.json`, and one `inference_requests/` file per inference call
/// across every session in the bundle.
///
/// `redacted` selects the export policy. The default (`true`) is the
/// non-bypassable path: every member body **and** every session-derived member
/// path is scrubbed through the enforced export redaction table
/// (`redact.enabled = false` cannot disable it) and `manifest.json` records
/// `"redacted": true`. The only `false` producer is the explicit local
/// `cockpit export --include-sensitive` opt-in
/// ([`build_bundle_zip_bytes_raw_local`]); it emits stored artifacts as-is via
/// an empty (no-op) table and is never reachable over the daemon RPC or the
/// TUI. Provider trust controls inference custody only; it never relaxes export
/// redaction.
#[derive(Debug, Clone, Copy)]
struct ExportBundleOptions {
    include_generated_artifacts: bool,
    /// Whether this export scrubs through the enforced redaction table. `true`
    /// for every default path (CLI, TUI, RPC); `false` only for the explicit
    /// local raw opt-in.
    redacted: bool,
}

impl Default for ExportBundleOptions {
    fn default() -> Self {
        Self {
            include_generated_artifacts: false,
            // Default to the non-bypassable redacted policy: a raw export is
            // only ever produced by the explicit local opt-in, never by
            // omission.
            redacted: true,
        }
    }
}

#[cfg(test)]
fn test_export_env() -> HashMap<String, String> {
    HashMap::new()
}

#[cfg(test)]
pub(crate) async fn build_zip(
    db: &Db,
    target: &SessionRow,
    bundle: &[SessionRow],
) -> Result<Vec<u8>> {
    build_zip_with_options_and_env(
        db,
        target,
        bundle,
        ExportBundleOptions::default(),
        &test_export_env(),
    )
    .await
}

#[cfg(test)]
async fn build_zip_with_options_and_env(
    db: &Db,
    target: &SessionRow,
    bundle: &[SessionRow],
    options: ExportBundleOptions,
    env: &HashMap<String, String>,
) -> Result<Vec<u8>> {
    let db_for_files = db.clone();
    let target = target.clone();
    let bundle = bundle.to_vec();
    let env = env.clone();
    let vault = if options.redacted {
        Some(crate::secure_key::vault_for_db(db).map_err(|e| anyhow::anyhow!("{e}"))?)
    } else {
        None
    };
    let store = vault
        .as_ref()
        .map(|vault| crate::credentials::CredentialStore::from_vault(std::sync::Arc::clone(vault)))
        .transpose()?;
    // Redacted test assemblies get a warmed test resolver so the in-snapshot
    // protected-history fold can decrypt any rows synchronously (raw = None).
    let resolver = if options.redacted {
        let resolver = crate::session::test_redaction_key_resolver();
        crate::redact::protected_redaction_history::warm_all_redaction_key_versions(
            resolver.as_ref(),
        )
        .await?;
        Some(resolver)
    } else {
        None
    };
    let trust_policy = crate::config::trust::current_workspace_trust_policy();
    db.read(move |conn| {
        let build = || {
            build_zip_with_options_and_env_conn(
                &db_for_files,
                conn,
                &target,
                &bundle,
                options,
                &env,
                vault.as_deref(),
                store.as_ref(),
                resolver.as_deref(),
            )
        };
        match trust_policy {
            Some(policy) => crate::config::trust::with_workspace_trust_policy(policy, build),
            None => build(),
        }
    })
    .await
}

#[allow(clippy::too_many_arguments)]
fn build_zip_with_options_and_env_conn(
    db: &Db,
    conn: &Connection,
    target: &SessionRow,
    bundle: &[SessionRow],
    options: ExportBundleOptions,
    env: &HashMap<String, String>,
    vault: Option<&crate::secure_key::SecretVault>,
    store: Option<&crate::credentials::CredentialStore>,
    resolver: Option<&dyn crate::redact::protected_redaction_history::RedactionKeyResolver>,
) -> Result<Vec<u8>> {
    let export_redactor = if options.redacted {
        // Non-bypassable default: the enforced table unioned across every
        // bundled session's persisted redaction-table union (column or vault),
        // then folded IN-SNAPSHOT with each bundled session's rehydrated
        // protected-history literals (the resolver must be present and warm).
        // Fails closed if a persisted/vault table cannot be parsed or a literal
        // cannot be rehydrated.
        let resolver =
            resolver.context("a redacted export requires a warm redaction key resolver")?;
        export_redaction_table_for_bundle(vault, store, Some(conn), target, bundle, env, resolver)?
    } else {
        // Explicit local raw export: a no-op table so every member body and
        // member path is emitted exactly as stored. No journal rehydration and
        // no key resolver are involved.
        RedactionTable::empty()
    };
    build_zip_with_options_and_env_conn_with_redactor(
        db,
        conn,
        target,
        bundle,
        options,
        env,
        &export_redactor,
    )
}

/// Test-only seam for asserting that a redaction-table construction failure
/// aborts bundle assembly before any archive bytes are returned.
#[cfg(test)]
fn build_zip_with_options_and_redactor_result_for_test(
    db: &Db,
    conn: &Connection,
    target: &SessionRow,
    bundle: &[SessionRow],
    options: ExportBundleOptions,
    env: &HashMap<String, String>,
    redactor: Result<RedactionTable>,
) -> Result<Vec<u8>> {
    let export_redactor = redactor.context("building export redaction table")?;
    build_zip_with_options_and_env_conn_with_redactor(
        db,
        conn,
        target,
        bundle,
        options,
        env,
        &export_redactor,
    )
}

fn build_zip_with_options_and_env_conn_with_redactor(
    db: &Db,
    conn: &Connection,
    target: &SessionRow,
    bundle: &[SessionRow],
    options: ExportBundleOptions,
    env: &HashMap<String, String>,
    export_redactor: &RedactionTable,
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
        all_events.extend(Db::list_session_events_conn(conn, s.session_id)?);
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
    let utility_call_ids = Db::utility_call_ids_conn(conn, &candidate_call_ids)?;
    // `(call_id, ordinal)` pairs that have a successful `inference_request`
    // event: each owns its own captured-body file. A failed/hung ATTEMPT records
    // an `inference_failure` event (not an `inference_request`) instead — its
    // captured body (status `timed_out`/`errored`/`pending`) is still stored, so
    // we assign a file off the failure event when no request event exists for
    // that SAME `(call_id, ordinal)`. The key is per-attempt, not per call: a
    // failed primary (ordinal 0) whose logical call later SUCCEEDED on a
    // failover attempt (ordinal 1) keeps its own immutable body file — the
    // sibling ordinal's success must never suppress it, or the export drops the
    // failed attempt's audited request body.
    let request_event_keys: HashSet<(String, i64)> = all_events
        .iter()
        .filter(|e| e.kind == "inference_request")
        .filter_map(|e| {
            let call_id = e.call_id.clone()?;
            let ordinal = e.data.get("ordinal").and_then(Value::as_i64).unwrap_or(0);
            Some((call_id, ordinal))
        })
        .collect();

    // First pass: assign inference_request filenames so the matching
    // event can reference the exact file (explicit correlation).
    // `{seq:05}_{short_id}_{call_id}.json`, in `inference_requests/` for
    // regular calls and `inference_requests_utility/` for utility calls.
    let mut request_files: Vec<(String, String, i64)> = Vec::new(); // (path, call_id, ordinal)
    let mut tool_output_files: Vec<(String, Value)> = Vec::new(); // (path, sidecar payload)
    // Artifact payloads are already transformed by the dedicated
    // length-preserving projection below, so they must bypass the ordinary
    // placeholder renderer at write time.
    let mut text_artifact_files: Vec<(String, String)> = Vec::new(); // (path, exported content)
    let mut text_artifact_index: Vec<Value> = Vec::new();
    let mut exported_source_preview: HashMap<(Uuid, i64), (String, usize)> = HashMap::new();
    // Projection state remains marker-free event metadata, but an available
    // tool artifact's previews describe the same exported body. Keep the
    // length-preserving form separately so the ordinary placeholder scrubber
    // cannot make a /3 event preview disagree with its sidecar on re-import.
    let mut exported_tool_artifact_previews: HashMap<(Uuid, i64, i64), (String, String)> =
        HashMap::new();
    let mut delegation_payload_files: Vec<(String, String)> = Vec::new(); // (path, content)
    let mut delegation_payload_index: Vec<Value> = Vec::new();
    let mut delegation_steer_index: Vec<Value> = Vec::new();
    let mut delegation_index: Vec<Value> = Vec::new();
    let mut tool_identity_by_call: BTreeMap<(Uuid, String), Value> = BTreeMap::new();
    let mut inference_call_index: Vec<Value> = Vec::new();
    let mut tool_call_index: Vec<Value> = Vec::new();
    for s in bundle {
        for job in Db::list_task_delegation_export_jobs_conn(conn, s.session_id)? {
            delegation_index.push(json!({
                "task_call_id": job.task_call_id, "function_call_id": job.function_call_id,
                "parent_session_id": job.parent_session_id, "parent_agent": job.parent_agent,
                "original_args_json": job.original_args_json, "status": job.status,
                "ack_delivered": job.ack_delivered, "final_delivered": job.final_delivered,
                "created_at": job.created_at, "updated_at": job.updated_at,
                "children": job.children.into_iter().map(|child| json!({
                    "label": child.label, "child_agent": child.child_agent, "model": child.model,
                    "status": child.status, "report": child.report, "output_dir": child.output_dir,
                    "todo_ids_json": child.todo_ids_json, "result_delivered": child.result_delivered,
                    "started_at": child.started_at, "finished_at": child.finished_at,
                    "created_at": child.created_at, "updated_at": child.updated_at,
                    "requested_cwd": child.requested_cwd, "resolved_cwd": child.resolved_cwd,
                })).collect::<Vec<_>>(),
            }));
        }
        for inference_call in Db::list_inference_calls_for_session_conn(conn, s.session_id)? {
            // Collected RAW; scrubbed exactly once by the member funnel at write.
            inference_call_index.push(inference_call_export_json(&inference_call));
        }
        for tool_call in Db::list_tool_calls_for_session_conn(conn, s.session_id)? {
            // Collected RAW; scrubbed exactly once by the member funnel at write.
            tool_call_index.push(tool_call_export_json(&tool_call));
            let identity = tool_provider_identity_json(&tool_call)?;
            tool_identity_by_call
                .insert((tool_call.session_id, tool_call.call_id.clone()), identity);
        }
        let short = short_ids
            .get(&s.session_id)
            .cloned()
            .unwrap_or_else(|| s.session_id.to_string());
        for entry in crate::db::text_artifacts::list_text_artifacts_conn(conn, s.session_id)? {
            let path = format!("{TEXT_ARTIFACTS_DIR}/{}.txt", entry.artifact_id);
            // `export_redacted` is an irreversible imported representation.
            // A later include-sensitive export has no raw body to restore and
            // must retain both its exact safe bytes and its representation
            // rather than relabeling them as raw.
            let raw_content =
                match crate::text_artifact_blob::path_from_provenance(&entry.provenance_json)? {
                    Some(blob_path) => {
                        crate::text_artifact_blob::read(&blob_path).with_context(|| {
                            format!("reading text artifact {} for export", entry.artifact_id)
                        })?
                    }
                    None => entry.content.clone(),
                };
            anyhow::ensure!(
                raw_content.len() == entry.content_bytes,
                "text artifact blob accounting differs from its ledger row"
            );
            let content = if entry.representation
                == crate::db::text_artifacts::TextArtifactRepresentation::ExportRedacted
            {
                raw_content
            } else if options.redacted {
                redact_artifact_length_preserving(&raw_content, export_redactor)
            } else {
                raw_content
            };
            debug_assert_eq!(content.len(), entry.content_bytes);
            let representation_mode = if entry.representation
                == crate::db::text_artifacts::TextArtifactRepresentation::ExportRedacted
                || options.redacted
            {
                "redacted_length_preserving"
            } else {
                "raw"
            };
            if entry.relation == crate::db::text_artifacts::TextArtifactRelation::SourceUserInput {
                let provenance: Value = serde_json::from_str(&entry.provenance_json)
                    .context("parsing source artifact provenance for export")?;
                let preview_lines = provenance
                    .get("preview_lines")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .filter(|value| *value > 0)
                    .unwrap_or(crate::agents::ContextPolicy::DEFAULT_ARTIFACT_PREVIEW_LINES);
                exported_source_preview.insert(
                    (entry.session_id, entry.event_seq),
                    (content.clone(), preview_lines),
                );
            }
            let model_envelope = if entry.relation
                == crate::db::text_artifacts::TextArtifactRelation::SourceUserInput
            {
                Db::user_message_model_envelope_conn(conn, entry.session_id, entry.event_seq)?
            } else {
                None
            };
            if entry.relation
                == crate::db::text_artifacts::TextArtifactRelation::ModelContextToolResult
            {
                let slot = entry
                    .projection_slot
                    .ok_or_else(|| anyhow!("tool artifact lacks an export projection slot"))?;
                let (head, tail) = crate::engine::text_artifact_frame::utf8_preview_pair(&content);
                exported_tool_artifact_previews.insert(
                    (entry.session_id, entry.event_seq, slot),
                    (head.to_owned(), tail.to_owned()),
                );
            }
            let index_entry = json!({
                "artifact_id": entry.artifact_id.to_string(),
                "session_id": entry.session_id.to_string(),
                "event_seq": entry.event_seq,
                "relation": entry.relation,
                "projection_slot": entry.projection_slot,
                "kind": entry.kind,
                "capture_reason": entry.capture_reason,
                "provenance": serde_json::from_str::<Value>(&entry.provenance_json)?,
                "host_captured_bytes": entry.host_captured_bytes,
                "host_original_bytes": entry.host_original_bytes,
                "host_dropped_bytes": entry.host_dropped_bytes,
                "stored_source_bytes": entry.stored_source_bytes,
                "model_envelope": model_envelope,
                "representation": { "mode": representation_mode, "content_bytes": content.len(), "content_file": path },
                "created_at": entry.created_at,
            });
            text_artifact_index.push(index_entry);
            text_artifact_files.push((path, content));
        }
        for row in Db::list_task_delegation_steers_conn(conn, s.session_id)? {
            // Collected RAW (body embedded whole, no truncation); the whole index
            // member is scrubbed exactly once by the funnel at write.
            delegation_steer_index.push(json!({
                "id": row.id,
                "task_call_id": row.task_call_id,
                "label": row.label,
                "session_id": s.session_id.to_string(),
                "short_id": short,
                "origin_principal": row.origin_principal,
                "body": row.body,
                "delivered": row.delivered,
                "created_at": row.created_at,
                "delivered_at": row.delivered_at,
            }));
        }
        for row in Db::list_task_delegation_payloads_conn(conn, s.session_id)? {
            let file = format!(
                "{DELEGATION_PAYLOADS_DIR}/{}_{}_{}_{}.txt",
                short,
                fs_safe_scrubbed(&row.task_call_id, export_redactor),
                fs_safe_scrubbed(&row.label, export_redactor),
                fs_safe(&row.payload_hash)
            );
            let loaded = load_task_delegation_payload_from_row(db, &row);
            let (excerpt, load_error, emit_file) = match loaded {
                Ok(payload) => {
                    // Scrub the body ONCE to build a leak-safe excerpt: a raw
                    // char-prefix could split a secret across the excerpt
                    // boundary, which the whole-literal member funnel could not
                    // match. The FILE body is emitted RAW below and scrubbed
                    // exactly once by its text funnel.
                    let scrubbed = redact_string_for_export(payload.body.clone(), export_redactor);
                    (
                        Some(row.excerpt(&scrubbed)),
                        None::<String>,
                        Some(payload.body),
                    )
                }
                Err(e) => (None, Some(format!("{e:#}")), None),
            };
            // Build the index entry with RAW metadata; the pre-scrubbed `excerpt`
            // and the entry-name `file` (already `fs_safe_scrubbed`) are inserted
            // AFTER the metadata scrub so they are never double-scrubbed.
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
                "source_sidecar": row.sidecar_path,
            });
            if let Some(load_error) = load_error
                && let Some(obj) = meta.as_object_mut()
            {
                obj.insert("load_error".to_string(), json!(load_error));
            }
            // Scrub the metadata (and load_error) EXACTLY once; the index is then
            // written via the prescrubbed writer, so nothing here is re-scrubbed.
            redact_value_for_export(&mut meta, export_redactor);
            if let Some(obj) = meta.as_object_mut() {
                if let Some(excerpt) = excerpt {
                    obj.insert("excerpt".to_string(), json!(excerpt));
                }
                if emit_file.is_some() {
                    obj.insert("file".to_string(), json!(file.clone()));
                }
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
                fs_safe_scrubbed(call_id, export_redactor)
            );
            value["output_file"] = json!(path);
            if let Some(data) = value["data"].as_object_mut() {
                data.remove("output_sidecar");
            }
            tool_output_files.push((path, sidecar));
        }
        // The dispatched-target attempt index this event owns. Two attempts of
        // one logical call share `call_id`, so the ordinal is part of the file
        // name and never collides on disk. Absent (compact-brief / legacy
        // events) → ordinal 0.
        let ordinal = ev.data.get("ordinal").and_then(Value::as_i64).unwrap_or(0);
        // An `inference_request` event always owns its `(call_id, ordinal)` file;
        // an `inference_failure` event owns one only when no successful request
        // event exists for the SAME `(call_id, ordinal)` (the hung/failed
        // ATTEMPT — the captured body still exists, with a non-`completed`
        // status). Keying per attempt means a failed primary whose logical call
        // later succeeded on a DIFFERENT ordinal is NOT suppressed by that
        // sibling's success: its immutable body is exported for auditability.
        let owns_file = match ev.kind.as_str() {
            "inference_request" => true,
            "inference_failure" => ev
                .call_id
                .as_deref()
                .is_some_and(|c| !request_event_keys.contains(&(c.to_string(), ordinal))),
            _ => false,
        };
        if owns_file && let Some(call_id) = ev.call_id.as_deref() {
            let dir = if utility_call_ids.contains(call_id) {
                REQ_DIR_UTILITY
            } else {
                REQ_DIR
            };
            let path = format!(
                "{dir}/{:05}_{}_{}_o{}.json",
                ev.seq,
                short,
                fs_safe_scrubbed(call_id, export_redactor),
                ordinal
            );
            // Surface the file reference on the event itself — pointing at
            // the correct (regular vs utility) folder.
            value["file"] = json!(path);
            request_files.push((path, call_id.to_string(), ordinal));
        }
        // Collected RAW; scrubbed exactly once by the events.json funnel at write.
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
        for rec in Db::list_tandem_inference_conn(conn, s.session_id)? {
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
                fs_safe_scrubbed(&rec.parent_call_id, export_redactor),
                fs_safe_scrubbed(&rec.provider, export_redactor),
                fs_safe_scrubbed(&rec.model, export_redactor),
            );
            let workspace_scratch_dir =
                crate::session::workspace_scratch_path_for_session(&s.project_id, s.session_id)?;
            let tool_call_validation = tandem_validation::validate_tandem_tool_calls(
                &rec.request,
                rec.response.as_ref(),
                Path::new(&s.project_root),
                None,
                Some(&workspace_scratch_dir),
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
            let event = json!({
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
            // Collected RAW; scrubbed exactly once by the events.json funnel.
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

    // Event members ordinarily use the common one-pass export scrubber. A
    // `user_input_source` keeps only its bounded, length-preserving preview in
    // the event; the separately exported artifact sidecar is the full body.
    // Rebuild that preview after the sidecar has crossed the export redactor so
    // import can verify the same no-full-body SQLite invariant.
    for value in &mut event_values {
        let source_preview = value
            .get("session_id")
            .and_then(Value::as_str)
            .and_then(|session_id| Uuid::parse_str(session_id).ok())
            .zip(value.get("seq").and_then(Value::as_i64))
            .and_then(|key| exported_source_preview.get(&key).cloned());
        redact_value_for_export(value, export_redactor);
        if let Some((source_text, preview_lines)) = source_preview {
            let data = value
                .get_mut("data")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| {
                    anyhow!("source artifact event lost its object data during export")
                })?;
            data.insert(
                "text".to_string(),
                json!(crate::engine::text_artifact_frame::utf8_preview_lines(
                    &source_text,
                    preview_lines,
                )),
            );
        }
        restore_exported_tool_artifact_previews(value, &exported_tool_artifact_previews)?;
    }

    let manifest = build_manifest_conn(conn, target, bundle, options, env)?;
    let config_entries = collect_config_entries_with_env(
        target,
        options.include_generated_artifacts,
        export_redactor,
    );
    let approval_entries = collect_approval_entries_conn(conn, bundle)?;

    // Write the archive.
    let mut buf = Cursor::new(Vec::<u8>::new());
    {
        let mut zw = ZipWriter::new(&mut buf);
        let opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        write_redacted_json_member(&mut zw, opts, "manifest.json", &manifest, export_redactor)?;

        write_prescrubbed_json_member(
            &mut zw,
            opts,
            "events.json",
            &Value::Array(event_values.clone()),
        )?;

        // One file per inference request, split across `inference_requests/`
        // (regular) and `inference_requests_utility/` (utility) by the
        // persisted flag. The payload is the full post-redaction request body
        // — no second redaction pass (the leak-detection use case wants the
        // exact wire form).
        for (path, call_id, ordinal) in &request_files {
            let payload = match Db::get_inference_request_conn(conn, call_id, *ordinal)? {
                // Envelope: the immutable `request` body, the dispatch-time
                // lifecycle `status`, and the phase timestamps read from their
                // dedicated columns — phases are NOT re-injected into `request`,
                // so the body stays the exact wire form. Per-attempt
                // provider/model/trust + the ordinal ride alongside.
                Some(row) => json!({
                    "status": row.status,
                    "ordinal": row.ordinal,
                    "provider": row.provider,
                    "model": row.model,
                    "trust": row.trust,
                    "request": row.payload,
                    "phases": {
                        "first_token_ms": row.first_token_ms,
                        "completed_ms": row.completed_ms,
                        "failed_ms": row.failed_ms,
                    },
                }),
                // A captured event without a stored payload (e.g. capture
                // failed mid-turn). Emit a marker so the file the event
                // references always exists.
                None => json!({ "error": "no captured request payload for this call_id" }),
            };
            write_redacted_json_member(&mut zw, opts, path, &payload, export_redactor)?;
        }

        // Model-comparison tandem (shadow) records: one file per (main call,
        // tandem model) under `inference_requests_tandem/`. An unsettled tandem
        // request at export time carries `status: "pending"` (its body's status
        // field) — the export does not block waiting for it.
        for (path, body) in &tandem_files {
            write_redacted_json_member(&mut zw, opts, path, body, export_redactor)?;
        }

        for (path, body) in &tool_output_files {
            write_redacted_json_member(&mut zw, opts, path, body, export_redactor)?;
        }

        if !inference_call_index.is_empty() {
            write_redacted_json_member(
                &mut zw,
                opts,
                "inference_calls/index.json",
                &Value::Array(inference_call_index.clone()),
                export_redactor,
            )?;
        }
        if !tool_call_index.is_empty() {
            write_redacted_json_member(
                &mut zw,
                opts,
                "tool_calls/index.json",
                &Value::Array(tool_call_index.clone()),
                export_redactor,
            )?;
        }

        // `/3` always carries the typed-artifact index, including an empty
        // array, so import has one exact membership authority rather than a
        // legacy absence fallback.
        let path = format!("{TEXT_ARTIFACTS_DIR}/index.json");
        write_redacted_json_member(
            &mut zw,
            opts,
            &path,
            &Value::Array(text_artifact_index.clone()),
            export_redactor,
        )?;
        for (path, body) in &text_artifact_files {
            write_prescrubbed_text_member(&mut zw, opts, path, body)?;
        }

        if !delegation_index.is_empty() {
            let path = format!("{DELEGATIONS_DIR}/index.json");
            write_redacted_json_member(
                &mut zw,
                opts,
                &path,
                &Value::Array(delegation_index.clone()),
                export_redactor,
            )?;
        }

        if !delegation_payload_index.is_empty() {
            // PRESCRUBBED: each entry's metadata was scrubbed exactly once at
            // collection, and its boundary-safe `excerpt` was inserted after that
            // scrub, so this member must NOT be re-scrubbed by the funnel.
            let path = format!("{DELEGATION_PAYLOADS_DIR}/index.json");
            write_prescrubbed_json_member(
                &mut zw,
                opts,
                &path,
                &Value::Array(delegation_payload_index.clone()),
            )?;
        }
        if !delegation_steer_index.is_empty() {
            let path = format!("{DELEGATION_STEERS_DIR}/index.json");
            write_redacted_json_member(
                &mut zw,
                opts,
                &path,
                &Value::Array(delegation_steer_index.clone()),
                export_redactor,
            )?;
        }
        for (path, body) in &delegation_payload_files {
            write_redacted_text_member(&mut zw, opts, path, body, export_redactor)?;
        }

        // Config copy: a deep-merged effective extended-config plus untouched
        // raw per-layer trees. Each body was structurally sanitized AND value
        // scrubbed exactly once at collection (`config_entries_from_layers`), so
        // it is written PRESCRUBBED — the funnel must not re-scrub it. Always
        // writes at least a marker so `config/` exists even on a machine with no
        // cockpit config on disk.
        for (path, body) in &config_entries {
            write_prescrubbed_text_member(&mut zw, opts, path, body)?;
        }

        // Explicit approval snapshot: `events.json` records decisions as
        // they happened, but persisted grants are what explain why a later
        // tool did not prompt. Keep them separate from raw config copies so
        // audits have a stable, direct place to inspect. Scrubbed through the
        // same funnel: a persisted grant can name a token-bearing command/path.
        for (path, body) in &approval_entries {
            write_redacted_text_member(&mut zw, opts, path, body, export_redactor)?;
        }

        zw.finish().context("zip: finalizing archive")?;
    }
    Ok(buf.into_inner())
}

fn load_task_delegation_payload_from_row(
    db: &Db,
    row: &TaskDelegationPayloadRow,
) -> Result<LoadedTaskDelegationPayload> {
    if let Some(body) = row.body_inline.clone() {
        return Ok(LoadedTaskDelegationPayload { body });
    }
    let path = db
        .task_delegation_payload_sidecar_abs_path(row)?
        .with_context(|| {
            format!(
                "task delegation payload `{}`:`{}` has no inline body or sidecar",
                row.task_call_id, row.label
            )
        })?;
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("reading delegation payload sidecar {}", path.display()))?;
    Ok(LoadedTaskDelegationPayload { body })
}

/// Build `manifest.json`: target session metadata + the fork/compaction
/// tree across the whole bundle. Kept small.
fn build_manifest_conn(
    conn: &Connection,
    target: &SessionRow,
    bundle: &[SessionRow],
    options: ExportBundleOptions,
    env: &HashMap<String, String>,
) -> Result<Value> {
    let active_model = session_active_model(target)?;
    let config_active_model = config_active_model(&target.project_root, env);
    let active_model_diverged =
        active_models_diverged(active_model.as_ref(), config_active_model.as_ref());
    let sessions = bundle
        .iter()
        .map(|session| {
            let active_model = session_active_model(session)?;
            Ok(json!({
                "session_id": session.session_id.to_string(),
                "short_id": session.short_id,
                "parent_session_id": session.parent_session_id.map(|p| p.to_string()),
                "fork_point_turn_id": session.fork_point_turn_id,
                "assistant_name": session.assistant_name,
                "is_assistant_thread": session.is_assistant_thread,
                "active_model": active_model,
                "session_entry_mode": session.session_entry_mode,
                "active_agent": session.active_agent,
                "started_at_unix_ms": session.started_at_unix_ms,
                "ended_at_unix_ms": session.ended_at_unix_ms,
                "title": session.title,
            }))
        })
        .collect::<Result<Vec<Value>>>()?;

    let mut manifest = json!({
        "schema": "cockpit-session-export/4",
        // The version of the cockpit binary producing THIS export — not
        // persisted per session, so a CLI export of an old session reflects
        // the exporting binary, not the one that created the session.
        "cockpit_version": env!("CARGO_PKG_VERSION"),
        "exporter_cockpit_version": env!("CARGO_PKG_VERSION"),
        // The target/root session date, derived from its signed Unix-millisecond
        // timestamp, as both ISO-8601 and the raw durable value.
        "session_date": iso8601_from_unix_ms(target.started_at_unix_ms),
        "session_started_at_unix_ms": target.started_at_unix_ms,
        "target": {
            "session_id": target.session_id.to_string(),
            "short_id": target.short_id,
            "project_id": target.project_id,
            "project_root": target.project_root,
            "active_model": active_model,
            "config_active_model": config_active_model,
            "active_model_diverged": active_model_diverged,
            "title": target.title,
            "started_at_unix_ms": target.started_at_unix_ms,
            "ended_at_unix_ms": target.ended_at_unix_ms,
        },
        "session_count": bundle.len(),
        "excluded_generated_artifacts": !options.include_generated_artifacts,
        "include_generated_artifacts": options.include_generated_artifacts,
        // `true` for every default (non-bypassable) export; `false` only for
        // the explicit local `--include-sensitive` raw opt-in.
        "redacted": options.redacted,
        "sessions": sessions,
    });
    if let Some(repair) = export_resume_repair_state_conn(conn, target)
        && let Some(obj) = manifest.as_object_mut()
    {
        obj.insert("resume_repair_required".to_string(), repair);
    }
    Ok(manifest)
}

fn session_active_model(
    row: &SessionRow,
) -> Result<Option<crate::config::providers::ActiveModelRef>> {
    match (
        row.model_selection_json.as_deref(),
        row.provider.as_deref(),
        row.model.as_deref(),
    ) {
        (None, None, None) => Ok(None),
        (Some(raw), Some(provider), Some(model)) => {
            let selection: crate::config::providers::ActiveModelRef = serde_json::from_str(raw)
                .with_context(|| {
                    format!(
                        "decoding active model for exported session {}",
                        row.session_id
                    )
                })?;
            anyhow::ensure!(
                selection.provider == provider && selection.model == model,
                "session {} active-model projections disagree with model_selection_json",
                row.session_id
            );
            Ok(Some(selection))
        }
        (None, _, _) => anyhow::bail!(
            "session {} model projections require model_selection_json",
            row.session_id
        ),
        _ => anyhow::bail!(
            "session {} has inconsistent active-model projections",
            row.session_id
        ),
    }
}

fn config_active_model(
    project_root: &str,
    env: &HashMap<String, String>,
) -> Option<crate::config::providers::ActiveModelRef> {
    let paths = config_file_paths_for_export(Path::new(project_root), env);
    // Masked resolution: an export must not record a half-committed default
    // from a layer whose transaction is still pending.
    crate::config::providers::ConfigDoc::providers_from_paths_masked(&paths).active_model
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
    active_model: Option<&crate::config::providers::ActiveModelRef>,
    config_active_model: Option<&crate::config::providers::ActiveModelRef>,
) -> bool {
    active_model.is_some() && active_model != config_active_model
}

fn export_resume_repair_state_conn(conn: &Connection, target: &SessionRow) -> Option<Value> {
    let provider = target.provider.clone().unwrap_or_default();
    let model = target.model.clone().unwrap_or_default();
    let providers = crate::secret_ref::load_effective(Path::new(&target.project_root));
    let wire_api = providers.resolve_wire_api_or_detect(&provider, &model);
    if !matches!(wire_api, crate::config::providers::WireApi::Responses) {
        return None;
    }
    let err = crate::engine::rehydrate::rehydrate_session_with_policy_conn(
        conn,
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

fn inference_call_export_json(row: &crate::db::inference_calls::InferenceCallRow) -> Value {
    json!({"call_id": row.call_id, "session_id": row.session_id, "project_id": row.project_id, "project_root": row.project_root, "model": row.model, "provider": row.provider, "timestamp": row.timestamp, "input_tokens": row.input_tokens, "output_tokens": row.output_tokens, "cached_input_tokens": row.cached_input_tokens, "cache_creation_input_tokens": row.cache_creation_input_tokens, "cost_usd_micros": row.cost_usd_micros, "is_utility": row.is_utility})
}

fn tool_call_export_json(row: &ToolCallEvent) -> Value {
    let (recovery_kind, recovery_stage) = row.recovery.raw_db_fields();
    json!({"event_id": row.event_id, "session_id": row.session_id, "call_id": row.call_id, "parent_call_id": row.parent_call_id, "parent_child_index": row.parent_child_index, "provider_item_id": row.provider_item_id, "provider_call_id": row.provider_call_id, "provider_call_id_source": row.provider_call_id_source, "wire_api": row.wire_api, "provider_family": row.provider_family, "timestamp": row.timestamp, "model": row.model, "provider": row.provider, "project_id": row.project_id, "project_root": row.project_root, "agent": row.agent, "tool": row.tool, "mcp_server": row.mcp_server, "path": row.path, "recovery_kind": recovery_kind, "recovery_stage": recovery_stage, "hard_fail": row.hard_fail, "exit_code": row.exit_code, "sandbox_enabled": row.sandbox_enabled, "sandboxed": row.sandboxed, "sandbox_unavailable_reason": row.sandbox_unavailable_reason, "original_input_json": row.original_input_json, "wire_input_json": row.wire_input_json, "output": row.output, "truncated": row.truncated, "duration_ms": row.duration_ms, "cockpit_version": row.cockpit_version, "shape_fingerprint": row.shape_fingerprint, "hint": row.hint})
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
            Some("completions") | Some("responses") if tool_call.provider_call_id.is_none() => {
                anyhow::bail!(
                    "invalid provider identity for tool_call row {}: {} wire requires provider_call_id",
                    tool_call.call_id,
                    tool_call.wire_api.as_deref().unwrap_or("unknown")
                );
            }
            Some("completions") | Some("responses") => {}
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

/// Recursively scrub every JSON string value (and nested object/array value)
/// through the export redaction table. This is the same scrub the debug ZIP
/// applies to every member; the transcript JSON export shares it so the RPC
/// payload is redacted before base64/staging.
pub fn scrub_export_json_value(value: &mut Value, redactor: &RedactionTable) {
    redact_value_for_export(value, redactor);
}

fn session_persisted_or_vault_redaction_json(
    vault: Option<&crate::secure_key::SecretVault>,
    conn: Option<&Connection>,
    session: &SessionRow,
) -> Result<Option<String>> {
    if let Some(json) = session
        .redaction_table_json
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        return Ok(Some(json.to_string()));
    }
    let Some(vault) = vault else {
        return Ok(None);
    };
    let item_id = crate::secure_key::redaction_table_item_id(&session.session_id.to_string());
    let loaded = match conn {
        Some(conn) => vault.get_item_on_conn(
            conn,
            cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
            &item_id,
        ),
        None => vault.get_item(
            cockpit_db::secret_vault::SecretVaultKind::RedactionTable,
            &item_id,
        ),
    };
    match loaded {
        Ok(secret) => {
            let json = String::from_utf8(secret.as_slice().to_vec())
                .context("redaction table vault item is not UTF-8")?;
            Ok(Some(json))
        }
        Err(crate::secure_key::SecureKeyError::NotFound(_)) => Ok(None),
        Err(error) => Err(anyhow::anyhow!(
            "reading redaction table vault item: {error}"
        )),
    }
}

/// The non-bypassable export redactor for a whole bundle: the target project's
/// live scan unioned with **every** bundled session's persisted redaction-table
/// union, forced enforced. Every bundled session's historically-persisted
/// entries are included, so a secret the bundle's sessions saw is scrubbed even
/// if it has since been rotated out of the live environment. Fails closed on
/// any unparseable persisted table.
#[allow(clippy::too_many_arguments)]
fn export_redaction_table_for_bundle(
    vault: Option<&crate::secure_key::SecretVault>,
    store: Option<&crate::credentials::CredentialStore>,
    conn: Option<&Connection>,
    target: &SessionRow,
    bundle: &[SessionRow],
    env: &HashMap<String, String>,
    resolver: &dyn crate::redact::protected_redaction_history::RedactionKeyResolver,
) -> Result<RedactionTable> {
    // The debug bundle folds history IN-SNAPSHOT via the resolver so the folded
    // set equals the assembled set (`bundle` was discovered on the same `conn`).
    export_redaction_table_for_sessions(vault, store, conn, target, bundle, env, Some(resolver))
}

#[allow(clippy::too_many_arguments)]
fn export_redaction_table_for_sessions(
    vault: Option<&crate::secure_key::SecretVault>,
    store: Option<&crate::credentials::CredentialStore>,
    conn: Option<&Connection>,
    target: &SessionRow,
    sessions: &[SessionRow],
    env: &HashMap<String, String>,
    resolver: Option<&dyn crate::redact::protected_redaction_history::RedactionKeyResolver>,
) -> Result<RedactionTable> {
    let cwd = PathBuf::from(&target.project_root);
    let extended = crate::config::extended::load_for_cwd(&cwd);
    let mut table = match store {
        Some(store) => {
            RedactionTable::build_with_env_and_credential_store(&extended.redact, &cwd, env, store)
        }
        None => RedactionTable::build_with_env_and_store(&extended.redact, &cwd, env),
    }
    .context("building export redaction table")?;
    for session in sessions {
        let Some(json) = session_persisted_or_vault_redaction_json(vault, conn, session)? else {
            continue;
        };
        // Fail closed: a persisted or vault table that cannot be parsed aborts
        // the export rather than silently dropping historically-classified secrets.
        let persisted = RedactionTable::from_persisted_json(&json).with_context(|| {
            format!(
                "parsing persisted redaction table for session {}",
                session.session_id
            )
        })?;
        table = table
            .union(&persisted)
            .context("unioning persisted redaction table into export table")?;
    }
    // Fold the `protected_redaction_history` journal literals. This is what keeps
    // a disk-derived (.env / SSH) secret scrubbed after it has been rotated or
    // deleted from the live scan AND aged out of the persisted table: only the
    // encrypted journal still holds it, and it is added here as a forced literal
    // so it is scrubbed from every export member. The rehydration runs
    // SYNCHRONOUSLY from the SAME read snapshot (`conn`) that discovered
    // `sessions` and assembles them, so the folded literals correspond exactly to
    // the sessions this snapshot ships — no discover-then-assemble TOCTOU. Both
    // the debug bundle (multi-session) and the redacted transcript (single
    // session) supply a warm `resolver`.
    if let Some(resolver) = resolver {
        let conn = conn.context("in-snapshot history fold requires a read connection")?;
        for session in sessions {
            let literals =
                crate::redact::protected_redaction_history::rehydrate_session_literals_conn(
                    resolver,
                    conn,
                    &session.session_id.to_string(),
                )
                .with_context(|| {
                    format!(
                        "rehydrating protected redaction history for session {}",
                        session.session_id
                    )
                })?;
            for literal in literals {
                table = table
                    .with_forced_literal(
                        literal.to_string(),
                        "protected_redaction_history".to_string(),
                    )
                    .context("folding protected redaction history literal into export table")?;
            }
        }
    }
    // Always the enforced view: `redact.enabled = false` never affects export
    // output. Config still supplies the placeholder, denylist, allowlist, and
    // dotenv patterns via the live build above.
    Ok(table.enforced())
}

/// Restore only the previews whose paired artifact sidecars have already been
/// transformed through the /3 length-preserving path.  The ordinary export
/// redactor is intentionally allowed to scrub the rest of the event state
/// (including provenance), but it uses a configurable placeholder and must
/// never alter a durable preview that rehydration compares with the imported
/// immutable body.
fn restore_exported_tool_artifact_previews(
    value: &mut Value,
    previews: &HashMap<(Uuid, i64, i64), (String, String)>,
) -> Result<()> {
    let Some(session_id) = value
        .get("session_id")
        .and_then(Value::as_str)
        .and_then(|raw| Uuid::parse_str(raw).ok())
    else {
        return Ok(());
    };
    let Some(event_seq) = value.get("seq").and_then(Value::as_i64) else {
        return Ok(());
    };
    let Some(data) = value.get_mut("data").and_then(Value::as_object_mut) else {
        return Ok(());
    };
    if let Some(projection) = data.get_mut("artifact_projection") {
        restore_exported_tool_artifact_preview(projection, session_id, event_seq, previews)?;
    }
    if let Some(projections) = data.get_mut("artifact_projections") {
        let projections = projections.as_array_mut().ok_or_else(|| {
            anyhow::anyhow!("artifact projection array was not preserved by export")
        })?;
        for projection in projections {
            restore_exported_tool_artifact_preview(projection, session_id, event_seq, previews)?;
        }
    }
    Ok(())
}

fn restore_exported_tool_artifact_preview(
    projection: &mut Value,
    session_id: Uuid,
    event_seq: i64,
    previews: &HashMap<(Uuid, i64, i64), (String, String)>,
) -> Result<()> {
    let projection = projection
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("artifact projection was not an object during export"))?;
    let slot = projection
        .get("projection_slot")
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow::anyhow!("artifact projection lacks a stable slot during export"))?;
    let Some((head, tail)) = previews.get(&(session_id, event_seq, slot)) else {
        return Ok(());
    };
    anyhow::ensure!(
        projection.get("status").and_then(Value::as_str) == Some("available"),
        "available text artifact sidecar has a non-available durable projection"
    );
    projection.insert("preview_head".to_owned(), json!(head));
    projection.insert("preview_tail".to_owned(), json!(tail));
    Ok(())
}

fn redact_value_for_export(value: &mut Value, redactor: &RedactionTable) {
    match value {
        Value::String(s) => {
            let scrubbed = redactor.scrub(s);
            if scrubbed != *s {
                *s = scrubbed;
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_value_for_export(item, redactor);
            }
        }
        Value::Object(map) => {
            // Scrub every value first (in place), then scrub the object's KEYS.
            // A secret can hide in a key just as readily as a value (a captured
            // header map, an env dump, a tool-args object keyed by a token), so
            // both sides of every entry are covered uniformly.
            for item in map.values_mut() {
                redact_value_for_export(item, redactor);
            }
            // Rebuild the map with scrubbed keys. When two scrubbed keys render
            // to the SAME text, we cannot keep either entry without arbitrarily
            // dropping or overwriting one (which could resurrect or mis-attach a
            // value), so the entire containing object is replaced by the uniform
            // terminal collision object `{"<placeholder>": "<placeholder>"}` — a
            // valid JSON shape that carries no colliding data.
            let mut rebuilt = serde_json::Map::with_capacity(map.len());
            let mut collided = false;
            for (key, item) in std::mem::take(map) {
                let scrubbed_key = redactor.scrub(&key);
                if rebuilt.insert(scrubbed_key, item).is_some() {
                    collided = true;
                    break;
                }
            }
            if collided {
                let placeholder = redactor.placeholder().to_string();
                let mut terminal = serde_json::Map::with_capacity(1);
                terminal.insert(placeholder.clone(), Value::String(placeholder));
                *map = terminal;
            } else {
                *map = rebuilt;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn redact_string_for_export(value: String, redactor: &RedactionTable) -> String {
    redactor.scrub(&value)
}

/// Deterministic archive-only redaction for immutable artifact bodies.
///
/// Ordinary export strings use the configurable placeholder, which may change
/// byte length. Artifact manifests promise exact accounting, so we instead
/// union every table-matched UTF-8 range and replace each matched *byte* with
/// ASCII `*`. Replacing all bytes of a matched code point remains valid UTF-8;
/// unmatched slices are copied unchanged. This is deliberately not a general
/// egress redactor and never feeds a model-facing payload.
fn redact_artifact_length_preserving(body: &str, redactor: &RedactionTable) -> String {
    let mut ranges = Vec::<(usize, usize)>::new();
    for matched in crate::redact::match_sensitive_literals(redactor, body) {
        if matched.literal.is_empty() {
            continue;
        }
        for (start, _) in body.match_indices(&matched.literal) {
            ranges.push((start, start + matched.literal.len()));
        }
    }
    if ranges.is_empty() {
        return body.to_string();
    }
    ranges.sort_unstable_by_key(|range| range.0);
    let mut merged = Vec::<(usize, usize)>::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some((_, prior_end)) if start <= *prior_end => *prior_end = (*prior_end).max(end),
            _ => merged.push((start, end)),
        }
    }
    let mut bytes = body.as_bytes().to_vec();
    for (start, end) in merged {
        bytes[start..end].fill(b'*');
    }
    String::from_utf8(bytes).expect("replacing UTF-8 bytes with ASCII preserves UTF-8")
}

/// The scrub funnel for a JSON member whose content is collected RAW.
///
/// Recursively scrubs the value through `redactor` EXACTLY ONCE immediately
/// before serialization, so no generated-artifact builder can emit a raw member
/// while nothing is scrubbed twice. On the raw `--include-sensitive` path the
/// redactor is [`RedactionTable::empty`] (a no-op matcher), so this is correct
/// for both modes without a branch. The counterpart [`write_prescrubbed_json_member`]
/// exists for content that MUST be scrubbed at collection (a truncated preview
/// whose boundary a whole-literal matcher could not fix): route that content
/// through the prescrubbed writer so it is not double-scrubbed here. Never write
/// a JSON member with a raw `write_all(to_string_pretty(..))` — one of these two
/// helpers must own every JSON member so it is scrubbed exactly once.
fn write_redacted_json_member<W: Write + Seek>(
    zw: &mut ZipWriter<W>,
    opts: SimpleFileOptions,
    path: &str,
    value: &Value,
    redactor: &RedactionTable,
) -> Result<()> {
    let mut value = value.clone();
    redact_value_for_export(&mut value, redactor);
    write_prescrubbed_json_member(zw, opts, path, &value)
}

/// Write a JSON member whose content was ALREADY scrubbed exactly once at
/// collection. Skips the scrub so the content is not double-scrubbed (a second
/// `replace_all` pass over an inserted placeholder could re-match a literal that
/// is a substring of the placeholder and mangle it). The caller is responsible
/// for having scrubbed every secret-bearing field of `value` exactly once.
fn write_prescrubbed_json_member<W: Write + Seek>(
    zw: &mut ZipWriter<W>,
    opts: SimpleFileOptions,
    path: &str,
    value: &Value,
) -> Result<()> {
    zw.start_file(path, opts)
        .with_context(|| format!("zip: entry `{path}`"))?;
    zw.write_all(serde_json::to_string_pretty(value)?.as_bytes())
        .with_context(|| format!("zip: writing `{path}`"))?;
    Ok(())
}

/// Text-body analogue of [`write_redacted_json_member`] for members that are
/// already serialized to a string (config copies, pre-rendered bodies, the
/// approvals snapshot). The whole text is scrubbed through the same redactor so
/// a secret literal embedded in a serialized body cannot ride out raw.
fn write_redacted_text_member<W: Write + Seek>(
    zw: &mut ZipWriter<W>,
    opts: SimpleFileOptions,
    path: &str,
    body: &str,
    redactor: &RedactionTable,
) -> Result<()> {
    let body = redact_string_for_export(body.to_string(), redactor);
    write_prescrubbed_text_member(zw, opts, path, &body)
}

/// Text analogue of [`write_prescrubbed_json_member`]: write a body that was
/// ALREADY scrubbed exactly once at collection (the config copies are structurally
/// sanitized and value-scrubbed as they are read). Skips the scrub so the body is
/// not double-scrubbed.
fn write_prescrubbed_text_member<W: Write + Seek>(
    zw: &mut ZipWriter<W>,
    opts: SimpleFileOptions,
    path: &str,
    body: &str,
) -> Result<()> {
    zw.start_file(path, opts)
        .with_context(|| format!("zip: entry `{path}`"))?;
    zw.write_all(body.as_bytes())
        .with_context(|| format!("zip: writing `{path}`"))?;
    Ok(())
}

/// Format a signed Unix-millisecond timestamp as ISO-8601 / RFC 3339 UTC.
/// Returns `None` (serialized as JSON `null`) for an out-of-range value
/// rather than failing the export.
fn iso8601_from_unix_ms(unix_ms: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(unix_ms).map(|dt| dt.to_rfc3339())
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
    redactor: &RedactionTable,
) -> Vec<(String, String)> {
    let cwd = PathBuf::from(&target.project_root);
    let layers = discover_config_dirs(&cwd);
    config_entries_from_layers(&layers, redactor, include_generated_artifacts)
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
fn collect_approval_entries_conn(
    conn: &Connection,
    bundle: &[SessionRow],
) -> Result<Vec<(String, String)>> {
    let session_grants = session_approval_snapshot_conn(conn, bundle)?;

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

fn session_approval_snapshot_conn(conn: &Connection, bundle: &[SessionRow]) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for session in bundle {
        let session_id = session.session_id.to_string();
        let (commands, paths, loop_accept, loop_reject): (
            Vec<Value>,
            Vec<Value>,
            Vec<String>,
            Vec<String>,
        ) = {
            let read_keys = |sql: &str| -> Result<Vec<String>> {
                let mut stmt = conn.prepare(sql)?;
                let rows = stmt.query_map([session_id.as_str()], |row| row.get::<_, String>(0))?;
                let mut values = Vec::new();
                for row in rows {
                    values.push(row?);
                }
                Ok(values)
            };
            let read_commands = || -> Result<Vec<Value>> {
                let mut stmt = conn.prepare(
                    "SELECT grant_key, risk_tier FROM approval_grants \
                     WHERE session_id = ?1 AND grant_kind = 'command' AND verdict = 'allow' \
                     ORDER BY grant_key",
                )?;
                let rows = stmt.query_map([session_id.as_str()], |row| {
                    let key: String = row.get(0)?;
                    let risk_tier: String = row.get(1)?;
                    Ok(json!({ "key": key, "riskTier": risk_tier }))
                })?;
                let mut values = Vec::new();
                for row in rows {
                    values.push(row?);
                }
                Ok(values)
            };
            let read_paths = || -> Result<Vec<Value>> {
                let mut stmt = conn.prepare(
                    "SELECT grant_key, access FROM approval_grants \
                     WHERE session_id = ?1 AND grant_kind = 'path' AND verdict = 'allow' \
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

            Ok::<_, anyhow::Error>((
                read_commands()?,
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
        }?;

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
