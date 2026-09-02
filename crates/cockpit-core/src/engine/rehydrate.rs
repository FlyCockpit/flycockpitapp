//! Session resume rehydration (implementation note).
//!
//! Resuming a session must be a **true continuation**: after `/prune`,
//! `/exit`, a daemon stop+restart, and `/resume`, the user's next message
//! is sent to the model with the prior conversation **rebuilt and in its
//! pruned form** as preceding context. A fresh worker (the daemon died, so
//! the in-memory `Vec<Message>` is gone) reconstructs the root foreground
//! agent's model-bound history from the durable transcript, then re-applies
//! the persisted prune ledger so it returns byte-identically to what the
//! model last saw.
//!
//! ## Single source of truth
//!
//! We never persist a second verbatim copy of the wire message list.
//! `session_events` (seq-ordered) carries the conversation structure +
//! user/assistant text; `tool_call_events` carries each tool call's
//! canonical **wire** form (`wire_input_json`, what the model originally
//! saw) and its result body. The prune ledger (`prune_ledger` table) is the
//! small durable delta that reproduces the *pruned* form. This module joins
//! the three.
//!
//! ## Reconstruction model
//!
//! Walk the **root agent's** events in `seq` order and assemble turns:
//!
//! - `user_message` → a `Message::User` text prompt (a turn boundary).
//! - `assistant_message` → the assistant turn's text (one per inference).
//! - `tool_call` (real tools) → an `AssistantContent::ToolCall` whose
//!   arguments are the `tool_call_events` row's `wire_input_json`, folded
//!   into the current assistant turn, with its result body pushed into the
//!   following `Message::User` as a paired `tool_result` (same `id`, so
//!   tool_use↔tool_result pairing is provider-valid).
//! - `subagent_spawned` → the `task` delegation's `ToolCall` (args
//!   `{agent, prompt, …}`); its result is the matching `subagent_report`
//!   event (correlated by the task `call_id`), folded into the following
//!   user turn exactly like a real tool result.
//!
//! Validation runs before the history is handed to the driver: every
//! tool_use must have a matching tool_result. A history that cannot be
//! rebuilt into a provider-valid conversation is a hard error (priority #1
//! — never a malformed or silently-fresh context); a transcript that
//! rebuilds but whose prune ledger cannot cleanly apply falls back to the
//! full unpruned form with a warning.

use anyhow::{Context, Result, anyhow};
use rig::message::{
    AssistantContent, Message, ProviderCallId, ToolCall, ToolCallId, ToolFunction, ToolResult,
    ToolResultContent, UserContent,
};
use rusqlite::Connection;
use std::sync::Arc;
use uuid::Uuid;

use crate::daemon::proto;
use crate::db::Db;
use crate::db::session_log::SessionEventRow;
use crate::db::tool_calls::Recovery;
use crate::db::tool_calls::ToolCallEvent;
use crate::engine::prune::{PruneLedger, ledger_is_empty, reapply_ledger};

/// Honest stub body for a tool call whose result never landed in the durable
/// transcript (an interrupted/aborted call). The model sees that the call did
/// not complete — we never fabricate a plausible success.
///
/// With the capability-aware turn scheduler (issue #57), every tool call in
/// an assistant turn is dispatched by the scheduler before any structural
/// outcome is returned. A call that lacks a result was therefore in progress
/// (started but not settled) when the session was interrupted — it was never
/// silently dropped. The stub body reflects this: it says the call was in
/// progress, not that it was interrupted "before resume" (the old wording
/// implied the call might never have started).
const ABORTED_CALL_BODY: &str = "[cockpit] tool call was in progress when the session was interrupted; its result is unavailable.";

/// Honest stub body for a `task` delegation whose `subagent_report` never
/// landed (the delegation did not complete before the session was resumed).
const MISSING_REPORT_BODY: &str =
    "[cockpit] subagent report unavailable; this delegation did not complete before resume.";

/// The outcome of rehydrating a session's root history.
#[derive(Debug)]
pub struct Rehydrated {
    /// The reconstructed, prune-applied model-bound history.
    pub history: Vec<Message>,
    /// The foreground root watermark to restore on the driver (the
    /// `prune_watermark` at depth 1) so auto-prune's short-circuit stays
    /// consistent. `0` when no ledger / no prior prune.
    pub watermark: usize,
    /// `true` when the prune ledger was present but could not be cleanly
    /// applied, so we fell back to the **full unpruned** reconstruction.
    /// The caller surfaces a warning (continuity preserved, less pruned).
    pub ledger_fallback: bool,
    /// One [`Recovery::ResumeHeal`] per row the heal pass stubbed/dropped to
    /// rebuild a provider-valid pairing (audit trail, GOALS §14). Empty on
    /// the clean common path — the caller surfaces a summarizing Notice only
    /// when this is non-empty.
    pub heals: Vec<Recovery>,
}

/// A backward-paged slice of rendered transcript history.
#[derive(Debug)]
pub struct HistoryPage {
    /// Oldest-first, like every other history snapshot.
    pub entries: Vec<proto::HistoryEntry>,
    /// True when older events exist before this page.
    pub has_more: bool,
    /// Cursor for the next older page: the oldest underlying event seq in
    /// this page. `None` when the page is empty.
    pub oldest_seq: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RehydratePolicy {
    repair_mode: RepairMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepairMode {
    Heal,
    Strict,
}

impl RehydratePolicy {
    pub fn heal() -> Self {
        Self {
            repair_mode: RepairMode::Heal,
        }
    }

    pub fn strict() -> Self {
        Self {
            repair_mode: RepairMode::Strict,
        }
    }

    fn is_strict(self) -> bool {
        matches!(self.repair_mode, RepairMode::Strict)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("Responses transcript repair required: {failure_kind} for {failing_tool_call_ids:?}")]
pub struct RehydrateRepairRequired {
    pub failure_kind: String,
    pub failing_tool_call_ids: Vec<String>,
    pub safe_last_turn_seq: Option<i64>,
    pub detail: String,
}

impl RehydrateRepairRequired {
    fn new(
        failure_kind: impl Into<String>,
        failing_tool_call_ids: Vec<String>,
        safe_last_turn_seq: Option<i64>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            failure_kind: failure_kind.into(),
            failing_tool_call_ids,
            safe_last_turn_seq,
            detail: detail.into(),
        }
    }
}

/// Rebuild the root agent's pruned model history for a resumed session.
///
/// `root_agent` is the session's resolved root primary (events are tagged
/// with the agent that produced them; only the root foreground agent's
/// turns belong in the rebuilt context — subagent frames are transient and
/// not resumed). Returns `Ok(None)` when there is nothing to rebuild (no
/// recorded turns yet — a brand-new session), so the caller leaves the
/// driver's empty history in place.
///
/// Errors (priority #1: never a malformed or silently-fresh context):
/// - the rebuilt conversation is not provider-valid (corrupt / unpairable
///   rows) → `Err`, surfaced as a clear failure.
#[allow(dead_code)]
pub async fn rehydrate_session(
    db: &Db,
    session_id: Uuid,
    root_agent: &str,
) -> Result<Option<Rehydrated>> {
    rehydrate_session_with_policy(db, session_id, root_agent, RehydratePolicy::heal()).await
}

pub async fn rehydrate_session_with_policy(
    db: &Db,
    session_id: Uuid,
    root_agent: &str,
    policy: RehydratePolicy,
) -> Result<Option<Rehydrated>> {
    rehydrate_session_with_policy_and_redaction(
        db,
        session_id,
        root_agent,
        policy,
        Arc::new(crate::redact::RedactionTable::empty()),
    )
    .await
}

/// Production rehydration supplies the session's current outbound redaction
/// table. Imported artifact representation metadata is structural provenance,
/// never a bypass for the current provider-safety boundary.
pub(crate) async fn rehydrate_session_with_policy_and_redaction(
    db: &Db,
    session_id: Uuid,
    root_agent: &str,
    policy: RehydratePolicy,
    redaction: Arc<crate::redact::RedactionTable>,
) -> Result<Option<Rehydrated>> {
    let root_agent = root_agent.to_string();
    db.read(move |conn| {
        rehydrate_session_with_policy_conn_with_redaction(
            conn,
            session_id,
            &root_agent,
            policy,
            redaction.as_ref(),
        )
    })
    .await
}

pub fn rehydrate_session_with_policy_conn(
    conn: &Connection,
    session_id: Uuid,
    root_agent: &str,
    policy: RehydratePolicy,
) -> Result<Option<Rehydrated>> {
    rehydrate_session_with_policy_conn_with_redaction(
        conn,
        session_id,
        root_agent,
        policy,
        &crate::redact::RedactionTable::empty(),
    )
}

pub(crate) fn rehydrate_session_with_policy_conn_with_redaction(
    conn: &Connection,
    session_id: Uuid,
    root_agent: &str,
    policy: RehydratePolicy,
    redaction: &crate::redact::RedactionTable,
) -> Result<Option<Rehydrated>> {
    let mut events = Db::list_session_events_conn(conn, session_id)
        .map_err(|e| anyhow!("loading session events for rehydration: {e}"))?;
    for event in &mut events {
        if event.kind == "session_compacted"
            && let Some(reference) = event
                .data
                .get("handoff_ref")
                .and_then(|value| value.as_str())
            && let Some(payload) = Db::compaction_payload_conn(conn, session_id, reference)?
        {
            event.data = serde_json::from_str(&payload)
                .context("decoding stored compaction payload for rehydration")?;
        }
    }
    let tool_calls = Db::list_tool_calls_for_session_conn(conn, session_id)
        .map_err(|e| anyhow!("loading tool calls for rehydration: {e}"))?;
    let scheduler_continuations = Db::list_turn_scheduler_continuations_conn(conn, session_id)
        .map_err(|e| anyhow!("loading turn scheduler continuations for rehydration: {e}"))?;

    // Per-rehydrate history pipeline (fixed order, idempotent — a reorder is a
    // contract break; see `composed-repair-pipeline-idempotence.md`):
    //   1. rebuild   (`rebuild_history`)
    //   2. heal       (`heal_pairing` — stub/drop orphans)
    //   3. validate   (`validate_pairing` — final provider-validity assertion)
    // Order is load-bearing: heal precedes validate so an orphaned transcript
    // resumes instead of hard-erroring. `heal(heal(x)) == heal(x)`, so a
    // resume→persist→resume cycle yields the same healed history with no new
    // `ResumeHeal` records.
    // Heals accumulated across the rebuild (missing tool-call result body /
    // missing subagent report) and the post-rebuild pairing heal pass. Empty
    // on the clean common path.
    let mut heals: Vec<Recovery> = Vec::new();
    let mut history = rebuild_history(
        &events,
        &tool_calls,
        &scheduler_continuations,
        root_agent,
        &mut heals,
        policy,
    )?;
    if history.is_empty() {
        // No recorded turns — a fresh session, nothing to rehydrate.
        return Ok(None);
    }

    apply_text_artifact_user_projections(
        conn,
        session_id,
        &events,
        &mut history,
        root_agent,
        redaction,
    )?;

    // Heal pass (implementation note): stub honest
    // results for orphan tool_uses and drop orphan tool_results so the
    // pairing is provider-valid, degrading gracefully instead of dead-ending.
    if policy.is_strict() {
        detect_responses_identity_gaps(&history)?;
    } else {
        heal_pairing(&mut history, &mut heals);
    }

    // Provider-validity gate: every tool_use must have a paired
    // tool_result, and vice-versa, or the provider rejects the request. After
    // the heal pass this is a final assertion (defense-in-depth) — a failure
    // here is a genuine bug in the heal, and must never fire in normal
    // operation.
    validate_pairing(&history)?;

    // Re-apply the prune ledger so the rebuilt history returns in pruned
    // form. A missing/corrupt/inconsistent ledger falls back to the full
    // unpruned form with a warning — never a silent fresh context.
    let (watermark, ledger_fallback) = match load_ledger_conn(conn, session_id) {
        Some(ledger) if !ledger_is_empty(&ledger) => match reapply_ledger(&ledger, &mut history) {
            Ok(_) => (ledger.watermark, false),
            Err(missing) => {
                tracing::warn!(
                    session_id = %session_id,
                    missing = ?missing,
                    "resume: prune ledger could not be cleanly applied; \
                     falling back to full unpruned context",
                );
                (0, true)
            }
        },
        // No ledger (or an empty one): nothing was pruned. The full
        // rebuilt form is exactly the pruned form.
        Some(ledger) => (ledger.watermark, false),
        None => (0, false),
    };

    // The canonical `tool_call` event deliberately stores the capped
    // delivered body, never a frame.  Apply typed projections only after the
    // prune ledger has selected the current wire body: a prune-boundary frame
    // then replaces its target deterministically instead of being copied into
    // the ledger and accidentally retaining a stale source UUID.  A corrupt
    // ledger's documented full-history fallback deliberately skips only
    // prune-boundary projections; ordinary tool retention remains safe.
    apply_text_artifact_tool_projections(
        conn,
        session_id,
        &events,
        &mut history,
        !ledger_fallback,
        root_agent,
        redaction,
    )?;

    // Scrub all tool result text bodies through the redaction table.  The
    // projection function above already redacts tool results that have a
    // durable text-artifact projection; this pass covers tool results
    // without a projection (e.g. forced-skill preludes) so the rehydrated
    // history matches the live dispatch's egress boundary.
    scrub_tool_result_bodies(&mut history, redaction);

    Ok(Some(Rehydrated {
        history,
        watermark,
        ledger_fallback,
        heals,
    }))
}

fn apply_text_artifact_tool_projections(
    conn: &Connection,
    session_id: Uuid,
    events: &[SessionEventRow],
    history: &mut [Message],
    include_prune_projections: bool,
    root_agent: &str,
    redaction: &crate::redact::RedactionTable,
) -> Result<()> {
    use crate::db::text_artifacts::{TextArtifact, TextArtifactRelation};

    let mut artifacts_by_owner = std::collections::BTreeMap::<(i64, i64), TextArtifact>::new();
    for artifact in crate::db::text_artifacts::list_text_artifacts_conn(conn, session_id)? {
        if artifact.relation != TextArtifactRelation::ModelContextToolResult {
            continue;
        }
        let slot = artifact
            .projection_slot
            .ok_or_else(|| anyhow!("tool artifact owner lacks a projection slot"))?;
        if artifacts_by_owner
            .insert((artifact.event_seq, slot), artifact)
            .is_some()
        {
            return Err(anyhow!(
                "multiple tool artifact owners share one event slot"
            ));
        }
    }

    // `false` means the prune ledger could not be applied cleanly. Preserve
    // its established full-history fallback without treating the intentionally
    // ignored prune-owner rows as an orphan/corruption signal.
    if !include_prune_projections {
        for event in events.iter().filter(|event| event.kind == "context_pruned") {
            artifacts_by_owner.retain(|(event_seq, _), _| *event_seq != event.seq);
        }
    }

    // Same in-place `/compact` boundary as the user-artifact pass: rebuilt
    // model history no longer contains pre-compaction tool turns, so their
    // `tool_call` / `context_pruned` projections must not be required to map
    // into it. Tail messages already carry the live frames for any retained
    // pre-compaction tool results.
    let compact_seq = last_root_compaction_cursor(events, root_agent)?.map(|(seq, _prefix)| seq);
    let precedes_compaction = |seq: i64| compact_seq.is_some_and(|cursor| seq <= cursor);
    if let Some(seq) = compact_seq {
        artifacts_by_owner.retain(|(event_seq, _), _| *event_seq > seq);
    }

    let mut projections_by_call = std::collections::BTreeMap::<String, (String, bool)>::new();
    for event in events {
        if precedes_compaction(event.seq) {
            continue;
        }
        match event.kind.as_str() {
            "tool_call" => {
                let projection = event.data.get("artifact_projection");
                let artifact = artifacts_by_owner.remove(&(event.seq, 0));
                match (projection, artifact) {
                    (None, None) => {}
                    (Some(serde_json::Value::Object(projection)), artifact) => {
                        let call_id = event
                            .call_id
                            .as_deref()
                            .ok_or_else(|| anyhow!("tool artifact event lacks a call_id"))?;
                        let (projection_call_id, frame) = render_rehydrated_tool_artifact_frame(
                            projection,
                            artifact.as_ref(),
                            0,
                            redaction,
                        )?;
                        if projection_call_id != call_id {
                            return Err(anyhow!(
                                "tool artifact projection provenance does not match event call id"
                            ));
                        }
                        if projections_by_call
                            .insert(call_id.to_owned(), (frame, false))
                            .is_some()
                        {
                            return Err(anyhow!(
                                "multiple ordinary artifact projections share one tool call id"
                            ));
                        }
                    }
                    (Some(_), _) => {
                        return Err(anyhow!("tool artifact projection must be an object"));
                    }
                    (None, Some(_)) => {
                        return Err(anyhow!(
                            "tool artifact owner has no durable projection state"
                        ));
                    }
                }
            }
            "context_pruned" if include_prune_projections => {
                let Some(states) = event.data.get("artifact_projections") else {
                    if artifacts_by_owner
                        .keys()
                        .any(|(event_seq, _)| *event_seq == event.seq)
                    {
                        return Err(anyhow!(
                            "prune artifact owner has no durable projection states"
                        ));
                    }
                    continue;
                };
                let states = states
                    .as_array()
                    .ok_or_else(|| anyhow!("prune artifact projections must be an array"))?;
                for (ordinal, state) in states.iter().enumerate() {
                    let projection = state
                        .as_object()
                        .ok_or_else(|| anyhow!("prune artifact projection must be an object"))?;
                    let slot: i64 = ordinal
                        .try_into()
                        .map_err(|_| anyhow!("prune projection slot overflows i64"))?;
                    if projection
                        .get("projection_slot")
                        .and_then(serde_json::Value::as_i64)
                        != Some(slot)
                    {
                        return Err(anyhow!("prune artifact projection slot is unstable"));
                    }
                    let artifact = artifacts_by_owner.remove(&(event.seq, slot));
                    let (call_id, frame) = render_rehydrated_tool_artifact_frame(
                        projection,
                        artifact.as_ref(),
                        slot,
                        redaction,
                    )?;
                    match projections_by_call.insert(call_id.to_owned(), (frame, true)) {
                        None | Some((_, false)) => {}
                        Some((_, true)) => {
                            return Err(anyhow!(
                                "multiple prune artifact projections share one tool call id"
                            ));
                        }
                    }
                }
                if artifacts_by_owner
                    .keys()
                    .any(|(event_seq, _)| *event_seq == event.seq)
                {
                    return Err(anyhow!(
                        "prune artifact owner has no matching durable projection slot"
                    ));
                }
            }
            _ => {}
        }
    }

    if !artifacts_by_owner.is_empty() {
        return Err(anyhow!(
            "tool artifact relation is attached to a non-owning event or slot"
        ));
    }

    let mut applied = std::collections::BTreeSet::new();
    for message in history {
        let Message::User { content } = message else {
            continue;
        };
        for part in content {
            let UserContent::ToolResult(result) = part else {
                continue;
            };
            if let Some((frame, _)) = projections_by_call.get(result.call.as_str()) {
                if !result
                    .content
                    .iter()
                    .all(|part| matches!(part, ToolResultContent::Text(_)))
                {
                    return Err(anyhow!(
                        "text artifact projection cannot replace typed tool-result content"
                    ));
                }
                result.content = vec![ToolResultContent::text(frame.clone())];
                applied.insert(result.call.to_string());
            }
        }
    }
    if projections_by_call
        .keys()
        .any(|call_id| !applied.contains(call_id))
    {
        return Err(anyhow!(
            "artifact projection does not map to a rehydrated tool result"
        ));
    }
    Ok(())
}

/// Scrub all tool result text bodies through the redaction table.  Tool
/// results that already received a redacted frame from
/// `apply_text_artifact_tool_projections` are unaffected (the scrub is
/// idempotent for already-redacted text); tool results without a durable
/// projection (e.g. forced-skill preludes) get the same egress boundary
/// the live dispatch applies.
fn scrub_tool_result_bodies(history: &mut [Message], redaction: &crate::redact::RedactionTable) {
    for message in history.iter_mut() {
        if let Message::User { content, .. } = message {
            for part in content.iter_mut() {
                if let UserContent::ToolResult(result) = part {
                    for item in result.content.iter_mut() {
                        if let ToolResultContent::Text(text_part) = item {
                            text_part.text = redaction.scrub(&text_part.text);
                        }
                    }
                }
            }
        }
    }
}

fn render_rehydrated_tool_artifact_frame<'a>(
    projection: &'a serde_json::Map<String, serde_json::Value>,
    artifact: Option<&crate::db::text_artifacts::TextArtifact>,
    expected_slot: i64,
    redaction: &crate::redact::RedactionTable,
) -> Result<(&'a str, String)> {
    if projection
        .get("version")
        .and_then(serde_json::Value::as_i64)
        != Some(1)
        || projection
            .get("projection_slot")
            .and_then(serde_json::Value::as_i64)
            != Some(expected_slot)
    {
        return Err(anyhow!(
            "tool artifact projection has an invalid version or slot"
        ));
    }
    let status = projection
        .get("status")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("tool artifact projection lacks status"))?;
    let capture_reason = projection
        .get("capture_reason")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("tool artifact projection lacks capture reason"))?;
    let kind = projection
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("tool artifact projection lacks kind"))?;
    if kind != "tool_result" || !matches!(capture_reason, "display_truncation" | "prune_boundary") {
        return Err(anyhow!(
            "tool artifact projection has an invalid kind or capture reason"
        ));
    }

    let numeric = |field: &str| -> Result<usize> {
        projection
            .get(field)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| anyhow!("tool artifact projection lacks {field}"))?
            .try_into()
            .map_err(|_| anyhow!("tool artifact projection {field} exceeds usize"))
    };
    let provenance = projection
        .get("provenance")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow!("tool artifact projection lacks provenance"))?;
    let valid_provenance_keys = [
        "agent_id",
        "tool",
        "call_id",
        "source",
        "preview_lines",
        "blob_path",
    ];
    if !provenance.contains_key("agent_id")
        || !provenance.contains_key("tool")
        || !provenance.contains_key("call_id")
        || !provenance
            .keys()
            .all(|key| valid_provenance_keys.contains(&key.as_str()))
        || (provenance.contains_key("blob_path")
            && (!provenance.contains_key("source") || !provenance.contains_key("preview_lines")))
    {
        return Err(anyhow!(
            "tool artifact projection provenance has an invalid shape"
        ));
    }
    let bounded = |key: &str| -> Result<&str> {
        let value = provenance
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("tool artifact projection provenance lacks {key}"))?;
        if value.is_empty()
            || value.len() > 256
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(anyhow!(
                "tool artifact projection provenance {key} is invalid"
            ));
        }
        Ok(value)
    };
    if let Some(agent) = provenance.get("agent_id")
        && !agent.is_null()
        && !agent.as_str().is_some_and(|value| {
            !value.is_empty()
                && value.len() <= 256
                && !value.bytes().any(|byte| byte.is_ascii_control())
        })
    {
        return Err(anyhow!(
            "tool artifact projection provenance agent_id is invalid"
        ));
    }
    let _tool = bounded("tool")?;
    let call_id = bounded("call_id")?;
    let provenance_value = serde_json::Value::Object(provenance.clone());
    let provenance_json = serde_json::to_string(&provenance_value)?;
    let preview = |field: &str| -> Result<&str> {
        let value = projection
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("tool artifact projection lacks {field}"))?;
        if value.len() > 16 * 1024 {
            return Err(anyhow!(
                "tool artifact projection {field} exceeds preview cap"
            ));
        }
        Ok(value)
    };
    let preview_head = preview("preview_head")?;
    let preview_tail = preview("preview_tail")?;
    let host_captured_bytes = numeric("host_captured_bytes")?;
    let host_original_bytes = numeric("host_original_bytes")?;
    let host_dropped_bytes = numeric("host_dropped_bytes")?;
    let stored_source_bytes = numeric("stored_source_bytes")?;
    let content_bytes = numeric("content_bytes")?;
    let line_count = numeric("line_count")?;
    if host_original_bytes < host_captured_bytes
        || host_dropped_bytes != host_original_bytes - host_captured_bytes
        || stored_source_bytes > host_captured_bytes
    {
        return Err(anyhow!(
            "tool artifact projection has invalid byte accounting"
        ));
    }

    match status {
        "available" => {
            let artifact = artifact
                .ok_or_else(|| anyhow!("available tool projection lacks an artifact owner"))?;
            if projection.get("reason") != Some(&serde_json::Value::Null)
                || artifact.relation
                    != crate::db::text_artifacts::TextArtifactRelation::ModelContextToolResult
                || artifact.projection_slot != Some(expected_slot)
                || artifact.capture_reason.as_str() != capture_reason
                || artifact.host_captured_bytes != host_captured_bytes
                || artifact.host_original_bytes != host_original_bytes
                || artifact.host_dropped_bytes != host_dropped_bytes
                || artifact.stored_source_bytes != stored_source_bytes
                || artifact.content_bytes != content_bytes
            {
                return Err(anyhow!("available tool artifact projection is malformed"));
            }
            let artifact_provenance: serde_json::Value =
                serde_json::from_str(&artifact.provenance_json)
                    .context("available tool artifact provenance is invalid")?;
            if artifact_provenance != provenance_value {
                return Err(anyhow!(
                    "available tool artifact provenance differs from durable projection state"
                ));
            }
            let artifact_content = crate::text_artifact_blob::read_artifact_content(artifact)?;
            if artifact_content.lines().count() != line_count {
                return Err(anyhow!("available tool artifact projection is malformed"));
            }
            let outbound_content = redaction.scrub(&artifact_content);
            let (preview_head, preview_tail) = if artifact_provenance.get("preview_lines").is_some()
            {
                let preview_lines = artifact_provenance
                    .get("preview_lines")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or(crate::agents::ContextPolicy::DEFAULT_ARTIFACT_PREVIEW_LINES);
                (
                    crate::engine::text_artifact_frame::utf8_preview_lines(
                        &outbound_content,
                        preview_lines,
                    ),
                    String::new(),
                )
            } else {
                let (head, tail) =
                    crate::engine::text_artifact_frame::utf8_preview_pair(&outbound_content);
                (head.to_owned(), tail.to_owned())
            };
            // Locally captured artifacts have already passed this boundary and
            // retain their durable previews. Imported (or newly matched)
            // content is rendered from the current safe view instead of
            // trusting its representation metadata.
            if outbound_content == artifact_content
                && (preview_head.as_str() != preview("preview_head")?
                    || preview_tail.as_str() != preview("preview_tail")?)
            {
                return Err(anyhow!(
                    "available tool artifact preview differs from durable projection state"
                ));
            }
            Ok((
                call_id,
                crate::engine::text_artifact_frame::render_artifact_frame(
                    &crate::engine::text_artifact_frame::ArtifactFrame {
                        status,
                        reason: None,
                        artifact_id: Some(artifact.artifact_id),
                        kind,
                        capture_reason,
                        provenance_json: &artifact.provenance_json,
                        host_captured_bytes: artifact.host_captured_bytes,
                        host_original_bytes: artifact.host_original_bytes,
                        host_dropped_bytes: artifact.host_dropped_bytes,
                        stored_source_bytes: artifact.stored_source_bytes,
                        content_bytes: artifact.content_bytes,
                        line_count: artifact_content.lines().count(),
                        preview_head: &preview_head,
                        preview_tail: &preview_tail,
                    },
                ),
            ))
        }
        "unavailable" => {
            if artifact.is_some() {
                return Err(anyhow!("unavailable tool projection has an artifact owner"));
            }
            let reason = projection
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .filter(|reason| {
                    matches!(
                        *reason,
                        "artifact_limit" | "session_quota" | "persistence_unavailable"
                    )
                })
                .ok_or_else(|| {
                    anyhow!("unavailable tool artifact projection has an invalid reason")
                })?;
            // An unavailable projection has no artifact body to join, but its
            // persisted previews still originated in an archive/event payload.
            // Treat them as untrusted outbound text just like an imported
            // artifact body; accounting remains the immutable durable value.
            let outbound_preview_head = redaction.scrub(preview_head);
            let outbound_preview_tail = redaction.scrub(preview_tail);
            Ok((
                call_id,
                crate::engine::text_artifact_frame::render_artifact_frame(
                    &crate::engine::text_artifact_frame::ArtifactFrame {
                        status,
                        reason: Some(reason),
                        artifact_id: None,
                        kind,
                        capture_reason,
                        provenance_json: &provenance_json,
                        host_captured_bytes,
                        host_original_bytes,
                        host_dropped_bytes,
                        stored_source_bytes,
                        content_bytes,
                        line_count,
                        preview_head: &outbound_preview_head,
                        preview_tail: &outbound_preview_tail,
                    },
                ),
            ))
        }
        _ => Err(anyhow!("tool artifact projection has an invalid status")),
    }
}

/// Model-history prefix a root `session_compacted` event replaces live
/// history with: one handoff user message plus the retained tail.
///
/// Shared by `rebuild_history` and the post-rebuild artifact-projection
/// cursor so the materialized prefix and the skip offset cannot drift.
fn compacted_model_history(event: &SessionEventRow) -> Result<Vec<Message>> {
    let handoff = event
        .data
        .get("handoff_text")
        .and_then(|value| value.as_str())
        .or_else(|| {
            event
                .data
                .get("brief_text")
                .and_then(|value| value.as_str())
        })
        .unwrap_or("")
        .to_string();
    let mut history = vec![Message::user(handoff)];
    if let Some(tail) = event.data.get("tail_messages") {
        let tail: Vec<Message> = serde_json::from_value(tail.clone())
            .map_err(|error| anyhow!("decoding compacted tail_messages: {error}"))?;
        history.extend(tail);
    }
    Ok(history)
}

/// Last in-place `/compact` boundary in `events`, if any.
///
/// `rebuild_history` clears model history at a root `session_compacted` event
/// and replaces it with [`compacted_model_history`]. `/compact` is in-place
/// (`successor_session_id` is this session), so pre-compaction transcript
/// rows remain in the log. Post-rebuild text-artifact projection must not
/// replay those rows (`user_message`, `tool_call`, `context_pruned`) against
/// the post-compact history.
///
/// Returns `(seq, history_prefix)`: `seq` is the last root compaction event;
/// `history_prefix` is the length of the prefix `rebuild_history` materializes
/// so post-compaction turns still line up.
fn last_root_compaction_cursor(
    events: &[SessionEventRow],
    root_agent: &str,
) -> Result<Option<(i64, usize)>> {
    let Some(event) = events.iter().rev().find(|event| {
        event.kind == "session_compacted" && event.agent.as_deref() == Some(root_agent)
    }) else {
        return Ok(None);
    };
    Ok(Some((event.seq, compacted_model_history(event)?.len())))
}

/// Replace only the authored text part of materialized oversized-user events.
/// The canonical event is still rebuilt first for transcript fidelity; this
/// second relational pass turns its model-only representation into the exact
/// shared artifact frame.  No frame text is parsed back into identity.
fn apply_text_artifact_user_projections(
    conn: &Connection,
    session_id: Uuid,
    events: &[SessionEventRow],
    history: &mut Vec<Message>,
    root_agent: &str,
    redaction: &crate::redact::RedactionTable,
) -> Result<()> {
    use crate::db::text_artifacts::{
        CaptureReason, TextArtifact, TextArtifactKind, TextArtifactRelation,
    };

    let mut by_event = std::collections::BTreeMap::<i64, Vec<TextArtifact>>::new();
    for artifact in crate::db::text_artifacts::list_text_artifacts_conn(conn, session_id)? {
        if matches!(
            artifact.relation,
            TextArtifactRelation::SourceUserInput | TextArtifactRelation::ModelUserInputProjection
        ) {
            by_event
                .entry(artifact.event_seq)
                .or_default()
                .push(artifact);
        }
    }

    let (compact_seq, mut next_history) = last_root_compaction_cursor(events, root_agent)?
        .map(|(seq, prefix)| (Some(seq), prefix))
        .unwrap_or((None, 0));
    let precedes_compaction = |seq: i64| compact_seq.is_some_and(|cursor| seq <= cursor);
    if let Some(seq) = compact_seq {
        by_event.retain(|event_seq, _| *event_seq > seq);
    }

    let mut frames = std::collections::BTreeMap::<i64, String>::new();
    for event in events {
        if event.kind != "user_message" {
            continue;
        }
        if precedes_compaction(event.seq) {
            continue;
        }
        let authored = event
            .data
            .get("text")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("user artifact event lacks canonical text"))?;
        let slots = by_event.remove(&event.seq).unwrap_or_default();
        let has_user_artifact = !slots.is_empty();
        // Artifact-backed sources are deliberately text-only. Their event text
        // is a bounded preview, so artifact ownership — not its byte length —
        // identifies this invariant.
        if (has_user_artifact || authored.len() > 64 * 1024)
            && user_event_has_media_or_file_parts(&event.data)
        {
            return Err(anyhow!(
                "oversized user event {} cannot carry media/file parts",
                event.seq
            ));
        }
        if !has_user_artifact {
            if authored.len() > 64 * 1024 {
                return Err(anyhow!(
                    "oversized user event {} must own exactly one source artifact",
                    event.seq
                ));
            }
            continue;
        }
        // An artifact-backed event must own exactly one source. This makes a
        // missing/deleted/swapped association a resume failure instead of a
        // silent full-text provider handoff.
        let sources = slots
            .iter()
            .filter(|artifact| artifact.relation == TextArtifactRelation::SourceUserInput)
            .collect::<Vec<_>>();
        if sources.len() != 1 {
            return Err(anyhow!(
                "oversized user event {} must own exactly one source artifact",
                event.seq
            ));
        }
        let source = sources[0];
        let source_content = crate::text_artifact_blob::read_artifact_content(source)
            .context("reading blob-backed user source during rehydration")?;
        let source_provenance: serde_json::Value = serde_json::from_str(&source.provenance_json)
            .context("user source artifact provenance is invalid")?;
        let preview_lines = source_provenance
            .get("preview_lines")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(crate::agents::ContextPolicy::DEFAULT_ARTIFACT_PREVIEW_LINES);
        let event_preview = if source_provenance.get("blob_path").is_some() {
            source.content.clone()
        } else {
            crate::engine::text_artifact_frame::utf8_preview_lines(&source_content, preview_lines)
        };
        if source.kind != TextArtifactKind::UserInputSource
            || source.capture_reason != CaptureReason::OversizedUserInput
            || source.projection_slot.is_some()
            || event_preview != authored
            || source_content.len() != source.content_bytes
        {
            return Err(anyhow!(
                "user source artifact does not match its bounded event preview"
            ));
        }
        if source_provenance
            .get("event_seq")
            .and_then(serde_json::Value::as_i64)
            != Some(event.seq)
        {
            return Err(anyhow!(
                "user source artifact provenance does not own its event"
            ));
        }
        let projections = slots
            .iter()
            .filter(|artifact| artifact.relation == TextArtifactRelation::ModelUserInputProjection)
            .collect::<Vec<_>>();
        if projections.len() > 1 || slots.len() != sources.len() + projections.len() {
            return Err(anyhow!("user artifact event has invalid owner slots"));
        }
        let effective = if let Some(projection) = projections.first() {
            let projection = *projection;
            if projection.kind != TextArtifactKind::UserInputProjection
                || projection.capture_reason != CaptureReason::OversizedUserInput
                || projection.projection_slot != Some(0)
            {
                return Err(anyhow!(
                    "user projection artifact has an invalid owner relation"
                ));
            }
            let provenance: serde_json::Value =
                serde_json::from_str(&projection.provenance_json)
                    .context("user projection artifact provenance is invalid")?;
            let expected_source_id = source.artifact_id.to_string();
            if provenance
                .get("source_artifact_id")
                .and_then(serde_json::Value::as_str)
                != Some(expected_source_id.as_str())
                || provenance
                    .get("preprocessing_version")
                    .and_then(serde_json::Value::as_i64)
                    != Some(1)
            {
                return Err(anyhow!(
                    "user projection artifact does not derive from its source"
                ));
            }
            let projection_content =
                crate::text_artifact_blob::read_artifact_content(projection)
                    .context("reading blob-backed user projection during rehydration")?;
            if projection_content == source_content {
                return Err(anyhow!(
                    "user projection artifact must differ from its source"
                ));
            }
            projection
        } else {
            source
        };
        let effective_content = crate::text_artifact_blob::read_artifact_content(effective)
            .context("reading blob-backed user projection during rehydration")?;
        let outbound_content = redaction.scrub(&effective_content);
        let frame = crate::engine::text_artifact_frame::render_user_input_artifact_frame_with_outbound_content_and_preview_lines(
            effective,
            &outbound_content,
            preview_lines,
        )
        .context("rendering rehydrated user artifact frame")?;
        if frames.insert(event.seq, frame).is_some() {
            return Err(anyhow!("multiple user artifact frames share one event"));
        }
    }
    if !by_event.is_empty() {
        return Err(anyhow!(
            "user artifact relation is attached to a non-user event"
        ));
    }

    for event in events.iter().filter(|event| event.kind == "user_message") {
        if precedes_compaction(event.seq) {
            continue;
        }
        let authored = event
            .data
            .get("text")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("user artifact event lacks canonical text"))?;
        let Some((mut index, text)) =
            history
                .iter_mut()
                .enumerate()
                .skip(next_history)
                .find_map(|(index, message)| match message {
                    Message::User { content }
                        if content.len() == 1
                            && matches!(content.first(), Some(UserContent::Text(_))) =>
                    {
                        match content.first_mut() {
                            Some(UserContent::Text(text)) => Some((index, text)),
                            _ => None,
                        }
                    }
                    _ => None,
                })
        else {
            return Err(anyhow!(
                "rehydrated history lacks the user message for artifact event {}",
                event.seq
            ));
        };
        if text.text != authored {
            return Err(anyhow!(
                "rehydrated user message does not match artifact event {}",
                event.seq
            ));
        }
        if let Some(frame) = frames.remove(&event.seq) {
            let envelope = Db::user_message_model_envelope_conn(conn, session_id, event.seq)?
                .ok_or_else(|| anyhow!("oversized user event lacks accepted model envelope"))?;
            let composition = crate::engine::text_artifact_frame::render_accepted_user_composition_with_redaction(
                &envelope, &frame, redaction,
            )?;
            let leading_call_id = composition
                .leading
                .first()
                .and_then(|message| match message {
                    Message::Assistant { content, .. } => {
                        content.iter().find_map(|part| match part {
                            AssistantContent::ToolCall(call) => Some(call.id.to_string()),
                            _ => None,
                        })
                    }
                    _ => None,
                });
            history[index] = Message::User {
                content: composition.content,
            };
            if let Some(call_id) = leading_call_id {
                let existing = history.iter().any(|message| match message {
                    Message::Assistant { content, .. } => content.iter().any(|part| {
                        matches!(part, AssistantContent::ToolCall(call) if call.id.to_string() == call_id)
                    }),
                    _ => false,
                });
                if existing {
                    // The later audit row is observability, not a second
                    // model composition. Replace its reconstructed pair with
                    // the persisted phase-two prelude, already rendered at
                    // the current outbound-redaction boundary. This keeps
                    // restart byte-identical to live dispatch even if audit
                    // reconstruction changes independently.
                    let matching_positions = history
                        .iter()
                        .enumerate()
                        .filter_map(|(position, message)| {
                            let belongs_to_prelude = match message {
                                Message::Assistant { content, .. } => matches!(
                                    content.as_slice(),
                                    [AssistantContent::ToolCall(call)] if call.id.to_string() == call_id
                                ),
                                Message::User { content } => matches!(
                                    content.as_slice(),
                                    [UserContent::ToolResult(result)] if result.call.to_string() == call_id
                                ),
                                _ => false,
                            };
                            belongs_to_prelude.then_some(position)
                        })
                        .collect::<Vec<_>>();
                    if let Some(&insert_at) = matching_positions.first() {
                        for position in matching_positions.into_iter().rev() {
                            history.remove(position);
                            if position < index {
                                index -= 1;
                            }
                        }
                        let leading_len = composition.leading.len();
                        history.splice(insert_at..insert_at, composition.leading);
                        if insert_at <= index {
                            index += leading_len;
                        }
                    } else {
                        // A malformed audit representation must not cause us
                        // to drop unrelated batched tool content. Keep it and
                        // add the authoritative persisted prelude instead.
                        history.splice(index..index, composition.leading);
                    }
                } else {
                    history.splice(index..index, composition.leading);
                }
            }
        }
        next_history = index + 1;
    }
    if !frames.is_empty() {
        return Err(anyhow!(
            "not every user artifact frame was applied to history"
        ));
    }
    Ok(())
}

/// Returns true for a nonempty media/file part or for a malformed non-array
/// declaration. The latter is deliberately fail-closed: a canonical user
/// event has no scalar media/file representation.
fn user_event_has_media_or_file_parts(data: &serde_json::Value) -> bool {
    const MEDIA_OR_FILE_KEYS: [&str; 5] =
        ["images", "image_refs", "attachments", "files", "file_refs"];

    data.as_object().is_some_and(|object| {
        MEDIA_OR_FILE_KEYS.iter().any(|key| match object.get(*key) {
            Some(serde_json::Value::Array(parts)) => !parts.is_empty(),
            Some(_) => true,
            None => false,
        })
    })
}

/// Build the **wire history snapshot** the daemon sends in its `Attached`
/// response so a resuming TUI repopulates the full prior transcript (user
/// messages + assistant turns + tool calls, chronological).
///
/// Single source of truth (implementation note): this
/// reuses the exact event-loading + ordering [`rehydrate_session`] uses —
/// [`Db::list_session_events`] walked in `seq` order, joined to the
/// [`Db::list_tool_calls_for_session`] rows by `call_id` — projected into the
/// **wire** [`proto::HistoryEntry`] shape instead of the model-bound
/// `Vec<Message>`. The two never drift: same loader, same seq order, same
/// root-agent gate (`assistant_message` / `tool_call` events belong to the
/// snapshot only when produced by the resumed `root_agent`; subagent-internal
/// turns stay in their transient frames, exactly as model rehydration drops
/// them). User messages are unconditional (the root conversation's turns).
///
/// The wire-vs-user split (GOALS §14) survives: a `tool_call` projects from
/// its `tool_call_events` row, carrying `original_input` (user side),
/// `wire_input` (model side), and the recovery kind/stage chip. A `tool_call`
/// timeline event without a matching audit row (an interrupted call whose
/// result body never landed durably) still renders from the timeline event's
/// own recorded fields so the transcript shows it rather than silently
/// dropping it.
#[allow(dead_code)]
pub async fn history_snapshot(
    db: &Db,
    session_id: Uuid,
    root_agent: &str,
) -> Result<Vec<proto::HistoryEntry>> {
    let root_agent = root_agent.to_string();
    db.read(move |conn| history_snapshot_conn(conn, session_id, &root_agent))
        .await
}

pub fn history_snapshot_conn(
    conn: &Connection,
    session_id: Uuid,
    root_agent: &str,
) -> Result<Vec<proto::HistoryEntry>> {
    history_snapshot_with_active_subagent_conn(conn, session_id, root_agent, None)
}

pub fn history_snapshot_with_active_subagent_conn(
    conn: &Connection,
    session_id: Uuid,
    root_agent: &str,
    active_subagent: Option<&proto::ActiveSubagent>,
) -> Result<Vec<proto::HistoryEntry>> {
    let events = Db::list_session_events_conn(conn, session_id)
        .map_err(|e| anyhow!("loading session events for history snapshot: {e}"))?;
    history_snapshot_from_events_conn(conn, session_id, root_agent, active_subagent, events)
}

pub fn history_snapshot_since_with_active_subagent_conn(
    conn: &Connection,
    session_id: Uuid,
    root_agent: &str,
    active_subagent: Option<&proto::ActiveSubagent>,
    since_seq: i64,
) -> Result<Vec<proto::HistoryEntry>> {
    let events = Db::list_session_events_since_conn(conn, session_id, since_seq)
        .map_err(|e| anyhow!("loading session events for history replay: {e}"))?;
    history_snapshot_from_events_conn(conn, session_id, root_agent, active_subagent, events)
}

/// Render a backward page of transcript history. Pages walk strictly
/// backwards from `before_seq`, so mid-turn appends after one page is fetched
/// cannot shift, duplicate, or skip older rows in the next page.
pub fn history_page_before_conn(
    conn: &Connection,
    session_id: Uuid,
    root_agent: &str,
    before_seq: Option<i64>,
    limit: u32,
) -> Result<HistoryPage> {
    let page = Db::list_session_events_before_conn(conn, session_id, before_seq, limit)
        .map_err(|e| anyhow!("loading session events for history page: {e}"))?;
    let entries =
        history_snapshot_from_events_conn(conn, session_id, root_agent, None, page.events)?;
    Ok(HistoryPage {
        entries,
        has_more: page.has_more,
        oldest_seq: page.oldest_seq,
    })
}

/// Project one already-read ledger snapshot into transcript entries. Keeping
/// the input rows caller-owned lets an attach couple history with other
/// ledger-derived metadata from the exact same SQLite read.
pub(crate) fn history_snapshot_from_events_conn(
    conn: &Connection,
    session_id: Uuid,
    root_agent: &str,
    active_subagent: Option<&proto::ActiveSubagent>,
    events: Vec<SessionEventRow>,
) -> Result<Vec<proto::HistoryEntry>> {
    let tool_calls = Db::list_tool_calls_for_session_conn(conn, session_id)
        .map_err(|e| anyhow!("loading tool calls for history snapshot: {e}"))?;

    // call_id → tool-call audit row (the same join key `rebuild_history`
    // uses). One row per call_id.
    let mut tc_by_id: std::collections::HashMap<&str, &ToolCallEvent> =
        std::collections::HashMap::new();
    for tc in &tool_calls {
        tc_by_id.insert(tc.call_id.as_str(), tc);
    }

    let active_child = active_subagent.map(|sub| sub.child.as_str());
    let visible_agent = |agent: Option<&str>| {
        agent == Some(root_agent) || active_child.is_some_and(|child| agent == Some(child))
    };
    let visible_lineage = |ev: &SessionEventRow| match ev.task_call_id.as_deref() {
        None => true,
        Some(task_call_id) => active_subagent.is_some_and(|active| {
            task_call_id == active.task_call_id
                && ev.label.as_deref() == Some(active.label.as_str())
        }),
    };

    let mut snapshot: Vec<proto::HistoryEntry> = Vec::new();
    for ev in &events {
        match ev.kind.as_str() {
            "interrupt_decision" if visible_lineage(ev) => {
                if let Some(value) = ev.data.get("decision")
                    && let Ok(decision) = serde_json::from_value(value.clone())
                {
                    snapshot.push(proto::HistoryEntry::InterruptDecision {
                        decision,
                        seq: ev.seq,
                    });
                }
            }
            "user_message" if visible_lineage(ev) => {
                let text = ev
                    .data
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let display_text = ev
                    .data
                    .get("display_text")
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string);
                let tag_expansions = ev
                    .data
                    .get("tag_expansions")
                    .cloned()
                    .and_then(|value| serde_json::from_value(value).ok())
                    .unwrap_or_default();
                let client_submission_ids = ev
                    .data
                    .get("client_submission_ids")
                    .cloned()
                    .and_then(|value| serde_json::from_value(value).ok())
                    .unwrap_or_default();
                snapshot.push(proto::HistoryEntry::User {
                    text,
                    display_text,
                    tag_expansions,
                    client_submission_ids,
                    ts_ms: ev.ts_ms,
                    seq: ev.seq,
                    origin_principal: ev.origin_principal.clone(),
                });
            }
            "user_note" if visible_lineage(ev) => {
                let text = ev
                    .data
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                snapshot.push(proto::HistoryEntry::UserNote {
                    text,
                    ts_ms: ev.ts_ms,
                    seq: ev.seq,
                });
            }
            "assistant_message" if visible_agent(ev.agent.as_deref()) && visible_lineage(ev) => {
                let agent = ev.agent.as_deref().unwrap_or(root_agent).to_string();
                let text = ev
                    .data
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let reasoning = ev
                    .data
                    .get("reasoning")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let presentation_text = ev
                    .data
                    .get("presentation_text")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let response_performance = ev.data.get("response_performance").and_then(|v| {
                    serde_json::from_value::<proto::ResponsePerformance>(v.clone()).ok()
                });
                snapshot.push(proto::HistoryEntry::Assistant {
                    agent,
                    text,
                    presentation_text,
                    reasoning,
                    response_performance,
                    ts_ms: ev.ts_ms,
                    seq: ev.seq,
                });
            }
            "tool_call" if visible_agent(ev.agent.as_deref()) && visible_lineage(ev) => {
                let Some(call_id) = ev.call_id.as_deref() else {
                    // A corrupt tool_call row with no call_id can't be paired
                    // or rendered meaningfully — skip it (the model-history
                    // path hard-errors here; the display path degrades).
                    continue;
                };
                // Prefer the audit row (canonical wire form + recovery chip +
                // result body, GOALS §14). Fall back to the timeline event's
                // own recorded fields for an interrupted call whose audit row
                // never landed, so the transcript still shows it.
                let entry = match tc_by_id.get(call_id) {
                    Some(tc) => {
                        let (recovery_kind, recovery_stage) = tc.recovery.raw_db_fields();
                        proto::HistoryEntry::ToolCall {
                            seq: ev.seq,
                            agent: tc.agent.clone(),
                            call_id: call_id.to_string(),
                            parent_call_id: tc.parent_call_id.clone(),
                            parent_child_index: tc.parent_child_index,
                            tool: tc.tool.clone(),
                            mcp_server: tc.mcp_server.clone(),
                            mcp_builtin: ev
                                .data
                                .get("mcp_builtin")
                                .and_then(serde_json::Value::as_bool),
                            mcp_kind: ev
                                .data
                                .get("mcp_kind")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_string),
                            original_input: tc.original_input_json.clone(),
                            wire_input: tc.wire_input_json.clone(),
                            recovery_kind: recovery_kind.map(|s| s.into_owned()),
                            recovery_stage: recovery_stage.map(|s| s.into_owned()),
                            output: tc.output.clone(),
                            hard_fail: tc.hard_fail,
                            truncated: tc.truncated,
                            // Post-result hint chip (`engine::bash_hints`), from
                            // the persisted `hint` JSON's `text` field.
                            hint: hint_text(tc.hint.as_ref()),
                        }
                    }
                    None => {
                        let tool = ev
                            .data
                            .get("tool")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let original_input = ev
                            .data
                            .get("original_input")
                            .or_else(|| ev.data.get("wire_input"))
                            .cloned()
                            .unwrap_or(serde_json::Value::Null);
                        let wire_input = ev
                            .data
                            .get("wire_input")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null);
                        let output = ev
                            .data
                            .get("output")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        proto::HistoryEntry::ToolCall {
                            seq: ev.seq,
                            agent: ev.agent.clone().unwrap_or_default(),
                            call_id: call_id.to_string(),
                            parent_call_id: ev
                                .data
                                .get("parent_call_id")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_string),
                            parent_child_index: ev
                                .data
                                .get("parent_child_index")
                                .and_then(serde_json::Value::as_i64),
                            tool,
                            mcp_server: ev
                                .data
                                .get("mcp_server")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_string),
                            mcp_builtin: ev
                                .data
                                .get("mcp_builtin")
                                .and_then(serde_json::Value::as_bool),
                            mcp_kind: ev
                                .data
                                .get("mcp_kind")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_string),
                            original_input,
                            wire_input,
                            recovery_kind: None,
                            recovery_stage: None,
                            output,
                            hard_fail: false,
                            truncated: false,
                            // The interrupted call's audit row never landed; the
                            // timeline event still carries `data.hint`.
                            hint: hint_text(ev.data.get("hint")),
                        }
                    }
                };
                snapshot.push(entry);
            }
            "inference_failure" if visible_agent(ev.agent.as_deref()) && visible_lineage(ev) => {
                let summary = inference_failure_summary(&ev.data);
                if summary.trim().is_empty() {
                    continue;
                }
                let detail = ev
                    .data
                    .get("detail")
                    .or_else(|| ev.data.get("full_detail"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                snapshot.push(proto::HistoryEntry::InferenceError {
                    seq: ev.seq,
                    summary,
                    detail,
                });
            }
            "subagent_spawned" => {
                let Some(active) = active_subagent else {
                    continue;
                };
                let parent = ev.data.get("parent").and_then(|v| v.as_str()).unwrap_or("");
                let child = ev.data.get("child").and_then(|v| v.as_str()).unwrap_or("");
                let label = ev
                    .data
                    .get("label")
                    .and_then(|v| v.as_str())
                    .unwrap_or("default");
                let task_call_id = ev
                    .call_id
                    .as_deref()
                    .or_else(|| ev.data.get("task_call_id").and_then(|v| v.as_str()))
                    .unwrap_or("");
                if parent == active.parent
                    && child == active.child
                    && task_call_id == active.task_call_id
                    && label == active.label
                {
                    snapshot.push(proto::HistoryEntry::Subagent {
                        seq: ev.seq,
                        parent: parent.to_string(),
                        child: child.to_string(),
                        task_call_id: task_call_id.to_string(),
                        label: label.to_string(),
                    });
                }
            }
            "session_compacted" if ev.agent.as_deref() == Some(root_agent) => {
                let data = match ev.data.get("handoff_ref").and_then(|v| v.as_str()) {
                    Some(reference) => Db::compaction_payload_conn(conn, session_id, reference)?
                        .map(|payload| {
                            serde_json::from_str(&payload)
                                .context("decoding stored compaction payload for history")
                        })
                        .transpose()?
                        .unwrap_or_else(|| ev.data.clone()),
                    None => ev.data.clone(),
                };
                let predecessor_short_id = data
                    .get("predecessor_short_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let seed_tool_count = data
                    .get("seed_tool_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as usize;
                let brief = data
                    .get("brief_text")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let handoff = data
                    .get("handoff_text")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .or_else(|| brief.clone());
                snapshot.push(proto::HistoryEntry::CompactBoundary {
                    seq: ev.seq,
                    predecessor_short_id,
                    seed_tool_count,
                    seed_tool_tokens: 0,
                    source: data
                        .get("source")
                        .and_then(|v| v.as_str())
                        .unwrap_or("manual")
                        .to_string(),
                    trigger_ctx_pct: data.get("trigger_ctx_pct").and_then(|v| v.as_f64()),
                    tokens_before: data
                        .get("tokens_before")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    tokens_after: data
                        .get("tokens_after")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    turns_summarized: data
                        .get("turns_summarized")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as usize,
                    tail_kept: data.get("tail_kept").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
                    tail_trimmed: data
                        .get("tail_trimmed")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as usize,
                    brief,
                    handoff,
                });
            }
            // Everything else (subagent frames, notes, prune markers, other
            // agents' turns) is not part of the resumed root transcript.
            _ => {}
        }
    }

    Ok(snapshot)
}

pub fn subagent_history_snapshot_conn(
    conn: &Connection,
    session_id: Uuid,
    task_call_id: &str,
    label: &str,
) -> Result<Vec<proto::HistoryEntry>> {
    let events = Db::list_session_events_conn(conn, session_id)
        .map_err(|e| anyhow!("loading session events for subagent history snapshot: {e}"))?;
    let tool_calls = Db::list_tool_calls_for_session_conn(conn, session_id)
        .map_err(|e| anyhow!("loading tool calls for subagent history snapshot: {e}"))?;
    let owned_events = events
        .into_iter()
        .filter(|ev| {
            ev.task_call_id.as_deref() == Some(task_call_id) && ev.label.as_deref() == Some(label)
        })
        .collect::<Vec<_>>();
    Ok(subagent_history_entries_from_events(
        &owned_events,
        &tool_calls,
    ))
}

pub fn subagent_history_page_before_conn(
    conn: &Connection,
    session_id: Uuid,
    task_call_id: &str,
    label: &str,
    before_seq: Option<i64>,
    limit: u32,
) -> Result<HistoryPage> {
    let page = Db::list_subagent_session_events_before_conn(
        conn,
        session_id,
        task_call_id,
        label,
        before_seq,
        limit,
    )
    .map_err(|e| anyhow!("loading session events for subagent history page: {e}"))?;
    let tool_calls = Db::list_tool_calls_for_session_conn(conn, session_id)
        .map_err(|e| anyhow!("loading tool calls for subagent history page: {e}"))?;
    Ok(HistoryPage {
        entries: subagent_history_entries_from_events(&page.events, &tool_calls),
        has_more: page.has_more,
        oldest_seq: page.oldest_seq,
    })
}

fn subagent_history_entries_from_events(
    events: &[SessionEventRow],
    tool_calls: &[ToolCallEvent],
) -> Vec<proto::HistoryEntry> {
    let mut tc_by_id: std::collections::HashMap<&str, &ToolCallEvent> =
        std::collections::HashMap::new();
    for tc in tool_calls {
        tc_by_id.insert(tc.call_id.as_str(), tc);
    }

    let mut snapshot: Vec<proto::HistoryEntry> = Vec::new();
    for ev in events {
        match ev.kind.as_str() {
            "user_message" => {
                let text = ev
                    .data
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let display_text = ev
                    .data
                    .get("display_text")
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string);
                let tag_expansions = ev
                    .data
                    .get("tag_expansions")
                    .cloned()
                    .and_then(|value| serde_json::from_value(value).ok())
                    .unwrap_or_default();
                let client_submission_ids = ev
                    .data
                    .get("client_submission_ids")
                    .cloned()
                    .and_then(|value| serde_json::from_value(value).ok())
                    .unwrap_or_default();
                snapshot.push(proto::HistoryEntry::User {
                    text,
                    display_text,
                    tag_expansions,
                    client_submission_ids,
                    ts_ms: ev.ts_ms,
                    seq: ev.seq,
                    origin_principal: ev.origin_principal.clone(),
                });
            }
            "assistant_message" => {
                let agent = ev.agent.clone().unwrap_or_default();
                let text = ev
                    .data
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let reasoning = ev
                    .data
                    .get("reasoning")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let presentation_text = ev
                    .data
                    .get("presentation_text")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let response_performance = ev.data.get("response_performance").and_then(|v| {
                    serde_json::from_value::<proto::ResponsePerformance>(v.clone()).ok()
                });
                snapshot.push(proto::HistoryEntry::Assistant {
                    agent,
                    text,
                    presentation_text,
                    reasoning,
                    response_performance,
                    ts_ms: ev.ts_ms,
                    seq: ev.seq,
                });
            }
            "tool_call" => {
                let Some(call_id) = ev.call_id.as_deref() else {
                    continue;
                };
                let entry = match tc_by_id.get(call_id) {
                    Some(tc) => {
                        let (recovery_kind, recovery_stage) = tc.recovery.raw_db_fields();
                        proto::HistoryEntry::ToolCall {
                            seq: ev.seq,
                            agent: tc.agent.clone(),
                            call_id: call_id.to_string(),
                            parent_call_id: tc.parent_call_id.clone(),
                            parent_child_index: tc.parent_child_index,
                            tool: tc.tool.clone(),
                            mcp_server: tc.mcp_server.clone(),
                            mcp_builtin: ev
                                .data
                                .get("mcp_builtin")
                                .and_then(serde_json::Value::as_bool),
                            mcp_kind: ev
                                .data
                                .get("mcp_kind")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_string),
                            original_input: tc.original_input_json.clone(),
                            wire_input: tc.wire_input_json.clone(),
                            recovery_kind: recovery_kind.map(|s| s.into_owned()),
                            recovery_stage: recovery_stage.map(|s| s.into_owned()),
                            output: tc.output.clone(),
                            hard_fail: tc.hard_fail,
                            truncated: tc.truncated,
                            hint: hint_text(tc.hint.as_ref()),
                        }
                    }
                    None => {
                        let tool = ev
                            .data
                            .get("tool")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let original_input = ev
                            .data
                            .get("original_input")
                            .or_else(|| ev.data.get("wire_input"))
                            .cloned()
                            .unwrap_or(serde_json::Value::Null);
                        let wire_input = ev
                            .data
                            .get("wire_input")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null);
                        let output = ev
                            .data
                            .get("output")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        proto::HistoryEntry::ToolCall {
                            seq: ev.seq,
                            agent: ev.agent.clone().unwrap_or_default(),
                            call_id: call_id.to_string(),
                            parent_call_id: ev
                                .data
                                .get("parent_call_id")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_string),
                            parent_child_index: ev
                                .data
                                .get("parent_child_index")
                                .and_then(serde_json::Value::as_i64),
                            tool,
                            mcp_server: ev
                                .data
                                .get("mcp_server")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_string),
                            mcp_builtin: ev
                                .data
                                .get("mcp_builtin")
                                .and_then(serde_json::Value::as_bool),
                            mcp_kind: ev
                                .data
                                .get("mcp_kind")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_string),
                            original_input,
                            wire_input,
                            recovery_kind: None,
                            recovery_stage: None,
                            output,
                            hard_fail: false,
                            truncated: false,
                            hint: hint_text(ev.data.get("hint")),
                        }
                    }
                };
                snapshot.push(entry);
            }
            "inference_failure" => {
                let summary = inference_failure_summary(&ev.data);
                if summary.trim().is_empty() {
                    continue;
                }
                let detail = ev
                    .data
                    .get("detail")
                    .or_else(|| ev.data.get("full_detail"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                snapshot.push(proto::HistoryEntry::InferenceError {
                    seq: ev.seq,
                    summary,
                    detail,
                });
            }
            "subagent_spawned" => {
                let parent = ev.data.get("parent").and_then(|v| v.as_str()).unwrap_or("");
                let child = ev
                    .data
                    .get("child")
                    .or_else(|| ev.data.get("child_agent"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let child_label = ev
                    .data
                    .get("label")
                    .and_then(|v| v.as_str())
                    .unwrap_or("default");
                let child_task_call_id = ev
                    .call_id
                    .as_deref()
                    .or_else(|| ev.data.get("task_call_id").and_then(|v| v.as_str()))
                    .unwrap_or("");
                snapshot.push(proto::HistoryEntry::Subagent {
                    seq: ev.seq,
                    parent: parent.to_string(),
                    child: child.to_string(),
                    task_call_id: child_task_call_id.to_string(),
                    label: child_label.to_string(),
                });
            }
            _ => {}
        }
    }
    snapshot
}

fn inference_failure_summary(data: &serde_json::Value) -> String {
    let provider = data.get("provider").and_then(|v| v.as_str()).unwrap_or("");
    let model = data.get("model").and_then(|v| v.as_str()).unwrap_or("");
    let class_value = data
        .get("error_class")
        .or_else(|| data.get("class"))
        .cloned()
        .unwrap_or_else(|| serde_json::Value::String("inference_error".to_string()));
    let detail = data
        .get("detail")
        .or_else(|| data.get("full_detail"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let parsed_class =
        serde_json::from_value::<crate::engine::model::InferenceErrorClass>(class_value.clone())
            .unwrap_or_else(|_| {
                crate::engine::model::InferenceErrorClass::Other(class_value.to_string())
            });
    let reason = match &parsed_class {
        crate::engine::model::InferenceErrorClass::TimeoutTtft => {
            "no first token within the timeout".to_string()
        }
        crate::engine::model::InferenceErrorClass::TimeoutIdle => {
            "stream stalled past the idle timeout".to_string()
        }
        _ if detail.trim().is_empty() => parsed_class.to_string(),
        _ => format!(
            "{}: {}",
            parsed_class,
            cockpit_host::text::first_line(detail, 200)
        ),
    };
    if provider.is_empty() && model.is_empty() {
        format!("Inference failed: {reason}")
    } else {
        format!("Inference failed ({provider}/{model}): {reason}")
    }
}

/// Extract the post-result hint chip text from a stored `hint` JSON value
/// (`{ kind, text, severity }` — the `engine::bash_hints` user-side surface).
/// `None` when absent or malformed (forward-compat — a missing/odd shape just
/// drops the chip, never errors the restore).
fn hint_text(hint: Option<&serde_json::Value>) -> Option<String> {
    hint?
        .get("text")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn load_ledger_conn(conn: &Connection, session_id: Uuid) -> Option<PruneLedger> {
    match Db::load_prune_ledger_conn(conn, session_id) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(session_id = %session_id, error = %e, "resume: reading prune ledger failed; treating as absent");
            None
        }
    }
}

/// A partial assistant turn under construction while walking events. One
/// turn = one inference: an assistant `Message` (its text + the tool calls
/// it issued) followed by the tool results, each pushed as its **own**
/// `Message::User` — matching the live wire format `agent::turn` produces
/// (`history.push(tool_result_message(...))` per call), so the rebuilt
/// history is byte-shaped like the original.
#[derive(Default)]
struct PendingTurn {
    text_parts: Vec<String>,
    calls: Vec<ToolCall>,
    /// One `(internal id, provider identity, tool name, body)` per issued
    /// call, in dispatch order. The two identities remain distinct so a
    /// resumed Responses turn echoes the provider's wire handle without
    /// losing Cockpit's durable call correlation.
    results: Vec<(
        ToolCallId,
        Option<ProviderCallId>,
        String,
        Vec<ToolResultContent>,
    )>,
    /// Durable scheduler source positions for calls in this inference. Public
    /// timeline rows and crash-only continuation rows can be encountered in a
    /// different order, but provider replay must retain the model's order.
    scheduler_source_order: std::collections::HashMap<String, (uuid::Uuid, usize)>,
}

impl PendingTurn {
    fn is_empty(&self) -> bool {
        self.text_parts.is_empty() && self.calls.is_empty()
    }

    /// Flush the buffered assistant turn (text + tool calls) and its tool
    /// results into `history`. A turn with no text and no calls contributes
    /// nothing.
    fn flush(mut self, history: &mut Vec<Message>) {
        if self.is_empty() {
            return;
        }
        let source_order = &self.scheduler_source_order;
        if scheduler_turn_is_complete(source_order, self.calls.iter().map(|call| call.id.as_ref()))
        {
            self.calls.sort_by_key(|call| {
                source_order
                    .get(call.id.as_ref())
                    .expect("scheduler completeness checked")
                    .1
            });
            self.results.sort_by_key(|result| {
                source_order
                    .get(result.0.as_ref())
                    .expect("scheduler completeness checked")
                    .1
            });
        }
        let mut content: Vec<AssistantContent> = Vec::new();
        let text = self.text_parts.join("\n");
        if !text.is_empty() {
            content.push(AssistantContent::text(text));
        }
        for tc in self.calls {
            content.push(AssistantContent::ToolCall(tc));
        }
        // `content` is non-empty here: `is_empty()` returned false, so there
        // is text and/or at least one call.
        if !content.is_empty() {
            history.push(Message::Assistant { id: None, content });
        }
        // Each tool result is its own user message (the live wire shape).
        // Provider contract: the results immediately follow the assistant
        // turn that issued the calls.
        for (call, provider, name, content) in self.results {
            history.push(Message::User {
                content: vec![UserContent::ToolResult(ToolResult {
                    call,
                    provider,
                    name,
                    content,
                })],
            });
        }
    }
}

fn scheduler_turn_is_complete<'a>(
    source_order: &std::collections::HashMap<String, (uuid::Uuid, usize)>,
    call_ids: impl Iterator<Item = &'a str>,
) -> bool {
    let mut turn_id = None;
    let mut saw_call = false;
    for call_id in call_ids {
        let Some((call_turn_id, _)) = source_order.get(call_id) else {
            return false;
        };
        if turn_id.is_some_and(|turn_id| turn_id != *call_turn_id) {
            return false;
        }
        turn_id = Some(*call_turn_id);
        saw_call = true;
    }
    saw_call
}

/// Walk the root agent's events (seq order) + the tool-call rows and
/// assemble the provider-valid message list. The tool-call rows are keyed
/// by `call_id` for the canonical wire input + result body; `task`
/// delegations pair with their `subagent_report` event.
#[derive(Clone)]
struct SpawnInfo {
    child: String,
    prompt: String,
    label: String,
    extras: serde_json::Map<String, serde_json::Value>,
    provider_call_id: Option<String>,
    provider_item_id: Option<String>,
}

#[derive(Clone)]
struct ReportInfo {
    child: String,
    label: String,
    report: String,
    provider_call_id: Option<String>,
    provider_item_id: Option<String>,
}

fn append_interrupted_scheduler_continuation(
    pending: &mut PendingTurn,
    continuation: &crate::db::turn_scheduler_continuations::TurnSchedulerContinuationRow,
    durable_tool_call: Option<&ToolCallEvent>,
) {
    pending.scheduler_source_order.insert(
        continuation.call_id.clone(),
        (continuation.turn_id, continuation.source_index),
    );
    let provider = continuation
        .provider_call_id
        .clone()
        .and_then(ProviderCallId::new)
        .map(|provider| match continuation.provider_item_id.clone() {
            Some(item_id) => provider.with_item_id(item_id),
            None => provider,
        });
    let call = ToolCall {
        id: ToolCallId::new_or_mint(continuation.call_id.clone()),
        provider: provider.clone(),
        function: ToolFunction {
            name: continuation.resolved_tool.clone(),
            arguments: continuation.wire_input.clone(),
        },
        signature: None,
        additional_params: None,
    };
    pending.calls.push(call.clone());
    pending.results.push((
        call.id,
        provider,
        continuation.resolved_tool.clone(),
        // A terminal scheduler row owns the canonical paired result even for
        // structural calls, which deliberately have no ordinary tool-call
        // audit row. Only a genuinely unsettled continuation uses the honest
        // scheduler interruption result on replay.
        vec![ToolResultContent::text(
            durable_tool_call
                .map(|tool_call| tool_call.output.clone())
                .or_else(|| continuation.terminal_result_body.clone())
                .unwrap_or_else(|| {
                    crate::engine::agent::turn_scheduler::SCHEDULER_INTERRUPTED_BODY.to_string()
                }),
        )],
    ));
}

fn rebuild_history(
    events: &[SessionEventRow],
    tool_calls: &[ToolCallEvent],
    scheduler_continuations: &[crate::db::turn_scheduler_continuations::TurnSchedulerContinuationRow],
    root_agent: &str,
    heals: &mut Vec<Recovery>,
    policy: RehydratePolicy,
) -> Result<Vec<Message>> {
    // A scheduler plan durably claims every original source call id before
    // execution. If a worker dies before a real tool/task row settles one of
    // them, recovery pairs that exact id with a scheduler-specific interruption
    // result instead of the generic orphan-call body.
    let scheduler_owned_calls = scheduler_continuations
        .iter()
        .filter(|call| call.agent_id == root_agent)
        .map(|call| call.call_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    let scheduler_continuation_by_call = scheduler_continuations
        .iter()
        .filter(|call| call.agent_id == root_agent)
        .map(|call| (call.call_id.as_str(), call))
        .collect::<std::collections::HashMap<_, _>>();
    // call_id → tool-call row (wire form + output). Last write wins (a
    // call_id is unique per call, so there is one row each).
    let mut tc_by_id: std::collections::HashMap<&str, &ToolCallEvent> =
        std::collections::HashMap::new();
    for tc in tool_calls {
        tc_by_id.insert(tc.call_id.as_str(), tc);
    }
    // task call_id → spawn rows. A single row rebuilds as
    // `task(intent=delegate, payload={...})`; multiple rows for the same call
    // rebuild as one `task(intent=batch, payload=[...])` call.
    let mut spawns_by_call: std::collections::HashMap<String, Vec<SpawnInfo>> =
        std::collections::HashMap::new();
    for ev in events {
        if ev.kind == "subagent_spawned"
            && ev.agent.as_deref() == Some(root_agent)
            && let Some(call_id) = ev.call_id.as_deref()
        {
            let child = ev
                .data
                .get("child_agent")
                .and_then(|v| v.as_str())
                .unwrap_or("builder")
                .to_string();
            let prompt = ev
                .data
                .get("prompt")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let label = ev
                .data
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("default")
                .to_string();
            let mut extras = serde_json::Map::new();
            if let Some(obj) = ev.data.as_object() {
                for (key, value) in obj {
                    if !matches!(
                        key.as_str(),
                        "child_agent"
                            | "task_call_id"
                            | "prompt"
                            | "label"
                            | "noninteractive"
                            | "provider_item_id"
                            | "provider_call_id"
                            | "provider_call_id_source"
                            | "function_call_id"
                            | "provider_identity"
                    ) && meaningful_delegation_arg(value)
                    {
                        extras.insert(key.clone(), value.clone());
                    }
                }
            }
            spawns_by_call
                .entry(call_id.to_string())
                .or_default()
                .push(SpawnInfo {
                    child,
                    prompt,
                    label,
                    extras,
                    provider_call_id: event_provider_call_id(ev),
                    provider_item_id: event_provider_item_id(ev),
                });
        }
    }
    // task call_id → subagent report text. The report event is tagged with
    // the CHILD agent but its call_id is the parent's task call id.
    let mut report_by_call: std::collections::HashMap<&str, ReportInfo> =
        std::collections::HashMap::new();
    let mut reports_by_call: std::collections::HashMap<String, Vec<ReportInfo>> =
        std::collections::HashMap::new();
    for ev in events {
        if ev.kind == "subagent_report"
            && let Some(call_id) = ev.call_id.as_deref()
        {
            let report = ev
                .data
                .get("report")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let child = ev
                .data
                .get("child_agent")
                .and_then(|v| v.as_str())
                .or(ev.agent.as_deref())
                .unwrap_or("")
                .to_string();
            let label = ev
                .data
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("default")
                .to_string();
            let info = ReportInfo {
                child,
                label,
                report,
                provider_call_id: event_provider_call_id(ev),
                provider_item_id: event_provider_item_id(ev),
            };
            report_by_call.insert(call_id, info.clone());
            reports_by_call
                .entry(call_id.to_string())
                .or_default()
                .push(info);
        }
    }

    let mut history: Vec<Message> = Vec::new();
    let mut pending = PendingTurn::default();
    let mut rebuilt_task_calls: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let publicly_represented_calls = events
        .iter()
        .filter(|event| {
            event.agent.as_deref() == Some(root_agent)
                && matches!(event.kind.as_str(), "tool_call" | "subagent_spawned")
        })
        .filter_map(|event| event.call_id.clone())
        .collect::<std::collections::HashSet<_>>();
    let mut anchored_scheduler_turns = std::collections::HashSet::new();

    for ev in events {
        match ev.kind.as_str() {
            "user_message" => {
                // A user message starts a fresh turn: flush the prior
                // assistant turn (+ its results) first.
                std::mem::take(&mut pending).flush(&mut history);
                let text = ev
                    .data
                    .get("text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                history.push(Message::user(text));
            }
            // Only the root foreground agent's turns belong in the rebuilt
            // context; subagent text/tool events stay in their transient
            // frames (not resumed). An `assistant_message` is one inference,
            // so it opens a fresh turn — flush the prior one first.
            "assistant_message" if ev.agent.as_deref() == Some(root_agent) => {
                std::mem::take(&mut pending).flush(&mut history);
                if let Some(text) = ev.data.get("text").and_then(|v| v.as_str())
                    && !text.is_empty()
                {
                    pending.text_parts.push(text.to_string());
                }
            }
            "tool_call" if ev.agent.as_deref() == Some(root_agent) && !is_mcp_child_event(ev) => {
                let Some(call_id) = ev.call_id.as_deref() else {
                    return Err(anyhow!("tool_call event without a call_id (corrupt row)"));
                };
                // Oversized forced skills are durably accepted with the user
                // envelope first, then their synthetic audit row is applied.
                // Live dispatch still presents the native seed pair before
                // that user message. Rebuild the pair at that same model-wire
                // position; if a crash occurred after phase two but before this
                // audit row, the envelope alone remains the complete handoff.
                let postphase_skill_seed = ev
                    .data
                    .get("skill_slash")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
                    && matches!(history.last(), Some(Message::User { .. }));
                let retained_user = postphase_skill_seed.then(|| history.pop()).flatten();
                // Canonical wire form + result body from the tool-call row.
                // A missing row means the call's result body never landed
                // durably (an interrupted call): heal it with an honest
                // aborted stub rather than dropping the whole conversation.
                // The tool name is unknown without the row, so reconstruct
                // the call from the timeline event's recorded `tool`.
                match tc_by_id.get(call_id) {
                    Some(tc) => {
                        let provider_identity = tc.provider_call_id.clone().or_else(|| {
                            ev.data
                                .get("provider_identity")
                                .and_then(|identity| identity.get("provider_call_id"))
                                .and_then(|value| value.as_str())
                                .map(str::to_string)
                        });
                        if policy.is_strict() && provider_identity.as_deref().is_none() {
                            return Err(anyhow::Error::new(RehydrateRepairRequired::new(
                                "missing_provider_call_id",
                                vec![call_id.to_string()],
                                Some(ev.seq.saturating_sub(1)),
                                "Responses replay needs the provider function call id recorded with the tool-call audit row",
                            )));
                        }
                        let provider_item_id = tc
                            .provider_item_id
                            .clone()
                            .unwrap_or_else(|| call_id.to_string());
                        let provider_call_id = provider_identity;
                        let provider = provider_call_id
                            .clone()
                            .and_then(ProviderCallId::new)
                            .map(|provider| provider.with_item_id(provider_item_id));
                        let call = ToolCall {
                            id: ToolCallId::new_or_mint(call_id.to_string()),
                            provider: provider.clone(),
                            function: ToolFunction {
                                name: tc.tool.clone(),
                                arguments: tc.wire_input_json.clone(),
                            },
                            signature: None,
                            additional_params: None,
                        };
                        pending.calls.push(call.clone());
                        let canonical_result = ev
                            .data
                            .get("canonical_output")
                            .and_then(|value| {
                                serde_json::from_value::<
                                    Vec<crate::typed_media_result::CanonicalToolResultContent>,
                                >(value.clone())
                                .ok()
                            })
                            .and_then(|parts| {
                                crate::engine::tool::CanonicalToolResultContents::new(parts).ok()
                            })
                            .and_then(|parts| parts.to_rig_contents().ok());
                        let projection_required = ev
                            .data
                            .get("model_projection_required")
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(false);
                        let canonical_text = ev
                            .data
                            .get("canonical_output_text")
                            .and_then(serde_json::Value::as_str)
                            .map(|text| vec![ToolResultContent::text(text.to_string())]);
                        let result_content = canonical_result
                            .or_else(|| projection_required.then(|| canonical_text).flatten());
                        if projection_required && result_content.is_none() {
                            return Err(anyhow::Error::new(RehydrateRepairRequired::new(
                                "missing_model_projection",
                                vec![call_id.to_string()],
                                Some(ev.seq.saturating_sub(1)),
                                "model-ephemeral structured result projection is missing or malformed; refusing unprojected replay",
                            )));
                        }
                        let result_content = result_content
                            .unwrap_or_else(|| vec![ToolResultContent::text(tc.output.clone())]);
                        pending
                            .results
                            .push((call.id, provider, tc.tool.clone(), result_content));
                    }
                    None => {
                        if scheduler_owned_calls.contains(call_id) {
                            let tool = ev
                                .data
                                .get("tool")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let provider = event_provider_call_id(ev)
                                .and_then(ProviderCallId::new)
                                .map(|provider| match event_provider_item_id(ev) {
                                    Some(item_id) => provider.with_item_id(item_id),
                                    None => provider,
                                });
                            let call = ToolCall {
                                id: ToolCallId::new_or_mint(call_id.to_string()),
                                provider: provider.clone(),
                                function: ToolFunction {
                                    name: tool.clone(),
                                    arguments: ev
                                        .data
                                        .get("wire_input")
                                        .cloned()
                                        .unwrap_or(serde_json::Value::Null),
                                },
                                signature: None,
                                additional_params: None,
                            };
                            pending.calls.push(call.clone());
                            pending.results.push((
                                call.id,
                                provider,
                                tool,
                                vec![ToolResultContent::text(
                                    scheduler_continuation_by_call
                                        .get(call_id)
                                        .and_then(|continuation| {
                                            continuation.terminal_result_body.clone()
                                        })
                                        .unwrap_or_else(|| {
                                            crate::engine::agent::turn_scheduler::SCHEDULER_INTERRUPTED_BODY
                                                .to_string()
                                        }),
                                )],
                            ));
                            continue;
                        }
                        if policy.is_strict() {
                            return Err(anyhow::Error::new(RehydrateRepairRequired::new(
                                "missing_provider_call_id",
                                vec![call_id.to_string()],
                                Some(ev.seq.saturating_sub(1)),
                                "Responses replay cannot rebuild a provider-valid tool pair without the durable tool-call audit row",
                            )));
                        }
                        let tool = ev
                            .data
                            .get("tool")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let arguments = ev
                            .data
                            .get("wire_input")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null);
                        let call = ToolCall {
                            id: ToolCallId::new_or_mint(call_id.to_string()),
                            provider: None,
                            function: ToolFunction {
                                name: tool.clone(),
                                arguments,
                            },
                            signature: None,
                            additional_params: None,
                        };
                        pending.calls.push(call.clone());
                        pending.results.push((
                            call.id,
                            None,
                            tool,
                            vec![ToolResultContent::text(ABORTED_CALL_BODY.to_string())],
                        ));
                        heals.push(Recovery::ResumeHeal {
                            kind: "stub_orphan_tool_call",
                            id: call_id.to_string(),
                        });
                    }
                }
                if let Some(user) = retained_user {
                    std::mem::take(&mut pending).flush(&mut history);
                    history.push(user);
                }
            }
            "session_compacted" if ev.agent.as_deref() == Some(root_agent) => {
                std::mem::take(&mut pending).flush(&mut history);
                history = compacted_model_history(ev)?;
            }
            "subagent_spawned" if ev.agent.as_deref() == Some(root_agent) => {
                let Some(call_id) = ev.call_id.as_deref() else {
                    return Err(anyhow!(
                        "subagent_spawned event without a task call_id (corrupt row)"
                    ));
                };
                if !rebuilt_task_calls.insert(call_id.to_string()) {
                    continue;
                }
                let spawns = spawns_by_call.get(call_id).cloned().unwrap_or_default();
                let arguments = if spawns.len() > 1 {
                    let why = spawns.iter().find_map(|spawn| {
                        spawn
                            .extras
                            .get("why")
                            .and_then(|value| value.as_str())
                            .filter(|value| !value.is_empty())
                            .map(str::to_string)
                    });
                    let parallel: Vec<_> = spawns
                        .iter()
                        .map(|spawn| {
                            let mut entry = spawn.extras.clone();
                            entry.remove("why");
                            entry.insert("label".to_string(), serde_json::json!(spawn.label));
                            entry.insert("agent".to_string(), serde_json::json!(spawn.child));
                            entry.insert("prompt".to_string(), serde_json::json!(spawn.prompt));
                            serde_json::Value::Object(entry)
                        })
                        .collect();
                    let mut arguments = serde_json::Map::new();
                    arguments.insert(
                        "intent".to_string(),
                        serde_json::Value::String("batch".to_string()),
                    );
                    arguments.insert("payload".to_string(), serde_json::Value::Array(parallel));
                    if let Some(why) = why {
                        arguments.insert("why".to_string(), serde_json::Value::String(why));
                    }
                    serde_json::Value::Object(arguments)
                } else {
                    let spawn = spawns.first().cloned().unwrap_or_else(|| SpawnInfo {
                        child: ev
                            .data
                            .get("child_agent")
                            .and_then(|v| v.as_str())
                            .unwrap_or("builder")
                            .to_string(),
                        prompt: ev
                            .data
                            .get("prompt")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        label: "default".to_string(),
                        extras: serde_json::Map::new(),
                        provider_call_id: None,
                        provider_item_id: None,
                    });
                    let mut delegate = spawn.extras;
                    delegate.insert("agent".to_string(), serde_json::json!(spawn.child));
                    delegate.insert("prompt".to_string(), serde_json::json!(spawn.prompt));
                    let mut arguments = serde_json::Map::new();
                    arguments.insert(
                        "intent".to_string(),
                        serde_json::Value::String("delegate".to_string()),
                    );
                    arguments.insert("payload".to_string(), serde_json::Value::Object(delegate));
                    serde_json::Value::Object(arguments)
                };
                let reports = reports_by_call.get(call_id).cloned().unwrap_or_default();
                let provider_call_id = task_provider_call_id(ev, &spawns, &reports);
                let provider_item_id = task_provider_item_id(ev, &spawns, &reports);
                let task_provider =
                    provider_call_id
                        .clone()
                        .and_then(ProviderCallId::new)
                        .map(|provider| match provider_item_id.clone() {
                            Some(item_id) => provider.with_item_id(item_id),
                            None => provider,
                        });
                let task_call = ToolCall {
                    id: ToolCallId::new_or_mint(call_id.to_string()),
                    provider: task_provider.clone(),
                    function: ToolFunction {
                        name: "task".to_string(),
                        arguments,
                    },
                    signature: None,
                    additional_params: None,
                };
                pending.calls.push(task_call.clone());
                // The task call's result is the subagent report. A missing
                // report means the delegation did not complete before resume:
                // heal it with an honest stub rather than dropping the whole
                // conversation (treated like a missing tool-call result).
                if spawns.len() > 1 {
                    let mut children = Vec::new();
                    for spawn in &spawns {
                        let report = reports
                            .iter()
                            .find(|r| r.label == spawn.label && r.child == spawn.child)
                            .or_else(|| reports.iter().find(|r| r.label == spawn.label))
                            .cloned();
                        let (report, failed) = match report {
                            Some(report) => {
                                ensure_report_provider_identity_matches(
                                    policy,
                                    call_id,
                                    provider_item_id.as_deref(),
                                    report.provider_item_id.as_deref(),
                                    provider_call_id.as_deref(),
                                    report.provider_call_id.as_deref(),
                                    ev.seq,
                                )?;
                                let failed =
                                    super::driver::is_host_failure_sentinel(&report.report);
                                (report.report, failed)
                            }
                            None => {
                                if policy.is_strict() {
                                    return Err(anyhow::Error::new(RehydrateRepairRequired::new(
                                        "orphan_assistant_call",
                                        vec![call_id.to_string()],
                                        Some(ev.seq.saturating_sub(1)),
                                        "Responses replay found a task delegation without a durable subagent report",
                                    )));
                                }
                                heals.push(Recovery::ResumeHeal {
                                    kind: "stub_missing_subagent_report",
                                    id: call_id.to_string(),
                                });
                                (MISSING_REPORT_BODY.to_string(), true)
                            }
                        };
                        children.push(serde_json::json!({
                            "label": spawn.label,
                            "agent": spawn.child,
                            "failed": failed,
                            "report": report,
                        }));
                    }
                    let body = serde_json::json!({
                        "status": "completed",
                        "children": children,
                    })
                    .to_string();
                    pending.results.push((
                        task_call.id.clone(),
                        task_provider.clone(),
                        "task".to_string(),
                        vec![ToolResultContent::text(body)],
                    ));
                } else {
                    match report_by_call.get(call_id) {
                        Some(report) => {
                            ensure_report_provider_identity_matches(
                                policy,
                                call_id,
                                provider_item_id.as_deref(),
                                report.provider_item_id.as_deref(),
                                provider_call_id.as_deref(),
                                report.provider_call_id.as_deref(),
                                ev.seq,
                            )?;
                            pending.results.push((
                                task_call.id.clone(),
                                task_provider.clone(),
                                "task".to_string(),
                                vec![ToolResultContent::text(report.report.clone())],
                            ));
                        }
                        None => {
                            if policy.is_strict() {
                                return Err(anyhow::Error::new(RehydrateRepairRequired::new(
                                    "orphan_assistant_call",
                                    vec![call_id.to_string()],
                                    Some(ev.seq.saturating_sub(1)),
                                    "Responses replay found a task delegation without a durable subagent report",
                                )));
                            }
                            pending.results.push((
                                task_call.id.clone(),
                                task_provider.clone(),
                                "task".to_string(),
                                vec![ToolResultContent::text(MISSING_REPORT_BODY.to_string())],
                            ));
                            heals.push(Recovery::ResumeHeal {
                                kind: "stub_missing_subagent_report",
                                id: call_id.to_string(),
                            });
                        }
                    }
                }
            }
            // A root-agent `inference_request` marks an inference boundary.
            // The primary per-inference event is recorded once by live dispatch
            // (`turn_phases.rs`, "Part B") BEFORE that inference's assistant
            // text and tool_call events, so flushing the pending turn here
            // splits *sequential* inferences into distinct assistant messages —
            // the live wire shape — even when an inference issued tool calls but
            // produced no assistant text (so no `assistant_message` event fired
            // to trigger the split). Parallel calls within ONE inference share a
            // single `inference_request`, so they stay in one turn.
            //
            // Two utility inferences (`context_reduction.rs` compact-brief /
            // compact-sample) ALSO record root-tagged `inference_request`
            // events. They are safe here because they only run at a turn
            // boundary: auto-compact runs synchronously while the agent is idle
            // (and its `session_compacted` event clears history anyway), and a
            // backgrounded shadow brief is preempted + joined
            // (`preempt_shadow_brief_for_foreground`) before any foreground
            // dispatch records a tool_call. So no root `inference_request` ever
            // lands between an inference's `assistant_message` and its
            // `tool_call`s; the flush they trigger is a no-op on empty `pending`
            // or a correct complete-turn flush. INVARIANT for future work: a new
            // foreground root-inference path that dispatches while a shadow
            // brief is in flight WITHOUT that preempt would break this split.
            //
            // The flush is a no-op when `pending` is empty (e.g. the first
            // inference of a turn, right after the user message), so pairing
            // with the `assistant_message` flush above never double-splits an
            // inference. Sessions predating this event fall back to the
            // `assistant_message` split (text-ful inferences only).
            "inference_request" if ev.agent.as_deref() == Some(root_agent) => {
                std::mem::take(&mut pending).flush(&mut history);
            }
            "tool_call_scheduling" if ev.agent.as_deref() == Some(root_agent) => {
                let Some(turn_id) = ev
                    .data
                    .get("continuation_turn_id")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| uuid::Uuid::parse_str(value).ok())
                else {
                    continue;
                };
                anchored_scheduler_turns.insert(turn_id);
                for continuation in scheduler_continuations.iter().filter(|continuation| {
                    continuation.agent_id == root_agent && continuation.turn_id == turn_id
                }) {
                    pending.scheduler_source_order.insert(
                        continuation.call_id.clone(),
                        (continuation.turn_id, continuation.source_index),
                    );
                    if !publicly_represented_calls.contains(&continuation.call_id) {
                        append_interrupted_scheduler_continuation(
                            &mut pending,
                            continuation,
                            tc_by_id.get(continuation.call_id.as_str()).copied(),
                        );
                    }
                }
            }
            // Everything else (non-root-agent inference_request, context_pruned,
            // permission_decision, subagent_report,
            // other agents' turns) is not part of the root model history.
            _ => {}
        }
    }
    // The private plan is committed before the exportable scheduling event or
    // any dispatch. A crash can therefore leave calls with no public row at
    // all. Materialize each such source identity in canonical plan order and
    // pair it with the scheduler interruption result.
    for continuation in scheduler_continuations {
        if continuation.agent_id != root_agent
            || anchored_scheduler_turns.contains(&continuation.turn_id)
            || publicly_represented_calls.contains(&continuation.call_id)
        {
            continue;
        }
        append_interrupted_scheduler_continuation(
            &mut pending,
            continuation,
            tc_by_id.get(continuation.call_id.as_str()).copied(),
        );
    }
    // Flush the final assistant turn (+ results), if any.
    pending.flush(&mut history);
    crate::engine::delegation_prompt_prune::prune_completed_delegation_prompts(&mut history);
    // Same projection as the live path: rehydrate rebuilds args from
    // `tool_call_events.wire_input_json` (full durable form), then stubs
    // applied write/edit fields for the model-visible history.
    crate::engine::write_edit_arg_elision::elide_applied_write_edit_args(&mut history);

    Ok(history)
}

fn is_mcp_child_event(ev: &SessionEventRow) -> bool {
    ev.data
        .get("mcp_child")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

fn event_provider_call_id(ev: &SessionEventRow) -> Option<String> {
    ev.data
        .get("provider_call_id")
        .or_else(|| ev.data.get("function_call_id"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            ev.data
                .get("provider_identity")
                .and_then(|identity| identity.get("provider_call_id"))
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
}

fn event_provider_item_id(ev: &SessionEventRow) -> Option<String> {
    ev.data
        .get("provider_item_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            ev.data
                .get("provider_identity")
                .and_then(|identity| identity.get("provider_item_id"))
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
}

fn task_provider_call_id(
    ev: &SessionEventRow,
    spawns: &[SpawnInfo],
    reports: &[ReportInfo],
) -> Option<String> {
    event_provider_call_id(ev)
        .or_else(|| {
            spawns
                .iter()
                .find_map(|spawn| spawn.provider_call_id.clone())
        })
        .or_else(|| {
            reports
                .iter()
                .find_map(|report| report.provider_call_id.clone())
        })
        .or_else(|| Some(ev.call_id.as_ref()?.to_string()))
}

fn task_provider_item_id(
    ev: &SessionEventRow,
    spawns: &[SpawnInfo],
    reports: &[ReportInfo],
) -> Option<String> {
    event_provider_item_id(ev)
        .or_else(|| {
            spawns
                .iter()
                .find_map(|spawn| spawn.provider_item_id.clone())
        })
        .or_else(|| {
            reports
                .iter()
                .find_map(|report| report.provider_item_id.clone())
        })
}

fn ensure_report_provider_identity_matches(
    policy: RehydratePolicy,
    call_id: &str,
    expected_item_id: Option<&str>,
    actual_item_id: Option<&str>,
    expected_call_id: Option<&str>,
    actual_call_id: Option<&str>,
    seq: i64,
) -> Result<()> {
    if policy.is_strict()
        && ((matches!(
            (expected_item_id, actual_item_id),
            (Some(expected), Some(actual)) if expected != actual
        )) || matches!(
            (expected_call_id, actual_call_id),
            (Some(expected), Some(actual)) if expected != actual
        ))
    {
        return Err(anyhow::Error::new(RehydrateRepairRequired::new(
            "mismatched_pair",
            vec![call_id.to_string()],
            Some(seq.saturating_sub(1)),
            "Responses replay found a subagent report paired to a different provider identity",
        )));
    }
    Ok(())
}

fn meaningful_delegation_arg(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(items) => !items.is_empty(),
        _ => true,
    }
}

/// Collect a message's tool-result ids (each result is its own user
/// message in the rebuilt shape, but handle multiples defensively).
fn result_ids(msg: &Message) -> Vec<String> {
    match msg {
        Message::User { content } => content
            .iter()
            .filter_map(|c| match c {
                UserContent::ToolResult(tr) => Some(tr.call.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// A synthetic, honest tool_result user message for a stubbed orphan call.
/// Retain the exact wire identity and name from its assistant tool_use: Rig
/// pairs provider replay results by all three fields.
fn stub_result_message(call: &ToolCall, body: &str) -> Message {
    Message::User {
        content: vec![UserContent::ToolResult(ToolResult {
            call: call.id.clone(),
            provider: call.provider.clone(),
            name: call.function.name.clone(),
            content: vec![ToolResultContent::text(body.to_string())],
        })],
    }
}

/// Heal the rebuilt history so it is provider-valid before the final
/// `validate_pairing` assertion (implementation note).
/// Two orphan classes are handled in one forward pass:
///
/// - **Orphan tool_result** (no preceding tool_use of the same id) → the
///   offending result item is dropped (an emptied user message is removed),
///   leaving sibling results in the same user turn untouched.
/// - **Orphan tool_use** (an assistant tool_use id not covered by the run of
///   tool_result user messages that immediately follows) → a synthetic,
///   honest aborted `tool_result` (same id) is inserted right after that run
///   so the call did not silently disappear and is not fabricated as a
///   success.
///
/// Each heal appends a [`Recovery::ResumeHeal`] to `heals`. The pass is
/// idempotent: an already-paired history yields no edits and no heals.
///
/// Resume callers heal a fully-assembled history (no pending follow-on);
/// the live pre-send path (implementation note) calls
/// [`heal_pairing_pending`] instead, naming the result ids carried by the
/// not-yet-pushed `prompt` so a structural tool's own driver-injected result
/// (delivered out of band as that `prompt`) is treated as covering its
/// tool_use rather than being wrongly stubbed.
fn heal_pairing(history: &mut Vec<Message>, heals: &mut Vec<Recovery>) {
    heal_pairing_pending(history, &[], ABORTED_CALL_BODY, heals);
}

/// Heal `history` so it is provider-valid, treating `pending_results` — the
/// tool_result ids carried by a not-yet-pushed `prompt` that will immediately
/// follow `history` on the wire — as already covering their tool_uses. The
/// pending results trail the final assistant turn's result run, so they are
/// folded into the `covered` set for the last assistant turn only.
///
/// Allocation-free on the clean path: pass 2's per-turn `call_ids`/`covered`
/// vectors are only built for assistant turns that actually issue calls, and a
/// fully-paired turn inserts nothing and records no heal.
fn heal_pairing_pending(
    history: &mut Vec<Message>,
    pending_results: &[String],
    orphan_body: &str,
    heals: &mut Vec<Recovery>,
) {
    // 1. Drop orphan tool_results. Walk forward tracking the call ids the
    //    most-recent assistant turn issued; a tool_result whose id is not in
    //    that open set is an orphan and is removed. A plain user prompt (no
    //    results) closes the open set, mirroring `validate_pairing`.
    let mut open_calls: Vec<String> = Vec::new();
    let mut i = 0;
    while i < history.len() {
        match &mut history[i] {
            Message::Assistant { content, .. } => {
                let calls: Vec<String> = content
                    .iter()
                    .filter_map(|c| match c {
                        AssistantContent::ToolCall(tc) => Some(tc.id.to_string()),
                        _ => None,
                    })
                    .collect();
                if !calls.is_empty() {
                    open_calls = calls;
                }
                i += 1;
            }
            Message::User { content } => {
                let has_result = content
                    .iter()
                    .any(|c| matches!(c, UserContent::ToolResult(_)));
                if !has_result {
                    // A plain user prompt closes the open call set.
                    open_calls.clear();
                    i += 1;
                    continue;
                }
                let has_orphan = content.iter().any(|c| {
                    matches!(c, UserContent::ToolResult(tr)
                        if !open_calls.iter().any(|call| call == tr.call.as_str()))
                });
                if !has_orphan {
                    i += 1;
                    continue;
                }
                // Keep only results that pair with an open call; non-result
                // items (defensive) are always kept. Cloning happens only on
                // the repair path.
                let mut kept: Vec<UserContent> = Vec::new();
                for c in content.iter() {
                    match c {
                        UserContent::ToolResult(tr)
                            if !open_calls.iter().any(|call| call == tr.call.as_str()) =>
                        {
                            heals.push(Recovery::ResumeHeal {
                                kind: "drop_orphan_tool_result",
                                id: tr.call.to_string(),
                            });
                        }
                        _ => kept.push(c.clone()),
                    }
                }
                if kept.is_empty() {
                    // The whole user message was orphan results — drop it.
                    history.remove(i);
                    // Do not advance: the next message shifts into index `i`.
                } else {
                    *content = kept;
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }

    // 2. Stub orphan tool_uses. For each assistant turn with tool calls,
    //    gather the contiguous run of following tool-result user messages
    //    (mirroring `validate_pairing`'s forward pass) and insert a synthetic
    //    honest result for any call id not covered, right after that run.
    let mut i = 0;
    while i < history.len() {
        if let Message::Assistant { content, .. } = &history[i] {
            let calls: Vec<ToolCall> = content
                .iter()
                .filter_map(|c| match c {
                    AssistantContent::ToolCall(tc) => Some(tc.clone()),
                    _ => None,
                })
                .collect();
            if !calls.is_empty() {
                let mut covered: Vec<String> = Vec::new();
                let mut j = i + 1;
                while let Some(msg @ Message::User { .. }) = history.get(j) {
                    let ids = result_ids(msg);
                    if ids.is_empty() {
                        break; // a plain user text message ends the run
                    }
                    covered.extend(ids);
                    j += 1;
                }
                // The not-yet-pushed `prompt` (live pre-send path) continues
                // this turn's result run *only* when the run reaches the end of
                // `history` — the prompt lands right after the last message.
                // This is how a structural tool's own driver-injected result
                // (carried by that prompt) covers its tool_use instead of being
                // wrongly stubbed.
                if j == history.len() {
                    covered.extend(pending_results.iter().cloned());
                }
                // `j` is the insertion point (just past the result run).
                for call in &calls {
                    if !covered.contains(&call.id.to_string()) {
                        history.insert(j, stub_result_message(call, orphan_body));
                        j += 1;
                        heals.push(Recovery::ResumeHeal {
                            kind: "stub_orphan_tool_call",
                            id: call.id.to_string(),
                        });
                    }
                }
            }
        }
        i += 1;
    }
}

/// Live pre-send pairing heal (implementation note).
///
/// Run this on the LIVE root history immediately before each provider request
/// so the wire never carries an orphan `tool_use` — backstopping the
/// structural-then-sibling case (a structural tool returns early, leaving a
/// trailing sibling `tool_use` with no result) and any future path that could
/// leave one. Single source of truth: it shares [`heal_pairing_pending`] with
/// the resume path, reuses the same `ResumeHeal` recovery kinds, and is a
/// no-op (no allocation, no edit, no heal) on the overwhelmingly common
/// already-paired history.
///
/// `prompt` is the not-yet-pushed message that will immediately follow
/// `history` on the wire (typically the user message or, after a structural
/// tool, its driver-injected `tool_result`). Its result ids cover the matching
/// tool_uses so the structural tool's own pending result is **not**
/// double-stubbed.
///
/// Returns the heals applied (empty on the clean path) for the caller's audit
/// trail (GOALS §14).
pub(crate) fn heal_live_history(history: &mut Vec<Message>, prompt: &Message) -> Vec<Recovery> {
    let mut heals: Vec<Recovery> = Vec::new();
    // A non-tool-result prompt (plain user text/images) yields no pending ids —
    // the common case.
    let pending = result_ids(prompt);
    heal_pairing_pending(
        history,
        &pending,
        crate::engine::agent::turn_scheduler::SCHEDULER_INTERRUPTED_BODY,
        &mut heals,
    );
    heals
}

fn detect_responses_identity_gaps(history: &[Message]) -> Result<()> {
    let mut open: Vec<(String, String)> = Vec::new();
    for msg in history {
        match msg {
            Message::Assistant { content, .. } => {
                if let Some((id, _)) = open.first() {
                    return Err(anyhow::Error::new(RehydrateRepairRequired::new(
                        "orphan_assistant_call",
                        vec![id.clone()],
                        None,
                        "Responses replay found an assistant tool call with no following tool result",
                    )));
                }
                open.clear();
                for part in content.iter() {
                    if let AssistantContent::ToolCall(tc) = part {
                        let Some(call_id) = tc
                            .provider
                            .as_ref()
                            .map(|provider| provider.call_id.clone())
                        else {
                            return Err(anyhow::Error::new(RehydrateRepairRequired::new(
                                "missing_provider_call_id",
                                vec![tc.id.to_string()],
                                None,
                                "Responses replay requires the provider function call id for each assistant tool call",
                            )));
                        };
                        open.push((tc.id.to_string(), call_id));
                    }
                }
            }
            Message::User { content } => {
                let mut saw_result = false;
                for part in content.iter() {
                    if let UserContent::ToolResult(tr) = part {
                        saw_result = true;
                        let Some(pos) = open.iter().position(|(id, _)| id == tr.call.as_str())
                        else {
                            return Err(anyhow::Error::new(RehydrateRepairRequired::new(
                                "orphan_tool_result",
                                vec![tr.call.to_string()],
                                None,
                                "Responses replay found a tool result with no preceding assistant tool call",
                            )));
                        };
                        let expected_call_id = open[pos].1.clone();
                        match tr
                            .provider
                            .as_ref()
                            .map(|provider| provider.call_id.as_str())
                        {
                            Some(actual) if actual == expected_call_id.as_str() => {}
                            Some(_) => {
                                return Err(anyhow::Error::new(RehydrateRepairRequired::new(
                                    "mismatched_pair",
                                    vec![tr.call.to_string()],
                                    None,
                                    "Responses replay found a tool result paired to a different provider call id",
                                )));
                            }
                            None => {
                                return Err(anyhow::Error::new(RehydrateRepairRequired::new(
                                    "missing_provider_call_id",
                                    vec![tr.call.to_string()],
                                    None,
                                    "Responses replay requires the provider function call id on each tool result",
                                )));
                            }
                        }
                        open.remove(pos);
                    }
                }
                if !saw_result {
                    if let Some((id, _)) = open.first() {
                        return Err(anyhow::Error::new(RehydrateRepairRequired::new(
                            "orphan_assistant_call",
                            vec![id.clone()],
                            None,
                            "Responses replay found an assistant tool call before the next plain user turn",
                        )));
                    }
                    open.clear();
                }
            }
            Message::System { .. } => {
                if let Some((id, _)) = open.first() {
                    return Err(anyhow::Error::new(RehydrateRepairRequired::new(
                        "orphan_assistant_call",
                        vec![id.clone()],
                        None,
                        "Responses replay found an assistant tool call before a system message",
                    )));
                }
                open.clear();
            }
        }
    }
    if let Some((id, _)) = open.first() {
        return Err(anyhow::Error::new(RehydrateRepairRequired::new(
            "orphan_assistant_call",
            vec![id.clone()],
            None,
            "Responses replay found an assistant tool call at the end of the transcript",
        )));
    }
    Ok(())
}

/// Provider-validity gate (priority #1: never send a malformed context).
/// Every assistant `tool_use` id must have a matching `tool_result` in the
/// run of user messages that immediately follows the assistant turn (each
/// result is its own user message — the live wire shape), and no orphan
/// `tool_result` (one with no preceding tool_use of the same id) may
/// appear. A failure is a hard error.
pub(crate) fn validate_pairing(history: &[Message]) -> Result<()> {
    // Forward pass: each assistant turn's call ids must be covered by the
    // immediately-following run of tool-result user messages.
    let mut i = 0;
    while i < history.len() {
        if let Message::Assistant { content, .. } = &history[i] {
            let call_ids: Vec<String> = content
                .iter()
                .filter_map(|c| match c {
                    AssistantContent::ToolCall(tc) => Some(tc.id.to_string()),
                    _ => None,
                })
                .collect();
            if !call_ids.is_empty() {
                // Gather the contiguous run of following tool-result ids.
                let mut covered: Vec<String> = Vec::new();
                let mut j = i + 1;
                while let Some(msg @ Message::User { .. }) = history.get(j) {
                    let ids = result_ids(msg);
                    if ids.is_empty() {
                        break; // a plain user text message ends the run
                    }
                    covered.extend(ids);
                    j += 1;
                }
                for id in &call_ids {
                    if !covered.contains(id) {
                        return Err(anyhow!(
                            "rebuilt history has an unpaired tool_use `{id}` \
                             (no matching tool_result); refusing to send a malformed context"
                        ));
                    }
                }
            }
        }
        i += 1;
    }

    // Reverse-ish pass: every tool_result must trace back to a preceding
    // assistant tool_use of the same id (no orphan results). Walk forward,
    // tracking the call ids the most-recent assistant turn issued.
    let mut open_calls: Vec<String> = Vec::new();
    for msg in history {
        match msg {
            Message::Assistant { content, .. } => {
                let calls: Vec<String> = content
                    .iter()
                    .filter_map(|c| match c {
                        AssistantContent::ToolCall(tc) => Some(tc.id.to_string()),
                        _ => None,
                    })
                    .collect();
                if !calls.is_empty() {
                    open_calls = calls;
                }
            }
            Message::User { content } => {
                let mut had_result = false;
                for c in content.iter() {
                    if let UserContent::ToolResult(tr) = c {
                        had_result = true;
                        if !open_calls.iter().any(|call| call == tr.call.as_str()) {
                            return Err(anyhow!(
                                "rebuilt history has an orphan tool_result `{}` \
                                 (no preceding tool_use); refusing to send a malformed context",
                                tr.call
                            ));
                        }
                    }
                }
                // A plain user prompt (no tool results) closes the open set.
                if !had_result {
                    open_calls.clear();
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tool_calls::Recovery;
    use crate::engine::prune::{Elision, LedgerEntry};
    use crate::session::{Session, ToolCallRow};
    use serde_json::json;
    use std::path::PathBuf;

    fn root_session() -> Session {
        let db = Db::open_in_memory().unwrap();
        let s = Session::create_for_test(
            db,
            PathBuf::from("/x"),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        s.set_active_model("anthropic", "opus").unwrap();
        s
    }

    async fn stage_user_blob(s: &Session, text: &str) -> String {
        let path = crate::text_artifact_blob::new_path(s.id);
        s.db.stage_text_artifact_blob_cleanup_intent(path.clone(), s.id, 1)
            .await
            .unwrap();
        crate::text_artifact_blob::write_at(&path, text).unwrap()
    }

    async fn record_user(s: &Session, text: &str) {
        s.record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &json!({ "text": text }),
        )
        .await
        .unwrap();
    }

    async fn record_assistant(s: &Session, call_id: &str, text: &str) {
        s.record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("Build"),
            Some(call_id),
            &json!({ "text": text }),
        )
        .await
        .unwrap();
    }

    /// Record an assistant turn the way the engine does for an
    /// inline-`<think>` model: the stored `text` is already STRIPPED (no
    /// tags), and the reasoning rides its own `data_json` field.
    async fn record_assistant_with_reasoning(
        s: &Session,
        call_id: &str,
        text: &str,
        reasoning: &str,
    ) {
        s.record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("Build"),
            Some(call_id),
            &json!({ "text": text, "reasoning": reasoning }),
        )
        .await
        .unwrap();
    }

    /// Record the `inference_request` timeline event the engine emits once per
    /// inference (Part B), tagged with the root agent and marking an inference
    /// boundary. Live dispatch emits this BEFORE that inference's assistant
    /// text / tool_call events, so callers record it immediately before the
    /// `record_assistant` / `record_tool` calls for that inference.
    async fn record_inference_request(s: &Session, call_id: &str) {
        record_inference_request_for_agent(s, "Build", call_id).await;
    }

    /// Same as [`record_inference_request`] but for an arbitrary agent, so a
    /// subagent's inference boundary can be interleaved to prove the root-agent
    /// guard on the flush arm.
    async fn record_inference_request_for_agent(s: &Session, agent: &str, call_id: &str) {
        s.record_event(
            crate::db::session_log::SessionEventKind::InferenceRequest,
            Some(agent),
            Some(call_id),
            &json!({ "ordinal": 0 }),
        )
        .await
        .unwrap();
    }

    /// Record a real tool call (both the timeline event and the audit row,
    /// as the engine does), with a chosen wire input distinct from the
    /// original to prove `wire_input_json` is the source used.
    async fn record_tool(
        s: &Session,
        call_id: &str,
        tool: &str,
        original: serde_json::Value,
        wire: serde_json::Value,
        output: &str,
    ) {
        s.record_tool_call(ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".into(),
            call_id: call_id.into(),
            parent_call_id: None,
            parent_child_index: None,
            identity: crate::session::ToolCallProviderIdentity::default(),
            tool: tool.into(),
            path: None,
            mcp_server: None,
            original_input_json: original.clone(),
            wire_input_json: wire.clone(),
            recovery: Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            output: output.into(),
            truncated: false,
            duration_ms: 1,
            shape_fingerprint: None,
            hint: None,
        })
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some(call_id),
            &json!({
                "tool": tool,
                "original_input": original,
                "wire_input": wire,
                "output": output,
            }),
        )
        .await
        .unwrap();
    }

    async fn record_tool_with_model_artifact(
        s: &Session,
        call_id: &str,
        tool: &str,
        output: &str,
        artifact_body: &str,
    ) {
        s.record_tool_call(ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".into(),
            call_id: call_id.into(),
            parent_call_id: None,
            parent_child_index: None,
            identity: crate::session::ToolCallProviderIdentity::default(),
            tool: tool.into(),
            path: None,
            mcp_server: None,
            original_input_json: json!({ "path": "/f" }),
            wire_input_json: json!({ "path": "/f" }),
            recovery: Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            output: output.into(),
            truncated: false,
            duration_ms: 1,
            shape_fingerprint: None,
            hint: None,
        })
        .await
        .unwrap();
        s.db.record_event_with_text_artifacts(crate::db::text_artifacts::TextArtifactEventInput {
            session_id: s.id,
            kind: crate::db::session_log::SessionEventKind::ToolCall,
            agent: Some("Build".into()),
            call_id: Some(call_id.into()),
            context: Default::default(),
            ts_ms: chrono::Utc::now().timestamp_millis(),
            data_json: json!({
                "tool": tool,
                "original_input": { "path": "/f" },
                "wire_input": { "path": "/f" },
                "output": output,
            })
            .to_string(),
            artifacts: vec![crate::db::text_artifacts::TextArtifactCandidate {
                relation: crate::db::text_artifacts::TextArtifactRelation::ModelContextToolResult,
                projection_slot: Some(0),
                kind: crate::db::text_artifacts::TextArtifactKind::ToolResult,
                capture_reason: crate::db::text_artifacts::CaptureReason::DisplayTruncation,
                content: artifact_body.into(),
                host_captured_bytes: artifact_body.len(),
                host_original_bytes: artifact_body.len(),
                host_dropped_bytes: 0,
                stored_source_bytes: artifact_body.len(),
                provenance_json: json!({
                    "agent_id": "Build",
                    "tool": tool,
                    "call_id": call_id,
                })
                .to_string(),
                created_at: chrono::Utc::now().timestamp_millis(),
            }],
            staged_blob_paths: Vec::new(),
            unavailable_projection: None,
        })
        .await
        .unwrap();
    }

    async fn record_prune_with_model_artifact(s: &Session, call_id: &str, artifact_body: &str) {
        s.record_context_pruned_with_artifacts(
            "Build",
            false,
            4,
            2,
            100,
            50,
            &[call_id.to_string()],
            "budget",
            50,
            None,
            None,
            vec![crate::db::text_artifacts::TextArtifactCandidate {
                relation: crate::db::text_artifacts::TextArtifactRelation::ModelContextToolResult,
                projection_slot: Some(0),
                kind: crate::db::text_artifacts::TextArtifactKind::ToolResult,
                capture_reason: crate::db::text_artifacts::CaptureReason::PruneBoundary,
                content: artifact_body.into(),
                host_captured_bytes: artifact_body.len(),
                host_original_bytes: artifact_body.len(),
                host_dropped_bytes: 0,
                stored_source_bytes: artifact_body.len(),
                provenance_json: json!({
                    "agent_id": "Build",
                    "tool": "bash",
                    "call_id": call_id,
                })
                .to_string(),
                created_at: chrono::Utc::now().timestamp_millis(),
            }],
        )
        .await
        .unwrap();
    }

    async fn record_inplace_compact(s: &Session, handoff: &str, tail: &[Message]) {
        s.record_session_compacted_with_source(
            "Build",
            crate::session::SessionCompactionRecord {
                successor_session_id: s.id,
                successor_short_id: &s.short_id(),
                seed_tool_count: 0,
                brief_text: "brief",
                handoff_text: handoff,
                source: "manual",
                trigger_ctx_pct: None,
                tokens_before: 500,
                tokens_after: 100,
                turns_summarized: 3,
                tail_kept: 1,
                tail_trimmed: 0,
                tail_messages: tail,
            },
            None,
        )
        .await
        .unwrap();
    }

    /// Record the durable audit trail emitted after a forced `/skill` prelude
    /// has already been accepted into an oversized user envelope.
    async fn record_post_audit_forced_skill(s: &Session, call_id: &str, body: &str) {
        s.record_tool_call(ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".into(),
            call_id: call_id.into(),
            parent_call_id: None,
            parent_child_index: None,
            identity: crate::session::ToolCallProviderIdentity::default(),
            tool: "skill".into(),
            path: None,
            mcp_server: None,
            original_input_json: json!({ "name": "review" }),
            wire_input_json: json!({ "name": "review" }),
            recovery: Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            output: body.into(),
            truncated: false,
            duration_ms: 1,
            shape_fingerprint: None,
            hint: None,
        })
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some(call_id),
            &json!({
                "tool": "skill",
                "original_input": { "name": "review" },
                "wire_input": { "name": "review" },
                "output": body,
                "skill_slash": true,
            }),
        )
        .await
        .unwrap();
    }

    async fn record_tool_with_identity(
        s: &Session,
        call_id: &str,
        identity: crate::session::ToolCallProviderIdentity,
    ) {
        s.record_tool_call(ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".into(),
            call_id: call_id.into(),
            parent_call_id: None,
            parent_child_index: None,
            identity,
            tool: "read".into(),
            path: None,
            mcp_server: None,
            original_input_json: json!({ "path": "/f" }),
            wire_input_json: json!({ "path": "/f" }),
            recovery: Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            output: "body".into(),
            truncated: false,
            duration_ms: 1,
            shape_fingerprint: None,
            hint: None,
        })
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some(call_id),
            &json!({
                "tool": "read",
                "original_input": { "path": "/f" },
                "wire_input": { "path": "/f" },
                "output": "body",
            }),
        )
        .await
        .unwrap();
    }

    async fn record_inference_failure(s: &Session, data: serde_json::Value) {
        s.record_event(
            crate::db::session_log::SessionEventKind::InferenceFailure,
            Some("Build"),
            None,
            &data,
        )
        .await
        .unwrap();
    }

    fn assistant_text(m: &Message) -> String {
        match m {
            Message::Assistant { content, .. } => content
                .iter()
                .filter_map(|c| match c {
                    AssistantContent::Text(t) => Some(t.text.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n"),
            _ => panic!("not assistant"),
        }
    }

    fn assistant_calls(m: &Message) -> Vec<ToolCall> {
        match m {
            Message::Assistant { content, .. } => content
                .iter()
                .filter_map(|c| match c {
                    AssistantContent::ToolCall(tc) => Some(tc.clone()),
                    _ => None,
                })
                .collect(),
            _ => panic!("not assistant"),
        }
    }

    fn long_delegation_prompt() -> String {
        let mut s = String::new();
        while crate::tokens::count(&s) < 140 {
            s.push_str("Investigate live and resume delegation history, preserve provider-valid tool-call pairing, compare event reconstruction paths, and return concise findings with file references. ");
        }
        s
    }

    fn user_text(m: &Message) -> String {
        match m {
            Message::User { content } => content
                .iter()
                .filter_map(|c| match c {
                    UserContent::Text(t) => Some(t.text.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(""),
            _ => panic!("not user"),
        }
    }

    fn tool_result_body(m: &Message) -> String {
        match m {
            Message::User { content } => content
                .iter()
                .filter_map(|c| match c {
                    UserContent::ToolResult(tr) => Some(
                        tr.content
                            .iter()
                            .filter_map(|c| match c {
                                ToolResultContent::Text(t) => Some(t.text.clone()),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join(""),
                    ),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(""),
            _ => panic!("not user"),
        }
    }

    fn tool_result_text_ptr(m: &Message) -> *const str {
        match m {
            Message::User { content } => content
                .iter()
                .find_map(|c| match c {
                    UserContent::ToolResult(tr) => tr.content.iter().find_map(|part| match part {
                        ToolResultContent::Text(t) => Some(t.text.as_str() as *const str),
                        _ => None,
                    }),
                    _ => None,
                })
                .expect("tool result text"),
            _ => panic!("not user"),
        }
    }

    fn tool_results(m: &Message) -> Vec<ToolResult> {
        match m {
            Message::User { content } => content
                .iter()
                .filter_map(|c| match c {
                    UserContent::ToolResult(tr) => Some(tr.clone()),
                    _ => None,
                })
                .collect(),
            _ => panic!("not user"),
        }
    }

    /// A plain user/assistant exchange rebuilds with correct roles + order.
    #[tokio::test]
    async fn rebuilds_plain_exchange() {
        let s = root_session();
        record_user(&s, "hello").await;
        record_assistant(&s, "call-1", "hi there").await;
        record_user(&s, "bye").await;
        record_assistant(&s, "call-2", "goodbye").await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        assert_eq!(h.len(), 4);
        assert_eq!(user_text(&h[0]), "hello");
        assert_eq!(assistant_text(&h[1]), "hi there");
        assert_eq!(user_text(&h[2]), "bye");
        assert_eq!(assistant_text(&h[3]), "goodbye");
    }

    #[tokio::test]
    async fn oversized_user_rehydrate_rejects_a_long_mixed_media_event_before_artifact_lookup() {
        let s = root_session();
        // This is the legacy shape that dispatch must now reject before it is
        // durable. Rehydrate remains fail-closed for a corrupted/old archive:
        // it must not silently hand the full body to a provider.
        s.record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &json!({
                "text": "x".repeat(64 * 1024 + 1),
                "images": [{"id": Uuid::new_v4()}],
            }),
        )
        .await
        .unwrap();

        let error = rehydrate_session(&s.db, s.id, "Build")
            .await
            .expect_err("a long mixed-media user event is never artifact-eligible");
        assert!(
            error.to_string().contains("cannot carry media/file parts"),
            "unexpected rehydrate error: {error:#}"
        );
    }

    #[tokio::test]
    async fn materialized_oversized_composition_rehydrates_one_forced_pair_and_ordered_parts() {
        struct AllowJoin;
        impl crate::db::message_attachments::MessageAcceptanceJoin for AllowJoin {
            fn validate_and_join(
                &self,
                _: &rusqlite::Connection,
                _: &crate::db::message_attachments::AcceptMessageInput,
            ) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let _env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
        let s = root_session();
        let source = "x".repeat(65_537);
        let operation_id = Uuid::new_v4();
        let submission_id = Uuid::new_v4();
        let reserved =
            s.db.accept_message_with_text_artifact_reservation(
                crate::db::message_attachments::AcceptMessageInput {
                    session_id: s.id,
                    operation_id: *operation_id.as_bytes(),
                    actor: crate::db::message_attachments::MessageActor::LocalOwner,
                    request_hash: [7; 32],
                    message_request_digest: [8; 32],
                    attachment_set_digest: [9; 32],
                    client_submission_id: *submission_id.as_bytes(),
                    queue_item_id: *submission_id.as_bytes(),
                    canonical_message: b"FCM2\x02".to_vec(),
                    attachments: Vec::new(),
                    outbox_sequence: 0,
                    now_ms: 10,
                    tool_media_subject_binding: None,
                },
                Arc::new(AllowJoin),
                crate::db::text_artifacts::source_digest(&source),
                source.len(),
            )
            .await
            .unwrap();
        let reservation = match reserved {
            crate::db::text_artifacts::TextArtifactPhaseOneResult::Reserved(reservation) => {
                reservation
            }
            other => panic!("expected reservation, got {other:?}"),
        };
        let typed =
            UserContent::image_base64("YWJj", Some(rig::message::ImageMediaType::PNG), None);
        let envelope = json!({
            "version": 3,
            "prelude": [{
                "type": "forced_skill",
                "call_id": "forced-1",
                "name": "review",
                "args": {"name":"review"},
                "body": "FORCED",
                "hard_fail": false
            }],
            "parts": [
                {"type":"text","text":"AUTO\\n"},
                {"type":"text","text":"TAG\\n"},
                {"type":"image","payload": serde_json::to_value(&typed).unwrap()},
                {"type":"authored_text_slot"}
            ]
        });
        let source_blob_path = stage_user_blob(&s, &source).await;
        s.db.materialize_reserved_user_text_artifacts(
            crate::db::text_artifacts::ReservedUserArtifactMaterialization {
                reservation,
                canonical_event_json: json!({"text": source.clone()}).to_string(),
                model_envelope_json: envelope.to_string(),
                source_text: source,
                source_blob_path: Some(source_blob_path),
                source_preview_lines: None,
                model_projection_blob_path: None,
                model_projection: None,
                agent: Some("Build".to_owned()),
                context: crate::db::text_artifacts::TextArtifactEventContext::default(),
                now_ms: 11,
            },
        )
        .await
        .unwrap();

        // This is the crash window: phase two is durable but the ordinary
        // post-commit audit bookkeeping did not run. The envelope is therefore
        // the sole source of the one forced pair.
        let history = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap()
            .history;
        assert_eq!(history.len(), 3);
        assert!(matches!(
            &history[0],
            Message::Assistant { content, .. }
                if matches!(content.as_slice(), [AssistantContent::ToolCall(call)]
                    if call.function.name == "skill"
                        && call.function.arguments == json!({"name":"review"}))
        ));
        assert!(matches!(
            &history[1],
            Message::User { content }
                if matches!(content.as_slice(), [UserContent::ToolResult(result)]
                    if result.name == "skill"
                        && result.content == vec![ToolResultContent::text("FORCED")])
        ));
        assert!(matches!(
            &history[2],
            Message::User { content }
                if content.len() == 4
                    && matches!(&content[0], UserContent::Text(text) if text.text == "AUTO\\n")
                    && matches!(&content[1], UserContent::Text(text) if text.text == "TAG\\n")
                    && content[2] == typed
                    && matches!(&content[3], UserContent::Text(text) if text.text.contains("<cockpit_artifact_v1 "))
        ));
    }

    #[tokio::test]
    async fn post_audit_forced_prelude_is_redacted_identically_on_restart() {
        struct AllowJoin;
        impl crate::db::message_attachments::MessageAcceptanceJoin for AllowJoin {
            fn validate_and_join(
                &self,
                _: &rusqlite::Connection,
                _: &crate::db::message_attachments::AcceptMessageInput,
            ) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let _env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
        let s = root_session();
        let source = "x".repeat(65_537);
        let operation_id = Uuid::new_v4();
        let submission_id = Uuid::new_v4();
        let reserved =
            s.db.accept_message_with_text_artifact_reservation(
                crate::db::message_attachments::AcceptMessageInput {
                    session_id: s.id,
                    operation_id: *operation_id.as_bytes(),
                    actor: crate::db::message_attachments::MessageActor::LocalOwner,
                    request_hash: [17; 32],
                    message_request_digest: [18; 32],
                    attachment_set_digest: [19; 32],
                    client_submission_id: *submission_id.as_bytes(),
                    queue_item_id: *submission_id.as_bytes(),
                    canonical_message: b"FCM2\x02".to_vec(),
                    attachments: Vec::new(),
                    outbox_sequence: 0,
                    now_ms: 10,
                    tool_media_subject_binding: None,
                },
                Arc::new(AllowJoin),
                crate::db::text_artifacts::source_digest(&source),
                source.len(),
            )
            .await
            .unwrap();
        let reservation = match reserved {
            crate::db::text_artifacts::TextArtifactPhaseOneResult::Reserved(reservation) => {
                reservation
            }
            other => panic!("expected reservation, got {other:?}"),
        };
        let secret = "post-audit-forced-secret";
        let envelope = json!({
            "version": 3,
            "prelude": [{
                "type": "forced_skill",
                "call_id": "forced-redaction",
                "name": "review",
                "args": {"name":"review"},
                "body": secret,
                "hard_fail": false
            }],
            "parts": [{"type":"authored_text_slot"}]
        });
        let source_blob_path = stage_user_blob(&s, &source).await;
        s.db.materialize_reserved_user_text_artifacts(
            crate::db::text_artifacts::ReservedUserArtifactMaterialization {
                reservation,
                canonical_event_json: json!({"text": source.clone()}).to_string(),
                model_envelope_json: envelope.to_string(),
                source_text: source,
                source_blob_path: Some(source_blob_path),
                source_preview_lines: None,
                model_projection_blob_path: None,
                model_projection: None,
                agent: Some("Build".to_owned()),
                context: crate::db::text_artifacts::TextArtifactEventContext::default(),
                now_ms: 11,
            },
        )
        .await
        .unwrap();

        // Phase two has committed; then the ordinary post-commit `/skill`
        // audit bookkeeping lands. Resume must not trust its unredacted body
        // over the same accepted-envelope prelude used by live dispatch.
        record_post_audit_forced_skill(&s, "forced-redaction", secret).await;
        let cfg = crate::config::extended::RedactConfig {
            enabled: true,
            denylist: vec![secret.to_owned()],
            placeholder: "***REDACT***".to_owned(),
            ..crate::config::extended::RedactConfig::default()
        };
        let redaction = Arc::new(
            crate::redact::RedactionTable::build(&cfg, std::path::Path::new(".")).unwrap(),
        );
        let live_prelude =
            crate::engine::text_artifact_frame::render_accepted_user_composition_with_redaction(
                &envelope.to_string(),
                "live artifact frame is irrelevant to the prelude assertion",
                redaction.as_ref(),
            )
            .unwrap()
            .leading;
        let history = rehydrate_session_with_policy_and_redaction(
            &s.db,
            s.id,
            "Build",
            RehydratePolicy::heal(),
            redaction,
        )
        .await
        .unwrap()
        .unwrap()
        .history;

        assert_eq!(history.len(), 3);
        assert_eq!(&history[..2], live_prelude.as_slice());
        assert!(matches!(
            &history[0],
            Message::Assistant { content, .. }
                if matches!(content.as_slice(), [AssistantContent::ToolCall(call)]
                    if call.function.name == "skill" && call.function.arguments == json!({"name":"review"}))
        ));
        assert!(matches!(
            &history[1],
            Message::User { content }
                if matches!(content.as_slice(), [UserContent::ToolResult(result)]
                    if result.name == "skill"
                        && result.content == vec![ToolResultContent::text("***REDACT***")])
        ));
        assert!(format!("{history:?}").contains("***REDACT***"));
        assert!(!format!("{history:?}").contains(secret));
    }

    #[tokio::test]
    async fn rehydrate_model_context_omits_inference_failure_events() {
        let s = root_session();
        record_user(&s, "hello").await;
        record_inference_failure(
            &s,
            json!({
                "provider": "local",
                "model": "bad",
                "error_class": crate::engine::model::InferenceErrorClass::Network,
                "detail": "first line\nsecond line",
            }),
        )
        .await;
        record_user(&s, "after").await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        assert_eq!(h.len(), 2);
        assert_eq!(user_text(&h[0]), "hello");
        assert_eq!(user_text(&h[1]), "after");
    }

    #[tokio::test]
    async fn rehydrate_model_context_omits_mcp_child_tool_events() {
        let s = root_session();
        record_user(&s, "use mcp").await;
        record_assistant(&s, "infer-1", "calling mcp").await;
        record_tool(
            &s,
            "outer-mcp",
            "mcp",
            json!({ "script": "mcp.invoke('cockpit', 'context_usage', {})" }),
            json!({ "script": "mcp.invoke('cockpit', 'context_usage', {})" }),
            "{\"ok\":true}",
        )
        .await;

        s.record_tool_call(ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".into(),
            call_id: "outer-mcp:mcp:0".into(),
            parent_call_id: Some("outer-mcp".into()),
            parent_child_index: Some(0),
            identity: crate::session::ToolCallProviderIdentity::synthetic_cockpit_call(
                "outer-mcp:mcp:0",
                None,
            ),
            tool: "context_usage".into(),
            path: None,
            mcp_server: Some("cockpit".into()),
            original_input_json: json!({
                "server": "cockpit",
                "tool": "context_usage",
                "args": {}
            }),
            wire_input_json: json!({
                "server": "cockpit",
                "tool": "context_usage",
                "args": {}
            }),
            recovery: Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            output: "{\"snapshot\":\"unavailable\"}".into(),
            truncated: false,
            duration_ms: 1,
            shape_fingerprint: None,
            hint: None,
        })
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some("outer-mcp:mcp:0"),
            &json!({
                "tool": "context_usage",
                "mcp_child": true,
                "mcp_kind": "invoke",
                "mcp_server": "cockpit",
                "mcp_builtin": true,
                "parent_call_id": "outer-mcp",
                "parent_child_index": 0,
                "wire_input": {
                    "server": "cockpit",
                    "tool": "context_usage",
                    "args": {}
                },
                "output": "{\"snapshot\":\"unavailable\"}",
            }),
        )
        .await
        .unwrap();

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        assert_eq!(h.len(), 3);
        let calls = assistant_calls(&h[1]);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "mcp");
        assert_eq!(tool_results(&h[2]).len(), 1);
        assert_eq!(tool_result_body(&h[2]), "{\"ok\":true}");
    }

    #[tokio::test]
    async fn history_snapshot_includes_inference_failure_display_rows_in_order() {
        let s = root_session();
        record_user(&s, "before").await;
        record_inference_failure(
            &s,
            json!({
                "provider": "local",
                "model": "bad",
                "error_class": crate::engine::model::InferenceErrorClass::Network,
                "detail": "first line\nsecond line",
            }),
        )
        .await;
        record_user(&s, "after").await;

        let snapshot = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        assert_eq!(snapshot.len(), 3);
        assert!(matches!(snapshot[0], proto::HistoryEntry::User { .. }));
        match &snapshot[1] {
            proto::HistoryEntry::InferenceError {
                summary, detail, ..
            } => {
                assert_eq!(summary, "Inference failed (local/bad): network: first line");
                assert_eq!(detail, "first line\nsecond line");
            }
            other => panic!("snapshot[1] should be InferenceError, got {other:?}"),
        }
        assert!(matches!(snapshot[2], proto::HistoryEntry::User { .. }));
    }

    #[tokio::test]
    async fn error_class_wire_legacy_flat_string_row_still_reads_and_renders() {
        let s = root_session();
        let legacy = r#"{
            "provider": "local",
            "model": "bad",
            "phase_reached": "dispatched",
            "error_class": "network",
            "detail": "first line\nsecond line",
            "elapsed_ms": 37
        }"#;
        record_inference_failure(&s, serde_json::from_str(legacy).unwrap()).await;

        let snapshot = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        assert_eq!(snapshot.len(), 1);
        match &snapshot[0] {
            proto::HistoryEntry::InferenceError {
                summary, detail, ..
            } => {
                assert_eq!(summary, "Inference failed (local/bad): network: first line");
                assert_eq!(detail, "first line\nsecond line");
            }
            other => panic!("snapshot[0] should be InferenceError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn history_snapshot_handles_old_inference_failure_without_detail() {
        let s = root_session();
        record_inference_failure(
            &s,
            json!({
                "provider": "local",
                "model": "slow",
                "error_class": crate::engine::model::InferenceErrorClass::TimeoutTtft,
            }),
        )
        .await;

        let snapshot = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        assert_eq!(snapshot.len(), 1);
        match &snapshot[0] {
            proto::HistoryEntry::InferenceError {
                summary, detail, ..
            } => {
                assert_eq!(
                    summary,
                    "Inference failed (local/slow): no first token within the timeout"
                );
                assert!(detail.is_empty());
            }
            other => panic!("snapshot[0] should be InferenceError, got {other:?}"),
        }
    }

    /// An inline-`<think>` model's stored transcript rebuilds a model
    /// history that carries NO `<think>` tags (the stored text is already
    /// stripped) and NEVER injects the separately-stored reasoning into the
    /// model context (token economy — implementation note).
    #[tokio::test]
    async fn rehydrated_history_is_tag_free_and_omits_reasoning() {
        let s = root_session();
        record_user(&s, "do it").await;
        // Stored as the engine now stores it: clean body + reasoning aside.
        record_assistant_with_reasoning(
            &s,
            "infer-1",
            "the clean answer",
            "the model's hidden chain of thought",
        )
        .await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        assert_eq!(h.len(), 2);
        let rebuilt = assistant_text(&h[1]);
        // The body is exactly the stored (stripped) text…
        assert_eq!(rebuilt, "the clean answer");
        // …with no `<think>` tags and none of the reasoning text leaking in.
        assert!(!rebuilt.contains("<think>"));
        assert!(!rebuilt.contains("chain of thought"));
    }

    /// The stored reasoning is durable on the assistant_message event so a
    /// resume/export can repopulate the thinking chip; it lives on its own
    /// `data_json` field (and the `reasoning` generated column), separate
    /// from the model-bound `text`.
    #[tokio::test]
    async fn stored_reasoning_persists_on_the_event() {
        let s = root_session();
        record_user(&s, "go").await;
        record_assistant_with_reasoning(&s, "infer-1", "answer", "secret reasoning").await;

        let events = s.db.list_session_events(s.id).await.unwrap();
        let am = events
            .iter()
            .find(|e| e.kind == "assistant_message")
            .expect("assistant_message event");
        assert_eq!(am.data.get("text").and_then(|v| v.as_str()), Some("answer"));
        assert_eq!(
            am.data.get("reasoning").and_then(|v| v.as_str()),
            Some("secret reasoning")
        );
    }

    /// A tool turn rebuilds with the assistant tool_use + a paired
    /// tool_result, and the tool args come from `wire_input_json` (not the
    /// model's original input).
    #[tokio::test]
    async fn rebuilds_tool_turn_using_wire_input() {
        let s = root_session();
        record_user(&s, "read the file").await;
        record_assistant(&s, "infer-1", "let me read it").await;
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "src/main.rs", "typo": true }),
            json!({ "path": "src/main.rs" }),
            "fn main() {}",
        )
        .await;
        record_assistant(&s, "infer-2", "done").await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        // user / assistant(text+toolcall) / user(toolresult) / assistant
        assert_eq!(h.len(), 4);
        assert_eq!(user_text(&h[0]), "read the file");
        let calls = assistant_calls(&h[1]);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "tc-1");
        assert_eq!(calls[0].function.name, "read");
        // The canonical WIRE form is used, not the original (no `typo`).
        assert_eq!(
            calls[0].function.arguments,
            json!({ "path": "src/main.rs" })
        );
        assert_eq!(tool_result_body(&h[2]), "fn main() {}");
        assert_eq!(assistant_text(&h[3]), "done");

        validate_pairing(&h).expect("provider-valid");
    }

    #[tokio::test]
    async fn rebuilds_parallel_tool_calls_as_one_assistant_turn() {
        let s = root_session();
        record_user(&s, "read both files").await;
        record_assistant(&s, "infer-1", "reading both").await;
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "a.rs" }),
            json!({ "path": "a.rs" }),
            "A",
        )
        .await;
        record_tool(
            &s,
            "tc-2",
            "read",
            json!({ "path": "b.rs" }),
            json!({ "path": "b.rs" }),
            "B",
        )
        .await;
        record_assistant(&s, "infer-2", "done").await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        assert_eq!(h.len(), 5);
        let calls = assistant_calls(&h[1]);
        assert_eq!(
            calls.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            vec!["tc-1", "tc-2"]
        );
        assert_eq!(tool_result_body(&h[2]), "A");
        assert_eq!(tool_result_body(&h[3]), "B");
        assert_eq!(assistant_text(&h[4]), "done");
        validate_pairing(&h).expect("provider-valid");
    }

    #[tokio::test]
    async fn rebuilds_sequential_textless_inferences_as_distinct_turns() {
        // Two back-to-back inferences that each issued a tool call but produced
        // NO assistant text. Without an `inference_request` boundary the two
        // calls would merge into one assistant turn (breaking byte-identical
        // reconstruction and the provider cache prefix); the boundary event
        // splits them, matching the live wire shape.
        let s = root_session();
        record_user(&s, "do two things").await;

        // Inference 1: text-less, one tool call.
        record_inference_request(&s, "infer-1").await;
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "a.rs" }),
            json!({ "path": "a.rs" }),
            "A",
        )
        .await;

        // Inference 2: text-less, one tool call, informed by tc-1's result.
        record_inference_request(&s, "infer-2").await;
        record_tool(
            &s,
            "tc-2",
            "read",
            json!({ "path": "b.rs" }),
            json!({ "path": "b.rs" }),
            "B",
        )
        .await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        // user / assistant(tc-1) / user(A) / assistant(tc-2) / user(B):
        // TWO distinct assistant turns, not one merged turn.
        assert_eq!(h.len(), 5);
        assert_eq!(user_text(&h[0]), "do two things");
        let first = assistant_calls(&h[1]);
        assert_eq!(
            first.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            vec!["tc-1"]
        );
        assert_eq!(tool_result_body(&h[2]), "A");
        let second = assistant_calls(&h[3]);
        assert_eq!(
            second.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            vec!["tc-2"]
        );
        assert_eq!(tool_result_body(&h[4]), "B");
        validate_pairing(&h).expect("provider-valid");
    }

    #[tokio::test]
    async fn inference_request_boundary_keeps_parallel_calls_in_one_turn() {
        // A single inference issuing two parallel calls shares ONE
        // `inference_request`; the boundary event must not split it.
        let s = root_session();
        record_user(&s, "read both files").await;
        record_inference_request(&s, "infer-1").await;
        record_assistant(&s, "infer-1", "reading both").await;
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "a.rs" }),
            json!({ "path": "a.rs" }),
            "A",
        )
        .await;
        record_tool(
            &s,
            "tc-2",
            "read",
            json!({ "path": "b.rs" }),
            json!({ "path": "b.rs" }),
            "B",
        )
        .await;
        record_inference_request(&s, "infer-2").await;
        record_assistant(&s, "infer-2", "done").await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        assert_eq!(h.len(), 5);
        let calls = assistant_calls(&h[1]);
        assert_eq!(
            calls.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            vec!["tc-1", "tc-2"]
        );
        assert_eq!(assistant_text(&h[1]), "reading both");
        assert_eq!(tool_result_body(&h[2]), "A");
        assert_eq!(tool_result_body(&h[3]), "B");
        assert_eq!(assistant_text(&h[4]), "done");
        validate_pairing(&h).expect("provider-valid");
    }

    #[tokio::test]
    async fn non_root_inference_request_does_not_split_root_turn() {
        // A non-root-agent `inference_request` (e.g. a subagent's inference
        // boundary) interleaves in the log but must NOT split the root agent's
        // turn — the flush arm is guarded on `== Some(root_agent)`.
        let s = root_session();
        record_user(&s, "read both files").await;
        record_inference_request(&s, "infer-1").await;
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "a.rs" }),
            json!({ "path": "a.rs" }),
            "A",
        )
        .await;
        // A CHILD-agent inference boundary lands between the root's two calls.
        record_inference_request_for_agent(&s, "child", "child-infer").await;
        record_tool(
            &s,
            "tc-2",
            "read",
            json!({ "path": "b.rs" }),
            json!({ "path": "b.rs" }),
            "B",
        )
        .await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        // Still ONE root turn holding both calls: user / assistant(tc-1,tc-2)
        // / user(A) / user(B).
        assert_eq!(h.len(), 4);
        let calls = assistant_calls(&h[1]);
        assert_eq!(
            calls.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            vec!["tc-1", "tc-2"]
        );
        assert_eq!(tool_result_body(&h[2]), "A");
        assert_eq!(tool_result_body(&h[3]), "B");
        validate_pairing(&h).expect("provider-valid");
    }

    #[tokio::test]
    async fn rebuilds_textless_then_textful_inferences_as_distinct_turns() {
        // Asymmetric sequence: a text-less inference followed by a text-ful
        // one. The boundary splits them; the second turn keeps its text.
        let s = root_session();
        record_user(&s, "go").await;
        // Inference 1: text-less, one call.
        record_inference_request(&s, "infer-1").await;
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "a.rs" }),
            json!({ "path": "a.rs" }),
            "A",
        )
        .await;
        // Inference 2: text-ful, one call.
        record_inference_request(&s, "infer-2").await;
        record_assistant(&s, "infer-2", "now editing").await;
        record_tool(
            &s,
            "tc-2",
            "edit",
            json!({ "path": "a.rs" }),
            json!({ "path": "a.rs" }),
            "ok",
        )
        .await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        // user / assistant(tc-1) / user(A) / assistant("now editing"+tc-2) /
        // user(ok).
        assert_eq!(h.len(), 5);
        assert_eq!(assistant_text(&h[1]), "");
        assert_eq!(
            assistant_calls(&h[1])
                .iter()
                .map(|c| c.id.as_str())
                .collect::<Vec<_>>(),
            vec!["tc-1"]
        );
        assert_eq!(tool_result_body(&h[2]), "A");
        assert_eq!(assistant_text(&h[3]), "now editing");
        assert_eq!(
            assistant_calls(&h[3])
                .iter()
                .map(|c| c.id.as_str())
                .collect::<Vec<_>>(),
            vec!["tc-2"]
        );
        assert_eq!(tool_result_body(&h[4]), "ok");
        validate_pairing(&h).expect("provider-valid");
    }

    #[tokio::test]
    async fn trailing_inference_request_emits_no_spurious_turn() {
        // A trailing inference boundary that never produced text or calls (the
        // session ended, or the next inference failed before recording any
        // content) must not emit a spurious empty assistant turn.
        let s = root_session();
        record_user(&s, "go").await;
        record_inference_request(&s, "infer-1").await;
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "a.rs" }),
            json!({ "path": "a.rs" }),
            "A",
        )
        .await;
        record_inference_request(&s, "infer-2").await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        // user / assistant(tc-1) / user(A) — the trailing boundary adds nothing.
        assert_eq!(h.len(), 3);
        assert_eq!(
            assistant_calls(&h[1])
                .iter()
                .map(|c| c.id.as_str())
                .collect::<Vec<_>>(),
            vec!["tc-1"]
        );
        assert_eq!(tool_result_body(&h[2]), "A");
        validate_pairing(&h).expect("provider-valid");
    }

    #[tokio::test]
    async fn rehydrates_historical_task_sibling_wire_input_without_rewriting() {
        let s = root_session();
        record_user(&s, "delegate").await;
        record_assistant(&s, "infer-1", "spawning").await;
        record_tool(
            &s,
            "task-legacy",
            "task",
            json!({
                "intent": "delegate",
                "delegate": { "agent": "builder", "prompt": "old shape" }
            }),
            json!({
                "intent": "delegate",
                "delegate": { "agent": "builder", "prompt": "old shape" }
            }),
            "done",
        )
        .await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        let calls = assistant_calls(&h[1]);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "task");
        assert_eq!(
            calls[0].function.arguments,
            json!({
                "intent": "delegate",
                "delegate": { "agent": "builder", "prompt": "old shape" }
            })
        );
        assert!(calls[0].function.arguments.get("payload").is_none());
        assert_eq!(tool_result_body(&h[2]), "done");
        validate_pairing(&h).expect("provider-valid");
    }

    #[tokio::test]
    async fn rehydrated_tool_turn_preserves_provider_call_identity() {
        let s = root_session();
        record_user(&s, "read the file").await;
        record_assistant(&s, "infer-1", "let me read it").await;
        record_tool_with_identity(
            &s,
            "cockpit-internal",
            crate::session::ToolCallProviderIdentity {
                provider_item_id: Some("provider-item".into()),
                provider_call_id: Some("provider-call".into()),
                provider_call_id_source: Some("provider".into()),
                wire_api: Some("responses".into()),
                provider_family: Some("codex".into()),
            },
        )
        .await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        let calls = assistant_calls(&h[1]);
        assert_eq!(calls.len(), 1);
        // Rig 0.42 keeps Cockpit's durable correlation id separate from the
        // provider identity: `id` is the internal call id, while `provider`
        // retains both the item and function-call handles.
        assert_eq!(calls[0].id, "cockpit-internal");
        assert_eq!(
            calls[0]
                .provider
                .as_ref()
                .and_then(|provider| provider.item_id.as_deref()),
            Some("provider-item")
        );
        assert_eq!(
            calls[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("provider-call")
        );
        let results = tool_results(&h[2]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].call, "cockpit-internal");
        assert_eq!(
            results[0]
                .provider
                .as_ref()
                .and_then(|provider| provider.item_id.as_deref()),
            Some("provider-item")
        );
        assert_eq!(
            results[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("provider-call")
        );
    }

    #[tokio::test]
    async fn strict_responses_rehydrate_accepts_identified_tool_pair() {
        let s = root_session();
        record_user(&s, "read the file").await;
        record_assistant(&s, "infer-1", "let me read it").await;
        record_tool_with_identity(
            &s,
            "cockpit-internal",
            crate::session::ToolCallProviderIdentity {
                provider_item_id: Some("provider-item".into()),
                provider_call_id: Some("provider-call".into()),
                provider_call_id_source: Some("provider".into()),
                wire_api: Some("responses".into()),
                provider_family: Some("codex".into()),
            },
        )
        .await;

        let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .await
            .unwrap()
            .unwrap();
        let calls = assistant_calls(&r.history[1]);
        assert_eq!(
            calls[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("provider-call")
        );
    }

    #[tokio::test]
    async fn strict_responses_rehydrate_requires_provider_call_identity() {
        let s = root_session();
        record_user(&s, "read the file").await;
        record_assistant(&s, "infer-1", "let me read it").await;
        record_tool(
            &s,
            "call-without-provider-id",
            "read",
            json!({ "path": "/f" }),
            json!({ "path": "/f" }),
            "body",
        )
        .await;

        let err = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .await
            .unwrap_err();
        let repair = err
            .downcast_ref::<RehydrateRepairRequired>()
            .expect("strict Responses failure is structured");
        assert_eq!(repair.failure_kind, "missing_provider_call_id");
        assert_eq!(
            repair.failing_tool_call_ids,
            vec!["call-without-provider-id"]
        );
    }

    #[tokio::test]
    async fn strict_responses_rehydrate_accepts_synthetic_skill_slash_identity() {
        let s = root_session();
        record_user(&s, "/skill test-skill").await;
        let call_id = "skillslash-synthetic";
        let identity = crate::session::ToolCallProviderIdentity::synthetic_cockpit_call(
            call_id,
            Some(crate::config::providers::WireApi::Responses),
        );
        s.record_tool_call(ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".into(),
            call_id: call_id.into(),
            parent_call_id: None,
            parent_child_index: None,
            identity: identity.clone(),
            tool: "skill".into(),
            path: None,
            mcp_server: None,
            original_input_json: json!({ "name": "test-skill" }),
            wire_input_json: json!({ "name": "test-skill" }),
            recovery: Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            output: "Skill body".into(),
            truncated: false,
            duration_ms: 1,
            shape_fingerprint: None,
            hint: None,
        })
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some(call_id),
            &json!({
                "tool": "skill",
                "original_input": { "name": "test-skill" },
                "wire_input": { "name": "test-skill" },
                "output": "Skill body",
                "skill_slash": true,
                "provider_identity": {
                    "provider_item_id": identity.provider_item_id,
                    "provider_call_id": identity.provider_call_id,
                    "provider_call_id_source": identity.provider_call_id_source,
                    "wire_api": identity.wire_api,
                    "provider_family": identity.provider_family,
                },
            }),
        )
        .await
        .unwrap();

        let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .await
            .unwrap()
            .unwrap();
        // Skill-slash rebuilds the seed pair before the retained user
        // envelope, so the assistant is at index 0 and the result at 1.
        let calls = assistant_calls(&r.history[0]);
        assert_eq!(calls[0].id, call_id);
        assert_eq!(
            calls[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some(call_id)
        );
        let results = tool_results(&r.history[1]);
        assert_eq!(results[0].call, call_id);
        assert_eq!(
            results[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some(call_id)
        );
    }

    #[tokio::test]
    async fn strict_responses_rehydrate_accepts_synthetic_seed_identity() {
        let s = root_session();
        record_user(&s, "delegate with seed").await;
        record_assistant(&s, "infer-1", "reading seed").await;
        let call_id = "seed-synthetic";
        let identity = crate::session::ToolCallProviderIdentity::synthetic_cockpit_call(
            call_id,
            Some(crate::config::providers::WireApi::Responses),
        );
        s.record_tool_call(ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".into(),
            call_id: call_id.into(),
            parent_call_id: None,
            parent_child_index: None,
            identity: identity.clone(),
            tool: "read".into(),
            path: Some("seed.txt".into()),
            mcp_server: None,
            original_input_json: json!({ "path": "seed.txt" }),
            wire_input_json: json!({ "path": "seed.txt" }),
            recovery: Recovery::Clean,
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            output: "seed body".into(),
            truncated: false,
            duration_ms: 1,
            shape_fingerprint: None,
            hint: None,
        })
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some(call_id),
            &json!({
                "tool": "read",
                "original_input": { "path": "seed.txt" },
                "wire_input": { "path": "seed.txt" },
                "output": "seed body",
                "seed": true,
                "provider_identity": {
                    "provider_item_id": identity.provider_item_id,
                    "provider_call_id": identity.provider_call_id,
                    "provider_call_id_source": identity.provider_call_id_source,
                    "wire_api": identity.wire_api,
                    "provider_family": identity.provider_family,
                },
            }),
        )
        .await
        .unwrap();

        let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .await
            .unwrap()
            .unwrap();
        let calls = assistant_calls(&r.history[1]);
        assert_eq!(calls[0].id, call_id);
        assert_eq!(
            calls[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some(call_id)
        );
        let results = tool_results(&r.history[2]);
        assert_eq!(results[0].call, call_id);
        assert_eq!(
            results[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some(call_id)
        );
    }

    #[tokio::test]
    async fn responses_fc_prefix_rehydrate_accepts_old_and_new_prefixes() {
        for call_id in [
            "skillslash-persisted",
            "fc-skillslash-fresh",
            "seed-persisted",
            "fc-seed-fresh",
        ] {
            let s = root_session();
            record_user(&s, "synthetic tool context").await;
            let is_skill = call_id.contains("skillslash");
            if !is_skill {
                record_assistant(&s, "infer-1", "reading seed").await;
            }
            let tool = if is_skill { "skill" } else { "read" };
            let identity = crate::session::ToolCallProviderIdentity::synthetic_cockpit_call(
                call_id,
                Some(crate::config::providers::WireApi::Responses),
            );
            s.record_tool_call(ToolCallRow {
                event_id: Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                agent: "Build".into(),
                call_id: call_id.into(),
                parent_call_id: None,
                parent_child_index: None,
                identity: identity.clone(),
                tool: tool.into(),
                path: (!is_skill).then(|| "seed.txt".into()),
                mcp_server: None,
                original_input_json: if is_skill {
                    json!({ "name": "test-skill" })
                } else {
                    json!({ "path": "seed.txt" })
                },
                wire_input_json: if is_skill {
                    json!({ "name": "test-skill" })
                } else {
                    json!({ "path": "seed.txt" })
                },
                recovery: Recovery::Clean,
                hard_fail: false,
                exit_code: None,
                sandbox_enabled: false,
                sandboxed: false,
                sandbox_unavailable_reason: None,
                output: if is_skill {
                    "Skill body".into()
                } else {
                    "seed body".into()
                },
                truncated: false,
                duration_ms: 1,
                shape_fingerprint: None,
                hint: None,
            })
            .await
            .unwrap();
            s.record_event(
                crate::db::session_log::SessionEventKind::ToolCall,
                Some("Build"),
                Some(call_id),
                &json!({
                    "tool": tool,
                    "original_input": if is_skill {
                        json!({ "name": "test-skill" })
                    } else {
                        json!({ "path": "seed.txt" })
                    },
                    "wire_input": if is_skill {
                        json!({ "name": "test-skill" })
                    } else {
                        json!({ "path": "seed.txt" })
                    },
                    "output": if is_skill { "Skill body" } else { "seed body" },
                    "skill_slash": is_skill,
                    "seed": !is_skill,
                    "provider_identity": {
                        "provider_item_id": identity.provider_item_id,
                        "provider_call_id": identity.provider_call_id,
                        "provider_call_id_source": identity.provider_call_id_source,
                        "wire_api": identity.wire_api,
                        "provider_family": identity.provider_family,
                    },
                }),
            )
            .await
            .unwrap();

            let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
                .await
                .unwrap()
                .unwrap();
            // Skill-slash events rebuild the seed pair (assistant call +
            // result) before the retained user envelope, so the assistant
            // is at index 0 and the result at index 1. Non-skill events
            // keep the user message first, so the assistant is at index 1
            // and the result at index 2.
            let (assistant_idx, results_idx) = if is_skill { (0, 1) } else { (1, 2) };
            let calls = assistant_calls(&r.history[assistant_idx]);
            assert_eq!(calls[0].id, call_id);
            assert_eq!(
                calls[0]
                    .provider
                    .as_ref()
                    .map(|provider| provider.call_id.as_str()),
                Some(call_id)
            );
            let results = tool_results(&r.history[results_idx]);
            assert_eq!(results[0].call, call_id);
            assert_eq!(
                results[0]
                    .provider
                    .as_ref()
                    .map(|provider| provider.call_id.as_str()),
                Some(call_id)
            );
        }
    }

    /// A `task` delegation rebuilds as a `task` tool_use paired with the
    /// subagent report as its result.
    #[tokio::test]
    async fn rebuilds_task_delegation_with_report() {
        let s = root_session();
        record_user(&s, "investigate").await;
        record_assistant(&s, "infer-1", "delegating").await;
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-1"),
            &json!({ "child_agent": "explore", "task_call_id": "task-1", "prompt": "look around" }),
        )
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some("explore"),
            Some("task-1"),
            &json!({ "report": "found three modules" }),
        )
        .await
        .unwrap();
        record_assistant(&s, "infer-2", "thanks").await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        let calls = assistant_calls(&h[1]);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "task");
        assert_eq!(calls[0].id, "task-1");
        assert_eq!(
            calls[0].function.arguments,
            json!({
                "intent": "delegate",
                "payload": { "agent": "explore", "prompt": "look around" }
            })
        );
        assert_eq!(tool_result_body(&h[2]), "found three modules");
        validate_pairing(&h).expect("provider-valid");
    }

    #[tokio::test]
    async fn routing_amend_event_does_not_break_task_pairing() {
        let s = root_session();
        record_user(&s, "investigate").await;
        record_assistant(&s, "infer-1", "delegating").await;
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-1"),
            &json!({
                "child_agent": "explore",
                "task_call_id": "task-1",
                "label": "default",
                "prompt": "look around"
            }),
        )
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentRouting,
            Some("explore"),
            Some("task-1"),
            &json!({
                "child_agent": "explore",
                "task_call_id": "task-1",
                "label": "default",
                "provider": "lmstudio",
                "model": "child-model",
                "model_trusted": true,
                "routing": { "resolved_model": "child-model" }
            }),
        )
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some("explore"),
            Some("task-1"),
            &json!({ "report": "found three modules" }),
        )
        .await
        .unwrap();
        record_assistant(&s, "infer-2", "thanks").await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        let calls = assistant_calls(&h[1]);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "task");
        assert_eq!(calls[0].id, "task-1");
        let results = tool_results(&h[2]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].call, "task-1");
        assert_eq!(tool_result_body(&h[2]), "found three modules");
        validate_pairing(&h).expect("provider-valid");
    }

    #[tokio::test]
    async fn strict_responses_rehydrate_preserves_dual_task_provider_identity() {
        let s = root_session();
        record_user(&s, "investigate").await;
        record_assistant(&s, "infer-1", "delegating").await;
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-1"),
            &json!({
                "child_agent": "explore",
                "task_call_id": "task-1",
                "provider_item_id": "fc_task_1",
                "provider_call_id": "call_task_1",
                "provider_call_id_source": "provider",
                "provider_identity": {
                    "cockpit_call_id": "task-1",
                    "provider_item_id": "fc_task_1",
                    "provider_call_id": "call_task_1",
                    "provider_call_id_source": "provider",
                    "wire_api": "responses"
                },
                "prompt": "look around"
            }),
        )
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some("explore"),
            Some("task-1"),
            &json!({
                "report": "found three modules",
                "provider_item_id": "fc_task_1",
                "provider_call_id": "call_task_1",
                "provider_call_id_source": "provider",
                "provider_identity": {
                    "cockpit_call_id": "task-1",
                    "provider_item_id": "fc_task_1",
                    "provider_call_id": "call_task_1",
                    "provider_call_id_source": "provider",
                    "wire_api": "responses"
                }
            }),
        )
        .await
        .unwrap();

        let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .await
            .unwrap()
            .unwrap();
        let calls = assistant_calls(&r.history[1]);
        assert_eq!(calls[0].id, "task-1");
        assert_eq!(
            calls[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("call_task_1")
        );
        assert_eq!(
            calls[0]
                .provider
                .as_ref()
                .and_then(|provider| provider.item_id.as_deref()),
            Some("fc_task_1")
        );
        let payload = &calls[0].function.arguments["payload"];
        assert!(
            payload.get("provider_call_id").is_none(),
            "provider identity must not leak into replayed task args"
        );
        assert!(payload.get("provider_item_id").is_none());
        assert!(payload.get("provider_call_id_source").is_none());
        assert!(payload.get("provider_identity").is_none());
        let results = tool_results(&r.history[2]);
        assert_eq!(results[0].call, "task-1");
        assert_eq!(
            results[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("call_task_1")
        );
        assert_eq!(
            results[0]
                .provider
                .as_ref()
                .and_then(|provider| provider.item_id.as_deref()),
            Some("fc_task_1")
        );
    }

    #[tokio::test]
    async fn strict_responses_rehydrate_accepts_synthetic_task_provider_call_identity() {
        let s = root_session();
        record_user(&s, "investigate").await;
        record_assistant(&s, "infer-1", "delegating").await;
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-synthetic"),
            &json!({
                "child_agent": "explore",
                "task_call_id": "task-synthetic",
                "provider_call_id": "task-synthetic",
                "provider_call_id_source": "synthetic_from_cockpit_call_id",
                "provider_identity": {
                    "cockpit_call_id": "task-synthetic",
                    "provider_call_id": "task-synthetic",
                    "provider_call_id_source": "synthetic_from_cockpit_call_id",
                    "wire_api": "responses"
                },
                "prompt": "look around"
            }),
        )
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some("explore"),
            Some("task-synthetic"),
            &json!({
                "report": "found three modules",
                "provider_call_id": "task-synthetic",
                "provider_call_id_source": "synthetic_from_cockpit_call_id",
                "provider_identity": {
                    "cockpit_call_id": "task-synthetic",
                    "provider_call_id": "task-synthetic",
                    "provider_call_id_source": "synthetic_from_cockpit_call_id",
                    "wire_api": "responses"
                }
            }),
        )
        .await
        .unwrap();

        let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .await
            .unwrap()
            .unwrap();
        let calls = assistant_calls(&r.history[1]);
        assert_eq!(calls[0].id, "task-synthetic");
        assert_eq!(
            calls[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("task-synthetic")
        );
        let payload = &calls[0].function.arguments["payload"];
        assert!(payload.get("provider_call_id").is_none());
        assert!(payload.get("provider_call_id_source").is_none());
        assert!(payload.get("provider_identity").is_none());
        let results = tool_results(&r.history[2]);
        assert_eq!(results[0].call, "task-synthetic");
        assert_eq!(
            results[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("task-synthetic")
        );
    }

    #[tokio::test]
    async fn strict_responses_rehydrate_preserves_interactive_task_provider_call_identity() {
        let s = root_session();
        record_user(&s, "investigate").await;
        record_assistant(&s, "infer-1", "delegating").await;
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-interactive"),
            &json!({
                "child_agent": "explore",
                "task_call_id": "task-interactive",
                "provider_call_id": "call-provider-interactive",
                "provider_call_id_source": "provider",
                "provider_identity": {
                    "cockpit_call_id": "task-interactive",
                    "provider_call_id": "call-provider-interactive",
                    "provider_call_id_source": "provider",
                    "wire_api": "responses"
                },
                "label": "default",
                "noninteractive": false,
                "prompt": "look around"
            }),
        )
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some("explore"),
            Some("task-interactive"),
            &json!({
                "child_agent": "explore",
                "task_call_id": "task-interactive",
                "label": "default",
                "report": "found three modules",
                "provider_call_id": "call-provider-interactive",
                "provider_call_id_source": "provider",
                "provider_identity": {
                    "cockpit_call_id": "task-interactive",
                    "provider_call_id": "call-provider-interactive",
                    "provider_call_id_source": "provider",
                    "wire_api": "responses"
                }
            }),
        )
        .await
        .unwrap();

        let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .await
            .unwrap()
            .unwrap();
        let calls = assistant_calls(&r.history[1]);
        assert_eq!(calls[0].id, "task-interactive");
        assert_eq!(
            calls[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("call-provider-interactive")
        );
        let payload = &calls[0].function.arguments["payload"];
        assert!(payload.get("noninteractive").is_none());
        assert!(payload.get("provider_call_id").is_none());
        assert!(payload.get("provider_call_id_source").is_none());
        assert!(payload.get("provider_identity").is_none());
        let results = tool_results(&r.history[2]);
        assert_eq!(results[0].call, "task-interactive");
        assert_eq!(
            results[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("call-provider-interactive")
        );
    }

    #[tokio::test]
    async fn strict_responses_rehydrate_backfills_legacy_completed_task_identity() {
        let s = root_session();
        record_user(&s, "investigate").await;
        record_assistant(&s, "infer-1", "delegating").await;
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-legacy"),
            &json!({ "child_agent": "explore", "task_call_id": "task-legacy", "prompt": "look" }),
        )
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some("explore"),
            Some("task-legacy"),
            &json!({ "report": "done" }),
        )
        .await
        .unwrap();

        let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .await
            .unwrap()
            .unwrap();
        let calls = assistant_calls(&r.history[1]);
        assert_eq!(
            calls[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("task-legacy")
        );
        let results = tool_results(&r.history[2]);
        assert_eq!(
            results[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("task-legacy")
        );
    }

    #[tokio::test]
    async fn strict_responses_rehydrate_rejects_mismatched_task_report_identity() {
        let s = root_session();
        record_user(&s, "investigate").await;
        record_assistant(&s, "infer-1", "delegating").await;
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-1"),
            &json!({
                "child_agent": "explore",
                "task_call_id": "task-1",
                "provider_call_id": "call-provider-task",
                "prompt": "look around"
            }),
        )
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some("explore"),
            Some("task-1"),
            &json!({
                "report": "found three modules",
                "provider_call_id": "different-provider-call"
            }),
        )
        .await
        .unwrap();

        let err = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .await
            .unwrap_err();
        let repair = err
            .downcast_ref::<RehydrateRepairRequired>()
            .expect("strict Responses failure is structured");
        assert_eq!(repair.failure_kind, "mismatched_pair");
        assert_eq!(repair.failing_tool_call_ids, vec!["task-1"]);
    }

    #[tokio::test]
    async fn rehydrate_prunes_completed_long_task_prompt() {
        let s = root_session();
        record_user(&s, "investigate").await;
        record_assistant(&s, "infer-1", "delegating").await;
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-1"),
            &json!({
                "child_agent": "explore",
                "task_call_id": "task-1",
                "prompt": long_delegation_prompt(),
                "model": "slow",
            }),
        )
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some("explore"),
            Some("task-1"),
            &json!({ "report": "found three modules" }),
        )
        .await
        .unwrap();

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        let calls = assistant_calls(&h[1]);
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].function.arguments["payload"]["prompt"],
            json!("[pruned after subagent returned; see paired tool_result task-1]")
        );
        assert_eq!(calls[0].function.arguments["intent"], json!("delegate"));
        assert_eq!(
            calls[0].function.arguments["payload"]["agent"],
            json!("explore")
        );
        assert_eq!(
            calls[0].function.arguments["payload"]["model"],
            json!("slow")
        );
        assert_eq!(tool_result_body(&h[2]), "found three modules");
        validate_pairing(&h).expect("provider-valid");
    }

    #[tokio::test]
    async fn rebuilds_parallel_independent_task_calls_as_one_assistant_turn() {
        let s = root_session();
        record_user(&s, "investigate auth and db").await;
        record_assistant(&s, "infer-1", "delegating both").await;
        for (call_id, child, prompt, report) in [
            ("task-auth", "explore", "inspect auth", "auth report"),
            ("task-db", "explore", "inspect db", "db report"),
        ] {
            s.record_event(
                crate::db::session_log::SessionEventKind::SubagentSpawned,
                Some("Build"),
                Some(call_id),
                &json!({ "child_agent": child, "task_call_id": call_id, "prompt": prompt }),
            )
            .await
            .unwrap();
            s.record_event(
                crate::db::session_log::SessionEventKind::SubagentReport,
                Some(child),
                Some(call_id),
                &json!({ "child_agent": child, "task_call_id": call_id, "report": report }),
            )
            .await
            .unwrap();
        }
        record_assistant(&s, "infer-2", "thanks").await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        assert_eq!(h.len(), 5);
        let calls = assistant_calls(&h[1]);
        assert_eq!(
            calls.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            vec!["task-auth", "task-db"]
        );
        assert!(calls.iter().all(|c| c.function.name == "task"));
        assert_eq!(tool_result_body(&h[2]), "auth report");
        assert_eq!(tool_result_body(&h[3]), "db report");
        assert_eq!(assistant_text(&h[4]), "thanks");
        validate_pairing(&h).expect("provider-valid");
    }

    #[tokio::test]
    async fn rebuilds_parallel_task_delegation_with_aggregate_report() {
        let s = root_session();
        record_user(&s, "investigate auth and db").await;
        record_assistant(&s, "infer-1", "delegating").await;
        for (label, prompt) in [("auth", "inspect auth"), ("db", "inspect db")] {
            s.record_event(
                crate::db::session_log::SessionEventKind::SubagentSpawned,
                Some("Build"),
                Some("task-1"),
                &json!({
                    "child_agent": "explore",
                    "task_call_id": "task-1",
                    "provider_call_id": "call-provider-batch",
                    "provider_call_id_source": "provider",
                    "provider_identity": {
                        "cockpit_call_id": "task-1",
                        "provider_call_id": "call-provider-batch",
                        "provider_call_id_source": "provider",
                        "wire_api": "responses"
                    },
                    "label": label,
                    "prompt": prompt,
                    "why": "compare both areas",
                }),
            )
            .await
            .unwrap();
        }
        for (label, report) in [("auth", "auth report"), ("db", "db report")] {
            s.record_event(
                crate::db::session_log::SessionEventKind::SubagentReport,
                Some("explore"),
                Some("task-1"),
                &json!({
                    "child_agent": "explore",
                    "task_call_id": "task-1",
                    "label": label,
                    "report": report,
                    "provider_call_id": "call-provider-batch",
                    "provider_call_id_source": "provider",
                    "provider_identity": {
                        "cockpit_call_id": "task-1",
                        "provider_call_id": "call-provider-batch",
                        "provider_call_id_source": "provider",
                        "wire_api": "responses"
                    },
                }),
            )
            .await
            .unwrap();
        }
        record_assistant(&s, "infer-2", "thanks").await;

        let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        let calls = assistant_calls(&h[1]);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "task");
        assert_eq!(
            calls[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("call-provider-batch")
        );
        assert_eq!(
            calls[0].function.arguments,
            json!({
                "intent": "batch",
                "why": "compare both areas",
                "payload": [
                    { "label": "auth", "agent": "explore", "prompt": "inspect auth" },
                    { "label": "db", "agent": "explore", "prompt": "inspect db" },
                ]
            })
        );
        let body: serde_json::Value = serde_json::from_str(&tool_result_body(&h[2])).unwrap();
        assert_eq!(
            body,
            json!({
                "status": "completed",
                "children": [
                    { "label": "auth", "agent": "explore", "failed": false, "report": "auth report" },
                    { "label": "db", "agent": "explore", "failed": false, "report": "db report" },
                ]
            })
        );
        let results = tool_results(&h[2]);
        assert_eq!(
            results[0]
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str()),
            Some("call-provider-batch")
        );
        validate_pairing(&h).expect("provider-valid");
    }

    /// Subagent (non-root) turns are excluded from the root model history.
    #[tokio::test]
    async fn excludes_subagent_turns() {
        let s = root_session();
        record_user(&s, "go").await;
        record_assistant(&s, "infer-1", "root says hi").await;
        // An explore subagent's own assistant turn — must not leak in.
        s.record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("explore"),
            Some("infer-x"),
            &json!({ "text": "subagent internal reasoning" }),
        )
        .await
        .unwrap();

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        assert_eq!(h.len(), 2);
        assert_eq!(assistant_text(&h[1]), "root says hi");
    }

    /// CRITICAL INVARIANT (implementation note): a `user_note`
    /// session event (`/note <text>`) is NEVER reconstructed into the
    /// model-bound history. It sits chronologically between two real turns yet
    /// rehydration skips it entirely — the rebuilt context is byte-identical to
    /// one with no note at all, so prior note text never reaches the model.
    #[tokio::test]
    async fn rehydration_skips_user_note_events() {
        let s = root_session();
        record_user(&s, "first").await;
        record_assistant(&s, "infer-1", "ok").await;
        // A user note recorded mid-conversation (between turns).
        s.record_event(
            crate::db::session_log::SessionEventKind::UserNote,
            Some("Build"),
            None,
            &json!({ "text": "remember: secret sk-NOTE-123 caused the bug" }),
        )
        .await
        .unwrap();
        record_user(&s, "second").await;
        record_assistant(&s, "infer-2", "done").await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        // Exactly the four real turns — the note contributes nothing.
        assert_eq!(h.len(), 4);
        assert_eq!(user_text(&h[0]), "first");
        assert_eq!(assistant_text(&h[1]), "ok");
        assert_eq!(user_text(&h[2]), "second");
        assert_eq!(assistant_text(&h[3]), "done");
        // The note text never appears anywhere in the model-bound history.
        for m in &h {
            let rendered = format!("{m:?}");
            assert!(
                !rendered.contains("sk-NOTE-123"),
                "note text must never enter model-bound history"
            );
        }
    }

    /// Empty session → nothing to rehydrate.
    #[tokio::test]
    async fn empty_session_rehydrates_to_none() {
        let s = root_session();
        assert!(
            rehydrate_session(&s.db, s.id, "Build")
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The ledger re-applies, yielding byte-identical pruned bodies: the
    /// elided tool-result body becomes the exact marker.
    #[tokio::test]
    async fn ledger_reapply_yields_byte_identical_pruned_form() {
        let s = root_session();
        record_user(&s, "read twice").await;
        record_assistant(&s, "infer-1", "").await;
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "/f" }),
            json!({ "path": "/f" }),
            "FIRST BODY",
        )
        .await;
        record_assistant(&s, "infer-2", "").await;
        record_tool(
            &s,
            "tc-2",
            "read",
            json!({ "path": "/f" }),
            json!({ "path": "/f" }),
            "SECOND BODY",
        )
        .await;

        // Persist a ledger that elides the older read (tc-1).
        let ledger = PruneLedger {
            elided: vec![LedgerEntry {
                original_event_id: "tc-1".into(),
                reason: "snapshot superseded".into(),
                partial_body: None,
            }],
            watermark: 4,
        };
        s.db.save_prune_ledger(s.id, &ledger).await.unwrap();

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        assert!(!r.ledger_fallback);
        assert_eq!(r.watermark, 4);
        // tc-1's body is the exact marker; tc-2's body is intact.
        let expected_marker = Elision {
            original_event_id: "tc-1".into(),
            reason: "snapshot superseded",
        }
        .marker_text();
        assert_eq!(tool_result_body(&r.history[2]), expected_marker);
        assert_eq!(tool_result_body(&r.history[4]), "SECOND BODY");
    }

    /// A ledger referencing an id that isn't in the rebuilt history is
    /// inconsistent → fall back to the FULL UNPRUNED form + flag, never a
    /// fresh context.
    #[tokio::test]
    async fn bad_ledger_falls_back_to_full_unpruned() {
        let s = root_session();
        record_user(&s, "read once").await;
        record_assistant(&s, "infer-1", "").await;
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "/f" }),
            json!({ "path": "/f" }),
            "ONLY BODY",
        )
        .await;

        // Ledger points at a non-existent id.
        let ledger = PruneLedger {
            elided: vec![LedgerEntry {
                original_event_id: "ghost".into(),
                reason: "snapshot superseded".into(),
                partial_body: None,
            }],
            watermark: 9,
        };
        s.db.save_prune_ledger(s.id, &ledger).await.unwrap();

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        assert!(r.ledger_fallback, "inconsistent ledger → fallback");
        assert_eq!(r.watermark, 0, "fallback resets the watermark");
        // Body is the full original — NOT a marker, NOT dropped.
        assert_eq!(tool_result_body(&r.history[2]), "ONLY BODY");
    }

    /// A `tool_call` timeline event with no matching audit row (its result
    /// body never landed durably) is HEALED with an honest aborted stub —
    /// the prior conversation rebuilds instead of dead-ending, and the heal
    /// is surfaced as a `Recovery::ResumeHeal` audit record.
    #[tokio::test]
    async fn missing_tool_call_row_is_stubbed_not_an_error() {
        let s = root_session();
        record_user(&s, "go").await;
        record_assistant(&s, "infer-1", "calling a tool").await;
        // A tool_call timeline event WITHOUT the audit row.
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some("orphan"),
            &json!({ "tool": "read", "wire_input": { "path": "/f" }, "output": "x" }),
        )
        .await
        .unwrap();

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        // The stubbed call is paired with an honest aborted result.
        validate_pairing(&r.history).expect("healed history is provider-valid");
        let calls = assistant_calls(&r.history[1]);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "orphan");
        assert_eq!(calls[0].function.name, "read");
        let results = tool_results(&r.history[2]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].call, calls[0].id);
        assert_eq!(results[0].provider, calls[0].provider);
        assert_eq!(results[0].name, calls[0].function.name);
        assert_eq!(tool_result_body(&r.history[2]), ABORTED_CALL_BODY);
        assert_eq!(
            r.heals,
            vec![Recovery::ResumeHeal {
                kind: "stub_orphan_tool_call",
                id: "orphan".into(),
            }]
        );
    }

    /// Redaction is NOT applied during rehydration: the transcript is
    /// stored pre-redaction and `redact::scrub()` runs on the outbound
    /// prompt at send time exactly as for a live history — never stored
    /// redacted, never double-applied. The rebuilt bodies must be verbatim.
    #[tokio::test]
    async fn rehydration_does_not_redact() {
        let s = root_session();
        record_user(&s, "my token is sk-SECRET-123").await;
        record_assistant(&s, "infer-1", "noted: sk-SECRET-123").await;
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "/f" }),
            json!({ "path": "/f" }),
            "file contains sk-SECRET-123",
        )
        .await;
        record_assistant(&s, "infer-2", "").await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let h = r.history;
        // Verbatim — no scrub applied (the send path scrubs, as today).
        assert_eq!(user_text(&h[0]), "my token is sk-SECRET-123");
        assert_eq!(assistant_text(&h[1]), "noted: sk-SECRET-123");
        assert_eq!(tool_result_body(&h[2]), "file contains sk-SECRET-123");
    }

    /// A `/compact` successor that has ALREADY had turns rebuilds from its
    /// transcript (rehydration returns `Some`).
    #[tokio::test]
    async fn successor_with_turns_rebuilds_from_transcript() {
        let s = root_session();
        record_user(&s, "continue from compact").await;
        record_assistant(&s, "infer-1", "carrying on").await;
        let r = rehydrate_session(&s.db, s.id, "Build").await.unwrap();
        assert!(
            r.is_some(),
            "a successor with turns rebuilds from transcript"
        );
        // A fresh successor with NO recorded turns rehydrates to None.
        let fresh = root_session();
        assert!(
            rehydrate_session(&fresh.db, fresh.id, "Build")
                .await
                .unwrap()
                .is_none()
        );
    }

    /// No ledger at all → the rebuilt full form IS the pruned form (no
    /// fallback flag, watermark 0).
    #[tokio::test]
    async fn no_ledger_rebuilds_full_form() {
        let s = root_session();
        record_user(&s, "hi").await;
        record_assistant(&s, "infer-1", "hello").await;
        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        assert!(!r.ledger_fallback);
        assert_eq!(r.watermark, 0);
        assert_eq!(r.history.len(), 2);
    }

    // ---- heal-then-validate (implementation note) ---

    /// Build an assistant message issuing the given tool-call ids.
    fn assistant_with_calls(ids: &[&str]) -> Message {
        let calls: Vec<AssistantContent> = ids
            .iter()
            .map(|id| {
                AssistantContent::ToolCall(ToolCall {
                    id: ToolCallId::new_or_mint((*id).to_string()),
                    provider: None,
                    function: ToolFunction {
                        name: "read".into(),
                        arguments: json!({ "path": "/f" }),
                    },
                    signature: None,
                    additional_params: None,
                })
            })
            .collect();
        Message::Assistant {
            id: None,
            content: calls,
        }
    }

    /// One tool_result user message (the live wire shape).
    fn result_msg(id: &str, body: &str) -> Message {
        let call = ToolCall {
            id: ToolCallId::new_or_mint(id.to_string()),
            provider: None,
            function: ToolFunction {
                name: "read".to_string(),
                arguments: serde_json::Value::Null,
            },
            signature: None,
            additional_params: None,
        };
        stub_result_message(&call, body)
    }

    /// A `task` delegation whose `subagent_report` never landed is HEALED
    /// with an honest "delegation did not complete" stub instead of erroring.
    #[tokio::test]
    async fn missing_subagent_report_is_stubbed_not_an_error() {
        let s = root_session();
        record_user(&s, "investigate").await;
        record_assistant(&s, "infer-1", "delegating").await;
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-1"),
            &json!({ "child_agent": "explore", "task_call_id": "task-1", "prompt": "look" }),
        )
        .await
        .unwrap();
        // No SubagentReport recorded.
        record_assistant(&s, "infer-2", "continuing without it").await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        validate_pairing(&r.history).expect("healed history is provider-valid");
        let calls = assistant_calls(&r.history[1]);
        assert_eq!(calls[0].function.name, "task");
        assert_eq!(calls[0].id, "task-1");
        assert_eq!(tool_result_body(&r.history[2]), MISSING_REPORT_BODY);
        assert_eq!(
            r.heals,
            vec![Recovery::ResumeHeal {
                kind: "stub_missing_subagent_report",
                id: "task-1".into(),
            }]
        );
    }

    /// An orphan tool_use (assistant tool-call with no following result) is
    /// stubbed with an honest aborted result; the healed history validates.
    #[tokio::test]
    async fn heal_stubs_orphan_tool_use() {
        let provider = ProviderCallId::new("fn-orphan-1".to_string())
            .expect("provider call id")
            .with_item_id("fc-orphan-1".to_string());
        let call = ToolCall {
            id: ToolCallId::for_provider(Some(&provider)),
            provider: Some(provider),
            function: ToolFunction {
                name: "read".to_string(),
                arguments: json!({ "path": "/f" }),
            },
            signature: None,
            additional_params: None,
        };
        let mut history = vec![
            Message::user("go"),
            Message::Assistant {
                id: None,
                content: vec![AssistantContent::ToolCall(call.clone())],
            },
            // No tool_result follows c1.
            Message::user("next"),
        ];
        let mut heals = Vec::new();
        heal_pairing(&mut history, &mut heals);
        validate_pairing(&history).expect("provider-valid after heal");
        // A stub result was inserted right after the assistant turn.
        assert_eq!(tool_result_body(&history[2]), ABORTED_CALL_BODY);
        let results = tool_results(&history[2]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].call, call.id);
        assert_eq!(results[0].provider, call.provider);
        assert_eq!(results[0].name, call.function.name);
        assert_eq!(
            heals,
            vec![Recovery::ResumeHeal {
                kind: "stub_orphan_tool_call",
                id: call.id.to_string(),
            }]
        );
    }

    /// An orphan tool_result (no preceding tool_use of its id) is dropped;
    /// the healed history validates and the heal is recorded.
    #[tokio::test]
    async fn heal_drops_orphan_tool_result() {
        let mut history = vec![
            Message::user("go"),
            // A bare tool_result with no preceding assistant tool_use.
            result_msg("ghost", "stale body"),
            Message::user("after"),
        ];
        let mut heals = Vec::new();
        heal_pairing(&mut history, &mut heals);
        validate_pairing(&history).expect("provider-valid after heal");
        // The orphan result message was removed entirely.
        assert_eq!(history.len(), 2);
        assert_eq!(user_text(&history[0]), "go");
        assert_eq!(user_text(&history[1]), "after");
        assert_eq!(
            heals,
            vec![Recovery::ResumeHeal {
                kind: "drop_orphan_tool_result",
                id: "ghost".into(),
            }]
        );
    }

    /// Dropping an orphan result must not disturb a sibling paired result in
    /// the same user message (multiple results defensively handled).
    #[tokio::test]
    async fn heal_drops_only_the_orphan_sibling_result() {
        // Assistant issues c1 only; a user message carries BOTH c1 (paired)
        // and ghost (orphan) results.
        let mixed = Message::User {
            content: vec![
                UserContent::ToolResult(ToolResult {
                    call: ToolCallId::new_or_mint("c1".to_string()),
                    provider: None,
                    name: "read".to_string(),
                    content: vec![ToolResultContent::text("real")],
                }),
                UserContent::ToolResult(ToolResult {
                    call: ToolCallId::new_or_mint("ghost".to_string()),
                    provider: None,
                    name: "read".to_string(),
                    content: vec![ToolResultContent::text("stale")],
                }),
            ],
        };
        let mut history = vec![Message::user("go"), assistant_with_calls(&["c1"]), mixed];
        let mut heals = Vec::new();
        heal_pairing(&mut history, &mut heals);
        validate_pairing(&history).expect("provider-valid after heal");
        // The paired sibling survives; only the orphan was dropped.
        assert_eq!(result_ids(&history[2]), vec!["c1".to_string()]);
        assert_eq!(
            heals,
            vec![Recovery::ResumeHeal {
                kind: "drop_orphan_tool_result",
                id: "ghost".into(),
            }]
        );
    }

    /// Multiple mixed orphans in one transcript heal in a single pass and the
    /// result passes `validate_pairing`.
    #[tokio::test]
    async fn heal_handles_mixed_orphans_in_one_pass() {
        let mut history = vec![
            Message::user("start"),
            // Orphan result with no preceding call.
            result_msg("ghost", "stale"),
            // Orphan tool_use with no following result.
            assistant_with_calls(&["c1"]),
            Message::user("middle"),
            // Properly paired turn — must remain untouched.
            assistant_with_calls(&["c2"]),
            result_msg("c2", "ok"),
        ];
        let mut heals = Vec::new();
        heal_pairing(&mut history, &mut heals);
        validate_pairing(&history).expect("provider-valid after heal");
        // Both an orphan-drop and an orphan-stub fired; the paired c2 turn
        // produced no heal.
        assert_eq!(heals.len(), 2);
        assert!(heals.contains(&Recovery::ResumeHeal {
            kind: "drop_orphan_tool_result",
            id: "ghost".into(),
        }));
        assert!(heals.contains(&Recovery::ResumeHeal {
            kind: "stub_orphan_tool_call",
            id: "c1".into(),
        }));
    }

    /// Idempotence: healing an already-healed history is a no-op (no edits,
    /// no new heals).
    #[tokio::test]
    async fn heal_is_idempotent() {
        let mut history = vec![
            Message::user("start"),
            result_msg("ghost", "stale"),
            assistant_with_calls(&["c1"]),
            Message::user("middle"),
        ];
        let mut first = Vec::new();
        heal_pairing(&mut history, &mut first);
        assert!(!first.is_empty(), "first pass heals");
        let after_first = history.clone();

        let mut second = Vec::new();
        heal_pairing(&mut history, &mut second);
        assert!(second.is_empty(), "second pass is a no-op");
        assert_eq!(history, after_first, "heal(heal(x)) == heal(x)");
    }

    // ---- live pre-send heal (implementation note) ----

    /// Regression: a turn where the model emitted a structural tool followed by
    /// a sibling (`[task, read]`) leaves the trailing `read` tool_use orphaned
    /// in `history` (the structural `task` returns early from the dispatch
    /// loop). The live pre-send heal stubs `read` with an honest aborted
    /// result and — crucially — does NOT double-stub `task`, whose own result
    /// is carried by the not-yet-pushed `prompt`. The send sequence
    /// (history + prompt) is provider-valid.
    /// AC2 (issue #57): `scheduler_cancellation_preserves_pairing_on_resume`
    /// proves that with the capability-aware turn scheduler, started calls
    /// settle/cancel once, barriers receive deterministic paired outcomes, and
    /// neither live nor resume healing emits `ABORTED_CALL_BODY` for a
    /// scheduler-owned call.
    ///
    /// The scheduler dispatches every sibling call before returning a
    /// structural outcome. So a history where both `read` and `task` were
    /// dispatched (both have results) heals nothing — no orphan, no stub.
    /// Even when only the `read` result landed (the `task` result rides the
    /// prompt), the heal stubs `read` with the updated body (which says the
    /// call was in progress, not "interrupted before resume" as the old
    /// `ABORTED_CALL_BODY` did).
    #[tokio::test]
    async fn scheduler_cancellation_preserves_pairing_on_resume() {
        // Case 1: both calls dispatched and settled — heal is a no-op.
        // The scheduler dispatched `read` before returning the `task`
        // structural outcome, so both have results in history.
        let mut history_paired = vec![
            Message::user("do X"),
            assistant_with_calls(&["task", "read"]),
            result_msg("read", "file contents"),
        ];
        let prompt_paired = result_msg("task", "delegation result");
        let heals_paired = heal_live_history(&mut history_paired, &prompt_paired);
        assert!(
            heals_paired.is_empty(),
            "scheduler-dispatched calls with results heal nothing"
        );

        // Case 2: only `read` was dispatched and settled; `task` result rides
        // the prompt (the structural outcome was returned after the read
        // settled). The heal should NOT stub `read` (it has a result), and
        // should NOT stub `task` (its result rides the prompt).
        let mut history_read_settled = vec![
            Message::user("do X"),
            assistant_with_calls(&["task", "read"]),
            result_msg("read", "file contents"),
        ];
        let prompt_task = result_msg("task", "delegation result");
        let heals_read = heal_live_history(&mut history_read_settled, &prompt_task);
        assert!(
            heals_read.is_empty(),
            "both calls are paired (read has a result, task rides the prompt) — no heal needed"
        );

        // Case 3: the scheduler dispatched `read` but it was interrupted before
        // its result settled (crash edge case). `task` result rides the prompt.
        // The heal stubs `read` with the updated body that says the call was
        // "in progress when the session was interrupted" — NOT the old
        // "interrupted before resume" wording. `task` is NOT double-stubbed.
        let mut history_interrupted = vec![
            Message::user("do X"),
            assistant_with_calls(&["task", "read"]),
        ];
        let prompt_interrupted = result_msg("task", "delegation result");

        // BEFORE the heal: the send sequence is NOT provider-valid (the
        // sibling `read` tool_use has no matching tool_result anywhere).
        let mut unhealed = history_interrupted.clone();
        unhealed.push(prompt_interrupted.clone());
        assert!(
            validate_pairing(&unhealed).is_err(),
            "without the heal the orphan sibling read makes the send malformed"
        );

        let heals = heal_live_history(&mut history_interrupted, &prompt_interrupted);

        // Exactly one heal: the interrupted `read` was stubbed; `task` was
        // NOT (its result rides the prompt).
        assert_eq!(
            heals,
            vec![Recovery::ResumeHeal {
                kind: "stub_orphan_tool_call",
                id: "read".into(),
            }],
            "only the interrupted read is stubbed; the structural task is not double-stubbed"
        );

        // The stub body says the call was "in progress when the session was
        // interrupted" — the scheduler-owned contract, not the old
        // "interrupted before resume" wording.
        assert_eq!(history_interrupted.len(), 3);
        assert_eq!(
            tool_result_body(&history_interrupted[2]),
            crate::engine::agent::turn_scheduler::SCHEDULER_INTERRUPTED_BODY
        );
        assert_eq!(
            result_ids(&history_interrupted[2]),
            vec!["read".to_string()]
        );
        assert!(
            !tool_result_body(&history_interrupted[2]).contains("before resume"),
            "scheduler-owned call must not use the old 'before resume' wording"
        );

        // The full wire send sequence (history + prompt) is provider-valid.
        let mut wire = history_interrupted.clone();
        wire.push(prompt_interrupted);
        validate_pairing(&wire).expect("history + prompt is provider-valid");

        // Persist/resume: a scheduler-owned call with a public tool_call event
        // but no audit row must pair with SCHEDULER_INTERRUPTED_BODY. Live
        // `heal_live_history` always stubs with that body, so it cannot fail a
        // resume path that still assigned ABORTED_CALL_BODY at rebuild.
        let session = root_session();
        record_user(&session, "inspect both").await;
        record_assistant(&session, "infer-1", "").await;
        let turn_id = uuid::Uuid::new_v4();
        session
            .db
            .persist_turn_scheduler_plan(
                session.id,
                turn_id,
                "Build".to_string(),
                vec![
                    crate::db::turn_scheduler_continuations::TurnSchedulerContinuationInput {
                        source_index: 0,
                        call_id: "read-crash".to_string(),
                        provider_item_id: Some("fc-read".to_string()),
                        provider_call_id: Some("fn-read".to_string()),
                        resolved_tool: "read".to_string(),
                        wire_input: json!({ "path": "README.md" }),
                        classification: "parallel_lane".to_string(),
                    },
                    crate::db::turn_scheduler_continuations::TurnSchedulerContinuationInput {
                        source_index: 1,
                        call_id: "task-crash".to_string(),
                        provider_item_id: Some("fc-task".to_string()),
                        provider_call_id: Some("fn-task".to_string()),
                        resolved_tool: "task".to_string(),
                        wire_input: json!({
                            "intent": "delegate",
                            "payload": { "agent": "explore", "prompt": "inspect" }
                        }),
                        classification: "deferred_delegate".to_string(),
                    },
                ],
                1,
            )
            .await
            .unwrap();
        session
            .record_event(
                crate::db::session_log::SessionEventKind::ToolCall,
                Some("Build"),
                Some("read-crash"),
                &json!({ "tool": "read", "wire_input": { "path": "README.md" } }),
            )
            .await
            .unwrap();

        let restored = rehydrate_session(&session.db, session.id, "Build")
            .await
            .unwrap()
            .expect("scheduler-owned interrupted calls rebuild a turn");
        let bodies = restored
            .history
            .iter()
            .flat_map(|message| match message {
                Message::User { content } => content
                    .iter()
                    .filter_map(|content| match content {
                        UserContent::ToolResult(result) => Some(
                            result
                                .content
                                .iter()
                                .filter_map(|part| match part {
                                    ToolResultContent::Text(text) => Some(text.text.as_str()),
                                    _ => None,
                                })
                                .collect::<String>(),
                        ),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            })
            .collect::<Vec<_>>();
        assert_eq!(bodies.len(), 2);
        assert!(
            bodies.iter().all(|body| *body != ABORTED_CALL_BODY),
            "resume must not assign ABORTED_CALL_BODY to a scheduler-owned call: {bodies:?}"
        );
        assert_eq!(
            bodies,
            vec![
                crate::engine::agent::turn_scheduler::SCHEDULER_INTERRUPTED_BODY,
                crate::engine::agent::turn_scheduler::SCHEDULER_INTERRUPTED_BODY,
            ]
        );
        validate_pairing(&restored.history)
            .expect("resumed scheduler-owned history is provider-valid");
    }

    /// A private continuation rebuilds calls that crashed after scheduling but
    /// before any public tool/subagent row. A terminal canonical body wins for
    /// the settled source, while only the genuinely unstarted source receives
    /// the scheduler interruption body; neither falls through to the generic
    /// aborted-call healer.
    #[tokio::test]
    async fn scheduler_private_continuation_recovers_terminal_and_unstarted_source_calls() {
        let session = root_session();
        record_user(&session, "inspect both").await;
        let turn_id = uuid::Uuid::new_v4();
        session
            .db
            .persist_turn_scheduler_plan(
                session.id,
                turn_id,
                "Build".to_string(),
                vec![
                    crate::db::turn_scheduler_continuations::TurnSchedulerContinuationInput {
                        source_index: 0,
                        call_id: "read-crash".to_string(),
                        provider_item_id: Some("fc-read".to_string()),
                        provider_call_id: Some("fn-read".to_string()),
                        resolved_tool: "read".to_string(),
                        wire_input: json!({ "path": "README.md" }),
                        classification: "parallel_lane".to_string(),
                    },
                    crate::db::turn_scheduler_continuations::TurnSchedulerContinuationInput {
                        source_index: 1,
                        call_id: "task-crash".to_string(),
                        provider_item_id: Some("fc-task".to_string()),
                        provider_call_id: Some("fn-task".to_string()),
                        resolved_tool: "task".to_string(),
                        wire_input: json!({
                            "intent": "delegate",
                            "payload": { "agent": "explore", "prompt": "inspect" }
                        }),
                        classification: "deferred_delegate".to_string(),
                    },
                ],
                1,
            )
            .await
            .unwrap();
        session
            .db
            .settle_turn_scheduler_call(
                session.id,
                turn_id,
                "read-crash".to_string(),
                "refused".to_string(),
                "Error: the scheduler refused this read request.".to_string(),
                2,
            )
            .await
            .unwrap();

        let restored = rehydrate_session(&session.db, session.id, "Build")
            .await
            .unwrap()
            .expect("private continuation is a recorded turn");
        let calls = restored
            .history
            .iter()
            .find_map(|message| match message {
                Message::Assistant { .. } => {
                    let calls = assistant_calls(message);
                    (!calls.is_empty()).then_some(calls)
                }
                _ => None,
            })
            .expect("recovered assistant calls");
        assert_eq!(
            calls
                .iter()
                .map(|call| call.id.to_string())
                .collect::<Vec<_>>(),
            vec!["read-crash", "task-crash"]
        );
        assert_eq!(calls[0].function.arguments, json!({ "path": "README.md" }));
        assert_eq!(calls[1].function.arguments["payload"]["agent"], "explore");
        let bodies = restored
            .history
            .iter()
            .flat_map(|message| match message {
                Message::User { content } => content
                    .iter()
                    .filter_map(|content| match content {
                        UserContent::ToolResult(result) => Some(
                            result
                                .content
                                .iter()
                                .filter_map(|part| match part {
                                    ToolResultContent::Text(text) => Some(text.text.as_str()),
                                    _ => None,
                                })
                                .collect::<String>(),
                        ),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            })
            .collect::<Vec<_>>();
        assert_eq!(bodies.len(), 2);
        assert_eq!(
            bodies,
            vec![
                "Error: the scheduler refused this read request.",
                crate::engine::agent::turn_scheduler::SCHEDULER_INTERRUPTED_BODY,
            ],
            "only the genuinely unsettled source call receives the scheduler interruption body"
        );
        assert!(bodies.iter().all(|body| *body != ABORTED_CALL_BODY));
        validate_pairing(&restored.history).unwrap();
    }

    #[test]
    fn scheduler_partial_crash_materialization_keeps_source_order() {
        let turn_id = uuid::Uuid::new_v4();
        let call = |id: &str| ToolCall {
            id: ToolCallId::new_or_mint(id.to_string()),
            provider: None,
            function: ToolFunction {
                name: "read".to_string(),
                arguments: json!({ "path": id }),
            },
            signature: None,
            additional_params: None,
        };
        let mut pending = PendingTurn::default();
        // A crash can expose the later private continuation before replay
        // encounters the earlier call's public settled row.
        for (id, source_index, body) in [("later", 1, "interrupted"), ("earlier", 0, "ok")] {
            let call = call(id);
            pending.calls.push(call.clone());
            pending.results.push((
                call.id,
                None,
                "read".to_string(),
                vec![ToolResultContent::text(body.to_string())],
            ));
            pending
                .scheduler_source_order
                .insert(id.to_string(), (turn_id, source_index));
        }

        let mut history = Vec::new();
        pending.flush(&mut history);
        assert_eq!(
            assistant_calls(&history[0])
                .iter()
                .map(|call| call.id.to_string())
                .collect::<Vec<_>>(),
            vec!["earlier", "later"]
        );
        assert_eq!(result_ids(&history[1]), vec!["earlier"]);
        assert_eq!(result_ids(&history[2]), vec!["later"]);
        assert_eq!(tool_result_body(&history[1]), "ok");
        assert_eq!(tool_result_body(&history[2]), "interrupted");
        validate_pairing(&history).expect("source-ordered materialization remains provider-valid");
    }

    /// The live heal is a no-op (byte-identical, no heals) on an already-paired
    /// turn — the overwhelmingly common path, run every turn.
    #[tokio::test]
    async fn live_heal_is_a_noop_on_paired_history() {
        let history = vec![
            Message::user("read it"),
            assistant_with_calls(&["c1"]),
            result_msg("c1", "ok"),
        ];
        // A plain user prompt (no tool results) is the next turn's input.
        let prompt = Message::user("now what");

        let mut subject = history.clone();
        let before_ptr = tool_result_text_ptr(&subject[2]);
        let heals = heal_live_history(&mut subject, &prompt);
        assert!(heals.is_empty(), "paired history heals nothing");
        assert_eq!(subject, history, "no-op: byte-identical before/after");
        assert_eq!(
            tool_result_text_ptr(&subject[2]),
            before_ptr,
            "clean path must not clone or replace paired tool-result content"
        );
    }

    /// The live heal is idempotent across turns: after it stubs the sibling,
    /// the next turn (with the structural result now pushed into history) heals
    /// nothing — no double-stub, no drift.
    #[tokio::test]
    async fn live_heal_is_idempotent_across_turns() {
        let mut history = vec![
            Message::user("do X"),
            assistant_with_calls(&["task", "read"]),
        ];
        let structural_result = result_msg("task", "delegation result");

        // Turn N+1: heal the orphan sibling, then the driver pushes the
        // structural result into history (as the live path does at send-1).
        let first = heal_live_history(&mut history, &structural_result);
        assert_eq!(first.len(), 1);
        history.push(structural_result);

        // Turn N+2: a fresh user prompt; nothing left to heal.
        let prompt = Message::user("continue");
        let before = history.clone();
        let second = heal_live_history(&mut history, &prompt);
        assert!(second.is_empty(), "no new heals on the following turn");
        assert_eq!(history, before, "no drift, no double-stub");
        validate_pairing(&history).expect("provider-valid");
    }

    /// A transcript with an orphan tool_use, an orphan tool_result, AND a
    /// `task` delegation missing its report resumes successfully end-to-end:
    /// validates, preserves prior context, and records one heal per orphan.
    #[tokio::test]
    async fn mixed_orphans_resume_successfully_end_to_end() {
        let s = root_session();
        record_user(&s, "do work").await;
        record_assistant(&s, "infer-1", "calling read").await;
        // Orphan tool-call: timeline event, no audit row → stubbed.
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some("orphan-call"),
            &json!({ "tool": "read", "wire_input": { "path": "/f" }, "output": "" }),
        )
        .await
        .unwrap();
        record_assistant(&s, "infer-2", "delegating").await;
        // Task delegation with no report → stubbed.
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-1"),
            &json!({ "child_agent": "explore", "task_call_id": "task-1", "prompt": "p" }),
        )
        .await
        .unwrap();
        record_assistant(&s, "infer-3", "wrapping up").await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        validate_pairing(&r.history).expect("healed history is provider-valid");
        // Prior user context preserved.
        assert_eq!(user_text(&r.history[0]), "do work");
        // Two rebuild-time stubs fired.
        let kinds: Vec<&str> = r
            .heals
            .iter()
            .map(|h| match h {
                Recovery::ResumeHeal { kind, .. } => *kind,
                _ => panic!("expected ResumeHeal"),
            })
            .collect();
        assert!(kinds.contains(&"stub_orphan_tool_call"));
        assert!(kinds.contains(&"stub_missing_subagent_report"));
    }

    /// Clean-history no-op: a well-formed transcript rehydrates with NO heals
    /// (and thus no resume Notice) — the common path stays silent.
    #[tokio::test]
    async fn clean_transcript_produces_no_heals() {
        let s = root_session();
        record_user(&s, "read the file").await;
        record_assistant(&s, "infer-1", "reading").await;
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "/f" }),
            json!({ "path": "/f" }),
            "body",
        )
        .await;
        record_assistant(&s, "infer-2", "done").await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        assert!(r.heals.is_empty(), "clean transcript heals nothing");
        validate_pairing(&r.history).expect("clean transcript is already valid");
    }

    // ---- COMPOSED rehydrate pipeline (order + idempotence) ---------------
    // Pins the end-to-end contract of the rehydrate history pipeline
    // (implementation note): rebuild → heal →
    // validate. Per-stage idempotence is already covered above
    // (`heal_is_idempotent`); these assert the COMPOSED behavior: the full
    // `rehydrate_session` cycle is stable, heal precedes validate, and a
    // post-heal validate failure stays a hard error.

    /// Composed idempotence on the heal stage of an already-rebuilt history:
    /// a transcript that required healing yields a history that, fed through
    /// the heal pass AGAIN, is unchanged (`heal(heal(x)) == heal(x)`) and still
    /// passes `validate_pairing`. Drives the rebuilt history straight off
    /// `rehydrate_session`, so it composes the real rebuild output.
    #[tokio::test]
    async fn composed_heal_then_validate_is_idempotent_on_rebuilt_history() {
        let s = root_session();
        record_user(&s, "go").await;
        record_assistant(&s, "infer-1", "calling a tool").await;
        // Orphan tool-call: timeline event, no audit row → healed at rebuild.
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some("orphan"),
            &json!({ "tool": "read", "wire_input": { "path": "/f" }, "output": "x" }),
        )
        .await
        .unwrap();
        record_assistant(&s, "infer-2", "done").await;

        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        assert!(!r.heals.is_empty(), "the transcript required healing");
        let healed = r.history.clone();
        validate_pairing(&healed).expect("rebuilt+healed history is provider-valid");

        // Re-running the heal pass on the already-healed history is a no-op.
        let mut again = healed.clone();
        let mut second_heals = Vec::new();
        heal_pairing(&mut again, &mut second_heals);
        assert!(second_heals.is_empty(), "second heal pass adds no heals");
        assert_eq!(again, healed, "heal(heal(x)) == heal(x)");
        validate_pairing(&again).expect("still provider-valid");
    }

    /// Stability across a resume cycle: rehydrate → (persist is already the
    /// durable transcript) → rehydrate AGAIN produces the same healed history
    /// with the same heal records — the orphans were stubbed/dropped in the
    /// rebuilt history, never written back, so the second rehydrate re-derives
    /// an identical result (no drift, no double-stub).
    #[tokio::test]
    async fn composed_resume_cycle_is_stable() {
        let s = root_session();
        record_user(&s, "do work").await;
        record_assistant(&s, "infer-1", "calling read").await;
        // Orphan tool-call (no audit row) → stubbed at rebuild.
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some("orphan-call"),
            &json!({ "tool": "read", "wire_input": { "path": "/f" }, "output": "" }),
        )
        .await
        .unwrap();
        record_assistant(&s, "infer-2", "delegating").await;
        // Task delegation with no report → stubbed at rebuild.
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-1"),
            &json!({ "child_agent": "explore", "task_call_id": "task-1", "prompt": "p" }),
        )
        .await
        .unwrap();
        record_assistant(&s, "infer-3", "wrapping up").await;

        let first = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        let second = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        // Same healed history and the same heal records on the second resume.
        assert_eq!(first.history, second.history, "resume cycle is stable");
        assert_eq!(first.heals, second.heals, "no new ResumeHeal records");
        validate_pairing(&second.history).expect("provider-valid on re-resume");
    }

    /// Order dependency: heal runs BEFORE validate, so a transcript with
    /// orphans rehydrates successfully (Ok) instead of hard-erroring. Proven by
    /// contrast: the rebuilt-but-UNhealed history would FAIL `validate_pairing`,
    /// yet `rehydrate_session` (heal-then-validate) returns Ok.
    #[tokio::test]
    async fn composed_heal_precedes_validate_so_orphans_resume() {
        let s = root_session();
        record_user(&s, "go").await;
        record_assistant(&s, "infer-1", "calling a tool").await;
        // Orphan tool-call with no audit row → an orphan tool_use at rebuild.
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some("orphan"),
            &json!({ "tool": "read", "wire_input": { "path": "/f" }, "output": "x" }),
        )
        .await
        .unwrap();

        // The rebuilt-but-unhealed history would not pass validation: rebuild
        // alone leaves the orphan stub already paired (the rebuild stubs a
        // missing audit row), so to exhibit the order dependency we construct
        // an explicitly unpaired history and confirm validate rejects it…
        let unhealed = vec![Message::user("go"), assistant_with_calls(&["c1"])];
        assert!(
            validate_pairing(&unhealed).is_err(),
            "an unhealed orphan tool_use must FAIL validation"
        );

        // …while the full pipeline (heal-then-validate) resumes the real
        // orphaned transcript successfully.
        let r = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap();
        validate_pairing(&r.history).expect("heal ran before validate → Ok");
        assert!(!r.heals.is_empty());
    }

    /// Genuine-bug guard (must never fire normally): a post-heal
    /// `validate_pairing` failure remains a HARD ERROR. We feed an explicitly
    /// unpairable history straight to the validator (bypassing heal) to pin
    /// that the final assertion is real and not weakened to a warning.
    #[tokio::test]
    async fn composed_post_heal_validate_failure_is_a_hard_error() {
        // An assistant tool_use with no matching tool_result anywhere — the
        // shape heal is designed to prevent, so if it ever reaches validate
        // unhealed, validate must hard-error.
        let unpaired = vec![Message::user("go"), assistant_with_calls(&["c1"])];
        let err = validate_pairing(&unpaired).expect_err("must be a hard error");
        assert!(err.to_string().contains("unpaired tool_use"), "got: {err}");
    }

    // ---- wire history snapshot (implementation note) -----

    #[tokio::test]
    async fn rehydrate_user_message_prefers_display_text() {
        let s = root_session();
        s.record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &json!({
                "text": "<file path=\"src/lib.rs\">expanded</file>",
                "display_text": "review @src/lib.rs",
                "tag_expansions": [{
                    "tool": "read",
                    "path": "src/lib.rs",
                    "detail": "142 lines",
                    "ok": true
                }]
            }),
        )
        .await
        .unwrap();

        let snapshot = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        match &snapshot[0] {
            proto::HistoryEntry::User {
                text,
                display_text,
                tag_expansions,
                ..
            } => {
                assert!(text.starts_with("<file"));
                assert_eq!(display_text.as_deref(), Some("review @src/lib.rs"));
                assert_eq!(tag_expansions.len(), 1);
                assert_eq!(tag_expansions[0].path, "src/lib.rs");
            }
            other => panic!("expected user history entry, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rehydrate_user_message_legacy_text_fallback() {
        let s = root_session();
        record_user(&s, "legacy wire text").await;

        let snapshot = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        match &snapshot[0] {
            proto::HistoryEntry::User {
                text,
                display_text,
                tag_expansions,
                ..
            } => {
                assert_eq!(text, "legacy wire text");
                assert!(display_text.is_none());
                assert!(tag_expansions.is_empty());
            }
            other => panic!("expected user history entry, got {other:?}"),
        }
    }

    /// REGRESSION: the daemon attach snapshot must carry ALL THREE entry kinds
    /// (user message → assistant message → tool call) in chronological order —
    /// not just the tool call (the old `list_tool_calls_for_session`-only path
    /// dropped every message). The seq order is the same one model rehydration
    /// uses, so the two never drift.
    #[tokio::test]
    async fn history_snapshot_includes_messages_and_tool_calls_in_order() {
        let s = root_session();
        record_user(&s, "read the file").await;
        record_assistant(&s, "infer-1", "let me read it").await;
        record_tool(
            &s,
            "tc-1",
            "read",
            // Original carries a typo field the wire form drops (§14).
            json!({ "path": "src/main.rs", "typo": true }),
            json!({ "path": "src/main.rs" }),
            "fn main() {}",
        )
        .await;

        let snap = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        assert_eq!(snap.len(), 3, "all three kinds present, none dropped");

        match &snap[0] {
            proto::HistoryEntry::User { text, seq, .. } => {
                assert_eq!(text, "read the file");
                assert!(*seq > 0, "user row carries its ordering seq");
            }
            other => panic!("snap[0] should be User, got {other:?}"),
        }
        match &snap[1] {
            proto::HistoryEntry::Assistant {
                agent, text, seq, ..
            } => {
                assert_eq!(agent, "Build");
                assert_eq!(text, "let me read it");
                assert!(*seq > 0);
            }
            other => panic!("snap[1] should be Assistant, got {other:?}"),
        }
        match &snap[2] {
            proto::HistoryEntry::ToolCall {
                tool,
                original_input,
                wire_input,
                output,
                ..
            } => {
                assert_eq!(tool, "read");
                // Wire-vs-user split survives into the snapshot (§14): the user
                // side keeps the typo, the model side is the canonical wire form.
                assert_eq!(
                    original_input,
                    &json!({ "path": "src/main.rs", "typo": true })
                );
                assert_eq!(wire_input, &json!({ "path": "src/main.rs" }));
                assert_eq!(output, "fn main() {}");
            }
            other => panic!("snap[2] should be ToolCall, got {other:?}"),
        }

        // The two message rows carry strictly increasing seqs — the same
        // chronological order rehydration walks — and the tool call (no seq in
        // the wire shape) lands after them by position.
        let (u, a) = (msg_seq(&snap[0]), msg_seq(&snap[1]));
        assert!(u < a, "user precedes assistant in seq order: {u} < {a}");
    }

    #[tokio::test]
    async fn btw_events_absent_from_parent_history() {
        let parent = root_session();
        record_user(&parent, "parent before btw").await;
        let btw = parent
            .db
            .create_btw_fork(parent.id, true)
            .await
            .expect("btw fork");
        let btw_session = Session::resume_for_test(
            parent.db.clone(),
            btw.info.session_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .expect("btw session");
        record_user(&btw_session, "btw-only prompt").await;
        record_assistant(&btw_session, "btw-call", "btw-only answer").await;

        let parent_snapshot = history_snapshot(&parent.db, parent.id, "Build")
            .await
            .unwrap();
        assert_eq!(parent_snapshot.len(), 1);
        assert!(
            matches!(&parent_snapshot[0], proto::HistoryEntry::User { text, .. } if text == "parent before btw")
        );

        let btw_snapshot = history_snapshot(&parent.db, btw.info.session_id, "Build")
            .await
            .unwrap();
        assert!(
            btw_snapshot.iter().any(
                |entry| matches!(entry, proto::HistoryEntry::User { text, .. } if text == "btw-only prompt")
            ),
            "btw fork retains its own history"
        );
    }

    #[tokio::test]
    async fn history_snapshot_conn_matches_db_wrapper_byte_for_byte() {
        let s = root_session();
        record_user(&s, "read the file").await;
        record_assistant(&s, "infer-1", "let me read it").await;
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "src/main.rs", "typo": true }),
            json!({ "path": "src/main.rs" }),
            "fn main() {}",
        )
        .await;

        let wrapped = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        let session_id = s.id;
        let direct =
            s.db.read(move |conn| history_snapshot_conn(conn, session_id, "Build"))
                .await
                .unwrap();

        assert_eq!(
            serde_json::to_value(&direct).unwrap(),
            serde_json::to_value(&wrapped).unwrap()
        );
    }

    #[tokio::test]
    async fn db_async_rehydrate_full_history_read_uses_async_api() {
        let s = root_session();
        record_user(&s, "inspect src/main.rs").await;
        record_assistant(&s, "infer-1", "reading it").await;
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({"path": "src/main.rs"}),
            json!({"path": "src/main.rs"}),
            "fn main() {}",
        )
        .await;

        let snapshot = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        assert_eq!(snapshot.len(), 3);
        assert!(matches!(
            &snapshot[0],
            proto::HistoryEntry::User { text, .. } if text == "inspect src/main.rs"
        ));
        assert!(matches!(
            &snapshot[1],
            proto::HistoryEntry::Assistant { text, .. } if text == "reading it"
        ));
        assert!(matches!(
            &snapshot[2],
            proto::HistoryEntry::ToolCall { call_id, output, .. }
                if call_id == "tc-1" && output == "fn main() {}"
        ));
    }

    #[tokio::test]
    async fn history_snapshot_since_replays_only_rows_after_cursor() {
        let s = root_session();
        record_user(&s, "already rendered").await;
        record_assistant(&s, "infer-1", "also rendered").await;
        let cursor =
            s.db.list_session_events(s.id)
                .await
                .unwrap()
                .into_iter()
                .map(|row| row.seq)
                .max()
                .unwrap();
        record_user(&s, "missed user").await;
        record_assistant(&s, "infer-2", "missed assistant").await;

        let session_id = s.id;
        let replay =
            s.db.read(move |conn| {
                history_snapshot_since_with_active_subagent_conn(
                    conn, session_id, "Build", None, cursor,
                )
            })
            .await
            .unwrap();

        assert_eq!(replay.len(), 2);
        match &replay[0] {
            proto::HistoryEntry::User { text, seq, .. } => {
                assert_eq!(text, "missed user");
                assert!(*seq > cursor);
            }
            other => panic!("expected replayed user entry, got {other:?}"),
        }
        match &replay[1] {
            proto::HistoryEntry::Assistant { text, seq, .. } => {
                assert_eq!(text, "missed assistant");
                assert!(*seq > cursor);
            }
            other => panic!("expected replayed assistant entry, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn history_page_before_returns_newest_entries_oldest_first() {
        let s = root_session();
        record_user(&s, "one").await;
        record_user(&s, "two").await;
        record_user(&s, "three").await;

        let session_id = s.id;
        let page =
            s.db.read(move |conn| history_page_before_conn(conn, session_id, "Build", None, 2))
                .await
                .unwrap();

        assert!(page.has_more);
        assert!(page.oldest_seq.is_some());
        assert_eq!(page.entries.len(), 2);
        assert!(
            matches!(&page.entries[0], proto::HistoryEntry::User { text, .. } if text == "two")
        );
        assert!(
            matches!(&page.entries[1], proto::HistoryEntry::User { text, .. } if text == "three")
        );
    }

    #[tokio::test]
    async fn history_page_before_walk_reconstructs_full_snapshot() {
        let s = root_session();
        record_user(&s, "one").await;
        record_assistant(&s, "infer-1", "two").await;
        record_user(&s, "three").await;
        record_assistant(&s, "infer-2", "four").await;
        record_user(&s, "five").await;

        let full = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        let mut cursor = None;
        let mut pages = Vec::new();
        let session_id = s.id;
        loop {
            let before_seq = cursor;
            let page =
                s.db.read(move |conn| {
                    history_page_before_conn(conn, session_id, "Build", before_seq, 2)
                })
                .await
                .unwrap();
            let has_more = page.has_more;
            cursor = page.oldest_seq;
            pages.push(page.entries);
            if !has_more {
                break;
            }
        }

        let mut walked = Vec::new();
        for page in pages.into_iter().rev() {
            walked.extend(page);
        }
        assert_eq!(
            serde_json::to_value(&walked).unwrap(),
            serde_json::to_value(&full).unwrap()
        );
    }

    #[tokio::test]
    async fn history_page_before_reports_has_more_until_first_entry() {
        let s = root_session();
        record_user(&s, "one").await;
        record_user(&s, "two").await;
        record_user(&s, "three").await;
        record_user(&s, "four").await;
        record_user(&s, "five").await;

        let session_id = s.id;
        let first =
            s.db.read(move |conn| history_page_before_conn(conn, session_id, "Build", None, 2))
                .await
                .unwrap();
        assert!(first.has_more);
        let second_before_seq = first.oldest_seq;
        let second =
            s.db.read(move |conn| {
                history_page_before_conn(conn, session_id, "Build", second_before_seq, 2)
            })
            .await
            .unwrap();
        assert!(second.has_more);
        let third_before_seq = second.oldest_seq;
        let third =
            s.db.read(move |conn| {
                history_page_before_conn(conn, session_id, "Build", third_before_seq, 2)
            })
            .await
            .unwrap();
        assert!(!third.has_more);
        assert_eq!(third.entries.len(), 1);
        assert!(
            matches!(&third.entries[0], proto::HistoryEntry::User { text, .. } if text == "one")
        );
    }

    #[tokio::test]
    async fn subagent_history_page_query_scopes_and_orders() {
        let s = root_session();
        let session_id = s.id;

        async fn record_subagent_user(
            s: &Session,
            task_call_id: &'static str,
            label: &'static str,
            text: &'static str,
        ) -> i64 {
            s.db.insert_session_event_with_context(
                s.id,
                crate::db::session_log::SessionEventKind::UserMessage,
                Some("Explore"),
                None,
                crate::db::session_log::SessionEventContext {
                    task_call_id: Some(task_call_id),
                    label: Some(label),
                    ..Default::default()
                },
                &json!({ "text": text }),
            )
            .await
            .unwrap()
        }

        let _a1 = record_subagent_user(&s, "task-a", "default", "a1").await;
        let _other_task = record_subagent_user(&s, "task-b", "default", "b1").await;
        let _other_label = record_subagent_user(&s, "task-a", "alternate", "alt1").await;
        let a2 = record_subagent_user(&s, "task-a", "default", "a2").await;
        let _a3 = record_subagent_user(&s, "task-a", "default", "a3").await;

        let first =
            s.db.read(move |conn| {
                subagent_history_page_before_conn(conn, session_id, "task-a", "default", None, 2)
            })
            .await
            .unwrap();
        assert!(first.has_more);
        assert_eq!(first.oldest_seq, Some(a2));
        assert_eq!(first.entries.len(), 2);
        assert!(
            matches!(&first.entries[0], proto::HistoryEntry::User { text, .. } if text == "a2")
        );
        assert!(
            matches!(&first.entries[1], proto::HistoryEntry::User { text, .. } if text == "a3")
        );

        let before_seq = first.oldest_seq;
        let second =
            s.db.read(move |conn| {
                subagent_history_page_before_conn(
                    conn, session_id, "task-a", "default", before_seq, 2,
                )
            })
            .await
            .unwrap();
        assert!(!second.has_more);
        assert_eq!(second.entries.len(), 1);
        assert!(
            matches!(&second.entries[0], proto::HistoryEntry::User { text, .. } if text == "a1")
        );
    }

    #[tokio::test]
    async fn history_page_before_empty_session_returns_empty_page() {
        let s = root_session();

        let session_id = s.id;
        let page =
            s.db.read(move |conn| history_page_before_conn(conn, session_id, "Build", None, 20))
                .await
                .unwrap();

        assert!(page.entries.is_empty());
        assert!(!page.has_more);
        assert_eq!(page.oldest_seq, None);
    }

    #[tokio::test]
    async fn history_page_before_carries_compact_boundary_brief() {
        let s = root_session();
        let handoff_id = Uuid::new_v4();
        s.db.store_compaction_payload(
            handoff_id,
            s.id,
            &json!({
                "predecessor_short_id": "abc123",
                "seed_tool_count": 2,
                "brief_text": "handoff summary",
            })
            .to_string(),
        )
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::SessionCompacted,
            Some("Build"),
            None,
            &json!({
                "handoff_ref": handoff_id.to_string(),
            }),
        )
        .await
        .unwrap();

        let full = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        let session_id = s.id;
        let page =
            s.db.read(move |conn| history_page_before_conn(conn, session_id, "Build", None, 1))
                .await
                .unwrap();

        assert_eq!(
            serde_json::to_value(&page.entries).unwrap(),
            serde_json::to_value(&full).unwrap()
        );
        assert!(matches!(
            &page.entries[..],
            [proto::HistoryEntry::CompactBoundary {
                brief: Some(brief),
                ..
            }] if brief == "handoff summary"
        ));
    }

    #[tokio::test]
    async fn attach_read_conn_shape_completes_without_relocking() {
        let s = root_session();
        record_user(&s, "go").await;
        record_assistant(&s, "infer-1", "done").await;
        let db = s.db.clone();
        let session_id = s.id;
        let cfg = crate::config::extended::ExtendedConfig::default();

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), async move {
            db.read(move |conn| {
                let root_agent =
                    crate::daemon::session_worker::resolve_root_agent_conn(conn, session_id, &cfg);
                let history = history_snapshot_conn(conn, session_id, &root_agent)?;
                let paused = Db::paused_session_work_conn(conn, session_id)?;
                let row = Db::get_session_conn(conn, session_id)?;
                Ok((history, paused, row))
            })
            .await
        })
        .await
        .expect("attach-read shape must not deadlock");

        let (history, paused, row) = result.unwrap();
        assert_eq!(history.len(), 2);
        assert!(paused.is_none());
        assert!(row.is_some());
    }

    #[tokio::test]
    async fn history_snapshot_carries_compact_boundary_brief_when_present() {
        let s = root_session();
        s.record_event(
            crate::db::session_log::SessionEventKind::SessionCompacted,
            Some("Build"),
            None,
            &json!({
                "predecessor_short_id": "abc123",
                "seed_tool_count": 2,
                "brief_text": "handoff summary",
            }),
        )
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::SessionCompacted,
            Some("Build"),
            None,
            &json!({
                "predecessor_short_id": "legacy",
                "seed_tool_count": 1,
            }),
        )
        .await
        .unwrap();

        let snap = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        assert_eq!(snap.len(), 2);
        match &snap[0] {
            proto::HistoryEntry::CompactBoundary {
                predecessor_short_id,
                seed_tool_count,
                brief,
                ..
            } => {
                assert_eq!(predecessor_short_id, "abc123");
                assert_eq!(*seed_tool_count, 2);
                assert_eq!(brief.as_deref(), Some("handoff summary"));
            }
            other => panic!("snap[0] should be CompactBoundary, got {other:?}"),
        }
        match &snap[1] {
            proto::HistoryEntry::CompactBoundary { brief, .. } => {
                assert!(brief.is_none(), "legacy compact events omit the chip");
            }
            other => panic!("snap[1] should be CompactBoundary, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn session_compacted_persists_handoff() {
        let s = root_session();
        let handoff = format!("## Decisions\n{}", "durable ".repeat(3_000));
        let tail = vec![
            Message::user(format!("recent {}", "tail ".repeat(1_000))),
            Message::assistant("recent answer"),
        ];
        s.record_session_compacted_with_source(
            "Build",
            crate::session::SessionCompactionRecord {
                successor_session_id: s.id,
                successor_short_id: &s.short_id(),
                seed_tool_count: 2,
                brief_text: &handoff,
                handoff_text: &handoff,
                source: "manual",
                trigger_ctx_pct: Some(62.0),
                tokens_before: 9_000,
                tokens_after: 3_000,
                turns_summarized: 5,
                tail_kept: 4,
                tail_trimmed: 1,
                tail_messages: &tail,
            },
            None,
        )
        .await
        .unwrap();
        let session_id = s.id;
        let raw_data: String = s
            .db
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT data_json FROM session_events WHERE session_id = ?1 AND type = 'session_compacted'",
                    [session_id.to_string()],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        let raw_data: serde_json::Value = serde_json::from_str(&raw_data).unwrap();
        assert!(raw_data["handoff_ref"].as_str().is_some());
        assert!(raw_data.get("brief_text").is_none());
        assert!(raw_data.get("tail_messages").is_none());
        assert!(raw_data.to_string().len() < 16 * 1024);
        assert_eq!(raw_data["tail_trimmed"], 1);

        let event =
            s.db.list_session_events(s.id)
                .await
                .unwrap()
                .into_iter()
                .find(|event| event.kind == "session_compacted")
                .unwrap();
        assert_eq!(event.data["handoff_text"], handoff);
        assert!(event.data["tail_messages"].is_array());

        let snapshot = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        match &snapshot[0] {
            proto::HistoryEntry::CompactBoundary {
                handoff: Some(restored),
                tokens_before,
                tokens_after,
                tail_kept,
                ..
            } => {
                assert_eq!(restored, &handoff);
                assert_eq!(
                    (*tokens_before, *tokens_after, *tail_kept),
                    (9_000, 3_000, 4)
                );
            }
            other => panic!("expected durable compaction entry, got {other:?}"),
        }

        let preview = s.db.read_session_messages(s.id, None, 10).await.unwrap().0;
        assert!(preview.iter().any(|message| message.text == handoff));
    }

    #[tokio::test]
    async fn compaction_payload_refs_are_session_scoped() {
        let owner = root_session();
        let other = root_session();
        let payload_id = Uuid::new_v4();
        let payload = json!({"handoff_text": "owner secret"}).to_string();
        owner
            .db
            .store_compaction_payload(payload_id, owner.id, &payload)
            .await
            .unwrap();

        assert_eq!(
            owner
                .db
                .compaction_payload(owner.id, &payload_id.to_string())
                .await
                .unwrap()
                .as_deref(),
            Some(payload.as_str())
        );
        assert!(
            owner
                .db
                .compaction_payload(other.id, &payload_id.to_string())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn compaction_entries_survive_replay() {
        let s = root_session();
        let seq = s
            .record_session_compacted_with_source(
                "Build",
                crate::session::SessionCompactionRecord {
                    successor_session_id: s.id,
                    successor_short_id: &s.short_id(),
                    seed_tool_count: 0,
                    brief_text: "brief",
                    handoff_text: "full handoff",
                    source: "auto",
                    trigger_ctx_pct: Some(60.0),
                    tokens_before: 600,
                    tokens_after: 100,
                    turns_summarized: 2,
                    tail_kept: 1,
                    tail_trimmed: 0,
                    tail_messages: &[],
                },
                None,
            )
            .await
            .unwrap();
        let session_id = s.id;
        let replay =
            s.db.read(move |conn| {
                history_snapshot_since_with_active_subagent_conn(
                    conn,
                    session_id,
                    "Build",
                    None,
                    seq - 1,
                )
            })
            .await
            .unwrap();
        assert!(matches!(
            &replay[..],
            [proto::HistoryEntry::CompactBoundary {
                source,
                handoff: Some(handoff),
                ..
            }] if source == "auto" && handoff == "full handoff"
        ));
    }

    #[tokio::test]
    async fn compacted_model_history_rehydrates_handoff_and_tail() {
        let s = root_session();
        let tail = vec![
            Message::user("recent user"),
            Message::assistant("recent answer"),
        ];
        s.record_session_compacted_with_source(
            "Build",
            crate::session::SessionCompactionRecord {
                successor_session_id: s.id,
                successor_short_id: &s.short_id(),
                seed_tool_count: 0,
                brief_text: "brief",
                handoff_text: "exact handoff",
                source: "manual",
                trigger_ctx_pct: None,
                tokens_before: 500,
                tokens_after: 100,
                turns_summarized: 3,
                tail_kept: 1,
                tail_trimmed: 0,
                tail_messages: &tail,
            },
            None,
        )
        .await
        .unwrap();
        let restored = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap()
            .history;
        assert_eq!(
            serde_json::to_value(restored).unwrap(),
            serde_json::to_value([vec![Message::user("exact handoff")], tail].concat()).unwrap()
        );
    }

    /// REGRESSION (#276): `/compact` resets in-place history but leaves
    /// pre-compaction `user_message` rows in the log. Rehydrate must skip
    /// those rows when applying text-artifact projections; otherwise the
    /// first historical user message hard-fails against the compacted handoff.
    #[tokio::test]
    async fn compacted_model_history_with_prior_turns_rehydrates() {
        let s = root_session();
        record_user(&s, "first question").await;
        record_assistant(&s, "a1", "first answer").await;
        record_user(&s, "second question").await;
        record_assistant(&s, "a2", "second answer").await;
        let tail = vec![
            Message::user("recent user"),
            Message::assistant("recent answer"),
        ];
        s.record_session_compacted_with_source(
            "Build",
            crate::session::SessionCompactionRecord {
                successor_session_id: s.id,
                successor_short_id: &s.short_id(),
                seed_tool_count: 0,
                brief_text: "brief",
                handoff_text: "exact handoff",
                source: "manual",
                trigger_ctx_pct: None,
                tokens_before: 500,
                tokens_after: 100,
                turns_summarized: 3,
                tail_kept: 1,
                tail_trimmed: 0,
                tail_messages: &tail,
            },
            None,
        )
        .await
        .unwrap();
        let restored = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap()
            .history;
        assert_eq!(
            serde_json::to_value(restored).unwrap(),
            serde_json::to_value([vec![Message::user("exact handoff")], tail].concat()).unwrap()
        );
    }

    /// Compact, continue the session, then resume: post-compaction user
    /// turns must still validate against history after the handoff/tail
    /// prefix, not against the compacted handoff itself.
    #[tokio::test]
    async fn compacted_model_history_with_prior_turns_then_followup_rehydrates() {
        let s = root_session();
        record_user(&s, "first question").await;
        record_assistant(&s, "a1", "first answer").await;
        let tail = vec![
            Message::user("recent user"),
            Message::assistant("recent answer"),
        ];
        s.record_session_compacted_with_source(
            "Build",
            crate::session::SessionCompactionRecord {
                successor_session_id: s.id,
                successor_short_id: &s.short_id(),
                seed_tool_count: 0,
                brief_text: "brief",
                handoff_text: "exact handoff",
                source: "manual",
                trigger_ctx_pct: None,
                tokens_before: 500,
                tokens_after: 100,
                turns_summarized: 3,
                tail_kept: 1,
                tail_trimmed: 0,
                tail_messages: &tail,
            },
            None,
        )
        .await
        .unwrap();
        record_user(&s, "after compact").await;
        let restored = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap()
            .history;
        assert_eq!(
            serde_json::to_value(restored).unwrap(),
            serde_json::to_value(
                [
                    vec![Message::user("exact handoff")],
                    tail,
                    vec![Message::user("after compact")]
                ]
                .concat()
            )
            .unwrap()
        );
    }

    /// REGRESSION (#276 class sweep): pre-compaction oversized tool results
    /// and prune-boundary projections stay in the log after in-place
    /// `/compact`. Rehydrate must not require those projections to map into
    /// the rebuilt (cleared) model history, while still projecting
    /// post-compaction tool artifacts.
    #[tokio::test]
    async fn compacted_model_history_skips_pre_compaction_tool_artifact_projections() {
        let s = root_session();
        record_user(&s, "first question").await;
        record_assistant(&s, "a1", "calling tool").await;
        record_tool_with_model_artifact(
            &s,
            "pre-compact-tool",
            "bash",
            "capped",
            "pre-compact-body",
        )
        .await;
        record_prune_with_model_artifact(&s, "pre-compact-pruned", "pre-compact-pruned-body").await;
        let tail = vec![
            Message::user("recent user"),
            Message::assistant("recent answer"),
        ];
        record_inplace_compact(&s, "exact handoff", &tail).await;
        record_user(&s, "after compact").await;
        record_assistant(&s, "a2", "calling again").await;
        record_tool_with_model_artifact(
            &s,
            "post-compact-tool",
            "bash",
            "capped-after",
            "post-compact-body",
        )
        .await;

        let restored = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap()
            .history;
        assert_eq!(user_text(&restored[0]), "exact handoff");
        assert_eq!(user_text(&restored[1]), "recent user");
        assert_eq!(assistant_text(&restored[2]), "recent answer");
        assert_eq!(user_text(&restored[3]), "after compact");
        let dump = format!("{restored:?}");
        assert!(
            !dump.contains("pre-compact-body") && !dump.contains("pre-compact-pruned-body"),
            "pre-compaction tool/prune bodies must not leak into rebuilt history: {dump}"
        );
        assert!(
            matches!(
                &restored[5],
                Message::User { content }
                    if matches!(
                        content.as_slice(),
                        [UserContent::ToolResult(result)]
                            if result.call.to_string() == "post-compact-tool"
                                && result.content.iter().any(|part| {
                                    matches!(
                                        part,
                                        ToolResultContent::Text(text)
                                            if text.text.starts_with("<cockpit_artifact_v1 ")
                                    )
                                })
                    )
            ),
            "post-compaction tool artifact must still project: {:?}",
            restored.get(5)
        );
    }

    /// Pre-compaction oversized user artifacts are dropped from validation
    /// (`by_event.retain`) because they are no longer in model context.
    /// Resume must succeed rather than abort on those leftover owner rows.
    #[tokio::test]
    async fn compacted_model_history_skips_pre_compaction_user_artifacts() {
        struct AllowJoin;
        impl crate::db::message_attachments::MessageAcceptanceJoin for AllowJoin {
            fn validate_and_join(
                &self,
                _: &rusqlite::Connection,
                _: &crate::db::message_attachments::AcceptMessageInput,
            ) -> anyhow::Result<()> {
                Ok(())
            }
        }

        let _env = crate::test_env::TestEnvGuard::isolated_cockpit_home_async().await;
        let s = root_session();
        let source = "x".repeat(65_537);
        let operation_id = Uuid::new_v4();
        let submission_id = Uuid::new_v4();
        let reserved =
            s.db.accept_message_with_text_artifact_reservation(
                crate::db::message_attachments::AcceptMessageInput {
                    session_id: s.id,
                    operation_id: *operation_id.as_bytes(),
                    actor: crate::db::message_attachments::MessageActor::LocalOwner,
                    request_hash: [7; 32],
                    message_request_digest: [8; 32],
                    attachment_set_digest: [9; 32],
                    client_submission_id: *submission_id.as_bytes(),
                    queue_item_id: *submission_id.as_bytes(),
                    canonical_message: b"FCM2\x02".to_vec(),
                    attachments: Vec::new(),
                    outbox_sequence: 0,
                    now_ms: 10,
                    tool_media_subject_binding: None,
                },
                Arc::new(AllowJoin),
                crate::db::text_artifacts::source_digest(&source),
                source.len(),
            )
            .await
            .unwrap();
        let reservation = match reserved {
            crate::db::text_artifacts::TextArtifactPhaseOneResult::Reserved(reservation) => {
                reservation
            }
            other => panic!("expected reservation, got {other:?}"),
        };
        let envelope = json!({
            "version": 3,
            "prelude": [],
            "parts": [{"type":"authored_text_slot"}]
        });
        let source_blob_path = stage_user_blob(&s, &source).await;
        s.db.materialize_reserved_user_text_artifacts(
            crate::db::text_artifacts::ReservedUserArtifactMaterialization {
                reservation,
                canonical_event_json: json!({"text": source.clone()}).to_string(),
                model_envelope_json: envelope.to_string(),
                source_text: source,
                source_blob_path: Some(source_blob_path),
                source_preview_lines: None,
                model_projection_blob_path: None,
                model_projection: None,
                agent: Some("Build".to_owned()),
                context: crate::db::text_artifacts::TextArtifactEventContext::default(),
                now_ms: 11,
            },
        )
        .await
        .unwrap();
        let tail = vec![
            Message::user("recent user"),
            Message::assistant("recent answer"),
        ];
        record_inplace_compact(&s, "exact handoff", &tail).await;
        let restored = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap()
            .history;
        assert_eq!(
            serde_json::to_value(restored).unwrap(),
            serde_json::to_value([vec![Message::user("exact handoff")], tail].concat()).unwrap()
        );
    }

    /// Offloaded compaction payloads (`handoff_ref`) must hydrate before the
    /// projection cursor reads `tail_messages`; otherwise the history prefix
    /// is 1 and a follow-up user turn mismatches the retained tail.
    #[tokio::test]
    async fn compacted_model_history_with_offloaded_handoff_and_prior_turns_rehydrates() {
        let s = root_session();
        record_user(&s, "first question").await;
        record_assistant(&s, "a1", "first answer").await;
        let handoff = format!("## Decisions\n{}", "durable ".repeat(3_000));
        let tail = vec![
            Message::user(format!("recent {}", "tail ".repeat(1_000))),
            Message::assistant("recent answer"),
        ];
        s.record_session_compacted_with_source(
            "Build",
            crate::session::SessionCompactionRecord {
                successor_session_id: s.id,
                successor_short_id: &s.short_id(),
                seed_tool_count: 0,
                brief_text: &handoff,
                handoff_text: &handoff,
                source: "manual",
                trigger_ctx_pct: None,
                tokens_before: 9_000,
                tokens_after: 3_000,
                turns_summarized: 3,
                tail_kept: 1,
                tail_trimmed: 0,
                tail_messages: &tail,
            },
            None,
        )
        .await
        .unwrap();
        let session_id = s.id;
        let raw_data: String = s
            .db
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT data_json FROM session_events WHERE session_id = ?1 AND type = 'session_compacted'",
                    [session_id.to_string()],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        let raw_data: serde_json::Value = serde_json::from_str(&raw_data).unwrap();
        assert!(
            raw_data["handoff_ref"].as_str().is_some(),
            "expected offloaded compaction payload, got {raw_data}"
        );
        record_user(&s, "after compact").await;
        let restored = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap()
            .history;
        assert_eq!(user_text(&restored[0]), handoff);
        assert_eq!(restored.len(), 1 + tail.len() + 1);
        assert_eq!(user_text(restored.last().unwrap()), "after compact");
    }

    /// `last_root_compaction_cursor` must use the last root compaction, not
    /// the first: turns between two in-place `/compact`s are summarized away
    /// by the later boundary.
    #[tokio::test]
    async fn compacted_model_history_uses_last_of_multiple_compaction_boundaries() {
        let s = root_session();
        record_user(&s, "first question").await;
        record_assistant(&s, "a1", "first answer").await;
        let first_tail = vec![
            Message::user("first tail user"),
            Message::assistant("first tail answer"),
        ];
        record_inplace_compact(&s, "first handoff", &first_tail).await;
        record_user(&s, "between compacts").await;
        record_assistant(&s, "a2", "between answer").await;
        let second_tail = vec![
            Message::user("second tail user"),
            Message::assistant("second tail answer"),
        ];
        record_inplace_compact(&s, "second handoff", &second_tail).await;
        record_user(&s, "after second compact").await;
        let restored = rehydrate_session(&s.db, s.id, "Build")
            .await
            .unwrap()
            .unwrap()
            .history;
        assert_eq!(
            serde_json::to_value(restored).unwrap(),
            serde_json::to_value(
                [
                    vec![Message::user("second handoff")],
                    second_tail,
                    vec![Message::user("after second compact")]
                ]
                .concat()
            )
            .unwrap()
        );
    }

    /// Recovery chip survives into the snapshot for a repaired tool call
    /// (wire-vs-user split, GOALS §14).
    #[tokio::test]
    async fn history_snapshot_carries_recovery_chip() {
        let s = root_session();
        record_user(&s, "edit it").await;
        record_assistant(&s, "infer-1", "").await;
        s.record_tool_call(crate::session::ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".into(),
            call_id: "tc-1".into(),
            parent_call_id: None,
            parent_child_index: None,
            identity: crate::session::ToolCallProviderIdentity::default(),
            tool: "read".into(),
            path: None,
            mcp_server: None,
            original_input_json: json!({ "path": "/f" }),
            wire_input_json: json!({ "path": "/f" }),
            recovery: Recovery::ShapeRepair {
                stage: "wrap_bare_string",
                path: "$".into(),
                hint: None,
            },
            hard_fail: false,
            exit_code: None,
            sandbox_enabled: false,
            sandboxed: false,
            sandbox_unavailable_reason: None,
            output: "ok".into(),
            truncated: false,
            duration_ms: 1,
            shape_fingerprint: None,
            hint: None,
        })
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some("tc-1"),
            &json!({ "tool": "read", "wire_input": { "path": "/f" }, "output": "ok" }),
        )
        .await
        .unwrap();

        let snap = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        let tc = snap
            .iter()
            .find(|e| matches!(e, proto::HistoryEntry::ToolCall { .. }))
            .expect("tool call present");
        match tc {
            proto::HistoryEntry::ToolCall {
                recovery_kind,
                recovery_stage,
                ..
            } => {
                assert_eq!(recovery_kind.as_deref(), Some("shape_repair"));
                assert_eq!(recovery_stage.as_deref(), Some("wrap_bare_string"));
            }
            _ => unreachable!(),
        }
    }

    /// An empty session yields an empty snapshot (no error) — the brand-new
    /// session edge case.
    #[tokio::test]
    async fn history_snapshot_empty_session_is_empty() {
        let s = root_session();
        assert!(
            history_snapshot(&s.db, s.id, "Build")
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// A session with tool calls but no assistant text still renders the
    /// subset that exists, in order (edge case: subset-only history).
    #[tokio::test]
    async fn history_snapshot_tool_calls_without_assistant_text() {
        let s = root_session();
        record_user(&s, "go").await;
        record_tool(
            &s,
            "tc-1",
            "bash",
            json!({ "command": "ls" }),
            json!({ "command": "ls" }),
            "a.rs",
        )
        .await;
        let snap = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        assert_eq!(snap.len(), 2);
        assert!(matches!(snap[0], proto::HistoryEntry::User { .. }));
        assert!(matches!(snap[1], proto::HistoryEntry::ToolCall { .. }));
    }

    /// Subagent (non-root) turns are excluded from the snapshot, exactly as
    /// model rehydration excludes them — single source of truth, same gate.
    #[tokio::test]
    async fn history_snapshot_excludes_subagent_turns() {
        let s = root_session();
        record_user(&s, "go").await;
        record_assistant(&s, "infer-1", "root says hi").await;
        s.record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("explore"),
            Some("infer-x"),
            &json!({ "text": "subagent internal" }),
        )
        .await
        .unwrap();
        let snap = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        assert_eq!(snap.len(), 2);
        assert!(matches!(snap[1], proto::HistoryEntry::Assistant { .. }));
    }

    #[tokio::test]
    async fn history_snapshot_active_subagent_includes_running_row_and_child_turns() {
        let s = root_session();
        record_user(&s, "build it").await;
        record_assistant(&s, "infer-1", "delegating").await;
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-1"),
            &json!({
                "parent": "Build",
                "child": "builder",
                "task_call_id": "task-1",
                "label": "default",
                "prompt": "build it",
            }),
        )
        .await
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("builder"),
            Some("infer-child"),
            &json!({ "text": "child progress" }),
        )
        .await
        .unwrap();

        let active = proto::ActiveSubagent {
            parent: "Build".into(),
            child: "builder".into(),
            task_call_id: "task-1".into(),
            label: "default".into(),
        };
        let session_id = s.id;
        let active_for_read = active.clone();
        let snap =
            s.db.read(move |conn| {
                history_snapshot_with_active_subagent_conn(
                    conn,
                    session_id,
                    "Build",
                    Some(&active_for_read),
                )
            })
            .await
            .unwrap();

        assert_eq!(snap.len(), 4);
        assert!(matches!(snap[0], proto::HistoryEntry::User { .. }));
        assert!(matches!(snap[1], proto::HistoryEntry::Assistant { .. }));
        match &snap[2] {
            proto::HistoryEntry::Subagent {
                parent,
                child,
                task_call_id,
                label,
                ..
            } => {
                assert_eq!(parent, "Build");
                assert_eq!(child, "builder");
                assert_eq!(task_call_id, "task-1");
                assert_eq!(label, "default");
            }
            other => panic!("snap[2] should be Subagent, got {other:?}"),
        }
        match &snap[3] {
            proto::HistoryEntry::Assistant { agent, text, .. } => {
                assert_eq!(agent, "builder");
                assert_eq!(text, "child progress");
            }
            other => panic!("snap[3] should be child Assistant, got {other:?}"),
        }

        let root_only = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        assert_eq!(
            root_only.len(),
            2,
            "ordinary root-only resume still excludes child internals"
        );
    }

    /// Helper: the ordering seq carried by a message snapshot entry.
    fn msg_seq(e: &proto::HistoryEntry) -> i64 {
        match e {
            proto::HistoryEntry::User { seq, .. } | proto::HistoryEntry::Assistant { seq, .. } => {
                *seq
            }
            proto::HistoryEntry::ToolCall { .. }
            | proto::HistoryEntry::InterruptDecision { .. }
            | proto::HistoryEntry::UserNote { .. }
            | proto::HistoryEntry::CompactBoundary { .. }
            | proto::HistoryEntry::Subagent { .. }
            | proto::HistoryEntry::InferenceError { .. } => panic!("not a message entry"),
        }
    }

    #[tokio::test]
    async fn response_performance_restores_agent_history() {
        let s = root_session();
        s.record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("Build"),
            Some("call-perf"),
            &json!({
                "text": "Bonjour",
                "presentation_text": "Hello",
                "reasoning": "thought",
                "response_performance": {
                    "ttft_ms": 150,
                    "generation_ms": 400,
                    "displayed_tokens": 12,
                    "encoding": "cl100k_base"
                }
            }),
        )
        .await
        .unwrap();

        let snapshot = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        match &snapshot[0] {
            proto::HistoryEntry::Assistant {
                text,
                presentation_text,
                reasoning,
                response_performance,
                ..
            } => {
                assert_eq!(text, "Bonjour");
                assert_eq!(presentation_text.as_deref(), Some("Hello"));
                assert_eq!(reasoning, "thought");
                let perf = response_performance.as_ref().expect("restored snapshot");
                assert_eq!(perf.ttft_ms, 150);
                assert_eq!(perf.generation_ms, 400);
                assert_eq!(perf.displayed_tokens, 12);
                assert_eq!(perf.encoding, "cl100k_base");
            }
            other => panic!("expected Assistant, got {other:?}"),
        }

        // Legacy row without response_performance still restores.
        s.record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("Build"),
            Some("call-legacy"),
            &json!({ "text": "legacy", "reasoning": "" }),
        )
        .await
        .unwrap();
        let snapshot = history_snapshot(&s.db, s.id, "Build").await.unwrap();
        assert_eq!(snapshot.len(), 2);
        match &snapshot[1] {
            proto::HistoryEntry::Assistant {
                response_performance: None,
                presentation_text: None,
                text,
                ..
            } => assert_eq!(text, "legacy"),
            other => panic!("expected legacy Assistant, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod subagent_observe_tests {
    use super::*;
    use crate::db::session_log::SessionEventKind;
    use serde_json::json;

    #[tokio::test]
    async fn subagent_snapshot_isolates_interleaved_runs_with_same_agent() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/tmp/project", "Build")
            .await
            .unwrap();
        let sid = session.session_id;

        db.insert_session_event_with_context(
            sid,
            SessionEventKind::UserMessage,
            Some("Explore"),
            None,
            crate::db::session_log::SessionEventContext {
                origin_principal: None,
                task_call_id: Some("task-a"),
                label: Some("default"),
                ..Default::default()
            },
            &json!({ "text": "brief a" }),
        )
        .await
        .unwrap();
        db.insert_session_event_with_context(
            sid,
            SessionEventKind::UserMessage,
            Some("Explore"),
            None,
            crate::db::session_log::SessionEventContext {
                origin_principal: None,
                task_call_id: Some("task-b"),
                label: Some("default"),
                ..Default::default()
            },
            &json!({ "text": "brief b" }),
        )
        .await
        .unwrap();
        db.insert_session_event_with_context(
            sid,
            SessionEventKind::AssistantMessage,
            Some("Explore"),
            Some("call-a"),
            crate::db::session_log::SessionEventContext {
                origin_principal: None,
                task_call_id: Some("task-a"),
                label: Some("default"),
                ..Default::default()
            },
            &json!({ "text": "answer a", "reasoning": "ra" }),
        )
        .await
        .unwrap();
        db.insert_session_event_with_context(
            sid,
            SessionEventKind::AssistantMessage,
            Some("Explore"),
            Some("call-b"),
            crate::db::session_log::SessionEventContext {
                origin_principal: None,
                task_call_id: Some("task-b"),
                label: Some("default"),
                ..Default::default()
            },
            &json!({ "text": "answer b", "reasoning": "rb" }),
        )
        .await
        .unwrap();

        let child_a = db
            .read(move |conn| subagent_history_snapshot_conn(conn, sid, "task-a", "default"))
            .await
            .unwrap();
        assert_eq!(child_a.len(), 2);
        assert!(matches!(&child_a[0], proto::HistoryEntry::User { text, .. } if text == "brief a"));
        assert!(
            matches!(&child_a[1], proto::HistoryEntry::Assistant { text, reasoning, .. } if text == "answer a" && reasoning == "ra")
        );

        let child_b = db
            .read(move |conn| subagent_history_snapshot_conn(conn, sid, "task-b", "default"))
            .await
            .unwrap();
        assert_eq!(child_b.len(), 2);
        assert!(matches!(&child_b[0], proto::HistoryEntry::User { text, .. } if text == "brief b"));
        assert!(
            matches!(&child_b[1], proto::HistoryEntry::Assistant { text, reasoning, .. } if text == "answer b" && reasoning == "rb")
        );
    }

    #[tokio::test]
    async fn root_snapshot_hides_finished_child_rows() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/tmp/project", "Build")
            .await
            .unwrap();
        let sid = session.session_id;
        db.insert_session_event(
            sid,
            SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &json!({ "text": "root prompt" }),
        )
        .await
        .unwrap();
        db.insert_session_event_with_context(
            sid,
            SessionEventKind::AssistantMessage,
            Some("Explore"),
            Some("call-child"),
            crate::db::session_log::SessionEventContext {
                origin_principal: None,
                task_call_id: Some("task-child"),
                label: Some("default"),
                ..Default::default()
            },
            &json!({ "text": "hidden child", "reasoning": "" }),
        )
        .await
        .unwrap();

        let root = db
            .read(move |conn| history_snapshot_with_active_subagent_conn(conn, sid, "Build", None))
            .await
            .unwrap();
        assert_eq!(root.len(), 1);
        assert!(
            matches!(&root[0], proto::HistoryEntry::User { text, .. } if text == "root prompt")
        );
    }
}
