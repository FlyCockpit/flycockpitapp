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
use rig::OneOrMany;
use rig::message::{
    AssistantContent, Message, ToolCall, ToolFunction, ToolResult, ToolResultContent, UserContent,
};
use rusqlite::Connection;
use uuid::Uuid;

use crate::daemon::proto;
use crate::db::Db;
use crate::db::session_log::SessionEventRow;
use crate::db::tool_calls::Recovery;
use crate::db::tool_calls::ToolCallEvent;
use crate::engine::prune::{PruneLedger, ledger_is_empty, reapply_ledger};

/// Honest stub body for an assistant tool call whose result never landed in
/// the durable transcript (an interrupted/aborted call). The model sees that
/// the call did not complete — we never fabricate a plausible success.
const ABORTED_CALL_BODY: &str =
    "[cockpit] tool call interrupted before resume; its result is unavailable.";

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
pub fn rehydrate_session(
    db: &Db,
    session_id: Uuid,
    root_agent: &str,
) -> Result<Option<Rehydrated>> {
    rehydrate_session_with_policy(db, session_id, root_agent, RehydratePolicy::heal())
}

pub fn rehydrate_session_with_policy(
    db: &Db,
    session_id: Uuid,
    root_agent: &str,
    policy: RehydratePolicy,
) -> Result<Option<Rehydrated>> {
    let mut events = db
        .list_session_events(session_id)
        .map_err(|e| anyhow!("loading session events for rehydration: {e}"))?;
    for event in &mut events {
        if event.kind == "session_compacted"
            && let Some(reference) = event
                .data
                .get("handoff_ref")
                .and_then(|value| value.as_str())
            && let Some(payload) = db.compaction_payload(session_id, reference)?
        {
            event.data = serde_json::from_str(&payload)
                .context("decoding stored compaction payload for rehydration")?;
        }
    }
    let tool_calls = db
        .list_tool_calls_for_session(session_id)
        .map_err(|e| anyhow!("loading tool calls for rehydration: {e}"))?;

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
    let mut history = rebuild_history(&events, &tool_calls, root_agent, &mut heals, policy)?;
    if history.is_empty() {
        // No recorded turns — a fresh session, nothing to rehydrate.
        return Ok(None);
    }

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
    let (watermark, ledger_fallback) = match load_ledger(db, session_id) {
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

    Ok(Some(Rehydrated {
        history,
        watermark,
        ledger_fallback,
        heals,
    }))
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
pub fn history_snapshot(
    db: &Db,
    session_id: Uuid,
    root_agent: &str,
) -> Result<Vec<proto::HistoryEntry>> {
    db.read_blocking(|conn| history_snapshot_conn(conn, session_id, root_agent))
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

fn history_snapshot_from_events_conn(
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
                snapshot.push(proto::HistoryEntry::User {
                    text,
                    display_text,
                    tag_expansions,
                    ts_ms: ev.ts_ms,
                    seq: ev.seq,
                    origin_principal: ev.origin_principal.clone(),
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
                snapshot.push(proto::HistoryEntry::Assistant {
                    agent,
                    text,
                    reasoning,
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
                            tool: tc.tool.clone(),
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
                            tool,
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

    let mut tc_by_id: std::collections::HashMap<&str, &ToolCallEvent> =
        std::collections::HashMap::new();
    for tc in &tool_calls {
        tc_by_id.insert(tc.call_id.as_str(), tc);
    }

    let owns_row = |ev: &SessionEventRow| {
        ev.task_call_id.as_deref() == Some(task_call_id) && ev.label.as_deref() == Some(label)
    };

    let mut snapshot: Vec<proto::HistoryEntry> = Vec::new();
    for ev in events.iter().filter(|ev| owns_row(ev)) {
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
                snapshot.push(proto::HistoryEntry::User {
                    text,
                    display_text,
                    tag_expansions,
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
                snapshot.push(proto::HistoryEntry::Assistant {
                    agent,
                    text,
                    reasoning,
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
                            tool: tc.tool.clone(),
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
                            tool,
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

    Ok(snapshot)
}

fn inference_failure_summary(data: &serde_json::Value) -> String {
    let provider = data.get("provider").and_then(|v| v.as_str()).unwrap_or("");
    let model = data.get("model").and_then(|v| v.as_str()).unwrap_or("");
    let class = data
        .get("error_class")
        .or_else(|| data.get("class"))
        .and_then(|v| v.as_str())
        .unwrap_or("inference_error");
    let detail = data
        .get("detail")
        .or_else(|| data.get("full_detail"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let reason = match class {
        "timeout_ttft" => "no first token within the timeout".to_string(),
        "timeout_idle" => "stream stalled past the idle timeout".to_string(),
        other if detail.trim().is_empty() => other.to_string(),
        other => format!(
            "{other}: {}",
            crate::tui::agent_runner::first_line(detail, 200)
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

/// Load the prune ledger, treating a corrupt/unreadable row as absent (we
/// then rebuild the full unpruned form — never a silent fresh context).
fn load_ledger(db: &Db, session_id: Uuid) -> Option<PruneLedger> {
    match db.load_prune_ledger(session_id) {
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
    /// One `(id, provider_call_id, body)` per issued call, in dispatch order.
    results: Vec<(String, Option<String>, String)>,
}

impl PendingTurn {
    fn is_empty(&self) -> bool {
        self.text_parts.is_empty() && self.calls.is_empty()
    }

    /// Flush the buffered assistant turn (text + tool calls) and its tool
    /// results into `history`. A turn with no text and no calls contributes
    /// nothing.
    fn flush(self, history: &mut Vec<Message>) {
        if self.is_empty() {
            return;
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
        if let Ok(content) = OneOrMany::many(content) {
            history.push(Message::Assistant { id: None, content });
        }
        // Each tool result is its own user message (the live wire shape).
        // Provider contract: the results immediately follow the assistant
        // turn that issued the calls.
        for (id, call_id, body) in self.results {
            history.push(Message::User {
                content: OneOrMany::one(UserContent::ToolResult(ToolResult {
                    id,
                    call_id,
                    content: OneOrMany::one(ToolResultContent::text(body)),
                })),
            });
        }
    }
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
}

#[derive(Clone)]
struct ReportInfo {
    child: String,
    label: String,
    report: String,
    provider_call_id: Option<String>,
}

fn rebuild_history(
    events: &[SessionEventRow],
    tool_calls: &[ToolCallEvent],
    root_agent: &str,
    heals: &mut Vec<Recovery>,
    policy: RehydratePolicy,
) -> Result<Vec<Message>> {
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
            "tool_call" if ev.agent.as_deref() == Some(root_agent) => {
                let Some(call_id) = ev.call_id.as_deref() else {
                    return Err(anyhow!("tool_call event without a call_id (corrupt row)"));
                };
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
                        pending.calls.push(ToolCall {
                            id: provider_item_id.clone(),
                            call_id: provider_call_id.clone(),
                            function: ToolFunction {
                                name: tc.tool.clone(),
                                arguments: tc.wire_input_json.clone(),
                            },
                            signature: None,
                            additional_params: None,
                        });
                        pending.results.push((
                            provider_item_id,
                            provider_call_id,
                            tc.output.clone(),
                        ));
                    }
                    None => {
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
                        pending.calls.push(ToolCall {
                            id: call_id.to_string(),
                            call_id: None,
                            function: ToolFunction {
                                name: tool,
                                arguments,
                            },
                            signature: None,
                            additional_params: None,
                        });
                        pending.results.push((
                            call_id.to_string(),
                            None,
                            ABORTED_CALL_BODY.to_string(),
                        ));
                        heals.push(Recovery::ResumeHeal {
                            kind: "stub_orphan_tool_call",
                            id: call_id.to_string(),
                        });
                    }
                }
            }
            "session_compacted" if ev.agent.as_deref() == Some(root_agent) => {
                std::mem::take(&mut pending).flush(&mut history);
                let handoff = ev
                    .data
                    .get("handoff_text")
                    .and_then(|value| value.as_str())
                    .or_else(|| ev.data.get("brief_text").and_then(|value| value.as_str()))
                    .unwrap_or("")
                    .to_string();
                history.clear();
                history.push(Message::user(handoff));
                if let Some(tail) = ev.data.get("tail_messages") {
                    let tail: Vec<Message> = serde_json::from_value(tail.clone())
                        .map_err(|error| anyhow!("decoding compacted tail_messages: {error}"))?;
                    history.extend(tail);
                }
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
                pending.calls.push(ToolCall {
                    id: call_id.to_string(),
                    call_id: provider_call_id.clone(),
                    function: ToolFunction {
                        name: "task".to_string(),
                        arguments,
                    },
                    signature: None,
                    additional_params: None,
                });
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
                                ensure_report_provider_call_id_matches(
                                    policy,
                                    call_id,
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
                    pending
                        .results
                        .push((call_id.to_string(), provider_call_id.clone(), body));
                } else {
                    match report_by_call.get(call_id) {
                        Some(report) => {
                            ensure_report_provider_call_id_matches(
                                policy,
                                call_id,
                                provider_call_id.as_deref(),
                                report.provider_call_id.as_deref(),
                                ev.seq,
                            )?;
                            pending.results.push((
                                call_id.to_string(),
                                provider_call_id.clone(),
                                report.report.clone(),
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
                                call_id.to_string(),
                                provider_call_id.clone(),
                                MISSING_REPORT_BODY.to_string(),
                            ));
                            heals.push(Recovery::ResumeHeal {
                                kind: "stub_missing_subagent_report",
                                id: call_id.to_string(),
                            });
                        }
                    }
                }
            }
            // Everything else (inference_request, context_pruned,
            // permission_decision, subagent_report,
            // other agents' turns) is not part of the root model history.
            _ => {}
        }
    }
    // Flush the final assistant turn (+ results), if any.
    pending.flush(&mut history);
    crate::engine::delegation_prompt_prune::prune_completed_delegation_prompts(&mut history);

    Ok(history)
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

fn ensure_report_provider_call_id_matches(
    policy: RehydratePolicy,
    call_id: &str,
    expected: Option<&str>,
    actual: Option<&str>,
    seq: i64,
) -> Result<()> {
    if policy.is_strict()
        && let (Some(expected), Some(actual)) = (expected, actual)
        && expected != actual
    {
        return Err(anyhow::Error::new(RehydrateRepairRequired::new(
            "mismatched_pair",
            vec![call_id.to_string()],
            Some(seq.saturating_sub(1)),
            "Responses replay found a subagent report paired to a different provider call id",
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
                UserContent::ToolResult(tr) => Some(tr.id.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// A synthetic, honest tool_result user message for a stubbed orphan call.
fn stub_result_message(id: &str, body: &str) -> Message {
    Message::User {
        content: OneOrMany::one(UserContent::ToolResult(ToolResult {
            id: id.to_string(),
            call_id: None,
            content: OneOrMany::one(ToolResultContent::text(body.to_string())),
        })),
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
    heal_pairing_pending(history, &[], heals);
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
                        AssistantContent::ToolCall(tc) => Some(tc.id.clone()),
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
                let has_orphan = content.iter().any(
                    |c| matches!(c, UserContent::ToolResult(tr) if !open_calls.contains(&tr.id)),
                );
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
                        UserContent::ToolResult(tr) if !open_calls.contains(&tr.id) => {
                            heals.push(Recovery::ResumeHeal {
                                kind: "drop_orphan_tool_result",
                                id: tr.id.clone(),
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
                    *content = OneOrMany::many(kept).expect("kept is non-empty (checked above)");
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
            let call_ids: Vec<String> = content
                .iter()
                .filter_map(|c| match c {
                    AssistantContent::ToolCall(tc) => Some(tc.id.clone()),
                    _ => None,
                })
                .collect();
            if !call_ids.is_empty() {
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
                for id in &call_ids {
                    if !covered.contains(id) {
                        history.insert(j, stub_result_message(id, ABORTED_CALL_BODY));
                        j += 1;
                        heals.push(Recovery::ResumeHeal {
                            kind: "stub_orphan_tool_call",
                            id: id.clone(),
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
    heal_pairing_pending(history, &pending, &mut heals);
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
                        let Some(call_id) = tc.call_id.clone() else {
                            return Err(anyhow::Error::new(RehydrateRepairRequired::new(
                                "missing_provider_call_id",
                                vec![tc.id.clone()],
                                None,
                                "Responses replay requires the provider function call id for each assistant tool call",
                            )));
                        };
                        open.push((tc.id.clone(), call_id));
                    }
                }
            }
            Message::User { content } => {
                let mut saw_result = false;
                for part in content.iter() {
                    if let UserContent::ToolResult(tr) = part {
                        saw_result = true;
                        let Some(pos) = open.iter().position(|(id, _)| id == &tr.id) else {
                            return Err(anyhow::Error::new(RehydrateRepairRequired::new(
                                "orphan_tool_result",
                                vec![tr.id.clone()],
                                None,
                                "Responses replay found a tool result with no preceding assistant tool call",
                            )));
                        };
                        let expected_call_id = open[pos].1.clone();
                        match tr.call_id.as_deref() {
                            Some(actual) if actual == expected_call_id.as_str() => {}
                            Some(_) => {
                                return Err(anyhow::Error::new(RehydrateRepairRequired::new(
                                    "mismatched_pair",
                                    vec![tr.id.clone()],
                                    None,
                                    "Responses replay found a tool result paired to a different provider call id",
                                )));
                            }
                            None => {
                                return Err(anyhow::Error::new(RehydrateRepairRequired::new(
                                    "missing_provider_call_id",
                                    vec![tr.id.clone()],
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
fn validate_pairing(history: &[Message]) -> Result<()> {
    // Forward pass: each assistant turn's call ids must be covered by the
    // immediately-following run of tool-result user messages.
    let mut i = 0;
    while i < history.len() {
        if let Message::Assistant { content, .. } = &history[i] {
            let call_ids: Vec<String> = content
                .iter()
                .filter_map(|c| match c {
                    AssistantContent::ToolCall(tc) => Some(tc.id.clone()),
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
                        AssistantContent::ToolCall(tc) => Some(tc.id.clone()),
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
                        if !open_calls.contains(&tr.id) {
                            return Err(anyhow!(
                                "rebuilt history has an orphan tool_result `{}` \
                                 (no preceding tool_use); refusing to send a malformed context",
                                tr.id
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
        let s = Session::create(db, PathBuf::from("/x"), "Build").unwrap();
        s.set_active_model("anthropic", "opus").unwrap();
        s
    }

    fn record_user(s: &Session, text: &str) {
        s.record_event(
            crate::db::session_log::SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &json!({ "text": text }),
        )
        .unwrap();
    }

    fn record_assistant(s: &Session, call_id: &str, text: &str) {
        s.record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("Build"),
            Some(call_id),
            &json!({ "text": text }),
        )
        .unwrap();
    }

    /// Record an assistant turn the way the engine does for an
    /// inline-`<think>` model: the stored `text` is already STRIPPED (no
    /// tags), and the reasoning rides its own `data_json` field.
    fn record_assistant_with_reasoning(s: &Session, call_id: &str, text: &str, reasoning: &str) {
        s.record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("Build"),
            Some(call_id),
            &json!({ "text": text, "reasoning": reasoning }),
        )
        .unwrap();
    }

    /// Record a real tool call (both the timeline event and the audit row,
    /// as the engine does), with a chosen wire input distinct from the
    /// original to prove `wire_input_json` is the source used.
    fn record_tool(
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
            identity: crate::session::ToolCallProviderIdentity::default(),
            tool: tool.into(),
            path: None,
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
            llm_mode: crate::config::extended::LlmMode::default(),
            shape_fingerprint: None,
            hint: None,
        })
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
        .unwrap();
    }

    fn record_tool_with_identity(
        s: &Session,
        call_id: &str,
        identity: crate::session::ToolCallProviderIdentity,
    ) {
        s.record_tool_call(ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".into(),
            call_id: call_id.into(),
            identity,
            tool: "read".into(),
            path: None,
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
            llm_mode: crate::config::extended::LlmMode::default(),
            shape_fingerprint: None,
            hint: None,
        })
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
        .unwrap();
    }

    fn record_inference_failure(s: &Session, data: serde_json::Value) {
        s.record_event(
            crate::db::session_log::SessionEventKind::InferenceFailure,
            Some("Build"),
            None,
            &data,
        )
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
    #[test]
    fn rebuilds_plain_exchange() {
        let s = root_session();
        record_user(&s, "hello");
        record_assistant(&s, "call-1", "hi there");
        record_user(&s, "bye");
        record_assistant(&s, "call-2", "goodbye");

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
        let h = r.history;
        assert_eq!(h.len(), 4);
        assert_eq!(user_text(&h[0]), "hello");
        assert_eq!(assistant_text(&h[1]), "hi there");
        assert_eq!(user_text(&h[2]), "bye");
        assert_eq!(assistant_text(&h[3]), "goodbye");
    }

    #[test]
    fn rehydrate_model_context_omits_inference_failure_events() {
        let s = root_session();
        record_user(&s, "hello");
        record_inference_failure(
            &s,
            json!({
                "provider": "local",
                "model": "bad",
                "error_class": "network",
                "detail": "first line\nsecond line",
            }),
        );
        record_user(&s, "after");

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
        let h = r.history;
        assert_eq!(h.len(), 2);
        assert_eq!(user_text(&h[0]), "hello");
        assert_eq!(user_text(&h[1]), "after");
    }

    #[test]
    fn history_snapshot_includes_inference_failure_display_rows_in_order() {
        let s = root_session();
        record_user(&s, "before");
        record_inference_failure(
            &s,
            json!({
                "provider": "local",
                "model": "bad",
                "error_class": "network",
                "detail": "first line\nsecond line",
            }),
        );
        record_user(&s, "after");

        let snapshot = history_snapshot(&s.db, s.id, "Build").unwrap();
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

    #[test]
    fn history_snapshot_handles_old_inference_failure_without_detail() {
        let s = root_session();
        record_inference_failure(
            &s,
            json!({
                "provider": "local",
                "model": "slow",
                "error_class": "timeout_ttft",
            }),
        );

        let snapshot = history_snapshot(&s.db, s.id, "Build").unwrap();
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
    #[test]
    fn rehydrated_history_is_tag_free_and_omits_reasoning() {
        let s = root_session();
        record_user(&s, "do it");
        // Stored as the engine now stores it: clean body + reasoning aside.
        record_assistant_with_reasoning(
            &s,
            "infer-1",
            "the clean answer",
            "the model's hidden chain of thought",
        );

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
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
    #[test]
    fn stored_reasoning_persists_on_the_event() {
        let s = root_session();
        record_user(&s, "go");
        record_assistant_with_reasoning(&s, "infer-1", "answer", "secret reasoning");

        let events = s.db.list_session_events(s.id).unwrap();
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
    #[test]
    fn rebuilds_tool_turn_using_wire_input() {
        let s = root_session();
        record_user(&s, "read the file");
        record_assistant(&s, "infer-1", "let me read it");
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "src/main.rs", "typo": true }),
            json!({ "path": "src/main.rs" }),
            "fn main() {}",
        );
        record_assistant(&s, "infer-2", "done");

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
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

    #[test]
    fn rebuilds_parallel_tool_calls_as_one_assistant_turn() {
        let s = root_session();
        record_user(&s, "read both files");
        record_assistant(&s, "infer-1", "reading both");
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "a.rs" }),
            json!({ "path": "a.rs" }),
            "A",
        );
        record_tool(
            &s,
            "tc-2",
            "read",
            json!({ "path": "b.rs" }),
            json!({ "path": "b.rs" }),
            "B",
        );
        record_assistant(&s, "infer-2", "done");

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
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

    #[test]
    fn rehydrates_historical_task_sibling_wire_input_without_rewriting() {
        let s = root_session();
        record_user(&s, "delegate");
        record_assistant(&s, "infer-1", "spawning");
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
        );

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
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

    #[test]
    fn rehydrated_tool_turn_preserves_provider_call_identity() {
        let s = root_session();
        record_user(&s, "read the file");
        record_assistant(&s, "infer-1", "let me read it");
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
        );

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
        let h = r.history;
        let calls = assistant_calls(&h[1]);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "provider-item");
        assert_eq!(calls[0].call_id.as_deref(), Some("provider-call"));
        let results = tool_results(&h[2]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "provider-item");
        assert_eq!(results[0].call_id.as_deref(), Some("provider-call"));
    }

    #[test]
    fn strict_responses_rehydrate_accepts_identified_tool_pair() {
        let s = root_session();
        record_user(&s, "read the file");
        record_assistant(&s, "infer-1", "let me read it");
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
        );

        let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .unwrap()
            .unwrap();
        let calls = assistant_calls(&r.history[1]);
        assert_eq!(calls[0].call_id.as_deref(), Some("provider-call"));
    }

    #[test]
    fn strict_responses_rehydrate_requires_provider_call_identity() {
        let s = root_session();
        record_user(&s, "read the file");
        record_assistant(&s, "infer-1", "let me read it");
        record_tool(
            &s,
            "call-without-provider-id",
            "read",
            json!({ "path": "/f" }),
            json!({ "path": "/f" }),
            "body",
        );

        let err = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
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

    #[test]
    fn strict_responses_rehydrate_accepts_synthetic_skill_slash_identity() {
        let s = root_session();
        record_user(&s, "/skill test-skill");
        let call_id = "skillslash-synthetic";
        let identity = crate::session::ToolCallProviderIdentity::synthetic_responses_call(call_id);
        s.record_tool_call(ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".into(),
            call_id: call_id.into(),
            identity: identity.clone(),
            tool: "skill".into(),
            path: None,
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
            llm_mode: crate::config::extended::LlmMode::default(),
            shape_fingerprint: None,
            hint: None,
        })
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
        .unwrap();

        let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .unwrap()
            .unwrap();
        let calls = assistant_calls(&r.history[1]);
        assert_eq!(calls[0].id, call_id);
        assert_eq!(calls[0].call_id.as_deref(), Some(call_id));
        let results = tool_results(&r.history[2]);
        assert_eq!(results[0].id, call_id);
        assert_eq!(results[0].call_id.as_deref(), Some(call_id));
    }

    #[test]
    fn strict_responses_rehydrate_accepts_synthetic_seed_identity() {
        let s = root_session();
        record_user(&s, "delegate with seed");
        record_assistant(&s, "infer-1", "reading seed");
        let call_id = "seed-synthetic";
        let identity = crate::session::ToolCallProviderIdentity::synthetic_responses_call(call_id);
        s.record_tool_call(ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".into(),
            call_id: call_id.into(),
            identity: identity.clone(),
            tool: "read".into(),
            path: Some("seed.txt".into()),
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
            llm_mode: crate::config::extended::LlmMode::default(),
            shape_fingerprint: None,
            hint: None,
        })
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
        .unwrap();

        let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .unwrap()
            .unwrap();
        let calls = assistant_calls(&r.history[1]);
        assert_eq!(calls[0].id, call_id);
        assert_eq!(calls[0].call_id.as_deref(), Some(call_id));
        let results = tool_results(&r.history[2]);
        assert_eq!(results[0].id, call_id);
        assert_eq!(results[0].call_id.as_deref(), Some(call_id));
    }

    /// A `task` delegation rebuilds as a `task` tool_use paired with the
    /// subagent report as its result.
    #[test]
    fn rebuilds_task_delegation_with_report() {
        let s = root_session();
        record_user(&s, "investigate");
        record_assistant(&s, "infer-1", "delegating");
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-1"),
            &json!({ "child_agent": "explore", "task_call_id": "task-1", "prompt": "look around" }),
        )
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some("explore"),
            Some("task-1"),
            &json!({ "report": "found three modules" }),
        )
        .unwrap();
        record_assistant(&s, "infer-2", "thanks");

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
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

    #[test]
    fn strict_responses_rehydrate_preserves_task_provider_call_identity() {
        let s = root_session();
        record_user(&s, "investigate");
        record_assistant(&s, "infer-1", "delegating");
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-1"),
            &json!({
                "child_agent": "explore",
                "task_call_id": "task-1",
                "provider_call_id": "call-provider-task",
                "provider_call_id_source": "provider",
                "provider_identity": {
                    "cockpit_call_id": "task-1",
                    "provider_call_id": "call-provider-task",
                    "provider_call_id_source": "provider",
                    "wire_api": "responses"
                },
                "prompt": "look around"
            }),
        )
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some("explore"),
            Some("task-1"),
            &json!({
                "report": "found three modules",
                "provider_call_id": "call-provider-task",
                "provider_call_id_source": "provider",
                "provider_identity": {
                    "cockpit_call_id": "task-1",
                    "provider_call_id": "call-provider-task",
                    "provider_call_id_source": "provider",
                    "wire_api": "responses"
                }
            }),
        )
        .unwrap();

        let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .unwrap()
            .unwrap();
        let calls = assistant_calls(&r.history[1]);
        assert_eq!(calls[0].id, "task-1");
        assert_eq!(calls[0].call_id.as_deref(), Some("call-provider-task"));
        let payload = &calls[0].function.arguments["payload"];
        assert!(
            payload.get("provider_call_id").is_none(),
            "provider identity must not leak into replayed task args"
        );
        assert!(payload.get("provider_call_id_source").is_none());
        assert!(payload.get("provider_identity").is_none());
        let results = tool_results(&r.history[2]);
        assert_eq!(results[0].id, "task-1");
        assert_eq!(results[0].call_id.as_deref(), Some("call-provider-task"));
    }

    #[test]
    fn strict_responses_rehydrate_accepts_synthetic_task_provider_call_identity() {
        let s = root_session();
        record_user(&s, "investigate");
        record_assistant(&s, "infer-1", "delegating");
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
        .unwrap();

        let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .unwrap()
            .unwrap();
        let calls = assistant_calls(&r.history[1]);
        assert_eq!(calls[0].id, "task-synthetic");
        assert_eq!(calls[0].call_id.as_deref(), Some("task-synthetic"));
        let payload = &calls[0].function.arguments["payload"];
        assert!(payload.get("provider_call_id").is_none());
        assert!(payload.get("provider_call_id_source").is_none());
        assert!(payload.get("provider_identity").is_none());
        let results = tool_results(&r.history[2]);
        assert_eq!(results[0].id, "task-synthetic");
        assert_eq!(results[0].call_id.as_deref(), Some("task-synthetic"));
    }

    #[test]
    fn strict_responses_rehydrate_preserves_interactive_task_provider_call_identity() {
        let s = root_session();
        record_user(&s, "investigate");
        record_assistant(&s, "infer-1", "delegating");
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
        .unwrap();

        let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .unwrap()
            .unwrap();
        let calls = assistant_calls(&r.history[1]);
        assert_eq!(calls[0].id, "task-interactive");
        assert_eq!(
            calls[0].call_id.as_deref(),
            Some("call-provider-interactive")
        );
        let payload = &calls[0].function.arguments["payload"];
        assert!(payload.get("noninteractive").is_none());
        assert!(payload.get("provider_call_id").is_none());
        assert!(payload.get("provider_call_id_source").is_none());
        assert!(payload.get("provider_identity").is_none());
        let results = tool_results(&r.history[2]);
        assert_eq!(results[0].id, "task-interactive");
        assert_eq!(
            results[0].call_id.as_deref(),
            Some("call-provider-interactive")
        );
    }

    #[test]
    fn strict_responses_rehydrate_backfills_legacy_completed_task_identity() {
        let s = root_session();
        record_user(&s, "investigate");
        record_assistant(&s, "infer-1", "delegating");
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-legacy"),
            &json!({ "child_agent": "explore", "task_call_id": "task-legacy", "prompt": "look" }),
        )
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some("explore"),
            Some("task-legacy"),
            &json!({ "report": "done" }),
        )
        .unwrap();

        let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .unwrap()
            .unwrap();
        let calls = assistant_calls(&r.history[1]);
        assert_eq!(calls[0].call_id.as_deref(), Some("task-legacy"));
        let results = tool_results(&r.history[2]);
        assert_eq!(results[0].call_id.as_deref(), Some("task-legacy"));
    }

    #[test]
    fn strict_responses_rehydrate_rejects_mismatched_task_report_identity() {
        let s = root_session();
        record_user(&s, "investigate");
        record_assistant(&s, "infer-1", "delegating");
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
        .unwrap();

        let err = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .unwrap_err();
        let repair = err
            .downcast_ref::<RehydrateRepairRequired>()
            .expect("strict Responses failure is structured");
        assert_eq!(repair.failure_kind, "mismatched_pair");
        assert_eq!(repair.failing_tool_call_ids, vec!["task-1"]);
    }

    #[test]
    fn rehydrate_prunes_completed_long_task_prompt() {
        let s = root_session();
        record_user(&s, "investigate");
        record_assistant(&s, "infer-1", "delegating");
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
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some("explore"),
            Some("task-1"),
            &json!({ "report": "found three modules" }),
        )
        .unwrap();

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
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

    #[test]
    fn rebuilds_parallel_independent_task_calls_as_one_assistant_turn() {
        let s = root_session();
        record_user(&s, "investigate auth and db");
        record_assistant(&s, "infer-1", "delegating both");
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
            .unwrap();
            s.record_event(
                crate::db::session_log::SessionEventKind::SubagentReport,
                Some(child),
                Some(call_id),
                &json!({ "child_agent": child, "task_call_id": call_id, "report": report }),
            )
            .unwrap();
        }
        record_assistant(&s, "infer-2", "thanks");

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
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

    #[test]
    fn rebuilds_parallel_task_delegation_with_aggregate_report() {
        let s = root_session();
        record_user(&s, "investigate auth and db");
        record_assistant(&s, "infer-1", "delegating");
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
            .unwrap();
        }
        record_assistant(&s, "infer-2", "thanks");

        let r = rehydrate_session_with_policy(&s.db, s.id, "Build", RehydratePolicy::strict())
            .unwrap()
            .unwrap();
        let h = r.history;
        let calls = assistant_calls(&h[1]);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "task");
        assert_eq!(calls[0].call_id.as_deref(), Some("call-provider-batch"));
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
        assert_eq!(results[0].call_id.as_deref(), Some("call-provider-batch"));
        validate_pairing(&h).expect("provider-valid");
    }

    /// Subagent (non-root) turns are excluded from the root model history.
    #[test]
    fn excludes_subagent_turns() {
        let s = root_session();
        record_user(&s, "go");
        record_assistant(&s, "infer-1", "root says hi");
        // An explore subagent's own assistant turn — must not leak in.
        s.record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("explore"),
            Some("infer-x"),
            &json!({ "text": "subagent internal reasoning" }),
        )
        .unwrap();

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
        let h = r.history;
        assert_eq!(h.len(), 2);
        assert_eq!(assistant_text(&h[1]), "root says hi");
    }

    /// CRITICAL INVARIANT (implementation note): a `user_note`
    /// session event (`/note <text>`) is NEVER reconstructed into the
    /// model-bound history. It sits chronologically between two real turns yet
    /// rehydration skips it entirely — the rebuilt context is byte-identical to
    /// one with no note at all, so prior note text never reaches the model.
    #[test]
    fn rehydration_skips_user_note_events() {
        let s = root_session();
        record_user(&s, "first");
        record_assistant(&s, "infer-1", "ok");
        // A user note recorded mid-conversation (between turns).
        s.record_event(
            crate::db::session_log::SessionEventKind::UserNote,
            Some("Build"),
            None,
            &json!({ "text": "remember: secret sk-NOTE-123 caused the bug" }),
        )
        .unwrap();
        record_user(&s, "second");
        record_assistant(&s, "infer-2", "done");

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
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
    #[test]
    fn empty_session_rehydrates_to_none() {
        let s = root_session();
        assert!(rehydrate_session(&s.db, s.id, "Build").unwrap().is_none());
    }

    /// The ledger re-applies, yielding byte-identical pruned bodies: the
    /// elided tool-result body becomes the exact marker.
    #[test]
    fn ledger_reapply_yields_byte_identical_pruned_form() {
        let s = root_session();
        record_user(&s, "read twice");
        record_assistant(&s, "infer-1", "");
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "/f" }),
            json!({ "path": "/f" }),
            "FIRST BODY",
        );
        record_assistant(&s, "infer-2", "");
        record_tool(
            &s,
            "tc-2",
            "read",
            json!({ "path": "/f" }),
            json!({ "path": "/f" }),
            "SECOND BODY",
        );

        // Persist a ledger that elides the older read (tc-1).
        let ledger = PruneLedger {
            elided: vec![LedgerEntry {
                original_event_id: "tc-1".into(),
                reason: "snapshot superseded".into(),
                partial_body: None,
            }],
            watermark: 4,
        };
        s.db.save_prune_ledger(s.id, &ledger).unwrap();

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
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
    #[test]
    fn bad_ledger_falls_back_to_full_unpruned() {
        let s = root_session();
        record_user(&s, "read once");
        record_assistant(&s, "infer-1", "");
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "/f" }),
            json!({ "path": "/f" }),
            "ONLY BODY",
        );

        // Ledger points at a non-existent id.
        let ledger = PruneLedger {
            elided: vec![LedgerEntry {
                original_event_id: "ghost".into(),
                reason: "snapshot superseded".into(),
                partial_body: None,
            }],
            watermark: 9,
        };
        s.db.save_prune_ledger(s.id, &ledger).unwrap();

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
        assert!(r.ledger_fallback, "inconsistent ledger → fallback");
        assert_eq!(r.watermark, 0, "fallback resets the watermark");
        // Body is the full original — NOT a marker, NOT dropped.
        assert_eq!(tool_result_body(&r.history[2]), "ONLY BODY");
    }

    /// A `tool_call` timeline event with no matching audit row (its result
    /// body never landed durably) is HEALED with an honest aborted stub —
    /// the prior conversation rebuilds instead of dead-ending, and the heal
    /// is surfaced as a `Recovery::ResumeHeal` audit record.
    #[test]
    fn missing_tool_call_row_is_stubbed_not_an_error() {
        let s = root_session();
        record_user(&s, "go");
        record_assistant(&s, "infer-1", "calling a tool");
        // A tool_call timeline event WITHOUT the audit row.
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some("orphan"),
            &json!({ "tool": "read", "wire_input": { "path": "/f" }, "output": "x" }),
        )
        .unwrap();

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
        // The stubbed call is paired with an honest aborted result.
        validate_pairing(&r.history).expect("healed history is provider-valid");
        let calls = assistant_calls(&r.history[1]);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "orphan");
        assert_eq!(calls[0].function.name, "read");
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
    #[test]
    fn rehydration_does_not_redact() {
        let s = root_session();
        record_user(&s, "my token is sk-SECRET-123");
        record_assistant(&s, "infer-1", "noted: sk-SECRET-123");
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "/f" }),
            json!({ "path": "/f" }),
            "file contains sk-SECRET-123",
        );
        record_assistant(&s, "infer-2", "");

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
        let h = r.history;
        // Verbatim — no scrub applied (the send path scrubs, as today).
        assert_eq!(user_text(&h[0]), "my token is sk-SECRET-123");
        assert_eq!(assistant_text(&h[1]), "noted: sk-SECRET-123");
        assert_eq!(tool_result_body(&h[2]), "file contains sk-SECRET-123");
    }

    /// A `/compact` successor that has ALREADY had turns rebuilds from its
    /// transcript (rehydration returns `Some`). The session_worker gate
    /// keys off this `Some`/`None` to skip seed-tool re-execution — the two
    /// paths are mutually exclusive (implementation note).
    #[test]
    fn successor_with_turns_rebuilds_from_transcript() {
        let s = root_session();
        record_user(&s, "continue from compact");
        record_assistant(&s, "infer-1", "carrying on");
        let r = rehydrate_session(&s.db, s.id, "Build").unwrap();
        assert!(
            r.is_some(),
            "a successor with turns rebuilds → seeds are skipped"
        );
        // A fresh successor with NO recorded turns rehydrates to None → the
        // seed-tool path runs instead.
        let fresh = root_session();
        assert!(
            rehydrate_session(&fresh.db, fresh.id, "Build")
                .unwrap()
                .is_none()
        );
    }

    /// No ledger at all → the rebuilt full form IS the pruned form (no
    /// fallback flag, watermark 0).
    #[test]
    fn no_ledger_rebuilds_full_form() {
        let s = root_session();
        record_user(&s, "hi");
        record_assistant(&s, "infer-1", "hello");
        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
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
                    id: (*id).to_string(),
                    call_id: None,
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
            content: OneOrMany::many(calls).unwrap(),
        }
    }

    /// One tool_result user message (the live wire shape).
    fn result_msg(id: &str, body: &str) -> Message {
        stub_result_message(id, body)
    }

    /// A `task` delegation whose `subagent_report` never landed is HEALED
    /// with an honest "delegation did not complete" stub instead of erroring.
    #[test]
    fn missing_subagent_report_is_stubbed_not_an_error() {
        let s = root_session();
        record_user(&s, "investigate");
        record_assistant(&s, "infer-1", "delegating");
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-1"),
            &json!({ "child_agent": "explore", "task_call_id": "task-1", "prompt": "look" }),
        )
        .unwrap();
        // No SubagentReport recorded.
        record_assistant(&s, "infer-2", "continuing without it");

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
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
    #[test]
    fn heal_stubs_orphan_tool_use() {
        let mut history = vec![
            Message::user("go"),
            assistant_with_calls(&["c1"]),
            // No tool_result follows c1.
            Message::user("next"),
        ];
        let mut heals = Vec::new();
        heal_pairing(&mut history, &mut heals);
        validate_pairing(&history).expect("provider-valid after heal");
        // A stub result was inserted right after the assistant turn.
        assert_eq!(tool_result_body(&history[2]), ABORTED_CALL_BODY);
        assert_eq!(
            heals,
            vec![Recovery::ResumeHeal {
                kind: "stub_orphan_tool_call",
                id: "c1".into(),
            }]
        );
    }

    /// An orphan tool_result (no preceding tool_use of its id) is dropped;
    /// the healed history validates and the heal is recorded.
    #[test]
    fn heal_drops_orphan_tool_result() {
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
    #[test]
    fn heal_drops_only_the_orphan_sibling_result() {
        // Assistant issues c1 only; a user message carries BOTH c1 (paired)
        // and ghost (orphan) results.
        let mixed = Message::User {
            content: OneOrMany::many(vec![
                UserContent::ToolResult(ToolResult {
                    id: "c1".into(),
                    call_id: None,
                    content: OneOrMany::one(ToolResultContent::text("real")),
                }),
                UserContent::ToolResult(ToolResult {
                    id: "ghost".into(),
                    call_id: None,
                    content: OneOrMany::one(ToolResultContent::text("stale")),
                }),
            ])
            .unwrap(),
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
    #[test]
    fn heal_handles_mixed_orphans_in_one_pass() {
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
    #[test]
    fn heal_is_idempotent() {
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
    #[test]
    fn live_heal_structural_then_sibling_pairs_without_double_stubbing() {
        // history ends with the assistant turn carrying BOTH calls; no result
        // for either is in history yet (the dispatch loop returned early on
        // `task`).
        let mut history = vec![
            Message::user("do X"),
            assistant_with_calls(&["task", "read"]),
        ];
        // The structural tool's own result is injected by the driver as the
        // next prompt (out of band) — it is NOT in history.
        let prompt = result_msg("task", "delegation result");

        // BEFORE the heal: the send sequence is NOT provider-valid (the
        // sibling `read` tool_use has no matching tool_result anywhere).
        let mut unhealed = history.clone();
        unhealed.push(prompt.clone());
        assert!(
            validate_pairing(&unhealed).is_err(),
            "without the heal the orphan sibling read makes the send malformed"
        );

        let heals = heal_live_history(&mut history, &prompt);

        // Exactly one heal: the orphan sibling `read` was stubbed; `task` was
        // NOT (its result rides the prompt).
        assert_eq!(
            heals,
            vec![Recovery::ResumeHeal {
                kind: "stub_orphan_tool_call",
                id: "read".into(),
            }],
            "only the sibling read is stubbed; the structural task is not double-stubbed"
        );

        // The stub landed at the end of history (right after the assistant turn,
        // before the prompt continues the run on the wire).
        assert_eq!(history.len(), 3);
        assert_eq!(tool_result_body(&history[2]), ABORTED_CALL_BODY);
        assert_eq!(result_ids(&history[2]), vec!["read".to_string()]);

        // The full wire send sequence (history + prompt) is provider-valid:
        // assistant(task, read) → user(stub read) → user(result task).
        let mut wire = history.clone();
        wire.push(prompt);
        validate_pairing(&wire).expect("history + prompt is provider-valid");
    }

    /// The live heal is a no-op (byte-identical, no heals) on an already-paired
    /// turn — the overwhelmingly common path, run every turn.
    #[test]
    fn live_heal_is_a_noop_on_paired_history() {
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
    #[test]
    fn live_heal_is_idempotent_across_turns() {
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
    #[test]
    fn mixed_orphans_resume_successfully_end_to_end() {
        let s = root_session();
        record_user(&s, "do work");
        record_assistant(&s, "infer-1", "calling read");
        // Orphan tool-call: timeline event, no audit row → stubbed.
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some("orphan-call"),
            &json!({ "tool": "read", "wire_input": { "path": "/f" }, "output": "" }),
        )
        .unwrap();
        record_assistant(&s, "infer-2", "delegating");
        // Task delegation with no report → stubbed.
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-1"),
            &json!({ "child_agent": "explore", "task_call_id": "task-1", "prompt": "p" }),
        )
        .unwrap();
        record_assistant(&s, "infer-3", "wrapping up");

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
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
    #[test]
    fn clean_transcript_produces_no_heals() {
        let s = root_session();
        record_user(&s, "read the file");
        record_assistant(&s, "infer-1", "reading");
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "/f" }),
            json!({ "path": "/f" }),
            "body",
        );
        record_assistant(&s, "infer-2", "done");

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
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
    #[test]
    fn composed_heal_then_validate_is_idempotent_on_rebuilt_history() {
        let s = root_session();
        record_user(&s, "go");
        record_assistant(&s, "infer-1", "calling a tool");
        // Orphan tool-call: timeline event, no audit row → healed at rebuild.
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some("orphan"),
            &json!({ "tool": "read", "wire_input": { "path": "/f" }, "output": "x" }),
        )
        .unwrap();
        record_assistant(&s, "infer-2", "done");

        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
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
    #[test]
    fn composed_resume_cycle_is_stable() {
        let s = root_session();
        record_user(&s, "do work");
        record_assistant(&s, "infer-1", "calling read");
        // Orphan tool-call (no audit row) → stubbed at rebuild.
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some("orphan-call"),
            &json!({ "tool": "read", "wire_input": { "path": "/f" }, "output": "" }),
        )
        .unwrap();
        record_assistant(&s, "infer-2", "delegating");
        // Task delegation with no report → stubbed at rebuild.
        s.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some("Build"),
            Some("task-1"),
            &json!({ "child_agent": "explore", "task_call_id": "task-1", "prompt": "p" }),
        )
        .unwrap();
        record_assistant(&s, "infer-3", "wrapping up");

        let first = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
        let second = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
        // Same healed history and the same heal records on the second resume.
        assert_eq!(first.history, second.history, "resume cycle is stable");
        assert_eq!(first.heals, second.heals, "no new ResumeHeal records");
        validate_pairing(&second.history).expect("provider-valid on re-resume");
    }

    /// Order dependency: heal runs BEFORE validate, so a transcript with
    /// orphans rehydrates successfully (Ok) instead of hard-erroring. Proven by
    /// contrast: the rebuilt-but-UNhealed history would FAIL `validate_pairing`,
    /// yet `rehydrate_session` (heal-then-validate) returns Ok.
    #[test]
    fn composed_heal_precedes_validate_so_orphans_resume() {
        let s = root_session();
        record_user(&s, "go");
        record_assistant(&s, "infer-1", "calling a tool");
        // Orphan tool-call with no audit row → an orphan tool_use at rebuild.
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some("orphan"),
            &json!({ "tool": "read", "wire_input": { "path": "/f" }, "output": "x" }),
        )
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
        let r = rehydrate_session(&s.db, s.id, "Build").unwrap().unwrap();
        validate_pairing(&r.history).expect("heal ran before validate → Ok");
        assert!(!r.heals.is_empty());
    }

    /// Genuine-bug guard (must never fire normally): a post-heal
    /// `validate_pairing` failure remains a HARD ERROR. We feed an explicitly
    /// unpairable history straight to the validator (bypassing heal) to pin
    /// that the final assertion is real and not weakened to a warning.
    #[test]
    fn composed_post_heal_validate_failure_is_a_hard_error() {
        // An assistant tool_use with no matching tool_result anywhere — the
        // shape heal is designed to prevent, so if it ever reaches validate
        // unhealed, validate must hard-error.
        let unpaired = vec![Message::user("go"), assistant_with_calls(&["c1"])];
        let err = validate_pairing(&unpaired).expect_err("must be a hard error");
        assert!(err.to_string().contains("unpaired tool_use"), "got: {err}");
    }

    // ---- wire history snapshot (implementation note) -----

    #[test]
    fn rehydrate_user_message_prefers_display_text() {
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
        .unwrap();

        let snapshot = history_snapshot(&s.db, s.id, "Build").unwrap();
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

    #[test]
    fn rehydrate_user_message_legacy_text_fallback() {
        let s = root_session();
        record_user(&s, "legacy wire text");

        let snapshot = history_snapshot(&s.db, s.id, "Build").unwrap();
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
    #[test]
    fn history_snapshot_includes_messages_and_tool_calls_in_order() {
        let s = root_session();
        record_user(&s, "read the file");
        record_assistant(&s, "infer-1", "let me read it");
        record_tool(
            &s,
            "tc-1",
            "read",
            // Original carries a typo field the wire form drops (§14).
            json!({ "path": "src/main.rs", "typo": true }),
            json!({ "path": "src/main.rs" }),
            "fn main() {}",
        );

        let snap = history_snapshot(&s.db, s.id, "Build").unwrap();
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

    #[test]
    fn history_snapshot_conn_matches_db_wrapper_byte_for_byte() {
        let s = root_session();
        record_user(&s, "read the file");
        record_assistant(&s, "infer-1", "let me read it");
        record_tool(
            &s,
            "tc-1",
            "read",
            json!({ "path": "src/main.rs", "typo": true }),
            json!({ "path": "src/main.rs" }),
            "fn main() {}",
        );

        let wrapped = history_snapshot(&s.db, s.id, "Build").unwrap();
        let direct =
            s.db.read_blocking(|conn| history_snapshot_conn(conn, s.id, "Build"))
                .unwrap();

        assert_eq!(
            serde_json::to_value(&direct).unwrap(),
            serde_json::to_value(&wrapped).unwrap()
        );
    }

    #[test]
    fn history_snapshot_since_replays_only_rows_after_cursor() {
        let s = root_session();
        record_user(&s, "already rendered");
        record_assistant(&s, "infer-1", "also rendered");
        let cursor =
            s.db.list_session_events(s.id)
                .unwrap()
                .into_iter()
                .map(|row| row.seq)
                .max()
                .unwrap();
        record_user(&s, "missed user");
        record_assistant(&s, "infer-2", "missed assistant");

        let replay =
            s.db.read_blocking(|conn| {
                history_snapshot_since_with_active_subagent_conn(conn, s.id, "Build", None, cursor)
            })
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
    async fn attach_read_conn_shape_completes_without_relocking() {
        let s = root_session();
        record_user(&s, "go");
        record_assistant(&s, "infer-1", "done");
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

    #[test]
    fn history_snapshot_carries_compact_boundary_brief_when_present() {
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
        .unwrap();

        let snap = history_snapshot(&s.db, s.id, "Build").unwrap();
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

    #[test]
    fn session_compacted_persists_handoff() {
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
                successor_short_id: &s.short_id,
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
        )
        .unwrap();
        let raw_data: String = s
            .db
            .read_blocking(|conn| {
                Ok(conn.query_row(
                    "SELECT data_json FROM session_events WHERE session_id = ?1 AND type = 'session_compacted'",
                    [s.id.to_string()],
                    |row| row.get(0),
                )?)
            })
            .unwrap();
        let raw_data: serde_json::Value = serde_json::from_str(&raw_data).unwrap();
        assert!(raw_data["handoff_ref"].as_str().is_some());
        assert!(raw_data.get("brief_text").is_none());
        assert!(raw_data.get("tail_messages").is_none());
        assert!(raw_data.to_string().len() < 16 * 1024);
        assert_eq!(raw_data["tail_trimmed"], 1);

        let event =
            s.db.list_session_events(s.id)
                .unwrap()
                .into_iter()
                .find(|event| event.kind == "session_compacted")
                .unwrap();
        assert_eq!(event.data["handoff_text"], handoff);
        assert!(event.data["tail_messages"].is_array());

        let snapshot = history_snapshot(&s.db, s.id, "Build").unwrap();
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

        let preview = s.db.read_session_messages(s.id, None, 10).unwrap().0;
        assert!(preview.iter().any(|message| message.text == handoff));
    }

    #[test]
    fn compaction_payload_refs_are_session_scoped() {
        let owner = root_session();
        let other = root_session();
        let payload_id = Uuid::new_v4();
        let payload = json!({"handoff_text": "owner secret"}).to_string();
        owner
            .db
            .store_compaction_payload(payload_id, owner.id, &payload)
            .unwrap();

        assert_eq!(
            owner
                .db
                .compaction_payload(owner.id, &payload_id.to_string())
                .unwrap()
                .as_deref(),
            Some(payload.as_str())
        );
        assert!(
            owner
                .db
                .compaction_payload(other.id, &payload_id.to_string())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn compaction_entries_survive_replay() {
        let s = root_session();
        let seq = s
            .record_session_compacted_with_source(
                "Build",
                crate::session::SessionCompactionRecord {
                    successor_session_id: s.id,
                    successor_short_id: &s.short_id,
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
            )
            .unwrap();
        let replay =
            s.db.read_blocking(|conn| {
                history_snapshot_since_with_active_subagent_conn(conn, s.id, "Build", None, seq - 1)
            })
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

    #[test]
    fn compacted_model_history_rehydrates_handoff_and_tail() {
        let s = root_session();
        let tail = vec![
            Message::user("recent user"),
            Message::assistant("recent answer"),
        ];
        s.record_session_compacted_with_source(
            "Build",
            crate::session::SessionCompactionRecord {
                successor_session_id: s.id,
                successor_short_id: &s.short_id,
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
        )
        .unwrap();
        let restored = rehydrate_session(&s.db, s.id, "Build")
            .unwrap()
            .unwrap()
            .history;
        assert_eq!(
            serde_json::to_value(restored).unwrap(),
            serde_json::to_value([vec![Message::user("exact handoff")], tail].concat()).unwrap()
        );
    }

    /// Recovery chip survives into the snapshot for a repaired tool call
    /// (wire-vs-user split, GOALS §14).
    #[test]
    fn history_snapshot_carries_recovery_chip() {
        let s = root_session();
        record_user(&s, "edit it");
        record_assistant(&s, "infer-1", "");
        s.record_tool_call(crate::session::ToolCallRow {
            event_id: Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent: "Build".into(),
            call_id: "tc-1".into(),
            identity: crate::session::ToolCallProviderIdentity::default(),
            tool: "read".into(),
            path: None,
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
            llm_mode: crate::config::extended::LlmMode::default(),
            shape_fingerprint: None,
            hint: None,
        })
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::ToolCall,
            Some("Build"),
            Some("tc-1"),
            &json!({ "tool": "read", "wire_input": { "path": "/f" }, "output": "ok" }),
        )
        .unwrap();

        let snap = history_snapshot(&s.db, s.id, "Build").unwrap();
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
    #[test]
    fn history_snapshot_empty_session_is_empty() {
        let s = root_session();
        assert!(history_snapshot(&s.db, s.id, "Build").unwrap().is_empty());
    }

    /// A session with tool calls but no assistant text still renders the
    /// subset that exists, in order (edge case: subset-only history).
    #[test]
    fn history_snapshot_tool_calls_without_assistant_text() {
        let s = root_session();
        record_user(&s, "go");
        record_tool(
            &s,
            "tc-1",
            "bash",
            json!({ "command": "ls" }),
            json!({ "command": "ls" }),
            "a.rs",
        );
        let snap = history_snapshot(&s.db, s.id, "Build").unwrap();
        assert_eq!(snap.len(), 2);
        assert!(matches!(snap[0], proto::HistoryEntry::User { .. }));
        assert!(matches!(snap[1], proto::HistoryEntry::ToolCall { .. }));
    }

    /// Subagent (non-root) turns are excluded from the snapshot, exactly as
    /// model rehydration excludes them — single source of truth, same gate.
    #[test]
    fn history_snapshot_excludes_subagent_turns() {
        let s = root_session();
        record_user(&s, "go");
        record_assistant(&s, "infer-1", "root says hi");
        s.record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("explore"),
            Some("infer-x"),
            &json!({ "text": "subagent internal" }),
        )
        .unwrap();
        let snap = history_snapshot(&s.db, s.id, "Build").unwrap();
        assert_eq!(snap.len(), 2);
        assert!(matches!(snap[1], proto::HistoryEntry::Assistant { .. }));
    }

    #[test]
    fn history_snapshot_active_subagent_includes_running_row_and_child_turns() {
        let s = root_session();
        record_user(&s, "build it");
        record_assistant(&s, "infer-1", "delegating");
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
        .unwrap();
        s.record_event(
            crate::db::session_log::SessionEventKind::AssistantMessage,
            Some("builder"),
            Some("infer-child"),
            &json!({ "text": "child progress" }),
        )
        .unwrap();

        let active = proto::ActiveSubagent {
            parent: "Build".into(),
            child: "builder".into(),
            task_call_id: "task-1".into(),
            label: "default".into(),
        };
        let snap =
            s.db.read_blocking(|conn| {
                history_snapshot_with_active_subagent_conn(conn, s.id, "Build", Some(&active))
            })
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

        let root_only = history_snapshot(&s.db, s.id, "Build").unwrap();
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
            | proto::HistoryEntry::CompactBoundary { .. }
            | proto::HistoryEntry::Subagent { .. }
            | proto::HistoryEntry::InferenceError { .. } => panic!("not a message entry"),
        }
    }
}

#[cfg(test)]
mod subagent_observe_tests {
    use super::*;
    use crate::db::session_log::SessionEventKind;
    use serde_json::json;

    #[test]
    fn subagent_snapshot_isolates_interleaved_runs_with_same_agent() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/tmp/project", "Build")
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
            },
            &json!({ "text": "brief a" }),
        )
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
            },
            &json!({ "text": "brief b" }),
        )
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
            },
            &json!({ "text": "answer a", "reasoning": "ra" }),
        )
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
            },
            &json!({ "text": "answer b", "reasoning": "rb" }),
        )
        .unwrap();

        let child_a = db
            .read_blocking(|conn| subagent_history_snapshot_conn(conn, sid, "task-a", "default"))
            .unwrap();
        assert_eq!(child_a.len(), 2);
        assert!(matches!(&child_a[0], proto::HistoryEntry::User { text, .. } if text == "brief a"));
        assert!(
            matches!(&child_a[1], proto::HistoryEntry::Assistant { text, reasoning, .. } if text == "answer a" && reasoning == "ra")
        );

        let child_b = db
            .read_blocking(|conn| subagent_history_snapshot_conn(conn, sid, "task-b", "default"))
            .unwrap();
        assert_eq!(child_b.len(), 2);
        assert!(matches!(&child_b[0], proto::HistoryEntry::User { text, .. } if text == "brief b"));
        assert!(
            matches!(&child_b[1], proto::HistoryEntry::Assistant { text, reasoning, .. } if text == "answer b" && reasoning == "rb")
        );
    }

    #[test]
    fn root_snapshot_hides_finished_child_rows() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/tmp/project", "Build")
            .unwrap();
        let sid = session.session_id;
        db.insert_session_event(
            sid,
            SessionEventKind::UserMessage,
            Some("Build"),
            None,
            &json!({ "text": "root prompt" }),
        )
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
            },
            &json!({ "text": "hidden child", "reasoning": "" }),
        )
        .unwrap();

        let root = db
            .read_blocking(|conn| {
                history_snapshot_with_active_subagent_conn(conn, sid, "Build", None)
            })
            .unwrap();
        assert_eq!(root.len(), 1);
        assert!(
            matches!(&root[0], proto::HistoryEntry::User { text, .. } if text == "root prompt")
        );
    }
}
