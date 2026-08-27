//! Deterministic context pruning — snapshot dedup (`plan.md` T6.b/T6.d).
//!
//! The single rule that both the live "% prunable" projection
//! ([`dedup_plan`]) and the actual `/prune` execution ([`apply_plan`])
//! consume. Because they share one function, the figure the status line
//! shows always equals what `/prune` then removes — the stable-contract
//! property GOALS §1a / `plan.md` T6.d require.
//!
//! ## What it does
//!
//! For every snapshot-class tool call of *exact identity* (same
//! canonical path + identical args JSON), all but the most recent
//! result **body** is redundant given the newer one. We replace the
//! superseded body with a [`Part::Elided`] marker, keeping the
//! `tool_use`/`tool_result` **call shape** intact:
//!
//! - the assistant `ToolCall` is never touched;
//! - the `ToolResult` keeps its `id` + `call_id` (so the provider's
//!   tool_use↔tool_result pairing stays valid, and reasoning blocks
//!   that reference the earlier read still parse);
//! - only the `ToolResultContent::Text` body is rewritten to the
//!   marker string.
//!
//! ## Wire-only (GOALS §14)
//!
//! Elision touches the **model-bound** `Vec<Message>` history only. The
//! on-disk `tool_calls` rows and the TUI scrollback are driven by a
//! separate event stream and keep full fidelity, so the original body
//! is always recoverable (`cockpit session show`). The marker tells the
//! model to use the later full result that is still in the wire history;
//! `original_event_id` remains in the prune ledger for audit readers.
//!
//! ## Snapshot-class tools
//!
//! `read` and the non-mutating codebase-intelligence tools
//! (`code`, `graph`, `search`). Deliberately excluded this pass (see
//! `plan.md` T6.d): `bash` (the command is interpretive context;
//! classifying which commands are snapshots is the hard problem) and
//! `edit`/`write` (their args carry semantic content).

pub use crate::db::prune_ledger::{LedgerEntry, PruneLedger};

use crate::config::providers::{CacheConfig, CacheMode};
use crate::engine::message::{AssistantContent, Message};
use crate::tools::shell_compress;
use rig::message::{ToolResultContent, UserContent};

mod overlap;
pub use overlap::OVERLAP_REASON;

/// Tools whose repeated identical calls produce a redundant snapshot
/// body. `read` plus the non-mutating intel tools. `bash`, `edit`, and
/// `write` are intentionally absent (see module docs).
pub const SNAPSHOT_TOOLS: &[&str] = &["read", "code", "graph", "search"];

pub const REASON_TOOL_RESULT_CONDENSED: &str = "tool result condensed";

const PRUNE_BOUNDARY_CONDENSE_TOOLS: &[&str] = &["bash"];
const PRUNE_BOUNDARY_CONDENSE_EXCLUDED_TOOLS: &[&str] =
    &["read", "read", "write", "edit", "unlock"];

fn is_snapshot_tool(name: &str) -> bool {
    SNAPSHOT_TOOLS.contains(&name)
}

fn is_prune_boundary_condense_tool(name: &str) -> bool {
    PRUNE_BOUNDARY_CONDENSE_TOOLS.contains(&name)
        && !PRUNE_BOUNDARY_CONDENSE_EXCLUDED_TOOLS.contains(&name)
}

fn contains_overlap_marker(body: &str) -> bool {
    let marker = overlap::overlap_marker_line();
    body.lines().any(|line| line == marker)
}

fn exact_snapshot_marker(body: &str, _call_id: &str) -> bool {
    body == (Elision {
        original_event_id: String::new(),
        reason: REASON_SNAPSHOT_SUPERSEDED,
    })
    .marker_text()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondenseCandidate {
    pub history_index: usize,
    pub tool: String,
    pub call_id: String,
    pub original_body: String,
    pub condensed_body: String,
}

/// Render the only model-visible representation of a prune-boundary body.
/// The original remains in the session artifact store; `condensed_body` is a
/// planning aid and must never become a second ad-hoc retrieval protocol.
pub fn render_prune_artifact_frame(
    candidate: &CondenseCandidate,
    artifact: Option<&crate::db::text_artifacts::TextArtifact>,
    unavailable_reason: Option<&str>,
) -> String {
    render_prune_artifact_frame_with_agent(candidate, artifact, unavailable_reason, None)
}

/// Render a prune frame with the exact agent provenance that the owning
/// `context_pruned` event persisted.  The generic helper keeps the historical
/// test/planning path deterministic (`agent_id: null`), while the live
/// composition supplies its active agent so an unavailable quota frame and its
/// restart regeneration cannot diverge.
pub fn render_prune_artifact_frame_with_agent(
    candidate: &CondenseCandidate,
    artifact: Option<&crate::db::text_artifacts::TextArtifact>,
    unavailable_reason: Option<&str>,
    agent_id: Option<&str>,
) -> String {
    let (
        content,
        artifact_id,
        host_captured_bytes,
        host_original_bytes,
        host_dropped_bytes,
        stored_source_bytes,
        content_bytes,
        provenance_json,
    ) = if let Some(artifact) = artifact {
        (
            artifact.content.as_str(),
            Some(artifact.artifact_id),
            artifact.host_captured_bytes,
            artifact.host_original_bytes,
            artifact.host_dropped_bytes,
            artifact.stored_source_bytes,
            artifact.content_bytes,
            artifact.provenance_json.as_str(),
        )
    } else {
        let agent_id = agent_id
            .map(|agent_id| serde_json::to_string(agent_id).expect("agent id is serializable"))
            .unwrap_or_else(|| "null".to_owned());
        let provenance = format!(
            "{{\"agent_id\":{},\"tool\":{},\"call_id\":{}}}",
            agent_id,
            serde_json::to_string(&candidate.tool).expect("tool name is serializable"),
            serde_json::to_string(&candidate.call_id).expect("call ID is serializable"),
        );
        let bytes = candidate.original_body.len();
        let (head, tail) =
            crate::engine::text_artifact_frame::utf8_preview_pair(&candidate.original_body);
        return crate::engine::text_artifact_frame::render_artifact_frame(
            &crate::engine::text_artifact_frame::ArtifactFrame {
                status: "unavailable",
                reason: unavailable_reason.or(Some("persistence_unavailable")),
                artifact_id: None,
                kind: "tool_result",
                capture_reason: "prune_boundary",
                provenance_json: &provenance,
                host_captured_bytes: bytes,
                host_original_bytes: bytes,
                host_dropped_bytes: 0,
                stored_source_bytes: bytes,
                content_bytes: bytes,
                line_count: candidate.original_body.lines().count(),
                preview_head: head,
                preview_tail: tail,
            },
        );
    };
    let (preview_head, preview_tail) =
        crate::engine::text_artifact_frame::utf8_preview_pair(content);
    crate::engine::text_artifact_frame::render_artifact_frame(
        &crate::engine::text_artifact_frame::ArtifactFrame {
            status: "available",
            reason: None,
            artifact_id,
            kind: "tool_result",
            capture_reason: "prune_boundary",
            provenance_json,
            host_captured_bytes,
            host_original_bytes,
            host_dropped_bytes,
            stored_source_bytes,
            content_bytes,
            line_count: content.lines().count(),
            preview_head,
            preview_tail,
        },
    )
}

/// A reasoning-block / superseded snapshot body that has been removed
/// from the wire history. The single mechanism for body removal: it
/// rewrites a tool-result body, never a call's shape.
///
/// `original_event_id` is the originating tool call's `id` (the same
/// value the `tool_calls` row keys on), retained for the ledger/audit
/// reader. `reason` is a terse, human-readable explanation rendered into
/// the marker text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elision {
    pub original_event_id: String,
    pub reason: &'static str,
}

impl Elision {
    /// The marker body the model sees in place of the elided snapshot.
    /// One line; terse (token economy §10). The newest identical call's
    /// full body is still in context, so the model can read it there.
    pub fn marker_text(&self) -> String {
        format!(
            "[elided: {} — a later identical call in this conversation still carries the full result; use that one. Not retrievable and not worth re-running.]",
            self.reason
        )
    }

    /// True when a tool-result body is **wholly** an elision marker (so we
    /// never double-count or re-elide it). Matches the `[elided: ` prefix
    /// `marker_text` emits.
    pub fn is_marker(body: &str) -> bool {
        body.starts_with("[elided:")
    }

    /// True when a body carries an elision marker anywhere — a whole-body
    /// marker ([`Self::is_marker`]) OR a partial-body overlap-merge result
    /// (which keeps non-overlapping content and embeds a `[elided:` marker
    /// line for each elided sub-range). Used by the live-elided scan and the
    /// ledger capture so a partial elision is recognized as pruned state, not
    /// mistaken for a still-full body (which would be re-walked and double-
    /// counted).
    pub fn contains_marker(body: &str) -> bool {
        body.lines().any(|l| l.starts_with("[elided:"))
    }
}

/// One body to elide: its index in the history `Vec<Message>` plus the
/// marker to write there. Produced by [`dedup_plan`]; consumed by
/// [`apply_plan`] and the token-savings projection.
#[derive(Debug, Clone)]
pub struct ElisionTarget {
    /// Index into the `history` slice of the `Message::User` carrying the
    /// `ToolResult` to elide.
    pub history_index: usize,
    /// The current (full) body text at that index — used to compute the
    /// token savings without re-walking history.
    pub current_body: String,
    pub elision: Elision,
    /// For an overlap-merge target only: the pre-rendered partial body that
    /// keeps the non-overlapping remainder and replaces the overlapping line
    /// run(s) with a marker pointing at the retaining body. `None` for a
    /// whole-body exact-identity elision (which writes [`Elision::marker_text`]).
    pub partial_body: Option<String>,
    /// Cached cl100k token saving for this target. Computed once when the
    /// plan is built so repeated projections do not re-tokenize immutable
    /// bodies.
    pub tokens_saved: usize,
    /// The tool-result `id` (== originating tool-call `id`) of the body being
    /// rewritten — the row [`apply_plan`] mutates. For a whole-body elision
    /// this equals `elision.original_event_id`; for an overlap-merge elision
    /// they differ (the elision points at the *retaining* body, the target is
    /// the *older* body).
    pub target_call_id: String,
}

impl ElisionTarget {
    /// The body text this target writes onto the wire: the pre-rendered
    /// partial body for an overlap-merge, else the whole-body marker. Single
    /// source so the savings projection and the actual rewrite agree.
    fn replacement_body(&self) -> String {
        self.partial_body
            .clone()
            .unwrap_or_else(|| self.elision.marker_text())
    }
}

/// The deterministic plan: every superseded snapshot body that `/prune`
/// would elide, in history order. Empty when nothing is prunable.
#[derive(Debug, Clone, Default)]
pub struct DedupPlan {
    pub targets: Vec<ElisionTarget>,
}

impl DedupPlan {
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// cl100k_base token count that would be dropped from the wire by
    /// applying this plan. Each target trades its full body for the
    /// (small) marker, so the saving is `count(body) - count(marker)`,
    /// floored at zero. The per-target values are cached at plan-build time.
    pub fn tokens_saved(&self) -> usize {
        self.targets.iter().map(|t| t.tokens_saved).sum()
    }
}

/// Walk `history` and build the dedup plan. The identity key is
/// `(tool_name, canonical_args)` where `canonical_args` is the
/// tool-call's argument JSON serialized canonically (serde_json's
/// `Value` ordering is stable for objects via `BTreeMap`-like sorting in
/// `to_string` only for `Map` insertion order, so we normalize through a
/// round-trip — see [`canonical_args`]). For each identity group we keep
/// the **last** body and mark every earlier one for elision.
///
/// Bodies already elided (marker text) are skipped — they neither get
/// re-elided nor count as "the surviving body" for a group. If the only
/// surviving (newest) body of a group is already elided, the older
/// bodies are left full: a marker pointing at a body no longer in
/// context would be a lie (`plan.md` T6.d edge case).
pub fn dedup_plan(history: &[Message]) -> DedupPlan {
    // First pass: map every assistant tool-call id → its identity key,
    // for the snapshot tools only.
    let mut call_identity: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for msg in history {
        if let Message::Assistant { content, .. } = msg {
            for c in content.iter() {
                if let AssistantContent::ToolCall(tc) = c
                    && is_snapshot_tool(&tc.function.name)
                {
                    let key = format!(
                        "{}\u{0}{}",
                        tc.function.name,
                        canonical_args(&tc.function.arguments)
                    );
                    call_identity.insert(tc.id.to_string(), key);
                }
            }
        }
    }

    // Second pass: collect, per identity group, the history indices of
    // the (non-elided) tool-result bodies in order, plus their call id.
    struct ResultLoc {
        history_index: usize,
        call_id: String,
        body: String,
        elided: bool,
    }
    let mut groups: std::collections::HashMap<String, Vec<ResultLoc>> =
        std::collections::HashMap::new();

    for (idx, msg) in history.iter().enumerate() {
        if let Message::User { content } = msg {
            for c in content.iter() {
                if let UserContent::ToolResult(tr) = c {
                    let Some(key) = call_identity.get(tr.call.as_str()) else {
                        continue;
                    };
                    if !tool_result_is_text_only(&tr.content) {
                        continue;
                    }
                    let body = tool_result_body(&tr.content);
                    let elided = Elision::is_marker(&body);
                    groups.entry(key.clone()).or_default().push(ResultLoc {
                        history_index: idx,
                        call_id: tr.call.to_string(),
                        body,
                        elided,
                    });
                }
            }
        }
    }

    // Third pass: for each group with >1 result, keep the newest body
    // and elide the older non-elided ones — but only if the newest body
    // is still full (not already elided).
    let mut targets = Vec::new();
    for locs in groups.values() {
        if locs.len() < 2 {
            continue;
        }
        let newest = locs.last().expect("len >= 2");
        if newest.elided {
            // The surviving body is gone; a marker would point at
            // nothing. Leave the older bodies intact.
            continue;
        }
        for loc in &locs[..locs.len() - 1] {
            if loc.elided {
                continue;
            }
            targets.push(ElisionTarget {
                history_index: loc.history_index,
                current_body: loc.body.clone(),
                elision: Elision {
                    original_event_id: loc.call_id.clone(),
                    reason: REASON_SNAPSHOT_SUPERSEDED,
                },
                partial_body: None,
                tokens_saved: 0,
                target_call_id: loc.call_id.clone(),
            });
        }
    }

    // Overlap-merge (implementation note): partial-body
    // elision of overlapping `read` ranges of one file, which exact-identity
    // dedup (above) never catches. A body already whole-body-elided by the
    // exact-identity pass is excluded so we never emit two targets for one
    // row (exact-identity elides MORE — the whole body — so it wins).
    let exact_targeted: std::collections::HashSet<String> =
        targets.iter().map(|t| t.target_call_id.clone()).collect();
    // The overlap module restricts to its own read-class tools (`read`/
    // `read`); this closure only extracts the `path` arg, so a `read`
    // read participates in overlap-merge too (it isn't a snapshot tool for the
    // exact-identity pass, but its body is line-numbered identically).
    let overlap = overlap::overlap_targets(history, &|_tool, args| arg_canonical_path(args));
    for t in overlap {
        if !exact_targeted.contains(&t.target_call_id) {
            targets.push(t);
        }
    }

    for target in &mut targets {
        target.tokens_saved = cached_tokens_saved(target);
    }

    // Stable order: by history index so application + display agree.
    targets.sort_by_key(|t| t.history_index);
    DedupPlan { targets }
}

fn cached_tokens_saved(target: &ElisionTarget) -> usize {
    let before = crate::tokens::count(&target.current_body);
    let after = crate::tokens::count(&target.replacement_body());
    before.saturating_sub(after)
}

/// The canonical file path a `read` call addressed, from its `path`
/// argument. Used to group overlapping reads of the same file even when the
/// `offset`/`limit` differ. Returns `None` when no `path` is present.
fn arg_canonical_path(args: &serde_json::Value) -> Option<String> {
    args.get("path")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// Apply the plan to `history` in place, replacing each targeted
/// tool-result body with its elision marker while preserving the
/// `ToolResult`'s `id`/`call_id` (the call shape). Returns the number of
/// bodies elided. Safe to call with a plan computed against the same
/// history; indices are validated defensively.
pub fn apply_plan(history: &mut [Message], plan: &DedupPlan) -> usize {
    let applied = count_plan_matches(history, plan);
    apply_plan_direct(history, plan);
    applied
}

/// Return a derived history with `plan` applied, leaving `history` untouched.
/// The output has the same length and message ordering as the input; only
/// matching tool-result bodies are rewritten.
pub fn apply_plan_to(history: &[Message], plan: &DedupPlan) -> Vec<Message> {
    let mut derived = history.to_vec();
    apply_plan_direct(&mut derived, plan);
    derived
}

fn count_plan_matches(history: &[Message], plan: &DedupPlan) -> usize {
    let mut n = 0;
    for target in &plan.targets {
        let Some(msg) = history.get(target.history_index) else {
            continue;
        };
        if let Message::User { content } = msg {
            for c in content.iter() {
                if let UserContent::ToolResult(tr) = c
                    && tr.call.as_str() == target.target_call_id
                {
                    n += 1;
                }
            }
        }
    }
    n
}

fn apply_plan_direct(history: &mut [Message], plan: &DedupPlan) {
    for target in &plan.targets {
        let Some(msg) = history.get_mut(target.history_index) else {
            continue;
        };
        if let Message::User { content } = msg {
            for c in content.iter_mut() {
                if let UserContent::ToolResult(tr) = c
                    && tr.call.as_str() == target.target_call_id
                {
                    // Rewrite the body only; keep id/call_id intact so
                    // the tool_use↔tool_result pairing stays valid. An
                    // overlap-merge target writes its pre-rendered partial
                    // body (non-overlapping remainder + marker); an
                    // exact-identity target writes the whole-body marker.
                    tr.content = vec![ToolResultContent::text(target.replacement_body())];
                }
            }
        }
    }
}

/// Convenience: compute and apply in one shot. Returns the plan that was
/// applied (so callers can report token savings / count).
pub fn prune_history(history: &mut [Message]) -> DedupPlan {
    let plan = dedup_plan(history);
    apply_plan(history, &plan);
    plan
}

pub fn condense_candidates(history: &[Message]) -> Vec<CondenseCandidate> {
    condense_candidates_with_artifact_calls(history, &std::collections::BTreeSet::new())
}

/// Return newly eligible prune-boundary captures. Existing projections are
/// selected from their durable owner state, never from frame-shaped text in a
/// tool result; a tool can legitimately emit either artifact sentinel as part
/// of its ordinary output.
pub fn condense_candidates_with_artifact_calls(
    history: &[Message],
    model_context_artifact_calls: &std::collections::BTreeSet<String>,
) -> Vec<CondenseCandidate> {
    let mut calls: std::collections::HashMap<String, (String, String)> =
        std::collections::HashMap::new();
    for msg in history {
        if let Message::Assistant { content, .. } = msg {
            for c in content.iter() {
                if let AssistantContent::ToolCall(tc) = c {
                    let tool = tc.function.name.as_str();
                    if !is_prune_boundary_condense_tool(tool) {
                        continue;
                    }
                    let command = tc
                        .function
                        .arguments
                        .get("command")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    calls.insert(tc.id.to_string(), (tool.to_string(), command));
                }
            }
        }
    }

    let mut candidates = Vec::new();
    for (idx, msg) in history.iter().enumerate() {
        if let Message::User { content } = msg {
            for c in content.iter() {
                if let UserContent::ToolResult(tr) = c {
                    let Some((tool, command)) = calls.get(tr.call.as_str()) else {
                        continue;
                    };
                    if !tool_result_is_text_only(&tr.content) {
                        continue;
                    }
                    let body = tool_result_body(&tr.content);
                    if Elision::contains_marker(&body)
                        || model_context_artifact_calls.contains(tr.call.as_str())
                    {
                        continue;
                    }
                    let Some(condensed_body) =
                        shell_compress::prune_boundary_condense(command, &body)
                    else {
                        continue;
                    };
                    candidates.push(CondenseCandidate {
                        history_index: idx,
                        tool: tool.clone(),
                        call_id: tr.call.to_string(),
                        original_body: body,
                        condensed_body,
                    });
                }
            }
        }
    }
    candidates
}

pub fn apply_condensed_tool_result(
    history: &mut [Message],
    candidate: &CondenseCandidate,
    replacement: &str,
) -> bool {
    apply_condensed_tool_result_direct(history, candidate, replacement)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondensePlan {
    pub targets: Vec<CondenseTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondenseTarget {
    pub candidate: CondenseCandidate,
    /// The already-rendered model projection.  Production passes the shared
    /// artifact frame after the owning event commits; private planning may use
    /// the deterministic condensed preview while no durable artifact exists.
    pub replacement: String,
}

pub fn apply_condense_plan_to(history: &[Message], plan: &CondensePlan) -> Vec<Message> {
    let mut derived = history.to_vec();
    for target in &plan.targets {
        apply_condensed_tool_result_direct(&mut derived, &target.candidate, &target.replacement);
    }
    derived
}

pub fn apply_condensed_tool_result_to(
    history: &[Message],
    candidate: &CondenseCandidate,
    replacement: &str,
) -> Vec<Message> {
    apply_condense_plan_to(
        history,
        &CondensePlan {
            targets: vec![CondenseTarget {
                candidate: candidate.clone(),
                replacement: replacement.to_string(),
            }],
        },
    )
}

fn apply_condensed_tool_result_direct(
    history: &mut [Message],
    candidate: &CondenseCandidate,
    replacement: &str,
) -> bool {
    let Some(msg) = history.get_mut(candidate.history_index) else {
        return false;
    };
    if let Message::User { content } = msg {
        for c in content.iter_mut() {
            if let UserContent::ToolResult(tr) = c
                && tr.call.as_str() == candidate.call_id
            {
                tr.content = vec![ToolResultContent::text(replacement.to_string())];
                return true;
            }
        }
    }
    false
}

fn tool_names_by_call_id(history: &[Message]) -> std::collections::HashMap<String, String> {
    let mut tools = std::collections::HashMap::new();
    for msg in history {
        if let Message::Assistant { content, .. } = msg {
            for c in content.iter() {
                if let AssistantContent::ToolCall(tc) = c {
                    tools.insert(tc.id.to_string(), tc.function.name.clone());
                }
            }
        }
    }
    tools
}

fn is_generated_prune_body(
    body: &str,
    call_id: &str,
    tool: Option<&str>,
    prune_boundary_calls: &std::collections::BTreeSet<String>,
) -> bool {
    let Some(tool) = tool else {
        return false;
    };
    if is_snapshot_tool(tool) {
        exact_snapshot_marker(body, call_id) || contains_overlap_marker(body)
    } else if is_prune_boundary_condense_tool(tool) {
        prune_boundary_calls.contains(call_id)
    } else {
        false
    }
}

/// The set of `original_event_id`s whose tool-result body is **currently**
/// an elision marker in the wire history. This is the cumulative live set
/// — every body that has been elided so far and not since restored —
/// derived by walking history rather than tracking deltas, so it tracks
/// the true wire state exactly even across multiple prunes and the
/// engine-fallback "keep full content" edge case (an un-elided body simply
/// isn't a marker, so it's absent here).
///
/// The TUI consumes this to dim the matching scrollback tool-result
/// bodies: a `ToolResult`'s `id` equals the originating tool call's `id`
/// (`apply_plan` preserves it), which is the same `call_id` the TUI keys
/// its rendered tool-call entries on. Render-time lookup, not a persisted
/// flag (GOALS §14: dimming is a wire-state view; scrollback stays
/// full-fidelity).
pub fn current_elided_ids(history: &[Message]) -> Vec<String> {
    current_elided_ids_with_prune_boundary_calls(history, &std::collections::BTreeSet::new())
}

/// Return live elision ids using the durable set of prune-boundary projection
/// owners. The set comes from the session event state and therefore cannot be
/// forged by a tool result that happens to contain a frame-looking string.
pub fn current_elided_ids_with_prune_boundary_calls(
    history: &[Message],
    prune_boundary_calls: &std::collections::BTreeSet<String>,
) -> Vec<String> {
    let tools = tool_names_by_call_id(history);
    let mut ids = Vec::new();
    for msg in history {
        if let Message::User { content } = msg {
            for c in content.iter() {
                if let UserContent::ToolResult(tr) = c {
                    if !tool_result_is_text_only(&tr.content) {
                        continue;
                    }
                    let body = tool_result_body(&tr.content);
                    if is_generated_prune_body(
                        &body,
                        tr.call.as_str(),
                        tools.get(tr.call.as_str()).map(String::as_str),
                        prune_boundary_calls,
                    ) {
                        ids.push(tr.call.to_string());
                    }
                }
            }
        }
    }
    ids
}

/// The durable record of the in-memory prune state, persisted at every
/// inference boundary and on every `/prune` so a resumed session can
/// return its rebuilt transcript to **pruned** form byte-identically
/// (implementation note). It is the on-disk twin of
/// what [`apply_plan`] + [`current_elided_ids`] + the driver's
/// `prune_watermark` keep only in memory.
///
/// Contents:
/// - `elided`: every currently-elided body, each carrying the exact
///   `original_event_id` + `reason` [`apply_plan`] wrote, so the audit pointer
///   and marker reason reproduce character-for-character on rebuild (the same
///   [`Elision`] type, never a forked marker format).
/// - `watermark`: the foreground root history length at the last prune
///   (the driver's depth-1 `prune_watermark`), so auto-prune's
///   short-circuit stays consistent after resume.
///
/// Serialized to JSON for the `prune_ledger` table. Single source of
/// truth stays `session_events` + `tool_calls`; this is the small delta
/// that re-derives the *pruned* form, not a second copy of the wire list.
/// The single canonical elision reason today (`apply_plan` writes only
/// this). Stored as `&'static str` on [`Elision`]; the ledger round-trips
/// through this so a persisted reason re-binds to the static form and the
/// marker text reproduces byte-identically.
pub const REASON_SNAPSHOT_SUPERSEDED: &str = "snapshot superseded";

/// Re-bind a persisted reason string to its canonical `&'static str`.
/// Unknown reasons (future ledger writers) fall back to the snapshot
/// reason so the marker is always well-formed — never an empty marker.
fn static_reason(reason: &str) -> &'static str {
    match reason {
        REASON_SNAPSHOT_SUPERSEDED => REASON_SNAPSHOT_SUPERSEDED,
        overlap::OVERLAP_REASON => overlap::OVERLAP_REASON,
        REASON_TOOL_RESULT_CONDENSED => REASON_TOOL_RESULT_CONDENSED,
        _ => REASON_SNAPSHOT_SUPERSEDED,
    }
}

/// Capture the current prune state of a wire history + the driver's
/// foreground watermark into a durable ledger. Walks the history for the
/// currently-elided bodies (the same scan [`current_elided_ids`] does) and
/// records each as a [`LedgerEntry`] carrying the canonical reason, so re-apply
/// reproduces the exact marker. `watermark` is the depth-1 `prune_watermark`
/// (root history length at the last prune).
pub fn capture_ledger(history: &[Message], watermark: usize) -> PruneLedger {
    capture_ledger_with_prune_boundary_calls(history, watermark, &std::collections::BTreeSet::new())
}

/// Capture the wire-prune delta using durable prune-boundary owner ids rather
/// than parsing the rendered artifact frame.  Only these typed owners can be
/// re-rendered after restart.
pub fn capture_ledger_with_prune_boundary_calls(
    history: &[Message],
    watermark: usize,
    prune_boundary_calls: &std::collections::BTreeSet<String>,
) -> PruneLedger {
    let tools = tool_names_by_call_id(history);
    let mut elided = Vec::new();
    for msg in history {
        if let Message::User { content } = msg {
            for c in content.iter() {
                if let UserContent::ToolResult(tr) = c {
                    if !tool_result_is_text_only(&tr.content) {
                        continue;
                    }
                    let body = tool_result_body(&tr.content);
                    let tool = tools.get(tr.call.as_str()).map(String::as_str);
                    if tool.is_some_and(is_snapshot_tool)
                        && exact_snapshot_marker(&body, tr.call.as_str())
                    {
                        // Whole-body exact-identity marker: re-renders from
                        // id + reason, no body to store.
                        elided.push(LedgerEntry {
                            original_event_id: tr.call.to_string(),
                            reason: REASON_SNAPSHOT_SUPERSEDED.to_string(),
                            partial_body: None,
                        });
                    } else if tool.is_some_and(is_snapshot_tool) && contains_overlap_marker(&body) {
                        // Overlap-merge partial body: store it verbatim so
                        // resume reproduces it byte-identically (the overlap
                        // geometry is not re-derived from a possibly-shifted
                        // file).
                        elided.push(LedgerEntry {
                            original_event_id: tr.call.to_string(),
                            reason: overlap::OVERLAP_REASON.to_string(),
                            partial_body: Some(body),
                        });
                    } else if tool.is_some_and(is_prune_boundary_condense_tool)
                        && prune_boundary_calls.contains(tr.call.as_str())
                    {
                        // The immutable original and the frame identity are
                        // owned by the `context_pruned` event's typed
                        // association. Do not copy a rendered frame (and its
                        // source UUID) into the ledger: resume re-renders it
                        // from that association after applying the ledger.
                        elided.push(LedgerEntry {
                            original_event_id: tr.call.to_string(),
                            reason: REASON_TOOL_RESULT_CONDENSED.to_string(),
                            partial_body: None,
                        });
                    }
                }
            }
        }
    }
    PruneLedger { elided, watermark }
}

/// True when the ledger records no elisions — the rebuilt transcript is already
/// in its final (unpruned) form and re-apply is a no-op.
pub fn ledger_is_empty(ledger: &PruneLedger) -> bool {
    ledger.elided.is_empty()
}

/// Re-apply the ledger to a freshly-rebuilt `history`, eliding every
/// reconstructed tool-result body whose id is recorded, with the identical
/// marker. Reuses [`apply_plan`] (and thus the one marker format) by building a
/// [`DedupPlan`] whose targets point at the matching reconstructed indices.
///
/// Returns `Err(missing)` listing any ledger ids that have **no** matching full
/// (un-elided) tool-result in the rebuilt history — an inconsistent ledger. The
/// caller then falls back to the full unpruned reconstruction and warns
/// (priority #1: never a malformed or silently-fresh context). On `Ok(n)`, `n`
/// bodies were elided.
pub fn reapply_ledger(
    ledger: &PruneLedger,
    history: &mut [Message],
) -> std::result::Result<usize, Vec<String>> {
    // Index the rebuilt history: id → (history_index, current_body),
    // for every full tool-result body present.
    let mut by_id: std::collections::HashMap<&str, (usize, String)> =
        std::collections::HashMap::new();
    for (idx, msg) in history.iter().enumerate() {
        if let Message::User { content } = msg {
            for c in content.iter() {
                if let UserContent::ToolResult(tr) = c {
                    if !tool_result_is_text_only(&tr.content) {
                        continue;
                    }
                    by_id.insert(tr.call.as_str(), (idx, tool_result_body(&tr.content)));
                }
            }
        }
    }

    let mut targets = Vec::new();
    let mut missing = Vec::new();
    for entry in &ledger.elided {
        match by_id.get(entry.original_event_id.as_str()) {
            Some((idx, body)) => targets.push(ElisionTarget {
                history_index: *idx,
                current_body: body.clone(),
                elision: Elision {
                    original_event_id: entry.original_event_id.clone(),
                    reason: static_reason(&entry.reason),
                },
                // An overlap-merge entry carries its pre-rendered partial
                // body, written verbatim; a whole-body entry has `None` and
                // re-renders the marker. Either way the row to write onto is
                // the entry's own id.
                partial_body: entry.partial_body.clone(),
                tokens_saved: 0,
                target_call_id: entry.original_event_id.clone(),
            }),
            None => missing.push(entry.original_event_id.clone()),
        }
    }
    if !missing.is_empty() {
        return Err(missing);
    }
    targets.sort_by_key(|t| t.history_index);
    for target in &mut targets {
        target.tokens_saved = cached_tokens_saved(target);
    }
    let plan = DedupPlan { targets };
    let applied = count_plan_matches(history, &plan);
    apply_plan_direct(history, &plan);
    Ok(applied)
}

/// The cache-cold predicate (GOALS §10 / `plan.md` T6.f): "expected
/// cache-hit on the next call is zero." When this is true, pruning costs
/// no cache bust, so auto-prune may fire for free. Three cases, unified.
///
/// This is the clean public API other features reuse (auto-prune,
/// `/compact`'s prune-first step, the `/prune` confirm copy's hot/cold
/// label). Pure over its inputs so it's trivially testable.
///
/// Inputs:
/// - `cache`: the resolved per-(provider, model) cache config.
/// - `secs_since_last_send`: `None` ⇒ no warm prefix yet (cold).
/// - `upstream_bust`: the next call already invalidates the cache anchor
///   for an unrelated reason (a tool-result edit before the breakpoint,
///   a redaction/system-block mutation). Caller computes this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheState {
    /// A warm prefix is expected on the next call; pruning would bust it.
    Hot,
    /// No cache hit expected; pruning is free. Carries which case fired.
    Cold(ColdReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdReason {
    /// Provider has no prompt cache (`cache.mode = none`).
    NoCacheProvider,
    /// The cache TTL has elapsed since the last send (or no send yet).
    TtlElapsed,
    /// The next call already busts the cache upstream this turn.
    UpstreamBust,
}

impl CacheState {
    pub fn is_cold(self) -> bool {
        matches!(self, CacheState::Cold(_))
    }
}

/// The cache-aware reuse-vs-fresh decision for a re-queried subagent
/// (implementation note). A follow-up always rebuilds
/// the subagent's message array from its stored transcript (the finished
/// subagent retains no live in-memory context); this enum records *why* —
/// which is the verifiable, deterministic decision the spec calls for. The
/// resulting provider-side cache behavior (a prefix cache **read** vs a cache
/// **creation**) confirms it in the `inference_calls` record
/// (`cached_input_tokens` vs `cache_creation_input_tokens`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowupReuse {
    /// Provider/model caches **and** the warm prefix is still intact
    /// ([`CacheState::Hot`]): re-sending the identical rebuilt prefix hits the
    /// provider cache — the cheapest path (a cache *read*).
    WarmReuse,
    /// Provider/model caches but the cache is broken (TTL elapsed or an
    /// upstream bust): the rebuilt prefix is sent fresh and the provider
    /// re-creates the cache (a cache *creation*). The deterministic
    /// "spawn a fresh agent rehydrated from the stored transcript" case.
    RehydrateFresh,
    /// Provider/model does not cache at all
    /// ([`ColdReason::NoCacheProvider`]): there is no warm context to lose, so
    /// the rebuilt transcript is simply re-run (no cache read or creation).
    NoCacheReuse,
}

/// Map the live [`cache_state`] onto the three-way follow-up reuse decision.
/// Pure over its inputs — the decision is deterministic given the resolved
/// cache config and time-since-last-send.
pub fn followup_reuse(
    cache: &CacheConfig,
    secs_since_last_send: Option<u64>,
    upstream_bust: bool,
) -> FollowupReuse {
    match cache_state(cache, secs_since_last_send, upstream_bust) {
        CacheState::Hot => FollowupReuse::WarmReuse,
        CacheState::Cold(ColdReason::NoCacheProvider) => FollowupReuse::NoCacheReuse,
        CacheState::Cold(ColdReason::TtlElapsed) | CacheState::Cold(ColdReason::UpstreamBust) => {
            FollowupReuse::RehydrateFresh
        }
    }
}

/// Evaluate the cache-cold predicate. Order matters only for the
/// `ColdReason` attribution, not the boolean outcome.
pub fn cache_state(
    cache: &CacheConfig,
    secs_since_last_send: Option<u64>,
    upstream_bust: bool,
) -> CacheState {
    // Case (a): provider has no cache support at all.
    if cache.mode == CacheMode::None {
        return CacheState::Cold(ColdReason::NoCacheProvider);
    }
    // Case (c): the next call busts the cache upstream regardless of TTL.
    if upstream_bust {
        return CacheState::Cold(ColdReason::UpstreamBust);
    }
    // Case (b): TTL elapsed (or never sent → no warm prefix).
    match secs_since_last_send {
        None => CacheState::Cold(ColdReason::TtlElapsed),
        Some(secs) if secs >= cache.ttl_secs => CacheState::Cold(ColdReason::TtlElapsed),
        Some(_) => CacheState::Hot,
    }
}

/// Prune rewrites replace a complete result body with a marker, so only
/// text-only results are eligible. Typed JSON/media parts remain authoritative
/// and must never be silently discarded by a text optimization.
fn tool_result_is_text_only(content: &[ToolResultContent]) -> bool {
    content
        .iter()
        .all(|part| matches!(part, ToolResultContent::Text(_)))
}

/// Concatenate a text-only tool-result into one body string. Callers that may
/// rewrite the result must first enforce [`tool_result_is_text_only`].
fn tool_result_body(content: &[ToolResultContent]) -> String {
    content
        .iter()
        .filter_map(|c| match c {
            ToolResultContent::Text(t) => Some(t.text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Canonicalize a tool call's argument JSON so two structurally-equal
/// arg objects hash to the same identity key regardless of key order.
/// Round-trips through `serde_json::Value` with sorted object keys.
fn canonical_args(args: &serde_json::Value) -> String {
    fn sort_value(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(map) => {
                let mut sorted = serde_json::Map::new();
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for k in keys {
                    sorted.insert(k.clone(), sort_value(&map[k]));
                }
                serde_json::Value::Object(sorted)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(sort_value).collect())
            }
            other => other.clone(),
        }
    }
    sort_value(args).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::message::ToolCall;
    use rig::message::{AssistantContent, ToolResult};
    use serde_json::json;

    /// Build an assistant message carrying one snapshot tool call.
    fn assistant_call(call_id: &str, tool: &str, args: serde_json::Value) -> Message {
        let tc = ToolCall {
            id: rig::message::ToolCallId::new_or_mint(call_id.to_string()),
            provider: None,
            function: rig::message::ToolFunction {
                name: tool.to_string(),
                arguments: args,
            },
            signature: None,
            additional_params: None,
        };
        Message::Assistant {
            id: None,
            content: vec![AssistantContent::ToolCall(tc)],
        }
    }

    /// Build a user message carrying one tool result body.
    fn tool_result(call_id: &str, body: &str) -> Message {
        Message::User {
            content: vec![UserContent::ToolResult(ToolResult {
                call: rig::message::ToolCallId::new_or_mint(call_id.to_string()),
                provider: None,
                name: "tool".to_string(),
                content: vec![ToolResultContent::text(body)],
            })],
        }
    }

    fn tool_results(results: &[(&str, &str)]) -> Message {
        Message::User {
            content: results
                .iter()
                .map(|(call_id, body)| {
                    UserContent::ToolResult(ToolResult {
                        call: rig::message::ToolCallId::new_or_mint((*call_id).to_string()),
                        provider: None,
                        name: "tool".to_string(),
                        content: vec![ToolResultContent::text(*body)],
                    })
                })
                .collect::<Vec<_>>(),
        }
    }

    fn body_at(history: &[Message], idx: usize) -> String {
        match &history[idx] {
            Message::User { content } => tool_result_body(match content.first() {
                Some(UserContent::ToolResult(tr)) => &tr.content,
                _ => panic!("not a tool result"),
            }),
            _ => panic!("not a user message"),
        }
    }

    fn tool_result_id_at(history: &[Message], idx: usize) -> String {
        match &history[idx] {
            Message::User { content } => match content.first() {
                Some(UserContent::ToolResult(tr)) => tr.call.to_string(),
                _ => panic!("not a tool result"),
            },
            _ => panic!("not a user message"),
        }
    }

    fn assert_message_kinds(history: &[Message], expected: &[&str]) {
        let actual = history
            .iter()
            .map(|msg| match msg {
                Message::System { .. } => "system",
                Message::Assistant { .. } => "assistant",
                Message::User { .. } => "user",
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn characterize_dedup_apply_wire_shape() {
        let exact_args = json!({ "path": "/abs/exact.rs" });
        let overlap_older = json!({ "path": "/abs/overlap.rs", "offset": 1, "limit": 3 });
        let overlap_newer = json!({ "path": "/abs/overlap.rs", "offset": 2, "limit": 3 });
        let mut history = vec![
            assistant_call("exact-old", "read", exact_args.clone()),
            tool_result("exact-old", "exact old body with enough padding"),
            assistant_call("exact-new", "read", exact_args),
            tool_result("exact-new", "exact new body with enough padding"),
            assistant_call("overlap-old", "read", overlap_older),
            tool_result(
                "overlap-old",
                "1|line 1 content\n2|line 2 content\n3|line 3 content\n",
            ),
            assistant_call("overlap-new", "read", overlap_newer),
            tool_result(
                "overlap-new",
                "2|line 2 content\n3|line 3 content\n4|line 4 content\n",
            ),
        ];

        let plan = dedup_plan(&history);
        assert_eq!(plan.targets.len(), 2);
        assert_eq!(apply_plan(&mut history, &plan), 2);

        assert_eq!(history.len(), 8);
        assert_message_kinds(
            &history,
            &[
                "assistant",
                "user",
                "assistant",
                "user",
                "assistant",
                "user",
                "assistant",
                "user",
            ],
        );
        assert_eq!(tool_result_id_at(&history, 1), "exact-old");
        assert_eq!(tool_result_id_at(&history, 3), "exact-new");
        assert_eq!(tool_result_id_at(&history, 5), "overlap-old");
        assert_eq!(tool_result_id_at(&history, 7), "overlap-new");
        assert_eq!(
            body_at(&history, 1),
            "[elided: snapshot superseded — a later identical call in this conversation still carries the full result; use that one. Not retrievable and not worth re-running.]"
        );
        assert_eq!(body_at(&history, 3), "exact new body with enough padding");
        assert_eq!(
            body_at(&history, 5),
            format!("1|line 1 content\n{}\n", overlap::overlap_marker_line())
        );
        assert_eq!(
            body_at(&history, 7),
            "2|line 2 content\n3|line 3 content\n4|line 4 content\n"
        );
    }

    #[test]
    fn characterize_prune_artifact_frame_wire_shape() {
        let original = long_shell_body();
        let mut history = vec![
            assistant_call("bash-one", "bash", json!({ "command": "cargo test" })),
            tool_result("bash-one", &original),
        ];

        let candidates = condense_candidates(&history);
        assert_eq!(candidates.len(), 1);
        let expected = render_prune_artifact_frame(&candidates[0], None, Some("artifact_limit"));

        assert!(apply_condensed_tool_result(
            &mut history,
            &candidates[0],
            &expected,
        ));

        assert_eq!(history.len(), 2);
        assert_message_kinds(&history, &["assistant", "user"]);
        assert_eq!(tool_result_id_at(&history, 1), "bash-one");
        assert_eq!(body_at(&history, 1), expected);
    }

    #[test]
    fn apply_plan_to_matches_apply_plan() {
        let empty = vec![
            assistant_call("empty", "read", json!({ "path": "/empty" })),
            tool_result("empty", "single body"),
        ];
        let empty_plan = DedupPlan::default();
        let mut empty_mutating = empty.clone();
        assert_eq!(apply_plan(&mut empty_mutating, &empty_plan), 0);
        assert_eq!(apply_plan_to(&empty, &empty_plan), empty_mutating);

        let args = json!({ "path": "/exact" });
        let whole = vec![
            assistant_call("whole-old", "read", args.clone()),
            tool_result("whole-old", "older whole body padding padding"),
            assistant_call("whole-new", "read", args),
            tool_result("whole-new", "newer whole body padding padding"),
        ];
        let whole_plan = dedup_plan(&whole);
        let mut whole_mutating = whole.clone();
        assert_eq!(apply_plan(&mut whole_mutating, &whole_plan), 1);
        assert_eq!(
            serde_json::to_value(apply_plan_to(&whole, &whole_plan)).unwrap(),
            serde_json::to_value(&whole_mutating).unwrap()
        );

        let partial = vec![
            assistant_call(
                "partial-old",
                "read",
                json!({ "path": "/p", "offset": 1, "limit": 3 }),
            ),
            tool_result("partial-old", "1|a\n2|b\n3|c\n"),
            assistant_call(
                "partial-new",
                "read",
                json!({ "path": "/p", "offset": 2, "limit": 3 }),
            ),
            tool_result("partial-new", "2|b\n3|c\n4|d\n"),
        ];
        let partial_plan = dedup_plan(&partial);
        let mut partial_mutating = partial.clone();
        assert_eq!(apply_plan(&mut partial_mutating, &partial_plan), 1);
        assert_eq!(
            serde_json::to_value(apply_plan_to(&partial, &partial_plan)).unwrap(),
            serde_json::to_value(&partial_mutating).unwrap()
        );

        let index_miss_plan = DedupPlan {
            targets: vec![ElisionTarget {
                history_index: 99,
                current_body: "missing".into(),
                elision: Elision {
                    original_event_id: "missing".into(),
                    reason: REASON_SNAPSHOT_SUPERSEDED,
                },
                partial_body: None,
                tokens_saved: 0,
                target_call_id: "missing".into(),
            }],
        };
        let mut index_mutating = partial.clone();
        assert_eq!(apply_plan(&mut index_mutating, &index_miss_plan), 0);
        assert_eq!(apply_plan_to(&partial, &index_miss_plan), index_mutating);

        let multi = vec![
            assistant_call("multi-a", "read", json!({ "path": "/a" })),
            assistant_call("multi-b", "read", json!({ "path": "/b" })),
            tool_results(&[
                ("multi-a", "multi body a padding padding"),
                ("multi-b", "multi body b padding padding"),
            ]),
        ];
        let multi_plan = DedupPlan {
            targets: vec![
                ElisionTarget {
                    history_index: 2,
                    current_body: "multi body a padding padding".into(),
                    elision: Elision {
                        original_event_id: "multi-a".into(),
                        reason: REASON_SNAPSHOT_SUPERSEDED,
                    },
                    partial_body: None,
                    tokens_saved: 0,
                    target_call_id: "multi-a".into(),
                },
                ElisionTarget {
                    history_index: 2,
                    current_body: "multi body b padding padding".into(),
                    elision: Elision {
                        original_event_id: "multi-b".into(),
                        reason: REASON_SNAPSHOT_SUPERSEDED,
                    },
                    partial_body: None,
                    tokens_saved: 0,
                    target_call_id: "multi-b".into(),
                },
            ],
        };
        let mut multi_mutating = multi.clone();
        assert_eq!(apply_plan(&mut multi_mutating, &multi_plan), 2);
        assert_eq!(
            serde_json::to_value(apply_plan_to(&multi, &multi_plan)).unwrap(),
            serde_json::to_value(&multi_mutating).unwrap()
        );
    }

    #[test]
    fn apply_plan_preserves_length_and_order() {
        let args = json!({ "path": "/abs/order.rs" });
        let history = vec![
            assistant_call("order-old", "read", args.clone()),
            tool_result("order-old", "older body padding padding"),
            assistant_call("order-new", "read", args),
            tool_result("order-new", "newer body padding padding"),
        ];
        let plan = dedup_plan(&history);
        let derived = apply_plan_to(&history, &plan);

        assert_eq!(derived.len(), history.len());
        assert_message_kinds(&derived, &["assistant", "user", "assistant", "user"]);
        assert_eq!(tool_result_id_at(&derived, 1), "order-old");
        assert_eq!(tool_result_id_at(&derived, 3), "order-new");
        assert_ne!(body_at(&derived, 1), body_at(&history, 1));
        assert_eq!(body_at(&derived, 3), body_at(&history, 3));
    }

    #[test]
    fn condense_plan_applies_in_bulk() {
        let first = long_shell_body();
        let second = (0..720)
            .map(|index| format!("second noise line {index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let history = vec![
            assistant_call("bash-a", "bash", json!({ "command": "cargo test" })),
            tool_result("bash-a", &first),
            assistant_call("bash-b", "bash", json!({ "command": "cargo test" })),
            tool_result("bash-b", &second),
        ];
        let candidates = condense_candidates(&history);
        assert_eq!(candidates.len(), 2);
        let plan = CondensePlan {
            targets: candidates
                .iter()
                .map(|candidate| CondenseTarget {
                    candidate: candidate.clone(),
                    replacement: render_prune_artifact_frame(
                        candidate,
                        None,
                        Some("artifact_limit"),
                    ),
                })
                .collect(),
        };

        let mut sequential = history.clone();
        for target in &plan.targets {
            assert!(apply_condensed_tool_result(
                &mut sequential,
                &target.candidate,
                &target.replacement,
            ));
        }
        let bulk = apply_condense_plan_to(&history, &plan);

        assert_eq!(
            serde_json::to_value(bulk).unwrap(),
            serde_json::to_value(&sequential).unwrap()
        );
        assert!(body_at(&sequential, 1).contains("<cockpit_artifact_v1"));
        assert!(body_at(&sequential, 3).contains("<cockpit_artifact_v1"));
    }

    #[test]
    fn index_miss_is_tolerated() {
        let history = vec![
            assistant_call("real", "read", json!({ "path": "/real" })),
            tool_result("real", "real body padding padding"),
        ];
        let wrong_id = DedupPlan {
            targets: vec![ElisionTarget {
                history_index: 1,
                current_body: "real body padding padding".into(),
                elision: Elision {
                    original_event_id: "ghost".into(),
                    reason: REASON_SNAPSHOT_SUPERSEDED,
                },
                partial_body: None,
                tokens_saved: 0,
                target_call_id: "ghost".into(),
            }],
        };
        assert_eq!(apply_plan_to(&history, &wrong_id), history);

        let wrong_index = DedupPlan {
            targets: vec![ElisionTarget {
                history_index: 99,
                current_body: "real body padding padding".into(),
                elision: Elision {
                    original_event_id: "real".into(),
                    reason: REASON_SNAPSHOT_SUPERSEDED,
                },
                partial_body: None,
                tokens_saved: 0,
                target_call_id: "real".into(),
            }],
        };
        assert_eq!(apply_plan_to(&history, &wrong_index), history);
    }

    /// Two identical reads of the same file: the older body is elided,
    /// the newest survives, call shapes (the assistant turns) untouched.
    #[test]
    fn dedups_repeated_identical_reads() {
        let args = json!({ "path": "/abs/foo.rs" });
        let mut history = vec![
            assistant_call("c1", "read", args.clone()),
            tool_result("c1", "FULL BODY ONE with lots of content here"),
            assistant_call("c2", "read", args.clone()),
            tool_result("c2", "FULL BODY TWO with lots of content here"),
        ];

        let plan = dedup_plan(&history);
        assert_eq!(plan.targets.len(), 1, "older read elided, newer kept");
        assert_eq!(plan.targets[0].history_index, 1);
        assert_eq!(plan.targets[0].elision.original_event_id, "c1");

        let n = apply_plan(&mut history, &plan);
        assert_eq!(n, 1);
        // Older body became the marker; newer body intact.
        assert!(Elision::is_marker(&body_at(&history, 1)));
        assert_eq!(
            body_at(&history, 3),
            "FULL BODY TWO with lots of content here"
        );
        // Call shapes (assistant turns) are unchanged — still 4 messages,
        // assistant turns at 0 and 2.
        assert_eq!(history.len(), 4);
        assert!(matches!(history[0], Message::Assistant { .. }));
        assert!(matches!(history[2], Message::Assistant { .. }));
    }

    /// PROJECTION == EXECUTION: the same `dedup_plan` drives both the
    /// "% prunable" figure and the actual prune, so tokens_saved before
    /// applying equals the wire bytes that actually disappear.
    #[test]
    fn projection_equals_execution() {
        let args = json!({ "path": "/abs/big.rs" });
        let big = "x".repeat(4000);
        let mut history = vec![
            assistant_call("c1", "read", args.clone()),
            tool_result("c1", &big),
            assistant_call("c2", "read", args.clone()),
            tool_result("c2", &big),
        ];
        // The projection the status line would show.
        let projected = dedup_plan(&history);
        let projected_saving = projected.tokens_saved();
        assert!(projected_saving > 0);

        // Measure wire tokens before/after the ACTUAL prune.
        let before: usize = history.iter().map(wire_tokens).sum();
        let applied = prune_history(&mut history);
        let after: usize = history.iter().map(wire_tokens).sum();
        let actual_saving = before - after;

        // The plan used for projection and the plan applied are identical
        // (same function), so the saving the user was promised is the
        // saving they got.
        assert_eq!(applied.targets.len(), projected.targets.len());
        assert_eq!(projected_saving, actual_saving);
    }

    #[test]
    fn tokens_saved_reuses_plan_time_counts() {
        let args = json!({ "path": "/abs/big.rs" });
        let big = "x".repeat(4000);
        let history = vec![
            assistant_call("c1", "read", args.clone()),
            tool_result("c1", &big),
            assistant_call("c2", "read", args.clone()),
            tool_result("c2", &big),
        ];

        crate::tokens::reset_count_call_count();
        let plan = dedup_plan(&history);
        assert_eq!(plan.targets.len(), 1);
        let calls_after_plan = crate::tokens::count_call_count();
        assert_eq!(
            calls_after_plan, 2,
            "one target counts body and replacement once"
        );

        let first = plan.tokens_saved();
        let second = plan.tokens_saved();
        assert_eq!(first, second);
        assert_eq!(
            crate::tokens::count_call_count(),
            calls_after_plan,
            "repeated projections must not re-tokenize target bodies"
        );
    }

    #[test]
    fn applying_precomputed_plan_matches_prune_history() {
        let args = json!({ "path": "/abs/big.rs" });
        let original = vec![
            assistant_call("c1", "read", args.clone()),
            tool_result("c1", "older exact body with enough padding"),
            assistant_call("c2", "read", args),
            tool_result("c2", "newer exact body with enough padding"),
            assistant_call("c3", "read", json!({ "path": "/abs/other.rs" })),
            tool_result("c3", "unrelated body survives"),
        ];
        let mut precomputed = original.clone();
        let mut convenience = original;

        let plan = dedup_plan(&precomputed);
        let applied_count = apply_plan(&mut precomputed, &plan);
        let applied = prune_history(&mut convenience);

        assert_eq!(applied_count, applied.targets.len());
        assert_eq!(plan.tokens_saved(), applied.tokens_saved());
        assert_eq!(precomputed, convenience);
    }

    /// Different args (different offset) are NOT the same identity — no
    /// dedup.
    #[test]
    fn distinct_args_not_deduped() {
        let mut history = vec![
            assistant_call("c1", "read", json!({ "path": "/f", "offset": 1 })),
            tool_result("c1", "page one body padding padding"),
            assistant_call("c2", "read", json!({ "path": "/f", "offset": 200 })),
            tool_result("c2", "page two body padding padding"),
        ];
        let plan = dedup_plan(&history);
        assert!(plan.is_empty(), "different offsets are different snapshots");
        assert_eq!(apply_plan(&mut history, &plan), 0);
    }

    /// Key-order differences in args don't defeat identity matching.
    #[test]
    fn arg_key_order_is_canonicalized() {
        let mut history = vec![
            assistant_call("c1", "read", json!({ "path": "/f", "limit": 50 })),
            tool_result("c1", "body alpha padding padding padding"),
            assistant_call("c2", "read", json!({ "limit": 50, "path": "/f" })),
            tool_result("c2", "body beta padding padding padding"),
        ];
        let plan = dedup_plan(&history);
        assert_eq!(plan.targets.len(), 1);
        assert_eq!(apply_plan(&mut history, &plan), 1);
    }

    /// bash / edit / write are not snapshot tools; repeated identical
    /// calls are never deduped.
    #[test]
    fn non_snapshot_tools_untouched() {
        let history = vec![
            assistant_call("c1", "bash", json!({ "command": "ls" })),
            tool_result("c1", "file listing body padding"),
            assistant_call("c2", "bash", json!({ "command": "ls" })),
            tool_result("c2", "file listing body padding"),
        ];
        let plan = dedup_plan(&history);
        assert!(plan.is_empty(), "bash is not a snapshot tool this pass");
    }

    fn long_shell_body() -> String {
        let mut lines = Vec::new();
        for i in 0..700 {
            lines.push(format!("noise line {i}"));
        }
        lines.join("\n")
    }

    #[test]
    fn tool_result_prune_artifact_boundary_replaces_large_surviving_bash_result_with_a_frame() {
        let mut history = vec![
            assistant_call("c1", "bash", json!({ "command": "cargo test" })),
            tool_result("c1", &long_shell_body()),
        ];

        let candidates = condense_candidates(&history);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].tool, "bash");
        assert!(candidates[0].condensed_body.len() < candidates[0].original_body.len());

        assert!(apply_condensed_tool_result(
            &mut history,
            &candidates[0],
            &render_prune_artifact_frame(&candidates[0], None, Some("artifact_limit"))
        ));
        let body = body_at(&history, 1);
        assert!(body.starts_with("<cockpit_artifact_v1 "));
        assert!(body.contains("\"capture_reason\":\"prune_boundary\""));
        assert!(body.contains("\"line_count\":700"));
        assert!(body.contains("\"status\":\"unavailable\""));
    }

    #[test]
    fn elision_marker_states_wire_recovery_and_omits_event_id() {
        let marker = Elision {
            original_event_id: "call-hidden".to_string(),
            reason: REASON_SNAPSHOT_SUPERSEDED,
        }
        .marker_text();

        assert!(marker.starts_with("[elided: "));
        assert!(marker.contains("snapshot superseded — "));
        assert!(marker.contains("later identical call in this conversation"));
        assert!(marker.contains("use that one"));
        assert!(marker.contains("Not retrievable"));
        assert!(marker.contains("not worth re-running"));
        assert!(!marker.contains("transcript event"));
        assert!(!marker.contains("call-hidden"));
    }

    #[test]
    fn frame_shaped_output_needs_a_durable_prune_owner() {
        let snapshot = Elision {
            original_event_id: "call-hidden".to_string(),
            reason: REASON_SNAPSHOT_SUPERSEDED,
        }
        .marker_text();
        let overlap = overlap::overlap_marker_line();

        for body in [snapshot, overlap] {
            let history = vec![
                assistant_call("c1", "bash", json!({ "command": "printf marker" })),
                tool_result("c1", &body),
            ];
            assert!(current_elided_ids(&history).is_empty());
            assert!(capture_ledger(&history, history.len()).elided.is_empty());
        }
    }

    #[test]
    fn elision_marker_predicates_match_both_new_markers() {
        let snapshot = Elision {
            original_event_id: "call-hidden".to_string(),
            reason: REASON_SNAPSHOT_SUPERSEDED,
        }
        .marker_text();
        let overlap = overlap::overlap_marker_line();

        assert!(Elision::is_marker(&snapshot));
        assert!(Elision::contains_marker(&snapshot));
        assert!(Elision::is_marker(&overlap));
        assert!(Elision::contains_marker(&overlap));
    }

    #[test]
    fn contains_overlap_marker_distinguishes_the_two_families() {
        let snapshot = Elision {
            original_event_id: "call-hidden".to_string(),
            reason: REASON_SNAPSHOT_SUPERSEDED,
        }
        .marker_text();
        let overlap = overlap::overlap_marker_line();

        assert!(contains_overlap_marker(&overlap));
        assert!(!contains_overlap_marker(&snapshot));
    }

    #[test]
    fn exact_snapshot_marker_matches_the_new_marker_text() {
        let marker = Elision {
            original_event_id: "call-hidden".to_string(),
            reason: REASON_SNAPSHOT_SUPERSEDED,
        }
        .marker_text();

        assert!(exact_snapshot_marker(&marker, "call-hidden"));
    }

    #[test]
    fn prune_is_idempotent_over_its_own_snapshot_output() {
        let args = json!({ "path": "/abs/idempotent.rs" });
        let mut history = vec![
            assistant_call("c1", "read", args.clone()),
            tool_result("c1", "same body with enough padding"),
            assistant_call("c2", "read", args),
            tool_result("c2", "same body with enough padding"),
        ];

        let first = dedup_plan(&history);
        assert_eq!(first.targets.len(), 1);
        assert_eq!(apply_plan(&mut history, &first), 1);
        let after_first = history.clone();
        let second = dedup_plan(&history);
        assert!(second.is_empty());
        assert_eq!(second.tokens_saved(), 0);
        assert_eq!(apply_plan(&mut history, &second), 0);

        assert_eq!(history, after_first);
    }

    #[test]
    fn bash_truncated_body_is_replaced_by_one_artifact_frame() {
        let original = format!("[truncated]\n{}", long_shell_body());
        let mut history = vec![
            assistant_call("c1", "bash", json!({ "command": "cargo test" })),
            tool_result("c1", &original),
        ];

        let candidates = condense_candidates(&history);
        assert_eq!(candidates.len(), 1);
        assert!(apply_condensed_tool_result(
            &mut history,
            &candidates[0],
            &render_prune_artifact_frame(&candidates[0], None, Some("artifact_limit"))
        ));

        let body = body_at(&history, 1);
        assert_eq!(body.matches("<cockpit_artifact_v1").count(), 1, "{body}");
    }

    #[test]
    fn prune_boundary_leaves_short_bash_result_full() {
        let history = vec![
            assistant_call("c1", "bash", json!({ "command": "echo ok" })),
            tool_result("c1", "ok\n"),
        ];

        assert!(condense_candidates(&history).is_empty());
    }

    #[test]
    fn prune_boundary_never_condenses_excluded_file_tools() {
        for tool in ["read", "read", "write", "edit", "unlock"] {
            let history = vec![
                assistant_call(
                    "c1",
                    tool,
                    json!({ "command": "cat big", "path": "/tmp/x" }),
                ),
                tool_result("c1", &long_shell_body()),
            ];

            assert!(
                condense_candidates(&history).is_empty(),
                "{tool} must not be prune-boundary condensed"
            );
        }
    }

    #[test]
    fn prune_ledger_keeps_artifact_frame_out_of_the_durable_delta() {
        let original = long_shell_body();
        let mut pruned = vec![
            assistant_call("c1", "bash", json!({ "command": "cargo test" })),
            tool_result("c1", &original),
        ];
        let candidates = condense_candidates(&pruned);
        let frame = render_prune_artifact_frame(&candidates[0], None, Some("artifact_limit"));
        apply_condensed_tool_result(&mut pruned, &candidates[0], &frame);
        let durable_prune_calls = std::collections::BTreeSet::from(["c1".to_owned()]);
        assert!(condense_candidates_with_artifact_calls(&pruned, &durable_prune_calls).is_empty());
        let ledger = capture_ledger_with_prune_boundary_calls(&pruned, 2, &durable_prune_calls);
        assert_eq!(ledger.elided.len(), 1);
        assert_eq!(ledger.elided[0].reason, REASON_TOOL_RESULT_CONDENSED);
        assert_eq!(ledger.elided[0].partial_body, None);

        let mut rebuilt = vec![
            assistant_call("c1", "bash", json!({ "command": "cargo test" })),
            tool_result("c1", &original),
        ];
        assert_eq!(reapply_ledger(&ledger, &mut rebuilt).unwrap(), 1);
        assert_ne!(body_at(&rebuilt, 1), frame);
    }

    /// Already-elided newest body → leave older bodies full (no marker
    /// pointing at nothing).
    #[test]
    fn newest_already_elided_keeps_older_full() {
        let args = json!({ "path": "/f" });
        let marker = Elision {
            original_event_id: "c2".into(),
            reason: "snapshot superseded",
        }
        .marker_text();
        let history = vec![
            assistant_call("c1", "read", args.clone()),
            tool_result("c1", "older full body padding padding"),
            assistant_call("c2", "read", args),
            tool_result("c2", &marker),
        ];
        let plan = dedup_plan(&history);
        assert!(
            plan.is_empty(),
            "surviving body is elided; older must stay full"
        );
    }

    /// Three identical reads: the two older bodies elide, the newest
    /// survives.
    #[test]
    fn three_reads_elides_two() {
        let args = json!({ "path": "/f" });
        let mut history = vec![
            assistant_call("c1", "read", args.clone()),
            tool_result("c1", "body one padding padding padding"),
            assistant_call("c2", "read", args.clone()),
            tool_result("c2", "body two padding padding padding"),
            assistant_call("c3", "read", args.clone()),
            tool_result("c3", "body three padding padding padding"),
        ];
        let plan = dedup_plan(&history);
        assert_eq!(plan.targets.len(), 2);
        assert_eq!(apply_plan(&mut history, &plan), 2);
        assert!(Elision::is_marker(&body_at(&history, 1)));
        assert!(Elision::is_marker(&body_at(&history, 3)));
        assert!(!Elision::is_marker(&body_at(&history, 5)));
    }

    /// `current_elided_ids` reflects the live wire state exactly: after a
    /// prune it returns the elided body's id; the kept newest body is
    /// absent; an un-pruned history yields nothing.
    #[test]
    fn marker_like_tool_output_is_not_captured_as_prune_state() {
        let cases = [
            (
                "bash-elided",
                "bash",
                json!({ "command": "printf marker" }),
                "[elided: command output, not cockpit state]\nstill real output",
            ),
            (
                "bash-frame-shaped",
                "bash",
                json!({ "command": "printf marker" }),
                "<cockpit_artifact_v1 payload_utf8_bytes=1>\nnot a valid generated frame\n</cockpit_artifact_v1>\nstill real output",
            ),
            (
                "read-elided",
                "read",
                json!({ "path": "/f" }),
                "[elided: file content, not cockpit state]\nstill real file body",
            ),
        ];

        for (call_id, tool, args, body) in cases {
            let mut history = vec![
                assistant_call(call_id, tool, args),
                tool_result(call_id, body),
            ];
            assert_eq!(
                current_elided_ids(&history),
                Vec::<String>::new(),
                "{call_id}"
            );
            let ledger = capture_ledger(&history, history.len());
            assert!(ledger.elided.is_empty(), "{call_id} captured: {ledger:?}");
            assert_eq!(reapply_ledger(&ledger, &mut history).unwrap(), 0);
            assert_eq!(body_at(&history, 1), body, "{call_id} body changed");
        }
    }

    #[test]
    fn actual_apply_plan_elisions_still_capture_and_reapply() {
        let args = json!({ "path": "/abs/foo.rs" });
        let mut history = vec![
            assistant_call("c1", "read", args.clone()),
            tool_result("c1", "FULL BODY ONE with lots of content here"),
            assistant_call("c2", "read", args.clone()),
            tool_result("c2", "FULL BODY TWO with lots of content here"),
        ];
        prune_history(&mut history);
        assert_eq!(current_elided_ids(&history), vec!["c1".to_string()]);
        let ledger = capture_ledger(&history, history.len());
        assert_eq!(ledger.elided.len(), 1);

        let mut rebuilt = vec![
            assistant_call("c1", "read", args.clone()),
            tool_result("c1", "FULL BODY ONE with lots of content here"),
            assistant_call("c2", "read", args),
            tool_result("c2", "FULL BODY TWO with lots of content here"),
        ];
        assert_eq!(reapply_ledger(&ledger, &mut rebuilt).unwrap(), 1);
        assert_eq!(body_at(&rebuilt, 1), body_at(&history, 1));
        assert_eq!(body_at(&rebuilt, 3), body_at(&history, 3));
    }

    #[test]
    fn current_elided_ids_tracks_wire_state() {
        let args = json!({ "path": "/abs/foo.rs" });
        let mut history = vec![
            assistant_call("c1", "read", args.clone()),
            tool_result("c1", "FULL BODY ONE with lots of content here"),
            assistant_call("c2", "read", args.clone()),
            tool_result("c2", "FULL BODY TWO with lots of content here"),
        ];
        // Nothing elided yet.
        assert!(current_elided_ids(&history).is_empty());

        prune_history(&mut history);
        let elided = current_elided_ids(&history);
        // Only the older body's id is elided; the kept newest is not.
        assert_eq!(elided, vec!["c1".to_string()]);
        assert!(!elided.contains(&"c2".to_string()));
    }

    /// The prune ledger captured from a pruned history re-applies to a
    /// freshly-rebuilt (full) copy to yield a BYTE-IDENTICAL pruned form:
    /// the same marker text on the same id, every other body intact. This
    /// is the resume-rehydration fidelity guarantee
    /// (implementation note).
    #[test]
    fn ledger_capture_reapply_is_byte_identical() {
        let args = json!({ "path": "/abs/foo.rs" });
        let mut history = vec![
            assistant_call("c1", "read", args.clone()),
            tool_result("c1", "FULL BODY ONE with lots of content here"),
            assistant_call("c2", "read", args.clone()),
            tool_result("c2", "FULL BODY TWO with lots of content here"),
        ];
        // Prune in place, then capture the ledger from the pruned state.
        prune_history(&mut history);
        let ledger = capture_ledger(&history, history.len());
        assert_eq!(ledger.elided.len(), 1);
        assert_eq!(ledger.elided[0].original_event_id, "c1");
        assert_eq!(ledger.watermark, history.len());

        // A fresh "rebuilt-from-transcript" copy with FULL bodies.
        let mut rebuilt = vec![
            assistant_call("c1", "read", args.clone()),
            tool_result("c1", "FULL BODY ONE with lots of content here"),
            assistant_call("c2", "read", args.clone()),
            tool_result("c2", "FULL BODY TWO with lots of content here"),
        ];
        let n = reapply_ledger(&ledger, &mut rebuilt).expect("clean re-apply");
        assert_eq!(n, 1);
        // Byte-identical to the in-place-pruned history.
        assert_eq!(body_at(&rebuilt, 1), body_at(&history, 1));
        assert_eq!(body_at(&rebuilt, 3), body_at(&history, 3));
        assert!(Elision::is_marker(&body_at(&rebuilt, 1)));
        assert_eq!(
            body_at(&rebuilt, 3),
            "FULL BODY TWO with lots of content here"
        );
    }

    /// A ledger naming an id that isn't a full tool-result in the rebuilt
    /// history is inconsistent — `reapply` returns the missing ids (the
    /// caller then falls back to the full unpruned form + warn).
    #[test]
    fn ledger_reapply_reports_missing_ids() {
        let args = json!({ "path": "/f" });
        let mut rebuilt = vec![
            assistant_call("c1", "read", args.clone()),
            tool_result("c1", "only body padding padding"),
        ];
        let ledger = PruneLedger {
            elided: vec![LedgerEntry {
                original_event_id: "ghost".into(),
                reason: REASON_SNAPSHOT_SUPERSEDED.into(),
                partial_body: None,
            }],
            watermark: 2,
        };
        let err = reapply_ledger(&ledger, &mut rebuilt).unwrap_err();
        assert_eq!(err, vec!["ghost".to_string()]);
        // The history was NOT mutated (no partial elision on inconsistency).
        assert_eq!(body_at(&rebuilt, 1), "only body padding padding");
    }

    /// An empty ledger (nothing pruned) re-applies as a no-op.
    #[test]
    fn empty_ledger_reapply_is_noop() {
        let args = json!({ "path": "/f" });
        let mut rebuilt = vec![
            assistant_call("c1", "read", args.clone()),
            tool_result("c1", "body padding padding"),
        ];
        let ledger = PruneLedger::default();
        assert!(ledger_is_empty(&ledger));
        assert_eq!(reapply_ledger(&ledger, &mut rebuilt).unwrap(), 0);
        assert_eq!(body_at(&rebuilt, 1), "body padding padding");
    }

    #[test]
    fn cache_cold_three_cases() {
        let none = CacheConfig {
            mode: CacheMode::None,
            ttl_secs: 300,
        };
        let ephemeral = CacheConfig {
            mode: CacheMode::Ephemeral,
            ttl_secs: 300,
        };

        // (a) no-cache provider → cold regardless of timing.
        assert_eq!(
            cache_state(&none, Some(0), false),
            CacheState::Cold(ColdReason::NoCacheProvider)
        );
        // (c) upstream bust → cold even when the prefix would be warm.
        assert_eq!(
            cache_state(&ephemeral, Some(1), true),
            CacheState::Cold(ColdReason::UpstreamBust)
        );
        // (b) TTL elapsed → cold.
        assert_eq!(
            cache_state(&ephemeral, Some(301), false),
            CacheState::Cold(ColdReason::TtlElapsed)
        );
        // No send yet → cold (no warm prefix to lose).
        assert_eq!(
            cache_state(&ephemeral, None, false),
            CacheState::Cold(ColdReason::TtlElapsed)
        );
        // Warm: ephemeral, within TTL, no bust.
        assert_eq!(cache_state(&ephemeral, Some(10), false), CacheState::Hot);
        assert!(!cache_state(&ephemeral, Some(10), false).is_cold());
    }

    /// The cache-aware reuse-vs-fresh decision for a re-queried subagent
    /// (implementation note) maps the three cache states
    /// onto the three follow-up paths, deterministically.
    #[test]
    fn followup_reuse_three_cases() {
        let none = CacheConfig {
            mode: CacheMode::None,
            ttl_secs: 300,
        };
        let ephemeral = CacheConfig {
            mode: CacheMode::Ephemeral,
            ttl_secs: 300,
        };
        // Caches + warm prefix intact → reuse the warm context (cheapest).
        assert_eq!(
            followup_reuse(&ephemeral, Some(10), false),
            FollowupReuse::WarmReuse
        );
        // Caches but TTL elapsed → rehydrate fresh (cache will be re-created).
        assert_eq!(
            followup_reuse(&ephemeral, Some(301), false),
            FollowupReuse::RehydrateFresh
        );
        // Caches but the next call busts the anchor upstream → rehydrate fresh.
        assert_eq!(
            followup_reuse(&ephemeral, Some(10), true),
            FollowupReuse::RehydrateFresh
        );
        // No warm prefix yet (never sent) but the provider DOES cache → fresh.
        assert_eq!(
            followup_reuse(&ephemeral, None, false),
            FollowupReuse::RehydrateFresh
        );
        // Provider has no cache at all → reuse the existing agent context.
        assert_eq!(
            followup_reuse(&none, Some(10), false),
            FollowupReuse::NoCacheReuse
        );
    }

    // ---- overlap-merge (implementation note) ----------

    /// Build a line-numbered read body covering inclusive lines `[start,
    /// end]`, in the exact `"{n}|…"` shape the read tool emits, so the
    /// overlap parser sees real line numbers.
    fn read_body(start: usize, end: usize) -> String {
        let mut s = String::new();
        for n in start..=end {
            s.push_str(&format!("{n}|line {n} content padding padding\n"));
        }
        s
    }

    /// A newer read of the same file whose range OVERLAPS an older read: the
    /// older body's overlapping lines are elided (partial body) and tell the
    /// model to use the newer body; its non-overlapping remainder is kept
    /// verbatim.
    #[test]
    fn overlap_merge_elides_overlap_keeps_remainder() {
        let args1 = json!({ "path": "/f", "offset": 1, "limit": 20 });
        let args2 = json!({ "path": "/f", "offset": 10, "limit": 20 });
        let mut history = vec![
            assistant_call("c1", "read", args1),
            tool_result("c1", &read_body(1, 20)),
            assistant_call("c2", "read", args2),
            tool_result("c2", &read_body(10, 29)),
        ];
        let plan = dedup_plan(&history);
        assert_eq!(plan.targets.len(), 1, "the older read's overlap is elided");
        assert_eq!(plan.targets[0].target_call_id, "c1");
        assert_eq!(plan.targets[0].elision.reason, OVERLAP_REASON);
        assert!(plan.targets[0].partial_body.is_some());
        assert!(plan.tokens_saved() > 0, "material savings");

        apply_plan(&mut history, &plan);
        let older = body_at(&history, 1);
        // Lines 1..=9 (non-overlap) kept; 10..=20 (overlap) elided; one
        // marker tells the model to use the newer retaining body.
        assert!(older.contains("1|line 1"));
        assert!(older.contains("9|line 9"));
        assert!(!older.contains("10|line 10"));
        assert!(!older.contains("20|line 20"));
        assert!(older.contains("[elided:"));
        assert!(older.contains("later read in this conversation"));
        assert!(!older.contains("c2"));
        // The newer body is untouched (the union of content survives in it).
        assert!(body_at(&history, 3).contains("29|line 29"));
    }

    /// A read fully contained by a later read (superset supersession) is
    /// fully elided — every line is retained by the newer body.
    #[test]
    fn overlap_merge_subset_is_fully_elided() {
        let inner = json!({ "path": "/f", "offset": 5, "limit": 3 });
        let whole = json!({ "path": "/f", "limit": 100 });
        let mut history = vec![
            assistant_call("c1", "read", inner),
            tool_result("c1", &read_body(5, 7)),
            assistant_call("c2", "read", whole),
            tool_result("c2", &read_body(1, 30)),
        ];
        let plan = dedup_plan(&history);
        assert_eq!(plan.targets.len(), 1);
        apply_plan(&mut history, &plan);
        let older = body_at(&history, 1);
        // No content lines left — just the marker (all lines retained in c2).
        assert!(!older.contains("5|line 5"));
        assert!(older.contains("[elided:"));
    }

    /// Disjoint (non-overlapping) reads of the same file are NOT redundant —
    /// both bodies are kept in full.
    #[test]
    fn overlap_merge_disjoint_reads_both_kept() {
        let a = json!({ "path": "/f", "offset": 1, "limit": 10 });
        let b = json!({ "path": "/f", "offset": 50, "limit": 10 });
        let mut history = vec![
            assistant_call("c1", "read", a),
            tool_result("c1", &read_body(1, 10)),
            assistant_call("c2", "read", b),
            tool_result("c2", &read_body(50, 59)),
        ];
        let plan = dedup_plan(&history);
        assert!(plan.is_empty(), "disjoint ranges are not redundant");
        assert_eq!(apply_plan(&mut history, &plan), 0);
    }

    /// Overlapping reads of DIFFERENT files don't merge.
    #[test]
    fn overlap_merge_different_files_untouched() {
        let a = json!({ "path": "/a", "offset": 1, "limit": 20 });
        let b = json!({ "path": "/b", "offset": 1, "limit": 20 });
        let history = vec![
            assistant_call("c1", "read", a),
            tool_result("c1", &read_body(1, 20)),
            assistant_call("c2", "read", b),
            tool_result("c2", &read_body(1, 20)),
        ];
        let plan = dedup_plan(&history);
        assert!(plan.is_empty(), "different files never overlap-merge");
    }

    /// The overlap-merge form survives a ledger capture + re-apply
    /// byte-identically (deterministic resume).
    #[test]
    fn overlap_merge_ledger_round_trip_is_byte_identical() {
        let args1 = json!({ "path": "/f", "offset": 1, "limit": 20 });
        let args2 = json!({ "path": "/f", "offset": 10, "limit": 20 });
        let build = || {
            vec![
                assistant_call("c1", "read", args1.clone()),
                tool_result("c1", &read_body(1, 20)),
                assistant_call("c2", "read", args2.clone()),
                tool_result("c2", &read_body(10, 29)),
            ]
        };
        let mut history = build();
        prune_history(&mut history);
        let ledger = capture_ledger(&history, history.len());
        assert_eq!(ledger.elided.len(), 1);
        assert!(ledger.elided[0].partial_body.is_some());
        assert_eq!(ledger.elided[0].reason, OVERLAP_REASON);

        // A fresh full rebuild re-pruned via the ledger is byte-identical.
        let mut rebuilt = build();
        let n = reapply_ledger(&ledger, &mut rebuilt).expect("clean re-apply");
        assert_eq!(n, 1);
        assert_eq!(body_at(&rebuilt, 1), body_at(&history, 1));
        assert_eq!(body_at(&rebuilt, 3), body_at(&history, 3));
    }

    /// A synthetic climb of overlapping reads of ONE file collapses to the
    /// union with redundant overlap elided and total tokens materially down.
    #[test]
    fn overlap_merge_collapses_overlapping_climb() {
        let mk = |id: &str, off: usize| {
            let args = json!({ "path": "/big.rs", "offset": off, "limit": 30 });
            (
                assistant_call(id, "read", args),
                tool_result(id, &read_body(off, off + 49)),
            )
        };
        // Five heavily-overlapping reads sliding down the same file.
        let mut history = Vec::new();
        for (i, off) in [1usize, 10, 20, 30, 40].iter().enumerate() {
            let (a, r) = mk(&format!("c{i}"), *off);
            history.push(a);
            history.push(r);
        }
        let before: usize = history.iter().map(wire_tokens).sum();
        let plan = dedup_plan(&history);
        assert!(!plan.is_empty());
        prune_history(&mut history);
        let after: usize = history.iter().map(wire_tokens).sum();
        // The overlap is materially reclaimed (not a token or two).
        assert!(
            before.saturating_sub(after) > before / 4,
            "expected material reduction; before={before} after={after}"
        );
        // The newest read (c4) is untouched — the union's tail survives.
        assert!(body_at(&history, 9).contains("89|line 89"));
    }

    /// Helper: approximate the wire tokens of one message via the same
    /// tokenizer the projection uses, over its tool-result body (the only
    /// thing prune touches).
    fn wire_tokens(msg: &Message) -> usize {
        match msg {
            Message::User { content } => content
                .iter()
                .map(|c| match c {
                    UserContent::ToolResult(tr) => {
                        crate::tokens::count(&tool_result_body(&tr.content))
                    }
                    _ => 0,
                })
                .sum(),
            _ => 0,
        }
    }
}
