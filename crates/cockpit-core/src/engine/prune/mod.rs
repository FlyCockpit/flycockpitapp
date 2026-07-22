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
//! is always recoverable (`cockpit session show`). The marker carries
//! the originating `call_id` as `original_event_id` to point a reader
//! at the full body.
//!
//! ## Snapshot-class tools
//!
//! `read` and the non-mutating codebase-intelligence tools
//! (`outline`, `symbol_find`, `word`, `deps`, `circular`, `tree`,
//! `search`). Deliberately excluded this pass (see `plan.md` T6.d):
//! `bash` (the command is interpretive context; classifying which
//! commands are snapshots is the hard problem), `edit`/`write` (their
//! args carry semantic content), and `hot` (a ranking, not a snapshot
//! of a single addressable resource).

pub use crate::db::prune_ledger::{LedgerEntry, PruneLedger};

use crate::config::providers::{CacheConfig, CacheMode};
use crate::engine::message::{AssistantContent, Message};
use crate::tools::shell_compress;
use rig::OneOrMany;
use rig::message::{ToolResultContent, UserContent};

mod overlap;
pub use overlap::OVERLAP_REASON;

/// Tools whose repeated identical calls produce a redundant snapshot
/// body. `read` plus the non-mutating intel tools. `hot`, `bash`,
/// `edit`, `write` are intentionally absent (see module docs).
pub const SNAPSHOT_TOOLS: &[&str] = &[
    "read",
    "outline",
    "symbol_find",
    "word",
    "deps",
    "circular",
    "tree",
    "search",
];

pub const COMPRESSED_RESULT_MARKER_PREFIX: &str = "[compressed tool result:";
pub const REASON_TOOL_RESULT_CONDENSED: &str = "tool result condensed";

const PRUNE_BOUNDARY_CONDENSE_TOOLS: &[&str] = &["bash"];
const PRUNE_BOUNDARY_CONDENSE_EXCLUDED_TOOLS: &[&str] =
    &["read", "readlock", "writeunlock", "editunlock", "unlock"];

fn is_snapshot_tool(name: &str) -> bool {
    SNAPSHOT_TOOLS.contains(&name)
}

fn is_prune_boundary_condense_tool(name: &str) -> bool {
    PRUNE_BOUNDARY_CONDENSE_TOOLS.contains(&name)
        && !PRUNE_BOUNDARY_CONDENSE_EXCLUDED_TOOLS.contains(&name)
}

pub fn compressed_tool_result_marker(
    tool: &str,
    original_bytes: usize,
    condensed_bytes: usize,
    lines: usize,
    hash: &str,
) -> String {
    format!(
        "{COMPRESSED_RESULT_MARKER_PREFIX} tool={tool} original_bytes={original_bytes} condensed_bytes={condensed_bytes} lines={lines} hash={hash} retrieve with tool_result_retrieve]"
    )
}

pub fn is_compressed_tool_result_marker(body: &str) -> bool {
    body.lines().any(is_compressed_tool_result_marker_line)
}

fn is_compressed_tool_result_marker_line(line: &str) -> bool {
    line.starts_with(COMPRESSED_RESULT_MARKER_PREFIX)
        && line.contains(" retrieve with tool_result_retrieve]")
}

fn is_truncated_tool_result_marker_line(line: &str) -> bool {
    line.starts_with("[truncated")
        && line.contains(" tool result:")
        && line.contains(" retrieve with tool_result_retrieve]")
}

fn strip_truncated_tool_result_marker_lines(body: &str) -> String {
    let mut out = String::new();
    let mut stripped = false;
    for line in body.lines() {
        if is_truncated_tool_result_marker_line(line) {
            stripped = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if stripped { out } else { body.to_string() }
}

fn contains_overlap_marker(body: &str) -> bool {
    let prefix = format!(
        "[elided: {OVERLAP_REASON} — these lines are in a later read; full body in transcript event "
    );
    body.lines()
        .any(|line| line.starts_with(&prefix) && line.ends_with(']'))
}

fn exact_snapshot_marker(body: &str, call_id: &str) -> bool {
    body == (Elision {
        original_event_id: call_id.to_string(),
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

/// A reasoning-block / superseded snapshot body that has been removed
/// from the wire history. The single mechanism for body removal: it
/// rewrites a tool-result body, never a call's shape.
///
/// `original_event_id` is the originating tool call's `id` (the same
/// value the `tool_calls` row keys on), so a reader can recover the
/// full body from the on-disk transcript. `reason` is a terse,
/// human-readable explanation rendered into the marker text.
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
            "[elided: {} — superseded by a later identical call; full body in transcript event {}]",
            self.reason, self.original_event_id
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
                    call_identity.insert(tc.id.clone(), key);
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
                    let Some(key) = call_identity.get(&tr.id) else {
                        continue;
                    };
                    let body = tool_result_body(&tr.content);
                    let elided = Elision::is_marker(&body);
                    groups.entry(key.clone()).or_default().push(ResultLoc {
                        history_index: idx,
                        call_id: tr.id.clone(),
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
    // `readlock`); this closure only extracts the `path` arg, so a `readlock`
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

/// The canonical file path a `read`/`readlock` call addressed, from its `path`
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
                    && tr.id == target.target_call_id
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
                    && tr.id == target.target_call_id
                {
                    // Rewrite the body only; keep id/call_id intact so
                    // the tool_use↔tool_result pairing stays valid. An
                    // overlap-merge target writes its pre-rendered partial
                    // body (non-overlapping remainder + marker); an
                    // exact-identity target writes the whole-body marker.
                    tr.content = OneOrMany::one(ToolResultContent::text(target.replacement_body()));
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
                    calls.insert(tc.id.clone(), (tool.to_string(), command));
                }
            }
        }
    }

    let mut candidates = Vec::new();
    for (idx, msg) in history.iter().enumerate() {
        if let Message::User { content } = msg {
            for c in content.iter() {
                if let UserContent::ToolResult(tr) = c {
                    let Some((tool, command)) = calls.get(&tr.id) else {
                        continue;
                    };
                    let body = tool_result_body(&tr.content);
                    if Elision::contains_marker(&body) || is_compressed_tool_result_marker(&body) {
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
                        call_id: tr.id.clone(),
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
    hash: &str,
) -> bool {
    apply_condensed_tool_result_direct(history, candidate, hash)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondensePlan {
    pub targets: Vec<CondenseTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondenseTarget {
    pub candidate: CondenseCandidate,
    pub hash: String,
}

pub fn apply_condense_plan_to(history: &[Message], plan: &CondensePlan) -> Vec<Message> {
    let mut derived = history.to_vec();
    for target in &plan.targets {
        apply_condensed_tool_result_direct(&mut derived, &target.candidate, &target.hash);
    }
    derived
}

pub fn apply_condensed_tool_result_to(
    history: &[Message],
    candidate: &CondenseCandidate,
    hash: &str,
) -> Vec<Message> {
    apply_condense_plan_to(
        history,
        &CondensePlan {
            targets: vec![CondenseTarget {
                candidate: candidate.clone(),
                hash: hash.to_string(),
            }],
        },
    )
}

fn apply_condensed_tool_result_direct(
    history: &mut [Message],
    candidate: &CondenseCandidate,
    hash: &str,
) -> bool {
    let condensed_body = strip_truncated_tool_result_marker_lines(&candidate.condensed_body);
    let replacement = format!(
        "{}\n{}",
        compressed_tool_result_marker(
            &candidate.tool,
            candidate.original_body.len(),
            condensed_body.len(),
            candidate.original_body.lines().count(),
            hash,
        ),
        condensed_body
    );
    let Some(msg) = history.get_mut(candidate.history_index) else {
        return false;
    };
    if let Message::User { content } = msg {
        for c in content.iter_mut() {
            if let UserContent::ToolResult(tr) = c
                && tr.id == candidate.call_id
            {
                tr.content = OneOrMany::one(ToolResultContent::text(replacement));
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
                    tools.insert(tc.id.clone(), tc.function.name.clone());
                }
            }
        }
    }
    tools
}

fn is_generated_prune_body(body: &str, call_id: &str, tool: Option<&str>) -> bool {
    let Some(tool) = tool else {
        return false;
    };
    if is_snapshot_tool(tool) {
        exact_snapshot_marker(body, call_id) || contains_overlap_marker(body)
    } else if is_prune_boundary_condense_tool(tool) {
        body.lines()
            .next()
            .is_some_and(is_compressed_tool_result_marker_line)
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
    let tools = tool_names_by_call_id(history);
    let mut ids = Vec::new();
    for msg in history {
        if let Message::User { content } = msg {
            for c in content.iter() {
                if let UserContent::ToolResult(tr) = c {
                    let body = tool_result_body(&tr.content);
                    if is_generated_prune_body(&body, &tr.id, tools.get(&tr.id).map(String::as_str))
                    {
                        ids.push(tr.id.clone());
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
///   `original_event_id` + `reason` [`apply_plan`] wrote, so the marker
///   text reproduces character-for-character on rebuild (the same
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
    let tools = tool_names_by_call_id(history);
    let mut elided = Vec::new();
    for msg in history {
        if let Message::User { content } = msg {
            for c in content.iter() {
                if let UserContent::ToolResult(tr) = c {
                    let body = tool_result_body(&tr.content);
                    let tool = tools.get(&tr.id).map(String::as_str);
                    if tool.is_some_and(is_snapshot_tool) && exact_snapshot_marker(&body, &tr.id) {
                        // Whole-body exact-identity marker: re-renders from
                        // id + reason, no body to store.
                        elided.push(LedgerEntry {
                            original_event_id: tr.id.clone(),
                            reason: REASON_SNAPSHOT_SUPERSEDED.to_string(),
                            partial_body: None,
                        });
                    } else if tool.is_some_and(is_snapshot_tool) && contains_overlap_marker(&body) {
                        // Overlap-merge partial body: store it verbatim so
                        // resume reproduces it byte-identically (the overlap
                        // geometry is not re-derived from a possibly-shifted
                        // file).
                        elided.push(LedgerEntry {
                            original_event_id: tr.id.clone(),
                            reason: overlap::OVERLAP_REASON.to_string(),
                            partial_body: Some(body),
                        });
                    } else if tool.is_some_and(is_prune_boundary_condense_tool)
                        && body
                            .lines()
                            .next()
                            .is_some_and(is_compressed_tool_result_marker_line)
                    {
                        // Prune-boundary tool condensation: store the
                        // model-bound condensed body verbatim so resume
                        // reproduces the pruned context exactly. The exact
                        // full body lives in compressed_tool_results.
                        elided.push(LedgerEntry {
                            original_event_id: tr.id.clone(),
                            reason: REASON_TOOL_RESULT_CONDENSED.to_string(),
                            partial_body: Some(body),
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
                    by_id.insert(tr.id.as_str(), (idx, tool_result_body(&tr.content)));
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

/// Concatenate a tool-result's text content into one body string.
/// Images contribute nothing to the textual body (snapshot tools never
/// emit images anyway).
fn tool_result_body(content: &OneOrMany<ToolResultContent>) -> String {
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
    use rig::OneOrMany;
    use rig::message::{AssistantContent, ToolResult};
    use serde_json::json;

    /// Build an assistant message carrying one snapshot tool call.
    fn assistant_call(call_id: &str, tool: &str, args: serde_json::Value) -> Message {
        let tc = ToolCall {
            id: call_id.to_string(),
            call_id: None,
            function: rig::message::ToolFunction {
                name: tool.to_string(),
                arguments: args,
            },
            signature: None,
            additional_params: None,
        };
        Message::Assistant {
            id: None,
            content: OneOrMany::one(AssistantContent::ToolCall(tc)),
        }
    }

    /// Build a user message carrying one tool result body.
    fn tool_result(call_id: &str, body: &str) -> Message {
        Message::User {
            content: OneOrMany::one(UserContent::ToolResult(ToolResult {
                id: call_id.to_string(),
                call_id: None,
                content: OneOrMany::one(ToolResultContent::text(body)),
            })),
        }
    }

    fn tool_results(results: &[(&str, &str)]) -> Message {
        Message::User {
            content: OneOrMany::many(
                results
                    .iter()
                    .map(|(call_id, body)| {
                        UserContent::ToolResult(ToolResult {
                            id: (*call_id).to_string(),
                            call_id: None,
                            content: OneOrMany::one(ToolResultContent::text(*body)),
                        })
                    })
                    .collect::<Vec<_>>(),
            )
            .expect("non-empty tool results"),
        }
    }

    fn body_at(history: &[Message], idx: usize) -> String {
        match &history[idx] {
            Message::User { content } => tool_result_body(match content.first_ref() {
                UserContent::ToolResult(tr) => &tr.content,
                _ => panic!("not a tool result"),
            }),
            _ => panic!("not a user message"),
        }
    }

    fn tool_result_id_at(history: &[Message], idx: usize) -> String {
        match &history[idx] {
            Message::User { content } => match content.first_ref() {
                UserContent::ToolResult(tr) => tr.id.clone(),
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
            "[elided: snapshot superseded — superseded by a later identical call; full body in transcript event exact-old]"
        );
        assert_eq!(body_at(&history, 3), "exact new body with enough padding");
        assert_eq!(
            body_at(&history, 5),
            "1|line 1 content\n[elided: overlapping read superseded — these lines are in a later read; full body in transcript event overlap-new]\n"
        );
        assert_eq!(
            body_at(&history, 7),
            "2|line 2 content\n3|line 3 content\n4|line 4 content\n"
        );
    }

    #[test]
    fn characterize_condense_apply_wire_shape() {
        let original = long_shell_body();
        let mut history = vec![
            assistant_call("bash-one", "bash", json!({ "command": "cargo test" })),
            tool_result("bash-one", &original),
        ];

        let candidates = condense_candidates(&history);
        assert_eq!(candidates.len(), 1);
        let expected_condensed =
            crate::tools::shell_compress::prune_boundary_condense("cargo test", &original)
                .expect("fixture should condense");
        let expected = format!(
            "{}\n{}",
            compressed_tool_result_marker(
                "bash",
                original.len(),
                expected_condensed.len(),
                original.lines().count(),
                "0123456789abcdefabcdef12",
            ),
            expected_condensed
        );

        assert!(apply_condensed_tool_result(
            &mut history,
            &candidates[0],
            "0123456789abcdefabcdef12",
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
                .enumerate()
                .map(|(index, candidate)| CondenseTarget {
                    candidate: candidate.clone(),
                    hash: format!("hash-{index}"),
                })
                .collect(),
        };

        let mut sequential = history.clone();
        for target in &plan.targets {
            assert!(apply_condensed_tool_result(
                &mut sequential,
                &target.candidate,
                &target.hash,
            ));
        }
        let bulk = apply_condense_plan_to(&history, &plan);

        assert_eq!(
            serde_json::to_value(bulk).unwrap(),
            serde_json::to_value(&sequential).unwrap()
        );
        assert!(body_at(&sequential, 1).contains("hash=hash-0"));
        assert!(body_at(&sequential, 3).contains("hash=hash-1"));
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
    fn prune_boundary_condenses_large_surviving_bash_result() {
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
            "0123456789abcdefabcdef12"
        ));
        let body = body_at(&history, 1);
        assert!(body.contains(COMPRESSED_RESULT_MARKER_PREFIX));
        assert!(body.contains("tool=bash"));
        assert!(body.contains("original_bytes="));
        assert!(body.contains("condensed_bytes="));
        assert!(body.contains("lines=700"));
        assert!(body.contains("hash=0123456789abcdefabcdef12"));
        assert!(body.contains("[deterministic shell condensation]"));
    }

    #[test]
    fn compressed_marker_reports_line_count() {
        let marker =
            compressed_tool_result_marker("bash", 1000, 100, 42, "0123456789abcdefabcdef12");

        assert!(marker.contains("lines=42"));
        assert!(marker.contains("retrieve with tool_result_retrieve"));
    }

    #[test]
    fn compressed_marker_with_line_count_is_still_detected() {
        let marker =
            compressed_tool_result_marker("bash", 1000, 100, 42, "0123456789abcdefabcdef12");

        assert!(is_compressed_tool_result_marker(&marker));
        assert!(is_compressed_tool_result_marker_line(&marker));
    }

    #[test]
    fn bash_truncated_body_still_condenses_to_one_compressed_marker() {
        let original = format!(
            "[truncated tool result: tool=bash delivered_bytes=8000 stored_bytes=12000 original_bytes=12000 lines=900 hash=aaaaaaaaaaaaaaaaaaaaaaaa retrieve with tool_result_retrieve]\n{}",
            long_shell_body()
        );
        let mut history = vec![
            assistant_call("c1", "bash", json!({ "command": "cargo test" })),
            tool_result("c1", &original),
        ];

        let candidates = condense_candidates(&history);
        assert_eq!(candidates.len(), 1);
        assert!(apply_condensed_tool_result(
            &mut history,
            &candidates[0],
            "0123456789abcdefabcdef12"
        ));

        let body = body_at(&history, 1);
        assert_eq!(
            body.lines()
                .filter(|line| line.starts_with(COMPRESSED_RESULT_MARKER_PREFIX))
                .count(),
            1,
            "{body}"
        );
        assert_eq!(
            body.matches("retrieve with tool_result_retrieve").count(),
            1
        );
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
        for tool in ["read", "readlock", "writeunlock", "editunlock", "unlock"] {
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
    fn prune_ledger_reapplies_condensed_tool_result_body() {
        let original = long_shell_body();
        let mut pruned = vec![
            assistant_call("c1", "bash", json!({ "command": "cargo test" })),
            tool_result("c1", &original),
        ];
        let candidates = condense_candidates(&pruned);
        apply_condensed_tool_result(&mut pruned, &candidates[0], "0123456789abcdefabcdef12");
        let condensed = body_at(&pruned, 1);

        let ledger = capture_ledger(&pruned, 2);
        assert_eq!(ledger.elided.len(), 1);
        assert_eq!(ledger.elided[0].reason, REASON_TOOL_RESULT_CONDENSED);
        assert_eq!(
            ledger.elided[0].partial_body.as_deref(),
            Some(condensed.as_str())
        );

        let mut rebuilt = vec![
            assistant_call("c1", "bash", json!({ "command": "cargo test" })),
            tool_result("c1", &original),
        ];
        assert_eq!(reapply_ledger(&ledger, &mut rebuilt).unwrap(), 1);
        assert_eq!(body_at(&rebuilt, 1), condensed);
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
                "bash-compressed",
                "bash",
                json!({ "command": "printf marker" }),
                "[compressed tool result: command output, not cockpit state]\nstill real output",
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
    /// older body's overlapping lines are elided (partial body) and point at
    /// the newer body; its non-overlapping remainder is kept verbatim.
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
        // Lines 1..=9 (non-overlap) kept; 10..=20 (overlap) elided; one marker
        // pointing at c2 (the newer retaining body).
        assert!(older.contains("1|line 1"));
        assert!(older.contains("9|line 9"));
        assert!(!older.contains("10|line 10"));
        assert!(!older.contains("20|line 20"));
        assert!(older.contains("[elided:"));
        assert!(older.contains("c2"));
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
