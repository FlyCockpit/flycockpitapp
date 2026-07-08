//! Overlap-merge dedup for repeated near-identical `read`s of one file
//! (implementation note).
//!
//! The exact-identity dedup in the parent module ([`super::dedup_plan`])
//! only collapses byte-identical snapshot calls. Two reads of the SAME file
//! with **overlapping** line ranges (a re-read at a shifted `offset`, a
//! superset re-read of the whole file) escape it — yet the overlapping lines
//! are redundant: the newer read carries the current version of them.
//!
//! This module computes, for the `read`/`readlock` tool-result bodies of one
//! canonical file, which older bodies' line sub-ranges are **fully covered**
//! by a newer read of the same file, and rewrites the older body to elide
//! exactly those lines while keeping its non-overlapping remainder. The
//! elided sub-range is replaced by a one-line marker that points at the
//! newer (retaining) body's `original_event_id`, mirroring the whole-body
//! [`super::Elision`] marker convention.
//!
//! ## Reconstructable from the WIRE (correctness #1)
//!
//! A sub-range is elided from an older body **only** when some newer body
//! still in the wire history covers those exact lines in full. The union of
//! content therefore always remains reconstructable from the model-bound
//! history itself — never only from the on-disk transcript. A read whose
//! whole covered range is a subset of a newer read is fully elided (every
//! line is retained elsewhere); a read with a non-overlapping remainder
//! keeps that remainder verbatim.
//!
//! ## Read body line-range format
//!
//! The `read` tool ([`crate::tools::read`]) emits a line-numbered body:
//! every content line is `"{n}|{text}"` ([`crate::tools::common::line_number`]).
//! Range-mode reads prepend a `"[hash=… total_lines=… returned=A-B]"` header
//! and plain reads may prepend `Note:`/lock preludes and append a
//! `"… [truncated, …]"` marker — none of which are numbered lines. We parse
//! the **numbered lines** (their 1-indexed line number is the prefix) to
//! learn exactly which file lines a body carries; non-numbered prelude/header/
//! truncation lines are structural and are always preserved. This is the same
//! `"{n}: "` shape the line-numberer produces, so the parse is exact, not a
//! heuristic.

use std::collections::HashMap;

use rig::message::UserContent;

use super::{Elision, ElisionTarget};
use crate::engine::message::{AssistantContent, Message};

/// The canonical reason recorded for an overlap-merge partial/whole elision,
/// distinct from the exact-identity `"snapshot superseded"` so telemetry and
/// the ledger can tell the two apart.
pub const OVERLAP_REASON: &str = "overlapping read superseded";

/// The `read`-class tools whose bodies are line-numbered and so participate
/// in overlap-merge. Only these — the other snapshot tools
/// (`outline`/`symbol_find`/… ) keep the unchanged whole-body exact-identity
/// dedup.
const READ_TOOLS: &[&str] = &["read", "readlock"];

fn is_read_tool(name: &str) -> bool {
    READ_TOOLS.contains(&name)
}

/// An inclusive 1-indexed line span `[start, end]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineRange {
    pub start: usize,
    pub end: usize,
}

impl LineRange {
    fn contains_line(&self, n: usize) -> bool {
        n >= self.start && n <= self.end
    }
}

/// Parse the contiguous 1-indexed line range a `read` result body carries,
/// from its numbered lines (`"{n}|…"`). Returns `None` when the body has
/// no numbered lines (an empty/`offset`-past-EOF read, or an
/// already-elided marker) — such a body never participates in overlap-merge.
///
/// The covered range is `min..=max` of the numbered line numbers present.
/// Reads are emitted as a contiguous slice, so the present line numbers are
/// contiguous in practice; we tolerate a gap by treating the range as the
/// full `min..=max` span (a gap would only make us *more* conservative about
/// what a newer read must cover to elide).
pub fn line_range_of_read(body: &str) -> Option<LineRange> {
    let mut min = usize::MAX;
    let mut max = 0usize;
    for line in body.lines() {
        if let Some(n) = numbered_line_no(line) {
            min = min.min(n);
            max = max.max(n);
        }
    }
    if max == 0 {
        None
    } else {
        Some(LineRange {
            start: min,
            end: max,
        })
    }
}

/// The 1-indexed line number a numbered body line carries, or `None` for a
/// header/prelude/truncation line. The current numberer emits `"{n}|{text}"`,
/// i.e. ASCII digits then `'|'` (no leading padding). We require that exact
/// shape so a content line that merely happens to start with a number is not
/// mistaken for a line-number prefix. As a resume-compat fallback we also
/// accept the legacy `"{:>5}: {text}"` form (optional leading spaces, digits,
/// then `": "` / bare `":"`) so old-format read bodies persisted in a resumed
/// session still overlap-dedup. The `'|'` branch takes precedence.
fn numbered_line_no(line: &str) -> Option<usize> {
    // Primary form: no leading padding, digits, then `'|'`.
    let digits_end = line.find(|c: char| !c.is_ascii_digit())?;
    if digits_end > 0 {
        let (digits, rest) = line.split_at(digits_end);
        if rest.starts_with('|') {
            return digits.parse::<usize>().ok();
        }
    }
    // Legacy fallback: optional leading spaces, digits, then `": "` / `":"`.
    let trimmed = line.trim_start_matches(' ');
    let digits_end = trimmed.find(|c: char| !c.is_ascii_digit())?;
    if digits_end == 0 {
        return None;
    }
    let (digits, rest) = trimmed.split_at(digits_end);
    if !rest.starts_with(": ") && rest != ":" {
        return None;
    }
    digits.parse::<usize>().ok()
}

/// One read result located in the wire history: where it is, its call id, the
/// canonical file it read, its covered line range, and whether it is already
/// an elision marker.
struct ReadLoc {
    history_index: usize,
    call_id: String,
    canonical_path: String,
    range: LineRange,
    body: String,
    already_elided: bool,
}

/// Compute the overlap-merge elision targets for the read bodies in
/// `history`. For each older read whose covered lines are (partly or wholly)
/// also covered by a **newer** read of the same canonical file, produce one
/// [`ElisionTarget`] that rewrites the older body, eliding the overlapping
/// lines and keeping the non-overlapping remainder. Targets are returned in
/// history order; the parent module merges them with the exact-identity plan.
///
/// `canonical_path_of` maps an assistant tool-call's args to the canonical
/// file path the read addressed (so two reads of the same file via different
/// path spellings still merge). The parent passes the same canonicalizer used
/// for the identity key.
pub fn overlap_targets(
    history: &[Message],
    canonical_path_of: &dyn Fn(&str, &serde_json::Value) -> Option<String>,
) -> Vec<ElisionTarget> {
    // call_id → canonical path, for the read-class tools only.
    let mut path_of_call: HashMap<String, String> = HashMap::new();
    for msg in history {
        if let Message::Assistant { content, .. } = msg {
            for c in content.iter() {
                if let AssistantContent::ToolCall(tc) = c
                    && is_read_tool(&tc.function.name)
                    && let Some(p) = canonical_path_of(&tc.function.name, &tc.function.arguments)
                {
                    path_of_call.insert(tc.id.clone(), p);
                }
            }
        }
    }

    // Collect the read results in history order.
    let mut reads: Vec<ReadLoc> = Vec::new();
    for (idx, msg) in history.iter().enumerate() {
        if let Message::User { content } = msg {
            for c in content.iter() {
                if let UserContent::ToolResult(tr) = c {
                    let Some(path) = path_of_call.get(&tr.id) else {
                        continue;
                    };
                    let body = super::tool_result_body(&tr.content);
                    // A body carrying ANY elision marker (whole-body OR a
                    // partial overlap result) is already-pruned state: it is
                    // neither a candidate to elide further NOR usable as a
                    // "covering" newer body — a partial body's numbered-line
                    // span has a gap where its marker sits, so it does not
                    // actually retain every line in `min..=max`. Treating it
                    // as covering would break reconstructability (#1).
                    let already_elided = Elision::contains_marker(&body);
                    // A whole-body marker has no numbered lines, so
                    // `line_range_of_read` returns None and it is skipped.
                    let Some(range) = line_range_of_read(&body) else {
                        continue;
                    };
                    reads.push(ReadLoc {
                        history_index: idx,
                        call_id: tr.id.clone(),
                        canonical_path: path.clone(),
                        range,
                        body,
                        already_elided,
                    });
                }
            }
        }
    }

    let mut targets = Vec::new();
    for i in 0..reads.len() {
        let older = &reads[i];
        if older.already_elided {
            continue;
        }
        // The set of older-body lines covered by SOME strictly-newer read of
        // the same file whose body is still full (a marker retains nothing).
        // Reconstructability (#1): we only ever elide lines a newer full body
        // still carries.
        let covering: Vec<&ReadLoc> = reads[i + 1..]
            .iter()
            .filter(|newer| {
                !newer.already_elided
                    && newer.canonical_path == older.canonical_path
                    && ranges_overlap(older.range, newer.range)
            })
            .collect();
        if covering.is_empty() {
            continue;
        }

        // Rewrite the older body, eliding each numbered line that a covering
        // newer read retains, and pointing the marker at the newest covering
        // body (the one whose content the model should read instead).
        let pointer = covering
            .last()
            .map(|c| c.call_id.clone())
            .expect("covering is non-empty");
        let Some(new_body) = rewrite_eliding_covered(&older.body, &covering) else {
            // Nothing was actually elided (e.g. a present gap line no newer
            // read covers) — skip rather than emit a no-op target.
            continue;
        };
        if new_body == older.body {
            continue;
        }
        targets.push(ElisionTarget {
            history_index: older.history_index,
            current_body: older.body.clone(),
            elision: Elision {
                original_event_id: pointer,
                reason: OVERLAP_REASON,
            },
            // The pre-rendered partial-body replacement. When present,
            // `apply_plan` writes this verbatim instead of the whole-body
            // marker, so the non-overlapping remainder survives.
            partial_body: Some(new_body),
            target_call_id: older.call_id.clone(),
        });
    }
    targets
}

/// Two inclusive ranges overlap when neither lies entirely before the other.
fn ranges_overlap(a: LineRange, b: LineRange) -> bool {
    a.start <= b.end && b.start <= a.end
}

/// Rewrite `body`, dropping every numbered line whose line number is covered
/// by some `covering` newer read, and collapsing each maximal run of dropped
/// lines into one marker pointing at the newest covering body. Non-numbered
/// structural lines (header / `Note:` prelude / truncation marker) are always
/// kept. Returns `None` when no numbered line was covered (no elision to do).
fn rewrite_eliding_covered(body: &str, covering: &[&ReadLoc]) -> Option<String> {
    // The newest covering body's id is the pointer for every marker we write
    // (the freshest retained copy of the lines).
    let pointer = covering.last()?.call_id.as_str();

    let mut out = String::with_capacity(body.len());
    let mut in_elided_run = false;
    let mut any_elided = false;
    let trailing_newline = body.ends_with('\n');

    for line in body.lines() {
        let covered = match numbered_line_no(line) {
            Some(n) => covering.iter().any(|c| c.range.contains_line(n)),
            None => false,
        };
        if covered {
            if !in_elided_run {
                // Open a new elided run with a single marker line.
                out.push_str(&overlap_marker_line(pointer));
                out.push('\n');
                in_elided_run = true;
                any_elided = true;
            }
            // Skip the covered line itself.
        } else {
            in_elided_run = false;
            out.push_str(line);
            out.push('\n');
        }
    }
    if !any_elided {
        return None;
    }
    // Restore the body's original trailing-newline shape (we always push a
    // trailing '\n' per line above; trim it when the original had none).
    if !trailing_newline && out.ends_with('\n') {
        out.pop();
    }
    Some(out)
}

/// The one-line marker that replaces an elided overlapping line run, pointing
/// at the newer body that retains those lines. Terse (token economy §10) and
/// prefixed `"[elided:"` so [`Elision::is_marker`] recognizes it (it never
/// re-elides and the resume scan treats it as a pruned body).
pub fn overlap_marker_line(pointer_event_id: &str) -> String {
    format!(
        "[elided: {OVERLAP_REASON} — these lines are in a later read; full body in transcript event {pointer_event_id}]"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_numbered_line_numbers() {
        // Current `{n}|{content}` form.
        assert_eq!(numbered_line_no("1|hello"), Some(1));
        assert_eq!(numbered_line_no("123|x"), Some(123));
        // Empty content (`{n}|`) still counts.
        assert_eq!(numbered_line_no("5|"), Some(5));
        // Content with a `|` further along still recovers the leading number.
        assert_eq!(numbered_line_no("7|a | b | c"), Some(7));
        // Header / prelude / truncation lines are not numbered lines.
        assert_eq!(
            numbered_line_no("[hash=abc total_lines=9 returned=1-3]"),
            None
        );
        assert_eq!(numbered_line_no("Note: lock acquired"), None);
        assert_eq!(
            numbered_line_no("... [truncated, ask read with offset 5]"),
            None
        );
        // A content line that merely starts with a digit but no separator.
        assert_eq!(numbered_line_no("3 blind mice"), None);
    }

    #[test]
    fn parses_legacy_numbered_line_numbers() {
        // Resume-compat fallback: the old `{:>5}: {content}` form.
        assert_eq!(numbered_line_no("    1: hello"), Some(1));
        assert_eq!(numbered_line_no("  123: x"), Some(123));
        // A bare colon (empty content) still counts.
        assert_eq!(numbered_line_no("    5:"), Some(5));
    }

    #[test]
    fn line_range_spans_min_to_max() {
        let body = "3|a\n4|b\n5|c\n";
        assert_eq!(
            line_range_of_read(body),
            Some(LineRange { start: 3, end: 5 })
        );
        // No numbered lines → None.
        assert_eq!(line_range_of_read("Note: empty file\n"), None);
    }

    #[test]
    fn rewrite_elides_only_covered_lines() {
        // Older body covers lines 1..=5; a newer read covers 3..=5.
        let body = "1|a\n2|b\n3|c\n4|d\n5|e\n";
        let newer = ReadLoc {
            history_index: 99,
            call_id: "newer".into(),
            canonical_path: "/f".into(),
            range: LineRange { start: 3, end: 5 },
            body: String::new(),
            already_elided: false,
        };
        let out = rewrite_eliding_covered(body, &[&newer]).expect("some elision");
        // Lines 1,2 kept verbatim; 3-5 collapsed to one marker.
        assert!(out.contains("1|a"));
        assert!(out.contains("2|b"));
        assert!(!out.contains("3|c"));
        assert!(!out.contains("5|e"));
        assert!(out.contains("[elided:"));
        assert!(out.contains("newer"));
        // One marker line for the contiguous covered run.
        assert_eq!(out.matches("[elided:").count(), 1);
    }

    #[test]
    fn rewrite_returns_none_when_nothing_covered() {
        let body = "1|a\n2|b\n";
        let newer = ReadLoc {
            history_index: 99,
            call_id: "newer".into(),
            canonical_path: "/f".into(),
            range: LineRange { start: 50, end: 60 },
            body: String::new(),
            already_elided: false,
        };
        assert!(rewrite_eliding_covered(body, &[&newer]).is_none());
    }

    /// Producer → parser round-trip: numbering a multi-line body and feeding
    /// each line back through `numbered_line_no` recovers the line numbers.
    #[test]
    fn producer_parser_roundtrip() {
        let body = crate::tools::common::line_number("a\nb\nc\nd\ne", 97);
        let recovered: Vec<usize> = body.lines().filter_map(numbered_line_no).collect();
        assert_eq!(recovered, vec![97, 98, 99, 100, 101]);
    }
}
