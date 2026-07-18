//! Live instructions-file diff injection (prompt
//! `instructions-file-live-diff.md`).
//!
//! The resolved agent-guidance file (`AGENTS.md` / `project guidance`, see
//! [`crate::engine::builtin`]) is baked into the **cached system block**
//! when a session's system prompt is composed, then frozen for the
//! session's lifetime so the client-side prompt cache hits (GOALS §17g).
//! A mid-session edit to that file is therefore invisible to the model.
//!
//! This module supplies the *pure* decision + formatting logic for
//! detecting an in-place edit and injecting it as a trailing
//! **system-role** message — appended only, never rewriting the cached
//! prefix. The stateful glue (snapshot at session start, check-and-inject
//! on every outbound request, baseline advance) lives in
//! [`crate::engine::agent::turn`] + [`crate::session::Session`] +
//! [`crate::db::guidance`]; the functions here are kept side-effect-free
//! so the diff-vs-full-contents decision and the hashing are unit-testable
//! in isolation.

use sha2::{Digest, Sha256};
use similar::{ChangeTag, TextDiff};

/// Fraction-of-lines-changed at or above which a unified diff is judged
/// useless (the change is near-total) and the full new contents are
/// injected instead. `≳50%` per the spec.
const NEAR_TOTAL_THRESHOLD: f64 = 0.5;

/// Content hash of a guidance body, hex-encoded SHA-256. Reuses the same
/// hash the codebase-intelligence index uses (`sha2::Sha256`,
/// [`crate::intel::hex_lower`]) rather than introducing a new hash crate.
pub fn hash_contents(body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    crate::intel::hex_lower(&hasher.finalize())
}

/// What to inject when the guidance file changed in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Injection {
    /// A unified diff (old → new), matching the inline `-`/`+`/context
    /// style of [`crate::tui::diff`]. The default.
    Diff(String),
    /// The full new contents — the fallback when a diff would be useless
    /// (no usable baseline, or a near-total rewrite).
    FullContents(String),
}

impl Injection {
    /// The body text of the injection (diff or full contents), without
    /// the framing header.
    pub fn body(&self) -> &str {
        match self {
            Injection::Diff(s) | Injection::FullContents(s) => s,
        }
    }
}

/// Decide what to inject given the prior stored baseline contents (if any)
/// and the new contents. Pure — no I/O, no DB.
///
/// - No usable baseline (`None`, or a baseline byte-identical to `new`
///   which would diff to nothing) → full contents.
/// - Near-total change (≳50% of lines changed) → full contents.
/// - Otherwise → unified diff.
pub fn decide_injection(baseline: Option<&str>, new: &str) -> Injection {
    let Some(old) = baseline else {
        return Injection::FullContents(new.to_string());
    };
    if old == new {
        // Should not happen on the inject path (the hashes differed), but
        // a hash collision or an upstream caller passing equal bodies must
        // not produce an empty diff. Fall back to full contents.
        return Injection::FullContents(new.to_string());
    }
    if is_near_total(old, new) {
        Injection::FullContents(new.to_string())
    } else {
        Injection::Diff(unified_diff(old, new))
    }
}

/// `true` when the line-level change between `old` and `new` covers at
/// least [`NEAR_TOTAL_THRESHOLD`] of the larger side — i.e. a diff would
/// be mostly noise. Measured as (inserted + deleted) lines over the max of
/// the two line counts, so a full rewrite of an N-line file (N deletes +
/// N inserts vs. N lines) reads as 2.0 ≥ 0.5, and a one-line tweak in a
/// large file stays well under.
fn is_near_total(old: &str, new: &str) -> bool {
    let diff = TextDiff::from_lines(old, new);
    let mut changed = 0usize;
    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Insert | ChangeTag::Delete => changed += 1,
            ChangeTag::Equal => {}
        }
    }
    let old_lines = old.lines().count();
    let new_lines = new.lines().count();
    let denom = old_lines.max(new_lines).max(1);
    (changed as f64) / (denom as f64) >= NEAR_TOTAL_THRESHOLD
}

/// Unified diff (old → new), line-granular, matching the inline style in
/// [`crate::tui::diff`]: `- ` removed, `+ ` added, `  ` context, with
/// [`CONTEXT_LINES`] of context per hunk and a `…` separator between
/// hunks. Reuses `similar` (already a dependency).
pub fn unified_diff(old: &str, new: &str) -> String {
    const CONTEXT_LINES: usize = 3;
    let diff = TextDiff::from_lines(old, new);
    let mut out = String::new();
    let mut first_group = true;
    for group in diff.grouped_ops(CONTEXT_LINES) {
        if !first_group {
            out.push_str("…\n");
        }
        first_group = false;
        for op in group {
            for change in diff.iter_changes(&op) {
                let prefix = match change.tag() {
                    ChangeTag::Delete => "- ",
                    ChangeTag::Insert => "+ ",
                    ChangeTag::Equal => "  ",
                };
                out.push_str(prefix);
                let value = change.value();
                out.push_str(value.strip_suffix('\n').unwrap_or(value));
                out.push('\n');
            }
        }
    }
    // Trim a single trailing newline so the body has no dangling blank
    // line; the caller adds its own framing newlines.
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

/// One-line authoritative framing header for the injected change. `path`
/// is the resolved guidance file's display path. Kept to a single line
/// per token economy (GOALS §10).
pub fn injection_header(path: &str) -> String {
    format!(
        "Your instructions file (`{path}`) changed since this conversation began. Apply the updated version:"
    )
}

/// The full synthetic system-message body: the framing header followed by
/// the diff or full contents. This is what gets [`crate::redact`]-scrubbed
/// and appended to history as a trailing `Message::System`.
pub fn injection_message(path: &str, injection: &Injection) -> String {
    format!("{}\n{}", injection_header(path), injection.body())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_distinguishing() {
        let a = hash_contents("hello\nworld\n");
        let b = hash_contents("hello\nworld\n");
        let c = hash_contents("hello\nWORLD\n");
        assert_eq!(a, b, "same body must hash identically");
        assert_ne!(a, c, "different body must hash differently");
        // SHA-256 hex is 64 lowercase hex chars.
        assert_eq!(a.len(), 64);
        assert!(
            a.chars()
                .all(|ch| ch.is_ascii_hexdigit() && !ch.is_uppercase())
        );
    }

    #[test]
    fn no_baseline_yields_full_contents() {
        let inj = decide_injection(None, "a\nb\nc\n");
        assert_eq!(inj, Injection::FullContents("a\nb\nc\n".to_string()));
    }

    #[test]
    fn equal_baseline_yields_full_contents_not_empty_diff() {
        // Defensive: equal bodies must never produce an empty diff.
        let inj = decide_injection(Some("x\ny\n"), "x\ny\n");
        assert_eq!(inj, Injection::FullContents("x\ny\n".to_string()));
    }

    #[test]
    fn small_edit_yields_unified_diff() {
        let old = "line one\nline two\nline three\nline four\nline five\n";
        let new = "line one\nline two\nline THREE\nline four\nline five\n";
        let inj = decide_injection(Some(old), new);
        match inj {
            Injection::Diff(d) => {
                assert!(d.contains("- line three"), "diff was: {d}");
                assert!(d.contains("+ line THREE"), "diff was: {d}");
                // Context lines present (unchanged neighbors).
                assert!(d.contains("  line two"), "diff was: {d}");
            }
            other => panic!("expected a diff, got {other:?}"),
        }
    }

    #[test]
    fn near_total_rewrite_yields_full_contents() {
        let old = "alpha\nbeta\ngamma\ndelta\nepsilon\n";
        // Every line changed: 5 deletes + 5 inserts over 5 lines = 2.0.
        let new = "ALPHA\nBETA\nGAMMA\nDELTA\nEPSILON\n";
        let inj = decide_injection(Some(old), new);
        assert_eq!(inj, Injection::FullContents(new.to_string()));
    }

    #[test]
    fn just_under_threshold_stays_a_diff() {
        // 10 lines, change exactly 2 (2 del + 2 ins = 4 changed lines over
        // 10 = 0.4 < 0.5) — must remain a diff.
        let old = (0..10).map(|i| format!("line {i}\n")).collect::<String>();
        let mut lines: Vec<String> = (0..10).map(|i| format!("line {i}")).collect();
        lines[3] = "line CHANGED-3".to_string();
        lines[7] = "line CHANGED-7".to_string();
        let new = lines
            .into_iter()
            .map(|l| format!("{l}\n"))
            .collect::<String>();
        assert!(matches!(
            decide_injection(Some(&old), &new),
            Injection::Diff(_)
        ));
    }

    #[test]
    fn at_threshold_is_full_contents() {
        // 4 lines, change exactly 2 (2 del + 2 ins = 4 over 4 = 1.0 ≥ 0.5).
        let old = "a\nb\nc\nd\n";
        let new = "a\nB\nc\nD\n";
        assert_eq!(
            decide_injection(Some(old), new),
            Injection::FullContents(new.to_string())
        );
    }

    #[test]
    fn unified_diff_uses_inline_style_prefixes() {
        let old = "keep\nold\ntail\n";
        let new = "keep\nnew\ntail\n";
        let d = unified_diff(old, new);
        assert!(d.contains("- old"), "{d}");
        assert!(d.contains("+ new"), "{d}");
        assert!(d.contains("  keep"), "{d}");
        assert!(d.contains("  tail"), "{d}");
    }

    #[test]
    fn injection_message_has_one_line_header_then_body() {
        let inj = Injection::Diff("- a\n+ b".to_string());
        let msg = injection_message("/proj/AGENTS.md", &inj);
        let mut lines = msg.lines();
        let header = lines.next().unwrap();
        assert!(header.starts_with("Your instructions file (`/proj/AGENTS.md`) changed"));
        assert!(header.ends_with("Apply the updated version:"));
        assert!(msg.contains("- a"));
        assert!(msg.contains("+ b"));
    }
}
