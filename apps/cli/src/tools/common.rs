//! Shared utilities for the file tools.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::engine::tool::ToolCtx;

/// Resolve a path argument the way every file tool does:
///   - tilde-expand,
///   - relative paths join against the session cwd.
pub fn resolve(arg: &str, cwd: &Path) -> PathBuf {
    let expanded = shellexpand::tilde(arg);
    let p = Path::new(expanded.as_ref());
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

/// Tool-result byte cap per GOALS §10.
pub const OUTPUT_BYTE_CAP: usize = 8 * 1024;
/// Default line cap for the read tools (plan §13a / §10).
pub const READ_LINE_CAP: usize = 2000;

/// Build the §10 truncation marker. Includes a hint for the next call
/// the model should issue.
pub fn truncation_marker(next_offset: usize) -> String {
    format!("... [truncated, ask read with offset {next_offset} to see more]")
}

/// Largest char boundary `<= index`. Polyfill for nightly-only
/// `str::floor_char_boundary`; shared by every tool that caps output.
pub fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    let mut i = index;
    while !s.is_char_boundary(i) && i > 0 {
        i -= 1;
    }
    i
}

/// Smallest char boundary `>= index`.
pub fn ceil_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    let mut i = index;
    while !s.is_char_boundary(i) && i < s.len() {
        i += 1;
    }
    i
}

/// Cap `s` to `cap` bytes, byte-boundary-safe, keeping a **head and a
/// tail** so the failure signal (which usually surfaces at the tail —
/// stderr, a non-zero exit line, a panic message) survives. The elided
/// middle is replaced with a one-line `[truncated N bytes]` marker.
/// Returns `s` unchanged when it already fits.
pub fn truncate_head_tail(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        return s.to_string();
    }
    // Reserve room for the marker, then split the remaining budget
    // 3:2 between head and tail.
    let marker_reserve = 48;
    let budget = cap.saturating_sub(marker_reserve);
    let head_budget = budget * 3 / 5;
    let tail_budget = budget - head_budget;
    let head_end = floor_char_boundary(s, head_budget);
    let tail_start = ceil_char_boundary(s, s.len().saturating_sub(tail_budget));
    let elided = tail_start.saturating_sub(head_end);
    let mut out = String::with_capacity(head_end + (s.len() - tail_start) + marker_reserve);
    out.push_str(&s[..head_end]);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!("... [truncated {elided} bytes] ...\n"));
    out.push_str(&s[tail_start..]);
    out
}

/// Result of [`read_slice`]: the line-numbered body, whether it was
/// capped, and the 1-indexed line the model/composer should pass as the
/// next `offset` to continue reading. It also carries the total line
/// count discovered during the same pass and whether the requested
/// offset was past EOF.
pub struct ReadSlice {
    pub numbered: String,
    pub truncated: bool,
    pub next_offset: usize,
    pub total_lines: usize,
    pub offset_exceeded: bool,
}

/// Core of the `read` tool's output formatting (plan §13a), factored out
/// so composer `@`-tag inlining produces byte-for-byte identical
/// line-numbered, capped output. `offset` is 1-indexed, `limit` is in
/// lines; applies the 2000-line / 8 KB caps. An `offset` past EOF yields
/// an empty body (caller decides how to message it).
pub fn read_slice(text: &str, offset: usize, limit: usize) -> ReadSlice {
    let offset = offset.max(1);
    let byte_cap = OUTPUT_BYTE_CAP.saturating_sub(80);
    let mut numbered = String::new();
    let mut total_lines = 0;
    let mut emitted = 0;
    let mut truncated = false;

    for (i, line) in text.lines().enumerate() {
        let line_no = i + 1;
        total_lines = line_no;
        if line_no < offset {
            continue;
        }
        if emitted >= limit {
            truncated = true;
            continue;
        }
        emitted += 1;
        if numbered.len() <= byte_cap {
            push_numbered_line(&mut numbered, line_no, line);
        } else {
            truncated = true;
        }
    }

    if numbered.len() > byte_cap {
        let safe = floor_char_boundary(&numbered, byte_cap);
        numbered.truncate(safe);
        if !numbered.ends_with('\n') {
            numbered.push('\n');
        }
        truncated = true;
    }
    let offset_exceeded = offset > total_lines;
    let next_offset = if offset_exceeded {
        total_lines + 1
    } else {
        offset + emitted
    };
    ReadSlice {
        numbered,
        truncated,
        next_offset,
        total_lines,
        offset_exceeded,
    }
}

/// Line-number a slice of text in the `${n}|${line}` format GOALS §13a
/// requires. `start_line` is 1-indexed.
#[cfg(test)]
pub fn line_number(text: &str, start_line: usize) -> String {
    let mut out = String::with_capacity(text.len() + text.lines().count() * 3);
    for (i, line) in text.lines().enumerate() {
        push_numbered_line(&mut out, start_line + i, line);
    }
    out
}

fn push_numbered_line(out: &mut String, line_no: usize, line: &str) {
    out.push_str(&line_no.to_string());
    out.push('|');
    out.push_str(line);
    out.push('\n');
}

/// Detect a binary file from the first 1 KB — NUL byte presence, per
/// plan §13a and §1e. Returns true if the file appears binary.
pub fn looks_binary(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(1024)];
    head.contains(&0u8)
}

/// Detect line-ending style (CRLF vs LF) from the first 1 KB.
pub fn detect_crlf(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(1024)];
    head.windows(2).any(|w| w == b"\r\n")
}

pub const LOCK_BOOKKEEPING_ADVISORY: &str = " (note: write landed; lock bookkeeping did not persist — released in-memory only, may reappear on daemon restart)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteReleaseOutcome {
    pub persist_ok: bool,
}

impl WriteReleaseOutcome {
    pub fn advisory(self) -> Option<&'static str> {
        (!self.persist_ok).then_some(LOCK_BOOKKEEPING_ADVISORY)
    }
}

/// Write `bytes` to `path`, release the file lock, and mark the path as
/// read for this session. Creates parent directories as needed.
///
/// Centralizes the post-write sequence shared by every write-capable
/// tool. Once the write lands, lock bookkeeping becomes best-effort:
/// callers still report the write as success and append the rare advisory
/// when release persistence failed.
pub fn write_and_release(
    ctx: &ToolCtx,
    path: &Path,
    bytes: &[u8],
    guard: crate::locks::WriteGuard<'_>,
) -> Result<WriteReleaseOutcome> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes).map_err(|e| anyhow::anyhow!("write `{}`: {e}", path.display()))?;
    let persist_ok = guard.release_after_write();
    ctx.locks.note_read(path, &ctx.agent_id, ctx.session.id);
    Ok(WriteReleaseOutcome { persist_ok })
}

/// Build a minimal in-memory [`ToolCtx`] for tool tests: a fresh
/// in-memory DB, a session rooted at `root`, an empty redaction table,
/// and a lock manager. Shared by the file-tool and intel-tool test
/// modules so each doesn't re-spell the wiring.
#[cfg(test)]
pub(crate) fn test_ctx(root: &Path) -> ToolCtx {
    test_ctx_with_db(root).0
}

#[cfg(test)]
pub(crate) fn test_ctx_with_db(root: &Path) -> (ToolCtx, crate::db::Db) {
    use std::sync::Arc;

    let db = crate::db::Db::open_in_memory().unwrap();
    let session =
        crate::session::Session::create(db.clone(), root.to_path_buf(), "builder").unwrap();
    // Test ctx has no daemon and no zerobox Linux helper installed, so
    // the shell sandbox can't run here (sandboxing part 2). Default the
    // session sandbox OFF — tests that exercise sandbox config/decision
    // logic build their own ctx or flip the flag explicitly.
    session.set_sandbox_enabled(false);
    let locks = Arc::new(crate::locks::LockManager::from_db(db.clone()).unwrap());
    let cfg = crate::config::extended::RedactConfig::default();
    let redact = Arc::new(crate::redact::RedactionTable::build(&cfg, root).unwrap());
    (
        ToolCtx {
            agent_id: "builder".to_string(),
            llm_mode: crate::config::extended::LlmMode::Normal,
            locks,
            session: Arc::new(session),
            cwd: root.to_path_buf(),
            redact,
            interrupts: Arc::new(crate::engine::interrupt::InterruptHub::detached()),
            cancel: tokio_util::sync::CancellationToken::new(),
            approver: None,
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            seeds: crate::engine::seed_collector::SeedCollector::new(),
            has_tree: false,
            has_bash: false,
            events: None,
            lsp: None,
            resource_scheduler: None,
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        },
        db,
    )
}

/// Normalize content for writing: if the original file used CRLF,
/// rewrite plain-LF content to CRLF before writing (per
/// implementation notes §1g).
pub fn normalize_line_endings(content: &str, want_crlf: bool) -> String {
    if want_crlf {
        // Idempotent — never re-double an existing CRLF.
        let mut out = String::with_capacity(content.len() + 16);
        for (i, line) in content.split('\n').enumerate() {
            if i > 0 {
                out.push_str("\r\n");
            }
            // strip a trailing \r left from a previous split if the
            // content already used CRLF
            out.push_str(line.strip_suffix('\r').unwrap_or(line));
        }
        out
    } else {
        // Strip any stray \r so an LF-shaped file stays LF.
        content.replace('\r', "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_number_unpadded_pipe_format() {
        // Single-digit line: no leading padding, `|` separator, no trailing
        // space; an empty content line is `${n}|`.
        assert_eq!(line_number("x", 5), "5|x\n");
        // An empty content line (a blank line in a body) is `${n}|`.
        assert_eq!(line_number("a\n\nb", 5), "5|a\n6|\n7|b\n");
        // No leading space before the number (the old `"    5: "` padding).
        let out = line_number("x", 5);
        assert!(!out.contains("    5|"));
        assert!(!out.contains("5: "));
        // Multi-line increments and keeps the unpadded shape.
        assert_eq!(line_number("a\nb", 99), "99|a\n100|b\n");
    }

    #[test]
    fn write_and_release_prewrite_failure_errors_and_keeps_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let blocked_parent = tmp.path().join("not-a-dir");
        std::fs::write(&blocked_parent, "file blocks directory creation").unwrap();
        let target = blocked_parent.join("child.txt");
        ctx.locks
            .acquire(&target, &ctx.agent_id, ctx.session.id)
            .unwrap();

        let guard = ctx
            .locks
            .begin_write(&target, &ctx.agent_id, ctx.session.id)
            .unwrap();

        let err = write_and_release(&ctx, &target, b"new", guard).unwrap_err();

        assert!(
            err.to_string().contains("Not a directory")
                || err.to_string().contains("not a directory")
                || err.to_string().contains("File exists"),
            "{err}"
        );
        assert_eq!(
            ctx.locks.holder(&target).map(|(_, agent)| agent),
            Some(ctx.agent_id.clone())
        );
    }

    #[test]
    fn truncate_head_tail_short_input_unchanged() {
        assert_eq!(truncate_head_tail("hello", 100), "hello");
    }

    #[test]
    fn read_slice_empty_file_reports_eof_metadata() {
        let slice = read_slice("", 1, READ_LINE_CAP);

        assert_eq!(slice.numbered, "");
        assert!(!slice.truncated);
        assert_eq!(slice.next_offset, 1);
        assert_eq!(slice.total_lines, 0);
        assert!(slice.offset_exceeded);
    }

    #[test]
    fn read_slice_offset_beyond_eof_reports_total_once() {
        let slice = read_slice("a\nb\n", 4, 2);

        assert_eq!(slice.numbered, "");
        assert!(!slice.truncated);
        assert_eq!(slice.next_offset, 3);
        assert_eq!(slice.total_lines, 2);
        assert!(slice.offset_exceeded);
    }

    #[test]
    fn read_slice_exact_limit_is_not_truncated() {
        let slice = read_slice("a\nb\nc\n", 2, 2);

        assert_eq!(slice.numbered, "2|b\n3|c\n");
        assert!(!slice.truncated);
        assert_eq!(slice.next_offset, 4);
        assert_eq!(slice.total_lines, 3);
        assert!(!slice.offset_exceeded);
    }

    #[test]
    fn read_slice_truncation_reports_next_offset() {
        let slice = read_slice("a\nb\nc\n", 1, 2);

        assert_eq!(slice.numbered, "1|a\n2|b\n");
        assert!(slice.truncated);
        assert_eq!(slice.next_offset, 3);
        assert_eq!(slice.total_lines, 3);
        assert!(!slice.offset_exceeded);
    }

    #[test]
    fn truncate_head_tail_never_panics_on_multibyte_boundary() {
        // The bug this guards: `String::truncate` panics if the cap
        // lands mid-codepoint. Build a string of 4-byte chars so most
        // byte offsets are NOT char boundaries.
        let s = "🚀".repeat(2000); // 8000 bytes, no ASCII boundaries
        let out = truncate_head_tail(&s, 8 * 1024 / 2); // cap below len
        assert!(out.len() <= 8 * 1024 / 2 + 64);
        assert!(out.contains("truncated"));
        // Output must be valid UTF-8 (guaranteed by &str) and split on
        // rocket boundaries only.
        assert!(
            out.chars()
                .all(|c| c == '🚀' || !c.is_alphanumeric() || c.is_ascii())
        );
    }

    #[test]
    fn truncate_head_tail_keeps_head_and_tail() {
        let s = format!("{}TAILMARKER", "x".repeat(20_000));
        let out = truncate_head_tail(&s, 1000);
        assert!(out.starts_with("xxxx"));
        assert!(out.ends_with("TAILMARKER"));
        assert!(out.contains("truncated"));
    }
}
