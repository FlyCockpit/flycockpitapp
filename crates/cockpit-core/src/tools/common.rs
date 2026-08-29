//! Shared utilities for the file tools.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::engine::tool::ToolCtx;
use cockpit_host::text::{ceil_char_boundary, floor_char_boundary};

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

/// Drop the unsafe FRONT margin of a segment whose START abuts an omitted region
/// (a bounded-drain middle, a head/tail junction, or a truncation elision). A
/// registered secret straddling that boundary leaves only its SUFFIX at offset
/// `0` of `seg`, which the downstream whole-value §7 scrub cannot match. The
/// enforced/session table matches only finite literals (aho-corasick, no regex),
/// so a finite `M = max_match_len()` bounds any such survivor to `< M` bytes;
/// dropping the leading `M - 1` bytes removes it, and the fixpoint cut snaps
/// PAST any fully-retained secret straddling that margin point so re-scrubbing
/// the remainder never bisects a real secret. Returns `""` (fail-closed) when the
/// whole segment lies inside the unsafe margin. Coordinates are RAW (pre-scrub);
/// this only ELIDES bytes and never substitutes, so it neither double-scrubs nor
/// bypasses the §7 chokepoint that scrubs the emitted text afterward.
pub(crate) fn drop_front_margin<'a>(
    table: &crate::redact::RedactionTable,
    seg: &'a str,
) -> &'a str {
    let max_match = table.max_match_len();
    if max_match <= 1 {
        // Empty table or only 1-byte literals: no multi-byte occurrence can
        // straddle, so there is no partial to strip.
        return seg;
    }
    let margin = max_match - 1;
    if margin >= seg.len() {
        return "";
    }
    let cut = table.straddle_fixpoint_cut(seg, margin);
    if cut >= seg.len() {
        return "";
    }
    &seg[cut..]
}

/// Mirror of [`drop_front_margin`] for a segment whose END abuts an omitted
/// region: a registered secret straddling that boundary leaves only its PREFIX at
/// the END of `seg`. Drops the trailing `M - 1` bytes (snapping the cut BELOW any
/// fully-retained straddling secret via the back fixpoint) so no boundary prefix
/// survives into the whole-value §7 scrub. Returns `""` (fail-closed) when the
/// whole segment lies inside the unsafe margin.
pub(crate) fn drop_back_margin<'a>(table: &crate::redact::RedactionTable, seg: &'a str) -> &'a str {
    let max_match = table.max_match_len();
    if max_match <= 1 {
        return seg;
    }
    let margin = max_match - 1;
    if margin >= seg.len() {
        return "";
    }
    let start = seg.len() - margin;
    let cut = table.straddle_fixpoint_cut_back(seg, start);
    if cut == 0 {
        return "";
    }
    &seg[..cut]
}

/// Boundary-safe [`truncate_head_tail`]. Keeps the same head, `[truncated N bytes]`
/// marker, and tail shape, but the retained head's END and the retained tail's START
/// each abut the elided middle. A registered secret straddling either boundary would
/// otherwise leave a PREFIX (head end) or SUFFIX (tail start) that the downstream
/// whole-value §7 scrub cannot match — a partial-secret leak. This elides the
/// unsafe margin on each side (RAW coordinates, via the table's fixpoint cuts) so
/// only WHOLE secrets — which §7 scrubs normally — remain in the emitted text.
/// The marker itself is a fixed constant scrubbed whole by §7. Output stays
/// within `cap` (it only ever drops MORE than [`truncate_head_tail`]).
pub(crate) fn truncate_head_tail_redacted(
    table: &crate::redact::RedactionTable,
    s: &str,
    cap: usize,
) -> String {
    if s.len() <= cap {
        return s.to_string();
    }
    let marker_reserve = 48;
    let budget = cap.saturating_sub(marker_reserve);
    let head_budget = budget * 3 / 5;
    let tail_budget = budget - head_budget;
    let head_end = floor_char_boundary(s, head_budget);
    let tail_start = ceil_char_boundary(s, s.len().saturating_sub(tail_budget));
    // The head slice ends at, and the tail slice starts at, the elided middle.
    let safe_head = drop_back_margin(table, &s[..head_end]);
    let safe_tail = drop_front_margin(table, &s[tail_start..]);
    let elided = s.len() - safe_head.len() - safe_tail.len();
    let mut out = String::with_capacity(safe_head.len() + safe_tail.len() + marker_reserve);
    out.push_str(safe_head);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!("... [truncated {elided} bytes] ...\n"));
    out.push_str(safe_tail);
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

/// Core of the `read` tool's output formatting (plan §13a). It returns
/// line-numbered output in the shared format used by `read` and composer
/// `@`-tag inlining. `offset` is 1-indexed, `limit` is in lines; the `read`
/// tool uses the legacy 2000-line / 8 KB caps while tag inlining may pass a
/// mode-specific byte ceiling via [`read_slice_with_byte_cap`]. An `offset`
/// past EOF yields an empty body (caller decides how to message it).
pub fn read_slice(text: &str, offset: usize, limit: usize) -> ReadSlice {
    read_slice_with_byte_cap(text, offset, limit, OUTPUT_BYTE_CAP)
}

pub fn read_slice_with_byte_cap(
    text: &str,
    offset: usize,
    limit: usize,
    output_byte_cap: usize,
) -> ReadSlice {
    let offset = offset.max(1);
    let byte_cap = output_byte_cap.saturating_sub(80);
    let mut numbered = String::new();
    let mut total_lines = 0;
    let mut emitted = 0;
    let mut truncated = false;
    let mut stopped_for_byte_cap = false;

    for (i, line) in text.lines().enumerate() {
        let line_no = i + 1;
        total_lines = line_no;
        if line_no < offset {
            continue;
        }
        if emitted >= limit || stopped_for_byte_cap {
            truncated = true;
            continue;
        }
        let before_len = numbered.len();
        push_numbered_line(&mut numbered, line_no, line);
        if numbered.len() > byte_cap {
            numbered.truncate(before_len);
            stopped_for_byte_cap = true;
            truncated = true;
            continue;
        }
        emitted += 1;
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
/// read for this session.
///
/// Centralizes the post-write sequence shared by every write-capable
/// tool. Once the write lands, lock bookkeeping becomes best-effort:
/// callers still report the write as success and append the rare advisory
/// when release persistence failed.
///
/// New-file creation does **not** go through this helper: `WriteTool` uses
/// `create_new_and_release` so missing parents are created with the
/// descriptor-anchored walk. The `create_dir_all` below is leftover
/// defensive code for the existing-file atomic-replace path (the parent
/// already exists; `atomic_write_with` also `metadata(path)?` before
/// rename). Do not unify new-file parent creation with this branch.
pub async fn write_and_release(
    ctx: &ToolCtx,
    path: &Path,
    bytes: &[u8],
    guard: crate::locks::WriteGuard<'_>,
) -> Result<WriteReleaseOutcome> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    atomic_write(path, bytes)?;
    let persist_ok = guard.release_after_write().await;
    ctx.locks
        .note_read(path, &ctx.lock_identity, ctx.session.id)
        .await;
    Ok(WriteReleaseOutcome { persist_ok })
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    atomic_write_with(path, bytes, |_| Ok(()))
}

fn atomic_write_with(
    path: &Path,
    bytes: &[u8],
    before_rename: impl FnOnce(&Path) -> std::io::Result<()>,
) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("write `{}`: no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)?;
    let metadata = std::fs::metadata(path)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.as_file().set_permissions(metadata.permissions())?;
    before_rename(temp.path())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::AsRawFd;
        let rc =
            unsafe { libc::fchown(temp.as_file().as_raw_fd(), metadata.uid(), metadata.gid()) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    temp.persist(path)
        .map_err(|error| anyhow::anyhow!("write `{}`: {}", path.display(), error.error))?;
    Ok(())
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

    debug_assert!(
        root.parent().is_some(),
        "tool test_ctx must use an isolated temp/project root, not the filesystem root"
    );

    let db = crate::db::Db::open_in_memory().unwrap();
    let session = Arc::new(
        crate::session::Session::create_for_test(
            db.clone(),
            root.to_path_buf(),
            "builder",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap(),
    );
    // Test ctx has no daemon and no zerobox Linux helper installed, so
    // the shell sandbox cannot run here (sandboxing part 2). Default the
    // session sandbox OFF — tests that exercise sandbox config/decision
    // logic build their own ctx or flip the flag explicitly.
    session.set_sandbox_enabled(false);
    session.set_approval_mode(crate::config::extended::ApprovalMode::Yolo);
    let locks = Arc::new(crate::locks::LockManager::in_memory(db.clone()));
    let redact = Arc::new(crate::redact::RedactionTable::empty());
    let interrupts = Arc::new(crate::engine::interrupt::InterruptHub::detached());
    let config = crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(root);
    let approver = Arc::new(crate::approval::Approver::new_for_session(
        crate::approval::store::GrantStore::new(
            db.clone(),
            session.id,
            root.to_path_buf(),
            config.clone(),
        ),
        db.clone(),
        session.clone(),
        Arc::new(std::sync::RwLock::new(redact.clone())),
        "builder",
        interrupts.clone(),
    ));
    (
        ToolCtx {
            agent_id: "builder".to_string(),
            agent_instance_id: None,
            lock_identity: "builder".to_string().clone(),
            write_scope: None,
            workspace_lease: None,
            current_tool_call_id: None,
            tool_steering: crate::agents::ToolSteering::Terse,
            locks,
            session,
            cwd: root.to_path_buf(),
            redact,
            interrupts,
            cancel: tokio_util::sync::CancellationToken::new(),
            shutdown_gate: crate::daemon::shutdown::ShutdownSignal::new(),
            approver: Some(approver),
            image_generation_dispatch: None,
            transcription_dispatch: None,
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            root_agent_frame: true,
            skill_write_origin: crate::skills::manage::SkillWriteOrigin::Foreground,
            review_cage: None,
            context_usage: None,
            available_tools: Arc::new(std::collections::HashSet::new()),
            mcp_builtin_registry: Arc::new(crate::mcp::builtin::BuiltinRegistry::default_with(
                Vec::new(),
            )),
            has_tree: false,
            has_bash: false,
            events: None,
            lsp: None,
            resource_scheduler: None,
            media_authority: None,
            media_availability: crate::tool_media_authority::MediaToolAvailability::unavailable(),
            config,
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            mcp_resolver: crate::mcp::resolver::EffectiveCatalogResolver::for_cwd(root),
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

    #[tokio::test]

    async fn line_number_unpadded_pipe_format() {
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

    #[tokio::test]

    async fn write_and_release_prewrite_failure_errors_and_keeps_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let blocked_parent = tmp.path().join("not-a-dir");
        std::fs::write(&blocked_parent, "file blocks directory creation").unwrap();
        let target = blocked_parent.join("child.txt");
        ctx.locks
            .acquire(&target, &ctx.lock_identity, ctx.session.id)
            .await
            .unwrap();

        let guard = ctx
            .locks
            .begin_write(&target, &ctx.lock_identity, ctx.session.id, "write")
            .await
            .unwrap();

        let err = write_and_release(&ctx, &target, b"new", guard)
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("Not a directory")
                || err.to_string().contains("not a directory")
                || err.to_string().contains("File exists"),
            "{err}"
        );
        assert_eq!(
            ctx.locks.holder(&target).map(|(_, agent)| agent),
            Some(ctx.lock_identity.clone())
        );
    }

    #[tokio::test]

    async fn truncate_head_tail_short_input_unchanged() {
        assert_eq!(truncate_head_tail("hello", 100), "hello");
    }

    #[tokio::test]

    async fn read_slice_empty_file_reports_eof_metadata() {
        let slice = read_slice("", 1, READ_LINE_CAP);

        assert_eq!(slice.numbered, "");
        assert!(!slice.truncated);
        assert_eq!(slice.next_offset, 1);
        assert_eq!(slice.total_lines, 0);
        assert!(slice.offset_exceeded);
    }

    #[tokio::test]

    async fn read_slice_offset_beyond_eof_reports_total_once() {
        let slice = read_slice("a\nb\n", 4, 2);

        assert_eq!(slice.numbered, "");
        assert!(!slice.truncated);
        assert_eq!(slice.next_offset, 3);
        assert_eq!(slice.total_lines, 2);
        assert!(slice.offset_exceeded);
    }

    #[tokio::test]

    async fn read_slice_exact_limit_is_not_truncated() {
        let slice = read_slice("a\nb\nc\n", 2, 2);

        assert_eq!(slice.numbered, "2|b\n3|c\n");
        assert!(!slice.truncated);
        assert_eq!(slice.next_offset, 4);
        assert_eq!(slice.total_lines, 3);
        assert!(!slice.offset_exceeded);
    }

    #[tokio::test]

    async fn read_slice_truncation_reports_next_offset() {
        let slice = read_slice("a\nb\nc\n", 1, 2);

        assert_eq!(slice.numbered, "1|a\n2|b\n");
        assert!(slice.truncated);
        assert_eq!(slice.next_offset, 3);
        assert_eq!(slice.total_lines, 3);
        assert!(!slice.offset_exceeded);
    }

    #[tokio::test]

    async fn read_slice_byte_cap_does_not_skip_unshown_lines() {
        let huge = "x".repeat(OUTPUT_BYTE_CAP + 200);
        let slice = read_slice(&format!("{huge}\nsmall\n"), 1, READ_LINE_CAP);

        assert_eq!(slice.numbered, "");
        assert!(slice.truncated);
        assert_eq!(slice.next_offset, 1);
        assert_eq!(slice.total_lines, 2);
        assert!(!slice.offset_exceeded);
    }

    #[tokio::test]

    async fn read_slice_with_byte_cap_uses_explicit_ceiling() {
        let text = format!("{}\nsmall\n", "x".repeat(OUTPUT_BYTE_CAP + 200));
        let legacy = read_slice(&text, 1, READ_LINE_CAP);
        let larger = read_slice_with_byte_cap(&text, 1, READ_LINE_CAP, 48 * 1024);

        assert!(legacy.truncated);
        assert_eq!(legacy.numbered, "");
        assert!(!larger.truncated);
        assert!(larger.numbered.contains("1|"));
        assert!(larger.numbered.contains("2|small"));
    }

    #[tokio::test]

    async fn truncate_head_tail_never_panics_on_multibyte_boundary() {
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

    #[tokio::test]

    async fn truncate_head_tail_keeps_head_and_tail() {
        let s = format!("{}TAILMARKER", "x".repeat(20_000));
        let out = truncate_head_tail(&s, 1000);
        assert!(out.starts_with("xxxx"));
        assert!(out.ends_with("TAILMARKER"));
        assert!(out.contains("truncated"));
    }

    fn leak_table(secret: &str) -> crate::redact::RedactionTable {
        crate::redact::RedactionTable::empty()
            .with_forced_literal(secret.to_string(), "$leak:test".to_string())
            .unwrap()
    }

    // A registered secret straddling the truncate HEAD→middle boundary leaves only
    // its PREFIX at the head end. The whole-value scrub cannot match a prefix, so
    // the plain `truncate_head_tail` leaks it; the redacted variant elides the
    // back margin so nothing partial survives. FAILS against the plain helper.
    #[tokio::test]
    async fn truncate_head_tail_redacted_drops_head_end_straddling_prefix() {
        const SECRET: &str = "sk-live-HEADSTRADDLE-0123456789abcdefXY"; // 39 bytes
        let table = leak_table(SECRET);
        let cap = OUTPUT_BYTE_CAP; // 8192; head_end = floor((8192-48)*3/5) = 4886
        // Place SECRET so it straddles head_end (4886): starts 16 bytes before.
        let s = format!("{}{SECRET}{}", "A".repeat(4870), "B".repeat(7091));
        assert!(s.len() > cap);
        let prefix = &SECRET[..16]; // the head-end survivor a blind cut would keep

        // Current (plain) behavior leaks the straddling prefix past the scrub.
        let leaky = table.scrub(&truncate_head_tail(&s, cap));
        assert!(
            leaky.contains(prefix),
            "precondition: plain truncate must leak the head-end prefix"
        );

        // Boundary-safe variant: neither the full secret nor its prefix survives.
        let fixed = table.scrub(&truncate_head_tail_redacted(&table, &s, cap));
        assert!(!fixed.contains(SECRET));
        assert!(
            !fixed.contains(prefix),
            "head-end straddling prefix leaked: {}",
            &fixed[..64.min(fixed.len())]
        );
        assert!(fixed.len() <= cap);
    }

    // Mirror: a secret straddling the truncate middle→TAIL boundary leaves only
    // its SUFFIX at the tail start. FAILS against the plain helper.
    #[tokio::test]
    async fn truncate_head_tail_redacted_drops_tail_start_straddling_suffix() {
        const SECRET: &str = "sk-live-TAILSTRADDLE-0123456789abcdefXY"; // 39 bytes
        let table = leak_table(SECRET);
        let cap = OUTPUT_BYTE_CAP; // tail_start = ceil(len - 3258)
        // len 12000 → tail_start = 8742. Place SECRET at 8736 → suffix at tail.
        let s = format!("{}{SECRET}{}", "A".repeat(8736), "B".repeat(3225));
        assert_eq!(s.len(), 12000);
        let suffix = &SECRET[SECRET.len() - 20..];

        let leaky = table.scrub(&truncate_head_tail(&s, cap));
        assert!(
            leaky.contains(suffix),
            "precondition: plain truncate must leak the tail-start suffix"
        );

        let fixed = table.scrub(&truncate_head_tail_redacted(&table, &s, cap));
        assert!(!fixed.contains(SECRET));
        assert!(
            !fixed.contains(suffix),
            "tail-start straddling suffix leaked"
        );
        assert!(fixed.len() <= cap);
    }

    // A secret fully contained in the retained head (or tail) is NOT a boundary
    // partial: the redacted truncate must keep it whole so the §7 scrub still
    // replaces it. Guards against over-eliding a real secret out of scrub range.
    #[tokio::test]
    async fn truncate_head_tail_redacted_keeps_contained_secret_scrubbable() {
        const SECRET: &str = "sk-live-CONTAINED-0123456789abcdefghij"; // 38 bytes
        let table = leak_table(SECRET);
        let cap = OUTPUT_BYTE_CAP;
        // SECRET well inside the head (offset 100, head_end ~4886), far from any
        // boundary — it must remain and be scrubbed to the placeholder.
        let s = format!("{}{SECRET}{}", "A".repeat(100), "B".repeat(12000));
        let fixed = table.scrub(&truncate_head_tail_redacted(&table, &s, cap));
        assert!(!fixed.contains(SECRET), "contained secret not scrubbed");
        assert!(fixed.contains(table.placeholder()));
    }

    // Overlapping registered literals at a FRONT margin: the fixpoint must snap
    // past every straddler (aho-corasick emits only leftmost-longest, so a single
    // snap leaves the suppressed literal's suffix). Ported from the harness shape.
    #[tokio::test]
    async fn drop_front_margin_snaps_past_overlapping_literals() {
        let table = crate::redact::RedactionTable::empty()
            .with_forced_literal("abcdefghij".to_string(), "$leak:a".to_string())
            .unwrap()
            .with_forced_literal("cdefghijWXYZ".to_string(), "$leak:b".to_string())
            .unwrap();
        assert_eq!(table.max_match_len(), 12); // margin = 11
        let seg = format!("PPPPPabcdefghijWXYZ{}", "Q".repeat(50));
        // Whole-value redaction must remain safe for overlapping literals too;
        // this guards the redactor independently of the boundary-elision path.
        assert!(
            !table.scrub(&seg).contains("WXYZ"),
            "whole-value scrub leaked an overlapping literal suffix"
        );

        let safe = drop_front_margin(&table, &seg);
        assert!(
            !safe.contains("WXYZ"),
            "overlapping straddler suffix leaked: {safe}"
        );
        assert!(!safe.contains("abcdefghij"));
    }

    // Self-overlapping literal at a front margin (`aaaa` at [0,4) and [1,5)).
    #[tokio::test]
    async fn drop_front_margin_snaps_past_self_overlapping_literal() {
        let table = crate::redact::RedactionTable::empty()
            .with_forced_literal("zzzzz".to_string(), "$leak:m".to_string())
            .unwrap()
            .with_forced_literal("aaaa".to_string(), "$leak:a".to_string())
            .unwrap();
        assert_eq!(table.max_match_len(), 5); // margin = 4
        let seg = format!("aaaaa{}", "Q".repeat(20));
        let safe = drop_front_margin(&table, &seg);
        assert!(
            !safe.contains("aQ"),
            "self-overlapping partial leaked: {safe}"
        );
    }

    // Overlapping registered literals at a BACK margin (the mirror direction):
    // both `WXYZabcdef` and `abcdefghij` end near the segment end; the back
    // fixpoint retreats past both so no PREFIX survives.
    #[tokio::test]
    async fn drop_back_margin_snaps_past_overlapping_literals() {
        let table = crate::redact::RedactionTable::empty()
            .with_forced_literal("WXYZabcdef".to_string(), "$leak:a".to_string())
            .unwrap()
            .with_forced_literal("abcdefghij".to_string(), "$leak:b".to_string())
            .unwrap();
        assert_eq!(table.max_match_len(), 10); // margin = 9
        // `WXYZabcdef` [40,50), `abcdefghij` [44,54); segment ends at 54.
        let seg = format!("{}WXYZabcdefghij", "Q".repeat(40));
        let safe = drop_back_margin(&table, &seg);
        assert!(!safe.contains("WXYZ"), "back straddler leaked: {safe}");
        assert!(!safe.contains("abcdefghij"));
        // Kept the clean prefix, dropped only the trailing straddlers.
        assert!(safe.starts_with("QQQQ"));
    }
}

#[cfg(test)]
mod atomic_write_tests {
    use super::*;

    #[test]
    fn interrupted_write_leaves_original_intact() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("target");
        std::fs::write(&path, b"original").unwrap();
        let error = atomic_write_with(&path, b"replacement", |_| {
            Err(std::io::Error::other("interrupted"))
        })
        .unwrap_err();
        assert!(error.to_string().contains("interrupted"));
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_preserves_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("private");
        std::fs::write(&path, b"before").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        atomic_write(&path, b"after").unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
