//! Shared utilities for the file tools.

use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

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
///
/// This is the redacting output truncator (issue #294): the ONLY head/tail
/// truncator, and every output-truncation site routes through it. The
/// retained head's END and the retained tail's START each abut the elided
/// middle, and a registered secret straddling either boundary would
/// otherwise leave a PREFIX (head end) or SUFFIX (tail start) that the
/// downstream whole-value §7 scrub cannot match — a partial-secret leak.
/// The unsafe margin on each side is elided (RAW coordinates, via the
/// table's fixpoint cuts) so only WHOLE secrets — which §7 scrubs normally
/// — remain in the emitted text. The marker itself is a fixed constant
/// scrubbed whole by §7. Output stays within `cap`.
pub(crate) fn truncate_head_tail_redacted(
    table: &crate::redact::RedactionTable,
    s: &str,
    cap: usize,
) -> String {
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

/// Fixed marker inserted at a bounded-drain head/tail junction whose middle was
/// omitted. A constant (never secret-bearing); the §7 scrub matches it whole.
pub(crate) const OMITTED_MIDDLE_MARKER: &str =
    "\n... [output truncated: middle bytes elided] ...\n";

/// Join a bounded-drain capture (retained HEAD + omitted MIDDLE + retained TAIL)
/// into one string, eliding the unsafe margin at the head/tail junction so no
/// boundary-straddling secret PARTIAL reaches the downstream §7 whole-value
/// scrub (issue #294).
///
/// When nothing was dropped (`dropped_bytes == 0`) the head and tail are
/// contiguous in the original stream — there is no omission boundary — so this is
/// exactly the prior `head ++ tail` concatenation. It is likewise a no-op join
/// when the table has no multi-byte literal (`max_match_len <= 1`), so an empty
/// table never perturbs output. Otherwise it drops the back margin of the head
/// (which may hold a straddling secret's PREFIX) and the front margin of the tail
/// (which may hold a straddling secret's SUFFIX) and joins them around the fixed
/// marker. The head and tail are UTF-8-lossy-decoded SEPARATELY at the
/// stream-char-boundary split (`head_len`), so an invalid byte in one never
/// shifts the junction offset.
pub(crate) fn boundary_safe_join(
    table: &crate::redact::RedactionTable,
    cap: cockpit_host::process::BoundedPipeCapture,
) -> String {
    let split = cap.head_len.min(cap.bytes.len());
    let head = String::from_utf8_lossy(&cap.bytes[..split]);
    let tail = String::from_utf8_lossy(&cap.bytes[split..]);
    if cap.dropped_bytes == 0 || table.max_match_len() <= 1 {
        return format!("{head}{tail}");
    }
    let safe_head = drop_back_margin(table, &head);
    let safe_tail = drop_front_margin(table, &tail);
    format!("{safe_head}{OMITTED_MIDDLE_MARKER}{safe_tail}")
}

/// Boundary-safe [`TextArtifactCapture`] builder: the capture's retained body is
/// a PREFIX cut of `combined` at the host byte cap, and a registered secret
/// straddling that cut would leave only its PREFIX in the durable artifact —
/// a partial the admission/export whole-value scrubs cannot match. Elides the
/// unsafe back margin (no-op when nothing was dropped or the table is empty).
pub(crate) fn boundary_safe_capture(
    table: &crate::redact::RedactionTable,
    combined: &str,
) -> crate::engine::tool::TextArtifactCapture {
    let mut base = crate::intel::budget::capture_text_artifact_body(combined);
    if base.host_dropped_bytes == 0 {
        return base;
    }
    let safe = drop_back_margin(table, &base.content);
    base.content = safe.to_string();
    base.stored_source_bytes = base.content.len();
    base
}

/// Result of [`read_slice`]: the line-numbered body, whether it was
/// capped, and the 1-indexed line the model/composer should pass as the
/// next `offset` to continue reading. `next_offset` is the source line
/// immediately after the last shown line, in the SAME post-elision
/// coordinates the rendered numbering is anchored to: when front-margin
/// redaction consumes complete leading lines, both the `${n}|` numbering
/// and the resume cursor advance past them — the cursor must never point
/// back into already-elided or already-emitted content. It also carries
/// the total line count discovered during the same pass and whether the
/// requested offset was past EOF.
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
///
/// Both of the slice's omission edges — the lines before `offset` and any
/// lines cut by the line/byte caps — are redaction-aware (issue #294): the
/// unsafe margin at each edge that abuts omitted content is elided in RAW
/// line-content coordinates (before the `${n}|` numbering is attached, so the
/// line-number prefixes cannot interleave a partial) so a registered secret
/// straddling either edge — a multi-line literal spanning the boundary
/// included — never leaves a PARTIAL the downstream §7 whole-value scrub
/// cannot match.
pub fn read_slice(
    redact: &crate::redact::RedactionTable,
    text: &str,
    offset: usize,
    limit: usize,
) -> ReadSlice {
    read_slice_with_byte_cap(redact, text, offset, limit, OUTPUT_BYTE_CAP)
}

pub fn read_slice_with_byte_cap(
    redact: &crate::redact::RedactionTable,
    text: &str,
    offset: usize,
    limit: usize,
    output_byte_cap: usize,
) -> ReadSlice {
    let offset = offset.max(1);
    let byte_cap = output_byte_cap.saturating_sub(80);

    // Pass 1: walk every line for the total count and collect the requested
    // window (`offset..`, at most `limit` lines). Nothing is rendered yet.
    let mut total_lines = 0usize;
    let mut window: Vec<&str> = Vec::new();
    for (i, line) in text.lines().enumerate() {
        total_lines = i + 1;
        let line_no = i + 1;
        if line_no >= offset && window.len() < limit {
            window.push(line);
        }
    }
    let more_lines = total_lines > (offset - 1) + window.len();
    let offset_exceeded = offset > total_lines;
    if window.is_empty() {
        return ReadSlice {
            numbered: String::new(),
            truncated: more_lines,
            next_offset: if offset_exceeded {
                total_lines + 1
            } else {
                offset
            },
            total_lines,
            offset_exceeded,
        };
    }

    // Front margin: the lines before `offset` were omitted, so the first shown
    // line may begin mid-secret. The margin is applied to the JOINED window
    // content (a multi-line literal's partial may span several leading lines)
    // in raw line-content coordinates — before numbering. Lines the margin
    // consumed keep their numbers: the first RETAINED line is numbered by how
    // many newlines the elided prefix crossed, so numbering stays faithful to
    // the source even when the elision removes leading lines.
    let joined = window.join("\n");
    let (content, first_line_no) = if offset > 1 {
        let safe = drop_front_margin(redact, &joined);
        let dropped_bytes = joined.len() - safe.len();
        let dropped_lines = joined[..dropped_bytes].matches('\n').count();
        (safe.to_string(), offset + dropped_lines)
    } else {
        (joined, offset)
    };
    // Fail-closed margin: when the whole window sat inside the unsafe front
    // margin, show nothing rather than a fragment.
    let safe_lines: Vec<&str> = if content.is_empty() {
        Vec::new()
    } else {
        content.split('\n').collect()
    };

    // Pass 2: dry-run the byte cap over the numbered rendering. A numbered
    // line costs `line_no` digits + 1 (`|`) + line bytes + 1 (`\n`), so a
    // line is kept iff the accumulated numbered length stays within the cap
    // (exactly the original push-then-revert accounting).
    let mut kept = 0usize;
    let mut stopped_for_byte_cap = false;
    let mut len_acc = 0usize;
    for (idx, line) in safe_lines.iter().enumerate() {
        let added = (first_line_no + idx).to_string().len() + 1 + line.len() + 1;
        if len_acc + added > byte_cap {
            stopped_for_byte_cap = true;
            break;
        }
        len_acc += added;
        kept += 1;
    }

    // Back margin: the retained window's END abuts omitted content when
    // EITHER cap fires — the byte cap stopped mid-window, or the LINE LIMIT
    // left lines past the window unshown (`more_lines`) — so the last kept
    // line may end mid-secret (multi-line partials included, via the
    // joined-content coordinates again). Issue #294: the limit edge is an
    // omission edge exactly like the byte-cap edge; a boundary-blind
    // line-limit cut would hand the §7 whole-value scrub a straddling
    // secret's unmatchable PREFIX.
    let shown: Vec<String> = if stopped_for_byte_cap || more_lines {
        let kept_content = safe_lines[..kept].join("\n");
        let safe = drop_back_margin(redact, &kept_content);
        // Fail-closed: when the elision empties the segment (nothing was
        // kept, or the whole kept span lay inside the unsafe margin), show
        // NO lines — never a fabricated empty `${n}|` row — so `next_offset`
        // stays at the first RETAINED line and paging re-offers rather than
        // skips. Own the split lines: `drop_back_margin` borrows
        // `kept_content`, which does not outlive this branch.
        if safe.is_empty() {
            Vec::new()
        } else {
            safe.split('\n').map(str::to_string).collect()
        }
    } else {
        safe_lines[..kept]
            .iter()
            .map(|line| line.to_string())
            .collect()
    };

    let mut numbered = String::with_capacity(len_acc);
    let mut line_no = first_line_no;
    for line in &shown {
        push_numbered_line(&mut numbered, line_no, line);
        line_no += 1;
    }

    // Defensive backstop mirroring the original contract: a single numbered
    // line larger than the whole cap is cut mid-content. The retained end
    // abuts the discarded remainder, so the same back-margin elision applies
    // (no `${n}|` prefixes can interleave a trailing single-line partial).
    if numbered.len() > byte_cap {
        let safe = floor_char_boundary(&numbered, byte_cap);
        numbered.truncate(safe);
        let cut = drop_back_margin(redact, &numbered);
        numbered.truncate(cut.len());
        stopped_for_byte_cap = true;
    }
    if !numbered.is_empty() && !numbered.ends_with('\n') {
        numbered.push('\n');
    }

    ReadSlice {
        numbered,
        truncated: more_lines || stopped_for_byte_cap,
        next_offset: if offset_exceeded {
            total_lines + 1
        } else {
            // Resume at the source line immediately after the last shown
            // line. `shown` is numbered from `first_line_no` — the POST-elision
            // first retained line — so the cursor must anchor there too, not
            // at the pre-elision window start `offset`: when the front margin
            // consumed complete leading lines, `offset + shown.len()` would
            // point back into already-elided or already-emitted content.
            first_line_no + shown.len()
        },
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

/// Finish bookkeeping after a knowledge-base transaction performed the actual
/// mutation. The transaction owns the filesystem/Git rollback boundary, while
/// the native file tools still own their normal lock lifecycle.
pub async fn release_after_external_write(
    ctx: &ToolCtx,
    path: &Path,
    guard: crate::locks::WriteGuard<'_>,
) -> WriteReleaseOutcome {
    let persist_ok = guard.release_after_write().await;
    ctx.locks
        .note_read(path, &ctx.lock_identity, ctx.session.id)
        .await;
    WriteReleaseOutcome { persist_ok }
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
        use std::os::unix::{fs::MetadataExt, io::AsRawFd};
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
            allowed_knowledge_bases: None,
            executing_model_trusted: false,
            knowledge_access_trusted: false,
            caller_model: None,
            agent_instance_id: None,
            lock_identity: "builder".to_string().clone(),
            write_scope: None,
            dream_read_scope: std::sync::Arc::new(std::sync::RwLock::new(None)),
            workspace_lease: None,
            current_tool_call_id: None,
            current_tool_call_scope: None,
            tool_steering: crate::agents::ToolSteering::Terse,
            locks,
            session,
            cwd: root.to_path_buf(),
            redact,
            interrupts,
            cancel: tokio_util::sync::CancellationToken::new(),
            shutdown_gate: crate::daemon::shutdown::ShutdownSignal::new(),
            approver: Some(approver),
            #[cfg(feature = "extended")]
            image_generation_dispatch: None,
            transcription_dispatch: None,
            deferred_log: crate::engine::deferred::DeferredLog::new(),
            root_agent_frame: true,
            skill_write_origin: crate::skills::manage::SkillWriteOrigin::Foreground,
            review_cage: None,
            context_usage: None,
            available_tools: Arc::new(
                [
                    "bash",
                    "escalate",
                    "read",
                    "write",
                    "edit",
                    "history_search",
                    "semantic_search",
                    "structured_search",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
            ),
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

    fn empty_table() -> crate::redact::RedactionTable {
        crate::redact::RedactionTable::empty()
    }

    #[tokio::test]

    async fn truncate_head_tail_redacted_short_input_unchanged() {
        assert_eq!(
            truncate_head_tail_redacted(&empty_table(), "hello", 100),
            "hello"
        );
    }

    #[tokio::test]

    async fn read_slice_empty_file_reports_eof_metadata() {
        let slice = read_slice(&empty_table(), "", 1, READ_LINE_CAP);

        assert_eq!(slice.numbered, "");
        assert!(!slice.truncated);
        assert_eq!(slice.next_offset, 1);
        assert_eq!(slice.total_lines, 0);
        assert!(slice.offset_exceeded);
    }

    #[tokio::test]

    async fn read_slice_offset_beyond_eof_reports_total_once() {
        let slice = read_slice(&empty_table(), "a\nb\n", 4, 2);

        assert_eq!(slice.numbered, "");
        assert!(!slice.truncated);
        assert_eq!(slice.next_offset, 3);
        assert_eq!(slice.total_lines, 2);
        assert!(slice.offset_exceeded);
    }

    #[tokio::test]

    async fn read_slice_exact_limit_is_not_truncated() {
        let slice = read_slice(&empty_table(), "a\nb\nc\n", 2, 2);

        assert_eq!(slice.numbered, "2|b\n3|c\n");
        assert!(!slice.truncated);
        assert_eq!(slice.next_offset, 4);
        assert_eq!(slice.total_lines, 3);
        assert!(!slice.offset_exceeded);
    }

    #[tokio::test]

    async fn read_slice_truncation_reports_next_offset() {
        let slice = read_slice(&empty_table(), "a\nb\nc\n", 1, 2);

        assert_eq!(slice.numbered, "1|a\n2|b\n");
        assert!(slice.truncated);
        assert_eq!(slice.next_offset, 3);
        assert_eq!(slice.total_lines, 3);
        assert!(!slice.offset_exceeded);
    }

    #[tokio::test]

    async fn read_slice_byte_cap_does_not_skip_unshown_lines() {
        let huge = "x".repeat(OUTPUT_BYTE_CAP + 200);
        let slice = read_slice(
            &empty_table(),
            &format!("{huge}\nsmall\n"),
            1,
            READ_LINE_CAP,
        );

        assert_eq!(slice.numbered, "");
        assert!(slice.truncated);
        assert_eq!(slice.next_offset, 1);
        assert_eq!(slice.total_lines, 2);
        assert!(!slice.offset_exceeded);
    }

    #[tokio::test]

    async fn read_slice_with_byte_cap_uses_explicit_ceiling() {
        let text = format!("{}\nsmall\n", "x".repeat(OUTPUT_BYTE_CAP + 200));
        let legacy = read_slice(&empty_table(), &text, 1, READ_LINE_CAP);
        let larger = read_slice_with_byte_cap(&empty_table(), &text, 1, READ_LINE_CAP, 48 * 1024);

        assert!(legacy.truncated);
        assert_eq!(legacy.numbered, "");
        assert!(!larger.truncated);
        assert!(larger.numbered.contains("1|"));
        assert!(larger.numbered.contains("2|small"));
    }

    #[tokio::test]

    async fn truncate_head_tail_redacted_never_panics_on_multibyte_boundary() {
        // The bug this guards: `String::truncate` panics if the cap
        // lands mid-codepoint. Build a string of 4-byte chars so most
        // byte offsets are NOT char boundaries.
        let s = "🚀".repeat(2000); // 8000 bytes, no ASCII boundaries
        let out = truncate_head_tail_redacted(&empty_table(), &s, 8 * 1024 / 2); // cap below len
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

    async fn truncate_head_tail_redacted_keeps_head_and_tail() {
        let s = format!("{}TAILMARKER", "x".repeat(20_000));
        let out = truncate_head_tail_redacted(&empty_table(), &s, 1000);
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
    // a boundary-unsafe cut would leak it; the redacting truncator — now the only
    // head/tail truncator, wired into every output-truncation site (issue #294) —
    // elides the back margin so nothing partial survives the §7 scrub.
    #[tokio::test]
    async fn truncate_head_tail_redacted_drops_head_end_straddling_prefix() {
        const SECRET: &str = "sk-live-HEADSTRADDLE-0123456789abcdefXY"; // 39 bytes
        let table = leak_table(SECRET);
        let cap = OUTPUT_BYTE_CAP; // 8192; head_end = floor((8192-48)*3/5) = 4886
        // Place SECRET so it straddles head_end (4886): starts 16 bytes before.
        let s = format!("{}{SECRET}{}", "A".repeat(4870), "B".repeat(7091));
        assert!(s.len() > cap);
        let prefix = &SECRET[..16]; // the head-end survivor a blind cut would keep

        // Redacting truncator: neither the full secret nor its prefix survives.
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
    // its SUFFIX at the tail start; the redacting truncator elides the front
    // margin so nothing partial survives the §7 scrub.
    #[tokio::test]
    async fn truncate_head_tail_redacted_drops_tail_start_straddling_suffix() {
        const SECRET: &str = "sk-live-TAILSTRADDLE-0123456789abcdefXY"; // 39 bytes
        let table = leak_table(SECRET);
        let cap = OUTPUT_BYTE_CAP; // tail_start = ceil(len - 3258)
        // len 12000 → tail_start = 8742. Place SECRET at 8736 → suffix at tail.
        let s = format!("{}{SECRET}{}", "A".repeat(8736), "B".repeat(3225));
        assert_eq!(s.len(), 12000);
        let suffix = &SECRET[SECRET.len() - 20..];

        let fixed = table.scrub(&truncate_head_tail_redacted(&table, &s, cap));
        assert!(!fixed.contains(SECRET));
        assert!(
            !fixed.contains(suffix),
            "tail-start straddling suffix leaked"
        );
        assert!(fixed.len() <= cap);
    }

    // A MULTI-LINE registered literal straddling the read-slice FRONT edge
    // (the lines before `offset` were omitted): its second line begins the
    // first shown line, and a boundary-blind slice would hand the §7
    // whole-value scrub a partial it cannot match. The front-margin elision
    // must remove it — and the retained lines must keep their TRUE source
    // numbers after the elision consumed leading lines.
    #[tokio::test]
    async fn read_slice_front_edge_elides_multi_line_straddling_secret() {
        const SECRET: &str = "SECRET-HEAD-99\nSECRET-TAIL-99"; // two-line literal
        let table = leak_table(SECRET);
        let partial_tail = "SECRET-TAIL-99";
        let line4 = format!("filler four {}", "z".repeat(40));
        let body = format!("filler one\nfiller two\n{partial_tail}\n{line4}\n");
        let slice = read_slice(&table, &body, 3, 2);
        let scrubbed = table.scrub(&slice.numbered);
        assert!(
            !scrubbed.contains(partial_tail),
            "front-edge multi-line partial leaked: {scrubbed}"
        );
        assert!(!scrubbed.contains("SECRET-HEAD-99"));
        // The margin consumed leading lines; the first RETAINED line must
        // still carry its true source number (4), not the window start (3).
        assert!(slice.numbered.starts_with("4|"), "{}", slice.numbered);
        // The resume cursor shares that post-elision anchor: it is the first
        // source line AFTER the shown one (5, past EOF for this 4-line body)
        // — never the already-shown line 4 that a pre-elision
        // `offset + shown.len()` anchor would produce.
        assert_eq!(slice.next_offset, 5);
    }

    // The pagination-cursor regression (issue #294): when the front margin
    // consumes a complete leading line AND an omission edge makes the read
    // truncated (the line limit leaves line 5 unshown), the continuation
    // marker's cursor must be anchored in POST-elision coordinates — the
    // first UNSHOWN source line (5) — not at the pre-elision window start,
    // whose `offset + shown.len()` yields 4: the line just emitted.
    #[tokio::test]
    async fn read_slice_front_edge_elision_cursor_resumes_after_shown_lines() {
        const SECRET: &str = "SECRET-HEAD-99\nSECRET-TAIL-99"; // 31-byte literal
        let table = leak_table(SECRET);
        let partial_tail = "SECRET-TAIL-99";
        let line4 = format!("filler four {}", "z".repeat(40));
        let body = format!("filler one\nfiller two\n{partial_tail}\n{line4}\nfiller five\n");
        let slice = read_slice(&table, &body, 3, 2);
        let scrubbed = table.scrub(&slice.numbered);
        assert!(
            !scrubbed.contains(partial_tail),
            "front-edge multi-line partial leaked: {scrubbed}"
        );
        assert!(!scrubbed.contains("SECRET-HEAD-99"));
        // Front margin (30 bytes) consumed line 3 wholly and 14 bytes of
        // line 4; the back margin (line 5 unshown) trimmed line 4's tail —
        // exactly one retained row, numbered by its TRUE source line.
        assert!(slice.truncated);
        assert!(slice.numbered.starts_with("4|"), "{}", slice.numbered);
        assert_eq!(slice.numbered.lines().count(), 1);
        // The cursor a `read` continuation should use: the first line after
        // the one shown. The pre-elision anchor regressed to 4 (already
        // emitted); 5 is the first unseen content.
        assert_eq!(slice.next_offset, 5);
    }

    // A multi-line registered literal straddling the read-slice BACK edge (the
    // byte cap stopped mid-window): its first line ends the last kept line, and
    // the back-margin elision must remove that partial before numbering.
    #[tokio::test]
    async fn read_slice_byte_cap_edge_elides_multi_line_straddling_secret() {
        const SECRET: &str = "SECRET-BACKHEAD-99\nSECRET-BACKTAIL-99"; // 37 bytes
        let table = leak_table(SECRET);
        let partial_head = "SECRET-BACKHEAD-99";
        // Line 1 ends with the literal's first line (418 bytes); a 430-byte
        // numbered cap keeps line 1 and stops before line 2, putting the
        // partial at the retained back edge.
        let line1 = format!("{}{partial_head}", "x".repeat(400));
        let body = format!("{line1}\nfiller tail\n");
        let slice = read_slice_with_byte_cap(&table, &body, 1, 10, 510);
        let scrubbed = table.scrub(&slice.numbered);
        assert!(
            !scrubbed.contains(partial_head),
            "back-edge multi-line partial leaked: {scrubbed}"
        );
        assert!(!scrubbed.contains("SECRET-BACKTAIL-99"));
        assert!(slice.truncated);
        assert!(slice.numbered.starts_with("1|"), "{}", slice.numbered);
    }

    // The LINE-LIMIT back edge (issue #294): `limit` omits the lines after the
    // window exactly like the byte cap does, so a multi-line registered
    // literal whose first line ends the last permitted line and whose second
    // line begins the first omitted line must be elided too — the whole-value
    // §7 scrub cannot match the surviving PREFIX.
    #[tokio::test]
    async fn read_slice_line_limit_edge_elides_multi_line_straddling_secret() {
        const SECRET: &str = "SECRET-LINEHEAD-99\nSECRET-LINETAIL-99"; // 37 bytes
        let table = leak_table(SECRET);
        let partial_head = "SECRET-LINEHEAD-99";
        // Line 1 ends with the literal's first line; the byte cap never
        // engages (tiny body), so only `limit = 1` cuts the window.
        let line1 = format!("{}{partial_head}", "x".repeat(400));
        let body = format!("{line1}\nSECRET-LINETAIL-99 filler\n");
        let slice = read_slice(&table, &body, 1, 1);
        let scrubbed = table.scrub(&slice.numbered);
        assert!(
            !scrubbed.contains(partial_head),
            "line-limit back-edge partial leaked: {scrubbed}"
        );
        assert!(!scrubbed.contains("SECRET-LINETAIL-99"));
        assert!(slice.truncated);
        assert!(slice.numbered.starts_with("1|"), "{}", slice.numbered);
        // The elided tail is re-offered, never skipped: the resume offset is
        // the first line after the one retained row.
        assert_eq!(slice.next_offset, 2);
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
