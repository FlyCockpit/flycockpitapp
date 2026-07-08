//! `read` — snapshot read with no lock.
//!
//! Used by `Build` for shallow inspection and by `builder`
//! for read-only context. Lock-acquiring reads go through
//! [`crate::tools::readlock`]. Both share output format + caps.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};

use crate::engine::tool::{Tool, ToolCtx, ToolOutput};
use crate::tools::common::{READ_LINE_CAP, looks_binary, read_slice, resolve, truncation_marker};

pub struct ReadTool;

#[async_trait]
impl Tool for ReadTool {
    fn name(&self) -> &str {
        "read"
    }

    fn description(&self) -> &str {
        "Snapshot-read a file; line-numbered output, 2000-line/8KB cap, no lock"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "After `tree`/`search` shows a file exists, `read` it — do NOT `cat`/`head`/`tail` \
             it; `read` returns line-numbered, budgeted output (it does NOT lock — to edit, \
             `readlock` first). Before calling this, be sure the path is REAL: only read a file \
             you have already seen in a `tree`, `search`, or bash result. Do NOT guess \
             conventional names like `README`, `LICENSE`, `CONTRIBUTING`, `CODE_OF_CONDUCT` — \
             many repos don't have them, and a read on a path that doesn't exist burns a whole \
             turn. When unsure, run `tree` first and read what's actually listed. Give exactly \
             one concrete file path — not a directory, glob, or list. For a large file don't \
             re-read the whole thing: page with `offset`+`limit`, or `outline` it to find the \
             right lines and read just that span with `start_line`+`end_line`."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "path",
            "properties": {
                "path":       { "type": "string", "x-cockpit-kind": "path", "x-cockpit-aliases": ["file_path", "filePath", "filepath", "pathname", "target_file", "file", "absolute_path"], "description": "Path to read" },
                "offset":     { "type": "integer", "description": "1-indexed start line (default 1)" },
                "limit":      { "type": "integer", "description": "Max lines (default 2000)" },
                "start_line": { "type": "integer", "description": "1-indexed inclusive range start" },
                "end_line":   { "type": "integer", "description": "1-indexed inclusive range end" }
            },
            "required": ["path"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "x-cockpit-primary-field": "path",
            "properties": {
                "path":       { "type": "string", "x-cockpit-kind": "path", "x-cockpit-aliases": ["file_path", "filePath", "filepath", "pathname", "target_file", "file", "absolute_path"], "description": "Path to the single file to read, absolute or relative to the session working directory; must be a real file, not a directory or glob" },
                "offset":     { "type": "integer", "description": "1-indexed line number to start reading from; defaults to 1 (the top of the file). Use with `limit` to page through a long file" },
                "limit":      { "type": "integer", "description": "Maximum number of lines to return from `offset`; defaults to 2000. Lower it to keep the result small when you only need a slice" },
                "start_line": { "type": "integer", "description": "1-indexed first line of an inclusive range to read; pair with `end_line` to read exactly that span instead of paging" },
                "end_line":   { "type": "integer", "description": "1-indexed last line of the inclusive range to read; pair with `start_line`" }
            },
            "required": ["path"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        // Native-tool boundary check (sandboxing part 2): a path outside
        // cwd + session tmp escalates via the approval prompt (naming the
        // exact path) before any read happens.
        if let Some(p) = args.get("path").and_then(Value::as_str) {
            let resolved = resolve(p, &ctx.cwd);
            let checked = crate::tools::sandbox::check_native_access(ctx, &resolved).await?;
            // Gitignore read-allowlist gate (read/readlock only): a gitignored,
            // un-allowlisted path raises the two-stage approval; a refusal is a
            // non-fatal tool result the model sees, never a crash.
            if let Some(refusal) =
                crate::tools::sandbox::check_gitignore_read(ctx, &checked).await?
            {
                return Ok(refusal);
            }
            return read_impl_with_path(args, ctx, false, checked);
        }
        read_impl(args, ctx, false)
    }
}

#[derive(Debug)]
pub(crate) enum ReadOutcome {
    /// Real read: bytes were returned, or the caller learned the file is
    /// empty/out of requested range. The read tracker was updated.
    Content(ToolOutput),
    /// No bytes were returned because the target was absent, a directory, or
    /// binary. The read tracker was not updated.
    NoContent(ToolOutput),
}

/// Shared implementation for `read` and `readlock`. The locking variant
/// acquires the lock first, then calls this. Both produce identical
/// output and real reads mark the file as read in the lock manager's
/// read-tracker (so a subsequent `writeunlock` is permitted).
pub(crate) fn read_impl(args: Value, ctx: &ToolCtx, was_locked: bool) -> Result<ToolOutput> {
    match read_impl_outcome(args, ctx, was_locked)? {
        ReadOutcome::Content(out) | ReadOutcome::NoContent(out) => Ok(out),
    }
}

pub(crate) fn read_impl_with_path(
    args: Value,
    ctx: &ToolCtx,
    was_locked: bool,
    path: PathBuf,
) -> Result<ToolOutput> {
    match read_impl_outcome_with_path(args, ctx, was_locked, path, |path| std::fs::read(path))? {
        ReadOutcome::Content(out) | ReadOutcome::NoContent(out) => Ok(out),
    }
}

pub(crate) fn read_impl_outcome(
    args: Value,
    ctx: &ToolCtx,
    was_locked: bool,
) -> Result<ReadOutcome> {
    read_impl_outcome_with(args, ctx, was_locked, |path| std::fs::read(path))
}

pub(crate) fn read_impl_outcome_with(
    args: Value,
    ctx: &ToolCtx,
    was_locked: bool,
    read_file: impl FnOnce(&Path) -> io::Result<Vec<u8>>,
) -> Result<ReadOutcome> {
    let path_arg = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| crate::engine::tool::invalid_input("`path` is required"))?;
    let path = resolve(path_arg, &ctx.cwd);
    read_impl_outcome_with_path(args, ctx, was_locked, path, read_file)
}

pub(crate) fn read_impl_outcome_with_path(
    args: Value,
    ctx: &ToolCtx,
    was_locked: bool,
    path: PathBuf,
    read_file: impl FnOnce(&Path) -> io::Result<Vec<u8>>,
) -> Result<ReadOutcome> {
    // Directory case: `read` needs a single file. Detect it with a portable
    // `is_dir()` check (never errno/ErrorKind — `os error 21` is Unix-only) so
    // the branch fires identically on every platform, and return a non-fatal
    // recovery hint steered to the caller's actual tool surface (same shape as
    // the binary-file branch below), not a leaked raw OS error.
    if path.is_dir() {
        return Ok(ReadOutcome::NoContent(directory_recovery(&path, ctx)));
    }

    // A path that does not exist is the weak-model path-hallucination case
    // (guessed conventional filenames like `CONTRIBUTING.md`). Steer to `tree`
    // so the lesson — list before you read — lands at the moment the model
    // errs, matching the recovery-hint convention. Other read errors keep the
    // raw cause.
    if !path.exists() {
        return Ok(ReadOutcome::NoContent(missing_path_recovery(&path, ctx)));
    }
    let bytes = match read_file(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            if let Some(recovery) = classify_read_race(&path, ctx, &err) {
                return Ok(ReadOutcome::NoContent(recovery));
            }
            return Err(anyhow::anyhow!("read `{}`: {err}", path.display()));
        }
    };
    if looks_binary(&bytes) {
        return Ok(ReadOutcome::NoContent(ToolOutput::text(format!(
            "Error: `{}` looks binary (NUL bytes in first 1 KB); use `bash` with `head -c` or `file` for binary inspection",
            path.display()
        ))));
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();

    // Range mode: an explicit `start_line`/`end_line` reads that
    // inclusive 1-indexed slice and prepends a content-hash header. This
    // is a separate path; when neither is present the behavior below is
    // byte-identical to before.
    if args.get("start_line").is_some() || args.get("end_line").is_some() {
        return read_range(&bytes, &text, &path, args, ctx, was_locked).map(ReadOutcome::Content);
    }

    let (offset, default_offset) = match args.get("offset").and_then(Value::as_u64) {
        Some(o) if o >= 1 => (o as usize, false),
        _ => (1, true),
    };
    let (limit, default_limit) = match args.get("limit").and_then(Value::as_u64) {
        Some(l) if l > 0 => (l as usize, false),
        _ => (READ_LINE_CAP, true),
    };

    let slice = read_slice(&text, offset, limit);
    if slice.offset_exceeded {
        let mut out = String::new();
        if default_offset && default_limit {
            // Empty file is a clean read — no Note needed.
        } else {
            out.push_str(&format!(
                "Note: offset {offset} exceeds file length ({} lines).\n",
                slice.total_lines
            ));
        }
        // Always track the read attempt so a subsequent write is allowed.
        ctx.locks.note_read(&path, &ctx.agent_id, ctx.session.id);
        return Ok(ReadOutcome::Content(ToolOutput::text(out)));
    }

    let mut prelude = String::new();
    if was_locked {
        prelude.push_str(&format!(
            "Note: lock acquired on `{}`; release with writeunlock / editunlock / unlock.\n",
            path.display()
        ));
    }
    if default_offset && default_limit && slice.truncated {
        prelude.push_str(
            "Note: `limit` defaulted to 2000; pass both `offset` and `limit` to override.\n",
        );
    }
    if slice.truncated {
        let mut tail = slice.numbered;
        tail.push_str(&truncation_marker(slice.next_offset));
        tail.push('\n');
        ctx.locks.note_read(&path, &ctx.agent_id, ctx.session.id);
        return Ok(ReadOutcome::Content(ToolOutput::truncated_text(format!(
            "{prelude}{tail}"
        ))));
    }

    ctx.locks.note_read(&path, &ctx.agent_id, ctx.session.id);
    Ok(ReadOutcome::Content(ToolOutput::text(format!(
        "{prelude}{}",
        slice.numbered
    ))))
}

fn directory_recovery(path: &Path, ctx: &ToolCtx) -> ToolOutput {
    let alt = if ctx.has_tree {
        "; use `tree` to list it"
    } else if ctx.has_bash {
        "; use `bash` (e.g. `ls`) to list it"
    } else {
        ""
    };
    ToolOutput::text(format!(
        "Error: `{}` is a directory; `read` needs a single file path{alt}",
        path.display()
    ))
}

fn missing_path_recovery(path: &Path, ctx: &ToolCtx) -> ToolOutput {
    let alt = if ctx.has_tree {
        "; run `tree` to see existing files before reading"
    } else if ctx.has_bash {
        "; use `bash` (e.g. `ls`) to see existing files before reading"
    } else {
        ""
    };
    ToolOutput::text(format!("Error: `{}` does not exist{alt}", path.display()))
}

fn classify_read_race(path: &Path, ctx: &ToolCtx, err: &io::Error) -> Option<ToolOutput> {
    match err.kind() {
        io::ErrorKind::NotFound => return Some(missing_path_recovery(path, ctx)),
        io::ErrorKind::IsADirectory => return Some(directory_recovery(path, ctx)),
        _ => {}
    }

    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => Some(directory_recovery(path, ctx)),
        Err(meta_err) if meta_err.kind() == io::ErrorKind::NotFound => {
            Some(missing_path_recovery(path, ctx))
        }
        _ => None,
    }
}

/// Range-mode read: returns the inclusive 1-indexed `[start_line,
/// end_line]` slice with a `[hash=<12hex> total_lines=<n>
/// returned=<a>-<b>]` header so a caller (the intel tools) can verify
/// the file hasn't shifted under it. `end_line` defaults to EOF;
/// `start_line` defaults to 1.
fn read_range(
    bytes: &[u8],
    text: &str,
    path: &std::path::Path,
    args: Value,
    ctx: &ToolCtx,
    was_locked: bool,
) -> Result<ToolOutput> {
    let start = args
        .get("start_line")
        .and_then(Value::as_u64)
        .map(|s| s.max(1) as usize)
        .unwrap_or(1);
    let requested_end = args
        .get("end_line")
        .and_then(Value::as_u64)
        .map(|e| e as usize);
    let limit = requested_end
        .map(|end| end.max(start) - start + 1)
        .unwrap_or(usize::MAX);
    let slice = read_slice(text, start, limit);
    let total = slice.total_lines;
    let end = requested_end.unwrap_or(total).max(start);

    // 12-hex prefix of the file's SHA-256.
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let hash = crate::intel::hex_lower(&digest);
    let hash12 = &hash[..hash.len().min(12)];

    ctx.locks.note_read(path, &ctx.agent_id, ctx.session.id);

    if slice.offset_exceeded {
        let header = format!("[hash={hash12} total_lines={total} returned=none]\n");
        let note = format!("Note: start_line {start} exceeds file length ({total} lines).\n");
        return Ok(ToolOutput::text(format!("{header}{note}")));
    }
    let end = end.min(total);
    let header = format!("[hash={hash12} total_lines={total} returned={start}-{end}]\n");
    let mut prelude = String::new();
    if was_locked {
        prelude.push_str(&format!(
            "Note: lock acquired on `{}`; release with writeunlock / editunlock / unlock.\n",
            path.display()
        ));
    }
    if slice.truncated {
        let mut tail = slice.numbered;
        tail.push_str(&truncation_marker(slice.next_offset));
        tail.push('\n');
        return Ok(ToolOutput::truncated_text(format!(
            "{header}{prelude}{tail}"
        )));
    }
    Ok(ToolOutput::text(format!(
        "{header}{prelude}{}",
        slice.numbered
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::common::test_ctx;

    #[tokio::test]
    async fn range_mode_prepends_hash_header() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("f.txt");
        std::fs::write(&file, "l1\nl2\nl3\nl4\nl5\n").unwrap();
        let ctx = test_ctx(tmp.path());
        let args = serde_json::json!({
            "path": file.to_string_lossy(),
            "start_line": 2,
            "end_line": 4
        });
        let out = ReadTool.call(args, &ctx).await.unwrap();
        // Header present, with total_lines and the requested range.
        assert!(out.content.starts_with("[hash="), "got: {}", out.content);
        assert!(out.content.contains("total_lines=5"));
        assert!(out.content.contains("returned=2-4"));
        // Only the requested lines are numbered in the body.
        assert!(out.content.contains("2|l2"));
        assert!(out.content.contains("4|l4"));
        assert!(!out.content.contains("1|l1"));
        assert!(!out.content.contains("5|l5"));
    }

    #[tokio::test]
    async fn range_mode_end_line_defaults_to_total_from_slice() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("f.txt");
        std::fs::write(&file, "l1\nl2\nl3\n").unwrap();
        let ctx = test_ctx(tmp.path());
        let args = serde_json::json!({
            "path": file.to_string_lossy(),
            "start_line": 2
        });

        let out = ReadTool.call(args, &ctx).await.unwrap();

        assert!(
            out.content.contains("total_lines=3"),
            "got: {}",
            out.content
        );
        assert!(out.content.contains("returned=2-3"), "got: {}", out.content);
        assert!(out.content.contains("2|l2"));
        assert!(out.content.contains("3|l3"));
    }

    /// A directory is reported as a directory via the portable check, never
    /// as the raw `os error 21` string, and the result is a non-`Err`
    /// `ToolOutput` the model can recover from.
    #[tokio::test]
    async fn directory_returns_recovery_message_not_errno() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("subdir");
        std::fs::create_dir(&dir).unwrap();
        let ctx = test_ctx(tmp.path());
        let args = serde_json::json!({ "path": dir.to_string_lossy() });
        // Non-`Err`: the model sees a recoverable tool result.
        let out = ReadTool.call(args, &ctx).await.unwrap();
        assert!(
            out.content.contains("is a directory"),
            "got: {}",
            out.content
        );
        assert!(
            !out.content.contains("os error"),
            "must not leak raw errno: {}",
            out.content
        );
    }

    /// Steering variant (a): an agent holding `tree` is pointed at `tree`.
    #[tokio::test]
    async fn directory_message_suggests_tree_when_available() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        std::fs::create_dir(&dir).unwrap();
        let mut ctx = test_ctx(tmp.path());
        ctx.has_tree = true;
        ctx.has_bash = true; // tree wins even when bash is also present
        let args = serde_json::json!({ "path": dir.to_string_lossy() });
        let out = read_impl(args, &ctx, false).unwrap();
        assert!(out.content.contains("`tree`"), "got: {}", out.content);
        assert!(!out.content.contains("`bash`"), "got: {}", out.content);
    }

    /// Steering variant (b): no `tree` but `bash` → suggest `bash`.
    #[tokio::test]
    async fn directory_message_suggests_bash_when_no_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        std::fs::create_dir(&dir).unwrap();
        let mut ctx = test_ctx(tmp.path());
        ctx.has_tree = false;
        ctx.has_bash = true;
        let args = serde_json::json!({ "path": dir.to_string_lossy() });
        let out = read_impl(args, &ctx, false).unwrap();
        assert!(out.content.contains("`bash`"), "got: {}", out.content);
        assert!(!out.content.contains("`tree`"), "got: {}", out.content);
    }

    /// Steering variant (c): neither `tree` nor `bash` (e.g. the `docs`
    /// answerer) → no alternative tool is named.
    #[tokio::test]
    async fn directory_message_suggests_nothing_without_tree_or_bash() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        std::fs::create_dir(&dir).unwrap();
        let mut ctx = test_ctx(tmp.path());
        ctx.has_tree = false;
        ctx.has_bash = false;
        let args = serde_json::json!({ "path": dir.to_string_lossy() });
        let out = read_impl(args, &ctx, false).unwrap();
        assert!(
            out.content.contains("is a directory"),
            "got: {}",
            out.content
        );
        assert!(!out.content.contains("`tree`"), "got: {}", out.content);
        assert!(!out.content.contains("`bash`"), "got: {}", out.content);
    }

    /// A nonexistent path (the weak-model path-hallucination case) returns a
    /// non-`Err` recovery message that steers to `tree`, never a raw OS error.
    #[tokio::test]
    async fn nonexistent_path_steers_to_tree_when_available() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = test_ctx(tmp.path());
        ctx.has_tree = true;
        ctx.has_bash = true; // tree wins
        let missing = tmp.path().join("CONTRIBUTING.md");
        let args = serde_json::json!({ "path": missing.to_string_lossy() });
        let out = read_impl(args, &ctx, false).unwrap();
        assert!(
            out.content.contains("does not exist"),
            "got: {}",
            out.content
        );
        assert!(out.content.contains("`tree`"), "got: {}", out.content);
        assert!(
            !out.content.contains("os error") && !out.content.contains("No such file"),
            "must not leak raw OS error: {}",
            out.content
        );
    }

    /// No `tree` but `bash` present → steer to `bash` instead.
    #[tokio::test]
    async fn nonexistent_path_steers_to_bash_when_no_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = test_ctx(tmp.path());
        ctx.has_tree = false;
        ctx.has_bash = true;
        let missing = tmp.path().join("README.md");
        let args = serde_json::json!({ "path": missing.to_string_lossy() });
        let out = read_impl(args, &ctx, false).unwrap();
        assert!(
            out.content.contains("does not exist"),
            "got: {}",
            out.content
        );
        assert!(out.content.contains("`bash`"), "got: {}", out.content);
        assert!(!out.content.contains("`tree`"), "got: {}", out.content);
    }

    #[tokio::test]
    async fn read_deleted_after_preflight_uses_missing_path_recovery() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("gone.txt");
        std::fs::write(&file, "content").unwrap();
        let mut ctx = test_ctx(tmp.path());
        ctx.has_tree = true;
        let args = serde_json::json!({ "path": file.to_string_lossy() });

        let out = match read_impl_outcome_with(args, &ctx, false, |path| {
            std::fs::remove_file(path).unwrap();
            Err(io::Error::new(io::ErrorKind::NotFound, "gone"))
        })
        .unwrap()
        {
            ReadOutcome::NoContent(out) => out,
            ReadOutcome::Content(out) => {
                panic!("expected no-content recovery, got {}", out.content)
            }
        };

        assert!(
            out.content.contains("does not exist"),
            "got: {}",
            out.content
        );
        assert!(
            out.content
                .contains("; run `tree` to see existing files before reading"),
            "got: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn read_replaced_by_directory_after_preflight_uses_directory_recovery() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("now-dir");
        std::fs::write(&file, "content").unwrap();
        let mut ctx = test_ctx(tmp.path());
        ctx.has_bash = true;
        let args = serde_json::json!({ "path": file.to_string_lossy() });

        let out = match read_impl_outcome_with(args, &ctx, false, |path| {
            std::fs::remove_file(path).unwrap();
            std::fs::create_dir(path).unwrap();
            Err(io::Error::other("became directory"))
        })
        .unwrap()
        {
            ReadOutcome::NoContent(out) => out,
            ReadOutcome::Content(out) => {
                panic!("expected no-content recovery, got {}", out.content)
            }
        };

        assert!(
            out.content.contains("is a directory"),
            "got: {}",
            out.content
        );
        assert!(
            out.content.contains("; use `bash` (e.g. `ls`) to list it"),
            "got: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn read_unclassified_error_stays_hard_error() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("f.txt");
        std::fs::write(&file, "content").unwrap();
        let ctx = test_ctx(tmp.path());
        let args = serde_json::json!({ "path": file.to_string_lossy() });

        let err = read_impl_outcome_with(args, &ctx, false, |_| {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "blocked"))
        })
        .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("read `"), "got: {msg}");
        assert!(msg.contains("blocked"), "got: {msg}");
    }

    #[tokio::test]
    async fn binary_file_hint_backticks_commands() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("blob.bin");
        std::fs::write(&file, b"\0binary").unwrap();
        let mut ctx = test_ctx(tmp.path());
        ctx.has_bash = true;
        let args = serde_json::json!({ "path": file.to_string_lossy() });
        let out = read_impl(args, &ctx, false).unwrap();

        assert!(
            out.content.contains("use `bash` with `head -c` or `file`"),
            "got: {}",
            out.content
        );
        assert!(
            !out.content.contains(" head -c ") && !out.content.contains(" file "),
            "literal commands should be backticked: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn plain_mode_has_no_header() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("f.txt");
        std::fs::write(&file, "a\nb\nc\n").unwrap();
        let ctx = test_ctx(tmp.path());
        let args = serde_json::json!({ "path": file.to_string_lossy() });
        let out = ReadTool.call(args, &ctx).await.unwrap();
        // No range header in the default path — behavior unchanged.
        assert!(!out.content.contains("[hash="));
        assert!(out.content.contains("1|a"));
        assert!(out.content.contains("3|c"));
    }
}
