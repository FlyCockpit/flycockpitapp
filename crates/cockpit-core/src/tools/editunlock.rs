//! `editunlock` — search/replace with the §13b cascade, then release the lock.
//!
//! Eight-stage cascade per plan §13b, in order:
//!   1. Exact match.
//!   2. Line-trim (strip trailing whitespace per line).
//!   3. Block-anchor (first + last lines pin the region, interior char
//!      overlap ≥ 90% with target).
//!   4. Whitespace-normalized (collapse runs).
//!   5. Indent-flexible (strip common leading indentation).
//!   6. Escape-normalized (reconcile `\n` / `\t` / `\"`).
//!   7. Trimmed-boundary (trim outer whitespace).
//!   8. Context-aware (first + last lines exact, interior char overlap
//!      ≥ 50% — falls below the block-anchor threshold).
//!
//! On match, the canonical bytes from the file are used as `old_string`
//! when constructing the replacement (so the replacement is always
//! against the file's actual bytes). For matches past stage 1 the tool
//! also returns a `Recovery::EditCascade { stage, path: "old_string" }`
//! and the rewritten args back through [`ToolOutput::with_recovery`];
//! the dispatcher persists the canonical args to
//! `tool_call_events.wire_input_json` and mutates the in-history
//! assistant `ToolCall` so the next inference carries the canonical
//! form. This is plan §13c.
//!
//! Multiple matches at any stage with `replace_all = false` produce an
//! ambiguity error (the same loud failure mode plan §13b prescribes).

use anyhow::{Result, bail};
use async_trait::async_trait;
use serde_json::Value;
use std::ops::Range;

use crate::db::tool_calls::Recovery;
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, ToolPresentation, path_or_readable_args};
use crate::tools::common::{detect_crlf, normalize_line_endings, resolve, write_and_release};

pub struct EditunlockTool;

#[async_trait]
impl Tool for EditunlockTool {
    fn name(&self) -> &str {
        "editunlock"
    }

    fn description(&self) -> &str {
        "Replace old_string with new_string in a file (8-stage match cascade) and release the lock"
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Make a targeted change to a locked file: find `old_string` and replace it with \
             `new_string`, then release the lock. This is the preferred way to edit — you only \
             state the snippet that changes, not the whole file. `old_string` must match the \
             current file text closely (the tool tolerates minor whitespace differences via a \
             match cascade); copy it verbatim from a recent read, and include enough surrounding \
             context that it appears EXACTLY once, or the edit is rejected as ambiguous. To \
             change every occurrence on purpose, set `replace_all`. You must have locked the \
             file (`readlock`) first. To delete text, make `new_string` empty."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path":        { "type": "string", "x-cockpit-kind": "path", "x-cockpit-aliases": ["file_path", "filePath", "filepath", "pathname", "target_file", "file", "absolute_path"], "description": "Path to edit" },
                "old_string":  { "type": "string", "x-cockpit-aliases": ["oldString", "old", "old_str", "from", "old_text", "old_content"], "description": "Text to find" },
                "new_string":  { "type": "string", "x-cockpit-aliases": ["newString", "new", "new_str", "to", "new_text", "new_content"], "description": "Text to replace with" },
                "replace_all": { "type": "boolean", "description": "Replace every match (default false)" }
            },
            "required": ["path", "old_string", "new_string"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "path":        { "type": "string", "x-cockpit-kind": "path", "x-cockpit-aliases": ["file_path", "filePath", "filepath", "pathname", "target_file", "file", "absolute_path"], "description": "Path to the locked file to edit, absolute or relative to the session working directory" },
                "old_string":  { "type": "string", "x-cockpit-aliases": ["oldString", "old", "old_str", "from", "old_text", "old_content"], "description": "The exact existing text to find and replace, copied verbatim from the current file with enough surrounding context that it is unique. Must occur exactly once unless `replace_all` is set" },
                "new_string":  { "type": "string", "x-cockpit-aliases": ["newString", "new", "new_str", "to", "new_text", "new_content"], "description": "The replacement text that takes the place of `old_string`. Leave empty to delete the matched text" },
                "replace_all": { "type": "boolean", "description": "When true, replace every occurrence of `old_string` instead of requiring a single unique match; defaults to false" }
            },
            "required": ["path", "old_string", "new_string"]
        }))
    }

    fn presentation(&self, args: &Value) -> ToolPresentation {
        let (summary, full_input) = path_or_readable_args(args);
        ToolPresentation::with_parts(Some("🔓"), "editunlock", summary, full_input)
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let path_arg = args
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::engine::tool::invalid_input("`path` is required"))?;
        let old_string = args
            .get("old_string")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::engine::tool::invalid_input("`old_string` is required"))?;
        if old_string.is_empty() {
            return Err(crate::engine::tool::invalid_input(
                "`old_string` must not be empty",
            ));
        }
        let new_string = args
            .get("new_string")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::engine::tool::invalid_input("`new_string` is required"))?;
        let replace_all = args
            .get("replace_all")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let path = resolve(path_arg, &ctx.cwd);
        // Native-tool boundary check (sandboxing part 2) before the
        // write-permitted check — a denied out-of-cwd path never edits.
        let path = crate::tools::sandbox::check_native_access(
            ctx,
            &path,
            crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
        )
        .await?;
        let identity_note =
            match crate::assistants::identity::check_identity_write(ctx, &path).await? {
                crate::assistants::identity::IdentityWriteGate::Allow { note } => note,
                crate::assistants::identity::IdentityWriteGate::Refuse(message) => {
                    return Ok(crate::assistants::identity::tool_refusal(message));
                }
            };
        let write_guard = ctx
            .locks
            .begin_write(&path, &ctx.agent_id, ctx.session.id)?;

        let existing =
            std::fs::read(&path).map_err(|e| anyhow::anyhow!("read `{}`: {e}", path.display()))?;
        let want_crlf = detect_crlf(&existing);
        let original = String::from_utf8_lossy(&existing).into_owned();

        let Match {
            canonical,
            stage,
            spans,
        } = match find_match(&original, old_string, replace_all)? {
            Some(m) => m,
            None => {
                // Total miss — write nothing, return a near-miss diagnostic.
                let near = nearest_miss(&original, old_string);
                return Err(crate::engine::tool::invalid_input(format!(
                    "no match for `old_string` in `{}`. Closest near-miss:\n```\n{near}\n```",
                    path.display()
                )));
            }
        };

        let updated = replace_spans(&original, &spans, new_string)?;

        let normalized = normalize_line_endings(&updated, want_crlf);
        let outcome = write_and_release(ctx, &path, normalized.as_bytes(), write_guard)?;
        crate::assistants::identity::record_identity_write(ctx, &path)?;

        let mut message = format!(
            "edited `{}` ({}; {} bytes)",
            path.display(),
            stage,
            normalized.len()
        );
        let config = crate::config::extended::load_for_cwd(&ctx.cwd);
        if let Some(lsp) = &ctx.lsp {
            message.push_str(&lsp.diagnostics_after_write(&ctx.cwd, &path, &config).await);
        }
        if let Some(note) =
            crate::tools::data_syntax::data_syntax_note(&path, &normalized, &config.data_syntax)
        {
            message.push_str(&note);
        }
        if let Some(advisory) = outcome.advisory() {
            message.push_str(advisory);
        }
        if let Some(note) = identity_note {
            message.push_str(&note);
        }
        let out = ToolOutput::text(message);
        // Per §13c, every cascade stage past `exact` is a content-
        // equivalent rewrite: substituting `canonical` for the model's
        // submitted `old_string` does not change the edit's effect, but
        // does give the model's next attention pass over its own prior
        // outputs the form that *would have* matched at stage 1. We
        // hand the dispatcher both the recovery annotation and the
        // rewritten args; it does the wire/history mutation.
        if stage != "exact" {
            let mut canonical_args = args.clone();
            if let Value::Object(map) = &mut canonical_args {
                map.insert("old_string".to_string(), Value::String(canonical.clone()));
            }
            Ok(out.with_recovery(
                Recovery::EditCascade {
                    stage,
                    path: "old_string".to_string(),
                },
                canonical_args,
            ))
        } else {
            Ok(out)
        }
    }
}

struct Match {
    /// The exact bytes from the file that we matched against.
    canonical: String,
    /// Non-overlapping byte spans in the original file to replace.
    spans: Vec<Range<usize>>,
    stage: &'static str,
}

/// Walk the cascade in §13b order. Returns `Ok(Some(_))` on a
/// successful match (any stage), `Ok(None)` on total miss. An `Err`
/// only fires for ambiguous matches (multiple-match errors per §13b).
fn find_match(file: &str, target: &str, replace_all: bool) -> Result<Option<Match>> {
    if target.is_empty() {
        return Err(crate::engine::tool::invalid_input(
            "`old_string` must not be empty",
        ));
    }

    // Stage 1 — exact.
    if file.contains(target) {
        let spans: Vec<Range<usize>> = file
            .match_indices(target)
            .map(|(start, m)| start..start + m.len())
            .collect();
        if !replace_all && spans.len() > 1 {
            return Err(crate::engine::tool::invalid_input(
                "Found multiple matches for `old_string`; pass more surrounding context or set replace_all: true",
            ));
        }
        return Ok(Some(Match {
            canonical: target.to_string(),
            spans: if replace_all {
                spans
            } else {
                spans.into_iter().take(1).collect()
            },
            stage: "exact",
        }));
    }

    // Stage 2 — line-trim.
    if let Some(spans) = match_via_normalizer(file, target, replace_all, line_trim_normalize)? {
        return Ok(Some(Match {
            canonical: file[spans[0].clone()].to_string(),
            spans,
            stage: "line_trim",
        }));
    }

    // Stage 3 — block-anchor (anchored region with ≥90% interior overlap).
    if let Some(c) = anchor_match(file, target, /*min_ratio=*/ 90)? {
        let span = span_for_canonical(file, &c)?;
        return Ok(Some(Match {
            canonical: c,
            spans: vec![span],
            stage: "block_anchor",
        }));
    }

    // Stage 4 — whitespace-normalized (collapse runs).
    if let Some(spans) = match_via_normalizer(file, target, replace_all, whitespace_collapse)? {
        return Ok(Some(Match {
            canonical: file[spans[0].clone()].to_string(),
            spans,
            stage: "whitespace_normalized",
        }));
    }

    // Stage 5 — indent-flexible (strip common leading indentation from both).
    if let Some(spans) = match_via_normalizer(file, target, replace_all, indent_flexible_normalize)?
    {
        return Ok(Some(Match {
            canonical: file[spans[0].clone()].to_string(),
            spans,
            stage: "indent_flexible",
        }));
    }

    // Stage 6 — escape-normalized.
    if let Some(spans) = match_via_normalizer(file, target, replace_all, escape_normalize)? {
        return Ok(Some(Match {
            canonical: file[spans[0].clone()].to_string(),
            spans,
            stage: "escape_normalized",
        }));
    }

    // Stage 7 — trimmed-boundary (trim outer whitespace of the whole block).
    if let Some(spans) = match_via_normalizer(file, target, replace_all, trim_boundary_normalize)? {
        return Ok(Some(Match {
            canonical: file[spans[0].clone()].to_string(),
            spans,
            stage: "trimmed_boundary",
        }));
    }

    // Stage 8 — context-aware (anchored region with ≥50% interior overlap;
    // the looser cousin of stage 3).
    if let Some(c) = anchor_match(file, target, /*min_ratio=*/ 50)? {
        let span = span_for_canonical(file, &c)?;
        return Ok(Some(Match {
            canonical: c,
            spans: vec![span],
            stage: "context_aware",
        }));
    }

    Ok(None)
}

/// Generic "normalize both sides and find" stage. The normalizer maps
/// chunks of bytes onto a canonical form; we slide a window of the
/// same shape over the file and compare normalized forms. On a match
/// we return the *original file bytes* that produced the equivalent
/// normalized form.
fn match_via_normalizer(
    file: &str,
    target: &str,
    replace_all: bool,
    normalize: fn(&str) -> String,
) -> Result<Option<Vec<Range<usize>>>> {
    let norm_target = normalize(target);
    if norm_target.trim().is_empty() {
        return Ok(None);
    }

    // We brute-force: for each newline-delimited substring of the file
    // that's the same line count as `target`, compare its normalized
    // form against `norm_target`.
    let target_lines = target.matches('\n').count() + 1;
    let mut file_lines: Vec<(usize, &str)> = Vec::new();
    let mut offset = 0usize;
    for line in file.split_inclusive('\n') {
        file_lines.push((offset, line));
        offset += line.len();
    }
    if file_lines.len() < target_lines {
        return Ok(None);
    }

    let mut hits: Vec<Range<usize>> = Vec::new();
    let mut last_end = 0usize;
    for start in 0..=file_lines.len() - target_lines {
        let span_start = file_lines[start].0;
        let candidate: String = file_lines[start..start + target_lines]
            .iter()
            .map(|(_, line)| *line)
            .collect();
        // Strip the trailing newline that split_inclusive kept iff target
        // didn't have one — match equivalence has to compare like with like.
        let cand_for_compare = if target.ends_with('\n') {
            candidate.clone()
        } else {
            candidate
                .strip_suffix('\n')
                .map(str::to_string)
                .unwrap_or_else(|| candidate.clone())
        };
        let norm = normalize(&cand_for_compare);
        if norm == norm_target {
            let span = span_start..span_start + cand_for_compare.len();
            if !replace_all && !hits.is_empty() {
                return Err(crate::engine::tool::invalid_input(
                    "Found multiple matches for `old_string` at normalized stage; pass more surrounding context or set replace_all: true",
                ));
            }
            if replace_all && span.start < last_end {
                continue;
            }
            last_end = span.end;
            hits.push(span);
        }
    }
    if replace_all {
        Ok((!hits.is_empty()).then_some(hits))
    } else {
        Ok(hits.into_iter().next().map(|span| vec![span]))
    }
}

fn span_for_canonical(file: &str, canonical: &str) -> Result<Range<usize>> {
    match file.find(canonical) {
        Some(start) => Ok(start..start + canonical.len()),
        None => bail!("internal error: matched stage produced no canonical occurrence"),
    }
}

fn replace_spans(file: &str, spans: &[Range<usize>], replacement: &str) -> Result<String> {
    if spans.is_empty() {
        bail!("internal error: matched stage produced no spans");
    }
    let mut out = String::with_capacity(file.len());
    let mut cursor = 0usize;
    for span in spans {
        if span.start < cursor
            || span.end < span.start
            || span.end > file.len()
            || !file.is_char_boundary(span.start)
            || !file.is_char_boundary(span.end)
        {
            bail!("internal error: matched stage produced invalid replacement span");
        }
        out.push_str(&file[cursor..span.start]);
        out.push_str(replacement);
        cursor = span.end;
    }
    out.push_str(&file[cursor..]);
    Ok(out)
}

fn line_trim_normalize(s: &str) -> String {
    s.lines().map(str::trim_end).collect::<Vec<_>>().join("\n")
}

fn whitespace_collapse(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_space = false;
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.push(ch);
            last_space = false;
        }
    }
    out.trim().to_string()
}

fn indent_flexible_normalize(s: &str) -> String {
    let lines: Vec<&str> = s.lines().collect();
    let min_indent = lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.bytes().take_while(|b| *b == b' ' || *b == b'\t').count())
        .min()
        .unwrap_or(0);
    lines
        .iter()
        .map(|l| {
            if l.len() >= min_indent && l.is_char_boundary(min_indent) {
                &l[min_indent..]
            } else {
                *l
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn escape_normalize(s: &str) -> String {
    s.replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\\"", "\"")
}

fn trim_boundary_normalize(s: &str) -> String {
    s.trim().to_string()
}

/// Anchor-based match shared by stages 3 and 8. Pin candidate regions
/// by exact first + last lines, then accept only candidates whose
/// interior char overlap with `target` meets `min_ratio` percent. The
/// caller picks the threshold: 90 for block-anchor (stage 3), 50 for
/// context-aware (stage 8). Among acceptable candidates, the one with
/// the highest overlap wins.
///
/// Char overlap is a cheap proxy for Levenshtein — sufficient for "is
/// this region similar?" without pulling in an extra crate.
fn anchor_match(file: &str, target: &str, min_ratio: usize) -> Result<Option<String>> {
    let target_lines: Vec<&str> = target.lines().collect();
    if target_lines.len() < 2 {
        return Ok(None);
    }
    let first = target_lines.first().unwrap().trim();
    let last = target_lines.last().unwrap().trim();
    if first.is_empty() || last.is_empty() {
        return Ok(None);
    }

    let file_lines: Vec<&str> = file.split_inclusive('\n').collect();
    let n = target_lines.len();
    let mut best: Option<(String, usize)> = None;

    for start in 0..=file_lines.len().saturating_sub(n) {
        let cand_first = file_lines[start].trim_end_matches('\n').trim();
        if cand_first != first {
            continue;
        }
        let cand_last_idx = start + n - 1;
        if cand_last_idx >= file_lines.len() {
            continue;
        }
        let cand_last = file_lines[cand_last_idx].trim_end_matches('\n').trim();
        if cand_last != last {
            continue;
        }

        let candidate: String = file_lines[start..start + n].concat();
        let cand_for_compare = if target.ends_with('\n') {
            candidate.clone()
        } else {
            candidate
                .strip_suffix('\n')
                .map(str::to_string)
                .unwrap_or_else(|| candidate.clone())
        };

        let target_chars: std::collections::HashMap<char, usize> = char_counts(target);
        let cand_chars: std::collections::HashMap<char, usize> = char_counts(&cand_for_compare);
        let common: usize = target_chars
            .iter()
            .map(|(c, n)| n.min(cand_chars.get(c).unwrap_or(&0)))
            .copied()
            .sum();
        let denom = target.chars().count().max(1);
        let ratio = common * 100 / denom;

        if ratio < min_ratio {
            continue;
        }
        if best.as_ref().map(|(_, r)| *r < ratio).unwrap_or(true) {
            best = Some((cand_for_compare, ratio));
        }
    }

    Ok(best.map(|(canonical, _)| canonical))
}

fn char_counts(s: &str) -> std::collections::HashMap<char, usize> {
    let mut m = std::collections::HashMap::new();
    for c in s.chars() {
        *m.entry(c).or_insert(0) += 1;
    }
    m
}

/// Return the file region nearest to `target` (by char overlap), at
/// most ~10 lines, for the "no match" error message.
fn nearest_miss(file: &str, target: &str) -> String {
    let target_lines = target.lines().count().max(1);
    let file_lines: Vec<&str> = file.split_inclusive('\n').collect();
    if file_lines.len() < target_lines {
        return file.to_string();
    }
    let target_counts = char_counts(target);
    let mut best: Option<(usize, usize)> = None;
    for start in 0..=file_lines.len() - target_lines {
        let cand: String = file_lines[start..start + target_lines].concat();
        let cand_counts = char_counts(&cand);
        let common: usize = target_counts
            .iter()
            .map(|(c, n)| n.min(cand_counts.get(c).unwrap_or(&0)))
            .copied()
            .sum();
        if best.as_ref().map(|(_, s)| *s < common).unwrap_or(true) {
            best = Some((start, common));
        }
    }
    let Some((start, _)) = best else {
        return String::new();
    };
    let end = (start + target_lines).min(file_lines.len());
    file_lines[start..end].concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::engine::tool::Tool;
    use crate::tools::common::{LOCK_BOOKKEEPING_ADVISORY, test_ctx_with_db};

    fn fail_lock_state_deletes(db: &Db) {
        db.write_blocking(move |conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER fail_lock_state_delete
                 BEFORE DELETE ON lock_state
                 BEGIN
                     SELECT RAISE(FAIL, 'forced lock_state delete failure');
                 END;",
            )?;
            Ok(())
        })
        .unwrap();
    }

    async fn edit_file(
        contents: &str,
        old_string: &str,
        new_string: &str,
        replace_all: bool,
    ) -> String {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("edit.txt");
        std::fs::write(&file, contents).unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.locks.note_read(&file, &ctx.agent_id, ctx.session.id);

        EditunlockTool
            .call(
                serde_json::json!({
                    "path": "edit.txt",
                    "old_string": old_string,
                    "new_string": new_string,
                    "replace_all": replace_all,
                }),
                &ctx,
            )
            .await
            .unwrap();

        std::fs::read_to_string(&file).unwrap()
    }

    #[test]
    fn exact_match() {
        let res = find_match("hello world\n", "hello", false)
            .unwrap()
            .unwrap();
        assert_eq!(res.canonical, "hello");
        assert_eq!(res.stage, "exact");
    }

    #[test]
    fn line_trim_match() {
        let file = "line one   \nline two\n";
        // target has no trailing whitespace on line one
        let res = find_match(file, "line one\nline two", false)
            .unwrap()
            .unwrap();
        assert_eq!(res.stage, "line_trim");
    }

    #[test]
    fn no_match_returns_none() {
        let res = find_match("hello world", "goodbye", false).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn ambiguous_exact_errors_unless_replace_all() {
        let file = "x\nx\n";
        assert!(find_match(file, "x", false).is_err());
        assert!(find_match(file, "x", true).is_ok());
    }

    #[tokio::test]
    async fn replace_all_replaces_every_line_trim_normalized_match() {
        let out = edit_file("foo   \nbar\nfoo \nbar\n", "foo\nbar", "X", true).await;

        assert_eq!(out, "X\nX\n");
    }

    #[tokio::test]
    async fn replace_all_replaces_every_whitespace_normalized_shape() {
        let out = edit_file("a    b\na\tb\n", "a b", "X", true).await;

        assert_eq!(out, "X\nX\n");
    }

    #[test]
    fn replace_all_false_still_errors_on_multiple_normalized_matches() {
        let err = match find_match("a    b\na\tb\n", "a b", false) {
            Ok(_) => panic!("multiple normalized matches should be ambiguous"),
            Err(err) => err,
        };

        assert!(
            err.to_string().contains("Found multiple matches"),
            "multiple normalized matches stay ambiguous without replace_all: {err}"
        );
    }

    #[tokio::test]
    async fn replace_all_does_not_recurse_into_new_string() {
        let out = edit_file("x x\n", "x", "x x", true).await;

        assert_eq!(out, "x x x x\n");
    }

    #[tokio::test]
    async fn empty_old_string_is_invalid_without_replace_all() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());

        let err = EditunlockTool
            .call(
                serde_json::json!({
                    "path": "missing.txt",
                    "old_string": "",
                    "new_string": "x",
                    "replace_all": false,
                }),
                &ctx,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("`old_string` must not be empty"));
    }

    #[tokio::test]
    async fn empty_old_string_is_invalid_with_replace_all() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());

        let err = EditunlockTool
            .call(
                serde_json::json!({
                    "path": "missing.txt",
                    "old_string": "",
                    "new_string": "x",
                    "replace_all": true,
                }),
                &ctx,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("`old_string` must not be empty"));
    }

    #[tokio::test]
    async fn empty_new_string_deletes_non_empty_match() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("delete.txt");
        std::fs::write(&file, "alpha beta gamma\n").unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.locks.note_read(&file, &ctx.agent_id, ctx.session.id);

        EditunlockTool
            .call(
                serde_json::json!({
                    "path": "delete.txt",
                    "old_string": " beta",
                    "new_string": "",
                }),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "alpha gamma\n",
            "empty replacement remains the deletion path"
        );
    }

    #[tokio::test]
    async fn editunlock_reports_success_when_release_persist_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("edit.txt");
        std::fs::write(&file, "alpha beta gamma\n").unwrap();
        let (ctx, db) = test_ctx_with_db(tmp.path());
        ctx.locks.note_read(&file, &ctx.agent_id, ctx.session.id);
        ctx.locks
            .acquire(&file, &ctx.agent_id, ctx.session.id)
            .unwrap();
        fail_lock_state_deletes(&db);

        let out = EditunlockTool
            .call(
                serde_json::json!({
                    "path": "edit.txt",
                    "old_string": "beta",
                    "new_string": "delta",
                }),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "alpha delta gamma\n"
        );
        assert!(out.content.contains("edited `"), "{}", out.content);
        assert!(
            out.content.contains("lock bookkeeping did not persist"),
            "{}",
            out.content
        );
        assert!(out.content.ends_with(LOCK_BOOKKEEPING_ADVISORY));
        assert!(ctx.locks.holder(&file).is_none());
        assert!(ctx.locks.has_read(&file, &ctx.agent_id, ctx.session.id));
    }

    #[tokio::test]
    async fn editunlock_toml_syntax_notes_are_advisory() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("Cargo.toml");
        std::fs::write(&file, "[package]\nname = \"ok\"\n").unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.locks.note_read(&file, &ctx.agent_id, ctx.session.id);

        let out = EditunlockTool
            .call(
                serde_json::json!({
                    "path": "Cargo.toml",
                    "old_string": "name = \"ok\"",
                    "new_string": "name =",
                }),
                &ctx,
            )
            .await
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "[package]\nname =\n"
        );
        assert!(
            out.content.contains("warning: content is not valid TOML"),
            "{}",
            out.content
        );
    }

    #[tokio::test]
    async fn editunlock_toml_success_note() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("Cargo.toml");
        std::fs::write(&file, "[package]\nname = \"old\"\n").unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.locks.note_read(&file, &ctx.agent_id, ctx.session.id);

        let out = EditunlockTool
            .call(
                serde_json::json!({
                    "path": "Cargo.toml",
                    "old_string": "old",
                    "new_string": "new",
                }),
                &ctx,
            )
            .await
            .unwrap();

        assert!(out.content.contains("syntax OK (TOML)"), "{}", out.content);
    }

    #[test]
    fn indent_flexible_normalize_keeps_multibyte_whitespace_lines_safe() {
        let normalized = indent_flexible_normalize(" x\n\u{a0}\n y");

        assert_eq!(
            normalized, "x\n\u{a0}\ny",
            "ASCII-indented lines normalize while NBSP-only line is left intact"
        );
    }

    #[test]
    fn block_anchor_runs_before_whitespace_normalization() {
        // First+last anchors match a region whose interior is char-
        // identical to target (different whitespace shape inside).
        // Stage 3 (block-anchor, 90% overlap) should fire — not stage 4
        // (whitespace-normalized) — because of the new ordering.
        let file = "fn foo() {\n    let a = 1;\n    let b = 2;\n}\n";
        let target = "fn foo() {\n    let a=1;\n    let b=2;\n}";
        let m = find_match(file, target, false).unwrap().unwrap();
        assert_eq!(m.stage, "block_anchor");
    }

    #[test]
    fn context_aware_matches_when_interior_loosely_similar() {
        // Anchors match; interior overlap is between 50% and 90% — too
        // sparse for block-anchor but fine for context-aware.
        let file = "start\nentirely different middle content\nend\n";
        let target = "start\nsome middle text\nend";
        let m = find_match(file, target, false).unwrap().unwrap();
        assert_eq!(m.stage, "context_aware");
    }
}
