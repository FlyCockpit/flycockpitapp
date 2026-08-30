//! The `cockpit://` recall namespace.
//!
//! This is deliberately a provider, not a filesystem mount: callers dispatch
//! here before resolving a host path, so history can never inherit cwd,
//! gitignore, or sandbox authority.

use anyhow::Result;
use regex::RegexBuilder;
use serde_json::Value;
use uuid::Uuid;

use crate::engine::tool::{ToolCtx, ToolOutput, invalid_input};
use crate::intel::budget::BudgetedWriter;
use crate::tools::common::OUTPUT_BYTE_CAP;
use crate::tools::session_search::caller_history_trust;

const PREFIX: &str = "cockpit://";
const DEFAULT_LINES: usize = 2_000;
const MAX_SEARCH_MATCHES: usize = 100;
const GLOB_TOKEN_CAP: usize = 4_000;
const CONTINUATION_RESERVE_BYTES: usize = 256;

#[derive(Debug, Clone, Copy)]
enum RecallPath {
    History,
    Transcript(Uuid),
    Compaction(Uuid, usize),
    Plan(Uuid),
    Artifact(Uuid, Uuid),
}

#[derive(Debug, Clone, Copy)]
enum PageMode {
    Offset { start: usize, limit: usize },
    Range { start: usize, end: usize },
}

#[derive(Debug, Clone, Copy)]
struct PageRequest {
    mode: PageMode,
    start_byte: usize,
}

pub fn is_recall_path(path: &str) -> bool {
    path.starts_with(PREFIX)
}

/// `history_search` is the recall capability. The ordinary file tools may
/// route `cockpit://` requests here, but that routing must not turn their
/// ambient filesystem authority into history authority.
fn require_recall_authority(ctx: &ToolCtx) -> Result<()> {
    if ctx.available_tools.contains("history_search") {
        return Ok(());
    }
    Err(invalid_input(
        "`cockpit://` recall is unavailable to this agent; use an agent granted `history_search`",
    ))
}

pub async fn read(args: &Value, ctx: &ToolCtx) -> Result<ToolOutput> {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input("`path` is required"))?;
    if is_recall_path(path) {
        require_recall_authority(ctx)?;
    }
    let target = parse(path, ctx).await?;
    // Rehydrate and union the target's durable redaction knowledge before
    // loading any target-owned bytes for the recall response.
    let redactor = redactor_for_target(ctx, target).await?;
    let content = match target {
        RecallPath::History => history_directory(ctx).await?,
        target => match pseudofile_content(target, ctx).await? {
            Some(content) => content,
            None => return Ok(not_found(path, target)),
        },
    };
    // Scrub before selecting a page so a secret split across a page boundary
    // cannot leave a prefix or suffix in a later continuation.
    render_page(&redactor.scrub(&content), path, args)
}

pub async fn write(args: &Value, ctx: &ToolCtx) -> Result<Option<ToolOutput>> {
    let path = args.get("path").and_then(Value::as_str).unwrap_or_default();
    if !is_recall_path(path) {
        return Ok(None);
    }
    let content = args
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input("`content` is required"))?;
    let RecallPath::Plan(session_id) = parse(path, ctx).await? else {
        return Err(invalid_input(
            "only `cockpit://session/<short_id>/plan` is writable",
        ));
    };
    if session_id != ctx.session.id {
        return Err(invalid_input(
            "only the current session's plan pseudofile is writable",
        ));
    }
    if content.len() > 256 * 1024 {
        return Err(invalid_input("plan document exceeds 256 KiB"));
    }

    let caller_trust = caller_history_trust(ctx);
    let observed = ctx
        .session
        .db
        .get_session_plan_doc_for_trust(session_id, caller_trust)
        .await?;
    let expected_revision = parse_expected_revision(args)?;
    let current_revision = observed.as_ref().map(|doc| doc.revision).unwrap_or(0);
    if observed.is_some() && expected_revision.is_none() {
        return Err(invalid_input(
            "`expected_revision` is required because a plan document already exists; read the plan and retry with the revision it reports",
        ));
    }
    let expected_revision = expected_revision.unwrap_or(0);
    if expected_revision != current_revision {
        return Err(invalid_input(format!(
            "stale `expected_revision`: expected {expected_revision}, but the current revision is {current_revision}; read the plan and retry"
        )));
    }
    let Some(doc) = ctx
        .session
        .db
        .write_session_plan_doc_if_revision(session_id, expected_revision, content, caller_trust)
        .await?
    else {
        return Err(invalid_input(
            "stale `expected_revision`: the plan changed while this write was pending; read it and retry",
        ));
    };
    Ok(Some(ToolOutput::text(format!(
        "wrote `{path}` (revision {}, {} bytes)",
        doc.revision,
        content.len()
    ))))
}

pub async fn glob(pattern: &str, path: Option<&str>, ctx: &ToolCtx) -> Result<Option<ToolOutput>> {
    let requested = path.unwrap_or(pattern);
    if !is_recall_path(requested) && !pattern.starts_with(PREFIX) {
        return Ok(None);
    }
    require_recall_authority(ctx)?;
    let resolved_pattern = history_glob_pattern(pattern, path)?;
    let matcher = globset::Glob::new(&resolved_pattern)
        .map_err(|err| invalid_input(format!("invalid glob `{resolved_pattern}`: {err}")))?
        .compile_matcher();
    let mut writer = BudgetedWriter::new(GLOB_TOKEN_CAP);
    for entry in history_entries(ctx).await? {
        if matcher.is_match(&entry) {
            // The model view is token-capped, but retain the complete bounded
            // discovery listing for the common configurable spill boundary.
            let _ = writer.writeln(&entry);
        }
    }
    if writer.is_empty() {
        return Ok(Some(ToolOutput::text(
            "No matching cockpit pseudofiles.".to_string(),
        )));
    }
    let truncated = writer.is_truncated();
    let capture = writer.text_artifact_capture();
    let mut body = writer.into_string();
    if truncated {
        body.push_str("... [truncated; narrow the pattern]\n");
        let output = ToolOutput::truncated_text(body);
        Ok(Some(match capture {
            Some(capture) => output.with_text_artifact_capture(capture),
            None => output,
        }))
    } else {
        Ok(Some(ToolOutput::text(body)))
    }
}

pub async fn grep(args: &Value, ctx: &ToolCtx) -> Result<Option<ToolOutput>> {
    let Some(path) = args.get("path").and_then(Value::as_str) else {
        return Ok(None);
    };
    if !is_recall_path(path) {
        return Ok(None);
    }
    require_recall_authority(ctx)?;
    let target = parse(path, ctx).await?;
    if matches!(target, RecallPath::History) {
        return Err(invalid_input(
            "use `history_search` for cockpit history discovery; grep only searches one returned pseudofile",
        ));
    }
    let pattern = args
        .get("pattern")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_input("`pattern` is required"))?;
    // Construct the union before loading target-owned bytes so every recall
    // path has the same target-redaction ordering as `read`.
    let redactor = redactor_for_target(ctx, target).await?;
    let Some(content) = pseudofile_content(target, ctx).await? else {
        return Ok(Some(not_found(path, target)));
    };
    let mode = args.get("mode").and_then(Value::as_str).unwrap_or("regex");
    let expression = match mode {
        "literal" => regex::escape(pattern),
        "regex" => pattern.to_owned(),
        _ => return Err(invalid_input("`mode` must be `literal` or `regex`")),
    };
    let regex = RegexBuilder::new(&expression)
        .case_insensitive(
            args.get("case_insensitive")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        )
        .build()
        .map_err(|err| invalid_input(format!("invalid regex: {err}")))?;

    // Search the complete redacted pseudofile, rather than `read`'s first
    // byte-capped result. The result itself has an independent byte cap.
    let content = redactor.scrub(&content);
    let mut out = String::new();
    let mut matches = 0usize;
    for (line, text) in content.lines().enumerate() {
        if !regex.is_match(text) {
            continue;
        }
        matches += 1;
        if matches > MAX_SEARCH_MATCHES
            || !append_capped_record(&mut out, &format!("{path}:{}: {text}\n", line + 1))
        {
            return Ok(Some(truncated_search_output(out)));
        }
    }
    Ok(Some(ToolOutput::text(if out.is_empty() {
        "No matches.".to_string()
    } else {
        out
    })))
}

async fn parse(path: &str, ctx: &ToolCtx) -> Result<RecallPath> {
    if path == "cockpit://history" || path == "cockpit://history/" {
        return Ok(RecallPath::History);
    }
    let parts: Vec<_> = path.trim_end_matches('/').split('/').collect();
    if parts.len() < 5 || parts[0] != "cockpit:" || parts[2] != "session" {
        return Err(invalid_input(
            "invalid cockpit path; use `cockpit://session/<short_id-or-uuid>/transcript`, `/compactions/<n>`, `/artifacts/<uuid>`, or `/plan`",
        ));
    }
    let session_id = resolve_session(ctx, parts[3]).await?;
    match parts.as_slice() {
        ["cockpit:", "", "session", _, "transcript"] => Ok(RecallPath::Transcript(session_id)),
        ["cockpit:", "", "session", _, "plan"] => Ok(RecallPath::Plan(session_id)),
        ["cockpit:", "", "session", _, "compactions", n] => {
            let n = n
                .parse::<usize>()
                .map_err(|_| invalid_input("compaction number must be a positive integer"))?;
            if n == 0 {
                return Err(invalid_input(
                    "compaction number must be a positive integer",
                ));
            }
            Ok(RecallPath::Compaction(session_id, n))
        }
        ["cockpit:", "", "session", _, "artifacts", id] => Ok(RecallPath::Artifact(
            session_id,
            Uuid::parse_str(id).map_err(|_| invalid_input("artifact id must be a UUID"))?,
        )),
        _ => Err(invalid_input("invalid cockpit pseudofile path")),
    }
}

async fn resolve_session(ctx: &ToolCtx, id: &str) -> Result<Uuid> {
    if id == ctx.session.short_id() {
        return Ok(ctx.session.id);
    }
    if let Ok(id) = Uuid::parse_str(id) {
        let allowed = ctx
            .session
            .db
            .session_access_allowed(&ctx.session.project_id, id)
            .await?;
        if !allowed {
            return Err(invalid_input("no accessible session with that id"));
        }
        return Ok(id);
    }
    ctx.session
        .db
        .get_session_by_short_id(&ctx.session.project_id, id)
        .await?
        .map(|row| row.session_id)
        .ok_or_else(|| invalid_input(format!("no session with short id `{id}`")))
}

async fn pseudofile_content(target: RecallPath, ctx: &ToolCtx) -> Result<Option<String>> {
    match target {
        RecallPath::History => Ok(Some(history_directory(ctx).await?)),
        RecallPath::Transcript(session_id) => {
            let turns = ctx
                .session
                .db
                .thread_turns_for_trust(session_id, caller_history_trust(ctx))
                .await?;
            Ok(Some(
                turns
                    .iter()
                    .map(|turn| {
                        format!(
                            "[{}] {}: {}",
                            turn.seq,
                            if turn.role == "assistant" {
                                "Assistant"
                            } else {
                                "User"
                            },
                            turn.text.trim()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
            ))
        }
        RecallPath::Compaction(session_id, n) => {
            ctx.session
                .db
                .compaction_text_for_trust(session_id, n, caller_history_trust(ctx))
                .await
        }
        RecallPath::Plan(session_id) => Ok(Some(
            ctx.session
                .db
                .get_session_plan_doc_for_trust(session_id, caller_history_trust(ctx))
                .await?
                .map(|doc| format!("[revision={}]\n{}", doc.revision, doc.content))
                .unwrap_or_else(|| "[revision=0]\n".to_string()),
        )),
        RecallPath::Artifact(session_id, artifact_id) => Ok(ctx
            .session
            .db
            .text_artifact_for_trust(session_id, artifact_id, caller_history_trust(ctx))
            .await?
            .map(|artifact| crate::text_artifact_blob::read_artifact_content(&artifact))
            .transpose()?),
    }
}

async fn redactor_for_target(
    ctx: &ToolCtx,
    target: RecallPath,
) -> Result<crate::redact::RedactionTable> {
    let session_id = match target {
        RecallPath::History => return Ok(ctx.redact.as_ref().clone()),
        RecallPath::Transcript(session_id)
        | RecallPath::Compaction(session_id, _)
        | RecallPath::Plan(session_id)
        | RecallPath::Artifact(session_id, _) => session_id,
    };
    let Some(target_table) = ctx
        .session
        .persisted_redaction_table_for_session(session_id)
        .await?
    else {
        return Ok(ctx.redact.as_ref().clone());
    };
    ctx.redact
        .union(&target_table)
        .map_err(|error| anyhow::anyhow!("unioning target-session redaction table: {error:#}"))
}

fn not_found(path: &str, target: RecallPath) -> ToolOutput {
    let message = match target {
        RecallPath::Artifact(_, _) => format!("No readable artifact exists at `{path}`."),
        RecallPath::Compaction(_, n) => format!("No compaction {n} exists for `{path}`."),
        _ => format!("No readable pseudofile exists at `{path}`."),
    };
    ToolOutput::text(message)
}

fn render_page(content: &str, path: &str, args: &Value) -> Result<ToolOutput> {
    let request = page_request(args, content.lines().count())?;
    let lines: Vec<_> = content.lines().collect();
    let (start, end) = match request.mode {
        PageMode::Offset { start, limit } => (start, start.saturating_add(limit.saturating_sub(1))),
        PageMode::Range { start, end } => (start, end),
    };
    if lines.is_empty() {
        return Ok(ToolOutput::text(String::new()));
    }
    if start > lines.len() {
        return Ok(ToolOutput::text(format!(
            "Note: start line {start} exceeds file length ({} lines).\n",
            lines.len()
        )));
    }

    let mut out = String::new();
    let mut next = None;
    for number in start..=end.min(lines.len()) {
        let line = lines[number - 1];
        let byte = if number == start {
            request.start_byte
        } else {
            0
        };
        if byte > line.len() || !line.is_char_boundary(byte) {
            return Err(invalid_input(
                "`start_byte` must be a UTF-8 boundary within the selected line",
            ));
        }
        let prefix = format!("{number}|");
        let remaining = OUTPUT_BYTE_CAP
            .saturating_sub(out.len())
            .saturating_sub(CONTINUATION_RESERVE_BYTES);
        if remaining <= prefix.len() + 1 {
            next = Some((number, byte));
            break;
        }
        let text_budget = remaining - prefix.len() - 1;
        let slice = &line[byte..];
        let clipped = utf8_prefix(slice, text_budget);
        out.push_str(&prefix);
        out.push_str(clipped);
        out.push('\n');
        if clipped.len() != slice.len() {
            next = Some((number, byte + clipped.len()));
            break;
        }
    }

    if next.is_none() && matches!(request.mode, PageMode::Offset { .. }) && end < lines.len() {
        next = Some((end + 1, 0));
    }
    let Some((next_line, next_byte)) = next else {
        return Ok(ToolOutput::text(out));
    };
    let continuation = continuation(path, request.mode, end, next_line, next_byte);
    while out.len() + continuation.len() > OUTPUT_BYTE_CAP {
        out.pop();
    }
    out.push_str(&continuation);
    Ok(ToolOutput::truncated_text(out))
}

fn page_request(args: &Value, line_count: usize) -> Result<PageRequest> {
    let start_byte = nonnegative_usize(args, "start_byte")?.unwrap_or(0);
    if args.get("start_line").is_some()
        || args.get("end_line").is_some()
        || (args.get("start_byte").is_some() && args.get("offset").is_none())
    {
        let start = positive_or_one(args, "start_line")?.unwrap_or(1);
        let end = positive_or_one(args, "end_line")?.unwrap_or_else(|| {
            if args.get("start_byte").is_some() {
                start
            } else {
                line_count
            }
        });
        if end < start {
            return Err(invalid_input(
                "`end_line` must be greater than or equal to `start_line`",
            ));
        }
        return Ok(PageRequest {
            mode: PageMode::Range { start, end },
            start_byte,
        });
    }
    let start = positive_or_one(args, "offset")?.unwrap_or(1);
    let limit = line_limit(args)?;
    Ok(PageRequest {
        mode: PageMode::Offset { start, limit },
        start_byte,
    })
}

fn continuation(
    path: &str,
    mode: PageMode,
    selected_end: usize,
    next_line: usize,
    next_byte: usize,
) -> String {
    match mode {
        PageMode::Offset { limit, .. } => {
            let remaining = if next_line > selected_end {
                limit
            } else {
                selected_end
                    .saturating_sub(next_line)
                    .saturating_add(1)
                    .max(1)
            };
            if next_byte == 0 {
                format!(
                    "... [truncated; read `{path}` with offset={next_line}, limit={remaining}]\n"
                )
            } else {
                format!(
                    "... [truncated; read `{path}` with offset={next_line}, limit={remaining}, start_byte={next_byte}]\n"
                )
            }
        }
        PageMode::Range { end, .. } => {
            if next_byte == 0 {
                format!(
                    "... [truncated; read `{path}` with start_line={next_line}, end_line={end}]\n"
                )
            } else {
                format!(
                    "... [truncated; read `{path}` with start_line={next_line}, end_line={end}, start_byte={next_byte}]\n"
                )
            }
        }
    }
}

fn line_limit(args: &Value) -> Result<usize> {
    let Some(value) = args.get("limit") else {
        return Ok(DEFAULT_LINES);
    };
    let value = value
        .as_u64()
        .ok_or_else(|| invalid_input("`limit` must be an integer"))?;
    if value == 0 {
        return Ok(DEFAULT_LINES);
    }
    usize::try_from(value).map_err(|_| invalid_input("`limit` exceeds this platform's line range"))
}

fn positive_or_one(args: &Value, name: &str) -> Result<Option<usize>> {
    let Some(value) = args.get(name) else {
        return Ok(None);
    };
    let value = value
        .as_u64()
        .ok_or_else(|| invalid_input(format!("`{name}` must be an integer")))?;
    usize::try_from(value.max(1))
        .map(Some)
        .map_err(|_| invalid_input(format!("`{name}` exceeds this platform's line range")))
}

fn nonnegative_usize(args: &Value, name: &str) -> Result<Option<usize>> {
    let Some(value) = args.get(name) else {
        return Ok(None);
    };
    let value = value
        .as_u64()
        .ok_or_else(|| invalid_input(format!("`{name}` must be a non-negative integer")))?;
    usize::try_from(value)
        .map(Some)
        .map_err(|_| invalid_input(format!("`{name}` exceeds this platform's byte range")))
}

fn parse_expected_revision(args: &Value) -> Result<Option<i64>> {
    args.get("expected_revision")
        .map(|value| {
            value
                .as_i64()
                .filter(|value| *value >= 0)
                .ok_or_else(|| invalid_input("`expected_revision` must be a non-negative integer"))
        })
        .transpose()
}

fn utf8_prefix(value: &str, budget: usize) -> &str {
    if value.len() <= budget {
        return value;
    }
    let mut end = budget;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

async fn history_entries(ctx: &ToolCtx) -> Result<Vec<String>> {
    let mut entries = Vec::new();
    for session in ctx
        .session
        .db
        .list_active_sessions_for_project(&ctx.session.project_id)
        .await?
    {
        let short = session
            .short_id
            .unwrap_or_else(|| session.session_id.to_string());
        entries.push(format!("cockpit://session/{short}/transcript"));
        if ctx
            .session
            .db
            .get_session_plan_doc_for_trust(session.session_id, caller_history_trust(ctx))
            .await?
            .is_some()
        {
            entries.push(format!("cockpit://session/{short}/plan"));
        }
        let compactions = ctx
            .session
            .db
            .compaction_numbers_for_trust(session.session_id, caller_history_trust(ctx))
            .await?;
        for n in compactions {
            entries.push(format!("cockpit://session/{short}/compactions/{n}"));
        }
        for artifact in ctx
            .session
            .db
            .list_text_artifacts_for_trust(session.session_id, caller_history_trust(ctx))
            .await?
        {
            entries.push(format!(
                "cockpit://session/{short}/artifacts/{}",
                artifact.artifact_id
            ));
        }
    }
    Ok(entries)
}

/// `cockpit://history/` is a discovery pseudodirectory whose children are
/// canonical `cockpit://session/...` pseudofiles. Rebase patterns expressed
/// at that directory before matching the canonical names. This makes both
/// `cockpit://history/**` and the standard scoped form (`path` + `pattern`)
/// enumerate the same visible entries.
fn history_glob_pattern(pattern: &str, path: Option<&str>) -> Result<String> {
    const HISTORY: &str = "cockpit://history";
    const SESSIONS: &str = "cockpit://session";

    if let Some(suffix) = pattern.strip_prefix(HISTORY) {
        return Ok(format!("{SESSIONS}{suffix}"));
    }
    match path.map(|value| value.trim_end_matches('/')) {
        Some(HISTORY) => Ok(format!("{SESSIONS}/{pattern}")),
        Some(other) if is_recall_path(other) => Err(invalid_input(
            "`glob` supports `cockpit://history/` as its only recall directory",
        )),
        _ => Ok(pattern.to_string()),
    }
}

async fn history_directory(ctx: &ToolCtx) -> Result<String> {
    Ok(history_entries(ctx).await?.join("\n"))
}

fn append_capped_record(out: &mut String, row: &str) -> bool {
    const MARKER: &str = "... [truncated; narrow the search]\n";
    if out.len() + row.len() + MARKER.len() <= OUTPUT_BYTE_CAP {
        out.push_str(row);
        return true;
    }
    if out.is_empty() {
        out.push_str(utf8_prefix(
            row,
            OUTPUT_BYTE_CAP.saturating_sub(MARKER.len()),
        ));
    }
    false
}

fn truncated_search_output(mut out: String) -> ToolOutput {
    const MARKER: &str = "... [truncated; narrow the search]\n";
    while out.len() + MARKER.len() > OUTPUT_BYTE_CAP {
        out.pop();
    }
    out.push_str(MARKER);
    ToolOutput::truncated_text(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashSet;
    use std::sync::Arc;
    use tempfile::TempDir;

    #[test]
    fn oversized_line_continuation_advances_within_the_line() {
        let content = "x".repeat(OUTPUT_BYTE_CAP * 2);
        let first = render_page(
            &content,
            "cockpit://session/abc123/transcript",
            &json!({ "offset": 1, "limit": 1 }),
        )
        .unwrap();
        let first_text = first.content.model_text();
        assert!(first_text.len() <= OUTPUT_BYTE_CAP);
        assert!(first_text.contains("offset=1, limit=1, start_byte="));

        let cursor = first_text
            .split("start_byte=")
            .nth(1)
            .unwrap()
            .split(']')
            .next()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert!(cursor > 0);
        let second = render_page(
            &content,
            "cockpit://session/abc123/transcript",
            &json!({ "offset": 1, "limit": 1, "start_byte": cursor }),
        )
        .unwrap();
        assert!(second.content.model_text().starts_with("1|"));
        assert_ne!(first.content.model_text(), second.content.model_text());
    }

    #[test]
    fn range_mode_uses_the_read_tool_start_and_end_grammar() {
        let output = render_page(
            "one\ntwo\nthree",
            "cockpit://session/abc123/transcript",
            &json!({ "start_line": 2, "end_line": 2 }),
        )
        .unwrap();
        assert_eq!(output.content.model_text(), "2|two\n");
    }

    #[test]
    fn history_globs_rebase_to_canonical_session_entries() {
        assert_eq!(
            history_glob_pattern("cockpit://history/**", None).unwrap(),
            "cockpit://session/**"
        );
        assert_eq!(
            history_glob_pattern("*", Some("cockpit://history/")).unwrap(),
            "cockpit://session/*"
        );
    }

    #[tokio::test]
    async fn plan_pseudofile_uses_read_write_revision_contract() {
        let tmp = TempDir::new().unwrap();
        let (ctx, _db) = crate::tools::common::test_ctx_with_db(tmp.path());
        let path = format!("cockpit://session/{}/plan", ctx.session.short_id());

        let wrote = write(&json!({ "path": path.clone(), "content": "# Plan" }), &ctx)
            .await
            .unwrap()
            .unwrap();
        assert!(wrote.content.model_text().contains("revision 1"));

        let read = self::read(&json!({ "path": path.clone() }), &ctx)
            .await
            .unwrap();
        assert!(read.content.model_text().contains("[revision=1]\n# Plan"));

        let error = write(&json!({ "path": path, "content": "# Revised" }), &ctx)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("expected_revision"));
    }

    #[tokio::test]
    async fn single_pseudofile_grep_supports_literal_and_regex_modes() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        db.insert_session_event(
            ctx.session.id,
            crate::db::session_log::SessionEventKind::UserMessage,
            None,
            None,
            &json!({ "text": "a+b\naxb", "display_text": "a+b\naxb" }),
        )
        .await
        .unwrap();
        let path = format!("cockpit://session/{}/transcript", ctx.session.short_id());

        let literal = grep(
            &json!({ "path": path, "pattern": "a+b", "mode": "literal" }),
            &ctx,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(literal.content.model_text().contains("a+b"));
        assert!(!literal.content.model_text().contains("axb"));

        let regex = grep(
            &json!({ "path": path, "pattern": "a.b", "mode": "regex" }),
            &ctx,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(regex.content.model_text().contains("a+b"));
        assert!(regex.content.model_text().contains("axb"));
    }

    #[tokio::test]
    async fn recall_provider_rejects_callers_without_history_search() {
        let tmp = TempDir::new().unwrap();
        let (mut ctx, _db) = crate::tools::common::test_ctx_with_db(tmp.path());
        ctx.available_tools = Arc::new(HashSet::from(["read".to_string(), "grep".to_string()]));
        let path = format!("cockpit://session/{}/transcript", ctx.session.short_id());

        for result in [
            read(&json!({ "path": path.clone() }), &ctx)
                .await
                .map(|_| ()),
            grep(
                &json!({ "path": path.clone(), "pattern": "anything", "mode": "literal" }),
                &ctx,
            )
            .await
            .map(|_| ()),
            glob("cockpit://history/**", None, &ctx).await.map(|_| ()),
        ] {
            assert!(result.is_err());
            assert!(format!("{:#}", result.unwrap_err()).contains("history_search"));
        }
    }
}
