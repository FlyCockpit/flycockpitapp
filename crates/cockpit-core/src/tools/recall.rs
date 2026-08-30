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
use crate::tools::common::OUTPUT_BYTE_CAP;
use crate::tools::session_search::caller_history_trust;

const PREFIX: &str = "cockpit://";
const DEFAULT_LINES: usize = 2_000;
const MAX_SEARCH_MATCHES: usize = 100;

#[derive(Debug)]
enum RecallPath {
    History,
    Transcript(Uuid),
    Compaction(Uuid, usize),
    Plan(Uuid),
    Artifact(Uuid, Uuid),
}

pub fn is_recall_path(path: &str) -> bool {
    path.starts_with(PREFIX)
}

pub async fn read(args: &Value, ctx: &ToolCtx) -> Result<ToolOutput> {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_input("`path` is required"))?;
    match parse(path, ctx).await? {
        RecallPath::History => Ok(ToolOutput::text(history_directory(ctx).await?)),
        RecallPath::Transcript(session_id) => {
            let turns = ctx
                .session
                .db
                .thread_turns_for_trust(session_id, caller_history_trust(ctx))
                .await?;
            let content = turns
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
                .join("\n");
            Ok(render_page(&content, path, args))
        }
        RecallPath::Compaction(session_id, n) => {
            let Some(content) = ctx
                .session
                .db
                .compaction_text_for_trust(session_id, n, caller_history_trust(ctx))
                .await?
            else {
                return Ok(ToolOutput::text(format!(
                    "No compaction {n} exists for `{path}`."
                )));
            };
            Ok(render_page(&content, path, args))
        }
        RecallPath::Plan(session_id) => {
            let content = ctx
                .session
                .db
                .get_session_plan_doc(session_id)
                .await?
                .map(|doc| format!("[revision={}]\n{}", doc.revision, doc.content))
                .unwrap_or_default();
            Ok(render_page(&content, path, args))
        }
        RecallPath::Artifact(session_id, artifact_id) => {
            let Some(artifact) = ctx
                .session
                .db
                .text_artifact_for_trust(session_id, artifact_id, caller_history_trust(ctx))
                .await?
            else {
                return Ok(ToolOutput::text(format!(
                    "No readable artifact exists at `{path}`."
                )));
            };
            Ok(render_page(
                &ctx.redact.scrub(&artifact.content),
                path,
                args,
            ))
        }
    }
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
    if content.len() > 256 * 1024 {
        return Err(invalid_input("plan document exceeds 256 KiB"));
    }
    let doc = ctx
        .session
        .db
        .write_session_plan_doc(session_id, content)
        .await?;
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
    let entries = history_entries(ctx).await?;
    let matcher = globset::Glob::new(pattern)
        .map_err(|err| invalid_input(format!("invalid glob `{pattern}`: {err}")))?
        .compile_matcher();
    let body = entries
        .into_iter()
        .filter(|entry| matcher.is_match(entry))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Some(if body.is_empty() {
        ToolOutput::text("No matching cockpit pseudofiles.".to_string())
    } else {
        ToolOutput::text(format!("{body}\n"))
    }))
}

pub async fn grep(args: &Value, ctx: &ToolCtx) -> Result<Option<ToolOutput>> {
    let Some(path) = args.get("path").and_then(Value::as_str) else {
        return Ok(None);
    };
    if !is_recall_path(path) {
        return Ok(None);
    }
    let target = parse(path, ctx).await?;
    if matches!(target, RecallPath::History) {
        // #134 owns the final history-search tool.  Until then, discovery is
        // FTS-only; never fall back to recursively regex-scanning transcripts.
        return Ok(Some(history_fts_search(args, ctx).await?));
    }
    let pattern = args
        .get("pattern")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_input("`pattern` is required"))?;
    let content = read(
        &serde_json::json!({ "path": path, "limit": usize::MAX }),
        ctx,
    )
    .await?;
    let regex = RegexBuilder::new(pattern)
        .case_insensitive(
            args.get("case_insensitive")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        )
        .build()
        .map_err(|err| invalid_input(format!("invalid regex: {err}")))?;
    let mut out = String::new();
    for (line, text) in content.content.model_text().lines().enumerate() {
        if regex.is_match(text) {
            let row = format!("{path}:{}: {text}\n", line + 1);
            if out.len() + row.len() > OUTPUT_BYTE_CAP || out.lines().count() >= MAX_SEARCH_MATCHES
            {
                return Ok(Some(ToolOutput::truncated_text(format!(
                    "{out}... [truncated]\n"
                ))));
            }
            out.push_str(&row);
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
            "invalid cockpit path; use `cockpit://session/<short_id>/transcript`, `/compactions/<n>`, `/artifacts/<uuid>`, or `/plan`",
        ));
    }
    let session_id = resolve_session(ctx, parts[3]).await?;
    match parts.as_slice() {
        ["cockpit:", "", "session", _, "transcript"] => Ok(RecallPath::Transcript(session_id)),
        ["cockpit:", "", "session", _, "plan"] => Ok(RecallPath::Plan(session_id)),
        ["cockpit:", "", "session", _, "compactions", n] => Ok(RecallPath::Compaction(
            session_id,
            n.parse()
                .map_err(|_| invalid_input("compaction number must be a positive integer"))?,
        )),
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
        return ctx
            .session
            .db
            .get_session(id)
            .await?
            .map(|_| id)
            .ok_or_else(|| invalid_input("session does not exist"));
    }
    if let Some(row) = ctx
        .session
        .db
        .get_session_by_short_id(&ctx.session.project_id, id)
        .await?
    {
        return Ok(row.session_id);
    }
    let found = ctx.session.db.find_sessions_by_short_id_global(id).await?;
    match found.as_slice() {
        [row] => Ok(row.session_id),
        [] => Err(invalid_input(format!("no session with short id `{id}`"))),
        _ => Err(invalid_input(format!(
            "short id `{id}` is ambiguous; use the full UUID"
        ))),
    }
}

fn render_page(content: &str, path: &str, args: &Value) -> ToolOutput {
    let offset = args
        .get("offset")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        .max(1) as usize;
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_LINES as u64) as usize;
    let lines: Vec<_> = content.lines().collect();
    let mut out = String::new();
    let mut next = None;
    for (index, line) in lines.iter().enumerate().skip(offset - 1).take(limit) {
        let row = format!("{}|{}\n", index + 1, line);
        if out.len() + row.len() + 96 > OUTPUT_BYTE_CAP {
            next = Some(index + 1);
            break;
        }
        out.push_str(&row);
    }
    if next.is_none() && offset.saturating_sub(1).saturating_add(limit) < lines.len() {
        next = Some(offset.saturating_add(limit));
    }
    if let Some(next) = next {
        out.push_str(&format!(
            "... [truncated; read `{path}` with offset={next}]\n"
        ));
        ToolOutput::truncated_text(out)
    } else {
        ToolOutput::text(out)
    }
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
        entries.push(format!("cockpit://session/{short}/plan"));
        let compactions = ctx
            .session
            .db
            .compaction_count_for_trust(session.session_id, caller_history_trust(ctx))
            .await?;
        for n in 1..=compactions {
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

async fn history_directory(ctx: &ToolCtx) -> Result<String> {
    Ok(format!("{}\n", history_entries(ctx).await?.join("\n")))
}

async fn history_fts_search(args: &Value, ctx: &ToolCtx) -> Result<ToolOutput> {
    let query = args
        .get("pattern")
        .and_then(Value::as_str)
        .unwrap_or_default();
    ctx.session.db.fts5_available().await?;
    let hits = ctx
        .session
        .db
        .search_candidates_for_trust(
            query,
            Some(&ctx.session.project_id),
            None,
            None,
            20,
            caller_history_trust(ctx),
        )
        .await?;
    let body = hits
        .into_iter()
        .map(|hit| {
            format!(
                "cockpit://session/{}/transcript: {}",
                hit.short_id.unwrap_or_else(|| hit.session_id.to_string()),
                hit.snippet.trim()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(ToolOutput::text(if body.is_empty() {
        "No matches.".to_string()
    } else {
        format!("{body}\n")
    }))
}
