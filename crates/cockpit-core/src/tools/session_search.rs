//! `session_search` — BM25 recall across past threads.
//!
//! Finds prior conversations whose title or message text matches a
//! query, ranked by FTS5 BM25 with `last_active_at_unix_ms` recency as the
//! tiebreaker (migration 0013 / [`crate::db::session_search`]). Defaults
//! to the current project, excludes archived + the live session, and
//! returns one highlighted ~150-char snippet per thread. The companion
//! `read cockpit://session/<short_id>/transcript` reads a chosen thread back.
//!
//! Output is plain tool text; it passes back through the redaction
//! chokepoint on the next outbound prompt like any other tool result —
//! no bypass, no second pre-redaction (prompt decision). Stored history is raw,
//! and trusted-model rows may contain secrets because trusted outbound redaction
//! is a no-op; history text must only reach models as ordinary tool output.

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::db::session_search::HistoryCallerTrust;
use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};

/// Default number of threads shown; the agent can widen via `limit`.
const DEFAULT_LIMIT: u32 = 10;
/// Hard ceiling on `limit` so a runaway value can't dump the whole DB.
const MAX_LIMIT: u32 = 50;
const TOOL_SCAN_MAX_SESSIONS: u32 = 16;
const TOOL_SCAN_MAX_ROWS_PER_SESSION: u32 = 20;

pub struct SessionSearchTool;

#[async_trait]
impl Tool for SessionSearchTool {
    fn name(&self) -> &str {
        "session_search"
    }

    fn description(&self) -> &str {
        "Search past sessions' titles and messages by relevance; returns ranked threads with snippets"
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }

    fn verbose_description(&self) -> Option<String> {
        Some(
            "Search your earlier conversations (past sessions) by keyword and get back the most \
             relevant threads, each with its short id and a matching snippet. Use this when the \
             user refers to prior work — \"like we did before\", \"the bug from last week\" — to \
             find which session it was; then read it in full through its `cockpit://` transcript. Searches the \
             current project by default; set `all_projects` to widen it. Narrow large result \
             sets with `since` (only sessions active after a date). This is recall of past \
             conversations, not a code or web search."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "query":      { "type": "string", "description": "Keyword search text" },
                "all_projects": { "type": "boolean", "description": "All-project recall (default current project)" },
                "limit":      { "type": "integer", "description": "Max threads (default 10, max 50)" },
                "since":      { "type": "string", "description": "RFC3339/`YYYY-MM-DD` lower bound on last activity" }
            },
            "required": ["query"]
        })
    }

    fn verbose_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "query":      { "type": "string", "description": "Literal keywords to search past sessions for; matches titles and message text" },
                "all_projects": { "type": "boolean", "description": "When true, search sessions across all projects; defaults to the current project only" },
                "limit":      { "type": "integer", "description": "Maximum number of matching threads to return; defaults to 10, maximum 50" },
                "since":      { "type": "string", "description": "Optional lower bound on last activity (RFC3339 timestamp or `YYYY-MM-DD`); only sessions active after this are returned" }
            },
            "required": ["query"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        ctx.session
            .db
            .fts5_available()
            .await
            .map_err(|e| crate::engine::tool::invalid_input(format!("{e:#}")))?;

        let query = args
            .get("query")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|q| !q.is_empty())
            .ok_or_else(|| invalid_input("`query` is required"))?;

        let all_projects = args
            .get("all_projects")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let project_id = if all_projects {
            None
        } else {
            Some(ctx.session.project_id.as_str())
        };

        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .map(|l| (l as u32).clamp(1, MAX_LIMIT))
            .unwrap_or(DEFAULT_LIMIT);

        let since = match args.get("since").and_then(Value::as_str) {
            Some(s) if !s.trim().is_empty() => Some(parse_since(s.trim())?),
            _ => None,
        };

        // Fetch a candidate pool larger than the display budget so the
        // ranking seam has room to reorder before we truncate (future
        // embedding re-ranker; identity today).
        let pool = (limit.saturating_mul(3)).clamp(limit, MAX_LIMIT * 3);
        let hits = ctx
            .session
            .db
            .search_candidates_for_trust(
                query,
                project_id,
                Some(ctx.session.id),
                since,
                pool,
                caller_history_trust(ctx),
            )
            .await
            .map_err(|e| anyhow::anyhow!("session_search: {e:#}"))?;

        if hits.is_empty() {
            let scope = if all_projects {
                "any project".to_string()
            } else {
                format!("project `{}`", ctx.session.project_id)
            };
            return Ok(ToolOutput::text(format!(
                "No past sessions in {scope} match `{query}`."
            )));
        }

        let mut out = String::new();
        for hit in hits.iter().take(limit as usize) {
            // A pre-§17 row may lack a short_id; fall back to the full
            // UUID, which the cockpit pseudofile path also accepts, so the
            // thread stays reachable.
            let id = hit
                .short_id
                .clone()
                .unwrap_or_else(|| hit.session_id.to_string());
            let short = id.as_str();
            let title = hit.title.as_deref().unwrap_or("(untitled)");
            let date = human_date(hit.last_active_at_unix_ms);
            let snippet = hit.snippet.trim();
            out.push_str(&format!("{short}  {date}  {title}\n    {snippet}\n"));
        }
        out.push_str("\nUse `read` on `cockpit://session/<short_id>/transcript` for a thread.\n");
        Ok(ToolOutput::text(out))
    }
}

pub struct SessionLineageSearchTool;

#[async_trait]
impl Tool for SessionLineageSearchTool {
    fn name(&self) -> &str {
        "session_lineage_search"
    }

    fn description(&self) -> &str {
        "Search the current session's compaction lineage, including compacted predecessors and the current session"
    }

    fn verbose_description(&self) -> Option<String> {
        Some(
            "Search the current session's persisted history lineage, including compacted \
             predecessor sessions and the current session, for a keyword or phrase. Use this \
             when a detail may have been summarized away by compaction. It returns bounded \
             snippets and can also scan bounded tool-call event JSON; follow up with \
             `read` on a cockpit transcript only for a specific session/topic you need. This is recall of \
             stored conversation history, not a code search."
                .to_string(),
        )
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Keyword search text" },
                "limit": { "type": "integer", "description": "Max FTS hits (default 10, max 50)" },
                "include_tool_events": { "type": "boolean", "description": "Also scan bounded tool-call event JSON inside the lineage" }
            },
            "required": ["query"]
        })
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        ctx.session
            .db
            .fts5_available()
            .await
            .map_err(|e| invalid_input(format!("{e:#}")))?;

        let query = args
            .get("query")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|q| !q.is_empty())
            .ok_or_else(|| invalid_input("`query` is required"))?;
        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .map(|l| (l as u32).clamp(1, MAX_LIMIT))
            .unwrap_or(DEFAULT_LIMIT);
        let include_tool_events = args
            .get("include_tool_events")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let trust = caller_history_trust(ctx);

        let lineage = ctx
            .session
            .db
            .compaction_lineage_sessions(ctx.session.id)
            .await
            .map_err(|e| anyhow::anyhow!("session_lineage_search: {e:#}"))?;
        let hits = ctx
            .session
            .db
            .search_lineage_candidates(query, ctx.session.id, limit, trust)
            .await
            .map_err(|e| anyhow::anyhow!("session_lineage_search: {e:#}"))?;
        let scan = if include_tool_events {
            Some(
                ctx.session
                    .db
                    .scan_tool_events_in_sessions(
                        query,
                        &lineage,
                        trust,
                        TOOL_SCAN_MAX_SESSIONS,
                        TOOL_SCAN_MAX_ROWS_PER_SESSION,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("session_lineage_search: {e:#}"))?,
            )
        } else {
            None
        };

        if hits.is_empty() && scan.as_ref().is_none_or(|scan| scan.hits.is_empty()) {
            return Ok(ToolOutput::text(format!(
                "No accessible lineage history matches `{query}`."
            )));
        }

        let mut out = format!("Lineage history matches for `{query}`:\n");
        for hit in &hits {
            let id = hit
                .short_id
                .clone()
                .unwrap_or_else(|| hit.session_id.to_string());
            let title = hit.title.as_deref().unwrap_or("(untitled)");
            out.push_str(&format!(
                "{}  {}  {}\n    {}\n",
                id,
                human_date(hit.last_active_at_unix_ms),
                title,
                hit.snippet.trim()
            ));
        }
        if let Some(scan) = scan {
            if !scan.hits.is_empty() {
                out.push_str("\nBounded tool-event matches:\n");
                for hit in scan.hits {
                    out.push_str(&format!(
                        "{} [{}] {}: {}\n",
                        hit.session_id,
                        hit.seq,
                        hit.event_type,
                        hit.snippet.trim()
                    ));
                }
            }
            if scan.truncated {
                out.push_str(
                    "\nTool-event scan hit its bounded cap; narrow the query for more detail.\n",
                );
                return Ok(ToolOutput::truncated_text(out));
            }
        }
        Ok(ToolOutput::text(out))
    }
}

pub(crate) fn caller_history_trust(ctx: &ToolCtx) -> HistoryCallerTrust {
    let (Some(provider), Some(model)) = (ctx.session.active_provider(), ctx.session.active_model())
    else {
        return HistoryCallerTrust::Untrusted;
    };
    if ctx
        .config
        .providers()
        .resolve_trust(&provider, &model)
        .is_trusted()
    {
        HistoryCallerTrust::Trusted
    } else {
        HistoryCallerTrust::Untrusted
    }
}

/// `last_active_at_unix_ms` → `YYYY-MM-DD HH:MM UTC`, matching
/// the session browser's date format.
fn human_date(unix_ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(unix_ms)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| unix_ms.to_string())
}

/// Parse the `since` bound: a full RFC3339 timestamp, or a bare
/// `YYYY-MM-DD` date (interpreted as midnight UTC). Returns epoch
/// milliseconds. A bad value is the model's fault → invalid-input.
fn parse_since(s: &str) -> Result<i64> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.timestamp_millis());
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let dt = date
            .and_hms_opt(0, 0, 0)
            .expect("midnight is a valid time")
            .and_utc();
        return Ok(dt.timestamp_millis());
    }
    Err(invalid_input(format!(
        "`since` `{s}` is not an RFC3339 timestamp or `YYYY-MM-DD` date"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::session_log::SessionEventKind;
    use crate::tools::common::test_ctx;
    use serde_json::json;

    fn write_untrusted_provider(root: &std::path::Path) {
        let providers = root.join(".cockpit/providers");
        std::fs::create_dir_all(&providers).unwrap();
        std::fs::write(root.join(".cockpit/config.json"), r#"{}"#).unwrap();
        std::fs::write(
            providers.join("local.json"),
            serde_json::json!({
                "url": "https://example.test/v1",
                "models": [{
                    "id": "local-model",
                    "trust": "untrusted",
                }]
            })
            .to_string(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn search_returns_ranked_threads_with_snippets() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        // A sibling session in the same project with a matching message.
        let other = ctx
            .session
            .db
            .create_session(&ctx.session.project_id, "/x", "Build")
            .await
            .unwrap();
        ctx.session
            .db
            .insert_session_event(
                other.session_id,
                SessionEventKind::UserMessage,
                None,
                None,
                &json!({ "text": "we discussed the peregrine migration route" }),
            )
            .await
            .unwrap();

        let out = SessionSearchTool
            .call(json!({ "query": "peregrine" }), &ctx)
            .await
            .unwrap();
        assert!(out.content.contains(other.short_id.as_ref().unwrap()));
        assert!(out.content.contains("peregrine") || out.content.contains('['));
    }

    #[tokio::test]
    async fn search_empty_match_is_clean_message_not_error() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let out = SessionSearchTool
            .call(json!({ "query": "nothingmatchesthis" }), &ctx)
            .await
            .unwrap();
        assert!(out.content.contains("No past sessions"));
    }

    #[tokio::test]
    async fn search_excludes_the_current_session() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        // Put a matching message in the CURRENT session.
        ctx.session
            .db
            .insert_session_event(
                ctx.session.id,
                SessionEventKind::UserMessage,
                None,
                None,
                &json!({ "text": "current session mentions the wombat" }),
            )
            .await
            .unwrap();
        let out = SessionSearchTool
            .call(json!({ "query": "wombat" }), &ctx)
            .await
            .unwrap();
        assert!(
            out.content.contains("No past sessions"),
            "current session must be excluded: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn history_trust_lineage_search_includes_current_session_without_relaxing_session_search()
    {
        let tmp = tempfile::tempdir().unwrap();
        write_untrusted_provider(tmp.path());
        let ctx = test_ctx(tmp.path());
        ctx.session
            .set_active_model("local", "local-model")
            .unwrap();
        ctx.session
            .db
            .insert_session_event(
                ctx.session.id,
                SessionEventKind::UserMessage,
                None,
                None,
                &json!({ "text": "current lineage has moonstone detail" }),
            )
            .await
            .unwrap();

        let lineage = SessionLineageSearchTool
            .call(
                json!({ "query": "moonstone", "include_tool_events": false }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(lineage.content.contains("moonstone"), "{}", lineage.content);

        let cross_thread = SessionSearchTool
            .call(json!({ "query": "moonstone" }), &ctx)
            .await
            .unwrap();
        assert!(
            cross_thread.content.contains("No past sessions"),
            "{}",
            cross_thread.content
        );
    }

    #[test]
    fn parse_since_accepts_date_and_rfc3339() {
        assert!(parse_since("2024-01-01").is_ok());
        assert!(parse_since("2024-01-01T12:00:00Z").is_ok());
        assert!(parse_since("not-a-date").is_err());
    }
}
