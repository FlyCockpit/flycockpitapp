//! `history_search` — scope-selected FTS recall.
//!
//! Finds prior conversations whose title or message text matches a
//! query, ranked by FTS5 BM25 with `last_active_at_unix_ms` recency as the
//! tiebreaker (migration 0013 / [`crate::db::session_search`]). Defaults
//! to the current project, excludes archived + the live session, and
//! returns one highlighted ~150-char snippet per recall target. The companion
//! `read cockpit://session/<short_id-or-uuid>/transcript` reads a chosen thread back.
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

pub struct HistorySearchTool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HistorySearchScope {
    Past,
    Lineage,
    CurrentArtifacts,
    AllProjects,
}

impl HistorySearchScope {
    fn parse(args: &Value) -> Result<Self> {
        match args.get("scope").and_then(Value::as_str).unwrap_or("past") {
            "past" => Ok(Self::Past),
            "lineage" => Ok(Self::Lineage),
            "current-artifacts" => Ok(Self::CurrentArtifacts),
            "all-projects" => Ok(Self::AllProjects),
            _ => Err(invalid_input(
                "`scope` must be `past`, `lineage`, `current-artifacts`, or `all-projects`",
            )),
        }
    }
}

#[async_trait]
impl Tool for HistorySearchTool {
    fn name(&self) -> &str {
        "history_search"
    }

    fn description(&self) -> &str {
        "Search persisted history by scope with FTS; returns bounded ranked snippets and cockpit pseudofile targets"
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }

    fn verbose_description(&self) -> Option<String> {
        Some(
            "Search your earlier conversations (past sessions) by keyword and get back the most \
             relevant history, each with a bounded FTS snippet and a `cockpit://` target. Choose \
             `past` for earlier sessions in this workspace, `lineage` for compaction predecessors \
             plus the current session, `current-artifacts` for the current session's text artifacts, \
             or `all-projects` for consent-permitted cross-workspace recall. Read one returned \
             pseudofile for details; this tool never recursively scans transcripts. Narrow large \
             result sets with `since` (only sessions active after a date)."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "query":      { "type": "string", "description": "FTS keyword search text" },
                "scope": { "type": "string", "enum": ["past", "lineage", "current-artifacts", "all-projects"], "description": "Recall area (default `past`)" },
                "limit":      { "type": "integer", "description": "Max threads (default 10, max 50)" },
                "since":      { "type": "string", "description": "RFC3339/`YYYY-MM-DD` lower bound on last activity; applies to past scopes" },
                "include_tool_events": { "type": "boolean", "description": "For `lineage`, also scan bounded tool-event JSON" }
            },
            "required": ["query"]
        })
    }

    fn verbose_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "query":      { "type": "string", "description": "Literal keywords to search indexed titles, descriptions, messages, compactions, or artifacts" },
                "scope": { "type": "string", "enum": ["past", "lineage", "current-artifacts", "all-projects"], "description": "`past` excludes the current session; `lineage` includes it; `current-artifacts` returns artifact pseudofiles; `all-projects` requires two-way workspace consent" },
                "limit":      { "type": "integer", "description": "Maximum number of matching targets to return; defaults to 10, maximum 50" },
                "since":      { "type": "string", "description": "Optional lower bound on last activity for past scopes" },
                "include_tool_events": { "type": "boolean", "description": "For `lineage`, scan a bounded set of tool-event JSON rows (default true)" }
            },
            "required": ["query"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let scope = HistorySearchScope::parse(&args)?;
        crate::tools::history_scope::require_recall_permission(ctx)?;
        crate::tools::history_scope::require_session_access(ctx, ctx.session.id).await?;
        // Keep consent stable across discovery, target-redaction union, and
        // output construction. Revocations acquire the exclusive side first.
        let _disclosure_permit = ctx.session.db.history_scope_disclosure_permit().await;
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

        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .map(|l| (l as u32).clamp(1, MAX_LIMIT))
            .unwrap_or(DEFAULT_LIMIT);

        let since = match args.get("since").and_then(Value::as_str) {
            Some(s) if !s.trim().is_empty() => Some(parse_since(s.trim())?),
            _ => None,
        };

        let trust = caller_history_trust(ctx);
        match scope {
            HistorySearchScope::CurrentArtifacts => {
                let hits = ctx
                    .session
                    .db
                    .search_current_artifact_candidates_for_trust(
                        query,
                        ctx.session.id,
                        limit,
                        trust,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("history_search: {e:#}"))?;
                if hits.is_empty() {
                    return Ok(ToolOutput::text(format!(
                        "No accessible current-session artifacts match `{query}`."
                    )));
                }
                let mut out = format!("Current artifact matches for `{query}`:\n");
                for hit in hits {
                    let snippet =
                        redact_target_text(ctx, ctx.session.id, hit.snippet.trim()).await?;
                    out.push_str(&format!(
                        "cockpit://session/{}/artifacts/{}\n    {}\n",
                        ctx.session.short_id(),
                        hit.artifact_id,
                        snippet.trim()
                    ));
                }
                Ok(ToolOutput::text(out))
            }
            HistorySearchScope::Lineage => {
                let lineage = ctx
                    .session
                    .db
                    .compaction_lineage_sessions(ctx.session.id)
                    .await
                    .map_err(|e| anyhow::anyhow!("history_search: {e:#}"))?;
                let hits = ctx
                    .session
                    .db
                    .search_lineage_candidates_in_sessions(
                        query,
                        &ctx.session.project_id,
                        &lineage,
                        trust,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("history_search: {e:#}"))?;
                let include_tool_events = args
                    .get("include_tool_events")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                let scan = if include_tool_events {
                    Some(
                        ctx.session
                            .db
                            .scan_tool_events_in_sessions(
                                query,
                                &ctx.session.project_id,
                                &lineage,
                                trust,
                                TOOL_SCAN_MAX_SESSIONS,
                                TOOL_SCAN_MAX_ROWS_PER_SESSION,
                            )
                            .await
                            .map_err(|e| anyhow::anyhow!("history_search: {e:#}"))?,
                    )
                } else {
                    None
                };
                render_lineage(query, hits, scan, limit, ctx).await
            }
            HistorySearchScope::Past | HistorySearchScope::AllProjects => {
                let all_projects = scope == HistorySearchScope::AllProjects;
                let project_id = (!all_projects).then_some(ctx.session.project_id.as_str());
                let hits = if all_projects {
                    ctx.session
                        .db
                        .search_permitted_candidates_for_trust(
                            query,
                            &ctx.session.project_id,
                            Some(ctx.session.id),
                            since,
                            limit,
                            trust,
                        )
                        .await
                } else {
                    ctx.session
                        .db
                        .search_candidates_for_trust(
                            query,
                            project_id,
                            Some(ctx.session.id),
                            since,
                            limit,
                            trust,
                        )
                        .await
                }
                .map_err(|e| anyhow::anyhow!("history_search: {e:#}"))?;
                render_session_hits(query, &hits, limit, all_projects, ctx).await
            }
        }
    }
}

async fn render_session_hits(
    query: &str,
    hits: &[crate::db::session_search::SearchHit],
    limit: u32,
    all_projects: bool,
    ctx: &ToolCtx,
) -> Result<ToolOutput> {
    if hits.is_empty() {
        let scope = if all_projects {
            "permitted projects"
        } else {
            "this project"
        };
        return Ok(ToolOutput::text(format!(
            "No past sessions in {scope} match `{query}`."
        )));
    }
    let mut out = String::new();
    for hit in hits.iter().take(limit as usize) {
        let id = if hit.project_id == ctx.session.project_id {
            hit.short_id
                .clone()
                .unwrap_or_else(|| hit.session_id.to_string())
        } else {
            hit.session_id.to_string()
        };
        let title = redact_target_text(
            ctx,
            hit.session_id,
            hit.title.as_deref().unwrap_or("(untitled)"),
        )
        .await?;
        let snippet = redact_target_text(ctx, hit.session_id, hit.snippet.trim()).await?;
        out.push_str(&format!(
            "cockpit://session/{id}/transcript  {}  {title}\n    {}\n",
            human_date(hit.last_active_at_unix_ms),
            snippet.trim()
        ));
    }
    let displayed: Vec<_> = hits
        .iter()
        .take(limit as usize)
        .map(|hit| hit.session_id)
        .collect();
    if !ctx
        .session
        .db
        .sessions_access_allowed(&ctx.session.project_id, &displayed)
        .await?
    {
        return Err(invalid_input(
            "history access changed before results could be returned",
        ));
    }
    Ok(ToolOutput::text(out))
}

async fn render_lineage(
    query: &str,
    hits: Vec<crate::db::session_search::SearchHit>,
    scan: Option<crate::db::session_search::ToolEventScan>,
    limit: u32,
    ctx: &ToolCtx,
) -> Result<ToolOutput> {
    if hits.is_empty() && scan.as_ref().is_none_or(|scan| scan.hits.is_empty()) {
        return Ok(ToolOutput::text(format!(
            "No accessible lineage history matches `{query}`."
        )));
    }
    let mut out = format!("Lineage history matches for `{query}`:\n");
    for hit in hits.into_iter().take(limit as usize) {
        let id = if hit.project_id == ctx.session.project_id {
            hit.short_id.unwrap_or_else(|| hit.session_id.to_string())
        } else {
            hit.session_id.to_string()
        };
        let title = redact_target_text(
            ctx,
            hit.session_id,
            hit.title.as_deref().unwrap_or("(untitled)"),
        )
        .await?;
        let snippet = redact_target_text(ctx, hit.session_id, hit.snippet.trim()).await?;
        out.push_str(&format!(
            "cockpit://session/{id}/transcript  {}  {}\n    {}\n",
            human_date(hit.last_active_at_unix_ms),
            title.trim(),
            snippet.trim()
        ));
    }
    if let Some(scan) = scan {
        if !scan.hits.is_empty() {
            out.push_str("\nBounded tool-event matches:\n");
            for hit in scan.hits {
                let event_type = redact_target_text(ctx, hit.session_id, &hit.event_type).await?;
                let snippet = redact_target_text(ctx, hit.session_id, hit.snippet.trim()).await?;
                out.push_str(&format!(
                    "{} [{}] {}: {}\n",
                    hit.session_id,
                    hit.seq,
                    event_type.trim(),
                    snippet.trim()
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

/// Build the model-visible redactor for one history target. A target session's
/// persisted table is durable knowledge of secrets it observed, so it must be
/// unioned with the caller's table even for same-workspace recall. Parse and
/// union errors fail the search rather than exposing an unredacted snippet.
async fn redact_target_text(ctx: &ToolCtx, session_id: uuid::Uuid, text: &str) -> Result<String> {
    let Some(target_table) = ctx
        .session
        .persisted_redaction_table_for_session(&ctx.session.project_id, session_id)
        .await?
    else {
        return Ok(ctx.redact.scrub(text));
    };
    let redactor = ctx
        .redact
        .union(&target_table)
        .map_err(|error| anyhow::anyhow!("history_search target redaction union: {error:#}"))?;
    Ok(redactor.scrub(text))
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

        let out = HistorySearchTool
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
        let out = HistorySearchTool
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
        let out = HistorySearchTool
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
    async fn target_session_redaction_covers_search_snippets_and_recall_content() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let secret = "target-session-history-secret";
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
                &json!({ "text": format!("stored {secret}") }),
            )
            .await
            .unwrap();
        let target_redaction = crate::redact::RedactionTable::empty()
            .with_forced_literal(secret.to_string(), "test".to_string())
            .unwrap();
        ctx.session
            .db
            .set_session_redaction_table_json(
                other.session_id,
                Some(target_redaction.to_persisted_json().unwrap()),
            )
            .await
            .unwrap();

        let found = HistorySearchTool
            .call(json!({ "query": secret }), &ctx)
            .await
            .unwrap();
        assert!(!found.content.contains(secret), "{}", found.content);

        let path = format!("cockpit://session/{}/transcript", other.short_id.unwrap());
        let read = crate::tools::recall::read(&json!({ "path": path.clone() }), &ctx)
            .await
            .unwrap();
        assert!(!read.content.contains(secret), "{}", read.content);
        let grep = crate::tools::recall::grep(
            &json!({ "path": path, "pattern": secret, "mode": "literal" }),
            &ctx,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(grep.content, "No matches.");
    }

    #[tokio::test]
    async fn history_search_lineage_includes_current_session_without_relaxing_past_scope() {
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

        let lineage = HistorySearchTool
            .call(
                json!({ "query": "moonstone", "scope": "lineage", "include_tool_events": false }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(lineage.content.contains("moonstone"), "{}", lineage.content);

        let cross_thread = HistorySearchTool
            .call(json!({ "query": "moonstone" }), &ctx)
            .await
            .unwrap();
        assert!(
            cross_thread.content.contains("No past sessions"),
            "{}",
            cross_thread.content
        );
    }

    #[tokio::test]
    async fn all_projects_scope_requires_two_directional_workspace_consent() {
        use crate::db::history_scope::WorkspaceHistoryScope;

        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let other = ctx
            .session
            .db
            .create_session("other-workspace", "/other", "Elsewhere")
            .await
            .unwrap();
        ctx.session
            .db
            .insert_session_event(
                other.session_id,
                SessionEventKind::UserMessage,
                None,
                None,
                &json!({ "text": "cross workspace lodestone" }),
            )
            .await
            .unwrap();

        let denied = HistorySearchTool
            .call(
                json!({ "query": "lodestone", "scope": "all-projects" }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(
            denied.content.contains("No past sessions"),
            "{}",
            denied.content
        );

        ctx.session
            .db
            .set_workspace_history_scope(
                &ctx.session.project_id,
                WorkspaceHistoryScope {
                    outbound: true,
                    inbound: false,
                },
            )
            .await
            .unwrap();
        ctx.session
            .db
            .set_workspace_history_scope(
                "other-workspace",
                WorkspaceHistoryScope {
                    outbound: false,
                    inbound: true,
                },
            )
            .await
            .unwrap();
        let permitted = HistorySearchTool
            .call(
                json!({ "query": "lodestone", "scope": "all-projects" }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(
            permitted.content.contains(&other.session_id.to_string()),
            "{}",
            permitted.content
        );

        let recalled = crate::tools::recall::read(
            &json!({
                "path": format!("cockpit://session/{}/transcript", other.session_id),
            }),
            &ctx,
        )
        .await
        .unwrap();
        assert!(
            recalled.content.contains("cross workspace lodestone"),
            "{}",
            recalled.content
        );
    }

    #[test]
    fn scope_rejects_retired_tool_shapes() {
        assert_eq!(
            HistorySearchScope::parse(&json!({ "scope": "past" })).unwrap(),
            HistorySearchScope::Past
        );
        assert_eq!(
            HistorySearchScope::parse(&json!({})).unwrap(),
            HistorySearchScope::Past
        );
        assert!(HistorySearchScope::parse(&json!({ "scope": "invalid" })).is_err());
    }

    #[test]
    fn parse_since_accepts_date_and_rfc3339() {
        assert!(parse_since("2024-01-01").is_ok());
        assert!(parse_since("2024-01-01T12:00:00Z").is_ok());
        assert!(parse_since("not-a-date").is_err());
    }
}
