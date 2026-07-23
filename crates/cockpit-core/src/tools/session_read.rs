//! `session_read` — read a past thread back, windowed and paginated.
//!
//! Resolves a `short_id` (or full UUID) to a thread and returns its
//! ordered user/assistant turns with light role labels. With a `query`
//! the window centers on matching messages plus a few surrounding turns;
//! without one it starts at the first message. Long threads paginate via
//! a `seq`-addressable `offset`, mirroring the `read` tool's truncation
//! marker (prompt `search-old-sessions.md`).
//!
//! Output is plain tool text and passes back through the redaction
//! chokepoint normally — no bypass.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

use crate::db::session_search::ThreadTurn;
use crate::engine::tool::{Tool, ToolCtx, ToolEffect, ToolOutput, invalid_input};

/// Turns per page. A thread rarely needs the whole transcript at once;
/// the agent pages with `offset` (a `seq`) to see more.
const PAGE_TURNS: usize = 30;
/// Turns of context kept on each side of a matched turn when windowing
/// around a `query`.
const CONTEXT_TURNS: usize = 3;

pub struct SessionReadTool;

#[async_trait]
impl Tool for SessionReadTool {
    fn name(&self) -> &str {
        "session_read"
    }

    fn description(&self) -> &str {
        "Read a past session's turns by short id; optional query windows around matches, paginated by seq"
    }

    fn effect(&self) -> ToolEffect {
        ToolEffect::ReadOnly
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Read the actual conversation turns of a PAST session by its short id (find the id \
             first with `session_search`). Use this to recover details from earlier work — what \
             was decided, what code was touched, why. Pass a `query` to center the result on the \
             turns about that topic instead of reading from the top, and `offset` to page through \
             a long session. This reads a different, finished conversation; it does not affect \
             the current one."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "short_id": { "type": "string", "description": "Session short id or full UUID" },
                "query":    { "type": "string", "description": "Topic to center the window on" },
                "offset":   { "type": "integer", "description": "First turn seq to read from" }
            },
            "required": ["short_id"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "short_id": { "type": "string", "description": "The short id (or full UUID) of the past session to read, as returned by `session_search`" },
                "query":    { "type": "string", "description": "Optional topic to center the returned window on; the read shows turns around the best match instead of starting at the top" },
                "offset":   { "type": "integer", "description": "Optional turn sequence number to start reading from, for paging through a long session" }
            },
            "required": ["short_id"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        ctx.session
            .db
            .fts5_available()
            .await
            .map_err(|e| invalid_input(format!("{e:#}")))?;

        let id_arg = args
            .get("short_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_input("`short_id` is required"))?;

        let session_id = resolve_session(ctx, id_arg).await?;

        let turns = ctx
            .session
            .db
            .thread_turns(session_id)
            .await
            .map_err(|e| anyhow::anyhow!("session_read: {e:#}"))?;
        if turns.is_empty() {
            return Ok(ToolOutput::text(format!(
                "Session `{id_arg}` has no user/assistant turns."
            )));
        }

        let query = args
            .get("query")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|q| !q.is_empty());
        let offset = args
            .get("offset")
            .and_then(Value::as_u64)
            .map(i64::try_from)
            .transpose()
            .map_err(|_| invalid_input("`offset` is too large"))?;

        // Pick the window start `seq`. An explicit `offset` always wins
        // (pagination). Otherwise a `query` centers on the first matching
        // turn (minus a little context); with neither we start at turn 1.
        let start_seq = if let Some(o) = offset {
            o
        } else if let Some(q) = query {
            match_window_start(ctx, session_id, q, &turns).await?
        } else {
            turns[0].seq
        };

        Ok(render_window(&turns, start_seq, id_arg))
    }
}

/// Resolve `id_arg` to a session id. Accepts a full UUID or a 6-char
/// short id. Short ids are unique only within a project, so we
/// disambiguate by the current `project_id` first; if that misses we
/// look globally and report an ambiguous match by id rather than
/// guessing. An archived thread is readable by explicit id (the
/// archive exclusion only applies to search).
async fn resolve_session(ctx: &ToolCtx, id_arg: &str) -> Result<Uuid> {
    if let Ok(uuid) = Uuid::parse_str(id_arg) {
        if ctx
            .session
            .db
            .get_session(uuid)
            .await
            .map_err(|e| anyhow::anyhow!("session_read: {e:#}"))?
            .is_some()
        {
            return Ok(uuid);
        }
        return Err(invalid_input(format!("no session with id `{id_arg}`")));
    }

    // Project-scoped first — short ids are unique per project.
    if let Some(row) = ctx
        .session
        .db
        .get_session_by_short_id(&ctx.session.project_id, id_arg)
        .await
        .map_err(|e| anyhow::anyhow!("session_read: {e:#}"))?
    {
        return Ok(row.session_id);
    }

    // Fall back to a global lookup so a thread from another repo is
    // still reachable; report ambiguity explicitly.
    let global = ctx
        .session
        .db
        .find_sessions_by_short_id_global(id_arg)
        .await
        .map_err(|e| anyhow::anyhow!("session_read: {e:#}"))?;
    match global.len() {
        0 => Err(invalid_input(format!(
            "no session with short id `{id_arg}`"
        ))),
        1 => Ok(global[0].session_id),
        n => Err(invalid_input(format!(
            "short id `{id_arg}` is ambiguous ({n} matches across projects); \
             pass the full session UUID instead"
        ))),
    }
}

/// Choose the window start `seq` for a `query`: the first turn (FTS5)
/// whose text matches, backed up by [`CONTEXT_TURNS`] turns of context.
/// No textual match → start from the first turn (so the read still
/// returns something useful rather than nothing).
async fn match_window_start(
    ctx: &ToolCtx,
    session_id: Uuid,
    query: &str,
    turns: &[ThreadTurn],
) -> Result<i64> {
    let seqs = ctx
        .session
        .db
        .thread_match_seqs(session_id, query)
        .await
        .map_err(|e| anyhow::anyhow!("session_read: {e:#}"))?;
    let Some(&first_match) = seqs.first() else {
        return Ok(turns[0].seq);
    };
    // Find the matched turn's index, back up CONTEXT_TURNS, return that
    // turn's seq as the window start.
    let idx = turns.iter().position(|t| t.seq == first_match).unwrap_or(0);
    let start_idx = idx.saturating_sub(CONTEXT_TURNS);
    Ok(turns[start_idx].seq)
}

/// Render up to [`PAGE_TURNS`] turns starting at the first turn with
/// `seq >= start_seq`. Appends a `read`-style truncation marker (keyed
/// to the next turn's `seq`) when more turns remain.
fn render_window(turns: &[ThreadTurn], start_seq: i64, id_arg: &str) -> ToolOutput {
    let start_idx = turns
        .iter()
        .position(|t| t.seq >= start_seq)
        .unwrap_or(turns.len());
    let page = &turns[start_idx..turns.len().min(start_idx + PAGE_TURNS)];

    let mut out = format!("Session `{id_arg}` ({} turns):\n", turns.len());
    if start_idx > 0 {
        out.push_str(&format!(
            "... [{} earlier turns; read with offset {} to see from the start]\n",
            start_idx, turns[0].seq
        ));
    }
    for turn in page {
        let label = if turn.role == "assistant" {
            "Assistant"
        } else {
            "User"
        };
        out.push_str(&format!("[{}] {label}: {}\n", turn.seq, turn.text.trim()));
    }

    let next_idx = start_idx + page.len();
    if next_idx < turns.len() {
        let next_seq = turns[next_idx].seq;
        out.push_str(&format!(
            "... [truncated, ask session_read with offset {next_seq} to see more]\n"
        ));
        return ToolOutput::truncated_text(out);
    }
    ToolOutput::text(out)
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]

    use super::*;
    use crate::db::session_log::SessionEventKind;
    use crate::tools::common::test_ctx;
    use serde_json::json;

    /// Seed a sibling session with `n` turns; return its (short_id, uuid).
    async fn seed_thread(ctx: &ToolCtx, texts: &[(&str, bool)]) -> (String, Uuid) {
        let s = ctx
            .session
            .db
            .write({
                let project_id = ctx.session.project_id.clone();
                move |conn| {
                    crate::db::Db::insert_session_row_conn(
                        conn,
                        &crate::db::Db::build_new_session_row_conn(
                            conn,
                            &project_id,
                            "/x",
                            "Build",
                        )?,
                    )
                }
            })
            .await
            .unwrap();
        for (text, is_assistant) in texts {
            let kind = if *is_assistant {
                SessionEventKind::AssistantMessage
            } else {
                SessionEventKind::UserMessage
            };
            ctx.session
                .db
                .insert_session_event(s.session_id, kind, None, None, &json!({ "text": text }))
                .await
                .unwrap();
        }
        (s.short_id.unwrap(), s.session_id)
    }

    #[tokio::test]
    async fn read_without_query_starts_from_first_turn() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let (short, _) = seed_thread(
            &ctx,
            &[
                ("first message", false),
                ("a reply", true),
                ("third", false),
            ],
        )
        .await;
        let out = SessionReadTool
            .call(json!({ "short_id": short }), &ctx)
            .await
            .unwrap();
        assert!(out.content.contains("first message"));
        assert!(out.content.contains("User:"));
        assert!(out.content.contains("Assistant:"));
        assert!(!out.content.contains("earlier turns"));
    }

    #[tokio::test]
    async fn read_with_query_windows_around_match() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        // 10 filler turns, then the match, then more filler — the window
        // should skip the early filler and note elided earlier turns.
        let mut texts: Vec<(String, bool)> = Vec::new();
        for i in 0..10 {
            texts.push((format!("filler turn {i}"), i % 2 == 1));
        }
        texts.push(("here we talk about the elusive narwhal".to_string(), false));
        texts.push(("narwhal facts follow".to_string(), true));
        let refs: Vec<(&str, bool)> = texts.iter().map(|(t, a)| (t.as_str(), *a)).collect();
        let (short, _) = seed_thread(&ctx, &refs).await;

        let out = SessionReadTool
            .call(json!({ "short_id": short, "query": "narwhal" }), &ctx)
            .await
            .unwrap();
        assert!(out.content.contains("narwhal"));
        assert!(
            out.content.contains("earlier turns"),
            "windowing should elide early turns: {}",
            out.content
        );
        // The very first filler turn is before the window → not shown.
        assert!(!out.content.contains("filler turn 0"));
    }

    #[tokio::test]
    async fn read_paginates_long_threads() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let texts: Vec<(String, bool)> = (0..(PAGE_TURNS + 5))
            .map(|i| (format!("turn body {i}"), i % 2 == 1))
            .collect();
        let refs: Vec<(&str, bool)> = texts.iter().map(|(t, a)| (t.as_str(), *a)).collect();
        let (short, _) = seed_thread(&ctx, &refs).await;

        let out = SessionReadTool
            .call(json!({ "short_id": short }), &ctx)
            .await
            .unwrap();
        assert!(out.truncated, "a long thread must paginate");
        assert!(out.content.contains("ask session_read with offset"));
    }

    #[tokio::test]
    async fn unknown_short_id_errors_with_the_id() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let err = SessionReadTool
            .call(json!({ "short_id": "zzzzzz" }), &ctx)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("zzzzzz"),
            "error names the id: {err}"
        );
    }

    #[tokio::test]
    async fn accepts_full_uuid() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let (_, uuid) = seed_thread(&ctx, &[("hello via uuid", false)]).await;
        let out = SessionReadTool
            .call(json!({ "short_id": uuid.to_string() }), &ctx)
            .await
            .unwrap();
        assert!(out.content.contains("hello via uuid"));
    }

    #[tokio::test]
    async fn offset_above_i64_max_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = test_ctx(tmp.path());
        let (short, _) = seed_thread(&ctx, &[("hello", false)]).await;

        let err = SessionReadTool
            .call(json!({ "short_id": short, "offset": u64::MAX }), &ctx)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("offset"), "{err}");
        assert!(err.to_string().contains("too large"), "{err}");
    }
}
