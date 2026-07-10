//! Virtual plan document tools for the `Plan` agent.

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

use crate::db::session_plan_docs::SessionPlanDoc;
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};

const MAX_PLAN_DOC_BYTES: usize = 256 * 1024;

pub struct PlanReadTool;
pub struct PlanWriteTool;
pub struct PlanEditTool;
pub struct StartBuildTool;

#[async_trait]
impl Tool for PlanReadTool {
    fn name(&self) -> &str {
        "plan_read"
    }

    fn description(&self) -> &str {
        "Read the current virtual plan document"
    }

    fn defensive_description(&self) -> Option<String> {
        Some("Read the current session-scoped virtual plan document and its revision without changing it; use the returned content as the source of truth before editing.".to_string())
    }

    fn parameters(&self) -> Value {
        Value::Null
    }

    async fn call(&self, _args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let doc = ctx.session.db.get_session_plan_doc(ctx.session.id)?;
        Ok(ToolOutput::text(render_doc(doc)))
    }
}

#[async_trait]
impl Tool for PlanWriteTool {
    fn name(&self) -> &str {
        "plan_write"
    }

    fn description(&self) -> &str {
        "Create or replace the virtual plan document"
    }

    fn defensive_description(&self) -> Option<String> {
        Some("Replace the entire session-scoped virtual plan document. Use this for the first draft or full rewrites; for small revisions prefer plan_edit.".to_string())
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "content": { "type": "string", "description": "Complete plan document" }
            },
            "required": ["content"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "content": { "type": "string", "description": "The complete standalone plan document. This replaces the previous plan; include every section that should remain." }
            },
            "required": ["content"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let content = args
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`content` is required"))?;
        enforce_size(content)?;
        let old = ctx.session.db.get_session_plan_doc(ctx.session.id)?;
        let doc = ctx
            .session
            .db
            .write_session_plan_doc(ctx.session.id, content)?;
        Ok(ToolOutput::text(render_update(
            "wrote",
            old.as_ref().map(|d| d.content.as_str()).unwrap_or(""),
            &doc,
        )))
    }
}

#[async_trait]
impl Tool for PlanEditTool {
    fn name(&self) -> &str {
        "plan_edit"
    }

    fn description(&self) -> &str {
        "Replace one exact string in the virtual plan document"
    }

    fn defensive_description(&self) -> Option<String> {
        Some("Make a targeted edit to the virtual plan document. `old_string` must appear exactly once; include enough surrounding context to make it unique.".to_string())
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "old_string": { "type": "string", "description": "Text to find" },
                "new_string": { "type": "string", "description": "Replacement text" }
            },
            "required": ["old_string", "new_string"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "old_string": { "type": "string", "description": "Exact text currently in the plan document. It must occur exactly once; copy enough context from plan_read to make it unique." },
                "new_string": { "type": "string", "description": "Replacement text. Use an empty string to delete the matched text." }
            },
            "required": ["old_string", "new_string"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let old_string = args
            .get("old_string")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`old_string` is required"))?;
        if old_string.is_empty() {
            return Err(invalid_input("`old_string` must not be empty"));
        }
        let new_string = args
            .get("new_string")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`new_string` is required"))?;
        let Some(old_doc) = ctx.session.db.get_session_plan_doc(ctx.session.id)? else {
            return Err(invalid_input(
                "no plan document exists; call plan_write first",
            ));
        };
        let matches: Vec<_> = old_doc.content.match_indices(old_string).collect();
        match matches.len() {
            0 => {
                let near = nearest_miss(&old_doc.content, old_string);
                Err(invalid_input(format!(
                    "no match for `old_string` in the plan document. Closest near-miss:\n```\n{near}\n```"
                )))
            }
            1 => {
                let updated = old_doc.content.replacen(old_string, new_string, 1);
                enforce_size(&updated)?;
                let doc = ctx
                    .session
                    .db
                    .write_session_plan_doc(ctx.session.id, &updated)?;
                Ok(ToolOutput::text(render_update(
                    "edited",
                    &old_doc.content,
                    &doc,
                )))
            }
            n => Err(invalid_input(format!(
                "found {n} matches for `old_string`; include more surrounding context so it is unique"
            ))),
        }
    }
}

#[async_trait]
impl Tool for StartBuildTool {
    fn name(&self) -> &str {
        "start_build"
    }

    fn description(&self) -> &str {
        "Create a fresh Build session from the plan document"
    }

    fn defensive_description(&self) -> Option<String> {
        Some("After the user agrees with the plan, create a fresh Build session whose first user message is the virtual plan document.".to_string())
    }

    fn parameters(&self) -> Value {
        Value::Null
    }

    async fn call(&self, _args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let Some(doc) = ctx.session.db.get_session_plan_doc(ctx.session.id)? else {
            return Err(invalid_input(
                "write a non-empty plan document before calling start_build",
            ));
        };
        if doc.content.trim().is_empty() {
            return Err(invalid_input(
                "write a non-empty plan document before calling start_build",
            ));
        }
        enforce_size(&doc.content)?;

        let row = ctx.session.db.create_session(
            &ctx.session.project_id,
            &ctx.session.project_root.to_string_lossy(),
            "Build",
        )?;
        insert_user_message(&ctx.session.db, row.session_id, &doc.content)
            .context("recording Build kickoff message")?;
        let build_ref = row.short_id.as_deref().unwrap_or("unknown");
        let plan_ref = ctx.session.short_id.clone();
        insert_note(
            &ctx.session.db,
            ctx.session.id,
            "Plan",
            &format!("Handed off to `Build` in session `{build_ref}`."),
        )?;
        insert_note(
            &ctx.session.db,
            row.session_id,
            "Build",
            &format!("Created from plan session `{plan_ref}`."),
        )?;

        Ok(ToolOutput::text(format!(
            "created Build session `{build_ref}` with the plan document as its first user message"
        )))
    }
}

fn enforce_size(content: &str) -> Result<()> {
    let len = content.len();
    if len > MAX_PLAN_DOC_BYTES {
        return Err(invalid_input(format!(
            "plan document is {len} bytes; maximum is {MAX_PLAN_DOC_BYTES} bytes"
        )));
    }
    Ok(())
}

fn render_doc(doc: Option<SessionPlanDoc>) -> String {
    match doc {
        Some(doc) => format!("revision: {}\n\n{}", doc.revision, doc.content),
        None => "revision: 0\n\n(plan document is empty)".to_string(),
    }
}

fn render_update(action: &str, old: &str, doc: &SessionPlanDoc) -> String {
    format!(
        "{action} plan document (revision {}, {} bytes)\n\n```diff\n{}\n```",
        doc.revision,
        doc.content.len(),
        simple_diff(old, &doc.content)
    )
}

fn simple_diff(old: &str, new: &str) -> String {
    if old == new {
        return " unchanged".to_string();
    }
    let mut out = String::new();
    for line in old.lines() {
        out.push('-');
        out.push_str(line);
        out.push('\n');
    }
    for line in new.lines() {
        out.push('+');
        out.push_str(line);
        out.push('\n');
    }
    if out.is_empty() {
        out.push_str("+\n");
    }
    out.trim_end().to_string()
}

fn nearest_miss(content: &str, target: &str) -> String {
    let needle = target.lines().next().unwrap_or(target).trim();
    if needle.is_empty() {
        return content.lines().take(8).collect::<Vec<_>>().join("\n");
    }
    content
        .lines()
        .find(|line| line.contains(needle) || needle.contains(line.trim()))
        .or_else(|| content.lines().find(|line| !line.trim().is_empty()))
        .unwrap_or("")
        .to_string()
}

fn insert_user_message(db: &crate::db::Db, session_id: Uuid, text: &str) -> Result<()> {
    db.insert_session_event(
        session_id,
        crate::db::session_log::SessionEventKind::UserMessage,
        None,
        None,
        &serde_json::json!({
            "text": text,
            "display_text": text,
            "image_refs": [],
        }),
    )?;
    Ok(())
}

fn insert_note(db: &crate::db::Db, session_id: Uuid, agent: &str, text: &str) -> Result<()> {
    db.insert_session_event(
        session_id,
        crate::db::session_log::SessionEventKind::UserNote,
        Some(agent),
        None,
        &serde_json::json!({ "text": text }),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tool::Tool;
    use serde_json::json;
    use tempfile::TempDir;

    #[tokio::test]
    async fn plan_document_tools_round_trip_and_persist() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());

        let read = PlanReadTool;
        assert!(
            read.call(Value::Null, &ctx)
                .await
                .unwrap()
                .content
                .contains("revision: 0")
        );

        let write = PlanWriteTool;
        let wrote = write
            .call(json!({ "content": "# Plan\n\n- build the thing" }), &ctx)
            .await
            .unwrap();
        assert!(wrote.content.contains("revision 1"));

        let edit = PlanEditTool;
        let edited = edit
            .call(
                json!({
                    "old_string": "- build the thing",
                    "new_string": "- build the better thing"
                }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(edited.content.contains("revision 2"));
        assert!(edited.content.contains("+"));

        let doc = db.get_session_plan_doc(ctx.session.id).unwrap().unwrap();
        assert_eq!(doc.revision, 2);
        assert_eq!(doc.content, "# Plan\n\n- build the better thing");

        let resumed = crate::session::Session::resume(db.clone(), ctx.session.id)
            .unwrap()
            .unwrap();
        let persisted = db.get_session_plan_doc(resumed.id).unwrap().unwrap();
        assert_eq!(persisted.content, doc.content);
    }

    #[tokio::test]
    async fn plan_edit_requires_one_exact_match() {
        let tmp = TempDir::new().unwrap();
        let (ctx, _db) = crate::tools::common::test_ctx_with_db(tmp.path());
        PlanWriteTool
            .call(json!({ "content": "same\nsame\nother" }), &ctx)
            .await
            .unwrap();

        let err = PlanEditTool
            .call(json!({ "old_string": "same", "new_string": "new" }), &ctx)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("found 2 matches"));

        let err = PlanEditTool
            .call(
                json!({ "old_string": "missing", "new_string": "new" }),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("no match"));
    }

    #[tokio::test]
    async fn start_build_creates_fresh_build_session_with_only_plan_message() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        db.insert_session_event(
            ctx.session.id,
            crate::db::session_log::SessionEventKind::UserMessage,
            None,
            None,
            &json!({ "text": "planning conversation", "display_text": "planning conversation" }),
        )
        .unwrap();
        PlanWriteTool
            .call(json!({ "content": "Standalone implementation plan" }), &ctx)
            .await
            .unwrap();

        let output = StartBuildTool
            .call(Value::Null, &ctx)
            .await
            .unwrap()
            .content;
        assert!(output.contains("created Build session"));

        let rows: Vec<(String, String)> = db
            .read_blocking(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT session_id, active_agent FROM sessions WHERE session_id != ?1",
                )?;
                let rows = stmt
                    .query_map([ctx.session.id.to_string()], |row| {
                        Ok((row.get(0)?, row.get(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, "Build");

        let events: Vec<(String, serde_json::Value)> = db
            .read_blocking(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT type, data_json FROM session_events WHERE session_id = ?1 ORDER BY seq",
                )?;
                let rows = stmt
                    .query_map([rows[0].0.as_str()], |row| {
                        let kind: String = row.get(0)?;
                        let data: String = row.get(1)?;
                        Ok((kind, serde_json::from_str(&data).unwrap()))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, "user_message");
        assert_eq!(events[0].1["text"], "Standalone implementation plan");
        assert_eq!(events[1].0, "user_note");
    }
}
