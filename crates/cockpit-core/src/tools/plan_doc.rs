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
        "Read the current virtual plan document before `plan_edit`/`plan_write`; use `todo` for task tracking and `goal` for session objective"
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
        "Create/replace full plan; expected_revision required whenever plan document exists; use `plan_edit` for revisions, `todo` for tasks, `goal` for status"
    }

    fn defensive_description(&self) -> Option<String> {
        Some("Replace the entire session-scoped virtual plan document with complete standalone content. expected_revision is required whenever a plan document already exists: call plan_read first and pass the revision it reports. Use this for the first draft or full rewrites; for small revisions prefer `plan_edit`.".to_string())
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "content": { "type": "string", "description": "Complete plan document" },
                "expected_revision": { "type": "integer", "description": "Revision value last returned by plan_read, or 0 when no document exists yet. Required whenever a plan document already exists." }
            },
            "required": ["content"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "content": { "type": "string", "description": "The complete standalone plan document. This replaces the previous plan; include every section that should remain." },
                "expected_revision": { "type": "integer", "description": "Revision value last returned by plan_read, or 0 when no document exists yet. Required whenever a plan document already exists." }
            },
            "required": ["content"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let content = args
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_input("`content` is required"))?;
        let old = ctx.session.db.get_session_plan_doc(ctx.session.id)?;
        validate_plan_write_revision(&args, old.as_ref())?;
        enforce_size(content)?;
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
        "Replace one exact string in the virtual plan document after `plan_read`; use `plan_write` for full rewrites"
    }

    fn defensive_description(&self) -> Option<String> {
        Some("Make a targeted edit to the virtual plan document after reading it with `plan_read`. `old_string` must appear exactly once; include enough surrounding context to make it unique. Use `plan_write` instead for full rewrites, and do not use plan tools as a todo list or goal-status store.".to_string())
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
        "After user agrees with the plan, create a Build session from it"
    }

    fn defensive_description(&self) -> Option<String> {
        Some("Use `start_build` only after the user agrees with the plan: it creates a fresh Build session whose first user message is the virtual plan document. Do not call it for drafting, editing, or todo tracking; keep using `plan_read`/`plan_write`/`plan_edit` until the plan is accepted.".to_string())
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "force": {
                    "type": "boolean",
                    "description": "Create a new Build session even if this plan already started one"
                }
            },
            "additionalProperties": false
        })
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let force = parse_start_build_force(&args)?;
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

        if !force
            && let Some(existing) = find_existing_build_handoff(&ctx.session.db, ctx.session.id)?
        {
            let build_ref = existing.short_id.as_deref().unwrap_or("unknown");
            return Ok(ToolOutput::text(format!(
                "Build session `{build_ref}` was already started from this plan; no new session was created"
            )));
        }

        let row = ctx
            .session
            .db
            .create_session(
                &ctx.session.project_id,
                &ctx.session.project_root.to_string_lossy(),
                "Build",
            )
            .await?;
        insert_user_message(&ctx.session.db, row.session_id, &doc.content)
            .context("recording Build kickoff message")?;
        let build_ref = row.short_id.as_deref().unwrap_or("unknown");
        let plan_ref = ctx.session.short_id.clone();
        insert_note(
            &ctx.session.db,
            ctx.session.id,
            "Plan",
            &format!("Handed off to `Build` in session `{build_ref}`."),
            Some(serde_json::json!({ "build_session_id": row.session_id })),
        )?;
        insert_note(
            &ctx.session.db,
            row.session_id,
            "Build",
            &format!("Created from plan session `{plan_ref}`."),
            None,
        )?;

        let action = if force {
            "created new Build session"
        } else {
            "created Build session"
        };
        let suffix = if force { " (forced fork)" } else { "" };
        Ok(ToolOutput::text(format!(
            "{action} `{build_ref}` with the plan document as its first user message{suffix}"
        )))
    }
}

fn validate_plan_write_revision(args: &Value, old: Option<&SessionPlanDoc>) -> Result<()> {
    let expected = match args.get("expected_revision") {
        Some(value) => Some(
            value
                .as_i64()
                .ok_or_else(|| invalid_input("`expected_revision` must be an integer"))?,
        ),
        None => None,
    };
    let current = old.map(|doc| doc.revision).unwrap_or(0);
    if current > 0 && expected.is_none() {
        return Err(invalid_input(
            "`expected_revision` is required because a plan document already exists; call `plan_read` first and retry with the revision it reports",
        ));
    }
    if let Some(expected) = expected
        && expected != current
    {
        return Err(invalid_input(format!(
            "stale `expected_revision`: expected {expected}, but the current revision is {current}; call `plan_read` and retry with the revision it reports"
        )));
    }
    // This is a model-attention guard, not a distributed CAS: one session has
    // one driver, so the read-then-write window is intentional here.
    Ok(())
}

fn parse_start_build_force(args: &Value) -> Result<bool> {
    match args {
        Value::Null => Ok(false),
        Value::Object(map) => {
            for key in map.keys() {
                if key != "force" {
                    return Err(invalid_input(format!(
                        "unknown start_build argument `{key}`"
                    )));
                }
            }
            match map.get("force") {
                Some(value) => value
                    .as_bool()
                    .ok_or_else(|| invalid_input("`force` must be a boolean")),
                None => Ok(false),
            }
        }
        _ => Err(invalid_input("start_build arguments must be an object")),
    }
}

#[expect(
    deprecated,
    reason = "db-async-foundation bridge; plan-doc tool remains sync until db-async-session-log"
)]
fn find_existing_build_handoff(
    db: &crate::db::Db,
    plan_session_id: Uuid,
) -> Result<Option<crate::db::sessions::SessionRow>> {
    let events = db.list_session_events(plan_session_id)?;
    for event in events.iter().rev() {
        if event.kind != "user_note" {
            continue;
        }
        let Some(raw_id) = event.data.get("build_session_id").and_then(Value::as_str) else {
            continue;
        };
        let Ok(build_session_id) = Uuid::parse_str(raw_id) else {
            return Ok(None);
        };
        if let Some(row) =
            db.write_blocking(move |conn| crate::db::Db::get_session_conn(conn, build_session_id))?
            && row.active_agent == "Build"
        {
            return Ok(Some(row));
        }
        return Ok(None);
    }
    Ok(None)
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

fn insert_note(
    db: &crate::db::Db,
    session_id: Uuid,
    agent: &str,
    text: &str,
    extra: Option<Value>,
) -> Result<()> {
    let mut data = serde_json::json!({ "text": text });
    if let (Some(extra), Some(data_obj)) = (extra, data.as_object_mut())
        && let Some(extra_obj) = extra.as_object()
    {
        for (key, value) in extra_obj {
            data_obj.insert(key.clone(), value.clone());
        }
    }
    db.insert_session_event(
        session_id,
        crate::db::session_log::SessionEventKind::UserNote,
        Some(agent),
        None,
        &data,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tool::{Tool, ToolFailKind, classify_failure};
    use serde_json::json;
    use tempfile::TempDir;

    fn revision_from_read_output(output: &str) -> i64 {
        output
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("revision: "))
            .unwrap()
            .parse()
            .unwrap()
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db-async-locks-and-plan-docs"
    )]
    fn other_sessions(db: &crate::db::Db, plan_session_id: Uuid) -> Vec<(Uuid, String, String)> {
        db.read_blocking(|conn| {
            let mut stmt = conn.prepare(
                "SELECT session_id, active_agent, COALESCE(short_id, 'unknown')
                  FROM sessions
                  WHERE session_id != ?1
                  ORDER BY session_id",
            )?;
            let rows = stmt
                .query_map([plan_session_id.to_string()], |row| {
                    let id: String = row.get(0)?;
                    Ok((
                        Uuid::parse_str(&id).unwrap(),
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .unwrap()
    }

    fn events_of_kind(db: &crate::db::Db, session_id: Uuid, kind: &str) -> Vec<serde_json::Value> {
        db.list_session_events(session_id)
            .unwrap()
            .into_iter()
            .filter(|event| event.kind == kind)
            .map(|event| event.data)
            .collect()
    }

    fn plan_handoff_notes(db: &crate::db::Db, plan_session_id: Uuid) -> Vec<serde_json::Value> {
        events_of_kind(db, plan_session_id, "user_note")
            .into_iter()
            .filter(|data| {
                data.get("build_session_id").is_some()
                    || data
                        .get("text")
                        .and_then(Value::as_str)
                        .is_some_and(|text| text.contains("Handed off to `Build`"))
            })
            .collect()
    }

    fn backtick_ref(output: &str) -> &str {
        let start = output.find('`').unwrap() + 1;
        let end = output[start..].find('`').unwrap() + start;
        &output[start..end]
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db-async-locks-and-plan-docs"
    )]
    fn rewrite_handoff_note_text(db: &crate::db::Db, plan_session_id: Uuid, arbitrary: &str) {
        let arbitrary = arbitrary.to_string();
        let event = db
            .list_session_events(plan_session_id)
            .unwrap()
            .into_iter()
            .find(|event| event.data.get("build_session_id").is_some())
            .unwrap();
        let build_session_id = event.data["build_session_id"].clone();
        db.write_blocking(move |conn| {
            conn.execute(
                "UPDATE session_events SET data_json = ?1 WHERE seq = ?2",
                rusqlite::params![
                    serde_json::json!({
                        "text": arbitrary,
                        "build_session_id": build_session_id,
                    })
                    .to_string(),
                    event.seq
                ],
            )?;
            Ok(())
        })
        .unwrap();
    }

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
    async fn first_plan_write_needs_no_expected_revision() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());

        let wrote = PlanWriteTool
            .call(json!({ "content": "# First plan" }), &ctx)
            .await
            .unwrap();

        assert!(wrote.content.contains("revision 1"));
        let doc = db.get_session_plan_doc(ctx.session.id).unwrap().unwrap();
        assert_eq!(doc.revision, 1);
        assert_eq!(doc.content, "# First plan");
    }

    #[tokio::test]
    async fn overwriting_requires_expected_revision() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        PlanWriteTool
            .call(json!({ "content": "original" }), &ctx)
            .await
            .unwrap();

        let err = PlanWriteTool
            .call(json!({ "content": "overwrite" }), &ctx)
            .await
            .unwrap_err();

        assert_eq!(classify_failure(&err), ToolFailKind::Invocation);
        let text = format!("{err:#}");
        assert!(text.contains("plan_read"), "{text}");
        let doc = db.get_session_plan_doc(ctx.session.id).unwrap().unwrap();
        assert_eq!(doc.revision, 1);
        assert_eq!(doc.content, "original");
    }

    #[tokio::test]
    async fn stale_expected_revision_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        PlanWriteTool
            .call(json!({ "content": "v1" }), &ctx)
            .await
            .unwrap();
        PlanWriteTool
            .call(json!({ "content": "v2", "expected_revision": 1 }), &ctx)
            .await
            .unwrap();

        let err = PlanWriteTool
            .call(json!({ "content": "stale", "expected_revision": 1 }), &ctx)
            .await
            .unwrap_err();

        assert_eq!(classify_failure(&err), ToolFailKind::Invocation);
        let text = format!("{err:#}");
        assert!(text.contains("expected 1"), "{text}");
        assert!(text.contains("current revision is 2"), "{text}");
        let doc = db.get_session_plan_doc(ctx.session.id).unwrap().unwrap();
        assert_eq!(doc.revision, 2);
        assert_eq!(doc.content, "v2");
    }

    #[tokio::test]
    async fn matching_expected_revision_writes() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        PlanWriteTool
            .call(json!({ "content": "v1" }), &ctx)
            .await
            .unwrap();
        let read = PlanReadTool.call(Value::Null, &ctx).await.unwrap().content;
        let revision = revision_from_read_output(&read);

        let wrote = PlanWriteTool
            .call(
                json!({ "content": "v2", "expected_revision": revision }),
                &ctx,
            )
            .await
            .unwrap();

        assert!(wrote.content.contains("revision 2"));
        let doc = db.get_session_plan_doc(ctx.session.id).unwrap().unwrap();
        assert_eq!(doc.revision, revision + 1);
        assert_eq!(doc.content, "v2");
    }

    #[tokio::test]
    async fn non_integer_expected_revision_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        PlanWriteTool
            .call(json!({ "content": "v1" }), &ctx)
            .await
            .unwrap();

        let err = PlanWriteTool
            .call(json!({ "content": "v2", "expected_revision": "1" }), &ctx)
            .await
            .unwrap_err();

        assert_eq!(classify_failure(&err), ToolFailKind::Invocation);
        assert!(format!("{err:#}").contains("must be an integer"));
        let doc = db.get_session_plan_doc(ctx.session.id).unwrap().unwrap();
        assert_eq!(doc.revision, 1);
        assert_eq!(doc.content, "v1");
    }

    #[test]
    fn plan_write_schema_declares_expected_revision() {
        let tool = PlanWriteTool;
        for params in [tool.parameters(), tool.defensive_parameters().unwrap()] {
            assert_eq!(params["properties"]["expected_revision"]["type"], "integer");
            assert_eq!(params["required"], json!(["content"]));
        }
        assert!(
            tool.description()
                .contains("expected_revision required whenever plan document exists")
        );
        assert!(
            tool.defensive_description()
                .unwrap()
                .contains("expected_revision is required whenever a plan document already exists")
        );
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

    #[test]
    fn plan_edit_is_unchanged() {
        let params = PlanEditTool.parameters();
        assert!(params["properties"].get("expected_revision").is_none());
        assert!(
            PlanEditTool.defensive_parameters().unwrap()["properties"]
                .get("expected_revision")
                .is_none()
        );
    }

    #[tokio::test]
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db-async-locks-and-plan-docs"
    )]
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

    #[tokio::test]
    async fn start_build_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        PlanWriteTool
            .call(json!({ "content": "Accepted plan" }), &ctx)
            .await
            .unwrap();

        let first = StartBuildTool
            .call(Value::Null, &ctx)
            .await
            .unwrap()
            .content;
        let first_ref = backtick_ref(&first).to_string();
        let second = StartBuildTool
            .call(Value::Null, &ctx)
            .await
            .unwrap()
            .content;

        assert!(second.contains(&first_ref));
        assert!(second.contains("no new session was created"));
        let sessions = other_sessions(&db, ctx.session.id);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].1, "Build");
        assert_eq!(events_of_kind(&db, sessions[0].0, "user_message").len(), 1);
        assert_eq!(plan_handoff_notes(&db, ctx.session.id).len(), 1);
    }

    #[tokio::test]
    async fn start_build_force_forks() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        PlanWriteTool
            .call(json!({ "content": "Accepted plan" }), &ctx)
            .await
            .unwrap();
        let first = StartBuildTool
            .call(Value::Null, &ctx)
            .await
            .unwrap()
            .content;
        let first_ref = backtick_ref(&first).to_string();

        let forced = StartBuildTool
            .call(json!({ "force": true }), &ctx)
            .await
            .unwrap()
            .content;
        let forced_ref = backtick_ref(&forced).to_string();

        assert!(forced.contains("created new Build session"));
        assert!(forced.contains("forced fork"));
        assert_ne!(forced_ref, first_ref);
        assert_eq!(other_sessions(&db, ctx.session.id).len(), 2);
        assert_eq!(plan_handoff_notes(&db, ctx.session.id).len(), 2);
    }

    #[tokio::test]
    async fn start_build_handoff_note_carries_build_session_id() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        PlanWriteTool
            .call(json!({ "content": "Accepted plan" }), &ctx)
            .await
            .unwrap();

        let first = StartBuildTool
            .call(Value::Null, &ctx)
            .await
            .unwrap()
            .content;
        let build_ref = backtick_ref(&first).to_string();
        let notes = plan_handoff_notes(&db, ctx.session.id);
        assert_eq!(notes.len(), 1);
        let build_session_id = Uuid::parse_str(notes[0]["build_session_id"].as_str().unwrap())
            .expect("build_session_id uuid");
        assert_eq!(
            db.get_session(build_session_id)
                .await
                .unwrap()
                .unwrap()
                .short_id
                .as_deref(),
            Some(build_ref.as_str())
        );

        rewrite_handoff_note_text(&db, ctx.session.id, "arbitrary prose");
        let second = StartBuildTool
            .call(Value::Null, &ctx)
            .await
            .unwrap()
            .content;
        assert!(second.contains(&build_ref));
        assert!(second.contains("no new session was created"));
        assert_eq!(other_sessions(&db, ctx.session.id).len(), 1);
    }

    #[tokio::test]
    async fn start_build_deleted_latest_handoff_creates_fresh_build() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        PlanWriteTool
            .call(json!({ "content": "Accepted plan" }), &ctx)
            .await
            .unwrap();
        let first = StartBuildTool
            .call(Value::Null, &ctx)
            .await
            .unwrap()
            .content;
        let first_ref = backtick_ref(&first).to_string();
        StartBuildTool
            .call(json!({ "force": true }), &ctx)
            .await
            .unwrap();
        let latest_notes = plan_handoff_notes(&db, ctx.session.id);
        let deleted_build_session_id = Uuid::parse_str(
            latest_notes
                .last()
                .unwrap()
                .get("build_session_id")
                .and_then(Value::as_str)
                .unwrap(),
        )
        .unwrap();
        db.delete_session(deleted_build_session_id, true)
            .await
            .unwrap();

        let fresh = StartBuildTool
            .call(Value::Null, &ctx)
            .await
            .unwrap()
            .content;
        let fresh_ref = backtick_ref(&fresh).to_string();

        assert!(fresh.contains("created Build session"));
        assert_ne!(fresh_ref, first_ref);
        assert_eq!(other_sessions(&db, ctx.session.id).len(), 2);

        let idempotent = StartBuildTool
            .call(Value::Null, &ctx)
            .await
            .unwrap()
            .content;
        assert!(idempotent.contains(&fresh_ref));
        assert!(idempotent.contains("no new session was created"));
        assert_eq!(other_sessions(&db, ctx.session.id).len(), 2);
    }

    #[test]
    fn start_build_schema_and_normal_description() {
        let params = StartBuildTool.parameters();
        assert_eq!(params["type"], "object");
        assert_eq!(params["additionalProperties"], false);
        assert_eq!(params["properties"]["force"]["type"], "boolean");
        assert!(params.get("required").is_none());
        assert!(
            StartBuildTool
                .description()
                .contains("After user agrees with the plan")
        );
    }
}
