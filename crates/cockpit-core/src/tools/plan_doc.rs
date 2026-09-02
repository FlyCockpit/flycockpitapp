//! Plan-to-Build handoff tool.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};

const MAX_PLAN_DOC_BYTES: usize = 256 * 1024;
pub struct StartBuildTool;

#[async_trait]
impl Tool for StartBuildTool {
    fn name(&self) -> &str {
        "start_build"
    }

    fn description(&self) -> &str {
        "After user agrees with the plan, create a Build session from it"
    }

    fn verbose_description(&self) -> Option<String> {
        Some("Use `start_build` only after the user agrees with the plan: it creates a fresh Build session whose first user message is the virtual plan document. Do not call it for drafting, editing, or todo tracking; keep `cockpit://session/<short_id>/plan` current with `read` and `write` until the plan is accepted.".to_string())
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
        let Some(doc) = ctx
            .session
            .db
            .get_session_plan_doc_for_trust(
                ctx.session.id,
                crate::tools::session_search::caller_history_trust(ctx),
            )
            .await?
        else {
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
            && let Some(existing) =
                find_existing_build_handoff(&ctx.session.db, ctx.session.id).await?
        {
            let build_ref = existing.short_id.as_deref().unwrap_or("unknown");
            return Ok(ToolOutput::text(format!(
                "Build session `{build_ref}` was already started from this plan; no new session was created"
            )));
        }

        let row = crate::session::lifecycle::persist_session_with_redaction_custody(
            &ctx.session.db,
            Arc::clone(ctx.session.secret_vault()),
            &ctx.session.project_id,
            &ctx.session.project_root.to_string_lossy(),
            "Build",
        )
        .await?;
        insert_user_message(&ctx.session.db, row.session_id, &doc.content)
            .await
            .context("recording Build kickoff message")?;
        let build_ref = row.short_id.as_deref().unwrap_or("unknown");
        let plan_ref = ctx.session.short_id();
        insert_note(
            &ctx.session.db,
            ctx.session.id,
            "Plan",
            &format!("Handed off to `Build` in session `{build_ref}`."),
            Some(serde_json::json!({ "build_session_id": row.session_id })),
        )
        .await?;
        insert_note(
            &ctx.session.db,
            row.session_id,
            "Build",
            &format!("Created from plan session `{plan_ref}`."),
            None,
        )
        .await?;

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

async fn find_existing_build_handoff(
    db: &crate::db::Db,
    plan_session_id: Uuid,
) -> Result<Option<crate::db::sessions::SessionRow>> {
    let events = db.list_session_events(plan_session_id).await?;
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
        if let Some(row) = db.get_session(build_session_id).await?
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

async fn insert_user_message(db: &crate::db::Db, session_id: Uuid, text: &str) -> Result<()> {
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
    )
    .await?;
    Ok(())
}

async fn insert_note(
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
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tool::Tool;
    use serde_json::json;
    use tempfile::TempDir;

    async fn other_sessions(
        db: &crate::db::Db,
        plan_session_id: Uuid,
    ) -> Vec<(Uuid, String, String)> {
        db.read(move |conn| {
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
        .await
        .unwrap()
    }

    async fn write_plan(db: &crate::db::Db, session_id: Uuid, content: &str) {
        db.write_session_plan_doc_if_revision(
            session_id,
            0,
            content,
            crate::db::session_search::HistoryCallerTrust::Untrusted,
        )
        .await
        .unwrap()
        .unwrap();
    }

    async fn events_of_kind(
        db: &crate::db::Db,
        session_id: Uuid,
        kind: &str,
    ) -> Vec<serde_json::Value> {
        db.list_session_events(session_id)
            .await
            .unwrap()
            .into_iter()
            .filter(|event| event.kind == kind)
            .map(|event| event.data)
            .collect()
    }

    async fn plan_handoff_notes(
        db: &crate::db::Db,
        plan_session_id: Uuid,
    ) -> Vec<serde_json::Value> {
        events_of_kind(db, plan_session_id, "user_note")
            .await
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

    async fn rewrite_handoff_note_text(db: &crate::db::Db, plan_session_id: Uuid, arbitrary: &str) {
        let arbitrary = arbitrary.to_string();
        let event = db
            .list_session_events(plan_session_id)
            .await
            .unwrap()
            .into_iter()
            .find(|event| event.data.get("build_session_id").is_some())
            .unwrap();
        let build_session_id = event.data["build_session_id"].clone();
        db.write(move |conn| {
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
        .await
        .unwrap();
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
        .await
        .unwrap();
        write_plan(&db, ctx.session.id, "Standalone implementation plan").await;

        let output = StartBuildTool
            .call(Value::Null, &ctx)
            .await
            .unwrap()
            .content;
        assert!(output.contains("created Build session"));

        let rows: Vec<(String, String)> = db
            .read(move |conn| {
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
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, "Build");

        let build_id = Uuid::parse_str(&rows[0].0).unwrap();
        let events: Vec<(String, serde_json::Value)> = db
            .read(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT type, data_json FROM session_events WHERE session_id = ?1 ORDER BY seq",
                )?;
                let rows = stmt
                    .query_map([build_id.to_string()], |row| {
                        let kind: String = row.get(0)?;
                        let data: String = row.get(1)?;
                        Ok((kind, serde_json::from_str(&data).unwrap()))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await
            .unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].0, "user_message");
        assert_eq!(events[0].1["text"], "Standalone implementation plan");
        assert_eq!(events[1].0, "user_note");

        crate::session::Session::resume_for_test(
            db,
            build_id,
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap()
        .expect("start_build session must resume with redaction custody");
    }

    #[tokio::test]
    async fn start_build_does_not_handoff_a_plan_hidden_by_model_trust() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        db.write_session_plan_doc_if_revision(
            ctx.session.id,
            0,
            "Trusted-only plan",
            crate::db::session_search::HistoryCallerTrust::Trusted,
        )
        .await
        .unwrap()
        .unwrap();

        let error = StartBuildTool.call(Value::Null, &ctx).await.unwrap_err();
        assert!(format!("{error:#}").contains("write a non-empty plan document"));
        assert!(other_sessions(&db, ctx.session.id).await.is_empty());
    }

    #[tokio::test]
    async fn start_build_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        write_plan(&db, ctx.session.id, "Accepted plan").await;

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
        let sessions = other_sessions(&db, ctx.session.id).await;
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].1, "Build");
        assert_eq!(
            events_of_kind(&db, sessions[0].0, "user_message")
                .await
                .len(),
            1
        );
        assert_eq!(plan_handoff_notes(&db, ctx.session.id).await.len(), 1);
    }

    #[tokio::test]
    async fn start_build_force_forks() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        write_plan(&db, ctx.session.id, "Accepted plan").await;
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
        assert_eq!(other_sessions(&db, ctx.session.id).await.len(), 2);
        assert_eq!(plan_handoff_notes(&db, ctx.session.id).await.len(), 2);
    }

    #[tokio::test]
    async fn start_build_handoff_note_carries_build_session_id() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        write_plan(&db, ctx.session.id, "Accepted plan").await;

        let first = StartBuildTool
            .call(Value::Null, &ctx)
            .await
            .unwrap()
            .content;
        let build_ref = backtick_ref(&first).to_string();
        let notes = plan_handoff_notes(&db, ctx.session.id).await;
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

        rewrite_handoff_note_text(&db, ctx.session.id, "arbitrary prose").await;
        let second = StartBuildTool
            .call(Value::Null, &ctx)
            .await
            .unwrap()
            .content;
        assert!(second.contains(&build_ref));
        assert!(second.contains("no new session was created"));
        assert_eq!(other_sessions(&db, ctx.session.id).await.len(), 1);
    }

    #[tokio::test]
    async fn start_build_deleted_latest_handoff_creates_fresh_build() {
        let tmp = TempDir::new().unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(tmp.path());
        write_plan(&db, ctx.session.id, "Accepted plan").await;
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
        let latest_notes = plan_handoff_notes(&db, ctx.session.id).await;
        let deleted_build_session_id = Uuid::parse_str(
            latest_notes
                .last()
                .unwrap()
                .get("build_session_id")
                .and_then(Value::as_str)
                .unwrap(),
        )
        .unwrap();
        db.delete_session(deleted_build_session_id).await.unwrap();

        let fresh = StartBuildTool
            .call(Value::Null, &ctx)
            .await
            .unwrap()
            .content;
        let fresh_ref = backtick_ref(&fresh).to_string();

        assert!(fresh.contains("created Build session"));
        assert_ne!(fresh_ref, first_ref);
        assert_eq!(other_sessions(&db, ctx.session.id).await.len(), 2);

        let idempotent = StartBuildTool
            .call(Value::Null, &ctx)
            .await
            .unwrap()
            .content;
        assert!(idempotent.contains(&fresh_ref));
        assert!(idempotent.contains("no new session was created"));
        assert_eq!(other_sessions(&db, ctx.session.id).await.len(), 2);
    }

    #[tokio::test]
    async fn start_build_schema_and_normal_description() {
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
