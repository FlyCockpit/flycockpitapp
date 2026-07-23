//! `todo` — create, read, and maintain durable session todos.

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::db::task_todos::{TaskTodoDetail, TodoNoteKind, TodoStatus};
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input, typed_args};

pub struct TodoTool;

#[derive(Debug, Deserialize)]
struct TodoArgs {
    action: String,
    content: Option<String>,
    id_or_name: Option<String>,
    todo_id: Option<String>,
    status: Option<String>,
    priority: Option<i64>,
    outcome_summary: Option<String>,
    note_kind: Option<String>,
    note: Option<String>,
}

#[async_trait]
impl Tool for TodoTool {
    fn name(&self) -> &str {
        "todo"
    }

    fn description(&self) -> &str {
        "Manage many long-horizon durable data-plane todos and notes; compaction and task(todo_ids=...) briefs read them, but they never control goal continuation"
    }

    fn defensive_description(&self) -> Option<String> {
        Some("Maintain many durable data-plane work items for this session: create rows, list state, read detail, update status/content/priority, and append structured notes. Compaction and task(todo_ids=...) delegation briefs read todos; todo status is not a control signal and never decides whether the session keeps working.".to_string())
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "description": "Operation", "enum": ["create", "list", "detail", "update", "append_note"] },
                "content": { "type": "string", "description": "Todo content for create/update" },
                "id_or_name": { "type": "string", "description": "Todo id or unique content fragment for detail" },
                "todo_id": { "type": "string", "description": "Todo UUID for update/append_note" },
                "status": { "type": "string", "description": "Todo status", "enum": ["pending", "in_progress", "completed", "cancelled"] },
                "priority": { "type": "integer", "description": "Priority; higher sorts earlier in compact overview" },
                "outcome_summary": { "type": "string", "description": "One-line outcome/current summary" },
                "note_kind": { "type": "string", "description": "Structured note kind", "enum": ["summary", "finding", "decision", "artifact", "blocker", "handoff"] },
                "note": { "type": "string", "description": "Append-only note body" }
            },
            "required": ["action"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "description": "create a todo, list todos, read detail, update fields, or append a structured note", "enum": ["create", "list", "detail", "update", "append_note"] },
                "content": { "type": "string", "description": "Required for create; optional replacement content for update" },
                "id_or_name": { "type": "string", "description": "Required for detail; use an exact todo UUID or unambiguous content fragment" },
                "todo_id": { "type": "string", "description": "Required UUID for update and append_note" },
                "status": { "type": "string", "description": "Optional update status", "enum": ["pending", "in_progress", "completed", "cancelled"] },
                "priority": { "type": "integer", "description": "Optional create/update priority; higher sorts earlier" },
                "outcome_summary": { "type": "string", "description": "Optional one-line outcome/current summary for update" },
                "note_kind": { "type": "string", "description": "Optional append_note kind; defaults to finding", "enum": ["summary", "finding", "decision", "artifact", "blocker", "handoff"] },
                "note": { "type": "string", "description": "Required append-only note body for append_note" }
            },
            "required": ["action"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let args: TodoArgs = typed_args(args)?;
        match args.action.as_str() {
            "create" => {
                let content = required_opt_str(args.content.as_deref(), "content")?;
                let priority = args.priority.unwrap_or(0);
                let todo = ctx
                    .session
                    .db
                    .create_task_todo(ctx.session.id, content, priority)?;
                Ok(ToolOutput::text(format!(
                    "Created todo `{}`: {}",
                    todo.id, todo.content
                )))
            }
            "list" => {
                let todos = ctx.session.db.list_task_todos(ctx.session.id)?;
                if todos.is_empty() {
                    return Ok(ToolOutput::text("No todos for this session."));
                }
                let mut out = String::from("Todos:\n");
                for t in todos {
                    out.push_str(&format!(
                        "- `{}` [{} p{} #{}] {}\n",
                        t.id,
                        t.status.as_str(),
                        t.priority,
                        t.position,
                        t.content
                    ));
                }
                Ok(ToolOutput::text(out))
            }
            "detail" => {
                let key = required_opt_str(args.id_or_name.as_deref(), "id_or_name")?;
                let Some(detail) = ctx
                    .session
                    .db
                    .task_todo_detail_by_id_or_name(ctx.session.id, key)?
                else {
                    return Ok(ToolOutput::text(format!("No todo matched `{key}`.")));
                };
                Ok(ToolOutput::text(render_detail(&detail)))
            }
            "update" => {
                let todo_id = parse_uuid(required_opt_str(args.todo_id.as_deref(), "todo_id")?)?;
                let status = args
                    .status
                    .as_deref()
                    .map(TodoStatus::parse)
                    .transpose()
                    .map_err(|e| invalid_input(format!("{e:#}")))?;
                let content = args.content.as_deref();
                let priority = args.priority;
                let summary = args.outcome_summary.as_deref();
                ctx.session.db.update_task_todo(
                    ctx.session.id,
                    todo_id,
                    status,
                    content,
                    priority,
                    summary,
                )?;
                Ok(ToolOutput::text(format!("Updated todo `{todo_id}`.")))
            }
            "append_note" => {
                let todo_id = parse_uuid(required_opt_str(args.todo_id.as_deref(), "todo_id")?)?;
                let kind = args
                    .note_kind
                    .as_deref()
                    .map(TodoNoteKind::parse)
                    .transpose()
                    .map_err(|e| invalid_input(format!("{e:#}")))?
                    .unwrap_or(TodoNoteKind::Finding);
                let note = required_opt_str(args.note.as_deref(), "note")?;
                let id = ctx.session.db.append_task_todo_note(
                    ctx.session.id,
                    todo_id,
                    kind,
                    note,
                    &ctx.agent_id,
                    None,
                )?;
                Ok(ToolOutput::text(format!(
                    "Appended {} note `{}` to todo `{}`.",
                    kind.as_str(),
                    id,
                    todo_id
                )))
            }
            other => Err(invalid_input(format!(
                "`action` must be create, list, detail, update, or append_note (got `{other}`)"
            ))),
        }
    }
}

fn required_opt_str<'a>(value: Option<&'a str>, key: &str) -> Result<&'a str> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid_input(format!("`{key}` is required")))
}

fn parse_uuid(s: &str) -> Result<Uuid> {
    Uuid::parse_str(s).map_err(|_| invalid_input(format!("invalid todo UUID `{s}`")))
}

fn render_detail(detail: &TaskTodoDetail) -> String {
    let todo = &detail.todo;
    let mut out = format!(
        "Todo `{}`\nstatus: {}\npriority: {}\nposition: {}\ncontent: {}\n",
        todo.id,
        todo.status.as_str(),
        todo.priority,
        todo.position,
        todo.content
    );
    if let Some(summary) = &todo.outcome_summary {
        out.push_str(&format!("summary: {summary}\n"));
    }
    if !detail.assignments.is_empty() {
        out.push_str("\nAssigned child sessions:\n");
        for a in &detail.assignments {
            let child = a
                .child_session_id
                .map(|u| u.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            out.push_str(&format!(
                "- {} via task {}: {} ({})\n",
                a.child_agent, a.task_call_id, a.state, child
            ));
        }
    }
    for kind in [
        TodoNoteKind::Summary,
        TodoNoteKind::Finding,
        TodoNoteKind::Decision,
        TodoNoteKind::Artifact,
        TodoNoteKind::Blocker,
        TodoNoteKind::Handoff,
    ] {
        let notes: Vec<_> = detail.notes.iter().filter(|n| n.kind == kind).collect();
        if notes.is_empty() {
            continue;
        }
        out.push_str(&format!("\n{} notes:\n", kind.as_str()));
        for n in notes {
            out.push_str(&format!(
                "- [{}] {}: {}\n",
                n.created_at,
                n.author_agent,
                n.body.replace('\n', " ")
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tool::{Tool, ToolFailKind, classify_failure};

    fn enum_values(schema: Value, property: &str) -> Vec<String> {
        schema["properties"][property]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn todo_tool_actions_enum_is_exact() {
        assert_eq!(
            enum_values(TodoTool.parameters(), "action"),
            ["create", "list", "detail", "update", "append_note"]
        );
    }

    #[tokio::test]
    async fn todo_tool_detail_action_requires_id_or_name() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());

        let err = TodoTool
            .call(serde_json::json!({"action": "detail"}), &ctx)
            .await
            .unwrap_err();

        assert_eq!(classify_failure(&err), ToolFailKind::Invocation);
        assert!(err.to_string().contains("`id_or_name` is required"));
    }

    #[tokio::test]
    async fn todo_tool_detail_action_reads_by_id_or_name() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let todo = ctx
            .session
            .db
            .create_task_todo(ctx.session.id, "write launch notes", 2)
            .unwrap();
        ctx.session
            .db
            .append_task_todo_note(
                ctx.session.id,
                todo.id,
                TodoNoteKind::Decision,
                "Ship it.",
                "Build",
                None,
            )
            .unwrap();

        let out = TodoTool
            .call(
                serde_json::json!({"action": "detail", "id_or_name": "launch"}),
                &ctx,
            )
            .await
            .unwrap();

        assert!(out.content.contains(&format!("Todo `{}`", todo.id)));
        assert!(out.content.contains("content: write launch notes"));
        assert!(out.content.contains("decision notes:"));
    }

    #[test]
    fn todo_tool_description_states_data_plane_role() {
        let description = TodoTool.description().to_ascii_lowercase();
        assert!(description.contains("many"));
        assert!(description.contains("data-plane"));
        assert!(description.contains("compaction"));
        assert!(description.contains("task(todo_ids=...)"));
        assert!(description.contains("never control"));
        assert!(TodoTool.defensive_parameters().is_some());
    }
}
