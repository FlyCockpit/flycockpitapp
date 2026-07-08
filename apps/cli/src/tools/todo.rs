//! `todo` — create and maintain durable session todos.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

use crate::db::task_todos::{TodoNoteKind, TodoStatus};
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};

pub struct TodoTool;

#[async_trait]
impl Tool for TodoTool {
    fn name(&self) -> &str {
        "todo"
    }

    fn description(&self) -> &str {
        "Create/list/update session todos and append structured task notes"
    }

    fn defensive_description(&self) -> Option<String> {
        Some("Maintain the durable todo list for this session: create planning rows, list current state, update parent-owned status/content/priority, and append structured notes (summary/finding/decision/artifact/blocker/handoff). Use todos for long-horizon work before delegating with task.".to_string())
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "description": "Operation", "enum": ["create", "list", "update", "append_note"] },
                "content": { "type": "string", "description": "Todo content for create/update" },
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

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        match args.get("action").and_then(Value::as_str).unwrap_or("") {
            "create" => {
                let content = required_str(&args, "content")?;
                let priority = args.get("priority").and_then(Value::as_i64).unwrap_or(0);
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
            "update" => {
                let todo_id = parse_uuid(required_str(&args, "todo_id")?)?;
                let status = args
                    .get("status")
                    .and_then(Value::as_str)
                    .map(TodoStatus::parse)
                    .transpose()
                    .map_err(|e| invalid_input(format!("{e:#}")))?;
                let content = args.get("content").and_then(Value::as_str);
                let priority = args.get("priority").and_then(Value::as_i64);
                let summary = args.get("outcome_summary").and_then(Value::as_str);
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
                let todo_id = parse_uuid(required_str(&args, "todo_id")?)?;
                let kind = args
                    .get("note_kind")
                    .and_then(Value::as_str)
                    .map(TodoNoteKind::parse)
                    .transpose()
                    .map_err(|e| invalid_input(format!("{e:#}")))?
                    .unwrap_or(TodoNoteKind::Finding);
                let note = required_str(&args, "note")?;
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
                "`action` must be create, list, update, or append_note (got `{other}`)"
            ))),
        }
    }
}

fn required_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid_input(format!("`{key}` is required")))
}

fn parse_uuid(s: &str) -> Result<Uuid> {
    Uuid::parse_str(s).map_err(|_| invalid_input(format!("invalid todo UUID `{s}`")))
}
