//! `todo_read` — compact retrieval for task-backed todo details.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;

use crate::db::task_todos::TodoNoteKind;
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input};

pub struct TodoReadTool;

#[async_trait]
impl Tool for TodoReadTool {
    fn name(&self) -> &str {
        "todo_read"
    }

    fn description(&self) -> &str {
        "Read full details and notes for a session todo by id or unambiguous name"
    }

    fn defensive_description(&self) -> Option<String> {
        Some("Read full details for a current-session todo/task by id or unambiguous content fragment, including status, assigned subagents, structured notes, artifacts, blockers, and handoff notes. Use after compaction when the overview says details exist; do not use it to mutate todos, and provide an id when a name fragment could match more than one row.".to_string())
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "id_or_name": { "type": "string", "description": "Todo id or unique content fragment" }
            },
            "required": ["id_or_name"]
        })
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let key = args
            .get("id_or_name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_input("`id_or_name` is required"))?;
        let Some(detail) = ctx
            .session
            .db
            .task_todo_detail_by_id_or_name(ctx.session.id, key)?
        else {
            return Ok(ToolOutput::text(format!("No todo matched `{key}`.")));
        };
        Ok(ToolOutput::text(render_detail(&detail)))
    }
}

pub(crate) fn render_detail(detail: &crate::db::task_todos::TaskTodoDetail) -> String {
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
