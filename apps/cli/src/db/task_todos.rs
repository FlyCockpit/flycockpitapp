//! Durable task/todo state for compaction-backed long-horizon work.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TodoStatus {
    Pending,
    InProgress,
    Completed,
    Cancelled,
}

impl TodoStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "pending" => Ok(Self::Pending),
            "in_progress" => Ok(Self::InProgress),
            "completed" => Ok(Self::Completed),
            "cancelled" => Ok(Self::Cancelled),
            _ => anyhow::bail!("invalid todo status `{s}`"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TodoNoteKind {
    Summary,
    Finding,
    Decision,
    Artifact,
    Blocker,
    Handoff,
}

impl TodoNoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Summary => "summary",
            Self::Finding => "finding",
            Self::Decision => "decision",
            Self::Artifact => "artifact",
            Self::Blocker => "blocker",
            Self::Handoff => "handoff",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "summary" => Ok(Self::Summary),
            "finding" => Ok(Self::Finding),
            "decision" => Ok(Self::Decision),
            "artifact" => Ok(Self::Artifact),
            "blocker" => Ok(Self::Blocker),
            "handoff" => Ok(Self::Handoff),
            _ => anyhow::bail!("invalid todo note kind `{s}`"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskTodo {
    pub id: Uuid,
    pub session_id: Uuid,
    pub content: String,
    pub status: TodoStatus,
    pub priority: i64,
    pub position: i64,
    pub outcome_summary: Option<String>,
    pub version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskTodoNote {
    pub id: Uuid,
    pub todo_id: Uuid,
    pub kind: TodoNoteKind,
    pub body: String,
    pub author_agent: String,
    pub child_session_id: Option<Uuid>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskTodoAssignment {
    pub todo_id: Uuid,
    pub task_call_id: String,
    pub label: String,
    pub child_agent: String,
    pub child_session_id: Option<Uuid>,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskTodoDetail {
    pub todo: TaskTodo,
    pub notes: Vec<TaskTodoNote>,
    pub assignments: Vec<TaskTodoAssignment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskTodoOverview {
    pub total: usize,
    pub omitted: usize,
    pub items: Vec<TaskTodo>,
}

impl Db {
    pub fn create_task_todo(
        &self,
        session_id: Uuid,
        content: &str,
        priority: i64,
    ) -> Result<TaskTodo> {
        let content = content.trim();
        if content.is_empty() {
            anyhow::bail!("todo content must not be empty");
        }
        let id = Uuid::new_v4();
        let now = Utc::now().timestamp();
        self.with_conn(|conn| {
            let pos: i64 = conn
                .query_row(
                    "SELECT COALESCE(MAX(position), -1) + 1 FROM task_todos WHERE session_id = ?1",
                    [session_id.to_string()],
                    |row| row.get(0),
                )
                .context("computing next todo position")?;
            conn.execute(
                "INSERT INTO task_todos
                    (id, session_id, content, status, priority, position, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6, ?6)",
                params![
                    id.to_string(),
                    session_id.to_string(),
                    content,
                    priority,
                    pos,
                    now
                ],
            )
            .context("inserting task_todo")?;
            Ok(TaskTodo {
                id,
                session_id,
                content: content.to_string(),
                status: TodoStatus::Pending,
                priority,
                position: pos,
                outcome_summary: None,
                version: 0,
            })
        })
    }

    pub fn list_task_todos(&self, session_id: Uuid) -> Result<Vec<TaskTodo>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, session_id, content, status, priority, position, outcome_summary, version
                     FROM task_todos
                     WHERE session_id = ?1
                     ORDER BY position ASC, created_at ASC",
                )
                .context("preparing list_task_todos")?;
            let rows = stmt
                .query_map([session_id.to_string()], decode_todo)
                .context("querying task_todos")?;
            rows.map(|r| r.context("decoding task_todo"))
                .collect::<Result<Vec<_>>>()
        })
    }

    pub fn update_task_todo(
        &self,
        session_id: Uuid,
        todo_id: Uuid,
        status: Option<TodoStatus>,
        content: Option<&str>,
        priority: Option<i64>,
        outcome_summary: Option<&str>,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        self.with_conn(|conn| {
            let existing = load_todo(conn, session_id, todo_id)?;
            let new_content = content
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(&existing.content);
            conn.execute(
                "UPDATE task_todos
                    SET content = ?1,
                        status = ?2,
                        priority = ?3,
                        outcome_summary = COALESCE(?4, outcome_summary),
                        version = version + 1,
                        updated_at = ?5
                  WHERE id = ?6 AND session_id = ?7",
                params![
                    new_content,
                    status.unwrap_or(existing.status).as_str(),
                    priority.unwrap_or(existing.priority),
                    outcome_summary.map(str::trim).filter(|s| !s.is_empty()),
                    now,
                    todo_id.to_string(),
                    session_id.to_string()
                ],
            )
            .context("updating task_todo")?;
            Ok(())
        })
    }

    pub fn append_task_todo_note(
        &self,
        session_id: Uuid,
        todo_id: Uuid,
        kind: TodoNoteKind,
        body: &str,
        author_agent: &str,
        child_session_id: Option<Uuid>,
    ) -> Result<Uuid> {
        let body = body.trim();
        if body.is_empty() {
            anyhow::bail!("todo note body must not be empty");
        }
        let id = Uuid::new_v4();
        let now = Utc::now().timestamp();
        self.with_conn(|conn| {
            load_todo(conn, session_id, todo_id)?;
            conn.execute(
                "INSERT INTO task_todo_notes
                    (id, todo_id, session_id, kind, body, author_agent, child_session_id, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    id.to_string(),
                    todo_id.to_string(),
                    session_id.to_string(),
                    kind.as_str(),
                    body,
                    author_agent,
                    child_session_id.map(|u| u.to_string()),
                    now
                ],
            )
            .context("inserting task_todo_note")?;
            Ok(id)
        })
    }

    pub fn assign_task_todos(
        &self,
        session_id: Uuid,
        todo_ids: &[Uuid],
        task_call_id: &str,
        label: &str,
        child_agent: &str,
    ) -> Result<Vec<TaskTodo>> {
        let now = Utc::now().timestamp();
        self.with_conn(|conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin assign_task_todos tx")?;
            let mut assigned = Vec::new();
            for todo_id in todo_ids {
                let todo = load_todo(&tx, session_id, *todo_id)?;
                let assignment_id = Uuid::new_v4();
                tx.execute(
                    "INSERT OR IGNORE INTO task_todo_assignments
                        (id, todo_id, session_id, task_call_id, label, child_agent, state, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'running', ?7, ?7)",
                    params![
                        assignment_id.to_string(),
                        todo_id.to_string(),
                        session_id.to_string(),
                        task_call_id,
                        label,
                        child_agent,
                        now
                    ],
                )
                .context("inserting task_todo_assignment")?;
                if matches!(todo.status, TodoStatus::Pending) {
                    tx.execute(
                        "UPDATE task_todos SET status = 'in_progress', version = version + 1, updated_at = ?1
                         WHERE id = ?2 AND session_id = ?3 AND status = 'pending'",
                        params![now, todo_id.to_string(), session_id.to_string()],
                    )
                    .context("marking assigned todo in_progress")?;
                }
                assigned.push(load_todo(&tx, session_id, *todo_id)?);
            }
            tx.commit().context("commit assign_task_todos tx")?;
            Ok(assigned)
        })
    }

    pub fn finish_task_assignment(
        &self,
        session_id: Uuid,
        task_call_id: &str,
        label: &str,
        state: &str,
        child_session_id: Option<Uuid>,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE task_todo_assignments
                    SET state = ?1, child_session_id = COALESCE(?2, child_session_id), updated_at = ?3
                  WHERE session_id = ?4 AND task_call_id = ?5 AND label = ?6",
                params![
                    state,
                    child_session_id.map(|u| u.to_string()),
                    now,
                    session_id.to_string(),
                    task_call_id,
                    label
                ],
            )
            .context("updating task_todo_assignment")?;
            Ok(())
        })
    }

    pub fn task_todo_detail_by_id_or_name(
        &self,
        session_id: Uuid,
        id_or_name: &str,
    ) -> Result<Option<TaskTodoDetail>> {
        let key = id_or_name.trim();
        if key.is_empty() {
            anyhow::bail!("todo id or name must not be empty");
        }
        self.with_conn(|conn| {
            let todo = if let Ok(id) = Uuid::parse_str(key) {
                load_todo_opt(conn, session_id, id)?
            } else {
                let like = format!("%{key}%");
                let mut stmt = conn
                    .prepare(
                        "SELECT id, session_id, content, status, priority, position, outcome_summary, version
                         FROM task_todos
                         WHERE session_id = ?1 AND content LIKE ?2
                         ORDER BY position ASC",
                    )
                    .context("preparing todo name lookup")?;
                let rows = stmt
                    .query_map(params![session_id.to_string(), like], decode_todo)
                    .context("querying todo name lookup")?;
                let mut matches = Vec::new();
                for row in rows {
                    matches.push(row.context("decoding todo name match")?);
                }
                match matches.len() {
                    0 => None,
                    1 => matches.pop(),
                    _ => anyhow::bail!("todo name `{key}` is ambiguous; pass the id"),
                }
            };
            let Some(todo) = todo else {
                return Ok(None);
            };
            let notes = list_notes(conn, todo.id)?;
            let assignments = list_assignments(conn, todo.id)?;
            Ok(Some(TaskTodoDetail {
                todo,
                notes,
                assignments,
            }))
        })
    }

    pub fn task_todo_overview(&self, session_id: Uuid, limit: usize) -> Result<TaskTodoOverview> {
        let all = self.list_task_todos(session_id)?;
        let total = all.len();
        let mut active: Vec<_> = all
            .iter()
            .filter(|t| !matches!(t.status, TodoStatus::Completed | TodoStatus::Cancelled))
            .cloned()
            .collect();
        active.sort_by_key(|t| (status_rank(t.status), -t.priority, t.position));
        let mut completed: Vec<_> = all
            .iter()
            .filter(|t| matches!(t.status, TodoStatus::Completed))
            .cloned()
            .collect();
        completed.sort_by_key(|t| t.position);
        let mut cancelled: Vec<_> = all
            .iter()
            .filter(|t| matches!(t.status, TodoStatus::Cancelled))
            .cloned()
            .collect();
        cancelled.sort_by_key(|t| t.position);
        let mut items = Vec::new();
        items.extend(completed.into_iter().take(8));
        items.extend(active);
        items.extend(cancelled.into_iter().take(3));
        if items.len() > limit {
            items.truncate(limit);
        }
        let omitted = total.saturating_sub(items.len());
        Ok(TaskTodoOverview {
            total,
            omitted,
            items,
        })
    }
}

fn status_rank(status: TodoStatus) -> i32 {
    match status {
        TodoStatus::InProgress => 0,
        TodoStatus::Pending => 1,
        TodoStatus::Completed => 2,
        TodoStatus::Cancelled => 3,
    }
}

fn load_todo(conn: &rusqlite::Connection, session_id: Uuid, id: Uuid) -> Result<TaskTodo> {
    load_todo_opt(conn, session_id, id)?.ok_or_else(|| anyhow::anyhow!("todo `{id}` not found"))
}

fn load_todo_opt(
    conn: &rusqlite::Connection,
    session_id: Uuid,
    id: Uuid,
) -> Result<Option<TaskTodo>> {
    conn.query_row(
        "SELECT id, session_id, content, status, priority, position, outcome_summary, version
         FROM task_todos
         WHERE id = ?1 AND session_id = ?2",
        params![id.to_string(), session_id.to_string()],
        decode_todo,
    )
    .optional()
    .context("loading task_todo")
}

fn decode_todo(row: &rusqlite::Row<'_>) -> rusqlite::Result<TaskTodo> {
    let id: String = row.get(0)?;
    let session_id: String = row.get(1)?;
    let status: String = row.get(3)?;
    Ok(TaskTodo {
        id: Uuid::parse_str(&id).map_err(to_sql_err)?,
        session_id: Uuid::parse_str(&session_id).map_err(to_sql_err)?,
        content: row.get(2)?,
        status: TodoStatus::parse(&status).map_err(to_sql_err)?,
        priority: row.get(4)?,
        position: row.get(5)?,
        outcome_summary: row.get(6)?,
        version: row.get(7)?,
    })
}

fn list_notes(conn: &rusqlite::Connection, todo_id: Uuid) -> Result<Vec<TaskTodoNote>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, todo_id, kind, body, author_agent, child_session_id, created_at
             FROM task_todo_notes
             WHERE todo_id = ?1
             ORDER BY created_at ASC, rowid ASC",
        )
        .context("preparing task_todo_notes")?;
    let rows = stmt
        .query_map([todo_id.to_string()], |row| {
            let id: String = row.get(0)?;
            let todo_id: String = row.get(1)?;
            let kind: String = row.get(2)?;
            let child: Option<String> = row.get(5)?;
            Ok(TaskTodoNote {
                id: Uuid::parse_str(&id).map_err(to_sql_err)?,
                todo_id: Uuid::parse_str(&todo_id).map_err(to_sql_err)?,
                kind: TodoNoteKind::parse(&kind).map_err(to_sql_err)?,
                body: row.get(3)?,
                author_agent: row.get(4)?,
                child_session_id: child
                    .map(|s| Uuid::parse_str(&s).map_err(to_sql_err))
                    .transpose()?,
                created_at: row.get(6)?,
            })
        })
        .context("querying task_todo_notes")?;
    rows.map(|r| r.context("decoding task_todo_note"))
        .collect::<Result<Vec<_>>>()
}

fn list_assignments(conn: &rusqlite::Connection, todo_id: Uuid) -> Result<Vec<TaskTodoAssignment>> {
    let mut stmt = conn
        .prepare(
            "SELECT todo_id, task_call_id, label, child_agent, child_session_id, state
             FROM task_todo_assignments
             WHERE todo_id = ?1
             ORDER BY created_at ASC, rowid ASC",
        )
        .context("preparing task_todo_assignments")?;
    let rows = stmt
        .query_map([todo_id.to_string()], |row| {
            let todo_id: String = row.get(0)?;
            let child: Option<String> = row.get(4)?;
            Ok(TaskTodoAssignment {
                todo_id: Uuid::parse_str(&todo_id).map_err(to_sql_err)?,
                task_call_id: row.get(1)?,
                label: row.get(2)?,
                child_agent: row.get(3)?,
                child_session_id: child
                    .map(|s| Uuid::parse_str(&s).map_err(to_sql_err))
                    .transpose()?,
                state: row.get(5)?,
            })
        })
        .context("querying task_todo_assignments")?;
    rows.map(|r| r.context("decoding task_todo_assignment"))
        .collect::<Result<Vec<_>>>()
}

fn to_sql_err<E: std::fmt::Display>(e: E) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.to_string(),
        )),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignment_preserves_parallel_notes_append_only() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").unwrap();
        let todo = db
            .create_task_todo(s.session_id, "implement thing", 5)
            .unwrap();
        db.assign_task_todos(s.session_id, &[todo.id], "call-a", "default", "explore")
            .unwrap();
        db.assign_task_todos(s.session_id, &[todo.id], "call-b", "default", "builder")
            .unwrap();
        db.append_task_todo_note(
            s.session_id,
            todo.id,
            TodoNoteKind::Finding,
            "A found",
            "explore",
            None,
        )
        .unwrap();
        db.append_task_todo_note(
            s.session_id,
            todo.id,
            TodoNoteKind::Artifact,
            "B wrote file",
            "builder",
            None,
        )
        .unwrap();

        let detail = db
            .task_todo_detail_by_id_or_name(s.session_id, &todo.id.to_string())
            .unwrap()
            .unwrap();
        assert_eq!(detail.assignments.len(), 2);
        assert_eq!(detail.notes.len(), 2);
        assert!(matches!(detail.todo.status, TodoStatus::InProgress));
    }

    #[test]
    fn assign_task_todos_failure_rolls_back_prior_assignments() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").unwrap();
        let todo = db.create_task_todo(s.session_id, "auth", 5).unwrap();
        let missing = Uuid::new_v4();

        let err = db
            .assign_task_todos(
                s.session_id,
                &[todo.id, missing],
                "call-1",
                "default",
                "explore",
            )
            .unwrap_err();

        assert!(
            format!("{err:#}").contains("not found"),
            "unexpected error: {err:#}"
        );
        let detail = db
            .task_todo_detail_by_id_or_name(s.session_id, &todo.id.to_string())
            .unwrap()
            .unwrap();
        assert!(detail.assignments.is_empty());
        assert_eq!(detail.todo.status, TodoStatus::Pending);
        assert_eq!(detail.todo.version, 0);
    }

    #[test]
    fn assignments_scope_finish_by_task_call_and_label() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").unwrap();
        let a = db.create_task_todo(s.session_id, "auth", 5).unwrap();
        let b = db.create_task_todo(s.session_id, "db", 5).unwrap();
        db.assign_task_todos(s.session_id, &[a.id], "call-1", "auth", "explore")
            .unwrap();
        db.assign_task_todos(s.session_id, &[b.id], "call-1", "db", "explore")
            .unwrap();
        db.finish_task_assignment(s.session_id, "call-1", "auth", "completed", None)
            .unwrap();

        let auth = db
            .task_todo_detail_by_id_or_name(s.session_id, &a.id.to_string())
            .unwrap()
            .unwrap();
        let db_todo = db
            .task_todo_detail_by_id_or_name(s.session_id, &b.id.to_string())
            .unwrap()
            .unwrap();
        assert_eq!(auth.assignments[0].label, "auth");
        assert_eq!(auth.assignments[0].state, "completed");
        assert_eq!(db_todo.assignments[0].label, "db");
        assert_eq!(db_todo.assignments[0].state, "running");
    }

    #[test]
    fn retrieves_completed_details_with_summary_artifacts_and_blockers() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").unwrap();
        let todo = db
            .create_task_todo(s.session_id, "ship compact overview", 9)
            .unwrap();
        db.assign_task_todos(s.session_id, &[todo.id], "call-1", "default", "builder")
            .unwrap();
        db.update_task_todo(
            s.session_id,
            todo.id,
            Some(TodoStatus::Completed),
            None,
            None,
            Some("overview renders ids"),
        )
        .unwrap();
        db.append_task_todo_note(
            s.session_id,
            todo.id,
            TodoNoteKind::Artifact,
            "src/engine/compact.rs",
            "builder",
            None,
        )
        .unwrap();
        db.append_task_todo_note(
            s.session_id,
            todo.id,
            TodoNoteKind::Blocker,
            "none",
            "builder",
            None,
        )
        .unwrap();
        db.finish_task_assignment(s.session_id, "call-1", "default", "completed", None)
            .unwrap();

        let detail = db
            .task_todo_detail_by_id_or_name(s.session_id, "compact overview")
            .unwrap()
            .unwrap();
        assert!(matches!(detail.todo.status, TodoStatus::Completed));
        assert_eq!(
            detail.todo.outcome_summary.as_deref(),
            Some("overview renders ids")
        );
        assert_eq!(detail.assignments[0].state, "completed");
        assert!(
            detail
                .notes
                .iter()
                .any(|n| n.kind == TodoNoteKind::Artifact)
        );
        assert!(detail.notes.iter().any(|n| n.kind == TodoNoteKind::Blocker));
    }
}
