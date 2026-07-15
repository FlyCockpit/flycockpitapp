//! Durable noninteractive `task` delegation state (migration 0046).

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::params;
use uuid::Uuid;

use crate::db::Db;

const LOST_RESTART_REPORT: &str = "lost: daemon restarted before this delegation finished";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationStatus {
    Running,
    Backgrounded,
    Completed,
    Failed,
    Cancelled,
    PausedPendingTool,
    Lost,
}

impl DelegationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Backgrounded => "backgrounded",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::PausedPendingTool => "paused_pending_tool",
            Self::Lost => "lost",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "running" => Self::Running,
            "backgrounded" => Self::Backgrounded,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            "paused_pending_tool" => Self::PausedPendingTool,
            "lost" => Self::Lost,
            _ => Self::Lost,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DelegationChildInit<'a> {
    pub label: &'a str,
    pub child_agent: &'a str,
    pub model: Option<&'a str>,
    pub output_dir: Option<&'a str>,
    pub requested_cwd: Option<&'a str>,
    pub resolved_cwd: Option<&'a str>,
    pub todo_ids_json: Option<&'a str>,
}

#[derive(Debug, Clone)]
struct DelegationChildInitOwned {
    label: String,
    child_agent: String,
    model: Option<String>,
    output_dir: Option<String>,
    requested_cwd: Option<String>,
    resolved_cwd: Option<String>,
    todo_ids_json: Option<String>,
}

impl From<&DelegationChildInit<'_>> for DelegationChildInitOwned {
    fn from(value: &DelegationChildInit<'_>) -> Self {
        Self {
            label: value.label.to_owned(),
            child_agent: value.child_agent.to_owned(),
            model: value.model.map(str::to_owned),
            output_dir: value.output_dir.map(str::to_owned),
            requested_cwd: value.requested_cwd.map(str::to_owned),
            resolved_cwd: value.resolved_cwd.map(str::to_owned),
            todo_ids_json: value.todo_ids_json.map(str::to_owned),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DelegationChildRow {
    pub task_call_id: String,
    pub label: String,
    pub child_agent: String,
    pub status: DelegationStatus,
    pub report: Option<String>,
    pub result_delivered: bool,
}

#[derive(Debug, Clone)]
pub struct TaskDelegationSteerRow {
    pub id: i64,
    pub task_call_id: String,
    pub label: String,
    pub body: String,
    pub origin_principal: String,
    pub delivered: bool,
    pub created_at: i64,
    pub delivered_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct DelegationChildDetail {
    pub task_call_id: String,
    pub label: String,
    pub child_agent: String,
    pub model: Option<String>,
    pub status: DelegationStatus,
    pub report: Option<String>,
    pub result_delivered: bool,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub updated_at: i64,
    pub pending_steers: i64,
}

impl Db {
    pub fn upsert_task_delegation_job(
        &self,
        session_id: Uuid,
        task_call_id: &str,
        function_call_id: Option<&str>,
        parent_agent: &str,
        original_args_json: Option<&str>,
        children: &[DelegationChildInit<'_>],
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let task_call_id = task_call_id.to_owned();
        let function_call_id = function_call_id.map(str::to_owned);
        let parent_agent = parent_agent.to_owned();
        let original_args_json = original_args_json.map(str::to_owned);
        let children: Vec<DelegationChildInitOwned> = children
            .iter()
            .map(DelegationChildInitOwned::from)
            .collect();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO task_delegation_jobs (
                    task_call_id, function_call_id, parent_session_id, parent_agent,
                    original_args_json, status, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'running', ?6, ?6)
                 ON CONFLICT(task_call_id) DO UPDATE SET
                    function_call_id = excluded.function_call_id,
                    parent_session_id = excluded.parent_session_id,
                    parent_agent = excluded.parent_agent,
                    original_args_json = COALESCE(excluded.original_args_json, task_delegation_jobs.original_args_json),
                    updated_at = excluded.updated_at",
                params![
                    task_call_id,
                    function_call_id,
                    session_id.to_string(),
                    parent_agent,
                    original_args_json,
                    now,
                ],
            )
            .context("upserting task delegation job")?;

            for child in children {
                conn.execute(
                    "INSERT INTO task_delegation_children (
                        task_call_id, label, child_agent, model, status, output_dir,
                        requested_cwd, resolved_cwd, todo_ids_json, started_at,
                        created_at, updated_at
                     ) VALUES (?1, ?2, ?3, ?4, 'running', ?5, ?6, ?7, ?8, ?9, ?9, ?9)
                     ON CONFLICT(task_call_id, label) DO UPDATE SET
                        child_agent = excluded.child_agent,
                        model = excluded.model,
                        output_dir = excluded.output_dir,
                        requested_cwd = excluded.requested_cwd,
                        resolved_cwd = excluded.resolved_cwd,
                        todo_ids_json = excluded.todo_ids_json,
                        updated_at = excluded.updated_at",
                    params![
                        task_call_id,
                        child.label,
                        child.child_agent,
                        child.model,
                        child.output_dir,
                        child.requested_cwd,
                        child.resolved_cwd,
                        child.todo_ids_json,
                        now,
                    ],
                )
                .context("upserting task delegation child")?;
            }
            Ok(())
        })
    }

    pub fn background_task_delegation_child(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Result<bool> {
        let now = Utc::now().timestamp();
        let task_call_id = task_call_id.to_owned();
        let label = label.to_owned();
        self.write_blocking(move |conn| {
            immediate_transaction(
                conn,
                "beginning background delegation transaction",
                "committing background delegation transaction",
                || {
                    let changed = conn
                        .execute(
                            "UPDATE task_delegation_children
                                SET status = 'backgrounded', updated_at = ?3
                              WHERE task_call_id = ?1
                                AND label = ?2
                                AND status = 'running'",
                            params![task_call_id, label, now],
                        )
                        .context("marking task delegation child backgrounded")?;
                    if changed > 0 {
                        conn.execute(
                            "UPDATE task_delegation_jobs
                                SET status = 'backgrounded', ack_delivered = 1, updated_at = ?2
                              WHERE task_call_id = ?1
                                AND status IN ('running', 'backgrounded')",
                            params![task_call_id, now],
                        )
                        .context("marking task delegation job backgrounded")?;
                    }
                    Ok(changed > 0)
                },
            )
        })
    }

    pub fn complete_task_delegation_child(
        &self,
        task_call_id: &str,
        label: &str,
        report: &str,
        failed: bool,
        snapshot_json: Option<&str>,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let status = if failed {
            DelegationStatus::Failed
        } else {
            DelegationStatus::Completed
        };
        let task_call_id = task_call_id.to_owned();
        let label = label.to_owned();
        let report = report.to_owned();
        let snapshot_json = snapshot_json.map(str::to_owned);
        self.write_blocking(move |conn| {
            immediate_transaction(
                conn,
                "beginning complete delegation transaction",
                "committing complete delegation transaction",
                || {
                    conn.execute(
                        "UPDATE task_delegation_children
                            SET status = ?3,
                                report = ?4,
                                snapshot_json = COALESCE(?5, snapshot_json),
                                finished_at = COALESCE(finished_at, ?6),
                                updated_at = ?6
                          WHERE task_call_id = ?1
                            AND label = ?2
                            AND status IN ('running', 'backgrounded', 'paused_pending_tool')",
                        params![
                            task_call_id,
                            label,
                            status.as_str(),
                            report,
                            snapshot_json,
                            now
                        ],
                    )
                    .context("completing task delegation child")?;

                    let (remaining, failed): (i64, i64) = conn
                        .query_row(
                            "SELECT
                                COALESCE(SUM(status IN ('running', 'backgrounded', 'paused_pending_tool')), 0),
                                COALESCE(SUM(status IN ('failed', 'lost')), 0)
                               FROM task_delegation_children
                              WHERE task_call_id = ?1",
                            params![task_call_id],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .context("summarizing task delegation children")?;
                    if remaining == 0 {
                        let job_status = if failed > 0 {
                            DelegationStatus::Failed
                        } else {
                            DelegationStatus::Completed
                        };
                        conn.execute(
                            "UPDATE task_delegation_jobs
                                SET status = ?2, updated_at = ?3
                              WHERE task_call_id = ?1",
                            params![task_call_id, job_status.as_str(), now],
                        )
                        .context("completing task delegation job")?;
                    }
                    Ok(())
                },
            )
        })
    }

    pub fn undelivered_task_delegation_children(
        &self,
        task_call_id: &str,
    ) -> Result<Vec<DelegationChildRow>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT task_call_id, label, child_agent, status, report, result_delivered
                       FROM task_delegation_children
                      WHERE task_call_id = ?1
                        AND status IN ('completed', 'failed', 'cancelled', 'lost')
                        AND result_delivered = 0
                      ORDER BY label ASC",
                )
                .context("preparing undelivered delegation children query")?;
            let rows = stmt
                .query_map(params![task_call_id], decode_child)
                .context("querying undelivered delegation children")?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .context("decoding undelivered delegation children")
        })
    }

    pub fn mark_task_delegation_child_delivered(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Result<bool> {
        let now = Utc::now().timestamp();
        let task_call_id = task_call_id.to_owned();
        let label = label.to_owned();
        self.write_blocking(move |conn| {
            immediate_transaction(
                conn,
                "beginning delivered delegation transaction",
                "committing delivered delegation transaction",
                || {
                    let changed = conn
                        .execute(
                            "UPDATE task_delegation_children
                                SET result_delivered = 1, updated_at = ?3
                              WHERE task_call_id = ?1
                                AND label = ?2
                                AND result_delivered = 0",
                            params![task_call_id, label, now],
                        )
                        .context("marking task delegation child delivered")?;
                    let remaining: i64 = conn
                        .query_row(
                            "SELECT COUNT(*)
                               FROM task_delegation_children
                              WHERE task_call_id = ?1 AND result_delivered = 0",
                            params![task_call_id],
                            |row| row.get(0),
                        )
                        .context("counting undelivered task delegation children")?;
                    if remaining == 0 {
                        conn.execute(
                            "UPDATE task_delegation_jobs
                                SET final_delivered = 1, updated_at = ?2
                              WHERE task_call_id = ?1",
                            params![task_call_id, now],
                        )
                        .context("marking task delegation final delivered")?;
                    }
                    Ok(changed > 0)
                },
            )
        })
    }

    pub fn list_task_delegation_children(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<DelegationChildDetail>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT c.task_call_id, c.label, c.child_agent, c.model, c.status,
                            c.report, c.result_delivered, c.started_at, c.finished_at,
                            c.updated_at,
                            (SELECT COUNT(*) FROM task_delegation_steers s
                              WHERE s.task_call_id = c.task_call_id
                                AND s.label = c.label
                                AND s.delivered = 0) AS pending_steers
                       FROM task_delegation_children c
                       JOIN task_delegation_jobs j ON j.task_call_id = c.task_call_id
                      WHERE j.parent_session_id = ?1
                      ORDER BY c.updated_at DESC, c.task_call_id ASC, c.label ASC",
                )
                .context("preparing task delegation children list")?;
            let rows = stmt
                .query_map(params![session_id.to_string()], decode_child_detail)
                .context("querying task delegation children")?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .context("decoding task delegation children")
        })
    }

    pub fn cancel_task_delegation_child(&self, task_call_id: &str, label: &str) -> Result<bool> {
        let now = Utc::now().timestamp();
        let task_call_id = task_call_id.to_owned();
        let label = label.to_owned();
        self.write_blocking(move |conn| {
            immediate_transaction(
                conn,
                "beginning cancel delegation transaction",
                "committing cancel delegation transaction",
                || {
                    let changed = conn
                        .execute(
                            "UPDATE task_delegation_children
                                SET status = 'cancelled',
                                    report = COALESCE(report, 'cancelled'),
                                    finished_at = COALESCE(finished_at, ?3),
                                    updated_at = ?3
                              WHERE task_call_id = ?1
                                AND label = ?2
                                AND status IN ('running', 'backgrounded', 'paused_pending_tool')",
                            params![task_call_id, label, now],
                        )
                        .context("cancelling task delegation child")?;
                    let (remaining, failed): (i64, i64) = conn
                        .query_row(
                            "SELECT
                                COALESCE(SUM(status IN ('running', 'backgrounded', 'paused_pending_tool')), 0),
                                COALESCE(SUM(status IN ('failed', 'lost')), 0)
                               FROM task_delegation_children
                              WHERE task_call_id = ?1",
                            params![task_call_id],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .context("summarizing delegation after cancel")?;
                    if remaining == 0 {
                        let status = if failed > 0 { "failed" } else { "cancelled" };
                        conn.execute(
                            "UPDATE task_delegation_jobs
                                SET status = ?2, updated_at = ?3
                              WHERE task_call_id = ?1",
                            params![task_call_id, status, now],
                        )
                        .context("marking delegation job cancelled")?;
                    }
                    Ok(changed > 0)
                },
            )
        })
    }

    pub fn mark_task_delegation_child_lost(&self, task_call_id: &str, label: &str) -> Result<bool> {
        let now = Utc::now().timestamp();
        let task_call_id = task_call_id.to_owned();
        let label = label.to_owned();
        self.write_blocking(move |conn| {
            immediate_transaction(
                conn,
                "beginning lost delegation transaction",
                "committing lost delegation transaction",
                || {
                    let changed = mark_child_lost(conn, &task_call_id, &label, now)?;
                    if changed {
                        reconcile_job_after_lost(conn, &task_call_id, now)?;
                    }
                    Ok(changed)
                },
            )
        })
    }

    pub fn reconcile_orphaned_task_delegations(&self) -> Result<usize> {
        let now = Utc::now().timestamp();
        self.write_blocking(move |conn| {
            immediate_transaction(
                conn,
                "beginning orphaned delegation reconcile",
                "committing orphaned delegation reconcile",
                || {
                    let mut stmt = conn
                        .prepare(
                            "SELECT task_call_id, label
                           FROM task_delegation_children
                          WHERE status IN ('running', 'backgrounded', 'paused_pending_tool')
                          ORDER BY task_call_id ASC, label ASC",
                        )
                        .context("preparing orphaned delegation child scan")?;
                    let rows = stmt
                        .query_map([], |row| {
                            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                        })
                        .context("querying orphaned delegation children")?
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .context("decoding orphaned delegation children")?;
                    drop(stmt);

                    for (task_call_id, label) in &rows {
                        mark_child_lost(conn, task_call_id, label, now)?;
                    }

                    let mut job_stmt = conn
                        .prepare(
                            "SELECT DISTINCT task_call_id
                           FROM task_delegation_jobs
                          WHERE status IN ('running', 'backgrounded')",
                        )
                        .context("preparing orphaned delegation job scan")?;
                    let jobs = job_stmt
                        .query_map([], |row| row.get::<_, String>(0))
                        .context("querying orphaned delegation jobs")?
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .context("decoding orphaned delegation jobs")?;
                    drop(job_stmt);

                    for task_call_id in &jobs {
                        reconcile_job_after_lost(conn, task_call_id, now)?;
                    }

                    Ok(rows.len())
                },
            )
        })
    }

    pub fn enqueue_task_delegation_steer(
        &self,
        task_call_id: &str,
        label: &str,
        body: &str,
        origin_principal: &str,
    ) -> Result<()> {
        let body = body.trim();
        let origin_principal = origin_principal.trim();
        if body.is_empty() {
            anyhow::bail!("steer body must not be empty");
        }
        if origin_principal.is_empty() {
            anyhow::bail!("steer origin principal must not be empty");
        }
        let now = Utc::now().timestamp();
        let task_call_id = task_call_id.to_owned();
        let label = label.to_owned();
        let body = body.to_owned();
        let origin_principal = origin_principal.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO task_delegation_steers (task_call_id, label, body, origin_principal, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![task_call_id, label, body, origin_principal, now],
            )
            .context("enqueueing task delegation steer")?;
            Ok(())
        })
    }

    pub fn drain_task_delegation_steers(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Result<Vec<TaskDelegationSteerRow>> {
        let now = Utc::now().timestamp();
        let task_call_id = task_call_id.to_owned();
        let label = label.to_owned();
        self.write_blocking(move |conn| {
            let pending = {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, task_call_id, label, body, origin_principal, delivered, created_at, delivered_at
                           FROM task_delegation_steers
                          WHERE task_call_id = ?1
                            AND label = ?2
                            AND delivered = 0
                          ORDER BY id ASC",
                    )
                    .context("preparing pending delegation steer drain")?;
                let rows = stmt
                    .query_map(params![task_call_id, label], decode_steer)
                    .context("querying pending delegation steers")?;
                rows.collect::<rusqlite::Result<Vec<_>>>()
                    .context("decoding pending delegation steers")?
            };
            for steer in &pending {
                conn.execute(
                    "UPDATE task_delegation_steers
                        SET delivered = 1, delivered_at = ?2
                      WHERE id = ?1",
                    params![steer.id, now],
                )
                .context("marking delegation steer delivered")?;
            }
            Ok(pending)
        })
    }

    pub fn list_task_delegation_steers(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<TaskDelegationSteerRow>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT s.id, s.task_call_id, s.label, s.body, s.origin_principal,
                            s.delivered, s.created_at, s.delivered_at
                       FROM task_delegation_steers s
                       JOIN task_delegation_jobs j ON j.task_call_id = s.task_call_id
                      WHERE j.parent_session_id = ?1
                      ORDER BY s.id ASC",
                )
                .context("preparing task delegation steers list")?;
            let rows = stmt
                .query_map(params![session_id.to_string()], decode_steer)
                .context("querying task delegation steers")?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .context("decoding task delegation steers")
        })
    }
}

fn immediate_transaction<T>(
    conn: &rusqlite::Connection,
    begin_context: &str,
    commit_context: &str,
    f: impl FnOnce() -> Result<T>,
) -> Result<T> {
    conn.execute_batch("BEGIN IMMEDIATE")
        .with_context(|| begin_context.to_string())?;
    let result = f();
    match result {
        Ok(value) => {
            conn.execute_batch("COMMIT")
                .with_context(|| commit_context.to_string())?;
            Ok(value)
        }
        Err(error) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

fn mark_child_lost(
    conn: &rusqlite::Connection,
    task_call_id: &str,
    label: &str,
    now: i64,
) -> Result<bool> {
    let changed = conn
        .execute(
            "UPDATE task_delegation_children
                SET status = 'lost',
                    report = COALESCE(report, ?4),
                    finished_at = COALESCE(finished_at, ?3),
                    updated_at = ?3
              WHERE task_call_id = ?1
                AND label = ?2
                AND status IN ('running', 'backgrounded', 'paused_pending_tool')",
            params![task_call_id, label, now, LOST_RESTART_REPORT],
        )
        .context("marking task delegation child lost")?;
    Ok(changed > 0)
}

fn reconcile_job_after_lost(
    conn: &rusqlite::Connection,
    task_call_id: &str,
    now: i64,
) -> Result<()> {
    let (remaining, lost): (i64, i64) = conn
        .query_row(
            "SELECT
                COALESCE(SUM(status IN ('running', 'backgrounded', 'paused_pending_tool')), 0),
                COALESCE(SUM(status = 'lost'), 0)
               FROM task_delegation_children
              WHERE task_call_id = ?1",
            params![task_call_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("summarizing delegation after lost reconcile")?;
    if remaining == 0 && lost > 0 {
        conn.execute(
            "UPDATE task_delegation_jobs
                SET status = 'lost', updated_at = ?2
              WHERE task_call_id = ?1
                AND status IN ('running', 'backgrounded')",
            params![task_call_id, now],
        )
        .context("marking delegation job lost")?;
    }
    Ok(())
}

fn decode_child(row: &rusqlite::Row<'_>) -> rusqlite::Result<DelegationChildRow> {
    let status: String = row.get(3)?;
    let delivered: i64 = row.get(5)?;
    Ok(DelegationChildRow {
        task_call_id: row.get(0)?,
        label: row.get(1)?,
        child_agent: row.get(2)?,
        status: DelegationStatus::from_str(&status),
        report: row.get(4)?,
        result_delivered: delivered != 0,
    })
}

fn decode_steer(row: &rusqlite::Row<'_>) -> rusqlite::Result<TaskDelegationSteerRow> {
    Ok(TaskDelegationSteerRow {
        id: row.get(0)?,
        task_call_id: row.get(1)?,
        label: row.get(2)?,
        body: row.get(3)?,
        origin_principal: row.get(4)?,
        delivered: row.get::<_, i64>(5)? != 0,
        created_at: row.get(6)?,
        delivered_at: row.get(7)?,
    })
}

fn decode_child_detail(row: &rusqlite::Row<'_>) -> rusqlite::Result<DelegationChildDetail> {
    let status: String = row.get(4)?;
    let delivered: i64 = row.get(6)?;
    Ok(DelegationChildDetail {
        task_call_id: row.get(0)?,
        label: row.get(1)?,
        child_agent: row.get(2)?,
        model: row.get(3)?,
        status: DelegationStatus::from_str(&status),
        report: row.get(5)?,
        result_delivered: delivered != 0,
        started_at: row.get(7)?,
        finished_at: row.get(8)?,
        updated_at: row.get(9)?,
        pending_steers: row.get(10)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_job(db: &Db, task_call_id: &str, children: &[&str]) -> Uuid {
        let session = db.create_session("p", "/tmp/p", "Build").unwrap();
        let inits = children
            .iter()
            .map(|label| DelegationChildInit {
                label,
                child_agent: "explore",
                model: None,
                output_dir: None,
                requested_cwd: None,
                resolved_cwd: None,
                todo_ids_json: None,
            })
            .collect::<Vec<_>>();
        db.upsert_task_delegation_job(
            session.session_id,
            task_call_id,
            Some("fc-1"),
            "Build",
            None,
            &inits,
        )
        .unwrap();
        session.session_id
    }

    #[test]
    fn completed_child_allows_error_prefixed_report_text() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_job(&db, "task-1", &["default"]);

        db.complete_task_delegation_child(
            "task-1",
            "default",
            "Error: bar was unhandled in baz.rs - fixed by adding a guard",
            false,
            None,
        )
        .unwrap();

        let rows = db.list_task_delegation_children(session_id).unwrap();
        assert_eq!(rows[0].status, DelegationStatus::Completed);
        assert_eq!(job_status(&db, "task-1"), DelegationStatus::Completed);
    }

    #[test]
    fn failed_child_uses_explicit_flag_not_report_text() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_job(&db, "task-1", &["default"]);

        db.complete_task_delegation_child("task-1", "default", "ordinary report", true, None)
            .unwrap();

        let rows = db.list_task_delegation_children(session_id).unwrap();
        assert_eq!(rows[0].status, DelegationStatus::Failed);
        assert_eq!(job_status(&db, "task-1"), DelegationStatus::Failed);
    }

    #[test]
    fn error_prefixed_success_child_does_not_taint_job_rollup() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_job(&db, "task-1", &["a", "b"]);

        db.complete_task_delegation_child("task-1", "a", "Error: quoted and fixed", false, None)
            .unwrap();
        db.complete_task_delegation_child("task-1", "b", "plain report", false, None)
            .unwrap();

        let rows = db.list_task_delegation_children(session_id).unwrap();
        assert!(
            rows.iter()
                .all(|row| row.status == DelegationStatus::Completed)
        );
        assert_eq!(job_status(&db, "task-1"), DelegationStatus::Completed);
    }

    #[test]
    fn explicit_failed_child_taints_job_rollup() {
        let db = Db::open_in_memory().unwrap();
        seed_job(&db, "task-1", &["a", "b"]);

        db.complete_task_delegation_child("task-1", "a", "plain report", false, None)
            .unwrap();
        db.complete_task_delegation_child("task-1", "b", "plain report", true, None)
            .unwrap();

        assert_eq!(job_status(&db, "task-1"), DelegationStatus::Failed);
    }

    #[test]
    fn child_delivery_is_durable_and_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/p", "Build").unwrap();
        db.upsert_task_delegation_job(
            session.session_id,
            "task-1",
            Some("fc-1"),
            "Build",
            None,
            &[DelegationChildInit {
                label: "default",
                child_agent: "explore",
                model: None,
                output_dir: None,
                requested_cwd: None,
                resolved_cwd: None,
                todo_ids_json: None,
            }],
        )
        .unwrap();

        assert!(
            db.background_task_delegation_child("task-1", "default")
                .unwrap()
        );
        db.complete_task_delegation_child("task-1", "default", "report", false, None)
            .unwrap();

        let rows = db.undelivered_task_delegation_children("task-1").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, "default");
        assert_eq!(rows[0].status, DelegationStatus::Completed);

        assert!(
            db.mark_task_delegation_child_delivered("task-1", "default")
                .unwrap()
        );
        assert!(
            !db.mark_task_delegation_child_delivered("task-1", "default")
                .unwrap()
        );
        assert!(
            db.undelivered_task_delegation_children("task-1")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn cancellation_is_terminal_and_steers_are_counted_fifo_pending() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/p", "Build").unwrap();
        db.upsert_task_delegation_job(
            session.session_id,
            "task-1",
            Some("fc-1"),
            "Build",
            None,
            &[DelegationChildInit {
                label: "default",
                child_agent: "explore",
                model: None,
                output_dir: None,
                requested_cwd: None,
                resolved_cwd: None,
                todo_ids_json: None,
            }],
        )
        .unwrap();

        db.enqueue_task_delegation_steer("task-1", "default", "first", "agent:task-1")
            .unwrap();
        db.enqueue_task_delegation_steer("task-1", "default", "second", "local:test")
            .unwrap();
        assert!(
            db.cancel_task_delegation_child("task-1", "default")
                .unwrap()
        );
        assert!(
            !db.cancel_task_delegation_child("task-1", "default")
                .unwrap(),
            "second cancel is idempotent"
        );
        db.complete_task_delegation_child("task-1", "default", "late report", false, None)
            .unwrap();

        let rows = db
            .list_task_delegation_children(session.session_id)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, DelegationStatus::Cancelled);
        assert_eq!(rows[0].report.as_deref(), Some("cancelled"));
        assert_eq!(rows[0].pending_steers, 2);
        let drained = db
            .drain_task_delegation_steers("task-1", "default")
            .unwrap();
        assert_eq!(
            drained
                .iter()
                .map(|row| row.body.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        assert_eq!(drained[0].origin_principal, "agent:task-1");
        assert_eq!(drained[1].origin_principal, "local:test");
        let rows = db
            .list_task_delegation_children(session.session_id)
            .unwrap();
        assert_eq!(rows[0].pending_steers, 0);
        assert!(
            db.drain_task_delegation_steers("task-1", "default")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn reconcile_orphaned_task_delegations_marks_active_children_lost_once() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/p", "Build").unwrap();
        db.upsert_task_delegation_job(
            session.session_id,
            "task-1",
            Some("fc-1"),
            "Build",
            None,
            &[DelegationChildInit {
                label: "default",
                child_agent: "explore",
                model: None,
                output_dir: None,
                requested_cwd: None,
                resolved_cwd: None,
                todo_ids_json: None,
            }],
        )
        .unwrap();

        assert_eq!(db.reconcile_orphaned_task_delegations().unwrap(), 1);
        assert_eq!(db.reconcile_orphaned_task_delegations().unwrap(), 0);

        let rows = db
            .list_task_delegation_children(session.session_id)
            .unwrap();
        assert_eq!(rows[0].status, DelegationStatus::Lost);
        assert_eq!(rows[0].report.as_deref(), Some(LOST_RESTART_REPORT));
        assert!(rows[0].finished_at.is_some());
        assert_eq!(job_status(&db, "task-1"), DelegationStatus::Lost);
    }

    #[test]
    fn mark_task_delegation_child_lost_preserves_completed_jobs() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/p", "Build").unwrap();
        db.upsert_task_delegation_job(
            session.session_id,
            "task-1",
            Some("fc-1"),
            "Build",
            None,
            &[
                DelegationChildInit {
                    label: "done",
                    child_agent: "explore",
                    model: None,
                    output_dir: None,
                    requested_cwd: None,
                    resolved_cwd: None,
                    todo_ids_json: None,
                },
                DelegationChildInit {
                    label: "orphan",
                    child_agent: "reviewer",
                    model: None,
                    output_dir: None,
                    requested_cwd: None,
                    resolved_cwd: None,
                    todo_ids_json: None,
                },
            ],
        )
        .unwrap();
        db.complete_task_delegation_child("task-1", "done", "done report", false, None)
            .unwrap();
        db.write_blocking(move |conn| {
            conn.execute(
                "UPDATE task_delegation_jobs SET status = 'completed' WHERE task_call_id = 'task-1'",
                [],
            )?;
            Ok(())
        })
        .unwrap();

        assert!(
            db.mark_task_delegation_child_lost("task-1", "orphan")
                .unwrap()
        );
        assert_eq!(job_status(&db, "task-1"), DelegationStatus::Completed);
    }

    #[test]
    fn lost_reconciled_child_delivers_report_once() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/p", "Build").unwrap();
        db.upsert_task_delegation_job(
            session.session_id,
            "task-1",
            Some("fc-1"),
            "Build",
            None,
            &[DelegationChildInit {
                label: "default",
                child_agent: "explore",
                model: None,
                output_dir: None,
                requested_cwd: None,
                resolved_cwd: None,
                todo_ids_json: None,
            }],
        )
        .unwrap();

        assert_eq!(db.reconcile_orphaned_task_delegations().unwrap(), 1);
        let rows = db.undelivered_task_delegation_children("task-1").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, DelegationStatus::Lost);
        assert_eq!(rows[0].report.as_deref(), Some(LOST_RESTART_REPORT));

        assert!(
            db.mark_task_delegation_child_delivered("task-1", "default")
                .unwrap()
        );
        assert!(
            db.undelivered_task_delegation_children("task-1")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn complete_child_rolls_back_when_job_update_fails() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_job(&db, "task-rollback", &["default"]);
        db.write_blocking(move |conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER fail_task_job_update
                 BEFORE UPDATE ON task_delegation_jobs
                 BEGIN
                   SELECT RAISE(ABORT, 'injected job update failure');
                 END;",
            )?;
            Ok(())
        })
        .unwrap();

        let err = db
            .complete_task_delegation_child("task-rollback", "default", "report", false, None)
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("injected job update failure"),
            "unexpected error: {err:#}"
        );

        let rows = db.list_task_delegation_children(session_id).unwrap();
        assert_eq!(rows[0].status, DelegationStatus::Running);
        assert_eq!(rows[0].report, None);
        assert_eq!(job_status(&db, "task-rollback"), DelegationStatus::Running);
    }

    fn job_status(db: &Db, task_call_id: &str) -> DelegationStatus {
        db.read_blocking(|conn| {
            let status: String = conn.query_row(
                "SELECT status FROM task_delegation_jobs WHERE task_call_id = ?1",
                params![task_call_id],
                |row| row.get(0),
            )?;
            Ok(DelegationStatus::from_str(&status))
        })
        .unwrap()
    }
}
