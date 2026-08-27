//! Durable noninteractive `task` delegation state (migration 0046).

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;
use crate::db::task_delegation_payloads::{NewTaskDelegationPayload, TaskDelegationPayloadRow};

const LOST_RESTART_REPORT: &str = "lost: daemon restarted before this delegation finished";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationStatus {
    /// The durable task/payload record exists, but no executor has been
    /// advertised yet. A child leaves this state only in the transaction that
    /// stores its first recoverable continuation snapshot.
    Created,
    Running,
    Backgrounded,
    Completed,
    Failed,
    Cancelled,
    PausedPendingTool,
    Lost,
}

impl DelegationStatus {
    pub const ALL: [Self; 8] = [
        Self::Created,
        Self::Running,
        Self::Backgrounded,
        Self::Completed,
        Self::Failed,
        Self::Cancelled,
        Self::PausedPendingTool,
        Self::Lost,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
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
            "created" => Self::Created,
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

#[derive(Debug, Clone, Copy)]
pub struct TaskDelegationJobUpsert<'a> {
    pub session_id: Uuid,
    pub task_call_id: &'a str,
    pub function_call_id: Option<&'a str>,
    pub parent_agent: &'a str,
    pub original_args_json: Option<&'a str>,
    pub children: &'a [DelegationChildInit<'a>],
}

#[derive(Debug, Clone)]
struct DelegationChildInitOwned {
    label: String,
    child_uuid: String,
    child_agent: String,
    model: Option<String>,
    output_dir: Option<String>,
    requested_cwd: Option<String>,
    resolved_cwd: Option<String>,
    todo_ids_json: Option<String>,
}

#[derive(Debug, Clone)]
struct TaskDelegationJobWrite {
    session_id: Uuid,
    task_call_id: String,
    function_call_id: Option<String>,
    parent_agent: String,
    original_args_json: Option<String>,
    children: Vec<DelegationChildInitOwned>,
}

/// Decode the DAG embedded in the canonical batch job record. The engine has
/// already validated this at tool ingress, but the storage boundary repeats the
/// checks before inserting foreign-keyed rows so recovery never sees an edge
/// that could not have been scheduled by a live executor.
fn declared_batch_dependency_edges(
    original_args_json: Option<&str>,
) -> Result<Vec<(String, String)>> {
    let Some(original_args_json) = original_args_json else {
        return Ok(Vec::new());
    };
    let args: serde_json::Value = serde_json::from_str(original_args_json)
        .context("decoding task delegation original args for dependency edges")?;
    let Some(entries) = args.get("entries") else {
        // Single and interactive delegations have no batch dependency graph.
        return Ok(Vec::new());
    };
    let entries = entries
        .as_array()
        .context("batch task delegation entries must be an array")?;
    let mut labels = std::collections::HashSet::with_capacity(entries.len());
    for entry in entries {
        let label = entry
            .get("label")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .context("batch task delegation entry is missing label")?;
        anyhow::ensure!(
            labels.insert(label.to_string()),
            "batch task delegation contains duplicate label `{label}`"
        );
    }

    let mut edges = Vec::new();
    let mut graph = std::collections::HashMap::<String, Vec<String>>::new();
    for entry in entries {
        let label = entry
            .get("label")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .expect("labels were validated above");
        let dependencies = match entry.get("depends_on") {
            None => Vec::new(),
            Some(value) => value
                .as_array()
                .with_context(|| format!("batch entry `{label}` has non-array depends_on"))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::trim)
                        .filter(|dependency| !dependency.is_empty())
                        .map(str::to_string)
                        .with_context(|| {
                            format!("batch entry `{label}` has invalid depends_on label")
                        })
                })
                .collect::<Result<Vec<_>>>()?,
        };
        let mut unique_dependencies = std::collections::HashSet::new();
        for dependency in &dependencies {
            anyhow::ensure!(
                dependency != label,
                "batch entry `{label}` cannot depend on itself"
            );
            anyhow::ensure!(
                labels.contains(dependency),
                "batch entry `{label}` depends on unknown label `{dependency}`"
            );
            anyhow::ensure!(
                unique_dependencies.insert(dependency.as_str()),
                "batch entry `{label}` lists dependency `{dependency}` more than once"
            );
            edges.push((label.to_string(), dependency.clone()));
        }
        graph.insert(label.to_string(), dependencies);
    }

    fn visit(
        label: &str,
        graph: &std::collections::HashMap<String, Vec<String>>,
        visiting: &mut std::collections::HashSet<String>,
        visited: &mut std::collections::HashSet<String>,
    ) -> Result<()> {
        if visited.contains(label) {
            return Ok(());
        }
        anyhow::ensure!(
            visiting.insert(label.to_string()),
            "batch dependency cycle includes `{label}`"
        );
        for dependency in graph
            .get(label)
            .expect("dependency labels were validated above")
        {
            visit(dependency, graph, visiting, visited)?;
        }
        visiting.remove(label);
        visited.insert(label.to_string());
        Ok(())
    }

    let mut visiting = std::collections::HashSet::new();
    let mut visited = std::collections::HashSet::new();
    for label in &labels {
        visit(label, &graph, &mut visiting, &mut visited)?;
    }
    Ok(edges)
}

impl From<TaskDelegationJobUpsert<'_>> for TaskDelegationJobWrite {
    fn from(value: TaskDelegationJobUpsert<'_>) -> Self {
        Self {
            session_id: value.session_id,
            task_call_id: value.task_call_id.to_owned(),
            function_call_id: value.function_call_id.map(str::to_owned),
            parent_agent: value.parent_agent.to_owned(),
            original_args_json: value.original_args_json.map(str::to_owned),
            children: value
                .children
                .iter()
                .map(DelegationChildInitOwned::from)
                .collect(),
        }
    }
}

impl From<&DelegationChildInit<'_>> for DelegationChildInitOwned {
    fn from(value: &DelegationChildInit<'_>) -> Self {
        Self {
            label: value.label.to_owned(),
            child_uuid: Uuid::new_v4().to_string(),
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
pub struct DelegationExportChild {
    pub label: String,
    pub child_agent: String,
    pub model: Option<String>,
    pub status: String,
    pub report: Option<String>,
    pub output_dir: Option<String>,
    pub todo_ids_json: Option<String>,
    pub result_delivered: bool,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub requested_cwd: Option<String>,
    pub resolved_cwd: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DelegationExportJob {
    pub task_call_id: String,
    pub function_call_id: Option<String>,
    pub parent_session_id: Uuid,
    pub parent_agent: String,
    pub original_args_json: Option<String>,
    pub status: String,
    pub ack_delivered: bool,
    pub final_delivered: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub children: Vec<DelegationExportChild>,
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
    /// Publish one or more newly-created delegated executors only after every
    /// exact first continuation is durable.  A task child must never be
    /// visible as `running` with a null snapshot: such a row has no legitimate
    /// restart owner and used to strand a tree child indefinitely after a
    /// crash between launch bookkeeping and the first model turn.
    ///
    /// This is intentionally a batch operation.  A batch task starts all
    /// sibling lifecycle nodes as one graph, so publishing the first half and
    /// failing the second would manufacture a partial recovery set.
    pub async fn activate_task_delegation_children_with_snapshots(
        &self,
        task_call_id: &str,
        snapshots: Vec<(String, String)>,
    ) -> Result<bool> {
        anyhow::ensure!(
            !snapshots.is_empty(),
            "task delegation activation requires at least one child snapshot"
        );
        let task_call_id = task_call_id.to_owned();
        let now = Utc::now().timestamp();
        self.transaction(move |conn| {
            let mut labels = std::collections::HashSet::with_capacity(snapshots.len());
            for (label, snapshot_json) in &snapshots {
                anyhow::ensure!(
                    labels.insert(label),
                    "task delegation activation contains duplicate label `{label}`"
                );
                anyhow::ensure!(
                    !snapshot_json.trim().is_empty(),
                    "task delegation activation snapshot is empty"
                );
                let changed = conn.execute(
                    "UPDATE task_delegation_children
                        SET status = 'running', snapshot_json = ?3,
                            started_at = COALESCE(started_at, ?4), updated_at = ?4
                      WHERE task_call_id = ?1 AND label = ?2 AND status = 'created'",
                    params![&task_call_id, label, snapshot_json, now],
                )?;
                if changed == 1 {
                    continue;
                }
                // A transport retry can arrive after the executor has already
                // advanced its snapshot. Never overwrite that continuation;
                // merely prove that this exact child was published before the
                // retry is allowed to bind another in-memory handle.
                let existing: Option<(String, Option<String>)> = conn
                    .query_row(
                        "SELECT status, snapshot_json FROM task_delegation_children
                          WHERE task_call_id = ?1 AND label = ?2",
                        params![&task_call_id, label],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                let Some((status, existing_snapshot)) = existing else {
                    anyhow::bail!("task delegation activation child `{label}` is missing");
                };
                anyhow::ensure!(
                    matches!(
                        status.as_str(),
                        "running" | "backgrounded" | "paused_pending_tool"
                    ) && existing_snapshot.is_some(),
                    "task delegation child `{label}` is not safely published"
                );
            }
            Ok(true)
        })
        .await
    }

    /// Replace the durable continuation snapshot for one still-live child.
    /// Recovery treats this as executor state, not an optional diagnostic: a
    /// stale or malformed snapshot is rejected by the caller rather than
    /// silently starting the task from a different prompt.
    pub async fn persist_task_delegation_snapshot(
        &self,
        task_call_id: &str,
        label: &str,
        snapshot_json: &str,
    ) -> Result<bool> {
        let task_call_id = task_call_id.to_owned();
        let label = label.to_owned();
        let snapshot_json = snapshot_json.to_owned();
        let now = Utc::now().timestamp();
        self.write(move |conn| {
            let changed = conn.execute(
                "UPDATE task_delegation_children
                    SET snapshot_json = ?3, updated_at = ?4
                  WHERE task_call_id = ?1
                    AND label = ?2
                    AND status IN ('running', 'backgrounded', 'paused_pending_tool')",
                params![task_call_id, label, snapshot_json, now],
            )?;
            Ok(changed == 1)
        })
        .await
    }

    pub async fn upsert_task_delegation_job(
        &self,
        session_id: Uuid,
        task_call_id: &str,
        function_call_id: Option<&str>,
        parent_agent: &str,
        original_args_json: Option<&str>,
        children: &[DelegationChildInit<'_>],
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let job = TaskDelegationJobWrite::from(TaskDelegationJobUpsert {
            session_id,
            task_call_id,
            function_call_id,
            parent_agent,
            original_args_json,
            children,
        });
        // The ownership read in `upsert_task_delegation_job_conn` must share a
        // `BEGIN IMMEDIATE` transaction with the conflict insert and every
        // child write.  A plain queued write only serializes one process: two
        // daemon connections could both observe no owner and let the loser
        // update the winner's job on the conflict path.
        self.transaction(move |conn| Self::upsert_task_delegation_job_conn(conn, job, now))
            .await
    }

    pub async fn upsert_task_delegation_job_and_payload(
        &self,
        job: TaskDelegationJobUpsert<'_>,
        payload: NewTaskDelegationPayload<'_>,
    ) -> Result<TaskDelegationPayloadRow> {
        let mut rows = self
            .upsert_task_delegation_job_and_payloads(job, vec![payload])
            .await?;
        rows.pop()
            .context("combined delegation payload insert returned no rows")
    }

    pub async fn upsert_task_delegation_job_and_payloads(
        &self,
        job: TaskDelegationJobUpsert<'_>,
        payloads: Vec<NewTaskDelegationPayload<'_>>,
    ) -> Result<Vec<TaskDelegationPayloadRow>> {
        let now = Utc::now().timestamp();
        let job = TaskDelegationJobWrite::from(job);
        let mut prepared_payloads = Vec::with_capacity(payloads.len());
        for payload in payloads {
            prepared_payloads.push(self.prepare_task_delegation_payload(payload).await?);
        }
        // Keep the owner check, job, children, and payload rows under the
        // same immediate transaction.  `upsert_task_delegation_job_conn` is a
        // connection helper specifically so this does not nest transactions.
        let result = self
            .transaction(move |conn| {
                Self::upsert_task_delegation_job_conn(conn, job, now)?;
                let mut rows = Vec::with_capacity(prepared_payloads.len());
                for prepared_payload in prepared_payloads {
                    rows.push(Self::insert_prepared_task_delegation_payload_conn(
                        conn,
                        prepared_payload,
                    )?);
                }
                Ok(rows)
            })
            .await;
        let rows = match result {
            Ok(rows) => rows,
            Err(error) => {
                if let Err(reconcile_error) =
                    self.reconcile_delegation_sidecar_prepare_intents().await
                {
                    tracing::warn!(%reconcile_error, "delegation sidecar prepare recovery remains pending after transaction failure");
                }
                return Err(error);
            }
        };
        if let Err(error) = self.reconcile_delegation_sidecar_cleanup_intents().await {
            tracing::warn!(%error, "replaced delegation sidecar cleanup remains durable and pending");
        }
        Ok(rows)
    }

    fn upsert_task_delegation_job_conn(
        conn: &Connection,
        job: TaskDelegationJobWrite,
        now: i64,
    ) -> Result<()> {
        let task_call_id = job.task_call_id;
        let function_call_id = job.function_call_id;
        let session_id = job.session_id;
        let parent_agent = job.parent_agent;
        let original_args_json = job.original_args_json;
        let children = job.children;
        // Treat the persisted original args as the durable source of the batch
        // graph. Re-validate before writing so a malformed or hostile caller
        // cannot create edges that the executor would not accept.
        let dependency_edges = declared_batch_dependency_edges(original_args_json.as_deref())?;
        let existing_owner: Option<String> = conn
            .query_row(
                "SELECT parent_session_id FROM task_delegation_jobs WHERE task_call_id = ?1",
                [&task_call_id],
                |row| row.get(0),
            )
            .optional()
            .context("checking task delegation job ownership")?;
        if let Some(existing_owner) = existing_owner {
            anyhow::ensure!(
                existing_owner == session_id.to_string(),
                "task delegation job belongs to another session"
            );
        }
        conn.execute(
            "INSERT INTO task_delegation_jobs (
                    task_call_id, function_call_id, parent_session_id, parent_agent,
                    original_args_json, status, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'running', ?6, ?6)
                 ON CONFLICT(task_call_id) DO UPDATE SET
                    function_call_id = excluded.function_call_id,
                    parent_agent = excluded.parent_agent,
                    original_args_json = COALESCE(excluded.original_args_json, task_delegation_jobs.original_args_json),
                    updated_at = excluded.updated_at",
            params![
                &task_call_id,
                function_call_id.as_deref(),
                session_id.to_string(),
                &parent_agent,
                original_args_json.as_deref(),
                now,
            ],
        )
        .context("upserting task delegation job")?;

        for child in children {
            conn.execute(
                "INSERT INTO task_delegation_children (
                        task_call_id, label, child_uuid, child_agent, model, status, output_dir,
                        requested_cwd, resolved_cwd, todo_ids_json, started_at,
                        created_at, updated_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 'created', ?6, ?7, ?8, ?9, NULL, ?10, ?10)
                     ON CONFLICT(task_call_id, label) DO UPDATE SET
                        child_agent = excluded.child_agent,
                        model = excluded.model,
                        output_dir = excluded.output_dir,
                        requested_cwd = excluded.requested_cwd,
                        resolved_cwd = excluded.resolved_cwd,
                        todo_ids_json = excluded.todo_ids_json,
                        updated_at = excluded.updated_at",
                params![
                    &task_call_id,
                    &child.label,
                    &child.child_uuid,
                    &child.child_agent,
                    child.model.as_deref(),
                    child.output_dir.as_deref(),
                    child.requested_cwd.as_deref(),
                    child.resolved_cwd.as_deref(),
                    child.todo_ids_json.as_deref(),
                    now,
                ],
            )
            .context("upserting task delegation child")?;
        }
        conn.execute(
            "DELETE FROM task_delegation_dependency_edges WHERE task_call_id = ?1",
            [&task_call_id],
        )
        .context("replacing task delegation dependency edges")?;
        for (dependent_label, prerequisite_label) in dependency_edges {
            conn.execute(
                "INSERT INTO task_delegation_dependency_edges (
                        task_call_id, dependent_label, prerequisite_label
                 ) VALUES (?1, ?2, ?3)",
                params![&task_call_id, dependent_label, prerequisite_label],
            )
            .context("persisting task delegation dependency edge")?;
        }
        Ok(())
    }

    pub async fn background_task_delegation_child(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Result<bool> {
        let now = Utc::now().timestamp();
        let task_call_id = task_call_id.to_owned();
        let label = label.to_owned();
        self.write(move |conn| {
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
        .await
    }

    pub async fn complete_task_delegation_child(
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
        self.write(move |conn| {
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
        .await
    }

    pub async fn undelivered_task_delegation_children(
        &self,
        task_call_id: &str,
    ) -> Result<Vec<DelegationChildRow>> {
        let task_call_id = task_call_id.to_owned();
        self.read(move |conn| {
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
        .await
    }

    pub async fn mark_task_delegation_child_delivered(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Result<bool> {
        let now = Utc::now().timestamp();
        let task_call_id = task_call_id.to_owned();
        let label = label.to_owned();
        self.write(move |conn| {
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
        .await
    }

    pub fn list_task_delegation_export_jobs_conn(
        conn: &Connection,
        session_id: Uuid,
    ) -> Result<Vec<DelegationExportJob>> {
        let mut jobs = conn.prepare("SELECT task_call_id, function_call_id, parent_session_id, parent_agent, original_args_json, status, ack_delivered, final_delivered, created_at, updated_at FROM task_delegation_jobs WHERE parent_session_id = ?1 ORDER BY created_at, task_call_id").context("preparing delegation export jobs")?;
        let job_rows = jobs.query_map([session_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get(1)?,
                row.get::<_, String>(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get::<_, i64>(6)? != 0,
                row.get::<_, i64>(7)? != 0,
                row.get(8)?,
                row.get(9)?,
            ))
        })?;
        let mut out = Vec::new();
        for job in job_rows {
            let (
                task_call_id,
                function_call_id,
                parent_session_id,
                parent_agent,
                original_args_json,
                status,
                ack_delivered,
                final_delivered,
                created_at,
                updated_at,
            ) = job.context("decoding delegation export job")?;
            let parent_session_id = Uuid::parse_str(&parent_session_id)
                .context("decoding delegation export session id")?;
            let mut children_stmt = conn.prepare("SELECT label, child_agent, model, status, report, output_dir, todo_ids_json, result_delivered, started_at, finished_at, created_at, updated_at, requested_cwd, resolved_cwd FROM task_delegation_children WHERE task_call_id = ?1 ORDER BY label")?;
            let children = children_stmt
                .query_map([&task_call_id], |row| {
                    Ok(DelegationExportChild {
                        label: row.get(0)?,
                        child_agent: row.get(1)?,
                        model: row.get(2)?,
                        status: row.get(3)?,
                        report: row.get(4)?,
                        output_dir: row.get(5)?,
                        todo_ids_json: row.get(6)?,
                        result_delivered: row.get::<_, i64>(7)? != 0,
                        started_at: row.get(8)?,
                        finished_at: row.get(9)?,
                        created_at: row.get(10)?,
                        updated_at: row.get(11)?,
                        requested_cwd: row.get(12)?,
                        resolved_cwd: row.get(13)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()
                .context("decoding delegation export children")?;
            out.push(DelegationExportJob {
                task_call_id,
                function_call_id,
                parent_session_id,
                parent_agent,
                original_args_json,
                status,
                ack_delivered,
                final_delivered,
                created_at,
                updated_at,
                children,
            });
        }
        Ok(out)
    }

    pub async fn list_task_delegation_children(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<DelegationChildDetail>> {
        self.read(move |conn| {
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
        .await
    }

    pub async fn cancel_task_delegation_child(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Result<bool> {
        let now = Utc::now().timestamp();
        let task_call_id = task_call_id.to_owned();
        let label = label.to_owned();
        self.write(move |conn| {
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
        .await
    }

    pub async fn mark_task_delegation_child_lost(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Result<bool> {
        let now = Utc::now().timestamp();
        let task_call_id = task_call_id.to_owned();
        let label = label.to_owned();
        self.write(move |conn| {
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
        .await
    }

    pub async fn reconcile_orphaned_task_delegations(&self) -> Result<usize> {
        // Restart recovery reattaches these executors from their durable
        // launch payload/snapshot. A missing in-memory worker is never proof
        // that a child was lost, so this historical boot hook deliberately
        // performs no lifecycle mutation. Explicit operator cancellation and
        // irrecoverable descriptor validation retain their narrow terminal
        // paths elsewhere.
        Ok(0)
    }

    pub async fn enqueue_task_delegation_steer(
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
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO task_delegation_steers (task_call_id, label, body, origin_principal, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![task_call_id, label, body, origin_principal, now],
            )
            .context("enqueueing task delegation steer")?;
            Ok(())
        })
        .await
    }

    pub async fn drain_task_delegation_steers(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Result<Vec<TaskDelegationSteerRow>> {
        let now = Utc::now().timestamp();
        let task_call_id = task_call_id.to_owned();
        let label = label.to_owned();
        self.write(move |conn| {
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
        .await
    }

    pub async fn list_task_delegation_steers(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<TaskDelegationSteerRow>> {
        self.read(move |conn| Self::list_task_delegation_steers_conn(conn, session_id))
            .await
    }

    pub fn list_task_delegation_steers_conn(
        conn: &Connection,
        session_id: Uuid,
    ) -> Result<Vec<TaskDelegationSteerRow>> {
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
    }
}

fn immediate_transaction<T>(
    conn: &rusqlite::Connection,
    begin_context: &str,
    commit_context: &str,
    f: impl FnOnce() -> Result<T>,
) -> Result<T> {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    conn.execute_batch("BEGIN IMMEDIATE")
        .with_context(|| begin_context.to_string())?;
    // Mirror `super::run_transaction`: a failed COMMIT — or a panic inside `f` —
    // must roll back. Otherwise the shared single writer connection is left
    // inside an open `BEGIN IMMEDIATE`, poisoning every subsequent delegation
    // write for the life of the daemon (this previously only rolled back on a
    // clean `Err`, leaking the transaction on a COMMIT failure or panic).
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(value)) => match conn.execute_batch("COMMIT") {
            Ok(()) => Ok(value),
            Err(error) => {
                let primary = anyhow::Error::new(error).context(commit_context.to_string());
                finish_immediate_rollback(conn, primary)
            }
        },
        Ok(Err(error)) => finish_immediate_rollback(conn, error),
        Err(_) => finish_immediate_rollback(conn, anyhow::anyhow!("db transaction job panicked")),
    }
}

/// Roll back the current transaction and surface `primary`, chaining a rollback
/// failure the way `super::run_transaction` does so a wedged connection is not
/// silently masked.
fn finish_immediate_rollback<T>(conn: &rusqlite::Connection, primary: anyhow::Error) -> Result<T> {
    match super::rollback_transaction(conn) {
        Ok(()) => Err(primary),
        Err(rollback) => Err(super::TransactionRollbackFailed { primary, rollback }.into()),
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

    #[test]
    fn immediate_transaction_commits_on_success() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (x INTEGER);").unwrap();
        let out = immediate_transaction(&conn, "begin", "commit", || -> Result<i64> {
            conn.execute("INSERT INTO t (x) VALUES (1)", [])?;
            Ok(42)
        })
        .unwrap();
        assert_eq!(out, 42);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn immediate_transaction_rolls_back_on_error_and_leaves_connection_usable() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let result = immediate_transaction(&conn, "begin", "commit", || -> Result<()> {
            Err(anyhow::anyhow!("body failed"))
        });
        assert!(result.is_err());
        // The connection must not be wedged inside an open `BEGIN IMMEDIATE`.
        conn.execute_batch("BEGIN IMMEDIATE; COMMIT;")
            .expect("connection left inside an open transaction");
    }

    #[test]
    fn immediate_transaction_rolls_back_on_panic_and_leaves_connection_usable() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        // A panic inside the body is caught, rolled back, and surfaced as an
        // error — the connection is not left inside an open transaction (which
        // would poison every later write on the shared writer connection).
        let result = immediate_transaction(&conn, "begin", "commit", || -> Result<()> {
            panic!("body panicked");
        });
        assert!(result.is_err());
        conn.execute_batch("BEGIN IMMEDIATE; COMMIT;")
            .expect("connection left inside an open transaction after a panic");
    }

    async fn seed_job(db: &Db, task_call_id: &str, children: &[&str]) -> Uuid {
        let session = db.create_session("p", "/tmp/p", "Build").await.unwrap();
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
        .await
        .unwrap();
        db.activate_task_delegation_children_with_snapshots(
            task_call_id,
            children
                .iter()
                .map(|label| {
                    (
                        (*label).to_string(),
                        r#"{"version":1,"history":[]}"#.to_string(),
                    )
                })
                .collect(),
        )
        .await
        .unwrap();
        session.session_id
    }

    async fn activate_test_children(db: &Db, task_call_id: &str, labels: &[&str]) {
        db.activate_task_delegation_children_with_snapshots(
            task_call_id,
            labels
                .iter()
                .map(|label| {
                    (
                        (*label).to_string(),
                        r#"{"version":1,"history":[]}"#.to_string(),
                    )
                })
                .collect(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn batch_dependency_edges_are_durable_and_reject_cycles() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/p", "Build").await.unwrap();
        let children = ["independent", "base", "dependent"]
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
        let args = r#"{
            "entries": [
                {"label":"independent","depends_on":[]},
                {"label":"base","depends_on":[]},
                {"label":"dependent","depends_on":["base"]}
            ]
        }"#;
        db.upsert_task_delegation_job(
            session.session_id,
            "dependency-job",
            None,
            "Build",
            Some(args),
            &children,
        )
        .await
        .unwrap();
        let edges = db
            .read(|conn| {
                let mut statement = conn.prepare(
                    "SELECT dependent_label, prerequisite_label
                       FROM task_delegation_dependency_edges
                      WHERE task_call_id = 'dependency-job'",
                )?;
                let rows = statement
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await
            .unwrap();
        assert_eq!(edges, vec![("dependent".to_string(), "base".to_string())]);

        let cycle = r#"{
            "entries": [
                {"label":"left","depends_on":["right"]},
                {"label":"right","depends_on":["left"]}
            ]
        }"#;
        assert!(declared_batch_dependency_edges(Some(cycle)).is_err());
    }

    #[tokio::test]
    async fn db_async_delegation_upsert_roundtrip_through_async_api() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_job(&db, "task-async-roundtrip", &["default"]).await;

        let rows = db.list_task_delegation_children(session_id).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].task_call_id, "task-async-roundtrip");
        assert_eq!(rows[0].label, "default");
        assert_eq!(rows[0].status, DelegationStatus::Running);
    }

    #[tokio::test]
    async fn child_is_not_running_until_its_initial_snapshot_is_published() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/p", "Build").await.unwrap();
        let children = [DelegationChildInit {
            label: "default",
            child_agent: "explore",
            model: None,
            output_dir: None,
            requested_cwd: None,
            resolved_cwd: None,
            todo_ids_json: None,
        }];
        db.upsert_task_delegation_job(
            session.session_id,
            "task-initial-snapshot",
            None,
            "Build",
            None,
            &children,
        )
        .await
        .unwrap();
        let before = db
            .list_task_delegation_children(session.session_id)
            .await
            .unwrap();
        assert_eq!(before[0].status, DelegationStatus::Created);
        assert!(before[0].started_at.is_none());

        assert!(
            db.activate_task_delegation_children_with_snapshots(
                "task-initial-snapshot",
                vec![(
                    "default".to_string(),
                    r#"{"version":2,"history":[],"next_prompt":{"User":{"content":[]}}}"#
                        .to_string(),
                )],
            )
            .await
            .unwrap()
        );
        let after = db
            .list_task_delegation_children(session.session_id)
            .await
            .unwrap();
        assert_eq!(after[0].status, DelegationStatus::Running);
        assert!(after[0].started_at.is_some());
    }

    #[tokio::test]
    async fn db_async_delegation_row_and_payload_are_written_atomically() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/p", "Build").await.unwrap();
        let reader_db = db.clone();
        let session_id = session.session_id;
        let reader = tokio::spawn(async move {
            for _ in 0..128 {
                let rows = reader_db
                    .list_task_delegation_children(session_id)
                    .await
                    .unwrap();
                if rows.iter().any(|row| row.task_call_id == "task-atomic") {
                    assert!(
                        reader_db
                            .task_delegation_payload("task-atomic", "default")
                            .await
                            .unwrap()
                            .is_some(),
                        "reader observed delegation row without payload"
                    );
                }
            }
        });
        let children = [DelegationChildInit {
            label: "default",
            child_agent: "explore",
            model: None,
            output_dir: None,
            requested_cwd: None,
            resolved_cwd: None,
            todo_ids_json: None,
        }];
        let row = db
            .upsert_task_delegation_job_and_payload(
                TaskDelegationJobUpsert {
                    session_id: session.session_id,
                    task_call_id: "task-atomic",
                    function_call_id: Some("fc-atomic"),
                    parent_agent: "Build",
                    original_args_json: None,
                    children: &children,
                },
                NewTaskDelegationPayload {
                    task_call_id: "task-atomic",
                    function_call_id: Some("fc-atomic"),
                    parent_session_id: session.session_id,
                    parent_agent: "Build",
                    label: "default",
                    child_agent: "explore",
                    prompt: "atomic prompt",
                },
            )
            .await
            .unwrap();
        reader.await.unwrap();
        assert_eq!(row.label, "default");
        assert_eq!(
            db.load_task_delegation_payload("task-atomic", "default")
                .await
                .unwrap()
                .body,
            "atomic prompt"
        );
    }

    #[tokio::test]
    async fn db_async_delegation_cancelled_upsert_leaves_no_orphan_row() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/p", "Build").await.unwrap();
        let children = [DelegationChildInit {
            label: "default",
            child_agent: "explore",
            model: None,
            output_dir: None,
            requested_cwd: None,
            resolved_cwd: None,
            todo_ids_json: None,
        }];
        let future = db.upsert_task_delegation_job_and_payload(
            TaskDelegationJobUpsert {
                session_id: session.session_id,
                task_call_id: "task-dropped",
                function_call_id: Some("fc-dropped"),
                parent_agent: "Build",
                original_args_json: None,
                children: &children,
            },
            NewTaskDelegationPayload {
                task_call_id: "task-dropped",
                function_call_id: Some("fc-dropped"),
                parent_session_id: session.session_id,
                parent_agent: "Build",
                label: "default",
                child_agent: "explore",
                prompt: "dropped prompt",
            },
        );
        drop(future);

        assert!(
            db.list_task_delegation_children(session.session_id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            db.task_delegation_payload("task-dropped", "default")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn completed_child_allows_error_prefixed_report_text() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_job(&db, "task-1", &["default"]).await;

        db.complete_task_delegation_child(
            "task-1",
            "default",
            "Error: bar was unhandled in baz.rs - fixed by adding a guard",
            false,
            None,
        )
        .await
        .unwrap();

        let rows = db.list_task_delegation_children(session_id).await.unwrap();
        assert_eq!(rows[0].status, DelegationStatus::Completed);
        assert_eq!(job_status(&db, "task-1").await, DelegationStatus::Completed);
    }

    #[tokio::test]
    async fn failed_child_uses_explicit_flag_not_report_text() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_job(&db, "task-1", &["default"]).await;

        db.complete_task_delegation_child("task-1", "default", "ordinary report", true, None)
            .await
            .unwrap();

        let rows = db.list_task_delegation_children(session_id).await.unwrap();
        assert_eq!(rows[0].status, DelegationStatus::Failed);
        assert_eq!(job_status(&db, "task-1").await, DelegationStatus::Failed);
    }

    #[tokio::test]
    async fn error_prefixed_success_child_does_not_taint_job_rollup() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_job(&db, "task-1", &["a", "b"]).await;

        db.complete_task_delegation_child("task-1", "a", "Error: quoted and fixed", false, None)
            .await
            .unwrap();
        db.complete_task_delegation_child("task-1", "b", "plain report", false, None)
            .await
            .unwrap();

        let rows = db.list_task_delegation_children(session_id).await.unwrap();
        assert!(
            rows.iter()
                .all(|row| row.status == DelegationStatus::Completed)
        );
        assert_eq!(job_status(&db, "task-1").await, DelegationStatus::Completed);
    }

    #[tokio::test]
    async fn explicit_failed_child_taints_job_rollup() {
        let db = Db::open_in_memory().unwrap();
        seed_job(&db, "task-1", &["a", "b"]).await;

        db.complete_task_delegation_child("task-1", "a", "plain report", false, None)
            .await
            .unwrap();
        db.complete_task_delegation_child("task-1", "b", "plain report", true, None)
            .await
            .unwrap();

        assert_eq!(job_status(&db, "task-1").await, DelegationStatus::Failed);
    }

    #[tokio::test]
    async fn child_delivery_is_durable_and_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/p", "Build").await.unwrap();
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
        .await
        .unwrap();

        activate_test_children(&db, "task-1", &["default"]).await;

        assert!(
            db.background_task_delegation_child("task-1", "default")
                .await
                .unwrap()
        );
        db.complete_task_delegation_child("task-1", "default", "report", false, None)
            .await
            .unwrap();

        let rows = db
            .undelivered_task_delegation_children("task-1")
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, "default");
        assert_eq!(rows[0].status, DelegationStatus::Completed);

        assert!(
            db.mark_task_delegation_child_delivered("task-1", "default")
                .await
                .unwrap()
        );
        assert!(
            !db.mark_task_delegation_child_delivered("task-1", "default")
                .await
                .unwrap()
        );
        assert!(
            db.undelivered_task_delegation_children("task-1")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn cancellation_is_terminal_and_steers_are_counted_fifo_pending() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/p", "Build").await.unwrap();
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
        .await
        .unwrap();

        activate_test_children(&db, "task-1", &["default"]).await;

        db.enqueue_task_delegation_steer("task-1", "default", "first", "agent:task-1")
            .await
            .unwrap();
        db.enqueue_task_delegation_steer("task-1", "default", "second", "local:test")
            .await
            .unwrap();
        assert!(
            db.cancel_task_delegation_child("task-1", "default")
                .await
                .unwrap()
        );
        assert!(
            !db.cancel_task_delegation_child("task-1", "default")
                .await
                .unwrap(),
            "second cancel is idempotent"
        );
        db.complete_task_delegation_child("task-1", "default", "late report", false, None)
            .await
            .unwrap();

        let rows = db
            .list_task_delegation_children(session.session_id)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, DelegationStatus::Cancelled);
        assert_eq!(rows[0].report.as_deref(), Some("cancelled"));
        assert_eq!(rows[0].pending_steers, 2);
        let drained = db
            .drain_task_delegation_steers("task-1", "default")
            .await
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
            .await
            .unwrap();
        assert_eq!(rows[0].pending_steers, 0);
        assert!(
            db.drain_task_delegation_steers("task-1", "default")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn reconcile_orphaned_task_delegations_preserves_recoverable_children() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/p", "Build").await.unwrap();
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
        .await
        .unwrap();

        activate_test_children(&db, "task-1", &["default"]).await;

        assert_eq!(db.reconcile_orphaned_task_delegations().await.unwrap(), 0);
        assert_eq!(db.reconcile_orphaned_task_delegations().await.unwrap(), 0);

        let rows = db
            .list_task_delegation_children(session.session_id)
            .await
            .unwrap();
        assert_eq!(rows[0].status, DelegationStatus::Running);
        assert!(rows[0].report.is_none());
        assert!(rows[0].finished_at.is_none());
        assert_eq!(job_status(&db, "task-1").await, DelegationStatus::Running);
    }

    #[tokio::test]
    async fn mark_task_delegation_child_lost_preserves_completed_jobs() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/p", "Build").await.unwrap();
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
        .await
        .unwrap();
        activate_test_children(&db, "task-1", &["done", "orphan"]).await;
        db.complete_task_delegation_child("task-1", "done", "done report", false, None)
            .await
            .unwrap();
        db.write(move |conn| {
            conn.execute(
                "UPDATE task_delegation_jobs SET status = 'completed' WHERE task_call_id = 'task-1'",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        assert!(
            db.mark_task_delegation_child_lost("task-1", "orphan")
                .await
                .unwrap()
        );
        assert_eq!(job_status(&db, "task-1").await, DelegationStatus::Completed);
    }

    #[tokio::test]
    async fn restart_reconcile_leaves_child_for_executor_recovery() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/p", "Build").await.unwrap();
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
        .await
        .unwrap();

        activate_test_children(&db, "task-1", &["default"]).await;

        assert_eq!(db.reconcile_orphaned_task_delegations().await.unwrap(), 0);
        let rows = db
            .undelivered_task_delegation_children("task-1")
            .await
            .unwrap();
        assert!(rows.is_empty());
        let children = db
            .list_task_delegation_children(session.session_id)
            .await
            .unwrap();
        assert_eq!(children[0].status, DelegationStatus::Running);
    }

    #[tokio::test]
    async fn complete_child_rolls_back_when_job_update_fails() {
        let db = Db::open_in_memory().unwrap();
        let session_id = seed_job(&db, "task-rollback", &["default"]).await;
        db.write(move |conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER fail_task_job_update
                 BEFORE UPDATE ON task_delegation_jobs
                 BEGIN
                   SELECT RAISE(ABORT, 'injected job update failure');
                 END;",
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let err = db
            .complete_task_delegation_child("task-rollback", "default", "report", false, None)
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("injected job update failure"),
            "unexpected error: {err:#}"
        );

        let rows = db.list_task_delegation_children(session_id).await.unwrap();
        assert_eq!(rows[0].status, DelegationStatus::Running);
        assert_eq!(rows[0].report, None);
        assert_eq!(
            job_status(&db, "task-rollback").await,
            DelegationStatus::Running
        );
    }

    async fn job_status(db: &Db, task_call_id: &str) -> DelegationStatus {
        let task_call_id = task_call_id.to_owned();
        db.read(move |conn| {
            let status: String = conn.query_row(
                "SELECT status FROM task_delegation_jobs WHERE task_call_id = ?1",
                params![task_call_id],
                |row| row.get(0),
            )?;
            Ok(DelegationStatus::from_str(&status))
        })
        .await
        .unwrap()
    }
}
