//! Durable payload store for fresh `task` delegations.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

const PAYLOAD_DIR: &str = "delegation_payloads";
const EXPORT_EXCERPT_CHARS: usize = 512;

#[derive(Debug, Clone)]
pub struct NewTaskDelegationPayload<'a> {
    pub task_call_id: &'a str,
    pub function_call_id: Option<&'a str>,
    pub parent_session_id: Uuid,
    pub parent_agent: &'a str,
    pub label: &'a str,
    pub child_agent: &'a str,
    pub prompt: &'a str,
}

#[derive(Debug, Clone)]
pub struct TaskDelegationPayloadRow {
    pub task_call_id: String,
    pub label: String,
    pub payload_hash: String,
    pub parent_session_id: Uuid,
    pub parent_agent: String,
    pub function_call_id: Option<String>,
    pub child_agent: String,
    pub prompt_byte_len: usize,
    pub body_inline: Option<String>,
    pub sidecar_path: Option<String>,
    pub created_at: i64,
    pub delivered_at: Option<i64>,
}

impl TaskDelegationPayloadRow {
    pub fn delivered(&self) -> bool {
        self.delivered_at.is_some()
    }

    pub fn excerpt(&self, body: &str) -> String {
        body.chars().take(EXPORT_EXCERPT_CHARS).collect()
    }
}

#[derive(Debug, Clone)]
pub struct LoadedTaskDelegationPayload {
    pub body: String,
}

pub(crate) struct PreparedTaskDelegationPayload {
    task_call_id: String,
    label: String,
    hash: String,
    parent_session_id: Uuid,
    parent_agent: String,
    function_call_id: Option<String>,
    child_agent: String,
    byte_len: usize,
    body_inline: Option<String>,
    sidecar_path: Option<String>,
    created_at: i64,
    /// Armed until the database row has committed. This closes the ordinary
    /// insert-failure window without letting an unpublished sidecar leak.
    cleanup_abs_path: Option<PathBuf>,
}

pub(crate) struct CommittedTaskDelegationPayload {
    pub(crate) row: TaskDelegationPayloadRow,
    cleanup_abs_path: Option<PathBuf>,
}

impl CommittedTaskDelegationPayload {
    pub(crate) fn confirm_outer_commit(mut self) -> TaskDelegationPayloadRow {
        self.cleanup_abs_path = None;
        self.row
    }
}

impl Drop for CommittedTaskDelegationPayload {
    fn drop(&mut self) {
        if let Some(path) = self.cleanup_abs_path.take()
            && let Err(error) = std::fs::remove_file(&path)
        {
            tracing::warn!(%error, path=%path.display(), "failed to clean uncommitted delegation sidecar");
        }
    }
}

impl Drop for PreparedTaskDelegationPayload {
    fn drop(&mut self) {
        if let Some(path) = self.cleanup_abs_path.take()
            && let Err(error) = std::fs::remove_file(&path)
        {
            tracing::warn!(%error, path=%path.display(), "failed to clean unpublished delegation sidecar");
        }
    }
}

pub fn delegation_payload_hash(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(content.as_bytes());
    hex_lower(&digest)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

impl Db {
    pub async fn insert_task_delegation_payload(
        &self,
        payload: NewTaskDelegationPayload<'_>,
    ) -> Result<TaskDelegationPayloadRow> {
        let prepared = self.prepare_task_delegation_payload(payload).await?;
        let committed = self
            .write(move |conn| Self::insert_prepared_task_delegation_payload_conn(conn, prepared))
            .await?;
        let row = committed.confirm_outer_commit();
        self.reconcile_delegation_sidecar_cleanup_intents().await?;
        Ok(row)
    }

    pub(crate) async fn prepare_task_delegation_payload(
        &self,
        payload: NewTaskDelegationPayload<'_>,
    ) -> Result<PreparedTaskDelegationPayload> {
        let hash = delegation_payload_hash(payload.prompt);
        let byte_len = payload.prompt.len();
        let created_at = Utc::now().timestamp();
        let (body_inline, sidecar_path, cleanup_abs_path) =
            self.persist_delegation_payload_body(payload.parent_session_id, &hash, payload.prompt)
                .await?;
        Ok(PreparedTaskDelegationPayload {
            task_call_id: payload.task_call_id.to_owned(),
            label: payload.label.to_owned(),
            hash,
            parent_session_id: payload.parent_session_id,
            parent_agent: payload.parent_agent.to_owned(),
            function_call_id: payload.function_call_id.map(str::to_owned),
            child_agent: payload.child_agent.to_owned(),
            byte_len,
            body_inline,
            sidecar_path,
            created_at,
            cleanup_abs_path,
        })
    }

    pub(crate) fn insert_prepared_task_delegation_payload_conn(
        conn: &Connection,
        mut payload: PreparedTaskDelegationPayload,
    ) -> Result<CommittedTaskDelegationPayload> {
        // A replacement must retain deletion authority for the old unique
        // pathname in the same transaction that removes its last reference.
        conn.execute(
            "INSERT OR IGNORE INTO task_delegation_sidecar_cleanup_intents
             (sidecar_path,session_id,created_at_unix_ms)
             SELECT sidecar_path,parent_session_id,?3 FROM task_delegation_payloads
              WHERE task_call_id=?1 AND label=?2 AND sidecar_path IS NOT NULL
                AND sidecar_path IS NOT ?4",
            params![payload.task_call_id, payload.label, Utc::now().timestamp_millis(), payload.sidecar_path],
        ).context("recording replaced delegation sidecar cleanup intent")?;
        conn.execute(
            "INSERT INTO task_delegation_payloads (
                    task_call_id, label, payload_hash, parent_session_id, parent_agent,
                    function_call_id, child_agent, prompt_byte_len, body_inline,
                    sidecar_path, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(task_call_id, label) DO UPDATE SET
                    payload_hash = excluded.payload_hash,
                    parent_session_id = excluded.parent_session_id,
                    parent_agent = excluded.parent_agent,
                    function_call_id = excluded.function_call_id,
                    child_agent = excluded.child_agent,
                    prompt_byte_len = excluded.prompt_byte_len,
                    body_inline = excluded.body_inline,
                    sidecar_path = excluded.sidecar_path,
                    created_at = excluded.created_at,
                    delivered_at = NULL",
            params![
                payload.task_call_id,
                payload.label,
                payload.hash,
                payload.parent_session_id.to_string(),
                payload.parent_agent,
                payload.function_call_id,
                payload.child_agent,
                payload.byte_len as i64,
                payload.body_inline.as_deref(),
                payload.sidecar_path.as_deref(),
                payload.created_at,
            ],
        )
        .context("inserting task delegation payload")?;
        let row = Self::task_delegation_payload_conn(conn, &payload.task_call_id, &payload.label)?
            .context("inserted task delegation payload missing")?;
        if let Some(sidecar_path) = payload.sidecar_path.as_deref() {
            let removed = conn.execute(
                "DELETE FROM task_delegation_sidecar_prepare_intents WHERE sidecar_path=?1",
                [sidecar_path],
            )?;
            anyhow::ensure!(removed == 1, "published sidecar prepare intent is missing");
        }
        let cleanup_abs_path = payload.cleanup_abs_path.take();
        Ok(CommittedTaskDelegationPayload {
            row,
            cleanup_abs_path,
        })
    }

    pub async fn task_delegation_payload(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Result<Option<TaskDelegationPayloadRow>> {
        let task_call_id = task_call_id.to_owned();
        let label = label.to_owned();
        self.read(move |conn| Self::task_delegation_payload_conn(conn, &task_call_id, &label))
            .await
    }

    pub fn task_delegation_payload_conn(
        conn: &Connection,
        task_call_id: &str,
        label: &str,
    ) -> Result<Option<TaskDelegationPayloadRow>> {
        conn.query_row(
            "SELECT task_call_id, label, payload_hash, parent_session_id,
                    parent_agent, function_call_id, child_agent, prompt_byte_len,
                    body_inline, sidecar_path, created_at, delivered_at
               FROM task_delegation_payloads
              WHERE task_call_id = ?1 AND label = ?2",
            params![task_call_id, label],
            decode_payload_row,
        )
        .optional()
        .context("querying task delegation payload")
    }

    pub async fn task_delegation_payload_by_hash(
        &self,
        session_id: Uuid,
        hash: &str,
    ) -> Result<Option<TaskDelegationPayloadRow>> {
        let hash = hash.to_owned();
        self.read(move |conn| {
            conn.query_row(
                "SELECT task_call_id, label, payload_hash, parent_session_id,
                        parent_agent, function_call_id, child_agent, prompt_byte_len,
                        body_inline, sidecar_path, created_at, delivered_at
                   FROM task_delegation_payloads
                  WHERE parent_session_id = ?1 AND payload_hash = ?2
                  ORDER BY created_at ASC
                  LIMIT 1",
                params![session_id.to_string(), hash],
                decode_payload_row,
            )
            .optional()
            .context("querying task delegation payload by hash")
        })
        .await
    }

    pub async fn load_task_delegation_payload(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Result<LoadedTaskDelegationPayload> {
        let row = self
            .task_delegation_payload(task_call_id, label)
            .await?
            .with_context(|| format!("task delegation payload `{task_call_id}:{label}` missing"))?;
        let body = self.load_task_delegation_payload_body(&row)?;
        Ok(LoadedTaskDelegationPayload { body })
    }

    pub async fn load_task_delegation_payload_by_hash(
        &self,
        session_id: Uuid,
        hash: &str,
    ) -> Result<Option<LoadedTaskDelegationPayload>> {
        let Some(row) = self
            .task_delegation_payload_by_hash(session_id, hash)
            .await?
        else {
            return Ok(None);
        };
        let body = self.load_task_delegation_payload_body(&row)?;
        Ok(Some(LoadedTaskDelegationPayload { body }))
    }

    pub async fn mark_task_delegation_payload_delivered(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let task_call_id = task_call_id.to_owned();
        let label = label.to_owned();
        self.write(move |conn| {
            conn.execute(
                "UPDATE task_delegation_payloads
                    SET delivered_at = COALESCE(delivered_at, ?3)
                  WHERE task_call_id = ?1 AND label = ?2",
                params![task_call_id, label, now],
            )
            .context("marking task delegation payload delivered")?;
            Ok(())
        })
        .await
    }

    pub async fn session_has_task_delegation_payloads(&self, session_id: Uuid) -> Result<bool> {
        self.read(move |conn| {
            let exists: i64 = conn
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM task_delegation_payloads WHERE parent_session_id = ?1
                     )",
                    [session_id.to_string()],
                    |row| row.get(0),
                )
                .context("checking task delegation payload presence")?;
            Ok(exists != 0)
        })
        .await
    }

    pub async fn list_task_delegation_payloads(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<TaskDelegationPayloadRow>> {
        self.read(move |conn| Self::list_task_delegation_payloads_conn(conn, session_id))
            .await
    }

    pub fn list_task_delegation_payloads_conn(
        conn: &Connection,
        session_id: Uuid,
    ) -> Result<Vec<TaskDelegationPayloadRow>> {
        let mut stmt = conn
            .prepare(
                "SELECT task_call_id, label, payload_hash, parent_session_id,
                        parent_agent, function_call_id, child_agent, prompt_byte_len,
                        body_inline, sidecar_path, created_at, delivered_at
                   FROM task_delegation_payloads
                  WHERE parent_session_id = ?1
                  ORDER BY created_at ASC, task_call_id ASC, label ASC",
            )
            .context("preparing task delegation payload list")?;
        let rows = stmt
            .query_map([session_id.to_string()], decode_payload_row)
            .context("querying task delegation payloads")?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.context("decoding task delegation payload")?);
        }
        Ok(out)
    }

    pub fn task_delegation_payload_sidecar_abs_path(
        &self,
        row: &TaskDelegationPayloadRow,
    ) -> Result<Option<PathBuf>> {
        let Some(rel) = row.sidecar_path.as_deref() else {
            return Ok(None);
        };
        Ok(Some(self.delegation_payload_base_dir()?.join(rel)))
    }

    async fn persist_delegation_payload_body(
        &self,
        session_id: Uuid,
        hash: &str,
        body: &str,
    ) -> Result<(Option<String>, Option<String>, Option<PathBuf>)> {
        let Some(_db_path) = self.path() else {
            return Ok((Some(body.to_string()), None, None));
        };
        // Each durable payload gets a non-reusable pathname. Cleanup can then
        // never unlink a freshly prepared row which happens to have the same
        // content hash as a deleted predecessor.
        let rel = delegation_payload_relative_path(session_id, hash, Uuid::now_v7());
        let abs = self.delegation_payload_base_dir()?.join(&rel);
        let relative = rel_to_string(&rel);
        let intent_relative = relative.clone();
        self.transaction(move |conn| {
            conn.execute(
                "INSERT INTO task_delegation_sidecar_prepare_intents(sidecar_path,session_id,created_at_unix_ms)
                 VALUES(?1,?2,?3)",
                params![intent_relative, session_id.to_string(), Utc::now().timestamp_millis()],
            )?;
            Ok(())
        })
        .await
        .context("recording delegation sidecar prepare intent")?;
        crate::db::files::ensure_parent_dir_private(&abs)?;
        if abs.exists() {
            let existing = std::fs::read_to_string(&abs).with_context(|| {
                format!("reading existing delegation payload {}", abs.display())
            })?;
            let existing_hash = delegation_payload_hash(&existing);
            if existing_hash != hash {
                bail!(
                    "delegation payload sidecar hash mismatch for {}",
                    abs.display()
                );
            }
        } else {
            crate::db::files::publish_private_file_durable(&abs, body.as_bytes())
                .with_context(|| format!("publishing delegation payload {}", abs.display()))?;
        }
        Ok((None, Some(relative), Some(abs)))
    }

    fn load_task_delegation_payload_body(&self, row: &TaskDelegationPayloadRow) -> Result<String> {
        let body = if let Some(body) = &row.body_inline {
            body.clone()
        } else {
            let path = self
                .task_delegation_payload_sidecar_abs_path(row)?
                .context("task delegation payload sidecar path missing")?;
            std::fs::read_to_string(&path)
                .with_context(|| format!("reading delegation payload {}", path.display()))?
        };
        let actual = delegation_payload_hash(&body);
        if actual != row.payload_hash {
            bail!(
                "delegation payload hash mismatch for {}:{}",
                row.task_call_id,
                row.label
            );
        }
        Ok(body)
    }

    pub(crate) fn delegation_payload_base_dir(&self) -> Result<PathBuf> {
        if let Some(path) = self.path()
            && let Some(parent) = path.parent()
        {
            return Ok(parent.to_path_buf());
        }
        crate::db::files::cockpit_data_dir()
    }

    /// Recover publication attempts that never reached an outer payload-row
    /// commit. The durable intent precedes the rename, so absence is success;
    /// a live payload reference instead proves the outer commit won and only
    /// the stale prepare marker is removed.
    pub async fn reconcile_delegation_sidecar_prepare_intents(&self) -> Result<usize> {
        let rows = self
            .read(|conn| {
                let mut statement = conn.prepare(
                    "SELECT sidecar_path FROM task_delegation_sidecar_prepare_intents
                     ORDER BY created_at_unix_ms,sidecar_path",
                )?;
                Ok(statement
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?)
            })
            .await?;
        let base = self.delegation_payload_base_dir()?;
        let mut completed = 0;
        for relative in rows {
            let cleanup_base = base.clone();
            let cleanup_relative = relative.clone();
            let result = self
                .transaction(move |conn| {
                    let referenced: bool = conn.query_row(
                        "SELECT EXISTS(SELECT 1 FROM task_delegation_payloads WHERE sidecar_path=?1)",
                        [&cleanup_relative],
                        |row| row.get(0),
                    )?;
                    if !referenced {
                        crate::db::files::delete_relative_file_durable_nofollow(
                            &cleanup_base,
                            Path::new(&cleanup_relative),
                        )?;
                    }
                    Ok(conn.execute(
                        "DELETE FROM task_delegation_sidecar_prepare_intents WHERE sidecar_path=?1",
                        [cleanup_relative],
                    )? == 1)
                })
                .await;
            match result {
                Ok(true) => completed += 1,
                Ok(false) => {}
                Err(error) => tracing::warn!(
                    %error,
                    sidecar_path = %relative,
                    "delegation sidecar prepare recovery remains pending"
                ),
            }
        }
        Ok(completed)
    }
}

fn delegation_payload_relative_path(session_id: Uuid, hash: &str, generation: Uuid) -> PathBuf {
    Path::new(PAYLOAD_DIR)
        .join(session_id.to_string())
        .join(format!("{hash}-{generation}.txt"))
}

fn rel_to_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn decode_payload_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TaskDelegationPayloadRow> {
    let parent_session_id: String = row.get("parent_session_id")?;
    let prompt_byte_len: i64 = row.get("prompt_byte_len")?;
    Ok(TaskDelegationPayloadRow {
        task_call_id: row.get("task_call_id")?,
        label: row.get("label")?,
        payload_hash: row.get("payload_hash")?,
        parent_session_id: Uuid::parse_str(&parent_session_id).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e))
        })?,
        parent_agent: row.get("parent_agent")?,
        function_call_id: row.get("function_call_id")?,
        child_agent: row.get("child_agent")?,
        prompt_byte_len: prompt_byte_len.max(0) as usize,
        body_inline: row.get("body_inline")?,
        sidecar_path: row.get("sidecar_path")?,
        created_at: row.get("created_at")?,
        delivered_at: row.get("delivered_at")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_store_load_and_mark_delivered() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/proj", "Build").await.unwrap();
        db.upsert_task_delegation_job(
            session.session_id,
            "task-1",
            Some("fn-1"),
            "Build",
            None,
            &[crate::db::task_delegations::DelegationChildInit {
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

        let row = db
            .insert_task_delegation_payload(NewTaskDelegationPayload {
                task_call_id: "task-1",
                function_call_id: Some("fn-1"),
                parent_session_id: session.session_id,
                parent_agent: "Build",
                label: "default",
                child_agent: "explore",
                prompt: "redacted prompt",
            })
            .await
            .unwrap();
        assert_eq!(row.payload_hash, delegation_payload_hash("redacted prompt"));
        assert_eq!(row.prompt_byte_len, "redacted prompt".len());
        assert!(row.body_inline.is_some());
        assert!(!row.delivered());

        let loaded = db
            .load_task_delegation_payload("task-1", "default")
            .await
            .unwrap();
        assert_eq!(loaded.body, "redacted prompt");
        db.mark_task_delegation_payload_delivered("task-1", "default")
            .await
            .unwrap();
        assert!(
            db.task_delegation_payload("task-1", "default")
                .await
                .unwrap()
                .unwrap()
                .delivered()
        );
    }

    #[tokio::test]
    async fn file_backed_store_uses_hash_sidecar_and_detects_missing_body() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
        let session = db.create_session("p", "/proj", "Build").await.unwrap();
        db.upsert_task_delegation_job(
            session.session_id,
            "task-2",
            None,
            "Build",
            None,
            &[crate::db::task_delegations::DelegationChildInit {
                label: "alpha",
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
        let row = db
            .insert_task_delegation_payload(NewTaskDelegationPayload {
                task_call_id: "task-2",
                function_call_id: None,
                parent_session_id: session.session_id,
                parent_agent: "Build",
                label: "alpha",
                child_agent: "explore",
                prompt: "sidecar prompt",
            })
            .await
            .unwrap();
        assert!(row.body_inline.is_none());
        let sidecar = db
            .task_delegation_payload_sidecar_abs_path(&row)
            .unwrap()
            .unwrap();
        assert!(sidecar.exists());
        assert_eq!(std::fs::read_to_string(&sidecar).unwrap(), "sidecar prompt");
        std::fs::remove_file(sidecar).unwrap();
        let err = db
            .load_task_delegation_payload("task-2", "alpha")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("reading delegation payload"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn prepared_sidecar_is_recoverable_before_payload_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
        let session = db.create_session("p", "/proj", "Build").await.unwrap();
        let prepared = db
            .prepare_task_delegation_payload(NewTaskDelegationPayload {
                task_call_id: "crash-before-row",
                function_call_id: None,
                parent_session_id: session.session_id,
                parent_agent: "Build",
                label: "default",
                child_agent: "explore",
                prompt: "published before the row",
            })
            .await
            .unwrap();
        let published = prepared.cleanup_abs_path.clone().unwrap();
        assert!(published.exists());
        std::mem::forget(prepared); // simulate process loss before RAII cleanup
        assert_eq!(
            db.reconcile_delegation_sidecar_prepare_intents()
                .await
                .unwrap(),
            1,
            "boot recovery must retire the durable crash intent"
        );
        assert!(!published.exists());
    }

    #[tokio::test]
    async fn outer_commit_failure_keeps_cleanup_armed() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
        let session = db.create_session("p", "/proj", "Build").await.unwrap();
        db.upsert_task_delegation_job(
            session.session_id,
            "rollback",
            None,
            "Build",
            None,
            &[crate::db::task_delegations::DelegationChildInit {
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
        let prepared = db
            .prepare_task_delegation_payload(NewTaskDelegationPayload {
                task_call_id: "rollback",
                function_call_id: None,
                parent_session_id: session.session_id,
                parent_agent: "Build",
                label: "default",
                child_agent: "explore",
                prompt: "must not survive rollback",
            })
            .await
            .unwrap();
        let published = prepared.cleanup_abs_path.clone().unwrap();
        let result: Result<()> = db
            .transaction(move |conn| {
                let committed =
                    Db::insert_prepared_task_delegation_payload_conn(conn, prepared)?;
                drop(committed);
                bail!("injected outer transaction failure")
            })
            .await;
        assert!(result.is_err());
        assert!(!published.exists());
        assert!(
            db.task_delegation_payload("rollback", "default")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn repeated_upsert_reconciles_replaced_unique_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
        let session = db.create_session("p", "/proj", "Build").await.unwrap();
        db.upsert_task_delegation_job(
            session.session_id,
            "replace",
            None,
            "Build",
            None,
            &[crate::db::task_delegations::DelegationChildInit {
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
        let make = |prompt| NewTaskDelegationPayload {
            task_call_id: "replace",
            function_call_id: None,
            parent_session_id: session.session_id,
            parent_agent: "Build",
            label: "default",
            child_agent: "explore",
            prompt,
        };
        let first = db.insert_task_delegation_payload(make("first")).await.unwrap();
        let first_path = db
            .task_delegation_payload_sidecar_abs_path(&first)
            .unwrap()
            .unwrap();
        let second = db.insert_task_delegation_payload(make("second")).await.unwrap();
        let second_path = db
            .task_delegation_payload_sidecar_abs_path(&second)
            .unwrap()
            .unwrap();
        assert_ne!(first_path, second_path);
        assert!(!first_path.exists());
        assert!(second_path.exists());
    }
}
