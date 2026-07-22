//! Durable payload store for fresh `task` delegations.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
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
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn insert_task_delegation_payload(
        &self,
        payload: NewTaskDelegationPayload<'_>,
    ) -> Result<TaskDelegationPayloadRow> {
        let hash = delegation_payload_hash(payload.prompt);
        let byte_len = payload.prompt.len();
        let created_at = Utc::now().timestamp();
        let (body_inline, sidecar_path) =
            self.persist_delegation_payload_body(payload.parent_session_id, &hash, payload.prompt)?;
        let task_call_id = payload.task_call_id.to_owned();
        let label = payload.label.to_owned();
        let parent_session_id = payload.parent_session_id;
        let parent_agent = payload.parent_agent.to_owned();
        let function_call_id = payload.function_call_id.map(str::to_owned);
        let child_agent = payload.child_agent.to_owned();
        let lookup_task_call_id = task_call_id.clone();
        let lookup_label = label.clone();

        self.write_blocking(move |conn| {
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
                    task_call_id,
                    label,
                    hash,
                    parent_session_id.to_string(),
                    parent_agent,
                    function_call_id,
                    child_agent,
                    byte_len as i64,
                    body_inline.as_deref(),
                    sidecar_path.as_deref(),
                    created_at,
                ],
            )
            .context("inserting task delegation payload")?;
            Ok(())
        })?;

        self.task_delegation_payload(&lookup_task_call_id, &lookup_label)?
            .context("inserted task delegation payload missing")
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn task_delegation_payload(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Result<Option<TaskDelegationPayloadRow>> {
        self.read_blocking(|conn| {
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
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn task_delegation_payload_by_hash(
        &self,
        session_id: Uuid,
        hash: &str,
    ) -> Result<Option<TaskDelegationPayloadRow>> {
        self.read_blocking(|conn| {
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
    }

    pub fn load_task_delegation_payload(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Result<LoadedTaskDelegationPayload> {
        let row = self
            .task_delegation_payload(task_call_id, label)?
            .with_context(|| format!("task delegation payload `{task_call_id}:{label}` missing"))?;
        let body = self.load_task_delegation_payload_body(&row)?;
        Ok(LoadedTaskDelegationPayload { body })
    }

    pub fn load_task_delegation_payload_by_hash(
        &self,
        session_id: Uuid,
        hash: &str,
    ) -> Result<Option<LoadedTaskDelegationPayload>> {
        let Some(row) = self.task_delegation_payload_by_hash(session_id, hash)? else {
            return Ok(None);
        };
        let body = self.load_task_delegation_payload_body(&row)?;
        Ok(Some(LoadedTaskDelegationPayload { body }))
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn mark_task_delegation_payload_delivered(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let task_call_id = task_call_id.to_owned();
        let label = label.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE task_delegation_payloads
                    SET delivered_at = COALESCE(delivered_at, ?3)
                  WHERE task_call_id = ?1 AND label = ?2",
                params![task_call_id, label, now],
            )
            .context("marking task delegation payload delivered")?;
            Ok(())
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn session_has_task_delegation_payloads(&self, session_id: Uuid) -> Result<bool> {
        self.read_blocking(|conn| {
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
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn list_task_delegation_payloads(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<TaskDelegationPayloadRow>> {
        self.read_blocking(|conn| {
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
        })
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

    fn persist_delegation_payload_body(
        &self,
        session_id: Uuid,
        hash: &str,
        body: &str,
    ) -> Result<(Option<String>, Option<String>)> {
        let Some(_db_path) = self.path() else {
            return Ok((Some(body.to_string()), None));
        };
        let rel = delegation_payload_relative_path(session_id, hash);
        let abs = self.delegation_payload_base_dir()?.join(&rel);
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
            crate::db::files::write_private_file(&abs, body.as_bytes())
                .with_context(|| format!("writing delegation payload {}", abs.display()))?;
        }
        Ok((None, Some(rel_to_string(&rel))))
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

    fn delegation_payload_base_dir(&self) -> Result<PathBuf> {
        if let Some(path) = self.path()
            && let Some(parent) = path.parent()
        {
            return Ok(parent.to_path_buf());
        }
        crate::db::files::cockpit_data_dir()
    }
}

fn delegation_payload_relative_path(session_id: Uuid, hash: &str) -> PathBuf {
    Path::new(PAYLOAD_DIR)
        .join(session_id.to_string())
        .join(format!("{hash}.txt"))
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

    #[test]
    fn in_memory_store_load_and_mark_delivered() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/proj", "Build").unwrap();
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
            .unwrap();
        assert_eq!(row.payload_hash, delegation_payload_hash("redacted prompt"));
        assert_eq!(row.prompt_byte_len, "redacted prompt".len());
        assert!(row.body_inline.is_some());
        assert!(!row.delivered());

        let loaded = db
            .load_task_delegation_payload("task-1", "default")
            .unwrap();
        assert_eq!(loaded.body, "redacted prompt");
        db.mark_task_delegation_payload_delivered("task-1", "default")
            .unwrap();
        assert!(
            db.task_delegation_payload("task-1", "default")
                .unwrap()
                .unwrap()
                .delivered()
        );
    }

    #[test]
    fn file_backed_store_uses_hash_sidecar_and_detects_missing_body() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
        let session = db.create_session("p", "/proj", "Build").unwrap();
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
            .unwrap_err();
        assert!(
            err.to_string().contains("reading delegation payload"),
            "{err:#}"
        );
    }
}
