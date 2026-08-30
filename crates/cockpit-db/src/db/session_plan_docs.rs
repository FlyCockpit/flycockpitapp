//! Session-scoped virtual plan documents.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPlanDoc {
    pub session_id: Uuid,
    pub content: String,
    pub revision: i64,
    pub updated_at: i64,
}

impl Db {
    pub async fn get_session_plan_doc(&self, session_id: Uuid) -> Result<Option<SessionPlanDoc>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT session_id, content, revision, updated_at
                   FROM session_plan_docs
                  WHERE session_id = ?1",
                [session_id.to_string()],
                |row| {
                    let session_id_s: String = row.get(0)?;
                    let session_id = Uuid::parse_str(&session_id_s).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                    Ok(SessionPlanDoc {
                        session_id,
                        content: row.get(1)?,
                        revision: row.get(2)?,
                        updated_at: row.get(3)?,
                    })
                },
            )
            .optional()
            .context("reading session plan document")
        })
        .await
    }

    pub async fn write_session_plan_doc(
        &self,
        session_id: Uuid,
        content: &str,
    ) -> Result<SessionPlanDoc> {
        let updated_at = Utc::now().timestamp();
        let content = content.to_owned();
        self.write(move |conn| {
            let next_revision: i64 = conn
                .query_row(
                    "SELECT COALESCE(revision, 0) + 1
                       FROM session_plan_docs
                      WHERE session_id = ?1",
                    [session_id.to_string()],
                    |row| row.get(0),
                )
                .optional()
                .context("reading session plan document revision")?
                .unwrap_or(1);
            conn.execute(
                "INSERT INTO session_plan_docs (session_id, content, revision, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(session_id) DO UPDATE SET
                    content = excluded.content,
                    revision = excluded.revision,
                    updated_at = excluded.updated_at",
                params![session_id.to_string(), content, next_revision, updated_at],
            )
            .context("writing session plan document")?;
            Ok(SessionPlanDoc {
                session_id,
                content: content.to_string(),
                revision: next_revision,
                updated_at,
            })
        })
        .await
    }

    /// Replace a plan document only when its current revision is exactly the
    /// caller-observed revision. `None` means the document changed (or was
    /// created) after that observation. Keeping the check and mutation in one
    /// database write prevents a delayed tool call from overwriting a newer
    /// plan.
    pub async fn write_session_plan_doc_if_revision(
        &self,
        session_id: Uuid,
        expected_revision: i64,
        content: &str,
    ) -> Result<Option<SessionPlanDoc>> {
        let updated_at = Utc::now().timestamp();
        let content = content.to_owned();
        self.write(move |conn| {
            let current: Option<i64> = conn
                .query_row(
                    "SELECT revision FROM session_plan_docs WHERE session_id = ?1",
                    [session_id.to_string()],
                    |row| row.get(0),
                )
                .optional()
                .context("reading session plan document revision")?;
            if current.unwrap_or(0) != expected_revision {
                return Ok(None);
            }

            let revision = expected_revision
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("plan revision overflow"))?;
            conn.execute(
                "INSERT INTO session_plan_docs (session_id, content, revision, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(session_id) DO UPDATE SET
                    content = excluded.content,
                    revision = excluded.revision,
                    updated_at = excluded.updated_at",
                params![session_id.to_string(), content, revision, updated_at],
            )
            .context("conditionally writing session plan document")?;
            Ok(Some(SessionPlanDoc {
                session_id,
                content,
                revision,
                updated_at,
            }))
        })
        .await
    }
}
