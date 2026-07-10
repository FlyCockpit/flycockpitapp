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
    pub fn get_session_plan_doc(&self, session_id: Uuid) -> Result<Option<SessionPlanDoc>> {
        self.read_blocking(|conn| {
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
    }

    pub fn write_session_plan_doc(
        &self,
        session_id: Uuid,
        content: &str,
    ) -> Result<SessionPlanDoc> {
        let updated_at = Utc::now().timestamp();
        let content = content.to_owned();
        self.write_blocking(move |conn| {
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
    }
}
