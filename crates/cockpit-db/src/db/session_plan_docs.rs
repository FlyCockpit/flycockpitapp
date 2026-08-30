//! Session-scoped virtual plan documents.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;
use crate::db::session_search::HistoryCallerTrust;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPlanDoc {
    pub session_id: Uuid,
    pub content: String,
    pub revision: i64,
    pub updated_at: i64,
    pub model_trust: Option<String>,
}

impl Db {
    pub async fn get_session_plan_doc(&self, session_id: Uuid) -> Result<Option<SessionPlanDoc>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT session_id, content, revision, updated_at, model_trust
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
                        model_trust: row.get(4)?,
                    })
                },
            )
            .optional()
            .context("reading session plan document")
        })
        .await
    }

    /// Read a plan document through the same model-trust boundary as every
    /// other recall pseudofile. Hidden rows are indistinguishable from absent
    /// rows so an untrusted caller cannot use the plan surface as an oracle.
    pub async fn get_session_plan_doc_for_trust(
        &self,
        session_id: Uuid,
        caller_trust: HistoryCallerTrust,
    ) -> Result<Option<SessionPlanDoc>> {
        self.read(move |conn| {
            let permitted = matches!(caller_trust, HistoryCallerTrust::Trusted);
            conn.query_row(
                "SELECT session_id, content, revision, updated_at, model_trust
                   FROM session_plan_docs
                  WHERE session_id = ?1
                    AND (?2 OR model_trust IS NULL OR model_trust <> 'trusted')",
                params![session_id.to_string(), permitted],
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
                        model_trust: row.get(4)?,
                    })
                },
            )
            .optional()
            .context("reading trust-filtered session plan document")
        })
        .await
    }

    /// Replace a plan document only when its current revision is exactly the
    /// caller-observed revision and is visible to that caller. `None` means
    /// the document changed, is hidden by model trust, or was created after
    /// that observation. Keeping the check and mutation in one database write
    /// prevents a delayed tool call from overwriting a newer or trusted plan.
    pub async fn write_session_plan_doc_if_revision(
        &self,
        session_id: Uuid,
        expected_revision: i64,
        content: &str,
        caller_trust: HistoryCallerTrust,
    ) -> Result<Option<SessionPlanDoc>> {
        let updated_at = Utc::now().timestamp();
        let content = content.to_owned();
        self.write(move |conn| {
            let model_trust = match caller_trust {
                HistoryCallerTrust::Trusted => Some("trusted"),
                HistoryCallerTrust::Untrusted => Some("untrusted"),
            };
            let current: Option<(i64, Option<String>)> = conn
                .query_row(
                    "SELECT revision, model_trust FROM session_plan_docs WHERE session_id = ?1",
                    [session_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .context("reading session plan document revision")?;
            let visible = |trust: Option<&str>| {
                matches!(caller_trust, HistoryCallerTrust::Trusted) || trust != Some("trusted")
            };
            let Some((current_revision, current_trust)) = current else {
                if expected_revision != 0 {
                    return Ok(None);
                }
                conn.execute(
                    "INSERT INTO session_plan_docs (session_id, content, revision, updated_at, model_trust)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![session_id.to_string(), content, 1_i64, updated_at, model_trust],
                )
                .context("creating conditionally written session plan document")?;
                return Ok(Some(SessionPlanDoc {
                    session_id,
                    content,
                    revision: 1,
                    updated_at,
                    model_trust: model_trust.map(str::to_owned),
                }));
            };
            if current_revision != expected_revision || !visible(current_trust.as_deref()) {
                return Ok(None);
            }

            let revision = expected_revision
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("plan revision overflow"))?;
            conn.execute(
                "UPDATE session_plan_docs
                    SET content = ?2, revision = ?3, updated_at = ?4, model_trust = ?5
                  WHERE session_id = ?1",
                params![session_id.to_string(), content, revision, updated_at, model_trust],
            )
            .context("conditionally writing session plan document")?;
            Ok(Some(SessionPlanDoc {
                session_id,
                content,
                revision,
                updated_at,
                model_trust: model_trust.map(str::to_owned),
            }))
        })
        .await
    }
}
