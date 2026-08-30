//! Knowledge-base session consent and immutable dream completion facts.

use anyhow::{Context, Result, ensure};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;
use crate::db::session_search::HistoryCallerTrust;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreamSessionSource {
    pub session_id: Uuid,
    pub title: Option<String>,
    /// Cheap first-pass material: the latest compaction brief when available,
    /// otherwise the session title. Transcript/tool windows are deliberately
    /// fetched separately only when the orchestrator asks for evidence.
    pub description: String,
    pub last_active_at_unix_ms: i64,
}

impl Db {
    pub async fn attach_session_to_knowledge_base(
        &self,
        kb_id: &str,
        session_id: Uuid,
    ) -> Result<bool> {
        validate_kb_id(kb_id)?;
        let kb_id = kb_id.to_owned();
        self.write(move |conn| {
            let changed = conn.execute(
                "INSERT OR IGNORE INTO knowledge_base_session_attachments
                 (kb_id, session_id, attached_at_unix_ms) VALUES (?1, ?2, ?3)",
                params![kb_id, session_id.to_string(), Utc::now().timestamp_millis()],
            )?;
            Ok(changed == 1)
        })
        .await
    }

    pub async fn detach_session_from_knowledge_base(
        &self,
        kb_id: &str,
        session_id: Uuid,
    ) -> Result<bool> {
        validate_kb_id(kb_id)?;
        let kb_id = kb_id.to_owned();
        self.write(move |conn| {
            Ok(conn.execute(
                "DELETE FROM knowledge_base_session_attachments
                 WHERE kb_id = ?1 AND session_id = ?2",
                params![kb_id, session_id.to_string()],
            )? == 1)
        })
        .await
    }

    /// Read exactly the current consent set minus immutable completion facts.
    pub async fn undreamed_sessions_for_knowledge_base(
        &self,
        kb_id: &str,
        consumer_id: &str,
        caller_trust: HistoryCallerTrust,
    ) -> Result<Vec<DreamSessionSource>> {
        validate_kb_id(kb_id)?;
        validate_consumer_id(consumer_id)?;
        let kb_id = kb_id.to_owned();
        let consumer_id = consumer_id.to_owned();
        self.read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT s.session_id, s.title,
                        COALESCE(
                          (SELECT json_extract(e.data_json, '$.brief_text')
                           FROM session_events e
                           WHERE e.session_id = s.session_id
                             AND e.type = 'session_compacted'
                             AND (?3 OR e.model_trust IS NULL OR e.model_trust <> 'trusted')
                           ORDER BY e.seq DESC LIMIT 1),
                          s.title, ''),
                        s.last_active_at_unix_ms
                 FROM knowledge_base_session_attachments a
                 JOIN sessions s ON s.session_id = a.session_id
                 WHERE a.kb_id = ?1
                   AND NOT EXISTS (
                     SELECT 1 FROM knowledge_dreamed_sessions d
                     WHERE d.kb_id = a.kb_id
                       AND d.consumer_id = ?2
                       AND d.session_id = a.session_id)
                 ORDER BY s.last_active_at_unix_ms, s.session_id",
            )?;
            let rows = statement.query_map(
                params![
                    kb_id,
                    consumer_id,
                    caller_trust == HistoryCallerTrust::Trusted
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?;
            rows.map(|row| {
                let (session_id, title, description, last_active_at_unix_ms) = row?;
                Ok(DreamSessionSource {
                    session_id: Uuid::parse_str(&session_id)
                        .context("knowledge attachment contains an invalid session id")?,
                    title,
                    description,
                    last_active_at_unix_ms,
                })
            })
            .collect()
        })
        .await
    }

    /// Commit the whole consumed snapshot only after the sink succeeds. Every
    /// session must still be attached, so revoking consent while a dream is
    /// running fails closed instead of recording an unread session as dreamed.
    pub async fn record_knowledge_dream_completion(
        &self,
        kb_id: &str,
        consumer_id: &str,
        session_ids: &[Uuid],
    ) -> Result<()> {
        validate_kb_id(kb_id)?;
        validate_consumer_id(consumer_id)?;
        let kb_id = kb_id.to_owned();
        let consumer_id = consumer_id.to_owned();
        let session_ids = session_ids.to_vec();
        self.transaction(move |conn| {
            let dreamed_at = Utc::now().timestamp_millis();
            for session_id in session_ids {
                let session_id = session_id.to_string();
                let attached = conn
                    .query_row(
                        "SELECT 1 FROM knowledge_base_session_attachments
                         WHERE kb_id = ?1 AND session_id = ?2",
                        params![&kb_id, &session_id],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                ensure!(
                    attached,
                    "session {session_id} is no longer attached to knowledge base {kb_id}"
                );
                conn.execute(
                    "INSERT OR IGNORE INTO knowledge_dreamed_sessions
                     (kb_id, consumer_id, session_id, dreamed_at_unix_ms)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![&kb_id, &consumer_id, &session_id, dreamed_at],
                )?;
            }
            Ok(())
        })
        .await
    }

    pub async fn knowledge_base_last_dreamed_at(
        &self,
        kb_id: &str,
        consumer_id: &str,
    ) -> Result<Option<i64>> {
        validate_kb_id(kb_id)?;
        validate_consumer_id(consumer_id)?;
        let kb_id = kb_id.to_owned();
        let consumer_id = consumer_id.to_owned();
        self.read(move |conn| {
            conn.query_row(
                "SELECT MAX(dreamed_at_unix_ms) FROM knowledge_dreamed_sessions
                 WHERE kb_id = ?1 AND consumer_id = ?2",
                params![kb_id, consumer_id],
                |row| row.get(0),
            )
            .context("loading knowledge-base last dreamed time")
        })
        .await
    }
}

fn validate_kb_id(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty(),
        "knowledge base id must not be empty"
    );
    ensure!(value.len() <= 255, "knowledge base id is too long");
    Ok(())
}

fn validate_consumer_id(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty(),
        "dream consumer id must not be empty"
    );
    ensure!(value.len() <= 255, "dream consumer id is too long");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::session_log::{SessionEventContext, SessionEventKind};
    use serde_json::json;

    #[tokio::test]
    async fn attachment_minus_ledger_is_exact_and_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let first = db.create_session("p", "/p", "Build").await.unwrap();
        let second = db.create_session("p", "/p", "Build").await.unwrap();
        db.attach_session_to_knowledge_base("kb", first.session_id)
            .await
            .unwrap();

        let initial = db
            .undreamed_sessions_for_knowledge_base("kb", "consumer", HistoryCallerTrust::Trusted)
            .await
            .unwrap();
        assert_eq!(
            initial.iter().map(|row| row.session_id).collect::<Vec<_>>(),
            vec![first.session_id]
        );

        db.record_knowledge_dream_completion("kb", "consumer", &[first.session_id])
            .await
            .unwrap();
        assert!(
            db.undreamed_sessions_for_knowledge_base(
                "kb",
                "consumer",
                HistoryCallerTrust::Trusted,
            )
                .await
                .unwrap()
                .is_empty()
        );

        db.attach_session_to_knowledge_base("kb", second.session_id)
            .await
            .unwrap();
        let next = db
            .undreamed_sessions_for_knowledge_base("kb", "consumer", HistoryCallerTrust::Trusted)
            .await
            .unwrap();
        assert_eq!(
            next.iter().map(|row| row.session_id).collect::<Vec<_>>(),
            vec![second.session_id]
        );
    }

    #[tokio::test]
    async fn completion_fails_closed_after_consent_is_revoked() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/p", "Build").await.unwrap();
        db.attach_session_to_knowledge_base("kb", session.session_id)
            .await
            .unwrap();
        db.detach_session_from_knowledge_base("kb", session.session_id)
            .await
            .unwrap();
        assert!(
            db.record_knowledge_dream_completion("kb", "consumer", &[session.session_id])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn untrusted_dream_source_list_excludes_trusted_compaction_briefs() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("p", "/p", "Visible session title")
            .await
            .unwrap();
        db.attach_session_to_knowledge_base("kb", session.session_id)
            .await
            .unwrap();
        db.insert_session_event_with_context(
            session.session_id,
            SessionEventKind::SessionCompacted,
            Some("Build"),
            None,
            SessionEventContext {
                provider_id: Some("provider-a"),
                model_id: Some("trusted-model"),
                model_trust: Some("trusted"),
                ..Default::default()
            },
            &json!({ "brief_text": "trusted compaction secret" }),
        )
        .await
        .unwrap();

        let untrusted = db
            .undreamed_sessions_for_knowledge_base("kb", "consumer", HistoryCallerTrust::Untrusted)
            .await
            .unwrap();
        assert_eq!(untrusted.len(), 1);
        assert_eq!(untrusted[0].description, "Visible session title");

        let trusted = db
            .undreamed_sessions_for_knowledge_base("kb", "consumer", HistoryCallerTrust::Trusted)
            .await
            .unwrap();
        assert_eq!(trusted.len(), 1);
        assert_eq!(trusted[0].description, "trusted compaction secret");
    }
}
