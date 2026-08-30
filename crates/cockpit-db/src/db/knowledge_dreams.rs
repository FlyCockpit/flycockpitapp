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
        project_root: &str,
        session_id: Uuid,
    ) -> Result<bool> {
        validate_kb_id(kb_id)?;
        validate_project_root(project_root)?;
        let kb_id = kb_id.to_owned();
        let project_root = project_root.to_owned();
        self.write(move |conn| {
            let changed = conn.execute(
                "INSERT OR IGNORE INTO knowledge_base_session_attachments
                 (kb_id, project_root, session_id, attached_at_unix_ms) VALUES (?1, ?2, ?3, ?4)",
                params![
                    kb_id,
                    project_root,
                    session_id.to_string(),
                    Utc::now().timestamp_millis()
                ],
            )?;
            Ok(changed == 1)
        })
        .await
    }

    pub async fn detach_session_from_knowledge_base(
        &self,
        kb_id: &str,
        project_root: &str,
        session_id: Uuid,
    ) -> Result<bool> {
        validate_kb_id(kb_id)?;
        validate_project_root(project_root)?;
        let kb_id = kb_id.to_owned();
        let project_root = project_root.to_owned();
        self.write(move |conn| {
            Ok(conn.execute(
                "DELETE FROM knowledge_base_session_attachments
                 WHERE kb_id = ?1 AND project_root = ?2 AND session_id = ?3",
                params![kb_id, project_root, session_id.to_string()],
            )? == 1)
        })
        .await
    }

    /// Read exactly the current consent set minus immutable completion facts.
    pub async fn undreamed_sessions_for_knowledge_base(
        &self,
        kb_id: &str,
        project_root: &str,
        consumer_id: &str,
        caller_trust: HistoryCallerTrust,
    ) -> Result<Vec<DreamSessionSource>> {
        validate_kb_id(kb_id)?;
        validate_project_root(project_root)?;
        validate_consumer_id(consumer_id)?;
        let kb_id = kb_id.to_owned();
        let project_root = project_root.to_owned();
        let consumer_id = consumer_id.to_owned();
        self.read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT s.session_id, s.title,
                        COALESCE(
                          (SELECT json_extract(e.data_json, '$.brief_text')
                           FROM session_events e
                           WHERE e.session_id = s.session_id
                             AND e.type = 'session_compacted'
                             AND (?4 OR e.model_trust IS NULL OR e.model_trust <> 'trusted')
                           ORDER BY e.seq DESC LIMIT 1),
                          s.title, ''),
                        s.last_active_at_unix_ms
                 FROM knowledge_base_session_attachments a
                 JOIN sessions s ON s.session_id = a.session_id
                 WHERE a.kb_id = ?1
                   AND a.project_root = ?2
                   AND s.is_dream_session = 0
                   AND NOT EXISTS (
                     SELECT 1 FROM knowledge_dreamed_sessions d
                     WHERE d.kb_id = a.kb_id
                       AND d.project_root = a.project_root
                       AND d.consumer_id = ?3
                       AND d.session_id = a.session_id)
                 ORDER BY s.last_active_at_unix_ms, s.session_id",
            )?;
            let rows = statement.query_map(
                params![
                    kb_id,
                    project_root,
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
        project_root: &str,
        consumer_id: &str,
        session_ids: &[Uuid],
    ) -> Result<()> {
        validate_kb_id(kb_id)?;
        validate_project_root(project_root)?;
        validate_consumer_id(consumer_id)?;
        let kb_id = kb_id.to_owned();
        let project_root = project_root.to_owned();
        let consumer_id = consumer_id.to_owned();
        let session_ids = session_ids.to_vec();
        self.transaction(move |conn| {
            let dreamed_at = Utc::now().timestamp_millis();
            for session_id in session_ids {
                let session_id = session_id.to_string();
                let attached = conn
                    .query_row(
                        "SELECT 1 FROM knowledge_base_session_attachments
                         WHERE kb_id = ?1 AND project_root = ?2 AND session_id = ?3",
                        params![&kb_id, &project_root, &session_id],
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
                     (kb_id, project_root, consumer_id, session_id, dreamed_at_unix_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![&kb_id, &project_root, &consumer_id, &session_id, dreamed_at],
                )?;
            }
            Ok(())
        })
        .await
    }

    pub async fn knowledge_base_last_dreamed_at(
        &self,
        kb_id: &str,
        project_root: &str,
        consumer_id: &str,
    ) -> Result<Option<i64>> {
        validate_kb_id(kb_id)?;
        validate_project_root(project_root)?;
        validate_consumer_id(consumer_id)?;
        let kb_id = kb_id.to_owned();
        let project_root = project_root.to_owned();
        let consumer_id = consumer_id.to_owned();
        self.read(move |conn| {
            conn.query_row(
                "SELECT MAX(last_dreamed_at_unix_ms) FROM (
                    SELECT MAX(dreamed_at_unix_ms) AS last_dreamed_at_unix_ms
                      FROM knowledge_dreamed_sessions
                     WHERE kb_id = ?1 AND project_root = ?2 AND consumer_id = ?3
                    UNION ALL
                    SELECT last_dreamed_at_unix_ms
                      FROM knowledge_dream_schedule_state
                     WHERE kb_id = ?1 AND project_root = ?2 AND consumer_id = ?3
                 )",
                params![kb_id, project_root, consumer_id],
                |row| row.get(0),
            )
            .context("loading knowledge-base last dreamed time")
        })
        .await
    }

    /// The daemon's successful schedule cursor. `checked_at_unix_ms` is
    /// always advanced after a fire, while `last_dreamed_at_unix_ms` advances
    /// only for the no-new-sessions fast path; non-empty runs publish their
    /// displayed time through the immutable completion ledger instead.
    pub async fn record_knowledge_dream_schedule_fire(
        &self,
        kb_id: &str,
        project_root: &str,
        consumer_id: &str,
        checked_at_unix_ms: i64,
        last_dreamed_at_unix_ms: Option<i64>,
    ) -> Result<()> {
        validate_kb_id(kb_id)?;
        validate_project_root(project_root)?;
        validate_consumer_id(consumer_id)?;
        let kb_id = kb_id.to_owned();
        let project_root = project_root.to_owned();
        let consumer_id = consumer_id.to_owned();
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO knowledge_dream_schedule_state
                    (kb_id, project_root, consumer_id, last_scheduled_at_unix_ms, last_dreamed_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(kb_id, project_root, consumer_id) DO UPDATE SET
                    last_scheduled_at_unix_ms = excluded.last_scheduled_at_unix_ms,
                    last_dreamed_at_unix_ms = COALESCE(
                        excluded.last_dreamed_at_unix_ms,
                        knowledge_dream_schedule_state.last_dreamed_at_unix_ms
                    )",
                params![
                    kb_id,
                    project_root,
                    consumer_id,
                    checked_at_unix_ms,
                    last_dreamed_at_unix_ms,
                ],
            )?;
            Ok(())
        })
        .await
    }

    /// Record a successful manual empty check without moving the scheduler's
    /// cursor. Manual and scheduled dreams share the displayed timestamp, but
    /// a user-triggered no-op must not postpone a separately due schedule.
    pub async fn record_knowledge_dream_manual_empty_check(
        &self,
        kb_id: &str,
        project_root: &str,
        consumer_id: &str,
        checked_at_unix_ms: i64,
    ) -> Result<()> {
        validate_kb_id(kb_id)?;
        validate_project_root(project_root)?;
        validate_consumer_id(consumer_id)?;
        let kb_id = kb_id.to_owned();
        let project_root = project_root.to_owned();
        let consumer_id = consumer_id.to_owned();
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO knowledge_dream_schedule_state
                    (kb_id, project_root, consumer_id, last_scheduled_at_unix_ms, last_dreamed_at_unix_ms)
                 VALUES (?1, ?2, ?3, 0, ?4)
                 ON CONFLICT(kb_id, project_root, consumer_id) DO UPDATE SET
                    last_dreamed_at_unix_ms = excluded.last_dreamed_at_unix_ms",
                params![kb_id, project_root, consumer_id, checked_at_unix_ms],
            )?;
            Ok(())
        })
        .await
    }

    pub async fn knowledge_base_last_scheduled_at(
        &self,
        kb_id: &str,
        project_root: &str,
        consumer_id: &str,
    ) -> Result<Option<i64>> {
        validate_kb_id(kb_id)?;
        validate_project_root(project_root)?;
        validate_consumer_id(consumer_id)?;
        let kb_id = kb_id.to_owned();
        let project_root = project_root.to_owned();
        let consumer_id = consumer_id.to_owned();
        self.read(move |conn| {
            conn.query_row(
                "SELECT last_scheduled_at_unix_ms
                   FROM knowledge_dream_schedule_state
                  WHERE kb_id = ?1 AND project_root = ?2 AND consumer_id = ?3",
                params![kb_id, project_root, consumer_id],
                |row| row.get(0),
            )
            .optional()
            .context("loading knowledge-base last scheduled time")
        })
        .await
    }

    pub async fn list_knowledge_dream_workspace_roots(&self) -> Result<Vec<String>> {
        self.read(move |conn| {
            let mut statement = conn.prepare(
                "SELECT project_root
                   FROM (
                     SELECT root_path AS project_root
                       FROM workspace_trust
                      WHERE mode IN ('trust', 'ignore-config')
                     UNION
                     SELECT project_root FROM knowledge_base_session_attachments
                     UNION
                     SELECT project_root FROM knowledge_dream_schedule_state
                   )
                  ORDER BY project_root ASC",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .context("listing knowledge dream workspace roots")
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

fn validate_project_root(value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "project root must not be empty");
    ensure!(value.len() <= 32768, "project root is too long");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::session_log::{SessionEventContext, SessionEventKind};
    use serde_json::json;
    const ROOT_A: &str = "/p";
    const ROOT_B: &str = "/other";

    #[tokio::test]
    async fn attachment_minus_ledger_is_exact_and_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let first = db.create_session("p", "/p", "Build").await.unwrap();
        let second = db.create_session("p", "/p", "Build").await.unwrap();
        db.attach_session_to_knowledge_base("kb", ROOT_A, first.session_id)
            .await
            .unwrap();

        let initial = db
            .undreamed_sessions_for_knowledge_base(
                "kb",
                ROOT_A,
                "consumer",
                HistoryCallerTrust::Trusted,
            )
            .await
            .unwrap();
        assert_eq!(
            initial.iter().map(|row| row.session_id).collect::<Vec<_>>(),
            vec![first.session_id]
        );

        db.record_knowledge_dream_completion("kb", ROOT_A, "consumer", &[first.session_id])
            .await
            .unwrap();
        assert!(
            db.undreamed_sessions_for_knowledge_base(
                "kb",
                ROOT_A,
                "consumer",
                HistoryCallerTrust::Trusted,
            )
            .await
            .unwrap()
            .is_empty()
        );

        db.attach_session_to_knowledge_base("kb", ROOT_A, second.session_id)
            .await
            .unwrap();
        let next = db
            .undreamed_sessions_for_knowledge_base(
                "kb",
                ROOT_A,
                "consumer",
                HistoryCallerTrust::Trusted,
            )
            .await
            .unwrap();
        assert_eq!(
            next.iter().map(|row| row.session_id).collect::<Vec<_>>(),
            vec![second.session_id]
        );
    }

    #[tokio::test]
    async fn dream_session_attachments_are_never_undreamed_sources() {
        let db = Db::open_in_memory().unwrap();
        let ordinary = db.create_session("p", ROOT_A, "Build").await.unwrap();
        let dream = db.create_session("p", ROOT_A, "Dream").await.unwrap();
        let dream_id = dream.session_id;
        db.write(move |conn| {
            conn.execute(
                "UPDATE sessions SET is_dream_session = 1 WHERE session_id = ?1",
                [dream_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        for session_id in [ordinary.session_id, dream_id] {
            db.attach_session_to_knowledge_base("kb", ROOT_A, session_id)
                .await
                .unwrap();
        }

        let sources = db
            .undreamed_sessions_for_knowledge_base(
                "kb",
                ROOT_A,
                "consumer",
                HistoryCallerTrust::Trusted,
            )
            .await
            .unwrap();
        assert_eq!(
            sources
                .iter()
                .map(|source| source.session_id)
                .collect::<Vec<_>>(),
            vec![ordinary.session_id]
        );
    }

    #[tokio::test]
    async fn completion_fails_closed_after_consent_is_revoked() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/p", "Build").await.unwrap();
        db.attach_session_to_knowledge_base("kb", ROOT_A, session.session_id)
            .await
            .unwrap();
        db.detach_session_from_knowledge_base("kb", ROOT_A, session.session_id)
            .await
            .unwrap();
        assert!(
            db.record_knowledge_dream_completion("kb", ROOT_A, "consumer", &[session.session_id])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn scheduled_empty_check_advances_displayed_time_without_a_completion_fact() {
        let db = Db::open_in_memory().unwrap();
        db.record_knowledge_dream_schedule_fire("kb", ROOT_A, "machine-a", 100, Some(100))
            .await
            .unwrap();
        assert_eq!(
            db.knowledge_base_last_scheduled_at("kb", ROOT_A, "machine-a")
                .await
                .unwrap(),
            Some(100)
        );
        assert_eq!(
            db.knowledge_base_last_dreamed_at("kb", ROOT_A, "machine-a")
                .await
                .unwrap(),
            Some(100)
        );
        assert_eq!(
            db.knowledge_base_last_dreamed_at("kb", ROOT_A, "machine-b")
                .await
                .unwrap(),
            None,
            "each machine keeps an independent schedule display"
        );
    }

    #[tokio::test]
    async fn manual_empty_check_advances_displayed_time_without_moving_schedule_cursor() {
        let db = Db::open_in_memory().unwrap();
        db.record_knowledge_dream_schedule_fire("kb", ROOT_A, "machine-a", 100, Some(100))
            .await
            .unwrap();
        db.record_knowledge_dream_manual_empty_check("kb", ROOT_A, "machine-a", 200)
            .await
            .unwrap();

        assert_eq!(
            db.knowledge_base_last_scheduled_at("kb", ROOT_A, "machine-a")
                .await
                .unwrap(),
            Some(100)
        );
        assert_eq!(
            db.knowledge_base_last_dreamed_at("kb", ROOT_A, "machine-a")
                .await
                .unwrap(),
            Some(200)
        );
    }

    #[tokio::test]
    async fn untrusted_dream_source_list_excludes_trusted_compaction_briefs() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("p", "/p", "Visible session title")
            .await
            .unwrap();
        db.attach_session_to_knowledge_base("kb", ROOT_A, session.session_id)
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
            .undreamed_sessions_for_knowledge_base(
                "kb",
                ROOT_A,
                "consumer",
                HistoryCallerTrust::Untrusted,
            )
            .await
            .unwrap();
        assert_eq!(untrusted.len(), 1);
        assert_eq!(untrusted[0].description, "Visible session title");

        let trusted = db
            .undreamed_sessions_for_knowledge_base(
                "kb",
                ROOT_A,
                "consumer",
                HistoryCallerTrust::Trusted,
            )
            .await
            .unwrap();
        assert_eq!(trusted.len(), 1);
        assert_eq!(trusted[0].description, "trusted compaction secret");
    }

    #[tokio::test]
    async fn same_kb_id_is_isolated_by_workspace_root() {
        let db = Db::open_in_memory().unwrap();
        let first = db.create_session("p", ROOT_A, "Build").await.unwrap();
        let second = db.create_session("p", ROOT_B, "Build").await.unwrap();
        db.attach_session_to_knowledge_base("kb", ROOT_A, first.session_id)
            .await
            .unwrap();
        db.attach_session_to_knowledge_base("kb", ROOT_B, second.session_id)
            .await
            .unwrap();
        db.record_knowledge_dream_completion("kb", ROOT_A, "consumer", &[first.session_id])
            .await
            .unwrap();

        assert!(
            db.undreamed_sessions_for_knowledge_base(
                "kb",
                ROOT_A,
                "consumer",
                HistoryCallerTrust::Trusted
            )
            .await
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            db.undreamed_sessions_for_knowledge_base(
                "kb",
                ROOT_B,
                "consumer",
                HistoryCallerTrust::Trusted
            )
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.session_id)
            .collect::<Vec<_>>(),
            vec![second.session_id]
        );
    }

    #[tokio::test]
    async fn workspace_root_enumeration_comes_from_persisted_knowledge_state() {
        let db = Db::open_in_memory().unwrap();
        let first = db.create_session("p", ROOT_A, "Build").await.unwrap();
        db.attach_session_to_knowledge_base("kb", ROOT_A, first.session_id)
            .await
            .unwrap();
        db.record_knowledge_dream_schedule_fire("kb", ROOT_B, "consumer", 10, Some(10))
            .await
            .unwrap();

        assert_eq!(
            db.list_knowledge_dream_workspace_roots().await.unwrap(),
            vec![ROOT_B.to_string(), ROOT_A.to_string()]
        );
    }

    #[tokio::test]
    async fn workspace_root_enumeration_includes_trusted_workspace_without_knowledge_rows() {
        let db = Db::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap();

        db.set_workspace_trust(
            root.path(),
            crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        )
        .await
        .unwrap();

        assert_eq!(
            db.list_knowledge_dream_workspace_roots().await.unwrap(),
            vec![root.path().canonicalize().unwrap().display().to_string()]
        );
    }

    #[tokio::test]
    async fn failed_completion_does_not_advance_visible_dream_status() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", ROOT_A, "Build").await.unwrap();
        db.attach_session_to_knowledge_base("kb", ROOT_A, session.session_id)
            .await
            .unwrap();
        db.record_knowledge_dream_schedule_fire("kb", ROOT_A, "consumer", 100, Some(100))
            .await
            .unwrap();
        db.detach_session_from_knowledge_base("kb", ROOT_A, session.session_id)
            .await
            .unwrap();

        assert!(
            db.record_knowledge_dream_completion("kb", ROOT_A, "consumer", &[session.session_id])
                .await
                .is_err()
        );
        assert_eq!(
            db.knowledge_base_last_scheduled_at("kb", ROOT_A, "consumer")
                .await
                .unwrap(),
            Some(100)
        );
        assert_eq!(
            db.knowledge_base_last_dreamed_at("kb", ROOT_A, "consumer")
                .await
                .unwrap(),
            Some(100)
        );
    }
}
