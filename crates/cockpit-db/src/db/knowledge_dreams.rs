//! Durable knowledge-dream ordering boundaries.
//!
//! Dream snapshots a project's globally monotonic session-event sequence before
//! reading input, then records that exact boundary only after it has durably
//! incorporated all events through it into a concrete knowledge-base
//! attachment. Retrieval uses the value only to find sessions with a later
//! event; it never advances the boundary or writes knowledge content.

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

/// The durable identity of a concrete KB attachment in one project.
///
/// `knowledge_base_attachment_id` is an immutable UUID derived from a
/// workspace KB's concrete source (or assigned by a host-owned installer). It
/// is intentionally not the user-configured registry name: a replacement
/// source receives a new UUID even if it reuses that name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnowledgeDreamLedgerKey {
    pub project_uuid: [u8; 16],
    pub knowledge_base_attachment_id: Uuid,
}

/// A concrete KB attachment's durable dream boundary. Sessions with an event
/// whose globally monotonic sequence is strictly greater than this value may
/// not yet have been consolidated into that attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnowledgeDreamBoundary {
    pub last_dreamed_session_event_seq: i64,
}

impl Db {
    /// Read the ordering boundary recorded by dream for one concrete KB
    /// attachment.
    ///
    /// An absent row means dream has not established a bounded freshness
    /// window for this KB yet; callers must report that explicitly rather than
    /// treating all history as freshly consolidated.
    pub async fn knowledge_dream_boundary(
        &self,
        key: KnowledgeDreamLedgerKey,
    ) -> Result<Option<KnowledgeDreamBoundary>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT last_dreamed_session_event_seq
                   FROM knowledge_dream_ledger
                  WHERE project_uuid = ?1
                    AND knowledge_base_attachment_id = ?2",
                params![
                    key.project_uuid.as_slice(),
                    key.knowledge_base_attachment_id.as_bytes().as_slice()
                ],
                |row| {
                    Ok(KnowledgeDreamBoundary {
                        last_dreamed_session_event_seq: row.get(0)?,
                    })
                },
            )
            .optional()
            .context("reading knowledge dream boundary")
        })
        .await
    }

    /// Snapshot the current project-local session-event boundary for a dream
    /// run. The caller must incorporate every event through the returned
    /// sequence before recording it after the KB output is durable. Events
    /// committed after this read necessarily receive a greater sequence and
    /// remain eligible for fresh-session retrieval.
    pub async fn snapshot_knowledge_dream_boundary(&self, project_uuid: [u8; 16]) -> Result<i64> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT COALESCE(MAX(e.seq), 0)
                   FROM sessions AS s
                   JOIN project_identities AS p ON p.project_id = s.project_id
              LEFT JOIN session_events AS e ON e.session_id = s.session_id
                  WHERE p.project_uuid = ?1",
                [project_uuid.as_slice()],
                |row| row.get(0),
            )
            .context("snapshotting knowledge dream boundary")
        })
        .await
    }

    /// Advance (or initialize) a concrete KB attachment's dream boundary.
    /// This is the narrow ledger write that the dream job calls only after the
    /// matching KB output has been committed; retrieval remains read-only.
    pub async fn record_knowledge_dream_boundary(
        &self,
        key: KnowledgeDreamLedgerKey,
        last_dreamed_session_event_seq: i64,
        updated_at_unix_ms: i64,
    ) -> Result<()> {
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO knowledge_dream_ledger
                    (project_uuid, knowledge_base_attachment_id,
                     last_dreamed_session_event_seq, updated_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(project_uuid, knowledge_base_attachment_id) DO UPDATE SET
                    last_dreamed_session_event_seq = excluded.last_dreamed_session_event_seq,
                    updated_at_unix_ms = excluded.updated_at_unix_ms
                 WHERE excluded.last_dreamed_session_event_seq >= knowledge_dream_ledger.last_dreamed_session_event_seq",
                params![
                    key.project_uuid.as_slice(),
                    key.knowledge_base_attachment_id.as_bytes().as_slice(),
                    last_dreamed_session_event_seq,
                    updated_at_unix_ms
                ],
            )
            .context("recording knowledge dream boundary")?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dream_boundaries_are_scoped_to_project_and_attachment() {
        let db = Db::open_in_memory().expect("in-memory DB");
        let attachment = Uuid::from_u128(1);
        let project_a = ensure_project_identity(&db, "project-a").await;
        let project_b = ensure_project_identity(&db, "project-b").await;
        let key_a = KnowledgeDreamLedgerKey {
            project_uuid: project_a,
            knowledge_base_attachment_id: attachment,
        };
        let key_b = KnowledgeDreamLedgerKey {
            project_uuid: project_b,
            knowledge_base_attachment_id: attachment,
        };
        let replacement_key = KnowledgeDreamLedgerKey {
            project_uuid: project_a,
            knowledge_base_attachment_id: Uuid::from_u128(2),
        };
        assert!(
            db.knowledge_dream_boundary(key_a)
                .await
                .expect("read watermark")
                .is_none()
        );

        db.record_knowledge_dream_boundary(key_a, 100, 110)
            .await
            .expect("record first boundary");
        db.record_knowledge_dream_boundary(key_a, 90, 120)
            .await
            .expect("ignore stale boundary");

        assert_eq!(
            db.knowledge_dream_boundary(key_a)
                .await
                .expect("read boundary"),
            Some(KnowledgeDreamBoundary {
                last_dreamed_session_event_seq: 100,
            })
        );
        assert!(
            db.knowledge_dream_boundary(key_b)
                .await
                .expect("read isolated project boundary")
                .is_none()
        );
        assert!(
            db.knowledge_dream_boundary(replacement_key)
                .await
                .expect("read replacement attachment boundary")
                .is_none()
        );
    }

    #[tokio::test]
    async fn dream_boundary_snapshots_the_exact_project_event_sequence() {
        let db = Db::open_in_memory().expect("in-memory DB");
        let session = db
            .create_session("project-a", "/project", "test")
            .await
            .unwrap();
        let first = db
            .insert_session_event(
                session.session_id,
                crate::db::session_log::SessionEventKind::UserMessage,
                None,
                None,
                &serde_json::json!({ "text": "before dream" }),
            )
            .await
            .unwrap();
        let project_uuid = db
            .authoritative_project_uuid("project-a")
            .await
            .unwrap()
            .unwrap();

        let boundary = db
            .snapshot_knowledge_dream_boundary(project_uuid)
            .await
            .unwrap();
        let later = db
            .insert_session_event(
                session.session_id,
                crate::db::session_log::SessionEventKind::UserMessage,
                None,
                None,
                &serde_json::json!({ "text": "after dream snapshot" }),
            )
            .await
            .unwrap();

        assert_eq!(boundary, first);
        assert!(later > boundary);
    }

    async fn ensure_project_identity(db: &Db, project_id: &str) -> [u8; 16] {
        let project_id = project_id.to_string();
        db.write(move |conn| {
            let row = Db::build_new_session_row_conn(conn, &project_id, "/project", "test")?;
            Db::insert_session_row_conn(conn, &row)?;
            Db::authoritative_project_uuid_conn(conn, &project_id)?.context("project UUID")
        })
        .await
        .expect("create project identity")
    }
}
