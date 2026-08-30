//! Durable knowledge-dream watermarks.
//!
//! Dream owns writes to this ledger after it has incorporated every session up
//! to the recorded watermark into a concrete knowledge-base attachment.
//! Retrieval uses the value only as a lower bound for the bounded
//! fresh-session fallback; it never advances the watermark or writes knowledge
//! content.

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

/// A concrete KB attachment's durable dream watermark, expressed as session
/// activity Unix milliseconds. Sessions active strictly after this point may
/// not yet have been consolidated into that attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnowledgeDreamWatermark {
    pub last_dreamed_at_unix_ms: i64,
}

impl Db {
    /// Read the watermark recorded by dream for one concrete KB attachment.
    ///
    /// An absent row means dream has not established a bounded freshness
    /// window for this KB yet; callers must report that explicitly rather than
    /// treating all history as freshly consolidated.
    pub async fn knowledge_dream_watermark(
        &self,
        key: KnowledgeDreamLedgerKey,
    ) -> Result<Option<KnowledgeDreamWatermark>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT last_dreamed_at_unix_ms
                   FROM knowledge_dream_ledger
                  WHERE project_uuid = ?1
                    AND knowledge_base_attachment_id = ?2",
                params![
                    key.project_uuid.as_slice(),
                    key.knowledge_base_attachment_id.as_bytes().as_slice()
                ],
                |row| {
                    Ok(KnowledgeDreamWatermark {
                        last_dreamed_at_unix_ms: row.get(0)?,
                    })
                },
            )
            .optional()
            .context("reading knowledge dream watermark")
        })
        .await
    }

    /// Advance (or initialize) a concrete KB attachment's dream watermark.
    /// This is the narrow ledger write that the dream job will call after
    /// durable KB output has been committed; retrieval must remain read-only.
    pub async fn record_knowledge_dream_watermark(
        &self,
        key: KnowledgeDreamLedgerKey,
        last_dreamed_at_unix_ms: i64,
        updated_at_unix_ms: i64,
    ) -> Result<()> {
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO knowledge_dream_ledger
                    (project_uuid, knowledge_base_attachment_id,
                     last_dreamed_at_unix_ms, updated_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(project_uuid, knowledge_base_attachment_id) DO UPDATE SET
                    last_dreamed_at_unix_ms = excluded.last_dreamed_at_unix_ms,
                    updated_at_unix_ms = excluded.updated_at_unix_ms
                 WHERE excluded.last_dreamed_at_unix_ms >= knowledge_dream_ledger.last_dreamed_at_unix_ms",
                params![
                    key.project_uuid.as_slice(),
                    key.knowledge_base_attachment_id.as_bytes().as_slice(),
                    last_dreamed_at_unix_ms,
                    updated_at_unix_ms
                ],
            )
            .context("recording knowledge dream watermark")?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dream_watermarks_are_scoped_to_project_and_attachment() {
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
            db.knowledge_dream_watermark(key_a)
                .await
                .expect("read watermark")
                .is_none()
        );

        db.record_knowledge_dream_watermark(key_a, 100, 110)
            .await
            .expect("record first watermark");
        db.record_knowledge_dream_watermark(key_a, 90, 120)
            .await
            .expect("ignore stale watermark");

        assert_eq!(
            db.knowledge_dream_watermark(key_a)
                .await
                .expect("read watermark"),
            Some(KnowledgeDreamWatermark {
                last_dreamed_at_unix_ms: 100,
            })
        );
        assert!(
            db.knowledge_dream_watermark(key_b)
                .await
                .expect("read isolated project watermark")
                .is_none()
        );
        assert!(
            db.knowledge_dream_watermark(replacement_key)
                .await
                .expect("read replacement attachment watermark")
                .is_none()
        );
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
