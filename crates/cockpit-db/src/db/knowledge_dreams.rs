//! Durable knowledge-dream watermarks.
//!
//! Dream owns writes to this ledger after it has incorporated every session up
//! to the recorded watermark into a named knowledge base. Retrieval uses the
//! value only as a lower bound for the bounded fresh-session fallback; it
//! never advances the watermark or writes knowledge content.

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};

use crate::db::Db;

/// A named KB's durable dream watermark, expressed as session activity Unix
/// milliseconds. Sessions active strictly after this point may not yet have
/// been consolidated into the KB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnowledgeDreamWatermark {
    pub last_dreamed_at_unix_ms: i64,
}

impl Db {
    /// Read the watermark recorded by dream for `knowledge_base_id`.
    ///
    /// An absent row means dream has not established a bounded freshness
    /// window for this KB yet; callers must report that explicitly rather than
    /// treating all history as freshly consolidated.
    pub async fn knowledge_dream_watermark(
        &self,
        knowledge_base_id: &str,
    ) -> Result<Option<KnowledgeDreamWatermark>> {
        let knowledge_base_id = knowledge_base_id.to_string();
        self.read(move |conn| {
            conn.query_row(
                "SELECT last_dreamed_at_unix_ms
                   FROM knowledge_dream_ledger
                  WHERE knowledge_base_id = ?1",
                params![knowledge_base_id],
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

    /// Advance (or initialize) a KB's dream watermark. This is the narrow
    /// ledger write that the dream job will call after durable KB output has
    /// been committed; retrieval must remain read-only.
    pub async fn record_knowledge_dream_watermark(
        &self,
        knowledge_base_id: &str,
        last_dreamed_at_unix_ms: i64,
        updated_at_unix_ms: i64,
    ) -> Result<()> {
        let knowledge_base_id = knowledge_base_id.to_string();
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO knowledge_dream_ledger
                    (knowledge_base_id, last_dreamed_at_unix_ms, updated_at_unix_ms)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(knowledge_base_id) DO UPDATE SET
                    last_dreamed_at_unix_ms = excluded.last_dreamed_at_unix_ms,
                    updated_at_unix_ms = excluded.updated_at_unix_ms
                 WHERE excluded.last_dreamed_at_unix_ms >= knowledge_dream_ledger.last_dreamed_at_unix_ms",
                params![
                    knowledge_base_id,
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
    async fn dream_watermark_is_optional_and_never_moves_backward() {
        let db = Db::open_in_memory().expect("in-memory DB");
        assert!(
            db.knowledge_dream_watermark("project")
                .await
                .expect("read watermark")
                .is_none()
        );

        db.record_knowledge_dream_watermark("project", 100, 110)
            .await
            .expect("record first watermark");
        db.record_knowledge_dream_watermark("project", 90, 120)
            .await
            .expect("ignore stale watermark");

        assert_eq!(
            db.knowledge_dream_watermark("project")
                .await
                .expect("read watermark"),
            Some(KnowledgeDreamWatermark {
                last_dreamed_at_unix_ms: 100,
            })
        );
    }
}
