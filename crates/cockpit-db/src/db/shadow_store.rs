//! Durable store for speculative compaction shadows.
//!
//! The typed payload lives in `cockpit-core`; this crate stores it as opaque
//! JSON to preserve the downward-only crate graph.

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;
use crate::db::session_log::now_ms;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionShadowRow {
    pub session_id: Uuid,
    pub payload_json: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Db {
    /// Store or replace the one speculative compaction shadow for a
    /// non-ephemeral session. Returns `false` when the session row is absent or
    /// ephemeral; in both cases any stale shadow row is removed.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn upsert_compaction_shadow(&self, session_id: Uuid, payload_json: &str) -> Result<bool> {
        let payload_json = payload_json.to_string();
        self.write_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin upsert_compaction_shadow tx")?;
            let ephemeral = tx
                .query_row(
                    "SELECT ephemeral FROM sessions WHERE session_id = ?1",
                    params![session_id.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .context("querying compaction shadow session")?;
            if ephemeral != Some(0) {
                tx.execute(
                    "DELETE FROM compaction_shadows WHERE session_id = ?1",
                    params![session_id.to_string()],
                )
                .context("clearing compaction shadow for non-durable session")?;
                tx.commit()
                    .context("commit skipped upsert_compaction_shadow tx")?;
                return Ok(false);
            }

            let now = now_ms();
            tx.execute(
                "INSERT INTO compaction_shadows
                   (session_id, payload_json, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(session_id) DO UPDATE SET
                   payload_json = excluded.payload_json,
                   updated_at = excluded.updated_at",
                params![session_id.to_string(), payload_json, now],
            )
            .context("upserting compaction shadow")?;
            tx.commit().context("commit upsert_compaction_shadow tx")?;
            Ok(true)
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn compaction_shadow(&self, session_id: Uuid) -> Result<Option<CompactionShadowRow>> {
        self.read_blocking(move |conn| {
            conn.query_row(
                "SELECT session_id, payload_json, created_at, updated_at
                   FROM compaction_shadows
                  WHERE session_id = ?1",
                params![session_id.to_string()],
                decode_shadow_row,
            )
            .optional()
            .context("querying compaction shadow")
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn delete_compaction_shadow(&self, session_id: Uuid) -> Result<()> {
        self.write_blocking(move |conn| {
            conn.execute(
                "DELETE FROM compaction_shadows WHERE session_id = ?1",
                params![session_id.to_string()],
            )
            .context("deleting compaction shadow")?;
            Ok(())
        })
    }

    #[cfg(test)]
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    fn count_compaction_shadows(&self) -> Result<usize> {
        self.read_blocking(|conn| {
            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM compaction_shadows", [], |row| {
                    row.get(0)
                })?;
            Ok(count.max(0) as usize)
        })
    }
}

fn decode_shadow_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CompactionShadowRow> {
    let session_id: String = row.get("session_id")?;
    Ok(CompactionShadowRow {
        session_id: Uuid::parse_str(&session_id).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?,
        payload_json: row.get("payload_json")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn session(db: &Db, project: &str) -> Uuid {
        db.create_session(project, "/tmp/project", "Build")
            .await
            .unwrap()
            .session_id
    }

    #[tokio::test]
    async fn upsert_replaces_row_per_session() {
        let db = Db::open_in_memory().unwrap();
        let one = session(&db, "one").await;
        let two = session(&db, "two").await;

        assert!(
            db.upsert_compaction_shadow(one, r#"{"brief":"first"}"#)
                .unwrap()
        );
        assert!(
            db.upsert_compaction_shadow(one, r#"{"brief":"second"}"#)
                .unwrap()
        );
        assert!(
            db.upsert_compaction_shadow(two, r#"{"brief":"other"}"#)
                .unwrap()
        );

        assert_eq!(db.count_compaction_shadows().unwrap(), 2);
        assert_eq!(
            db.compaction_shadow(one).unwrap().unwrap().payload_json,
            r#"{"brief":"second"}"#
        );
        assert_eq!(
            db.compaction_shadow(two).unwrap().unwrap().payload_json,
            r#"{"brief":"other"}"#
        );

        db.delete_session(one, true).await.unwrap();
        assert!(db.compaction_shadow(one).unwrap().is_none());
        assert_eq!(db.count_compaction_shadows().unwrap(), 1);
    }

    #[tokio::test]
    async fn payload_round_trips_with_full_snapshot() {
        let db = Db::open_in_memory().unwrap();
        let session_id = session(&db, "round-trip").await;
        let payload = serde_json::json!({
            "kind": "ready_brief",
            "generation": 7,
            "snapshot_turns": 3,
            "snapshot_tail_turns": 2,
            "snapshot_history": [
                { "role": "user", "content": [{ "type": "text", "text": "hello" }] },
                { "role": "assistant", "content": [{ "text": "world" }], "id": null }
            ],
            "brief": "summary",
            "prepared": {
                "source": "future",
                "history": []
            }
        });
        let payload_json = serde_json::to_string(&payload).unwrap();

        db.upsert_compaction_shadow(session_id, &payload_json)
            .unwrap();

        let stored = db.compaction_shadow(session_id).unwrap().unwrap();
        assert_eq!(stored.payload_json, payload_json);
    }

    #[tokio::test]
    async fn large_payload_spills() {
        let db = Db::open_in_memory().unwrap();
        let session_id = session(&db, "large").await;
        let body = "x".repeat(20 * 1024);
        let payload = serde_json::json!({
            "kind": "ready_brief",
            "snapshot_history": [{ "role": "user", "content": [{ "type": "text", "text": body }] }],
        });
        let payload_json = serde_json::to_string(&payload).unwrap();
        assert!(payload_json.len() > 16 * 1024);

        db.upsert_compaction_shadow(session_id, &payload_json)
            .unwrap();

        assert_eq!(
            db.compaction_shadow(session_id)
                .unwrap()
                .unwrap()
                .payload_json,
            payload_json
        );
    }

    #[tokio::test]
    async fn ephemeral_session_writes_no_rows() {
        let db = Db::open_in_memory().unwrap();
        let parent = session(&db, "ephemeral").await;
        let ephemeral = db
            .create_ephemeral_fork(parent, None)
            .await
            .unwrap()
            .session_id;

        assert!(
            !db.upsert_compaction_shadow(ephemeral, r#"{"brief":"discard"}"#)
                .unwrap()
        );

        assert!(db.compaction_shadow(ephemeral).unwrap().is_none());
        assert_eq!(db.count_compaction_shadows().unwrap(), 0);
    }
}
