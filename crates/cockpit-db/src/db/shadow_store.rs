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
    pub async fn upsert_compaction_shadow(
        &self,
        session_id: Uuid,
        payload_json: &str,
    ) -> Result<bool> {
        let payload_json = payload_json.to_string();
        self.transaction(move |conn| {
            let ephemeral = conn
                .query_row(
                    "SELECT ephemeral FROM sessions WHERE session_id = ?1",
                    params![session_id.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .context("querying compaction shadow session")?;
            if ephemeral != Some(0) {
                conn.execute(
                    "DELETE FROM compaction_shadows WHERE session_id = ?1",
                    params![session_id.to_string()],
                )
                .context("clearing compaction shadow for non-durable session")?;
                return Ok(false);
            }

            let now = now_ms();
            conn.execute(
                "INSERT INTO compaction_shadows
                   (session_id, payload_json, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(session_id) DO UPDATE SET
                   payload_json = excluded.payload_json,
                   updated_at = excluded.updated_at",
                params![session_id.to_string(), payload_json, now],
            )
            .context("upserting compaction shadow")?;
            Ok(true)
        })
        .await
    }

    pub async fn compaction_shadow(&self, session_id: Uuid) -> Result<Option<CompactionShadowRow>> {
        self.read(move |conn| {
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
        .await
    }

    pub async fn delete_compaction_shadow(&self, session_id: Uuid) -> Result<()> {
        self.write(move |conn| {
            conn.execute(
                "DELETE FROM compaction_shadows WHERE session_id = ?1",
                params![session_id.to_string()],
            )
            .context("deleting compaction shadow")?;
            Ok(())
        })
        .await
    }

    #[cfg(test)]
    async fn count_compaction_shadows(&self) -> Result<usize> {
        self.read(|conn| {
            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM compaction_shadows", [], |row| {
                    row.get(0)
                })?;
            Ok(count.max(0) as usize)
        })
        .await
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
                .await
                .unwrap()
        );
        assert!(
            db.upsert_compaction_shadow(one, r#"{"brief":"second"}"#)
                .await
                .unwrap()
        );
        assert!(
            db.upsert_compaction_shadow(two, r#"{"brief":"other"}"#)
                .await
                .unwrap()
        );

        assert_eq!(db.count_compaction_shadows().await.unwrap(), 2);
        assert_eq!(
            db.compaction_shadow(one)
                .await
                .unwrap()
                .unwrap()
                .payload_json,
            r#"{"brief":"second"}"#
        );
        assert_eq!(
            db.compaction_shadow(two)
                .await
                .unwrap()
                .unwrap()
                .payload_json,
            r#"{"brief":"other"}"#
        );

        db.delete_session(one).await.unwrap();
        assert!(db.compaction_shadow(one).await.unwrap().is_none());
        assert_eq!(db.count_compaction_shadows().await.unwrap(), 1);
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
            .await
            .unwrap();

        let stored = db.compaction_shadow(session_id).await.unwrap().unwrap();
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
            .await
            .unwrap();

        assert_eq!(
            db.compaction_shadow(session_id)
                .await
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
                .await
                .unwrap()
        );

        assert!(db.compaction_shadow(ephemeral).await.unwrap().is_none());
        assert_eq!(db.count_compaction_shadows().await.unwrap(), 0);
    }
}
