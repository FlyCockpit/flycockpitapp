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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionHookDelivery {
    pub compaction_id: Uuid,
    pub edge: String,
    pub payload_json: String,
    pub lease_id: Uuid,
    pub attempt_count: u64,
}

impl Db {
    /// Idempotently enqueue one compaction lifecycle edge. The payload is
    /// immutable for a `(compaction_id, edge)` identity. Returns `true` for a
    /// durable session (including an existing identical row) and `false` for
    /// an absent or ephemeral session, which has no recovery surface.
    pub async fn enqueue_compaction_hook(
        &self,
        session_id: Uuid,
        compaction_id: Uuid,
        edge: &str,
        payload_json: &str,
    ) -> Result<bool> {
        anyhow::ensure!(matches!(edge, "pre" | "post"), "invalid compaction hook edge");
        let edge = edge.to_string();
        let payload_json = payload_json.to_string();
        self.transaction(move |conn| {
            let durable = conn.query_row(
                "SELECT ephemeral=0 FROM sessions WHERE session_id=?1",
                params![session_id.to_string()],
                |row| row.get::<_, bool>(0),
            ).optional().context("querying compaction hook session")?.unwrap_or(false);
            if !durable { return Ok(false); }
            let now = now_ms();
            let inserted = conn.execute(
                "INSERT INTO compaction_hook_outbox
                   (session_id, compaction_id, edge, state, payload_json, created_at, updated_at)
                 VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?5)
                 ON CONFLICT(compaction_id, edge) DO NOTHING",
                params![session_id.to_string(), compaction_id.to_string(), edge, payload_json, now],
            ).context("enqueuing compaction hook")?;
            if inserted == 0 {
                let matches: Option<i64> = conn.query_row(
                    "SELECT 1 FROM compaction_hook_outbox
                      WHERE session_id=?1 AND compaction_id=?2 AND edge=?3 AND payload_json=?4",
                    params![session_id.to_string(), compaction_id.to_string(), edge, payload_json],
                    |row| row.get(0),
                ).optional().context("checking existing compaction hook")?;
                anyhow::ensure!(matches.is_some(), "compaction hook identity reused with different payload");
            }
            Ok(true)
        }).await
    }

    /// Lease a pending delivery, or reclaim an expired delivery after a crash.
    pub async fn lease_compaction_hook(
        &self,
        session_id: Uuid,
        compaction_id: Uuid,
        edge: &str,
        lease_millis: i64,
    ) -> Result<Option<CompactionHookDelivery>> {
        let edge = edge.to_string();
        self.transaction(move |conn| {
            let now = now_ms();
            let lease_id = Uuid::now_v7();
            let expires = now.saturating_add(lease_millis.max(1));
            let changed = conn.execute(
                "UPDATE compaction_hook_outbox
                    SET state='leased', lease_id=?1, lease_expires_at=?2,
                        attempt_count=attempt_count+1, updated_at=?3
                  WHERE session_id=?4 AND compaction_id=?5 AND edge=?6
                    AND (state='pending' OR (state='leased' AND lease_expires_at<=?3))",
                params![lease_id.to_string(), expires, now, session_id.to_string(), compaction_id.to_string(), edge],
            ).context("leasing compaction hook")?;
            if changed == 0 { return Ok(None); }
            let (payload_json, attempt_count): (String, i64) = conn.query_row(
                "SELECT payload_json, attempt_count FROM compaction_hook_outbox
                  WHERE compaction_id=?1 AND edge=?2 AND lease_id=?3",
                params![compaction_id.to_string(), edge, lease_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).context("reading leased compaction hook")?;
            Ok(Some(CompactionHookDelivery {
                compaction_id,
                edge,
                payload_json,
                lease_id,
                attempt_count: attempt_count.max(0) as u64,
            }))
        }).await
    }

    pub async fn complete_compaction_hook(
        &self,
        compaction_id: Uuid,
        edge: &str,
        lease_id: Uuid,
    ) -> Result<bool> {
        let edge = edge.to_string();
        self.write(move |conn| {
            let now = now_ms();
            Ok(conn.execute(
                "UPDATE compaction_hook_outbox
                    SET state='completed', lease_id=NULL, lease_expires_at=NULL,
                        completed_at=?1, updated_at=?1
                  WHERE compaction_id=?2 AND edge=?3 AND state='leased' AND lease_id=?4",
                params![now, compaction_id.to_string(), edge, lease_id.to_string()],
            ).context("completing compaction hook")? == 1)
        }).await
    }

    pub async fn compaction_hook_completed(&self, compaction_id: Uuid, edge: &str) -> Result<bool> {
        let edge = edge.to_string();
        self.read(move |conn| {
            Ok(conn.query_row(
                "SELECT state='completed' FROM compaction_hook_outbox WHERE compaction_id=?1 AND edge=?2",
                params![compaction_id.to_string(), edge],
                |row| row.get::<_, bool>(0),
            ).optional()?.unwrap_or(false))
        }).await
    }

    pub async fn has_unfinished_compaction_hooks(&self, session_id: Uuid) -> Result<bool> {
        self.read(move |conn| {
            Ok(conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM compaction_hook_outbox
                  WHERE session_id=?1 AND state!='completed')",
                params![session_id.to_string()],
                |row| row.get::<_, bool>(0),
            )?)
        })
        .await
    }

    /// Bootstrap recovery owns the session exclusively, so leases left by the
    /// prior process can be reclaimed immediately instead of waiting on a wall
    /// clock timeout.
    pub async fn release_compaction_hook_leases(&self, session_id: Uuid) -> Result<()> {
        self.write(move |conn| {
            conn.execute(
                "UPDATE compaction_hook_outbox SET state='pending', lease_id=NULL,
                    lease_expires_at=NULL, updated_at=?1
                  WHERE session_id=?2 AND state='leased'",
                params![now_ms(), session_id.to_string()],
            ).context("releasing crashed compaction hook leases")?;
            Ok(())
        }).await
    }
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

    #[tokio::test]
    async fn compaction_hook_outbox_covers_crash_cuts_and_large_payloads() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("compaction-recovery.db");
        let db = Db::open(&path).unwrap();
        let session_id = session(&db, "hook-outbox").await;
        let compaction_id = Uuid::now_v7();
        let payload = serde_json::json!({
            "compaction_id": compaction_id,
            "edge": "pre",
            "source": "x".repeat(128 * 1024),
        }).to_string();

        // Crash before execution: pending remains claimable with the exact
        // payload, including payloads much larger than hook stdin normally is.
        assert!(db.enqueue_compaction_hook(session_id, compaction_id, "pre", &payload).await.unwrap());
        drop(db);

        // A real database reopen is the crash boundary after enqueue.
        let db = Db::open(&path).unwrap();
        let first = db.lease_compaction_hook(session_id, compaction_id, "pre", 60_000).await.unwrap().unwrap();
        assert_eq!(first.payload_json, payload);
        assert_eq!(first.attempt_count, 1);
        drop(db);

        // Crash after external execution but before its receipt: bootstrap
        // releases the stale lease and redelivers the same stable identity.
        let db = Db::open(&path).unwrap();
        db.release_compaction_hook_leases(session_id).await.unwrap();
        let second = db.lease_compaction_hook(session_id, compaction_id, "pre", 60_000).await.unwrap().unwrap();
        assert_eq!(second.compaction_id, first.compaction_id);
        assert_eq!(second.edge, first.edge);
        assert_eq!(second.attempt_count, 2);

        // Crash after receipt: completed rows are terminal and cannot lease.
        assert!(db.complete_compaction_hook(compaction_id, "pre", second.lease_id).await.unwrap());
        drop(db);
        let db = Db::open(&path).unwrap();
        assert!(db.compaction_hook_completed(compaction_id, "pre").await.unwrap());
        assert!(db.lease_compaction_hook(session_id, compaction_id, "pre", 1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn compaction_hook_identity_rejects_payload_drift() {
        let db = Db::open_in_memory().unwrap();
        let session_id = session(&db, "hook-identity").await;
        let compaction_id = Uuid::now_v7();
        assert!(db.enqueue_compaction_hook(session_id, compaction_id, "post", "one").await.unwrap());
        assert!(db.enqueue_compaction_hook(session_id, compaction_id, "post", "one").await.unwrap());
        assert!(db.enqueue_compaction_hook(session_id, compaction_id, "post", "two").await.is_err());
    }
}
