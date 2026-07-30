//! Durable session-scoped sealed values.  Only the core session layer may
//! resolve a literal; callers listing values receive metadata only.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

#[derive(Clone, PartialEq, Eq)]
pub struct SealedValueMetadata {
    pub value_id: String,
    pub reason: String,
    pub origin: String,
    pub created_at: i64,
    pub origin_session_id: Uuid,
}

impl Db {
    pub async fn upsert_sealed_value(
        &self,
        session_id: Uuid,
        value_id: &str,
        value: &str,
        reason: &str,
        origin: &str,
    ) -> Result<SealedValueMetadata> {
        let now = Utc::now().timestamp();
        let value_id = value_id.to_owned();
        let value = value.to_owned();
        let reason = reason.to_owned();
        let origin = origin.to_owned();
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO sealed_values (session_id, value_id, value, reason, origin, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(session_id, value_id) DO UPDATE SET
                   value = excluded.value, reason = excluded.reason, origin = excluded.origin,
                   created_at = excluded.created_at",
                params![session_id.to_string(), value_id, value, reason, origin, now],
            )
            .context("upserting sealed value")?;
            Ok(SealedValueMetadata {
                value_id,
                reason,
                origin,
                created_at: now,
                origin_session_id: session_id,
            })
        })
        .await
    }

    pub async fn delete_sealed_value(&self, session_id: Uuid, value_id: &str) -> Result<bool> {
        let value_id = value_id.to_owned();
        self.write(move |conn| {
            Ok(conn
                .execute(
                    "DELETE FROM sealed_values WHERE session_id = ?1 AND value_id = ?2",
                    params![session_id.to_string(), value_id],
                )
                .context("deleting sealed value")?
                > 0)
        })
        .await
    }

    pub async fn list_sealed_value_metadata(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<SealedValueMetadata>> {
        self.read(move |conn| list_metadata_conn(conn, session_id))
            .await
    }

    /// Internal injection-only resolution.  Metadata/listing APIs never
    /// expose literals; callers must not send this result to a model or proto.
    pub async fn resolve_sealed_value_for_injection(
        &self,
        session_id: Uuid,
        value_id: &str,
    ) -> Result<Option<String>> {
        let value_id = value_id.to_owned();
        self.read(move |conn| resolve_conn(conn, session_id, &value_id))
            .await
    }
}

fn list_metadata_conn(
    conn: &rusqlite::Connection,
    session_id: Uuid,
) -> Result<Vec<SealedValueMetadata>> {
    let mut stmt = conn.prepare(
        "SELECT value_id, reason, origin, created_at FROM sealed_values
         WHERE session_id = ?1 ORDER BY created_at ASC, value_id ASC",
    )?;
    stmt.query_map([session_id.to_string()], |row| {
        Ok(SealedValueMetadata {
            value_id: row.get(0)?,
            reason: row.get(1)?,
            origin: row.get(2)?,
            created_at: row.get(3)?,
            origin_session_id: session_id,
        })
    })?
    .collect::<rusqlite::Result<Vec<_>>>()
    .context("listing sealed value metadata")
}

fn resolve_conn(
    conn: &rusqlite::Connection,
    session_id: Uuid,
    value_id: &str,
) -> Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM sealed_values WHERE session_id = ?1 AND value_id = ?2",
        params![session_id.to_string(), value_id],
        |row| row.get(0),
    )
    .optional()
    .context("resolving sealed value")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn metadata_never_contains_value_and_fork_copies_its_snapshot() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/repo", "Build").await.unwrap();
        let metadata = db
            .upsert_sealed_value(
                parent.session_id,
                "prod_token",
                "long-high-entropy-token",
                "deployment credential",
                "user",
            )
            .await
            .unwrap();
        assert_eq!(metadata.value_id, "prod_token");
        assert_eq!(metadata.reason, "deployment credential");
        let child = db.create_fork(parent.session_id, None).await.unwrap();
        assert_eq!(
            db.resolve_sealed_value_for_injection(child.session_id, "prod_token")
                .await
                .unwrap()
                .as_deref(),
            Some("long-high-entropy-token")
        );
        assert!(
            db.delete_sealed_value(parent.session_id, "prod_token")
                .await
                .unwrap()
        );
        assert_eq!(
            db.resolve_sealed_value_for_injection(child.session_id, "prod_token")
                .await
                .unwrap(),
            Some("long-high-entropy-token".into())
        );
    }
}
