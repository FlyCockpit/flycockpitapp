//! Durable session-scoped sealed values.  Only the core session layer may
//! resolve a literal; callers listing values receive metadata only.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, params};
use uuid::Uuid;

use crate::db::Db;

/// Connection-scoped legacy sealed-value upsert, so a caller can compose it with
/// other writes (a redaction-table persist and a protected-history journal
/// append) inside one [`Db::transaction`] — either all commit or none do. Mirrors
/// [`Db::upsert_sealed_value`], including its refusal to overwrite a scoped
/// value's literal, checked in the same transaction so a concurrent create
/// cannot slip between.
pub fn upsert_sealed_value_conn(
    conn: &Connection,
    session_id: Uuid,
    value_id: &str,
    value: &str,
    reason: &str,
    origin: &str,
) -> Result<SealedValueMetadata> {
    let now = Utc::now().timestamp();
    let scoped: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sealed_value_records
              WHERE scope = 'session' AND scope_key = ?1 AND name = ?2",
            params![session_id.to_string(), value_id],
            |row| row.get(0),
        )
        .context("checking for a scoped record before a legacy upsert")?;
    if scoped > 0 {
        anyhow::bail!(
            "sealed value `{value_id}` is a scoped value; rotate it through \
             the scoped path so its version is bumped and grants fenced, \
             rather than overwriting the literal underneath them"
        );
    }
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
        value_id: value_id.to_owned(),
        reason: reason.to_owned(),
        origin: origin.to_owned(),
        created_at: now,
        origin_session_id: session_id,
    })
}

#[derive(Clone, PartialEq, Eq)]
pub struct SealedValueMetadata {
    pub value_id: String,
    pub reason: String,
    pub origin: String,
    pub created_at: i64,
    pub origin_session_id: Uuid,
}

impl Db {
    /// Write a **legacy, pre-scoped** sealed value row.
    ///
    /// Refuses when a scoped record owns the name, for a sharper reason than
    /// the delete sibling. Overwriting a scoped value's literal here would
    /// leave `sealed_value_records.active_version` untouched and every
    /// outstanding grant unfenced — so a grant authorized against version 1
    /// would go on resolving, and hand its holder a *different secret* than
    /// the one it was granted over. Version pinning
    /// (`authorize_sealed_use`'s `grant.value_version != record.active_version`
    /// check) is precisely what stops a rotation from silently upgrading a
    /// grant to a new secret, and a legacy overwrite would walk straight
    /// around it. Rotation belongs to `Db::rotate_session_sealed_value`.
    ///
    /// This stays `pub` rather than `pub(crate)`: callers outside this crate
    /// legitimately seed *legacy* rows (that path is unchanged and supported),
    /// and the refusal below removes the hazard itself rather than merely
    /// reducing who can reach it. The scoped create writes its own legacy row
    /// by raw SQL inside one transaction, so it does not come through here.
    pub async fn upsert_sealed_value(
        &self,
        session_id: Uuid,
        value_id: &str,
        value: &str,
        reason: &str,
        origin: &str,
    ) -> Result<SealedValueMetadata> {
        let value_id = value_id.to_owned();
        let value = value.to_owned();
        let reason = reason.to_owned();
        let origin = origin.to_owned();
        self.transaction(move |conn| {
            upsert_sealed_value_conn(conn, session_id, &value_id, &value, &reason, &origin)
        })
        .await
    }

    /// Delete a **legacy, pre-scoped** sealed value row.
    ///
    /// Narrowed to the crate and self-defending, because on its own this is
    /// the exact shape of a bug already fixed once: a session-scope *scoped*
    /// value is dual-written (record in `sealed_value_records`, literal here),
    /// so removing only this row leaves the record resolvable with no literal
    /// under it, its name un-tombstoned and its grants unfenced.
    ///
    /// Two things stop that rather than one, so it is impossible rather than
    /// merely unused:
    ///
    /// 1. `pub(crate)` — no caller outside `cockpit-db` can reach it at all.
    ///    The scoped entry point [`Db::delete_sealed_value_for_session`] is
    ///    the only way in from `cockpit-core`.
    /// 2. It refuses outright when a scoped record owns the name, checked in
    ///    the same transaction as the delete so a concurrent create cannot
    ///    slip between. A caller who reaches for the legacy path on a scoped
    ///    value gets an error, not a half-delete.
    #[cfg(test)]
    pub(crate) async fn delete_sealed_value(
        &self,
        session_id: Uuid,
        value_id: &str,
    ) -> Result<bool> {
        let value_id = value_id.to_owned();
        self.transaction(move |conn| {
            let session_key = session_id.to_string();
            let scoped: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sealed_value_records
                      WHERE scope = 'session' AND scope_key = ?1 AND name = ?2",
                    params![session_key, value_id],
                    |row| row.get(0),
                )
                .context("checking for a scoped record before a legacy delete")?;
            if scoped > 0 {
                anyhow::bail!(
                    "sealed value `{value_id}` is a scoped value; delete it through \
                     the scoped path (`delete_sealed_value_for_session`) so its \
                     record, name tombstone and grants are handled too"
                );
            }
            Ok(conn
                .execute(
                    "DELETE FROM sealed_values WHERE session_id = ?1 AND value_id = ?2",
                    params![session_key, value_id],
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

    /// Existence check only — sealed literals are never returned to callers
    /// (child-environment injection is retired).
    pub async fn sealed_value_exists(&self, session_id: Uuid, value_id: &str) -> Result<bool> {
        let value_id = value_id.to_owned();
        self.read(move |conn| exists_conn(conn, session_id, &value_id))
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

fn exists_conn(conn: &rusqlite::Connection, session_id: Uuid, value_id: &str) -> Result<bool> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(1) FROM sealed_values WHERE session_id = ?1 AND value_id = ?2",
            params![session_id.to_string(), value_id],
            |row| row.get(0),
        )
        .context("checking sealed value existence")?;
    Ok(count > 0)
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
        assert!(
            db.sealed_value_exists(child.session_id, "prod_token")
                .await
                .unwrap()
        );
        assert!(
            db.delete_sealed_value(parent.session_id, "prod_token")
                .await
                .unwrap()
        );
        // Child snapshot still has the value after parent delete.
        assert!(
            db.sealed_value_exists(child.session_id, "prod_token")
                .await
                .unwrap()
        );
    }
}
