//! Remote-principal audit upload cursor state.

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};

use crate::db::Db;
use crate::db::session_log::now_ms;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAuditUploadState {
    pub server_url: String,
    pub instance_id: String,
    pub cursor_audit_id: i64,
    pub last_uploaded_at_ms: Option<i64>,
    pub last_error: Option<String>,
    pub updated_at_ms: i64,
}

impl Db {
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn upsert_remote_audit_upload_state(
        &self,
        server_url: &str,
        instance_id: &str,
    ) -> Result<()> {
        let now = now_ms();
        let server_url = server_url.to_owned();
        let instance_id = instance_id.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO remote_audit_upload_state
                   (server_url, instance_id, cursor_audit_id, updated_at_ms)
                 VALUES (?1, ?2, 0, ?3)
                 ON CONFLICT(server_url, instance_id) DO UPDATE SET
                   updated_at_ms = excluded.updated_at_ms",
                params![server_url, instance_id, now],
            )
            .context("upserting remote audit upload state")?;
            Ok(())
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn remote_audit_upload_state(
        &self,
        server_url: &str,
        instance_id: &str,
    ) -> Result<Option<RemoteAuditUploadState>> {
        self.read_blocking(|conn| {
            conn.query_row(
                "SELECT server_url, instance_id, cursor_audit_id,
                        last_uploaded_at_ms, last_error, updated_at_ms
                   FROM remote_audit_upload_state
                  WHERE server_url = ?1 AND instance_id = ?2",
                params![server_url, instance_id],
                decode_state,
            )
            .optional()
            .context("querying remote audit upload state")
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn list_remote_audit_upload_states(&self) -> Result<Vec<RemoteAuditUploadState>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT server_url, instance_id, cursor_audit_id,
                            last_uploaded_at_ms, last_error, updated_at_ms
                       FROM remote_audit_upload_state
                      ORDER BY server_url, instance_id",
                )
                .context("preparing list_remote_audit_upload_states")?;
            let rows = stmt
                .query_map([], decode_state)
                .context("querying remote_audit_upload_state")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding remote_audit_upload_state row")?);
            }
            Ok(out)
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn update_remote_audit_upload_cursor(
        &self,
        server_url: &str,
        instance_id: &str,
        cursor_audit_id: i64,
    ) -> Result<()> {
        let now = now_ms();
        let server_url = server_url.to_owned();
        let instance_id = instance_id.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO remote_audit_upload_state
                   (server_url, instance_id, cursor_audit_id, last_uploaded_at_ms, last_error, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, NULL, ?4)
                 ON CONFLICT(server_url, instance_id) DO UPDATE SET
                   cursor_audit_id     = MAX(cursor_audit_id, excluded.cursor_audit_id),
                   last_uploaded_at_ms = excluded.last_uploaded_at_ms,
                   last_error          = NULL,
                   updated_at_ms       = excluded.updated_at_ms",
                params![server_url, instance_id, cursor_audit_id, now],
            )
            .context("updating remote audit upload cursor")?;
            Ok(())
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn update_remote_audit_upload_error(
        &self,
        server_url: &str,
        instance_id: &str,
        error: &str,
    ) -> Result<()> {
        let now = now_ms();
        let server_url = server_url.to_owned();
        let instance_id = instance_id.to_owned();
        let error = error.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO remote_audit_upload_state
                   (server_url, instance_id, cursor_audit_id, last_error, updated_at_ms)
                 VALUES (?1, ?2, 0, ?3, ?4)
                 ON CONFLICT(server_url, instance_id) DO UPDATE SET
                   last_error    = excluded.last_error,
                   updated_at_ms = excluded.updated_at_ms",
                params![server_url, instance_id, error, now],
            )
            .context("updating remote audit upload error")?;
            Ok(())
        })
    }
}

fn decode_state(row: &rusqlite::Row<'_>) -> rusqlite::Result<RemoteAuditUploadState> {
    Ok(RemoteAuditUploadState {
        server_url: row.get("server_url")?,
        instance_id: row.get("instance_id")?,
        cursor_audit_id: row.get("cursor_audit_id")?,
        last_uploaded_at_ms: row.get("last_uploaded_at_ms")?,
        last_error: row.get("last_error")?,
        updated_at_ms: row.get("updated_at_ms")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_state_round_trips_and_cursor_is_monotonic() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_remote_audit_upload_state("https://app.example.test", "inst-1")
            .unwrap();
        let state = db
            .remote_audit_upload_state("https://app.example.test", "inst-1")
            .unwrap()
            .unwrap();
        assert_eq!(state.cursor_audit_id, 0);

        db.update_remote_audit_upload_cursor("https://app.example.test", "inst-1", 10)
            .unwrap();
        db.update_remote_audit_upload_cursor("https://app.example.test", "inst-1", 7)
            .unwrap();
        let state = db
            .remote_audit_upload_state("https://app.example.test", "inst-1")
            .unwrap()
            .unwrap();
        assert_eq!(state.cursor_audit_id, 10);
        assert!(state.last_uploaded_at_ms.is_some());

        db.update_remote_audit_upload_error("https://app.example.test", "inst-1", "offline")
            .unwrap();
        let states = db.list_remote_audit_upload_states().unwrap();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].last_error.as_deref(), Some("offline"));
    }
}
