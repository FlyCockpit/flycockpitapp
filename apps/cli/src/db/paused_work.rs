//! Durable paused-session work lifecycle.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PausedWorkStatus {
    Paused,
    Resumed,
    Cancelled,
    FailedToPause,
    Lost,
}

impl PausedWorkStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Paused => "paused",
            Self::Resumed => "resumed",
            Self::Cancelled => "cancelled",
            Self::FailedToPause => "failed_to_pause",
            Self::Lost => "lost",
        }
    }

    fn from_str(value: &str) -> Self {
        match value {
            "paused" => Self::Paused,
            "resumed" => Self::Resumed,
            "cancelled" => Self::Cancelled,
            "failed_to_pause" => Self::FailedToPause,
            "lost" => Self::Lost,
            _ => Self::Lost,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PausedWorkRow {
    pub session_id: Uuid,
    pub status: PausedWorkStatus,
    pub active_agent: String,
    pub project_root: String,
    pub reason: String,
    pub pending_tool_count: i64,
    pub daemon_version: String,
    pub client_version: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub resolved_at: Option<i64>,
}

impl Db {
    pub fn upsert_paused_session_work(
        &self,
        session_id: Uuid,
        active_agent: &str,
        project_root: &str,
        reason: &str,
        pending_tool_count: i64,
        daemon_version: &str,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO paused_session_work (
                    session_id, status, active_agent, project_root, reason,
                    pending_tool_count, daemon_version, created_at, updated_at
                 ) VALUES (?1, 'paused', ?2, ?3, ?4, ?5, ?6, ?7, ?7)
                 ON CONFLICT(session_id) DO UPDATE SET
                    status = 'paused',
                    active_agent = excluded.active_agent,
                    project_root = excluded.project_root,
                    reason = excluded.reason,
                    pending_tool_count = excluded.pending_tool_count,
                    daemon_version = excluded.daemon_version,
                    updated_at = excluded.updated_at,
                    resolved_at = NULL",
                params![
                    session_id.to_string(),
                    active_agent,
                    project_root,
                    reason,
                    pending_tool_count,
                    daemon_version,
                    now,
                ],
            )
            .context("upserting paused session work")?;
            Ok(())
        })
    }

    pub fn mark_paused_session_work_resumed(&self, session_id: Uuid) -> Result<bool> {
        self.resolve_paused_session_work(session_id, PausedWorkStatus::Resumed)
    }

    pub fn cancel_paused_session_work(&self, session_id: Uuid) -> Result<bool> {
        self.resolve_paused_session_work(session_id, PausedWorkStatus::Cancelled)
    }

    fn resolve_paused_session_work(
        &self,
        session_id: Uuid,
        status: PausedWorkStatus,
    ) -> Result<bool> {
        let now = Utc::now().timestamp();
        self.with_conn(|conn| {
            let changed = conn
                .execute(
                    "UPDATE paused_session_work
                        SET status = ?2, updated_at = ?3, resolved_at = ?3
                      WHERE session_id = ?1 AND status = 'paused'",
                    params![session_id.to_string(), status.as_str(), now],
                )
                .context("resolving paused session work")?;
            Ok(changed > 0)
        })
    }

    #[allow(dead_code)]
    pub fn paused_session_work(&self, session_id: Uuid) -> Result<Option<PausedWorkRow>> {
        self.with_conn(|conn| Self::paused_session_work_conn(conn, session_id))
    }

    pub fn paused_session_work_conn(
        conn: &Connection,
        session_id: Uuid,
    ) -> Result<Option<PausedWorkRow>> {
        conn.query_row(
            "SELECT session_id, status, active_agent, project_root, reason,
                    pending_tool_count, daemon_version, client_version,
                    created_at, updated_at, resolved_at
               FROM paused_session_work
              WHERE session_id = ?1 AND status = 'paused'",
            params![session_id.to_string()],
            decode_paused_work,
        )
        .optional()
        .context("reading paused session work")
    }

    pub fn paused_session_work_all(&self) -> Result<Vec<PausedWorkRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT session_id, status, active_agent, project_root, reason,
                            pending_tool_count, daemon_version, client_version,
                            created_at, updated_at, resolved_at
                       FROM paused_session_work
                      WHERE status = 'paused'
                      ORDER BY updated_at DESC",
                )
                .context("preparing paused session work query")?;
            let rows = stmt
                .query_map([], decode_paused_work)
                .context("querying paused session work")?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .context("decoding paused session work")
        })
    }
}

fn decode_paused_work(row: &rusqlite::Row<'_>) -> rusqlite::Result<PausedWorkRow> {
    let session_id: String = row.get(0)?;
    let status: String = row.get(1)?;
    Ok(PausedWorkRow {
        session_id: Uuid::parse_str(&session_id).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?,
        status: PausedWorkStatus::from_str(&status),
        active_agent: row.get(2)?,
        project_root: row.get(3)?,
        reason: row.get(4)?,
        pending_tool_count: row.get(5)?,
        daemon_version: row.get(6)?,
        client_version: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
        resolved_at: row.get(10)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paused_work_round_trips_and_resolves_once() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/p", "Build").unwrap();

        db.upsert_paused_session_work(
            session.session_id,
            "Build",
            "/tmp/p",
            "daemon shutdown",
            2,
            "0.1.test",
        )
        .unwrap();

        let row = db.paused_session_work(session.session_id).unwrap().unwrap();
        assert_eq!(row.session_id, session.session_id);
        assert_eq!(row.status, PausedWorkStatus::Paused);
        assert_eq!(row.active_agent, "Build");
        assert_eq!(row.pending_tool_count, 2);

        assert!(
            db.mark_paused_session_work_resumed(session.session_id)
                .unwrap()
        );
        assert!(
            !db.mark_paused_session_work_resumed(session.session_id)
                .unwrap()
        );
        assert!(
            db.paused_session_work(session.session_id)
                .unwrap()
                .is_none()
        );
    }
}
