//! Per-workspace history-recall consent (issue #131).
//!
//! This is deliberately separate from workspace trust and execution sandbox
//! state. A cross-workspace recall is allowed only when the reader opted in
//! and the target opted in; missing decisions fail closed.

use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};

use crate::db::Db;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceHistoryScope {
    pub outbound: bool,
    pub inbound: bool,
}

impl WorkspaceHistoryScope {
    pub const CURRENT_WORKSPACE_ONLY: Self = Self {
        outbound: false,
        inbound: false,
    };
}

impl Db {
    /// Persist this workspace's independent cross-workspace recall consents.
    /// The onboarding-owned machine default is intentionally not consumed
    /// here yet; absent rows are the safe current-workspace-only default.
    pub async fn set_workspace_history_scope(
        &self,
        project_id: &str,
        scope: WorkspaceHistoryScope,
    ) -> Result<()> {
        validate_project_id(project_id)?;
        let project_id = project_id.to_string();
        let now = Utc::now().timestamp_millis();
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO workspace_history_scopes \
                    (project_id, outbound_enabled, inbound_enabled, updated_at_unix_ms) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(project_id) DO UPDATE SET \
                    outbound_enabled = excluded.outbound_enabled, \
                    inbound_enabled = excluded.inbound_enabled, \
                    updated_at_unix_ms = excluded.updated_at_unix_ms",
                params![project_id, scope.outbound, scope.inbound, now],
            )
            .context("upserting workspace history scope")?;
            Ok(())
        })
        .await
    }

    pub async fn workspace_history_scope(&self, project_id: &str) -> Result<WorkspaceHistoryScope> {
        validate_project_id(project_id)?;
        let project_id = project_id.to_string();
        self.read(move |conn| workspace_history_scope_conn(conn, &project_id))
            .await
    }

    /// Same-workspace history is always available.  Cross-workspace access
    /// requires both the reader workspace's outbound consent and the target
    /// workspace's inbound consent.  This is not coupled to any sandbox flag.
    pub async fn history_scope_allows(
        &self,
        reader_project: &str,
        target_project: &str,
    ) -> Result<bool> {
        validate_project_id(reader_project)?;
        validate_project_id(target_project)?;
        if reader_project == target_project {
            return Ok(true);
        }
        let reader_project = reader_project.to_string();
        let target_project = target_project.to_string();
        self.read(move |conn| {
            let reader = workspace_history_scope_conn(conn, &reader_project)?;
            let target = workspace_history_scope_conn(conn, &target_project)?;
            Ok(reader.outbound && target.inbound)
        })
        .await
    }

    /// Resolve a session only when it is visible to `reader_project`.  The
    /// lookup and both consent rows share one SQLite snapshot, so callers do
    /// not turn an existence probe into a cross-workspace disclosure.
    pub async fn session_access_allowed(
        &self,
        reader_project: &str,
        session_id: uuid::Uuid,
    ) -> Result<bool> {
        validate_project_id(reader_project)?;
        let reader_project = reader_project.to_string();
        self.read(move |conn| session_access_allowed_conn(conn, &reader_project, session_id))
            .await
    }

    /// Same as [`Self::session_access_allowed`], but resolves a short id
    /// without revealing how many inaccessible workspaces use that prefix.
    pub async fn accessible_sessions_by_short_id(
        &self,
        reader_project: &str,
        short_id: &str,
    ) -> Result<Vec<uuid::Uuid>> {
        validate_project_id(reader_project)?;
        let reader_project = reader_project.to_string();
        let short_id = short_id.to_string();
        self.read(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT s.session_id FROM sessions s
                  WHERE s.short_id = ?1
                    AND (s.project_id = ?2 OR (
                        EXISTS (SELECT 1 FROM workspace_history_scopes reader
                                WHERE reader.project_id = ?2 AND reader.outbound_enabled = 1)
                        AND EXISTS (SELECT 1 FROM workspace_history_scopes target
                                    WHERE target.project_id = s.project_id AND target.inbound_enabled = 1)
                    ))",
            )?;
            let rows = stmt.query_map(params![short_id, reader_project], |row| {
                row.get::<_, String>(0)
            })?;
            let mut visible = Vec::new();
            for row in rows {
                visible.push(uuid::Uuid::parse_str(&row?)?);
            }
            Ok(visible)
        })
        .await
    }

    /// Confirm an already-fetched batch immediately before it is disclosed.
    /// One read transaction snapshots every target and both consent rows.
    pub async fn sessions_access_allowed(
        &self,
        reader_project: &str,
        session_ids: &[uuid::Uuid],
    ) -> Result<bool> {
        validate_project_id(reader_project)?;
        let reader_project = reader_project.to_string();
        let session_ids = session_ids.to_vec();
        self.transaction(move |conn| {
            session_ids
                .into_iter()
                .try_fold(true, |allowed, session_id| {
                    Ok(allowed && session_access_allowed_conn(conn, &reader_project, session_id)?)
                })
        })
        .await
    }
}

fn validate_project_id(project_id: &str) -> Result<()> {
    if project_id.is_empty() || project_id.len() > 4096 {
        bail!("workspace history scope project id must contain between 1 and 4096 bytes");
    }
    Ok(())
}

fn workspace_history_scope_conn(
    conn: &Connection,
    project_id: &str,
) -> Result<WorkspaceHistoryScope> {
    conn.query_row(
        "SELECT outbound_enabled, inbound_enabled FROM workspace_history_scopes WHERE project_id = ?1",
        [project_id],
        |row| Ok(WorkspaceHistoryScope { outbound: row.get(0)?, inbound: row.get(1)? }),
    )
    .optional()
    .context("querying workspace history scope")
    .map(|scope| scope.unwrap_or(WorkspaceHistoryScope::CURRENT_WORKSPACE_ONLY))
}

pub(crate) fn session_access_allowed_conn(
    conn: &Connection,
    reader_project: &str,
    session_id: uuid::Uuid,
) -> Result<bool> {
    let allowed: Option<i64> = conn
        .query_row(
            "SELECT s.project_id = ?1 OR (
                EXISTS (SELECT 1 FROM workspace_history_scopes reader
                        WHERE reader.project_id = ?1 AND reader.outbound_enabled = 1)
                AND EXISTS (SELECT 1 FROM workspace_history_scopes target
                            WHERE target.project_id = s.project_id AND target.inbound_enabled = 1)
             )
             FROM sessions s WHERE s.session_id = ?2",
            params![reader_project, session_id.to_string()],
            |row| row.get(0),
        )
        .optional()
        .context("querying session workspace for history scope")?;
    Ok(allowed == Some(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fresh_workspaces_are_current_workspace_only() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(
            db.workspace_history_scope("workspace-a").await.unwrap(),
            WorkspaceHistoryScope::CURRENT_WORKSPACE_ONLY
        );
        assert!(
            db.history_scope_allows("workspace-a", "workspace-a")
                .await
                .unwrap()
        );
        assert!(
            !db.history_scope_allows("workspace-a", "workspace-b")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn cross_workspace_requires_both_directional_consents() {
        let db = Db::open_in_memory().unwrap();
        for (outbound, inbound, expected) in [
            (false, false, false),
            (false, true, false),
            (true, false, false),
            (true, true, true),
        ] {
            db.set_workspace_history_scope(
                "workspace-a",
                WorkspaceHistoryScope {
                    outbound,
                    inbound: false,
                },
            )
            .await
            .unwrap();
            db.set_workspace_history_scope(
                "workspace-b",
                WorkspaceHistoryScope {
                    outbound: false,
                    inbound,
                },
            )
            .await
            .unwrap();
            assert_eq!(
                db.history_scope_allows("workspace-a", "workspace-b")
                    .await
                    .unwrap(),
                expected
            );
        }
    }
}
