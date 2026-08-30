//! Per-workspace history-recall consent.
//!
//! Cross-workspace discovery is an explicit two-directional capability: the
//! workspace issuing the query enables outbound recall and the workspace that
//! owns a result enables inbound recall. Missing decisions fail closed.

use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

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
                "INSERT INTO workspace_history_scopes \\
                    (project_id, outbound_enabled, inbound_enabled, updated_at_unix_ms) \\
                 VALUES (?1, ?2, ?3, ?4) \\
                 ON CONFLICT(project_id) DO UPDATE SET \\
                    outbound_enabled = excluded.outbound_enabled, \\
                    inbound_enabled = excluded.inbound_enabled, \\
                    updated_at_unix_ms = excluded.updated_at_unix_ms",
                params![project_id, scope.outbound, scope.inbound, now],
            )
            .context("upserting workspace history scope")?;
            Ok(())
        })
        .await
    }

    /// Return this workspace's explicit consent state. Missing rows are the
    /// safe default so callers can render an actionable disabled status.
    pub async fn workspace_history_scope(&self, project_id: &str) -> Result<WorkspaceHistoryScope> {
        validate_project_id(project_id)?;
        let project_id = project_id.to_string();
        self.read(move |conn| workspace_history_scope_conn(conn, &project_id))
            .await
    }

    /// Same-workspace history is always visible. Cross-workspace history
    /// requires the querying workspace's outbound consent and the target
    /// workspace's inbound consent in one database snapshot.
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

    /// Fetch a target session's legacy redaction projection only when the
    /// reader can access that session in this statement's consent snapshot.
    /// The outer option distinguishes an inaccessible/nonexistent session
    /// from an accessible session whose legacy projection is absent.
    pub async fn session_redaction_table_json_for_reader_project(
        &self,
        reader_project: &str,
        session_id: Uuid,
    ) -> Result<Option<Option<String>>> {
        validate_project_id(reader_project)?;
        let reader_project = reader_project.to_string();
        self.read(move |conn| {
            conn.query_row(
                "SELECT s.redaction_table_json
                   FROM sessions AS s
                  WHERE s.session_id = ?1
                    AND (s.project_id = ?2
                         OR (EXISTS (SELECT 1 FROM workspace_history_scopes AS reader
                                     WHERE reader.project_id = ?2
                                       AND reader.outbound_enabled = 1)
                             AND EXISTS (SELECT 1 FROM workspace_history_scopes AS target
                                         WHERE target.project_id = s.project_id
                                           AND target.inbound_enabled = 1)))",
                params![session_id.to_string(), reader_project],
                |row| row.get(0),
            )
            .optional()
            .context("reading consent-scoped session redaction projection")
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
        "SELECT outbound_enabled, inbound_enabled
           FROM workspace_history_scopes
          WHERE project_id = ?1",
        [project_id],
        |row| {
            Ok(WorkspaceHistoryScope {
                outbound: row.get(0)?,
                inbound: row.get(1)?,
            })
        },
    )
    .optional()
    .context("querying workspace history scope")
    .map(|scope| scope.unwrap_or(WorkspaceHistoryScope::CURRENT_WORKSPACE_ONLY))
}

#[cfg(test)]
mod tests {
    use super::*;

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
