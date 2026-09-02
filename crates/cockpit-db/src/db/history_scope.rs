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
    /// Read the machine onboarding preference stored in
    /// `machine_history_scope_default`. This is presentation-only: callers
    /// must still create explicit per-workspace consent rows before any
    /// cross-workspace disclosure is allowed.
    pub async fn machine_history_scope_default(&self) -> Result<bool> {
        self.read(|conn| {
            conn.query_row(
                "SELECT cross_workspace_recall_enabled
                   FROM machine_history_scope_default
                  WHERE singleton = 1",
                [],
                |row| row.get::<_, bool>(0),
            )
            .optional()
            .map(|value| value.unwrap_or(false))
            .context("reading machine history scope default")
        })
        .await
    }

    /// Persist this workspace's independent cross-workspace recall consents.
    /// The onboarding-owned machine default is intentionally not consumed
    /// here yet; absent rows are the safe current-workspace-only default.
    pub async fn set_workspace_history_scope(
        &self,
        project_id: &str,
        scope: WorkspaceHistoryScope,
    ) -> Result<()> {
        validate_project_id(project_id)?;
        // A completed revocation must be ordered after every disclosure that
        // already passed its final access check, and before every later one.
        // Tool paths retain the shared permit through their return boundary.
        let _revocation_fence = self.history_scope_gate.write().await;
        let project_id = project_id.to_string();
        let now = Utc::now().timestamp_millis();
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO workspace_history_scopes
                    (project_id, outbound_enabled, inbound_enabled, updated_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(project_id) DO UPDATE SET
                    outbound_enabled = excluded.outbound_enabled,
                    inbound_enabled = excluded.inbound_enabled,
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

    /// Whether `session_id` is visible to `reader_project` in this statement's
    /// consent snapshot. Callers then load the session's vault redaction table
    /// only after this returns true.
    pub async fn session_visible_to_reader_project(
        &self,
        reader_project: &str,
        session_id: Uuid,
    ) -> Result<bool> {
        validate_project_id(reader_project)?;
        let reader_project = reader_project.to_string();
        self.read(move |conn| {
            let found: Option<i64> = conn
                .query_row(
                    "SELECT 1
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
                .context("reading consent-scoped session visibility")?;
            Ok(found.is_some())
        })
        .await
    }

    /// Resolve a session only when it is visible to `reader_project`. The
    /// lookup and both consent rows share one SQLite snapshot, preventing a
    /// cross-workspace existence probe from becoming a disclosure.
    pub async fn session_access_allowed(
        &self,
        reader_project: &str,
        session_id: Uuid,
    ) -> Result<bool> {
        validate_project_id(reader_project)?;
        let reader_project = reader_project.to_string();
        self.read(move |conn| session_access_allowed_conn(conn, &reader_project, session_id))
            .await
    }

    /// Resolve a short id without revealing inaccessible workspaces that use
    /// the same prefix.
    pub async fn accessible_sessions_by_short_id(
        &self,
        reader_project: &str,
        short_id: &str,
    ) -> Result<Vec<Uuid>> {
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
            rows.map(|row| Ok(Uuid::parse_str(&row?)?)).collect()
        })
        .await
    }

    /// Confirm an already-fetched batch immediately before disclosure. One
    /// transaction snapshots every target and both consent rows.
    pub async fn sessions_access_allowed(
        &self,
        reader_project: &str,
        session_ids: &[Uuid],
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

pub(crate) fn session_access_allowed_conn(
    conn: &Connection,
    reader_project: &str,
    session_id: Uuid,
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

    #[tokio::test]
    async fn revocation_waits_for_an_in_flight_disclosure_permit() {
        let db = Db::open_in_memory().unwrap();
        let permit = db.history_scope_disclosure_permit().await;
        let revoking_db = db.clone();
        let revocation = tokio::spawn(async move {
            revoking_db
                .set_workspace_history_scope(
                    "workspace-a",
                    WorkspaceHistoryScope {
                        outbound: false,
                        inbound: false,
                    },
                )
                .await
        });
        tokio::task::yield_now().await;
        assert!(
            !revocation.is_finished(),
            "revocation committed while the disclosure permit was retained"
        );
        drop(permit);
        revocation.await.unwrap().unwrap();
    }
}
