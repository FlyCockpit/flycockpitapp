use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAuditRow {
    pub principal: String,
    pub request_kind: String,
    pub session_id: Option<Uuid>,
    pub verdict: String,
    pub path: Option<String>,
}

impl Db {
    pub fn set_session_shared_with_collaborators(
        &self,
        session_id: Uuid,
        shared: bool,
    ) -> Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE sessions SET shared_with_collaborators = ?1 WHERE session_id = ?2",
                params![shared as i64, session_id.to_string()],
            )
            .context("setting session collaborator sharing")?;
            Ok(())
        })
    }

    pub fn insert_remote_audit(
        &self,
        principal: &str,
        request_kind: &str,
        session_id: Option<Uuid>,
        verdict: &str,
    ) -> Result<()> {
        self.insert_remote_audit_with_path(principal, request_kind, session_id, verdict, None)
    }

    pub fn insert_remote_audit_with_path(
        &self,
        principal: &str,
        request_kind: &str,
        session_id: Option<Uuid>,
        verdict: &str,
        path: Option<&str>,
    ) -> Result<()> {
        let ts_ms = crate::db::session_log::now_ms();
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO remote_principal_audit
                   (ts_ms, principal, request_kind, session_id, verdict, path)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    ts_ms,
                    principal,
                    request_kind,
                    session_id.map(|id| id.to_string()),
                    verdict,
                    path,
                ],
            )
            .context("inserting remote principal audit row")?;
            Ok(())
        })
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn list_remote_audit(&self) -> Result<Vec<RemoteAuditRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT principal, request_kind, session_id, verdict, path
                       FROM remote_principal_audit
                      ORDER BY audit_id ASC",
                )
                .context("preparing remote audit list")?;
            let rows = stmt
                .query_map([], |row| {
                    let sid: Option<String> = row.get("session_id")?;
                    let session_id =
                        sid.as_deref()
                            .map(Uuid::parse_str)
                            .transpose()
                            .map_err(|e| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    0,
                                    rusqlite::types::Type::Text,
                                    Box::new(e),
                                )
                            })?;
                    Ok(RemoteAuditRow {
                        principal: row.get("principal")?,
                        request_kind: row.get("request_kind")?,
                        session_id,
                        verdict: row.get("verdict")?,
                        path: row.get("path")?,
                    })
                })
                .context("querying remote audit rows")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding remote audit row")?);
            }
            Ok(out)
        })
    }

    #[allow(dead_code)]
    pub fn session_shared_with_collaborators(&self, session_id: Uuid) -> Result<Option<bool>> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT shared_with_collaborators FROM sessions WHERE session_id = ?1",
                [session_id.to_string()],
                |row| Ok(row.get::<_, i64>(0)? != 0),
            )
            .optional()
            .context("querying session shared flag")
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Db;

    #[test]
    fn sharing_flag_and_remote_audit_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let session = db
            .create_session("project", "/tmp/project", "Build")
            .unwrap();

        assert_eq!(
            db.session_shared_with_collaborators(session.session_id)
                .unwrap(),
            Some(false)
        );
        db.set_session_shared_with_collaborators(session.session_id, true)
            .unwrap();
        assert_eq!(
            db.session_shared_with_collaborators(session.session_id)
                .unwrap(),
            Some(true)
        );

        db.insert_remote_audit(
            "flycockpit:user-1",
            "send_user_message",
            Some(session.session_id),
            "allowed",
        )
        .unwrap();
        let rows = db.list_remote_audit().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].principal, "flycockpit:user-1");
        assert_eq!(rows[0].request_kind, "send_user_message");
        assert_eq!(rows[0].session_id, Some(session.session_id));
        assert_eq!(rows[0].verdict, "allowed");
        assert_eq!(rows[0].path, None);

        db.insert_remote_audit_with_path(
            "flycockpit:user-1",
            "fs_write",
            Some(session.session_id),
            "allowed",
            Some("src/main.rs"),
        )
        .unwrap();
        let rows = db.list_remote_audit().unwrap();
        assert_eq!(rows[1].path.as_deref(), Some("src/main.rs"));
    }
}
