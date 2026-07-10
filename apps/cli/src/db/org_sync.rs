//! Enterprise org-policy session-log sync state.

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};
use serde_json::Value;

use crate::db::Db;
use crate::db::session_log::{SessionEventRow, now_ms};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgSyncState {
    pub server_url: String,
    pub org_id: String,
    pub cursor_seq: i64,
    pub policy_version: Option<String>,
    pub enabled: bool,
    pub last_synced_at_ms: Option<i64>,
    pub last_error: Option<String>,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgSyncDisclosure {
    pub org_id: String,
    pub cursor_seq: i64,
    pub last_synced_at_ms: Option<i64>,
}

impl Db {
    pub fn upsert_org_sync_policy(
        &self,
        server_url: &str,
        org_id: &str,
        policy_version: Option<&str>,
        policy_json: &Value,
        enabled: bool,
    ) -> Result<()> {
        let policy_json =
            serde_json::to_string(policy_json).context("serializing org sync policy")?;
        let updated_at_ms = now_ms();
        let server_url = server_url.to_owned();
        let org_id = org_id.to_owned();
        let policy_version = policy_version.map(str::to_owned);
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO sync_state
                   (server_url, org_id, cursor_seq, policy_version, policy_json, enabled, last_error, updated_at_ms)
                 VALUES (?1, ?2, 0, ?3, ?4, ?5, NULL, ?6)
                 ON CONFLICT(server_url, org_id) DO UPDATE SET
                   policy_version = excluded.policy_version,
                   policy_json    = excluded.policy_json,
                   enabled        = excluded.enabled,
                   last_error     = NULL,
                   updated_at_ms  = excluded.updated_at_ms",
                params![
                    server_url,
                    org_id,
                    policy_version,
                    policy_json,
                    if enabled { 1_i64 } else { 0_i64 },
                    updated_at_ms,
                ],
            )
            .context("upserting org sync policy")?;
            Ok(())
        })
    }

    pub fn org_sync_state(&self, server_url: &str, org_id: &str) -> Result<Option<OrgSyncState>> {
        self.read_blocking(|conn| {
            conn.query_row(
                "SELECT server_url, org_id, cursor_seq, policy_version, enabled,
                        last_synced_at_ms, last_error, updated_at_ms
                   FROM sync_state
                  WHERE server_url = ?1 AND org_id = ?2",
                params![server_url, org_id],
                decode_state,
            )
            .optional()
            .context("querying org sync state")
        })
    }

    pub fn active_org_sync_state_for_server(
        &self,
        server_url: &str,
    ) -> Result<Option<OrgSyncState>> {
        self.read_blocking(|conn| {
            conn.query_row(
                "SELECT server_url, org_id, cursor_seq, policy_version, enabled,
                        last_synced_at_ms, last_error, updated_at_ms
                   FROM sync_state
                  WHERE server_url = ?1 AND enabled = 1
                  ORDER BY updated_at_ms DESC
                  LIMIT 1",
                [server_url],
                decode_state,
            )
            .optional()
            .context("querying active org sync state")
        })
    }

    pub fn org_sync_disclosure_for_server(
        &self,
        server_url: &str,
    ) -> Result<Option<OrgSyncDisclosure>> {
        Ok(self
            .active_org_sync_state_for_server(server_url)?
            .map(|state| OrgSyncDisclosure {
                org_id: state.org_id,
                cursor_seq: state.cursor_seq,
                last_synced_at_ms: state.last_synced_at_ms,
            }))
    }

    pub fn list_org_sync_states(&self) -> Result<Vec<OrgSyncState>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT server_url, org_id, cursor_seq, policy_version, enabled,
                            last_synced_at_ms, last_error, updated_at_ms
                       FROM sync_state
                      ORDER BY server_url, org_id",
                )
                .context("preparing list_org_sync_states")?;
            let rows = stmt
                .query_map([], decode_state)
                .context("querying sync_state")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding sync_state row")?);
            }
            Ok(out)
        })
    }

    pub fn mark_org_sync_disabled(&self, server_url: &str) -> Result<()> {
        let updated_at_ms = now_ms();
        let server_url = server_url.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sync_state
                    SET enabled = 0, updated_at_ms = ?2
                  WHERE server_url = ?1",
                params![server_url, updated_at_ms],
            )
            .context("marking org sync disabled")?;
            Ok(())
        })
    }

    pub fn update_org_sync_cursor(
        &self,
        server_url: &str,
        org_id: &str,
        cursor_seq: i64,
    ) -> Result<()> {
        let now = now_ms();
        let server_url = server_url.to_owned();
        let org_id = org_id.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sync_state
                    SET cursor_seq = MAX(cursor_seq, ?3),
                        last_synced_at_ms = ?4,
                        last_error = NULL,
                        updated_at_ms = ?4
                  WHERE server_url = ?1 AND org_id = ?2",
                params![server_url, org_id, cursor_seq, now],
            )
            .context("updating org sync cursor")?;
            Ok(())
        })
    }

    pub fn update_org_sync_error(&self, server_url: &str, org_id: &str, error: &str) -> Result<()> {
        let now = now_ms();
        let server_url = server_url.to_owned();
        let org_id = org_id.to_owned();
        let error = error.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sync_state
                    SET last_error = ?3,
                        updated_at_ms = ?4
                  WHERE server_url = ?1 AND org_id = ?2",
                params![server_url, org_id, error, now],
            )
            .context("updating org sync error")?;
            Ok(())
        })
    }

    pub fn list_org_sync_events_after(
        &self,
        cursor_seq: i64,
        limit: usize,
    ) -> Result<Vec<SessionEventRow>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT seq, session_id, ts_ms, type, agent, call_id, task_call_id, label, data_json
                       FROM session_events
                      WHERE seq > ?1
                      ORDER BY seq ASC
                      LIMIT ?2",
                )
                .context("preparing list_org_sync_events_after")?;
            let rows = stmt
                .query_map(params![cursor_seq, limit as i64], |row| {
                    let sid: String = row.get("session_id")?;
                    let data_json: String = row.get("data_json")?;
                    Ok((|| {
                        let session_id = uuid::Uuid::parse_str(&sid)
                            .with_context(|| format!("session_id `{sid}`"))?;
                        let data: Value =
                            serde_json::from_str(&data_json).context("deserializing data_json")?;
                        Ok::<SessionEventRow, anyhow::Error>(SessionEventRow {
                            seq: row.get("seq").map_err(anyhow::Error::from)?,
                            session_id,
                            ts_ms: row.get("ts_ms").map_err(anyhow::Error::from)?,
                            kind: row.get("type").map_err(anyhow::Error::from)?,
                            agent: row.get("agent").map_err(anyhow::Error::from)?,
                            call_id: row.get("call_id").map_err(anyhow::Error::from)?,
                            task_call_id: row.get("task_call_id").map_err(anyhow::Error::from)?,
                            label: row.get("label").map_err(anyhow::Error::from)?,
                            origin_principal: None,
                            data,
                        })
                    })())
                })
                .context("querying org sync session_events")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding org sync event row")??);
            }
            Ok(out)
        })
    }
}

fn decode_state(row: &rusqlite::Row<'_>) -> rusqlite::Result<OrgSyncState> {
    let enabled: i64 = row.get("enabled")?;
    Ok(OrgSyncState {
        server_url: row.get("server_url")?,
        org_id: row.get("org_id")?,
        cursor_seq: row.get("cursor_seq")?,
        policy_version: row.get("policy_version")?,
        enabled: enabled != 0,
        last_synced_at_ms: row.get("last_synced_at_ms")?,
        last_error: row.get("last_error")?,
        updated_at_ms: row.get("updated_at_ms")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn state_round_trips_and_disclosure_only_reports_enabled_policy() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_org_sync_policy(
            "https://app.example.test",
            "org-1",
            Some("v1"),
            &json!({"enabled": true}),
            true,
        )
        .unwrap();

        let disclosure = db
            .org_sync_disclosure_for_server("https://app.example.test")
            .unwrap()
            .unwrap();
        assert_eq!(disclosure.org_id, "org-1");
        assert_eq!(disclosure.cursor_seq, 0);

        db.mark_org_sync_disabled("https://app.example.test")
            .unwrap();
        assert!(
            db.org_sync_disclosure_for_server("https://app.example.test")
                .unwrap()
                .is_none()
        );
    }
}
