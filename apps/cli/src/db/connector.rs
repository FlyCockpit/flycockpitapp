use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use super::Db;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorState {
    pub server_url: String,
    pub instance_id: String,
    pub enabled: bool,
    pub status: String,
    pub relay_url: Option<String>,
    pub last_connected_at_ms: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorDisclosure {
    pub enabled: bool,
    pub status: String,
    pub relay_url: Option<String>,
    pub last_error: Option<String>,
}

impl Db {
    pub fn set_connector_enabled(
        &self,
        server_url: &str,
        instance_id: &str,
        enabled: bool,
    ) -> Result<()> {
        let now = now_ms();
        let status = if enabled { "reconnecting" } else { "off" };
        let server_url = server_url.to_owned();
        let instance_id = instance_id.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO connector_state
                       (server_url, instance_id, enabled, status, updated_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(server_url, instance_id) DO UPDATE SET
                       enabled = excluded.enabled,
                       status = excluded.status,
                       last_error = NULL,
                       updated_at_ms = excluded.updated_at_ms",
                params![server_url, instance_id, enabled as i64, status, now],
            )?;
            Ok(())
        })
    }

    pub fn connector_state(
        &self,
        server_url: &str,
        instance_id: &str,
    ) -> Result<Option<ConnectorState>> {
        self.read_blocking(|conn| {
            conn.query_row(
                "SELECT server_url, instance_id, enabled, status, relay_url,
                        last_connected_at_ms, last_error
                   FROM connector_state
                  WHERE server_url = ?1 AND instance_id = ?2",
                params![server_url, instance_id],
                connector_state_from_row,
            )
            .optional()
            .map_err(Into::into)
        })
    }

    pub fn connector_disclosure(
        &self,
        server_url: &str,
        instance_id: &str,
    ) -> Result<Option<ConnectorDisclosure>> {
        Ok(self
            .connector_state(server_url, instance_id)?
            .map(|state| ConnectorDisclosure {
                enabled: state.enabled,
                status: state.status,
                relay_url: state.relay_url,
                last_error: state.last_error,
            }))
    }

    pub fn update_connector_status(
        &self,
        server_url: &str,
        instance_id: &str,
        status: &str,
        relay_url: Option<&str>,
        last_error: Option<&str>,
    ) -> Result<()> {
        let now = now_ms();
        let last_connected_at_ms: Option<i64> = (status == "connected").then_some(now);
        let server_url = server_url.to_owned();
        let instance_id = instance_id.to_owned();
        let status = status.to_owned();
        let relay_url = relay_url.map(str::to_owned);
        let last_error = last_error.map(str::to_owned);
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO connector_state
                       (server_url, instance_id, enabled, status, relay_url,
                        last_connected_at_ms, last_error, updated_at_ms)
                 VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(server_url, instance_id) DO UPDATE SET
                       status = excluded.status,
                       relay_url = COALESCE(excluded.relay_url, connector_state.relay_url),
                       last_connected_at_ms = COALESCE(excluded.last_connected_at_ms,
                                                       connector_state.last_connected_at_ms),
                       last_error = excluded.last_error,
                       updated_at_ms = excluded.updated_at_ms",
                params![
                    server_url,
                    instance_id,
                    status,
                    relay_url,
                    last_connected_at_ms,
                    last_error,
                    now
                ],
            )?;
            Ok(())
        })
    }
}

fn connector_state_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConnectorState> {
    Ok(ConnectorState {
        server_url: row.get("server_url")?,
        instance_id: row.get("instance_id")?,
        enabled: row.get::<_, i64>("enabled")? != 0,
        status: row.get("status")?,
        relay_url: row.get("relay_url")?,
        last_connected_at_ms: row.get("last_connected_at_ms")?,
        last_error: row.get("last_error")?,
    })
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_state_round_trips() {
        let db = Db::open_in_memory().unwrap();
        db.set_connector_enabled("https://app.example.test", "inst-1", true)
            .unwrap();
        db.update_connector_status(
            "https://app.example.test",
            "inst-1",
            "connected",
            Some("wss://relay.example.test/ws"),
            None,
        )
        .unwrap();

        let state = db
            .connector_state("https://app.example.test", "inst-1")
            .unwrap()
            .unwrap();
        assert!(state.enabled);
        assert_eq!(state.status, "connected");
        assert_eq!(
            state.relay_url.as_deref(),
            Some("wss://relay.example.test/ws")
        );

        db.set_connector_enabled("https://app.example.test", "inst-1", false)
            .unwrap();
        let disclosure = db
            .connector_disclosure("https://app.example.test", "inst-1")
            .unwrap()
            .unwrap();
        assert!(!disclosure.enabled);
        assert_eq!(disclosure.status, "off");
    }
}
