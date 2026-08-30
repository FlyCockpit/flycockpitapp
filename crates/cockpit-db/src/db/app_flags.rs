//! Machine-local application flags.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};

use crate::db::Db;

impl Db {
    pub fn app_flag_version_conn(conn: &rusqlite::Connection, key: &str) -> Result<u64> {
        conn.query_row("SELECT 1 FROM app_flags WHERE key = ?1", [key], |_| {
            Ok(1_u64)
        })
        .optional()
        .map(|version| version.unwrap_or(0))
        .context("reading app flag version")
    }

    /// Compare-and-mark one closed, daemon-mapped flag. Version 0 is unseen
    /// and version 1 is seen; replaying expected version 1 is idempotent.
    pub fn mark_app_flag_seen_versioned_conn(
        conn: &rusqlite::Connection,
        key: &str,
        expected_version: u64,
    ) -> Result<Option<(u64, bool)>> {
        let current = Self::app_flag_version_conn(conn, key)?;
        if current != expected_version {
            return Ok(None);
        }
        if current == 1 {
            return Ok(Some((1, false)));
        }
        let changed = conn
            .execute(
                "INSERT OR IGNORE INTO app_flags (key, seen_at) VALUES (?1, ?2)",
                params![key, Utc::now().timestamp()],
            )
            .context("marking versioned app flag seen")?
            > 0;
        Ok(Some((1, changed)))
    }

    pub async fn app_flag_seen(&self, key: &str) -> Result<bool> {
        let key = key.to_owned();
        self.read(move |conn| {
            conn.query_row(
                "SELECT seen_at FROM app_flags WHERE key = ?1",
                [key],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
            .context("reading app flag")
        })
        .await
    }

    pub async fn mark_app_flag_seen(&self, key: &str) -> Result<bool> {
        let key = key.to_owned();
        self.write(move |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO app_flags (key, seen_at) VALUES (?1, ?2)",
                params![key, Utc::now().timestamp()],
            )
            .map(|changes| changes > 0)
            .context("marking app flag seen")
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn app_flag_is_seen_once() {
        let db = Db::open_in_memory().unwrap();
        assert!(!db.app_flag_seen("daemon-autostart").await.unwrap());
        assert!(db.mark_app_flag_seen("daemon-autostart").await.unwrap());
        assert!(db.app_flag_seen("daemon-autostart").await.unwrap());
        assert!(!db.mark_app_flag_seen("daemon-autostart").await.unwrap());
    }
}
