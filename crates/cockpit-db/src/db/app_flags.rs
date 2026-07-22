//! Machine-local application flags.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};

use crate::db::Db;

impl Db {
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn app_flag_seen(&self, key: &str) -> Result<bool> {
        let key = key.to_owned();
        self.read_blocking(move |conn| {
            conn.query_row(
                "SELECT seen_at FROM app_flags WHERE key = ?1",
                [key],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
            .context("reading app flag")
        })
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn mark_app_flag_seen(&self, key: &str) -> Result<bool> {
        let key = key.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT OR IGNORE INTO app_flags (key, seen_at) VALUES (?1, ?2)",
                params![key, Utc::now().timestamp()],
            )
            .map(|changes| changes > 0)
            .context("marking app flag seen")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_flag_is_seen_once() {
        let db = Db::open_in_memory().unwrap();
        assert!(!db.app_flag_seen("daemon-autostart").unwrap());
        assert!(db.mark_app_flag_seen("daemon-autostart").unwrap());
        assert!(db.app_flag_seen("daemon-autostart").unwrap());
        assert!(!db.mark_app_flag_seen("daemon-autostart").unwrap());
    }
}
