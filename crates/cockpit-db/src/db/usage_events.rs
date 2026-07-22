//! Autocomplete frequency tally.
//!
//! A 30-day rolling count of accepted picks — models, slash commands,
//! and `@` tags — used purely as a tie-breaker in the three autocomplete
//! surfaces in the TUI crate: slash-command matching, the model picker,
//! and `@` file-tag suggestions. The daemon owns this table; clients
//! emit `RecordUsage` on accept and read the aggregated maps at session
//! start.
//!
//! `kind` is one of `model` / `slash` / `tag`. `project_id` is `NULL`
//! for the global `model` / `slash` tallies and set for `tag` (tags are
//! ranked per project). Rows older than the window are pruned on daemon
//! startup; the window is also re-applied at aggregation time so a
//! between-prunes read never counts stale rows.

use std::collections::HashMap;

use anyhow::{Context, Result};
use rusqlite::params;

use crate::db::Db;

/// Rolling window for the tally, in seconds (30 days).
pub const USAGE_WINDOW_SECS: i64 = 30 * 24 * 60 * 60;

impl Db {
    /// Record one accepted pick. `project_id` is `Some` only for `tag`.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn record_usage(
        &self,
        kind: &str,
        key: &str,
        project_id: Option<&str>,
        ts: i64,
    ) -> Result<()> {
        let kind = kind.to_owned();
        let key = key.to_owned();
        let project_id = project_id.map(str::to_owned);
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO usage_events (kind, key, project_id, ts) VALUES (?1, ?2, ?3, ?4)",
                params![kind, key, project_id, ts],
            )
            .context("inserting usage_event")?;
            Ok(())
        })
    }

    /// Aggregate counts for `kind` within the window `ts >= since`,
    /// grouped by `key`. `project_filter` is applied only when `Some`
    /// (i.e. for `tag`); `model` / `slash` pass `None` for a global
    /// tally.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn usage_counts(
        &self,
        kind: &str,
        project_filter: Option<&str>,
        since: i64,
    ) -> Result<HashMap<String, u64>> {
        self.read_blocking(|conn| {
            let mut map = HashMap::new();
            match project_filter {
                Some(pid) => {
                    let mut stmt = conn.prepare(
                        "SELECT key, COUNT(*) FROM usage_events
                          WHERE kind = ?1 AND ts >= ?2 AND project_id = ?3
                          GROUP BY key",
                    )?;
                    let rows = stmt.query_map(params![kind, since, pid], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })?;
                    for row in rows {
                        let (key, count) = row?;
                        map.insert(key, count.max(0) as u64);
                    }
                }
                None => {
                    let mut stmt = conn.prepare(
                        "SELECT key, COUNT(*) FROM usage_events
                          WHERE kind = ?1 AND ts >= ?2
                          GROUP BY key",
                    )?;
                    let rows = stmt.query_map(params![kind, since], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })?;
                    for row in rows {
                        let (key, count) = row?;
                        map.insert(key, count.max(0) as u64);
                    }
                }
            }
            Ok(map)
        })
    }

    /// Delete rows older than `before` (unix seconds). Returns the number
    /// pruned. Called on daemon startup.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn prune_usage_events(&self, before: i64) -> Result<usize> {
        self.write_blocking(move |conn| {
            let n = conn
                .execute("DELETE FROM usage_events WHERE ts < ?1", params![before])
                .context("pruning usage_events")?;
            Ok(n)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count_for(db: &Db, kind: &str, project: Option<&str>, since: i64, key: &str) -> u64 {
        db.usage_counts(kind, project, since)
            .unwrap()
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    #[test]
    fn window_boundary_includes_29d_excludes_31d() {
        let db = Db::open_in_memory().unwrap();
        let now = 1_000_000_000i64;
        let since = now - USAGE_WINDOW_SECS;
        let day = 24 * 60 * 60;
        // 29 days ago → inside the window; 31 days ago → outside.
        db.record_usage("slash", "model", None, now - 29 * day)
            .unwrap();
        db.record_usage("slash", "model", None, now - 31 * day)
            .unwrap();
        // Only the 29-day-old row counts.
        assert_eq!(count_for(&db, "slash", None, since, "model"), 1);
    }

    #[test]
    fn tag_counts_filter_by_project() {
        let db = Db::open_in_memory().unwrap();
        let now = 1_000_000_000i64;
        let since = now - USAGE_WINDOW_SECS;
        db.record_usage("tag", "src/main.rs", Some("projA"), now)
            .unwrap();
        db.record_usage("tag", "src/main.rs", Some("projA"), now)
            .unwrap();
        db.record_usage("tag", "src/main.rs", Some("projB"), now)
            .unwrap();
        assert_eq!(
            count_for(&db, "tag", Some("projA"), since, "src/main.rs"),
            2
        );
        assert_eq!(
            count_for(&db, "tag", Some("projB"), since, "src/main.rs"),
            1
        );
    }

    #[test]
    fn prune_removes_only_old_rows() {
        let db = Db::open_in_memory().unwrap();
        let now = 1_000_000_000i64;
        let day = 24 * 60 * 60;
        db.record_usage("model", "a/b", None, now - 31 * day)
            .unwrap();
        db.record_usage("model", "a/b", None, now).unwrap();
        let pruned = db.prune_usage_events(now - USAGE_WINDOW_SECS).unwrap();
        assert_eq!(pruned, 1);
        // The recent row survives.
        let since = now - USAGE_WINDOW_SECS;
        assert_eq!(count_for(&db, "model", None, since, "a/b"), 1);
    }
}
