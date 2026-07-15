//! Retention pass for payload-heavy session tables.

use anyhow::{Context, Result};
use rusqlite::{Connection, ErrorCode, OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RetentionConfig {
    /// Payload-row retention window in days.
    #[serde(default = "default_retention_payload_window_days")]
    pub payload_window_days: u32,
    /// Whole-session retention window in days.
    #[serde(default)]
    pub session_window_days: u32,
    /// Periodic retention sweep interval in hours.
    #[serde(default = "default_retention_sweep_interval_hours")]
    pub sweep_interval_hours: u32,
    /// Deleted-row threshold for vacuum.
    #[serde(default = "default_retention_vacuum_min_deletions")]
    pub vacuum_min_deletions: u64,
    /// Vacuum interval in days.
    #[serde(default = "default_retention_vacuum_interval_days")]
    pub vacuum_interval_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            payload_window_days: default_retention_payload_window_days(),
            session_window_days: 0,
            sweep_interval_hours: default_retention_sweep_interval_hours(),
            vacuum_min_deletions: default_retention_vacuum_min_deletions(),
            vacuum_interval_days: default_retention_vacuum_interval_days(),
        }
    }
}

fn default_retention_payload_window_days() -> u32 {
    30
}

fn default_retention_sweep_interval_hours() -> u32 {
    6
}

fn default_retention_vacuum_min_deletions() -> u64 {
    1000
}

fn default_retention_vacuum_interval_days() -> u32 {
    7
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetentionOutcome {
    pub sessions_expired: u64,
    pub payload_rows_deleted: u64,
    pub vacuumed: bool,
}

impl Db {
    /// Delete old payload rows for closed sessions, preserving session rows.
    pub fn prune_session_payloads(&self, payload_cutoff_secs: i64) -> Result<u64> {
        if payload_cutoff_secs <= 0 {
            return Ok(0);
        }
        self.write_blocking(move |conn| prune_session_payloads_conn(conn, payload_cutoff_secs))
    }

    /// Delete old closed, non-ephemeral root sessions whose subtrees are closed.
    pub fn expire_old_sessions(&self, session_cutoff_secs: i64) -> Result<u64> {
        if session_cutoff_secs <= 0 {
            return Ok(0);
        }
        let roots = self.read_blocking(|conn| old_session_roots(conn, session_cutoff_secs))?;
        let mut removed = 0;
        for root in roots {
            self.delete_session(root, true)
                .with_context(|| format!("expiring old session {root}"))?;
            removed += 1;
        }
        Ok(removed)
    }

    /// Decide whether retention should vacuum after a pass.
    pub fn should_vacuum(&self, deleted: u64, now_secs: i64, cfg: &RetentionConfig) -> bool {
        if deleted >= cfg.vacuum_min_deletions {
            return true;
        }
        if cfg.vacuum_interval_days == 0 {
            return false;
        }
        let last = self.last_vacuum_secs().ok().flatten().unwrap_or(0);
        now_secs.saturating_sub(last) >= (cfg.vacuum_interval_days as i64) * 86_400
    }

    /// Record a successful retention vacuum timestamp.
    pub fn record_vacuum(&self, now_secs: i64) -> Result<()> {
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO retention_meta (key, value) VALUES ('last_vacuum_secs', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![now_secs],
            )
            .context("recording retention vacuum timestamp")?;
            Ok(())
        })
    }

    /// Run the two-tier retention pass and optional on-disk vacuum.
    pub fn run_retention_pass(
        &self,
        cfg: &RetentionConfig,
        now_secs: i64,
    ) -> Result<RetentionOutcome> {
        let mut outcome = RetentionOutcome::default();

        if cfg.session_window_days > 0 {
            let cutoff = now_secs - (cfg.session_window_days as i64) * 86_400;
            outcome.sessions_expired = self.expire_old_sessions(cutoff)?;
        }
        if cfg.payload_window_days > 0 {
            let cutoff = now_secs - (cfg.payload_window_days as i64) * 86_400;
            outcome.payload_rows_deleted = self.prune_session_payloads(cutoff)?;
        }

        let deleted = outcome.sessions_expired + outcome.payload_rows_deleted;
        if self.path.is_some()
            && self.should_vacuum(deleted, now_secs, cfg)
            && self.vacuum_retention_database()?
        {
            self.record_vacuum(now_secs)?;
            outcome.vacuumed = true;
        }

        Ok(outcome)
    }

    fn vacuum_retention_database(&self) -> Result<bool> {
        if self.path.is_none() {
            return Ok(false);
        }
        // VACUUM under WAL still needs exclusive access to rewrite the DB. Keep it on
        // the writer connection so retention does not bypass writer serialization.
        self.write_blocking(|conn| match conn.execute_batch("VACUUM") {
            Ok(()) => Ok(true),
            Err(err) if sqlite_busy(&err) => {
                tracing::debug!(error = %err, "retention vacuum skipped because sqlite is busy");
                Ok(false)
            }
            Err(err) => Err(err).context("vacuuming after retention pass"),
        })
    }

    fn last_vacuum_secs(&self) -> Result<Option<i64>> {
        self.read_blocking(|conn| {
            conn.query_row(
                "SELECT value FROM retention_meta WHERE key = 'last_vacuum_secs'",
                [],
                |row| row.get(0),
            )
            .optional()
            .context("querying retention vacuum timestamp")
        })
    }
}

fn sqlite_busy(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(code, _)
            if matches!(code.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

fn prune_session_payloads_conn(conn: &Connection, cutoff_secs: i64) -> Result<u64> {
    let tx = conn
        .unchecked_transaction()
        .context("begin prune_session_payloads tx")?;
    let cutoff_ms = cutoff_secs * 1000;
    let closed = "session_id IN (SELECT session_id FROM sessions WHERE ended_at IS NOT NULL)";
    let mut total = 0_u64;
    for (sql, cutoff) in [
        (
            format!("DELETE FROM inference_requests WHERE ts_ms < ?1 AND {closed}"),
            cutoff_ms,
        ),
        (
            format!("DELETE FROM session_events WHERE ts_ms < ?1 AND {closed}"),
            cutoff_ms,
        ),
        (
            format!("DELETE FROM tool_call_events WHERE timestamp < ?1 AND {closed}"),
            cutoff_secs,
        ),
        (
            format!("DELETE FROM inference_calls WHERE timestamp < ?1 AND {closed}"),
            cutoff_secs,
        ),
    ] {
        total += tx
            .execute(&sql, params![cutoff])
            .context("pruning session payload rows")? as u64;
    }
    tx.commit().context("commit prune_session_payloads tx")?;
    Ok(total)
}

fn old_session_roots(conn: &Connection, cutoff_secs: i64) -> Result<Vec<Uuid>> {
    let mut stmt = conn
        .prepare(
            "SELECT root.session_id
               FROM sessions root
              WHERE root.parent_session_id IS NULL
                AND root.ended_at IS NOT NULL
                AND root.ephemeral = 0
                AND root.last_active_at < ?1
                AND NOT EXISTS (
                    WITH RECURSIVE subtree(session_id, ended_at) AS (
                        SELECT session_id, ended_at FROM sessions WHERE session_id = root.session_id
                        UNION ALL
                        SELECT child.session_id, child.ended_at
                          FROM sessions child
                          JOIN subtree parent ON child.parent_session_id = parent.session_id
                    )
                    SELECT 1 FROM subtree WHERE ended_at IS NULL
                )",
        )
        .context("preparing old session roots")?;
    let rows = stmt
        .query_map(params![cutoff_secs], |row| {
            let raw: String = row.get(0)?;
            parse_uuid_sql(raw)
        })
        .context("querying old session roots")?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.context("decoding old session root")?);
    }
    Ok(out)
}

fn parse_uuid_sql(raw: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&raw).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn close_session(db: &Db, id: Uuid, ts: i64) {
        db.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET ended_at = ?2, last_active_at = ?2 WHERE session_id = ?1",
                params![id.to_string(), ts],
            )?;
            Ok(())
        })
        .unwrap();
    }

    fn insert_payload_rows(db: &Db, session_id: Uuid, call_id: &str, ts_secs: i64) {
        let call_id = call_id.to_owned();
        db.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO inference_requests (call_id, session_id, ts_ms, payload_json)
                 VALUES (?1, ?2, ?3, ?4)",
                params![call_id, session_id.to_string(), ts_secs * 1000, "{}"],
            )?;
            conn.execute(
                "INSERT INTO session_events (session_id, ts_ms, type, data_json)
                 VALUES (?1, ?2, 'user_message', '{}')",
                params![session_id.to_string(), ts_secs * 1000],
            )?;
            conn.execute(
                "INSERT INTO tool_call_events (
                    event_id, session_id, call_id, timestamp, model, provider, project_id,
                    project_root, agent, tool, original_input_json, wire_input_json, output
                 ) VALUES (?1, ?2, ?3, ?4, 'm', 'p', 'proj', '/x', 'a', 'read', '{}', '{}', '')",
                params![
                    Uuid::new_v4().to_string(),
                    session_id.to_string(),
                    call_id,
                    ts_secs
                ],
            )?;
            conn.execute(
                "INSERT INTO inference_calls (
                    call_id, session_id, project_id, project_root, model, provider, timestamp,
                    input_tokens, output_tokens, cached_input_tokens, cache_creation_input_tokens
                 ) VALUES (?1, ?2, 'proj', '/x', 'm', 'p', ?3, 1, 1, 0, 0)",
                params![call_id, session_id.to_string(), ts_secs],
            )?;
            Ok(())
        })
        .unwrap();
    }

    fn payload_count(db: &Db, table: &str, session_id: Uuid) -> i64 {
        db.read_blocking(|conn| {
            conn.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE session_id = ?1"),
                params![session_id.to_string()],
                |row| row.get(0),
            )
            .context("counting payload rows")
        })
        .unwrap()
    }

    #[test]
    fn payload_age_out_keeps_open_session_rows() {
        let db = Db::open_in_memory().unwrap();
        let closed = db.create_session("p", "/x", "Build").unwrap();
        let open = db.create_session("p", "/x", "Build").unwrap();
        close_session(&db, closed.session_id, 10);
        insert_payload_rows(&db, closed.session_id, "closed", 10);
        insert_payload_rows(&db, open.session_id, "open", 10);

        assert_eq!(db.prune_session_payloads(20).unwrap(), 4);

        for table in [
            "inference_requests",
            "session_events",
            "tool_call_events",
            "inference_calls",
        ] {
            assert_eq!(payload_count(&db, table, closed.session_id), 0, "{table}");
            assert_eq!(payload_count(&db, table, open.session_id), 1, "{table}");
        }
    }

    #[test]
    fn payload_prune_failure_rolls_back_prior_table_deletes() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").unwrap();
        close_session(&db, s.session_id, 10);
        insert_payload_rows(&db, s.session_id, "closed", 10);
        db.write_blocking(move |conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER fail_session_event_prune
                 BEFORE DELETE ON session_events
                 BEGIN
                     SELECT RAISE(FAIL, 'injected payload prune failure');
                 END;",
            )?;
            Ok(())
        })
        .unwrap();

        let err = db.prune_session_payloads(20).unwrap_err();

        assert!(
            format!("{err:#}").contains("injected payload prune failure"),
            "unexpected error: {err:#}"
        );
        for table in [
            "inference_requests",
            "session_events",
            "tool_call_events",
            "inference_calls",
        ] {
            assert_eq!(payload_count(&db, table, s.session_id), 1, "{table}");
        }
    }

    #[test]
    fn payload_age_out_respects_half_open_boundary() {
        let db = Db::open_in_memory().unwrap();
        let at = db.create_session("p", "/x", "Build").unwrap();
        let old = db.create_session("p", "/x", "Build").unwrap();
        close_session(&db, at.session_id, 100);
        close_session(&db, old.session_id, 99);
        insert_payload_rows(&db, at.session_id, "at", 100);
        insert_payload_rows(&db, old.session_id, "old", 99);

        assert_eq!(db.prune_session_payloads(100).unwrap(), 4);

        for table in [
            "inference_requests",
            "session_events",
            "tool_call_events",
            "inference_calls",
        ] {
            assert_eq!(payload_count(&db, table, at.session_id), 1, "{table}");
            assert_eq!(payload_count(&db, table, old.session_id), 0, "{table}");
        }
    }

    #[test]
    fn payload_age_out_preserves_session_metadata_row() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").unwrap();
        close_session(&db, s.session_id, 10);
        insert_payload_rows(&db, s.session_id, "closed", 10);

        db.prune_session_payloads(20).unwrap();

        assert!(db.get_session(s.session_id).unwrap().is_some());
    }

    #[test]
    fn session_age_out_skips_open_subtree() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("p", "/x", "Build").unwrap();
        let _child = db.create_fork(root.session_id, None).unwrap();
        close_session(&db, root.session_id, 10);

        assert_eq!(db.expire_old_sessions(20).unwrap(), 0);
        assert!(db.get_session(root.session_id).unwrap().is_some());
    }

    #[test]
    fn session_age_out_skips_ephemeral() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").unwrap();
        close_session(&db, s.session_id, 10);
        db.write_blocking(move |conn| {
            conn.execute(
                "UPDATE sessions SET ephemeral = 1 WHERE session_id = ?1",
                params![s.session_id.to_string()],
            )?;
            Ok(())
        })
        .unwrap();

        assert_eq!(db.expire_old_sessions(20).unwrap(), 0);
        assert!(db.get_session(s.session_id).unwrap().is_some());
    }

    #[test]
    fn session_age_out_zero_window_is_noop() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").unwrap();
        close_session(&db, s.session_id, 10);

        assert_eq!(db.expire_old_sessions(0).unwrap(), 0);
        assert!(db.get_session(s.session_id).unwrap().is_some());
    }

    #[test]
    fn vacuum_triggers_on_deletion_threshold() {
        let db = Db::open_in_memory().unwrap();
        let cfg = RetentionConfig::default();
        assert!(db.should_vacuum(cfg.vacuum_min_deletions, 100, &cfg));
    }

    #[test]
    fn vacuum_triggers_on_interval() {
        let db = Db::open_in_memory().unwrap();
        let cfg = RetentionConfig::default();
        db.record_vacuum(100).unwrap();
        assert!(!db.should_vacuum(0, 100 + 6 * 86_400, &cfg));
        assert!(db.should_vacuum(0, 100 + 7 * 86_400, &cfg));
    }

    #[test]
    fn record_vacuum_round_trips() {
        let db = Db::open_in_memory().unwrap();
        let cfg = RetentionConfig::default();
        db.record_vacuum(100).unwrap();
        assert!(!db.should_vacuum(0, 100, &cfg));
    }

    #[test]
    fn vacuum_uses_dedicated_connection_without_shared_mutex() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = Db::open(&tmp.path().join("retention.db")).unwrap();
        let db_for_vacuum = db.clone();
        db.read_blocking(|_conn| {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                tx.send(db_for_vacuum.vacuum_retention_database()).unwrap();
            });
            let result = rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("vacuum should not wait for the shared connection mutex")
                .unwrap();
            assert!(result);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn disabled_windows_delete_nothing() {
        let db = Db::open_in_memory().unwrap();
        let cfg = RetentionConfig {
            payload_window_days: 0,
            session_window_days: 0,
            vacuum_interval_days: 0,
            ..RetentionConfig::default()
        };

        assert_eq!(
            db.run_retention_pass(&cfg, 100).unwrap(),
            RetentionOutcome::default()
        );
    }

    #[test]
    fn retention_pass_is_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "Build").unwrap();
        close_session(&db, s.session_id, 10);
        insert_payload_rows(&db, s.session_id, "closed", 10);
        let cfg = RetentionConfig {
            payload_window_days: 1,
            vacuum_interval_days: 0,
            ..RetentionConfig::default()
        };

        let first = db.run_retention_pass(&cfg, 100_000).unwrap();
        let second = db.run_retention_pass(&cfg, 100_000).unwrap();

        assert_eq!(first.payload_rows_deleted, 4);
        assert_eq!(first.sessions_expired, 0);
        assert_eq!(second.payload_rows_deleted, 0);
        assert_eq!(second.sessions_expired, 0);
    }
}
