//! Crash-recovery mirror of the in-memory `LockManager`.
//!
//! On daemon startup the lock manager loads its state from these
//! tables. On acquire/release/note_read the manager writes through
//! synchronously so a crash leaves a coherent on-disk view.

use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone)]
pub struct LockStateRow {
    pub path: String,
    pub agent_id: String,
    pub session_id: Uuid,
    /// Unix-seconds the lock was last acquired/touched. Doubles as the
    /// idle-expiry liveness field: seeds the sweeper's deadline on daemon
    /// restart (implementation note).
    pub acquired_at: i64,
}

#[derive(Debug, Clone)]
pub struct LockReadRow {
    pub session_id: Uuid,
    pub agent_id: String,
    pub path: String,
    pub read_hash: Option<u64>,
}

impl Db {
    /// Record a freshly-acquired lock. Idempotent — re-acquiring by the
    /// same `(path, agent_id)` updates `acquired_at`.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn lock_acquire(&self, path: &Path, agent_id: &str, session_id: Uuid) -> Result<()> {
        let now = Utc::now().timestamp();
        let p = path_string(path);
        let agent_id = agent_id.to_owned();
        self.write_blocking(move |conn| {
            guarded_lock_acquire(conn, &p, &agent_id, session_id, now)?;
            Ok(())
        })
    }

    /// Refresh a held lock's last-touched timestamp (`acquired_at`
    /// doubles as the idle-expiry liveness field —
    /// implementation note). Scoped to the holding
    /// `(session_id, agent_id)` so a stale writer can't refresh a lock it no longer
    /// owns; a no-op row count is fine (the lock was released concurrently).
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn lock_touch(
        &self,
        path: &Path,
        agent_id: &str,
        session_id: Uuid,
        now: i64,
    ) -> Result<()> {
        let p = path_string(path);
        let agent_id = agent_id.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "UPDATE lock_state SET acquired_at = ?4
                 WHERE path = ?1 AND agent_id = ?2 AND session_id = ?3",
                params![p, agent_id, session_id.to_string(), now],
            )
            .context("touching lock_state")?;
            Ok(())
        })
    }

    /// Release a lock held by `(session_id, agent_id)`. No-op if not held by
    /// that owner (the in-memory manager errs loudly; the mirror just keeps
    /// disk consistent).
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn lock_release(&self, path: &Path, agent_id: &str, session_id: Uuid) -> Result<()> {
        let p = path_string(path);
        let agent_id = agent_id.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "DELETE FROM lock_state
                 WHERE path = ?1 AND agent_id = ?2 AND session_id = ?3",
                params![p, agent_id, session_id.to_string()],
            )
            .context("deleting lock_state")?;
            Ok(())
        })
    }

    /// Record a successful read for the §3c pre-write guard.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn lock_note_read(
        &self,
        path: &Path,
        agent_id: &str,
        session_id: Uuid,
        read_hash: Option<u64>,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let p = path_string(path);
        let agent_id = agent_id.to_owned();
        let read_hash = read_hash.map(|hash| hash as i64);
        self.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO lock_reads (session_id, agent_id, path, read_at, read_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(session_id, agent_id, path) DO UPDATE SET
                     read_at = excluded.read_at,
                     read_hash = excluded.read_hash",
                params![session_id.to_string(), agent_id, p, now, read_hash],
            )
            .context("upserting lock_reads")?;
            Ok(())
        })
    }

    /// Atomically record a held lock and the matching read guard entry.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn lock_acquire_with_read(
        &self,
        path: &Path,
        agent_id: &str,
        session_id: Uuid,
        read_hash: Option<u64>,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let p = path_string(path);
        let agent_id = agent_id.to_owned();
        let read_hash = read_hash.map(|hash| hash as i64);
        self.write_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin lock_acquire_with_read tx")?;
            guarded_lock_acquire(&tx, &p, &agent_id, session_id, now)?;
            tx.execute(
                "INSERT INTO lock_reads (session_id, agent_id, path, read_at, read_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(session_id, agent_id, path) DO UPDATE SET
                     read_at = excluded.read_at,
                     read_hash = excluded.read_hash",
                params![session_id.to_string(), agent_id, p, now, read_hash],
            )
            .context("upserting lock_reads")?;
            tx.commit().context("commit lock_acquire_with_read tx")?;
            Ok(())
        })
    }

    /// Acquire a lock after the in-memory manager already forced a release
    /// because deleting the stale `lock_state` row failed. This is narrower
    /// than normal acquire: callers must only use it for paths they have
    /// marked as forced-released in memory.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn lock_force_acquire_with_read(
        &self,
        path: &Path,
        agent_id: &str,
        session_id: Uuid,
        read_hash: Option<u64>,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let p = path_string(path);
        let agent_id = agent_id.to_owned();
        let read_hash = read_hash.map(|hash| hash as i64);
        self.write_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin lock_force_acquire_with_read tx")?;
            tx.execute(
                "INSERT INTO lock_state (path, agent_id, session_id, acquired_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(path) DO UPDATE SET
                     agent_id = excluded.agent_id,
                     session_id = excluded.session_id,
                     acquired_at = excluded.acquired_at",
                params![p, agent_id, session_id.to_string(), now],
            )
            .context("forcing lock_state acquire")?;
            tx.execute(
                "INSERT INTO lock_reads (session_id, agent_id, path, read_at, read_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(session_id, agent_id, path) DO UPDATE SET
                     read_at = excluded.read_at,
                     read_hash = excluded.read_hash",
                params![session_id.to_string(), agent_id, p, now, read_hash],
            )
            .context("upserting lock_reads")?;
            tx.commit()
                .context("commit lock_force_acquire_with_read tx")?;
            Ok(())
        })
    }

    /// Delete a read record that has been invalidated by lock expiry or
    /// failed drift/taken resume. No-op when the row is already gone.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn lock_delete_read(&self, path: &Path, agent_id: &str, session_id: Uuid) -> Result<()> {
        let p = path_string(path);
        let agent_id = agent_id.to_owned();
        self.write_blocking(move |conn| {
            conn.execute(
                "DELETE FROM lock_reads
                 WHERE session_id = ?1 AND agent_id = ?2 AND path = ?3",
                params![session_id.to_string(), agent_id, p],
            )
            .context("deleting lock_reads")?;
            Ok(())
        })
    }

    /// Atomically release locks and delete matching read guard entries.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn lock_release_and_delete_reads(&self, entries: &[(PathBuf, Uuid, String)]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let entries = entries.to_vec();
        self.write_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin lock release/read cleanup tx")?;
            for (path, session_id, agent_id) in entries {
                let p = path_string(&path);
                tx.execute(
                    "DELETE FROM lock_state
                     WHERE path = ?1 AND agent_id = ?2 AND session_id = ?3",
                    params![p, agent_id, session_id.to_string()],
                )
                .context("deleting lock_state")?;
                tx.execute(
                    "DELETE FROM lock_reads
                     WHERE session_id = ?1 AND agent_id = ?2 AND path = ?3",
                    params![session_id.to_string(), agent_id, p],
                )
                .context("deleting lock_reads")?;
            }
            tx.commit().context("commit lock release/read cleanup tx")?;
            Ok(())
        })
    }

    /// Atomically transfer every lock/read row for one agent in a session to
    /// another agent. Read rows are merged into the target agent's read set.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn lock_transfer_agent(
        &self,
        session_id: Uuid,
        from_agent: &str,
        to_agent: &str,
    ) -> Result<()> {
        if from_agent == to_agent {
            return Ok(());
        }
        let from_agent = from_agent.to_owned();
        let to_agent = to_agent.to_owned();
        self.write_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin lock agent-transfer tx")?;
            tx.execute(
                "UPDATE lock_state
                 SET agent_id = ?3
                 WHERE session_id = ?1 AND agent_id = ?2",
                params![session_id.to_string(), from_agent, to_agent],
            )
            .context("transferring lock_state owner")?;
            tx.execute(
                "INSERT OR REPLACE INTO lock_reads (session_id, agent_id, path, read_at, read_hash)
                 SELECT session_id, ?3, path, read_at, read_hash
                 FROM lock_reads
                 WHERE session_id = ?1 AND agent_id = ?2",
                params![session_id.to_string(), from_agent, to_agent],
            )
            .context("copying transferred lock_reads")?;
            tx.execute(
                "DELETE FROM lock_reads
                 WHERE session_id = ?1 AND agent_id = ?2",
                params![session_id.to_string(), from_agent],
            )
            .context("deleting old lock_reads owner")?;
            tx.commit().context("commit lock agent-transfer tx")?;
            Ok(())
        })
    }

    /// Permanently remove every persisted lock/read row for an ended session.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn lock_cleanup_session(&self, session_id: Uuid) -> Result<()> {
        self.write_blocking(move |conn| {
            let tx = conn
                .unchecked_transaction()
                .context("begin lock session cleanup tx")?;
            tx.execute(
                "DELETE FROM lock_state WHERE session_id = ?1",
                [session_id.to_string()],
            )
            .context("deleting session lock_state")?;
            tx.execute(
                "DELETE FROM lock_reads WHERE session_id = ?1",
                [session_id.to_string()],
            )
            .context("deleting session lock_reads")?;
            tx.commit().context("commit lock session cleanup tx")?;
            Ok(())
        })
    }

    /// All currently-held locks. Loaded on daemon startup to rebuild
    /// the in-memory manager.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn list_held_locks(&self) -> Result<Vec<LockStateRow>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare("SELECT path, agent_id, session_id, acquired_at FROM lock_state")
                .context("preparing list_held_locks")?;
            let rows = stmt
                .query_map([], |row| {
                    let session_id: String = row.get("session_id")?;
                    let session_id = Uuid::parse_str(&session_id).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                    Ok(LockStateRow {
                        path: row.get("path")?,
                        agent_id: row.get("agent_id")?,
                        session_id,
                        acquired_at: row.get("acquired_at")?,
                    })
                })
                .context("querying lock_state")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding lock_state row")?);
            }
            Ok(out)
        })
    }

    /// Every `(path, agent)` pair that has read in `session_id`. Retained for
    /// targeted queries and tests; startup loads all reads in one pass.
    #[allow(dead_code)]
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn list_reads_for_session(&self, session_id: Uuid) -> Result<Vec<(String, String)>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare("SELECT agent_id, path FROM lock_reads WHERE session_id = ?1")
                .context("preparing list_reads_for_session")?;
            let rows = stmt
                .query_map([session_id.to_string()], |row| {
                    Ok((
                        row.get::<_, String>("agent_id")?,
                        row.get::<_, String>("path")?,
                    ))
                })
                .context("querying lock_reads")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding lock_reads row")?);
            }
            Ok(out)
        })
    }

    /// Every persisted read record. Loaded on daemon startup independently of
    /// held locks so read-only pre-write guards survive restart too.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn list_lock_reads(&self) -> Result<Vec<LockReadRow>> {
        self.read_blocking(|conn| {
            let mut stmt = conn
                .prepare("SELECT session_id, agent_id, path, read_hash FROM lock_reads")
                .context("preparing list_lock_reads")?;
            let rows = stmt
                .query_map([], |row| {
                    let session_id: String = row.get("session_id")?;
                    let session_id = Uuid::parse_str(&session_id).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                    let read_hash = row
                        .get::<_, Option<i64>>("read_hash")?
                        .map(|hash| hash as u64);
                    Ok(LockReadRow {
                        session_id,
                        agent_id: row.get::<_, String>("agent_id")?,
                        path: row.get::<_, String>("path")?,
                        read_hash,
                    })
                })
                .context("querying lock_reads")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("decoding lock_reads row")?);
            }
            Ok(out)
        })
    }
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn guarded_lock_acquire(
    conn: &Connection,
    path: &str,
    agent_id: &str,
    session_id: Uuid,
    acquired_at: i64,
) -> Result<()> {
    let changed = conn
        .execute(
            "INSERT INTO lock_state (path, agent_id, session_id, acquired_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(path) DO UPDATE SET
                 acquired_at = excluded.acquired_at
             WHERE lock_state.session_id = excluded.session_id
               AND lock_state.agent_id = excluded.agent_id",
            params![path, agent_id, session_id.to_string(), acquired_at],
        )
        .context("upserting lock_state")?;
    if changed > 0 {
        return Ok(());
    }

    let owner = conn
        .query_row(
            "SELECT session_id, agent_id FROM lock_state WHERE path = ?1",
            [path],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .context("querying conflicting lock_state owner")?;
    match owner {
        Some((owner_session, owner_agent)) => {
            bail!(
                "lock_state acquire conflict for `{path}`: held by `{owner_agent}` in session {owner_session}, not `{agent_id}` in session {session_id}"
            );
        }
        None => {
            bail!(
                "lock_state acquire conflict for `{path}` but the owner row disappeared before it could be reported"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_release_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        let p = std::path::PathBuf::from("/x/main.rs");
        db.lock_acquire(&p, "builder", s.session_id).unwrap();
        let held = db.list_held_locks().unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].agent_id, "builder");
        db.lock_release(&p, "builder", s.session_id).unwrap();
        assert!(db.list_held_locks().unwrap().is_empty());
    }

    #[test]
    fn acquire_same_owner_refreshes_without_changing_owner() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        let p = std::path::PathBuf::from("/x/main.rs");
        db.lock_acquire(&p, "builder", s.session_id).unwrap();
        db.lock_touch(&p, "builder", s.session_id, 1).unwrap();

        db.lock_acquire(&p, "builder", s.session_id).unwrap();

        let held = db.list_held_locks().unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].agent_id, "builder");
        assert_eq!(held[0].session_id, s.session_id);
        assert!(
            held[0].acquired_at > 1,
            "same-owner acquire should refresh acquired_at"
        );
    }

    #[test]
    fn acquire_different_agent_errors_and_keeps_original_owner() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        let p = std::path::PathBuf::from("/x/main.rs");
        db.lock_acquire(&p, "builder", s.session_id).unwrap();
        db.lock_touch(&p, "builder", s.session_id, 123).unwrap();

        let err = db
            .lock_acquire(&p, "explore", s.session_id)
            .unwrap_err()
            .to_string();

        assert!(err.contains("lock_state acquire conflict"), "{err}");
        assert!(err.contains("builder"), "{err}");
        assert!(err.contains("explore"), "{err}");
        let held = db.list_held_locks().unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].agent_id, "builder");
        assert_eq!(held[0].session_id, s.session_id);
        assert_eq!(held[0].acquired_at, 123);
    }

    #[test]
    fn acquire_different_session_errors_and_keeps_original_owner() {
        let db = Db::open_in_memory().unwrap();
        let s1 = db.create_session("p", "/x", "a").unwrap();
        let s2 = db.create_session("p", "/y", "a").unwrap();
        let p = std::path::PathBuf::from("/x/main.rs");
        db.lock_acquire(&p, "builder", s1.session_id).unwrap();
        db.lock_touch(&p, "builder", s1.session_id, 456).unwrap();

        let err = db
            .lock_acquire(&p, "builder", s2.session_id)
            .unwrap_err()
            .to_string();

        assert!(err.contains("lock_state acquire conflict"), "{err}");
        assert!(err.contains(&s1.session_id.to_string()), "{err}");
        assert!(err.contains(&s2.session_id.to_string()), "{err}");
        let held = db.list_held_locks().unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].agent_id, "builder");
        assert_eq!(held[0].session_id, s1.session_id);
        assert_eq!(held[0].acquired_at, 456);
    }

    #[test]
    fn lock_touch_refreshes_acquired_at() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        let p = std::path::PathBuf::from("/x/main.rs");
        db.lock_acquire(&p, "builder", s.session_id).unwrap();
        // Refresh forward to a known timestamp; the row reflects it.
        db.lock_touch(&p, "builder", s.session_id, 9_999_999_999)
            .unwrap();
        let held = db.list_held_locks().unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].acquired_at, 9_999_999_999);
        // A touch scoped to a non-holder is a no-op (no row updated).
        db.lock_touch(&p, "explore", s.session_id, 1).unwrap();
        let held = db.list_held_locks().unwrap();
        assert_eq!(held[0].acquired_at, 9_999_999_999);
        // Same agent in a different session is also a no-op.
        let s2 = db.create_session("p", "/y", "a").unwrap();
        db.lock_touch(&p, "builder", s2.session_id, 1).unwrap();
        let held = db.list_held_locks().unwrap();
        assert_eq!(held[0].acquired_at, 9_999_999_999);
    }

    #[test]
    fn note_read_idempotent() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        let p = std::path::PathBuf::from("/x/a.rs");
        db.lock_note_read(&p, "builder", s.session_id, Some(7))
            .unwrap();
        db.lock_note_read(&p, "builder", s.session_id, Some(8))
            .unwrap();
        let reads = db.list_reads_for_session(s.session_id).unwrap();
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].0, "builder");
    }

    #[test]
    fn lock_reads_read_hash_column_round_trips() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        let with_hash = std::path::PathBuf::from("/x/with.rs");
        let without_hash = std::path::PathBuf::from("/x/without.rs");

        db.lock_note_read(&with_hash, "builder", s.session_id, Some(u64::MAX - 3))
            .unwrap();
        db.lock_note_read(&without_hash, "builder", s.session_id, None)
            .unwrap();

        let mut reads = db.list_lock_reads().unwrap();
        reads.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(reads.len(), 2);
        assert_eq!(reads[0].path, "/x/with.rs");
        assert_eq!(reads[0].read_hash, Some(u64::MAX - 3));
        assert_eq!(reads[1].path, "/x/without.rs");
        assert_eq!(reads[1].read_hash, None);
    }

    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    fn assert_transaction_closed(db: &Db) {
        db.write_blocking(move |conn| {
            conn.execute_batch("BEGIN IMMEDIATE; COMMIT;")?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    fn acquire_with_read_failure_rolls_back_lock_and_closes_transaction() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        let p = std::path::PathBuf::from("/x/fail.rs");
        db.write_blocking(move |conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER fail_lock_read_insert
                 BEFORE INSERT ON lock_reads
                 WHEN NEW.path = '/x/fail.rs'
                 BEGIN
                     SELECT RAISE(FAIL, 'injected lock read failure');
                 END;",
            )?;
            Ok(())
        })
        .unwrap();

        let err = db
            .lock_acquire_with_read(&p, "builder", s.session_id, Some(1))
            .unwrap_err();

        assert!(
            format!("{err:#}").contains("injected lock read failure"),
            "unexpected error: {err:#}"
        );
        assert!(db.list_held_locks().unwrap().is_empty());
        assert!(db.list_lock_reads().unwrap().is_empty());
        assert_transaction_closed(&db);
    }

    #[test]
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    fn transfer_agent_failure_rolls_back_memory_mirror_rows() {
        let db = Db::open_in_memory().unwrap();
        let s = db.create_session("p", "/x", "a").unwrap();
        let p = std::path::PathBuf::from("/x/main.rs");
        db.lock_acquire_with_read(&p, "builder", s.session_id, Some(11))
            .unwrap();
        db.write_blocking(move |conn| {
            conn.execute_batch(
                "CREATE TEMP TRIGGER fail_transfer_read_copy
                 BEFORE INSERT ON lock_reads
                 WHEN NEW.agent_id = 'explore'
                 BEGIN
                     SELECT RAISE(FAIL, 'injected transfer read failure');
                 END;",
            )?;
            Ok(())
        })
        .unwrap();

        let err = db
            .lock_transfer_agent(s.session_id, "builder", "explore")
            .unwrap_err();

        assert!(
            format!("{err:#}").contains("injected transfer read failure"),
            "unexpected error: {err:#}"
        );
        let held = db.list_held_locks().unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].agent_id, "builder");
        assert_eq!(
            db.list_reads_for_session(s.session_id).unwrap()[0].0,
            "builder"
        );
        assert_transaction_closed(&db);
    }

    #[test]
    fn list_and_delete_lock_reads() {
        let db = Db::open_in_memory().unwrap();
        let s1 = db.create_session("p", "/x", "a").unwrap();
        let s2 = db.create_session("p", "/y", "a").unwrap();
        let p1 = std::path::PathBuf::from("/x/a.rs");
        let p2 = std::path::PathBuf::from("/y/b.rs");
        db.lock_note_read(&p1, "builder", s1.session_id, Some(1))
            .unwrap();
        db.lock_note_read(&p2, "builder", s2.session_id, Some(2))
            .unwrap();

        let reads = db.list_lock_reads().unwrap();
        assert_eq!(reads.len(), 2);

        db.lock_delete_read(&p1, "builder", s1.session_id).unwrap();
        db.lock_delete_read(&p1, "builder", s1.session_id).unwrap();

        let reads = db.list_lock_reads().unwrap();
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].session_id, s2.session_id);
        assert_eq!(reads[0].path, "/y/b.rs");
    }
}
