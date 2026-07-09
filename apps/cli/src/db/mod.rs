//! SQLite persistence layer.
//!
//! Single connection, wrapped in `Arc<Mutex<>>`. Reads and writes are
//! cheap enough (point lookups, single-row inserts) to hold the lock
//! synchronously from tokio tasks; the multi-threaded runtime keeps
//! other tasks moving while one is in a critical section. Aggregate
//! queries that scan many rows go through [`Db::run_blocking`] so the
//! executor thread isn't pinned.
//!
//! Layout:
//!
//! - [`migrate`] — schema versioning over `schema_version`. Forward-only.
//! - [`sessions`] — session CRUD.
//! - [`tool_calls`] — `tool_call_events` writes + history reads.
//! - [`inference_calls`] — token / cost rows (GOALS §15b).
//! - [`locks`] — crash-recovery mirror of the in-memory `LockManager`.
//! - [`needs_attention`] — interrupt queue (GOALS §3b).
//! - [`lang`] — file-extension → language attribution (§15c).
//! - [`stats`] — `/stats` roll-up query layer + pricing (§15).
//!
//! Database path: `~/.local/share/cockpit/cockpit.db`
//! (XDG-canonical via [`crate::config::resolve::cockpit_data_dir`]).

pub mod compressed_results;
pub mod connector;
pub mod guidance;
pub mod inference_calls;
pub mod lang;
pub mod locks;
pub mod needs_attention;
pub mod org_sync;
pub mod packages;
pub mod paused_work;
pub mod pins;
pub mod principals;
pub mod project_notes;
pub mod prune_ledger;
pub mod remote_audit_upload;
pub mod retention;
pub mod seed_tools;
pub mod session_goals;
pub mod session_log;
pub mod session_plan_docs;
pub mod session_search;
pub mod sessions;
pub mod skill_pairs;
pub mod sql;
pub mod stats;
pub mod subagent_handles;
pub mod tandem;
pub mod task_delegation_payloads;
pub mod task_delegations;
pub mod task_todos;
pub mod tokenizer_calibration;
pub mod tool_calls;
pub mod usage_events;
pub mod workspace_trust;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::Connection;

const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
thread_local! {
    static OPEN_DEFAULT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_open_default_call_count() {
    OPEN_DEFAULT_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
pub(crate) fn open_default_call_count() -> usize {
    OPEN_DEFAULT_CALLS.with(std::cell::Cell::get)
}

/// Wrapper around a single `rusqlite::Connection`. Cheap to clone
/// (everything is behind `Arc<Mutex<>>`).
#[derive(Clone)]
pub struct Db {
    inner: Arc<Mutex<Connection>>,
    /// `None` for in-memory databases (tests).
    path: Option<PathBuf>,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Db {
    /// Open the canonical cockpit database, creating parent directories
    /// as needed. Runs every pending migration before returning.
    pub fn open_default() -> Result<Self> {
        #[cfg(test)]
        OPEN_DEFAULT_CALLS.with(|calls| calls.set(calls.get() + 1));

        let dir = crate::config::resolve::cockpit_data_dir()?;
        crate::private_fs::ensure_private_dir(&dir)
            .with_context(|| format!("securing {}", dir.display()))?;
        Self::open(&dir.join("cockpit.db"))
    }

    /// Open a database at an arbitrary path.
    pub fn open(path: &Path) -> Result<Self> {
        let mut timer = crate::startup::PhaseTimer::start("Db::open");
        crate::private_fs::ensure_parent_dir_private(path)
            .with_context(|| format!("securing parent of {}", path.display()))?;
        crate::private_fs::create_private_file_if_missing(path)?;
        let conn = Connection::open(path)
            .with_context(|| format!("opening sqlite at {}", path.display()))?;
        apply_connection_pragmas(&conn, true)
            .with_context(|| format!("setting pragmas on {}", path.display()))?;
        repair_db_file_permissions(path);
        timer.phase("connect_and_pragmas");
        let db = Self {
            inner: Arc::new(Mutex::new(conn)),
            path: Some(path.to_path_buf()),
        };
        db.migrate()?;
        timer.phase("migrate");
        timer.done();
        Ok(db)
    }

    /// In-memory database. Used by tests; not exposed for production
    /// because every restart would lose state.
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("opening in-memory sqlite")?;
        apply_connection_pragmas(&conn, false).context("setting pragmas on in-memory db")?;
        let db = Self {
            inner: Arc::new(Mutex::new(conn)),
            path: None,
        };
        db.migrate()?;
        Ok(db)
    }

    /// File path the database is backed by, or `None` for in-memory.
    // Retained for diagnostics/tooling that reports the backing DB path.
    #[allow(dead_code)]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Run an idempotent closure against the connection synchronously.
    /// Holds the connection lock for the duration of `f`. Use for cheap
    /// queries (single-row reads, inserts, schema metadata).
    pub fn with_conn<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let guard = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("db mutex poisoned"))?;
        f(&guard)
    }

    /// Async variant that runs the closure on a blocking thread. Use for
    /// queries that scan many rows (`/stats`, exports). The connection
    /// lock is still per-call so writes serialize correctly.
    pub async fn run_blocking<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let guard = inner
                .lock()
                .map_err(|_| anyhow::anyhow!("db mutex poisoned"))?;
            f(&guard)
        })
        .await
        .context("db worker thread joined")?
    }

    /// Apply every pending migration. Forward-only; downgrades are not
    /// supported. The runner takes a SQLite write lock before reading
    /// the current version so concurrent openers cannot race into the
    /// same pending DDL.
    fn migrate(&self) -> Result<()> {
        self.with_conn(migrate)
    }
}

fn repair_db_file_permissions(path: &Path) {
    for sidecar in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        if sidecar.exists()
            && let Err(e) = crate::private_fs::repair_private_file(&sidecar, "sqlite")
        {
            tracing::warn!(
                error = %e,
                path = %sidecar.display(),
                "sqlite file permissions could not be checked"
            );
        }
    }
}

/// Configure per-connection PRAGMAs. Called once at connection open.
///
/// - `foreign_keys = ON`: SQLite-default-off; we rely on the
///   CASCADE relationships in 0001_initial.sql. The migration runner
///   temporarily disables enforcement only around pending migration
///   transactions so table rebuilds can follow SQLite's documented
///   ordering, then validates with `foreign_key_check`.
/// - `journal_mode = WAL` (file DBs only): durable + better
///   concurrent-reader story. WAL doesn't apply to in-memory DBs
///   (SQLite ignores it).
/// - `busy_timeout = 5000ms`: short write-write contention waits for the
///   current writer instead of failing immediately with `SQLITE_BUSY`.
///
/// These can't live in migration SQL because `journal_mode = WAL`
/// fails when invoked inside a transaction, and migration SQL runs inside
/// a `BEGIN; ... COMMIT;` block for atomic apply.
fn apply_connection_pragmas(conn: &Connection, on_disk: bool) -> Result<()> {
    conn.busy_timeout(SQLITE_BUSY_TIMEOUT)
        .context("setting busy_timeout")?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .context("enabling foreign_keys")?;
    if on_disk {
        // `pragma_update` doesn't accept the kind of literal that
        // `journal_mode = WAL` needs; the query-row form does. The
        // return value is the resolved mode — we don't use it but a
        // non-`wal` result on a file DB would mean WAL is unavailable
        // (older SQLite, exotic FS), which is fine to silently fall
        // back to.
        let _: String = conn
            .query_row("PRAGMA journal_mode = WAL;", [], |row| row.get(0))
            .context("enabling WAL")?;
    }
    Ok(())
}

// ---- migration runner ------------------------------------------------------

/// All schema migrations, in order. Adding one: append `include_str!`
/// for the new file and bump nothing else — the index in this slice
/// is the version number.
const MIGRATIONS: &[&str] = &[include_str!("migrations/0001_initial.sql")];

fn migrate(conn: &Connection) -> Result<()> {
    migrate_with(conn, MIGRATIONS)
}

/// Apply pending migrations under one `BEGIN IMMEDIATE` writer lock.
///
/// Pending migration work runs with SQLite foreign-key enforcement
/// disabled and is re-verified after commit with `PRAGMA
/// foreign_key_check`. This is the runner-owned seam for SQLite
/// table-rebuild migrations; migration SQL must not emit
/// `PRAGMA foreign_keys` itself because that pragma is a no-op inside
/// a transaction.
fn migrate_with(conn: &Connection, migrations: &[&str]) -> Result<()> {
    let current_before_lock = current_schema_version(conn)?;
    if current_before_lock >= migrations.len() as i64 {
        return Ok(());
    }

    let fk_was_on = foreign_keys_enabled(conn).context("reading foreign_keys pragma")?;
    set_foreign_keys(conn, false).context("disabling foreign_keys for migrations")?;

    let apply = (|| -> Result<()> {
        conn.execute_batch("BEGIN IMMEDIATE;")
            .context("database is busy applying migrations")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);",
        )
        .context("creating schema_version table")?;

        let current = current_schema_version(conn)?;

        for (i, sql) in migrations.iter().enumerate() {
            let version = (i as i64) + 1;
            if version <= current {
                continue;
            }
            conn.execute_batch(sql)
                .with_context(|| format!("applying migration {version}"))?;
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                [version],
            )
            .with_context(|| format!("recording migration {version}"))?;
        }

        conn.execute_batch("COMMIT;")
            .context("committing migrations")?;
        Ok(())
    })();
    if let Err(e) = apply {
        let _ = conn.execute_batch("ROLLBACK;");
        let _ = set_foreign_keys(conn, fk_was_on);
        return Err(e);
    }

    if fk_was_on && let Err(e) = foreign_key_check(conn) {
        let _ = set_foreign_keys(conn, true);
        return Err(e);
    }
    set_foreign_keys(conn, fk_was_on).context("restoring foreign_keys after migrations")?;

    Ok(())
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let exists: i64 = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type='table' AND name=?1
            )",
            [name],
            |row| row.get(0),
        )
        .with_context(|| format!("checking table `{name}`"))?;
    Ok(exists != 0)
}

fn current_schema_version(conn: &Connection) -> Result<i64> {
    if !table_exists(conn, "schema_version")? {
        return Ok(0);
    }
    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )
    .context("reading current schema version")
}

fn foreign_keys_enabled(conn: &Connection) -> Result<bool> {
    let enabled: i64 = conn.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    Ok(enabled != 0)
}

fn set_foreign_keys(conn: &Connection, enabled: bool) -> Result<()> {
    let sql = if enabled {
        "PRAGMA foreign_keys = ON;"
    } else {
        "PRAGMA foreign_keys = OFF;"
    };
    conn.execute_batch(sql)?;
    Ok(())
}

fn foreign_key_check(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA foreign_key_check;")?;
    let violations = stmt
        .query_map([], |row| {
            let table: String = row.get(0)?;
            let rowid: Option<i64> = row.get(1)?;
            let parent: String = row.get(2)?;
            let fkid: i64 = row.get(3)?;
            Ok(format!(
                "table={table} rowid={} parent={parent} fkid={fkid}",
                rowid
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "NULL".to_string())
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if violations.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "migration left dangling foreign keys: {}",
        violations.join("; ")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Instant;
    use tempfile::TempDir;

    #[test]
    fn migrate_idempotent() {
        let db = Db::open_in_memory().unwrap();
        // Second migrate call is a no-op.
        db.with_conn(migrate).unwrap();
        let v: i64 = db
            .with_conn(|conn| {
                Ok(
                    conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                        row.get(0)
                    })?,
                )
            })
            .unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
    }

    #[test]
    fn connection_pragmas_set_busy_timeout_to_five_seconds() {
        let db = Db::open_in_memory().unwrap();
        let timeout_ms: i64 = db
            .with_conn(|conn| Ok(conn.query_row("PRAGMA busy_timeout;", [], |row| row.get(0))?))
            .unwrap();
        assert_eq!(timeout_ms, 5000);
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn open_default_creates_private_data_dir_and_db_file() {
        let tmp = TempDir::new().unwrap();
        let old_xdg_data_home = std::env::var_os("XDG_DATA_HOME");
        unsafe {
            std::env::set_var("XDG_DATA_HOME", tmp.path());
        }

        let db = Db::open_default().unwrap();
        drop(db);

        let data_dir = tmp.path().join("cockpit");
        let db_path = data_dir.join("cockpit.db");
        assert_eq!(mode(&data_dir), 0o700);
        assert_eq!(mode(&db_path), 0o600);

        unsafe {
            match old_xdg_data_home {
                Some(v) => std::env::set_var("XDG_DATA_HOME", v),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn open_repairs_existing_broad_db_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("cockpit.db");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let db = Db::open(&path).unwrap();
        drop(db);

        assert_eq!(mode(&path), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn open_repairs_existing_broad_wal_sidecars() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("cockpit.db");
        let seed = Connection::open(&path).unwrap();
        let _: String = seed
            .query_row("PRAGMA journal_mode = WAL;", [], |row| row.get(0))
            .unwrap();
        seed.execute_batch(
            "CREATE TABLE sidecar_probe (id INTEGER PRIMARY KEY);
             INSERT INTO sidecar_probe DEFAULT VALUES;",
        )
        .unwrap();
        let wal = PathBuf::from(format!("{}-wal", path.display()));
        let shm = PathBuf::from(format!("{}-shm", path.display()));
        assert!(
            wal.exists(),
            "WAL sidecar should exist while seed connection is open"
        );
        assert!(
            shm.exists(),
            "SHM sidecar should exist while seed connection is open"
        );
        for sidecar in [&wal, &shm] {
            std::fs::set_permissions(sidecar, std::fs::Permissions::from_mode(0o666)).unwrap();
        }

        let db = Db::open(&path).unwrap();
        drop(db);

        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&wal), 0o600);
        assert_eq!(mode(&shm), 0o600);
        drop(seed);
    }

    #[test]
    fn busy_timeout_waits_for_short_write_contention() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("busy.db");
        let db_a = Db::open(&path).unwrap();
        let db_b = Db::open(&path).unwrap();

        db_a.with_conn(|conn| {
            conn.execute_batch(
                "CREATE TABLE busy_probe (id INTEGER PRIMARY KEY, value TEXT NOT NULL);",
            )?;
            Ok(())
        })
        .unwrap();

        db_a.with_conn(|conn| {
            conn.execute_batch("BEGIN IMMEDIATE;")?;
            conn.execute("INSERT INTO busy_probe (value) VALUES ('held')", [])?;
            Ok(())
        })
        .unwrap();

        let (tx, rx) = mpsc::channel();
        let started = Instant::now();
        let writer = std::thread::spawn(move || {
            let result = db_b.with_conn(|conn| {
                conn.execute("INSERT INTO busy_probe (value) VALUES ('waited')", [])?;
                Ok(())
            });
            tx.send((started.elapsed(), result)).unwrap();
        });

        std::thread::sleep(Duration::from_millis(100));
        assert!(
            rx.try_recv().is_err(),
            "second writer returned immediately instead of waiting for busy timeout"
        );

        db_a.with_conn(|conn| {
            conn.execute_batch("COMMIT;")?;
            Ok(())
        })
        .unwrap();

        let (elapsed, result) = rx.recv().unwrap();
        writer.join().unwrap();
        result.unwrap();
        assert!(
            elapsed >= Duration::from_millis(100),
            "second writer did not wait for the held write lock: {elapsed:?}"
        );

        let count: i64 = db_a
            .with_conn(|conn| {
                Ok(conn.query_row("SELECT COUNT(*) FROM busy_probe", [], |row| row.get(0))?)
            })
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn migration_waits_for_lock_then_skips_already_applied_versions() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("migrate-wait.db");
        let conn_a = Connection::open(&path).unwrap();
        apply_connection_pragmas(&conn_a, true).unwrap();
        conn_a
            .execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
                CREATE TABLE migration_probe (id INTEGER PRIMARY KEY);
                INSERT INTO schema_version (version) VALUES (1);
                "#,
            )
            .unwrap();

        let path_for_thread = path.clone();
        let (tx, rx) = mpsc::channel();
        let started = Instant::now();
        let waiter = std::thread::spawn(move || {
            let conn_b = Connection::open(path_for_thread).unwrap();
            apply_connection_pragmas(&conn_b, true).unwrap();
            let result = migrate_with(
                &conn_b,
                &["CREATE TABLE migration_probe (id INTEGER PRIMARY KEY);"],
            );
            tx.send((started.elapsed(), result)).unwrap();
        });

        std::thread::sleep(Duration::from_millis(100));
        assert!(
            rx.try_recv().is_err(),
            "second migrator returned before the migration lock was released"
        );

        conn_a.execute_batch("COMMIT;").unwrap();
        let (elapsed, result) = rx.recv().unwrap();
        waiter.join().unwrap();
        result.unwrap();
        assert!(
            elapsed >= Duration::from_millis(100),
            "second migrator did not wait for the held migration lock: {elapsed:?}"
        );

        let version: i64 = conn_a
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 1);
        let table_count: i64 = conn_a
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='migration_probe'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_count, 1);
    }

    #[test]
    fn migration_busy_timeout_returns_clear_error() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("migrate-busy.db");
        let conn_a = Connection::open(&path).unwrap();
        apply_connection_pragmas(&conn_a, true).unwrap();
        conn_a.execute_batch("BEGIN IMMEDIATE;").unwrap();

        let conn_b = Connection::open(&path).unwrap();
        apply_connection_pragmas(&conn_b, true).unwrap();
        conn_b.busy_timeout(Duration::from_millis(50)).unwrap();
        let err = migrate_with(
            &conn_b,
            &["CREATE TABLE migration_probe (id INTEGER PRIMARY KEY);"],
        )
        .unwrap_err();

        assert!(
            format!("{err:#}").contains("database is busy applying migrations"),
            "unexpected migration busy error: {err:#}"
        );
        conn_a.execute_batch("ROLLBACK;").unwrap();
    }

    #[test]
    fn migration_rebuild_with_children_preserves_fk() {
        let conn = Connection::open_in_memory().unwrap();
        apply_connection_pragmas(&conn, false).unwrap();

        migrate_with(
            &conn,
            &[
                r#"
                CREATE TABLE parent (id INTEGER PRIMARY KEY);
                CREATE TABLE child (
                    id INTEGER PRIMARY KEY,
                    parent_id INTEGER NOT NULL REFERENCES parent(id) ON DELETE CASCADE
                );
                INSERT INTO parent (id) VALUES (1);
                INSERT INTO child (id, parent_id) VALUES (10, 1);
                "#,
                r#"
                CREATE TABLE parent_new (id INTEGER PRIMARY KEY);
                INSERT INTO parent_new (id) SELECT id FROM parent;
                DROP TABLE parent;
                ALTER TABLE parent_new RENAME TO parent;
                "#,
            ],
        )
        .unwrap();

        let child_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM child WHERE parent_id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(child_count, 1);
        foreign_key_check(&conn).unwrap();
        assert!(foreign_keys_enabled(&conn).unwrap());
    }

    #[test]
    fn migration_dangling_fk_is_rejected() {
        let conn = Connection::open_in_memory().unwrap();
        apply_connection_pragmas(&conn, false).unwrap();

        let err = migrate_with(
            &conn,
            &[
                r#"
                CREATE TABLE parent (id INTEGER PRIMARY KEY);
                CREATE TABLE child (
                    id INTEGER PRIMARY KEY,
                    parent_id INTEGER NOT NULL REFERENCES parent(id) ON DELETE CASCADE
                );
                INSERT INTO parent (id) VALUES (1);
                INSERT INTO child (id, parent_id) VALUES (10, 1);
                "#,
                r#"
                CREATE TABLE parent_new (id INTEGER PRIMARY KEY);
                DROP TABLE parent;
                ALTER TABLE parent_new RENAME TO parent;
                "#,
            ],
        )
        .unwrap_err();

        let message = format!("{err:#}");
        assert!(
            message.contains("migration left dangling foreign keys"),
            "unexpected error: {message}"
        );
        assert!(
            message.contains("table=child"),
            "unexpected error: {message}"
        );
        assert!(message.contains("rowid=10"), "unexpected error: {message}");
        assert!(foreign_keys_enabled(&conn).unwrap());
    }

    #[test]
    fn migrate_restores_foreign_keys_after_apply_error() {
        let conn = Connection::open_in_memory().unwrap();
        apply_connection_pragmas(&conn, false).unwrap();

        let err = migrate_with(
            &conn,
            &[
                "CREATE TABLE restore_probe (id INTEGER PRIMARY KEY);",
                "CREATE TABLE broken (",
            ],
        )
        .unwrap_err();

        assert!(
            format!("{err:#}").contains("applying migration 2"),
            "unexpected error: {err:#}"
        );
        assert!(foreign_keys_enabled(&conn).unwrap());
        let schema_table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(schema_table_count, 0);
        let probe_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='restore_probe'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(probe_count, 0);
    }

    #[test]
    fn migrate_skips_fk_dance_when_no_pending() {
        let conn = Connection::open_in_memory().unwrap();
        apply_connection_pragmas(&conn, false).unwrap();
        let migrations = &["CREATE TABLE no_pending_probe (id INTEGER PRIMARY KEY);"];

        migrate_with(&conn, migrations).unwrap();
        set_foreign_keys(&conn, false).unwrap();

        migrate_with(&conn, migrations).unwrap();

        assert!(!foreign_keys_enabled(&conn).unwrap());
        let version: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 1);
    }

    #[test]
    fn migrate_honors_fk_off_connection() {
        let conn = Connection::open_in_memory().unwrap();
        apply_connection_pragmas(&conn, false).unwrap();
        set_foreign_keys(&conn, false).unwrap();

        migrate_with(
            &conn,
            &[
                r#"
                CREATE TABLE parent (id INTEGER PRIMARY KEY);
                CREATE TABLE child (
                    id INTEGER PRIMARY KEY,
                    parent_id INTEGER NOT NULL REFERENCES parent(id) ON DELETE CASCADE
                );
                INSERT INTO parent (id) VALUES (1);
                INSERT INTO child (id, parent_id) VALUES (10, 1);
                "#,
                r#"
                CREATE TABLE parent_new (id INTEGER PRIMARY KEY);
                DROP TABLE parent;
                ALTER TABLE parent_new RENAME TO parent;
                "#,
            ],
        )
        .unwrap();

        assert!(!foreign_keys_enabled(&conn).unwrap());
        let orphan_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM child WHERE parent_id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(orphan_count, 1);
    }

    #[test]
    fn essential_tables_exist() {
        let db = Db::open_in_memory().unwrap();
        for table in [
            "sessions",
            "tool_call_events",
            "inference_calls",
            "lock_state",
            "lock_reads",
            "needs_attention",
        ] {
            let count: i64 = db
                .with_conn(|conn| {
                    Ok(conn.query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                        [table],
                        |row| row.get(0),
                    )?)
                })
                .unwrap();
            assert_eq!(count, 1, "table `{table}` missing");
        }
        // And the view.
        let view_count: i64 = db
            .with_conn(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='view' AND name='tool_call_stats'",
                    [],
                    |row| row.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(view_count, 1);
    }
}
