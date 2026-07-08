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
const MIGRATIONS: &[&str] = &[
    include_str!("migrations/0001_initial.sql"),
    include_str!("migrations/0002_sessions_fork.sql"),
    include_str!("migrations/0003_usage_events.sql"),
    include_str!("migrations/0004_tokenizer_calibration.sql"),
    include_str!("migrations/0005_intel_index.sql"),
    include_str!("migrations/0006_packages.sql"),
    include_str!("migrations/0007_seed_tools.sql"),
    include_str!("migrations/0008_interrupt_questions.sql"),
    include_str!("migrations/0009_session_log.sql"),
    include_str!("migrations/0010_sessions_read_archive.sql"),
    include_str!("migrations/0011_approval_grants.sql"),
    include_str!("migrations/0012_loop_guard_rules.sql"),
    include_str!("migrations/0013_session_search_fts.sql"),
    include_str!("migrations/0014_removed_graph_authoring.sql"),
    include_str!("migrations/0015_rename_build_agent.sql"),
    include_str!("migrations/0016_guidance_baseline.sql"),
    include_str!("migrations/0017_sessions_ephemeral.sql"),
    include_str!("migrations/0018_removed_graph_model.sql"),
    include_str!("migrations/0019_removed_graph_metrics.sql"),
    include_str!("migrations/0020_removed_graph_project_context.sql"),
    include_str!("migrations/0021_subagent_handles.sql"),
    include_str!("migrations/0022_removed_graph_harness.sql"),
    include_str!("migrations/0023_inference_calls_utility.sql"),
    include_str!("migrations/0024_project_notes.sql"),
    include_str!("migrations/0025_pins.sql"),
    include_str!("migrations/0026_prune_ledger.sql"),
    include_str!("migrations/0027_assistant_reasoning.sql"),
    include_str!("migrations/0028_removed_graph_lifecycle.sql"),
    include_str!("migrations/0029_inference_calls_cache_creation.sql"),
    include_str!("migrations/0030_inference_request_status.sql"),
    include_str!("migrations/0031_removed_graph_merge.sql"),
    include_str!("migrations/0032_tool_calls_version_and_mode.sql"),
    include_str!("migrations/0033_tandem_inference.sql"),
    include_str!("migrations/0034_removed_graph_events.sql"),
    include_str!("migrations/0035_tool_calls_shape_fingerprint.sql"),
    include_str!("migrations/0036_approval_grant_verdict.sql"),
    include_str!("migrations/0037_sessions_title_progress.sql"),
    include_str!("migrations/0038_intel_centrality.sql"),
    include_str!("migrations/0039_tool_calls_hint.sql"),
    include_str!("migrations/0040_task_todos.sql"),
    include_str!("migrations/0041_session_goals.sql"),
    include_str!("migrations/0042_repair_session_goals_fk.sql"),
    include_str!("migrations/0043_task_todo_assignment_labels.sql"),
    include_str!("migrations/0044_compressed_tool_results.sql"),
    include_str!("migrations/0045_workspace_trust.sql"),
    include_str!("migrations/0046_task_delegations.sql"),
    include_str!("migrations/0047_paused_work.sql"),
    include_str!("migrations/0048_task_delegation_steer.sql"),
    include_str!("migrations/0049_skill_pairs.sql"),
    include_str!("migrations/0050_package_prepare_scope.sql"),
    include_str!("migrations/0051_retention_meta.sql"),
    include_str!("migrations/0052_tool_call_provider_identity.sql"),
    include_str!("migrations/0053_task_delegation_payloads.sql"),
    include_str!("migrations/0054_task_delegation_child_cwd.sql"),
    include_str!("migrations/0055_subagent_handle_cwd.sql"),
    include_str!("migrations/0056_org_sync_state.sql"),
    include_str!("migrations/0057_connector_state.sql"),
    include_str!("migrations/0058_remote_principals.sql"),
    include_str!("migrations/0059_remote_audit_path.sql"),
    include_str!("migrations/0060_session_plan_docs.sql"),
];

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
            if version == 52 && !table_exists(conn, "tool_call_events")? {
                conn.execute(
                    "INSERT INTO schema_version (version) VALUES (?1)",
                    [version],
                )
                .with_context(|| format!("recording migration {version}"))?;
                continue;
            }
            if version == 60 {
                drop_legacy_graph_schema(conn).context("dropping legacy graph schema")?;
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

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let sql = format!("PRAGMA table_info({});", quote_ident(table));
    let mut stmt = conn
        .prepare(&sql)
        .with_context(|| format!("reading columns for `{table}`"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn drop_column_if_exists(conn: &Connection, table: &str, column: &str) -> Result<()> {
    if !table_exists(conn, table)? || !column_exists(conn, table, column)? {
        return Ok(());
    }
    let sql = format!(
        "ALTER TABLE {} DROP COLUMN {};",
        quote_ident(table),
        quote_ident(column)
    );
    conn.execute_batch(&sql)
        .with_context(|| format!("dropping legacy column `{column}` from `{table}`"))?;
    Ok(())
}

fn drop_legacy_graph_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        DROP INDEX IF EXISTS idx_ic_plan;
        DROP INDEX IF EXISTS idx_na_plan;
        ",
    )?;

    for table in [
        format!("{}{}", "plan_", "step_events"),
        format!("{}{}", "plan_", "step_progress"),
        format!("{}{}", "plan_", "run_state"),
        format!("{}{}", "plan_", "step_tests"),
        format!("{}{}", "plan_", "step_deps"),
        format!("{}{}", "plan_", "steps"),
        "plans".to_string(),
    ] {
        let sql = format!("DROP TABLE IF EXISTS {};", quote_ident(&table));
        conn.execute_batch(&sql)
            .with_context(|| format!("dropping legacy table `{table}`"))?;
    }

    let first_legacy_col = ["plan", "id"].join("_");
    let second_legacy_col = ["step", "id"].join("_");
    drop_column_if_exists(conn, "inference_calls", &first_legacy_col)?;
    drop_column_if_exists(conn, "inference_calls", &second_legacy_col)?;
    drop_column_if_exists(conn, "needs_attention", &first_legacy_col)?;
    drop_column_if_exists(conn, "needs_attention", &second_legacy_col)?;
    Ok(())
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
    fn migration_52_backfills_responses_identity_without_rekeying_call_id() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
            INSERT INTO schema_version (version) VALUES (51);
            CREATE TABLE tool_call_events (
                event_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                call_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                model TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL DEFAULT '',
                project_id TEXT NOT NULL,
                project_root TEXT NOT NULL,
                agent TEXT NOT NULL,
                tool TEXT NOT NULL,
                original_input_json TEXT NOT NULL,
                wire_input_json TEXT NOT NULL,
                output TEXT NOT NULL DEFAULT ''
            );
            INSERT INTO tool_call_events
                (event_id, session_id, call_id, timestamp, model, provider,
                 project_id, project_root, agent, tool, original_input_json,
                 wire_input_json, output)
            VALUES
                ('e1', 's', 'cockpit-1', 1, 'gpt-5.4-mini', 'openai',
                 'p', '/x', 'Build', 'read', '{}', '{}', ''),
                ('e2', 's', 'cockpit-2', 2, 'gpt-4o', 'openai-compatible',
                 'p', '/x', 'Build', 'read', '{}', '{}', '');
            ",
        )
        .unwrap();

        migrate_with(&conn, MIGRATIONS).unwrap();

        let rows: Vec<(
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        )> = conn
            .prepare(
                "SELECT call_id, provider_call_id, provider_call_id_source,
                        wire_api, provider_family
                   FROM tool_call_events
                  ORDER BY event_id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();

        assert_eq!(
            rows,
            vec![
                (
                    "cockpit-1".to_string(),
                    Some("cockpit-1".to_string()),
                    Some("legacy_synthesized_from_cockpit_call_id".to_string()),
                    Some("responses".to_string()),
                    Some("openai".to_string()),
                ),
                (
                    "cockpit-2".to_string(),
                    None,
                    Some("unknown_legacy".to_string()),
                    Some("unknown".to_string()),
                    Some("unknown".to_string()),
                ),
            ]
        );
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

    #[test]
    fn migration_repairs_session_goals_fk_before_deferred_persist() {
        let conn = Connection::open_in_memory().unwrap();
        apply_connection_pragmas(&conn, false).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
            INSERT INTO schema_version (version) VALUES (41);

            CREATE TABLE sessions (
                session_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                project_root TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                last_active_at INTEGER NOT NULL,
                ended_at INTEGER,
                active_agent TEXT NOT NULL,
                short_id TEXT,
                provider TEXT,
                model TEXT,
                guidance_baseline_path TEXT,
                guidance_baseline_hash TEXT
            );

            CREATE TABLE session_goals (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                project_id TEXT NOT NULL,
                objective TEXT NOT NULL,
                context TEXT,
                status TEXT NOT NULL,
                token_budget INTEGER,
                tokens_used INTEGER NOT NULL DEFAULT 0,
                blocked_attempts INTEGER NOT NULL DEFAULT 0,
                last_read_at INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE UNIQUE INDEX idx_session_goals_one_open
                ON session_goals(session_id)
                WHERE status IN ('draft', 'active', 'paused', 'blocked', 'budget_limited', 'usage_limited');

            CREATE INDEX idx_session_goals_session_status
                ON session_goals(session_id, status, updated_at DESC);
            "#,
        )
        .unwrap();

        let db = Db {
            inner: Arc::new(Mutex::new(conn)),
            path: None,
        };
        let existing_session = db.new_session_row("p", "/x", "builder").unwrap();
        db.insert_session_row(&existing_session).unwrap();
        let err = db
            .with_conn(|conn| {
                conn.execute(
                    "INSERT INTO session_goals
                     (id, session_id, project_id, objective, status, created_at, updated_at)
                     VALUES ('g1', ?1, 'p', 'ship it', 'active', 1, 1)",
                    [existing_session.session_id.to_string()],
                )
                .context("inserting broken session goal")?;
                Ok(())
            })
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("foreign key mismatch"),
            "unexpected goal insert error: {err:#}"
        );

        db.with_conn(migrate).unwrap();

        let parent_col: String = db
            .with_conn(|conn| {
                Ok(conn.query_row(
                    "SELECT \"to\" FROM pragma_foreign_key_list('session_goals') WHERE \"from\" = 'session_id'",
                    [],
                    |row| row.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(parent_col, "session_id");

        let repaired_row = db.new_session_row("p", "/x", "builder").unwrap();
        db.insert_session_row(&repaired_row).unwrap();
        db.with_conn(|conn| {
            conn.execute(
                "INSERT INTO session_goals
                 (id, session_id, project_id, objective, status, created_at, updated_at)
                 VALUES ('g2', ?1, 'p', 'ship it', 'active', 1, 1)",
                [repaired_row.session_id.to_string()],
            )
            .context("inserting repaired session goal")?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn migration_42_tolerates_missing_session_goals_table() {
        let conn = Connection::open_in_memory().unwrap();
        apply_connection_pragmas(&conn, false).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
            INSERT INTO schema_version (version) VALUES (41);

            CREATE TABLE sessions (
                session_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                project_root TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                last_active_at INTEGER NOT NULL,
                ended_at INTEGER,
                active_agent TEXT NOT NULL,
                short_id TEXT,
                provider TEXT,
                model TEXT,
                guidance_baseline_path TEXT,
                guidance_baseline_hash TEXT
            );
            "#,
        )
        .unwrap();

        let db = Db {
            inner: Arc::new(Mutex::new(conn)),
            path: None,
        };

        db.with_conn(migrate).unwrap();

        let table_count: i64 = db
            .with_conn(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='session_goals'",
                    [],
                    |row| row.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(table_count, 1);

        let parent_col: String = db
            .with_conn(|conn| {
                Ok(conn.query_row(
                    "SELECT \"to\" FROM pragma_foreign_key_list('session_goals') WHERE \"from\" = 'session_id'",
                    [],
                    |row| row.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(parent_col, "session_id");
    }
}
