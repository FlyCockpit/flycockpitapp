//! SQLite persistence layer.
//!
//! File-backed databases use one dedicated writer thread plus a small
//! read-only WAL connection pool. Async call sites use [`Db::read`] and
//! [`Db::write`]. The only non-deprecated synchronous escape hatch is
//! [`Db::blocking_for_sync_cli`], which runs a read/write-capable closure on
//! the writer connection and panics if called from any Tokio runtime; async
//! code must use [`Db::read`], [`Db::write`], or [`Db::transaction`] instead.
//!
//! Async migration rules:
//!
//! - `Db::write(...).await` completing means the write is committed, so a
//!   later awaited read observes it. A read racing an unawaited write may see
//!   the prior committed snapshot.
//! - Composing two async accessors is not atomic. Any multi-statement
//!   invariant that must not interleave with another writer belongs in a
//!   single [`Db::transaction`] closure.
//! - Pool checkouts are never held across an `.await` on the writer: read
//!   closures run wholly inside one blocking worker, and write/transaction
//!   closures run wholly on the writer thread before the async caller resumes.
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

pub mod app_flags;
pub mod assistants;
pub mod compressed_results;
pub mod connector;
mod files;
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
pub mod scheduler;
pub mod seed_tools;
pub mod session_goals;
pub mod session_log;
pub mod session_plan_docs;
pub mod session_search;
pub mod sessions;
pub mod shadow_store;
pub mod skill_pairs;
pub mod skill_usage;
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
pub mod wire;
pub mod workspace_trust;

use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};

const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Exact identity of the pre-release squashed schema in `0001_initial.sql`.
///
/// The migration ledger cannot detect edits to an already-applied squashed
/// migration, so every amendment to `0001_initial.sql` must also increment
/// this value and the matching `PRAGMA user_version` in that file. This gate
/// is intentionally strict until the first public release: developers move a
/// stale database aside and let Cockpit recreate it rather than running a
/// compatibility migration.
pub const EXPECTED_SCHEMA_VERSION: i64 = 6;

thread_local! {
    static OPEN_DEFAULT_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub fn reset_open_default_call_count() {
    OPEN_DEFAULT_CALLS.with(|calls| calls.set(0));
}

pub fn open_default_call_count() -> usize {
    OPEN_DEFAULT_CALLS.with(std::cell::Cell::get)
}

type DbJob = Box<dyn FnOnce(&Connection) -> Result<Box<dyn Any + Send>> + Send + 'static>;

struct WriteRequest {
    job: DbJob,
    reply: mpsc::SyncSender<Result<Box<dyn Any + Send>>>,
}

#[derive(Clone)]
struct Writer {
    tx: mpsc::SyncSender<WriteRequest>,
}

impl Writer {
    fn start(path: PathBuf) -> Result<Self> {
        let (tx, rx) = mpsc::sync_channel::<WriteRequest>(1024);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("cockpit-db-writer".into())
            .spawn(move || {
                let conn = match Connection::open(&path)
                    .with_context(|| format!("opening sqlite writer at {}", path.display()))
                    .and_then(|conn| {
                        apply_connection_pragmas(&conn, true).with_context(|| {
                            format!("setting writer pragmas on {}", path.display())
                        })?;
                        Ok(conn)
                    }) {
                    Ok(conn) => {
                        let _ = ready_tx.send(Ok(()));
                        conn
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e.to_string()));
                        return;
                    }
                };

                while let Ok(request) = rx.recv() {
                    let result = catch_unwind(AssertUnwindSafe(|| (request.job)(&conn)))
                        .map_err(|_| anyhow::anyhow!("db writer job panicked"))
                        .and_then(|result| result);
                    let _ = request.reply.send(result);
                }
            })
            .context("spawning db writer thread")?;
        match ready_rx.recv().context("waiting for db writer startup")? {
            Ok(()) => Ok(Self { tx }),
            Err(e) => anyhow::bail!(e),
        }
    }

    fn submit<F, T>(&self, f: F) -> Result<mpsc::Receiver<Result<Box<dyn Any + Send>>>>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let (reply, rx) = mpsc::sync_channel(1);
        let job: DbJob = Box::new(move |conn| {
            let value = f(conn)?;
            Ok(Box::new(value) as Box<dyn Any + Send>)
        });
        self.tx
            .send(WriteRequest { job, reply })
            .map_err(|_| anyhow::anyhow!("db writer is shut down"))?;
        Ok(rx)
    }
}

struct ReadPool {
    path: PathBuf,
    max: usize,
    total: AtomicUsize,
    idle: Mutex<Vec<Connection>>,
    available: Condvar,
}

impl ReadPool {
    fn new(path: PathBuf) -> Self {
        let cores = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        Self {
            path,
            max: cores.clamp(1, 4),
            total: AtomicUsize::new(0),
            idle: Mutex::new(Vec::new()),
            available: Condvar::new(),
        }
    }

    fn open_conn(&self) -> Result<Connection> {
        let conn = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("opening sqlite read connection at {}", self.path.display()))?;
        apply_connection_pragmas(&conn, false)
            .with_context(|| format!("setting read pragmas on {}", self.path.display()))?;
        conn.execute_batch("PRAGMA query_only = ON;")
            .context("enforcing read-only sqlite connection")?;
        Ok(conn)
    }

    fn checkout(&self) -> Result<Connection> {
        loop {
            if let Some(conn) = self
                .idle
                .lock()
                .map_err(|_| anyhow::anyhow!("db read pool mutex poisoned"))?
                .pop()
            {
                return Ok(conn);
            }

            let total = self.total.load(Ordering::SeqCst);
            if total < self.max {
                if self
                    .total
                    .compare_exchange(total, total + 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    match self.open_conn() {
                        Ok(conn) => return Ok(conn),
                        Err(e) => {
                            self.total.fetch_sub(1, Ordering::SeqCst);
                            self.available.notify_one();
                            return Err(e);
                        }
                    }
                }
                continue;
            }

            let guard = self
                .idle
                .lock()
                .map_err(|_| anyhow::anyhow!("db read pool mutex poisoned"))?;
            let mut guard = self
                .available
                .wait(guard)
                .map_err(|_| anyhow::anyhow!("db read pool mutex poisoned"))?;
            if let Some(conn) = guard.pop() {
                return Ok(conn);
            }
        }
    }

    fn checkin(&self, conn: Connection) -> Result<()> {
        self.idle
            .lock()
            .map_err(|_| anyhow::anyhow!("db read pool mutex poisoned"))?
            .push(conn);
        self.available.notify_one();
        Ok(())
    }

    fn run<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let conn = self.checkout()?;
        let result = f(&conn);
        let checkin = self.checkin(conn);
        match (result, checkin) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(e), _) => Err(e),
            (Ok(_), Err(e)) => Err(e),
        }
    }
}

/// Cloneable SQLite handle. File-backed databases use a writer thread and a
/// small WAL read pool; in-memory test databases use the single SQLite
/// connection because separate in-memory connections do not share state.
#[derive(Clone)]
pub struct Db {
    memory: Option<Arc<Mutex<Connection>>>,
    writer: Option<Writer>,
    read_pool: Option<Arc<ReadPool>>,
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
    /// Resolve the canonical database path without creating or opening it.
    pub fn default_path() -> Result<PathBuf> {
        Ok(files::cockpit_data_dir()?.join("cockpit.db"))
    }

    /// Open the canonical cockpit database, creating parent directories
    /// as needed. Runs every pending migration before returning.
    pub fn open_default() -> Result<Self> {
        OPEN_DEFAULT_CALLS.with(|calls| calls.set(calls.get() + 1));

        let path = Self::default_path()?;
        let dir = path
            .parent()
            .context("canonical cockpit DB path has no parent")?;
        files::ensure_private_dir(dir).with_context(|| format!("securing {}", dir.display()))?;
        Self::open(&path)
    }

    /// Open a database at an arbitrary path.
    pub fn open(path: &Path) -> Result<Self> {
        let mut timer = files::PhaseTimer::start("Db::open");
        files::ensure_parent_dir_private(path)
            .with_context(|| format!("securing parent of {}", path.display()))?;
        files::create_private_file_if_missing(path)?;
        let conn = Connection::open(path)
            .with_context(|| format!("opening sqlite at {}", path.display()))?;
        apply_connection_pragmas(&conn, true)
            .with_context(|| format!("setting pragmas on {}", path.display()))?;
        repair_db_file_permissions(path);
        timer.phase("connect_and_pragmas");
        migrate(&conn)?;
        timer.phase("migrate");
        validate_schema_version(&conn, Some(path))?;
        timer.phase("schema_version");
        drop(conn);
        let writer = Writer::start(path.to_path_buf())?;
        let db = Self {
            memory: None,
            writer: Some(writer),
            read_pool: Some(Arc::new(ReadPool::new(path.to_path_buf()))),
            path: Some(path.to_path_buf()),
        };
        timer.done();
        Ok(db)
    }

    /// In-memory database for tests and ephemeral callers; durable state
    /// should use [`Db::open`] or [`Db::open_default`].
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("opening in-memory sqlite")?;
        apply_connection_pragmas(&conn, false).context("setting pragmas on in-memory db")?;
        migrate(&conn)?;
        validate_schema_version(&conn, None)?;
        let db = Self {
            memory: Some(Arc::new(Mutex::new(conn))),
            writer: None,
            read_pool: None,
            path: None,
        };
        Ok(db)
    }

    /// In-memory database constructor for `#[tokio::test]` and other async
    /// tests that need to exercise [`Self::read`] and [`Self::write`].
    pub async fn open_in_memory_async() -> Result<Self> {
        tokio::task::spawn_blocking(Self::open_in_memory)
            .await
            .context("in-memory db worker thread joined")?
    }

    /// File path the database is backed by, or `None` for in-memory.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Stable identity for cache partitioning across cloned handles.
    pub fn identity_key(&self) -> String {
        if let Some(path) = &self.path {
            return format!("file:{}", path.display());
        }
        if let Some(memory) = &self.memory {
            return format!("memory:{:p}", Arc::as_ptr(memory));
        }
        "unknown".to_string()
    }

    /// Return the exact squashed-schema identity recorded in SQLite.
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    pub fn schema_version(&self) -> Result<i64> {
        self.read_blocking(sqlite_schema_version)
    }

    pub async fn read<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        if let Some(pool) = self.read_pool.clone() {
            tokio::task::spawn_blocking(move || pool.run(f))
                .await
                .context("db read worker thread joined")?
        } else {
            let inner = self
                .memory
                .clone()
                .ok_or_else(|| anyhow::anyhow!("db has no in-memory connection"))?;
            tokio::task::spawn_blocking(move || {
                let guard = inner
                    .lock()
                    .map_err(|_| anyhow::anyhow!("db mutex poisoned"))?;
                f(&guard)
            })
            .await
            .context("db read worker thread joined")?
        }
    }

    pub async fn write<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        if let Some(writer) = &self.writer {
            let rx = writer.submit(f)?;
            let boxed = tokio::task::spawn_blocking(move || {
                rx.recv()
                    .map_err(|_| anyhow::anyhow!("db writer reply dropped"))?
            })
            .await
            .context("db writer reply worker joined")??;
            boxed
                .downcast::<T>()
                .map(|value| *value)
                .map_err(|_| anyhow::anyhow!("db writer returned unexpected result type"))
        } else {
            let inner = self
                .memory
                .clone()
                .ok_or_else(|| anyhow::anyhow!("db has no in-memory connection"))?;
            tokio::task::spawn_blocking(move || {
                let guard = inner
                    .lock()
                    .map_err(|_| anyhow::anyhow!("db mutex poisoned"))?;
                f(&guard)
            })
            .await
            .context("db write worker thread joined")?
        }
    }

    /// Execute an atomic write transaction on the writer connection.
    ///
    /// Use this instead of composing multiple async accessors when the
    /// statements form one invariant. The closure runs entirely on the writer
    /// thread and cannot hold a read-pool checkout across an `.await`.
    pub async fn transaction<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        if let Some(writer) = &self.writer {
            let rx = writer.submit(move |conn| run_transaction(conn, f))?;
            let boxed = tokio::task::spawn_blocking(move || {
                rx.recv()
                    .map_err(|_| anyhow::anyhow!("db writer reply dropped"))?
            })
            .await
            .context("db transaction reply worker joined")??;
            boxed
                .downcast::<T>()
                .map(|value| *value)
                .map_err(|_| anyhow::anyhow!("db writer returned unexpected result type"))
        } else {
            let inner = self
                .memory
                .clone()
                .ok_or_else(|| anyhow::anyhow!("db has no in-memory connection"))?;
            tokio::task::spawn_blocking(move || {
                let guard = inner
                    .lock()
                    .map_err(|_| anyhow::anyhow!("db mutex poisoned"))?;
                run_transaction(&guard, f)
            })
            .await
            .context("db transaction worker thread joined")?
        }
    }

    /// Guarded blocking access for synchronous CLI one-shots.
    ///
    /// This closure runs on the writer connection, so it may read and write.
    /// It is the only non-deprecated blocking DB accessor; async code must use
    /// [`Self::read`], [`Self::write`], or [`Self::transaction`].
    pub fn blocking_for_sync_cli<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        if tokio::runtime::Handle::try_current().is_ok() {
            panic!(
                "Db::blocking_for_sync_cli called from async runtime; call Db::read/Db::write from async code instead"
            );
        }
        self.write_blocking_unguarded(f)
    }

    /// Explicit blocking read access for legacy synchronous paths.
    /// Async code should prefer [`Self::read`]. Removed by `db-blocking-api-removal`.
    #[deprecated(
        note = "temporary db-async-foundation bridge; migrate to Db::read/Db::write before db-blocking-api-removal"
    )]
    pub fn read_blocking<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        if let Some(pool) = self.read_pool.as_ref() {
            return pool.run(f);
        }
        let inner = self
            .memory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("db has no in-memory connection"))?;
        let guard = inner
            .lock()
            .map_err(|_| anyhow::anyhow!("db mutex poisoned"))?;
        f(&guard)
    }

    /// Explicit blocking write access for legacy synchronous paths.
    /// Async code should prefer [`Self::write`]. Removed by `db-blocking-api-removal`.
    #[deprecated(
        note = "temporary db-async-foundation bridge; migrate to Db::read/Db::write before db-blocking-api-removal"
    )]
    pub fn write_blocking<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        self.write_blocking_unguarded(f)
    }

    fn write_blocking_unguarded<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        if let Some(writer) = &self.writer {
            let rx = writer.submit(f)?;
            let boxed = rx
                .recv()
                .map_err(|_| anyhow::anyhow!("db writer reply dropped"))??;
            return boxed
                .downcast::<T>()
                .map(|value| *value)
                .map_err(|_| anyhow::anyhow!("db writer returned unexpected result type"));
        }
        let inner = self
            .memory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("db has no in-memory connection"))?;
        let guard = inner
            .lock()
            .map_err(|_| anyhow::anyhow!("db mutex poisoned"))?;
        f(&guard)
    }
}

fn run_transaction<F, T>(conn: &Connection, f: F) -> Result<T>
where
    F: FnOnce(&Connection) -> Result<T>,
{
    conn.execute_batch("BEGIN IMMEDIATE;")
        .context("beginning db transaction")?;
    let result = catch_unwind(AssertUnwindSafe(|| f(conn)));
    match result {
        Ok(Ok(value)) => {
            if let Err(error) = conn.execute_batch("COMMIT;") {
                let _ = conn.execute_batch("ROLLBACK;");
                Err(error).context("committing db transaction")
            } else {
                Ok(value)
            }
        }
        Ok(Err(error)) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(error)
        }
        Err(_) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(anyhow::anyhow!("db transaction job panicked"))
        }
    }
}

fn repair_db_file_permissions(path: &Path) {
    for sidecar in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        if sidecar.exists()
            && let Err(e) = files::repair_private_file(&sidecar, "sqlite")
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
/// disabled, then validates with `PRAGMA foreign_key_check` before
/// commit. This is the runner-owned seam for SQLite table-rebuild
/// migrations; migration SQL must not emit `PRAGMA foreign_keys` itself
/// because that pragma is a no-op inside a transaction.
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

        if fk_was_on {
            foreign_key_check(conn).context("validating migration foreign keys")?;
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

fn sqlite_schema_version(conn: &Connection) -> Result<i64> {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .context("reading SQLite schema version")
}

fn validate_schema_version(conn: &Connection, path: Option<&Path>) -> Result<()> {
    let actual = sqlite_schema_version(conn)?;
    if actual == EXPECTED_SCHEMA_VERSION {
        return Ok(());
    }
    let location = path
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<in-memory>".to_string());
    anyhow::bail!(
        "database schema version mismatch for {location}: found {actual}, expected \
         {EXPECTED_SCHEMA_VERSION}. This pre-release build uses a squashed schema; move the \
         database and its -wal/-shm sidecars aside, then restart Cockpit. See Cockpit CLI \
         README: Development schema resets"
    )
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
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    fn migrate_idempotent() {
        let db = Db::open_in_memory().unwrap();
        // Second migrate call is a no-op.
        db.read_blocking(migrate).unwrap();
        let v: i64 = db
            .read_blocking(|conn| {
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
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    fn connection_pragmas_set_busy_timeout_to_five_seconds() {
        let db = Db::open_in_memory().unwrap();
        let timeout_ms: i64 = db
            .read_blocking(|conn| Ok(conn.query_row("PRAGMA busy_timeout;", [], |row| row.get(0))?))
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
        let env = cockpit_test_support::TestEnvGuard::blocking_lock();
        env.set_var("XDG_DATA_HOME", tmp.path());

        let db = Db::open_default().unwrap();
        drop(db);

        let data_dir = tmp.path().join("cockpit");
        let db_path = data_dir.join("cockpit.db");
        assert_eq!(mode(&data_dir), 0o700);
        assert_eq!(mode(&db_path), 0o600);
    }

    #[tokio::test]
    #[should_panic(
        expected = "Db::blocking_for_sync_cli called from async runtime; call Db::read/Db::write from async code instead"
    )]
    async fn db_blocking_guard_panics_inside_current_thread_runtime() {
        let db = Db::open_in_memory().unwrap();
        let _: () = db.blocking_for_sync_cli(|_| Ok(())).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[should_panic(
        expected = "Db::blocking_for_sync_cli called from async runtime; call Db::read/Db::write from async code instead"
    )]
    async fn db_blocking_guard_panics_inside_multi_thread_runtime() {
        let db = Db::open_in_memory().unwrap();
        let _: () = db.blocking_for_sync_cli(|_| Ok(())).unwrap();
    }

    #[test]
    fn db_blocking_guard_succeeds_outside_any_runtime() {
        let db = Db::open_in_memory().unwrap();
        let value: i64 = db
            .blocking_for_sync_cli(|conn| Ok(conn.query_row("SELECT 7", [], |row| row.get(0))?))
            .unwrap();
        assert_eq!(value, 7);
    }

    #[tokio::test]
    async fn db_blocking_guard_panic_message_names_the_async_alternative() {
        let db = Db::open_in_memory().unwrap();
        let panic = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _: () = db.blocking_for_sync_cli(|_| Ok(())).unwrap();
        }))
        .expect_err("blocking guard must panic inside tokio runtime");
        let message = if let Some(message) = panic.downcast_ref::<String>() {
            message.as_str()
        } else if let Some(message) = panic.downcast_ref::<&'static str>() {
            message
        } else {
            panic!("unexpected panic payload type");
        };
        assert!(message.contains("Db::blocking_for_sync_cli"));
        assert!(message.contains("Db::read"));
        assert!(message.contains("Db::write"));
    }

    #[tokio::test]
    async fn db_blocking_guard_async_api_works_from_tokio_test() {
        let db = Db::open_in_memory_async().await.unwrap();
        db.write(|conn| {
            conn.execute_batch("CREATE TABLE async_probe (value INTEGER NOT NULL);")?;
            conn.execute("INSERT INTO async_probe (value) VALUES (11)", [])?;
            Ok(())
        })
        .await
        .unwrap();

        let value: i64 = db
            .read(|conn| Ok(conn.query_row("SELECT value FROM async_probe", [], |row| row.get(0))?))
            .await
            .unwrap();
        assert_eq!(value, 11);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn db_blocking_guard_transaction_helper_is_atomic() {
        let tmp = TempDir::new().unwrap();
        let db = Db::open(&tmp.path().join("transaction.db")).unwrap();
        db.write(|conn| {
            conn.execute_batch("CREATE TABLE tx_probe (value INTEGER NOT NULL);")?;
            Ok(())
        })
        .await
        .unwrap();

        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let writer_db = db.clone();
        let writer = tokio::spawn(async move {
            writer_db
                .transaction(move |conn| {
                    conn.execute("INSERT INTO tx_probe (value) VALUES (1)", [])?;
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    conn.execute("INSERT INTO tx_probe (value) VALUES (2)", [])?;
                    Ok(())
                })
                .await
        });

        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("transaction should reach the midpoint");
        let during_transaction: i64 = db
            .read(|conn| Ok(conn.query_row("SELECT COUNT(*) FROM tx_probe", [], |row| row.get(0))?))
            .await
            .unwrap();
        assert_eq!(during_transaction, 0);

        release_tx.send(()).unwrap();
        writer.await.unwrap().unwrap();
        let values = db
            .read(|conn| {
                let mut stmt = conn.prepare("SELECT value FROM tx_probe ORDER BY value")?;
                Ok(stmt
                    .query_map([], |row| row.get::<_, i64>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?)
            })
            .await
            .unwrap();
        assert_eq!(values, vec![1, 2]);
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

    #[tokio::test]
    async fn write_actor_applies_writes_in_submission_order() {
        let tmp = TempDir::new().unwrap();
        let db = Db::open(&tmp.path().join("actor.db")).unwrap();
        db.write(|conn| {
            conn.execute_batch("CREATE TABLE actor_order (value INTEGER NOT NULL);")?;
            Ok(())
        })
        .await
        .unwrap();
        db.write(|conn| {
            conn.execute("INSERT INTO actor_order (value) VALUES (1)", [])?;
            Ok(())
        })
        .await
        .unwrap();
        db.write(|conn| {
            conn.execute("INSERT INTO actor_order (value) VALUES (2)", [])?;
            Ok(())
        })
        .await
        .unwrap();

        let values = db
            .read(|conn| {
                let mut stmt = conn.prepare("SELECT value FROM actor_order ORDER BY rowid")?;
                Ok(stmt
                    .query_map([], |row| row.get::<_, i64>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?)
            })
            .await
            .unwrap();
        assert_eq!(values, vec![1, 2]);
    }

    #[tokio::test]
    async fn panicking_write_returns_error_and_actor_keeps_serving() {
        let tmp = TempDir::new().unwrap();
        let db = Db::open(&tmp.path().join("panic.db")).unwrap();
        let err = db
            .write(|_conn| -> Result<()> { panic!("intentional db writer panic") })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("panicked"));

        db.write(|conn| {
            conn.execute_batch("CREATE TABLE after_panic (value INTEGER NOT NULL);")?;
            conn.execute("INSERT INTO after_panic (value) VALUES (7)", [])?;
            Ok(())
        })
        .await
        .unwrap();
        let value: i64 = db
            .read(|conn| Ok(conn.query_row("SELECT value FROM after_panic", [], |row| row.get(0))?))
            .await
            .unwrap();
        assert_eq!(value, 7);
    }

    #[tokio::test]
    async fn read_pool_rejects_writes() {
        let tmp = TempDir::new().unwrap();
        let db = Db::open(&tmp.path().join("readonly.db")).unwrap();
        db.write(|conn| {
            conn.execute_batch("CREATE TABLE readonly_probe (value INTEGER NOT NULL);")?;
            Ok(())
        })
        .await
        .unwrap();
        let err = db
            .read(|conn| {
                conn.execute("INSERT INTO readonly_probe (value) VALUES (1)", [])?;
                Ok(())
            })
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("readonly") || msg.contains("attempt to write"),
            "unexpected read-only error: {msg}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wal_read_completes_while_writer_transaction_is_open() {
        let tmp = TempDir::new().unwrap();
        let db = Db::open(&tmp.path().join("wal.db")).unwrap();
        db.write(|conn| {
            conn.execute_batch(
                "CREATE TABLE wal_probe (value INTEGER NOT NULL);\n                 INSERT INTO wal_probe (value) VALUES (1);",
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let slow_db = db.clone();
        let writer = tokio::spawn(async move {
            slow_db
                .write(move |conn| {
                    conn.execute_batch("BEGIN IMMEDIATE;")?;
                    let _ = entered_tx.send(());
                    std::thread::sleep(Duration::from_millis(100));
                    conn.execute("INSERT INTO wal_probe (value) VALUES (2)", [])?;
                    conn.execute_batch("COMMIT;")?;
                    Ok(())
                })
                .await
        });
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("writer transaction should start");

        let start = Instant::now();
        let count: i64 = db
            .read(
                |conn| Ok(conn.query_row("SELECT COUNT(*) FROM wal_probe", [], |row| row.get(0))?),
            )
            .await
            .unwrap();
        assert_eq!(count, 1, "reader should see the pre-commit snapshot");
        assert!(
            start.elapsed() < Duration::from_millis(75),
            "read waited for slow writer: {:?}",
            start.elapsed()
        );
        writer.await.unwrap().unwrap();
    }

    #[test]
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    fn busy_timeout_waits_for_short_write_contention() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("busy.db");
        let db_a = Db::open(&path).unwrap();
        let db_b = Db::open(&path).unwrap();

        db_a.write_blocking(move |conn| {
            conn.execute_batch(
                "CREATE TABLE busy_probe (id INTEGER PRIMARY KEY, value TEXT NOT NULL);",
            )?;
            Ok(())
        })
        .unwrap();

        db_a.write_blocking(move |conn| {
            conn.execute_batch("BEGIN IMMEDIATE;")?;
            conn.execute("INSERT INTO busy_probe (value) VALUES ('held')", [])?;
            Ok(())
        })
        .unwrap();

        let (tx, rx) = mpsc::channel();
        let started = Instant::now();
        let writer = std::thread::spawn(move || {
            let result = db_b.write_blocking(move |conn| {
                conn.execute("INSERT INTO busy_probe (value) VALUES ('waited')", [])?;
                Ok(())
            });
            tx.send((started.elapsed(), result)).unwrap();
        });

        std::thread::sleep(Duration::from_millis(30));
        assert!(
            rx.try_recv().is_err(),
            "second writer returned immediately instead of waiting for busy timeout"
        );

        db_a.write_blocking(move |conn| {
            conn.execute_batch("COMMIT;")?;
            Ok(())
        })
        .unwrap();

        let (elapsed, result) = rx.recv().unwrap();
        writer.join().unwrap();
        result.unwrap();
        assert!(
            elapsed >= Duration::from_millis(30),
            "second writer did not wait for the held write lock: {elapsed:?}"
        );

        let count: i64 = db_a
            .read_blocking(|conn| {
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

        std::thread::sleep(Duration::from_millis(30));
        assert!(
            rx.try_recv().is_err(),
            "second migrator returned before the migration lock was released"
        );

        conn_a.execute_batch("COMMIT;").unwrap();
        let (elapsed, result) = rx.recv().unwrap();
        waiter.join().unwrap();
        result.unwrap();
        assert!(
            elapsed >= Duration::from_millis(30),
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
    fn migration_fk_violation_rolls_back_to_prior_version() {
        let conn = Connection::open_in_memory().unwrap();
        apply_connection_pragmas(&conn, false).unwrap();
        let first = r#"
            CREATE TABLE parent (id INTEGER PRIMARY KEY);
            CREATE TABLE child (
                id INTEGER PRIMARY KEY,
                parent_id INTEGER NOT NULL REFERENCES parent(id) ON DELETE CASCADE
            );
            INSERT INTO parent (id) VALUES (1);
            INSERT INTO child (id, parent_id) VALUES (10, 1);
        "#;
        let violating_second = r#"
            CREATE TABLE parent_new (id INTEGER PRIMARY KEY);
            DROP TABLE parent;
            ALTER TABLE parent_new RENAME TO parent;
        "#;

        migrate_with(&conn, &[first]).unwrap();
        let err = migrate_with(&conn, &[first, violating_second]).unwrap_err();
        assert!(
            format!("{err:#}").contains("migration left dangling foreign keys"),
            "unexpected error: {err:#}"
        );

        let version = current_schema_version(&conn).unwrap();
        assert_eq!(version, 1);
        let child_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM child WHERE id = 10 AND parent_id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(child_count, 1);
        foreign_key_check(&conn).unwrap();
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
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
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
                .read_blocking(|conn| {
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
            .read_blocking(|conn| {
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
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    fn approval_grants_has_risk_tier_column() {
        let db = Db::open_in_memory().unwrap();
        let columns: Vec<(String, String)> = db
            .read_blocking(|conn| {
                let mut stmt = conn.prepare("PRAGMA table_info(approval_grants)")?;
                let rows = stmt.query_map([], |row| {
                    Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
                })?;
                let mut columns = Vec::new();
                for row in rows {
                    columns.push(row?);
                }
                Ok(columns)
            })
            .unwrap();

        assert!(
            columns
                .iter()
                .any(|(name, ty)| name == "risk_tier" && ty == "TEXT"),
            "approval_grants.risk_tier TEXT column missing; columns were {columns:?}"
        );
    }

    #[test]
    #[expect(
        deprecated,
        reason = "db-async-foundation bridge; migrated later in db async accessor prompts"
    )]
    fn approval_grants_allows_mcp_tool_kind_with_null_access() {
        let db = Db::open_in_memory().unwrap();
        let session_id = uuid::Uuid::new_v4().to_string();

        db.write_blocking(move |conn| {
            conn.execute(
                "INSERT INTO sessions \
                 (session_id, project_id, project_root, started_at, last_active_at) \
                 VALUES (?1, 'project', '/tmp/project', 1, 1)",
                [&session_id],
            )?;

            conn.execute(
                "INSERT INTO approval_grants \
                 (session_id, grant_kind, grant_key, granted_at, verdict, access, risk_tier) \
                 VALUES (?1, 'mcp_tool', 'external/search', 2, 'allow', NULL, NULL)",
                [&session_id],
            )?;

            let access_result = conn.execute(
                "INSERT INTO approval_grants \
                 (session_id, grant_kind, grant_key, granted_at, verdict, access, risk_tier) \
                 VALUES (?1, 'mcp_tool', 'external/read', 2, 'allow', 'read', NULL)",
                [&session_id],
            );
            assert!(
                access_result.is_err(),
                "mcp_tool grants must not carry access"
            );

            let tier_result = conn.execute(
                "INSERT INTO approval_grants \
                 (session_id, grant_kind, grant_key, granted_at, verdict, access, risk_tier) \
                 VALUES (?1, 'mcp_tool', 'external/write', 2, 'allow', NULL, 'ordinary')",
                [&session_id],
            );
            assert!(
                tier_result.is_err(),
                "mcp_tool grants must not carry risk_tier"
            );
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn no_second_migration_file_exists() {
        let migrations_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("db")
            .join("migrations");
        let mut migrations: Vec<String> = std::fs::read_dir(&migrations_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".sql"))
            .collect();
        migrations.sort();

        assert_eq!(migrations, vec!["0001_initial.sql"]);
    }
}
